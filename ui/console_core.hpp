// console_core.hpp — the seam between the iLO protocol stack and a front end.
//
// Everything below this line is protocol; everything above it is presentation.
// Two front ends are planned and neither should need to know about the other:
// an SDL window, and an RFB bridge that lets any VNC viewer act as the display.
// Both want the same three things, which is all this exposes:
//
//   * a framebuffer, pulled when convenient rather than pushed from a socket
//     thread into someone else's event loop,
//   * the rectangles that ACTUALLY changed since the last pull,
//   * a way to send input without knowing anything about RC4 or telnet.
//
// The dirty-rectangle tracking is the part that earns its keep. The DVC encoder
// is not diff-based: every pass retransmits all 3072 tiles of a 1024x768 screen
// whether or not they changed, and in a settled capture 27099 of 32256 pastes
// were byte-identical rewrites (see testdata/README.md). Forwarding that
// verbatim would mean repainting the whole screen several times a second and,
// for the RFB bridge, sending it over the network. So every tile is compared
// against the framebuffer before being blitted, and only genuine changes are
// reported. That turns a non-diff protocol into a diff stream for the front end.
//
// Threading: a worker thread owns the socket, the decoder and the outbound RC4
// state. Input is queued rather than sent inline, because the encrypter is a
// stream cipher whose state cannot survive two threads touching it. The front
// end only ever calls pull() and the input methods, from any thread.
#pragma once
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <deque>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "ilo/cim_png.hpp"
#include "ilo/ilo2_input.hpp"
#include "ilo/ilo2_session.hpp"
#include "ilo/ilo_session.hpp"

namespace ilo2 {

struct Rect {
    int x = 0, y = 0, w = 0, h = 0;
};

enum class ConsoleState {
    Idle,
    Connecting,
    Connected,
    Stopped,
    Failed,
};

inline const char* console_state_name(ConsoleState s) {
    switch (s) {
        case ConsoleState::Idle:       return "idle";
        case ConsoleState::Connecting: return "connecting";
        case ConsoleState::Connected:  return "connected";
        case ConsoleState::Stopped:    return "stopped";
        case ConsoleState::Failed:     return "failed";
    }
    return "?";
}

// ---------------------------------------------------------------------------
// Framebuffer with change detection
// ---------------------------------------------------------------------------

// A FramebufferDecoder that records which 16x16 tiles genuinely changed.
// Not thread-safe on its own; ConsoleCore holds the lock.
class TrackingFramebuffer : public FramebufferDecoder {
public:
    static constexpr int TILE = 16;

    int tiles_x = 0, tiles_y = 0;
    std::vector<uint8_t> tile_dirty;      // 1 per tile
    uint64_t pastes = 0, changed_pastes = 0;
    std::string last_status;

    bool any_dirty() const {
        for (uint8_t d : tile_dirty) if (d) return true;
        return false;
    }
    void mark_all_dirty() { std::fill(tile_dirty.begin(), tile_dirty.end(), uint8_t(1)); }
    void clear_dirty()    { std::fill(tile_dirty.begin(), tile_dirty.end(), uint8_t(0)); }

protected:
    void on_set_dimensions(int w, int h) override {
        if (w == fb_w && h == fb_h) return;       // a repeat must be a no-op
        FramebufferDecoder::on_set_dimensions(w, h);
        tiles_x = (w + TILE - 1) / TILE;
        tiles_y = (h + TILE - 1) / TILE;
        tile_dirty.assign(static_cast<size_t>(tiles_x) * tiles_y, 1);
    }

    // Blit only what differs, and mark the tile dirty only if something did.
    void on_paste(const int* blk, int x, int y, int len) override {
        ++pastes;
        if (pixels.empty()) return;

        const int rows = (y + TILE > fb_h) ? (fb_h - y) : TILE;
        bool changed = false;
        for (int r = 0; r < rows; ++r) {
            const int yy = y + r;
            if (yy < 0 || yy >= fb_h) continue;
            for (int c = 0; c < len; ++c) {
                const int xx = x + c;
                if (xx < 0 || xx >= fb_w) continue;
                const uint32_t v = static_cast<uint32_t>(blk[r * TILE + c]);
                uint32_t& dst = pixels[static_cast<size_t>(yy) * fb_w + xx];
                if (dst != v) { dst = v; changed = true; }
            }
        }
        if (!changed) return;                     // the common case: a redundant repaint

        ++changed_pastes;
        const int tx = x / TILE, ty = y / TILE;
        if (tx >= 0 && tx < tiles_x && ty >= 0 && ty < tiles_y)
            tile_dirty[static_cast<size_t>(ty) * tiles_x + tx] = 1;
    }

    void on_show_text(const std::string& s) override { last_status = s; }
};

// ---------------------------------------------------------------------------
// ConsoleCore
// ---------------------------------------------------------------------------

class ConsoleCore {
public:
    struct Config {
        std::string host;
        std::string user = "Administrator";
        std::string pass;
        uint16_t    https_port   = 443;
        int         console_port = 0;      // 0 = take info6 from the iLO
        int         timeout_ms   = 15000;
        // Ask for a full redraw every N seconds. The encoder only retransmits
        // on its own schedule, so a client that has just attached may otherwise
        // wait a while for regions that are not changing.
        int         refresh_every_sec = 0;
    };

    ConsoleCore() = default;
    ~ConsoleCore() { stop(); }

    ConsoleCore(const ConsoleCore&)            = delete;
    ConsoleCore& operator=(const ConsoleCore&) = delete;

    // --- lifecycle ---------------------------------------------------------

    bool start(const Config& cfg, std::string& err) {
        if (worker_.joinable()) { err = "already running"; return false; }
        cfg_ = cfg;
        if (cfg_.host.empty()) { err = "no host"; return false; }
        set_state(ConsoleState::Connecting);
        running_ = true;
        worker_ = std::thread([this] { live_thread(); });
        return true;
    }

    // Replay a captured DVC stream instead of connecting. The bytes are the
    // decrypted post-ESC[R payload that tools/capture_dvc.cpp writes, so this
    // exercises the decoder, the change detection and the pull API with no
    // hardware and no credentials -- which is what makes the seam testable.
    bool start_replay(const std::string& path, int bytes_per_sec, std::string& err) {
        if (worker_.joinable()) { err = "already running"; return false; }
        std::FILE* f = std::fopen(path.c_str(), "rb");
        if (!f) { err = "cannot open " + path; return false; }
        std::fseek(f, 0, SEEK_END);
        const long n = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        replay_.resize(n > 0 ? static_cast<size_t>(n) : 0);
        if (!replay_.empty() && std::fread(replay_.data(), 1, replay_.size(), f) != replay_.size()) {
            std::fclose(f);
            err = "short read on " + path;
            return false;
        }
        std::fclose(f);

        replay_rate_ = bytes_per_sec;
        set_state(ConsoleState::Connecting);
        running_ = true;
        worker_ = std::thread([this] { replay_thread(); });
        return true;
    }

    void stop() {
        running_ = false;
        if (session_) session_->disconnect();   // unblocks run()'s recv
        if (worker_.joinable()) worker_.join();
        session_.reset();
        if (state() != ConsoleState::Failed) set_state(ConsoleState::Stopped);
    }

    ConsoleState state() const { return state_.load(); }
    bool         running() const { return running_.load(); }

    std::string error() const {
        std::lock_guard<std::mutex> lk(mu_);
        return error_;
    }
    std::string status() const {
        std::lock_guard<std::mutex> lk(mu_);
        return status_;
    }

    int width()  const { std::lock_guard<std::mutex> lk(mu_); return fb_.fb_w; }
    int height() const { std::lock_guard<std::mutex> lk(mu_); return fb_.fb_h; }

    uint64_t pastes()         const { std::lock_guard<std::mutex> lk(mu_); return fb_.pastes; }
    uint64_t changed_pastes() const { std::lock_guard<std::mutex> lk(mu_); return fb_.changed_pastes; }

    // --- the front end's view ---------------------------------------------

    // Copy the tiles that changed since the last pull into `dest`, which the
    // caller owns and keeps between calls. `dirty` receives the changed
    // rectangles, with horizontally adjacent tiles merged into runs so an RFB
    // client gets a handful of rectangles rather than hundreds of 16x16 ones.
    //
    // Returns false when nothing changed, in which case dest and dirty are
    // untouched. A resolution change reports the whole screen.
    bool pull(std::vector<uint32_t>& dest, int& w, int& h, std::vector<Rect>& dirty) {
        std::lock_guard<std::mutex> lk(mu_);
        if (fb_.pixels.empty()) return false;

        const bool resized = (dest.size() != fb_.pixels.size());
        if (resized) {
            dest.assign(fb_.pixels.begin(), fb_.pixels.end());
            w = fb_.fb_w;
            h = fb_.fb_h;
            dirty.clear();
            dirty.push_back(Rect{ 0, 0, fb_.fb_w, fb_.fb_h });
            fb_.clear_dirty();
            return true;
        }

        w = fb_.fb_w;
        h = fb_.fb_h;
        dirty.clear();

        for (int ty = 0; ty < fb_.tiles_y; ++ty) {
            int run_start = -1;
            for (int tx = 0; tx <= fb_.tiles_x; ++tx) {
                const bool d = (tx < fb_.tiles_x) &&
                               fb_.tile_dirty[static_cast<size_t>(ty) * fb_.tiles_x + tx] != 0;
                if (d && run_start < 0) run_start = tx;
                if (!d && run_start >= 0) {
                    emit_run(dest, dirty, run_start, tx, ty);
                    run_start = -1;
                }
            }
        }
        fb_.clear_dirty();
        return !dirty.empty();
    }

    // --- input -------------------------------------------------------------
    //
    // Queued, not sent inline: the outbound RC4 encrypter is a stream cipher
    // whose state cannot survive concurrent use, and the worker thread already
    // owns it. The receive loop drains this between reads.

    void mouse_move(int x, int y) {
        std::lock_guard<std::mutex> lk(mu_);
        input_.screen_w = fb_.fb_w;
        input_.screen_h = fb_.fb_h;
        queue_locked(input_.move(x, y));
    }
    void mouse_button(int button, bool down) {
        std::lock_guard<std::mutex> lk(mu_);
        queue_locked(down ? input_.press(button) : input_.release(button));
    }
    void type_char(char c) {
        std::lock_guard<std::mutex> lk(mu_);
        queue_locked(Input::type_char(c));
    }
    void type_text(const std::string& s) {
        std::lock_guard<std::mutex> lk(mu_);
        for (char c : s) queue_locked(Input::type_char(c));
    }
    void send_raw(const std::string& bytes) {
        std::lock_guard<std::mutex> lk(mu_);
        queue_locked(bytes);
    }
    // Neither Windows nor Linux will let an application capture a real
    // Ctrl-Alt-Del, so the front end has to offer it as a button -- exactly as
    // HP's applet did (remcons.java:46).
    void send_ctrl_alt_del() {
        std::lock_guard<std::mutex> lk(mu_);
        queue_locked(Input::ctrl_alt_del());
    }
    void request_refresh() {
        std::lock_guard<std::mutex> lk(mu_);
        want_refresh_ = true;
    }

private:
    // --- decoder plumbing --------------------------------------------------

    // CimSession routes decrypted DVC bytes here; the framebuffer and status
    // both live under the same lock the front end pulls against.
    class CoreSession : public CimSession {
    public:
        explicit CoreSession(ConsoleCore* core) : core_(core) {}
    protected:
        bool process_dvc(uint8_t c) override {
            std::lock_guard<std::mutex> lk(core_->mu_);
            return core_->fb_.process_dvc(c);
        }
        void set_status(int field, const std::string& text) override {
            std::lock_guard<std::mutex> lk(core_->mu_);
            core_->status_ = text;
            (void)field;
        }
        // Runs on the receive thread, which is the only thread allowed to touch
        // the outbound RC4 encrypter.
        void on_idle() override { core_->pump(); }
    private:
        ConsoleCore* core_;
    };

    void set_state(ConsoleState s) { state_.store(s); }

    void fail(const std::string& msg) {
        {
            std::lock_guard<std::mutex> lk(mu_);
            error_ = msg;
        }
        set_state(ConsoleState::Failed);
        running_ = false;
    }

    void queue_locked(const std::string& bytes) {
        if (bytes.empty()) return;
        if (outbox_.size() > 4096) return;        // a wedged link must not grow without bound
        outbox_.push_back(bytes);
    }

    void emit_run(std::vector<uint32_t>& dest, std::vector<Rect>& dirty,
                  int tx0, int tx_end, int ty) const {
        const int x = tx0 * TrackingFramebuffer::TILE;
        const int y = ty * TrackingFramebuffer::TILE;
        int rw = (tx_end - tx0) * TrackingFramebuffer::TILE;
        int rh = TrackingFramebuffer::TILE;
        if (x + rw > fb_.fb_w) rw = fb_.fb_w - x;
        if (y + rh > fb_.fb_h) rh = fb_.fb_h - y;
        if (rw <= 0 || rh <= 0) return;

        for (int r = 0; r < rh; ++r) {
            const size_t off = static_cast<size_t>(y + r) * fb_.fb_w + x;
            std::memcpy(dest.data() + off, fb_.pixels.data() + off,
                        static_cast<size_t>(rw) * sizeof(uint32_t));
        }
        dirty.push_back(Rect{ x, y, rw, rh });
    }

    // --- worker threads ----------------------------------------------------

    void live_thread() {
        std::string err;
        ConsoleParams cp;
        if (!acquire_console_session(cfg_.host, cfg_.https_port, cfg_.user, cfg_.pass, cp, err)) {
            fail(err);
            return;
        }

        const std::string info0 = cp.get("info0");
        if (info0.empty()) { fail("no info0 in the console parameters"); return; }

        std::string login = hp_base64_decode(info0);
        if (!login.empty()) {
            if (cp.has("info1")) login = "\x1b[4" + login;   // INFO1 is a presence flag
            login = "\x1b[7\x1b[9" + login;
        }

        auto sess = std::unique_ptr<CoreSession>(new CoreSession(this));

        const bool encrypted = (cp.get("infoa", "1") == "1");
        if (encrypted) {
            uint8_t kb[16], kc[16];
            if (!hex16(cp.get("infob"), kb) || !hex16(cp.get("infoc"), kc)) {
                fail("malformed session keys (infob/infoc)");
                return;
            }
            sess->setup_decryption(kb);          // must precede connect()
            sess->setup_encryption(kc, static_cast<uint32_t>(
                std::atoi(cp.get("infod", "0").c_str())));
        }

        const int port = cfg_.console_port ? cfg_.console_port
                                           : std::atoi(cp.get("info6", "23").c_str());
        if (!sess->connect(cfg_.host, login, port)) {
            fail("cannot connect to the console port " + std::to_string(port));
            return;
        }

        // Absolute mouse mode: the server positions the cursor from scaled
        // coordinates, so no MouseSync calibration is needed.
        sess->transmit(Input::select_mouse(true));

        session_ = std::move(sess);
        set_state(ConsoleState::Connected);
        last_refresh_ = std::chrono::steady_clock::now();

        session_->run();                     // pumps via CoreSession::on_idle
        running_ = false;
        if (state() != ConsoleState::Failed) set_state(ConsoleState::Stopped);
    }

    // Flush queued input and honour a periodic redraw request. Called only from
    // the receive thread, so transmit() (and the RC4 encrypter behind it) is
    // never touched concurrently.
    void pump() {
        std::deque<std::string> pending;
        bool refresh = false;
        {
            std::lock_guard<std::mutex> lk(mu_);
            pending.swap(outbox_);
            refresh = want_refresh_;
            want_refresh_ = false;
        }
        for (const auto& b : pending) session_->transmit(b);

        if (cfg_.refresh_every_sec > 0) {
            const auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::seconds>(now - last_refresh_).count()
                    >= cfg_.refresh_every_sec) {
                last_refresh_ = now;
                refresh = true;
            }
        }
        if (refresh) session_->refresh_screen();
    }

    void replay_thread() {
        set_state(ConsoleState::Connected);
        const size_t chunk = replay_rate_ > 0 ? static_cast<size_t>(replay_rate_) / 20 + 1
                                              : replay_.size();
        size_t pos = 0;
        while (running_ && pos < replay_.size()) {
            const size_t n = std::min(chunk, replay_.size() - pos);
            {
                std::lock_guard<std::mutex> lk(mu_);
                for (size_t i = 0; i < n; ++i) fb_.process_dvc(replay_[pos + i]);
            }
            pos += n;
            if (replay_rate_ > 0 && pos < replay_.size())
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        {
            std::lock_guard<std::mutex> lk(mu_);
            status_ = "replay finished";
        }
        running_ = false;
        set_state(ConsoleState::Stopped);
    }

    // --- helpers -----------------------------------------------------------

    static bool hex16(const std::string& s, uint8_t out[16]) {
        if (s.size() < 32) return false;
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        for (int i = 0; i < 16; ++i) {
            const int hi = nyb(s[2 * i]), lo = nyb(s[2 * i + 1]);
            if (hi < 0 || lo < 0) return false;
            out[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        return true;
    }

    // remcons.base64_decode: standard alphabet, but ':' decodes to '\r' and a
    // trailing '\r' is appended. Omitting that CR makes the iLO accept the
    // connection and then never answer.
    static std::string hp_base64_decode(const std::string& in) {
        auto val = [](char c) -> int {
            if (c >= 'A' && c <= 'Z') return c - 'A';
            if (c >= 'a' && c <= 'z') return c - 'a' + 26;
            if (c >= '0' && c <= '9') return c - '0' + 52;
            if (c == '+') return 62;
            if (c == '/') return 63;
            return 0;
        };
        auto fix = [](int v) {
            return static_cast<char>((v & 0xFF) == ':' ? '\r' : (v & 0xFF));
        };
        std::string out;
        size_t n = 0;
        int done = 0;
        while (n + 3 < in.size() && done == 0) {
            const int c1 = val(in[n]), c2 = val(in[n + 1]),
                      c3 = val(in[n + 2]), c4 = val(in[n + 3]);
            out += fix((c1 << 2) + (c2 >> 4));
            if (in[n + 2] == '=') ++done; else out += fix((c2 << 4) + (c3 >> 2));
            if (in[n + 3] == '=') ++done; else out += fix((c3 << 6) + c4);
            n += 4;
        }
        if (!out.empty()) out += '\r';
        return out;
    }

    Config                        cfg_;
    mutable std::mutex            mu_;
    TrackingFramebuffer           fb_;
    Input                         input_;
    std::deque<std::string>       outbox_;
    bool                          want_refresh_ = false;
    std::string                   status_, error_;
    std::unique_ptr<CoreSession>  session_;
    std::thread                   worker_;
    std::atomic<bool>             running_{ false };
    std::atomic<ConsoleState>     state_{ ConsoleState::Idle };
    std::chrono::steady_clock::time_point last_refresh_{};
    std::vector<uint8_t>          replay_;
    int                           replay_rate_ = 0;
};

} // namespace ilo2
