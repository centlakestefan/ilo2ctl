// capture_dvc.cpp — connect to a live iLO 2 remote-console port and capture the
// decrypted DVC video stream.
//
// This is the missing piece for the frame-level oracle: the FSM has been proven
// behaviourally identical to HP's cim on synthetic data, but only a REAL stream
// proves the decoder produces a correct IMAGE. So this tool does two things at
// once:
//
//   1. writes every decrypted post-ESC[R byte to a .bin, giving us a stream we
//      can replay offline forever (no hardware needed for future regressions),
//   2. runs those same bytes through FramebufferDecoder and saves PNGs, so the
//      result can be eyeballed immediately.
//
// Session parameters (login token, keys) come from the iLO's drc2fram.htm page.
// With no --info0 given, this binary scrapes them itself via ilo/ilo_session.hpp.
//
// Build:
//   cmake -S . -B build/cmake -G Ninja && cmake --build build/cmake --target capture_dvc
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <functional>
#include <string>
#include <thread>
#include <vector>

#include "ilo/ilo2_session.hpp"
#include "ilo/ilo_session.hpp"
#include "ilo/ilo2_input.hpp"
#include "ilo/cim_png.hpp"

using namespace ilo2;

// ---- small helpers ---------------------------------------------------------

static bool parse_hex16(const std::string& s, uint8_t out[16]) {
    if (s.size() < 32) return false;
    for (int i = 0; i < 16; ++i) {
        auto nyb = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int hi = nyb(s[2 * i]), lo = nyb(s[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        out[i] = static_cast<uint8_t>((hi << 4) | lo);
    }
    return true;
}

// Faithful port of remcons.base64_decode (remcons.java:462), applied to INFO0.
// The alphabet is standard, but two HP quirks are NOT and both matter:
//   * any decoded byte equal to ':' is rewritten to '\r' -- the token's field
//     separator is carried as a colon and restored to a carriage return here,
//   * a trailing '\r' is appended to the whole token; without it the iLO never
//     considers the login line complete and simply never answers.
// remcons.parse_login also handles a "Compaq-RIB-Login=" form; current firmware
// hands out the base64 form, which is what we implement.
static std::string base64_decode(const std::string& in) {
    auto val = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return 0;                       // HP's table is 0 for everything else
    };
    auto colon_to_cr = [](int v) {
        return static_cast<char>((v & 0xFF) == ':' ? '\r' : (v & 0xFF));
    };

    std::string out;
    size_t n = 0;
    int done = 0;
    while (n + 3 < in.size() && done == 0) {
        int c1 = val(in[n]), c2 = val(in[n + 1]), c3 = val(in[n + 2]), c4 = val(in[n + 3]);
        char b1 = colon_to_cr((c1 << 2) + (c2 >> 4));
        char b2 = colon_to_cr((c2 << 4) + (c3 >> 2));
        char b3 = colon_to_cr((c3 << 6) + c4);
        out += b1;
        if (in[n + 2] == '=') ++done; else out += b2;
        if (in[n + 3] == '=') ++done; else out += b3;
        n += 4;
    }
    if (!out.empty()) out += '\r';      // the terminator the firmware waits for
    return out;
}

// ---- capturing session -----------------------------------------------------

// The decoder needs to reach back into the transport for the one hook with a
// transport side effect: firmware cmd 9 (in-band rekey). In the JAR this is
// automatic because cim IS the telnet subclass; here the two are separate
// objects, so route the hook through callbacks.
class CapFb : public FramebufferDecoder {
public:
    std::function<void()> on_key_change;
    int pastes = 0, dims = 0;

protected:
    void on_change_key() override { if (on_key_change) on_key_change(); }
    void on_paste(const int* blk, int x, int y, int len) override {
        ++pastes;
        FramebufferDecoder::on_paste(blk, x, y, len);
    }
    void on_set_dimensions(int w, int h) override {
        ++dims;
        std::printf("[dvc] resolution %dx%d\n", w, h);
        std::fflush(stdout);
        FramebufferDecoder::on_set_dimensions(w, h);
    }
    void on_show_text(const std::string& s) override {
        std::printf("[dvc text] %s\n", s.c_str());
        std::fflush(stdout);
    }
    void on_firmware(int cmd) override {
        std::printf("[dvc] firmware cmd %d (ignored)\n", cmd);
        std::fflush(stdout);
    }
};

class CaptureSession : public CimSession {
public:
    std::vector<uint8_t> raw;          // decrypted DVC bytes, in order
    CapFb fb;

    CaptureSession() {
        fb.on_key_change = [this] {
            std::printf("[dvc] in-band rekey (firmware cmd 9)\n");
            std::fflush(stdout);
            this->change_key();        // rekeys BOTH encrypter and decrypter
        };
    }

protected:
    bool process_dvc(uint8_t c) override {
        raw.push_back(c);
        return fb.process_dvc(c);
    }
    void set_status(int field, const std::string& text) override {
        std::printf("[status %d] %s\n", field, text.c_str());
        std::fflush(stdout);
    }
};

int main(int argc, char** argv) {
    std::string host, info0, infob_hex, infoc_hex, out_bin = "build/dvc_capture.bin";
    std::string png_prefix = "build/frame";
    std::string user = "Administrator", pass, pass_file = ".ilo_pass";
    int port = 23, seconds = 20, infod = 0, refresh_every = 0;
    int https_port = 443;
    bool info1 = false, encrypted = true, wake = false, wake_keys = false;
    bool have_info1 = false, have_infoa = false;
    bool params_only = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host")    host = next();
        else if (a == "--user")    user = next();
        else if (a == "--pass")    pass = next();
        else if (a == "--pass-file") pass_file = next();
        else if (a == "--https-port") https_port = std::atoi(next().c_str());
        else if (a == "--port")    port = std::atoi(next().c_str());
        else if (a == "--info0")   info0 = next();
        else if (a == "--info1") { info1 = (next() == "1"); have_info1 = true; }
        else if (a == "--infoa") { encrypted = (next() == "1"); have_infoa = true; }
        else if (a == "--infob")   infob_hex = next();
        else if (a == "--infoc")   infoc_hex = next();
        else if (a == "--infod")   infod = std::atoi(next().c_str());
        else if (a == "--seconds") seconds = std::atoi(next().c_str());
        else if (a == "--params-only") params_only = true;
        else if (a == "--wake")      wake = true;
        else if (a == "--wake-keys") wake_keys = true;
        else if (a == "--refresh-every") refresh_every = std::atoi(next().c_str());
        else if (a == "--out")     out_bin = next();
        else if (a == "--png")     png_prefix = next();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }
    if (host.empty()) {
        std::fprintf(stderr,
            "usage: capture_dvc --host H [--user U] [--pass P | --pass-file F]\n"
            "                   [--seconds 20] [--out f.bin] [--png pfx]\n"
            "                   [--wake] [--wake-keys] [--refresh-every SEC]\n"
            "                   [--params-only]   log in, print params, stop\n"
            "\n"
            "  Logs in over HTTPS and scrapes the console parameters itself.\n"
            "  The password comes from --pass, else $ILO_PASS, else .ilo_pass.\n"
            "\n"
            "  To bypass the login and supply parameters directly:\n"
            "    --info0 <b64> [--info1 1] [--infoa 1] [--infob <32hex>]\n"
            "    [--infoc <32hex>] [--infod N] [--port 23]\n");
        return 2;
    }

    // No INFO0 given: acquire a session ourselves, which the Python wrapper
    // this replaced used to do by shelling out to curl.
    if (info0.empty()) {
        const std::string pw = read_ilo_password(pass, pass_file);
        if (pw.empty()) {
            std::fprintf(stderr,
                "no iLO password: pass --pass, set ILO_PASS, or put it in %s\n",
                pass_file.c_str());
            return 2;
        }
        std::printf("[*] logging in to %s as %s ...\n", host.c_str(), user.c_str());
        ConsoleParams cp;
        std::string err;
        if (!acquire_console_session(host, static_cast<uint16_t>(https_port),
                                     user, pw, cp, err)) {
            std::fprintf(stderr, "[!] %s\n", err.c_str());
            return 1;
        }
        std::printf("[+] session %s, %zu console parameters\n",
                    cp.session_index.c_str(), cp.info.size());

        info0 = cp.get("info0");
        // INFO1 is a PRESENCE flag: its value is ignored, only whether the
        // parameter appears at all (remcons.init_params, remcons.java:310).
        if (!have_info1) info1 = cp.has("info1");
        if (!have_infoa) encrypted = (cp.get("infoa", "1") == "1");
        if (infob_hex.empty()) infob_hex = cp.get("infob");
        if (infoc_hex.empty()) infoc_hex = cp.get("infoc");
        if (infod == 0)        infod = std::atoi(cp.get("infod", "0").c_str());
        if (port == 23)        port = std::atoi(cp.get("info6", "23").c_str());

        for (const auto& kv : cp.info) {
            const bool secret = (kv.first == "infob" || kv.first == "infoc");
            const std::string shown = secret
                ? kv.second.substr(0, 8) + "... (" + std::to_string(kv.second.size()) + " hex)"
                : kv.second;
            std::printf("    %-8s = %s\n", kv.first.c_str(), shown.c_str());
        }

        if (params_only) {
            // Stop before touching port 23. The iLO allows exactly one remote
            // console session, so this is the way to exercise the login and the
            // scrape without taking that slot.
            std::printf("[+] --params-only: not opening a console session\n");
            return 0;
        }
    }

    // remcons.init_params(): login = ESC[7 ESC[9 [ESC[4] <decoded INFO0>
    std::string login = base64_decode(info0);
    if (!login.empty()) {
        if (info1) login = "\x1b[4" + login;
        login = "\x1b[7\x1b[9" + login;
    }
    std::printf("[*] login token: %zu bytes\n", login.size());

    CaptureSession sess;

    if (encrypted) {
        uint8_t kb[16], kc[16];
        if (!parse_hex16(infob_hex, kb)) { std::fprintf(stderr, "bad --infob\n"); return 2; }
        if (!parse_hex16(infoc_hex, kc)) { std::fprintf(stderr, "bad --infoc\n"); return 2; }
        sess.setup_decryption(kb);              // must precede connect(): sets encryption_enabled_
        sess.setup_encryption(kc, static_cast<uint32_t>(infod));
        std::printf("[*] encryption on, key index %d\n", infod);
    }

    std::printf("[*] connecting to %s:%d ...\n", host.c_str(), port);
    if (!sess.connect(host, login, port)) {
        std::fprintf(stderr, "[!] connect failed\n");
        return 1;
    }
    std::printf("[+] connected, login sent\n");
    sess.start();

    // Force a full redraw so the capture contains a complete frame, not just the
    // deltas that happen to occur while we are watching.
    std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    std::printf("[*] requesting full screen refresh\n");
    sess.refresh_screen();

    // --wake: nudge the pointer to bring a blanked console back. Deliberately
    // mouse MOVES only -- no button press, no keystroke -- so nothing is
    // clicked or typed on the live server. This is also the first live exercise
    // of the outbound encoder (and of the 3000/screen coordinate scaling).
    if (wake) {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        Input in;
        in.screen_w = sess.fb.fb_w;
        in.screen_h = sess.fb.fb_h;
        in.absolute = true;
        if (in.screen_w <= 0 || in.screen_h <= 0) {
            std::printf("[!] --wake: no resolution yet, skipping\n");
        } else {
            std::printf("[*] --wake: moving pointer (no clicks, no keys)\n");
            sess.transmit(Input::select_mouse(true));      // FF D5 01, USB-absolute
            const int pts[][2] = {
                {in.screen_w / 2,     in.screen_h / 2},
                {in.screen_w / 2 + 80, in.screen_h / 2 + 60},
                {in.screen_w / 3,     in.screen_h / 3},
                {in.screen_w / 2,     in.screen_h / 2},
            };
            for (auto& p : pts) {
                sess.transmit(in.move(p[0], p[1]));
                std::this_thread::sleep_for(std::chrono::milliseconds(250));
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(800));
            sess.refresh_screen();   // redraw whatever the wake revealed
        }
    }

    // --wake-keys: wake a blanked Windows console. Deliberately restricted to
    // keys that cannot enter a character or activate anything: arrows and Esc.
    // A Windows lock screen treats any of them as "wake and show the login UI".
    if (wake_keys) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        std::printf("[*] --wake-keys: sending arrows + Esc (no characters)\n");
        const std::string keys[] = {
            Input::escape(),
            Input::arrow_right(), Input::arrow_left(),
            Input::arrow_down(),  Input::arrow_up(),
            Input::escape(),
        };
        for (const auto& k : keys) {
            sess.transmit(k);
            std::this_thread::sleep_for(std::chrono::milliseconds(350));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
        sess.refresh_screen();
    }

    auto t0 = std::chrono::steady_clock::now();
    int last_report = -1, snap = 0, last_refresh = -1;
    while (std::chrono::steady_clock::now() - t0 < std::chrono::seconds(seconds)) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        if (!sess.is_connected()) { std::printf("[!] disconnected early\n"); break; }
        int el = static_cast<int>(std::chrono::duration_cast<std::chrono::seconds>(
                     std::chrono::steady_clock::now() - t0).count());
        if (el != last_report) {
            last_report = el;
            std::printf("  t=%2ds  bytes=%zu  fb=%dx%d\n",
                        el, sess.raw.size(), sess.fb.fb_w, sess.fb.fb_h);
            std::fflush(stdout);
            if (el > 0 && el % 5 == 0 && sess.fb.fb_w > 0) {
                char p[512];
                std::snprintf(p, sizeof p, "%s_%02d.png", png_prefix.c_str(), ++snap);
                if (sess.fb.save_as_png(p)) std::printf("      -> %s\n", p);
            }
        }
        if (el > 0 && el % 8 == 0) sess.send_keep_alive_msg();
        // Periodic full redraws: the server only sends changed tiles, so a frame
        // captured mid-animation has gaps. A late refresh gives a settled frame.
        if (refresh_every > 0 && el > 0 && el != last_refresh && el % refresh_every == 0) {
            last_refresh = el;
            sess.refresh_screen();
        }
    }

    sess.disconnect();
    sess.join();

    if (FILE* f = std::fopen(out_bin.c_str(), "wb")) {
        std::fwrite(sess.raw.data(), 1, sess.raw.size(), f);
        std::fclose(f);
        std::printf("[+] wrote %s (%zu bytes)\n", out_bin.c_str(), sess.raw.size());
    } else {
        std::fprintf(stderr, "[!] cannot write %s\n", out_bin.c_str());
    }

    if (sess.fb.fb_w > 0) {
        std::string p = png_prefix + "_final.png";
        if (sess.fb.save_as_png(p))
            std::printf("[+] wrote %s (%dx%d)\n", p.c_str(), sess.fb.fb_w, sess.fb.fb_h);
    } else {
        std::printf("[!] no MODE2 dimensions seen -- no framebuffer to save\n");
    }
    return sess.raw.empty() ? 1 : 0;
}
