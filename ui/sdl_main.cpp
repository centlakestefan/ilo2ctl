// sdl_main.cpp — the standalone iLO 2 remote console.
//
// A thin front end over ui/console_core.hpp: the seam already delivers a
// framebuffer, the rectangles that changed, and an input sink, so this file is
// a rendering and event-mapping exercise and contains no protocol code at all.
//
// Two things here are consequences of the protocol rather than of SDL:
//
//   * The console image is one streaming texture, updated per dirty rectangle.
//     Because ConsoleCore drops redundant repaints, a static screen costs zero
//     texture uploads per frame rather than 3072 tile writes.
//   * Ctrl-Alt-Del is a toolbar button. Neither Windows nor Linux will hand a
//     real one to an application, which is exactly why HP's applet had the same
//     button (remcons.java:46).
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"
#include "ui/media_control.hpp"

#include <SDL3/SDL.h>
#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlrenderer3.h"

#include "ui/connections.hpp"
#include "ui/console_core.hpp"
#include "ui/power_control.hpp"

using namespace ilo2;

namespace {

// SDL hands the chosen file to a callback on its own thread, so the pick has
// to land somewhere stable that the frame loop can read next frame.
struct MediaPick {
    std::string path;
    std::string error;
    bool        open = false;   // a dialog is up; do not offer another
};

// Where in the image the firmware has been reading, drawn as a strip.
//
// Deliberately not a progress bar. The iLO seeks around the ISO in 2 KiB and
// 4 KiB reads, never touches most of it, and re-reads what it has already had,
// so a single percentage would be a fiction in both directions. The strip is
// the image end to end: dark where nothing has been asked for, bright where it
// is being read right now, fading over a couple of seconds to a mid tone for
// what was read earlier. That answers the two questions someone watching an
// install actually has -- is it still alive, and how far has it got -- and it
// answers the first one even when the second has barely moved.
void draw_read_map(const MediaServer::Stats& s) {
    if (s.map.empty() || s.size <= 0) return;

    const ImVec2 p = ImGui::GetCursorScreenPos();
    const float  w = ImGui::GetContentRegionAvail().x;
    const float  h = ImGui::GetTextLineHeight() * 1.25f;
    if (w < 16.0f || h < 2.0f) return;

    // Reserve the space first, so the strip is a real widget that can be
    // hovered rather than something painted over the layout.
    ImGui::InvisibleButton("##readmap", ImVec2(w, h));
    const bool hovered = ImGui::IsItemHovered();

    ImDrawList* dl = ImGui::GetWindowDrawList();
    dl->AddRectFilled(p, ImVec2(p.x + w, p.y + h), IM_COL32(26, 28, 36, 255));

    const float fade_ms = 2500.0f;      // bright -> mid, slow enough to notice
    const int   n       = static_cast<int>(s.map.size());
    const int   cols    = static_cast<int>(w);

    for (int x = 0; x < cols; ++x) {
        const int b0 = x * n / cols;
        int       b1 = (x + 1) * n / cols;
        if (b1 <= b0) b1 = b0 + 1;
        if (b1 > n)   b1 = n;
        // Several buckets can land on one column. Take the most recently read
        // rather than an average, so a single live read is never smeared into
        // invisibility by the cold buckets either side of it.
        uint32_t newest = 0;
        for (int b = b0; b < b1; ++b) {
            const uint32_t t = s.map[static_cast<size_t>(b)];
            if (t && (newest == 0 || static_cast<int32_t>(t - newest) > 0)) newest = t;
        }
        if (!newest) continue;
        const float age = static_cast<float>(static_cast<uint32_t>(s.now - newest));
        const float k   = age >= fade_ms ? 1.0f : age / fade_ms;
        const ImVec4 c(0.60f + (0.24f - 0.60f) * k,
                       0.84f + (0.38f - 0.84f) * k,
                       1.00f + (0.58f - 1.00f) * k,
                       1.0f);
        dl->AddRectFilled(ImVec2(p.x + x, p.y), ImVec2(p.x + x + 1.0f, p.y + h),
                          ImGui::ColorConvertFloat4ToU32(c));
    }
    dl->AddRect(p, ImVec2(p.x + w, p.y + h), IM_COL32(70, 74, 86, 255));

    // "Touched", not "read": a bucket is megabytes wide and lights up for a
    // single 4 KiB read inside it, so this is an upper bound on coverage.
    int covered = 0;
    for (int b = 0; b < n; ++b) if (s.map[static_cast<size_t>(b)]) ++covered;
    const double mib = s.size / (1024.0 * 1024.0);
    ImGui::TextDisabled("%.0f%% of the image touched  (%.0f MiB)",
                        covered * 100.0 / n, mib);

    if (hovered) {
        float f = (ImGui::GetIO().MousePos.x - p.x) / w;
        f = f < 0.0f ? 0.0f : (f > 1.0f ? 1.0f : f);
        ImGui::SetTooltip("%.0f MiB into the image", mib * f);
    }
}

struct Options {
    std::string host;
    std::string user = "Administrator";
    std::string pass;
    std::string replay;
    int         refresh_every = 0;
    bool        autoconnect = false;
    // Render N frames, save what the window actually shows, and exit. Lets the
    // front end be verified without a human watching a window -- and with the
    // dummy video driver, without a window existing at all.
    std::string screenshot;
    int         frames_before_shot = 150;
    // Send arrow keys and Escape once, shortly after connecting, to wake a
    // blanked console. Deliberately only keys that move nothing and commit
    // nothing: mouse motion does not wake a blanked Windows login screen, and
    // anything that types a character would be a change to the server rather
    // than a nudge.
    bool        wake = false;
    // Which panel tab to start on: console | power | health | media. Mostly
    // for screenshots of the others.
    std::string tab = "console";
};

// Where the console image lands inside an area, preserving aspect ratio and
// centred. Everything is in window units: the area comes from ImGui's content
// region and the result is handed back to ImGui and compared against SDL
// mouse coordinates, which use the same units.
SDL_FRect letterbox(int fb_w, int fb_h, const SDL_FRect& area) {
    if (fb_w <= 0 || fb_h <= 0 || area.w <= 0 || area.h <= 0) return SDL_FRect{ 0, 0, 0, 0 };
    const float s = std::min(area.w / float(fb_w), area.h / float(fb_h));
    const float w = float(fb_w) * s;
    const float h = float(fb_h) * s;
    return SDL_FRect{ area.x + (area.w - w) * 0.5f, area.y + (area.h - h) * 0.5f, w, h };
}

// Window coordinates -> console pixel coordinates. Returns false when the
// pointer is outside the image, so edge drags do not send bogus positions.
bool to_console(const SDL_FRect& dst, int fb_w, int fb_h, float wx, float wy,
                int& cx, int& cy) {
    if (dst.w <= 0 || dst.h <= 0) return false;
    if (wx < dst.x || wy < dst.y || wx >= dst.x + dst.w || wy >= dst.y + dst.h)
        return false;
    cx = int((wx - dst.x) / dst.w * float(fb_w));
    cy = int((wy - dst.y) / dst.h * float(fb_h));
    cx = std::max(0, std::min(fb_w - 1, cx));
    cy = std::max(0, std::min(fb_h - 1, cy));
    return true;
}

int sdl_button_to_ilo(Uint8 sdl_button) {
    switch (sdl_button) {
        case SDL_BUTTON_LEFT:   return Input::BTN_LEFT;
        case SDL_BUTTON_RIGHT:  return Input::BTN_RIGHT;
        case SDL_BUTTON_MIDDLE: return Input::BTN_CENTER;
        default:                return 0;
    }
}

// Keys that do not arrive as text. Everything printable comes through
// SDL_EVENT_TEXT_INPUT instead, which is what makes non-US layouts work at all
// for the characters the firmware does accept.
bool special_key_bytes(SDL_Keycode key, std::string& out) {
    switch (key) {
        case SDLK_RETURN:
        case SDLK_KP_ENTER:  out = Input::enter();       return true;
        case SDLK_BACKSPACE: out = Input::backspace();   return true;
        case SDLK_TAB:       out = Input::tab();         return true;
        case SDLK_ESCAPE:    out = Input::escape();      return true;
        case SDLK_UP:        out = Input::arrow_up();    return true;
        case SDLK_DOWN:      out = Input::arrow_down();  return true;
        case SDLK_LEFT:      out = Input::arrow_left();  return true;
        case SDLK_RIGHT:     out = Input::arrow_right(); return true;
        default: return false;
    }
}

void parse_args(int argc, char** argv, Options& o) {
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host")   { o.host = next(); o.autoconnect = true; }
        else if (a == "--user")     o.user = next();
        else if (a == "--pass")     o.pass = next();
        else if (a == "--replay") { o.replay = next(); o.autoconnect = true; }
        else if (a == "--refresh-every") o.refresh_every = std::atoi(next().c_str());
        else if (a == "--screenshot")    o.screenshot = next();
        else if (a == "--frames")        o.frames_before_shot = std::atoi(next().c_str());
        else if (a == "--wake")          o.wake = true;
        else if (a == "--tab")           o.tab = next();
    }
}

// Save whatever the renderer currently holds, so a screenshot shows the real
// composited result -- console texture, scaling and ImGui overlay together --
// rather than the framebuffer we happen to have in memory.
bool save_render_target(SDL_Renderer* renderer, const std::string& path) {
    SDL_Surface* shot = SDL_RenderReadPixels(renderer, nullptr);
    if (!shot) {
        std::fprintf(stderr, "SDL_RenderReadPixels: %s\n", SDL_GetError());
        return false;
    }
    SDL_Surface* conv = SDL_ConvertSurface(shot, SDL_PIXELFORMAT_XRGB8888);
    SDL_DestroySurface(shot);
    if (!conv) {
        std::fprintf(stderr, "SDL_ConvertSurface: %s\n", SDL_GetError());
        return false;
    }
    std::vector<uint32_t> px(size_t(conv->w) * conv->h);
    for (int y = 0; y < conv->h; ++y) {
        std::memcpy(px.data() + size_t(y) * conv->w,
                    static_cast<const uint8_t*>(conv->pixels) + size_t(y) * conv->pitch,
                    size_t(conv->w) * sizeof(uint32_t));
    }
    const bool ok = save_argb_png(path, px.data(), conv->w, conv->h);
    std::fprintf(stderr, "%s %s (%dx%d)\n", ok ? "wrote" : "FAILED to write",
                 path.c_str(), conv->w, conv->h);
    SDL_DestroySurface(conv);
    return ok;
}

} // namespace

int main(int argc, char** argv) {
    Options opt;
    parse_args(argc, argv, opt);

    if (!SDL_Init(SDL_INIT_VIDEO)) {
        std::fprintf(stderr, "SDL_Init: %s\n", SDL_GetError());
        return 1;
    }

    SDL_Window* window = SDL_CreateWindow("ilo2ctl", 1360, 830,
                                          SDL_WINDOW_RESIZABLE | SDL_WINDOW_HIGH_PIXEL_DENSITY);
    if (!window) {
        std::fprintf(stderr, "SDL_CreateWindow: %s\n", SDL_GetError());
        SDL_Quit();
        return 1;
    }
    SDL_Renderer* renderer = SDL_CreateRenderer(window, nullptr);
    if (!renderer) {
        std::fprintf(stderr, "SDL_CreateRenderer: %s\n", SDL_GetError());
        SDL_DestroyWindow(window);
        SDL_Quit();
        return 1;
    }
    SDL_SetRenderVSync(renderer, 1);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGui::GetIO().IniFilename = nullptr;          // no imgui.ini beside the binary
    ImGui::StyleColorsDark();
    ImGui_ImplSDL3_InitForSDLRenderer(window, renderer);
    ImGui_ImplSDLRenderer3_Init(renderer);

    ConsoleCore core;
    std::vector<uint32_t> fb;
    std::vector<Rect>     dirty;
    int fb_w = 0, fb_h = 0;
    SDL_Texture* tex = nullptr;
    int tex_w = 0, tex_h = 0;

    char host_buf[128] = { 0 };
    char user_buf[64]  = { 0 };
    char pass_buf[128] = { 0 };
    std::snprintf(host_buf, sizeof(host_buf), "%s", opt.host.c_str());
    std::snprintf(user_buf, sizeof(user_buf), "%s", opt.user.c_str());

    std::string ui_error;
    bool send_input = true;
    unsigned long long uploads = 0, frames = 0;
    int rendered = 0;
    int connected_frames = 0;
    bool wake_sent = false;
    // Where the console image was drawn last frame, whether the pointer was
    // over it, and whether the Console tab was showing -- the event loop
    // needs all three and runs before this frame's layout exists.
    SDL_FRect image_rect{ 0, 0, 0, 0 };
    bool image_hovered = false;
    bool console_tab_active = true;

    // Recent connections: host and user only, never the password. Stored in
    // the per-user preferences directory SDL picks for this platform.
    std::string connections_path, legacy_connections_path;
    if (char* pref = SDL_GetPrefPath("centlake", "ilo2ctl")) {
        connections_path = std::string(pref) + "connections.txt";
        SDL_free(pref);
    }
    // The app was called ilo2_console until it grew power, health and media
    // control. SDL derives the preferences directory from that name, so the
    // rename moved it. Read the old location once when the new one is empty;
    // the next recorded connection writes the list back to the new path.
    if (char* pref = SDL_GetPrefPath("centlake", "ilo2_console")) {
        legacy_connections_path = std::string(pref) + "connections.txt";
        SDL_free(pref);
    }
    std::vector<SavedConnection> recent = load_connections(connections_path);
    if (recent.empty() && !legacy_connections_path.empty())
        recent = load_connections(legacy_connections_path);
    bool connection_recorded = false;
    // With no host on the command line, start from the most recent one so the
    // usual session is: type the password, press Enter.
    if (opt.host.empty() && !recent.empty()) {
        std::snprintf(host_buf, sizeof(host_buf), "%s", recent[0].host.c_str());
        if (!recent[0].user.empty())
            std::snprintf(user_buf, sizeof(user_buf), "%s", recent[0].user.c_str());
    }

    // Server power control over RIBCL, on its own worker; started alongside
    // the console with the same credentials.
    PowerControl power;
    // Virtual media rides on its own worker for the same reason, and owns the
    // HTTP server that the iLO fetches the image from.
    MediaControl media;
    MediaPick    media_pick;            // chosen in the picker, mounted on demand
    bool         boot_armed_click = false;   // the Boot button is two-click, like power
    Uint64       boot_armed_at = 0;
    // Destructive power commands take two clicks: the first arms, the second
    // confirms, and the arm expires on its own.
    bool         armed = false;
    RibclCommand armed_cmd = RibclCommand::GetPowerStatus;
    Uint64       armed_at = 0;
    constexpr Uint64 ARM_TIMEOUT_MS = 6000;

    auto do_connect = [&] {
        ui_error.clear();
        connection_recorded = false;
        std::string err;
        if (!opt.replay.empty()) {
            if (!core.start_replay(opt.replay, 200000, err)) ui_error = err;
            return;
        }
        ConsoleCore::Config cfg;
        cfg.host = host_buf;
        cfg.user = user_buf;
        cfg.pass = pass_buf[0] ? std::string(pass_buf) : read_ilo_password(opt.pass);
        cfg.refresh_every_sec = opt.refresh_every;
        if (cfg.host.empty()) { ui_error = "no host"; return; }
        if (cfg.pass.empty()) { ui_error = "no password (field, --pass, ILO_PASS or .ilo_pass)"; return; }
        if (!core.start(cfg, err)) { ui_error = err; return; }

        PowerControl::Config pc;
        pc.host = cfg.host;
        pc.user = cfg.user;
        pc.pass = cfg.pass;
        power.start(pc);

        MediaControl::Config mc;
        mc.host = cfg.host;
        mc.user = cfg.user;
        mc.pass = cfg.pass;
        media.start(mc);
    };
    auto do_disconnect = [&] {
        core.stop();
        power.stop();
        // Ejects and stops serving before returning: an iLO left pointed at a
        // URL that has stopped answering is worse than never having mounted.
        media.stop();
        armed = false;
        boot_armed_click = false;
    };

    if (opt.autoconnect) do_connect();

    bool quit = false;
    while (!quit) {
        SDL_Event ev;
        while (SDL_PollEvent(&ev)) {
            ImGui_ImplSDL3_ProcessEvent(&ev);
            const ImGuiIO& io = ImGui::GetIO();

            if (ev.type == SDL_EVENT_QUIT) quit = true;
            if (ev.type == SDL_EVENT_WINDOW_CLOSE_REQUESTED &&
                ev.window.windowID == SDL_GetWindowID(window)) quit = true;

            if (!send_input || core.state() != ConsoleState::Connected) continue;

            // The console image is an ImGui item now, so ImGui's own capture
            // flags cannot gate forwarding: the whole window is ImGui, and the
            // image itself "captures" the mouse. Instead: mouse goes to the
            // server while the pointer is over the image (as ImGui reported it
            // last frame), keys go to the server unless a text field has focus.
            const SDL_FRect dst = image_rect;

            switch (ev.type) {
                case SDL_EVENT_MOUSE_MOTION: {
                    if (!image_hovered) break;
                    int cx = 0, cy = 0;
                    if (to_console(dst, fb_w, fb_h, ev.motion.x, ev.motion.y, cx, cy))
                        core.mouse_move(cx, cy);
                    break;
                }
                case SDL_EVENT_MOUSE_BUTTON_DOWN:
                case SDL_EVENT_MOUSE_BUTTON_UP: {
                    if (!image_hovered) break;
                    const int b = sdl_button_to_ilo(ev.button.button);
                    if (!b) break;
                    int cx = 0, cy = 0;
                    if (to_console(dst, fb_w, fb_h, ev.button.x, ev.button.y, cx, cy)) {
                        core.mouse_move(cx, cy);      // position first, then the click
                        core.mouse_button(b, ev.type == SDL_EVENT_MOUSE_BUTTON_DOWN);
                    }
                    break;
                }
                case SDL_EVENT_TEXT_INPUT: {
                    if (io.WantTextInput || !console_tab_active) break;
                    for (const char* p = ev.text.text; *p; ++p) core.type_char(*p);
                    break;
                }
                case SDL_EVENT_KEY_DOWN: {
                    if (io.WantTextInput || !console_tab_active) break;
                    std::string bytes;
                    if (special_key_bytes(ev.key.key, bytes)) core.send_raw(bytes);
                    break;
                }
                default: break;
            }
        }

        // A blanked console shows nothing until something wakes it. This goes
        // through exactly the same queue the toolbar and keyboard use, so it
        // exercises the outbound path rather than bypassing it.
        if (opt.wake && !wake_sent && core.state() == ConsoleState::Connected) {
            if (++connected_frames > 120) {          // ~2s after DVC mode starts
                core.send_raw(Input::arrow_right());
                core.send_raw(Input::arrow_left());
                core.send_raw(Input::escape());
                core.request_refresh();
                wake_sent = true;
            }
        }

        // --- pull the console image -------------------------------------
        if (core.pull(fb, fb_w, fb_h, dirty)) {
            ++frames;
            if (!tex || tex_w != fb_w || tex_h != fb_h) {
                if (tex) SDL_DestroyTexture(tex);
                tex = SDL_CreateTexture(renderer, SDL_PIXELFORMAT_XRGB8888,
                                        SDL_TEXTUREACCESS_STREAMING, fb_w, fb_h);
                SDL_SetTextureScaleMode(tex, SDL_SCALEMODE_NEAREST);
                tex_w = fb_w;
                tex_h = fb_h;
            }
            // One upload per changed rectangle. ConsoleCore has already merged
            // adjacent tiles and dropped identical repaints, so this loop is
            // usually empty and never runs 3072 times.
            for (const Rect& r : dirty) {
                const SDL_Rect sr{ r.x, r.y, r.w, r.h };
                SDL_UpdateTexture(tex, &sr, fb.data() + size_t(r.y) * fb_w + r.x,
                                  int(fb_w * sizeof(uint32_t)));
                ++uploads;
            }
        }

        // --- draw ---------------------------------------------------------
        ImGui_ImplSDLRenderer3_NewFrame();
        ImGui_ImplSDL3_NewFrame();
        ImGui::NewFrame();

        const bool connected = (core.state() == ConsoleState::Connected);

        // Two ImGui windows: a fixed side column on the left (connection,
        // recent servers, session controls, status), and a background-less
        // window over the rest holding the Console / Power / Health tabs.
        // The console texture is drawn by SDL underneath the right window.
        constexpr float kSideWidth = 300.0f;

        // Once the console is up, the credentials are known to be good: record
        // host and user (never the password) for next time.
        if (connected && !connection_recorded && opt.replay.empty()) {
            remember_connection(recent, host_buf, user_buf);
            if (!connections_path.empty()) save_connections(connections_path, recent);
            connection_recorded = true;
        }

        const ImVec4 ok_col  (0.6f, 0.9f, 0.6f, 1.0f);
        const ImVec4 warn_col(1.0f, 0.8f, 0.3f, 1.0f);
        const ImVec4 bad_col (1.0f, 0.4f, 0.4f, 1.0f);

        // --- left column ------------------------------------------------------
        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(kSideWidth, ImGui::GetIO().DisplaySize.y));
        ImGui::Begin("##side", nullptr,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse |
                     ImGuiWindowFlags_NoBringToFrontOnFocus);
        {
            const bool idle = core.state() == ConsoleState::Idle ||
                              core.state() == ConsoleState::Failed ||
                              core.state() == ConsoleState::Stopped;
            if (idle) {
                // Enter in any field connects, as in every login dialog.
                const ImGuiInputTextFlags enter = ImGuiInputTextFlags_EnterReturnsTrue;
                bool go = false;
                go |= ImGui::InputText("host", host_buf, sizeof(host_buf), enter);
                go |= ImGui::InputText("user", user_buf, sizeof(user_buf), enter);
                go |= ImGui::InputText("password", pass_buf, sizeof(pass_buf),
                                       enter | ImGuiInputTextFlags_Password);
                go |= ImGui::Button("Connect");
                if (go) do_connect();

                if (!recent.empty()) {
                    ImGui::Spacing();
                    ImGui::TextDisabled("recent");
                    size_t forget = recent.size();
                    for (size_t i = 0; i < recent.size(); ++i) {
                        const std::string label = recent[i].user.empty()
                            ? recent[i].host
                            : recent[i].user + "@" + recent[i].host;
                        ImGui::PushID(int(i));
                        // Click fills the fields; double-click connects; the
                        // small button on the right forgets the entry.
                        if (ImGui::Selectable(label.c_str(), false,
                                              ImGuiSelectableFlags_AllowDoubleClick,
                                              ImVec2(ImGui::GetContentRegionAvail().x - 24, 0))) {
                            std::snprintf(host_buf, sizeof(host_buf), "%s", recent[i].host.c_str());
                            std::snprintf(user_buf, sizeof(user_buf), "%s", recent[i].user.c_str());
                            if (ImGui::IsMouseDoubleClicked(ImGuiMouseButton_Left)) do_connect();
                        }
                        ImGui::SameLine();
                        if (ImGui::SmallButton("x")) forget = i;
                        ImGui::PopID();
                    }
                    if (forget < recent.size()) {
                        forget_connection(recent, forget);
                        if (!connections_path.empty()) save_connections(connections_path, recent);
                    }
                }
            } else {
                if (ImGui::Button("Disconnect")) do_disconnect();
                ImGui::SameLine();
                if (ImGui::Button("Refresh")) core.request_refresh();
                ImGui::SameLine();
                // The real key combination never reaches an application on
                // either platform, so it has to be a button.
                if (ImGui::Button("Ctrl-Alt-Del")) core.send_ctrl_alt_del();
                ImGui::Checkbox("forward keyboard and mouse", &send_input);
            }

            // Errors belong next to the controls that caused them.
            if (!ui_error.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, bad_col);
                ImGui::TextWrapped("%s", ui_error.c_str());
                ImGui::PopStyleColor();
            }
            const std::string core_err = core.error();
            if (!core_err.empty()) {
                ImGui::PushStyleColor(ImGuiCol_Text, bad_col);
                ImGui::TextWrapped("%s", core_err.c_str());
                ImGui::PopStyleColor();
            }

            // Status, pinned to the bottom of the column. Its height is
            // measured as it is drawn and used to place it next frame.
            static float status_height = 0.0f;
            {
                const float bottom = ImGui::GetWindowHeight() - ImGui::GetStyle().WindowPadding.y;
                const float y = bottom - status_height;
                if (y > ImGui::GetCursorPosY()) ImGui::SetCursorPosY(y);
                const float start = ImGui::GetCursorPosY();

                ImGui::PushTextWrapPos(0.0f);
                ImGui::Separator();
                ImGui::Text("state   : %s", console_state_name(core.state()));
                const std::string status = core.status();
                if (!status.empty()) ImGui::Text("status  : %s", status.c_str());
                if (fb_w) ImGui::Text("screen  : %dx%d", fb_w, fb_h);
                const unsigned long long p = core.pastes(), c = core.changed_pastes();
                if (p) {
                    ImGui::Text("tiles   : %llu received, %llu changed (%.1f%% redundant)",
                                p, c, 100.0 * double(p - c) / double(p));
                }
                ImGui::Text("uploads : %llu over %llu changed frames", uploads, frames);
                ImGui::Text("%.1f FPS", double(ImGui::GetIO().Framerate));
                ImGui::PopTextWrapPos();

                status_height = ImGui::GetCursorPosY() - start;
            }
        }
        ImGui::End();

        // --- right side: the tabs ---------------------------------------------
        ImGui::SetNextWindowPos(ImVec2(kSideWidth, 0));
        ImGui::SetNextWindowSize(ImVec2(ImGui::GetIO().DisplaySize.x - kSideWidth,
                                        ImGui::GetIO().DisplaySize.y));
        ImGui::Begin("##tabs", nullptr,
                     ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoMove |
                     ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoCollapse |
                     ImGuiWindowFlags_NoBringToFrontOnFocus |
                     ImGuiWindowFlags_NoBackground);   // the console texture shows through

        image_hovered = false;
        console_tab_active = false;
        if (ImGui::BeginTabBar("panel")) {
            // --tab picks the initial tab; only the first frame asks for it,
            // after which the user's clicks own the selection.
            static bool first_frame = true;
            auto tab_flags = [&](const char* name) {
                return (first_frame && opt.tab == name) ? ImGuiTabItemFlags_SetSelected
                                                        : ImGuiTabItemFlags_None;
            };

            // --- Console: the image, nothing else --------------------------
            if (ImGui::BeginTabItem("Console", nullptr, tab_flags("console"))) {
                // ImGui only lays out and hit-tests a placeholder; the texture
                // itself is drawn by SDL_RenderTexture underneath this
                // background-less window, because the SDL_Renderer backend's
                // geometry path does not draw a streaming texture on every
                // renderer (the software one, for a start) while
                // SDL_RenderTexture does. Same units as SDL's mouse events.
                console_tab_active = true;
                if (tex) {
                    const ImVec2 pos   = ImGui::GetCursorScreenPos();
                    const ImVec2 avail = ImGui::GetContentRegionAvail();
                    const SDL_FRect area{ pos.x, pos.y, avail.x, avail.y };
                    image_rect = letterbox(fb_w, fb_h, area);
                    if (image_rect.w > 0) {
                        ImGui::SetCursorScreenPos(ImVec2(image_rect.x, image_rect.y));
                        ImGui::Dummy(ImVec2(image_rect.w, image_rect.h));
                        image_hovered = ImGui::IsItemHovered();
                    }
                } else {
                    image_rect = SDL_FRect{ 0, 0, 0, 0 };
                    ImGui::TextDisabled(connected ? "waiting for video..." : "not connected");
                }
                ImGui::EndTabItem();
            }

            // --- Power -----------------------------------------------------
            const PowerControl::Snapshot ps = power.running() ? power.snapshot()
                                                              : PowerControl::Snapshot();
            if (ImGui::BeginTabItem("Power", nullptr, tab_flags("power"))) {
                if (!power.running()) {
                    ImGui::TextDisabled("connect to a server first");
                } else {
                    if (ps.host_power.empty()) ImGui::Text("power : %s", ps.busy ? "reading..." : "unknown");
                    else                       ImGui::Text("power : %s%s", ps.host_power.c_str(), ps.busy ? "  (busy)" : "");
                    if (ps.watts.valid) {
                        ImGui::SameLine();
                        ImGui::TextDisabled("%d W", ps.watts.present);
                    }
                    ImGui::Spacing();

                    if (armed && SDL_GetTicks() - armed_at > ARM_TIMEOUT_MS) armed = false;

                    // The destructive commands arm on the first click and act
                    // on the second, so a stray click on the panel can never
                    // reset the server.
                    auto arm_button = [&](const char* label, RibclCommand cmd) {
                        if (armed && armed_cmd == cmd) {
                            ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
                            ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
                            const std::string confirm = std::string("Confirm ") + label;
                            if (ImGui::Button(confirm.c_str())) { power.request(cmd); armed = false; }
                            ImGui::PopStyleColor(2);
                        } else if (ImGui::Button(label)) {
                            armed = true;
                            armed_cmd = cmd;
                            armed_at = SDL_GetTicks();
                        }
                    };
                    ImGui::BeginDisabled(ps.busy);
                    if (ps.host_power != "ON") {
                        if (ImGui::Button("Power on")) power.request(RibclCommand::PowerOn);
                    } else {
                        arm_button("Shut down", RibclCommand::PowerOff);
                        ImGui::SameLine();
                        arm_button("Force off", RibclCommand::ForcePowerOff);
                    }
                    arm_button("Reset", RibclCommand::Reset);
                    ImGui::SameLine();
                    arm_button("Cold boot", RibclCommand::ColdBoot);
                    ImGui::EndDisabled();
                    if (armed) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("cancel")) armed = false;
                    }
                    ImGui::Spacing();
                    ImGui::TextDisabled("UID light");
                    ImGui::SameLine();
                    if (ImGui::Button("on"))  power.request(RibclCommand::UidOn);
                    ImGui::SameLine();
                    if (ImGui::Button("off")) power.request(RibclCommand::UidOff);

                    if (!ps.last_action.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ps.error ? bad_col : ok_col);
                        ImGui::TextWrapped("%s: %s", ps.last_action.c_str(), ps.last_result.c_str());
                        ImGui::PopStyleColor();
                    } else if (ps.error) {
                        ImGui::PushStyleColor(ImGuiCol_Text, bad_col);
                        ImGui::TextWrapped("%s", ps.last_result.c_str());
                        ImGui::PopStyleColor();
                    }
                }
                ImGui::EndTabItem();
            }

            // --- Health ----------------------------------------------------
            if (ImGui::BeginTabItem("Health", nullptr, tab_flags("health"))) {
                auto status_col = [&](const std::string& s) -> ImVec4 {
                    if (s.empty() || s == "Ok" || s == "n/a" || s == "Not Installed")
                        return ImGui::GetStyle().Colors[ImGuiCol_Text];
                    return bad_col;
                };
                if (!power.running()) {
                    ImGui::TextDisabled("connect to a server first");
                } else if (!ps.watts.valid && !ps.health.valid) {
                    ImGui::TextDisabled("reading...");
                }
                if (ps.watts.valid) {
                    ImGui::Text("power : %d W", ps.watts.present);
                    ImGui::SameLine();
                    ImGui::TextDisabled("(avg %d, max %d)", ps.watts.average, ps.watts.maximum);
                }
                if (ps.health.valid) {
                    const HealthData& h = ps.health;
                    const HealthGlance& g = h.glance;
                    ImGui::Text("health: ");
                    ImGui::SameLine();
                    if (health_all_ok(g)) {
                        ImGui::TextColored(ok_col, "all Ok");
                    } else {
                        // Name the subsystems that are not, since that is the
                        // only time anyone reads this line.
                        ImGui::PushStyleColor(ImGuiCol_Text, bad_col);
                        ImGui::TextWrapped("fans %s, temps %s, vrm %s, psu %s, drives %s",
                                           g.fans.c_str(), g.temperature.c_str(), g.vrm.c_str(),
                                           g.supplies.c_str(), g.drives.c_str());
                        ImGui::PopStyleColor();
                    }
                    if (!g.fan_redundancy.empty() || !g.supply_redundancy.empty()) {
                        ImGui::PushStyleColor(ImGuiCol_Text, ImGui::GetStyle().Colors[ImGuiCol_TextDisabled]);
                        ImGui::TextWrapped("fans: %s, psu: %s",
                                           g.fan_redundancy.c_str(), g.supply_redundancy.c_str());
                        ImGui::PopStyleColor();
                    }

                    const ImGuiTableFlags tf = ImGuiTableFlags_SizingFixedFit |
                                               ImGuiTableFlags_RowBg | ImGuiTableFlags_NoClip;
                    const HealthTemp* hot = hottest(h);
                    char hdr[96];
                    if (hot) std::snprintf(hdr, sizeof(hdr), "Temperatures  (max %d C)###temps", hot->reading);
                    else     std::snprintf(hdr, sizeof(hdr), "Temperatures###temps");
                    if (ImGui::CollapsingHeader(hdr, ImGuiTreeNodeFlags_DefaultOpen)) {
                        if (ImGui::BeginTable("temps", 3, tf)) {
                            for (const auto& t : h.temps) {
                                if (t.reading < 0) continue;      // not fitted
                                ImVec4 col = ImGui::GetStyle().Colors[ImGuiCol_Text];
                                if (t.critical >= 0 && t.reading >= t.critical)     col = bad_col;
                                else if (t.caution >= 0 && t.reading >= t.caution)  col = warn_col;
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn(); ImGui::TextUnformatted(t.location.c_str());
                                ImGui::TableNextColumn(); ImGui::TextColored(col, "%3d C", t.reading);
                                ImGui::TableNextColumn(); ImGui::TextDisabled("caution %d", t.caution);
                            }
                            ImGui::EndTable();
                        }
                    }
                    if (ImGui::CollapsingHeader("Fans###fans", ImGuiTreeNodeFlags_DefaultOpen)) {
                        if (ImGui::BeginTable("fans", 3, tf)) {
                            for (const auto& f : h.fans) {
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn(); ImGui::TextUnformatted(f.label.c_str());
                                ImGui::TableNextColumn(); ImGui::Text("%3d%%", f.speed_pct);
                                ImGui::TableNextColumn(); ImGui::TextColored(status_col(f.status), "%s", f.status.c_str());
                            }
                            ImGui::EndTable();
                        }
                    }
                    if (ImGui::CollapsingHeader("Power supplies###psu", ImGuiTreeNodeFlags_DefaultOpen)) {
                        for (const auto& s : h.supplies) {
                            ImGui::TextUnformatted(s.label.c_str());
                            ImGui::SameLine();
                            ImGui::TextColored(status_col(s.status), "%s", s.status.c_str());
                        }
                    }
                    if (ImGui::CollapsingHeader("Drives###drives", ImGuiTreeNodeFlags_DefaultOpen)) {
                        if (ImGui::BeginTable("drives", 3, tf)) {
                            for (const auto& d : h.drives) {
                                ImGui::TableNextRow();
                                ImGui::TableNextColumn(); ImGui::Text("bay %d", d.bay);
                                ImGui::TableNextColumn(); ImGui::TextColored(status_col(d.status), "%s", d.status.c_str());
                                ImGui::TableNextColumn(); ImGui::TextDisabled("%s", d.product.c_str());
                            }
                            ImGui::EndTable();
                        }
                    }
                }
                ImGui::EndTabItem();
            }
            if (ImGui::BeginTabItem("Media", nullptr, tab_flags("media"))) {
                const MediaControl::Snapshot ms = media.running()
                    ? media.snapshot() : MediaControl::Snapshot();

                if (!media.running()) {
                    ImGui::TextDisabled("connect to a server first");
                } else if (ms.fw.valid && !vm_scripting_licensed(ms.fw)) {
                    // Say so once, plainly, instead of letting every mount fail
                    // inside the firmware with something less legible.
                    ImGui::TextColored(bad_col, "this iLO cannot script virtual media");
                    ImGui::TextDisabled("licence: %s (needs iLO 2 Advanced)",
                                        ms.fw.license_type.c_str());
                } else {
                    // ---- the image -------------------------------------------
                    ImGui::TextDisabled("image");
                    ImGui::SameLine(90);
                    if (media_pick.path.empty()) ImGui::TextDisabled("(none chosen)");
                    else                  ImGui::TextUnformatted(media_pick.path.c_str());

                    ImGui::BeginDisabled(media_pick.open || ms.busy);
                    if (ImGui::Button("Choose ISO...")) {
                        media_pick.error.clear();
                        media_pick.open = true;
                        static const SDL_DialogFileFilter filters[] = {
                            { "Disc images", "iso;img" },
                            { "All files",   "*" },
                        };
                        // The callback arrives on SDL's thread, so it only
                        // stores; the frame loop reads it next frame.
                        SDL_ShowOpenFileDialog(
                            [](void* ud, const char* const* list, int) {
                                auto* self = static_cast<MediaPick*>(ud);
                                if (!list)        { self->error = SDL_GetError(); }
                                else if (!*list)  { /* cancelled: leave as-is */ }
                                else              { self->path = *list; }
                                self->open = false;
                            },
                            &media_pick, window, filters, 2, nullptr, false);
                    }
                    ImGui::EndDisabled();

                    if (!media_pick.error.empty()) {
                        ImGui::SameLine();
                        ImGui::TextColored(bad_col, "%s", media_pick.error.c_str());
                    }

                    ImGui::Spacing();

                    // ---- mount / eject ---------------------------------------
                    const bool inserted = ms.vm.image_inserted;
                    ImGui::BeginDisabled(ms.busy || media_pick.path.empty() || inserted);
                    if (ImGui::Button("Mount")) media.mount(media_pick.path);
                    ImGui::EndDisabled();
                    ImGui::SameLine();
                    ImGui::BeginDisabled(ms.busy || !inserted);
                    if (ImGui::Button("Eject")) media.eject();
                    ImGui::EndDisabled();
                    ImGui::SameLine();
                    ImGui::BeginDisabled(ms.busy);
                    if (ImGui::Button("Refresh")) media.refresh();
                    ImGui::EndDisabled();

                    // ---- arming a boot ---------------------------------------
                    // Two clicks, like the destructive power buttons: this
                    // changes what the next reboot does.
                    if (boot_armed_click && SDL_GetTicks() - boot_armed_at > ARM_TIMEOUT_MS)
                        boot_armed_click = false;
                    ImGui::Spacing();
                    ImGui::BeginDisabled(ms.busy || !inserted);
                    if (boot_armed_click) {
                        ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0.8f, 0.2f, 0.2f, 1.0f));
                        ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(0.9f, 0.3f, 0.3f, 1.0f));
                        if (ImGui::Button("Confirm: boot from this image once")) {
                            media.arm_boot();
                            boot_armed_click = false;
                        }
                        ImGui::PopStyleColor(2);
                    } else if (ImGui::Button("Boot from image once")) {
                        boot_armed_click = true;
                        boot_armed_at = SDL_GetTicks();
                    }
                    ImGui::EndDisabled();
                    if (boot_armed_click) {
                        ImGui::SameLine();
                        if (ImGui::SmallButton("cancel")) boot_armed_click = false;
                    }
                    ImGui::TextDisabled("arming only sets the next boot; it does not reboot");
                    if (ms.boot_armed)
                        ImGui::TextColored(ImVec4(0.9f, 0.7f, 0.2f, 1.0f),
                                           "armed: the next reboot will use this image");

                    // ---- state ------------------------------------------------
                    ImGui::Spacing();
                    ImGui::Separator();
                    ImGui::Spacing();
                    if (!ms.vm.valid) {
                        ImGui::TextDisabled("reading...");
                    } else {
                        ImGui::Text("inserted    : %s", inserted ? "yes" : "no");
                        ImGui::Text("boot option : %s", ms.vm.boot_option.c_str());
                        ImGui::Text("applet      : %s", ms.vm.vm_applet.c_str());
                        if (!ms.url.empty()) {
                            ImGui::Text("serving at  : %s", ms.url.c_str());
                            // The count is the honest answer to "is this
                            // working?": inserting alone never fetches, so a
                            // mounted image with zero requests is expected
                            // until something actually boots.
                            ImGui::Text("requests    : %llu  (%.1f MiB)",
                                        (unsigned long long)ms.server.requests,
                                        ms.server.bytes / (1024.0 * 1024.0));
                            ImGui::Spacing();
                            draw_read_map(ms.server);
                            if (ms.server.requests == 0)
                                ImGui::TextDisabled("the iLO does not read the image until it boots from it");
                        }
                    }
                    if (ms.busy) { ImGui::Spacing(); ImGui::TextDisabled("working..."); }
                    if (!ms.last_result.empty()) {
                        ImGui::Spacing();
                        ImGui::TextColored(ms.error ? bad_col : ImGui::GetStyle().Colors[ImGuiCol_Text],
                                           "%s: %s", ms.last_action.c_str(), ms.last_result.c_str());
                    }
                }
                ImGui::EndTabItem();
            }
            ImGui::EndTabBar();
            first_frame = false;
        }
        ImGui::End();

        ImGui::Render();

        // SDL3 delivers SDL_EVENT_TEXT_INPUT only while text input is enabled,
        // and it is off by default (SDL2 had it on). The ImGui backend turns it
        // on for its own text fields and off again when they lose focus, so a
        // single SDL_StartTextInput() at startup would stop working the first
        // time the connect dialog was used. Re-arm it every frame the console
        // owns the keyboard instead; when ImGui wants it, it manages it itself.
        if (!ImGui::GetIO().WantTextInput && !SDL_TextInputActive(window))
            SDL_StartTextInput(window);

        // Clear, console texture (where the Console tab laid it out, scaled
        // from window units to render pixels), then ImGui on top.
        SDL_SetRenderDrawColor(renderer, 16, 16, 20, 255);
        SDL_RenderClear(renderer);
        if (tex && console_tab_active && image_rect.w > 0) {
            const float d = SDL_GetWindowPixelDensity(window);
            const SDL_FRect dst{ image_rect.x * d, image_rect.y * d, image_rect.w * d, image_rect.h * d };
            SDL_RenderTexture(renderer, tex, nullptr, &dst);
        }
        ImGui_ImplSDLRenderer3_RenderDrawData(ImGui::GetDrawData(), renderer);

        if (!opt.screenshot.empty() && ++rendered >= opt.frames_before_shot) {
            save_render_target(renderer, opt.screenshot);   // before Present
            quit = true;
        }
        SDL_RenderPresent(renderer);
    }

    core.stop();
    if (tex) SDL_DestroyTexture(tex);
    ImGui_ImplSDLRenderer3_Shutdown();
    ImGui_ImplSDL3_Shutdown();
    ImGui::DestroyContext();
    SDL_DestroyRenderer(renderer);
    SDL_DestroyWindow(window);
    SDL_Quit();
    return 0;
}
