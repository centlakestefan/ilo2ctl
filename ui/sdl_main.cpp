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

#include <SDL3/SDL.h>
#include "imgui.h"
#include "imgui_impl_sdl3.h"
#include "imgui_impl_sdlrenderer3.h"

#include "ui/connections.hpp"
#include "ui/console_core.hpp"
#include "ui/power_control.hpp"

using namespace ilo2;

namespace {

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
};

// The control panel is a fixed strip down the left edge; the console gets
// everything to its right, so the two never overlap. This is in ImGui's
// window units; the render target is in pixels, so callers scale it by the
// window's pixel density before handing it to letterbox().
constexpr float kPanelWidth = 300.0f;

// Where the console image lands inside the window, preserving aspect ratio,
// within the area to the right of the panel (panel_px wide, in pixels).
SDL_FRect letterbox(int fb_w, int fb_h, int win_w, int win_h, float panel_px) {
    if (fb_w <= 0 || fb_h <= 0) return SDL_FRect{ 0, 0, 0, 0 };
    const float area_x = panel_px;
    const float area_w = std::max(0.0f, float(win_w) - area_x);
    const float sx = area_w / float(fb_w);
    const float sy = float(win_h) / float(fb_h);
    const float s  = std::min(sx, sy);
    const float w  = float(fb_w) * s;
    const float h  = float(fb_h) * s;
    return SDL_FRect{ area_x + (area_w - w) * 0.5f, (float(win_h) - h) * 0.5f, w, h };
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

    SDL_Window* window = SDL_CreateWindow("iLO 2 Remote Console", 1344, 800,
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

    // Recent connections: host and user only, never the password. Stored in
    // the per-user preferences directory SDL picks for this platform.
    std::string connections_path;
    if (char* pref = SDL_GetPrefPath("centlake", "ilo2_console")) {
        connections_path = std::string(pref) + "connections.txt";
        SDL_free(pref);
    }
    std::vector<SavedConnection> recent = load_connections(connections_path);
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
    };
    auto do_disconnect = [&] {
        core.stop();
        power.stop();
        armed = false;
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

            int win_w = 0, win_h = 0;
            SDL_GetRenderOutputSize(renderer, &win_w, &win_h);
            const SDL_FRect dst = letterbox(fb_w, fb_h, win_w, win_h,
                                            kPanelWidth * SDL_GetWindowPixelDensity(window));

            switch (ev.type) {
                case SDL_EVENT_MOUSE_MOTION: {
                    if (io.WantCaptureMouse) break;
                    int cx = 0, cy = 0;
                    if (to_console(dst, fb_w, fb_h, ev.motion.x, ev.motion.y, cx, cy))
                        core.mouse_move(cx, cy);
                    break;
                }
                case SDL_EVENT_MOUSE_BUTTON_DOWN:
                case SDL_EVENT_MOUSE_BUTTON_UP: {
                    if (io.WantCaptureMouse) break;
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
                    if (io.WantCaptureKeyboard) break;
                    for (const char* p = ev.text.text; *p; ++p) core.type_char(*p);
                    break;
                }
                case SDL_EVENT_KEY_DOWN: {
                    if (io.WantCaptureKeyboard) break;
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

        ImGui::SetNextWindowPos(ImVec2(0, 0));
        ImGui::SetNextWindowSize(ImVec2(kPanelWidth, ImGui::GetIO().DisplaySize.y));
        ImGui::Begin("Console", nullptr,
                     ImGuiWindowFlags_NoMove | ImGuiWindowFlags_NoResize |
                     ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoBringToFrontOnFocus);
        ImGui::PushTextWrapPos(0.0f);

        // Once the console is up, the credentials are known to be good: record
        // host and user (never the password) for next time.
        if (connected && !connection_recorded && opt.replay.empty()) {
            remember_connection(recent, host_buf, user_buf);
            if (!connections_path.empty()) save_connections(connections_path, recent);
            connection_recorded = true;
        }

        // --- controls (top) -------------------------------------------------
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
                    // Click fills the fields; double-click connects; the small
                    // button on the right forgets the entry.
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
            // The real key combination never reaches an application on either
            // platform, so it has to be a button.
            if (ImGui::Button("Ctrl-Alt-Del")) core.send_ctrl_alt_del();
            ImGui::Checkbox("forward keyboard and mouse", &send_input);
        }

        // Errors belong next to the controls that caused them.
        if (!ui_error.empty())
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", ui_error.c_str());
        const std::string core_err = core.error();
        if (!core_err.empty())
            ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", core_err.c_str());

        // --- server power (RIBCL) ---------------------------------------------
        if (power.running()) {
            const PowerControl::Snapshot ps = power.snapshot();
            ImGui::Spacing();
            ImGui::SeparatorText("Server");
            if (ps.host_power.empty()) ImGui::Text("power : %s", ps.busy ? "reading..." : "unknown");
            else                       ImGui::Text("power : %s%s", ps.host_power.c_str(), ps.busy ? "  (busy)" : "");

            if (armed && SDL_GetTicks() - armed_at > ARM_TIMEOUT_MS) armed = false;

            // One row of buttons; the destructive ones arm on the first click
            // and act on the second, so a stray click on the panel can never
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
            if (ImGui::Button("UID on"))  power.request(RibclCommand::UidOn);
            ImGui::SameLine();
            if (ImGui::Button("UID off")) power.request(RibclCommand::UidOff);

            if (!ps.last_action.empty()) {
                const ImVec4 col = ps.error ? ImVec4(1.0f, 0.4f, 0.4f, 1.0f)
                                            : ImVec4(0.6f, 0.9f, 0.6f, 1.0f);
                ImGui::TextColored(col, "%s: %s", ps.last_action.c_str(), ps.last_result.c_str());
            } else if (ps.error) {
                ImGui::TextColored(ImVec4(1.0f, 0.4f, 0.4f, 1.0f), "%s", ps.last_result.c_str());
            }

            // --- health (GET_EMBEDDED_HEALTH / GET_POWER_READINGS) ---------
            // A one-line summary always; the sensor tables fold away so the
            // panel stays short unless something is worth looking at.
            const ImVec4 ok_col  (0.6f, 0.9f, 0.6f, 1.0f);
            const ImVec4 warn_col(1.0f, 0.8f, 0.3f, 1.0f);
            const ImVec4 bad_col (1.0f, 0.4f, 0.4f, 1.0f);
            auto status_col = [&](const std::string& s) -> ImVec4 {
                if (s.empty() || s == "Ok" || s == "n/a" || s == "Not Installed") return ImGui::GetStyle().Colors[ImGuiCol_Text];
                return bad_col;
            };
            if (ps.watts.valid || ps.health.valid) {
                ImGui::Spacing();
                ImGui::SeparatorText("Health");
            }
            if (ps.watts.valid) {
                ImGui::Text("power : %d W", ps.watts.present);
                ImGui::SameLine();
                ImGui::TextDisabled("(avg %d, max %d)", ps.watts.average, ps.watts.maximum);
            }
            if (ps.health.valid) {
                const HealthData& h = ps.health;
                const HealthGlance& g = h.glance;
                const bool all_ok = health_all_ok(g);
                ImGui::Text("health: ");
                ImGui::SameLine();
                if (all_ok) {
                    ImGui::TextColored(ok_col, "all Ok");
                } else {
                    // Name the subsystems that are not, since that is the
                    // only time anyone reads this line.
                    ImGui::TextColored(bad_col, "fans %s, temps %s, vrm %s, psu %s, drives %s",
                                       g.fans.c_str(), g.temperature.c_str(), g.vrm.c_str(),
                                       g.supplies.c_str(), g.drives.c_str());
                }

                const HealthTemp* hot = hottest(h);
                char hdr[96];
                if (hot) std::snprintf(hdr, sizeof(hdr), "Temperatures  (%s %d C)###temps", hot->location.c_str(), hot->reading);
                else     std::snprintf(hdr, sizeof(hdr), "Temperatures###temps");
                if (ImGui::CollapsingHeader(hdr)) {
                    if (ImGui::BeginTable("temps", 3, ImGuiTableFlags_SizingFixedFit)) {
                        for (const auto& t : h.temps) {
                            if (t.reading < 0) continue;      // not fitted
                            ImVec4 col = ImGui::GetStyle().Colors[ImGuiCol_Text];
                            if (t.critical >= 0 && t.reading >= t.critical)     col = bad_col;
                            else if (t.caution >= 0 && t.reading >= t.caution)  col = warn_col;
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(t.location.c_str());
                            ImGui::TableNextColumn(); ImGui::TextColored(col, "%3d C", t.reading);
                            ImGui::TableNextColumn(); ImGui::TextDisabled("/ %d", t.caution);
                        }
                        ImGui::EndTable();
                    }
                }
                if (ImGui::CollapsingHeader("Fans###fans")) {
                    if (ImGui::BeginTable("fans", 3, ImGuiTableFlags_SizingFixedFit)) {
                        for (const auto& f : h.fans) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn(); ImGui::TextUnformatted(f.label.c_str());
                            ImGui::TableNextColumn(); ImGui::Text("%3d%%", f.speed_pct);
                            ImGui::TableNextColumn(); ImGui::TextColored(status_col(f.status), "%s", f.status.c_str());
                        }
                        ImGui::EndTable();
                    }
                }
                if (ImGui::CollapsingHeader("Power supplies & drives###psu")) {
                    for (const auto& s : h.supplies) {
                        ImGui::TextUnformatted(s.label.c_str());
                        ImGui::SameLine();
                        ImGui::TextColored(status_col(s.status), "%s", s.status.c_str());
                    }
                    if (ImGui::BeginTable("drives", 3, ImGuiTableFlags_SizingFixedFit)) {
                        for (const auto& d : h.drives) {
                            ImGui::TableNextRow();
                            ImGui::TableNextColumn(); ImGui::Text("bay %d", d.bay);
                            ImGui::TableNextColumn(); ImGui::TextDisabled("%s", d.product.c_str());
                            ImGui::TableNextColumn(); ImGui::TextColored(status_col(d.status), "%s", d.status.c_str());
                        }
                        ImGui::EndTable();
                    }
                }
            }
        }

        // --- status (bottom) --------------------------------------------------
        // Pinned to the bottom of the panel so the controls stay put and the
        // counters stay out of the way. The block's height is measured as it is
        // drawn and used to place it next frame; one frame of lag is invisible.
        static float status_height = 0.0f;
        {
            const float bottom = ImGui::GetWindowHeight() - ImGui::GetStyle().WindowPadding.y;
            const float y = bottom - status_height;
            if (y > ImGui::GetCursorPosY()) ImGui::SetCursorPosY(y);
            const float start = ImGui::GetCursorPosY();

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

            status_height = ImGui::GetCursorPosY() - start;
        }
        ImGui::PopTextWrapPos();
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

        int win_w = 0, win_h = 0;
        SDL_GetRenderOutputSize(renderer, &win_w, &win_h);
        SDL_SetRenderDrawColor(renderer, 16, 16, 20, 255);
        SDL_RenderClear(renderer);
        if (tex) {
            const SDL_FRect dst = letterbox(fb_w, fb_h, win_w, win_h,
                                            kPanelWidth * SDL_GetWindowPixelDensity(window));
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
