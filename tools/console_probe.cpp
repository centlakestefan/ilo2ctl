// console_probe.cpp — drive ui/console_core.hpp against a live iLO, or a replay
// fixture, and report what the seam actually delivers.
//
// This is the front-end-shaped smoke test: it does exactly what an SDL loop or
// the RFB bridge will do — start the core, poll pull() on its own schedule, and
// act on the dirty rectangles — before any presentation code exists. If this
// looks right, a front end is a rendering exercise rather than a protocol one.
//
// Usage:
//   console_probe --host 192.0.2.10 [--seconds 10] [--refresh-every N]
//   console_probe --replay testdata/lock_screen_settled.bin
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "ui/console_core.hpp"

using namespace ilo2;

int main(int argc, char** argv) {
    std::string host, replay, pass, png = "build/console_probe";
    std::string user = "Administrator";
    int seconds = 10, refresh_every = 0;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host")    host = next();
        else if (a == "--replay")  replay = next();
        else if (a == "--user")    user = next();
        else if (a == "--pass")    pass = next();
        else if (a == "--seconds") seconds = std::atoi(next().c_str());
        else if (a == "--refresh-every") refresh_every = std::atoi(next().c_str());
        else if (a == "--png")     png = next();
        else { std::fprintf(stderr, "unknown arg: %s\n", a.c_str()); return 2; }
    }
    if (host.empty() && replay.empty()) {
        std::fprintf(stderr,
            "usage: console_probe --host H [--seconds N] [--refresh-every N]\n"
            "       console_probe --replay f.bin\n");
        return 2;
    }

    ConsoleCore core;
    std::string err;
    if (!replay.empty()) {
        if (!core.start_replay(replay, 0, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
    } else {
        ConsoleCore::Config cfg;
        cfg.host = host;
        cfg.user = user;
        cfg.pass = read_ilo_password(pass);
        cfg.refresh_every_sec = refresh_every;
        if (cfg.pass.empty()) {
            std::fprintf(stderr, "no password (--pass, ILO_PASS, or .ilo_pass)\n");
            return 2;
        }
        std::printf("[*] connecting to %s ...\n", host.c_str());
        if (!core.start(cfg, err)) {
            std::fprintf(stderr, "%s\n", err.c_str());
            return 1;
        }
    }

    std::vector<uint32_t> fb;
    std::vector<Rect> dirty;
    int w = 0, h = 0;
    size_t pulls = 0, frames = 0, rects = 0;
    unsigned long long area = 0;
    std::string last_state, last_status;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    while (std::chrono::steady_clock::now() < deadline) {
        const std::string st = console_state_name(core.state());
        if (st != last_state) {
            std::printf("[state] %s\n", st.c_str());
            std::fflush(stdout);
            last_state = st;
        }
        const std::string status = core.status();
        if (!status.empty() && status != last_status) {
            std::printf("[status] %s\n", status.c_str());
            std::fflush(stdout);
            last_status = status;
        }
        if (core.state() == ConsoleState::Failed) break;

        if (core.pull(fb, w, h, dirty)) {
            ++frames;
            rects += dirty.size();
            for (const auto& r : dirty)
                area += static_cast<unsigned long long>(r.w) * r.h;
        }
        ++pulls;
        if (!core.running() && !replay.empty()) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(33));   // ~30 Hz, like a GUI
    }

    if (core.state() == ConsoleState::Failed) {
        std::fprintf(stderr, "[!] %s\n", core.error().c_str());
        core.stop();
        return 1;
    }
    core.pull(fb, w, h, dirty);
    core.stop();

    std::printf("\n--- seam report ---\n");
    std::printf("  framebuffer : %dx%d\n", w, h);
    std::printf("  pulls       : %zu (%zu carried changes)\n", pulls, frames);
    std::printf("  rectangles  : %zu, %llu px total\n", rects, area);
    std::printf("  pastes      : %llu, of which %llu changed a pixel\n",
                static_cast<unsigned long long>(core.pastes()),
                static_cast<unsigned long long>(core.changed_pastes()));
    if (core.pastes())
        std::printf("  redundancy  : %.1f%% of pastes repainted identical pixels\n",
                    100.0 * double(core.pastes() - core.changed_pastes()) /
                    double(core.pastes()));

    size_t nonblack = 0;
    for (uint32_t px : fb) if ((px & 0x00FFFFFF) != 0) ++nonblack;
    std::printf("  image       : %zu of %zu pixels non-black\n", nonblack, fb.size());

    if (!fb.empty() && !png.empty()) {
        const std::string path = png + ".png";
        if (save_argb_png(path, fb.data(), w, h))
            std::printf("  wrote %s\n", path.c_str());
    }
    return 0;
}
