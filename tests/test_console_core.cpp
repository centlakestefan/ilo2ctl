// test_console_core.cpp — the front-end seam, driven from the committed capture
// fixtures rather than hardware.
//
// The property most worth pinning down is the change detection. The DVC encoder
// retransmits every tile on every pass, so a seam that forwarded pastes
// verbatim would report the whole screen as dirty several times a second. These
// tests assert that redundant repaints are recognised and dropped.
#include <chrono>
#include <string>
#include <thread>
#include <vector>
#include "tests/test_util.hpp"
#include "ui/console_core.hpp"

using namespace ilo2;

static void wait_until_done(ConsoleCore& core, int timeout_ms = 30000) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeout_ms);
    while (core.running() && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
}

static size_t total_area(const std::vector<Rect>& rects) {
    size_t a = 0;
    for (const auto& r : rects) a += static_cast<size_t>(r.w) * r.h;
    return a;
}

int main() {
    std::printf("[replaying the settled lock screen]\n");
    {
        ConsoleCore core;
        std::string err;
        t::ok(core.start_replay("testdata/lock_screen_settled.bin", 0, err),
              err.empty() ? "replay started" : err.c_str());
        wait_until_done(core);
        t::ok(!core.running(), "replay finished");
        t::ok(core.state() == ConsoleState::Stopped, "state is stopped");

        t::ok(core.width() == 1024 && core.height() == 768, "framebuffer is 1024x768");

        // The headline number: how much of the stream was redundant.
        const uint64_t all = core.pastes(), changed = core.changed_pastes();
        std::printf("  %llu pastes, %llu changed a pixel (%.1f%% redundant)\n",
                    static_cast<unsigned long long>(all),
                    static_cast<unsigned long long>(changed),
                    100.0 * double(all - changed) / double(all ? all : 1));
        t::ok(all == 32256, "paste count matches testdata/README.md");
        t::ok(changed < all / 4, "most pastes were redundant repaints");
        // 2085 is exactly the "rewrites with changed pixels" figure that
        // tools/replay_dvc.cpp reports for this fixture, and it arrives here by
        // a different route: replay_dvc hashes each tile and compares against
        // the previous content at that position, while this compares pixels
        // against the framebuffer. Two independent implementations agreeing on
        // the number is worth pinning.
        //
        // They agree exactly because the capture opens with black frames, which
        // the zeroed framebuffer already matches: measured, the first 6144
        // pastes -- two complete passes over the screen -- change nothing at
        // all, and the image only arrives afterwards. So every change this
        // counts is a rewrite, which is precisely what replay_dvc counts.
        t::ok(changed == 2085, "change count agrees with replay_dvc's independent figure");

        std::vector<uint32_t> fb;
        std::vector<Rect> dirty;
        int w = 0, h = 0;

        // First pull allocates, so it reports the whole screen.
        t::ok(core.pull(fb, w, h, dirty), "first pull returns a frame");
        t::ok(w == 1024 && h == 768, "dimensions reported");
        t::ok(fb.size() == 1024u * 768, "framebuffer sized");
        t::ok(dirty.size() == 1 && dirty[0].w == 1024 && dirty[0].h == 768,
              "the first pull is one full-screen rectangle");

        // The replay has finished, so nothing further can change.
        t::ok(!core.pull(fb, w, h, dirty), "a second pull reports no change");

        // Sanity: the decoded image is the lock screen, not a blank buffer.
        size_t nonblack = 0;
        for (uint32_t px : fb) if ((px & 0x00FFFFFF) != 0) ++nonblack;
        std::printf("  %zu of %zu pixels are non-black\n", nonblack, fb.size());
        t::ok(nonblack > fb.size() / 10, "the framebuffer holds a real image");
    }

    std::printf("[replaying the blank console]\n");
    {
        // A blanked screen is entirely black, and the framebuffer starts zeroed,
        // so after the resolution is set NOT ONE paste can change a pixel. This
        // is the cleanest possible demonstration that redundant repaints are
        // being dropped: the ideal answer is exactly zero.
        ConsoleCore core;
        std::string err;
        t::ok(core.start_replay("testdata/blank_console.bin", 0, err),
              err.empty() ? "replay started" : err.c_str());
        wait_until_done(core);

        const uint64_t all = core.pastes(), changed = core.changed_pastes();
        std::printf("  %llu pastes, %llu changed a pixel\n",
                    static_cast<unsigned long long>(all),
                    static_cast<unsigned long long>(changed));
        t::ok(all == 12288, "paste count matches testdata/README.md");
        t::ok(changed == 0, "a black screen produces no changed pastes at all");

        std::vector<uint32_t> fb;
        std::vector<Rect> dirty;
        int w = 0, h = 0;
        t::ok(core.pull(fb, w, h, dirty), "first pull still reports the initial frame");
        t::ok(!core.pull(fb, w, h, dirty), "and nothing after it");

        size_t nonblack = 0;
        for (uint32_t px : fb) if ((px & 0x00FFFFFF) != 0) ++nonblack;
        t::ok(nonblack == 0, "every pixel is black");
    }

    std::printf("[incremental pulls during a paced replay]\n");
    {
        // Pace the replay so the front end pulls partial frames, which is what
        // an SDL loop or an RFB client actually does.
        ConsoleCore core;
        std::string err;
        t::ok(core.start_replay("testdata/lock_screen_wake.bin", 150000, err),
              err.empty() ? "paced replay started" : err.c_str());

        std::vector<uint32_t> fb;
        std::vector<Rect> dirty;
        int w = 0, h = 0;
        size_t pulls = 0, frames = 0, rects = 0, area = 0;

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(30);
        while ((core.running() || frames == 0) &&
               std::chrono::steady_clock::now() < deadline) {
            if (core.pull(fb, w, h, dirty)) {
                ++frames;
                rects += dirty.size();
                area  += total_area(dirty);
                // Every rectangle must lie inside the framebuffer.
                for (const auto& r : dirty) {
                    if (r.x < 0 || r.y < 0 || r.w <= 0 || r.h <= 0 ||
                        r.x + r.w > w || r.y + r.h > h) {
                        t::ok(false, "a dirty rectangle escaped the framebuffer");
                        break;
                    }
                }
            }
            ++pulls;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        wait_until_done(core);
        core.pull(fb, w, h, dirty);          // drain whatever arrived last

        std::printf("  %zu pulls, %zu with changes, %zu rectangles, %zu px total\n",
                    pulls, frames, rects, area);
        t::ok(frames > 1, "changes arrived across several pulls, not all at once");
        t::ok(rects >= frames, "each changed pull produced at least one rectangle");
        t::ok(true, "all dirty rectangles stayed inside the framebuffer");

        // Horizontally adjacent dirty tiles are merged, so a full-width band
        // costs one rectangle rather than 64. Area over rectangles should
        // therefore comfortably exceed a single 16x16 tile.
        if (rects) {
            const double avg = double(area) / double(rects);
            std::printf("  average rectangle is %.0f px (a bare tile is 256)\n", avg);
            t::ok(avg >= 256.0, "rectangles are at least tile-sized");
        }
    }

    std::printf("[lifecycle]\n");
    {
        ConsoleCore core;
        std::string err;
        t::ok(core.state() == ConsoleState::Idle, "starts idle");
        t::ok(!core.start_replay("testdata/does_not_exist.bin", 0, err),
              "a missing replay file is refused");
        t::ok(!err.empty(), "and reports why");

        t::ok(core.start_replay("testdata/blank_console.bin", 0, err), "replay started");
        std::string err2;
        t::ok(!core.start_replay("testdata/blank_console.bin", 0, err2),
              "starting twice is refused");
        core.stop();
        t::ok(!core.running(), "stop() joins the worker");
        core.stop();
        t::ok(true, "stop() is idempotent");

        // A live start with no host must fail without spawning anything.
        ConsoleCore live;
        ConsoleCore::Config cfg;
        std::string err3;
        t::ok(!live.start(cfg, err3), "a live start with no host is refused");
        t::eq(err3, "no host", "and says so");
    }

    return t::report("test_console_core");
}
