// replay_dvc.cpp — replay a captured DVC byte stream offline and report what the
// decoder made of it. This is the regression half of the frame oracle: once a
// real capture exists, no hardware is needed to re-check the decoder.
//
// Build:
//   cmake -S . -B build/cmake -G Ninja && cmake --build build/cmake --target replay_dvc
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"

#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "ilo/cim_png.hpp"

using namespace ilo2;

class StatDecoder : public FramebufferDecoder {
public:
    int pastes = 0, dims = 0, texts = 0, rekeys = 0, fw = 0;
    int nonblack_pastes = 0;
    std::vector<std::string> log;

    // Geometry accounting: which tile positions get written, and how often.
    std::map<std::pair<int,int>, int> pos_hits;   // (x,y) -> paste count
    std::map<int, int> len_hist;                  // len -> count
    int max_x = -1, max_y = -1;

    // Is a repeat write to the same tile identical to what was already there
    // (pure redundancy) or different (a refinement / genuine screen change)?
    std::map<std::pair<int,int>, uint64_t> last_hash;
    int rewrite_same = 0, rewrite_diff = 0;

protected:
    void on_paste(const int* blk, int x, int y, int len) override {
        ++pastes;
        pos_hits[{x, y}]++;
        len_hist[len]++;
        if (x > max_x) max_x = x;
        if (y > max_y) max_y = y;

        uint64_t h = 1469598103934665603ull;          // FNV-1a over the tile
        for (int i = 0; i < 16 * 16; ++i) {
            h ^= static_cast<uint32_t>(blk[i]);
            h *= 1099511628211ull;
        }
        auto it = last_hash.find({x, y});
        if (it != last_hash.end()) {
            if (it->second == h) ++rewrite_same; else ++rewrite_diff;
            it->second = h;
        } else {
            last_hash[{x, y}] = h;
        }
        for (int i = 0; i < 16 * 16; ++i)
            if ((blk[i] & 0xFFFFFF) != 0) { ++nonblack_pastes; break; }
        FramebufferDecoder::on_paste(blk, x, y, len);
    }
    void on_set_dimensions(int w, int h) override {
        ++dims;
        char b[128]; std::snprintf(b, sizeof b, "dim %dx%d @paste %d", w, h, pastes);
        log.push_back(b);
        FramebufferDecoder::on_set_dimensions(w, h);
    }
    void on_show_text(const std::string& s) override { ++texts; log.push_back("text: " + s); }
    void on_change_key() override { ++rekeys; log.push_back("rekey"); }
    void on_firmware(int cmd) override {
        ++fw;
        char b[64]; std::snprintf(b, sizeof b, "firmware cmd %d", cmd);
        log.push_back(b);
    }
};

int main(int argc, char** argv) {
    const char* in  = (argc > 1) ? argv[1] : "build/dvc_capture.bin";
    const char* png = (argc > 2) ? argv[2] : "build/replay.png";

    FILE* f = std::fopen(in, "rb");
    if (!f) { std::fprintf(stderr, "cannot open %s\n", in); return 2; }
    std::fseek(f, 0, SEEK_END);
    long n = std::ftell(f);
    std::fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> buf(static_cast<size_t>(n));
    if (n > 0 && std::fread(buf.data(), 1, buf.size(), f) != buf.size()) {
        std::fprintf(stderr, "short read\n"); std::fclose(f); return 2;
    }
    std::fclose(f);
    std::printf("replaying %ld bytes from %s\n", n, in);

    StatDecoder d;
    size_t consumed = 0;
    for (uint8_t c : buf) {
        ++consumed;
        if (!d.process_dvc(c)) { std::printf("decoder left DVC mode at byte %zu\n", consumed); break; }
    }

    std::printf("\n--- events ---\n");
    for (const auto& s : d.log) std::printf("  %s\n", s.c_str());

    std::printf("\n--- totals ---\n");
    std::printf("  pastes        : %d (%d contained a non-black pixel)\n", d.pastes, d.nonblack_pastes);
    std::printf("  set_dimensions: %d\n", d.dims);
    std::printf("  show_text     : %d\n", d.texts);
    std::printf("  rekeys        : %d\n", d.rekeys);
    std::printf("  firmware cmds : %d\n", d.fw);
    std::printf("  framebuffer   : %dx%d\n", d.fb_w, d.fb_h);

    std::printf("\n--- geometry ---\n");
    std::printf("  distinct tile positions: %zu\n", d.pos_hits.size());
    std::printf("  max x = %d, max y = %d\n", d.max_x, d.max_y);
    if (d.fb_w > 0) {
        std::printf("  grid implied by fb   : %d x %d = %d tiles (16x16)\n",
                    d.fb_w / 16, d.fb_h / 16, (d.fb_w / 16) * (d.fb_h / 16));
    }
    for (auto& kv : d.len_hist)
        std::printf("  len=%d : %d pastes\n", kv.first, kv.second);
    {
        std::map<int, int> hit_hist;              // "written N times" -> how many positions
        for (auto& kv : d.pos_hits) hit_hist[kv.second]++;
        std::printf("  writes-per-position histogram:\n");
        int shown = 0;
        for (auto& kv : hit_hist) {
            if (shown++ >= 10) { std::printf("    ...\n"); break; }
            std::printf("    written %2d time(s): %d positions\n", kv.first, kv.second);
        }
    }
    // Are x/y always multiples of 16?
    {
        int offx = 0, offy = 0;
        for (auto& kv : d.pos_hits) {
            if (kv.first.first  % 16) ++offx;
            if (kv.first.second % 16) ++offy;
        }
        std::printf("  positions not 16-aligned: x=%d, y=%d\n", offx, offy);
    }
    std::printf("  rewrites identical to previous: %d\n", d.rewrite_same);
    std::printf("  rewrites with changed pixels  : %d\n", d.rewrite_diff);

    if (!d.pixels.empty()) {
        std::map<uint32_t, size_t> hist;
        for (uint32_t p : d.pixels) hist[p & 0xFFFFFF]++;
        std::printf("  distinct colors: %zu\n", hist.size());
        int shown = 0;
        for (auto it = hist.begin(); it != hist.end() && shown < 8; ++it, ++shown)
            std::printf("    #%06X  x%zu\n", it->first, it->second);
        d.save_as_png(png);
        std::printf("  wrote %s\n", png);
    }
    return 0;
}
