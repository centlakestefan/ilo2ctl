// replay_dvc.cpp — replay a captured DVC byte stream offline and report what the
// decoder made of it. This is the regression half of the frame oracle: once a
// real capture exists, no hardware is needed to re-check the decoder.
//
// Build:
//   g++ -O2 -std=c++17 -o build/replay_dvc.exe cpp/replay_dvc.cpp
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"

#include <cstdio>
#include <cstdlib>
#include <map>
#include <string>
#include <vector>

#include "cim_png.hpp"

using namespace ilo2;

class StatDecoder : public FramebufferDecoder {
public:
    int pastes = 0, dims = 0, texts = 0, rekeys = 0, fw = 0;
    int nonblack_pastes = 0;
    std::vector<std::string> log;

protected:
    void on_paste(const int* blk, int x, int y, int len) override {
        ++pastes;
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
