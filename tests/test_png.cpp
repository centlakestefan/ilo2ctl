// test_png.cpp — validate the PNG output path.
//
//  1. Encode a known gradient framebuffer and assert the encoded bytes match
//     tests/oracle/gradient.png. That fixture is the exact file
//     tests/PngCheck.java decoded through java.awt ImageIO and confirmed to be
//     a valid PNG whose 24000 pixels are all pixel-exact against the formula
//     below, so matching it byte-for-byte means the stb encoder still produces
//     correct, standard-decodable output. (PngCheck.java needs no HP jar, so
//     the semantic check can be re-run any time a JDK is around.)
//  2. Smoke test: run the DVC stream from test_dvc_decoder through
//     FramebufferDecoder and save whatever framebuffer results, proving the
//     decode->blit->encode pipeline runs and emits a PNG.
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"
#include "tests/test_util.hpp"
#include "ilo/cim_png.hpp"
#include <cstdio>
#include <string>
#include <vector>

using namespace ilo2;

// Binary fixture read -- deliberately not t::read_oracle, which strips CR.
static std::string read_bin(const char* path) {
    std::string s;
    if (FILE* f = std::fopen(path, "rb")) {
        char buf[65536]; size_t n;
        while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
        std::fclose(f);
    }
    return s;
}

int main() {
    // 1. Gradient encoder validation.
    const int W = 200, H = 120;
    std::vector<uint32_t> px(static_cast<size_t>(W) * H);
    for (int y = 0; y < H; ++y)
        for (int x = 0; x < W; ++x) {
            uint32_t R = static_cast<uint32_t>(x) & 0xFF;
            uint32_t G = static_cast<uint32_t>(y) & 0xFF;
            uint32_t B = static_cast<uint32_t>(x * 3 + y * 5) & 0xFF;
            px[static_cast<size_t>(y) * W + x] = (R << 16) | (G << 8) | B;
        }
    if (t::ok(save_argb_png("build/gradient.png", px.data(), W, H),
              "save_argb_png wrote build/gradient.png")) {
        const std::string got  = read_bin("build/gradient.png");
        const std::string want = read_bin("tests/oracle/gradient.png");
        if (t::ok(!want.empty(), "oracle fixture tests/oracle/gradient.png present")) {
            if (!t::ok(got == want, "gradient.png matches the ImageIO-verified fixture"))
                std::printf("       got %zu bytes, want %zu\n", got.size(), want.size());
        }
    }

    // 2. Pipeline smoke test with the DVC stream from test_dvc_decoder.
    FramebufferDecoder d;
    const std::string stream = read_bin("build/decoder_stream.bin");
    if (t::ok(!stream.empty(),
              "build/decoder_stream.bin present (run test_dvc_decoder first)")) {
        for (unsigned char c : stream) d.process_dvc(c);
        t::ok(d.save_as_png("build/random_frame.png"),
              "decode->blit->encode pipeline emits a PNG");
        std::printf("  pipeline framebuffer %dx%d (garbage image; shape only)\n", d.fb_w, d.fb_h);
    }

    return t::report("test_png");
}
