// test_png.cpp — validate the PNG output path.
//  1. Encode a known gradient framebuffer -> build/gradient.png (verified pixel-
//     exact by PngCheck.java via ImageIO).
//  2. Smoke test: run the existing random DVC stream through FramebufferDecoder
//     and save whatever framebuffer results -> build/random_frame.png (proves the
//     decode->blit->encode pipeline runs and emits a valid PNG).
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "third_party/stb_image_write.h"
#include "ilo/cim_png.hpp"
#include <cstdio>
#include <vector>

using namespace ilo2;

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
    if (save_argb_png("build/gradient.png", px.data(), W, H))
        printf("wrote build/gradient.png %dx%d\n", W, H);
    else { printf("FAILED to write gradient.png\n"); return 1; }

    // 2. Pipeline smoke test with the random DVC stream.
    FramebufferDecoder d;
    if (FILE* f = std::fopen("build/decoder_stream.bin", "rb")) {
        int c;
        while ((c = std::fgetc(f)) != EOF) d.process_dvc(static_cast<uint8_t>(c));
        std::fclose(f);
        if (d.save_as_png("build/random_frame.png"))
            printf("wrote build/random_frame.png %dx%d (garbage image; pipeline OK)\n", d.fb_w, d.fb_h);
        else
            printf("no framebuffer produced (stream had no MODE2 video)\n");
    } else {
        printf("build/decoder_stream.bin not found; skipping smoke test\n");
    }
    return 0;
}
