// cim_png.hpp — render the DVC decoder's output to a framebuffer and save it as
// a PNG, reusing the same approach as \proj\cpp-vnc (public-domain
// stb_image_write, 0xAARRGGBB pixels -> 3-byte RGB -> stbi_write_png).
//
// FramebufferDecoder subclasses DvcDecoder: on_set_dimensions allocates the
// framebuffer (from the DVC MODE2 resolution) and on_paste blits each decoded
// 16x16 tile into it, mirroring dvcwin.paste_array (16 rows, bottom-clipped).
//
// The single translation unit that includes this must define
// STB_IMAGE_WRITE_IMPLEMENTATION before including stb_image_write.h once.
#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include "dvc_decoder.hpp"

// Forward-declare the one stb function we use, so this header never pulls in the
// implementation. Exactly one translation unit must
//   #define STB_IMAGE_WRITE_IMPLEMENTATION
//   #include "third_party/stb_image_write.h"
// The signature matches stb's STBIWDEF declaration.
extern int stbi_write_png(char const* filename, int w, int h, int comp,
                          const void* data, int stride_in_bytes);

namespace ilo2 {

// Encode a 0x00RRGGBB / 0xAARRGGBB framebuffer as PNG (alpha dropped), exactly
// like cpp-vnc's save_as_png.
inline bool save_argb_png(const std::string& path, const uint32_t* px, int w, int h) {
    if (w <= 0 || h <= 0) return false;
    std::vector<uint8_t> rgb(static_cast<size_t>(w) * h * 3);
    for (int i = 0; i < w * h; ++i) {
        uint32_t p = px[i];
        rgb[i * 3 + 0] = (p >> 16) & 0xFF;  // R
        rgb[i * 3 + 1] = (p >> 8)  & 0xFF;  // G
        rgb[i * 3 + 2] = (p)       & 0xFF;  // B
    }
    return stbi_write_png(path.c_str(), w, h, 3, rgb.data(), w * 3) != 0;
}

class FramebufferDecoder : public DvcDecoder {
public:
    int fb_w = 0, fb_h = 0;
    std::vector<uint32_t> pixels;   // 0x00RRGGBB, row-major, size fb_w*fb_h

    bool save_as_png(const std::string& path) const {
        if (pixels.empty()) return false;
        return save_argb_png(path, pixels.data(), fb_w, fb_h);
    }

protected:
    // DVC MODE2 resolution -> (re)allocate the framebuffer.
    //
    // CRITICAL: a same-size call must be a complete no-op. dvcwin.set_abs_dimensions
    // (dvcwin.java:112) wraps its whole body in `if (n != screen_x || n2 != screen_y)`,
    // and real streams repeat the MODE2 resolution packet many times per session.
    // Without this guard every repeat reallocates and zeroes the buffer, blanking
    // the image -- a real 346KB capture decoded 4548 tiles containing pixels and
    // still rendered pure black, because a redundant 1024x768 packet arrived last.
    void on_set_dimensions(int w, int h) override {
        if (w == fb_w && h == fb_h) return;
        fb_w = w; fb_h = h;
        pixels.assign(static_cast<size_t>(w) * h, 0u);
    }

    // Blit a 16x16 tile (block laid out 16 ints/row) at (x,y), bottom-clipped to
    // the framebuffer height — the geometry of dvcwin.paste_array.
    void on_paste(const int* blk, int x, int y, int len) override {
        if (pixels.empty()) return;
        int rows = (y + 16 > fb_h) ? (fb_h - y) : 16;
        for (int r = 0; r < rows; ++r) {
            int yy = y + r;
            if (yy < 0 || yy >= fb_h) continue;
            for (int c = 0; c < len; ++c) {
                int xx = x + c;
                if (xx < 0 || xx >= fb_w) continue;
                pixels[static_cast<size_t>(yy) * fb_w + xx] = static_cast<uint32_t>(blk[r * 16 + c]);
            }
        }
    }
};

} // namespace ilo2
