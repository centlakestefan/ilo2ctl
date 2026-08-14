// test_ilo2_input.cpp — emit every ilo2_input encoder as labeled hex lines, to
// be diffed against HP's cim output (Ilo2InputProbe.java).
#include <cstdio>
#include <string>
#include "ilo2_input.hpp"

using namespace ilo2;

static std::string hex(const std::string& s) {
    static const char* H = "0123456789abcdef";
    std::string o;
    for (unsigned char c : s) { o += H[c >> 4]; o += H[c & 0xF]; }
    return o;
}

int main() {
    Input in; in.screen_w = 800; in.screen_h = 600; in.absolute = true;
    FILE* f = std::fopen("build/input_cpp.txt", "wb");
    if (!f) return 2;

    const int coords[][2] = {{0,0},{400,300},{799,599},{123,456}};
    for (auto& c : coords)
        std::fprintf(f, "MOVE %d %d %s\n", c[0], c[1], hex(in.move(c[0], c[1])).c_str());
    std::fprintf(f, "PRESS 4 %s\n", hex(Input::press(4)).c_str());
    std::fprintf(f, "PRESS 1 %s\n", hex(Input::press(1)).c_str());
    std::fprintf(f, "PRESS 2 %s\n", hex(Input::press(2)).c_str());
    std::fprintf(f, "RELEASE 4 %s\n", hex(Input::release(4)).c_str());
    std::fprintf(f, "SELECTABS %s\n", hex(Input::select_mouse(true)).c_str());
    std::fprintf(f, "SELECTREL %s\n", hex(Input::select_mouse(false)).c_str());
    std::fprintf(f, "CAD %s\n", hex(Input::ctrl_alt_del()).c_str());

    for (int c = 0x20; c <= 0x7e; ++c)
        std::fprintf(f, "KEYT %d %s\n", c, hex(Input::type_char((char)c)).c_str());
    std::fprintf(f, "KEYR 13 %s\n", hex(Input::type_char('\r')).c_str());
    std::fprintf(f, "KEYR 8 %s\n",  hex(Input::type_char('\b')).c_str());
    std::fprintf(f, "KEYS 9 %s\n",  hex(Input::tab()).c_str());
    std::fprintf(f, "KEYS 27 %s\n", hex(Input::escape()).c_str());
    std::fprintf(f, "KEYS 38 %s\n", hex(Input::arrow_up()).c_str());
    std::fprintf(f, "KEYS 40 %s\n", hex(Input::arrow_down()).c_str());
    std::fprintf(f, "KEYS 37 %s\n", hex(Input::arrow_left()).c_str());
    std::fprintf(f, "KEYS 39 %s\n", hex(Input::arrow_right()).c_str());
    std::fclose(f);
    printf("wrote build/input_cpp.txt\n");
    return 0;
}
