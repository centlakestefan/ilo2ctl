// test_ilo2_input.cpp — validates every ilo2_input encoder against HP's cim.
//
// The expected hex is HP's, captured from com.hp.ilo2.remcons.cim by
// tests/Ilo2InputProbe.java (a subclass that intercepts the transmit path
// instead of opening a socket) and frozen as tests/oracle/input.txt.
#include <cstdio>
#include <string>
#include "tests/test_util.hpp"
#include "ilo/ilo2_input.hpp"

using namespace ilo2;

static std::string hex(const std::string& s) {
    static const char* H = "0123456789abcdef";
    std::string o;
    for (unsigned char c : s) { o += H[c >> 4]; o += H[c & 0xF]; }
    return o;
}

int main() {
    Input in; in.screen_w = 800; in.screen_h = 600; in.absolute = true;
    std::string s;
    char buf[256];
    auto line = [&](const char* fmt, auto&&... a) {
        std::snprintf(buf, sizeof buf, fmt, a...);
        s += buf;
    };

    const int coords[][2] = {{0,0},{400,300},{799,599},{123,456}};
    for (auto& c : coords)
        line("MOVE %d %d %s\n", c[0], c[1], hex(in.move(c[0], c[1])).c_str());
    line("PRESS 4 %s\n",   hex(Input::press(4)).c_str());
    line("PRESS 1 %s\n",   hex(Input::press(1)).c_str());
    line("PRESS 2 %s\n",   hex(Input::press(2)).c_str());
    line("RELEASE 4 %s\n", hex(Input::release(4)).c_str());
    line("SELECTABS %s\n", hex(Input::select_mouse(true)).c_str());
    line("SELECTREL %s\n", hex(Input::select_mouse(false)).c_str());
    line("CAD %s\n",       hex(Input::ctrl_alt_del()).c_str());

    for (int c = 0x20; c <= 0x7e; ++c)
        line("KEYT %d %s\n", c, hex(Input::type_char((char)c)).c_str());
    line("KEYR 13 %s\n", hex(Input::type_char('\r')).c_str());
    line("KEYR 8 %s\n",  hex(Input::type_char('\b')).c_str());
    line("KEYS 9 %s\n",  hex(Input::tab()).c_str());
    line("KEYS 27 %s\n", hex(Input::escape()).c_str());
    line("KEYS 38 %s\n", hex(Input::arrow_up()).c_str());
    line("KEYS 40 %s\n", hex(Input::arrow_down()).c_str());
    line("KEYS 37 %s\n", hex(Input::arrow_left()).c_str());
    line("KEYS 39 %s\n", hex(Input::arrow_right()).c_str());

    t::eq_oracle(s, "input");
    return t::report("test_ilo2_input");
}
