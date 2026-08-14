// ilo2_input.hpp — outbound mouse/keyboard encoders for the iLO 2 remote
// console, for agent tools ilo2_click / ilo2_type.
//
// These build the PLAINTEXT protocol byte sequences that the applet's cim would
// transmit; the session layer is responsible for RC4-encrypting them (cim
// encrypts outbound with the INFOC key) and writing to the socket. All encoders
// are lifted verbatim from cim: serverMove / send_mouse_press / send_mouse_release
// / mouse_mode_change / send_ctrl_alt_del / translate_key / translate_special_key.
//
// Mouse is driven in ABSOLUTE mode (mouse_protocol != 0): the server positions
// the cursor from scaled absolute coordinates (3000 * pixel / screen) and ignores
// the relative deltas, so no MouseSync calibration is required. Keyboard is
// character-based: for the en_US locale translate(c) is the identity, so typing
// sends ASCII bytes directly (the firmware maps them to USB HID).
#pragma once
#include <cstdint>
#include <string>

namespace ilo2 {

class Input {
public:
    // Button mask values, as in cim / MouseSync.
    static constexpr int BTN_LEFT   = 4;
    static constexpr int BTN_CENTER = 2;
    static constexpr int BTN_RIGHT  = 1;

    int  screen_w = 0;      // current DVC screen_x (from MODE2)
    int  screen_h = 0;      // current DVC screen_y
    bool absolute = true;   // mouse_protocol != 0

    // ---- mouse ----

    // mouse_mode_change(abs): FF D5 01 (USB-absolute) or FF D5 02 (USB-relative).
    static std::string select_mouse(bool abs) {
        return bytes(0xFF, 0xD5, abs ? 0x01 : 0x02);
    }

    // cim.serverMove(0,0,x,y): FF D0 dx dy [Xhi Xlo Yhi Ylo].
    // Absolute mode appends the 16-bit scaled coordinates; deltas are 0.
    std::string move(int x, int y) const {
        int dx = 0, dy = 0;                     // server ignores these in absolute mode
        int sx, sy;
        if (screen_w > 0 && screen_h > 0) { sx = 3000 * x / screen_w; sy = 3000 * y / screen_h; }
        else                              { sx = 3000 * x;            sy = 3000 * y; }
        std::string s = bytes(0xFF, 0xD0);
        s += static_cast<char>(dx & 0xFF);
        s += static_cast<char>(dy & 0xFF);
        if (absolute) {
            s += static_cast<char>((sx / 256) & 0xFF);
            s += static_cast<char>((sx % 256) & 0xFF);
            s += static_cast<char>((sy / 256) & 0xFF);
            s += static_cast<char>((sy % 256) & 0xFF);
        }
        return s;
    }

    // cim.send_mouse_press / send_mouse_release: FF D1 b / FF D2 b.
    static std::string press(int button)   { return bytes(0xFF, 0xD1, button & 0xFF); }
    static std::string release(int button)  { return bytes(0xFF, 0xD2, button & 0xFF); }

    // Position + press + release (the ilo2_click primitive).
    std::string click(int x, int y, int button = BTN_LEFT) const {
        return move(x, y) + press(button) + release(button);
    }

    // ---- keyboard ----

    // One character as cim would send it. Printable ASCII is passed through
    // (en_US translate() is identity); a few controls follow cim's key handling.
    static std::string type_char(char c) {
        switch (c) {
            case '\n':
            case '\r': return "\r";                 // translate_key: Enter -> CR
            case '\t': return "\t";                 // translate_special_key(VK_TAB)
            case '\b': return "\b";                 // translate_key: Backspace
            case 0x1b: return std::string(1, 0x1b); // translate_special_key(VK_ESCAPE)
            default:   return std::string(1, c);    // en_US identity
        }
    }
    static std::string type_text(const std::string& text) {
        std::string s;
        for (char c : text) s += type_char(c);
        return s;
    }

    // cim.send_ctrl_alt_del(): ESC [ 2 ESC [ 0x7f.
    static std::string ctrl_alt_del() {
        return std::string({0x1b, '[', '2', 0x1b, '[', static_cast<char>(0x7f)});
    }

    // Arrow keys via translate_special_key.
    static std::string arrow_up()    { return "\x1b[A"; }
    static std::string arrow_down()  { return "\x1b[B"; }
    static std::string arrow_left()  { return "\x1b[D"; }
    static std::string arrow_right() { return "\x1b[C"; }
    static std::string enter()       { return "\r"; }
    static std::string tab()         { return "\t"; }
    static std::string backspace()   { return "\b"; }
    static std::string escape()      { return std::string(1, 0x1b); }

private:
    static std::string bytes(int a, int b) {
        std::string s; s += static_cast<char>(a); s += static_cast<char>(b); return s;
    }
    static std::string bytes(int a, int b, int c) {
        std::string s = bytes(a, b); s += static_cast<char>(c); return s;
    }
};

} // namespace ilo2
