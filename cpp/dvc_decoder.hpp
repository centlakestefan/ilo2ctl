// dvc_decoder.hpp — C++ port of the cim DVC decoder FSM (process_bits /
// process_dvc / next_block), integrating dvc_bits (bit reader) and dvc_cache
// (LRU palette). Faithful to com.hp.ilo2.remcons.cim.
//
// The 48-state machine is driven by three transcribed tables (bits_to_read,
// next_0, next_1); next_1[31] is patched at runtime from the palette size (kept
// in sync with the cache). Decoded pixels fill block[256] (a 16x16 tile) and are
// emitted through virtual hooks (on_paste etc.) so the rendering/GUI layer — or
// a validation harness — can observe them without the decoder knowing about AWT.
//
// State/GUI side effects that HP routed to dvcwin.paste_array / set_abs_dimensions
// / show_text are surfaced as on_paste / on_set_dimensions / on_show_text. Other
// seams (status text, repaint, refresh, RDP, seize, rekey) are no-op hooks by
// default.
#pragma once
#include <cstdint>
#include <string>
#include "dvc_bits.hpp"
#include "dvc_cache.hpp"

namespace ilo2 {

class DvcDecoder {
public:
    DvcDecoder() {
        for (int i = 0; i < 4096; ++i) color_remap_table[i] = dvc_color_remap(i);
        for (int i = 0; i < 48; ++i) next_1_[i] = NEXT_1_INIT[i];
        // bits/cache ctors already set state to cim's initial values.
    }
    virtual ~DvcDecoder() = default;

    // Feed one decrypted DVC byte. Returns true to stay in DVC mode (always true,
    // matching cim.process_dvc; on FSM exit it latches state 38 and re-syncs).
    bool process_dvc(uint8_t c) {
        int n = inhibit ? 0 : process_bits(c);
        if (n != 0) {
            bits.decoder_state = 38;
            bits.next_state = 38;
            fatal_count = 0;
            on_refresh_screen();
        }
        return true;
    }

    // ---- observable decoder state (public so harnesses can snapshot it) ----
    DvcBits  bits;
    DvcCache cache;

    int block[256]{};
    int pixel_count = 0;
    int last_color = 0;
    int color = 0;
    int lastx = 0, lasty = 0, newx = 0, newy = 0;
    int size_x = 0, size_y = 0, y_clipped = 0;
    int red = 0, green = 0, blue = 0;
    int scale_x = 1, scale_y = 1;
    int screen_x = 1, screen_y = 1;
    bool video_detected = true;

    int cmd_p_buff[256]{};
    int cmd_p_count = 0;
    int cmd_last = 0;
    int printchan = 0;
    std::string printstring;

    int  framerate = 30;
    int  fatal_count = 0;
    int64_t count_bytes = 0;
    int64_t timeout_count = 0;
    bool inhibit = false;
    bool seized = false;

    int color_remap_table[4096]{};
    int next_1_[48]{};

protected:
    // Rendering/GUI seams (default no-ops). Override to render or to record.
    virtual void on_paste(const int* /*block*/, int /*x*/, int /*y*/, int /*len*/) {}
    virtual void on_set_dimensions(int /*w*/, int /*h*/) {}
    virtual void on_show_text(const std::string& /*s*/) {}
    virtual void on_set_status(int /*field*/, const std::string& /*s*/) {}
    virtual void on_print(const std::string& /*s*/) {}
    virtual void on_repaint() {}
    virtual void on_refresh_screen() {}
    virtual void on_change_key() {}
    virtual void on_server_screen(int /*w*/, int /*h*/) {}
    virtual void on_firmware(int /*cmd*/) {}   // cmd 7 startRdp / cmd 8 stop_rdp
    // cim cmd 10 -> telnet.seize(): shows a message then drops the session.
    virtual void on_seize() { on_show_text("Session Acquired by another user."); seized = true; }

    void set_framerate(int n) { framerate = n; /* cim also: screen.set_framerate + status */ }
    void sync_next1() { next_1_[31] = cache.next_1_31; }
    void show_error(const char*) {}

    // Append `count` copies of last_color to the block; on overflow latch state 38.
    bool emit_run(int count, const char* where) {
        for (int i = 0; i < count; ++i) {
            if (pixel_count >= 256) { show_error(where); bits.next_state = 38; return false; }
            block[pixel_count++] = last_color;
        }
        return true;
    }

    // cim.next_block(count): (optionally) fill the y-clipped tail, blit the tile
    // to (lastx*16, lasty*16), advancing across `count` horizontal tiles until
    // the row ends. Sets next_state = 1 (START).
    void next_block(int count) {
        bool paint = video_detected;
        if (pixel_count != 0 && y_clipped > 0 && lasty == size_y) {
            int fill = color_remap_table[0];
            for (int i = y_clipped; i < 256; ++i) block[i] = fill;
        }
        pixel_count = 0;
        bits.next_state = 1;
        int x = lastx * 16;
        int y = lasty * 16;
        while (count != 0) {
            if (paint) on_paste(block, x, y, 16);
            x += 16;
            if (++lastx >= size_x) break;
            --count;
        }
    }

    int process_bits(uint8_t c) {
        int& state = bits.decoder_state;
        int& next  = bits.next_state;
        int& code  = bits.code;

        bits.add_bits(c);          // may redirect state->HUNT(43) on reset marker
        ++count_bytes;

        int n = 0;
        while (n == 0) {
            int need = bits_to_read[state];
            if (need > bits.ib_bcnt) { n = 0; break; }     // wait for more bytes
            bits.get_bits(need);
            next = (code == 0) ? next_0[state] : next_1_[state];

            switch (state) {
                case 3: case 4: case 5: case 6: case 7: case 32: {
                    if (cache.cc_active == 1)      code = cache.cc_usage[0];
                    else if (state == 4)           code = 0;
                    else if (state == 3)           code = 1;
                    else if (code != 0)            ++code;
                    int col = cache.cache_find(code); sync_next1();
                    if (col == -1) { show_error("LRU"); next = 38; break; }
                    last_color = color_remap_table[col];
                    if (pixel_count >= 256) { next = 38; break; }
                    block[pixel_count++] = last_color;
                    break;
                }
                case 12: {
                    if (code == 7) { next = 14; break; }
                    if (code == 6) { next = 13; break; }
                    code += 2;
                    emit_run(code, "block2");
                    break;
                }
                case 13: code += 8; [[fallthrough]];
                case 14: emit_run(code, "block3"); break;
                case 33:
                    if (pixel_count >= 256) { show_error("block4"); next = 38; break; }
                    block[pixel_count++] = last_color;
                    break;

                case 1: case 2: case 10: case 11: case 22: case 28: case 31: case 36:
                    break;
                case 35: next = cache.pixcode; break;

                case 9:  red = code << 8; break;
                case 41: green = code << 4; break;
                case 8:  red = code << 8; green = code << 4; [[fallthrough]];
                case 42: {
                    blue = code;
                    color = red | green | blue;
                    int hit = cache.cache_lru(color); sync_next1();
                    if (hit != 0) { show_error("hit"); next = 38; break; }
                    last_color = color_remap_table[color];
                    if (pixel_count >= 256) { next = 38; break; }
                    block[pixel_count++] = last_color;
                    break;
                }

                case 17: case 26:
                    newx = code;
                    if (state == 17 && newx > size_x) newx = 0;
                    break;
                case 39:
                    newy = code & 0x7F;
                    lastx = newx; lasty = newy;
                    if (lasty > size_y) lasty = 0;
                    on_repaint();
                    break;
                case 20: code = lastx + code + 1; [[fallthrough]];
                case 21:
                    lastx = code & 0x7F;
                    if (lastx > size_x) lastx = 0;
                    break;

                case 27:
                    if (timeout_count == count_bytes - 1) { show_error("double timeout"); next = 38; }
                    if ((bits.ib_bcnt & 7) != 0) bits.get_bits(bits.ib_bcnt & 7);
                    timeout_count = count_bytes;
                    on_repaint();
                    break;

                case 24:
                    if (cmd_p_count != 0) cmd_p_buff[cmd_p_count - 1] = cmd_last;
                    ++cmd_p_count;
                    cmd_last = code;
                    break;
                case 46: {
                    if (code != 0) break;
                    switch (cmd_last) {
                        case 1: next = 37; break;
                        case 2: next = 44; break;
                        case 3: set_framerate(cmd_p_count != 0 ? cmd_p_buff[0] : 0); break;
                        case 4: case 5: break;
                        case 6: on_show_text("Video suspended");
                                on_set_status(2, "Video_suspended");
                                screen_x = 640; screen_y = 100; break;
                        case 7: on_firmware(7); break;
                        case 8: on_firmware(8); break;
                        case 9: if ((bits.ib_bcnt & 7) != 0) bits.get_bits(bits.ib_bcnt & 7);
                                on_change_key(); break;
                        case 10: on_seize(); break;
                        default: break;
                    }
                    cmd_p_count = 0;
                    break;
                }
                case 44: printchan = code; printstring.clear(); break;
                case 45: {
                    if (code != 0) { printstring += static_cast<char>(code); break; }
                    switch (printchan) {
                        case 1: case 2: on_set_status(2 + printchan, printstring); break;
                        case 3: on_print(printstring); break;
                        case 4: on_show_text(printstring); break;
                    }
                    next = 1;
                    break;
                }

                case 15: case 16: case 18: case 19: case 23: case 25:
                    break;

                case 0:
                    cache.cache_reset();
                    pixel_count = 0; lastx = 0; lasty = 0;
                    red = 0; green = 0; blue = 0;
                    fatal_count = 0; timeout_count = -1; cmd_p_count = 0;
                    break;

                case 38:
                    if (fatal_count == 11680) on_refresh_screen();
                    if (++fatal_count == 120000) on_refresh_screen();
                    if (fatal_count != 12000000) break;
                    on_refresh_screen(); fatal_count = 41; break;

                case 34: next_block(1); break;
                case 29: code += 2; [[fallthrough]];
                case 30: next_block(code); break;
                case 40: size_x = newx; size_y = code; break;

                case 47: {
                    lastx = 0; lasty = 0; pixel_count = 0; cache.cache_reset();
                    scale_x = 1; scale_y = 1;
                    screen_x = size_x * 16;
                    screen_y = size_y * 16 + code;
                    video_detected = (screen_x != 0 && screen_y != 0);
                    y_clipped = code > 0 ? 256 - 16 * code : 0;
                    if (!video_detected) {
                        on_show_text("No Video");
                        on_set_status(2, "No Video");
                        screen_x = 640; screen_y = 100;
                        break;
                    }
                    on_set_dimensions(screen_x, screen_y);
                    on_server_screen(screen_x, screen_y);
                    on_set_status(2, " Video:" + std::to_string(screen_x) + "x" + std::to_string(screen_y));
                    break;
                }
                case 43:
                    if (next == state) break;
                    bits.ib_bcnt = 0; bits.ib_acc = 0; bits.zero_count = 0; count_bytes = 0;
                    break;
                case 37: return 1;
            }

            if (next == 2 && pixel_count == 256) { next_block(1); cache.cache_prune(); sync_next1(); }
            if (state == next && state != 45 && state != 38 && state != 43) { n = 6; continue; }
            state = next;
        }
        return n;
    }

    // --- the three transition tables (verbatim from cim) ---
    static constexpr int bits_to_read[48] = {
        0,1,1,1,1,1,2,3,4,4,1,1,3,3,8,1,1,7,1,1,3,7,1,1,8,1,7,0,1,3,7,1,4,0,0,0,1,0,1,7,7,4,4,1,8,8,1,4};
    static constexpr int next_0[48] = {
        1,2,31,2,2,10,10,10,10,41,2,33,2,2,2,16,19,39,22,20,1,1,34,25,46,26,40,1,29,1,1,36,10,2,1,35,8,37,38,1,47,42,10,43,45,45,1,1};
    static constexpr int NEXT_1_INIT[48] = {
        1,15,3,11,11,10,10,10,10,41,11,12,2,2,2,17,18,39,23,21,1,1,28,24,46,27,40,1,30,1,1,35,10,2,1,35,9,37,38,1,47,42,10,0,45,45,24,1};
};

} // namespace ilo2
