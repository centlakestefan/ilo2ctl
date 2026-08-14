// dvc_cache.hpp — C++ port of the cim DVC color pipeline: the RGB444->ARGB
// remap and the 17-entry LRU color cache (cache_reset/lru/find/prune).
//
// Faithful to com.hp.ilo2.remcons.cim. In the applet these were private-static
// (one global decoder); here they are instance state. `pixcode` and `next_1_31`
// mirror cim's dvc_pixcode and next_1[31]: cache_lru/prune recompute the pixel
// decoder state selected by the current palette size (PIXFAN dispatch). When the
// full FSM is assembled, next_1_31 becomes next_1[31] of the shared table.
#pragma once
#include <cstdint>

namespace ilo2 {

// cim: color_remap_table[i] = (i&0xF00)*4352 + (i&0xF0)*272 + (i&0xF)*17.
// Expands each 4-bit channel to 8 bits (nibble*0x11) -> 0x00RRGGBB.
inline int dvc_color_remap(int i) {
    return (i & 0xF00) * 4352 + (i & 0xF0) * 272 + (i & 0xF) * 17;
}

class DvcCache {
public:
    int cc_active = 0;
    int cc_color[17]{};
    int cc_usage[17]{};
    int cc_block[17]{};
    int pixcode   = 38;   // dvc_pixcode static-init
    int next_1_31 = 35;   // next_1[31] table value

    void cache_reset() { cc_active = 0; }

    // Recompute the PIXFAN target from the active palette size (cim's inline expr).
    void update_pixcode() {
        int a = cc_active;
        pixcode = a < 2 ? 38 : (a == 2 ? 4 : (a == 3 ? 5 : (a < 6 ? 6 : (a < 10 ? 7 : 32))));
        next_1_31 = pixcode;
    }

    // cache_lru(color): insert/promote a color. Returns 1 if it was already
    // present (a "hit"), 0 if newly inserted or LRU-evicted.
    int cache_lru(int color) {
        int active = cc_active;
        int slot = 0, found = 0;
        for (int k = 0; k < active; ++k) {
            if (color == cc_color[k]) { slot = k; found = 1; break; }
            if (cc_usage[k] == active - 1) slot = k;   // LRU eviction candidate
        }
        int aged_below = cc_usage[slot];
        if (found == 0) {
            if (active < 17) {
                slot = active;
                aged_below = active;
                active += 1;
                cc_active = active;
                update_pixcode();
            }
            cc_color[slot] = color;
        }
        cc_block[slot] = 1;
        for (int k = 0; k < active; ++k)
            if (cc_usage[k] < aged_below) ++cc_usage[k];
        cc_usage[slot] = 0;
        return found;
    }

    // cache_find(rank): return the color at LRU rank `rank`, promote it to front.
    // Returns -1 if no entry currently holds that rank.
    int cache_find(int rank) {
        int active = cc_active;
        for (int k = 0; k < active; ++k) {
            if (rank == cc_usage[k]) {
                int color = cc_color[k];
                int slot = k;
                for (int j = 0; j < active; ++j)
                    if (cc_usage[j] < rank) ++cc_usage[j];
                cc_usage[slot] = 0;
                cc_block[slot] = 1;
                return color;
            }
        }
        return -1;
    }

    // cache_prune(): drop entries not touched this block (block flag 0), compact
    // by moving the last entry into the hole; decrement survivors' block flags.
    void cache_prune() {
        int n = cc_active;
        int k = 0;
        while (k < n) {
            if (cc_block[k] == 0) {
                --n;
                cc_block[k] = cc_block[n];
                cc_color[k] = cc_color[n];
                cc_usage[k] = cc_usage[n];
                // recheck the moved entry (no k++)
            } else {
                cc_block[k] = cc_block[k] - 1;
                ++k;
            }
        }
        cc_active = n;
        update_pixcode();
    }
};

} // namespace ilo2
