// dvc_bits.hpp — C++ port of the cim DVC bit reader.
//
// Faithful reimplementation of the bit-level primitives from
// com.hp.ilo2.remcons.cim: init_reversal(), add_bits(), get_bits(), and the
// getmask/reversal/left/right tables. These feed the 48-state decoder FSM
// (ported separately). Field names track the cim `dvc_*` statics; here they are
// instance members (the Java decoder used one global instance per session).
//
// Bit model (matches cim exactly):
//   * add_bits(c): OR the 8 bits of c into the accumulator at bit offset bcnt
//     (little-endian), bcnt += 8. Track consecutive zero bits via right[]/left[]
//     and, on 31+ zeros, flag the reset marker (state HUNT=43) and return 4.
//   * get_bits(n): take the low n bits (LSB-first), bit-reverse them via
//     reversal[] and right-align, leaving the MSB-first field value in `code`.
#pragma once
#include <cstdint>

namespace ilo2 {

class DvcBits {
public:
    // HUNT state id, as in cim (reset marker detected).
    static constexpr int HUNT = 43;

    DvcBits() { init_reversal(); }

    // cim.init_reversal(): 8-bit reverse table + leading/trailing zero-run
    // indices used by add_bits' reset detector.
    void init_reversal() {
        for (int n = 0; n < 256; ++n) {
            int n2 = 8, n3 = 8, n4 = n, n5 = 0;
            for (int n6 = 0; n6 < 8; ++n6) {
                n5 <<= 1;
                if ((n4 & 1) == 1) {
                    if (n2 > n6) n2 = n6;
                    n5 |= 1;
                    n3 = 7 - n6;
                }
                n4 >>= 1;
            }
            reversal[n] = n5;   // 8-bit mirror of n
            right[n]    = n2;   // index of lowest set bit (8 if none) -> trailing zeros
            left[n]     = n3;   // 7 - index of highest set bit (8 if none) -> leading zeros
        }
    }

    // cim.add_bits(char): returns 0 normally, 4 when the reset sequence
    // (31+ consecutive zero bits) is detected.
    int add_bits(uint8_t c) {
        ib_acc |= static_cast<uint32_t>(c) << ib_bcnt;
        ib_bcnt += 8;
        zero_count += right[c];
        if (zero_count > 30) {
            next_state = HUNT;
            decoder_state = HUNT;
            return 4;
        }
        if (c != 0) zero_count = left[c];
        return 0;
    }

    // cim.get_bits(int): consume n bits, set `code` to the reversed/aligned value.
    int get_bits(int n) {
        if (n == 1) {
            code = ib_acc & 1u;
            ib_acc >>= 1;
            --ib_bcnt;
            return 0;
        }
        if (n == 0) return 0;
        uint32_t v = ib_acc & getmask[n];
        ib_bcnt -= n;
        ib_acc >>= n;
        v = reversal[v];
        code = v >> (8 - n);
        return 0;
    }

    // --- decoder-visible state (names track cim's dvc_* fields) ---
    uint32_t ib_acc = 0;      // dvc_ib_acc
    int      ib_bcnt = 0;     // dvc_ib_bcnt
    int      zero_count = 0;  // dvc_zero_count
    int      code = 0;        // dvc_code
    int      decoder_state = 0; // dvc_decoder_state
    int      next_state = 0;    // dvc_next_state

    int reversal[256]{};
    int left[256]{};
    int right[256]{};

    // dvc_getmask: (1<<n)-1 for n=0..8
    static constexpr uint32_t getmask[9] = {0, 1, 3, 7, 15, 31, 63, 127, 255};
};

} // namespace ilo2
