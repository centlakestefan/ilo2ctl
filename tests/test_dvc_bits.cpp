// test_dvc_bits.cpp — validates dvc_bits.hpp against the real cim bit reader.
//
// The expected values are HP's, recorded from com.hp.ilo2.remcons.cim by
// tests/DvcBitsProbe.java: the reversal/left/right tables as the frozen
// fixture tests/oracle/dvc_tables.txt, and the two short traces below as the
// literals the probe printed. The test asserts against them, so it needs
// neither Java nor the jar.
#include <cstdio>
#include <string>
#include "tests/test_util.hpp"
#include "ilo/dvc_bits.hpp"

using namespace ilo2;

static std::string tables(const DvcBits& b) {
    std::string s;
    char buf[16];
    auto row = [&](const auto& tbl) {
        for (int i = 0; i < 256; ++i) {
            std::snprintf(buf, sizeof buf, "%d%c", tbl[i], i == 255 ? '\n' : ' ');
            s += buf;
        }
    };
    row(b.reversal); row(b.left); row(b.right);
    return s;
}

int main() {
    DvcBits b;                 // ctor runs init_reversal()

    t::eq_oracle(tables(b), "dvc_tables");

    // --- get_bits read sequence: 3 bytes (24 bits), widths summing to 24 ---
    b.ib_acc = 0; b.ib_bcnt = 0; b.zero_count = 0; b.decoder_state = 1;
    b.add_bits(0xB3); b.add_bits(0x4D); b.add_bits(0xF0);
    const int widths[] = {1, 2, 3, 4, 1, 5, 8};
    std::string reads;
    for (int w : widths) {
        b.get_bits(w);
        if (!reads.empty()) reads += ' ';
        reads += std::to_string(b.code);
    }
    // DvcBitsProbe.java: "java_reads 1 2 3 6 1 18 15"
    t::eq(reads, "1 2 3 6 1 18 15", "get_bits read sequence vs cim");

    // --- zero-run reset: 0x81 then four 0x00 (31+ zero bits -> ret 4) ---
    b.ib_acc = 0; b.ib_bcnt = 0; b.zero_count = 0; b.decoder_state = 1; b.next_state = 1;
    const uint8_t stream[] = {0x81, 0x00, 0x00, 0x00, 0x00};
    std::string zeros;
    for (uint8_t c : stream) {
        int r = b.add_bits(c);
        if (!zeros.empty()) zeros += ' ';
        zeros += "r=" + std::to_string(r) + "/zc=" + std::to_string(b.zero_count);
    }
    // DvcBitsProbe.java: "java_zeros r=0/zc=0 r=0/zc=8 r=0/zc=16 r=0/zc=24 r=4/zc=32"
    t::eq(zeros, "r=0/zc=0 r=0/zc=8 r=0/zc=16 r=0/zc=24 r=4/zc=32",
          "zero-run reset trace vs cim");

    return t::report("test_dvc_bits");
}
