// test_dvc_bits.cpp — validates dvc_bits.hpp against the real cim bit reader
// (via DvcBitsProbe.java, which reflects into com.hp.ilo2.remcons.cim).
//
// Emits: the reversal/left/right tables to build/dvc_tables_cpp.txt, plus a
// get_bits read sequence and a zero-run reset trace on stdout, for comparison
// with the Java oracle.
#include <cstdio>
#include "ilo/dvc_bits.hpp"

using namespace ilo2;

static void dump_tables(const DvcBits& b) {
    FILE* f = std::fopen("build/dvc_tables_cpp.txt", "wb");
    if (!f) { std::fprintf(stderr, "cannot write tables\n"); return; }
    for (int i = 0; i < 256; ++i) std::fprintf(f, "%d%c", b.reversal[i], i == 255 ? '\n' : ' ');
    for (int i = 0; i < 256; ++i) std::fprintf(f, "%d%c", b.left[i],     i == 255 ? '\n' : ' ');
    for (int i = 0; i < 256; ++i) std::fprintf(f, "%d%c", b.right[i],    i == 255 ? '\n' : ' ');
    std::fclose(f);
}

int main() {
    DvcBits b;                 // ctor runs init_reversal()
    dump_tables(b);

    // --- get_bits read sequence: 3 bytes (24 bits), widths summing to 24 ---
    b.ib_acc = 0; b.ib_bcnt = 0; b.zero_count = 0; b.decoder_state = 1;
    b.add_bits(0xB3); b.add_bits(0x4D); b.add_bits(0xF0);
    const int widths[] = {1, 2, 3, 4, 1, 5, 8};
    printf("cpp_reads");
    for (int w : widths) { b.get_bits(w); printf(" %d", b.code); }
    printf("\n");

    // --- zero-run reset: 0x81 then four 0x00 (31+ zero bits -> ret 4) ---
    b.ib_acc = 0; b.ib_bcnt = 0; b.zero_count = 0; b.decoder_state = 1; b.next_state = 1;
    const uint8_t stream[] = {0x81, 0x00, 0x00, 0x00, 0x00};
    printf("cpp_zeros");
    for (uint8_t c : stream) { int r = b.add_bits(c); printf(" r=%d/zc=%d", r, b.zero_count); }
    printf("\n");
    return 0;
}
