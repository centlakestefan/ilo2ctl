// test_dvc_cache.cpp — validates dvc_cache.hpp against the real cim.
//
// Writes color_remap to build/remap_cpp.txt and a per-op LRU-cache trace to
// build/cache_cpp.txt, to be diffed against DvcCacheProbe.java.
#include <cstdio>
#include <string>
#include "dvc_cache.hpp"

using namespace ilo2;

// Shared op script (identical in the Java oracle). Types: R reset, L lru,
// F find, P prune. Exercises grow, hit, eviction at 17, find, prune.
static const char OPT[] = {
    'R',
    'L','L','L','L','L','L',            // 0x100 0x200 0x300 0x200(hit) 0x400 0x500
    'F','F','L','P','L','F','P',        // find0 find2 lru0x100 prune lru0x600 find1 prune
    'R',
    'L','L','L','L','L','L','L','L','L','L','L','L','L','L','L','L','L', // 17 inserts 1..17
    'L',                                // 0x99 eviction
    'F','F','P'                         // find16 find0 prune
};
static const int OPA[] = {
    0,
    0x100,0x200,0x300,0x200,0x400,0x500,
    0,2,0x100,0,0x600,1,0,
    0,
    1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,
    0x99,
    16,0,0
};
static const int NOPS = sizeof(OPT) / sizeof(OPT[0]);

static std::string join(const int* a, int n) {
    std::string s;
    for (int i = 0; i < n; ++i) { if (i) s += ','; s += std::to_string(a[i]); }
    return s;
}

int main() {
    // color_remap full table
    if (FILE* f = std::fopen("build/remap_cpp.txt", "wb")) {
        for (int i = 0; i < 4096; ++i) std::fprintf(f, "%d%c", dvc_color_remap(i), i == 4095 ? '\n' : ' ');
        std::fclose(f);
    }

    DvcCache c;
    FILE* out = std::fopen("build/cache_cpp.txt", "wb");
    if (!out) { std::fprintf(stderr, "cannot write cache trace\n"); return 2; }

    for (int i = 0; i < NOPS; ++i) {
        char t = OPT[i]; int arg = OPA[i]; int ret = 0; std::string label;
        switch (t) {
            case 'R': c.cache_reset();        label = "R";                    break;
            case 'L': ret = c.cache_lru(arg); label = "L" + std::to_string(arg); break;
            case 'F': ret = c.cache_find(arg);label = "F" + std::to_string(arg); break;
            case 'P': c.cache_prune();         label = "P";                    break;
        }
        std::fprintf(out, "%s a=%d pc=%d n31=%d ret=%d C=%s U=%s B=%s\n",
                     label.c_str(), c.cc_active, c.pixcode, c.next_1_31, ret,
                     join(c.cc_color, c.cc_active).c_str(),
                     join(c.cc_usage, c.cc_active).c_str(),
                     join(c.cc_block, c.cc_active).c_str());
    }
    std::fclose(out);
    printf("wrote build/cache_cpp.txt (%d ops) and build/remap_cpp.txt\n", NOPS);
    return 0;
}
