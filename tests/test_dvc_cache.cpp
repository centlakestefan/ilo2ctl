// test_dvc_cache.cpp — validates dvc_cache.hpp against the real cim.
//
// Both expected traces are HP's, recorded from com.hp.ilo2.remcons.cim by
// tests/DvcCacheProbe.java and frozen as tests/oracle/remap.txt (the full
// 4096-entry colour remap) and tests/oracle/cache.txt (a per-op LRU trace).
// The op script below is identical to the probe's, so the two line up 1:1.
#include <cstdio>
#include <string>
#include "tests/test_util.hpp"
#include "ilo/dvc_cache.hpp"

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

static std::string remap_table() {
    std::string s;
    char buf[16];
    for (int i = 0; i < 4096; ++i) {
        std::snprintf(buf, sizeof buf, "%d%c", dvc_color_remap(i), i == 4095 ? '\n' : ' ');
        s += buf;
    }
    return s;
}

static std::string cache_trace() {
    DvcCache c;
    std::string s;
    char buf[512];
    for (int i = 0; i < NOPS; ++i) {
        char type = OPT[i]; int arg = OPA[i]; int ret = 0; std::string label;
        switch (type) {
            case 'R': c.cache_reset();         label = "R";                          break;
            case 'L': ret = c.cache_lru(arg);  label = "L" + std::to_string(arg);     break;
            case 'F': ret = c.cache_find(arg); label = "F" + std::to_string(arg);     break;
            case 'P': c.cache_prune();         label = "P";                          break;
        }
        std::snprintf(buf, sizeof buf, "%s a=%d pc=%d n31=%d ret=%d C=%s U=%s B=%s\n",
                      label.c_str(), c.cc_active, c.pixcode, c.next_1_31, ret,
                      join(c.cc_color, c.cc_active).c_str(),
                      join(c.cc_usage, c.cc_active).c_str(),
                      join(c.cc_block, c.cc_active).c_str());
        s += buf;
    }
    return s;
}

int main() {
    t::eq_oracle(remap_table(), "remap");
    t::eq_oracle(cache_trace(), "cache");
    return t::report("test_dvc_cache");
}
