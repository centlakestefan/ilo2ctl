// test_crypto.cpp — validates the C++ RC4/MD5 ports.
//
//  1. MD5 against known RFC/standard test vectors.
//  2. RC4 keystream (initial + after one rekey) against the keystream HP's own
//     RC4 class produced, recorded by tests/KeystreamDump.java.
#include <cstdio>
#include <cstring>
#include <string>
#include "crypto/rc4.hpp"
#include "crypto/md5.hpp"

using namespace ilo2;

static std::string hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 0xF]; }
    return s;
}

static std::string md5hex(const std::string& in) {
    MD5 m;
    m.update(reinterpret_cast<const uint8_t*>(in.data()), in.size());
    auto d = m.digest();
    return hex(d.data(), d.size());
}

int main() {
    int fails = 0;

    // ---- MD5 known-answer tests ----
    struct { const char* in; const char* want; } mv[] = {
        {"",    "d41d8cd98f00b204e9800998ecf8427e"},
        {"abc", "900150983cd24fb0d6963f7d28e17f72"},
        {"message digest", "f96b697d7cb7938d525a2f31aaf161d0"},
        {"The quick brown fox jumps over the lazy dog",
         "9e107d9d372bb6826bd81d3542a419d6"},
    };
    for (auto& t : mv) {
        std::string got = md5hex(t.in);
        bool ok = (got == t.want);
        fails += !ok;
        printf("[MD5] %-45s %s %s\n", t.in, got.c_str(), ok ? "OK" : "FAIL");
    }

    // ---- RC4 keystream (same seed as KeystreamDump.java: byte i*17+3) ----
    uint8_t seed[16];
    for (int i = 0; i < 16; ++i) seed[i] = static_cast<uint8_t>(i * 17 + 3);

    // Expected keystreams are HP's, recorded from com.hp.ilo2.remcons.RC4 by
    // tests/KeystreamDump.java using this same seed. Pinning them keeps both
    // the standard KSA/PRGA and HP's own MD5 rekey derivation tied to the
    // applet's real behaviour without needing Java or the jar.
    struct { const char* what; const char* want; } rv[] = {
        {"RC4 keystream, initial",
         "bb6b156f15af631d4bc5dbaeda7e92f20f3dd84d544ba1dabefd80adb0a59255"},
        {"RC4 keystream, after update_key()",
         "3627de4f6abf540c9594025d780f8dda28a89b624b13b6c380b2c53ca69adf28"},
    };

    RC4 r(seed);
    uint8_t ks[32];
    for (int i = 0; i < 32; ++i) ks[i] = r.randomValue();
    std::string got = hex(ks, 32);
    bool ok1 = (got == rv[0].want);
    fails += !ok1;
    printf("[RC4] initial    %s %s\n", got.c_str(), ok1 ? "OK" : "FAIL");
    if (!ok1) printf("      want       %s\n", rv[0].want);

    r.update_key();  // rekey (TELNET_CHG_ENCRYPT_KEYS)
    for (int i = 0; i < 32; ++i) ks[i] = r.randomValue();
    got = hex(ks, 32);
    bool ok2 = (got == rv[1].want);
    fails += !ok2;
    printf("[RC4] post-rekey %s %s\n", got.c_str(), ok2 ? "OK" : "FAIL");
    if (!ok2) printf("      want       %s\n", rv[1].want);

    printf("\ntest_crypto: %s\n", fails ? "FAILED" : "all passed");
    return fails ? 1 : 0;
}
