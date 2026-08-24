// test_crypto.cpp — validates the C++ RC4/MD5 ports.
//
//  1. MD5 against known RFC/standard test vectors.
//  2. RC4 keystream (initial + after one rekey) printed as hex, to be diffed
//     against the real Java classes via KeystreamDump.java.
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

    RC4 r(seed);
    uint8_t ks1[32];
    for (int i = 0; i < 32; ++i) ks1[i] = r.randomValue();
    printf("[RC4] initial   %s\n", hex(ks1, 32).c_str());

    r.update_key();  // rekey (TELNET_CHG_ENCRYPT_KEYS)
    uint8_t ks2[32];
    for (int i = 0; i < 32; ++i) ks2[i] = r.randomValue();
    printf("[RC4] post-rekey %s\n", hex(ks2, 32).c_str());

    printf("\n%s\n", fails ? "MD5 VECTORS FAILED" : "MD5 vectors passed.");
    printf("Compare the two [RC4] lines against KeystreamDump.java output.\n");
    return fails ? 1 : 0;
}
