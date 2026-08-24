// test_bigint.cpp — the fixed-width bignum against Python's arbitrary-precision
// pow(m, e, n), including the REAL 1024-bit modulus from the iLO 2's
// certificate, which is the exact operand the TLS handshake will use.
#include <chrono>
#include <cstring>
#include <string>
#include "tests/test_util.hpp"
#include "crypto/bigint.hpp"

using namespace ilo2;

struct Vec { const char* m; uint32_t e; const char* n; const char* want; };

#include "tests/bigint_vectors.inc"

// Python formats integers with "%x": no leading zeros, and "0" for zero.
// Match that so the generated vectors can be compared as plain strings.
static std::string bn_hex(const RsaInt& x) {
    uint8_t buf[RsaInt::BYTES];
    x.to_bytes(buf);
    size_t i = 0;
    while (i + 1 < RsaInt::BYTES && buf[i] == 0) ++i;
    std::string s = t::hex(buf + i, RsaInt::BYTES - i);
    if (s.size() > 1 && s[0] == '0') s.erase(0, 1);
    return s;
}

static RsaInt bn_from_hex(const std::string& h) {
    std::string s = (h.size() % 2) ? ("0" + h) : h;
    auto b = t::unhex(s);
    RsaInt x;
    x.from_bytes(b.data(), b.size());
    return x;
}

static void run_vectors(const char* name, const Vec* v, size_t count) {
    std::printf("[%s]\n", name);
    for (size_t i = 0; i < count; ++i) {
        RsaInt m = bn_from_hex(v[i].m);
        RsaInt n = bn_from_hex(v[i].n);
        RsaInt r;
        if (!t::ok(RsaInt::modexp_u32(m, v[i].e, n, r), "modexp_u32 succeeded"))
            continue;
        char label[96];
        std::snprintf(label, sizeof(label), "%s[%zu]: m^%u mod n", name, i, v[i].e);
        t::eq(bn_hex(r), v[i].want, label);
    }
}

int main() {
    std::printf("[byte round-trips]\n");
    {
        RsaInt x;
        auto b = t::unhex("00bde79c0e220d27830ffa815173d9bf7d");   // leading zero, as in DER
        t::ok(x.from_bytes(b.data(), b.size()), "from_bytes tolerates a DER leading zero");
        t::eq(bn_hex(x), "bde79c0e220d27830ffa815173d9bf7d", "leading zero is not significant");

        // Oversized input that is not merely zero-padded must be rejected.
        std::vector<uint8_t> big(RsaInt::BYTES + 1, 0xAB);
        RsaInt y;
        t::ok(!y.from_bytes(big.data(), big.size()), "from_bytes rejects genuine overflow");

        // ... but an oversized buffer whose excess is zero is fine.
        std::vector<uint8_t> padded(RsaInt::BYTES + 4, 0x00);
        padded[RsaInt::BYTES + 3] = 0x2a;
        RsaInt z;
        t::ok(z.from_bytes(padded.data(), padded.size()), "from_bytes accepts zero padding");
        t::eq(bn_hex(z), "2a", "zero-padded value loads correctly");
    }

    std::printf("[bit_length]\n");
    {
        t::ok(bn_from_hex("0").bit_length() == 0,   "bit_length(0) == 0");
        t::ok(bn_from_hex("1").bit_length() == 1,   "bit_length(1) == 1");
        t::ok(bn_from_hex("ff").bit_length() == 8,  "bit_length(0xff) == 8");
        t::ok(bn_from_hex("100").bit_length() == 9, "bit_length(0x100) == 9");
        t::ok(bn_from_hex(ILO_MODULUS_HEX).bit_length() == 1024,
              "the iLO modulus is 1024 bits");
    }

    run_vectors("SMALL_VECTORS", SMALL_VECTORS, sizeof(SMALL_VECTORS) / sizeof(Vec));
    run_vectors("ILO_VECTORS",   ILO_VECTORS,   sizeof(ILO_VECTORS)   / sizeof(Vec));

    std::printf("[textbook RSA round-trip]\n");
    {
        // n=3233 (p=61,q=53), phi=3120, e=17, d=2753. Both exponents fit in a
        // uint32, so encrypt and decrypt can both go through modexp_u32 -- which
        // is why this codebase deliberately has NO big-exponent modexp: there is
        // no private key on the client side of an RSA key exchange, and not
        // providing one keeps a foot-gun out of the tree.
        RsaInt n = bn_from_hex("ca1");             // 3233
        for (uint32_t msg : {0u, 1u, 2u, 42u, 123u, 3232u}) {
            char h[16];
            std::snprintf(h, sizeof(h), "%x", msg);
            RsaInt m = bn_from_hex(h), c, back;
            RsaInt::modexp_u32(m, 17u, n, c);
            RsaInt::modexp_u32(c, 2753u, n, back);
            char label[64];
            std::snprintf(label, sizeof(label), "m=%u survives encrypt+decrypt", msg);
            t::eq(bn_hex(back), bn_hex(m), label);
        }
    }

    std::printf("[cost of one real key exchange]\n");
    {
        RsaInt n = bn_from_hex(ILO_MODULUS_HEX);
        RsaInt m = bn_from_hex(ILO_VECTORS[0].m), r;
        auto t0 = std::chrono::steady_clock::now();
        const int reps = 50;
        for (int i = 0; i < reps; ++i) RsaInt::modexp_u32(m, 65537u, n, r);
        auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                      std::chrono::steady_clock::now() - t0).count();
        std::printf("  17 modmuls on a 1024-bit modulus: %.2f ms each\n",
                    double(us) / reps / 1000.0);
        t::ok(true, "timing measured");
    }

    return t::report("test_bigint");
}
