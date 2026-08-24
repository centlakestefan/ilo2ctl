// bigint.hpp — fixed-width unsigned big integer, sized for RSA public-key ops.
//
// Scope is deliberately tiny. The only thing this has to do is compute
//     c = m^65537 mod n
// for the TLS RSA key exchange: one PKCS#1 v1.5 padded premaster, one public
// modulus, once per connection. e = 65537 = 2^16 + 1, so that is exactly 16
// modular squarings plus one modular multiply — 17 modmuls total.
//
// Consequences of that scope, all intentional:
//
//   * Reduction is plain BINARY long division (shift, compare, conditional
//     subtract). No Knuth algorithm D, no Montgomery form. Montgomery would
//     need n' = -n^-1 mod 2^32 and R^2 mod n to save time we do not need, and
//     both are more code to get wrong than the loop below.
//   * NO constant-time hardening, and none is required: the exponent is public
//     and fixed, so the square-and-multiply sequence is identical regardless of
//     the message. Classic RSA timing attacks recover a secret PRIVATE exponent;
//     there is no private key on this side of the handshake.
//   * No allocation, no exceptions, no dependencies.
//
// Limbs are little-endian (v[0] is least significant); bytes in and out are
// big-endian, which is what DER, PKCS#1 and the wire all use.
#pragma once
#include <cstdint>
#include <cstring>
#include <cstddef>

namespace ilo2 {

template <size_t BITS>
class BigInt {
public:
    static_assert(BITS % 32 == 0, "BITS must be a multiple of 32");
    static constexpr size_t LIMBS = BITS / 32;
    static constexpr size_t BYTES = BITS / 8;

    uint32_t v[LIMBS];

    BigInt() { zero(); }

    void zero() { std::memset(v, 0, sizeof(v)); }

    bool is_zero() const {
        for (size_t i = 0; i < LIMBS; ++i)
            if (v[i]) return false;
        return true;
    }

    // Big-endian load. Shorter inputs are left-zero-padded. Leading zero bytes
    // beyond the width are tolerated (a DER INTEGER carries one to stay
    // positive); anything longer than that is a genuine overflow -> false.
    bool from_bytes(const uint8_t* p, size_t len) {
        zero();
        while (len > BYTES && *p == 0) { ++p; --len; }
        if (len > BYTES) return false;
        for (size_t i = 0; i < len; ++i) {
            size_t sig = len - 1 - i;                    // 0 = least significant
            v[sig / 4] |= static_cast<uint32_t>(p[i]) << (8 * (sig % 4));
        }
        return true;
    }

    // Big-endian store, always exactly BYTES bytes (zero-padded on the left).
    void to_bytes(uint8_t* out) const {
        for (size_t i = 0; i < BYTES; ++i) {
            size_t sig = BYTES - 1 - i;
            out[i] = static_cast<uint8_t>(v[sig / 4] >> (8 * (sig % 4)));
        }
    }

    size_t bit_length() const { return bit_length_of(v, LIMBS); }

    static int cmp(const BigInt& a, const BigInt& b) {
        for (size_t i = LIMBS; i-- > 0; )
            if (a.v[i] != b.v[i]) return a.v[i] > b.v[i] ? 1 : -1;
        return 0;
    }
    bool operator==(const BigInt& o) const { return cmp(*this, o) == 0; }
    bool operator!=(const BigInt& o) const { return cmp(*this, o) != 0; }

    // c = m^e mod n for a small PUBLIC exponent, square-and-multiply MSB-first.
    // Generic in e rather than hard-coded to 65537: old certificates sometimes
    // carry e=3, and supporting them costs three lines.
    static bool modexp_u32(const BigInt& m, uint32_t e, const BigInt& n, BigInt& out) {
        if (n.is_zero() || e == 0) return false;
        BigInt base;
        mod_narrow(m.v, n.v, base.v);           // ensure base < n
        int top = 31;
        while (top > 0 && !((e >> top) & 1u)) --top;
        BigInt acc = base;                      // the top bit is always 1
        for (int i = top - 1; i >= 0; --i) {
            mulmod(acc.v, acc.v, n.v, acc.v);                       // square
            if ((e >> i) & 1u) mulmod(acc.v, base.v, n.v, acc.v);   // multiply
        }
        out = acc;
        return true;
    }

    // The TLS RSA key exchange case: e = 65537 = 2^16 + 1, so the loop above
    // runs 16 squarings and exactly one multiply -- 17 modmuls.
    static bool modexp_65537(const BigInt& m, const BigInt& n, BigInt& out) {
        return modexp_u32(m, 65537u, n, out);
    }

    // out = a * b mod n. Aliasing out with a or b is safe: the full product is
    // formed before any output limb is written.
    static void mulmod(const uint32_t* a, const uint32_t* b,
                       const uint32_t* n, uint32_t* out) {
        uint32_t wide[2 * LIMBS];
        mul_wide(a, b, wide);
        mod_wide(wide, n, out);
    }

private:
    static size_t bit_length_of(const uint32_t* p, size_t limbs) {
        for (size_t i = limbs; i-- > 0; ) {
            if (p[i]) {
                size_t b = 0;
                uint32_t x = p[i];
                while (x) { ++b; x >>= 1; }
                return i * 32 + b;
            }
        }
        return 0;
    }

    // out[2*LIMBS] = a[LIMBS] * b[LIMBS], schoolbook with a 64-bit accumulator.
    static void mul_wide(const uint32_t* a, const uint32_t* b, uint32_t* out) {
        std::memset(out, 0, 2 * LIMBS * sizeof(uint32_t));
        for (size_t i = 0; i < LIMBS; ++i) {
            if (!a[i]) continue;
            uint64_t carry = 0;
            for (size_t j = 0; j < LIMBS; ++j) {
                uint64_t t = static_cast<uint64_t>(a[i]) * b[j] + out[i + j] + carry;
                out[i + j] = static_cast<uint32_t>(t);
                carry = t >> 32;
            }
            for (size_t k = i + LIMBS; carry && k < 2 * LIMBS; ++k) {
                uint64_t t = static_cast<uint64_t>(out[k]) + carry;
                out[k] = static_cast<uint32_t>(t);
                carry = t >> 32;
            }
        }
    }

    // r[LIMBS] = wide[2*LIMBS] mod n[LIMBS].
    //
    // The accumulator needs one limb of headroom: it is kept < n, but the shift
    // that brings the next bit down can transiently reach 2n-1, which for a
    // modulus with its top bit set (every real RSA modulus) does not fit in
    // LIMBS limbs. Iteration starts at the true bit length of `wide`, so a
    // 1024-bit modulus in a 2048-bit type costs 1024-bit work, not 2048-bit.
    static void mod_wide(const uint32_t* wide, const uint32_t* n, uint32_t* r) {
        uint32_t acc[LIMBS + 1];
        std::memset(acc, 0, sizeof(acc));
        size_t top = bit_length_of(wide, 2 * LIMBS);
        for (size_t bit = top; bit-- > 0; ) {
            uint32_t carry = 0;                                  // acc <<= 1
            for (size_t i = 0; i < LIMBS + 1; ++i) {
                uint32_t next = acc[i] >> 31;
                acc[i] = (acc[i] << 1) | carry;
                carry = next;
            }
            acc[0] |= (wide[bit / 32] >> (bit % 32)) & 1u;       // bring bit down
            if (cmp_ext(acc, n) >= 0) sub_ext(acc, n);           // conditional subtract
        }
        std::memcpy(r, acc, LIMBS * sizeof(uint32_t));
    }

    static void mod_narrow(const uint32_t* a, const uint32_t* n, uint32_t* out) {
        uint32_t wide[2 * LIMBS];
        std::memset(wide, 0, sizeof(wide));
        std::memcpy(wide, a, LIMBS * sizeof(uint32_t));
        mod_wide(wide, n, out);
    }

    // Compare an (LIMBS+1)-limb accumulator against an LIMBS-limb modulus.
    static int cmp_ext(const uint32_t* acc, const uint32_t* n) {
        if (acc[LIMBS]) return 1;
        for (size_t i = LIMBS; i-- > 0; )
            if (acc[i] != n[i]) return acc[i] > n[i] ? 1 : -1;
        return 0;
    }

    static void sub_ext(uint32_t* acc, const uint32_t* n) {
        uint64_t borrow = 0;
        for (size_t i = 0; i < LIMBS; ++i) {
            uint64_t d = static_cast<uint64_t>(acc[i]) - n[i] - borrow;
            acc[i] = static_cast<uint32_t>(d);
            borrow = (d >> 32) ? 1 : 0;
        }
        acc[LIMBS] -= static_cast<uint32_t>(borrow);
    }
};

// The iLO 2's certificate is 1024-bit RSA; 2048 gives headroom if the cert is
// ever regenerated, and mod_wide's leading-zero skip keeps the 1024-bit case
// paying only 1024-bit cost.
using RsaInt = BigInt<2048>;

} // namespace ilo2
