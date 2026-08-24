// rsa.hpp — RSA public-key encryption, PKCS#1 v1.5 type 2.
//
// One job: wrap the TLS premaster secret under the server certificate's public
// key for a TLS_RSA_* key exchange. Encryption only — there is no private key on
// the client side of an RSA key exchange, so there is no decryption, no CRT and
// no blinding here. (crypto/bigint.hpp deliberately offers no big-exponent
// modexp either: without one, this tree cannot be casually misused to perform a
// private-key operation with no side-channel protection.)
//
// Padding and the modular exponentiation are kept as separate entry points so
// each can be tested on its own — the padding for structure, the public op
// against reference vectors.
#pragma once
#include <cstdint>
#include <cstring>
#include <vector>
#include "crypto/bigint.hpp"
#include "crypto/random.hpp"

namespace ilo2 {

struct RsaPublicKey {
    RsaInt   n;
    uint32_t e = 0;
    size_t   k = 0;                 // modulus size in bytes (128 for RSA-1024)

    bool valid() const {
        return k >= 64 && k <= RsaInt::BYTES && e >= 3 && !n.is_zero();
    }
};

// EM = 0x00 || 0x02 || PS || 0x00 || M, with |EM| = k and PS at least 8 nonzero
// random bytes. Returns false if the message cannot fit with legal padding, or
// if the system CSPRNG fails.
inline bool pkcs1v15_pad_type2(size_t k, const uint8_t* msg, size_t mlen,
                               std::vector<uint8_t>& em) {
    if (k < 12 || mlen + 11 > k) return false;      // needs >= 8 padding bytes

    const size_t pslen = k - mlen - 3;
    em.assign(k, 0);
    em[0] = 0x00;
    em[1] = 0x02;
    if (!secure_random(em.data() + 2, pslen)) return false;
    // No byte of PS may be zero: a zero would be taken for the 0x00 separator
    // and would truncate the recovered message. Resample the offending byte
    // rather than rejecting and redrawing the whole string.
    for (size_t i = 0; i < pslen; ++i)
        while (em[2 + i] == 0)
            if (!secure_random(&em[2 + i], 1)) return false;
    em[2 + pslen] = 0x00;
    if (mlen) std::memcpy(em.data() + 3 + pslen, msg, mlen);
    return true;
}

// c = m^e mod n, emitted as exactly k big-endian bytes (leading zeros kept).
inline bool rsa_public_op(const RsaPublicKey& key,
                          const uint8_t* in, size_t inlen,
                          std::vector<uint8_t>& out) {
    if (!key.valid()) return false;
    RsaInt m, c;
    if (!m.from_bytes(in, inlen)) return false;
    if (!RsaInt::modexp_u32(m, key.e, key.n, c)) return false;

    uint8_t full[RsaInt::BYTES];
    c.to_bytes(full);
    out.assign(full + (RsaInt::BYTES - key.k), full + RsaInt::BYTES);
    return true;
}

// The composition actually used by the handshake.
inline bool rsa_encrypt_pkcs1v15(const RsaPublicKey& key,
                                 const uint8_t* msg, size_t mlen,
                                 std::vector<uint8_t>& out) {
    if (!key.valid()) return false;
    std::vector<uint8_t> em;
    if (!pkcs1v15_pad_type2(key.k, msg, mlen, em)) return false;
    return rsa_public_op(key, em.data(), em.size(), out);
}

} // namespace ilo2
