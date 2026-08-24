// prf.hpp — the TLS 1.0 pseudo-random function (RFC 2246 §5) and the three
// derivations the handshake builds on it.
//
// This is the part that differs most from TLS 1.2. Where 1.2 uses a single
// P_SHA256, TLS 1.0 splits the secret in half and XORs two independent P_hash
// streams:
//
//     PRF(secret, label, seed) = P_MD5(S1, label + seed)
//                          XOR  P_SHA1(S2, label + seed)
//
// so both hashes are required, and neither can be dropped for being obsolete.
//
// The three named derivations below exist because each one encodes a detail
// that is easy to get wrong and produces nothing but an opaque decrypt failure
// when you do — most notably key_block's REVERSED random order.
#pragma once
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/hmac.hpp"

namespace ilo2 {
namespace tls {

constexpr size_t MASTER_SECRET_LEN = 48;
constexpr size_t RANDOM_LEN        = 32;   // gmt_unix_time(4) || random_bytes(28)
constexpr size_t VERIFY_DATA_LEN   = 12;

constexpr const char* LABEL_MASTER_SECRET  = "master secret";
constexpr const char* LABEL_KEY_EXPANSION  = "key expansion";
constexpr const char* LABEL_CLIENT_FINISHED = "client finished";
constexpr const char* LABEL_SERVER_FINISHED = "server finished";

// P_hash(secret, seed) = HMAC(secret, A(1) + seed) ||
//                        HMAC(secret, A(2) + seed) || ...
// with A(0) = seed and A(i) = HMAC(secret, A(i-1)), truncated to outlen.
template <class H>
inline void p_hash(const uint8_t* secret, size_t slen,
                   const uint8_t* seed, size_t seedlen,
                   uint8_t* out, size_t outlen) {
    if (outlen == 0) return;

    HMAC<H> mac(secret, slen);
    mac.update(seed, seedlen);
    auto a = mac.digest();                       // A(1)

    size_t off = 0;
    while (off < outlen) {
        mac.update(a.data(), a.size());
        mac.update(seed, seedlen);
        auto chunk = mac.digest();               // HMAC(secret, A(i) + seed)

        const size_t n = std::min(outlen - off, chunk.size());
        std::memcpy(out + off, chunk.data(), n);
        off += n;

        if (off < outlen) {                      // A(i+1) = HMAC(secret, A(i))
            mac.update(a.data(), a.size());
            a = mac.digest();
        }
    }
}

// PRF(secret, label, seed) = P_MD5(S1, label+seed) XOR P_SHA1(S2, label+seed)
inline void prf(const uint8_t* secret, size_t slen,
                const char* label,
                const uint8_t* seed, size_t seedlen,
                uint8_t* out, size_t outlen) {
    const size_t llen = std::strlen(label);
    std::vector<uint8_t> ls;
    ls.reserve(llen + seedlen);
    ls.insert(ls.end(), label, label + llen);
    if (seedlen) ls.insert(ls.end(), seed, seed + seedlen);

    // S1 is the first half of the secret and S2 the second, each ceil(L/2)
    // bytes. When L is ODD they OVERLAP by one byte: the last byte of S1 is
    // also the first byte of S2. A naive floor-based split silently produces
    // the wrong keys for any odd-length secret.
    const size_t half = (slen + 1) / 2;
    const uint8_t* s1 = secret;
    const uint8_t* s2 = secret + (slen - half);

    std::vector<uint8_t> from_md5(outlen), from_sha1(outlen);
    p_hash<MD5>(s1, half, ls.data(), ls.size(), from_md5.data(), outlen);
    p_hash<SHA1>(s2, half, ls.data(), ls.size(), from_sha1.data(), outlen);

    for (size_t i = 0; i < outlen; ++i)
        out[i] = static_cast<uint8_t>(from_md5[i] ^ from_sha1[i]);
}

// master_secret = PRF(pre_master_secret, "master secret",
//                     ClientHello.random + ServerHello.random)  [48 bytes]
inline void derive_master_secret(const uint8_t* pre_master, size_t pmlen,
                                 const uint8_t client_random[RANDOM_LEN],
                                 const uint8_t server_random[RANDOM_LEN],
                                 uint8_t out[MASTER_SECRET_LEN]) {
    uint8_t seed[RANDOM_LEN * 2];
    std::memcpy(seed,              client_random, RANDOM_LEN);
    std::memcpy(seed + RANDOM_LEN, server_random, RANDOM_LEN);
    prf(pre_master, pmlen, LABEL_MASTER_SECRET, seed, sizeof(seed), out, MASTER_SECRET_LEN);
}

// key_block = PRF(master_secret, "key expansion",
//                 ServerHello.random + ClientHello.random)
//
// NOTE THE ORDER: server random FIRST here, the reverse of the master-secret
// seed above. This is the single most commonly transposed detail in a TLS
// implementation, and getting it wrong yields keys that are perfectly
// well-formed and simply do not decrypt.
inline void derive_key_block(const uint8_t master[MASTER_SECRET_LEN],
                             const uint8_t server_random[RANDOM_LEN],
                             const uint8_t client_random[RANDOM_LEN],
                             uint8_t* out, size_t outlen) {
    uint8_t seed[RANDOM_LEN * 2];
    std::memcpy(seed,              server_random, RANDOM_LEN);
    std::memcpy(seed + RANDOM_LEN, client_random, RANDOM_LEN);
    prf(master, MASTER_SECRET_LEN, LABEL_KEY_EXPANSION, seed, sizeof(seed), out, outlen);
}

// verify_data = PRF(master_secret, finished_label,
//                   MD5(handshake_messages) + SHA1(handshake_messages))  [12 bytes]
//
// TLS 1.0 feeds BOTH hashes of the transcript, 36 bytes in total — not the
// single SHA-256 that 1.2 uses — and the result is always 12 bytes.
inline void derive_verify_data(const uint8_t master[MASTER_SECRET_LEN],
                               const char* label,
                               const uint8_t md5_hash[16],
                               const uint8_t sha1_hash[20],
                               uint8_t out[VERIFY_DATA_LEN]) {
    uint8_t seed[36];
    std::memcpy(seed,      md5_hash,  16);
    std::memcpy(seed + 16, sha1_hash, 20);
    prf(master, MASTER_SECRET_LEN, label, seed, sizeof(seed), out, VERIFY_DATA_LEN);
}

} // namespace tls
} // namespace ilo2
