// sha1.hpp — RFC 3174 SHA-1.
//
// Deliberately mirrors crypto/md5.hpp's shape — init() / update() / digest(),
// with digest() finalising AND re-initialising — so hmac.hpp and the TLS 1.0 PRF
// can be written once as templates over either hash. TLS 1.0 needs both:
//     PRF = P_MD5(S1, seed) XOR P_SHA1(S2, seed)
//
// Unlike MD5, SHA-1 is big-endian in both word packing and the length suffix.
//
// All state is POD, so the implicit copy constructor gives a cheap snapshot.
// That is load-bearing for the handshake hash: Finished is computed over the
// running hash so far, but the running hash must survive to cover the peer's
// Finished, so you copy before calling the destructive digest().
#pragma once
#include <cstdint>
#include <cstring>
#include <array>

namespace ilo2 {

class SHA1 {
public:
    static constexpr size_t DIGEST_SIZE = 20;
    static constexpr size_t BLOCK_SIZE  = 64;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    SHA1() { init(); }

    void init() {
        count_ = 0;
        state_[0] = 0x67452301u;
        state_[1] = 0xEFCDAB89u;
        state_[2] = 0x98BADCFEu;
        state_[3] = 0x10325476u;
        state_[4] = 0xC3D2E1F0u;
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    void reset() { init(); }

    void update(const uint8_t* data, size_t len) {
        size_t idx = static_cast<size_t>((count_ >> 3) & 0x3F);
        count_ += static_cast<uint64_t>(len) << 3;
        size_t part = 64 - idx;
        size_t i = 0;
        if (len >= part) {
            std::memcpy(buffer_ + idx, data, part);
            transform(buffer_);
            for (i = part; i + 63 < len; i += 64)
                transform(data + i);
            idx = 0;
        }
        std::memcpy(buffer_ + idx, data + i, len - i);
    }

    // Finalises, returns the 20-byte digest, and re-inits.
    Digest digest() {
        // Capture the length BEFORE padding extends count_.
        uint8_t bits[8];
        for (int i = 0; i < 8; ++i)
            bits[i] = static_cast<uint8_t>((count_ >> (56 - i * 8)) & 0xFF);

        size_t idx = static_cast<size_t>((count_ >> 3) & 0x3F);
        size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
        static const uint8_t PAD[64] = { 0x80 };
        update(PAD, padLen);
        update(bits, 8);

        Digest out{};
        for (int i = 0; i < 5; ++i) {
            out[i * 4 + 0] = static_cast<uint8_t>(state_[i] >> 24);
            out[i * 4 + 1] = static_cast<uint8_t>(state_[i] >> 16);
            out[i * 4 + 2] = static_cast<uint8_t>(state_[i] >> 8);
            out[i * 4 + 3] = static_cast<uint8_t>(state_[i]);
        }
        init();
        return out;
    }

private:
    static uint32_t rol(uint32_t v, int n) {
        return (v << n) | (v >> (32 - n));
    }

    void transform(const uint8_t* blk) {
        uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = (static_cast<uint32_t>(blk[i * 4 + 0]) << 24)
                 | (static_cast<uint32_t>(blk[i * 4 + 1]) << 16)
                 | (static_cast<uint32_t>(blk[i * 4 + 2]) << 8)
                 |  static_cast<uint32_t>(blk[i * 4 + 3]);
        for (int i = 16; i < 80; ++i)
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);

        uint32_t a = state_[0], b = state_[1], c = state_[2],
                 d = state_[3], e = state_[4];
        for (int i = 0; i < 80; ++i) {
            uint32_t f, k;
            if (i < 20)      { f = (b & c) | (~b & d);           k = 0x5A827999u; }
            else if (i < 40) { f = b ^ c ^ d;                    k = 0x6ED9EBA1u; }
            else if (i < 60) { f = (b & c) | (b & d) | (c & d);  k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;                    k = 0xCA62C1D6u; }
            uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d; d = c; c = rol(b, 30); b = a; a = t;
        }
        state_[0] += a; state_[1] += b; state_[2] += c;
        state_[3] += d; state_[4] += e;
    }

    uint64_t count_;        // message length in BITS
    uint32_t state_[5];
    uint8_t  buffer_[64];
};

} // namespace ilo2
