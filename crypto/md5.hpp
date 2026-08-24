// vmd5.hpp — C++ port of com.hp.ilo2.remcons.VMD5
//
// Faithful reimplementation of the applet's MD5. It is standard RFC 1321 MD5
// (IV 0x67452301..., little-endian length and word packing), exposed with the
// same streaming shape the Java class uses: init() / update() one or more
// times / digest(). digest() returns the 16 raw bytes AND re-initialises the
// state, exactly like VMD5.engineDigest().
//
// Used by RC4::update_key() to derive/rekey the RC4 key as MD5(pre || key).
#pragma once
#include <cstdint>
#include <cstring>
#include <array>

namespace ilo2 {

class MD5 {
public:
    // Mirrors SHA1's surface so hmac.hpp / the TLS 1.0 PRF can template over both.
    static constexpr size_t DIGEST_SIZE = 16;
    static constexpr size_t BLOCK_SIZE  = 64;
    using Digest = std::array<uint8_t, DIGEST_SIZE>;

    MD5() { init(); }

    void init() {
        count_ = 0;
        state_[0] = 0x67452301u;   //  1732584193
        state_[1] = 0xefcdab89u;   // -271733879
        state_[2] = 0x98badcfeu;   // -1732584194
        state_[3] = 0x10325476u;   //  271733878
        std::memset(buffer_, 0, sizeof(buffer_));
    }

    // Matches VMD5.reset()
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

    // Convenience: whole-buffer update, mirrors VMD5.update(byte[]).
    void update(const std::array<uint8_t, 16>& b) { update(b.data(), b.size()); }

    // Finalises, returns the 16-byte digest, and re-inits (like engineDigest()).
    std::array<uint8_t, 16> digest() {
        uint8_t bits[8];
        for (int i = 0; i < 8; ++i)
            bits[i] = static_cast<uint8_t>((count_ >> (i * 8)) & 0xFF);

        size_t idx = static_cast<size_t>((count_ >> 3) & 0x3F);
        size_t padLen = (idx < 56) ? (56 - idx) : (120 - idx);
        static const uint8_t PAD[64] = { 0x80 };
        update(PAD, padLen);
        update(bits, 8);

        std::array<uint8_t, 16> out{};
        for (int i = 0; i < 4; ++i)
            for (int j = 0; j < 4; ++j)
                out[i * 4 + j] = static_cast<uint8_t>((state_[i] >> (j * 8)) & 0xFF);

        init();
        return out;
    }

private:
    static uint32_t rotl(uint32_t x, int c) { return (x << c) | (x >> (32 - c)); }
    static uint32_t F(uint32_t x, uint32_t y, uint32_t z) { return (x & y) | (~x & z); }
    static uint32_t G(uint32_t x, uint32_t y, uint32_t z) { return (x & z) | (y & ~z); }
    static uint32_t H(uint32_t x, uint32_t y, uint32_t z) { return x ^ y ^ z; }
    static uint32_t I(uint32_t x, uint32_t y, uint32_t z) { return y ^ (x | ~z); }

    static void FF(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, int s, uint32_t t)
        { a = b + rotl(a + F(b, c, d) + x + t, s); }
    static void GG(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, int s, uint32_t t)
        { a = b + rotl(a + G(b, c, d) + x + t, s); }
    static void HH(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, int s, uint32_t t)
        { a = b + rotl(a + H(b, c, d) + x + t, s); }
    static void II(uint32_t& a, uint32_t b, uint32_t c, uint32_t d, uint32_t x, int s, uint32_t t)
        { a = b + rotl(a + I(b, c, d) + x + t, s); }

    void transform(const uint8_t* blk) {
        uint32_t m[16];
        for (int i = 0; i < 16; ++i)
            m[i] = static_cast<uint32_t>(blk[i * 4]) |
                   (static_cast<uint32_t>(blk[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(blk[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(blk[i * 4 + 3]) << 24);

        uint32_t a = state_[0], b = state_[1], c = state_[2], d = state_[3];

        FF(a,b,c,d,m[ 0], 7,0xd76aa478); FF(d,a,b,c,m[ 1],12,0xe8c7b756);
        FF(c,d,a,b,m[ 2],17,0x242070db); FF(b,c,d,a,m[ 3],22,0xc1bdceee);
        FF(a,b,c,d,m[ 4], 7,0xf57c0faf); FF(d,a,b,c,m[ 5],12,0x4787c62a);
        FF(c,d,a,b,m[ 6],17,0xa8304613); FF(b,c,d,a,m[ 7],22,0xfd469501);
        FF(a,b,c,d,m[ 8], 7,0x698098d8); FF(d,a,b,c,m[ 9],12,0x8b44f7af);
        FF(c,d,a,b,m[10],17,0xffff5bb1); FF(b,c,d,a,m[11],22,0x895cd7be);
        FF(a,b,c,d,m[12], 7,0x6b901122); FF(d,a,b,c,m[13],12,0xfd987193);
        FF(c,d,a,b,m[14],17,0xa679438e); FF(b,c,d,a,m[15],22,0x49b40821);

        GG(a,b,c,d,m[ 1], 5,0xf61e2562); GG(d,a,b,c,m[ 6], 9,0xc040b340);
        GG(c,d,a,b,m[11],14,0x265e5a51); GG(b,c,d,a,m[ 0],20,0xe9b6c7aa);
        GG(a,b,c,d,m[ 5], 5,0xd62f105d); GG(d,a,b,c,m[10], 9,0x02441453);
        GG(c,d,a,b,m[15],14,0xd8a1e681); GG(b,c,d,a,m[ 4],20,0xe7d3fbc8);
        GG(a,b,c,d,m[ 9], 5,0x21e1cde6); GG(d,a,b,c,m[14], 9,0xc33707d6);
        GG(c,d,a,b,m[ 3],14,0xf4d50d87); GG(b,c,d,a,m[ 8],20,0x455a14ed);
        GG(a,b,c,d,m[13], 5,0xa9e3e905); GG(d,a,b,c,m[ 2], 9,0xfcefa3f8);
        GG(c,d,a,b,m[ 7],14,0x676f02d9); GG(b,c,d,a,m[12],20,0x8d2a4c8a);

        HH(a,b,c,d,m[ 5], 4,0xfffa3942); HH(d,a,b,c,m[ 8],11,0x8771f681);
        HH(c,d,a,b,m[11],16,0x6d9d6122); HH(b,c,d,a,m[14],23,0xfde5380c);
        HH(a,b,c,d,m[ 1], 4,0xa4beea44); HH(d,a,b,c,m[ 4],11,0x4bdecfa9);
        HH(c,d,a,b,m[ 7],16,0xf6bb4b60); HH(b,c,d,a,m[10],23,0xbebfbc70);
        HH(a,b,c,d,m[13], 4,0x289b7ec6); HH(d,a,b,c,m[ 0],11,0xeaa127fa);
        HH(c,d,a,b,m[ 3],16,0xd4ef3085); HH(b,c,d,a,m[ 6],23,0x04881d05);
        HH(a,b,c,d,m[ 9], 4,0xd9d4d039); HH(d,a,b,c,m[12],11,0xe6db99e5);
        HH(c,d,a,b,m[15],16,0x1fa27cf8); HH(b,c,d,a,m[ 2],23,0xc4ac5665);

        II(a,b,c,d,m[ 0], 6,0xf4292244); II(d,a,b,c,m[ 7],10,0x432aff97);
        II(c,d,a,b,m[14],15,0xab9423a7); II(b,c,d,a,m[ 5],21,0xfc93a039);
        II(a,b,c,d,m[12], 6,0x655b59c3); II(d,a,b,c,m[ 3],10,0x8f0ccc92);
        II(c,d,a,b,m[10],15,0xffeff47d); II(b,c,d,a,m[ 1],21,0x85845dd1);
        II(a,b,c,d,m[ 8], 6,0x6fa87e4f); II(d,a,b,c,m[15],10,0xfe2ce6e0);
        II(c,d,a,b,m[ 6],15,0xa3014314); II(b,c,d,a,m[13],21,0x4e0811a1);
        II(a,b,c,d,m[ 4], 6,0xf7537e82); II(d,a,b,c,m[11],10,0xbd3af235);
        II(c,d,a,b,m[ 2],15,0x2ad7d2bb); II(b,c,d,a,m[ 9],21,0xeb86d391);

        state_[0] += a; state_[1] += b; state_[2] += c; state_[3] += d;
    }

    uint32_t state_[4];
    uint64_t count_;      // message length in BITS (matches VMD5.count)
    uint8_t  buffer_[64];
};

} // namespace ilo2
