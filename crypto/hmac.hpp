// hmac.hpp — RFC 2104 HMAC, templated over a hash with the shape shared by
// crypto/md5.hpp and crypto/sha1.hpp (DIGEST_SIZE / BLOCK_SIZE / Digest,
// init() / update() / destructive digest()).
//
// TLS 1.0 needs HMAC-MD5 and HMAC-SHA1 in two places:
//   * the record MAC (HMAC-MD5 for TLS_RSA_WITH_RC4_128_MD5),
//   * the PRF, which runs P_hash over both.
//
// The expanded ipad/opad key blocks are retained, so one object can compute many
// MACs with the same key — which is exactly what P_hash's iteration wants, and
// what the record layer wants across a whole connection.
#pragma once
#include <cstdint>
#include <cstring>
#include <array>
#include <string>
#include <vector>

namespace ilo2 {

template <class H>
class HMAC {
public:
    static constexpr size_t DIGEST_SIZE = H::DIGEST_SIZE;
    static constexpr size_t BLOCK_SIZE  = H::BLOCK_SIZE;
    using Digest = typename H::Digest;

    HMAC() { std::memset(ipad_, 0, sizeof(ipad_)); std::memset(opad_, 0, sizeof(opad_)); }
    HMAC(const uint8_t* key, size_t klen) { init(key, klen); }

    void init(const uint8_t* key, size_t klen) {
        uint8_t k[BLOCK_SIZE];
        std::memset(k, 0, sizeof(k));
        if (klen > BLOCK_SIZE) {
            // Keys longer than the block are replaced by their own hash.
            H h;
            h.update(key, klen);
            auto d = h.digest();
            std::memcpy(k, d.data(), d.size());
        } else if (klen) {
            std::memcpy(k, key, klen);
        }   // klen == 0 leaves k all-zero, which is the correct HMAC of an empty key
        for (size_t i = 0; i < BLOCK_SIZE; ++i) {
            ipad_[i] = static_cast<uint8_t>(k[i] ^ 0x36);
            opad_[i] = static_cast<uint8_t>(k[i] ^ 0x5C);
        }
        begin();
    }

    // Start a fresh message under the existing key.
    void begin() {
        inner_.init();
        inner_.update(ipad_, BLOCK_SIZE);
    }

    void update(const uint8_t* data, size_t len) { inner_.update(data, len); }
    void update(const std::string& s) {
        inner_.update(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }

    // Finalises this message and re-arms for the next one under the same key.
    Digest digest() {
        auto in = inner_.digest();
        H outer;
        outer.update(opad_, BLOCK_SIZE);
        outer.update(in.data(), in.size());
        auto out = outer.digest();
        begin();
        return out;
    }

    // One-shot convenience.
    static Digest mac(const uint8_t* key, size_t klen,
                      const uint8_t* msg, size_t mlen) {
        HMAC<H> h(key, klen);
        h.update(msg, mlen);
        return h.digest();
    }

private:
    H       inner_;
    uint8_t ipad_[BLOCK_SIZE];
    uint8_t opad_[BLOCK_SIZE];
};

} // namespace ilo2
