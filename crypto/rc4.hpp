// rc4.hpp — C++ port of com.hp.ilo2.remcons.RC4
//
// The applet's stream cipher: standard RC4 (KSA + PRGA) whose key is derived
// and periodically re-derived by MD5. The 16-byte session key ("pre", from the
// INFOB/INFOC applet params) seeds the object; each key schedule computes
//     key <- MD5(pre || key)
// with `key` starting as 16 zero bytes, then runs the RC4 KSA over `key`.
//
// randomValue() is the RC4 PRGA output byte; the transport XORs it against each
// stream byte (see telnet.java: plain = cipher ^ (randomValue() & 0xff)).
// update_key() performs the on-the-wire rekey (TELNET_CHG_ENCRYPT_KEYS /
// telnet.change_key()).
#pragma once
#include <cstdint>
#include <cstring>
#include "crypto/md5.hpp"

namespace ilo2 {

class RC4 {
public:
    // seed = 16-byte session key (the "pre" value).
    explicit RC4(const uint8_t seed[16]) {
        std::memcpy(pre_, seed, 16);
        std::memset(key_, 0, sizeof(key_));   // Java: key initialised to 16 zero bytes
        keylen_ = 16;
        i_ = j_ = 0;
        update_key();
    }

    // Tag type for the raw-key constructor below.
    struct RawKey { explicit RawKey() = default; };

    // Standard RC4 keyed DIRECTLY from `key`, with no MD5 derivation -- i.e. the
    // ordinary RC4 key schedule, which is what TLS uses. The KSA and PRGA below
    // are textbook; only the MD5 key derivation in update_key() is HP's.
    //
    // update_key() must NOT be called on an object built this way: HP's rekey
    // derives the next key from `pre_`, which a raw-keyed object does not have.
    RC4(RawKey, const uint8_t* key, size_t klen) {
        std::memset(pre_, 0, sizeof(pre_));
        std::memset(key_, 0, sizeof(key_));
        keylen_ = (klen == 0 || klen > sizeof(key_)) ? 1 : klen;
        if (klen && klen <= sizeof(key_)) std::memcpy(key_, key, klen);
        i_ = j_ = 0;
        schedule();
    }

    // MD5 rekey + RC4 KSA. Called once at construction and on every rekey.
    void update_key() {
        digest_.reset();
        digest_.update(pre_, 16);
        digest_.update(key_, 16);
        auto d = digest_.digest();
        std::memcpy(key_, d.data(), 16);
        keylen_ = 16;
        schedule();
    }

    // One PRGA keystream byte.
    uint8_t randomValue() {
        i_ = (i_ + 1) & 0xFF;
        j_ = (j_ + sBox_[i_]) & 0xFF;
        uint8_t t = sBox_[i_]; sBox_[i_] = sBox_[j_]; sBox_[j_] = t;
        int n = (sBox_[i_] + sBox_[j_]) & 0xFF;
        return sBox_[n];
    }

    // Convenience: XOR a buffer in place with the keystream (matches the
    // transport's per-byte cipher^keystream loop).
    void crypt(uint8_t* buf, size_t len) {
        for (size_t k = 0; k < len; ++k)
            buf[k] ^= randomValue();
    }

private:
    // The RC4 key schedule (KSA), identical for both key paths.
    void schedule() {
        for (int n = 0; n < 256; ++n) {
            sBox_[n]   = static_cast<uint8_t>(n);
            keyBox_[n] = key_[n % keylen_];
        }
        j_ = 0;
        for (i_ = 0; i_ < 256; ++i_) {
            j_ = (j_ + sBox_[i_] + keyBox_[i_]) & 0xFF;
            uint8_t t = sBox_[i_]; sBox_[i_] = sBox_[j_]; sBox_[j_] = t;
        }
        i_ = 0;
        j_ = 0;
    }

    MD5     digest_;
    uint8_t key_[256];
    size_t  keylen_ = 16;
    uint8_t pre_[16];
    uint8_t sBox_[256];
    uint8_t keyBox_[256];
    int     i_, j_;
};

} // namespace ilo2
