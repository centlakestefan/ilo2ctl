// test_hmac.cpp — HMAC-MD5 and HMAC-SHA1 against the RFC 2202 cases, plus the
// key-reuse behaviour the TLS 1.0 PRF and record MAC rely on.
#include <array>
#include <cstring>
#include "tests/test_util.hpp"
#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/hmac.hpp"

using namespace ilo2;

#include "tests/hash_vectors.inc"

int main() {
    std::printf("[HMAC-MD5 / HMAC-SHA1 known-answer vectors]\n");
    for (const auto& v : HMAC_VECTORS) {
        auto key  = t::unhex(v.key_hex);
        auto data = t::unhex(v.data_hex);
        char label[80];

        auto m = HMAC<MD5>::mac(key.data(), key.size(), data.data(), data.size());
        std::snprintf(label, sizeof(label), "hmac-md5(key=%zu, data=%zu)", key.size(), data.size());
        t::eq(t::hex(m), v.want_md5, label);

        auto s = HMAC<SHA1>::mac(key.data(), key.size(), data.data(), data.size());
        std::snprintf(label, sizeof(label), "hmac-sha1(key=%zu, data=%zu)", key.size(), data.size());
        t::eq(t::hex(s), v.want_sha1, label);
    }

    std::printf("[key reuse across messages]\n");
    {
        // P_hash iterates HMAC under one key, and the record layer MACs every
        // record under one key -- so digest() must re-arm cleanly rather than
        // requiring a fresh object.
        auto key = t::unhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
        HMAC<MD5> h(key.data(), key.size());

        const char* msgs[] = { "first", "second", "third" };
        for (const char* m : msgs) {
            h.update(reinterpret_cast<const uint8_t*>(m), std::strlen(m));
            std::string got = t::hex(h.digest());

            auto want = HMAC<MD5>::mac(key.data(), key.size(),
                                       reinterpret_cast<const uint8_t*>(m), std::strlen(m));
            char label[64];
            std::snprintf(label, sizeof(label), "reused key, message \"%s\"", m);
            t::eq(got, t::hex(want), label);
        }
    }

    std::printf("[incremental update equals one-shot]\n");
    {
        auto key = t::unhex("4a656665");                    // "Jefe"
        const char* a = "what do ya want ";
        const char* b = "for nothing?";
        std::string whole = std::string(a) + b;

        HMAC<SHA1> h(key.data(), key.size());
        h.update(reinterpret_cast<const uint8_t*>(a), std::strlen(a));
        h.update(reinterpret_cast<const uint8_t*>(b), std::strlen(b));

        auto want = HMAC<SHA1>::mac(key.data(), key.size(),
                                    reinterpret_cast<const uint8_t*>(whole.data()), whole.size());
        t::eq(t::hex(h.digest()), t::hex(want), "two updates == one update");
    }

    return t::report("test_hmac");
}
