// test_prf.cpp — the TLS 1.0 PRF against OpenSSL's TLS1-PRF (MD5-SHA1), plus
// the three named derivations and the ordering details they encode.
#include <cstring>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include "tls/prf.hpp"

using namespace ilo2;

#include "tests/prf_vectors.inc"

static std::string run_prf(const std::string& secret_hex, const char* label,
                           const std::string& seed_hex, size_t outlen) {
    auto secret = t::unhex(secret_hex);
    auto seed   = t::unhex(seed_hex);
    std::vector<uint8_t> out(outlen);
    tls::prf(secret.data(), secret.size(), label,
             seed.data(), seed.size(), out.data(), outlen);
    return t::hex(out);
}

int main() {
    std::printf("[PRF against OpenSSL TLS1-PRF]\n");
    for (const auto& v : PRF_VECTORS)
        t::eq(run_prf(v.secret_hex, v.label, v.seed_hex, v.outlen), v.want, v.desc);

    std::printf("[output length independence]\n");
    {
        // P_hash is a stream: a short request must be a prefix of a long one.
        // This catches an A(i) chain that is restarted or advanced incorrectly.
        auto secret = t::unhex("000102030405060708090a0b0c0d0e0f");
        auto seed   = t::unhex("a0a1a2a3a4a5a6a7");
        std::vector<uint8_t> long_out(128);
        tls::prf(secret.data(), secret.size(), "stream",
                 seed.data(), seed.size(), long_out.data(), long_out.size());

        for (size_t n : {size_t(1), size_t(15), size_t(16), size_t(17),
                         size_t(20), size_t(21), size_t(64), size_t(127)}) {
            std::vector<uint8_t> short_out(n);
            tls::prf(secret.data(), secret.size(), "stream",
                     seed.data(), seed.size(), short_out.data(), n);
            char label[64];
            std::snprintf(label, sizeof(label), "%zu bytes is a prefix of 128", n);
            t::eq(t::hex(short_out), t::hex(long_out.data(), n), label);
        }
    }

    std::printf("[odd-length secrets overlap S1 and S2]\n");
    {
        // With an odd secret, S1 and S2 share their middle byte. Demonstrate
        // that the shared byte actually participates: changing ONLY that byte
        // must change the output. A floor-based split would drop it entirely
        // for one of the two halves.
        std::vector<uint8_t> a = t::unhex("00112233445566778899aabbccddeeff01");  // 17 bytes
        std::vector<uint8_t> b = a;
        b[(a.size() - 1) / 2] ^= 0xFF;                    // the overlapping byte

        std::vector<uint8_t> oa(32), ob(32);
        const uint8_t seed[4] = { 1, 2, 3, 4 };
        tls::prf(a.data(), a.size(), "odd", seed, sizeof(seed), oa.data(), oa.size());
        tls::prf(b.data(), b.size(), "odd", seed, sizeof(seed), ob.data(), ob.size());
        t::ok(oa != ob, "the byte shared by S1 and S2 affects the output");
    }

    std::printf("[named derivations match a raw PRF call]\n");
    {
        uint8_t pre_master[48], client_random[32], server_random[32];
        for (int i = 0; i < 48; ++i) pre_master[i]    = static_cast<uint8_t>(0x30 + i);
        for (int i = 0; i < 32; ++i) client_random[i] = static_cast<uint8_t>(0xC0 + i);
        for (int i = 0; i < 32; ++i) server_random[i] = static_cast<uint8_t>(0x50 + i);

        uint8_t master[48];
        tls::derive_master_secret(pre_master, sizeof(pre_master),
                                  client_random, server_random, master);
        {
            uint8_t seed[64];
            std::memcpy(seed,      client_random, 32);      // client FIRST
            std::memcpy(seed + 32, server_random, 32);
            uint8_t want[48];
            tls::prf(pre_master, sizeof(pre_master), "master secret",
                     seed, sizeof(seed), want, sizeof(want));
            t::eq(t::hex(master, 48), t::hex(want, 48), "master secret seed is client||server");
        }

        uint8_t kb[64];
        tls::derive_key_block(master, server_random, client_random, kb, sizeof(kb));
        {
            uint8_t seed[64];
            std::memcpy(seed,      server_random, 32);      // server FIRST -- reversed
            std::memcpy(seed + 32, client_random, 32);
            uint8_t want[64];
            tls::prf(master, 48, "key expansion", seed, sizeof(seed), want, sizeof(want));
            t::eq(t::hex(kb, 64), t::hex(want, 64), "key block seed is server||client");
        }

        // The whole point of the reversal: swapping the randoms must change the
        // key block. If this ever passes as equal, the two seeds are identical
        // and the ordering bug would be invisible.
        {
            uint8_t swapped[64];
            tls::derive_key_block(master, client_random, server_random, swapped, sizeof(swapped));
            t::ok(std::memcmp(kb, swapped, 64) != 0,
                  "transposing the randoms yields a different key block");
        }

        uint8_t md5_hash[16], sha1_hash[20];
        for (int i = 0; i < 16; ++i) md5_hash[i]  = static_cast<uint8_t>(i);
        for (int i = 0; i < 20; ++i) sha1_hash[i] = static_cast<uint8_t>(0x80 + i);

        uint8_t vd_client[12], vd_server[12];
        tls::derive_verify_data(master, tls::LABEL_CLIENT_FINISHED,
                                md5_hash, sha1_hash, vd_client);
        tls::derive_verify_data(master, tls::LABEL_SERVER_FINISHED,
                                md5_hash, sha1_hash, vd_server);
        {
            uint8_t seed[36];
            std::memcpy(seed,      md5_hash,  16);
            std::memcpy(seed + 16, sha1_hash, 20);
            uint8_t want[12];
            tls::prf(master, 48, "client finished", seed, sizeof(seed), want, sizeof(want));
            t::eq(t::hex(vd_client, 12), t::hex(want, 12), "client verify_data");
        }
        t::ok(std::memcmp(vd_client, vd_server, 12) != 0,
              "client and server Finished labels differ");
    }

    std::printf("[degenerate inputs]\n");
    {
        auto secret = t::unhex("0011223344556677");
        std::vector<uint8_t> out(8, 0xEE);
        // A zero-length request must write nothing and must not misbehave.
        tls::prf(secret.data(), secret.size(), "none", nullptr, 0, out.data(), 0);
        t::eq(t::hex(out), "eeeeeeeeeeeeeeee", "outlen 0 writes nothing");

        std::vector<uint8_t> one(1);
        tls::prf(secret.data(), secret.size(), "", nullptr, 0, one.data(), 1);
        t::ok(true, "empty label and empty seed do not crash");
    }

    return t::report("test_prf");
}
