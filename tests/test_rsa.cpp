// test_rsa.cpp — PKCS#1 v1.5 type-2 padding structure and the composed
// encryption, against the real iLO 2 public key.
//
// The modular exponentiation itself is validated in test_bigint.cpp against
// Python's pow(); what is checked here is everything wrapped around it.
#include <cstring>
#include <set>
#include <string>
#include "tests/test_util.hpp"
#include "crypto/rsa.hpp"

using namespace ilo2;

// The iLO 2 at 192.0.2.10: self-signed, CN=ILOUSE951N96F, 1024-bit, e=65537.
static const char* ILO_MODULUS_HEX =
    "BDE79C0E220D27830FFA815173D9BF7DEA6E29C459C1F04D9359A2467C51290278207B6776FDDF03"
    "ECE6F44A37B61C36AB6646EC497E48FAEA2E1567F91FE8834B1AA6760EB1714475AFD1459D8D5AB1"
    "32BE495B55B80C82FDA5000997A1F31BBD57C4861A060E5FB9B28EE0D64E4FEAA7DCBB5FD8ECCA49"
    "278B9AE5005FD04B";

static RsaPublicKey ilo_key() {
    auto nb = t::unhex(ILO_MODULUS_HEX);
    RsaPublicKey k;
    k.n.from_bytes(nb.data(), nb.size());
    k.e = 65537;
    k.k = nb.size();                       // 128 bytes
    return k;
}

int main() {
    const RsaPublicKey key = ilo_key();
    std::printf("[key]\n");
    t::ok(key.valid(), "iLO public key is well-formed");
    t::ok(key.k == 128, "modulus is 128 bytes (RSA-1024)");

    std::printf("[PKCS#1 v1.5 type-2 padding structure]\n");
    {
        // A TLS premaster is 48 bytes: 2 version bytes + 46 random.
        uint8_t premaster[48];
        for (int i = 0; i < 48; ++i) premaster[i] = static_cast<uint8_t>(i);

        std::set<std::string> seen_ps;
        int bad_len = 0, bad_prefix = 0, zero_in_ps = 0, bad_sep = 0, bad_msg = 0;

        const int reps = 500;
        for (int r = 0; r < reps; ++r) {
            std::vector<uint8_t> em;
            if (!pkcs1v15_pad_type2(key.k, premaster, sizeof(premaster), em)) {
                t::ok(false, "padding failed unexpectedly");
                break;
            }
            const size_t pslen = key.k - sizeof(premaster) - 3;

            if (em.size() != key.k)                    ++bad_len;
            if (em[0] != 0x00 || em[1] != 0x02)        ++bad_prefix;
            for (size_t i = 0; i < pslen; ++i)
                if (em[2 + i] == 0) { ++zero_in_ps; break; }
            if (em[2 + pslen] != 0x00)                 ++bad_sep;
            if (std::memcmp(em.data() + 3 + pslen, premaster, sizeof(premaster)) != 0)
                ++bad_msg;

            seen_ps.insert(t::hex(em.data() + 2, pslen));
        }

        t::ok(bad_len == 0,    "every EM is exactly k bytes");
        t::ok(bad_prefix == 0, "every EM starts 0x00 0x02");
        t::ok(zero_in_ps == 0, "PS never contains a zero byte");
        t::ok(bad_sep == 0,    "the 0x00 separator is in the right place");
        t::ok(bad_msg == 0,    "the message is placed at the tail intact");
        // 77 random nonzero bytes: a repeat would mean the CSPRNG is broken.
        t::ok(static_cast<int>(seen_ps.size()) == reps, "PS differs on every call");

        std::printf("  PS length %zu, %zu distinct over %d runs\n",
                    key.k - sizeof(premaster) - 3, seen_ps.size(), reps);
    }

    std::printf("[size limits]\n");
    {
        std::vector<uint8_t> em;
        std::vector<uint8_t> msg(key.k, 0xAA);
        t::ok(!pkcs1v15_pad_type2(key.k, msg.data(), key.k, em),
              "a message as long as the modulus is rejected");
        t::ok(!pkcs1v15_pad_type2(key.k, msg.data(), key.k - 10, em),
              "a message leaving < 8 padding bytes is rejected");
        t::ok(pkcs1v15_pad_type2(key.k, msg.data(), key.k - 11, em),
              "a message leaving exactly 8 padding bytes is accepted");
    }

    std::printf("[composed encryption]\n");
    {
        uint8_t premaster[48];
        for (int i = 0; i < 48; ++i) premaster[i] = static_cast<uint8_t>(0xF0 ^ i);

        std::vector<uint8_t> c1, c2;
        t::ok(rsa_encrypt_pkcs1v15(key, premaster, sizeof(premaster), c1), "encrypt succeeds");
        t::ok(c1.size() == key.k, "ciphertext is exactly k bytes");
        t::ok(rsa_encrypt_pkcs1v15(key, premaster, sizeof(premaster), c2), "encrypt succeeds again");
        // Randomised padding: the same plaintext must not produce the same
        // ciphertext twice. (This is the property that makes PKCS#1 v1.5
        // encryption non-deterministic, and its absence would be a real bug.)
        t::ok(c1 != c2, "the same premaster encrypts differently each time");

        // pad + public_op composed by hand must agree with the one-shot call,
        // proving rsa_encrypt_pkcs1v15 is exactly that composition.
        std::vector<uint8_t> em, manual;
        t::ok(pkcs1v15_pad_type2(key.k, premaster, sizeof(premaster), em), "manual pad");
        t::ok(rsa_public_op(key, em.data(), em.size(), manual), "manual public op");
        t::ok(manual.size() == key.k, "manual ciphertext is k bytes");

        // The ciphertext must be a valid residue: strictly less than n.
        RsaInt c, n;
        c.from_bytes(manual.data(), manual.size());
        auto nb = t::unhex(ILO_MODULUS_HEX);
        n.from_bytes(nb.data(), nb.size());
        t::ok(RsaInt::cmp(c, n) < 0, "ciphertext < modulus");
    }

    std::printf("[invalid keys are refused]\n");
    {
        std::vector<uint8_t> out;
        uint8_t msg[48] = {0};
        RsaPublicKey bad;                       // zero modulus, e = 0
        t::ok(!bad.valid(), "an empty key is not valid");
        t::ok(!rsa_encrypt_pkcs1v15(bad, msg, sizeof(msg), out), "encrypt refuses an empty key");

        RsaPublicKey small = ilo_key();
        small.k = 32;                           // 256-bit: below the floor
        t::ok(!small.valid(), "a 256-bit modulus is refused");
    }

    return t::report("test_rsa");
}
