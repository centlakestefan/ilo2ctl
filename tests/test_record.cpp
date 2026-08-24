// test_record.cpp — the TLS 1.0 record layer for RC4 suites.
//
// The known-answer vectors come from an independent Python model rather than a
// third-party oracle (see tests/gen_record_vectors.py for why), so they catch
// transcription errors but not a shared misreading of RFC 2246 §6.2. The
// negative vectors are the part that carries real weight: each isolates one
// field of the MAC input and proves it participates.
#include <cstring>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include "tls/record.hpp"

using namespace ilo2;
using namespace ilo2::tls;

#include "tests/record_vectors.inc"

template <class Layer>
static void run_sequence(const char* name, const RecVec* vecs, size_t n,
                         const char* mac_hex, const char* enc_hex) {
    auto mac_key = t::unhex(mac_hex);
    auto enc_key = t::unhex(enc_hex);

    // One writer for the whole sequence: the vectors were produced by a single
    // RC4 object, so they only reproduce if the keystream is continuous.
    Layer writer;
    writer.enable_write_cipher(mac_key.data(), enc_key.data());

    Layer reader;
    reader.enable_read_cipher(mac_key.data(), enc_key.data());

    for (size_t i = 0; i < n; ++i) {
        auto plain = t::unhex(vecs[i].plaintext_hex);
        std::vector<uint8_t> rec;
        char label[96];

        std::snprintf(label, sizeof(label), "%s[%zu]: protect matches the model", name, i);
        t::ok(writer.protect(vecs[i].type, plain.data(), plain.size(), rec), "protect succeeds");
        t::eq(t::hex(rec), vecs[i].record_hex, label);

        // ... and the same bytes must come back out through unprotect.
        RecordHeader h;
        t::ok(parse_record_header(rec.data(), rec.size(), h), "header parses");
        std::vector<uint8_t> back;
        std::snprintf(label, sizeof(label), "%s[%zu]: round-trips", name, i);
        t::ok(reader.unprotect(h.type, h.version, rec.data() + RECORD_HEADER_LEN,
                               rec.size() - RECORD_HEADER_LEN, back), "unprotect succeeds");
        t::eq(t::hex(back), vecs[i].plaintext_hex, label);
    }

    char label[96];
    std::snprintf(label, sizeof(label), "%s: sequence numbers reached %zu", name, n);
    t::ok(writer.write_seq() == n && reader.read_seq() == n, label);
}

int main() {
    std::printf("[key_block split, RFC 2246 6.3 order]\n");
    {
        auto kb = t::unhex(KEY_BLOCK_HEX);
        t::ok(kb.size() == KeyMaterial::KEY_BLOCK_LEN, "key block is 64 bytes for RC4-MD5");
        KeyMaterial km;
        km.split(kb.data());
        t::eq(t::hex(km.client_mac, 16), KB_CLIENT_MAC, "client_write_MAC_secret first");
        t::eq(t::hex(km.server_mac, 16), KB_SERVER_MAC, "server_write_MAC_secret second");
        t::eq(t::hex(km.client_key, 16), KB_CLIENT_KEY, "client_write_key third");
        t::eq(t::hex(km.server_key, 16), KB_SERVER_KEY, "server_write_key fourth");
    }

    std::printf("[TLS_RSA_WITH_RC4_128_MD5 record sequence]\n");
    run_sequence<RecordLayer>("MD5", MD5_RECORDS,
                              sizeof(MD5_RECORDS) / sizeof(RecVec),
                              MD5_MAC_KEY, MD5_ENC_KEY);

    std::printf("[TLS_RSA_WITH_RC4_128_SHA record sequence]\n");
    run_sequence<RecordLayerSha>("SHA1", SHA1_RECORDS,
                                 sizeof(SHA1_RECORDS) / sizeof(RecVec),
                                 SHA_MAC_KEY, SHA_ENC_KEY);

    std::printf("[negative vectors: each field of the MAC input participates]\n");
    {
        auto mac_key = t::unhex(MD5_MAC_KEY);
        auto enc_key = t::unhex(MD5_ENC_KEY);
        for (const auto& nv : MD5_NEGATIVE) {
            // A fresh reader each time, so keystream position and sequence
            // number are both 0 and the named field is the only thing wrong.
            RecordLayer reader;
            reader.enable_read_cipher(mac_key.data(), enc_key.data());
            auto rec = t::unhex(nv.record_hex);
            RecordHeader h;
            t::ok(parse_record_header(rec.data(), rec.size(), h), "header parses");
            std::vector<uint8_t> out;
            t::ok(!reader.unprotect(h.type, h.version, rec.data() + RECORD_HEADER_LEN,
                                    rec.size() - RECORD_HEADER_LEN, out),
                  nv.desc);
        }
    }

    std::printf("[keystream continuity]\n");
    {
        auto mac_key = t::unhex(MD5_MAC_KEY);
        auto enc_key = t::unhex(MD5_ENC_KEY);
        const uint8_t msg[] = { 'h', 'e', 'l', 'l', 'o' };

        RecordLayer a;
        a.enable_write_cipher(mac_key.data(), enc_key.data());
        std::vector<uint8_t> r1, r2;
        a.protect(CT_APPLICATION_DATA, msg, sizeof(msg), r1);
        a.protect(CT_APPLICATION_DATA, msg, sizeof(msg), r2);
        t::ok(r1 != r2, "the same plaintext twice gives different records");

        // Re-enabling the cipher restarts both the keystream and the sequence
        // number, so record 1 of a restarted layer must equal the original
        // record 1 -- and must NOT equal the original record 2.
        RecordLayer b;
        b.enable_write_cipher(mac_key.data(), enc_key.data());
        std::vector<uint8_t> r1b;
        b.protect(CT_APPLICATION_DATA, msg, sizeof(msg), r1b);
        t::ok(r1b == r1, "a restarted layer reproduces the first record");
        t::ok(r1b != r2, "the second record depends on the advanced keystream");
        t::ok(b.write_seq() == 1, "sequence number reset on enable_write_cipher");
    }

    std::printf("[ChangeCipherSpec restarts the sequence number]\n");
    {
        // The handshake sends several cleartext records before the cipher is
        // enabled, and the null-cipher connection state counts them. When the
        // cipher spec changes a NEW connection state begins, so the first
        // protected record must use sequence number 0 -- it must equal
        // MD5_RECORDS[0] exactly, despite the records that preceded it.
        auto mac_key = t::unhex(MD5_MAC_KEY);
        auto enc_key = t::unhex(MD5_ENC_KEY);
        RecordLayer layer;

        const uint8_t ch[] = { 0x01, 0x00, 0x00, 0x04, 0x03, 0x01, 0x00, 0x00 };
        std::vector<uint8_t> junk;
        for (int i = 0; i < 3; ++i) layer.protect(CT_HANDSHAKE, ch, sizeof(ch), junk);
        t::ok(layer.write_seq() == 3, "cleartext records advance the sequence number");

        layer.enable_write_cipher(mac_key.data(), enc_key.data());
        t::ok(layer.write_seq() == 0, "enabling the cipher resets it to zero");

        auto plain = t::unhex(MD5_RECORDS[0].plaintext_hex);
        std::vector<uint8_t> rec;
        layer.protect(MD5_RECORDS[0].type, plain.data(), plain.size(), rec);
        t::eq(t::hex(rec), MD5_RECORDS[0].record_hex,
              "the first protected record uses seq 0 regardless of prior records");
    }

    std::printf("[records before ChangeCipherSpec are cleartext]\n");
    {
        RecordLayer layer;
        const uint8_t hello[] = { 0x01, 0x00, 0x00, 0x2A };
        std::vector<uint8_t> rec;
        t::ok(layer.protect(CT_HANDSHAKE, hello, sizeof(hello), rec), "protect succeeds");
        t::ok(rec.size() == RECORD_HEADER_LEN + sizeof(hello), "no MAC is appended");
        // type 0x16, version 0x0301, length 0x0004, then the fragment verbatim.
        t::eq(t::hex(rec), "16030100040100002a", "unencrypted record bytes");
    }

    std::printf("[malformed input]\n");
    {
        auto mac_key = t::unhex(MD5_MAC_KEY);
        auto enc_key = t::unhex(MD5_ENC_KEY);
        RecordLayer reader;
        reader.enable_read_cipher(mac_key.data(), enc_key.data());

        std::vector<uint8_t> out;
        const uint8_t tiny[] = { 0x00 };
        t::ok(!reader.unprotect(CT_APPLICATION_DATA, VERSION_TLS_1_0, tiny, 1, out),
              "a body shorter than the MAC is refused");

        std::vector<uint8_t> huge(MAX_CIPHERTEXT + 1, 0);
        t::ok(!reader.unprotect(CT_APPLICATION_DATA, VERSION_TLS_1_0,
                                huge.data(), huge.size(), out),
              "an oversized body is refused");

        RecordLayer writer;
        std::vector<uint8_t> rec;
        std::vector<uint8_t> big(MAX_PLAINTEXT + 1, 0);
        t::ok(!writer.protect(CT_APPLICATION_DATA, big.data(), big.size(), rec),
              "an oversized fragment is refused");

        RecordHeader h;
        const uint8_t short_hdr[] = { 0x16, 0x03, 0x01 };
        t::ok(!parse_record_header(short_hdr, sizeof(short_hdr), h),
              "a truncated header is refused");
        const uint8_t bad_len[] = { 0x16, 0x03, 0x01, 0xFF, 0xFF };
        t::ok(!parse_record_header(bad_len, sizeof(bad_len), h),
              "a length beyond 2^14+2048 is refused");
        t::ok(!is_valid_content_type(99), "an unknown content type is rejected");
        t::ok(is_valid_content_type(CT_HANDSHAKE), "handshake is a valid content type");
    }

    return t::report("test_record");
}
