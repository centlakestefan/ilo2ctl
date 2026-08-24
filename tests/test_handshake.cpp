// test_handshake.cpp — TLS 1.0 handshake message construction and parsing,
// plus an offline run of the whole exchange against a simulated server.
#include <cstring>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include "tls/handshake.hpp"
#include "tls/der.hpp"

using namespace ilo2;
using namespace ilo2::tls;

#include "tests/cert_fixture.inc"

// Wrap a DER certificate in a TLS Certificate message body.
static std::vector<uint8_t> certificate_body(const std::vector<uint8_t>& der) {
    std::vector<uint8_t> body;
    const size_t total = der.size() + 3;
    body.push_back(static_cast<uint8_t>(total >> 16));
    body.push_back(static_cast<uint8_t>(total >> 8));
    body.push_back(static_cast<uint8_t>(total));
    body.push_back(static_cast<uint8_t>(der.size() >> 16));
    body.push_back(static_cast<uint8_t>(der.size() >> 8));
    body.push_back(static_cast<uint8_t>(der.size()));
    body.insert(body.end(), der.begin(), der.end());
    return body;
}

static std::vector<uint8_t> server_hello_body(uint16_t version, const uint8_t random[32],
                                              uint16_t suite, const std::vector<uint8_t>& sid) {
    std::vector<uint8_t> b;
    b.push_back(static_cast<uint8_t>(version >> 8));
    b.push_back(static_cast<uint8_t>(version));
    b.insert(b.end(), random, random + 32);
    b.push_back(static_cast<uint8_t>(sid.size()));
    b.insert(b.end(), sid.begin(), sid.end());
    b.push_back(static_cast<uint8_t>(suite >> 8));
    b.push_back(static_cast<uint8_t>(suite));
    b.push_back(0x00);                                  // null compression
    return b;
}

int main() {
    std::printf("[ClientHello bytes]\n");
    {
        uint8_t rnd[32];
        for (int i = 0; i < 32; ++i) rnd[i] = static_cast<uint8_t>(i);
        auto ch = build_client_hello(VERSION_TLS_1_0, rnd,
                                     { TLS_RSA_WITH_RC4_128_MD5, TLS_RSA_WITH_RC4_128_SHA });
        t::eq(t::hex(ch),
              "0100002b0301"
              "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
              "00" "0004" "00040005" "0100",
              "ClientHello matches a byte-for-byte independent construction");
        t::ok(ch.size() == 47, "47 bytes total");
        t::ok(ch[0] == HT_CLIENT_HELLO, "type is client_hello");
        // No extensions: the body must end immediately after compression.
        t::ok(ch.size() == HANDSHAKE_HEADER_LEN + 43, "no extensions block is appended");
    }

    std::printf("[handshake framing]\n");
    {
        auto f = frame(HT_FINISHED, std::vector<uint8_t>(12, 0xAB));
        // type 0x14, then a 3-byte length of 0x00000c, then the body.
        t::eq(t::hex(f), "1400000cabababababababababababab",
              "frame writes type and a 3-byte length");
        HandshakeMessage m;
        t::ok(parse_handshake(f.data(), f.size(), m), "frame parses back");
        t::ok(m.type == HT_FINISHED && m.len == 12 && m.total == 16, "round-trips");

        t::ok(!parse_handshake(f.data(), 3, m), "a truncated header is refused");
        t::ok(!parse_handshake(f.data(), 15, m), "a truncated body is refused");
    }

    std::printf("[ServerHello]\n");
    {
        uint8_t rnd[32];
        for (int i = 0; i < 32; ++i) rnd[i] = static_cast<uint8_t>(0xA0 + i);
        auto body = server_hello_body(VERSION_TLS_1_0, rnd, TLS_RSA_WITH_RC4_128_MD5, {});
        ServerHello sh;
        t::ok(parse_server_hello(body.data(), body.size(), sh), "parses");
        t::ok(sh.version == VERSION_TLS_1_0, "version is TLS 1.0");
        t::ok(sh.cipher_suite == TLS_RSA_WITH_RC4_128_MD5, "suite is RC4-MD5");
        t::ok(sh.compression == 0, "compression is null");
        t::ok(sh.session_id.empty(), "no session id");
        t::eq(t::hex(sh.random, 32), t::hex(rnd, 32), "random round-trips");

        // With a session id, to check the variable-length field is honoured.
        std::vector<uint8_t> sid(32, 0x5A);
        auto body2 = server_hello_body(VERSION_TLS_1_0, rnd, TLS_RSA_WITH_RC4_128_SHA, sid);
        ServerHello sh2;
        t::ok(parse_server_hello(body2.data(), body2.size(), sh2), "parses with a session id");
        t::ok(sh2.session_id.size() == 32, "32-byte session id");
        t::ok(sh2.cipher_suite == TLS_RSA_WITH_RC4_128_SHA, "suite read past the session id");

        // An over-long SessionID must be refused rather than trusted. The
        // padding matters: without it a 33-byte SessionID simply runs off the
        // end of the buffer and is rejected for the wrong reason, which hides
        // whether the <0..32> bound is checked at all.
        auto bad = body2;
        bad[34] = 33;
        bad.insert(bad.end(), 4, 0x00);
        ServerHello sh3;
        t::ok(!parse_server_hello(bad.data(), bad.size(), sh3),
              "SessionID > 32 is refused by the bound, not by running out of bytes");
        auto padded_ok = body2;
        padded_ok.insert(padded_ok.end(), 4, 0x00);
        ServerHello sh4;
        t::ok(parse_server_hello(padded_ok.data(), padded_ok.size(), sh4),
              "the same message with a legal SessionID still parses");

        for (size_t n = 0; n < body.size(); ++n) {
            ServerHello tr;
            if (parse_server_hello(body.data(), n, tr)) {
                t::ok(false, "a truncated ServerHello was accepted");
                break;
            }
        }
        t::ok(true, "every truncated ServerHello is refused");
    }

    std::printf("[Certificate message carrying the real iLO certificate]\n");
    {
        auto der = t::unhex(ILO_CERT_DER_HEX);
        auto body = certificate_body(der);
        std::vector<CertificateEntry> certs;
        t::ok(parse_certificate_list(body.data(), body.size(), certs), "certificate list parses");
        t::ok(certs.size() == 1, "one certificate in the chain");
        t::ok(certs[0].len == der.size(), "length matches");

        // End to end: the bytes handed to der.hpp really do yield the key.
        RsaPublicKey key;
        t::ok(der::parse_certificate_rsa_key(certs[0].data, certs[0].len, key),
              "the extracted certificate yields an RSA key");
        t::ok(key.k == 128 && key.e == 65537, "1024-bit key with e=65537");

        for (size_t n = 0; n < body.size(); n += 13) {
            std::vector<CertificateEntry> tr;
            parse_certificate_list(body.data(), n, tr);      // must not over-read
        }
        t::ok(true, "truncated certificate lists are handled");
    }

    std::printf("[PreMasterSecret carries the OFFERED version]\n");
    {
        uint8_t pm1[48], pm2[48];
        t::ok(make_premaster(VERSION_TLS_1_0, pm1), "premaster generated");
        t::ok(make_premaster(VERSION_TLS_1_0, pm2), "premaster generated again");
        t::ok(pm1[0] == 0x03 && pm1[1] == 0x01, "first two bytes are the offered version");
        t::ok(std::memcmp(pm1 + 2, pm2 + 2, 46) != 0, "the remaining 46 bytes are random");
    }

    std::printf("[ClientKeyExchange length prefix]\n");
    {
        auto der = t::unhex(ILO_CERT_DER_HEX);
        RsaPublicKey key;
        t::ok(der::parse_certificate_rsa_key(der.data(), der.size(), key), "key extracted");

        uint8_t pm[48];
        make_premaster(VERSION_TLS_1_0, pm);
        std::vector<uint8_t> cke;
        t::ok(build_client_key_exchange(key, pm, cke), "ClientKeyExchange built");

        // 4 header + 2 length + 128 ciphertext.
        t::ok(cke.size() == 4 + 2 + 128, "total size is 134 bytes");
        t::ok(cke[0] == HT_CLIENT_KEY_EXCHANGE, "type is client_key_exchange");
        t::ok(cke[1] == 0 && cke[2] == 0 && cke[3] == 130, "handshake length is 130");
        // THE detail: TLS 1.0 prefixes the encrypted premaster with its length.
        // SSL 3.0 would start the ciphertext at offset 4 with no prefix.
        t::ok(cke[4] == 0x00 && cke[5] == 0x80, "two-byte length prefix reads 128");
    }

    std::printf("[transcript is genuinely MD5 and SHA-1 of the messages]\n");
    {
        // A known-answer test, because the simulated handshake below cannot
        // provide one: both sides there run this same code, so a fault that is
        // symmetric across them -- dropping SHA-1, say -- cancels out and goes
        // unnoticed. Pinning the digests to published values closes that.
        Transcript tr;
        const char* abc = "abc";
        tr.update(reinterpret_cast<const uint8_t*>(abc), 3);
        uint8_t m[16], sh[20];
        tr.snapshot(m, sh);
        t::eq(t::hex(m, 16), "900150983cd24fb0d6963f7d28e17f72",
              "transcript MD5 is MD5 of the concatenated messages");
        t::eq(t::hex(sh, 20), "a9993e364706816aba3e25717850c26c9cd0d89d",
              "transcript SHA-1 is SHA-1 of the concatenated messages");
    }

    std::printf("[transcript snapshot does not disturb the running hash]\n");
    {
        Transcript tr;
        const uint8_t a[] = { 1, 2, 3, 4 };
        const uint8_t b[] = { 5, 6, 7, 8 };
        tr.update(a, sizeof(a));

        uint8_t m1[16], s1[20], m2[16], s2[20];
        tr.snapshot(m1, s1);
        tr.snapshot(m2, s2);
        t::eq(t::hex(m1, 16), t::hex(m2, 16), "snapshot is repeatable");
        t::eq(t::hex(s1, 20), t::hex(s2, 20), "snapshot is repeatable (sha1)");

        tr.update(b, sizeof(b));
        uint8_t m3[16], s3[20];
        tr.snapshot(m3, s3);

        Transcript ref;
        ref.update(a, sizeof(a));
        ref.update(b, sizeof(b));
        uint8_t rm[16], rs[20];
        ref.snapshot(rm, rs);
        t::eq(t::hex(m3, 16), t::hex(rm, 16), "the running hash survived the snapshots");
        t::eq(t::hex(s3, 20), t::hex(rs, 20), "same for sha1");
    }

    std::printf("[alerts]\n");
    {
        const uint8_t fatal_hs[] = { 0x02, 0x28 };
        Alert al;
        t::ok(parse_alert(fatal_hs, 2, al), "alert parses");
        t::ok(al.level == 2 && al.description == 40, "fatal handshake_failure");
        t::eq(alert_name(40), "handshake_failure", "40 is handshake_failure");
        t::eq(alert_name(20), "bad_record_mac",    "20 is bad_record_mac");
        t::eq(alert_name(51), "decrypt_error",     "51 is decrypt_error");
        t::eq(alert_name(70), "protocol_version",  "70 is protocol_version");
        t::ok(!parse_alert(fatal_hs, 1, al), "a one-byte alert is refused");
    }

    // -----------------------------------------------------------------------
    // A full handshake against a simulated server.
    //
    // The simulated server is handed the premaster directly instead of RSA-
    // decrypting it: there is no private-key operation in this tree by design,
    // and RSA is covered by test_rsa / test_bigint. What this exercises is
    // everything else -- transcript ordering, the key schedule, the
    // ChangeCipherSpec transition, and both Finished computations meeting in
    // the middle through the real record layer.
    // -----------------------------------------------------------------------
    std::printf("[full handshake against a simulated server]\n");
    {
        uint8_t client_random[32], server_random[32], premaster[48];
        for (int i = 0; i < 32; ++i) client_random[i] = static_cast<uint8_t>(0x11 + i);
        for (int i = 0; i < 32; ++i) server_random[i] = static_cast<uint8_t>(0x77 + i);
        make_premaster(VERSION_TLS_1_0, premaster);

        auto der = t::unhex(ILO_CERT_DER_HEX);
        RsaPublicKey key;
        der::parse_certificate_rsa_key(der.data(), der.size(), key);

        Transcript client_tr, server_tr;

        auto ch = build_client_hello(VERSION_TLS_1_0, client_random,
                                     { TLS_RSA_WITH_RC4_128_MD5 });
        client_tr.update(ch);
        server_tr.update(ch);

        auto sh = frame(HT_SERVER_HELLO,
                        server_hello_body(VERSION_TLS_1_0, server_random,
                                          TLS_RSA_WITH_RC4_128_MD5, {}));
        auto cert = frame(HT_CERTIFICATE, certificate_body(der));
        auto done = frame(HT_SERVER_HELLO_DONE, {});
        for (const auto* m : { &sh, &cert, &done }) {
            client_tr.update(*m);
            server_tr.update(*m);
        }

        std::vector<uint8_t> cke;
        t::ok(build_client_key_exchange(key, premaster, cke), "client sends ClientKeyExchange");
        client_tr.update(cke);
        server_tr.update(cke);

        // Both sides derive the same secrets from the same inputs.
        uint8_t client_master[48], server_master[48];
        derive_master_secret(premaster, 48, client_random, server_random, client_master);
        derive_master_secret(premaster, 48, client_random, server_random, server_master);
        t::eq(t::hex(client_master, 48), t::hex(server_master, 48), "master secrets agree");

        uint8_t kb[KeyMaterial::KEY_BLOCK_LEN];
        derive_key_block(client_master, server_random, client_random, kb, sizeof(kb));
        KeyMaterial km;
        km.split(kb);

        // ChangeCipherSpec: the client's write side and the server's read side
        // switch to the CLIENT keys; the other direction uses the SERVER keys.
        RecordLayer client_layer, server_layer;
        client_layer.enable_write_cipher(km.client_mac, km.client_key);
        server_layer.enable_read_cipher (km.client_mac, km.client_key);

        auto client_fin = build_finished(client_master, LABEL_CLIENT_FINISHED, client_tr);
        std::vector<uint8_t> rec;
        t::ok(client_layer.protect(CT_HANDSHAKE, client_fin.data(), client_fin.size(), rec),
              "client Finished is protected");

        std::vector<uint8_t> got;
        RecordHeader h;
        parse_record_header(rec.data(), rec.size(), h);
        t::ok(server_layer.unprotect(h.type, h.version, rec.data() + RECORD_HEADER_LEN,
                                     rec.size() - RECORD_HEADER_LEN, got),
              "server decrypts and authenticates it");

        HandshakeMessage fin_msg;
        t::ok(parse_handshake(got.data(), got.size(), fin_msg), "Finished parses");
        t::ok(fin_msg.type == HT_FINISHED, "it is a Finished");
        t::ok(check_finished(server_master, LABEL_CLIENT_FINISHED, server_tr,
                             fin_msg.body, fin_msg.len),
              "server verifies the client's verify_data");

        // Both transcripts now absorb the client Finished, and the server replies.
        client_tr.update(client_fin);
        server_tr.update(client_fin);

        server_layer.enable_write_cipher(km.server_mac, km.server_key);
        client_layer.enable_read_cipher (km.server_mac, km.server_key);

        auto server_fin = build_finished(server_master, LABEL_SERVER_FINISHED, server_tr);
        std::vector<uint8_t> srec;
        server_layer.protect(CT_HANDSHAKE, server_fin.data(), server_fin.size(), srec);

        std::vector<uint8_t> sgot;
        parse_record_header(srec.data(), srec.size(), h);
        t::ok(client_layer.unprotect(h.type, h.version, srec.data() + RECORD_HEADER_LEN,
                                     srec.size() - RECORD_HEADER_LEN, sgot),
              "client decrypts the server Finished");
        HandshakeMessage sfin;
        parse_handshake(sgot.data(), sgot.size(), sfin);
        t::ok(check_finished(client_master, LABEL_SERVER_FINISHED, client_tr,
                             sfin.body, sfin.len),
              "client verifies the server's verify_data");

        // A transcript that diverges by one byte must break the verification --
        // otherwise Finished would not be binding the handshake at all.
        Transcript tampered = client_tr;
        const uint8_t extra = 0x00;
        tampered.update(&extra, 1);
        t::ok(!check_finished(client_master, LABEL_SERVER_FINISHED, tampered,
                              sfin.body, sfin.len),
              "a diverged transcript fails verification");

        // And the two labels must not be interchangeable.
        t::ok(!check_finished(client_master, LABEL_CLIENT_FINISHED, client_tr,
                              sfin.body, sfin.len),
              "the server Finished does not verify under the client label");

        // verify_data is exactly 12 bytes. A longer body must be rejected
        // outright rather than compared on its first 12, which would let a peer
        // append anything it liked to a valid Finished.
        std::vector<uint8_t> long_vd(sfin.body, sfin.body + sfin.len);
        long_vd.push_back(0x00);
        t::ok(!check_finished(client_master, LABEL_SERVER_FINISHED, client_tr,
                              long_vd.data(), long_vd.size()),
              "a 13-byte verify_data is refused");
        t::ok(!check_finished(client_master, LABEL_SERVER_FINISHED, client_tr,
                              sfin.body, sfin.len - 1),
              "an 11-byte verify_data is refused");
    }

    return t::report("test_handshake");
}
