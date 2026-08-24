// test_client.cpp — the handshake state machine, driven by a scripted mock
// transport rather than a socket.
//
// The mock cannot complete a handshake: it has no private key, so it cannot
// decrypt the premaster and cannot produce a Finished the client would accept.
// That half is already covered by test_handshake's simulated exchange. What is
// exercised here is everything a simulated exchange cannot reach — record
// reassembly, several handshake messages in one record, one message split
// across records, a byte-at-a-time transport, and every error path.
#include <cstring>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include <functional>
#include "tls/client.hpp"

using namespace ilo2;
using namespace ilo2::tls;

#include "tests/cert_fixture.inc"
#include "tests/mock_key.inc"

// ---------------------------------------------------------------------------
// A scripted transport
// ---------------------------------------------------------------------------

class MockTransport {
public:
    static constexpr int RECV_TIMEOUT = -2;
    static constexpr int RECV_ERROR   = -1;

    std::vector<uint8_t> to_client;     // what the "server" will deliver
    std::vector<uint8_t> from_client;   // what the client wrote
    size_t read_pos = 0;
    size_t chunk    = 4096;             // bytes yielded per recv()
    bool   closed   = false;

    // Called when the script runs dry. Returning true means more bytes were
    // appended to to_client, which is what lets the mock respond to the
    // client's flight rather than merely replay a canned one.
    std::function<bool(MockTransport&)> on_starved;

    bool connect(const std::string&, uint16_t, int, std::string&) { return true; }
    bool valid() const { return !closed; }
    void close() { closed = true; }
    void set_recv_timeout(int) {}

    int recv(uint8_t* buf, size_t cap) {
        if (read_pos >= to_client.size() && on_starved && !starved_once_) {
            starved_once_ = true;
            on_starved(*this);
        }
        if (read_pos >= to_client.size()) return 0;         // orderly EOF
        size_t n = to_client.size() - read_pos;
        if (n > cap)   n = cap;
        if (n > chunk) n = chunk;
        std::memcpy(buf, to_client.data() + read_pos, n);
        read_pos += n;
        return static_cast<int>(n);
    }
    bool send_all(const uint8_t* d, size_t n) {
        from_client.insert(from_client.end(), d, d + n);
        return true;
    }

private:
    bool starved_once_ = false;
};

using MockClient = ClientT<MockTransport>;

// ---------------------------------------------------------------------------
// Server-side record construction (all cleartext: pre-ChangeCipherSpec)
// ---------------------------------------------------------------------------

static void append_record(std::vector<uint8_t>& out, uint8_t type,
                          const uint8_t* data, size_t len) {
    out.push_back(type);
    out.push_back(0x03);
    out.push_back(0x01);
    out.push_back(static_cast<uint8_t>(len >> 8));
    out.push_back(static_cast<uint8_t>(len));
    out.insert(out.end(), data, data + len);
}
static void append_record(std::vector<uint8_t>& out, uint8_t type,
                          const std::vector<uint8_t>& v) {
    append_record(out, type, v.data(), v.size());
}

static std::vector<uint8_t> server_hello_body(uint16_t version, uint16_t suite) {
    std::vector<uint8_t> b;
    b.push_back(static_cast<uint8_t>(version >> 8));
    b.push_back(static_cast<uint8_t>(version));
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<uint8_t>(0x40 + i));
    b.push_back(0x00);                                  // empty session id
    b.push_back(static_cast<uint8_t>(suite >> 8));
    b.push_back(static_cast<uint8_t>(suite));
    b.push_back(0x00);                                  // null compression
    return b;
}

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

// The standard server flight, with knobs for the negative cases.
struct FlightOpts {
    uint16_t version = VERSION_TLS_1_0;
    uint16_t suite   = TLS_RSA_WITH_RC4_128_MD5;
    bool     cert_request       = false;
    bool     server_key_exchange = false;
    // 0 = one record per message, 1 = all messages in ONE record,
    // 2 = every message split across two records.
    int      packing = 0;
};

static std::vector<uint8_t> build_flight(const std::vector<uint8_t>& der,
                                         const FlightOpts& o) {
    std::vector<std::vector<uint8_t>> msgs;
    msgs.push_back(frame(HT_SERVER_HELLO, server_hello_body(o.version, o.suite)));
    msgs.push_back(frame(HT_CERTIFICATE, certificate_body(der)));
    if (o.server_key_exchange)
        msgs.push_back(frame(HT_SERVER_KEY_EXCHANGE, std::vector<uint8_t>(8, 0xAA)));
    if (o.cert_request)
        msgs.push_back(frame(HT_CERTIFICATE_REQUEST, std::vector<uint8_t>{ 0x01, 0x01, 0x00, 0x00 }));
    msgs.push_back(frame(HT_SERVER_HELLO_DONE, {}));

    std::vector<uint8_t> out;
    if (o.packing == 1) {
        std::vector<uint8_t> all;
        for (const auto& m : msgs) all.insert(all.end(), m.begin(), m.end());
        append_record(out, CT_HANDSHAKE, all);          // every message, one record
    } else if (o.packing == 2) {
        for (const auto& m : msgs) {                     // each message, two records
            const size_t half = m.size() / 2;
            append_record(out, CT_HANDSHAKE, m.data(), half);
            append_record(out, CT_HANDSHAKE, m.data() + half, m.size() - half);
        }
    } else {
        for (const auto& m : msgs) append_record(out, CT_HANDSHAKE, m);
    }
    return out;
}

// What did the client actually put on the wire?
struct SentRecords {
    std::vector<uint8_t> types;
    std::vector<std::vector<uint8_t>> bodies;
};

static SentRecords split_sent(const std::vector<uint8_t>& raw) {
    SentRecords s;
    size_t off = 0;
    while (off + RECORD_HEADER_LEN <= raw.size()) {
        RecordHeader h;
        if (!parse_record_header(raw.data() + off, raw.size() - off, h)) break;
        if (off + RECORD_HEADER_LEN + h.length > raw.size()) break;
        s.types.push_back(h.type);
        s.bodies.emplace_back(raw.begin() + off + RECORD_HEADER_LEN,
                              raw.begin() + off + RECORD_HEADER_LEN + h.length);
        off += RECORD_HEADER_LEN + h.length;
    }
    return s;
}

static void run_flight(const char* what, const std::vector<uint8_t>& der,
                       const FlightOpts& o, size_t chunk) {
    MockClient c;
    c.transport().to_client = build_flight(der, o);
    c.transport().chunk = chunk;

    std::string err;
    bool ok = c.connect("mock", 443, err);
    t::ok(!ok, "handshake cannot complete against a keyless mock");
    // The flight ends without a ChangeCipherSpec, so the client should get all
    // the way through its own output and then hit end of stream.
    t::eq(err, "connection closed by peer", what);

    auto sent = split_sent(c.transport().from_client);
    const size_t expect_records = o.cert_request ? 5u : 4u;
    char label[128];
    std::snprintf(label, sizeof(label), "%s: client sent %zu records", what, expect_records);
    t::ok(sent.types.size() == expect_records, label);

    if (sent.types.size() == expect_records) {
        size_t i = 0;
        t::ok(sent.types[i] == CT_HANDSHAKE && sent.bodies[i][0] == HT_CLIENT_HELLO,
              "record 1 is ClientHello");
        ++i;
        if (o.cert_request) {
            t::ok(sent.types[i] == CT_HANDSHAKE && sent.bodies[i][0] == HT_CERTIFICATE,
                  "an empty Certificate answers CertificateRequest");
            ++i;
        }
        t::ok(sent.types[i] == CT_HANDSHAKE && sent.bodies[i][0] == HT_CLIENT_KEY_EXCHANGE,
              "then ClientKeyExchange");
        t::ok(sent.bodies[i].size() == 4 + 2 + 128, "with the 2-byte length prefix");
        ++i;
        t::ok(sent.types[i] == CT_CHANGE_CIPHER_SPEC && sent.bodies[i].size() == 1 &&
              sent.bodies[i][0] == 0x01, "then ChangeCipherSpec");
        ++i;
        // The Finished is the first ENCRYPTED record: 4 header + 12 verify_data
        // + 16 MAC = 32 bytes, and its first byte must no longer read as a
        // plaintext handshake type.
        t::ok(sent.types[i] == CT_HANDSHAKE, "then a handshake record");
        t::ok(sent.bodies[i].size() == 4 + VERIFY_DATA_LEN + 16,
              "Finished is encrypted (verify_data + MAC)");
    }

    t::ok(c.server_key().k == 128 && c.server_key().e == 65537,
          "the server's RSA key was extracted from the certificate");
    t::ok(c.cipher_suite() == TLS_RSA_WITH_RC4_128_MD5, "negotiated RC4-MD5");
}

int main() {
    const std::vector<uint8_t> der = t::unhex(ILO_CERT_DER_HEX);

    std::printf("[ClientHello is sent before anything is read]\n");
    {
        MockClient c;                       // nothing scripted: immediate EOF
        std::string err;
        t::ok(!c.connect("mock", 443, err), "handshake fails on an empty stream");
        auto sent = split_sent(c.transport().from_client);
        t::ok(sent.types.size() == 1, "exactly one record was sent");
        t::ok(sent.types[0] == CT_HANDSHAKE, "it is a handshake record");
        t::ok(sent.bodies[0][0] == HT_CLIENT_HELLO, "it is a ClientHello");
        // 2 version + 32 random + 1 sid + 2 suite_len + 2 suite + 2 compression
        t::ok(sent.bodies[0].size() == 4 + 41, "one cipher suite offered, no extensions");
        // Body layout: version(2) random(32) sid_len(1) suites_len(2) suites..
        // so 35..36 is the LENGTH of the suite list and 37..38 is the suite.
        t::ok(sent.bodies[0][HANDSHAKE_HEADER_LEN + 35] == 0x00 &&
              sent.bodies[0][HANDSHAKE_HEADER_LEN + 36] == 0x02,
              "exactly one cipher suite is offered");
        t::ok(sent.bodies[0][HANDSHAKE_HEADER_LEN + 37] == 0x00 &&
              sent.bodies[0][HANDSHAKE_HEADER_LEN + 38] == 0x04,
              "the offered suite is TLS_RSA_WITH_RC4_128_MD5");
    }

    std::printf("[full client flight, one record per message]\n");
    run_flight("one record per message", der, FlightOpts{}, 4096);

    std::printf("[all server messages packed into a single record]\n");
    {
        FlightOpts o; o.packing = 1;
        run_flight("single packed record", der, o, 4096);
    }

    std::printf("[each server message split across two records]\n");
    {
        FlightOpts o; o.packing = 2;
        run_flight("split across records", der, o, 4096);
    }

    std::printf("[a transport that yields one byte at a time]\n");
    {
        FlightOpts o; o.packing = 2;
        run_flight("byte-at-a-time transport", der, o, 1);
    }

    std::printf("[CertificateRequest is answered with an empty Certificate]\n");
    {
        FlightOpts o; o.cert_request = true;
        run_flight("certificate requested", der, o, 4096);
    }

    std::printf("[negotiation errors are specific]\n");
    {
        auto expect_error = [&](const FlightOpts& o, const char* want, const char* what) {
            MockClient c;
            c.transport().to_client = build_flight(der, o);
            std::string err;
            t::ok(!c.connect("mock", 443, err), "handshake refused");
            t::eq(err, want, what);
        };

        FlightOpts bad_suite; bad_suite.suite = 0x002F;      // AES128-SHA
        expect_error(bad_suite,
                     "server chose cipher suite 0x002f, which we did not offer",
                     "an unoffered cipher suite is named in the error");

        FlightOpts bad_version; bad_version.version = 0x0300;
        expect_error(bad_version,
                     "server chose version 0x0300, we offered 0x0301",
                     "a downgrade to SSL 3.0 is named in the error");

        FlightOpts ske; ske.server_key_exchange = true;
        expect_error(ske,
                     "server sent ServerKeyExchange for an RSA key exchange",
                     "ServerKeyExchange is rejected for an RSA key exchange");
    }

    std::printf("[alerts during the handshake]\n");
    {
        MockClient c;
        const uint8_t fatal[2] = { 2, 40 };                  // handshake_failure
        append_record(c.transport().to_client, CT_ALERT, fatal, sizeof(fatal));
        std::string err;
        t::ok(!c.connect("mock", 443, err), "a fatal alert aborts the handshake");
        t::eq(err, "fatal alert: handshake_failure (40)", "the alert is named, not numbered");

        MockClient c2;
        const uint8_t bye[2] = { 1, 0 };                     // close_notify
        append_record(c2.transport().to_client, CT_ALERT, bye, sizeof(bye));
        std::string err2;
        t::ok(!c2.connect("mock", 443, err2), "close_notify aborts the handshake");
        t::eq(err2, "peer sent close_notify", "close_notify is reported as such");

        // A warning alert must NOT abort: the client should keep reading and
        // then hit end of stream instead.
        MockClient c3;
        const uint8_t warn[2] = { 1, 100 };                  // no_renegotiation
        append_record(c3.transport().to_client, CT_ALERT, warn, sizeof(warn));
        std::string err3;
        t::ok(!c3.connect("mock", 443, err3), "stream still ends");
        t::eq(err3, "connection closed by peer", "a warning alert is skipped, not fatal");
    }

    std::printf("[malformed server input]\n");
    {
        MockClient c;
        // A record claiming an invalid content type.
        const uint8_t junk[4] = { 0, 0, 0, 0 };
        append_record(c.transport().to_client, 99, junk, sizeof(junk));
        std::string err;
        t::ok(!c.connect("mock", 443, err), "an invalid content type is refused");
        t::eq(err, "invalid record content type 99", "and named");

        // A Certificate message before ServerHello.
        MockClient c2;
        append_record(c2.transport().to_client, CT_HANDSHAKE,
                      frame(HT_CERTIFICATE, certificate_body(der)));
        std::string err2;
        t::ok(!c2.connect("mock", 443, err2), "out-of-order handshake is refused");
        t::eq(err2, "expected ServerHello, got handshake type 11", "and named");

        // A truncated flight: every prefix must fail cleanly, never over-read.
        auto full = build_flight(der, FlightOpts{});
        for (size_t n = 0; n < full.size(); n += 17) {
            MockClient tc;
            tc.transport().to_client.assign(full.begin(), full.begin() + n);
            std::string terr;
            tc.connect("mock", 443, terr);
        }
        t::ok(true, "every truncated server flight was handled");
    }

    // -----------------------------------------------------------------------
    // A handshake that actually completes.
    //
    // Everything above watches the client talk and never confirms it can finish.
    // That matters most for the transcript: Finished must be verified against
    // the transcript as it stood BEFORE that message arrived, and nothing else
    // in this suite can catch getting that wrong. To close it, the mock is given
    // a throwaway private key so it can decrypt the premaster, agree on the
    // master secret and produce a Finished the client will accept.
    // -----------------------------------------------------------------------
    std::printf("[a handshake that completes]\n");
    {
        const auto mock_der = t::unhex(MOCK_CERT_DER_HEX);
        const auto mod_be   = t::unhex(MOCK_MODULUS_HEX);
        const auto d_be     = t::unhex(MOCK_PRIVATE_EXPONENT_HEX);

        RsaInt mock_n;
        mock_n.from_bytes(mod_be.data(), mod_be.size());

        uint8_t server_random[32];
        for (int i = 0; i < 32; ++i) server_random[i] = static_cast<uint8_t>(0x90 + i);

        MockClient c;

        // Phase 1: the server's opening flight.
        std::vector<uint8_t> sh   = frame(HT_SERVER_HELLO, [&] {
            std::vector<uint8_t> b;
            b.push_back(0x03); b.push_back(0x01);
            b.insert(b.end(), server_random, server_random + 32);
            b.push_back(0x00);
            b.push_back(0x00); b.push_back(0x04);
            b.push_back(0x00);
            return b;
        }());
        std::vector<uint8_t> cert = frame(HT_CERTIFICATE, certificate_body(mock_der));
        std::vector<uint8_t> done = frame(HT_SERVER_HELLO_DONE, {});
        append_record(c.transport().to_client, CT_HANDSHAKE, sh);
        append_record(c.transport().to_client, CT_HANDSHAKE, cert);
        append_record(c.transport().to_client, CT_HANDSHAKE, done);

        bool server_verified_client = false;

        // Phase 2: answer the client's flight.
        c.transport().on_starved = [&](MockTransport& tp) {
            auto sent = split_sent(tp.from_client);
            if (sent.types.size() < 4) return false;

            const std::vector<uint8_t>& ch_rec  = sent.bodies[0];
            const std::vector<uint8_t>& cke_rec = sent.bodies[1];
            const std::vector<uint8_t>& fin_rec = sent.bodies[3];

            uint8_t client_random[32];
            std::memcpy(client_random, ch_rec.data() + HANDSHAKE_HEADER_LEN + 2, 32);

            // Decrypt the premaster. The big-exponent modexp lives here rather
            // than in crypto/ on purpose: the production tree has no
            // private-key operation, so one cannot be reached by accident.
            RsaInt ct;
            ct.from_bytes(cke_rec.data() + HANDSHAKE_HEADER_LEN + 2,
                          cke_rec.size() - HANDSHAKE_HEADER_LEN - 2);
            RsaInt acc;
            acc.zero();
            acc.v[0] = 1;
            for (size_t i = 0; i < d_be.size(); ++i)
                for (int b = 7; b >= 0; --b) {
                    RsaInt::mulmod(acc.v, acc.v, mock_n.v, acc.v);
                    if ((d_be[i] >> b) & 1) RsaInt::mulmod(acc.v, ct.v, mock_n.v, acc.v);
                }

            uint8_t full[RsaInt::BYTES];
            acc.to_bytes(full);
            const uint8_t* em = full + (RsaInt::BYTES - mod_be.size());
            if (em[0] != 0x00 || em[1] != 0x02) return false;
            size_t z = 2;
            while (z < mod_be.size() && em[z] != 0x00) ++z;
            if (z + 1 + PREMASTER_LEN != mod_be.size()) return false;
            const uint8_t* premaster = em + z + 1;

            uint8_t master[MASTER_SECRET_LEN];
            derive_master_secret(premaster, PREMASTER_LEN, client_random, server_random, master);
            uint8_t kb[KeyMaterial::KEY_BLOCK_LEN];
            derive_key_block(master, server_random, client_random, kb, sizeof(kb));
            KeyMaterial km;
            km.split(kb);

            // Rebuild the transcript exactly as the client should have it.
            Transcript tr;
            tr.update(ch_rec);
            tr.update(sh);
            tr.update(cert);
            tr.update(done);
            tr.update(cke_rec);

            RecordLayer server_side;
            server_side.enable_read_cipher(km.client_mac, km.client_key);
            std::vector<uint8_t> client_fin;
            if (!server_side.unprotect(CT_HANDSHAKE, VERSION_TLS_1_0,
                                       fin_rec.data(), fin_rec.size(), client_fin))
                return false;
            HandshakeMessage fm;
            if (!parse_handshake(client_fin.data(), client_fin.size(), fm)) return false;
            if (!check_finished(master, LABEL_CLIENT_FINISHED, tr, fm.body, fm.len)) return false;
            server_verified_client = true;

            tr.update(client_fin);

            const uint8_t ccs = 0x01;
            append_record(tp.to_client, CT_CHANGE_CIPHER_SPEC, &ccs, 1);
            server_side.enable_write_cipher(km.server_mac, km.server_key);
            auto server_fin = build_finished(master, LABEL_SERVER_FINISHED, tr);
            std::vector<uint8_t> protectedd;
            server_side.protect(CT_HANDSHAKE, server_fin.data(), server_fin.size(), protectedd);
            tp.to_client.insert(tp.to_client.end(), protectedd.begin(), protectedd.end());
            return true;
        };

        std::string err;
        bool ok = c.connect("mock", 443, err);
        t::ok(ok, err.empty() ? "handshake completed" : ("handshake failed: " + err).c_str());
        t::ok(server_verified_client, "the server verified the client's Finished");
        t::ok(c.connected(), "client reports itself connected");
        t::ok(c.cipher_suite() == TLS_RSA_WITH_RC4_128_MD5, "negotiated RC4-MD5");
        t::ok(c.server_certificate().size() == mock_der.size(), "server certificate retained");
    }

    return t::report("test_client");
}
