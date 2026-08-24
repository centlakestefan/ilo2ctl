// client.hpp — the TLS 1.0 client: handshake state machine, record framing over
// a socket, and an HTTPS GET on top.
//
// Only TLS_RSA_WITH_RC4_128_MD5 is offered. That is not a limitation being
// tolerated, it is the measured first preference of the device this talks to,
// and offering exactly one suite means the negotiation either produces the
// cipher we implement or fails immediately with a diagnosable
// handshake_failure, rather than selecting something we would then have to
// refuse. Adding RC4-SHA is a typedef in record.hpp plus templating this class
// on the MAC hash.
//
// Certificates are NOT verified. The iLO 2 presents a self-signed, MD5-signed
// certificate that expired in 2022, so there is no configuration in which
// verification could succeed; the trust decision is "this is the BMC at the
// address I typed", exactly as with curl -k and HP's own applet. The public key
// is used for the key exchange and nothing else.
//
// Two structural points that a record layer alone does not handle:
//
//   * A handshake MESSAGE is not a record. One record can carry several
//     messages, and one message can span several records, so handshake bytes
//     are reassembled in a buffer independent of record boundaries.
//   * ChangeCipherSpec is a record content type, not a handshake message. It is
//     never fed to the transcript, and it is the point at which each direction
//     switches keys and resets its sequence number.
#pragma once
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include "crypto/rsa.hpp"
#include "tls/der.hpp"
#include "tls/handshake.hpp"
#include "tls/prf.hpp"
#include "tls/record.hpp"
#include "tls/socket.hpp"

namespace ilo2 {
namespace tls {

// Templated on the transport so the handshake state machine can be driven by a
// scripted mock in the tests. Record reassembly, multi-message records and the
// error paths are the bug-prone parts of this file, and none of them should
// need hardware to exercise.
template <class Transport>
class ClientT {
public:
    struct Options {
        uint16_t version    = VERSION_TLS_1_0;
        int      timeout_ms = 15000;
        uint32_t gmt_unix_time = 0;   // cosmetic; ClientHello.random's first 4 bytes
    };

    ClientT() = default;
    explicit ClientT(const Options& o) : opt_(o) {}

    // Test seam: lets a mock be preloaded with a scripted server flight and
    // inspected for what the client sent.
    Transport&       transport()       { return sock_; }
    const Transport& transport() const { return sock_; }

    bool connect(const std::string& host, uint16_t port, std::string& err) {
        if (!sock_.connect(host, port, opt_.timeout_ms, err)) return false;
        return handshake(err);
    }

    bool send(const uint8_t* data, size_t len, std::string& err) {
        // Fragment anything oversized; the record layer refuses > 2^14 outright.
        while (len) {
            const size_t n = len < MAX_PLAINTEXT ? len : MAX_PLAINTEXT;
            if (!send_record(CT_APPLICATION_DATA, data, n, err)) return false;
            data += n;
            len  -= n;
        }
        return true;
    }
    bool send(const std::string& s, std::string& err) {
        return send(reinterpret_cast<const uint8_t*>(s.data()), s.size(), err);
    }

    // One record's worth of application data. Returns false at end of stream or
    // on error; `eof` distinguishes a clean close_notify from a failure.
    bool recv(std::vector<uint8_t>& out, bool& eof, std::string& err) {
        eof = false;
        for (;;) {
            RecordHeader h;
            std::vector<uint8_t> pt;
            if (!read_record(h, pt, err)) {
                eof = eof_;
                return false;
            }
            if (h.type == CT_APPLICATION_DATA) {
                out = std::move(pt);
                return true;
            }
            if (h.type == CT_ALERT) {
                if (!handle_alert(pt, err)) { eof = eof_; return false; }
                continue;                       // a warning we chose to ignore
            }
            // Handshake records after the handshake would be renegotiation,
            // which this client does not do.
            err = "unexpected record type " + std::to_string(h.type) + " after handshake";
            return false;
        }
    }

    void close() {
        if (sock_.valid() && rec_.write_active()) {
            std::string ignored;
            const uint8_t close_notify[2] = { 1, 0 };
            send_record(CT_ALERT, close_notify, sizeof(close_notify), ignored);
        }
        sock_.close();
    }

    bool                connected()    const { return connected_; }
    const RsaPublicKey& server_key()   const { return server_key_; }
    uint16_t            cipher_suite() const { return suite_; }
    const std::vector<uint8_t>& server_certificate() const { return server_cert_; }

private:
    // ---- handshake ---------------------------------------------------------

    bool handshake(std::string& err) {
        uint8_t client_random[RANDOM_LEN];
        if (!make_client_random(opt_.gmt_unix_time, client_random)) {
            err = "the system CSPRNG failed";
            return false;
        }

        auto ch = build_client_hello(opt_.version, client_random,
                                     { TLS_RSA_WITH_RC4_128_MD5 });
        transcript_.update(ch);
        if (!send_record(CT_HANDSHAKE, ch.data(), ch.size(), err)) return false;

        // --- ServerHello ---
        std::vector<uint8_t> msg;
        HandshakeMessage m;
        if (!next_handshake(msg, m, err)) return false;
        if (m.type != HT_SERVER_HELLO) {
            err = "expected ServerHello, got handshake type " + std::to_string(m.type);
            return false;
        }
        transcript_.update(msg);
        ServerHello sh;
        if (!parse_server_hello(m.body, m.len, sh)) { err = "malformed ServerHello"; return false; }
        if (sh.version != opt_.version) {
            err = "server chose version 0x" + hex16(sh.version) +
                  ", we offered 0x" + hex16(opt_.version);
            return false;
        }
        if (sh.cipher_suite != TLS_RSA_WITH_RC4_128_MD5) {
            err = "server chose cipher suite 0x" + hex16(sh.cipher_suite) +
                  ", which we did not offer";
            return false;
        }
        if (sh.compression != 0) { err = "server selected compression"; return false; }
        suite_ = sh.cipher_suite;
        uint8_t server_random[RANDOM_LEN];
        std::memcpy(server_random, sh.random, RANDOM_LEN);

        // --- Certificate ---
        if (!next_handshake(msg, m, err)) return false;
        if (m.type != HT_CERTIFICATE) {
            err = "expected Certificate, got handshake type " + std::to_string(m.type);
            return false;
        }
        transcript_.update(msg);
        std::vector<CertificateEntry> certs;
        if (!parse_certificate_list(m.body, m.len, certs)) {
            err = "malformed Certificate message";
            return false;
        }
        server_cert_.assign(certs[0].data, certs[0].data + certs[0].len);
        if (!der::parse_certificate_rsa_key(certs[0].data, certs[0].len, server_key_)) {
            err = "no usable RSA public key in the server certificate";
            return false;
        }

        // --- optional messages, then ServerHelloDone ---
        bool cert_requested = false;
        for (;;) {
            if (!next_handshake(msg, m, err)) return false;
            transcript_.update(msg);
            if (m.type == HT_SERVER_HELLO_DONE) break;
            if (m.type == HT_CERTIFICATE_REQUEST) { cert_requested = true; continue; }
            if (m.type == HT_SERVER_KEY_EXCHANGE) {
                // Meaningless for an RSA key exchange: the premaster is
                // encrypted to the certificate's key, and there are no
                // ephemeral parameters to carry.
                err = "server sent ServerKeyExchange for an RSA key exchange";
                return false;
            }
            err = "unexpected handshake type " + std::to_string(m.type) +
                  " before ServerHelloDone";
            return false;
        }

        // --- our flight ---
        if (cert_requested) {
            auto empty = build_empty_certificate();
            transcript_.update(empty);
            if (!send_record(CT_HANDSHAKE, empty.data(), empty.size(), err)) return false;
        }

        uint8_t premaster[PREMASTER_LEN];
        // The OFFERED version, not the negotiated one -- a rollback check.
        if (!make_premaster(opt_.version, premaster)) {
            err = "the system CSPRNG failed";
            return false;
        }

        std::vector<uint8_t> cke;
        if (!build_client_key_exchange(server_key_, premaster, cke)) {
            err = "RSA encryption of the premaster failed";
            return false;
        }
        transcript_.update(cke);
        if (!send_record(CT_HANDSHAKE, cke.data(), cke.size(), err)) return false;

        uint8_t master[MASTER_SECRET_LEN];
        derive_master_secret(premaster, PREMASTER_LEN, client_random, server_random, master);
        std::memset(premaster, 0, sizeof(premaster));

        uint8_t kb[KeyMaterial::KEY_BLOCK_LEN];
        derive_key_block(master, server_random, client_random, kb, sizeof(kb));
        KeyMaterial km;
        km.split(kb);
        std::memset(kb, 0, sizeof(kb));

        // ChangeCipherSpec is a record, not a handshake message: it is NOT fed
        // to the transcript, and it is what switches our write side over.
        const uint8_t ccs = 0x01;
        if (!send_record(CT_CHANGE_CIPHER_SPEC, &ccs, 1, err)) return false;
        rec_.enable_write_cipher(km.client_mac, km.client_key);

        auto client_fin = build_finished(master, LABEL_CLIENT_FINISHED, transcript_);
        transcript_.update(client_fin);
        if (!send_record(CT_HANDSHAKE, client_fin.data(), client_fin.size(), err)) return false;

        // --- server flight ---
        if (!expect_change_cipher_spec(err)) return false;
        rec_.enable_read_cipher(km.server_mac, km.server_key);

        if (!next_handshake(msg, m, err)) return false;
        if (m.type != HT_FINISHED) {
            err = "expected Finished, got handshake type " + std::to_string(m.type);
            return false;
        }
        // Verify BEFORE absorbing: the transcript must not yet contain the
        // very message being verified.
        if (!check_finished(master, LABEL_SERVER_FINISHED, transcript_, m.body, m.len)) {
            err = "the server's Finished did not verify";
            return false;
        }
        transcript_.update(msg);
        std::memset(master, 0, sizeof(master));

        connected_ = true;
        return true;
    }

    // ---- record and message plumbing ---------------------------------------

    bool send_record(uint8_t type, const uint8_t* data, size_t len, std::string& err) {
        std::vector<uint8_t> rec;
        if (!rec_.protect(type, data, len, rec)) { err = "record protection failed"; return false; }
        if (!sock_.send_all(rec.data(), rec.size())) { err = "socket write failed"; return false; }
        return true;
    }

    bool fill(size_t need, std::string& err) {
        while (rx_.size() < need) {
            uint8_t buf[4096];
            int n = sock_.recv(buf, sizeof(buf));
            if (n > 0) { rx_.insert(rx_.end(), buf, buf + n); continue; }
            if (n == 0) {
                eof_ = true;
                err = "connection closed by peer";
                return false;
            }
            if (n == Transport::RECV_TIMEOUT) { err = "timed out waiting for data"; return false; }
            err = "socket read failed";
            return false;
        }
        return true;
    }

    bool read_record(RecordHeader& h, std::vector<uint8_t>& plaintext, std::string& err) {
        if (!fill(RECORD_HEADER_LEN, err)) return false;
        if (!parse_record_header(rx_.data(), rx_.size(), h)) {
            err = "malformed record header";
            return false;
        }
        if (!is_valid_content_type(h.type)) {
            err = "invalid record content type " + std::to_string(h.type);
            return false;
        }
        if (!fill(RECORD_HEADER_LEN + h.length, err)) return false;

        const uint8_t* body = rx_.data() + RECORD_HEADER_LEN;
        if (!rec_.unprotect(h.type, h.version, body, h.length, plaintext)) {
            // Unrecoverable: the keystream has already advanced over this
            // record, so the read cipher can never resynchronise.
            err = "record failed authentication (bad_record_mac)";
            return false;
        }
        rx_.erase(rx_.begin(),
                  rx_.begin() + static_cast<ptrdiff_t>(RECORD_HEADER_LEN + h.length));
        return true;
    }

    // Pull one complete handshake message, reassembling across records and
    // splitting records that carry more than one. `store` owns the bytes that
    // `out` points into, and is also what must be fed to the transcript.
    bool next_handshake(std::vector<uint8_t>& store, HandshakeMessage& out,
                        std::string& err) {
        for (;;) {
            HandshakeMessage m;
            if (parse_handshake(hs_.data(), hs_.size(), m)) {
                store.assign(hs_.begin(), hs_.begin() + static_cast<ptrdiff_t>(m.total));
                hs_.erase(hs_.begin(), hs_.begin() + static_cast<ptrdiff_t>(m.total));
                if (!parse_handshake(store.data(), store.size(), out)) {
                    err = "internal: handshake message did not re-parse";
                    return false;
                }
                // The transcript is deliberately NOT updated here. The
                // server's Finished must be verified against the transcript as
                // it stood BEFORE that message, so absorbing it automatically
                // would make verification compare against a hash that already
                // included what it is verifying. The caller absorbs each
                // message once it has been handled.
                return true;
            }

            RecordHeader h;
            std::vector<uint8_t> pt;
            if (!read_record(h, pt, err)) return false;
            if (h.type == CT_ALERT) {
                if (!handle_alert(pt, err)) return false;
                continue;
            }
            if (h.type != CT_HANDSHAKE) {
                err = "expected a handshake record, got content type " + std::to_string(h.type);
                return false;
            }
            hs_.insert(hs_.end(), pt.begin(), pt.end());
        }
    }

    bool expect_change_cipher_spec(std::string& err) {
        if (!hs_.empty()) {
            err = "handshake data remained when ChangeCipherSpec was expected";
            return false;
        }
        for (;;) {
            RecordHeader h;
            std::vector<uint8_t> pt;
            if (!read_record(h, pt, err)) return false;
            if (h.type == CT_ALERT) {
                if (!handle_alert(pt, err)) return false;
                continue;
            }
            if (h.type != CT_CHANGE_CIPHER_SPEC) {
                err = "expected ChangeCipherSpec, got content type " + std::to_string(h.type);
                return false;
            }
            if (pt.size() != 1 || pt[0] != 0x01) {
                err = "malformed ChangeCipherSpec";
                return false;
            }
            return true;
        }
    }

    // Returns true if the alert was a warning that can be ignored.
    bool handle_alert(const std::vector<uint8_t>& body, std::string& err) {
        Alert a;
        if (!parse_alert(body.data(), body.size(), a)) {
            err = "malformed alert";
            return false;
        }
        if (a.description == 0) {          // close_notify
            eof_ = true;
            err = "peer sent close_notify";
            return false;
        }
        if (a.level == 2) {
            err = std::string("fatal alert: ") + alert_name(a.description) +
                  " (" + std::to_string(a.description) + ")";
            return false;
        }
        return true;                       // warning: keep going
    }

    static std::string hex16(uint16_t v) {
        static const char* H = "0123456789abcdef";
        std::string s(4, '0');
        s[0] = H[(v >> 12) & 0xF];
        s[1] = H[(v >> 8)  & 0xF];
        s[2] = H[(v >> 4)  & 0xF];
        s[3] = H[v & 0xF];
        return s;
    }

    Options              opt_;
    Transport            sock_;
    RecordLayer          rec_;
    Transcript           transcript_;
    std::vector<uint8_t> rx_;            // raw bytes from the socket
    std::vector<uint8_t> hs_;            // reassembled handshake plaintext
    RsaPublicKey         server_key_;
    std::vector<uint8_t> server_cert_;
    uint16_t             suite_     = 0;
    bool                 connected_ = false;
    bool                 eof_       = false;
};

using Client = ClientT<net::TcpSocket>;

// ---------------------------------------------------------------------------
// HTTPS
// ---------------------------------------------------------------------------

struct HttpResponse {
    int         status = 0;
    std::string headers;
    std::string body;
};

// Case-insensitive header lookup; returns the value with surrounding space
// trimmed, or "" when the header is absent.
inline std::string header_value(const std::string& headers, const std::string& name) {
    auto lower = [](std::string v) {
        for (char& ch : v) if (ch >= 'A' && ch <= 'Z') ch = static_cast<char>(ch - 'A' + 'a');
        return v;
    };
    const std::string hay = lower(headers), needle = lower(name) + ":";
    size_t pos = 0;
    while (pos < hay.size()) {
        const size_t eol = hay.find("\r\n", pos);
        const size_t end = (eol == std::string::npos) ? hay.size() : eol;
        if (hay.compare(pos, needle.size(), needle) == 0) {
            size_t vs = pos + needle.size();
            while (vs < end && (headers[vs] == ' ' || headers[vs] == '\t')) ++vs;
            size_t ve = end;
            while (ve > vs && (headers[ve - 1] == ' ' || headers[ve - 1] == '\t')) --ve;
            return headers.substr(vs, ve - vs);
        }
        if (eol == std::string::npos) break;
        pos = eol + 2;
    }
    return std::string();
}

// Decode HTTP chunked transfer coding. The iLO uses it for every page, since it
// only serves HTTP/1.1 (see below), so this is not optional.
inline bool dechunk(const std::string& in, std::string& out) {
    size_t pos = 0;
    for (;;) {
        const size_t eol = in.find("\r\n", pos);
        if (eol == std::string::npos) return false;
        std::string line = in.substr(pos, eol - pos);
        const size_t semi = line.find(';');           // chunk extensions
        if (semi != std::string::npos) line.resize(semi);

        size_t size = 0;
        bool any = false;
        for (char ch : line) {
            int v;
            if (ch >= '0' && ch <= '9')      v = ch - '0';
            else if (ch >= 'a' && ch <= 'f') v = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F') v = ch - 'A' + 10;
            else if (ch == ' ' || ch == '\t') continue;
            else return false;
            size = size * 16 + static_cast<size_t>(v);
            any = true;
        }
        if (!any) return false;

        pos = eol + 2;
        if (size == 0) return true;                   // terminating chunk
        if (pos + size > in.size()) return false;
        out.append(in, pos, size);
        pos += size;
        if (in.compare(pos, 2, "\r\n") != 0) return false;
        pos += 2;
    }
}

// An HTTPS GET, replacing the `curl -k --tlsv1.0` the Python scrapers shell out
// to. Two things this device forces, both learned from it directly:
//
//   * HTTP/1.1 is mandatory. An HTTP/1.0 request is answered 200 OK with a page
//     reading "Your browser must support HTTP 1.1 to view iLO web pages" -- so
//     the failure is not an error code, it is a valid-looking wrong page, which
//     is exactly the sort of thing a scraper silently mistakes for content.
//   * Every response is then chunked, so the body must be de-chunked.
inline bool https_get(const std::string& host, uint16_t port, const std::string& path,
                      const std::string& cookie, HttpResponse& out, std::string& err) {
    Client c;
    if (!c.connect(host, port, err)) return false;

    std::string req = "GET " + path + " HTTP/1.1\r\n"
                      "Host: " + host + "\r\n"
                      "User-Agent: ilo2-console/1.0\r\n"
                      "Accept: */*\r\n";
    if (!cookie.empty()) req += "Cookie: " + cookie + "\r\n";
    req += "Connection: close\r\n\r\n";

    if (!c.send(req, err)) { c.close(); return false; }

    std::string raw;
    for (;;) {
        std::vector<uint8_t> chunk;
        bool eof = false;
        std::string rerr;
        if (!c.recv(chunk, eof, rerr)) {
            if (eof) break;               // close_notify or orderly EOF
            c.close();
            err = rerr;
            return false;
        }
        raw.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        if (raw.size() > 8u * 1024 * 1024) { err = "response too large"; c.close(); return false; }
    }
    c.close();

    if (raw.empty()) { err = "empty response"; return false; }

    const size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) {
        out.headers = raw;
    } else {
        out.headers = raw.substr(0, split);
        out.body    = raw.substr(split + 4);
    }
    if (raw.compare(0, 5, "HTTP/") == 0) {
        const size_t sp = out.headers.find(' ');
        if (sp != std::string::npos) out.status = std::atoi(out.headers.c_str() + sp + 1);
    }

    const std::string te = header_value(out.headers, "Transfer-Encoding");
    if (te.find("chunked") != std::string::npos) {
        std::string decoded;
        if (!dechunk(out.body, decoded)) {
            err = "malformed chunked response body";
            return false;
        }
        out.body.swap(decoded);
    } else {
        const std::string cl = header_value(out.headers, "Content-Length");
        if (!cl.empty()) {
            const size_t want = static_cast<size_t>(std::strtoul(cl.c_str(), nullptr, 10));
            if (out.body.size() > want) out.body.resize(want);
        }
    }
    return true;
}

} // namespace tls
} // namespace ilo2
