// handshake.hpp — TLS 1.0 handshake messages: construction, parsing, and the
// running transcript hash.
//
// Deliberately free of I/O and of any state machine. Everything here is a pure
// function over buffers, so the whole handshake can be exercised offline; the
// sequencing and socket work live in client.hpp.
//
// The details that differ from TLS 1.2, and that produce nothing but an opaque
// failure when wrong:
//
//   * The transcript is hashed with BOTH MD5 and SHA-1, and Finished carries 12
//     bytes derived from the 36-byte concatenation of the two.
//   * ClientKeyExchange LENGTH-PREFIXES the RSA-encrypted premaster with two
//     bytes. SSL 3.0 does not, and this is the classic interop failure between
//     the two.
//   * The PreMasterSecret carries the version the client OFFERED, not the one
//     negotiated — a rollback check. Servers that verify it reject a connection
//     that puts the negotiated version there.
//   * ChangeCipherSpec is its own record content type, not a handshake message,
//     and is NOT hashed into the transcript.
//   * No extensions are sent at all. The probe that characterised this device
//     got a clean ServerHello from a bare ClientHello, and 2002-era firmware is
//     exactly the sort to mishandle a trailing extensions block.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>
#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/random.hpp"
#include "crypto/rsa.hpp"
#include "tls/prf.hpp"
#include "tls/record.hpp"

namespace ilo2 {
namespace tls {

enum HandshakeType : uint8_t {
    HT_HELLO_REQUEST       = 0,
    HT_CLIENT_HELLO        = 1,
    HT_SERVER_HELLO        = 2,
    HT_CERTIFICATE         = 11,
    HT_SERVER_KEY_EXCHANGE = 12,
    HT_CERTIFICATE_REQUEST = 13,
    HT_SERVER_HELLO_DONE   = 14,
    HT_CERTIFICATE_VERIFY  = 15,
    HT_CLIENT_KEY_EXCHANGE = 16,
    HT_FINISHED            = 20,
};

constexpr uint16_t TLS_RSA_WITH_RC4_128_MD5 = 0x0004;
constexpr uint16_t TLS_RSA_WITH_RC4_128_SHA = 0x0005;

constexpr size_t HANDSHAKE_HEADER_LEN = 4;      // type(1) + length(3)
constexpr size_t PREMASTER_LEN        = 48;

// ---------------------------------------------------------------------------
// Bounds-checked big-endian reader
// ---------------------------------------------------------------------------

class Reader {
public:
    Reader(const uint8_t* p, size_t n) : p_(p), end_(p ? p + n : nullptr) {}

    bool u8(uint8_t& v) {
        if (remaining() < 1) return false;
        v = *p_++;
        return true;
    }
    bool u16(uint16_t& v) {
        if (remaining() < 2) return false;
        v = static_cast<uint16_t>((p_[0] << 8) | p_[1]);
        p_ += 2;
        return true;
    }
    bool u24(uint32_t& v) {
        if (remaining() < 3) return false;
        v = (static_cast<uint32_t>(p_[0]) << 16) |
            (static_cast<uint32_t>(p_[1]) << 8)  |
             static_cast<uint32_t>(p_[2]);
        p_ += 3;
        return true;
    }
    bool take(size_t n, const uint8_t*& out) {
        if (remaining() < n) return false;
        out = p_;
        p_ += n;
        return true;
    }
    bool skip(size_t n) {
        const uint8_t* ignored;
        return take(n, ignored);
    }
    size_t remaining() const { return (p_ && end_ >= p_) ? static_cast<size_t>(end_ - p_) : 0; }
    bool   done() const { return remaining() == 0; }

private:
    const uint8_t* p_;
    const uint8_t* end_;
};

// ---------------------------------------------------------------------------
// Transcript
// ---------------------------------------------------------------------------

// Running MD5 and SHA-1 over every handshake message (header included), in the
// order sent and received. ChangeCipherSpec is a record-layer message and never
// appears here.
class Transcript {
public:
    void update(const uint8_t* p, size_t n) {
        if (!n) return;
        md5_.update(p, n);
        sha1_.update(p, n);
    }
    void update(const std::vector<uint8_t>& v) { update(v.data(), v.size()); }

    // Digest the transcript SO FAR without disturbing it. Finished is computed
    // over the messages up to that point, and the transcript must then continue
    // in order to cover the peer's Finished — so this copies rather than
    // finalising. It works because MD5 and SHA1 are all-POD and trivially
    // copyable; digest() itself is destructive.
    void snapshot(uint8_t md5_out[16], uint8_t sha1_out[20]) const {
        MD5  m = md5_;
        SHA1 s = sha1_;
        auto md = m.digest();
        auto sd = s.digest();
        std::memcpy(md5_out,  md.data(), md.size());
        std::memcpy(sha1_out, sd.data(), sd.size());
    }

private:
    MD5  md5_;
    SHA1 sha1_;
};

// ---------------------------------------------------------------------------
// Building
// ---------------------------------------------------------------------------

inline std::vector<uint8_t> frame(uint8_t type, const std::vector<uint8_t>& body) {
    std::vector<uint8_t> out;
    out.reserve(HANDSHAKE_HEADER_LEN + body.size());
    out.push_back(type);
    out.push_back(static_cast<uint8_t>(body.size() >> 16));
    out.push_back(static_cast<uint8_t>(body.size() >> 8));
    out.push_back(static_cast<uint8_t>(body.size()));
    out.insert(out.end(), body.begin(), body.end());
    return out;
}

// ClientHello.random = gmt_unix_time(4) || random_bytes(28). The timestamp is
// cosmetic here; passing it in keeps the builder deterministic for tests.
inline bool make_client_random(uint32_t gmt_unix_time, uint8_t out[RANDOM_LEN]) {
    out[0] = static_cast<uint8_t>(gmt_unix_time >> 24);
    out[1] = static_cast<uint8_t>(gmt_unix_time >> 16);
    out[2] = static_cast<uint8_t>(gmt_unix_time >> 8);
    out[3] = static_cast<uint8_t>(gmt_unix_time);
    return secure_random(out + 4, RANDOM_LEN - 4);
}

inline std::vector<uint8_t> build_client_hello(uint16_t version,
                                               const uint8_t random[RANDOM_LEN],
                                               const std::vector<uint16_t>& suites) {
    std::vector<uint8_t> body;
    body.push_back(static_cast<uint8_t>(version >> 8));
    body.push_back(static_cast<uint8_t>(version));
    body.insert(body.end(), random, random + RANDOM_LEN);
    body.push_back(0x00);                                   // session_id: empty
    body.push_back(static_cast<uint8_t>((suites.size() * 2) >> 8));
    body.push_back(static_cast<uint8_t>(suites.size() * 2));
    for (uint16_t s : suites) {
        body.push_back(static_cast<uint8_t>(s >> 8));
        body.push_back(static_cast<uint8_t>(s));
    }
    body.push_back(0x01);                                   // one compression method
    body.push_back(0x00);                                   // null
    // No extensions block: see the note at the top of this file.
    return frame(HT_CLIENT_HELLO, body);
}

// PreMasterSecret = client_version(2) || 46 random bytes.
//
// `offered_version` MUST be the version sent in ClientHello.client_version, not
// the negotiated one. It exists so a server can detect a version-rollback
// attack, and a server that checks it will reject the handshake otherwise.
inline bool make_premaster(uint16_t offered_version, uint8_t out[PREMASTER_LEN]) {
    out[0] = static_cast<uint8_t>(offered_version >> 8);
    out[1] = static_cast<uint8_t>(offered_version);
    return secure_random(out + 2, PREMASTER_LEN - 2);
}

// ClientKeyExchange for an RSA key exchange.
//
// The encrypted premaster is carried as an opaque vector with a TWO-BYTE length
// prefix. SSL 3.0 omits that prefix; TLS 1.0 requires it. Sending the SSL 3.0
// form to a TLS server (or the reverse) is the classic interop failure for this
// message, and the symptom is a decrypt_error alert with nothing else to go on.
inline bool build_client_key_exchange(const RsaPublicKey& key,
                                      const uint8_t premaster[PREMASTER_LEN],
                                      std::vector<uint8_t>& out) {
    std::vector<uint8_t> ciphertext;
    if (!rsa_encrypt_pkcs1v15(key, premaster, PREMASTER_LEN, ciphertext)) return false;

    std::vector<uint8_t> body;
    body.reserve(2 + ciphertext.size());
    body.push_back(static_cast<uint8_t>(ciphertext.size() >> 8));
    body.push_back(static_cast<uint8_t>(ciphertext.size()));
    body.insert(body.end(), ciphertext.begin(), ciphertext.end());

    out = frame(HT_CLIENT_KEY_EXCHANGE, body);
    return true;
}

// An empty Certificate message, required if the server sent CertificateRequest
// and we have no certificate to offer.
inline std::vector<uint8_t> build_empty_certificate() {
    return frame(HT_CERTIFICATE, std::vector<uint8_t>{ 0x00, 0x00, 0x00 });
}

inline std::vector<uint8_t> build_finished(const uint8_t master[MASTER_SECRET_LEN],
                                           const char* label,
                                           const Transcript& transcript) {
    uint8_t md5_hash[16], sha1_hash[20], verify[VERIFY_DATA_LEN];
    transcript.snapshot(md5_hash, sha1_hash);
    derive_verify_data(master, label, md5_hash, sha1_hash, verify);
    return frame(HT_FINISHED, std::vector<uint8_t>(verify, verify + VERIFY_DATA_LEN));
}

// Verify a received Finished body against the transcript as it stood BEFORE
// that message was added.
inline bool check_finished(const uint8_t master[MASTER_SECRET_LEN],
                           const char* label,
                           const Transcript& transcript,
                           const uint8_t* body, size_t len) {
    if (len != VERIFY_DATA_LEN) return false;
    uint8_t md5_hash[16], sha1_hash[20], want[VERIFY_DATA_LEN];
    transcript.snapshot(md5_hash, sha1_hash);
    derive_verify_data(master, label, md5_hash, sha1_hash, want);
    return ct_equal(want, body, VERIFY_DATA_LEN);
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

struct HandshakeMessage {
    uint8_t        type = 0;
    const uint8_t* body = nullptr;
    size_t         len  = 0;
    size_t         total = 0;      // header + body, for advancing the transcript
};

inline bool parse_handshake(const uint8_t* p, size_t avail, HandshakeMessage& out) {
    Reader r(p, avail);
    uint8_t type;
    uint32_t len;
    if (!r.u8(type) || !r.u24(len)) return false;
    if (r.remaining() < len) return false;
    out.type  = type;
    out.body  = p + HANDSHAKE_HEADER_LEN;
    out.len   = len;
    out.total = HANDSHAKE_HEADER_LEN + len;
    return true;
}

struct ServerHello {
    uint16_t             version      = 0;
    uint8_t              random[RANDOM_LEN]{};
    std::vector<uint8_t> session_id;
    uint16_t             cipher_suite = 0;
    uint8_t              compression  = 0;
};

inline bool parse_server_hello(const uint8_t* body, size_t len, ServerHello& out) {
    Reader r(body, len);
    const uint8_t* rnd = nullptr;
    uint8_t sid_len = 0;
    if (!r.u16(out.version)) return false;
    if (!r.take(RANDOM_LEN, rnd)) return false;
    std::memcpy(out.random, rnd, RANDOM_LEN);
    if (!r.u8(sid_len)) return false;
    if (sid_len > 32) return false;                     // SessionID is <0..32>
    const uint8_t* sid = nullptr;
    if (!r.take(sid_len, sid)) return false;
    out.session_id.assign(sid, sid + sid_len);
    if (!r.u16(out.cipher_suite)) return false;
    if (!r.u8(out.compression)) return false;
    // Trailing bytes would be an extensions block; we sent none, so a server
    // that returns one is not following the negotiation. Tolerate but ignore.
    return true;
}

struct CertificateEntry {
    const uint8_t* data = nullptr;
    size_t         len  = 0;
};

// Certificate ::= 3-byte total length, then a sequence of 3-byte-length certs.
// The first entry is the server's own; the rest are chain material we have no
// use for, since nothing is verified.
inline bool parse_certificate_list(const uint8_t* body, size_t len,
                                   std::vector<CertificateEntry>& out) {
    out.clear();
    Reader r(body, len);
    uint32_t total = 0;
    if (!r.u24(total)) return false;
    if (r.remaining() < total) return false;

    Reader list(body + 3, total);
    while (!list.done()) {
        uint32_t clen = 0;
        if (!list.u24(clen)) return false;
        const uint8_t* cert = nullptr;
        if (!list.take(clen, cert)) return false;
        out.push_back(CertificateEntry{ cert, clen });
    }
    return !out.empty();
}

struct Alert {
    uint8_t level       = 0;    // 1 = warning, 2 = fatal
    uint8_t description = 0;
};

inline bool parse_alert(const uint8_t* body, size_t len, Alert& out) {
    if (len != 2) return false;
    out.level       = body[0];
    out.description = body[1];
    return true;
}

// Naming the alert is worth the table: a handshake that fails against real
// hardware surfaces as a number, and "handshake_failure" versus
// "bad_record_mac" versus "decrypt_error" points at three different bugs.
inline const char* alert_name(uint8_t description) {
    switch (description) {
        case 0:   return "close_notify";
        case 10:  return "unexpected_message";
        case 20:  return "bad_record_mac";
        case 21:  return "decryption_failed";
        case 22:  return "record_overflow";
        case 30:  return "decompression_failure";
        case 40:  return "handshake_failure";
        case 41:  return "no_certificate";
        case 42:  return "bad_certificate";
        case 43:  return "unsupported_certificate";
        case 44:  return "certificate_revoked";
        case 45:  return "certificate_expired";
        case 46:  return "certificate_unknown";
        case 47:  return "illegal_parameter";
        case 48:  return "unknown_ca";
        case 49:  return "access_denied";
        case 50:  return "decode_error";
        case 51:  return "decrypt_error";
        case 60:  return "export_restriction";
        case 70:  return "protocol_version";
        case 71:  return "insufficient_security";
        case 80:  return "internal_error";
        case 90:  return "user_canceled";
        case 100: return "no_renegotiation";
        default:  return "unknown_alert";
    }
}

} // namespace tls
} // namespace ilo2
