// der.hpp — just enough DER to lift an RSA public key out of an X.509
// certificate.
//
// Scope: the TLS_RSA key exchange needs the server's modulus and exponent and
// nothing else. There is no chain building, no signature verification, no name
// matching and no validity check — and none of that is a shortcut being taken
// under protest. The iLO 2's certificate is self-signed, MD5-signed and expired
// in 2022, so no amount of validation logic could ever make it verify; the trust
// decision here is "this is the BMC at the address I typed", which is the same
// decision `curl -k` and HP's own applet make.
//
// What this code DOES have to be is safe. The bytes come off the network from a
// device that is not authenticated at the point of parsing, so every read is
// bounds-checked against an explicit limit, indefinite-length encodings are
// rejected, and no length is ever trusted without first comparing it to the
// bytes actually remaining.
#pragma once
#include <cstdint>
#include <cstddef>
#include <cstring>
#include "crypto/rsa.hpp"

namespace ilo2 {
namespace der {

constexpr uint8_t TAG_INTEGER    = 0x02;
constexpr uint8_t TAG_BIT_STRING = 0x03;
constexpr uint8_t TAG_NULL       = 0x05;
constexpr uint8_t TAG_OID        = 0x06;
constexpr uint8_t TAG_SEQUENCE   = 0x30;
constexpr uint8_t TAG_SET        = 0x31;

// 1.2.840.113549.1.1.1 rsaEncryption — OID content bytes, tag and length excluded.
constexpr uint8_t OID_RSA_ENCRYPTION[] = {
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};

struct Element {
    uint8_t        tag     = 0;
    const uint8_t* content = nullptr;   // first content byte
    size_t         len     = 0;         // content length
    const uint8_t* end     = nullptr;   // one past the whole TLV

    bool constructed() const { return (tag & 0x20) != 0; }
};

// Parse one TLV starting at p, refusing to read at or beyond limit.
inline bool parse(const uint8_t* p, const uint8_t* limit, Element& out) {
    if (!p || !limit || p >= limit) return false;

    const uint8_t tag = *p++;
    // High-tag-number form (low five bits all set) does not occur anywhere in
    // the certificate structures we walk; refusing it keeps the parser small.
    if ((tag & 0x1F) == 0x1F) return false;
    if (p >= limit) return false;

    size_t len = 0;
    const uint8_t first = *p++;
    if (first == 0x80) {
        return false;                   // indefinite length: legal in BER, not DER
    } else if (first & 0x80) {
        const int nbytes = first & 0x7F;
        // Four bytes is already a 4 GiB element; anything longer is either an
        // attack or a corruption, and size_t may be 32-bit.
        if (nbytes < 1 || nbytes > 4) return false;
        if (limit - p < nbytes) return false;
        for (int i = 0; i < nbytes; ++i) len = (len << 8) | *p++;
    } else {
        len = first;
    }

    if (static_cast<size_t>(limit - p) < len) return false;

    out.tag     = tag;
    out.content = p;
    out.len     = len;
    out.end     = p + len;
    return true;
}

// Walks the children of a constructed element.
class Iter {
public:
    explicit Iter(const Element& e) : p_(e.content), limit_(e.content + e.len) {}

    bool next(Element& out) {
        if (p_ >= limit_) return false;
        if (!parse(p_, limit_, out)) return false;
        p_ = out.end;
        return true;
    }
    bool done() const { return p_ >= limit_; }

private:
    const uint8_t* p_;
    const uint8_t* limit_;
};

inline bool is_oid(const Element& e, const uint8_t* oid, size_t n) {
    return e.tag == TAG_OID && e.len == n && std::memcmp(e.content, oid, n) == 0;
}

// DER encodes INTEGERs as signed, so a value whose top bit is set carries a
// leading 0x00 to keep it positive. Strip that (and any other leading zeros)
// before treating the bytes as an unsigned magnitude.
inline void trim_leading_zeros(const uint8_t*& p, size_t& len) {
    while (len > 1 && p[0] == 0x00) { ++p; --len; }
}

// SubjectPublicKeyInfo ::= SEQUENCE {
//     algorithm         AlgorithmIdentifier,   -- SEQUENCE { OID, params }
//     subjectPublicKey  BIT STRING }           -- wraps RSAPublicKey
// RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
inline bool parse_spki_rsa(const Element& spki, RsaPublicKey& out) {
    if (spki.tag != TAG_SEQUENCE) return false;

    Iter it(spki);
    Element alg;
    if (!it.next(alg) || alg.tag != TAG_SEQUENCE) return false;

    Element oid;
    Iter alg_it(alg);
    if (!alg_it.next(oid)) return false;
    if (!is_oid(oid, OID_RSA_ENCRYPTION, sizeof(OID_RSA_ENCRYPTION))) return false;

    Element bits;
    if (!it.next(bits) || bits.tag != TAG_BIT_STRING) return false;
    // A BIT STRING's first content byte counts unused trailing bits. Anything
    // wrapping a DER structure is whole-byte, so it must be zero.
    if (bits.len < 2 || bits.content[0] != 0x00) return false;

    Element rsa;
    if (!parse(bits.content + 1, bits.end, rsa) || rsa.tag != TAG_SEQUENCE) return false;

    Element n_int, e_int;
    Iter rsa_it(rsa);
    if (!rsa_it.next(n_int) || n_int.tag != TAG_INTEGER) return false;
    if (!rsa_it.next(e_int) || e_int.tag != TAG_INTEGER) return false;

    const uint8_t* np = n_int.content; size_t nlen = n_int.len;
    const uint8_t* ep = e_int.content; size_t elen = e_int.len;
    trim_leading_zeros(np, nlen);
    trim_leading_zeros(ep, elen);

    if (nlen == 0 || nlen > RsaInt::BYTES) return false;
    if (elen == 0 || elen > 4) return false;        // small public exponents only

    uint32_t e = 0;
    for (size_t i = 0; i < elen; ++i) e = (e << 8) | ep[i];

    RsaPublicKey key;
    if (!key.n.from_bytes(np, nlen)) return false;
    key.e = e;
    key.k = nlen;                                   // 128 for RSA-1024, NOT the 129 DER carries
    if (!key.valid()) return false;

    out = key;
    return true;
}

// Certificate ::= SEQUENCE { tbsCertificate SEQUENCE, signatureAlgorithm, signatureValue }
//
// Rather than index into tbsCertificate by position, scan its children for the
// first one shaped like a SubjectPublicKeyInfo. Position is genuinely unsafe
// here: the version field is [0] EXPLICIT and DEFAULT v1, so it is absent from
// v1 certificates — including the iLO's — and every later field shifts by one.
// The shape (SEQUENCE{ SEQUENCE{ rsaEncryption OID .. }, BIT STRING }) is not
// matched by the issuer, subject, validity or signature-algorithm fields.
inline bool parse_certificate_rsa_key(const uint8_t* cert, size_t len, RsaPublicKey& out) {
    if (!cert || len == 0) return false;
    const uint8_t* limit = cert + len;

    Element top;
    if (!parse(cert, limit, top) || top.tag != TAG_SEQUENCE) return false;

    Element tbs;
    Iter top_it(top);
    if (!top_it.next(tbs) || tbs.tag != TAG_SEQUENCE) return false;

    Element child;
    Iter tbs_it(tbs);
    while (tbs_it.next(child)) {
        if (child.tag != TAG_SEQUENCE) continue;
        if (parse_spki_rsa(child, out)) return true;
    }
    return false;
}

} // namespace der
} // namespace ilo2
