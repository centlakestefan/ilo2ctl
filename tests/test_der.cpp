// test_der.cpp — the DER walk against the iLO 2's real certificate, plus the
// malformed-input handling that matters because these bytes arrive from a
// device that is not authenticated at the point of parsing.
#include <cstring>
#include <initializer_list>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include "tls/der.hpp"

using namespace ilo2;

#include "tests/cert_fixture.inc"

// ---- a tiny DER builder, for synthesising malformed structures -------------

static std::vector<uint8_t> tlv(uint8_t tag, const std::vector<uint8_t>& content) {
    std::vector<uint8_t> out;
    out.push_back(tag);
    const size_t n = content.size();
    if (n < 0x80) {
        out.push_back(static_cast<uint8_t>(n));
    } else if (n < 0x100) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(n));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(n >> 8));
        out.push_back(static_cast<uint8_t>(n));
    }
    out.insert(out.end(), content.begin(), content.end());
    return out;
}

static std::vector<uint8_t> cat(std::initializer_list<std::vector<uint8_t>> parts) {
    std::vector<uint8_t> out;
    for (const auto& p : parts) out.insert(out.end(), p.begin(), p.end());
    return out;
}

static const std::vector<uint8_t> RSA_OID_DER = {
    0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01
};
static const std::vector<uint8_t> EC_OID_DER = {          // 1.2.840.10045.2.1
    0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01
};
static const std::vector<uint8_t> DER_NULL = { 0x05, 0x00 };

struct CertOpts {
    std::vector<uint8_t> oid       = RSA_OID_DER;
    uint8_t              unused_bits = 0x00;
    size_t               modulus_len = 64;      // bytes, top bit set
    std::vector<uint8_t> exponent  = { 0x01, 0x00, 0x01 };
    bool                 omit_exponent = false;
    bool                 include_version = false;
};

static std::vector<uint8_t> make_cert(const CertOpts& o) {
    std::vector<uint8_t> mod(o.modulus_len, 0xAB);
    mod[0] = 0xBD;                                    // top bit set
    std::vector<uint8_t> mod_der = tlv(0x02, cat({ { 0x00 }, mod }));   // sign pad
    std::vector<uint8_t> exp_der = tlv(0x02, o.exponent);

    std::vector<uint8_t> rsa_key = o.omit_exponent ? tlv(0x30, mod_der)
                                                   : tlv(0x30, cat({ mod_der, exp_der }));
    std::vector<uint8_t> bit_content = cat({ { o.unused_bits }, rsa_key });
    std::vector<uint8_t> spki = tlv(0x30, cat({
        tlv(0x30, cat({ o.oid, DER_NULL })),
        tlv(0x03, bit_content)
    }));

    std::vector<uint8_t> name  = tlv(0x30, tlv(0x31, tlv(0x30, cat({
        { 0x06, 0x03, 0x55, 0x04, 0x03 },             // 2.5.4.3 commonName
        tlv(0x13, { 'i', 'L', 'O' })
    }))));
    std::vector<uint8_t> validity = tlv(0x30, cat({
        tlv(0x17, { '0','2','1','2','0','5','2','0','2','5','2','6','Z' }),
        tlv(0x17, { '2','2','1','2','0','5','2','0','2','5','2','6','Z' })
    }));
    std::vector<uint8_t> algid = tlv(0x30, cat({ RSA_OID_DER, DER_NULL }));

    std::vector<uint8_t> tbs_body = cat({
        tlv(0x02, { 0x69, 0x4C, 0x4F, 0x00 }),        // serialNumber
        algid, name, validity, name, spki
    });
    if (o.include_version)                            // [0] EXPLICIT Version
        tbs_body = cat({ tlv(0xA0, tlv(0x02, { 0x02 })), tbs_body });

    return tlv(0x30, cat({
        tlv(0x30, tbs_body), algid, tlv(0x03, { 0x00, 0xDE, 0xAD })
    }));
}

int main() {
    const std::vector<uint8_t> cert = t::unhex(ILO_CERT_DER_HEX);

    std::printf("[the real iLO 2 certificate]\n");
    {
        t::ok(cert.size() == 612, "fixture is 612 bytes");

        RsaPublicKey key;
        if (t::ok(der::parse_certificate_rsa_key(cert.data(), cert.size(), key),
                  "certificate parses")) {
            uint8_t mod[RsaInt::BYTES];
            key.n.to_bytes(mod);
            // to_bytes emits the full type width; the key is the low k bytes.
            t::eq(t::hex(mod + (RsaInt::BYTES - key.k), key.k), ILO_CERT_MODULUS_HEX,
                  "modulus matches the independent Python walk");
            t::ok(key.e == ILO_CERT_EXPONENT, "exponent is 65537");
            // The classic bug: DER carries 129 bytes for this modulus because
            // its top bit is set and needs a 0x00 sign pad. The KEY is 128.
            t::ok(key.k == ILO_CERT_MODULUS_BYTES, "k is 128, not the 129 DER encodes");
            t::ok(key.n.bit_length() == 1024, "modulus is 1024 bits");
            t::ok(key.valid(), "key passes RsaPublicKey::valid()");
        }
    }

    std::printf("[this certificate really is v1 -- position-based parsing would break]\n");
    {
        // Assert the premise behind scanning rather than indexing: there is no
        // [0] EXPLICIT version element, so tbsCertificate's first child is the
        // serial INTEGER and every field sits one slot earlier than in a v3 cert.
        der::Element top, tbs, first;
        t::ok(der::parse(cert.data(), cert.data() + cert.size(), top), "top-level TLV parses");
        der::Iter top_it(top);
        t::ok(top_it.next(tbs) && tbs.tag == der::TAG_SEQUENCE, "tbsCertificate found");
        der::Iter tbs_it(tbs);
        t::ok(tbs_it.next(first), "tbsCertificate has a first child");
        t::ok(first.tag == der::TAG_INTEGER, "first TBS child is the serial INTEGER, not [0]");
    }

    std::printf("[synthetic certificates]\n");
    {
        RsaPublicKey key;
        auto good = make_cert(CertOpts{});
        t::ok(der::parse_certificate_rsa_key(good.data(), good.size(), key),
              "a well-formed synthetic certificate parses");
        t::ok(key.k == 64 && key.e == 65537, "synthetic key has the expected shape");

        CertOpts v3; v3.include_version = true;
        auto with_version = make_cert(v3);
        RsaPublicKey k2;
        t::ok(der::parse_certificate_rsa_key(with_version.data(), with_version.size(), k2),
              "a v3-style certificate with [0] version also parses");
        t::ok(k2.k == 64, "the version field does not shift the result");

        struct { CertOpts o; const char* why; } bad[] = {
            { [] { CertOpts o; o.oid = EC_OID_DER;      return o; }(), "non-RSA OID is refused" },
            { [] { CertOpts o; o.unused_bits = 0x03;    return o; }(), "BIT STRING with unused bits is refused" },
            { [] { CertOpts o; o.omit_exponent = true;  return o; }(), "missing exponent is refused" },
            { [] { CertOpts o; o.exponent = {1,2,3,4,5};return o; }(), "oversized exponent is refused" },
            { [] { CertOpts o; o.modulus_len = 32;      return o; }(), "a 256-bit modulus is refused" },
        };
        for (const auto& b : bad) {
            auto c = make_cert(b.o);
            RsaPublicKey k;
            t::ok(!der::parse_certificate_rsa_key(c.data(), c.size(), k), b.why);
        }
    }

    std::printf("[length encodings]\n");
    {
        der::Element e;
        const uint8_t indefinite[] = { 0x30, 0x80, 0x02, 0x01, 0x05, 0x00, 0x00 };
        t::ok(!der::parse(indefinite, indefinite + sizeof(indefinite), e),
              "indefinite length is refused (BER, not DER)");

        const uint8_t too_many[] = { 0x30, 0x85, 1, 2, 3, 4, 5 };
        t::ok(!der::parse(too_many, too_many + sizeof(too_many), e),
              "a 5-byte length is refused");

        const uint8_t overrun[] = { 0x30, 0x7F, 0x01, 0x02 };
        t::ok(!der::parse(overrun, overrun + sizeof(overrun), e),
              "a length longer than the buffer is refused");

        const uint8_t high_tag[] = { 0x1F, 0x81, 0x00, 0x01, 0x00 };
        t::ok(!der::parse(high_tag, high_tag + sizeof(high_tag), e),
              "high-tag-number form is refused");

        const uint8_t truncated_len[] = { 0x30, 0x82, 0x01 };
        t::ok(!der::parse(truncated_len, truncated_len + sizeof(truncated_len), e),
              "truncated long-form length is refused");

        const uint8_t empty_seq[] = { 0x30, 0x00 };
        t::ok(der::parse(empty_seq, empty_seq + sizeof(empty_seq), e) && e.len == 0,
              "a zero-length SEQUENCE parses");

        const uint8_t long_form[] = { 0x04, 0x81, 0x02, 0xAA, 0xBB };
        t::ok(der::parse(long_form, long_form + sizeof(long_form), e) && e.len == 2,
              "long-form length for a small value parses");

        t::ok(!der::parse(nullptr, nullptr, e), "null input is refused");
        t::ok(!der::parse(cert.data(), cert.data(), e), "an empty range is refused");
    }

    std::printf("[truncation robustness]\n");
    {
        // Every prefix of a real certificate must be rejected cleanly rather
        // than read past its end. Reaching the end of this loop at all is the
        // assertion; an out-of-bounds read would abort the process.
        int accepted = 0;
        for (size_t n = 0; n < cert.size(); ++n) {
            RsaPublicKey k;
            if (der::parse_certificate_rsa_key(cert.data(), n, k)) ++accepted;
        }
        t::ok(accepted == 0, "no truncated prefix is accepted");
        std::printf("  %zu prefixes rejected without over-reading\n", cert.size());
    }

    std::printf("[mutation robustness]\n");
    {
        // Flip the high bit of each byte in turn. Many mutations land in the
        // signature or issuer name and legitimately still yield a valid key;
        // what must never happen is a crash or a read past the buffer.
        int parsed = 0, rejected = 0;
        for (size_t i = 0; i < cert.size(); ++i) {
            std::vector<uint8_t> m = cert;
            m[i] ^= 0x80;
            RsaPublicKey k;
            if (der::parse_certificate_rsa_key(m.data(), m.size(), k)) ++parsed; else ++rejected;
        }
        t::ok(parsed + rejected == static_cast<int>(cert.size()), "every mutation returned");
        std::printf("  %d mutations parsed, %d rejected, 0 crashes\n", parsed, rejected);

        // Same again with truncated buffers, to combine both failure modes.
        int survived = 0;
        for (size_t i = 0; i < cert.size(); i += 7) {
            std::vector<uint8_t> m(cert.begin(), cert.begin() + i);
            if (!m.empty()) m[m.size() / 2] ^= 0xFF;
            RsaPublicKey k;
            der::parse_certificate_rsa_key(m.data(), m.size(), k);
            ++survived;
        }
        t::ok(survived > 0, "mutated truncations all returned");
    }

    return t::report("test_der");
}
