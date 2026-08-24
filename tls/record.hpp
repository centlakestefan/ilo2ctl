// record.hpp — the TLS 1.0 record layer for a stream cipher suite.
//
// Structurally this is where a stream-cipher connection differs most from the
// CBC-based TLS 1.2 most people have written:
//
//   * THE RC4 KEYSTREAM IS CONTINUOUS ACROSS RECORDS. One RC4 object per
//     direction lives for the whole connection; record N+1 resumes the
//     keystream exactly where record N stopped. There is no per-record key, no
//     IV and no padding. Re-keying per record — the instinct a block cipher
//     trains — produces a connection that fails on the second record.
//
//   * MAC-then-encrypt, over the PLAINTEXT length. The MAC input is
//         seq_num(8) || type(1) || version(2) || length(2) || fragment
//     where `length` is the fragment length BEFORE the MAC is appended. TLS 1.0
//     includes the version field here; SSL 3.0 does not.
//
//   * Sequence numbers are implicit, 64-bit, per direction, and RESET TO ZERO
//     when that direction's cipher spec changes. They are never transmitted.
//
// A failed unprotect() is unrecoverable: the keystream has already advanced
// over the record, so the read cipher can never resynchronise. TLS treats a bad
// MAC as fatal anyway, and the caller must tear the connection down.
#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>
#include "crypto/md5.hpp"
#include "crypto/sha1.hpp"
#include "crypto/hmac.hpp"
#include "crypto/rc4.hpp"

namespace ilo2 {
namespace tls {

enum ContentType : uint8_t {
    CT_CHANGE_CIPHER_SPEC = 20,
    CT_ALERT              = 21,
    CT_HANDSHAKE          = 22,
    CT_APPLICATION_DATA   = 23,
};

constexpr uint16_t VERSION_TLS_1_0    = 0x0301;
constexpr size_t   RECORD_HEADER_LEN  = 5;
constexpr size_t   MAX_PLAINTEXT      = 16384;          // 2^14
constexpr size_t   MAX_CIPHERTEXT     = 16384 + 2048;   // RFC 2246 §6.2.3

struct RecordHeader {
    uint8_t  type    = 0;
    uint16_t version = 0;
    uint16_t length  = 0;
};

inline bool parse_record_header(const uint8_t* p, size_t avail, RecordHeader& h) {
    if (!p || avail < RECORD_HEADER_LEN) return false;
    h.type    = p[0];
    h.version = static_cast<uint16_t>((p[1] << 8) | p[2]);
    h.length  = static_cast<uint16_t>((p[3] << 8) | p[4]);
    return h.length <= MAX_CIPHERTEXT;
}

inline bool is_valid_content_type(uint8_t t) {
    return t == CT_CHANGE_CIPHER_SPEC || t == CT_ALERT ||
           t == CT_HANDSHAKE || t == CT_APPLICATION_DATA;
}

// Comparison whose timing does not depend on where the first difference is.
inline bool ct_equal(const uint8_t* a, const uint8_t* b, size_t n) {
    uint8_t diff = 0;
    for (size_t i = 0; i < n; ++i) diff = static_cast<uint8_t>(diff | (a[i] ^ b[i]));
    return diff == 0;
}

// key_block layout, RFC 2246 §6.3: every client MAC secret, then every server
// MAC secret, then the client key, then the server key. Write IVs follow for
// block ciphers only, so a stream suite stops here.
template <class MacHash>
struct KeyMaterialT {
    static constexpr size_t MAC_LEN       = MacHash::DIGEST_SIZE;
    static constexpr size_t KEY_LEN       = 16;                      // RC4-128
    static constexpr size_t KEY_BLOCK_LEN = 2 * MAC_LEN + 2 * KEY_LEN;

    uint8_t client_mac[MAC_LEN]{};
    uint8_t server_mac[MAC_LEN]{};
    uint8_t client_key[KEY_LEN]{};
    uint8_t server_key[KEY_LEN]{};

    void split(const uint8_t* kb) {
        const uint8_t* p = kb;
        std::memcpy(client_mac, p, MAC_LEN); p += MAC_LEN;
        std::memcpy(server_mac, p, MAC_LEN); p += MAC_LEN;
        std::memcpy(client_key, p, KEY_LEN); p += KEY_LEN;
        std::memcpy(server_key, p, KEY_LEN);
    }
};

template <class MacHash>
class RecordLayerT {
public:
    static constexpr size_t MAC_LEN = MacHash::DIGEST_SIZE;

    explicit RecordLayerT(uint16_t version = VERSION_TLS_1_0) : version_(version) {}

    // Called when our ChangeCipherSpec is sent / theirs is received. Both reset
    // the corresponding sequence number, which is what the spec requires and
    // what makes the first protected record use seq 0.
    void enable_write_cipher(const uint8_t* mac_key, const uint8_t* enc_key) {
        write_mac_.init(mac_key, MAC_LEN);
        write_rc4_.reset(new RC4(RC4::RawKey{}, enc_key, KEY_LEN));
        write_seq_    = 0;
        write_active_ = true;
    }
    void enable_read_cipher(const uint8_t* mac_key, const uint8_t* enc_key) {
        read_mac_.init(mac_key, MAC_LEN);
        read_rc4_.reset(new RC4(RC4::RawKey{}, enc_key, KEY_LEN));
        read_seq_    = 0;
        read_active_ = true;
    }

    bool write_active() const { return write_active_; }
    bool read_active()  const { return read_active_; }
    uint64_t write_seq() const { return write_seq_; }
    uint64_t read_seq()  const { return read_seq_; }

    // Build a complete record: 5-byte header followed by the protected fragment.
    bool protect(uint8_t type, const uint8_t* data, size_t len,
                 std::vector<uint8_t>& out) {
        if (len > MAX_PLAINTEXT) return false;
        if (!data && len) return false;
        out.clear();

        if (!write_active_) {                       // pre-ChangeCipherSpec: cleartext
            out.reserve(RECORD_HEADER_LEN + len);
            append_header(out, type, static_cast<uint16_t>(len));
            out.insert(out.end(), data, data + len);
            // The null-cipher connection state counts records too (RFC 2246
            // §6.1). Nothing reads the number yet, but keeping it accurate is
            // what makes the reset in enable_write_cipher() load-bearing rather
            // than decorative.
            ++write_seq_;
            return true;
        }

        // MAC covers the plaintext and its length; the appended MAC is not
        // counted in the `length` the MAC itself is computed over.
        auto mac = compute_mac(write_mac_, write_seq_, type, version_, data, len);

        std::vector<uint8_t> frag;
        frag.reserve(len + MAC_LEN);
        frag.insert(frag.end(), data, data + len);
        frag.insert(frag.end(), mac.begin(), mac.end());

        write_rc4_->crypt(frag.data(), frag.size());   // keystream continues

        out.reserve(RECORD_HEADER_LEN + frag.size());
        append_header(out, type, static_cast<uint16_t>(frag.size()));
        out.insert(out.end(), frag.begin(), frag.end());
        ++write_seq_;
        return true;
    }

    // Recover the plaintext of one record body (everything after the header).
    // On failure the connection must be abandoned -- see the note at the top.
    bool unprotect(uint8_t type, uint16_t version,
                   const uint8_t* body, size_t len, std::vector<uint8_t>& out) {
        out.clear();
        if (len > MAX_CIPHERTEXT) return false;
        if (!body && len) return false;

        if (!read_active_) {
            if (len > MAX_PLAINTEXT) return false;
            out.assign(body, body + len);
            ++read_seq_;
            return true;
        }
        if (len < MAC_LEN) return false;

        std::vector<uint8_t> buf(body, body + len);
        read_rc4_->crypt(buf.data(), buf.size());

        const size_t plain_len = buf.size() - MAC_LEN;
        if (plain_len > MAX_PLAINTEXT) return false;

        auto want = compute_mac(read_mac_, read_seq_, type, version, buf.data(), plain_len);
        if (!ct_equal(want.data(), buf.data() + plain_len, MAC_LEN)) return false;

        ++read_seq_;
        out.assign(buf.begin(), buf.begin() + static_cast<ptrdiff_t>(plain_len));
        return true;
    }

private:
    void append_header(std::vector<uint8_t>& out, uint8_t type, uint16_t len) const {
        out.push_back(type);
        out.push_back(static_cast<uint8_t>(version_ >> 8));
        out.push_back(static_cast<uint8_t>(version_));
        out.push_back(static_cast<uint8_t>(len >> 8));
        out.push_back(static_cast<uint8_t>(len));
    }

    // seq_num(8) || type(1) || version(2) || length(2) || fragment
    static typename MacHash::Digest compute_mac(HMAC<MacHash>& mac, uint64_t seq,
                                                uint8_t type, uint16_t version,
                                                const uint8_t* frag, size_t len) {
        uint8_t hdr[13];
        for (int i = 0; i < 8; ++i)
            hdr[i] = static_cast<uint8_t>(seq >> (56 - 8 * i));
        hdr[8]  = type;
        hdr[9]  = static_cast<uint8_t>(version >> 8);
        hdr[10] = static_cast<uint8_t>(version);
        hdr[11] = static_cast<uint8_t>(len >> 8);
        hdr[12] = static_cast<uint8_t>(len);
        mac.update(hdr, sizeof(hdr));
        if (len) mac.update(frag, len);
        return mac.digest();
    }

    uint16_t             version_;
    HMAC<MacHash>        write_mac_, read_mac_;
    std::unique_ptr<RC4> write_rc4_, read_rc4_;
    uint64_t             write_seq_ = 0, read_seq_ = 0;
    bool                 write_active_ = false, read_active_ = false;

    static constexpr size_t KEY_LEN = 16;
};

// TLS_RSA_WITH_RC4_128_MD5 -- the suite the iLO 2 prefers.
using KeyMaterial = KeyMaterialT<MD5>;
using RecordLayer = RecordLayerT<MD5>;

// TLS_RSA_WITH_RC4_128_SHA, the server's second choice, costs one typedef.
using KeyMaterialSha = KeyMaterialT<SHA1>;
using RecordLayerSha = RecordLayerT<SHA1>;

} // namespace tls
} // namespace ilo2
