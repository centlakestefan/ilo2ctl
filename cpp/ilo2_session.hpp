// ilo2_session.hpp — the outbound (client->iLO) half of com.hp.ilo2.remcons.cim.
//
// telnet.hpp carries the inbound transport (socket, receive loop, ESC[R trigger,
// RC4 decrypt). This header adds what cim layers on top of it for sending:
//
//   * setup_encryption(key, key_index)   -- cim.java:203
//       stores the INFOC key, builds a SEPARATE RC4 encrypter (outbound has its
//       own keystream, independent of the inbound decrypter), records INFOD.
//
//   * connect()                          -- cim.java:314
//       if encryption is enabled, prefixes the login token with FF C0 + four
//       placeholder spaces and arms `sending_encrypt_command`, then defers to
//       telnet.connect() (which transmits the token).
//
//   * transmit()                         -- cim.java:324
//       every byte is XORed with the encrypter's keystream, EXCEPT that on the
//       very first packet bytes 0..5 are sent in the clear as
//           FF C0 <key_index big-endian, 4 bytes>
//       (overwriting the four spaces) and the keystream starts at byte 6.
//
// That first-packet framing is the TELNET_ENCRYPT command telling the iLO which
// session key index the client is using; everything after it is ciphertext.
#pragma once
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include "telnet.hpp"
#include "rc4.hpp"

namespace ilo2 {

class CimSession : public Telnet {
public:
    using Telnet::transmit;   // keep the (const uint8_t*, size_t) overload visible

    // cim.setup_encryption(byte[], int)
    void setup_encryption(const uint8_t key[16], uint32_t key_index) {
        std::memcpy(encrypt_key_, key, 16);
        rc4_encrypter_ = std::make_unique<RC4>(key);
        key_index_ = key_index;
    }

    // cim.connect(): arm the FF C0 <key_index> preamble, then telnet.connect().
    // `encryption_enabled_` is set by Telnet::setup_decryption, exactly as in the
    // JAR (telnet.java:269), so call setup_decryption() before connect().
    bool connect(const std::string& host, const std::string& login, int port,
                 int ts_flags = 0, int ts_port = 0) {
        std::string tok = login;
        if (encryption_enabled_) {
            encryption_active_ = true;
            tok = std::string("\xFF\xC0", 2) + "    " + login;  // 4 spaces = key_index slot
            sending_encrypt_command_ = true;
        }
        return Telnet::connect(host, tok, port, ts_flags, ts_port);
    }

    // cim.transmit(String)
    void transmit(const std::string& s) override {
        if (s.empty()) return;
        std::string out(s.size(), '\0');
        if (encryption_active_ && rc4_encrypter_) {
            size_t i = 0;
            if (sending_encrypt_command_) {
                out[0] = s[0];                                          // FF
                out[1] = s[1];                                          // C0
                out[2] = static_cast<char>((key_index_ >> 24) & 0xFF);
                out[3] = static_cast<char>((key_index_ >> 16) & 0xFF);
                out[4] = static_cast<char>((key_index_ >> 8)  & 0xFF);
                out[5] = static_cast<char>((key_index_)       & 0xFF);
                i = 6;
                sending_encrypt_command_ = false;
            }
            for (; i < s.size(); ++i)
                out[i] = static_cast<char>(static_cast<uint8_t>(s[i]) ^
                                           (rc4_encrypter_->randomValue() & 0xFF));
        } else {
            out = s;
        }
        Telnet::transmit(reinterpret_cast<const uint8_t*>(out.data()), out.size());
    }

    // cim.change_key() (cim.java:1538): firmware cmd 9 rekeys BOTH directions --
    // the encrypter first, then super.change_key() for the decrypter.
    void change_key() {
        if (rc4_encrypter_) rc4_encrypter_->update_key();
        Telnet::change_key();
    }

    void refresh_screen()      { transmit("\x1b[~"); }   // cim.java:863 — force full redraw
    void send_keep_alive_msg() { transmit("\x1b[("); }   // cim.java:867

protected:
    std::unique_ptr<RC4> rc4_encrypter_;
    uint8_t  encrypt_key_[16]{};
    uint32_t key_index_ = 0;
    bool     encryption_active_ = false;
    bool     sending_encrypt_command_ = false;
};

} // namespace ilo2
