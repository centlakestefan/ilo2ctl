// test_telnet.cpp — validates telnet.hpp's receive-loop state machine + RC4
// decryption against the real applet. The expected payload is what HP's
// telnet.run() produced for this exact stream, recorded by tests/TelnetProbe.java
// and pinned as a literal below, so the test needs neither Java nor the jar.
//
// It builds a byte stream that exercises the ESC '[' 'R' trigger detection
// (including false starts that must reset the state machine), writes it to
// build/telnet_stream.bin for the Java oracle to replay, and feeds the same
// bytes through the C++ Telnet, capturing the decrypted DVC payload.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "tests/test_util.hpp"
#include "ilo/telnet.hpp"
#include "crypto/rc4.hpp"

using namespace ilo2;

// Subclass that captures decrypted DVC bytes, mirroring how cim will consume them.
class CaptureTelnet : public Telnet {
public:
    std::vector<uint8_t> dvc;
    void drive(const std::vector<uint8_t>& stream) { feed(stream.data(), stream.size()); }
protected:
    bool process_dvc(uint8_t c) override { dvc.push_back(c); return true; }
};

static std::string hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 0xF]; }
    return s;
}

int main() {
    // Key shared with TelnetProbe.java.
    uint8_t key[16];
    for (int i = 0; i < 16; ++i) key[i] = static_cast<uint8_t>(i * 7 + 1);

    // Plaintext DVC payload (what process_dvc must recover).
    std::vector<uint8_t> plain(48);
    for (int i = 0; i < 48; ++i) plain[i] = static_cast<uint8_t>(i * 13 + 5);

    // Ciphertext = plaintext XOR keystream(RC4(key)). A fresh RC4 here mirrors
    // the decrypter, whose keystream begins at the first post-trigger byte.
    RC4 kgen(key);
    std::vector<uint8_t> cipher(plain.size());
    for (size_t i = 0; i < plain.size(); ++i)
        cipher[i] = static_cast<uint8_t>(plain[i] ^ kgen.randomValue());

    // Stream: junk + false triggers (must reset) + real ESC[R trigger + cipher.
    std::vector<uint8_t> stream = {
        'A', 'B',
        0x1B, 'Z',            // ESC then non-'[' -> reset
        0x1B, '[', 'X',       // ESC '[' then non-R/r -> reset
        0x1B, '[', 'R'        // real trigger: DVC + RC4
    };
    stream.insert(stream.end(), cipher.begin(), cipher.end());

    // Share the exact bytes with the Java oracle.
    if (FILE* f = std::fopen("build/telnet_stream.bin", "wb")) {
        std::fwrite(stream.data(), 1, stream.size(), f);
        std::fclose(f);
    } else {
        std::fprintf(stderr, "cannot write build/telnet_stream.bin\n");
        return 2;
    }

    CaptureTelnet tel;
    tel.setup_decryption(key);
    tel.drive(stream);

    const std::string got = hex(tel.dvc.data(), tel.dvc.size());

    // The payload the C++ decrypter must recover, computed independently here.
    t::eq(got, hex(plain.data(), plain.size()), "round-trip decrypt");

    // The same payload as HP's telnet.run() actually produced for this stream,
    // recorded by tests/TelnetProbe.java. Pinning the literal keeps the trigger
    // detection and keystream alignment tied to the applet's real behaviour
    // without needing Java or the jar.
    t::eq(got,
          "05121f2c394653606d7a8794a1aebbc8d5e2effc091623303d4a5764717e8b98"
          "a5b2bfccd9e6f3000d1a2734414e5b68",
          "decrypted DVC payload vs real telnet.run()");

    return t::report("test_telnet");
}
