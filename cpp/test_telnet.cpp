// test_telnet.cpp — validates telnet.hpp's receive-loop state machine + RC4
// decryption against the real applet (via TelnetProbe.java driving telnet.run()).
//
// It builds a byte stream that exercises the ESC '[' 'R' trigger detection
// (including false starts that must reset the state machine), writes it to
// build/telnet_stream.bin for the Java oracle to replay, and feeds the same
// bytes through the C++ Telnet, capturing the decrypted DVC payload.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include "telnet.hpp"
#include "rc4.hpp"

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

    CaptureTelnet t;
    t.setup_decryption(key);
    t.drive(stream);

    std::string got = hex(t.dvc.data(), t.dvc.size());
    std::string want = hex(plain.data(), plain.size());
    bool ok = (t.dvc == plain);

    printf("cpp_dvc %s\n", got.c_str());
    printf("expect  %s\n", want.c_str());
    printf("round-trip decrypt: %s\n", ok ? "OK" : "FAIL");
    printf("wrote build/telnet_stream.bin (%zu bytes)\n", stream.size());
    return ok ? 0 : 1;
}
