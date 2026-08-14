// telnet.hpp — C++ port of com.hp.ilo2.remcons.telnet (transport core)
//
// This is the network/protocol half of the applet's `telnet` class. The Java
// class also carried the AWT UI (Panel/TextField/dvcwin), RDP/terminal-services
// launching, and key/mouse listeners; none of that is transport, so it is left
// to higher layers. What is faithfully preserved here:
//
//   * the telnet command constants,
//   * connect(): open TCP socket, then send the login token (transmit(login)),
//   * the run() receive loop and its byte-by-byte state machine that detects the
//       ESC '[' 'R'   -> DVC video mode, RC4-encrypted
//       ESC '[' 'r'   -> DVC video mode, cleartext
//     trigger, and thereafter XORs each byte with RC4::randomValue() before
//     handing it to process_dvc(),
//   * setup_decryption()/change_key() wiring to rc4.hpp.
//
// The per-byte logic is factored into feed() so it can be unit-tested without a
// socket; run() is just "recv() then feed()". process_dvc() is virtual and is
// overridden by the forthcoming cim (video decoder) port — the base version,
// exactly like telnet.process_dvc in the JAR, consumes the byte and stays in
// DVC mode.
#pragma once
#include <cstdint>
#include <string>
#include <memory>
#include <atomic>
#include <thread>
#include "rc4.hpp"

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
#else
  #include <sys/socket.h>
  #include <netinet/in.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <cerrno>
#endif

namespace ilo2 {

#if defined(_WIN32)
using socket_t = SOCKET;
inline constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t INVALID_SOCK = -1;
#endif

class Telnet {
public:
    // Telnet command bytes (identical to the applet's constants).
    static constexpr int TELNET_PORT            = 23;
    static constexpr int TELNET_ENCRYPT         = 192; // 0xC0
    static constexpr int TELNET_CHG_ENCRYPT_KEYS= 193; // 0xC1
    static constexpr int TELNET_SE              = 240;
    static constexpr int TELNET_NOP             = 241;
    static constexpr int TELNET_DM              = 242;
    static constexpr int TELNET_BRK             = 243;
    static constexpr int TELNET_IP              = 244;
    static constexpr int TELNET_AO              = 245;
    static constexpr int TELNET_AYT             = 246;
    static constexpr int TELNET_EC              = 247;
    static constexpr int TELNET_EL              = 248;
    static constexpr int TELNET_GA              = 249;
    static constexpr int TELNET_SB              = 250;
    static constexpr int TELNET_WILL            = 251;
    static constexpr int TELNET_WONT            = 252;
    static constexpr int TELNET_DO              = 253;
    static constexpr int TELNET_DONT            = 254;
    static constexpr int TELNET_IAC             = 255;

    Telnet() { net_init(); }
    virtual ~Telnet() { disconnect(); }

    Telnet(const Telnet&) = delete;
    Telnet& operator=(const Telnet&) = delete;

    // Mirrors telnet.setup_decryption(byte[]): store key, build the RC4
    // decrypter, mark encryption available.
    void setup_decryption(const uint8_t key[16]) {
        std::memcpy(decrypt_key_, key, 16);
        rc4_decrypter_ = std::make_unique<RC4>(key);
        encryption_enabled_ = true;
    }

    // telnet.change_key(): rekey the decrypter (server sent TELNET_CHG_ENCRYPT_KEYS).
    void change_key() {
        if (rc4_decrypter_) rc4_decrypter_->update_key();
    }

    // Open the socket and send the login token. Returns false on failure.
    // (ts_flags/ts_port from the Java signature are accepted but the terminal-
    // services launching they gated is out of scope for the transport core.)
    bool connect(const std::string& host, const std::string& login, int port,
                 int /*ts_flags*/ = 0, int /*ts_port*/ = 0) {
        if (connected_) return true;
        host_ = host; login_ = login; port_ = port;

        addrinfo hints{}; hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res)
            return false;
        socket_t fd = ::socket(res->ai_family, res->ai_socktype, res->ai_protocol);
        if (fd == INVALID_SOCK) { ::freeaddrinfo(res); return false; }
        if (::connect(fd, res->ai_addr, static_cast<int>(res->ai_addrlen)) != 0) {
            close_sock(fd); ::freeaddrinfo(res); return false;
        }
        ::freeaddrinfo(res);

        // s.setSoLinger(true, 0)
        linger lg{}; lg.l_onoff = 1; lg.l_linger = 0;
        ::setsockopt(fd, SOL_SOCKET, SO_LINGER,
                     reinterpret_cast<const char*>(&lg), sizeof(lg));

        sock_ = fd;
        connected_ = 1;
        set_status(1, "Online");
        transmit(login_);                 // telnet.connect(): transmit(this.login)
        return true;
    }

    void disconnect() {
        if (!connected_) return;
        connected_ = 0;
        running_ = false;
        if (sock_ != INVALID_SOCK) { close_sock(sock_); sock_ = INVALID_SOCK; }
        if (receiver_.joinable() && receiver_.get_id() != std::this_thread::get_id())
            receiver_.join();
        set_status(1, "Offline");
        decryption_active_ = false;
    }

    // telnet.transmit(String): write the low 8 bits of each char as raw bytes.
    // (The base class sends cleartext; cim overrides transmit() to encrypt.)
    void transmit(const std::string& s) {
        if (sock_ == INVALID_SOCK || s.empty()) return;
        send_all(reinterpret_cast<const uint8_t*>(s.data()), s.size());
    }
    void transmit(const uint8_t* data, size_t n) {
        if (sock_ == INVALID_SOCK || n == 0) return;
        send_all(data, n);
    }

    // Blocking receive loop (run on a thread via start()). Mirrors telnet.run():
    // 1s socket timeout, read up to 1024 bytes, feed() them; exit on close.
    void run() {
        set_recv_timeout(sock_, 1000);
        uint8_t buf[1024];
        running_ = true;
        while (running_ && connected_) {
            int n = recv_bytes(sock_, buf, sizeof(buf));
            if (n == RECV_TIMEOUT) continue;      // InterruptedIOException -> continue
            if (n <= 0) break;                    // <0 or EOF -> leave loop
            feed(buf, static_cast<size_t>(n));
        }
        if (connected_) disconnect();
    }

    // Launch run() on an internal receiver thread ("telnet_rcvr").
    void start() { receiver_ = std::thread([this]{ run(); }); }
    void join()  { if (receiver_.joinable()) receiver_.join(); }

    bool is_connected() const { return connected_ != 0; }
    bool in_dvc_mode()  const { return dvc_mode_; }

protected:
    // Overridden by the cim video decoder. Base behaviour == telnet.process_dvc:
    // consume the byte and remain in DVC mode.
    virtual bool process_dvc(uint8_t /*c*/) { return true; }

    // UI status hook. Base is a no-op (the transport core has no UI).
    virtual void set_status(int /*field*/, const std::string& /*text*/) {}

    // Exact per-byte state machine from telnet.run()'s inner loop. Public-ish
    // (protected) so tests can drive it without a socket.
    void feed(const uint8_t* data, size_t len) {
        for (size_t k = 0; k < len; ++k) {
            uint8_t c = data[k];                  // already 0..255 (Java: & 255)
            if (dvc_mode_) {
                if (dvc_encryption_ && rc4_decrypter_)
                    c = static_cast<uint8_t>(c ^ (rc4_decrypter_->randomValue() & 0xFF));
                dvc_mode_ = process_dvc(c);
                if (!dvc_mode_) set_status(1, "DVC Mode off at run");
            } else if (c == 0x1B) {               // ESC
                esc_state_ = 1;
            } else if (esc_state_ == 1 && c == '[') {
                esc_state_ = 2;
            } else if (esc_state_ == 2 && c == 'R') {
                dvc_mode_ = true;  dvc_encryption_ = true;
                set_status(1, "DVC Mode (RC4-128 bit)");
            } else if (esc_state_ == 2 && c == 'r') {
                dvc_mode_ = true;  dvc_encryption_ = false;
                set_status(1, "DVC Mode (no encryption)");
            } else {
                esc_state_ = 0;
            }
        }
    }

    // --- transport state (names track the Java fields) ---
    socket_t   sock_ = INVALID_SOCK;   // s
    int        connected_ = 0;
    std::string host_, login_;
    int        port_ = 23;

    bool       dvc_mode_ = false;
    bool       dvc_encryption_ = false;
    int        esc_state_ = 0;         // var3_2 in run()

    std::unique_ptr<RC4> rc4_decrypter_;
    uint8_t    decrypt_key_[16]{};
    bool       decryption_active_ = false;
    bool       encryption_enabled_ = false;

    std::thread        receiver_;
    std::atomic<bool>  running_{false};

    // --- platform socket helpers ---
    static constexpr int RECV_TIMEOUT = -2;

    static void net_init() {
#if defined(_WIN32)
        static bool done = [] {
            WSADATA w; return WSAStartup(MAKEWORD(2, 2), &w) == 0;
        }();
        (void)done;
#endif
    }
    static void close_sock(socket_t fd) {
#if defined(_WIN32)
        ::closesocket(fd);
#else
        ::close(fd);
#endif
    }
    static void set_recv_timeout(socket_t fd, int ms) {
        if (fd == INVALID_SOCK) return;
#if defined(_WIN32)
        DWORD tv = static_cast<DWORD>(ms);
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        timeval tv{ ms / 1000, (ms % 1000) * 1000 };
        ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }
    // Returns bytes read, 0 on EOF, RECV_TIMEOUT on timeout, -1 on error.
    static int recv_bytes(socket_t fd, uint8_t* buf, size_t cap) {
        int n = ::recv(fd, reinterpret_cast<char*>(buf), static_cast<int>(cap), 0);
        if (n > 0)  return n;
        if (n == 0) return 0;
#if defined(_WIN32)
        int e = WSAGetLastError();
        if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) return RECV_TIMEOUT;
#else
        if (errno == EAGAIN || errno == EWOULDBLOCK) return RECV_TIMEOUT;
#endif
        return -1;
    }
    void send_all(const uint8_t* data, size_t n) {
        size_t sent = 0;
        while (sent < n) {
            int w = ::send(sock_, reinterpret_cast<const char*>(data + sent),
                           static_cast<int>(n - sent), 0);
            if (w <= 0) break;
            sent += static_cast<size_t>(w);
        }
    }
};

} // namespace ilo2
