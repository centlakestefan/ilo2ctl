// socket.hpp — a minimal blocking TCP client socket, Windows and POSIX.
//
// ilo/telnet.hpp carries its own socket helpers. They are not shared yet on
// purpose: that file's receive loop is validated byte-for-byte against HP's
// telnet.run(), and refactoring underneath it buys nothing right now. When the
// GUI needs both transports at once, this is the one to keep and telnet.hpp
// should adopt it.
//
// getaddrinfo rather than gethostbyname, so a hostname or a literal address,
// IPv4 or IPv6, all work the same way.
#pragma once
#include <cstdint>
#include <cstring>
#include <string>

#if defined(_WIN32)
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #if defined(_MSC_VER)
    #pragma comment(lib, "ws2_32.lib")
  #endif
#else
  #include <sys/socket.h>
  #include <sys/types.h>
  #include <netinet/in.h>
  #include <netinet/tcp.h>
  #include <netdb.h>
  #include <unistd.h>
  #include <cerrno>
#endif

namespace ilo2 {
namespace net {

#if defined(_WIN32)
using socket_t = SOCKET;
inline constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
#else
using socket_t = int;
inline constexpr socket_t INVALID_SOCK = -1;
#endif

class TcpSocket {
public:
    static constexpr int RECV_TIMEOUT = -2;
    static constexpr int RECV_ERROR   = -1;

    TcpSocket() = default;
    ~TcpSocket() { close(); }

    TcpSocket(const TcpSocket&)            = delete;
    TcpSocket& operator=(const TcpSocket&) = delete;

    bool valid() const { return fd_ != INVALID_SOCK; }

    bool connect(const std::string& host, uint16_t port, int timeout_ms,
                 std::string& err) {
        init();
        close();

        char portstr[16];
        std::snprintf(portstr, sizeof(portstr), "%u", static_cast<unsigned>(port));

        addrinfo hints{};
        hints.ai_family   = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_protocol = IPPROTO_TCP;

        addrinfo* res = nullptr;
        if (::getaddrinfo(host.c_str(), portstr, &hints, &res) != 0 || !res) {
            err = "cannot resolve " + host;
            return false;
        }

        for (addrinfo* a = res; a; a = a->ai_next) {
            socket_t s = ::socket(a->ai_family, a->ai_socktype, a->ai_protocol);
            if (s == INVALID_SOCK) continue;
            if (::connect(s, a->ai_addr, static_cast<int>(a->ai_addrlen)) == 0) {
                fd_ = s;
                break;
            }
            close_fd(s);
        }
        ::freeaddrinfo(res);

        if (fd_ == INVALID_SOCK) {
            err = "cannot connect to " + host + ":" + portstr;
            return false;
        }

        set_recv_timeout(timeout_ms);
        int one = 1;
        ::setsockopt(fd_, IPPROTO_TCP, TCP_NODELAY,
                     reinterpret_cast<const char*>(&one), sizeof(one));
        return true;
    }

    // >0 bytes read, 0 on orderly EOF, RECV_TIMEOUT, or RECV_ERROR.
    int recv(uint8_t* buf, size_t cap) {
        if (!valid()) return RECV_ERROR;
        int n = ::recv(fd_, reinterpret_cast<char*>(buf), static_cast<int>(cap), 0);
        if (n > 0)  return n;
        if (n == 0) return 0;
#if defined(_WIN32)
        int e = WSAGetLastError();
        if (e == WSAETIMEDOUT || e == WSAEWOULDBLOCK) return RECV_TIMEOUT;
#else
        if (errno == EINTR) return RECV_TIMEOUT;
        if (errno == EAGAIN || errno == EWOULDBLOCK) return RECV_TIMEOUT;
#endif
        return RECV_ERROR;
    }

    bool send_all(const uint8_t* data, size_t len) {
        if (!valid()) return false;
        size_t sent = 0;
        while (sent < len) {
            int n = ::send(fd_, reinterpret_cast<const char*>(data + sent),
                           static_cast<int>(len - sent), 0);
            if (n <= 0) return false;
            sent += static_cast<size_t>(n);
        }
        return true;
    }

    void close() {
        if (fd_ != INVALID_SOCK) {
            close_fd(fd_);
            fd_ = INVALID_SOCK;
        }
    }

    void set_recv_timeout(int ms) {
        if (!valid()) return;
#if defined(_WIN32)
        DWORD tv = static_cast<DWORD>(ms);
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO,
                     reinterpret_cast<const char*>(&tv), sizeof(tv));
#else
        timeval tv{ ms / 1000, (ms % 1000) * 1000 };
        ::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    }

private:
    static void init() {
#if defined(_WIN32)
        static bool done = [] {
            WSADATA w;
            return WSAStartup(MAKEWORD(2, 2), &w) == 0;
        }();
        (void)done;
#endif
    }
    static void close_fd(socket_t s) {
#if defined(_WIN32)
        ::closesocket(s);
#else
        ::close(s);
#endif
    }

    socket_t fd_ = INVALID_SOCK;
};

} // namespace net
} // namespace ilo2
