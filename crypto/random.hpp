// random.hpp — cryptographically secure randomness, Windows + Linux.
//
// The TLS handshake needs this in three places, all of them security-critical:
// the 48-byte premaster secret, the 28-byte client random, and the PKCS#1 v1.5
// type-2 padding string. Neither rand() nor std::random_device is acceptable —
// the standard explicitly permits std::random_device to be deterministic, and
// on some MinGW builds it historically was.
//
// There is no fallback to a weak source. A failure here returns false and the
// caller must abort the handshake: continuing with predictable padding or a
// predictable premaster would silently void the session's confidentiality.
#pragma once
#include <cstdint>
#include <cstddef>

#if defined(_WIN32)
  // WIN32_LEAN_AND_MEAN keeps <windows.h> from pulling in the old <winsock.h>,
  // which would collide with the <winsock2.h> that ilo/telnet.hpp includes.
  #ifndef WIN32_LEAN_AND_MEAN
    #define WIN32_LEAN_AND_MEAN
  #endif
  #include <windows.h>
  #include <bcrypt.h>
#else
  #include <cerrno>
  #include <cstdio>
  #include <unistd.h>
  #if defined(__linux__)
    #include <sys/random.h>
  #endif
#endif

namespace ilo2 {

// Fills buf with len secure random bytes. Returns false on failure; treat that
// as fatal.
inline bool secure_random(uint8_t* buf, size_t len) {
    if (len == 0) return true;
#if defined(_WIN32)
    // A null algorithm handle with BCRYPT_USE_SYSTEM_PREFERRED_RNG asks for the
    // system CSPRNG directly, so there is no provider to open or close.
    return BCryptGenRandom(nullptr, buf, static_cast<ULONG>(len),
                           BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;  // STATUS_SUCCESS
#else
  #if defined(__linux__)
    size_t off = 0;
    while (off < len) {
        ssize_t n = ::getrandom(buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;                       // ENOSYS on pre-3.17 kernels -> fall through
        }
        off += static_cast<size_t>(n);
    }
    if (off == len) return true;
  #endif
    std::FILE* f = std::fopen("/dev/urandom", "rb");
    if (!f) return false;
    size_t got = std::fread(buf, 1, len, f);
    std::fclose(f);
    return got == len;
#endif
}

} // namespace ilo2
