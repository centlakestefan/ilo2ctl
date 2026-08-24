// test_util.hpp — shared helpers for the self-asserting crypto tests.
#pragma once
#include <cstdio>
#include <cstdint>
#include <string>
#include <vector>

namespace t {

inline int failures = 0;
inline int checks   = 0;

inline std::string hex(const uint8_t* p, size_t n) {
    static const char* H = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s += H[p[i] >> 4]; s += H[p[i] & 0xF]; }
    return s;
}

inline std::string hex(const std::vector<uint8_t>& v) { return hex(v.data(), v.size()); }

template <size_t N>
inline std::string hex(const std::array<uint8_t, N>& a) { return hex(a.data(), N); }

inline std::vector<uint8_t> unhex(const std::string& s) {
    auto nyb = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    for (size_t i = 0; i + 1 < s.size(); i += 2)
        out.push_back(static_cast<uint8_t>((nyb(s[i]) << 4) | nyb(s[i + 1])));
    return out;
}

// Compare two strings; report only failures unless verbose.
inline bool eq(const std::string& got, const std::string& want, const char* what) {
    ++checks;
    if (got == want) return true;
    ++failures;
    std::printf("  FAIL %s\n       got  %s\n       want %s\n", what, got.c_str(), want.c_str());
    return false;
}

inline bool ok(bool cond, const char* what) {
    ++checks;
    if (cond) return true;
    ++failures;
    std::printf("  FAIL %s\n", what);
    return false;
}

inline int report(const char* suite) {
    std::printf("%s: %d checks, %d failed -- %s\n",
                suite, checks, failures, failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}

} // namespace t
