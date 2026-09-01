// test_util.hpp — shared helpers for the self-asserting tests.
#pragma once
#include <algorithm>
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

// ---------------------------------------------------------------------------
// Oracle fixtures (tests/oracle/*.txt)
//
// Traces recorded from HP's real bytecode via tests/*Probe.java and frozen, so
// the ports stay pinned to the applet's observed behaviour without anyone
// needing the (non-redistributable) rc175p10.jar. How they were produced and
// how to regenerate them is in tests/oracle/README.md; neither the build nor
// the test suite requires the jar.
// ---------------------------------------------------------------------------

// Read a fixture. CR is stripped so a CRLF checkout on Windows still compares
// equal -- .gitattributes marks these -text, but do not rely on that alone.
inline std::string read_oracle(const std::string& name) {
    const std::string path = "tests/oracle/" + name + ".txt";
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) {
        ++checks; ++failures;
        std::printf("  FAIL missing oracle fixture %s\n", path.c_str());
        return std::string();
    }
    std::string s;
    char buf[65536];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    std::fclose(f);
    s.erase(std::remove(s.begin(), s.end(), '\r'), s.end());
    return s;
}

// Compare a generated trace against a frozen oracle fixture. On mismatch report
// the first differing line rather than dumping a megabyte of trace.
inline bool eq_oracle(const std::string& got, const std::string& name) {
    ++checks;
    const std::string want = read_oracle(name);
    if (want.empty()) return false;      // read_oracle already counted the failure
    std::string g = got;
    g.erase(std::remove(g.begin(), g.end(), '\r'), g.end());
    if (!g.empty() && g.back() != '\n') g += '\n';
    if (g == want) return true;
    ++failures;

    size_t gi = 0, wi = 0, line = 1;
    while (gi < g.size() && wi < want.size()) {
        size_t ge = g.find('\n', gi), we = want.find('\n', wi);
        if (ge == std::string::npos) ge = g.size();
        if (we == std::string::npos) we = want.size();
        if (g.compare(gi, ge - gi, want, wi, we - wi) != 0) {
            std::printf("  FAIL oracle %s differs at line %zu\n"
                        "       got  %s\n       want %s\n",
                        name.c_str(), line,
                        g.substr(gi, ge - gi).c_str(),
                        want.substr(wi, we - wi).c_str());
            return false;
        }
        gi = ge + 1; wi = we + 1; ++line;
    }
    std::printf("  FAIL oracle %s: length differs (got %zu bytes, want %zu) "
                "after %zu identical lines\n",
                name.c_str(), g.size(), want.size(), line - 1);
    return false;
}

inline int report(const char* suite) {
    std::printf("%s: %d checks, %d failed -- %s\n",
                suite, checks, failures, failures ? "FAILED" : "all passed");
    return failures ? 1 : 0;
}

} // namespace t
