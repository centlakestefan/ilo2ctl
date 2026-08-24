// test_random.cpp — sanity checks on the platform CSPRNG.
//
// These cannot prove randomness, but they do catch the failure modes that
// actually happen: the call silently doing nothing, returning a constant, or
// returning the same block twice. Any of those would quietly destroy the
// confidentiality of every session, so a cheap smoke test is worth having.
#include <cstring>
#include <set>
#include <string>
#include "tests/test_util.hpp"
#include "crypto/random.hpp"

using namespace ilo2;

int main() {
    std::printf("[basic behaviour]\n");
    {
        uint8_t buf[64];
        std::memset(buf, 0, sizeof(buf));
        t::ok(secure_random(buf, sizeof(buf)), "secure_random succeeds");

        bool all_zero = true;
        for (uint8_t b : buf) if (b) { all_zero = false; break; }
        t::ok(!all_zero, "output is not all zeros");

        t::ok(secure_random(nullptr, 0), "a zero-length request succeeds");
    }

    std::printf("[independence across calls]\n");
    {
        std::set<std::string> seen;
        const int reps = 2000;
        for (int i = 0; i < reps; ++i) {
            uint8_t buf[32];
            if (!secure_random(buf, sizeof(buf))) { t::ok(false, "call failed"); break; }
            seen.insert(t::hex(buf, sizeof(buf)));
        }
        t::ok(static_cast<int>(seen.size()) == reps, "no 32-byte block repeats");
    }

    std::printf("[distribution smoke test]\n");
    {
        // Not a statistical test -- just enough to catch a stuck or truncated
        // generator. Over 256 KiB every byte value should appear, and the
        // overall bit balance should sit near half.
        const size_t N = 256 * 1024;
        std::vector<uint8_t> buf(N);
        t::ok(secure_random(buf.data(), N), "bulk request succeeds");

        int counts[256] = {0};
        size_t ones = 0;
        for (uint8_t b : buf) {
            counts[b]++;
            for (int i = 0; i < 8; ++i) ones += (b >> i) & 1;
        }
        int missing = 0, extreme = 0;
        const int expect = static_cast<int>(N / 256);
        for (int c : counts) {
            if (c == 0) ++missing;
            if (c < expect / 2 || c > expect * 2) ++extreme;
        }
        t::ok(missing == 0, "every byte value 0..255 occurs");
        t::ok(extreme == 0, "no byte value is wildly over- or under-represented");

        double frac = double(ones) / double(N * 8);
        std::printf("  bit balance %.4f (expect ~0.5)\n", frac);
        t::ok(frac > 0.49 && frac < 0.51, "bit balance is near 0.5");
    }

    return t::report("test_random");
}
