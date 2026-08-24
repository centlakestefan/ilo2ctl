// test_sha1.cpp — SHA-1 against canonical vectors, plus the two behaviours the
// TLS 1.0 handshake hash depends on: chunked updates matching a single update,
// and a copied object being an independent snapshot.
#include <array>
#include "tests/test_util.hpp"
#include "crypto/sha1.hpp"

using namespace ilo2;

#include "tests/hash_vectors.inc"

static std::string sha1hex(const std::vector<uint8_t>& d) {
    SHA1 h;
    h.update(d.data(), d.size());
    return t::hex(h.digest());
}

int main() {
    std::printf("[SHA-1 known-answer vectors]\n");
    for (const auto& v : SHA1_VECTORS) {
        auto data = t::unhex(v.data_hex);
        char label[64];
        std::snprintf(label, sizeof(label), "sha1(%zu bytes)", data.size());
        t::eq(sha1hex(data), v.want, label);
    }

    // The classic long-message case, built rather than embedded.
    {
        SHA1 h;
        const uint8_t a = 'a';
        for (int i = 0; i < 1000000; ++i) h.update(&a, 1);
        t::eq(t::hex(h.digest()), SHA1_MILLION_A, "sha1(1,000,000 x 'a')");
    }

    std::printf("[streaming equivalence]\n");
    {
        // Chunk boundaries that straddle the 64-byte block in every way.
        std::vector<uint8_t> msg(1000);
        for (size_t i = 0; i < msg.size(); ++i) msg[i] = static_cast<uint8_t>(i * 7 + 3);
        std::string want = sha1hex(msg);

        for (size_t chunk : {size_t(1), size_t(7), size_t(63), size_t(64), size_t(65), size_t(127)}) {
            SHA1 h;
            for (size_t off = 0; off < msg.size(); off += chunk)
                h.update(msg.data() + off, std::min(chunk, msg.size() - off));
            char label[64];
            std::snprintf(label, sizeof(label), "chunked update, chunk=%zu", chunk);
            t::eq(t::hex(h.digest()), want, label);
        }
    }

    std::printf("[copy is an independent snapshot]\n");
    {
        // This is exactly the TLS 1.0 Finished pattern: hash the handshake so
        // far, snapshot to compute verify_data, then keep hashing into the
        // original so the peer's Finished can be verified over the longer
        // transcript. If the copy shared state, the second digest would differ.
        SHA1 running;
        const char* part1 = "handshake-messages-so-far";
        running.update(reinterpret_cast<const uint8_t*>(part1), std::strlen(part1));

        SHA1 snapshot = running;                 // implicit copy ctor
        std::string at_snapshot = t::hex(snapshot.digest());

        // Independently compute what the snapshot should have been.
        SHA1 ref;
        ref.update(reinterpret_cast<const uint8_t*>(part1), std::strlen(part1));
        t::eq(at_snapshot, t::hex(ref.digest()), "snapshot digest matches a fresh hash");

        // The original must be unaffected by the copy's destructive digest().
        const char* part2 = "-plus-the-clients-finished";
        running.update(reinterpret_cast<const uint8_t*>(part2), std::strlen(part2));
        SHA1 ref2;
        std::string whole = std::string(part1) + part2;
        ref2.update(reinterpret_cast<const uint8_t*>(whole.data()), whole.size());
        t::eq(t::hex(running.digest()), t::hex(ref2.digest()),
              "original survives the copy's digest()");
    }

    std::printf("[digest() re-initialises]\n");
    {
        SHA1 h;
        h.update(reinterpret_cast<const uint8_t*>("abc"), 3);
        h.digest();                              // discard; must leave a clean state
        h.update(reinterpret_cast<const uint8_t*>("abc"), 3);
        t::eq(t::hex(h.digest()), "a9993e364706816aba3e25717850c26c9cd0d89d",
              "reuse after digest() equals a fresh hash");
    }

    return t::report("test_sha1");
}
