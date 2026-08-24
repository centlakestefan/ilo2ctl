// tls_get.cpp — fetch a page from the iLO over the hand-written TLS 1.0 client.
//
// This is the replacement for `curl -k --tlsv1.0 --tls-max 1.0`, which the
// Python scrapers shell out to. That dependency is not merely inelegant: the
// curl on this box is Schannel-backed, which is the only reason it can still
// speak TLS 1.0. On Linux curl links the system OpenSSL 3, where TLS 1.0 is
// below the default security level, so the scrapers do not work there at all.
//
// Build:
//   cmake -S . -B build/cmake -G Ninja && cmake --build build/cmake --target tls_get
//
// Usage:
//   tls_get <host> [path] [--port N] [--cookie STR] [--head]
#include <cstdio>
#include <cstring>
#include <string>
#include "tls/client.hpp"

using namespace ilo2;

static void hexdump(const uint8_t* p, size_t n, size_t limit = 64) {
    const size_t m = n < limit ? n : limit;
    for (size_t i = 0; i < m; ++i) std::printf("%02x", p[i]);
    if (n > m) std::printf("... (%zu bytes)", n);
    std::printf("\n");
}

int main(int argc, char** argv) {
    if (argc < 2) {
        std::fprintf(stderr,
            "usage: tls_get <host> [path] [--port N] [--cookie STR] [--head]\n");
        return 2;
    }

    std::string host = argv[1];
    std::string path = "/";
    std::string cookie;
    uint16_t port = 443;
    bool head_only  = false;
    bool http10     = false;
    std::string outfile;

    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--port" && i + 1 < argc)        port = static_cast<uint16_t>(std::atoi(argv[++i]));
        else if (a == "--cookie" && i + 1 < argc) cookie = argv[++i];
        else if (a == "--head")                   head_only = true;
        else if (a == "--http10")                 http10 = true;
        else if (a == "--out" && i + 1 < argc)    outfile = argv[++i];
        else if (a.size() && a[0] != '-')         path = a;
    }

    std::printf("=== TLS 1.0 handshake: %s:%u ===\n", host.c_str(), port);

    // Do the handshake by hand first, so the diagnostics are visible even when
    // the HTTP layer is not the interesting part.
    tls::Client c;
    std::string err;
    if (!c.connect(host, port, err)) {
        std::printf("HANDSHAKE FAILED: %s\n", err.c_str());
        return 1;
    }

    std::printf("handshake OK\n");
    std::printf("  cipher suite : 0x%04x%s\n", c.cipher_suite(),
                c.cipher_suite() == tls::TLS_RSA_WITH_RC4_128_MD5
                    ? " (TLS_RSA_WITH_RC4_128_MD5)" : "");
    std::printf("  server key   : %zu-bit RSA, e=%u\n", c.server_key().k * 8,
                static_cast<unsigned>(c.server_key().e));
    std::printf("  certificate  : %zu bytes DER\n", c.server_certificate().size());
    std::printf("  cert head    : ");
    hexdump(c.server_certificate().data(), c.server_certificate().size(), 32);

    // HTTP/1.1 unless --http10 is given. The iLO answers an HTTP/1.0 request
    // with 200 OK and a page saying the browser must support HTTP 1.1 -- a
    // valid-looking wrong page rather than an error, so --http10 exists purely
    // to be able to demonstrate that.
    std::string req = std::string(head_only ? "HEAD " : "GET ") + path +
                      (http10 ? " HTTP/1.0\r\n" : " HTTP/1.1\r\n") +
                      "Host: " + host + "\r\n"
                      "User-Agent: ilo2-console/1.0\r\n"
                      "Accept: */*\r\n";
    if (!cookie.empty()) req += "Cookie: " + cookie + "\r\n";
    req += "Connection: close\r\n\r\n";
    std::printf("\n--- request (%zu bytes) ---\n%s", req.size(), req.c_str());

    if (!c.send(req, err)) {
        std::printf("SEND FAILED: %s\n", err.c_str());
        return 1;
    }

    std::string raw;
    size_t records = 0;
    for (;;) {
        std::vector<uint8_t> chunk;
        bool eof = false;
        std::string rerr;
        if (!c.recv(chunk, eof, rerr)) {
            if (eof) { std::printf("  stream ended: %s\n", rerr.c_str()); break; }
            // Keep whatever arrived: a stall still tells us what the server
            // said, which is the whole point of a diagnostic tool.
            std::printf("  stopped after %zu records: %s\n", records, rerr.c_str());
            break;
        }
        ++records;
        raw.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
    }
    c.close();

    std::printf("\n=== response: %zu bytes in %zu records ===\n", raw.size(), records);
    const size_t split = raw.find("\r\n\r\n");
    if (split == std::string::npos) {
        std::printf("%.*s\n", static_cast<int>(raw.size() > 2000 ? 2000 : raw.size()), raw.c_str());
        return 0;
    }
    const std::string headers = raw.substr(0, split);
    std::printf("%s\n", headers.c_str());

    std::string body = raw.substr(split + 4);
    const std::string te = tls::header_value(headers, "Transfer-Encoding");
    if (te.find("chunked") != std::string::npos) {
        std::string decoded;
        if (tls::dechunk(body, decoded)) {
            std::printf("--- de-chunked %zu -> %zu bytes ---\n", body.size(), decoded.size());
            body.swap(decoded);
        } else {
            std::printf("--- WARNING: malformed chunked body, showing raw ---\n");
        }
    }
    std::printf("--- body: %zu bytes ---\n", body.size());
    if (!outfile.empty()) {
        std::FILE* f = std::fopen(outfile.c_str(), "wb");
        if (!f) { std::printf("cannot write %s\n", outfile.c_str()); return 1; }
        std::fwrite(body.data(), 1, body.size(), f);
        std::fclose(f);
        std::printf("wrote %s\n", outfile.c_str());
        return 0;
    }
    std::printf("%.*s\n", static_cast<int>(body.size() > 1200 ? 1200 : body.size()), body.c_str());
    if (body.size() > 1200) std::printf("... (truncated)\n");
    return 0;
}
