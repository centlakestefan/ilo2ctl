// test_media.cpp — the virtual-media HTTP server and the URL assembly, with no
// iLO involved: the server is started for real and driven over the loopback.
//
// The one thing worth testing hardest is the range handling, because the
// firmware asks for ranges in a shape almost nothing else does -- offsets
// zero-padded to twenty digits (testdata/ilo2_vm_http_requests.log). That is
// cpp-httplib's parsing rather than ours, which is exactly why it needs a test:
// a library upgrade could silently stop accepting it.
#include <cstdio>
#include <string>
#include <vector>

#include "tests/test_util.hpp"
#include "ilo/media_server.hpp"
#include "tls/socket.hpp"

using namespace ilo2;

// A deterministic file to serve, so every byte can be predicted.
static std::string make_image(const char* path, size_t n) {
    std::string data;
    data.reserve(n);
    uint32_t x = 0x1234567u;
    for (size_t i = 0; i < n; ++i) {
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        data.push_back(static_cast<char>(x & 0xFF));
    }
    if (FILE* f = std::fopen(path, "wb")) {
        std::fwrite(data.data(), 1, data.size(), f);
        std::fclose(f);
    }
    return data;
}

// A tiny HTTP client over the raw socket: the point is to send exactly the
// bytes the firmware sends, including its odd padding. Returns the status code
// and fills `body`, or -1 if the exchange never got that far.
static int fetch(uint16_t port, const std::string& range_header, std::string& body) {
    net::TcpSocket c;
    std::string e;
    if (!c.connect("127.0.0.1", port, 4000, e)) return -1;
    std::string req = "GET /test_media_image.iso HTTP/1.1\r\n"
                      "Host: 127.0.0.1\r\n";
    if (!range_header.empty()) req += "Range: " + range_header + "\r\n";
    req += "Connection: close\r\n\r\n";
    if (!c.send_all(reinterpret_cast<const uint8_t*>(req.data()), req.size())) return -1;
    c.set_recv_timeout(4000);
    std::string all;
    for (;;) {
        uint8_t buf[8192];
        const int n = c.recv(buf, sizeof buf);
        if (n <= 0) break;
        all.append(reinterpret_cast<char*>(buf), static_cast<size_t>(n));
    }
    c.close();
    const size_t hdr = all.find("\r\n\r\n");
    if (hdr == std::string::npos) return -1;
    body = all.substr(hdr + 4);
    const size_t sp = all.find(' ');
    return (sp == std::string::npos) ? -1 : std::atoi(all.c_str() + sp + 1);
}

int main() {
    const char* iso = "build/test_media_image.iso";
    const size_t N = 300000;
    const std::string truth = make_image(iso, N);
    t::ok(truth.size() == N, "test image written");

    std::printf("[url path sanitising]\n");
    {
        // ISO names routinely carry spaces and parentheses; they must not end
        // up in a URL the firmware then fails to fetch.
        t::eq(MediaServer::basename_of("/tmp/win server (2022).iso"),
              "win_server__2022_.iso", "spaces and parens replaced");
        t::eq(MediaServer::basename_of("C:\\isos\\deb-12.iso"), "deb-12.iso",
              "windows separator, safe characters kept");
        t::eq(MediaServer::basename_of("plain.iso"), "plain.iso", "bare name");
        t::eq(MediaServer::basename_of(""), "image.iso", "empty falls back");
    }

    std::printf("[serving]\n");
    MediaServer srv;
    std::string err;
    const uint16_t PORT = 18099;
    if (!t::ok(srv.start(iso, PORT, err), "server starts")) {
        std::printf("  %s\n", err.c_str());
        return t::report("test_media");
    }
    t::ok(srv.running(), "server reports running");

    const MediaServer::Stats s0 = srv.stats();
    t::ok(s0.size == static_cast<int64_t>(N), "size reported correctly");
    t::eq(s0.url_path, "/test_media_image.iso", "url path from the file name");

    std::printf("[local address discovery]\n");
    {
        // The mechanism behind the virtual-media URL: ask the kernel which of
        // our addresses reaches a given peer. Over loopback the answer is
        // knowable, so this asserts rather than merely prints.
        const std::string local = net::local_address_towards("127.0.0.1", PORT);
        t::eq(local, "127.0.0.1", "local address towards loopback");
        t::eq(srv.url(local), "http://127.0.0.1:" + std::to_string(PORT) +
                              "/test_media_image.iso", "assembled URL");
        // No address, no URL -- never a guess.
        t::ok(srv.url("").empty(), "no address yields no URL");
        t::ok(net::local_address_towards("127.0.0.1", 1).empty(),
              "unreachable peer yields no address");
    }

    std::printf("[range requests]\n");
    {
        std::string body;
        t::ok(fetch(PORT, "", body) == 200, "plain GET is 200");
        t::ok(body.size() == N, "plain GET returns the whole image");
        t::ok(body == truth, "plain GET bytes are exact");

        t::ok(fetch(PORT, "bytes=100-131", body) == 206, "byte range is 206");
        t::ok(body == truth.substr(100, 32), "range bytes are exact");

        // The firmware's own spelling. Same 32 bytes, twenty-digit offsets.
        t::ok(fetch(PORT, "bytes=00000000000000000100-00000000000000000131", body) == 206,
              "zero-padded range is 206");
        t::ok(body == truth.substr(100, 32), "zero-padded range bytes are exact");

        // Open-ended, as a reader walking to the end would send.
        t::ok(fetch(PORT, "bytes=299990-", body) == 206, "open-ended range is 206");
        t::ok(body == truth.substr(299990), "open-ended range bytes are exact");
    }

    std::printf("[read map]\n");
    {
        // What a front end draws to show the firmware working through the
        // image. A second server on its own port so the counters asserted
        // below are not disturbed, and so the map starts empty.
        //
        // This also pins down something the strip depends on and nothing else
        // asserts directly: for a range request cpp-httplib hands the content
        // provider an *absolute* file offset, not one relative to the range.
        // If that ever changed, the bytes would still be right (we seek to the
        // offset we are given) but every read would be plotted at the wrong
        // place on the strip.
        MediaServer m;
        std::string e;
        const uint16_t MPORT = 18100;
        if (t::ok(m.start(iso, MPORT, e), "read-map server starts")) {
            MediaServer::Stats s = m.stats();
            t::ok(s.map.size() == static_cast<size_t>(MediaServer::kMapBuckets),
                  "map has one entry per bucket");
            t::ok(s.now != 0, "map carries a clock to age timestamps against");
            int marked = 0;
            for (uint32_t v : s.map) if (v) ++marked;
            t::ok(marked == 0, "nothing read yet, so nothing marked");

            // Ten bytes at the very end, and nothing else.
            std::string body;
            t::ok(fetch(MPORT, "bytes=299990-", body) == 206, "tail range served");
            s = m.stats();
            marked = 0;
            for (uint32_t v : s.map) if (v) ++marked;
            t::ok(marked == 1, "a ten-byte read marks exactly one bucket");
            t::ok(s.map[static_cast<size_t>(MediaServer::kMapBuckets - 1)] != 0,
                  "and it is the bucket at the end of the image");
            t::ok(s.map[0] == 0, "the head of the image is still untouched");

            // A whole-image GET covers everything, however it is chunked.
            t::ok(fetch(MPORT, "", body) == 200, "whole image served");
            s = m.stats();
            marked = 0;
            for (uint32_t v : s.map) if (v) ++marked;
            t::ok(marked == MediaServer::kMapBuckets, "a full read marks every bucket");

            // Restarting resets the map: a second image must not inherit the
            // first one's read history.
            t::ok(m.start(iso, MPORT, e), "server restarts");
            s = m.stats();
            marked = 0;
            for (uint32_t v : s.map) if (v) ++marked;
            t::ok(marked == 0, "restart clears the map");
            m.stop();
        }
    }

    std::printf("[shutdown]\n");
    {
        const MediaServer::Stats s = srv.stats();
        std::printf("  served %llu requests, %llu bytes\n",
                    (unsigned long long)s.requests, (unsigned long long)s.bytes);
        // Four fetches above, and the byte total is exactly the whole image
        // plus 32 + 32 + 10 from the three ranges. Asserting the exact figures
        // rather than a lower bound: this is what tells a GUI whether the iLO
        // is actually reading, so it being merely plausible is not enough.
        t::ok(s.requests == 4, "every request counted, and no extras");
        t::ok(s.bytes == N + 32 + 32 + 10, "byte total is exact");
        srv.stop();
        t::ok(!srv.running(), "server stops");
        // Stopping twice must not hang or crash: the worker's shutdown path
        // stops the server after the thread has already ejected.
        srv.stop();
        t::ok(true, "second stop is harmless");
    }

    std::remove(iso);
    return t::report("test_media");
}
