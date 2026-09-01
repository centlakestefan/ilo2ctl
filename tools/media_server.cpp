// media_server.cpp — serve one ISO over HTTP for the iLO's virtual media to
// fetch, on vendored cpp-httplib (third_party/httplib.h).
//
// This is the C++ replacement for range_http_server.py. The iLO 2 pulls the
// image itself, so the only hard requirements are HTTP/1.1, a correct
// Content-Length on a file that is comfortably over 4 GB, and byte ranges --
// the firmware seeks all over the image rather than streaming it.
//
// It logs every request and response line, because the firmware's HTTP client
// is from 2005 and what it actually asks for is the thing worth knowing.
//
//   media_server --iso path/to.iso [--port 8080] [--path /image.iso]
#include "third_party/httplib.h"   // must precede anything pulling in windows.h

#include <atomic>
#include <cstdio>
#include <cstdint>
#include <mutex>
#include <string>

namespace {

std::mutex g_log;
std::atomic<uint64_t> g_served{0};

void logline(const std::string& s) {
    std::lock_guard<std::mutex> lk(g_log);
    std::fputs(s.c_str(), stdout);
    std::fputc('\n', stdout);
    std::fflush(stdout);
}

int64_t file_size(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return -1;
#ifdef _WIN32
    _fseeki64(f, 0, SEEK_END);
    const int64_t n = _ftelli64(f);
#else
    fseeko(f, 0, SEEK_END);
    const int64_t n = ftello(f);
#endif
    std::fclose(f);
    return n;
}

} // namespace

int main(int argc, char** argv) {
    std::string iso, url_path = "/image.iso";
    int port = 8080;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--iso")  iso = next();
        else if (a == "--port") port = std::atoi(next().c_str());
        else if (a == "--path") url_path = next();
    }
    if (iso.empty()) {
        std::fprintf(stderr, "usage: media_server --iso FILE [--port 8080] [--path /image.iso]\n");
        return 2;
    }
    const int64_t size = file_size(iso);
    if (size < 0) { std::fprintf(stderr, "cannot open %s\n", iso.c_str()); return 1; }

    httplib::Server svr;

    // The firmware holds the image open for the whole install and reads it in
    // fits and starts, so the default 5s read/write timeouts are far too tight.
    svr.set_read_timeout(120, 0);
    svr.set_write_timeout(120, 0);
    svr.set_idle_interval(0, 500000);
    svr.set_keep_alive_max_count(1000);
    svr.set_keep_alive_timeout(60);

    svr.set_logger([](const httplib::Request& req, const httplib::Response& res) {
        std::string s = "REQ   " + req.method + " " + req.path + " " + req.version +
                        "  from " + req.remote_addr;
        for (const auto& h : req.headers)
            s += "\n        " + h.first + ": " + h.second;
        s += "\nRESP  " + std::to_string(res.status);
        auto cr = res.get_header_value("Content-Range");
        auto cl = res.get_header_value("Content-Length");
        if (!cr.empty()) s += "  Content-Range: " + cr;
        if (!cl.empty()) s += "  Content-Length: " + cl;
        logline(s);
    });

    // cpp-httplib parses Range itself and drives the provider with the right
    // offset/length, answering 206 with Content-Range. Multi-range requests it
    // answers as multipart/byteranges -- whether the firmware ever asks for one
    // is exactly what this test is for.
    auto handler = [&](const httplib::Request& req, httplib::Response& res) {
        if (!req.ranges.empty()) {
            std::string r = "      Range:";
            for (const auto& one : req.ranges)
                r += " [" + std::to_string(one.first) + "," + std::to_string(one.second) + "]";
            if (req.ranges.size() > 1) r += "   << MULTI-RANGE";
            logline(r);
        }
        res.set_content_provider(
            static_cast<size_t>(size), "application/octet-stream",
            [iso](size_t offset, size_t length, httplib::DataSink& sink) {
                std::FILE* f = std::fopen(iso.c_str(), "rb");
                if (!f) return false;
#ifdef _WIN32
                _fseeki64(f, static_cast<int64_t>(offset), SEEK_SET);
#else
                fseeko(f, static_cast<off_t>(offset), SEEK_SET);
#endif
                char buf[65536];
                const size_t want = length < sizeof buf ? length : sizeof buf;
                const size_t n = std::fread(buf, 1, want, f);
                std::fclose(f);
                if (n == 0) return false;
                g_served += n;
                sink.write(buf, n);
                return true;
            });
    };
    svr.Get(url_path, handler);
    svr.Get(".*", handler);          // the firmware may rewrite the path

    logline("serving " + iso + "  (" + std::to_string(size) + " bytes, " +
            std::to_string(size / (1024.0 * 1024 * 1024)).substr(0, 4) + " GiB)");
    logline("cpp-httplib " CPPHTTPLIB_VERSION "  listening on 0.0.0.0:" + std::to_string(port));
    if (!svr.listen("0.0.0.0", port)) {
        std::fprintf(stderr, "listen failed on port %d\n", port);
        return 1;
    }
    return 0;
}
