// media_server.hpp — serve one ISO over HTTP for an iLO 2 to boot from.
//
// The firmware pulls the image itself rather than being pushed it, so this has
// to be a real listening server for as long as the image is in use -- which
// during an OS install means tens of minutes, not seconds.
//
// What the firmware actually asks for is recorded in
// testdata/ilo2_vm_http_requests.log, and two details there drove this code:
// it sends byte ranges with the offsets zero-padded to twenty digits, and it
// sends nothing but Host and Range -- no User-Agent, no Accept, no Connection.
// cpp-httplib parses both without help, which is why it is here rather than a
// hand-rolled parser.
//
// Includes httplib.h, which is large. Only the media server and the GUI pay
// for it.
#pragma once

#include "third_party/httplib.h"   // must precede anything pulling in windows.h

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

namespace ilo2 {

class MediaServer {
public:
    struct Stats {
        bool     running  = false;
        uint64_t requests = 0;      // HTTP requests answered
        uint64_t bytes    = 0;      // payload bytes written
        int64_t  size     = 0;      // size of the image being served
        std::string iso;            // path being served
        std::string url_path;       // e.g. "/image.iso"
        uint16_t port = 0;
    };

    MediaServer() = default;
    ~MediaServer() { stop(); }

    MediaServer(const MediaServer&)            = delete;
    MediaServer& operator=(const MediaServer&) = delete;

    // Begin serving `iso` on `port`. Returns once the socket is accepting, so
    // a caller can hand the URL to the iLO immediately afterwards without a
    // race. `err` is set on failure.
    bool start(const std::string& iso, uint16_t port, std::string& err) {
        stop();
        size_ = file_size(iso);
        if (size_ < 0) { err = "cannot open " + iso; return false; }

        iso_      = iso;
        port_     = port;
        url_path_ = "/" + basename_of(iso);
        requests_ = 0;
        bytes_    = 0;

        svr_ = std::make_unique<httplib::Server>();

        // The firmware holds the image open for a whole install and reads it
        // in fits and starts, so the 5s defaults are far too tight.
        svr_->set_read_timeout(120, 0);
        svr_->set_write_timeout(120, 0);
        svr_->set_idle_interval(0, 500000);
        svr_->set_keep_alive_max_count(1000);
        svr_->set_keep_alive_timeout(60);

        auto handler = [this](const httplib::Request&, httplib::Response& res) {
            ++requests_;
            res.set_content_provider(
                static_cast<size_t>(size_), "application/octet-stream",
                [this](size_t offset, size_t length, httplib::DataSink& sink) {
                    std::FILE* f = std::fopen(iso_.c_str(), "rb");
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
                    bytes_ += n;
                    sink.write(buf, n);
                    return true;
                });
        };
        svr_->Get(url_path_, handler);
        svr_->Get(".*", handler);          // the firmware may rewrite the path

        if (!svr_->bind_to_port("0.0.0.0", port)) {
            err = "cannot listen on port " + std::to_string(port);
            svr_.reset();
            return false;
        }
        thread_ = std::thread([this] { svr_->listen_after_bind(); });
        return true;
    }

    void stop() {
        if (svr_) svr_->stop();
        if (thread_.joinable()) thread_.join();
        svr_.reset();
    }

    bool running() const { return thread_.joinable(); }

    // The URL to hand the iLO. `host` must be an address the *iLO* can reach,
    // which is not necessarily one this machine would pick for itself: see
    // net::TcpSocket::local_address().
    std::string url(const std::string& host) const {
        if (host.empty()) return {};
        return "http://" + host + ":" + std::to_string(port_) + url_path_;
    }

    Stats stats() const {
        Stats s;
        s.running  = thread_.joinable();
        s.requests = requests_;
        s.bytes    = bytes_;
        s.size     = size_;
        s.iso      = iso_;
        s.url_path = url_path_;
        s.port     = port_;
        return s;
    }

    static int64_t file_size(const std::string& path) {
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

    // Last path component, with anything that would need escaping in a URL
    // replaced. ISO filenames routinely contain spaces and parentheses.
    static std::string basename_of(const std::string& path) {
        const size_t cut = path.find_last_of("/\\");
        std::string name = (cut == std::string::npos) ? path : path.substr(cut + 1);
        std::string out;
        for (char c : name) {
            const bool safe = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_';
            out += safe ? c : '_';
        }
        return out.empty() ? std::string("image.iso") : out;
    }

private:
    std::unique_ptr<httplib::Server> svr_;
    std::thread            thread_;
    std::string            iso_;
    std::string            url_path_ = "/image.iso";
    int64_t                size_ = 0;
    uint16_t               port_ = 0;
    std::atomic<uint64_t>  requests_{0};
    std::atomic<uint64_t>  bytes_{0};
};

} // namespace ilo2
