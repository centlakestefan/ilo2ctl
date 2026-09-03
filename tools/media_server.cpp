// media_server.cpp — serve one ISO over HTTP for the iLO's virtual media.
//
// A thin front end for ilo/media_server.hpp, which is the same code the GUI
// runs in-process. The C++ replacement for range_http_server.py.
//
// The firmware's own requests are recorded in
// testdata/ilo2_vm_http_requests.log; --verbose prints them live, which is the
// quickest way to tell "the iLO never connected" from "the iLO is reading".
//
//   media_server --iso path/to.iso [--port 8080] [--verbose]
#include "ilo/media_server.hpp"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>

#include "tls/socket.hpp"

int main(int argc, char** argv) {
    std::string iso, towards;
    int port = 8080;
    bool verbose = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--iso")     iso = next();
        else if (a == "--port")    port = std::atoi(next().c_str());
        else if (a == "--verbose") verbose = true;
        // Print the URL to hand this iLO, chosen the way the GUI chooses it.
        else if (a == "--towards") towards = next();
    }
    if (iso.empty()) {
        std::fprintf(stderr,
            "usage: media_server --iso FILE [--port 8080] [--verbose] [--towards ILO_HOST]\n"
            "\n"
            "  --towards prints the URL to give that iLO, using the local address the\n"
            "  kernel picks to reach it rather than a guess from the interface list.\n");
        return 2;
    }

    ilo2::MediaServer srv;
    std::string err;
    if (!srv.start(iso, static_cast<uint16_t>(port), err)) {
        std::fprintf(stderr, "%s\n", err.c_str());
        return 1;
    }

    const ilo2::MediaServer::Stats s = srv.stats();
    std::printf("serving %s (%lld bytes, %.2f GiB) on 0.0.0.0:%d\n",
                s.iso.c_str(), static_cast<long long>(s.size),
                static_cast<double>(s.size) / (1024.0 * 1024 * 1024), port);
    std::printf("cpp-httplib " CPPHTTPLIB_VERSION "\n");

    if (!towards.empty()) {
        const std::string local = ilo2::net::local_address_towards(towards, 443);
        if (local.empty())
            std::printf("could not determine a local address reaching %s\n", towards.c_str());
        else
            std::printf("give this iLO: %s\n", srv.url(local).c_str());
    }

    // Nothing else to do on this thread: the server has its own.
    uint64_t last = 0;
    for (;;) {
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
        const ilo2::MediaServer::Stats now = srv.stats();
        if (verbose && now.requests != last) {
            std::printf("  %llu requests, %llu bytes served\n",
                        static_cast<unsigned long long>(now.requests),
                        static_cast<unsigned long long>(now.bytes));
            std::fflush(stdout);
            last = now.requests;
        }
        if (!now.running) break;
    }
    return 0;
}
