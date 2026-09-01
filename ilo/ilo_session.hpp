// ilo_session.hpp — acquire a remote-console session from an iLO 2 over HTTPS.
//
// Log in to get a session cookie, then scrape the applet parameters out of
// drc2fram.htm. This runs on tls/client.hpp, so the capture path has no
// external dependency at all.
//
// It replaced a Python scraper that shelled out to `curl -k --tlsv1.0
// --tls-max 1.0`, and dropping curl was not cosmetic. The curl on the
// development box is Schannel-backed, which is the only reason it could still
// negotiate TLS 1.0; a Linux curl links the system OpenSSL 3, where TLS 1.0
// sits below the default security level, so that scraper simply did not work
// there.
//
// Two behaviours of this firmware are worth knowing before reading the code:
//
//   * HTTP/1.1 is mandatory. An HTTP/1.0 request is answered 200 OK with a page
//     saying the browser must support HTTP 1.1 — a valid-looking wrong page
//     rather than an error, which a scraper will happily parse into nothing.
//     tls::https_get always sends 1.1 for that reason.
//   * The login "token" is not a header but a cookie value assembled from four
//     colon-separated fields, two of which are base64. The iLO hands out the
//     session key in a <script> variable on login.htm.
#pragma once
#include <cctype>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include "tls/client.hpp"

namespace ilo2 {

struct ConsoleParams {
    std::map<std::string, std::string> info;    // info0, info1, info6, infoa..infod, ...
    std::string session_index;
    std::string cookie;

    std::string get(const std::string& key, const std::string& dflt = "") const {
        auto it = info.find(key);
        return it == info.end() ? dflt : it->second;
    }
    bool has(const std::string& key) const { return info.count(key) != 0; }
};

// Standard base64, used for the user and password fields of the login cookie.
// (Note this is ENCODE with the ordinary alphabet — unrelated to the quirky
// base64_decode HP uses for INFO0, which rewrites ':' and appends a CR.)
inline std::string base64_encode(const std::string& in) {
    static const char* T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 2 < in.size()) {
        const uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8) |
                            static_cast<uint8_t>(in[i + 2]);
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];  out += T[n & 63];
        i += 3;
    }
    if (i + 1 == in.size()) {
        const uint32_t n = static_cast<uint8_t>(in[i]) << 16;
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += "==";
    } else if (i + 2 == in.size()) {
        const uint32_t n = (static_cast<uint8_t>(in[i]) << 16) |
                           (static_cast<uint8_t>(in[i + 1]) << 8);
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];  out += '=';
    }
    return out;
}

// Find `name="value"` in a page and return the value.
inline bool find_quoted(const std::string& page, const std::string& name,
                        std::string& out) {
    size_t pos = 0;
    while ((pos = page.find(name, pos)) != std::string::npos) {
        // Reject a hit that is really the tail of a longer identifier.
        if (pos > 0) {
            const char prev = page[pos - 1];
            if (std::isalnum(static_cast<unsigned char>(prev)) || prev == '_') {
                pos += name.size();
                continue;
            }
        }
        size_t p = pos + name.size();
        while (p < page.size() && (page[p] == ' ' || page[p] == '\t')) ++p;
        if (p >= page.size() || page[p] != '=') { pos += name.size(); continue; }
        ++p;
        while (p < page.size() && (page[p] == ' ' || page[p] == '\t')) ++p;
        if (p >= page.size() || page[p] != '"') { pos += name.size(); continue; }
        const size_t vs = p + 1;
        const size_t ve = page.find('"', vs);
        if (ve == std::string::npos) return false;
        out = page.substr(vs, ve - vs);
        return true;
    }
    return false;
}

// Scrape every `infoX="..."` and `infoX=NNN;` assignment out of drc2fram.htm.
// First occurrence wins, matching the Python's setdefault behaviour.
inline void scrape_info_params(const std::string& page,
                               std::map<std::string, std::string>& out) {
    size_t pos = 0;
    while ((pos = page.find("info", pos)) != std::string::npos) {
        if (pos > 0) {
            const char prev = page[pos - 1];
            if (std::isalnum(static_cast<unsigned char>(prev)) || prev == '_') {
                pos += 4;
                continue;
            }
        }
        size_t ne = pos + 4;
        while (ne < page.size() &&
               (std::islower(static_cast<unsigned char>(page[ne])) ||
                std::isdigit(static_cast<unsigned char>(page[ne])))) ++ne;
        const std::string name = page.substr(pos, ne - pos);

        size_t p = ne;
        while (p < page.size() && (page[p] == ' ' || page[p] == '\t')) ++p;
        if (p >= page.size() || page[p] != '=') { pos = ne; continue; }
        ++p;
        while (p < page.size() && (page[p] == ' ' || page[p] == '\t')) ++p;

        if (p < page.size() && page[p] == '"') {
            const size_t vs = p + 1;
            const size_t ve = page.find('"', vs);
            if (ve == std::string::npos) { pos = ne; continue; }
            out.emplace(name, page.substr(vs, ve - vs));
            pos = ve + 1;
        } else {
            // Accept a leading minus. infod is genuinely signed on this
            // firmware (-268733411 observed), and it happens to arrive quoted,
            // so a digits-only scan works today by luck. If a firmware revision
            // ever emitted it bare, a digits-only scan would yield nothing, the
            // key index would default to 0, and the session would fail to
            // decrypt with no hint as to why.
            const size_t vs = p;
            if (p < page.size() && page[p] == '-') ++p;
            const size_t digits = p;
            while (p < page.size() && std::isdigit(static_cast<unsigned char>(page[p]))) ++p;
            if (p > digits) out.emplace(name, page.substr(vs, p - vs));
            pos = (p > digits) ? p : ne;
        }
    }
}

// The iLO password, in the order the tools look for it: an explicit value, then
// $ILO_PASS, then a gitignored file (default .ilo_pass).
//
// Trailing whitespace is stripped, and that is not fussiness. A .ilo_pass
// written by hand can easily end "secret \r\n"; a reader that strips only the
// line ending sends the trailing space as part of the password, the iLO rejects
// the login, and drc2fram.htm still returns 200 with a page that simply has no
// info0 in it. The symptom is "the console is in use", several layers away from
// the cause. One shared implementation so two callers cannot disagree about it.
inline std::string read_ilo_password(const std::string& explicit_pass,
                                     const std::string& path = ".ilo_pass") {
    auto trim = [](std::string v) {
        while (!v.empty() && (v.back() == '\n' || v.back() == '\r' ||
                              v.back() == ' '  || v.back() == '\t'))
            v.pop_back();
        return v;
    };
    if (!explicit_pass.empty()) return trim(explicit_pass);
    if (const char* env = std::getenv("ILO_PASS")) {
        const std::string p = trim(env);
        if (!p.empty()) return p;
    }
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return std::string();
    char buf[512];
    const size_t n = std::fread(buf, 1, sizeof(buf) - 1, f);
    std::fclose(f);
    buf[n] = '\0';
    return trim(std::string(buf));
}

// Log in and assemble the session cookie.
//
// login.htm carries `var sessionkey="..."` and `var sessionindex="..."`. The
// cookie is  hp-iLO-Login=<index>:<b64 user>:<b64 pass>:<key>.
// A sessionkey of "NONEAVAILABLE" means the iLO has no free session slot, which
// is a wait-and-retry condition rather than a failure of the credentials.
inline bool ilo_login(const std::string& host, uint16_t port,
                      const std::string& user, const std::string& pass,
                      std::string& cookie, std::string& session_index,
                      std::string& err) {
    tls::HttpResponse resp;
    if (!tls::https_get(host, port, "/login.htm", "", resp, err)) return false;
    if (resp.status != 200) {
        err = "login.htm returned HTTP " + std::to_string(resp.status);
        return false;
    }

    std::string key;
    if (!find_quoted(resp.body, "sessionkey", key)) {
        err = "no sessionkey in login.htm (is this an iLO 2?)";
        return false;
    }
    if (key == "NONEAVAILABLE") {
        err = "the iLO has no session slots free -- wait a few minutes and retry";
        return false;
    }
    if (!find_quoted(resp.body, "sessionindex", session_index)) {
        err = "no sessionindex in login.htm";
        return false;
    }

    cookie = "hp-iLO-Login=" + session_index + ":" +
             base64_encode(user) + ":" + base64_encode(pass) + ":" + key;
    return true;
}

// Fetch drc2fram.htm with the login cookie and scrape the applet parameters.
inline bool fetch_console_params(const std::string& host, uint16_t port,
                                 const std::string& cookie, ConsoleParams& out,
                                 std::string& err) {
    tls::HttpResponse resp;
    if (!tls::https_get(host, port, "/drc2fram.htm", cookie, resp, err)) return false;
    if (resp.status != 200) {
        err = "drc2fram.htm returned HTTP " + std::to_string(resp.status);
        return false;
    }

    out.cookie = cookie;
    scrape_info_params(resp.body, out.info);

    if (!out.has("info0") || out.get("info0").empty()) {
        // The page comes back looking normal when the login was rejected or the
        // console is disabled, so say which of those it might be rather than
        // reporting a parse failure.
        err = "no info0 in drc2fram.htm -- the login was probably rejected, or "
              "the remote console is disabled or already in use";
        return false;
    }
    return true;
}

// The whole acquisition, login through parameters.
inline bool acquire_console_session(const std::string& host, uint16_t port,
                                    const std::string& user, const std::string& pass,
                                    ConsoleParams& out, std::string& err) {
    std::string cookie, index;
    if (!ilo_login(host, port, user, pass, cookie, index, err)) return false;
    if (!fetch_console_params(host, port, cookie, out, err)) return false;
    out.session_index = index;
    return true;
}

} // namespace ilo2
