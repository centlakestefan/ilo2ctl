// connections.hpp — the list of recently used iLOs.
//
// Host and user only, deliberately: the password is never written anywhere by
// this program. The file is one "host<TAB>user" line per entry, most recent
// first, so it can be read and fixed with any editor. Where it lives is the
// front end's business (SDL_GetPrefPath); this only knows how to read, write
// and reorder it, which is what can be tested without a window.
#pragma once

#include <cstdio>
#include <string>
#include <vector>

namespace ilo2 {

struct SavedConnection {
    std::string host;
    std::string user;
    bool operator==(const SavedConnection& o) const { return host == o.host && user == o.user; }
};

constexpr size_t MAX_SAVED_CONNECTIONS = 10;

inline std::vector<SavedConnection> parse_connections(const std::string& text) {
    std::vector<SavedConnection> out;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t nl = text.find('\n', pos);
        if (nl == std::string::npos) nl = text.size();
        std::string line = text.substr(pos, nl - pos);
        pos = nl + 1;
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty() || line[0] == '#') continue;
        const size_t tab = line.find('\t');
        SavedConnection c;
        c.host = line.substr(0, tab);
        if (tab != std::string::npos) c.user = line.substr(tab + 1);
        if (c.host.empty()) continue;
        out.push_back(c);
        if (out.size() >= MAX_SAVED_CONNECTIONS) break;
    }
    return out;
}

inline std::string format_connections(const std::vector<SavedConnection>& list) {
    std::string out = "# ilo2_console: recent connections, most recent first. host<TAB>user\n";
    for (const auto& c : list) out += c.host + "\t" + c.user + "\n";
    return out;
}

// Move (or insert) host/user to the front, dropping duplicates and anything
// past the cap.
inline void remember_connection(std::vector<SavedConnection>& list,
                                const std::string& host, const std::string& user) {
    const SavedConnection c{ host, user };
    for (auto it = list.begin(); it != list.end();) {
        if (*it == c) it = list.erase(it); else ++it;
    }
    list.insert(list.begin(), c);
    if (list.size() > MAX_SAVED_CONNECTIONS) list.resize(MAX_SAVED_CONNECTIONS);
}

inline void forget_connection(std::vector<SavedConnection>& list, size_t index) {
    if (index < list.size()) list.erase(list.begin() + static_cast<long>(index));
}

inline std::vector<SavedConnection> load_connections(const std::string& path) {
    std::FILE* f = std::fopen(path.c_str(), "rb");
    if (!f) return {};
    std::string text;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) text.append(buf, n);
    std::fclose(f);
    return parse_connections(text);
}

inline bool save_connections(const std::string& path, const std::vector<SavedConnection>& list) {
    std::FILE* f = std::fopen(path.c_str(), "wb");
    if (!f) return false;
    const std::string text = format_connections(list);
    const bool ok = std::fwrite(text.data(), 1, text.size(), f) == text.size();
    std::fclose(f);
    return ok;
}

} // namespace ilo2
