// test_connections.cpp — the recent-connections list: parse, format, reorder,
// cap, and a round trip through a file.
#include <cstdio>
#include <string>
#include <vector>

#include "ui/connections.hpp"

using namespace ilo2;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

int main() {
    std::printf("[parse]\n");
    {
        const auto l = parse_connections("# comment\n10.0.0.1\tAdministrator\r\n\nhostonly\n\tnouser\n");
        CHECK(l.size() == 2);
        CHECK(l.size() >= 1 && l[0].host == "10.0.0.1" && l[0].user == "Administrator");
        CHECK(l.size() >= 2 && l[1].host == "hostonly" && l[1].user.empty());
        CHECK(parse_connections("").empty());
        // No trailing newline still yields the last line.
        CHECK(parse_connections("a\tb").size() == 1);
    }

    std::printf("[remember: front, dedup, cap]\n");
    {
        std::vector<SavedConnection> l;
        remember_connection(l, "h1", "u");
        remember_connection(l, "h2", "u");
        CHECK(l.size() == 2 && l[0].host == "h2");
        remember_connection(l, "h1", "u");             // moves to front, no duplicate
        CHECK(l.size() == 2 && l[0].host == "h1" && l[1].host == "h2");
        remember_connection(l, "h1", "other");         // different user is a different entry
        CHECK(l.size() == 3);
        for (int i = 0; i < 20; ++i) remember_connection(l, "x" + std::to_string(i), "u");
        CHECK(l.size() == MAX_SAVED_CONNECTIONS);
        CHECK(l[0].host == "x19");
        forget_connection(l, 0);
        CHECK(l.size() == MAX_SAVED_CONNECTIONS - 1 && l[0].host == "x18");
        forget_connection(l, 999);                     // out of range is a no-op
        CHECK(l.size() == MAX_SAVED_CONNECTIONS - 1);
    }

    std::printf("[format/parse round trip and file]\n");
    {
        std::vector<SavedConnection> l = { { "10.10.123.130", "Administrator" }, { "ilo.example", "ops" } };
        const auto back = parse_connections(format_connections(l));
        CHECK(back == l);

        const std::string path = "build/test_connections.tmp";
        CHECK(save_connections(path, l));
        CHECK(load_connections(path) == l);
        std::remove(path.c_str());
        CHECK(load_connections("build/does-not-exist.tmp").empty());
    }

    // The file must never contain a password: the type has nowhere to put one.
    static_assert(sizeof(SavedConnection) == 2 * sizeof(std::string), "host and user only");

    if (failures) { std::printf("%d FAILURE(S)\n", failures); return 1; }
    std::printf("all checks passed\n");
    return 0;
}
