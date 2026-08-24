// test_ilo_session.cpp — the login-cookie assembly and page scraping that
// replaced capture_console.py's curl calls.
//
// This is exactly the sort of code that fails by quietly returning nothing: a
// scraper that matches no parameters looks identical to a page that had none.
#include <string>
#include "tests/test_util.hpp"
#include "ilo/ilo_session.hpp"

using namespace ilo2;

// A representative fragment of drc2fram.htm: quoted strings, bare numerics,
// a repeated parameter, and identifiers that merely start with "info".
static const char* DRC_PAGE = R"HTML(
<html><head><script language="javascript">
var information = "this is not a parameter";
var info0="MHg3DTUwY2FkNTMyZjVmN2QwNzMwODM0YmIyMzg4MDIwNzll";
var info1="LeifsFDIFieejf==";
var info6="23";
var infoa="1";
var infob="31004DD1AABBCCDD00112233445566778899AABBCCDDEEFF";
var infoc="DC98DD85FFEEDDCCBBAA998877665544332211000FFEEDDC";
infod=-268733411;
var infom=1;
var infomm = 2 ;
var infon=0;
var info0="SHOULD-NOT-OVERWRITE-THE-FIRST";
</script></head><body></body></html>
)HTML";

static const char* LOGIN_PAGE = R"HTML(
<html><head><script>
var sessionkey="QXKVNQLJUZMKYOYDEBMCGFGSWILZSHMQFVNTRRIR";
var sessionindex="00000003";
var notsessionkey="DECOY";
</script></head></html>
)HTML";

int main() {
    std::printf("[base64 encoding]\n");
    {
        // RFC 4648 section 10.
        struct { const char* in; const char* want; } v[] = {
            { "",       ""         },
            { "f",      "Zg=="     },
            { "fo",     "Zm8="     },
            { "foo",    "Zm9v"     },
            { "foob",   "Zm9vYg==" },
            { "fooba",  "Zm9vYmE=" },
            { "foobar", "Zm9vYmFy" },
        };
        for (const auto& t : v) {
            char label[64];
            std::snprintf(label, sizeof(label), "base64(\"%s\")", t.in);
            t::eq(base64_encode(t.in), t.want, label);
        }
        // Bytes above 0x7F must not be sign-extended into the index.
        t::eq(base64_encode(std::string("\xFF\xFE\xFD", 3)), "//79",
              "high bytes encode without sign extension");
    }

    std::printf("[quoted value extraction]\n");
    {
        std::string v;
        t::ok(find_quoted(LOGIN_PAGE, "sessionkey", v), "sessionkey found");
        t::eq(v, "QXKVNQLJUZMKYOYDEBMCGFGSWILZSHMQFVNTRRIR", "value is right");
        t::ok(find_quoted(LOGIN_PAGE, "sessionindex", v), "sessionindex found");
        t::eq(v, "00000003", "value is right");
        t::ok(!find_quoted(LOGIN_PAGE, "nosuchthing", v), "absent name is not found");

        // "sessionkey" also occurs inside "notsessionkey"; the first real
        // assignment must win rather than the decoy.
        t::ok(find_quoted(LOGIN_PAGE, "sessionkey", v), "found again");
        t::eq(v, "QXKVNQLJUZMKYOYDEBMCGFGSWILZSHMQFVNTRRIR",
              "a longer identifier ending in the name does not match");
    }

    std::printf("[drc2fram.htm parameter scraping]\n");
    {
        std::map<std::string, std::string> p;
        scrape_info_params(DRC_PAGE, p);

        t::eq(p["info0"], "MHg3DTUwY2FkNTMyZjVmN2QwNzMwODM0YmIyMzg4MDIwNzll",
              "info0 is the quoted base64 token");
        t::eq(p["info1"], "LeifsFDIFieejf==", "info1 present");
        t::eq(p["info6"], "23", "info6 is the console port");
        t::eq(p["infoa"], "1",  "infoa selects encryption");
        t::ok(p["infob"].size() == 48, "infob carries a session key");
        // infod is signed on this firmware. It arrives quoted from the live
        // device, so a digits-only scan would pass by luck; a bare negative
        // must still be captured whole, or the key index silently becomes 0.
        t::eq(p["infod"], "-268733411", "a bare NEGATIVE numeric is captured whole");
        t::eq(p["infom"], "1",  "bare numeric assignment");
        t::eq(p["infomm"], "2", "whitespace around = is tolerated");
        t::eq(p["infon"], "0",  "zero is captured, not treated as absent");

        // First occurrence wins, matching the Python's setdefault.
        t::eq(p["info0"], "MHg3DTUwY2FkNTMyZjVmN2QwNzMwODM0YmIyMzg4MDIwNzll",
              "a later duplicate does not overwrite the first");

        // "information" starts with "info" but is not a parameter we want to
        // mistake for one; if captured at all it must not collide with a real key.
        t::ok(p.find("info") == p.end(), "no bare \"info\" key was invented");

        std::printf("  scraped %zu parameters\n", p.size());
        t::ok(p.size() >= 9, "all the expected parameters were found");
    }

    std::printf("[cookie assembly]\n");
    {
        // hp-iLO-Login=<index>:<b64 user>:<b64 pass>:<key>
        const std::string cookie =
            "hp-iLO-Login=" + std::string("00000003") + ":" +
            base64_encode("Administrator") + ":" +
            base64_encode("secret") + ":" +
            "QXKVNQLJUZMKYOYDEBMCGFGSWILZSHMQFVNTRRIR";
        t::eq(cookie,
              "hp-iLO-Login=00000003:QWRtaW5pc3RyYXRvcg==:c2VjcmV0:"
              "QXKVNQLJUZMKYOYDEBMCGFGSWILZSHMQFVNTRRIR",
              "the four colon-separated fields are in the right order");
    }

    std::printf("[malformed pages]\n");
    {
        std::string v;
        t::ok(!find_quoted("", "sessionkey", v), "empty page yields nothing");
        t::ok(!find_quoted("var sessionkey=", "sessionkey", v), "truncated assignment");
        t::ok(!find_quoted("var sessionkey=\"unterminated", "sessionkey", v),
              "an unterminated quote is refused");

        std::map<std::string, std::string> p;
        scrape_info_params("", p);
        t::ok(p.empty(), "empty page scrapes to nothing");
        scrape_info_params("info", p);
        t::ok(p.empty(), "a bare \"info\" with no assignment is ignored");
        scrape_info_params("info0=", p);
        t::ok(p.empty(), "an assignment with no value is ignored");

        // Every prefix of the real page must be handled without over-reading.
        const std::string page(DRC_PAGE);
        for (size_t n = 0; n < page.size(); n += 5) {
            std::map<std::string, std::string> tmp;
            scrape_info_params(page.substr(0, n), tmp);
        }
        t::ok(true, "every truncated page was scraped safely");
    }

    return t::report("test_ilo_session");
}
