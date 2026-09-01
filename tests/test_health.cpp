// test_health.cpp — the health/power-readings parser against replies
// captured from a real iLO 2 (firmware 2.29), plus the scanner's tolerance
// for the firmware's loose XML.
#include <cstdio>
#include <string>

#include "ilo/health.hpp"

using namespace ilo2;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

static std::string slurp(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof(buf), f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

int main() {
    std::printf("[tag scanner]\n");
    {
        const std::string doc = "<?xml version=\"1.0\"?>\r\n<A>\r\n <B VALUE = \"x y\" UNIT='C'/>\r\n</A>";
        size_t pos = 0;
        XmlTag t;
        CHECK(xml_next_tag(doc, pos, t) && t.name == "A" && !t.closing && t.attrs.empty());
        CHECK(xml_next_tag(doc, pos, t) && t.name == "B" && t.value("VALUE") == "x y" && t.value("UNIT") == "C");
        CHECK(xml_next_tag(doc, pos, t) && t.name == "A" && t.closing);
        CHECK(!xml_next_tag(doc, pos, t));
        CHECK(health_int("41") == 41);
        CHECK(health_int("n/a") == -1);
        CHECK(health_int("") == -1);
    }

    std::printf("[embedded health fixture]\n");
    {
        const std::string xml = slurp("testdata/embedded_health.xml");
        CHECK(!xml.empty());
        const HealthData h = parse_embedded_health(xml);
        CHECK(h.valid);

        CHECK(h.fans.size() == 6);
        CHECK(h.fans.size() >= 1 && h.fans[0].label == "Fan 1" && h.fans[0].zone == "System" &&
              h.fans[0].status == "Ok" && h.fans[0].speed_pct == 13);
        CHECK(h.fans.size() >= 6 && h.fans[5].speed_pct == 43);

        CHECK(h.temps.size() == 30);
        CHECK(h.temps.size() >= 1 && h.temps[0].location == "Ambient" && h.temps[0].reading == 24 &&
              h.temps[0].caution == 41 && h.temps[0].critical == 45);
        CHECK(h.temps.size() >= 2 && h.temps[1].location == "CPU 1" && h.temps[1].reading == 40);
        // An unfitted sensor: status n/a, reading n/a -> -1, thresholds still present.
        CHECK(h.temps.size() >= 13 && h.temps[12].status == "n/a" && h.temps[12].reading == -1 &&
              h.temps[12].caution == 70);

        CHECK(h.supplies.size() == 2);
        CHECK(h.supplies.size() >= 2 && h.supplies[1].label == "Power Supply 2" && h.supplies[1].status == "Ok");

        CHECK(h.drives.size() == 8);
        CHECK(h.drives.size() >= 1 && h.drives[0].bay == 1 && h.drives[0].product == "H106030SDSUN300" && h.drives[0].status == "Ok");
        CHECK(h.drives.size() >= 3 && h.drives[2].bay == 3 && h.drives[2].status == "Not Installed");
        CHECK(h.drives.size() >= 8 && h.drives[7].bay == 8 && h.drives[7].product == "ST4000LM024-2AN");

        CHECK(h.glance.fans == "Ok");
        CHECK(h.glance.fan_redundancy == "Fully Redundant");
        CHECK(h.glance.temperature == "Ok");
        CHECK(h.glance.vrm == "Ok");
        CHECK(h.glance.supplies == "Ok");
        CHECK(h.glance.supply_redundancy == "Fully Redundant");
        CHECK(h.glance.drives == "Ok");
        CHECK(health_all_ok(h.glance));

        // The hottest sensor is not a CPU: Temp 30 on the I/O board reads 54.
        const HealthTemp* hot = hottest(h);
        CHECK(hot && hot->reading == 54 && hot->location == "I/O Board" && hot->label == "Temp 30");
    }

    std::printf("[power readings fixture]\n");
    {
        const PowerReadings p = parse_power_readings(slurp("testdata/power_readings.xml"));
        CHECK(p.valid);
        CHECK(p.present == 141);
        CHECK(p.average == 140);
        CHECK(p.maximum == 190);
        CHECK(p.minimum == 138);
    }

    std::printf("[degenerate input]\n");
    {
        CHECK(!parse_embedded_health("").valid);
        CHECK(!parse_power_readings("<RIBCL></RIBCL>").valid);
        // Truncated report: what was parsed is kept, but it is not valid.
        const std::string xml = slurp("testdata/embedded_health.xml");
        const HealthData part = parse_embedded_health(xml.substr(0, xml.size() / 2));
        CHECK(!part.valid);
        CHECK(part.fans.size() == 6);
        HealthGlance g;
        g.fans = "Degraded";
        CHECK(!health_all_ok(g));
    }

    if (failures) { std::printf("%d FAILURE(S)\n", failures); return 1; }
    std::printf("all checks passed\n");
    return 0;
}
