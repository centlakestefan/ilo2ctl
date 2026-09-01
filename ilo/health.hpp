// health.hpp — GET_EMBEDDED_HEALTH and GET_POWER_READINGS, parsed.
//
// iLO 2's health report is XML in the loosest sense: attributes are written
// `VALUE = "Fan 1"` with spaces around the equals, DRIVE is a self-closing
// tag whose details follow as siblings rather than children, and a sensor
// that is not fitted reads "n/a". A real XML parser would be more code than
// the report deserves, so this is a tag scanner that walks the document in
// order and fills flat records, which is all the panel needs.
//
// Shapes measured on firmware 2.29 (testdata/embedded_health.xml):
//
//   <FANS><FAN><LABEL VALUE = "Fan 1"/><ZONE .../><STATUS .../>
//               <SPEED VALUE = "13" UNIT="Percentage"/></FAN>...</FANS>
//   <TEMPERATURE><TEMP><LABEL/><LOCATION/><STATUS/><CURRENTREADING/>
//                      <CAUTION/><CRITICAL/></TEMP>...</TEMPERATURE>
//   <POWER_SUPPLIES><SUPPLY><LABEL/><STATUS/></SUPPLY>...</POWER_SUPPLIES>
//   <DRIVES><BACKPLANE><DRIVE BAY="1"/><PRODUCT ID=".."/><DRIVE_STATUS VALUE=".."/>
//   <HEALTH_AT_A_GLANCE><FANS STATUS= "Ok"/><FANS REDUNDANCY= "..."/>...
//   <GET_POWER_READINGS><PRESENT_POWER_READING VALUE="141" UNIT="Watts"/>...
#pragma once

#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

namespace ilo2 {

struct HealthFan    { std::string label, zone, status; int speed_pct = -1; };
struct HealthTemp   { std::string label, location, status; int reading = -1, caution = -1, critical = -1; };
struct HealthSupply { std::string label, status; };
struct HealthDrive  { int bay = 0; std::string product, status; };
struct HealthGlance {
    std::string fans, fan_redundancy, temperature, vrm, supplies, supply_redundancy, drives;
};
struct HealthData {
    bool valid = false;             // the closing GET_EMBEDDED_HEALTH_DATA tag was seen
    std::vector<HealthFan>    fans;
    std::vector<HealthTemp>   temps;
    std::vector<HealthSupply> supplies;
    std::vector<HealthDrive>  drives;
    HealthGlance              glance;
};
struct PowerReadings {
    bool valid = false;
    int present = -1, average = -1, maximum = -1, minimum = -1;   // watts
};

// ---- tag scanner ------------------------------------------------------------

struct XmlTag {
    std::string name;
    bool closing = false;                                   // </NAME>
    std::vector<std::pair<std::string, std::string>> attrs;
    const std::string* attr(const char* key) const {
        for (const auto& a : attrs) if (a.first == key) return &a.second;
        return nullptr;
    }
    std::string value(const char* key) const {
        const std::string* v = attr(key);
        return v ? *v : std::string();
    }
};

// Advance `pos` past the next tag and describe it. Skips <?xml ...?> and
// anything that is not an element. Returns false at end of input.
inline bool xml_next_tag(const std::string& s, size_t& pos, XmlTag& tag) {
    for (;;) {
        const size_t lt = s.find('<', pos);
        if (lt == std::string::npos) { pos = s.size(); return false; }
        const size_t gt = s.find('>', lt);
        if (gt == std::string::npos) { pos = s.size(); return false; }
        pos = gt + 1;
        size_t i = lt + 1;
        if (i < gt && (s[i] == '?' || s[i] == '!')) continue;   // prolog / comment
        tag = XmlTag();
        if (i < gt && s[i] == '/') { tag.closing = true; ++i; }
        auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
        auto is_name  = [&](char c) { return !is_space(c) && c != '=' && c != '/' && c != '>' && c != '"' && c != '\''; };
        while (i < gt && is_name(s[i])) tag.name += s[i++];
        if (tag.name.empty()) continue;
        // attributes: NAME [spaces] = [spaces] "value"
        while (i < gt) {
            while (i < gt && is_space(s[i])) ++i;
            if (i >= gt || s[i] == '/') break;
            std::string key;
            while (i < gt && is_name(s[i])) key += s[i++];
            while (i < gt && is_space(s[i])) ++i;
            if (i >= gt || s[i] != '=') { if (key.empty()) ++i; continue; }
            ++i;
            while (i < gt && is_space(s[i])) ++i;
            if (i >= gt) break;
            const char q = s[i];
            if (q != '"' && q != '\'') continue;
            const size_t end = s.find(q, i + 1);
            if (end == std::string::npos || end > gt) break;
            tag.attrs.emplace_back(key, s.substr(i + 1, end - i - 1));
            i = end + 1;
        }
        return true;
    }
}

// "n/a" (and anything else non-numeric) -> -1.
inline int health_int(const std::string& v) {
    if (v.empty() || v == "n/a" || v == "N/A") return -1;
    char* end = nullptr;
    const long n = std::strtol(v.c_str(), &end, 10);
    return end == v.c_str() ? -1 : static_cast<int>(n);
}

// ---- parsers ----------------------------------------------------------------

inline HealthData parse_embedded_health(const std::string& xml) {
    HealthData h;
    enum Section { None, Fans, Temps, Supplies, Drives, Glance } sec = None;
    size_t pos = 0;
    XmlTag t;
    while (xml_next_tag(xml, pos, t)) {
        if (t.closing) {
            if (t.name == "GET_EMBEDDED_HEALTH_DATA") h.valid = true;
            if (t.name == "FANS" || t.name == "TEMPERATURE" || t.name == "POWER_SUPPLIES" ||
                t.name == "DRIVES" || t.name == "HEALTH_AT_A_GLANCE") sec = None;
            continue;
        }
        if (sec == None) {
            if      (t.name == "FANS")               sec = Fans;
            else if (t.name == "TEMPERATURE")        sec = Temps;
            else if (t.name == "POWER_SUPPLIES")     sec = Supplies;
            else if (t.name == "DRIVES")             sec = Drives;
            else if (t.name == "HEALTH_AT_A_GLANCE") sec = Glance;
            continue;
        }
        const std::string v = t.value("VALUE");
        switch (sec) {
            case Fans:
                if      (t.name == "FAN")    h.fans.emplace_back();
                else if (h.fans.empty())     break;
                else if (t.name == "LABEL")  h.fans.back().label  = v;
                else if (t.name == "ZONE")   h.fans.back().zone   = v;
                else if (t.name == "STATUS") h.fans.back().status = v;
                else if (t.name == "SPEED")  h.fans.back().speed_pct = health_int(v);
                break;
            case Temps:
                if      (t.name == "TEMP")           h.temps.emplace_back();
                else if (h.temps.empty())            break;
                else if (t.name == "LABEL")          h.temps.back().label    = v;
                else if (t.name == "LOCATION")       h.temps.back().location = v;
                else if (t.name == "STATUS")         h.temps.back().status   = v;
                else if (t.name == "CURRENTREADING") h.temps.back().reading  = health_int(v);
                else if (t.name == "CAUTION")        h.temps.back().caution  = health_int(v);
                else if (t.name == "CRITICAL")       h.temps.back().critical = health_int(v);
                break;
            case Supplies:
                if      (t.name == "SUPPLY") h.supplies.emplace_back();
                else if (h.supplies.empty()) break;
                else if (t.name == "LABEL")  h.supplies.back().label  = v;
                else if (t.name == "STATUS") h.supplies.back().status = v;
                break;
            case Drives:
                // <DRIVE BAY="n"/> is self-closing; its details follow as siblings.
                if      (t.name == "DRIVE")        { h.drives.emplace_back(); h.drives.back().bay = health_int(t.value("BAY")); }
                else if (h.drives.empty())         break;
                else if (t.name == "PRODUCT")      h.drives.back().product = t.value("ID");
                else if (t.name == "DRIVE_STATUS") h.drives.back().status  = v;
                break;
            case Glance: {
                const std::string st = t.value("STATUS"), red = t.value("REDUNDANCY");
                if (t.name == "FANS")           { if (!st.empty()) h.glance.fans = st;     if (!red.empty()) h.glance.fan_redundancy = red; }
                if (t.name == "TEMPERATURE")    { if (!st.empty()) h.glance.temperature = st; }
                if (t.name == "VRM")            { if (!st.empty()) h.glance.vrm = st; }
                if (t.name == "POWER_SUPPLIES") { if (!st.empty()) h.glance.supplies = st; if (!red.empty()) h.glance.supply_redundancy = red; }
                if (t.name == "DRIVE")          { if (!st.empty()) h.glance.drives = st; }
                break;
            }
            case None: break;
        }
    }
    return h;
}

inline PowerReadings parse_power_readings(const std::string& xml) {
    PowerReadings p;
    size_t pos = 0;
    XmlTag t;
    while (xml_next_tag(xml, pos, t)) {
        if (t.closing) { if (t.name == "GET_POWER_READINGS") p.valid = true; continue; }
        const int v = health_int(t.value("VALUE"));
        if      (t.name == "PRESENT_POWER_READING") p.present = v;
        else if (t.name == "AVERAGE_POWER_READING") p.average = v;
        else if (t.name == "MAXIMUM_POWER_READING") p.maximum = v;
        else if (t.name == "MINIMUM_POWER_READING") p.minimum = v;
    }
    return p;
}

// Hottest sensor with a reading, or nullptr.
inline const HealthTemp* hottest(const HealthData& h) {
    const HealthTemp* best = nullptr;
    for (const auto& t : h.temps)
        if (t.reading >= 0 && (!best || t.reading > best->reading)) best = &t;
    return best;
}

// True when every at-a-glance status the firmware reported is "Ok".
inline bool health_all_ok(const HealthGlance& g) {
    for (const std::string* s : { &g.fans, &g.temperature, &g.vrm, &g.supplies, &g.drives })
        if (!s->empty() && *s != "Ok") return false;
    return true;
}

} // namespace ilo2
