// ilo_power.cpp — RIBCL server control from the command line.
//
// The C++ replacement for ilo_power.py: same raw-RIBCL-over-TLS dialect, no
// Python, no OpenSSL, and the same code path the GUI's power buttons use.
//
//   ilo_power --host 10.10.123.130 [--user U] [--pass P] <action>
//
// Actions: status (default) | on | off | force-off | reset | cold-boot |
//          uid-on | uid-off. Password from --pass, ILO_PASS, or .ilo_pass.
#include <cstdio>
#include <cstring>
#include <string>

#include "ilo/health.hpp"
#include "ilo/ilo_session.hpp"
#include "ilo/ribcl.hpp"

using namespace ilo2;

int main(int argc, char** argv) {
    std::string host, user = "Administrator", pass, action = "status", body;
    bool raw = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host") host = next();
        else if (a == "--user") user = next();
        else if (a == "--pass") pass = next();
        else if (a == "--raw")  raw = true;
        else if (a == "--body") body = next();     // arbitrary SERVER_INFO body, for probing
        else                    action = a;
    }
    if (host.empty()) {
        std::fprintf(stderr, "usage: ilo_power --host H [--user U] [--pass P] [--raw] "
                             "status|health|power|on|off|force-off|reset|cold-boot|uid-on|uid-off\n"
                             "       ilo_power --host H --body '<GET_.../>'   (any SERVER_INFO read, raw reply)\n");
        return 2;
    }
    pass = read_ilo_password(pass);
    if (pass.empty()) { std::fprintf(stderr, "no password (--pass, ILO_PASS or .ilo_pass)\n"); return 2; }

    if (!body.empty()) {
        tls::Client::Options o;
        o.timeout_ms = 8000;
        tls::Client c(o);
        std::string err;
        if (!c.connect(host, 443, err)) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
        c.transport().set_recv_timeout(1500);
        std::string out;
        const std::string wrapped = "<SERVER_INFO MODE=\"read\">\r\n" + body + "\r\n</SERVER_INFO>";
        const bool ok = ribcl_exchange(c, user, pass, wrapped, [](const std::string&) { return false; }, out, err);
        c.close();
        if (!ok) { std::fprintf(stderr, "%s\n", err.c_str()); return 1; }
        std::fputs(out.c_str(), stdout);
        return 0;
    }

    RibclCommand cmd;
    if      (action == "status")    cmd = RibclCommand::GetPowerStatus;
    else if (action == "health")    cmd = RibclCommand::GetEmbeddedHealth;
    else if (action == "power")     cmd = RibclCommand::GetPowerReadings;
    else if (action == "on")        cmd = RibclCommand::PowerOn;
    else if (action == "off")       cmd = RibclCommand::PowerOff;
    else if (action == "force-off") cmd = RibclCommand::ForcePowerOff;
    else if (action == "reset")     cmd = RibclCommand::Reset;
    else if (action == "cold-boot") cmd = RibclCommand::ColdBoot;
    else if (action == "uid-on")    cmd = RibclCommand::UidOn;
    else if (action == "uid-off")   cmd = RibclCommand::UidOff;
    else { std::fprintf(stderr, "unknown action %s\n", action.c_str()); return 2; }

    RibclReply reply;
    std::string err;
    if (!ribcl_run(host, 443, user, pass, cmd, reply, err)) {
        std::fprintf(stderr, "%s: %s\n", ribcl_command_name(cmd), err.c_str());
        return 1;
    }
    if (raw) std::fputs(reply.raw.c_str(), stdout);
    std::printf("%s: %s\n", ribcl_command_name(cmd),
                reply.ok ? "ok" : (reply.message.empty() ? "failed" : reply.message.c_str()));
    if (!reply.host_power.empty()) std::printf("HOST_POWER = %s\n", reply.host_power.c_str());

    if (cmd == RibclCommand::GetEmbeddedHealth) {
        const HealthData h = parse_embedded_health(reply.raw);
        if (!h.valid) { std::printf("(no health report in reply)\n"); return 1; }
        std::printf("fans %s (%s), temperature %s, VRM %s, power supplies %s (%s), drives %s\n",
                    h.glance.fans.c_str(), h.glance.fan_redundancy.c_str(),
                    h.glance.temperature.c_str(), h.glance.vrm.c_str(),
                    h.glance.supplies.c_str(), h.glance.supply_redundancy.c_str(),
                    h.glance.drives.c_str());
        for (const auto& f : h.fans)
            std::printf("  %-16s %-8s %3d%%  %s\n", f.label.c_str(), f.zone.c_str(), f.speed_pct, f.status.c_str());
        for (const auto& t : h.temps) {
            if (t.reading < 0) continue;
            std::printf("  %-8s %-14s %3d C  (caution %d, critical %d)  %s\n", t.label.c_str(),
                        t.location.c_str(), t.reading, t.caution, t.critical, t.status.c_str());
        }
        for (const auto& s : h.supplies)
            std::printf("  %-16s %s\n", s.label.c_str(), s.status.c_str());
        for (const auto& d : h.drives)
            std::printf("  bay %d  %-18s %s\n", d.bay, d.product.c_str(), d.status.c_str());
    }
    if (cmd == RibclCommand::GetPowerReadings) {
        const PowerReadings p = parse_power_readings(reply.raw);
        if (!p.valid) { std::printf("(no power readings in reply)\n"); return 1; }
        std::printf("present %d W, average %d W, max %d W, min %d W\n",
                    p.present, p.average, p.maximum, p.minimum);
    }
    return reply.ok ? 0 : 1;
}
