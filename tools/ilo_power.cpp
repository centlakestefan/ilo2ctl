// ilo_power.cpp — RIBCL server control from the command line.
//
// The C++ replacement for ilo_power.py: same raw-RIBCL-over-TLS dialect, no
// Python, no OpenSSL, and the same code path the GUI's power buttons use.
//
//   ilo_power --host 192.0.2.10 [--user U] [--pass P] <action>
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
    std::string host, user = "Administrator", pass, action = "status", body, value;
    std::string body_wrapper = "SERVER_INFO";
    bool raw = false, have_action = false;
    RibclArgs args;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host")   host = next();
        else if (a == "--user")   user = next();
        else if (a == "--pass")   pass = next();
        else if (a == "--raw")    raw = true;
        else if (a == "--device") args.device = next();   // CDROM (default) or FLOPPY
        else if (a == "--body")   body = next();          // arbitrary body, for probing
        else if (a == "--body-wrapper") body_wrapper = next();
        else if (!have_action)  { action = a; have_action = true; }
        else                      value = a;              // the one positional argument
    }
    if (host.empty()) {
        std::fprintf(stderr,
            "usage: ilo_power --host H [--user U] [--pass P] [--raw] [--device CDROM|FLOPPY] <action>\n"
            "\n"
            "  reads   status | health | power | fw | vm-status | one-time-boot\n"
            "  power   on | off | force-off | reset | cold-boot | uid-on | uid-off\n"
            "  media   vm-insert <url> | vm-eject | vm-boot <BOOT_ONCE|BOOT_ALWAYS|NO_BOOT|CONNECT|DISCONNECT>\n"
            "  boot    set-one-time-boot <CDROM|FLOPPY|HDD|NETWORK|NORMAL>\n"
            "\n"
            "  ilo_power --host H --body '<GET_.../>' [--body-wrapper RIB_INFO]   (raw probe)\n"
            "\n"
            "Note: vm-insert only records the URL. The firmware does not fetch anything\n"
            "until the device is connected, and vm-boot CONNECT sets BOOT_ALWAYS as a\n"
            "side effect -- read vm-status back and set NO_BOOT if no boot was intended.\n");
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
        const std::string wrapped =
            "<" + body_wrapper + " MODE=\"read\">\r\n" + body + "\r\n</" + body_wrapper + ">";
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
    else if (action == "fw")             cmd = RibclCommand::GetFwVersion;
    else if (action == "vm-status")      cmd = RibclCommand::GetVmStatus;
    else if (action == "one-time-boot")  cmd = RibclCommand::GetOneTimeBoot;
    else if (action == "vm-eject")       cmd = RibclCommand::EjectVirtualMedia;
    else if (action == "vm-insert") {
        cmd = RibclCommand::InsertVirtualMedia;
        if (value.empty()) { std::fprintf(stderr, "vm-insert needs an image URL\n"); return 2; }
        args.image_url = value;
    }
    else if (action == "vm-boot") {
        cmd = RibclCommand::SetVmBootOption;
        if (value.empty()) { std::fprintf(stderr, "vm-boot needs a boot option\n"); return 2; }
        args.boot_option = value;
    }
    else if (action == "set-one-time-boot") {
        cmd = RibclCommand::SetOneTimeBoot;
        if (value.empty()) { std::fprintf(stderr, "set-one-time-boot needs a device\n"); return 2; }
        args.boot_device = value;
    }
    else { std::fprintf(stderr, "unknown action %s\n", action.c_str()); return 2; }

    RibclReply reply;
    std::string err;
    if (!ribcl_run(host, 443, user, pass, cmd, args, reply, err)) {
        std::fprintf(stderr, "%s: %s\n", ribcl_command_name(cmd), err.c_str());
        return 1;
    }
    if (raw) std::fputs(reply.raw.c_str(), stdout);
    std::printf("%s: %s\n", ribcl_command_name(cmd),
                reply.ok ? "ok" : (reply.message.empty() ? "failed" : reply.message.c_str()));
    if (!reply.host_power.empty()) std::printf("HOST_POWER = %s\n", reply.host_power.c_str());

    if (cmd == RibclCommand::GetVmStatus) {
        const VmStatus v = parse_vm_status(reply.raw);
        if (!v.valid) std::printf("  (no GET_VM_STATUS element in the reply)\n");
        else {
            std::printf("  device         : %s\n", v.device.c_str());
            std::printf("  applet         : %s\n", v.vm_applet.c_str());
            std::printf("  boot option    : %s\n", v.boot_option.c_str());
            std::printf("  write protect  : %s\n", v.write_protect ? "yes" : "no");
            std::printf("  image inserted : %s\n", v.image_inserted ? "yes" : "no");
            std::printf("  image url      : %s\n",
                        v.image_url.empty() ? "(none)" : v.image_url.c_str());
        }
    }

    if (cmd == RibclCommand::GetFwVersion) {
        const FwInfo f = parse_fw_version(reply.raw);
        if (!f.valid) std::printf("  (no GET_FW_VERSION element in the reply)\n");
        else {
            std::printf("  firmware  : %s (%s)\n", f.firmware_version.c_str(), f.firmware_date.c_str());
            std::printf("  processor : %s\n", f.management_processor.c_str());
            std::printf("  licence   : %s\n", f.license_type.c_str());
            std::printf("  scripted virtual media: %s\n",
                        vm_scripting_licensed(f) ? "licensed"
                                                 : "NOT licensed (needs iLO 2 Advanced)");
        }
    }

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
