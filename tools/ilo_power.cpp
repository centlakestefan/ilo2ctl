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

#include "ilo/ilo_session.hpp"
#include "ilo/ribcl.hpp"

using namespace ilo2;

int main(int argc, char** argv) {
    std::string host, user = "Administrator", pass, action = "status";
    bool raw = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto next = [&]() -> std::string { return (i + 1 < argc) ? argv[++i] : std::string(); };
        if      (a == "--host") host = next();
        else if (a == "--user") user = next();
        else if (a == "--pass") pass = next();
        else if (a == "--raw")  raw = true;
        else                    action = a;
    }
    if (host.empty()) {
        std::fprintf(stderr, "usage: ilo_power --host H [--user U] [--pass P] [--raw] "
                             "status|on|off|force-off|reset|cold-boot|uid-on|uid-off\n");
        return 2;
    }
    pass = read_ilo_password(pass);
    if (pass.empty()) { std::fprintf(stderr, "no password (--pass, ILO_PASS or .ilo_pass)\n"); return 2; }

    RibclCommand cmd;
    if      (action == "status")    cmd = RibclCommand::GetPowerStatus;
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
    return reply.ok ? 0 : 1;
}
