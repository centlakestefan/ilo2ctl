// test_ribcl.cpp — RIBCL document construction, reply parsing, and the
// two-write framing an iLO 2 requires, driven through a fake client so no
// TLS and no hardware are involved.
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "ilo/ribcl.hpp"

using namespace ilo2;

static int failures = 0;
#define CHECK(cond) do { if (!(cond)) { \
    std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond); ++failures; } } while (0)

// A stand-in for tls::Client: records each send() as a separate write and
// hands back scripted chunks from recv().
struct FakeClient {
    std::vector<std::string> writes;
    std::vector<std::string> replies;
    size_t next = 0;
    bool   fail_send = false;
    bool   eof_after = true;      // end with EOF (true) or a timeout error (false)

    bool send(const std::string& s, std::string& err) {
        if (fail_send) { err = "send failed"; return false; }
        writes.push_back(s);
        return true;
    }
    bool recv(std::vector<uint8_t>& out, bool& eof, std::string& err) {
        if (next < replies.size()) {
            const std::string& r = replies[next++];
            out.assign(r.begin(), r.end());
            eof = false;
            return true;
        }
        eof = eof_after;
        if (!eof) err = "recv timed out";
        return false;
    }
};

// One acknowledgement document, as firmware 2.29 emits it for every tag it
// parses. A reply is a run of these; a status read carries HOST_POWER in the
// command's own (fifth) one.
#define PLAIN_DOC "<?xml version=\"1.0\"?>\r\n<RIBCL VERSION=\"2.22\">\r\n<RESPONSE\r\n    STATUS=\"0x0000\"\r\n    MESSAGE='No error'\r\n     />\r\n</RIBCL>\r\n"

static const char* STATUS_REPLY =
    PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC
    "<?xml version=\"1.0\"?>\r\n<RIBCL VERSION=\"2.22\">\r\n<RESPONSE\r\n    STATUS=\"0x0000\"\r\n    MESSAGE='No error'\r\n     />\r\n"
    "<GET_HOST_POWER\r\n    HOST_POWER=\"ON\"\r\n    />\r\n</RIBCL>\r\n";

static const char* WRITE_REPLY =
    PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC PLAIN_DOC;

static const char* LOGIN_FAIL_REPLY =
    "<?xml version=\"1.0\"?>\r\n"
    "<RIBCL VERSION=\"2.22\">\r\n<RESPONSE\r\n    STATUS=\"0x005F\"\r\n"
    "    MESSAGE='Login failed.'\r\n     />\r\n</RIBCL>\r\n";

static std::string slurp(const char* path) {
    std::FILE* f = std::fopen(path, "rb");
    if (!f) return {};
    std::string s;
    char buf[4096];
    size_t n;
    while ((n = std::fread(buf, 1, sizeof buf, f)) > 0) s.append(buf, n);
    std::fclose(f);
    return s;
}

int main() {
    std::printf("[command bodies]\n");
    {
        CHECK(ribcl_body(RibclCommand::GetPowerStatus).find("MODE=\"read\"") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::GetPowerStatus).find("<GET_HOST_POWER_STATUS/>") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::PowerOn).find("MODE=\"write\"") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::PowerOn).find("HOST_POWER=\"Yes\"") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::PowerOff).find("HOST_POWER=\"No\"") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::ForcePowerOff).find("<HOLD_PWR_BTN/>") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::Reset).find("<RESET_SERVER/>") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::ColdBoot).find("<COLD_BOOT_SERVER/>") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::UidOn).find("UID=\"Yes\"") != std::string::npos);
        CHECK(!ribcl_is_write(RibclCommand::GetPowerStatus));
        CHECK(ribcl_is_write(RibclCommand::Reset));
    }

    std::printf("[wrappers: virtual media is RIB_INFO, not SERVER_INFO]\n");
    {
        // The whole point of the rework. Sending GET_VM_STATUS inside
        // SERVER_INFO is answered with a syntax error after four "No error"
        // stages (testdata/README.md records it verbatim), so the wrapper is
        // asserted per command rather than assumed.
        CHECK(std::string(ribcl_wrapper(RibclCommand::GetPowerStatus))     == "SERVER_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::GetOneTimeBoot))     == "SERVER_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::SetOneTimeBoot))     == "SERVER_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::GetVmStatus))        == "RIB_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::GetFwVersion))       == "RIB_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::InsertVirtualMedia)) == "RIB_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::EjectVirtualMedia))  == "RIB_INFO");
        CHECK(std::string(ribcl_wrapper(RibclCommand::SetVmBootOption))    == "RIB_INFO");

        // ... and the body must actually carry it, opened and closed.
        const std::string vm = ribcl_body(RibclCommand::GetVmStatus);
        CHECK(vm.find("<RIB_INFO MODE=\"read\">") != std::string::npos);
        CHECK(vm.find("</RIB_INFO>") != std::string::npos);
        CHECK(vm.find("SERVER_INFO") == std::string::npos);

        const std::string pw = ribcl_body(RibclCommand::GetPowerStatus);
        CHECK(pw.find("<SERVER_INFO MODE=\"read\">") != std::string::npos);
        CHECK(pw.find("RIB_INFO") == std::string::npos);

        // Reads must not take a write lock; writes must not go out as reads.
        CHECK(!ribcl_is_write(RibclCommand::GetVmStatus));
        CHECK(!ribcl_is_write(RibclCommand::GetFwVersion));
        CHECK(!ribcl_is_write(RibclCommand::GetOneTimeBoot));
        CHECK(ribcl_is_write(RibclCommand::InsertVirtualMedia));
        CHECK(ribcl_is_write(RibclCommand::EjectVirtualMedia));
        CHECK(ribcl_is_write(RibclCommand::SetVmBootOption));
        CHECK(ribcl_is_write(RibclCommand::SetOneTimeBoot));
    }

    std::printf("[virtual-media command bodies]\n");
    {
        RibclArgs a;
        a.image_url = "http://198.51.100.20:8080/win2022.iso";
        const std::string ins = ribcl_body(RibclCommand::InsertVirtualMedia, a);
        CHECK(ins.find("<INSERT_VIRTUAL_MEDIA DEVICE=\"CDROM\"") != std::string::npos);
        CHECK(ins.find("IMAGE_URL=\"http://198.51.100.20:8080/win2022.iso\"") != std::string::npos);
        CHECK(ins.find("MODE=\"write\"") != std::string::npos);

        // A URL with a query string must survive as an attribute value.
        RibclArgs q;
        q.image_url = "http://h/i.iso?a=1&b=2";
        const std::string qs = ribcl_body(RibclCommand::InsertVirtualMedia, q);
        CHECK(qs.find("a=1&amp;b=2") != std::string::npos);
        CHECK(qs.find("a=1&b=2") == std::string::npos);

        // Device defaults to CDROM but is honoured when given.
        RibclArgs f; f.device = "FLOPPY";
        CHECK(ribcl_body(RibclCommand::GetVmStatus, f).find("DEVICE=\"FLOPPY\"") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::GetVmStatus).find("DEVICE=\"CDROM\"") != std::string::npos);

        // SET_VM_STATUS nests a child element rather than taking an attribute.
        RibclArgs b; b.boot_option = "BOOT_ONCE";
        const std::string sb = ribcl_body(RibclCommand::SetVmBootOption, b);
        CHECK(sb.find("<SET_VM_STATUS DEVICE=\"CDROM\">") != std::string::npos);
        CHECK(sb.find("<VM_BOOT_OPTION VALUE=\"BOOT_ONCE\"/>") != std::string::npos);
        CHECK(sb.find("</SET_VM_STATUS>") != std::string::npos);
        // Defaulting must be the harmless option, never a boot.
        CHECK(ribcl_body(RibclCommand::SetVmBootOption).find("VALUE=\"NO_BOOT\"") != std::string::npos);

        // Lower-case `value` is what the firmware accepts; see ribcl.hpp.
        RibclArgs o; o.boot_device = "CDROM";
        CHECK(ribcl_body(RibclCommand::SetOneTimeBoot, o).find("<SET_ONE_TIME_BOOT value=\"CDROM\"/>") != std::string::npos);
        CHECK(ribcl_body(RibclCommand::SetOneTimeBoot).find("value=\"NORMAL\"") != std::string::npos);

        CHECK(ribcl_body(RibclCommand::EjectVirtualMedia).find("<EJECT_VIRTUAL_MEDIA DEVICE=\"CDROM\"/>") != std::string::npos);
    }

    std::printf("[parsing real captured replies]\n");
    {
        // The fixtures are whole replies as fw 2.29 sent them, envelope and all.
        const std::string cd = slurp("testdata/vm_status_cdrom.xml");
        CHECK(!cd.empty());
        const VmStatus v = parse_vm_status(cd);
        CHECK(v.valid);
        CHECK(v.device == "CDROM");
        CHECK(v.vm_applet == "DISCONNECTED");
        CHECK(v.boot_option == "NO_BOOT");
        CHECK(v.write_protect);
        CHECK(!v.image_inserted);
        CHECK(v.image_url.empty());

        // WRITE_PROTECT genuinely differs by device out of the box, so this
        // is not a copy of the case above.
        const std::string fl = slurp("testdata/vm_status_floppy.xml");
        CHECK(!fl.empty());
        const VmStatus w = parse_vm_status(fl);
        CHECK(w.valid);
        CHECK(w.device == "FLOPPY");
        CHECK(!w.write_protect);

        const std::string fw = slurp("testdata/fw_version.xml");
        CHECK(!fw.empty());
        const FwInfo i = parse_fw_version(fw);
        CHECK(i.valid);
        CHECK(i.firmware_version == "2.29");
        CHECK(i.management_processor == "iLO2");
        CHECK(i.license_type == "iLO 2 Advanced");
        CHECK(vm_scripting_licensed(i));

        // A base-licence iLO must not be offered scripted virtual media.
        FwInfo base; base.valid = true; base.firmware_version = "2.29";
        base.license_type = "iLO 2 Standard";
        CHECK(!vm_scripting_licensed(base));
        CHECK(!vm_scripting_licensed(FwInfo{}));

        // Junk in, no crash and nothing claimed.
        CHECK(!parse_vm_status("").valid);
        CHECK(!parse_vm_status("<GET_VM_STATUS").valid);      // no terminator
        CHECK(!parse_fw_version("nonsense").valid);
    }

    std::printf("[document]\n");
    {
        const std::string d = ribcl_document("Administrator", "s3cret", "<X/>");
        CHECK(d.rfind("<RIBCL VERSION=\"2.0\">\r\n", 0) == 0);
        CHECK(d.find("<LOGIN USER_LOGIN=\"Administrator\" PASSWORD=\"s3cret\">\r\n<X/>\r\n</LOGIN>") != std::string::npos);
        CHECK(d.find("</RIBCL>\r\n") == d.size() - 10);
        // Characters that would break the XML are escaped, so a password with
        // a quote or ampersand still logs in rather than producing a syntax error.
        const std::string e = ribcl_document("u", "a\"b&c<d", "");
        CHECK(e.find("PASSWORD=\"a&quot;b&amp;c&lt;d\"") != std::string::npos);
    }

    std::printf("[reply parsing]\n");
    {
        const RibclReply r = ribcl_parse(STATUS_REPLY);
        CHECK(r.ok);
        CHECK(r.message.empty());
        CHECK(r.host_power == "ON");

        const RibclReply w = ribcl_parse(WRITE_REPLY);
        CHECK(w.ok);
        CHECK(w.host_power.empty());

        const RibclReply f = ribcl_parse(LOGIN_FAIL_REPLY);
        CHECK(!f.ok);
        CHECK(f.message == "Login failed.");
        CHECK(f.host_power.empty());

        const RibclReply n = ribcl_parse("");
        CHECK(!n.ok);

        // Mixed: a good login followed by a failed command still fails overall
        // and reports the command's message, not the login's "No error".
        const RibclReply m = ribcl_parse(std::string(STATUS_REPLY) + LOGIN_FAIL_REPLY);
        CHECK(!m.ok);
        CHECK(m.message == "Login failed.");
    }

    std::printf("[framing: prolog is its own write]\n");
    {
        FakeClient c;
        c.replies = { STATUS_REPLY };
        std::string raw, err;
        CHECK(ribcl_exchange(c, "u", "p", ribcl_body(RibclCommand::GetPowerStatus), ribcl_reply_complete, raw, err));
        CHECK(c.writes.size() == 2);
        CHECK(c.writes.size() >= 1 && c.writes[0] == "<?xml version=\"1.0\"?>\r\n");
        CHECK(c.writes.size() >= 2 && c.writes[1].rfind("<RIBCL", 0) == 0);
        CHECK(raw == STATUS_REPLY);
    }

    std::printf("[read termination]\n");
    {
        CHECK(ribcl_reply_complete(STATUS_REPLY));
        CHECK(!ribcl_reply_complete(WRITE_REPLY));
        CHECK(!ribcl_reply_complete(LOGIN_FAIL_REPLY));

        // A status read stops as soon as HOST_POWER arrives, not at EOF.
        FakeClient c;
        c.replies = { std::string(STATUS_REPLY).substr(0, 100), std::string(STATUS_REPLY).substr(100), "TRAILING" };
        std::string raw, err;
        CHECK(ribcl_exchange(c, "u", "p", "", ribcl_reply_complete, raw, err));
        CHECK(raw == STATUS_REPLY);
        CHECK(c.next == 2);

        // A write's reply ends in silence (a receive timeout after data):
        // success, and the data is the reply.
        FakeClient w;
        w.replies = { WRITE_REPLY };
        w.eof_after = false;
        CHECK(ribcl_exchange(w, "u", "p", "", ribcl_reply_complete, raw, err));
        CHECK(raw == WRITE_REPLY);

        // So does a failed login, which is how its message gets back.
        FakeClient t;
        t.replies = { LOGIN_FAIL_REPLY };
        t.eof_after = false;
        CHECK(ribcl_exchange(t, "u", "p", "", ribcl_reply_complete, raw, err));
        CHECK(raw == LOGIN_FAIL_REPLY);

        // Timeout with nothing received at all is a failure.
        FakeClient z;
        z.eof_after = false;
        CHECK(!ribcl_exchange(z, "u", "p", "", ribcl_reply_complete, raw, err));
        CHECK(err == "recv timed out");

        // Clean EOF with nothing received: the exchange itself succeeded and
        // the caller sees an empty reply.
        FakeClient e;
        CHECK(ribcl_exchange(e, "u", "p", "", ribcl_reply_complete, raw, err));
        CHECK(raw.empty());

        FakeClient s;
        s.fail_send = true;
        CHECK(!ribcl_exchange(s, "u", "p", "", ribcl_reply_complete, raw, err));
    }

    if (failures) { std::printf("%d FAILURE(S)\n", failures); return 1; }
    std::printf("all checks passed\n");
    return 0;
}
