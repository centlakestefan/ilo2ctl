// ribcl.hpp — RIBCL over raw TLS, the way an iLO 2 actually speaks it.
//
// iLO 3 and later accept RIBCL as an HTTP POST to /ribcl. iLO 2 404s that URL
// and instead reads the XML straight off a TLS socket on port 443, with no
// HTTP framing at all. Two quirks of that dialect are encoded here rather than
// left for the next person to rediscover:
//
//   * The XML declaration must be its own write. The firmware parses it as a
//     complete document, acknowledges it, and only then expects <RIBCL>. Both
//     in one write yields `syntax error near "?>"`.
//   * The firmware does not close the connection when the reply is complete,
//     so a reader has to stop on its own: on a marker it was told to expect,
//     or on the receive timeout.
//
// The exchange is templated on the TLS client so the framing above can be
// tested against a scripted transport; the tls::Client instantiation is what
// the GUI and tools use.
#pragma once

#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <thread>
#include <vector>

#include "tls/client.hpp"

namespace ilo2 {

// Attribute-value escaping: a password containing a quote or an ampersand
// must still log in rather than turn into an XML syntax error.
inline std::string xml_attr_escape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (char ch : in) {
        switch (ch) {
            case '&':  out += "&amp;";  break;
            case '<':  out += "&lt;";   break;
            case '>':  out += "&gt;";   break;
            case '"':  out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:   out += ch;       break;
        }
    }
    return out;
}

// The commands worth a button.
//
// Two things vary per command and neither is guessable, so both are spelled
// out below rather than inferred: the wrapper element and the mode.
//
//   * Power, health and boot-order commands sit inside <SERVER_INFO>; virtual
//     media and firmware queries sit inside <RIB_INFO>. Using the wrong one is
//     not a soft failure -- the firmware answers four cheerful "No error"
//     stages and only then a syntax error, so a caller that merely checks it
//     got a reply will read the whole thing as success.
//   * MODE is "read" or "write". A read command in write mode is accepted but
//     needlessly takes a write lock; a write command in read mode is rejected.
//
// Verified against firmware 2.29. See testdata/README.md, which records the
// GET_VM_STATUS-under-SERVER_INFO failure verbatim.
enum class RibclCommand {
    // ---- SERVER_INFO, read ----
    GetPowerStatus,     // GET_HOST_POWER_STATUS
    GetEmbeddedHealth,  // GET_EMBEDDED_HEALTH   (fans, temps, PSUs, drives)
    GetPowerReadings,   // GET_POWER_READINGS    (watts: present/avg/max/min)
    GetOneTimeBoot,     // GET_ONE_TIME_BOOT
    // ---- RIB_INFO, read ----
    GetVmStatus,        // GET_VM_STATUS         (args.device)
    GetFwVersion,       // GET_FW_VERSION        (also carries LICENSE_TYPE)
    // ---- SERVER_INFO, write ----
    PowerOn,            // SET_HOST_POWER Yes  (momentary press: no-op if on)
    PowerOff,           // SET_HOST_POWER No   (momentary press: OS shutdown)
    ForcePowerOff,      // HOLD_PWR_BTN        (hard off)
    Reset,              // RESET_SERVER        (hard reset)
    ColdBoot,           // COLD_BOOT_SERVER    (power cycle)
    UidOn,              // UID_CONTROL Yes
    UidOff,             // UID_CONTROL No
    SetOneTimeBoot,     // SET_ONE_TIME_BOOT     (args.boot_device)
    // ---- RIB_INFO, write ----
    InsertVirtualMedia, // INSERT_VIRTUAL_MEDIA  (args.device, args.image_url)
    EjectVirtualMedia,  // EJECT_VIRTUAL_MEDIA   (args.device)
    SetVmBootOption,    // SET_VM_STATUS         (args.device, args.boot_option)
};

// Everything a command might need beyond its own name. Defaulted, so the
// commands that take no arguments are still called as ribcl_body(cmd).
struct RibclArgs {
    std::string device;       // "CDROM" (default) or "FLOPPY"
    std::string image_url;    // InsertVirtualMedia
    std::string boot_option;  // SetVmBootOption: BOOT_ONCE | BOOT_ALWAYS | NO_BOOT | CONNECT | DISCONNECT
    std::string boot_device;  // SetOneTimeBoot:  CDROM | FLOPPY | HDD | NETWORK | NORMAL
};

inline bool ribcl_is_write(RibclCommand c) {
    switch (c) {
        case RibclCommand::GetPowerStatus:
        case RibclCommand::GetEmbeddedHealth:
        case RibclCommand::GetPowerReadings:
        case RibclCommand::GetOneTimeBoot:
        case RibclCommand::GetVmStatus:
        case RibclCommand::GetFwVersion:
            return false;
        default:
            return true;
    }
}

// SERVER_INFO or RIB_INFO. Getting this wrong fails in the misleading way
// described above, so it is a lookup rather than a rule of thumb.
inline const char* ribcl_wrapper(RibclCommand c) {
    switch (c) {
        case RibclCommand::GetVmStatus:
        case RibclCommand::GetFwVersion:
        case RibclCommand::InsertVirtualMedia:
        case RibclCommand::EjectVirtualMedia:
        case RibclCommand::SetVmBootOption:
            return "RIB_INFO";
        default:
            return "SERVER_INFO";
    }
}

inline const char* ribcl_command_name(RibclCommand c) {
    switch (c) {
        case RibclCommand::GetPowerStatus:    return "power status";
        case RibclCommand::GetEmbeddedHealth: return "health";
        case RibclCommand::GetPowerReadings:  return "power readings";
        case RibclCommand::GetOneTimeBoot:    return "one-time boot";
        case RibclCommand::GetVmStatus:       return "virtual media status";
        case RibclCommand::GetFwVersion:      return "firmware version";
        case RibclCommand::PowerOn:        return "power on";
        case RibclCommand::PowerOff:       return "power off";
        case RibclCommand::ForcePowerOff:  return "force power off";
        case RibclCommand::Reset:          return "reset";
        case RibclCommand::ColdBoot:       return "cold boot";
        case RibclCommand::UidOn:          return "UID on";
        case RibclCommand::UidOff:         return "UID off";
        case RibclCommand::SetOneTimeBoot: return "set one-time boot";
        case RibclCommand::InsertVirtualMedia: return "insert virtual media";
        case RibclCommand::EjectVirtualMedia:  return "eject virtual media";
        case RibclCommand::SetVmBootOption:    return "set virtual media boot option";
    }
    return "?";
}

// The body that goes inside <LOGIN>.
inline std::string ribcl_body(RibclCommand c, const RibclArgs& args = {}) {
    const std::string device = args.device.empty() ? "CDROM" : args.device;
    std::string inner;
    switch (c) {
        case RibclCommand::GetPowerStatus:    inner = "<GET_HOST_POWER_STATUS/>";     break;
        case RibclCommand::GetEmbeddedHealth: inner = "<GET_EMBEDDED_HEALTH/>";       break;
        case RibclCommand::GetPowerReadings:  inner = "<GET_POWER_READINGS/>";        break;
        case RibclCommand::GetOneTimeBoot:    inner = "<GET_ONE_TIME_BOOT/>";         break;
        case RibclCommand::GetFwVersion:      inner = "<GET_FW_VERSION/>";            break;
        case RibclCommand::PowerOn:        inner = "<SET_HOST_POWER HOST_POWER=\"Yes\"/>"; break;
        case RibclCommand::PowerOff:       inner = "<SET_HOST_POWER HOST_POWER=\"No\"/>";  break;
        case RibclCommand::ForcePowerOff:  inner = "<HOLD_PWR_BTN/>";                 break;
        case RibclCommand::Reset:          inner = "<RESET_SERVER/>";                 break;
        case RibclCommand::ColdBoot:       inner = "<COLD_BOOT_SERVER/>";             break;
        case RibclCommand::UidOn:          inner = "<UID_CONTROL UID=\"Yes\"/>";      break;
        case RibclCommand::UidOff:         inner = "<UID_CONTROL UID=\"No\"/>";       break;

        case RibclCommand::GetVmStatus:
            inner = "<GET_VM_STATUS DEVICE=\"" + xml_attr_escape(device) + "\"/>";
            break;
        // IMAGE_URL is escaped: a query string with an ampersand in it would
        // otherwise end the document early and be reported as a syntax error
        // somewhere unrelated.
        case RibclCommand::InsertVirtualMedia:
            inner = "<INSERT_VIRTUAL_MEDIA DEVICE=\"" + xml_attr_escape(device) +
                    "\" IMAGE_URL=\"" + xml_attr_escape(args.image_url) + "\"/>";
            break;
        case RibclCommand::EjectVirtualMedia:
            inner = "<EJECT_VIRTUAL_MEDIA DEVICE=\"" + xml_attr_escape(device) + "\"/>";
            break;
        // SET_VM_STATUS wraps a child element rather than taking an attribute.
        case RibclCommand::SetVmBootOption:
            inner = "<SET_VM_STATUS DEVICE=\"" + xml_attr_escape(device) + "\">\r\n"
                    "<VM_BOOT_OPTION VALUE=\"" +
                    xml_attr_escape(args.boot_option.empty() ? "NO_BOOT" : args.boot_option) +
                    "\"/>\r\n</SET_VM_STATUS>";
            break;
        // Lower-case `value` is not a typo: SET_ONE_TIME_BOOT is spelled that
        // way and was verified against fw 2.29 with the no-op value NORMAL.
        case RibclCommand::SetOneTimeBoot:
            inner = "<SET_ONE_TIME_BOOT value=\"" +
                    xml_attr_escape(args.boot_device.empty() ? "NORMAL" : args.boot_device) +
                    "\"/>";
            break;
    }
    const std::string w = ribcl_wrapper(c);
    return "<" + w + " MODE=\"" + (ribcl_is_write(c) ? "write" : "read") + "\">\r\n" +
           inner + "\r\n</" + w + ">";
}

// The VERSION="2.22" below is the RIBCL schema the firmware speaks, not its
// firmware version (2.29 on the box this was measured against) -- easy to
// confuse, since the schema version is what every reply puts in your face.
//
// The reply is a run of <RIBCL VERSION="2.22"><RESPONSE STATUS="0x0000"
// MESSAGE='No error'/>...</RIBCL> documents, one per stage. What a caller
// wants out of it is whether any stage failed, what it said, and, for a status
// read, the HOST_POWER value.
struct RibclReply {
    std::string raw;
    bool        ok = false;         // every RESPONSE had STATUS 0
    std::string message;            // first non-"No error" MESSAGE, if any
    std::string host_power;         // "ON" / "OFF" when the reply carried one
};

// Attribute scan: `name` [spaces] `=` [spaces] quoted value. RIBCL uses double
// quotes for most attributes and single quotes for MESSAGE, so both are
// accepted. Returns every occurrence, in order.
//
// The spaces are not hypothetical and the firmware is not consistent about
// them: GET_VM_STATUS writes VM_APPLET="DISCONNECTED", while GET_FW_VERSION in
// the same firmware writes FIRMWARE_VERSION = "2.29". Compare
// testdata/vm_status_cdrom.xml with testdata/fw_version.xml.
//
// The name must also start at a boundary, or a search for VERSION would happily
// return FIRMWARE_VERSION's value.
inline std::vector<std::string> ribcl_attr_values(const std::string& doc, const std::string& name) {
    auto is_space = [](char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    auto is_name_char = [](char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
               (c >= '0' && c <= '9') || c == '_' || c == '-';
    };

    std::vector<std::string> out;
    size_t pos = 0;
    while ((pos = doc.find(name, pos)) != std::string::npos) {
        const size_t start = pos;
        pos += name.size();
        // Must not be the tail of a longer attribute name, nor have more name
        // characters after it.
        if (start > 0 && is_name_char(doc[start - 1])) continue;
        if (pos < doc.size() && is_name_char(doc[pos])) continue;

        size_t i = pos;
        while (i < doc.size() && is_space(doc[i])) ++i;
        if (i >= doc.size() || doc[i] != '=') continue;
        ++i;
        while (i < doc.size() && is_space(doc[i])) ++i;
        if (i >= doc.size()) break;
        const char q = doc[i];
        if (q != '"' && q != '\'') continue;
        const size_t end = doc.find(q, i + 1);
        if (end == std::string::npos) break;
        out.push_back(doc.substr(i + 1, end - i - 1));
        pos = end + 1;
    }
    return out;
}

inline RibclReply ribcl_parse(const std::string& raw) {
    RibclReply r;
    r.raw = raw;
    const auto statuses = ribcl_attr_values(raw, "STATUS");
    const auto messages = ribcl_attr_values(raw, "MESSAGE");
    r.ok = !statuses.empty();
    for (const auto& s : statuses) {
        if (std::strtoul(s.c_str(), nullptr, 0) != 0) r.ok = false;
    }
    for (const auto& m : messages) {
        if (m != "No error") { r.message = m; break; }
    }
    const auto power = ribcl_attr_values(raw, "HOST_POWER");
    if (!power.empty()) r.host_power = power.back();
    return r;
}

// GET_VM_STATUS, as fw 2.29 answers it (testdata/vm_status_cdrom.xml):
//
//   <GET_VM_STATUS VM_APPLET="DISCONNECTED" DEVICE="CDROM"
//                  BOOT_OPTION="NO_BOOT" WRITE_PROTECT="YES"
//                  IMAGE_INSERTED="NO" IMAGE_URL=""/>
//
// Note what this does *not* tell you: whether the firmware has actually
// fetched anything. An insert sets IMAGE_INSERTED="YES" and records IMAGE_URL
// without contacting the URL at all -- only connecting the device does that.
struct VmStatus {
    bool        valid = false;
    std::string vm_applet;        // "DISCONNECTED" / "CONNECTED"
    std::string device;           // "CDROM" / "FLOPPY"
    std::string boot_option;      // "NO_BOOT" / "BOOT_ONCE" / "BOOT_ALWAYS" / "CONNECT"
    bool        write_protect = false;
    bool        image_inserted = false;
    std::string image_url;
};

// Scope the attribute scan to the GET_VM_STATUS element. The surrounding reply
// is a run of documents whose RESPONSE stages carry their own attributes, so
// scanning the whole thing would pick up the wrong ones.
inline VmStatus parse_vm_status(const std::string& raw) {
    VmStatus s;
    const size_t open = raw.find("<GET_VM_STATUS");
    if (open == std::string::npos) return s;
    const size_t close = raw.find("/>", open);
    if (close == std::string::npos) return s;
    const std::string el = raw.substr(open, close - open);

    auto one = [&](const char* name) -> std::string {
        const auto v = ribcl_attr_values(el, name);
        return v.empty() ? std::string() : v.front();
    };
    s.vm_applet      = one("VM_APPLET");
    s.device         = one("DEVICE");
    s.boot_option    = one("BOOT_OPTION");
    s.image_url      = one("IMAGE_URL");
    s.write_protect  = (one("WRITE_PROTECT") == "YES");
    s.image_inserted = (one("IMAGE_INSERTED") == "YES");
    s.valid          = !s.device.empty();
    return s;
}

// GET_FW_VERSION. LICENSE_TYPE is the interesting field: scripted virtual
// media by IMAGE_URL needs "iLO 2 Advanced", so a front end can check before
// offering it rather than failing at insert time.
struct FwInfo {
    bool        valid = false;
    std::string firmware_version;   // e.g. "2.29"
    std::string firmware_date;
    std::string management_processor;
    std::string license_type;       // e.g. "iLO 2 Advanced"
};

inline FwInfo parse_fw_version(const std::string& raw) {
    FwInfo f;
    const size_t open = raw.find("<GET_FW_VERSION");
    if (open == std::string::npos) return f;
    const size_t close = raw.find("/>", open);
    if (close == std::string::npos) return f;
    const std::string el = raw.substr(open, close - open);

    auto one = [&](const char* name) -> std::string {
        const auto v = ribcl_attr_values(el, name);
        return v.empty() ? std::string() : v.front();
    };
    f.firmware_version     = one("FIRMWARE_VERSION");
    f.firmware_date        = one("FIRMWARE_DATE");
    f.management_processor = one("MANAGEMENT_PROCESSOR");
    f.license_type         = one("LICENSE_TYPE");
    f.valid                = !f.firmware_version.empty();
    return f;
}

// Does this iLO permit scripted virtual media? The base licence does not.
inline bool vm_scripting_licensed(const FwInfo& f) {
    return f.valid && f.license_type.find("Advanced") != std::string::npos;
}

inline std::string ribcl_prolog() { return "<?xml version=\"1.0\"?>\r\n"; }

inline std::string ribcl_document(const std::string& user, const std::string& pass,
                                  const std::string& body) {
    return "<RIBCL VERSION=\"2.0\">\r\n"
           "<LOGIN USER_LOGIN=\"" + xml_attr_escape(user) + "\" PASSWORD=\"" +
           xml_attr_escape(pass) + "\">\r\n" +
           body + "\r\n"
           "</LOGIN>\r\n"
           "</RIBCL>\r\n";
}

// When is a reply over? The firmware answers every tag it parses with its own
// <RIBCL> document -- the prolog, <RIBCL>, <LOGIN>, <SERVER_INFO>, the
// command, the closing tags -- and the count varies by command (measured on
// firmware 2.29: a UID write yields 8, SET_HOST_POWER 9), so counting is not
// reliable. What is reliable is that the documents stream back-to-back and
// the firmware then goes silent without closing. ribcl_run therefore reads
// with a short receive timeout once data has started arriving, and treats
// that silence as the end. The one early exit is a status read: its answer is
// usable the moment HOST_POWER shows up.
inline bool ribcl_reply_complete(const std::string& raw) {
    return raw.find("HOST_POWER=") != std::string::npos ||
           raw.find("</GET_EMBEDDED_HEALTH_DATA>") != std::string::npos ||
           raw.find("</GET_POWER_READINGS>") != std::string::npos ||
           // GET_VM_STATUS and GET_FW_VERSION answer with a single self-closing
           // element, so there is no closing tag to wait for: the last
           // attribute of each is the marker instead.
           raw.find("IMAGE_URL=") != std::string::npos ||
           raw.find("LICENSE_TYPE=") != std::string::npos ||
           raw.find("</GET_ONE_TIME_BOOT>") != std::string::npos;
}

// Drive one exchange over an already-connected client. Reads until `done`
// says the reply is complete, EOF, or the receive timeout. The timeout is the
// normal way a reply ends (see above), so it is not an error once something
// has been received.
template <class Client, class Done>
bool ribcl_exchange(Client& c, const std::string& user, const std::string& pass,
                    const std::string& body, Done done,
                    std::string& raw, std::string& err) {
    if (!c.send(ribcl_prolog(), err)) return false;
    // Give the firmware time to parse and answer the prolog as its own
    // document before the real one lands in the same buffer.
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    if (!c.send(ribcl_document(user, pass, body), err)) return false;

    raw.clear();
    for (;;) {
        std::vector<uint8_t> chunk;
        bool eof = false;
        std::string rerr;
        if (!c.recv(chunk, eof, rerr)) {
            if (eof || !raw.empty()) break;
            err = rerr;
            return false;
        }
        raw.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
        if (done(raw)) break;
        if (raw.size() > 1u << 20) { err = "RIBCL reply too large"; return false; }
    }
    return true;
}

// The whole thing: connect, exchange, parse, close.
//
// The receive timeout is longer for a virtual-media insert than for a status
// read. Connecting an image makes the firmware go and open the URL before it
// answers, and a second of silence is not enough to conclude it has finished.
inline bool ribcl_run(const std::string& host, uint16_t port,
                      const std::string& user, const std::string& pass,
                      RibclCommand cmd, const RibclArgs& args,
                      RibclReply& reply, std::string& err) {
    tls::Client::Options o;
    o.timeout_ms = 8000;            // connect + handshake; a 1024-bit iLO is slow
    tls::Client c(o);
    if (!c.connect(host, port, err)) return false;
    // From here on, silence is the end-of-reply signal.
    const bool media = (ribcl_wrapper(cmd) == std::string("RIB_INFO")) && ribcl_is_write(cmd);
    c.transport().set_recv_timeout(media ? 5000 : 1000);
    std::string raw;
    const bool ok = ribcl_exchange(c, user, pass, ribcl_body(cmd, args),
                                   ribcl_reply_complete, raw, err);
    c.close();
    if (!ok) return false;
    reply = ribcl_parse(raw);
    if (reply.raw.empty()) { err = "no RIBCL reply"; return false; }
    return true;
}

inline bool ribcl_run(const std::string& host, uint16_t port,
                      const std::string& user, const std::string& pass,
                      RibclCommand cmd, RibclReply& reply, std::string& err) {
    return ribcl_run(host, port, user, pass, cmd, RibclArgs{}, reply, err);
}

} // namespace ilo2
