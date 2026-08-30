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

// The commands worth a button. Everything is a SERVER_INFO command; the read
// ones are harmless, the write ones are not, and the enum order groups them
// so a UI can draw a line between the two.
enum class RibclCommand {
    GetPowerStatus,     // GET_HOST_POWER_STATUS
    PowerOn,            // SET_HOST_POWER Yes  (momentary press: no-op if on)
    PowerOff,           // SET_HOST_POWER No   (momentary press: OS shutdown)
    ForcePowerOff,      // HOLD_PWR_BTN        (hard off)
    Reset,              // RESET_SERVER        (hard reset)
    ColdBoot,           // COLD_BOOT_SERVER    (power cycle)
    UidOn,              // UID_CONTROL Yes
    UidOff,             // UID_CONTROL No
};

inline bool ribcl_is_write(RibclCommand c) {
    return c != RibclCommand::GetPowerStatus;
}

inline const char* ribcl_command_name(RibclCommand c) {
    switch (c) {
        case RibclCommand::GetPowerStatus: return "power status";
        case RibclCommand::PowerOn:        return "power on";
        case RibclCommand::PowerOff:       return "power off";
        case RibclCommand::ForcePowerOff:  return "force power off";
        case RibclCommand::Reset:          return "reset";
        case RibclCommand::ColdBoot:       return "cold boot";
        case RibclCommand::UidOn:          return "UID on";
        case RibclCommand::UidOff:         return "UID off";
    }
    return "?";
}

// The body that goes inside <LOGIN>.
inline std::string ribcl_body(RibclCommand c) {
    const char* inner = "";
    switch (c) {
        case RibclCommand::GetPowerStatus: inner = "<GET_HOST_POWER_STATUS/>";        break;
        case RibclCommand::PowerOn:        inner = "<SET_HOST_POWER HOST_POWER=\"Yes\"/>"; break;
        case RibclCommand::PowerOff:       inner = "<SET_HOST_POWER HOST_POWER=\"No\"/>";  break;
        case RibclCommand::ForcePowerOff:  inner = "<HOLD_PWR_BTN/>";                 break;
        case RibclCommand::Reset:          inner = "<RESET_SERVER/>";                 break;
        case RibclCommand::ColdBoot:       inner = "<COLD_BOOT_SERVER/>";             break;
        case RibclCommand::UidOn:          inner = "<UID_CONTROL UID=\"Yes\"/>";      break;
        case RibclCommand::UidOff:         inner = "<UID_CONTROL UID=\"No\"/>";       break;
    }
    return std::string("<SERVER_INFO MODE=\"") + (ribcl_is_write(c) ? "write" : "read") +
           "\">\r\n" + inner + "\r\n</SERVER_INFO>";
}

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

// Minimal attribute scan: find `name=` followed by a quoted value. RIBCL uses
// double quotes for most attributes and single quotes for MESSAGE, so both are
// accepted. Returns every occurrence, in order.
inline std::vector<std::string> ribcl_attr_values(const std::string& doc, const std::string& name) {
    std::vector<std::string> out;
    const std::string key = name + "=";
    size_t pos = 0;
    while ((pos = doc.find(key, pos)) != std::string::npos) {
        pos += key.size();
        if (pos >= doc.size()) break;
        const char q = doc[pos];
        if (q != '"' && q != '\'') continue;
        const size_t end = doc.find(q, pos + 1);
        if (end == std::string::npos) break;
        out.push_back(doc.substr(pos + 1, end - pos - 1));
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

inline std::string ribcl_prolog() { return "<?xml version=\"1.0\"?>\r\n"; }

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
// firmware 2.22: a UID write yields 8, SET_HOST_POWER 9), so counting is not
// reliable. What is reliable is that the documents stream back-to-back and
// the firmware then goes silent without closing. ribcl_run therefore reads
// with a short receive timeout once data has started arriving, and treats
// that silence as the end. The one early exit is a status read: its answer is
// usable the moment HOST_POWER shows up.
inline bool ribcl_reply_complete(const std::string& raw) {
    return raw.find("HOST_POWER=") != std::string::npos;
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
inline bool ribcl_run(const std::string& host, uint16_t port,
                      const std::string& user, const std::string& pass,
                      RibclCommand cmd, RibclReply& reply, std::string& err) {
    tls::Client::Options o;
    o.timeout_ms = 8000;            // connect + handshake; a 1024-bit iLO is slow
    tls::Client c(o);
    if (!c.connect(host, port, err)) return false;
    // From here on, silence is the end-of-reply signal.
    c.transport().set_recv_timeout(1000);
    std::string raw;
    const bool ok = ribcl_exchange(c, user, pass, ribcl_body(cmd), ribcl_reply_complete, raw, err);
    c.close();
    if (!ok) return false;
    reply = ribcl_parse(raw);
    if (reply.raw.empty()) { err = "no RIBCL reply"; return false; }
    return true;
}

} // namespace ilo2
