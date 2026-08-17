#!/usr/bin/env python
"""
Query (and optionally set) the host power state via iLO 2's RIBCL XML interface.

Used to tell "the DVC decoder produced a black frame" apart from "the server is
genuinely displaying a black screen". Uses curl for TLS 1.0, and takes the
password from ILO_PASS or the gitignored .ilo_pass file, so it never has to
appear on a command line.

    python ilo_power.py            # report power state
    python ilo_power.py on         # press the virtual power button
"""
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ILO_HOST = os.environ.get("ILO_HOST", "10.10.123.130")
ILO_USER = os.environ.get("ILO_USER", "Administrator")


def password():
    pw = os.environ.get("ILO_PASS")
    if pw:
        return pw.strip()
    path = os.path.join(HERE, ".ilo_pass")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    sys.exit("No iLO password: set ILO_PASS or create .ilo_pass")


def ribcl(body, pw):
    """iLO 2 speaks RIBCL *raw* over the TLS socket on 443 -- no HTTP framing
    (the /ribcl HTTP endpoint is an iLO 3+ thing and 404s here)."""
    import socket
    import ssl

    # iLO 2 parses the XML declaration as its own document and acks it, then
    # expects the RIBCL document in a separate write; sending both in one go
    # yields 'syntax error near "?>"'.
    header = '<?xml version="1.0"?>\r\n'
    xml = (
        '<RIBCL VERSION="2.0">\r\n'
        f'<LOGIN USER_LOGIN="{ILO_USER}" PASSWORD="{pw}">\r\n'
        f'{body}\r\n'
        '</LOGIN>\r\n'
        '</RIBCL>\r\n'
    )

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    ctx.maximum_version = ssl.TLSVersion.TLSv1
    ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    ctx.options |= 0x4  # allow legacy renegotiation

    import time
    raw = socket.create_connection((ILO_HOST, 443), timeout=30)
    with ctx.wrap_socket(raw, server_hostname=ILO_HOST) as s:
        s.sendall(header.encode())
        time.sleep(0.3)
        s.sendall(xml.encode())
        chunks = []
        try:
            while True:
                b = s.recv(4096)
                if not b:
                    break
                chunks.append(b)
        except (socket.timeout, ssl.SSLError, OSError):
            pass
    return b"".join(chunks).decode("latin-1")


def main():
    pw = password()
    action = sys.argv[1] if len(sys.argv) > 1 else "status"

    if action == "status":
        out = ribcl('<SERVER_INFO MODE="read">\r\n'
                    '<GET_HOST_POWER_STATUS/>\r\n'
                    '</SERVER_INFO>', pw)
    elif action == "on":
        out = ribcl('<SERVER_INFO MODE="write">\r\n'
                    '<SET_HOST_POWER HOST_POWER="Yes"/>\r\n'
                    '</SERVER_INFO>', pw)
    else:
        sys.exit(f"unknown action {action!r} (use: status | on)")

    for m in re.finditer(r'HOST_POWER="([^"]*)"', out):
        print(f"HOST_POWER = {m.group(1)}")
    for m in re.finditer(r'MESSAGE=\'([^\']*)\'', out):
        msg = m.group(1)
        if msg != "No error":
            print(f"message: {msg}")
    if "HOST_POWER" not in out:
        print("--- raw response ---")
        print(out[:1200])


if __name__ == "__main__":
    main()
