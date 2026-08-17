#!/usr/bin/env python
"""
Scrape a remote-console session from iLO 2 and hand it to build/capture_dvc.exe,
which connects on port 23 and records the decrypted DVC video stream.

This is the hardware-dependent half of the frame-level oracle: the C++ decoder
has been proven behaviourally identical to HP's cim on synthetic input, but only
a real stream shows whether it renders a correct IMAGE. The captured .bin is
replayable offline, so this only has to succeed once.

    set ILO_PASS=...
    python capture_console.py [--seconds 20]

Note: iLO 2 permits a single remote-console session -- close the Java applet (and
any browser console) first, or the capture will connect and see nothing.
"""
import argparse
import base64
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ILO_HOST = os.environ.get("ILO_HOST", "10.10.123.130")
ILO_USER = os.environ.get("ILO_USER", "Administrator")
CAPTURE = os.path.join(HERE, "build", "capture_dvc.exe")


def _password():
    """ILO_PASS if set, else a gitignored .ilo_pass file next to this script."""
    pw = os.environ.get("ILO_PASS")
    if pw:
        return pw.strip()
    path = os.path.join(HERE, ".ilo_pass")
    if os.path.exists(path):
        with open(path) as f:
            return f.read().strip()
    return None


ILO_PASS = _password()


def fetch_page(url, cookie=None):
    """iLO 2 speaks only TLS 1.0 with legacy ciphers; curl handles it, Python's
    ssl module on a modern OpenSSL generally will not."""
    cmd = ["curl", "-k", "--tlsv1.0", "--tls-max", "1.0", "-s", url]
    if cookie:
        cmd += ["-b", cookie]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300).stdout


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seconds", type=int, default=20)
    ap.add_argument("--out", default=os.path.join("build", "dvc_capture.bin"))
    ap.add_argument("--png", default=os.path.join("build", "frame"))
    ap.add_argument("--host", default=ILO_HOST)
    ap.add_argument("--wake", action="store_true",
                    help="nudge the mouse (moves only, no clicks/keys) to wake a "
                         "blanked console")
    ap.add_argument("--wake-keys", action="store_true",
                    help="send arrow keys and Esc (never a character) to wake a "
                         "blanked Windows login screen")
    ap.add_argument("--refresh-every", type=int, default=0, metavar="SEC",
                    help="request a full redraw every SEC seconds, so the final "
                         "frame is complete rather than a mid-animation delta")
    args = ap.parse_args()

    if not ILO_PASS:
        sys.exit("No iLO password: set ILO_PASS, or put it in a .ilo_pass file "
                 "next to this script (gitignored).")
    if not os.path.exists(CAPTURE):
        sys.exit(f"Missing {CAPTURE}\n"
                 f"Build it: g++ -O2 -std=c++17 -o build/capture_dvc.exe "
                 f"cpp/capture_dvc.cpp -lws2_32")

    print(f"[*] logging in to {args.host} ...")
    login_page = fetch_page(f"https://{args.host}/login.htm")
    m = re.search(r'sessionkey="([^"]+)"', login_page)
    session_key = m.group(1) if m else None
    m = re.search(r'sessionindex="([^"]+)"', login_page)
    session_index = m.group(1) if m else None

    if not session_key or session_key == "NONEAVAILABLE":
        sys.exit("[!] No iLO sessions available. Wait a few minutes and retry.")

    token = "{}:{}:{}:{}".format(
        session_index,
        base64.b64encode(ILO_USER.encode()).decode(),
        base64.b64encode(ILO_PASS.encode()).decode(),
        session_key,
    )
    cookie = f"hp-iLO-Login={token}"
    print(f"[+] session {session_index}")

    print("[*] fetching console parameters (drc2fram.htm) ...")
    rc_page = fetch_page(f"https://{args.host}/drc2fram.htm", cookie)

    params = {}
    for m in re.finditer(r'(info[0-9a-z]+)="([^"]*)"', rc_page):
        params[m.group(1)] = m.group(2)
    for m in re.finditer(r'(info[a-z]+)=(\d+);', rc_page):
        params.setdefault(m.group(1), m.group(2))

    if not params.get("info0"):
        print("[!] No info0 in drc2fram.htm -- login likely failed or the console")
        print("    is disabled/in use. First 400 bytes of the page:")
        print(rc_page[:400])
        sys.exit(1)

    for k, v in sorted(params.items()):
        shown = v if k not in ("infob", "infoc") else v[:8] + "..." + f"({len(v)} hex)"
        print(f"    {k} = {shown}")

    cmd = [
        CAPTURE,
        "--host", args.host,
        "--port", params.get("info6", "23"),
        "--info0", params["info0"],
        "--info1", "1" if params.get("info1") else "0",
        "--infoa", params.get("infoa", "1"),
        "--infob", params.get("infob", ""),
        "--infoc", params.get("infoc", ""),
        "--infod", params.get("infod", "0"),
        "--seconds", str(args.seconds),
        "--out", args.out,
        "--png", args.png,
    ]
    if args.wake:
        cmd.append("--wake")
    if args.wake_keys:
        cmd.append("--wake-keys")
    if args.refresh_every:
        cmd += ["--refresh-every", str(args.refresh_every)]
    print(f"[*] running capture for {args.seconds}s ...")
    rc = subprocess.run(cmd, cwd=HERE).returncode
    print(f"[{'+' if rc == 0 else '!'}] capture exited {rc}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
