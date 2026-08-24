#!/usr/bin/env python
"""Thin wrapper around build/cmake/capture_dvc.

This script used to do the work: log in to the iLO over HTTPS, scrape the applet
parameters out of drc2fram.htm, and hand them to capture_dvc. All of that now
lives in C++ (ilo/ilo_session.hpp, on tls/client.hpp), so capture_dvc logs in by
itself and this file only forwards arguments.

The reason for moving it was not tidiness. The scraping shelled out to
`curl -k --tlsv1.0 --tls-max 1.0`, and the curl on the development box is
Schannel-backed -- which is the only reason it could still negotiate TLS 1.0. A
Linux curl links the system OpenSSL 3, where TLS 1.0 sits below the default
security level, so this script never worked there at all. The C++ path has no
external dependency and behaves the same on both platforms.

You can call capture_dvc directly; it takes the same options:

    build/cmake/capture_dvc --host 10.10.123.130 --seconds 20
    build/cmake/capture_dvc --host 10.10.123.130 --params-only

The password comes from --pass, else $ILO_PASS, else a gitignored .ilo_pass.
Note that the iLO permits a single remote-console session: close the Java applet
or browser console first, or use --params-only, which stops before port 23.
"""
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURE = os.path.join(HERE, "build", "cmake", "capture_dvc.exe")
if not os.path.exists(CAPTURE):
    CAPTURE = os.path.join(HERE, "build", "cmake", "capture_dvc")


def main():
    if not os.path.exists(CAPTURE):
        sys.exit(f"Missing {CAPTURE}\n"
                 f"Build it: cmake -S . -B build/cmake -G Ninja && "
                 f"cmake --build build/cmake --target capture_dvc")

    args = sys.argv[1:]
    if not any(a == "--host" for a in args):
        args += ["--host", os.environ.get("ILO_HOST", "10.10.123.130")]
    if not any(a == "--user" for a in args):
        args += ["--user", os.environ.get("ILO_USER", "Administrator")]

    return subprocess.run([CAPTURE] + args, cwd=HERE).returncode


if __name__ == "__main__":
    sys.exit(main())
