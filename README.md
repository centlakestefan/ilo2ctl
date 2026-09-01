# iLO 2 Remote Console — C++ port

A from-scratch C++ reimplementation of the HP iLO 2 remote-console applet
(`com.hp.ilo2.remcons`, shipped as `rc175p10.jar`), so an iLO 2 (e.g. a ProLiant
DL380 G6) can be driven headlessly — decode its remote-console video to PNG and,
later, send mouse/keyboard input — without Java, a browser, or the applet.

The applet is **not obfuscated**, so each class was decompiled (CFR) and ported
class-by-class, with every component validated **byte-for-byte against HP's real
bytecode** via small Java oracles (reflection / recording subclasses).

Those recordings are frozen in `tests/oracle/`, so the whole suite asserts
against HP's observed behaviour with **no jar, no Java and no network** — see
`tests/oracle/README.md`. HP's `rc175p10.jar` is proprietary: it is not in this
repository, has never been committed to it, and nothing here needs it.

## Layout

| Path | Role | Validated against |
|---|---|---|
| `crypto/md5.hpp` | MD5 | RFC 1321 vectors + Java `VMD5` |
| `crypto/rc4.hpp` | RC4 (KSA/PRGA standard; MD5 key derivation is HP's) | Java `RC4` keystream |
| `crypto/sha1.hpp` | SHA-1 | FIPS 180 vectors via Python `hashlib` |
| `crypto/hmac.hpp` | HMAC, templated over either hash | RFC 2202 vectors via Python `hmac` |
| `crypto/bigint.hpp` | fixed-width bignum; `m^e mod n` for public `e` | Python `pow(m, e, n)` |
| `crypto/rsa.hpp` | RSA PKCS#1 v1.5 type-2 encryption | structural + composition tests |
| `crypto/random.hpp` | CSPRNG (`BCryptGenRandom` / `getrandom`) | distribution smoke test |
| `tls/der.hpp` | X.509 -> RSA public key (no verification) | the real iLO certificate |
| `tls/prf.hpp` | TLS 1.0 PRF + master/key-block/Finished | OpenSSL `TLS1-PRF` (MD5-SHA1) |
| `tls/record.hpp` | record layer, RC4 + HMAC, continuous keystream | independent Python model |
| `tls/handshake.hpp` | messages, transcript, Finished | simulated handshake |
| `tls/client.hpp` | handshake state machine + `https_get` | scripted mock server |
| `tls/socket.hpp` | blocking TCP client, Windows + POSIX | — |
| `ilo/ilo_session.hpp` | iLO login + drc2fram.htm parameter scrape | live iLO 2 |
| `tools/tls_get.cpp` | HTTPS fetch (replaces `curl --tlsv1.0`) | byte-identical to curl |
| `ui/console_core.hpp` | front-end seam: framebuffer, dirty rects, input | replay fixtures + live |
| `ui/sdl_main.cpp` | the standalone console window (SDL3 + Dear ImGui) | live iLO 2 |
| `ui/power_control.hpp` | RIBCL worker behind the panel's power buttons | live iLO 2 |
| `ui/connections.hpp` | recent host/user list (never the password) | `test_connections` |
| `ilo/ribcl.hpp` | RIBCL over raw TLS: power status/on/off/reset, UID, health | live iLO 2 (fw 2.29) |
| `ilo/health.hpp` | GET_EMBEDDED_HEALTH / GET_POWER_READINGS parser | `testdata/*.xml` captured from the iLO |
| `tools/ilo_power.cpp` | RIBCL from the command line | live iLO 2 |
| `tools/console_probe.cpp` | drives the seam like a front end would | live iLO 2 |
| `ilo/telnet.hpp` | transport: socket, login, DVC trigger, decrypt | real `telnet.run()` |
| `ilo/dvc_bits.hpp` | DVC bit reader (reversal tables, get/add_bits) | real `cim` reflection |
| `ilo/dvc_cache.hpp` | RGB444 remap + LRU palette cache | real `cim` reflection |
| `ilo/dvc_decoder.hpp` | the 48-state DVC video FSM | deterministic equivalence vs `cim` |
| `ilo/cim_png.hpp` | framebuffer -> PNG (vendored `stb_image_write`) | Java `ImageIO` |
| `ilo/ilo2_input.hpp` | outbound mouse/keyboard encoders | real `cim` (transmit capture) |
| `ilo/ilo2_session.hpp` | outbound session layer (RC4 encrypt, key index) | live iLO 2 |
| `tools/capture_dvc.cpp` | live capture -> `.bin` + PNG | — |
| `tools/replay_dvc.cpp` | offline replay + decoder stats | `testdata/` fixtures |
| `tests/oracle/` | frozen recordings of HP's bytecode (the expected values) | — |
| `tests/test_*.cpp` | the suite; every test self-asserting | `tests/oracle/` + generated vectors |
| `tests/*Probe.java` | how those recordings were made; needs a jar you supply | — |
| `mount_and_boot.py` | virtual-media mount + boot via `hpilo` (unported) | — |
| `range_http_server.py` | HTTP server with Range support for virtual media | — |

Local includes are root-relative (`#include "crypto/md5.hpp"`), so the source
root is the only include directory required.

## Building

```
cmake -S . -B build/cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/cmake
cd build/cmake && ctest --output-on-failure
```

The GUI is off by default so a bare clone builds and tests with no network:

```
cmake -S . -B build/gui -G Ninja -DCMAKE_BUILD_TYPE=Release -DILO2_BUILD_GUI=ON
cmake --build build/gui --target ilo2_console
build/gui/ilo2_console --host 10.10.123.130
```

That clones pinned SDL3 (`release-3.4.14`) and Dear ImGui (`v1.92.9`) and links
them statically, so the result is a single binary that does not depend on what
a distro happens to ship. `--replay <file.bin>` runs it against a capture
fixture with no hardware, `--tab power|health` picks the starting tab, and `--screenshot out.png --frames N` renders N frames
and exits, which works under `SDL_VIDEO_DRIVER=dummy` for checking the front end
without a window.

- No Java is required. The oracles that recorded `tests/oracle/` needed JDK 17
  and HP's jar; re-running them is optional and documented in
  `tests/oracle/README.md`.
- stb: exactly one TU defines `STB_IMAGE_WRITE_IMPLEMENTATION` before including
  `third_party/stb_image_write.h`.
- Reference vectors are generated, not transcribed:
  `python tests/gen_hash_vectors.py > tests/hash_vectors.inc` and
  `python tests/gen_bigint_vectors.py > tests/bigint_vectors.inc`.

## Not tracked (see `.gitignore`)

`build/` is generated. `rc175p10.jar` is HP proprietary and deliberately absent:
it is not required to build, test, or run anything here. It is only needed to
regenerate the `tests/oracle/` fixtures, which is optional — obtain your own
copy from an iLO 2 if you want to, and note that `.gitignore` refuses to commit
it or the `_decomp/` and `_extract/` trees CFR produces from it.

## Status

Working end to end against a real iLO 2: TLS 1.0 login, session scrape,
DVC video, keyboard and mouse, plus server control over RIBCL (power, reset,
UID) and health readout (temperatures, fans, PSUs, drives, wattage). The
console window has three tabs — Console, Power, Health — over a status block.

Open: the Linux build has not been compiled yet (the code is branched for it);
`LocaleTranslator` is unported, so non-US layouts only send ASCII; virtual media
and one-time boot are still the Python scripts.
