# iLO 2 Remote Console — C++ port

A from-scratch C++ reimplementation of the HP iLO 2 remote-console applet
(`com.hp.ilo2.remcons`, shipped as `rc175p10.jar`), so an iLO 2 (e.g. a ProLiant
DL380 G6) can be driven headlessly — decode its remote-console video to PNG and,
later, send mouse/keyboard input — without Java, a browser, or the applet.

The applet is **not obfuscated**, so each class is decompiled (CFR) and ported
class-by-class, with every component validated **byte-for-byte against HP's real
bytecode** via small Java oracles (reflection / recording subclasses).

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
| `tls/` | hand-written TLS 1.0 client (in progress) | — |
| `ilo/telnet.hpp` | transport: socket, login, DVC trigger, decrypt | real `telnet.run()` |
| `ilo/dvc_bits.hpp` | DVC bit reader (reversal tables, get/add_bits) | real `cim` reflection |
| `ilo/dvc_cache.hpp` | RGB444 remap + LRU palette cache | real `cim` reflection |
| `ilo/dvc_decoder.hpp` | the 48-state DVC video FSM | deterministic equivalence vs `cim` |
| `ilo/cim_png.hpp` | framebuffer -> PNG (vendored `stb_image_write`) | Java `ImageIO` |
| `ilo/ilo2_input.hpp` | outbound mouse/keyboard encoders | real `cim` (transmit capture) |
| `ilo/ilo2_session.hpp` | outbound session layer (RC4 encrypt, key index) | live iLO 2 |
| `tools/capture_dvc.cpp` | live capture -> `.bin` + PNG | — |
| `tools/replay_dvc.cpp` | offline replay + decoder stats | `testdata/` fixtures |
| `tests/*Probe.java`, `tests/test_*.cpp` | validation oracles + tests | — |
| `launch_console.py` | original: iLO login + applet launcher (TLS 1.0 via curl) | — |
| `mount_and_boot.py` | original: virtual-media mount + boot via `hpilo` | — |
| `range_http_server.py` | HTTP server with Range support for virtual media | — |

Local includes are root-relative (`#include "crypto/md5.hpp"`), so the source
root is the only include directory required.

## Building

```
cmake -S . -B build/cmake -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build/cmake
cd build/cmake && ctest --output-on-failure
```

- Oracles: JDK 17 `javac`/`java`, compiled against `rc175p10.jar` (not tracked).
- stb: exactly one TU defines `STB_IMAGE_WRITE_IMPLEMENTATION` before including
  `third_party/stb_image_write.h`.
- Reference vectors are generated, not transcribed:
  `python tests/gen_hash_vectors.py > tests/hash_vectors.inc` and
  `python tests/gen_bigint_vectors.py > tests/bigint_vectors.inc`.

## Not tracked (see `.gitignore`)

`rc175p10.jar` is HP proprietary — obtain it from the iLO 2 and place it here to
run the Java oracles; `_decomp/` and `_extract/` are regenerated from it with
CFR. `build/` and `console.html` (holds a live session token) are generated.

## Status

Inbound path (crypto → transport → DVC decoder → PNG) and outbound input
encoders are ported and validated offline. Remaining work needs live hardware: a
one-time real DVC capture to confirm the decoded image, and the outbound
encrypt/session layer + `ilo2_click`/`ilo2_type` tools with a live test.
