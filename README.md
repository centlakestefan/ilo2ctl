# iLO 2 Remote Console — C++ port

A from-scratch C++ reimplementation of the HP iLO 2 remote-console applet
(`com.hp.ilo2.remcons`, shipped as `rc175p10.jar`), so an iLO 2 (e.g. a ProLiant
DL380 G6) can be driven headlessly — decode its remote-console video to PNG and,
later, send mouse/keyboard input — without Java, a browser, or the applet.

The applet is **not obfuscated**, so each class is decompiled (CFR) and ported
class-by-class, with every component validated **byte-for-byte against HP's real
bytecode** via small Java oracles (reflection / recording subclasses).

## Layout

| File | Role | Validated against |
|---|---|---|
| `cpp/vmd5.hpp` | MD5 | test vectors |
| `cpp/rc4.hpp` | RC4 keyed by MD5, with rekey | Java `RC4` keystream |
| `cpp/telnet.hpp` | transport: socket, login, DVC trigger, decrypt | real `telnet.run()` |
| `cpp/dvc_bits.hpp` | DVC bit reader (reversal tables, get/add_bits) | real `cim` reflection |
| `cpp/dvc_cache.hpp` | RGB444 remap + LRU palette cache | real `cim` reflection |
| `cpp/dvc_decoder.hpp` | the 48-state DVC video FSM | deterministic equivalence vs `cim` |
| `cpp/cim_png.hpp` | framebuffer → PNG (vendored `stb_image_write`) | Java `ImageIO` |
| `cpp/ilo2_input.hpp` | outbound mouse/keyboard encoders | real `cim` (transmit capture) |
| `cpp/*Probe.java`, `cpp/test_*.cpp` | validation oracles + tests | — |
| `launch_console.py` | original: iLO login + applet launcher (TLS 1.0 via curl) | — |
| `mount_and_boot.py` | original: virtual-media mount + boot via `hpilo` | — |
| `range_http_server.py` | HTTP server with Range support for virtual media | — |

## Building / validating (Windows, this box)

- C++: Strawberry `g++` (`-std=c++17`; link `-lws2_32` for `telnet.hpp`).
- Oracles: JDK 17 `javac`/`java`, compiled against `rc175p10.jar`.
- stb: exactly one TU defines `STB_IMAGE_WRITE_IMPLEMENTATION` before including
  `cpp/third_party/stb_image_write.h`.

## Not tracked (see `.gitignore`)

`rc175p10.jar` is HP proprietary — obtain it from the iLO 2 and place it here to
run the Java oracles; `_decomp/` and `_extract/` are regenerated from it with
CFR. `build/` and `console.html` (holds a live session token) are generated.

## Status

Inbound path (crypto → transport → DVC decoder → PNG) and outbound input
encoders are ported and validated offline. Remaining work needs live hardware: a
one-time real DVC capture to confirm the decoded image, and the outbound
encrypt/session layer + `ilo2_click`/`ilo2_type` tools with a live test.
