# Oracle fixtures — recordings of HP's bytecode

These files are the **expected values** the ports are tested against. Each one
was produced by running HP's real `com.hp.ilo2.remcons` classes out of
`rc175p10.jar` under the probes in `tests/*Probe.java`, and then frozen here.

They exist so the byte-for-byte validation survives without the jar.
`rc175p10.jar` is HP proprietary and is **not** in this repository; neither the
build nor `ctest` needs it, or Java, or a network. What is checked in is a
recording of observed behaviour — field values, encoder output, FSM state —
not HP code.

## Provenance

Recorded 2026-09-01 with JDK 17.0.17 against `rc175p10.jar`
(`com.hp.ilo2.remcons`, applet build stamp `20050808154652`), on the host the
rest of the port was developed against. Every fixture matched the C++ output
exactly at the moment it was frozen, so these are equally a record that the
port was correct on that date.

| Fixture | Bytes | Produced by | Pins |
|---|---:|---|---|
| `dvc_tables.txt` | 1938 | `DvcBitsProbe.java` | `cim`'s `dvc_reversal` / `dvc_left` / `dvc_right` tables after `init_reversal()` |
| `remap.txt` | 33977 | `DvcCacheProbe.java` | all 4096 entries of the RGB444 colour remap |
| `cache.txt` | 3052 | `DvcCacheProbe.java` | per-op LRU palette-cache state over a 36-op script (grow, hit, evict at 17, find, prune) |
| `decoder.txt` | 1496416 | `DvcDecoderProbe.java` | full 27-field FSM state after each of 20000 stream bytes |
| `decoder_events.txt` | 17919 | `DvcDecoderProbe.java` | the paste / set_dimensions / show_text callbacks from the same run |
| `input.txt` | 1403 | `Ilo2InputProbe.java` | every outbound mouse and keyboard encoding, as hex |
| `gradient.png` | 1283 | `PngCheck.java` | the encoded PNG that ImageIO confirmed decodes to 24000 pixel-exact values |

Two more oracles were short enough to pin as literals in the tests rather than
as files — see `test_crypto.cpp` (RC4 keystream before and after `update_key()`,
from `KeystreamDump.java`) and `test_telnet.cpp` (the DVC payload real
`telnet.run()` recovered, from `TelnetProbe.java`).

`gradient.png` is the odd one out: `PngCheck.java` needs no HP class at all, only
`javax.imageio`, so the *semantic* check — does this file decode to the right
pixels — can be re-run any time a JDK is around. The fixture pins the bytes;
`PngCheck.java` pins their meaning.

## Regenerating

Only needed if a port's observed behaviour must be re-derived, and only possible
with a copy of `rc175p10.jar` you obtain yourself from an iLO 2. Do not commit
the jar.

```sh
javac -cp rc175p10.jar -d build/probe tests/*.java

# DvcDecoderProbe and TelnetProbe replay streams the C++ tests write first
cmake --build build/cmake && (cd build/cmake && ctest)

for P in DvcBitsProbe DvcCacheProbe DvcDecoderProbe Ilo2InputProbe TelnetProbe; do
    java -cp "rc175p10.jar:build/probe" com.hp.ilo2.remcons.$P    # ';' not ':' on Windows
done
java -cp build/probe PngCheck                                     # needs no jar

# Java's PrintWriter emits CRLF on Windows; these fixtures are LF.
for f in dvc_tables cache remap decoder decoder_events input; do
    tr -d '\r' < build/${f}_java.txt > tests/oracle/${f}.txt
done
cp build/gradient.png tests/oracle/gradient.png
```

`DvcBitsProbe`, `KeystreamDump` and `TelnetProbe` also print short traces on
stdout; those are the literals pinned in the tests, not files.

The probes emit some noise of HP's own making — a `FileNotFoundException` for
`~/.java/hp.properties` and `Trying to select locale: ...` — on every run. It is
harmless and predates the port.

## If a fixture stops matching

The test names the first differing line. That is a real signal: either a port
changed behaviour, or the fixture was regenerated against a different applet
build. Check the stamp (`20050808154652`) before assuming the port is at fault.
