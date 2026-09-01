# DVC capture fixtures

Decrypted DVC video streams recorded from a live HP iLO 2 (ProLiant DL380 G6,
1024x768) on 2026-08-17 with `tools/capture_dvc.cpp`. These are the bytes *after*
RC4 decryption — everything the decoder sees following the `ESC [ R` trigger —
so replaying them needs no hardware, no credentials and no network.

They exist because the synthetic oracles could not catch everything. The
deterministic-equivalence test compares FSM state and paste *events* against
HP's `cim`, but never the rendered surface, so a bug in the framebuffer layer
(`dvcwin` semantics, not `cim` semantics) passed it cleanly while producing an
entirely black image. See `lock_screen_wake.bin` below.

## Replaying

```sh
cmake --build build/cmake --target replay_dvc
build/cmake/replay_dvc testdata/lock_screen_settled.bin build/out.png
```

## The fixtures

### `lock_screen_settled.bin` (1255439 bytes)

The primary rendering fixture: a Windows 10 lock screen, captured with periodic
full redraws (`--refresh-every 6`) so the final frame is complete rather than a
mid-animation delta. Decodes to the wallpaper photo, the antialiased clock, and
the Swedish date text. Exercises the whole chain — colour remap, LRU cache
ranks, pixel and block RLE, tile blitting.

```
pastes        : 32256 (17409 contained a non-black pixel)
set_dimensions: 9
show_text     : 1        ("No Video", as the console wakes)
rekeys        : 0
firmware cmds : 0
framebuffer   : 1024x768
distinct colors: 481
```

### `lock_screen_wake.bin` (346787 bytes)

**Regression fixture for the framebuffer-clearing bug.** Same lock screen, but
the stream happens to end with a redundant `1024x768` MODE2 resolution packet
after the last tile. `dvcwin.set_abs_dimensions` (dvcwin.java:112) wraps its
entire body in a size-changed guard; before `cim_png.hpp` did the same, that
trailing packet re-zeroed the framebuffer and the whole 346KB decoded to pure
black despite 4548 tiles carrying real pixels.

If `distinct colors` ever drops to 1 here, the guard has regressed.

```
pastes        : 13200 (4548 contained a non-black pixel)
set_dimensions: 5
show_text     : 1
rekeys        : 0
firmware cmds : 0
framebuffer   : 1024x768
distinct colors: 481
```

### `blank_console.bin` (12300 bytes)

A blanked console — the display asleep, host powered on. Useful as the negative
case: an all-black result here is *correct*. Also shows the signature of a
blanked screen, roughly 6140 bytes per full frame and exactly one colour, which
is worth recognising before assuming the decoder is broken.

```
pastes        : 12288 (0 contained a non-black pixel)
set_dimensions: 3
framebuffer   : 1024x768
distinct colors: 1
```

## Notes

- `distinct colors: 481` is expected, not a defect: DVC is RGB444, so every
  channel is a nibble times 0x11 (`#001111`, `#002211`, …), 4096 possible.
- **Tile geometry is exactly as the port assumes**, measured across all three
  fixtures: 3072 distinct positions, a 64x48 grid, every position 16-aligned,
  `max x` 1008 (63*16), `max y` 752 (47*16), `len` always 16. One full pass over
  the screen is 3072 pastes.
- The iLO emits the MODE2 resolution packet every **two** full passes, so the
  gap between consecutive `set_dimensions` events is 6144 pastes. That interval
  is a resolution-packet cadence, not a frame size — do not read it as one frame.
- This encoder is **not** diff-based: each pass retransmits every tile, and most
  of that is redundant. In `lock_screen_settled.bin`, 27099 of 32256 pastes were
  byte-identical rewrites of a tile that had not changed (only 2085 differed).
  A consequence worth knowing: because every tile really is retransmitted, the
  black regions along the bottom edge and behind the "Activate Windows"
  watermark are genuine server output, not stale tiles that were never repainted.
- The streams contain no credentials. Session keys were negotiated per-session
  and the payload is already decrypted; the login handshake is not included.
  They do depict the server's lock screen (wallpaper, clock, hostname-free).

## RIBCL XML replies

Raw replies from the iLO's RIBCL interface, saved exactly as the firmware sent
them: the whole run of back-to-back `<RIBCL>` documents, redundant `RESPONSE`
stages, loose attribute spacing and CRLF endings included. Coping with that
shape is the parser's job, so the fixtures must not be tidied.

Captured 2026-09-01 from the iLO 2 at 192.0.2.10, **firmware 2.29**
(Jul 16 2015), licence type `iLO 2 Advanced`. The `VERSION="2.22"` on every
`<RIBCL>` element is the RIBCL *schema* version the firmware speaks, not its
firmware version -- the two are easy to confuse.

| Fixture | Command | Wrapper |
|---|---|---|
| `embedded_health.xml` | `GET_EMBEDDED_HEALTH` | `SERVER_INFO` |
| `power_readings.xml` | `GET_POWER_READINGS` | `SERVER_INFO` |
| `vm_status_cdrom.xml` | `GET_VM_STATUS DEVICE="CDROM"` | **`RIB_INFO`** |
| `vm_status_floppy.xml` | `GET_VM_STATUS DEVICE="FLOPPY"` | **`RIB_INFO`** |
| `one_time_boot.xml` | `GET_ONE_TIME_BOOT` | `SERVER_INFO` |
| `persistent_boot.xml` | `GET_PERSISTENT_BOOT` | `SERVER_INFO` |
| `fw_version.xml` | `GET_FW_VERSION` | `RIB_INFO` |

**The wrapper is not uniform, and getting it wrong is not a soft failure.**
Virtual-media and firmware commands live under `<RIB_INFO>`; power, health and
boot-order commands live under `<SERVER_INFO>`. Sending `GET_VM_STATUS` inside
`SERVER_INFO` is answered

```
STATUS="0x0001"
MESSAGE='Syntax error: Line #0: syntax error near "GET_VM_STATUS" in the line: ""'
```

after four perfectly happy `No error` stages, so a caller that only checks
whether it got a reply will think it succeeded. This is why `ribcl_body()`
cannot keep hardcoding one wrapper once virtual media is ported.

The virtual-media state at capture time was idle -- nothing inserted, so
`IMAGE_URL` is empty and `BOOT_OPTION` is `NO_BOOT`. `WRITE_PROTECT` differs by
device out of the box: `YES` for CDROM, `NO` for FLOPPY.

All seven are read-only commands. The replies carry no credentials, no session
tokens and no image URLs.

## `ilo2_vm_http_requests.log`

What the iLO 2's own HTTP client does when it fetches a virtual-media image,
recorded 2026-09-01 by `tools/media_server.cpp` while firmware 2.29 pulled a
4.7 GiB Windows Server 2022 ISO. It is documentation, not a test input: nothing
parses it. It is here because the firmware is from 2005 and none of this is
guessable.

The first few requests are `curl` self-tests, kept deliberately -- the contrast
with the firmware's requests below them is the point.

The only edit to the capture is the addresses: the iLO reads as `192.0.2.10`
and the machine serving the image as `198.51.100.20`, both RFC 5737
documentation ranges, substituted for the real ones throughout this repository.
Byte offsets, header spelling, ordering and sizes are untouched.

**The Range header is zero-padded to 20 digits:**

```
Range: bytes=00000000000000561152-00000000000000563199
```

`strtoull` copes; a parser that assumes a plausible digit count does not. If you
ever replace the HTTP layer, this is the first thing to test.

Everything else the firmware does, over 38 requests, 41 `206` responses, no
errors and no dropped connections:

| | |
|---|---|
| Method / version | `GET`, `HTTP/1.1`, every time |
| Headers sent | **only `Host` and `Range`** -- no `User-Agent`, `Accept` or `Connection` |
| `Host` value | the bare address, **port omitted**, even on `:8080` |
| Read sizes | 2048 B (34x), 4096 B (3x), 256 B (1x) |
| Access pattern | seeks, not a stream: 561152, 622592, 2543616, 4814848, 2551808, ... |
| Multi-range | never asked for one, so `multipart/byteranges` never comes up |

Keep-alive was enabled throughout and nothing broke, so an HTTP/1.1 server with
default keep-alive is fine. (`range_http_server.py`, the Python script this
replaced, was accidentally HTTP/1.0 -- it never overrode
`SimpleHTTPRequestHandler.protocol_version` -- so connection-per-request was
merely what the firmware happened to get, not what it needs.)

## Driving virtual media over RIBCL

Two things learned the hard way while capturing the log above, both worth
knowing before writing the RIBCL side:

- **`INSERT_VIRTUAL_MEDIA` fetches nothing.** It records the URL and returns.
  Afterwards `GET_VM_STATUS` reports `IMAGE_INSERTED="YES"` with the right
  `IMAGE_URL` and the HTTP server has seen no request at all. What makes the
  firmware actually connect is
  `<SET_VM_STATUS DEVICE="CDROM"><VM_BOOT_OPTION VALUE="CONNECT"/></SET_VM_STATUS>`.
- **`CONNECT` is not boot-neutral.** It silently sets `BOOT_OPTION` to
  `BOOT_ALWAYS`, so the host boots the image on its next reboot whether or not
  anyone asked for that. Read `GET_VM_STATUS` back after connecting, and set
  `NO_BOOT` explicitly if a boot was not intended.

## The mount + one-time-boot sequence

`mount_and_boot.py` used to hold this, expressed as `hpilo` calls. It is
recorded here in raw RIBCL because that script is gone and the RIBCL side is
not ported yet. Wrappers matter: virtual media is `RIB_INFO`, boot order is
`SERVER_INFO`.

```
1. RIB_INFO    write  <INSERT_VIRTUAL_MEDIA DEVICE="CDROM" IMAGE_URL="http://host:8080/x.iso"/>
2. RIB_INFO    write  <SET_VM_STATUS DEVICE="CDROM"><VM_BOOT_OPTION VALUE="BOOT_ONCE"/></SET_VM_STATUS>
3. SERVER_INFO write  <SET_ONE_TIME_BOOT value="CDROM"/>
4. SERVER_INFO write  <RESET_SERVER/>            (warm boot; or SET_HOST_POWER if off)
   afterwards:  RIB_INFO write <EJECT_VIRTUAL_MEDIA DEVICE="CDROM"/>
```

What is verified against fw 2.29 and what is not, because the difference
matters:

- **Verified.** Every wrapper and mode above. Step 1 exactly as written. The
  `SET_VM_STATUS`/`VM_BOOT_OPTION` element shape, with values `CONNECT` and
  `NO_BOOT`. `SET_ONE_TIME_BOOT` as written, exercised with the no-op value
  `NORMAL`. Step 4's `RESET_SERVER` is what `tools/ilo_power.cpp` already
  sends. `EJECT_VIRTUAL_MEDIA` exactly as written.
- **Not verified.** The literal values `BOOT_ONCE` (step 2) and `CDROM`
  (step 3) were never sent to hardware -- setting either arms a boot, and the
  only iLO 2 available was building releases. They come from the `hpilo` calls
  the deleted script made (`boot_option='boot_once'`, `set_one_time_boot('cdrom')`).
  The elements around them are verified; only these two strings are inherited
  rather than observed.

Note step 2 uses `BOOT_ONCE`, not the `CONNECT` used when capturing
`ilo2_vm_http_requests.log`. `CONNECT` attaches the image to a *running* host,
which is how the HTTP client was exercised without rebooting anything;
`BOOT_ONCE` is what actually makes the next boot come off the virtual CD.

## `ilo_cert.der` (612 bytes)

The X.509 certificate the iLO 2 serves on port 443, captured with a raw
ClientHello probe. It is the fixture for `tls/der.hpp` and is regenerated into
`tests/cert_fixture.inc` by `tests/gen_cert_fixture.py`.

```
subject/issuer : C=US, ST=Texas, L=Houston, O=Hewlett-Packard Company,
                 OU=ISS, CN=ILOUSE951N96F   (self-signed)
key            : RSA 1024-bit, e=65537
signature      : md5WithRSAEncryption
validity       : 2002-12-05 .. 2022-12-05   (EXPIRED)
```

Two properties make it a better test input than a modern certificate:

- the modulus has its top bit set, so DER encodes it as **129** bytes with a
  leading `0x00` sign pad while the key size is **128** — conflating the two is
  the classic way to get RSA key handling wrong;
- it is a **v1** certificate, so `tbsCertificate` has no `[0] EXPLICIT` version
  field and every subsequent field sits one slot earlier than in a v3 cert. A
  parser that reaches SubjectPublicKeyInfo by counting children from a fixed
  offset lands in the wrong place, which is why `tls/der.hpp` matches on shape
  instead.

This is public key material — the device presents it to any client that opens a
TLS connection — and it contains no session or credential data.
