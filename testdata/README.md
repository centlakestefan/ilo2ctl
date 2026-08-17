# DVC capture fixtures

Decrypted DVC video streams recorded from a live HP iLO 2 (ProLiant DL380 G6,
1024x768) on 2026-08-17 with `capture_console.py`. These are the bytes *after*
RC4 decryption — everything the decoder sees following the `ESC [ R` trigger —
so replaying them needs no hardware, no credentials and no network.

They exist because the synthetic oracles could not catch everything. The
deterministic-equivalence test compares FSM state and paste *events* against
HP's `cim`, but never the rendered surface, so a bug in the framebuffer layer
(`dvcwin` semantics, not `cim` semantics) passed it cleanly while producing an
entirely black image. See `lock_screen_wake.bin` below.

## Replaying

```sh
g++ -O2 -std=c++17 -o build/replay_dvc.exe cpp/replay_dvc.cpp
./build/replay_dvc.exe testdata/lock_screen_settled.bin build/out.png
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
