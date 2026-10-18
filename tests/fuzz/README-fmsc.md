<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# `fmsc_fuzz` — libFuzzer target for `lib/fmsc`

`fmsc_fuzz.c` acts as the USB glue and a hostile host. Byte 0 picks the
configuration: cache 0–3 clusters, reorder 0–7 sectors, quiet/settle timers
on or off, and a consumer that refuses streams. The remaining bytes are a
sequence of operations (`op % 12`):

| op | action |
|---|---|
| 0 | raw OUT packet, 0..64 bytes (CBWs, data, junk) |
| 1 | host reads one IN packet (`fmsc_on_in_ready`) |
| 2, 3 | CLEAR_FEATURE(HALT) on IN / OUT |
| 4 | Bulk-Only reset |
| 5 | clock tick + `fmsc_poll` (0–10 s) |
| 6, 7 | well-formed WRITE(10) of 1..16 crafted sectors: zeros, PNG/JPEG starts, random, directory sectors pointing at hot clusters (with LFN / deleted entries / odd attributes and sizes), FAT sectors with contiguous chains (sometimes broken), AppleDouble, dot directories; sometimes with Ho > Do or the wrong direction |
| 8 | READ(10) |
| 9 | arbitrary CDB (often a supported opcode), CB length, transfer length and direction |
| 10 | SYNCHRONIZE CACHE / START STOP UNIT / PREVENT ALLOW |
| 11 | `fmsc_volume_read` at a random LBA |

LBAs come from a mix of the FAT area, the root directory, the first 48 data
clusters (biased towards cluster starts) and the whole volume. This
structure reaches the tracker's completion logic, not only the BOT parser.

Oracle: the harness traps on any contract violation.

* `send_in` while an IN packet is pending, or with a length outside 1..64.
* An IN stall with a packet still queued.
* Stream ids that do not strictly increase.
* Stream data that is not contiguous from offset 0, exceeds 256 KiB, or
  arrives after a terminal event.
* A second terminal event for one stream.
* A completion with size 0 or above 256 KiB, more bytes than were
  delivered, or a name that is not NUL-terminated.
* An unknown error or event code.
* `fmsc_wipe` leaving a non-zero byte in the context or the cache.

ASan and UBSan cover memory safety and undefined behaviour.

## Build and run

```sh
LLVM=/opt/homebrew/opt/llvm/bin   # or your distribution's clang
$LLVM/clang -g -O1 -std=c99 -fsanitize=fuzzer,address,undefined \
  -fno-sanitize-recover=all -Ilib/fmsc/include \
  tests/fuzz/fmsc_fuzz.c lib/fmsc/src/*.c -o build/fmsc_fuzz
mkdir -p build/fmsc_corpus && cp tests/fuzz/corpus/fmsc/* build/fmsc_corpus/
build/fmsc_fuzz -max_len=4096 -jobs=4 -workers=4 -max_total_time=600 build/fmsc_corpus
```

CI smoke: `-max_total_time=60`. To add new interesting inputs to the
committed corpus, keep it small:

```sh
build/fmsc_fuzz -merge=1 tests/fuzz/corpus/fmsc build/fmsc_corpus
```

## Regression replay

`tests/c/fmsc/CMakeLists.txt` builds the same file with
`-DFMSC_FUZZ_REPLAY_MAIN=1` (a plain `main`, no libFuzzer). The test
`fmsc_fuzz_corpus_replay` replays every file in `tests/fuzz/corpus/fmsc/` and
prints how many streams were started, completed and failed.

## Seeds

| file | content |
|---|---|
| `seed_windows` | FAT chain, root entry, PNG data, SYNC, eject: one completed stream |
| `seed_data_first` | data, FAT, root, quiet period: one completed stream |
| `seed_two_images` | two images, the second partly out of order, metadata, settle |
| `seed_too_large` | oversized entry, then data: `TOO_LARGE` |
| `seed_junk` | image followed by AppleDouble and a new directory; STOP |
| `seed_enumeration` | INQUIRY, TUR, REQUEST SENSE, READ CAPACITY, MODE SENSE, READ |
| `seed_invalid_cbw` | invalid CBW, clear-halts, reset recovery, TUR |
