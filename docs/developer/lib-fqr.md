---
title: Embedded QR code decoder in C (lib/fqr)
description: "lib/fqr detects and decodes QR Model 2 versions 1–40 from a monochrome bitmap: freestanding C99, caller-owned buffers, no allocation or recursion."
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# lib/fqr

`lib/fqr` detects and decodes QR Model 2 versions 1–40 from a monochrome
bitmap. It is freestanding C99 with caller-owned buffers, no allocation,
no recursion and no mutable global state. It runs in the unprivileged image
import module after `fimg` finishes receiving and binarizing the image.

## Interface and limits

See `lib/fqr/include/fqr.h` for the complete API. Input bits are MSB first,
one bit per pixel, with **1 = dark**. Dimensions are 1–1024 pixels per axis;
the stride is at least `(width + 7) / 8`. The caller must provide enough input
bytes for `(height - 1) * stride + (width + 7) / 8` and a workspace of
`FQR_WORKSPACE_SIZE = 12288` bytes; arbitrary workspace alignment is supported.

`fqr_decode()` locates codes and fills caller-provided payload buffers.
`fqr_decode_single()` searches for two spatially distinct codes and rejects
ambiguity. `fqr_decode_matrix()` skips image detection for an already sampled
module grid. Numeric, alphanumeric, byte and Kanji segments are decoded;
ECI and structured-append metadata are reported. Transport-frame reassembly
belongs to the application's backup importer.

The maximum decoded output is 7089 bytes (numeric version 40-L). An
insufficient output buffer is reported with the required length, rather than
truncated as a successful decode. The firmware importer imposes its own
smaller payload cap. Error statuses distinguish invalid arguments, insufficient
workspace, no code, format/ECC/data failure, insufficient payload space and
multiple codes.

The detector scans finder patterns, ranks geometrically plausible triples,
estimates perspective transforms and candidate dimensions, samples module
grids, checks BCH format/version information, reverses masks and interleaving,
and applies Reed-Solomon correction before bounded segment parsing. Defaults
include inverted-polarity fallback and mirrored-grid retry. The work budget
is **600,000 units**, measured approximately in sampled modules, with at most
32 retained finder triples per pass. It is an algorithmic bound, not a time
guarantee; `fqr_stats_t.budget_exhausted` exposes early search termination.

## Verification

The five CTest suites cover Reed-Solomon, segment parsing, module matrices,
detection and the committed corpus of **311 images**. The corpus includes all
versions and ECC levels, modes, rotations, perspective, blur, lighting, noise,
inversion, multiple symbols, damage, negative images and simulated OLED photos.
The test-only C encoder provides another source of randomized cases.

```sh
make test-c
uv run python tests/c/fqr/gen_vectors.py --large --out build/fqr-large
uv run python lib/fqr/tools/gen_tables.py --check
tools/fuzz.sh 60 fqr
source tools/env.sh
tests/c/fqr/m4bench/run.sh
```

Generated constants are cross-checked against Segno's independent tables and
formatted with the pinned development formatter. The libFuzzer harness covers
image detection, sampled matrices and segment parsing, including undersized
payload buffers and misaligned workspaces; see
[README-fqr.md](../../tests/fuzz/README-fqr.md).

On 18 October 2026, all five QR suites passed under Clang ASan/UBSan and in
an optimized GCC 16 build. A 60-second local fuzz run completed 15,034
executions without a reported failure. Cross-compilation for Cortex-M4/M33
passed with warnings treated as errors.

QEMU Cortex-M4F instruction counts (GCC `-O2`, not hardware timings):

| Corpus case | Instructions |
|---|---:|
| Phone-style photo, version 10, 724² | 7,023,920 |
| Version 40, 724² | 34,361,240 |
| OLED-style version 9, 724² | 5,058,160 |
| Noise, 724², both polarities | 186,906,040 |
| Hostile finder patterns, 724², both polarities | 142,948,240 |

Instruction counts do not account for real flash wait states, scheduling or
camera/display behavior. Physical QR readability and decode timing remain
hardware acceptance tasks.
