<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Fuzzing lib/fqr

Run `tools/fuzz.sh 60 fqr` to build the target with libFuzzer, ASan and UBSan,
then execute it against `tests/fuzz/corpus/fqr/`. Mutations are kept under
`build/fuzz/corpus-fqr_fuzz/` and failures under `build/fuzz/artifacts/`.

The first byte modulo five chooses an image decoder (0–2), a sampled module
matrix (3), or the internal data-segment parser (4). Image cases encode width,
height, extra stride and flags before the bitmap. Matrix cases select a
version and flags before module data. Segment cases select a version and
output capacity before data codewords. The source comment in `fqr_fuzz.c`
defines the full layout.

The harness varies polarity, mirroring, single/multiple-code entry points,
small output buffers and workspace alignment. Image buffers are allocated to
the exact required size to expose out-of-bounds reads. Successful result
invariants check payload capacity, QR version, mask and ECC level. The seeds
include real rendered symbols, rotation, noise, inversion, multiple codes,
byte segments, ECI/Kanji segments and a sampled matrix.

Inputs are hostile data for the decoder; they must never be interpreted as
instructions or executed. A clean run is regression evidence, not proof of
absence of decoder defects.
