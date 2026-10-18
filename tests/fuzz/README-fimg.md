<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Fuzzing lib/fimg

Four libFuzzer targets cover the streaming image decoders (`lib/fimg`). Each
one is built with ASan, UBSan and `-fno-sanitize-recover=all`.

| Target | Source | Seeds | What it checks |
|---|---|---|---|
| `fimg_png_fuzz` | `fimg_png_fuzz.c` | `corpus/fimg_png/` | PNG path: chunks, inflate, unfilter, luma, downscale, binarize. |
| `fimg_jpeg_fuzz` | `fimg_jpeg_fuzz.c` | `corpus/fimg_jpeg/` | JPEG path: markers, tables, Huffman, IDCT. |
| `fimg_jpeg_diff_fuzz` | `fimg_jpeg_fuzz.c` + `-DFIMG_FUZZ_LIBJPEG` | `corpus/fimg_jpeg/` | Same as `fimg_jpeg_fuzz`, plus a differential luma comparison with libjpeg-turbo. |
| `fimg_inflate_fuzz` | `fimg_inflate_fuzz.c` | `corpus/fimg_inflate/` | Differential test of the inflater against zlib. |

Both image targets use the same input layout, described in
`fimg_fuzz_common.h`. **Byte 0 is an option byte** and the image starts at
byte 1:

* bits 0–1 select the configuration: the default 720², 100 × 90 with a pixel
  cap, 1024², or strict trailer;
* bits 2–7 seed the chunking (0 means the whole file at once);
* in the PNG target, bit 7 also disables CRC fix-up.

Every input is decoded twice, once with fuzzer-chosen chunk sizes from 1 to
3589 bytes on a misaligned workspace, and once whole. The two runs must
return the same status. When the status is FIMG_OK they must also produce
the same info and bitmap. On success the harness also checks:

* the info invariants: dimensions ≤ the configured maximum, the stride, and
  `out = ceil(src / scale)`;
* the luma callback order: rows strictly increasing and complete;
* that `fimg_feed` after `fimg_finish` fails.

PNG CRC fix-up: unless bit 7 of the option byte is set, the PNG harness
recomputes every chunk CRC before decoding. Mutations then reach IHDR
validation, inflate and unfiltering instead of stopping at the first CRC
check. The library itself is unmodified. Inputs with bit 7 set keep the
CRC-failure paths covered.

JPEG differential mode: every input that fimg decodes successfully is
decoded again by libjpeg-turbo to grayscale with the islow IDCT. The luma
planes must be identical in two cases:

* libjpeg emits no warning;
* fimg's diagnostic saturation counter is zero (no overflow clamp engaged).

For out-of-specification coefficients libjpeg wraps while fimg clamps.
Files that libjpeg rejects but fimg accepts are allowed, because libjpeg
has a few stricter checks.

Inflate differential mode: byte 0 selects the input chunk size and the
per-call output limit, and the rest is a zlib stream. The two decoders must
agree on success or failure. On success they must agree on every output byte
and on the number of input bytes consumed. Output is capped at 4 MiB.

## Build and run

```sh
tests/fuzz/fimg_build.sh                 # -> build/fuzz-fimg/
# needs clang with libFuzzer (Homebrew LLVM on macOS is picked up
# automatically), zlib, and optionally libjpeg-turbo (JPEG_PREFIX).
mkdir -p /tmp/fz && cp -r tests/fuzz/corpus/fimg_png /tmp/fz/png
build/fuzz-fimg/fimg_png_fuzz /tmp/fz/png -max_len=300000 -rss_limit_mb=4096 -timeout=20
build/fuzz-fimg/fimg_jpeg_fuzz       <corpus copy> -max_len=300000
build/fuzz-fimg/fimg_jpeg_diff_fuzz  <corpus copy> -max_len=300000
build/fuzz-fimg/fimg_inflate_fuzz    <corpus copy>
```

Run on a copy of the corpus so that the committed seeds stay small. Large
images are left out of the seeds on purpose. A 1024² image costs about 70 ms
per execution under ASan, against about 1 ms for the small seeds. The fuzzer
can still grow the dimensions in IHDR or SOF.

To regenerate the seeds, run `uv run python tests/c/fimg/gen_vectors.py`.
It writes the test vectors and these seeds, each with its option byte
prepended.

## Results (local, Apple silicon, October 2026)

| Target | Wall time | Executions | Findings after the fixes below |
|---|---|---|---|
| `fimg_png_fuzz` | 15 min, then 6 workers × 15 min on the small-seed corpus | 79 k + 11.1 M | none (cov 744 edges) |
| `fimg_jpeg_fuzz` | 15 min | 2.98 M | none |
| `fimg_jpeg_diff_fuzz` | 15 min | 1.72 M | none (luma identical to libjpeg-turbo) |
| `fimg_inflate_fuzz` | 15 min | 1.06 M | none (identical to zlib) |

The early runs found three bugs, all fixed and covered by tests or seeds:

1. **JPEG DHT over-subscription.** The lookahead table was filled before the
   over-subscription check, so a hostile table could write outside it (UBSan
   out-of-bounds). The check now runs before any write.
2. **PNG error order.** A stream that inflated past the IHDR size *and*
   contained a bad filter byte reported different errors depending on the
   chunking. Complete rows are now processed before the size error, so
   errors come in stream order.
3. **Differential false positive.** Out-of-spec coefficients are clamped by
   fimg and wrapped by libjpeg. The saturation counter now gates the
   comparison.

The CI smoke run (60 s per target, architecture §9) should run all four
targets on the committed corpora.
