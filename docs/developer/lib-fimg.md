<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# lib/fimg — streaming PNG / baseline-JPEG decoder and binarizer

`lib/fimg` turns an image file that arrives in arbitrary pieces (USB mass
storage sector writes, see ADR-0003 and `lib-fmsc.md`) into a bounded
1-bit-per-pixel bitmap for the QR decoder `lib/fqr`. It implements spec §3.3
(PNG and baseline JPEG only, ≤ 256 KiB, ≤ 1024 × 1024, streaming, bounded
memory, no full-frame RGBA buffer, clear error for unsupported variants) and
contributes to §10.4 and R05/R06 (safe rejection of hostile, truncated,
over-compressed and oversized images).

The file is never stored. Every byte is consumed as it arrives.

* Language: freestanding C99 (`<stdint.h>`, `<stddef.h>`, `<stdbool.h>`,
  `<string.h>` only). No allocation, no recursion, no VLA, no floating point,
  no 64-bit division, no global mutable state.
* Code size: about 18 KiB of Thumb-2 code (`arm-none-eabi-gcc -O2
  -mcpu=cortex-m4`), no data, no BSS.
* Deepest stack frame: 112 B. The whole call chain stays under 1 KiB.
* Licence: GPL-3.0-only. All code is original. The inflater was written from
  RFC 1950/1951 and the IDCT follows the published LLM/islow algorithm
  (same constants as libjpeg). Nothing is vendored.

## 1. API in one screen

```c
fimg_config_t cfg;
fimg_config_default(&cfg);              /* 720 x 720 output, 256 KiB file cap */
size_t ws_size = fimg_workspace_size(&cfg);   /* 94 592 B (PNG+JPEG) */
size_t bm_size = fimg_bitmap_size(&cfg);      /* 64 800 B */
fimg_ctx_t *ctx;
fimg_init(&ctx, ws, ws_size, &cfg, bm, bm_size);
/* for every chunk, any length (1 byte .. whole file) */
st = fimg_feed(ctx, chunk, len);        /* FIMG_OK or a sticky error */
/* when the file is complete (fmsc: stream_complete) */
fimg_info_t info;
st = fimg_finish(ctx, &info);           /* FIMG_OK => bitmap complete */
/* bitmap: info.out_width x info.out_height, info.stride bytes per row,
 * MSB first, bit = 1 is dark -> fqr_image_t { bm, w, h, stride } */
fimg_secure_zero(ws, ws_size);          /* image of a secret: wipe */
fimg_secure_zero(bm, bm_size);
```

`fimg_get_info()` returns the format, source dimensions, scale factor and
output geometry as soon as the header has been parsed. Use it to reject a
file early or to show progress. `info.bytes_consumed` is the number of image
bytes up to and including IEND/EOI. fmsc can check it against the size in the
directory entry ("clean end within the reported size", ADR-0003).

Configuration (`fimg_config_t`):

| Field | Default | Meaning |
|---|---|---|
| `max_out_width`, `max_out_height` | 720, 720 | Bitmap bound, 8..1024 each. |
| `max_out_pixels` | 0 (= w·h) | Extra bound on the output pixel count. |
| `max_file_bytes` | 262 144 | Image bytes allowed before the end marker. |
| `flags` | 0 | `FIMG_FLAG_STRICT_TRAILER`, `FIMG_FLAG_NO_PNG`, `FIMG_FLAG_NO_JPEG`. |
| `luma_cb`, `luma_cb_user` | NULL | Full-resolution luma rows, for tests and diagnostics only. |

The default output of 720 × 720 keeps the bitmap at 64 800 B (≤ 64 KiB) with
stride 90. A width of 724 would need stride 91 and 65 884 B.

## 2. Pipeline

```
bytes ─► sniff ─┬─► PNG: chunk parser + CRC-32 ─► inflate (32 KiB window) ─► unfilter (2 scanlines) ─► luma row ─┐
                └─► JPEG: staging (4 KiB) ─► markers / DHT / DQT ─► Huffman ─► dequant ─► islow IDCT ─► MCU band ─┤
                                                                                                                  ▼
                       bitmap ◄─ adaptive binarizer (ring of K rows + column sums) ◄─ integer box downscaler (factor f)
```

### 2.1 Sniffing and byte accounting

The first bytes must be the PNG signature (8 bytes) or `FF D8 FF` (JPEG SOI
followed by a marker). Anything else gives `FIMG_E_NOT_IMAGE` on the first
mismatching byte. The signature bytes are then replayed into the selected
decoder.

`fimg_feed` passes at most `max_file_bytes − bytes_consumed` bytes to the
decoder. A stream that still needs bytes beyond the limit fails with
`FIMG_E_FILE_TOO_LARGE`. The limit counts image bytes up to and including
IEND / EOI.

**Trailing-data policy.** By default, bytes after IEND / EOI are discarded
unread and are not counted. MSC hosts write whole clusters, so the last
cluster normally carries padding past the end of the file. Only fmsc knows the
real file size (from the directory entry), so it bounds the stream.
`FIMG_FLAG_STRICT_TRAILER` turns any trailing byte into
`FIMG_E_TRAILING_DATA`.

### 2.2 PNG

* The chunk parser accepts any split of the input. Every chunk CRC-32 is
  verified, ancillary chunks included, and a mismatch is fatal. IHDR, PLTE and
  tRNS are buffered (≤ 768 B) and applied only after their CRC checks out.
  IDAT data is inflated as it arrives. Its CRC is checked at the end of the
  chunk, and a failure there still rejects the image before `fimg_finish`.
* Rules enforced:
  * IHDR comes first and is exactly 13 bytes.
  * Width and height must be in 1..1024, otherwise `FIMG_E_DIMENSIONS`.
  * Colour type / bit depth must be one of: 0 with 1, 2, 4, 8 or 16; 2, 4 or 6
    with 8 or 16; 3 with 1, 2, 4 or 8. Compression and filter methods must be
    0. Anything else gives `FIMG_E_PNG_UNSUPPORTED`.
  * Interlace 1 (Adam7) gives `FIMG_E_PNG_INTERLACED`.
  * PLTE appears at most once, before IDAT, with 1..256 entries. It is
    required for type 3 and forbidden for types 0 and 4.
  * IDAT chunks are contiguous.
  * IEND is empty and closes the image.
  * Chunk lengths are ≤ 2³¹−1 and chunk type bytes are ASCII letters.
  * Unknown critical chunks give `FIMG_E_PNG_UNSUPPORTED`. Unknown ancillary
    chunks are skipped.
  * An invalid tRNS (wrong length, position or colour type) is ignored, as an
    ancillary chunk may be.
* **APNG.** `acTL`, `fcTL` and `fdAT` are ancillary and skipped, so an APNG
  yields its default image (the IDAT stream). This is the frame that non-APNG
  viewers show.
* **Inflater** (`fimg_inflate.c`, written for feuristic):
  * Resumable at any byte. Stored, fixed and dynamic blocks; 32 KiB window
    that doubles as the output ring.
  * Validation mirrors zlib, and the two are fuzzed differentially:
    * CM = 8, CINFO ≤ 7, FCHECK, FDICT refused.
    * The code-length code must be complete.
    * Literal/length and distance codes must be complete, except a single
      1-bit code.
    * HLIT ≤ 286, HDIST ≤ 30, end-of-block code present, no repeat at the
      start, no repeat overflow.
    * Symbols 286/287 and 30/31 are refused, as are distances before the
      start of the output.
    * The Adler-32 trailer is checked.
* **Decompression bomb.** The inflated size must equal
  `height × (rowbytes + 1)` exactly:
  * One byte more is refused as soon as it is produced
    (`FIMG_E_PNG_DATA_SIZE`), after the complete rows have been processed, so
    the error does not depend on chunking.
  * A shorter stream is refused when the zlib stream ends.
  * Data after the end of the zlib stream gives `FIMG_E_PNG_CORRUPT`.
  * A 60 MB zero bomb is refused after 272 bytes of output.
* **Unfiltering.** All five filter types are applied on two scanline buffers
  of `rowbytes + 1` bytes (≤ 8193 B). Filter type > 4 gives
  `FIMG_E_PNG_CORRUPT`.
* **Luma.** Y = (19595 R + 38470 G + 7471 B + 32768) >> 16. This is
  Pillow's RGB→L fixed point.
  * 16-bit samples use their high byte.
  * 1/2/4-bit grey is scaled by 255, 85 or 17.
  * Alpha is composited over white: Y' = round((Y·a + 255·(255−a)) / 255),
    exact integer.
  * The tRNS colour key is compared on the raw sample (16-bit keys included),
    and a matching pixel becomes white.
  * The palette luma is precomputed with tRNS alpha applied. Indices beyond
    PLTE are black.

### 2.3 JPEG

* **Staging.** All input goes through a 4 KiB staging buffer.
  * Markers are parsed byte by byte: fill bytes, any segment length, DHT/DQT
    parsed incrementally (many tables per segment), SOF/SOS/DRI/APP0/APP14
    headers buffered.
  * An MCU is decoded only when the buffer holds at least 2560 bytes. This is
    the worst case for one MCU of at most 6 blocks: (27 + 63 × 26) bits per
    block, doubled for byte stuffing, plus prefetch. Alternatively, a marker
    must already be visible. The Huffman hot loop therefore never suspends in
    the middle of an MCU. Stuffed `FF 00` pairs and markers may be split
    across chunks.
* **Accepted:**
  * SOF0, 8-bit precision.
  * 1 component, or 3 components with luma H1V1, H2V1, H1V2 or H2V2 and
    chroma 1×1.
  * Interleaved scans, and non-interleaved / multi-scan sequential files. The
    Y scan is decoded. Other scans are skipped by marker search, before or
    after the Y scan.
  * Restart intervals, with RSTn checked in order.
  * DQT with 8- or 16-bit precision, tables 0..3.
  * DHT tables 0..1. Tables 2..3 are parsed and dropped, and are refused if a
    scan uses them.
  * APPn and COM skipped. EXIF thumbnails inside APP1 are skipped with it.
* **Colour model detection** follows libjpeg:
  * JFIF means YCbCr.
  * Otherwise an Adobe transform 0 means RGB, and RGB is refused.
  * Otherwise component ids 'R','G','B' mean RGB and are refused.
* **Only luma is reconstructed.** Chroma blocks of interleaved scans are
  Huffman-decoded and dropped, without dequantisation or IDCT.
* **IDCT.** libjpeg's `jidctint` "islow" (LLM, 13-bit constants, 2 extra
  pass-1 bits). It is **bit-exact with libjpeg-turbo** (`draft("L")` in
  Pillow, `djpeg -grayscale -dct int`) on every corpus file: max luma
  difference 0, within the ±2 the spec allows.
* **Overflow guards.** Dequantised coefficients and pass-1 outputs are clamped
  to ±32767. Interval analysis of the butterfly then bounds every
  intermediate by 0.94·2³¹, so a hostile stream cannot cause signed overflow
  (UBSan runs in the tests and fuzzers). Valid 8-bit data never reaches the
  clamps: |coef| ≤ 4096 and |pass 1| ≤ 23 170. A diagnostic counter
  (`fimg_jpeg_t::sat`) records any engagement; the differential fuzzer uses
  it.
* **Refused**, each with its own code:
  * SOF1 / precision ≠ 8 → `EXTENDED`.
  * SOF2 → `PROGRESSIVE`.
  * SOF3 / SOF55 (JPEG-LS) → `LOSSLESS`.
  * SOF5..7, DHP, EXP → `HIERARCHICAL`.
  * SOF9..15, DAC → `ARITHMETIC`.
  * 2 or 4 components (CMYK/YCCK) and RGB → `COLOR`.
  * Other sampling factors (4:1:1, chroma ≠ 1×1) → `SAMPLING`.
  * A second SOF → `MULTIFRAME`.
  * Height 0 (DNL) or a dimension > 1024 → `DIMENSIONS`.
  * Structure errors give `FIMG_E_JPEG_CORRUPT`: missing tables, bad
    lengths, wrong RSTn, garbage between segments, EOI before the image.
  * Entropy errors give `FIMG_E_JPEG_HUFFMAN`: invalid code, DC category
    > 11, AC size > 10, run past coefficient 63, codes running into a marker.
* **Lenient points** (as libjpeg):
  * Padding between the end of a scan and the next marker is skipped.
  * A Huffman table with an all-zero count is accepted, and fails only if it
    is used.
  * An all-ones code is refused, as in libjpeg.

### 2.4 Downscaler

The factor `f` is the smallest integer such that `ceil(w/f) ≤
max_out_width`, `ceil(h/f) ≤ max_out_height` and the pixel product ≤
`max_out_pixels`. For example, 1024² gives f = 2 (512²) with the default
configuration, and 721 × 720 gives f = 2.

Each output pixel is the rounded mean of its f × f block. Edge blocks use
their real size. The downscaler keeps one `u32` accumulator per output
column.

### 2.5 Adaptive binarizer

This is a single pass that adds no delay beyond `r` output rows. The window
radius is `r = clamp(max(out_w, out_h) / 32, 4, 63)`, a window of about 1/16
of the image side (45 px at 720). A ring of K = 2r+1 output rows and running
per-column sums of `v` and `round(v²/256)` (u16 each) give the local mean
`m` and variance `s²` in O(1) per pixel.

For a pixel `p`:

| Condition | Result |
|---|---|
| `p < m − δ` | dark |
| `p > m + δ` | light |
| window textured (`s ≥ σmin`) | dark iff `p < m` |
| window flat | dark iff `m ≤ lo + c/4` and `m ≤ hi/2` (light if global contrast `c < 48`) |

`lo` and `hi = lo + c` are the class means of the iterative-intermeans
(ISODATA) threshold on the histogram of every row received so far.
`δ = max(12, c/8)` and `σmin = max(8, c/16)`.

The flat rule keeps large uniform dark areas dark, such as finder-pattern
centres of big modules (version-1 QR at 44 px/module in the corpus). It keeps
shadowed paper light (photo-like renders with a 3× illumination gradient,
blur, noise and JPEG artefacts). A uniformly dark image therefore binarizes
to white. This is intended: no QR there.

Measured on the corpus (`fimg_vectors`):

* Clean renders: 100 % agreement with a fixed 128 threshold on the
  downscaled luma, ignoring edge pixels within 104..151. The worst clean
  render is 99.96 %.
* Every QR vector, including the degraded photos: 0 module errors when
  module centres are sampled.

The last `r` rows are flushed when the final source row arrives.
`fimg_finish()` only checks the end of the stream and returns.

## 3. Memory map

All memory comes from the caller. `fimg_workspace_size(cfg)` is the worst
case over every accepted image. It covers the larger of the two decoders,
because the format is unknown before the first bytes, unless
`FIMG_FLAG_NO_PNG` or `FIMG_FLAG_NO_JPEG` is set. Any alignment is accepted:
up to 8 bytes are skipped.

Default configuration (720 × 720), host build:

| Region | PNG | JPEG |
|---|---:|---:|
| context (`fimg_ctx_t`: state, inflate tables, Huffman / quant tables, histogram) | 6 232 | 6 232 |
| decoder heap: LZ77 window | 32 768 | — |
| decoder heap: 2 scanlines (worst case 1024 × RGBA16 + filter byte) | 16 400 | — |
| decoder heap: luma row | 1 024 | — |
| decoder heap: JPEG staging buffer | — | 4 096 |
| decoder heap: MCU band (1024 × 16) | — | 16 384 |
| binarizer ring (45 rows × 720) | 32 400 | 32 400 |
| column sums + column square sums (u16) | 2 880 | 2 880 |
| downscaler accumulators (u32) | 2 880 | 2 880 |
| alignment slack | 8 | 8 |
| **workspace total** | **94 592 (92.4 KiB)** | **64 880 (63.4 KiB)** |
| output bitmap (separate buffer) | 64 800 | 64 800 |

Both totals meet the targets (≤ 96 KiB PNG, ≤ 64 KiB JPEG, excluding the
bitmap). With the default flags the workspace is 94 592 B. Pointers are
4 bytes on Cortex-M, so the context is a little smaller there. With a
1024 × 1024 output the workspace is 131 184 B and the bitmap 131 072 B.

## 4. Performance

Measured on the host (Apple silicon, `-O2`, 512-byte feeds, decode +
downscale + binarize to 512²):

* 1024² 4:4:4/4:2:0 JPEG of 236 KB: 6.1 ms.
* 1000² 4:2:0 q90: 5.2 ms.
* 1024² grey PNG: 6.8 ms.
* Synthetic worst-case PNG, 1024² RGBA16 (8 MiB inflated from 53 KB):
  38 ms under ASan.

**Cortex-M4F @ 168 MHz (T2B1) estimate.** No cycle-accurate simulator was
used; these figures are derived from operation counts.

* **JPEG.** The 256 KiB cap bounds the entropy data to about 2.1 M bits.
  * Huffman: ≤ about 700 k symbols at about 30 cycles each, ≤ 21 M cycles.
  * IDCT: 16 384 luma blocks at about 700 cycles, 11 M cycles.
  * Downscale: 1 M pixels at about 6 cycles, 6 M cycles.
  * Binarizer: 262 k output pixels at about 40 cycles, 10 M cycles.
  * Staging copies: 1 M cycles.
  * Total: about 50 M cycles, **about 0.3 s**.
  * Applying a conservative 130× host→M4 ratio to the measured 6 ms gives
    0.8 s.
* **PNG worst case** (1024² RGBA16, 8 MiB of scanlines):
  * Inflate copy: about 6 cycles/byte, 50 M cycles.
  * Paeth unfilter: ≤ 15 cycles/byte, 125 M cycles.
  * Luma: 20 M cycles.
  * Total: **about 1.2 s**.
  * A typical 8-bit grey or 1-bit QR PNG takes about 0.2 s.
* All within the < 3 s target.
* The STM32U585 (M33 @ 160 MHz) is comparable.
* There are no 64-bit divisions. The binarizer's variance test uses
  32×32→64 multiplies (UMULL).

## 5. Status codes and user-facing messages

`fimg_status_category()` maps every code to one of eight messages. The
importer UI should show the category message. `fimg_status_name()` gives a
stable identifier for logs.

| Category | Codes | EN | FR |
|---|---|---|---|
| `NOT_IMAGE` | `NOT_IMAGE` | Not a PNG or JPEG image. | Ce fichier n'est pas une image PNG ou JPEG. |
| `FILE_TOO_LARGE` | `FILE_TOO_LARGE` | Image file larger than 256 KiB. | Fichier image trop volumineux (256 Kio max.). |
| `DIMENSIONS` | `DIMENSIONS` | Image too large (max. 1024 × 1024 pixels). | Image trop grande (1024 × 1024 pixels max.). |
| `PNG_UNSUPPORTED` | `PNG_INTERLACED`, `PNG_UNSUPPORTED` | Unsupported PNG (interlaced or unusual format). Save it again as a standard PNG. | PNG non pris en charge (entrelacé ou format inhabituel). Réenregistrez-le en PNG standard. |
| `JPEG_UNSUPPORTED` | `JPEG_PROGRESSIVE`, `JPEG_EXTENDED`, `JPEG_LOSSLESS`, `JPEG_ARITHMETIC`, `JPEG_HIERARCHICAL`, `JPEG_COLOR`, `JPEG_SAMPLING`, `JPEG_MULTIFRAME` | Unsupported JPEG (progressive, CMYK, 12-bit…). Save it as a baseline JPEG or as PNG. | JPEG non pris en charge (progressif, CMJN, 12 bits…). Réenregistrez-le en JPEG « baseline » ou en PNG. |
| `CORRUPT` | `PNG_CRC`, `PNG_CORRUPT`, `PNG_ZLIB`, `PNG_DATA_SIZE`, `JPEG_CORRUPT`, `JPEG_HUFFMAN`, `TRAILING_DATA` | Damaged image file. | Fichier image endommagé. |
| `TRUNCATED` | `TRUNCATED` | Incomplete image file. Copy it again. | Fichier image incomplet. Copiez-le à nouveau. |
| `INTERNAL` | `PARAM`, `WORKSPACE`, `STATE`, `LIMIT`, `INTERNAL` | Internal error while reading the image. | Erreur interne lors de la lecture de l'image. |

The specific code may be shown as a detail line. For example, for
progressive JPEGs: "Progressive JPEG: not supported" / « JPEG progressif :
non pris en charge ». Spec §3.3 asks for an understandable message when the
file is too large or the JPEG variant is unsupported.

`FIMG_E_LIMIT` is reserved for internal limits. It is unreachable with a
validated configuration (scale factor search).

## 6. Limits and known behaviour

* Grey levels only. Colour is reduced to BT.601 luma, so a QR printed in a
  colour whose luma matches the background is invisible. That is inherent to
  QR scanning.
* Pillow (11–13) mishandles tRNS for 1/2/4-bit greyscale: it compares the key
  with the scaled sample. fimg follows the PNG specification (raw sample).
  The corpus reference follows the specification.
* An Adobe APP14 with transform 0, or 'R','G','B' component ids, is refused
  as RGB. Other 3-component files are treated as YCbCr, as libjpeg does.
* Out-of-specification coefficient streams make fimg clamp where libjpeg
  wraps. Their output is undefined in both decoders.
* EOI is required (`TRUNCATED` otherwise), even when all image data has been
  received. This is the strict reading of R06.
* An all-dark or flat image gives an all-light bitmap. See §2.5.

## 7. Tests and fuzzing

* `tests/c/fimg/gen_vectors.py` (Pillow + segno) regenerates the corpus in
  `tests/c/fimg/vectors/`: 286 entries and 2.1 MB, with `manifest.txt`
  describing each. It contains:
  * PNGs of every colour type and bit depth, and of every filter type at three
    pixel sizes.
  * PNGs with stored, fixed, Huffman-only, RLE and small-window deflate, and
    with 1-byte and prime-split IDATs.
  * PNGs with palette + tRNS, gray/RGB 8/16-bit colour keys, an invalid tRNS,
    a short palette, ancillary chunks and APNG.
  * 44 broken or unsupported PNGs.
  * JPEGs from Pillow: grey, 4:4:4, 4:2:2 and 4:2:0 at sizes from 1 × 1 to
    130 × 7, quality 1–100, optimised tables, restart markers (blocks and
    rows), EXIF and COM segments.
  * JPEGs from an in-house baseline encoder: 4:4:0, 16-bit DQT, combined
    DHT/DQT, fill bytes, separate and chroma-first scans, grey declared 2×2,
    no APP0 with a large COM, a restart every MCU.
  * 46 broken or unsupported JPEGs.
  * 67 raw zlib streams, of which 23 are invalid or truncated (hand-crafted).
  * 13 QR renders, from clean 1-bit to degraded photos and 1024² backups.
* `fimg_vectors` decodes every file with 5 chunkings and requires identical
  results: whole file, 1 byte, a prime cycle {7, 13, 251, 4093, 3, 1, 509},
  64-byte USB packets and pseudo-random sizes. It checks the status, the
  luma (exact for PNG, ±2 for JPEG; observed 0), luma CRCs, and QR
  agreement / module errors. It also decodes every file with a 100 × 90 /
  7000-pixel configuration. Zlib streams run through the inflater with
  1-byte input and 100-byte output limits.
* `fimg_unit` covers:
  * API misuse, sticky errors, workspace and bitmap sizing, misaligned
    workspaces, status names and categories.
  * Checksums, and exhaustive `div255`.
  * Inflater suspension (1 input byte, 7 output bytes per call).
  * Binarizer: white, black, checkerboard, a large dark square, dots on a
    gradient.
  * Eleven scale-factor cases.
  * The file-size limit (exact, ±1, trailing data, strict mode, 300 KiB
    ancillary chunk).
  * Worst-case PNGs: 1024² RGBA16, an exact +1-byte bomb, a 60 MB bomb.
  * Maximal JPEG COM segments larger than the staging buffer.
* Fuzzing: see `tests/fuzz/README-fimg.md`.
