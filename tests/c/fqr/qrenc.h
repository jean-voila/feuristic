// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Test-only QR code encoder and renderer.
 *
 * It builds arbitrary (including deliberately malformed) bit streams, adds
 * Reed-Solomon codewords, places them with any mask and renders the module
 * matrix into 1-bpp bitmaps under arbitrary projective transforms. Its
 * placement, masking and BCH code are implemented independently of the
 * decoder; only the ISO block table is shared (that table is verified
 * against segno by lib/fqr/tools/gen_tables.py and by the corpus).
 */

#ifndef FQR_QRENC_H
#define FQR_QRENC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define QE_MAX_BITS (3706u * 8u + 64u)
#define QE_GRID_STRIDE 23u
#define QE_GRID_BYTES (177u * QE_GRID_STRIDE)

typedef struct {
  uint8_t buf[QE_MAX_BITS / 8u + 8u];
  size_t nbits;
  bool overflow;
} qe_bits_t;

void qe_bits_init(qe_bits_t *b);
void qe_put(qe_bits_t *b, uint32_t val, unsigned n);

unsigned qe_count_bits(unsigned mode, unsigned version);
void qe_seg_numeric(qe_bits_t *b, unsigned version, const char *digits,
                    size_t n);
void qe_seg_alnum(qe_bits_t *b, unsigned version, const char *s, size_t n);
void qe_seg_byte(qe_bits_t *b, unsigned version, const uint8_t *p, size_t n);
/* sjis: n_chars two-byte Shift JIS characters. */
void qe_seg_kanji(qe_bits_t *b, unsigned version, const uint8_t *sjis,
                  size_t n_chars);
void qe_seg_eci(qe_bits_t *b, uint32_t designator);
void qe_seg_sa(qe_bits_t *b, unsigned index, unsigned total, unsigned parity);
void qe_fnc1_first(qe_bits_t *b);
void qe_fnc1_second(qe_bits_t *b, unsigned app);

/* Number of data codewords for version / level (0 = L, 1 = M, 2 = Q, 3 = H). */
unsigned qe_data_codewords(unsigned version, unsigned level);

/* Adds the terminator and pad codewords; false if the stream is too long. */
bool qe_finalize(const qe_bits_t *b, unsigned version, unsigned level,
                 uint8_t *data_cw);

/* Builds the complete module matrix (size 17 + 4 * version) into grid. */
void qe_build(const uint8_t *data_cw, unsigned version, unsigned level,
              unsigned mask, uint8_t *grid, size_t stride);

/* Same, from an interleaved codeword sequence (data + EC) that may have
 * been corrupted on purpose. */
void qe_build_cw(const uint8_t *cw, size_t ncw, unsigned version,
                 unsigned level, unsigned mask, uint8_t *grid, size_t stride);

/* Index in the interleaved sequence of codeword `off` of block `blk`. */
size_t qe_interleaved_index(unsigned version, unsigned level, unsigned blk,
                            unsigned off);

/* Interleaved codeword sequence (data + EC), as placed in the symbol. */
size_t qe_codewords(const uint8_t *data_cw, unsigned version, unsigned level,
                    uint8_t *out);

/* Convenience: byte-mode payload, smallest version >= min_version that fits. */
bool qe_make_bytes(const uint8_t *p, size_t n, unsigned min_version,
                   unsigned level, int mask, uint8_t *grid,
                   unsigned *version_out);

static inline int qe_get(const uint8_t *g, size_t stride, unsigned r,
                         unsigned c) {
  return (g[(size_t)r * stride + (c >> 3)] >> (7u - (c & 7u))) & 1;
}
static inline void qe_set(uint8_t *g, size_t stride, unsigned r, unsigned c,
                          int v) {
  uint8_t m = (uint8_t)(0x80u >> (c & 7u));
  if (v) {
    g[(size_t)r * stride + (c >> 3)] |= m;
  } else {
    g[(size_t)r * stride + (c >> 3)] &= (uint8_t)~m;
  }
}

/* ---- images ---- */

typedef struct {
  uint8_t *data;
  uint32_t w, h;
  size_t stride;
} qe_img_t;

bool qe_img_alloc(qe_img_t *img, uint32_t w, uint32_t h);
void qe_img_free(qe_img_t *img);
void qe_img_fill(qe_img_t *img, int dark);
static inline void qe_img_set(qe_img_t *img, uint32_t x, uint32_t y, int dark) {
  uint8_t m = (uint8_t)(0x80u >> (x & 7u));
  uint8_t *p = &img->data[(size_t)y * img->stride + (x >> 3)];
  *p = dark ? (uint8_t)(*p | m) : (uint8_t)(*p & ~m);
}
static inline int qe_img_get(const qe_img_t *img, uint32_t x, uint32_t y) {
  return (img->data[(size_t)y * img->stride + (x >> 3)] >> (7u - (x & 7u))) & 1;
}

/*
 * Renders the symbol so that module-space corners (0,0), (dim,0), (dim,dim),
 * (0,dim) land on corners[0..7] (x0,y0,..,x3,y3). The quiet zone (modules)
 * is light (dark when inverted); pixels beyond it are left untouched.
 */
bool qe_render(qe_img_t *img, const uint8_t *grid, size_t gstride, unsigned dim,
               const float corners[8], unsigned quiet, bool invert);

/* Axis-aligned rendering at integer scale with top-left module at (x, y). */
void qe_render_scaled(qe_img_t *img, const uint8_t *grid, size_t gstride,
                      unsigned dim, uint32_t x, uint32_t y, uint32_t scale,
                      unsigned quiet, bool invert);

/* Rotated / perspective corners helper: centre (cx, cy), side s pixels,
 * rotation angle in degrees, and a perspective "tilt" factor (0 = none). */
void qe_corners(float out[8], float cx, float cy, float side, float angle_deg,
                float tilt_x, float tilt_y);

#endif /* FQR_QRENC_H */
