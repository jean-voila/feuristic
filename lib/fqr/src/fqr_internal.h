// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/**
 * @file fqr_internal.h
 * @brief Internal interfaces of lib/fqr (not part of the public API).
 *
 * Conventions:
 *  - Image coordinates are continuous: pixel (x, y) covers [x, x+1) x [y, y+1).
 *  - Module coordinates are continuous too: module (col c, row r) covers
 *    [c, c+1) x [r, r+1); its centre is (c + 0.5, r + 0.5).
 *  - "dark" is the logical colour after the optional polarity inversion.
 *  - Only single-precision float is used (no double, no libm).
 */

#ifndef FQR_INTERNAL_H
#define FQR_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fqr.h"

/* ------------------------------------------------------------------------ */
/* Compile-time helpers                                                     */
/* ------------------------------------------------------------------------ */

#define FQR_STATIC_ASSERT(cond, name) \
  typedef char fqr_static_assert_##name[(cond) ? 1 : -1]

#define FQR_MAX_ALIGN_PER_AXIS 7
#define FQR_MAX_ALIGN (FQR_MAX_ALIGN_PER_AXIS * FQR_MAX_ALIGN_PER_AXIS)
#define FQR_GRID_STRIDE \
  ((FQR_MAX_MODULES + 7u) / 8u) /* 23 bytes per module row */
#define FQR_GRID_BYTES (FQR_MAX_MODULES * FQR_GRID_STRIDE)
#define FQR_MAX_CODEWORDS 3706u /* version 40 */
#define FQR_MAX_EC_PER_BLOCK 30u
/* Longest Reed-Solomon block (data + EC) in any version. */
#define FQR_MAX_BLOCK_LEN 153u
#define FQR_MAX_CANDIDATES 96u /* finder candidates kept per polarity pass */
#define FQR_MAX_TRIPLES 32u    /* finder triples kept (best scores) per pass */
#define FQR_TRIPLE_POOL 24u    /* candidates entering triple enumeration */
#define FQR_DEFAULT_WORK 600000u /* default work budget (~modules sampled) */

/* ------------------------------------------------------------------------ */
/* Generated ISO/IEC 18004 tables (fqr_tables.c)                            */
/* ------------------------------------------------------------------------ */

extern const uint8_t fqr_gf_exp[512];
extern const uint8_t fqr_gf_log[256];
extern const uint8_t fqr_ecc_per_block[4][41];
extern const uint8_t fqr_num_blocks[4][41];
extern const uint16_t fqr_total_codewords[41];
extern const uint8_t fqr_remainder_bits[41];
extern const uint8_t fqr_align_pos[41][FQR_MAX_ALIGN_PER_AXIS];
extern const uint16_t fqr_format_codewords[32];
extern const uint32_t fqr_version_codewords[34];

/** Number of alignment coordinates per axis for @p version (0 for v1). */
static inline unsigned fqr_align_count(unsigned version) {
  return version < 2u ? 0u : version / 7u + 2u;
}

/* ------------------------------------------------------------------------ */
/* Float helpers (no libm)                                                  */
/* ------------------------------------------------------------------------ */

static inline float fqr_absf(float x) { return x < 0.0f ? -x : x; }
static inline float fqr_minf(float a, float b) { return a < b ? a : b; }
static inline float fqr_maxf(float a, float b) { return a > b ? a : b; }

/** True for finite values (false for NaN and +/-inf). */
static inline bool fqr_finite(float x) {
  return x == x && x > -3.0e38f && x < 3.0e38f;
}

/** True if @p x is finite and within [lo, hi]. */
static inline bool fqr_in_range(float x, float lo, float hi) {
  return x >= lo && x <= hi;
}

/**
 * Floor to int for values already known to be within +/- 1e6 (checked by
 * the caller); returns INT32_MIN-safe sentinel -2^30 for anything else so
 * that no float-to-int conversion is ever undefined.
 */
static inline int32_t fqr_floori(float x) {
  if (!(x > -1.0e6f && x < 1.0e6f)) {
    return -(1 << 30);
  }
  int32_t i = (int32_t)x;
  if ((float)i > x) {
    i--;
  }
  return i;
}

static inline int32_t fqr_roundi(float x) { return fqr_floori(x + 0.5f); }

float fqr_sqrtf(float x);

static inline float fqr_dist(float ax, float ay, float bx, float by) {
  float dx = ax - bx, dy = ay - by;
  return fqr_sqrtf(dx * dx + dy * dy);
}

/* ------------------------------------------------------------------------ */
/* Bitmap access                                                            */
/* ------------------------------------------------------------------------ */

/** Internal view of the input image with polarity and instrumentation. */
typedef struct {
  const uint8_t *data;
  int32_t w;
  int32_t h;
  size_t stride;
  uint8_t inv;      /**< 0 or 1: XORed into every pixel. */
  uint8_t inv_byte; /**< 0x00 or 0xFF. */
  fqr_stats_t *st;  /**< Never NULL inside the library. */
  uint32_t *work;   /**< Work counter (budget units), never NULL. */
  /** Read a virtual majority-filtered image (each pixel = majority of its
   *  3x3 neighbourhood): removes salt-and-pepper noise and 1-pixel lines
   *  (e.g. the dark gaps between OLED pixels in a photo) but also 1-pixel
   *  details, hence only used by the fallback scan. */
  uint8_t filter;
} fqr_bm_t;

/** Raw logical pixel; out-of-image pixels are light (0) in both polarities. */
static inline int fqr_px_raw(const fqr_bm_t *b, int32_t x, int32_t y) {
  if (x < 0 || y < 0 || x >= b->w || y >= b->h) {
    return 0;
  }
  unsigned v = b->data[(size_t)y * b->stride + ((uint32_t)x >> 3)];
  return (int)(((v >> (7u - ((uint32_t)x & 7u))) & 1u) ^ b->inv);
}

/** Logical pixel as seen by the detector (filtered when b->filter). */
static inline int fqr_px(const fqr_bm_t *b, int32_t x, int32_t y) {
  if (!b->filter) {
    return fqr_px_raw(b, x, y);
  }
  if (x < 0 || y < 0 || x >= b->w || y >= b->h) {
    return 0;
  }
  int s = 0;
  for (int32_t dy = -1; dy <= 1; dy++) {
    for (int32_t dx = -1; dx <= 1; dx++) {
      s += fqr_px_raw(b, x + dx, y + dy);
    }
  }
  return s >= 5;
}

/** Pixel at a continuous position (light if outside or not finite). */
static inline int fqr_px_f(const fqr_bm_t *b, float x, float y) {
  if (!(x >= 0.0f && y >= 0.0f && x < (float)b->w && y < (float)b->h)) {
    return 0;
  }
  return fqr_px(b, (int32_t)x, (int32_t)y);
}

/* ------------------------------------------------------------------------ */
/* Run tracker                                                              */
/* ------------------------------------------------------------------------ */

/** History of the last completed runs of a scan line; r[7] is the most
 *  recent one and has the colour of the run just completed (runs alternate). */
typedef struct {
  uint32_t r[8];
  uint32_t n; /**< Completed runs (saturates at 8). */
} fqr_runs_t;

static inline void fqr_runs_reset(fqr_runs_t *t) { memset(t, 0, sizeof *t); }

static inline void fqr_runs_push(fqr_runs_t *t, uint32_t len) {
  t->r[0] = t->r[1];
  t->r[1] = t->r[2];
  t->r[2] = t->r[3];
  t->r[3] = t->r[4];
  t->r[4] = t->r[5];
  t->r[5] = t->r[6];
  t->r[6] = t->r[7];
  t->r[7] = len;
  if (t->n < 8u) {
    t->n++;
  }
}

/* ------------------------------------------------------------------------ */
/* Perspective transform (fqr_geom.c)                                       */
/* ------------------------------------------------------------------------ */

/** Projective map: x = (m0 u + m1 v + m2) / w, y = (m3 u + m4 v + m5) / w,
 *  w = m6 u + m7 v + m8. */
typedef struct {
  float m[9];
} fqr_xform_t;

/**
 * Build the transform mapping quad (u0,v0)..(u3,v3) onto (x0,y0)..(x3,y3)
 * (point order around the quad must match). Returns false if degenerate.
 */
bool fqr_xform_quad(fqr_xform_t *t, const float src[8], const float dst[8]);

/** Apply @p t to (u, v). Returns false if the result is not finite/valid. */
bool fqr_xform_apply(const fqr_xform_t *t, float u, float v, float *x,
                     float *y);

/* ------------------------------------------------------------------------ */
/* Reed-Solomon (fqr_rs.c)                                                  */
/* ------------------------------------------------------------------------ */

/**
 * Correct one RS block in place over GF(256)/0x11D, generator roots
 * alpha^0 .. alpha^(ec-1), codeword[0] is the highest-degree coefficient.
 *
 * @param blk      Block of @p n codewords (data followed by EC).
 * @param n        1 .. 255, n > ec.
 * @param ec       1 .. FQR_MAX_EC_PER_BLOCK.
 * @param max_err  Maximum number of errors to correct (<= ec / 2).
 * @return number of corrected codewords (>= 0) or -1 if uncorrectable.
 */
int fqr_rs_correct(uint8_t *blk, unsigned n, unsigned ec, unsigned max_err);

/* ------------------------------------------------------------------------ */
/* BCH helpers and grid decoding (fqr_matrix.c)                             */
/* ------------------------------------------------------------------------ */

/** Decode 15 format bits; returns the 5 data bits or -1, distance in *dist. */
int fqr_bch_format(uint32_t bits, unsigned *dist);

/** Decode 18 version bits; returns the version 7..40 or -1, distance in *dist.
 */
int fqr_bch_version(uint32_t bits, unsigned *dist);

/** Map format level bits (M=0 L=1 H=2 Q=3) to fqr_ecc_level_t. */
static inline uint8_t fqr_level_from_bits(unsigned b) {
  static const uint8_t map[4] = {FQR_ECC_M, FQR_ECC_L, FQR_ECC_H, FQR_ECC_Q};
  return map[b & 3u];
}

/** True if module (row r, col c) belongs to a function pattern. */
bool fqr_is_function_module(unsigned version, unsigned r, unsigned c);

/** Internal decoding outcomes ordered by how far decoding progressed. */
typedef enum {
  FQR_STAGE_NONE = 0,
  FQR_STAGE_FORMAT = 1, /* failed at format / version information */
  FQR_STAGE_ECC = 2,    /* failed Reed-Solomon */
  FQR_STAGE_DATA = 3,   /* failed bit-stream parsing */
  FQR_STAGE_OK = 4,
} fqr_stage_t;

/**
 * Decode a sampled module grid.
 *
 * @param grid      Module bits (row-major, MSB first, 1 = dark).
 * @param stride    Bytes per grid row.
 * @param size      Modules per side (validated: 21..177, %4 == 1).
 * @param mirrored  Read the grid transposed.
 * @param cw        Scratch of FQR_MAX_CODEWORDS bytes.
 * @param res       Result (payload/payload_cap used; metadata filled).
 * @param overflow  Out: true if the payload did not fit.
 * @return stage reached (FQR_STAGE_OK on success).
 */
fqr_stage_t fqr_decode_grid(const uint8_t *grid, size_t stride, unsigned size,
                            bool mirrored, uint8_t *cw, fqr_result_t *res,
                            bool *overflow, fqr_stats_t *st);

/* ------------------------------------------------------------------------ */
/* Bit-stream parsing (fqr_bits.c)                                          */
/* ------------------------------------------------------------------------ */

/**
 * Parse the data segments of an error-corrected data codeword sequence.
 * Writes the payload to res->payload (up to res->payload_cap; the required
 * length is always computed) and fills the segment metadata of @p res.
 *
 * @return FQR_STAGE_OK or FQR_STAGE_DATA. *overflow tells whether the
 *         payload exceeded the capacity.
 */
fqr_stage_t fqr_parse_segments(const uint8_t *data, size_t ndata,
                               unsigned version, fqr_result_t *res,
                               bool *overflow);

/* ------------------------------------------------------------------------ */
/* Finder patterns (fqr_finder.c)                                           */
/* ------------------------------------------------------------------------ */

typedef struct {
  float x;
  float y;
  float ms;       /**< Estimated module size in pixels. */
  uint16_t count; /**< Number of confirming observations. */
  uint16_t flags; /**< FQR_CAND_* */
} fqr_cand_t;

enum { FQR_CAND_USED = 1u };

typedef struct {
  fqr_cand_t c[FQR_MAX_CANDIDATES];
  uint32_t n;
} fqr_cand_list_t;

/** Bytes per filtered row buffer. */
#define FQR_ROWBUF_BYTES (FQR_MAX_IMAGE_DIM / 8u)

/**
 * Logical row y of the 3x3-majority-filtered image (identical to fqr_px()
 * with b->filter set), computed 8 pixels at a time with bit-sliced adders.
 * @p out receives (w + 7) / 8 bytes, bits beyond the width cleared.
 */
void fqr_filter_row(const fqr_bm_t *b, int32_t y, uint8_t *out);

/** Scan the whole image for finder pattern candidates. @p rowbuf: scratch of
 *  FQR_ROWBUF_BYTES bytes (used when b->filter is set). */
void fqr_find_candidates(const fqr_bm_t *b, fqr_cand_list_t *list,
                         uint8_t *rowbuf);

/**
 * Module size estimate from black-white-black runs between two finder
 * centres (ZXing's method). Returns <= 0 on failure.
 */
float fqr_module_size_between(const fqr_bm_t *b, float ax, float ay, float bx,
                              float by);

/**
 * Fit the local axes of the finder pattern centred at (cx, cy) from its
 * outer edges. @p u and @p v are approximate unit axes (towards the
 * top-right and bottom-left finders); @p hu / @p hv receive the fitted unit
 * directions of the pattern's module rows / columns (unchanged when an edge
 * pair cannot be fitted). Returns a bitmask: 1 = hu fitted, 2 = hv fitted.
 */
unsigned fqr_finder_axes(const fqr_bm_t *b, float cx, float cy, float ms,
                         const float u[2], const float v[2], float hu[2],
                         float hv[2]);

/**
 * Count timing-pattern transitions along the image segment (x0,y0)-(x1,y1),
 * ignoring runs shorter than @p min_run pixels. Returns the count.
 */
uint32_t fqr_count_transitions(const fqr_bm_t *b, float x0, float y0, float x1,
                               float y1, float min_run);

/* ------------------------------------------------------------------------ */
/* Alignment patterns (fqr_align.c)                                         */
/* ------------------------------------------------------------------------ */

/**
 * Search an alignment pattern whose module-space centre is (mu, mv) under
 * transform @p t, within @p radius modules of the predicted position.
 * Candidates are verified against the full 5x5 template.
 *
 * @param ms   Module size in pixels.
 * @param out  Located centre in image coordinates.
 * @return true if a verified pattern was found.
 */
bool fqr_find_alignment(const fqr_bm_t *b, const fqr_xform_t *t, float mu,
                        float mv, float ms, float radius, fqr_point_t *out);

/* ------------------------------------------------------------------------ */
/* Workspace                                                                */
/* ------------------------------------------------------------------------ */

typedef struct {
  uint8_t a, b, c; /**< Candidate indices: top-left, top-right, bottom-left. */
  float score;     /**< Lower is better. */
} fqr_triple_t;

typedef struct {
  fqr_point_t q[4]; /**< Corners TL, TR, BR, BL. */
} fqr_quad_t;

typedef struct {
  uint8_t grid[FQR_GRID_BYTES];  /**< Sampled modules. */
  uint8_t cw[FQR_MAX_CODEWORDS]; /**< Codewords (de-interleaved, corrected). */
  fqr_cand_list_t cands;
  fqr_triple_t triples[FQR_MAX_TRIPLES];
  fqr_quad_t found[FQR_MAX_CODES];
  fqr_point_t align[FQR_MAX_ALIGN];
  uint8_t align_ok[FQR_MAX_ALIGN];
  uint8_t rowbuf[FQR_ROWBUF_BYTES];
  uint32_t n_triples;
  uint32_t n_found;
} fqr_ws_t;

/* +8 bytes of slack for aligning an arbitrary workspace pointer. */
FQR_STATIC_ASSERT(sizeof(fqr_ws_t) + 8u <= FQR_WORKSPACE_SIZE, workspace_fits);

#endif /* FQR_INTERNAL_H */
