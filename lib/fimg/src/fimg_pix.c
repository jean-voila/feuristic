// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Pixel pipeline: integer box downscaler + single-pass adaptive binarizer.
 *
 * Downscaler: the factor f is the smallest integer such that the output
 * (ceil(w/f) x ceil(h/f)) fits the configured maximum width, height and
 * pixel count. Each output pixel is the rounded mean of its f x f source
 * block (partial blocks at the right / bottom edges use their real size).
 * Memory: one u32 accumulator per output column.
 *
 * Binarizer: for output row y the local window is the (2r+1) x (2r+1)
 * square centred on the pixel, clipped to the image. A ring of K = 2r+1
 * output rows and running per-column sums of v and of round(v^2 / 256)
 * (both u16) give the window mean m and variance s^2 in O(1) per pixel
 * (horizontal sliding sums over the column sums). Rows are decided r rows
 * after they arrive; the last r rows are flushed when the final source row
 * is pushed. Decision for a pixel of value p:
 *
 *   p < m - delta                 -> dark   (clear local contrast)
 *   p > m + delta                 -> light
 *   otherwise, textured window    -> dark iff p < m   (s >= sigma_min)
 *   otherwise, flat window        -> dark iff m <= lo + c/4 and m <= hi/2,
 *                                    light when the image has no global
 *                                    contrast (c < 48) yet.
 *
 * lo / hi (= lo + c) are the dark and light class means of the iterative
 * intermeans (ISODATA) method on the histogram of every output row received
 * so far (rows up to y + r). The flat rule keeps large uniform dark areas
 * (e.g. finder-pattern centres of big modules) dark while shadowed paper
 * stays light. delta = max(12, c / 8), sigma_min = max(8, c / 16).
 * The radius is r = clamp(max(out_w, out_h) / 32, 4, 63) (window ~ 1/16 of
 * the image side).
 *
 * Arithmetic: window sums S <= 127^2 * 255 and Q <= 127^2 * 254 fit 32 bits;
 * the variance test n*256*Q - S^2 < sigma^2 * n^2 uses 32x32->64 bit
 * multiplications only (UMULL on Cortex-M), no 64-bit division.
 */
#include "fimg_internal.h"

#define FIMG_BIN_DELTA_MIN 12u
#define FIMG_BIN_DELTA_DIV 8u
#define FIMG_BIN_SIGMA_MIN 8u
#define FIMG_BIN_SIGMA_DIV 16u
#define FIMG_BIN_MIN_CONTRAST 48u

static uint32_t bin_radius(uint32_t dim) {
  uint32_t r = dim / FIMG_BIN_RDIV;
  if (r < FIMG_BIN_RMIN) r = FIMG_BIN_RMIN;
  if (r > FIMG_BIN_RMAX) r = FIMG_BIN_RMAX;
  return r;
}

static uint32_t sq8(uint32_t v) { return (v * v + 128u) >> 8; /* 0 .. 254 */ }

static size_t pix_block_sizes(const fimg_config_t *cfg, size_t *sizes,
                              int pad_pages) {
  uint32_t mw = cfg->max_out_width, mh = cfg->max_out_height;
  uint32_t k = 2u * bin_radius(mw > mh ? mw : mh) + 1u;
  uint32_t rows = FIMG_SCATTERED_BLOCK_MAX / mw;
  size_t count = 0;
  while (k != 0) {
    uint32_t take = k < rows ? k : rows;
    sizes[count++] = pad_pages && k > rows ? FIMG_SCATTERED_BLOCK_MAX
                                           : FIMG_ALIGN8((size_t)take * mw);
    k -= take;
  }
  sizes[count++] = FIMG_ALIGN8((size_t)mw * sizeof(uint16_t));
  sizes[count++] = FIMG_ALIGN8((size_t)mw * sizeof(uint16_t));
  sizes[count++] = FIMG_ALIGN8((size_t)mw * sizeof(uint32_t));
  return count;
}

size_t fimg_pix_block_sizes(const fimg_config_t *cfg, size_t *sizes) {
  return pix_block_sizes(cfg, sizes, 1);
}

size_t fimg_pix_heap_size(const fimg_config_t *cfg) {
  size_t sizes[FIMG_SCATTERED_MAX_BLOCKS], total = 0;
  size_t count = pix_block_sizes(cfg, sizes, 0);
  for (size_t i = 0; i < count; i++) total += sizes[i];
  return total;
}

static uint8_t *ring_row(const fimg_pix_t *p, uint32_t row) {
  row %= p->k;
  return p->ring[row / p->ring_rows] + (size_t)(row % p->ring_rows) * p->out_w;
}

fimg_status_t fimg_pix_setup(fimg_ctx_t *ctx, uint32_t w, uint32_t h) {
  fimg_pix_t *p = &ctx->pix;
  uint32_t f, ow = 0, oh = 0;

  if (p->ready || w == 0 || h == 0 || w > FIMG_MAX_DIM || h > FIMG_MAX_DIM)
    return FIMG_E_INTERNAL;
  for (f = 1; f <= FIMG_MAX_DIM; f++) {
    ow = (w + f - 1u) / f;
    oh = (h + f - 1u) / f;
    if (ow <= ctx->cfg.max_out_width && oh <= ctx->cfg.max_out_height &&
        ow * oh <= ctx->max_pixels)
      break;
  }
  if (f > FIMG_MAX_DIM)
    return FIMG_E_LIMIT; /* unreachable with a validated configuration */

  memset(p, 0, sizeof *p);
  p->src_w = w;
  p->src_h = h;
  p->f = f;
  p->out_w = ow;
  p->out_h = oh;
  p->stride = (ow + 7u) / 8u;
  if ((size_t)p->stride * oh > ctx->bitmap_size) return FIMG_E_INTERNAL;
  p->r = bin_radius(ow > oh ? ow : oh);
  p->k = 2u * p->r + 1u;
  p->ring_rows = FIMG_SCATTERED_BLOCK_MAX / ow;
  uint32_t remaining = p->k;
  for (size_t i = 0; remaining != 0; i++) {
    uint32_t take = remaining < p->ring_rows ? remaining : p->ring_rows;
    if (i >= sizeof p->ring / sizeof p->ring[0]) return FIMG_E_INTERNAL;
    p->ring[i] = (uint8_t *)fimg_alloc(ctx, (size_t)take * ow);
    if (p->ring[i] == NULL) return FIMG_E_INTERNAL;
    remaining -= take;
  }
  p->colsum = (uint16_t *)fimg_alloc(ctx, (size_t)ow * sizeof(uint16_t));
  p->colsq = (uint16_t *)fimg_alloc(ctx, (size_t)ow * sizeof(uint16_t));
  p->acc = (uint32_t *)fimg_alloc(ctx, (size_t)ow * sizeof(uint32_t));
  if (p->colsum == NULL || p->colsq == NULL || p->acc == NULL)
    return FIMG_E_INTERNAL;
  memset(p->colsum, 0, (size_t)ow * sizeof(uint16_t));
  memset(p->colsq, 0, (size_t)ow * sizeof(uint16_t));
  memset(p->acc, 0, (size_t)ow * sizeof(uint32_t));
  p->bitmap = ctx->bitmap;
  memset(p->bitmap, 0, (size_t)p->stride * oh);
  p->ready = 1;
  return FIMG_OK;
}

static void ring_remove_oldest(fimg_pix_t *p) {
  const uint8_t *q = ring_row(p, p->lo);
  uint16_t *cs = p->colsum, *cq = p->colsq;
  for (uint32_t x = 0; x < p->out_w; x++) {
    cs[x] = (uint16_t)(cs[x] - q[x]);
    cq[x] = (uint16_t)(cq[x] - sq8(q[x]));
  }
  p->lo++;
}

/* Global class means by iterative intermeans on the running histogram. */
static void update_global(fimg_pix_t *p) {
  uint32_t n = 0, s = 0, t, it, v;

  for (v = 0; v < 256u; v++) {
    n += p->hist[v];
    s += p->hist[v] * v;
  }
  p->gcontrast = 0;
  p->gmlo = 0;
  if (n == 0) return;
  t = s / n;
  for (it = 0; it < 8u; it++) {
    uint32_t nlo = 0, slo = 0, t2, mlo, mhi;
    for (v = 0; v <= t; v++) {
      nlo += p->hist[v];
      slo += p->hist[v] * v;
    }
    if (nlo == 0 || nlo == n) break; /* unimodal: no contrast */
    mlo = slo / nlo;
    mhi = (s - slo) / (n - nlo);
    p->gcontrast = mhi - mlo;
    p->gmlo = mlo;
    t2 = (mlo + mhi) / 2u;
    if (t2 == t) break;
    t = t2;
  }
}

static void decide_row(fimg_pix_t *p) {
  const uint32_t y = p->rows_out, r = p->r, w = p->out_w;
  const uint32_t lo_t = y >= r ? y - r : 0u;
  const uint8_t *px;
  const uint16_t *cs = p->colsum, *cq = p->colsq;
  uint8_t *dst;
  uint32_t nrows, x, s = 0, q = 0, ncols, delta, sigma, gvalid, gt, ghi;

  while (p->lo < lo_t) ring_remove_oldest(p);
  nrows = p->rows_in - p->lo;
  px = ring_row(p, y);
  dst = p->bitmap + (size_t)y * p->stride;
  memset(dst, 0, p->stride);

  update_global(p);
  gvalid = p->gcontrast >= FIMG_BIN_MIN_CONTRAST;
  /* flat areas: dark only at a quarter of the way from the dark to the
   * light level and below half the light level (ink, not shadowed paper) */
  gt = p->gmlo + p->gcontrast / 4u;
  ghi = p->gmlo + p->gcontrast;
  delta = p->gcontrast / FIMG_BIN_DELTA_DIV;
  if (delta < FIMG_BIN_DELTA_MIN) delta = FIMG_BIN_DELTA_MIN;
  sigma = p->gcontrast / FIMG_BIN_SIGMA_DIV;
  if (sigma < FIMG_BIN_SIGMA_MIN) sigma = FIMG_BIN_SIGMA_MIN;

  ncols = (r + 1u < w) ? r + 1u : w;
  for (x = 0; x < ncols; x++) {
    s += cs[x];
    q += cq[x];
  }
  for (x = 0; x < w; x++) {
    const uint32_t n = ncols * nrows, v = px[x];
    const uint32_t pn = v * n, dn = delta * n;
    uint32_t dark;
    if (pn + dn < s) {
      dark = 1;
    } else if (pn > s + dn) {
      dark = 0;
    } else if ((uint64_t)n * q * 256u >=
               (uint64_t)s * s + (uint64_t)(sigma * sigma) * n * n) {
      dark = pn < s; /* textured window: plain local mean */
    } else {
      dark = gvalid && s <= gt * n && 2u * s <= ghi * n; /* flat window */
    }
    if (dark) dst[x >> 3] |= (uint8_t)(0x80u >> (x & 7u));
    if (x + r + 1u < w) {
      s += cs[x + r + 1u];
      q += cq[x + r + 1u];
      ncols++;
    }
    if (x >= r) {
      s -= cs[x - r];
      q -= cq[x - r];
      ncols--;
    }
  }
  p->rows_out++;
}

/* Make room for output row rows_in and return its ring slot. */
static uint8_t *ring_slot(fimg_pix_t *p) {
  while (p->lo + p->k <= p->rows_in) ring_remove_oldest(p);
  return ring_row(p, p->rows_in);
}

static void ring_commit(fimg_pix_t *p) {
  const uint8_t *q = ring_row(p, p->rows_in);
  uint16_t *cs = p->colsum, *cq = p->colsq;
  for (uint32_t x = 0; x < p->out_w; x++) {
    cs[x] = (uint16_t)(cs[x] + q[x]);
    cq[x] = (uint16_t)(cq[x] + sq8(q[x]));
    p->hist[q[x]]++;
  }
  p->rows_in++;
  if (p->rows_in > p->r) decide_row(p);
  if (p->rows_in == p->out_h)
    while (p->rows_out < p->out_h) decide_row(p);
}

fimg_status_t fimg_pix_push(fimg_ctx_t *ctx, const uint8_t *row) {
  fimg_pix_t *p = &ctx->pix;
  const uint32_t f = p->f, sw = p->src_w;
  uint32_t ox, x;
  uint8_t *slot;

  if (!p->ready || p->src_rows >= p->src_h) return FIMG_E_INTERNAL;
  if (ctx->cfg.luma_cb != NULL)
    ctx->cfg.luma_cb(ctx->cfg.luma_cb_user, p->src_rows, row, sw);
  p->src_rows++;

  if (f == 1u) {
    slot = ring_slot(p);
    memcpy(slot, row, sw);
    ring_commit(p);
    return FIMG_OK;
  }
  x = 0;
  for (ox = 0; ox < p->out_w; ox++) {
    uint32_t end = x + f, sum = 0;
    if (end > sw) end = sw;
    for (; x < end; x++) sum += row[x];
    p->acc[ox] += sum;
  }
  p->band_rows++;
  if (p->band_rows == f || p->src_rows == p->src_h) {
    slot = ring_slot(p);
    for (ox = 0; ox < p->out_w; ox++) {
      uint32_t cx = (ox + 1u == p->out_w) ? sw - ox * f : f;
      uint32_t cnt = cx * p->band_rows;
      slot[ox] = (uint8_t)((p->acc[ox] + cnt / 2u) / cnt);
      p->acc[ox] = 0;
    }
    p->band_rows = 0;
    ring_commit(p);
  }
  return FIMG_OK;
}

int fimg_pix_complete(const fimg_ctx_t *ctx) {
  const fimg_pix_t *p = &ctx->pix;
  return p->ready && p->src_rows == p->src_h && p->rows_out == p->out_h;
}
