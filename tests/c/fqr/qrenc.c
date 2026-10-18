// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* Test-only QR encoder / renderer. See qrenc.h. */

#include "qrenc.h"

#include <math.h>
#include <stdlib.h>
#include <string.h>

#include "fqr_internal.h"

/* ---------------- bits ---------------- */

void qe_bits_init(qe_bits_t *b) { memset(b, 0, sizeof *b); }

void qe_put(qe_bits_t *b, uint32_t val, unsigned n) {
  for (unsigned i = n; i-- > 0;) {
    if (b->nbits >= QE_MAX_BITS) {
      b->overflow = true;
      return;
    }
    if ((val >> i) & 1u) {
      b->buf[b->nbits >> 3] |= (uint8_t)(0x80u >> (b->nbits & 7u));
    }
    b->nbits++;
  }
}

unsigned qe_count_bits(unsigned mode, unsigned version) {
  unsigned g = version <= 9u ? 0u : (version <= 26u ? 1u : 2u);
  static const unsigned t[4][3] = {
      {10, 12, 14}, {9, 11, 13}, {8, 16, 16}, {8, 10, 12}};
  switch (mode) {
    case 1:
      return t[0][g];
    case 2:
      return t[1][g];
    case 4:
      return t[2][g];
    default:
      return t[3][g];
  }
}

void qe_seg_numeric(qe_bits_t *b, unsigned version, const char *d, size_t n) {
  qe_put(b, 1, 4);
  qe_put(b, (uint32_t)n, qe_count_bits(1, version));
  size_t i = 0;
  for (; i + 3 <= n; i += 3) {
    qe_put(b,
           (uint32_t)((d[i] - '0') * 100 + (d[i + 1] - '0') * 10 +
                      (d[i + 2] - '0')),
           10);
  }
  if (n - i == 2) {
    qe_put(b, (uint32_t)((d[i] - '0') * 10 + (d[i + 1] - '0')), 7);
  } else if (n - i == 1) {
    qe_put(b, (uint32_t)(d[i] - '0'), 4);
  }
}

static unsigned alnum_val(char c) {
  static const char *tab = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
  const char *p = strchr(tab, c);
  return p != NULL && c != '\0' ? (unsigned)(p - tab) : 0u;
}

void qe_seg_alnum(qe_bits_t *b, unsigned version, const char *s, size_t n) {
  qe_put(b, 2, 4);
  qe_put(b, (uint32_t)n, qe_count_bits(2, version));
  size_t i = 0;
  for (; i + 2 <= n; i += 2) {
    qe_put(b, alnum_val(s[i]) * 45u + alnum_val(s[i + 1]), 11);
  }
  if (i < n) {
    qe_put(b, alnum_val(s[i]), 6);
  }
}

void qe_seg_byte(qe_bits_t *b, unsigned version, const uint8_t *p, size_t n) {
  qe_put(b, 4, 4);
  qe_put(b, (uint32_t)n, qe_count_bits(4, version));
  for (size_t i = 0; i < n; i++) {
    qe_put(b, p[i], 8);
  }
}

void qe_seg_kanji(qe_bits_t *b, unsigned version, const uint8_t *sj,
                  size_t n_chars) {
  qe_put(b, 8, 4);
  qe_put(b, (uint32_t)n_chars, qe_count_bits(8, version));
  for (size_t i = 0; i < n_chars; i++) {
    unsigned v = ((unsigned)sj[2 * i] << 8) | sj[2 * i + 1];
    v -= (v <= 0x9FFCu) ? 0x8140u : 0xC140u;
    qe_put(b, (v >> 8) * 0xC0u + (v & 0xFFu), 13);
  }
}

void qe_seg_eci(qe_bits_t *b, uint32_t d) {
  qe_put(b, 7, 4);
  if (d < 128u) {
    qe_put(b, d, 8);
  } else if (d < 16384u) {
    qe_put(b, 0x8000u | d, 16);
  } else {
    qe_put(b, 0xC00000u | d, 24);
  }
}

void qe_seg_sa(qe_bits_t *b, unsigned index, unsigned total, unsigned parity) {
  qe_put(b, 3, 4);
  qe_put(b, index, 4);
  qe_put(b, total - 1u, 4);
  qe_put(b, parity, 8);
}

void qe_fnc1_first(qe_bits_t *b) { qe_put(b, 5, 4); }

void qe_fnc1_second(qe_bits_t *b, unsigned app) {
  qe_put(b, 9, 4);
  qe_put(b, app, 8);
}

/* ---------------- RS + structure ---------------- */

static uint8_t gmul(uint8_t a, uint8_t b) {
  /* Bitwise multiplication: independent of the decoder's tables. */
  unsigned r = 0, x = a;
  for (unsigned i = 0; i < 8u; i++) {
    if ((b >> i) & 1u) {
      r ^= x << i;
    }
  }
  for (unsigned i = 15; i >= 8u; i--) {
    if ((r >> i) & 1u) {
      r ^= 0x11Du << (i - 8u);
    }
  }
  return (uint8_t)r;
}

static void rs_encode(const uint8_t *data, unsigned nd, unsigned ec,
                      uint8_t *out) {
  uint8_t gen[32];
  memset(gen, 0, sizeof gen);
  gen[0] = 1; /* gen[i] = coefficient of x^(deg - i), monic */
  unsigned deg = 0;
  uint8_t root = 1;
  for (unsigned i = 0; i < ec; i++) {
    /* multiply by (x - root) */
    gen[deg + 1] = 0;
    for (unsigned k = deg + 1; k > 0; k--) {
      gen[k] = (uint8_t)(gen[k] ^ gmul(gen[k - 1], root));
    }
    deg++;
    root = gmul(root, 2);
  }
  memset(out, 0, ec);
  for (unsigned i = 0; i < nd; i++) {
    uint8_t f = (uint8_t)(data[i] ^ out[0]);
    memmove(out, out + 1, ec - 1u);
    out[ec - 1u] = 0;
    for (unsigned k = 0; k < ec; k++) {
      out[k] = (uint8_t)(out[k] ^ gmul(gen[k + 1], f));
    }
  }
}

unsigned qe_data_codewords(unsigned version, unsigned level) {
  return fqr_total_codewords[version] -
         fqr_num_blocks[level][version] * fqr_ecc_per_block[level][version];
}

bool qe_finalize(const qe_bits_t *b, unsigned version, unsigned level,
                 uint8_t *data_cw) {
  unsigned cap = qe_data_codewords(version, level) * 8u;
  if (b->overflow || b->nbits > cap) {
    return false;
  }
  qe_bits_t t = *b;
  unsigned term = cap - (unsigned)t.nbits < 4u ? cap - (unsigned)t.nbits : 4u;
  qe_put(&t, 0, term);
  while (t.nbits % 8u) {
    qe_put(&t, 0, 1);
  }
  for (unsigned pad = 0; t.nbits < cap; pad ^= 1u) {
    qe_put(&t, pad ? 0x11u : 0xECu, 8);
  }
  memcpy(data_cw, t.buf, cap / 8u);
  return true;
}

size_t qe_codewords(const uint8_t *data_cw, unsigned version, unsigned level,
                    uint8_t *out) {
  unsigned total = fqr_total_codewords[version];
  unsigned nb = fqr_num_blocks[level][version];
  unsigned ec = fqr_ecc_per_block[level][version];
  unsigned short_len = total / nb, n_short = nb - total % nb;
  unsigned d_short = short_len - ec;
  static uint8_t ecbuf[81][32];
  unsigned off = 0;
  for (unsigned j = 0; j < nb; j++) {
    unsigned dl = d_short + (j >= n_short ? 1u : 0u);
    rs_encode(data_cw + off, dl, ec, ecbuf[j]);
    off += dl;
  }
  size_t k = 0;
  for (unsigned i = 0; i <= d_short; i++) {
    unsigned boff = 0;
    for (unsigned j = 0; j < nb; j++) {
      unsigned dl = d_short + (j >= n_short ? 1u : 0u);
      if (i < dl) {
        out[k++] = data_cw[boff + i];
      }
      boff += dl;
    }
  }
  for (unsigned i = 0; i < ec; i++) {
    for (unsigned j = 0; j < nb; j++) {
      out[k++] = ecbuf[j][i];
    }
  }
  return k;
}

size_t qe_interleaved_index(unsigned version, unsigned level, unsigned blk,
                            unsigned off) {
  unsigned total = fqr_total_codewords[version];
  unsigned nb = fqr_num_blocks[level][version];
  unsigned ec = fqr_ecc_per_block[level][version];
  unsigned short_len = total / nb, n_short = nb - total % nb;
  unsigned d_short = short_len - ec;
  unsigned ndata_total = total - nb * ec;
  unsigned dl = d_short + (blk >= n_short ? 1u : 0u);
  if (off >= dl) {
    return ndata_total + (size_t)(off - dl) * nb + blk;
  }
  if (off < d_short) {
    return (size_t)off * nb + blk;
  }
  /* extra data codeword of a long block */
  return (size_t)d_short * nb + (blk - n_short);
}

/* ---------------- matrix ---------------- */

static uint32_t bch_rem(uint32_t v, unsigned bits, uint32_t gen,
                        unsigned gdeg) {
  uint32_t r = v << gdeg;
  for (unsigned i = bits + gdeg; i-- > gdeg;) {
    if ((r >> i) & 1u) {
      r ^= gen << (i - gdeg);
    }
  }
  return (v << gdeg) | r;
}

static int qe_mask(unsigned mask, unsigned r, unsigned c) {
  switch (mask) {
    case 0:
      return (r + c) % 2 == 0;
    case 1:
      return r % 2 == 0;
    case 2:
      return c % 3 == 0;
    case 3:
      return (r + c) % 3 == 0;
    case 4:
      return (r / 2 + c / 3) % 2 == 0;
    case 5:
      return (r * c) % 2 + (r * c) % 3 == 0;
    case 6:
      return ((r * c) % 2 + (r * c) % 3) % 2 == 0;
    default:
      return ((r + c) % 2 + (r * c) % 3) % 2 == 0;
  }
}

void qe_build(const uint8_t *data_cw, unsigned version, unsigned level,
              unsigned mask, uint8_t *grid, size_t stride) {
  static uint8_t cw[3706];
  size_t ncw = qe_codewords(data_cw, version, level, cw);
  qe_build_cw(cw, ncw, version, level, mask, grid, stride);
}

void qe_build_cw(const uint8_t *cw, size_t ncw, unsigned version,
                 unsigned level, unsigned mask, uint8_t *grid, size_t stride) {
  unsigned size = 17u + 4u * version;
  static uint8_t isfn[177][177];
  memset(isfn, 0, sizeof isfn);
  for (unsigned r = 0; r < size; r++) {
    for (unsigned c = 0; c < size; c++) {
      qe_set(grid, stride, r, c, 0);
    }
  }
#define FN(r, c, v)                      \
  do {                                   \
    qe_set(grid, stride, (r), (c), (v)); \
    isfn[(r)][(c)] = 1;                  \
  } while (0)
  /* finders + separators */
  const unsigned fr[3] = {0, 0, size - 7u}, fc[3] = {0, size - 7u, 0};
  for (unsigned f = 0; f < 3; f++) {
    for (int dr = -1; dr <= 7; dr++) {
      for (int dc = -1; dc <= 7; dc++) {
        int r = (int)fr[f] + dr, c = (int)fc[f] + dc;
        if (r < 0 || c < 0 || r >= (int)size || c >= (int)size) {
          continue;
        }
        int ring = 0;
        if (dr >= 0 && dr <= 6 && dc >= 0 && dc <= 6) {
          int a = dr < 3 ? 3 - dr : dr - 3, b2 = dc < 3 ? 3 - dc : dc - 3;
          int m = a > b2 ? a : b2;
          ring = (m != 2);
        }
        FN((unsigned)r, (unsigned)c, ring);
      }
    }
  }
  /* timing */
  for (unsigned i = 8; i < size - 8u; i++) {
    FN(6u, i, (i % 2u) == 0u);
    FN(i, 6u, (i % 2u) == 0u);
  }
  /* alignment (positions recomputed with the ISO spacing rule) */
  if (version >= 2) {
    unsigned na = version / 7 + 2;
    unsigned step = (version * 8 + na * 3 + 5) / (na * 4 - 4) * 2;
    unsigned pos[7];
    pos[0] = 6;
    for (unsigned i = na - 1, p = version * 4 + 10; i >= 1; i--, p -= step) {
      pos[i] = p;
    }
    for (unsigned i = 0; i < na; i++) {
      for (unsigned j = 0; j < na; j++) {
        if ((i == 0 && j == 0) || (i == 0 && j == na - 1) ||
            (i == na - 1 && j == 0)) {
          continue;
        }
        for (int dr = -2; dr <= 2; dr++) {
          for (int dc = -2; dc <= 2; dc++) {
            int a = dr < 0 ? -dr : dr, b2 = dc < 0 ? -dc : dc;
            int m = a > b2 ? a : b2;
            FN((unsigned)((int)pos[i] + dr), (unsigned)((int)pos[j] + dc),
               m != 1);
          }
        }
      }
    }
  }
  /* format */
  static const unsigned lvl_bits[4] = {1, 0, 3, 2};
  uint32_t fmt = bch_rem((lvl_bits[level] << 3) | mask, 5, 0x537, 10) ^ 0x5412u;
  for (unsigned i = 0; i <= 5; i++) FN(i, 8u, (fmt >> i) & 1u);
  FN(7u, 8u, (fmt >> 6) & 1u);
  FN(8u, 8u, (fmt >> 7) & 1u);
  FN(8u, 7u, (fmt >> 8) & 1u);
  for (unsigned i = 9; i < 15; i++) FN(8u, 14u - i, (fmt >> i) & 1u);
  for (unsigned i = 0; i < 8; i++) FN(8u, size - 1u - i, (fmt >> i) & 1u);
  for (unsigned i = 8; i < 15; i++) FN(size - 15u + i, 8u, (fmt >> i) & 1u);
  FN(size - 8u, 8u, 1);
  /* version */
  if (version >= 7) {
    uint32_t vi = bch_rem(version, 6, 0x1F25, 12);
    for (unsigned i = 0; i < 18; i++) {
      int bit = (vi >> i) & 1u;
      FN(i / 3u, size - 11u + i % 3u, bit);
      FN(size - 11u + i % 3u, i / 3u, bit);
    }
  }
#undef FN
  /* data */
  size_t bi = 0;
  for (int right = (int)size - 1; right >= 1; right -= 2) {
    if (right == 6) {
      right = 5;
    }
    for (unsigned vert = 0; vert < size; vert++) {
      for (int j = 0; j < 2; j++) {
        unsigned c = (unsigned)(right - j);
        int upward = ((right + 1) & 2) == 0;
        unsigned r = upward ? size - 1u - vert : vert;
        if (isfn[r][c]) {
          continue;
        }
        int bit = 0;
        if (bi < ncw * 8u) {
          bit = (cw[bi >> 3] >> (7u - (bi & 7u))) & 1;
        }
        bi++;
        qe_set(grid, stride, r, c, bit ^ qe_mask(mask, r, c));
      }
    }
  }
}

bool qe_make_bytes(const uint8_t *p, size_t n, unsigned min_version,
                   unsigned level, int mask, uint8_t *grid,
                   unsigned *version_out) {
  static uint8_t data[3706];
  for (unsigned v = min_version ? min_version : 1u; v <= 40u; v++) {
    qe_bits_t b;
    qe_bits_init(&b);
    qe_seg_byte(&b, v, p, n);
    if ((v <= 9 && n > 255) || qe_finalize(&b, v, level, data) == false) {
      continue;
    }
    qe_build(data, v, level, mask < 0 ? (unsigned)(n % 8u) : (unsigned)mask,
             grid, QE_GRID_STRIDE);
    *version_out = v;
    return true;
  }
  return false;
}

/* ---------------- images ---------------- */

bool qe_img_alloc(qe_img_t *img, uint32_t w, uint32_t h) {
  img->w = w;
  img->h = h;
  img->stride = (w + 7u) / 8u;
  img->data = calloc(img->stride * h + 1u, 1);
  return img->data != NULL;
}

void qe_img_free(qe_img_t *img) {
  free(img->data);
  img->data = NULL;
}

void qe_img_fill(qe_img_t *img, int dark) {
  memset(img->data, dark ? 0xFF : 0x00, img->stride * img->h);
}

bool qe_render(qe_img_t *img, const uint8_t *grid, size_t gstride, unsigned dim,
               const float corners[8], unsigned quiet, bool invert) {
  float d = (float)dim;
  float sq[8] = {0, 0, d, 0, d, d, 0, d};
  fqr_xform_t inv, fwd;
  if (!fqr_xform_quad(&inv, corners, sq) ||
      !fqr_xform_quad(&fwd, sq, corners)) {
    return false;
  }
  /* Bounding box of the quiet-zone quad. */
  float q = (float)quiet;
  float qq[8] = {-q, -q, d + q, -q, d + q, d + q, -q, d + q};
  float minx = 1e9f, miny = 1e9f, maxx = -1e9f, maxy = -1e9f;
  for (int i = 0; i < 4; i++) {
    float x, y;
    if (!fqr_xform_apply(&fwd, qq[2 * i], qq[2 * i + 1], &x, &y)) {
      return false;
    }
    minx = fminf(minx, x);
    maxx = fmaxf(maxx, x);
    miny = fminf(miny, y);
    maxy = fmaxf(maxy, y);
  }
  int x0 = (int)fmaxf(0, floorf(minx)),
      x1 = (int)fminf((float)img->w - 1, ceilf(maxx));
  int y0 = (int)fmaxf(0, floorf(miny)),
      y1 = (int)fminf((float)img->h - 1, ceilf(maxy));
  for (int y = y0; y <= y1; y++) {
    for (int x = x0; x <= x1; x++) {
      float u, v;
      if (!fqr_xform_apply(&inv, (float)x + 0.5f, (float)y + 0.5f, &u, &v)) {
        continue;
      }
      if (u < -q || v < -q || u >= d + q || v >= d + q) {
        continue;
      }
      int dark = 0;
      if (u >= 0 && v >= 0 && u < d && v < d) {
        dark = qe_get(grid, gstride, (unsigned)v, (unsigned)u);
      }
      qe_img_set(img, (uint32_t)x, (uint32_t)y, invert ? !dark : dark);
    }
  }
  return true;
}

void qe_render_scaled(qe_img_t *img, const uint8_t *grid, size_t gstride,
                      unsigned dim, uint32_t x, uint32_t y, uint32_t scale,
                      unsigned quiet, bool invert) {
  int64_t q = (int64_t)quiet * scale;
  for (int64_t py = (int64_t)y - q;
       py < (int64_t)y + (int64_t)(dim * scale) + q; py++) {
    for (int64_t px = (int64_t)x - q;
         px < (int64_t)x + (int64_t)(dim * scale) + q; px++) {
      if (px < 0 || py < 0 || px >= img->w || py >= img->h) {
        continue;
      }
      int dark = 0;
      int64_t mu = px - (int64_t)x, mv = py - (int64_t)y;
      if (mu >= 0 && mv >= 0 && mu < (int64_t)(dim * scale) &&
          mv < (int64_t)(dim * scale)) {
        dark = qe_get(grid, gstride, (unsigned)(mv / scale),
                      (unsigned)(mu / scale));
      }
      qe_img_set(img, (uint32_t)px, (uint32_t)py, invert ? !dark : dark);
    }
  }
}

void qe_corners(float out[8], float cx, float cy, float side, float angle_deg,
                float tilt_x, float tilt_y) {
  const float pts[4][2] = {
      {-0.5f, -0.5f}, {0.5f, -0.5f}, {0.5f, 0.5f}, {-0.5f, 0.5f}};
  float a = angle_deg * 3.14159265f / 180.0f;
  float ca = cosf(a), sa = sinf(a);
  for (int i = 0; i < 4; i++) {
    float u = pts[i][0], v = pts[i][1];
    /* simple perspective: shrink the far edges */
    float w = 1.0f + tilt_x * u + tilt_y * v;
    float x = u / w * side, y = v / w * side;
    out[2 * i] = cx + ca * x - sa * y;
    out[2 * i + 1] = cy + sa * x + ca * y;
  }
}
