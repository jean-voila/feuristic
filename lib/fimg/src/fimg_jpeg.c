// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Streaming baseline JPEG decoder (ITU-T T.81, SOF0, Huffman, 8-bit),
 * producing the luma (Y) plane only.
 *
 * Input path: every byte goes through a 4 KiB staging buffer. The marker
 * parser consumes it byte by byte (DHT / DQT are parsed incrementally, so
 * segments of any length work; SOF / SOS / DRI / APP0 / APP14 headers are
 * buffered). Entropy-coded data is decoded one MCU at a time, and an MCU is
 * only started when the staging buffer holds either FIMG_JPEG_MCU_WORST
 * bytes (the most one MCU of at most 6 blocks can occupy, byte stuffing
 * included) or a marker: the hot loop therefore never has to suspend in the
 * middle of an MCU, whatever the input chunking (stuffed 0xFF00 pairs and
 * markers split across chunks included).
 *
 * Supported: 1 component (grey) or 3 components (YCbCr) with luma sampling
 * H1V1 / H2V1 / H1V2 / H2V2 and chroma 1x1; interleaved and non-interleaved
 * scans (a multi-scan sequential file decodes its Y scan, other scans are
 * skipped by marker search); restart intervals (RSTn order checked); 8- and
 * 16-bit quantisation tables. Chroma blocks of an interleaved scan are
 * Huffman-decoded and dropped (no dequantisation / IDCT).
 *
 * IDCT: libjpeg's "islow" (Loeffler-Ligtenberg-Moschytz, 13-bit constants,
 * 2 extra pass-1 bits), bit-exact with libjpeg(-turbo) for valid streams.
 * To exclude signed overflow on hostile streams, dequantised coefficients
 * and pass-1 outputs are clamped to +-32767; interval analysis of the
 * butterfly then bounds every intermediate by 0.94 * 2^31. Valid 8-bit data
 * never reaches those clamps (|coef| <= 4096, |pass 1| <= 23170).
 *
 * Strictness: SOF1/2/3/5-7/9-15, DAC, DHP, EXP, JPEG-LS, a second frame,
 * precision != 8, CMYK / RGB / 2 / 4 components and other subsamplings are
 * refused with dedicated codes; invalid tables, wrong RST numbers,
 * Huffman codes running into a marker, missing EOI are errors. Garbage
 * between the end of a scan and the next marker is skipped (like libjpeg).
 */
#include "fimg_internal.h"

enum {
  J_MARK_FF = 0,
  J_MARK_CODE,
  J_SEG_LEN,
  J_SEG_DATA,
  J_SCAN,
  J_SCAN_SKIP,
  J_DONE
};

#define M_SOF0 0xc0u
#define M_DHT 0xc4u
#define M_SOI 0xd8u
#define M_EOI 0xd9u
#define M_SOS 0xdau
#define M_DQT 0xdbu
#define M_DRI 0xddu
#define M_APP0 0xe0u
#define M_APP14 0xeeu
#define M_COM 0xfeu

static const uint8_t k_zigzag[64] = {
    0,  1,  8,  16, 9,  2,  3,  10, 17, 24, 32, 25, 18, 11, 4,  5,
    12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6,  7,  14, 21, 28,
    35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
    58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63};

size_t fimg_jpeg_heap_size(void) {
  return FIMG_ALIGN8(FIMG_JPEG_STG_SIZE) +
         FIMG_ALIGN8((size_t)FIMG_MAX_DIM * 16u);
}

fimg_status_t fimg_jpeg_begin(fimg_ctx_t *ctx) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  memset(j, 0, sizeof *j);
  j->stg = (uint8_t *)fimg_alloc(ctx, FIMG_JPEG_STG_SIZE);
  if (j->stg == NULL) return FIMG_E_INTERNAL;
  j->state = J_MARK_FF;
  return FIMG_OK;
}

/* ---------------------------------------------------------------------- */
/* Huffman tables                                                           */
/* ---------------------------------------------------------------------- */

/* Build from counts[1..16] and t->vals (libjpeg-compatible validation). */
static int jhuff_build(fimg_jhuff_t *t, const uint8_t *counts) {
  int32_t code = 0, p = 0;
  uint32_t l, i;

  memset(t->look, 0, sizeof t->look);
  for (l = 1; l <= 16u; l++) {
    uint32_t cnt = counts[l];
    if (cnt != 0) {
      t->valoff[l] = p - code;
      for (i = 0; i < cnt; i++, code++, p++) {
        if (code >= (int32_t)(1u << l))
          return -1; /* over-subscribed: checked before any table write */
        if (l <= FIMG_JPEG_LOOKAHEAD) {
          uint32_t shift = FIMG_JPEG_LOOKAHEAD - l,
                   base = (uint32_t)code << shift, k;
          for (k = 0; k < (1u << shift); k++)
            t->look[base + k] = (uint16_t)((l << 8) | t->vals[p]);
        }
      }
      t->maxcode[l] = code - 1;
    } else {
      t->valoff[l] = 0;
      t->maxcode[l] = -1;
    }
    if (code >= (int32_t)(1u << l))
      return -1; /* over-subscribed or all-ones code */
    code <<= 1;
  }
  t->maxcode[17] = 0x7fffffff;
  t->defined = 1;
  return 0;
}

/* ---------------------------------------------------------------------- */
/* bit reader over the staging buffer                                       */
/* ---------------------------------------------------------------------- */

static void fill_bits(fimg_jpeg_t *j) {
  while (j->bitcnt <= 24) {
    uint32_t b;
    if (j->marker_hit || j->stg_pos >= j->stg_len) {
      if (!j->marker_hit) j->starved = 1;
      j->bitcnt += 8; /* zero bits; flagged as fake */
      j->fake += 8;
      continue;
    }
    b = j->stg[j->stg_pos];
    if (b == 0xffu) {
      if (j->stg_pos + 1u >= j->stg_len) {
        j->starved = 1;
        j->bitcnt += 8;
        j->fake += 8;
        continue;
      }
      if (j->stg[j->stg_pos + 1u] != 0x00u) {
        j->marker_hit = 1; /* stop at the marker, leave it unread */
        continue;
      }
      j->stg_pos += 2;
    } else {
      j->stg_pos++;
    }
    j->bitbuf |= b << (24 - j->bitcnt);
    j->bitcnt += 8;
  }
}

static uint32_t get_bits(fimg_jpeg_t *j, uint32_t n) /* 1 <= n <= 16 */
{
  uint32_t v;
  if (j->bitcnt < (int32_t)n) fill_bits(j);
  v = j->bitbuf >> (32u - n);
  j->bitbuf <<= n;
  j->bitcnt -= (int32_t)n;
  return v;
}

static int32_t jdecode(fimg_jpeg_t *j, const fimg_jhuff_t *t) {
  uint32_t look, l, code;
  if (j->bitcnt < 16) fill_bits(j);
  look = t->look[j->bitbuf >> (32u - FIMG_JPEG_LOOKAHEAD)];
  if (look != 0) {
    l = look >> 8;
    j->bitbuf <<= l;
    j->bitcnt -= (int32_t)l;
    return (int32_t)(look & 0xffu);
  }
  l = FIMG_JPEG_LOOKAHEAD + 1u;
  code = j->bitbuf >> (32u - l);
  while ((int32_t)code > t->maxcode[l]) {
    if (++l > 16u) return -1;
    code = j->bitbuf >> (32u - l);
  }
  j->bitbuf <<= l;
  j->bitcnt -= (int32_t)l;
  return t->vals[(int32_t)code + t->valoff[l]];
}

static int32_t extend(uint32_t v, uint32_t s) {
  return v < (1u << (s - 1u)) ? (int32_t)v - (int32_t)(1u << s) + 1
                              : (int32_t)v;
}

/* Clamp to +-32767; *sat counts engagements (diagnostic, see fimg_jpeg_t::sat).
 */
static int32_t clamp16(int32_t v, uint32_t *sat) {
  if (v > 32767 || v < -32767) {
    (*sat)++;
    return v > 0 ? 32767 : -32767;
  }
  return v;
}

/* ---------------------------------------------------------------------- */
/* IDCT (libjpeg jidctint "islow")                                          */
/* ---------------------------------------------------------------------- */

#define CONST_BITS 13
#define PASS1_BITS 2
#define FIX_0_298631336 2446
#define FIX_0_390180644 3196
#define FIX_0_541196100 4433
#define FIX_0_765366865 6270
#define FIX_0_899976223 7373
#define FIX_1_175875602 9633
#define FIX_1_501321110 12299
#define FIX_1_847759065 15137
#define FIX_1_961570560 16069
#define FIX_2_053119869 16819
#define FIX_2_562915447 20995
#define FIX_3_072711026 25172
#define DESCALE(x, n) (((x) + (1 << ((n) - 1))) >> (n))

/* Level shift and clamp. libjpeg's range table agrees for -512 <= v < 512
 * and wraps beyond; such (out-of-spec) values are counted in *sat. */
static uint8_t range255(int32_t v, uint32_t *sat) {
  if (v < -512 || v > 511) (*sat)++;
  v += 128;
  return (uint8_t)(v < 0 ? 0 : (v > 255 ? 255 : v));
}

static void idct_islow(const int32_t *in, int32_t *ws, uint8_t *out,
                       uint32_t stride, uint32_t *sat) {
  int32_t tmp0, tmp1, tmp2, tmp3, tmp10, tmp11, tmp12, tmp13, z1, z2, z3, z4,
      z5;
  int c;

  for (c = 0; c < 8; c++) {
    const int32_t *ip = in + c;
    int32_t *wp = ws + c;
    if ((ip[8] | ip[16] | ip[24] | ip[32] | ip[40] | ip[48] | ip[56]) == 0) {
      int32_t dc = clamp16(ip[0] * (1 << PASS1_BITS), sat);
      wp[0] = wp[8] = wp[16] = wp[24] = wp[32] = wp[40] = wp[48] = wp[56] = dc;
      continue;
    }
    z2 = ip[16];
    z3 = ip[48];
    z1 = (z2 + z3) * FIX_0_541196100;
    tmp2 = z1 + z3 * (-FIX_1_847759065);
    tmp3 = z1 + z2 * FIX_0_765366865;
    z2 = ip[0];
    z3 = ip[32];
    tmp0 = (z2 + z3) * (1 << CONST_BITS);
    tmp1 = (z2 - z3) * (1 << CONST_BITS);
    tmp10 = tmp0 + tmp3;
    tmp13 = tmp0 - tmp3;
    tmp11 = tmp1 + tmp2;
    tmp12 = tmp1 - tmp2;
    tmp0 = ip[56];
    tmp1 = ip[40];
    tmp2 = ip[24];
    tmp3 = ip[8];
    z1 = tmp0 + tmp3;
    z2 = tmp1 + tmp2;
    z3 = tmp0 + tmp2;
    z4 = tmp1 + tmp3;
    z5 = (z3 + z4) * FIX_1_175875602;
    tmp0 = tmp0 * FIX_0_298631336;
    tmp1 = tmp1 * FIX_2_053119869;
    tmp2 = tmp2 * FIX_3_072711026;
    tmp3 = tmp3 * FIX_1_501321110;
    z1 = z1 * (-FIX_0_899976223);
    z2 = z2 * (-FIX_2_562915447);
    z3 = z3 * (-FIX_1_961570560);
    z4 = z4 * (-FIX_0_390180644);
    z3 += z5;
    z4 += z5;
    tmp0 += z1 + z3;
    tmp1 += z2 + z4;
    tmp2 += z2 + z3;
    tmp3 += z1 + z4;
    wp[0] = clamp16(DESCALE(tmp10 + tmp3, CONST_BITS - PASS1_BITS), sat);
    wp[56] = clamp16(DESCALE(tmp10 - tmp3, CONST_BITS - PASS1_BITS), sat);
    wp[8] = clamp16(DESCALE(tmp11 + tmp2, CONST_BITS - PASS1_BITS), sat);
    wp[48] = clamp16(DESCALE(tmp11 - tmp2, CONST_BITS - PASS1_BITS), sat);
    wp[16] = clamp16(DESCALE(tmp12 + tmp1, CONST_BITS - PASS1_BITS), sat);
    wp[40] = clamp16(DESCALE(tmp12 - tmp1, CONST_BITS - PASS1_BITS), sat);
    wp[24] = clamp16(DESCALE(tmp13 + tmp0, CONST_BITS - PASS1_BITS), sat);
    wp[32] = clamp16(DESCALE(tmp13 - tmp0, CONST_BITS - PASS1_BITS), sat);
  }

  for (c = 0; c < 8; c++) {
    const int32_t *wp = ws + 8 * c;
    uint8_t *op = out + (size_t)c * stride;
    if ((wp[1] | wp[2] | wp[3] | wp[4] | wp[5] | wp[6] | wp[7]) == 0) {
      uint8_t v = range255(DESCALE(wp[0], PASS1_BITS + 3), sat);
      memset(op, v, 8);
      continue;
    }
    z2 = wp[2];
    z3 = wp[6];
    z1 = (z2 + z3) * FIX_0_541196100;
    tmp2 = z1 + z3 * (-FIX_1_847759065);
    tmp3 = z1 + z2 * FIX_0_765366865;
    tmp0 = (wp[0] + wp[4]) * (1 << CONST_BITS);
    tmp1 = (wp[0] - wp[4]) * (1 << CONST_BITS);
    tmp10 = tmp0 + tmp3;
    tmp13 = tmp0 - tmp3;
    tmp11 = tmp1 + tmp2;
    tmp12 = tmp1 - tmp2;
    tmp0 = wp[7];
    tmp1 = wp[5];
    tmp2 = wp[3];
    tmp3 = wp[1];
    z1 = tmp0 + tmp3;
    z2 = tmp1 + tmp2;
    z3 = tmp0 + tmp2;
    z4 = tmp1 + tmp3;
    z5 = (z3 + z4) * FIX_1_175875602;
    tmp0 = tmp0 * FIX_0_298631336;
    tmp1 = tmp1 * FIX_2_053119869;
    tmp2 = tmp2 * FIX_3_072711026;
    tmp3 = tmp3 * FIX_1_501321110;
    z1 = z1 * (-FIX_0_899976223);
    z2 = z2 * (-FIX_2_562915447);
    z3 = z3 * (-FIX_1_961570560);
    z4 = z4 * (-FIX_0_390180644);
    z3 += z5;
    z4 += z5;
    tmp0 += z1 + z3;
    tmp1 += z2 + z4;
    tmp2 += z2 + z3;
    tmp3 += z1 + z4;
    op[0] = range255(DESCALE(tmp10 + tmp3, CONST_BITS + PASS1_BITS + 3), sat);
    op[7] = range255(DESCALE(tmp10 - tmp3, CONST_BITS + PASS1_BITS + 3), sat);
    op[1] = range255(DESCALE(tmp11 + tmp2, CONST_BITS + PASS1_BITS + 3), sat);
    op[6] = range255(DESCALE(tmp11 - tmp2, CONST_BITS + PASS1_BITS + 3), sat);
    op[2] = range255(DESCALE(tmp12 + tmp1, CONST_BITS + PASS1_BITS + 3), sat);
    op[5] = range255(DESCALE(tmp12 - tmp1, CONST_BITS + PASS1_BITS + 3), sat);
    op[3] = range255(DESCALE(tmp13 + tmp0, CONST_BITS + PASS1_BITS + 3), sat);
    op[4] = range255(DESCALE(tmp13 - tmp0, CONST_BITS + PASS1_BITS + 3), sat);
  }
}

/* ---------------------------------------------------------------------- */
/* entropy-coded segment                                                    */
/* ---------------------------------------------------------------------- */

/* Decode one block of component @p ci; luma blocks are reconstructed at @p out.
 */
static fimg_status_t decode_block(fimg_jpeg_t *j, uint32_t ci, uint8_t *out) {
  fimg_jcomp_t *c = &j->comp[ci];
  const fimg_jhuff_t *dc = &j->dc[c->td], *ac = &j->ac[c->ta];
  const uint16_t *q = j->qt[c->tq];
  const int luma = (ci == 0);
  int32_t s, diff = 0;
  uint32_t k;

  s = jdecode(j, dc);
  if (s < 0 || s > 11) return FIMG_E_JPEG_HUFFMAN;
  if (s) diff = extend(get_bits(j, (uint32_t)s), (uint32_t)s);
  if (!luma) {
    /* chroma: consume the bits only */
    for (k = 1; k < 64u; k++) {
      int32_t rs = jdecode(j, ac);
      uint32_t r, sz;
      if (rs < 0) return FIMG_E_JPEG_HUFFMAN;
      r = (uint32_t)rs >> 4;
      sz = (uint32_t)rs & 15u;
      if (sz) {
        k += r;
        if (k > 63u || sz > 10u) return FIMG_E_JPEG_HUFFMAN;
        (void)get_bits(j, sz);
      } else {
        if (r != 15u) break;
        k += 15u;
      }
    }
    return FIMG_OK;
  }

  memset(j->coef, 0, sizeof j->coef);
  c->pred += diff; /* |pred| <= 2047 * 65536 blocks: no overflow */
  if (q[0] > 32767u)
    j->sat++; /* libjpeg holds multipliers in 16-bit signed integers */
  j->coef[0] = clamp16(clamp16(c->pred, &j->sat) * (int32_t)q[0], &j->sat);
  for (k = 1; k < 64u; k++) {
    int32_t rs = jdecode(j, ac);
    uint32_t r, sz;
    if (rs < 0) return FIMG_E_JPEG_HUFFMAN;
    r = (uint32_t)rs >> 4;
    sz = (uint32_t)rs & 15u;
    if (sz) {
      k += r;
      if (k > 63u || sz > 10u) return FIMG_E_JPEG_HUFFMAN;
      if (q[k] > 32767u) j->sat++;
      j->coef[k_zigzag[k]] =
          clamp16(extend(get_bits(j, sz), sz) * (int32_t)q[k], &j->sat);
    } else {
      if (r != 15u) break;
      k += 15u;
    }
  }
  idct_islow(j->coef, j->ws, out, j->rowbuf_w, &j->sat);
  return FIMG_OK;
}

/* Is there a marker between stg_pos and the end of the staging data? */
static int marker_ahead(fimg_jpeg_t *j) {
  uint32_t i;
  if (j->mfound) return 1;
  i = j->mscan > j->stg_pos ? j->mscan : j->stg_pos;
  for (; i + 1u < j->stg_len; i++) {
    if (j->stg[i] == 0xffu && j->stg[i + 1u] != 0x00u) {
      j->mfound = 1;
      j->mscan = i;
      return 1;
    }
  }
  j->mscan = i;
  return 0;
}

static void reset_bits(fimg_jpeg_t *j) {
  j->bitbuf = 0;
  j->bitcnt = 0;
  j->fake = 0;
  j->marker_hit = 0;
  j->starved = 0;
}

/* Returns FIMG_OK with *need = 1 when more input is required. */
static fimg_status_t decode_scan(fimg_ctx_t *ctx, int *need) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  *need = 0;

  for (;;) {
    uint32_t b;
    if (j->mcu_y == j->mcus_y) {
      j->y_done = 1;
      reset_bits(j);
      j->state = J_SCAN_SKIP; /* tolerate padding up to the next marker */
      return FIMG_OK;
    }
    if (j->restart_interval != 0 && j->rst_left == 0) {
      reset_bits(j); /* discard the partial byte */
      for (;;) {
        if (j->stg_pos + 1u >= j->stg_len) {
          *need = 1;
          return FIMG_OK;
        }
        if (j->stg[j->stg_pos] != 0xffu)
          return FIMG_E_JPEG_CORRUPT; /* data where RSTn is expected */
        if (j->stg[j->stg_pos + 1u] == 0xffu) {
          j->stg_pos++; /* fill byte */
          continue;
        }
        if (j->stg[j->stg_pos + 1u] != 0xd0u + j->rst_next)
          return FIMG_E_JPEG_CORRUPT;
        j->stg_pos += 2;
        break;
      }
      j->rst_next = (j->rst_next + 1u) & 7u;
      j->rst_left = j->restart_interval;
      j->mfound = 0;
      j->mscan = j->stg_pos;
      for (b = 0; b < j->ncomp; b++) j->comp[b].pred = 0;
    }
    if (j->stg_len - j->stg_pos < FIMG_JPEG_MCU_WORST && !marker_ahead(j)) {
      *need = 1;
      return FIMG_OK;
    }
    for (b = 0; b < j->nblocks; b++) {
      uint32_t ci = j->blk_comp[b];
      uint8_t *out = NULL;
      fimg_status_t st;
      if (ci == 0) {
        uint32_t x0 = j->mcu_x * (j->nblocks == 1u ? 8u : 8u * j->hmax) +
                      8u * j->blk_x[b];
        out = j->rowbuf + (size_t)(8u * j->blk_y[b]) * j->rowbuf_w + x0;
      }
      st = decode_block(j, ci, out);
      if (st != FIMG_OK) return st;
    }
    if (j->starved)
      return FIMG_E_INTERNAL; /* MCU larger than FIMG_JPEG_MCU_WORST: cannot
                                 happen */
    if (j->bitcnt < j->fake)
      return FIMG_E_JPEG_HUFFMAN; /* codes ran into a marker */
    if (j->restart_interval != 0) j->rst_left--;
    if (++j->mcu_x == j->mcus_x) {
      uint32_t r, rows = j->h - j->mcu_y * j->band_h;
      if (rows > j->band_h) rows = j->band_h;
      for (r = 0; r < rows; r++) {
        fimg_status_t st =
            fimg_pix_push(ctx, j->rowbuf + (size_t)r * j->rowbuf_w);
        if (st != FIMG_OK) return st;
      }
      j->mcu_x = 0;
      j->mcu_y++;
    }
  }
}

/* Skip entropy-coded data up to the next non-RST marker. */
static int skip_scan(fimg_jpeg_t *j) {
  while (j->stg_pos < j->stg_len) {
    uint32_t n;
    if (j->stg[j->stg_pos] != 0xffu) {
      j->stg_pos++;
      continue;
    }
    if (j->stg_pos + 1u >= j->stg_len) return 0;
    n = j->stg[j->stg_pos + 1u];
    if (n == 0x00u || (n >= 0xd0u && n <= 0xd7u)) {
      j->stg_pos += 2;
    } else if (n == 0xffu) {
      j->stg_pos++;
    } else {
      j->state = J_MARK_FF;
      return 1;
    }
  }
  return 0;
}

/* ---------------------------------------------------------------------- */
/* marker segments                                                          */
/* ---------------------------------------------------------------------- */

static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

static fimg_status_t parse_sof(fimg_ctx_t *ctx, uint32_t total) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  const uint8_t *s = j->seg;
  uint32_t i, k;

  if (j->seg_n < 6u) return FIMG_E_JPEG_CORRUPT;
  if (s[0] != 8u) return FIMG_E_JPEG_EXTENDED;
  j->h = be16(s + 1);
  j->w = be16(s + 3);
  j->ncomp = s[5];
  if (j->w == 0 || j->h == 0 || j->w > FIMG_MAX_DIM || j->h > FIMG_MAX_DIM)
    return FIMG_E_DIMENSIONS;
  if (j->ncomp != 1u && j->ncomp != 3u) return FIMG_E_JPEG_COLOR;
  if (total != 6u + 3u * j->ncomp) return FIMG_E_JPEG_CORRUPT;
  for (i = 0; i < j->ncomp; i++) {
    fimg_jcomp_t *c = &j->comp[i];
    c->id = s[6 + 3 * i];
    c->h = (uint8_t)(s[7 + 3 * i] >> 4);
    c->v = (uint8_t)(s[7 + 3 * i] & 15u);
    c->tq = s[8 + 3 * i];
    if (c->h < 1 || c->h > 4 || c->v < 1 || c->v > 4 || c->tq > 3)
      return FIMG_E_JPEG_CORRUPT;
    for (k = 0; k < i; k++)
      if (j->comp[k].id == c->id) return FIMG_E_JPEG_CORRUPT;
  }
  if (j->ncomp == 1u) {
    j->hmax = j->vmax = 1; /* single component: scan is non-interleaved */
  } else {
    if (j->comp[0].h > 2 || j->comp[0].v > 2 || j->comp[1].h != 1 ||
        j->comp[1].v != 1 || j->comp[2].h != 1 || j->comp[2].v != 1)
      return FIMG_E_JPEG_SAMPLING;
    j->hmax = j->comp[0].h;
    j->vmax = j->comp[0].v;
  }
  j->have_sof = 1;
  j->rowbuf_w = ((j->w + 8u * j->hmax - 1u) / (8u * j->hmax)) * 8u * j->hmax;
  j->rowbuf = (uint8_t *)fimg_alloc(ctx, (size_t)j->rowbuf_w * 8u * j->vmax);
  if (j->rowbuf == NULL || j->rowbuf_w > FIMG_MAX_DIM) return FIMG_E_INTERNAL;
  return fimg_pix_setup(ctx, j->w, j->h);
}

static fimg_status_t parse_sos(fimg_jpeg_t *j, uint32_t total) {
  const uint8_t *s = j->seg;
  uint32_t ns, i, last = 0, has_y = 0;
  int first = 1;
  uint8_t in_scan[3] = {0, 0, 0};

  if (!j->have_sof || j->seg_n < 1u) return FIMG_E_JPEG_CORRUPT;
  ns = s[0];
  if (ns < 1u || ns > j->ncomp || total != 4u + 2u * ns)
    return FIMG_E_JPEG_CORRUPT;
  for (i = 0; i < ns; i++) {
    uint32_t cs = s[1 + 2 * i], tdta = s[2 + 2 * i], ci;
    for (ci = 0; ci < j->ncomp; ci++)
      if (j->comp[ci].id == cs) break;
    if (ci == j->ncomp || (!first && ci <= last) || j->comp[ci].scanned)
      return FIMG_E_JPEG_CORRUPT;
    first = 0;
    last = ci;
    if ((tdta >> 4) > 3u || (tdta & 15u) > 3u) return FIMG_E_JPEG_CORRUPT;
    j->comp[ci].td = (uint8_t)(tdta >> 4);
    j->comp[ci].ta = (uint8_t)(tdta & 15u);
    in_scan[ci] = 1;
    if (ci == 0) has_y = 1;
  }
  if (s[1 + 2 * ns] != 0 || s[2 + 2 * ns] != 63 || s[3 + 2 * ns] != 0)
    return FIMG_E_JPEG_CORRUPT; /* Ss, Se, Ah/Al of a sequential scan */

  if (!j->color_checked) {
    j->color_checked = 1;
    if (j->ncomp == 3u) {
      int rgb;
      if (j->jfif_seen)
        rgb = 0;
      else if (j->adobe_seen)
        rgb = j->adobe_transform == 0;
      else
        rgb = j->comp[0].id == 'R' && j->comp[1].id == 'G' &&
              j->comp[2].id == 'B';
      if (rgb) return FIMG_E_JPEG_COLOR;
    }
  }
  for (i = 0; i < j->ncomp; i++)
    if (in_scan[i]) j->comp[i].scanned = 1;
  if (!has_y) {
    j->scan_decode = 0;
    j->state = J_SCAN_SKIP;
    return FIMG_OK;
  }

  for (i = 0; i < j->ncomp; i++) {
    const fimg_jcomp_t *c = &j->comp[i];
    if (!in_scan[i]) continue;
    if (c->td > 1u || c->ta > 1u || !j->dc[c->td].defined ||
        !j->ac[c->ta].defined)
      return FIMG_E_JPEG_CORRUPT;
  }
  if (!j->qt_defined[j->comp[0].tq]) return FIMG_E_JPEG_CORRUPT;

  j->nblocks = 0;
  if (ns == 1u) {
    j->blk_comp[0] = 0;
    j->blk_x[0] = j->blk_y[0] = 0;
    j->nblocks = 1;
    j->mcus_x = (j->w + 7u) / 8u;
    j->mcus_y = (j->h + 7u) / 8u;
    j->band_h = 8;
  } else {
    uint32_t bx, by;
    for (by = 0; by < j->comp[0].v; by++)
      for (bx = 0; bx < j->comp[0].h; bx++) {
        j->blk_comp[j->nblocks] = 0;
        j->blk_x[j->nblocks] = (uint8_t)bx;
        j->blk_y[j->nblocks] = (uint8_t)by;
        j->nblocks++;
      }
    for (i = 1; i < j->ncomp; i++)
      if (in_scan[i]) {
        j->blk_comp[j->nblocks] = (uint8_t)i;
        j->blk_x[j->nblocks] = j->blk_y[j->nblocks] = 0;
        j->nblocks++;
      }
    j->mcus_x = (j->w + 8u * j->hmax - 1u) / (8u * j->hmax);
    j->mcus_y = (j->h + 8u * j->vmax - 1u) / (8u * j->vmax);
    j->band_h = 8u * j->vmax;
  }
  for (i = 0; i < j->ncomp; i++) j->comp[i].pred = 0;
  j->mcu_x = j->mcu_y = 0;
  j->rst_left = j->restart_interval;
  j->rst_next = 0;
  j->mfound = 0;
  j->mscan = j->stg_pos;
  reset_bits(j);
  j->scan_decode = 1;
  j->state = J_SCAN;
  return FIMG_OK;
}

/* Feed one byte of a DHT segment. */
static fimg_status_t dht_byte(fimg_jpeg_t *j, uint32_t b) {
  switch (j->dht_sub) {
    case 0:
      j->dht_tc = b >> 4;
      j->dht_th = b & 15u;
      if (j->dht_tc > 1u || j->dht_th > 3u) return FIMG_E_JPEG_CORRUPT;
      /* tables 2..3 are legal only outside baseline: parsed, then dropped */
      j->dht_tab = j->dht_th <= 1u
                       ? (j->dht_tc ? &j->ac[j->dht_th] : &j->dc[j->dht_th])
                       : NULL;
      if (j->dht_tab != NULL) j->dht_tab->defined = 0;
      j->dht_got = 0;
      j->dht_total = 0;
      j->dht_sub = 1;
      return FIMG_OK;
    case 1:
      j->dht_counts[1u + j->dht_got] = (uint8_t)b;
      j->dht_total += b;
      if (++j->dht_got < 16u) return FIMG_OK;
      if (j->dht_total > 256u) return FIMG_E_JPEG_CORRUPT;
      j->dht_got = 0;
      j->dht_sub = 2;
      if (j->dht_total != 0) return FIMG_OK;
      break;
    default:
      if (j->dht_tab != NULL) j->dht_tab->vals[j->dht_got] = (uint8_t)b;
      if (++j->dht_got < j->dht_total) return FIMG_OK;
      break;
  }
  /* table complete */
  j->dht_sub = 0;
  if (j->dht_tab != NULL && jhuff_build(j->dht_tab, j->dht_counts) != 0)
    return FIMG_E_JPEG_CORRUPT;
  return FIMG_OK;
}

/* Feed one byte of a DQT segment. */
static fimg_status_t dqt_byte(fimg_jpeg_t *j, uint32_t b) {
  if (j->dqt_sub == 0) {
    j->dqt_pq = b >> 4;
    j->dqt_tq = b & 15u;
    if (j->dqt_pq > 1u || j->dqt_tq > 3u) return FIMG_E_JPEG_CORRUPT;
    j->qt_defined[j->dqt_tq] = 0;
    j->dqt_got = 0;
    j->dqt_sub = 1;
    return FIMG_OK;
  }
  if (j->dqt_pq == 0) {
    j->qt[j->dqt_tq][j->dqt_got++] = (uint16_t)b;
  } else if (j->dqt_sub == 1) {
    j->qt[j->dqt_tq][j->dqt_got] = (uint16_t)(b << 8);
    j->dqt_sub = 2;
    return FIMG_OK;
  } else {
    j->qt[j->dqt_tq][j->dqt_got++] |= (uint16_t)b;
    j->dqt_sub = 1;
  }
  if (j->dqt_got == 64u) {
    j->qt_defined[j->dqt_tq] = 1;
    j->dqt_sub = 0;
  }
  return FIMG_OK;
}

/* Classify a marker that starts a segment; errors for unsupported ones. */
static fimg_status_t on_marker(fimg_ctx_t *ctx, uint32_t m) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  const int is_sof =
      (m >= 0xc0u && m <= 0xcfu && m != 0xc4u && m != 0xc8u && m != 0xccu) ||
      m == 0xf7u;

  if (!j->soi_seen) {
    if (m != M_SOI) return FIMG_E_JPEG_CORRUPT;
    j->soi_seen = 1;
    j->state = J_MARK_FF;
    return FIMG_OK;
  }
  if (is_sof && j->have_sof) return FIMG_E_JPEG_MULTIFRAME;
  switch (m) {
    case M_SOF0:
    case M_DHT:
    case M_DQT:
    case M_DRI:
    case M_SOS:
    case M_COM:
      break;
    case 0xc1u:
      return FIMG_E_JPEG_EXTENDED;
    case 0xc2u:
      return FIMG_E_JPEG_PROGRESSIVE;
    case 0xc3u:
    case 0xf7u: /* JPEG-LS SOF55 */
      return FIMG_E_JPEG_LOSSLESS;
    case 0xc5u:
    case 0xc6u:
    case 0xc7u:
    case 0xdeu: /* DHP */
    case 0xdfu: /* EXP */
      return FIMG_E_JPEG_HIERARCHICAL;
    case 0xc9u:
    case 0xcau:
    case 0xcbu:
    case 0xccu: /* DAC */
    case 0xcdu:
    case 0xceu:
    case 0xcfu:
      return FIMG_E_JPEG_ARITHMETIC;
    case M_EOI:
      if (!j->y_done) return FIMG_E_JPEG_CORRUPT; /* image data missing */
      j->state = J_DONE;
      ctx->phase = FIMG_PH_DONE;
      j->done_at = j->stg_pos;
      return FIMG_OK;
    default:
      if (m >= 0xe0u && m <= 0xefu) break; /* APPn */
      return FIMG_E_JPEG_CORRUPT; /* SOI, RSTn, DNL, TEM, JPG, reserved */
  }
  j->marker = m;
  j->state = J_SEG_LEN;
  return FIMG_OK;
}

static fimg_status_t end_segment(fimg_ctx_t *ctx) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  const uint32_t total = j->seg_total;

  j->state = J_MARK_FF;
  switch (j->marker) {
    case M_SOF0:
      return parse_sof(ctx, total);
    case M_SOS:
      return parse_sos(j, total);
    case M_DRI:
      if (total != 2u) return FIMG_E_JPEG_CORRUPT;
      j->restart_interval = be16(j->seg);
      return FIMG_OK;
    case M_DHT:
      return j->dht_sub == 0 ? FIMG_OK : FIMG_E_JPEG_CORRUPT;
    case M_DQT:
      return j->dqt_sub == 0 ? FIMG_OK : FIMG_E_JPEG_CORRUPT;
    case M_APP0:
      if (j->seg_n >= 5u && memcmp(j->seg, "JFIF\0", 5) == 0) j->jfif_seen = 1;
      return FIMG_OK;
    case M_APP14:
      if (j->seg_n >= 12u && memcmp(j->seg, "Adobe", 5) == 0) {
        j->adobe_seen = 1;
        j->adobe_transform = j->seg[11];
      }
      return FIMG_OK;
    default:
      return FIMG_OK;
  }
}

static fimg_status_t seg_bytes(fimg_jpeg_t *j, const uint8_t *p, uint32_t n) {
  uint32_t i;
  fimg_status_t st;
  switch (j->marker) {
    case M_DHT:
      for (i = 0; i < n; i++)
        if ((st = dht_byte(j, p[i])) != FIMG_OK) return st;
      return FIMG_OK;
    case M_DQT:
      for (i = 0; i < n; i++)
        if ((st = dqt_byte(j, p[i])) != FIMG_OK) return st;
      return FIMG_OK;
    case M_SOF0:
    case M_SOS:
    case M_DRI:
    case M_APP0:
    case M_APP14:
      for (i = 0; i < n && j->seg_n < sizeof j->seg; i++)
        j->seg[j->seg_n++] = p[i];
      return FIMG_OK;
    default:
      return FIMG_OK;
  }
}

/* Run the parser over the staging buffer until it needs input. */
static fimg_status_t run(fimg_ctx_t *ctx) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  fimg_status_t st;

  for (;;) {
    switch (j->state) {
      case J_MARK_FF:
        if (j->stg_pos >= j->stg_len) return FIMG_OK;
        if (j->stg[j->stg_pos++] != 0xffu)
          return FIMG_E_JPEG_CORRUPT; /* garbage where a marker is expected */
        j->state = J_MARK_CODE;
        break;
      case J_MARK_CODE: {
        uint32_t m;
        if (j->stg_pos >= j->stg_len) return FIMG_OK;
        m = j->stg[j->stg_pos++];
        if (m == 0xffu) break; /* fill byte */
        st = on_marker(ctx, m);
        if (st != FIMG_OK) return st;
        break;
      }
      case J_SEG_LEN: {
        uint32_t len;
        if (j->stg_len - j->stg_pos < 2u) return FIMG_OK;
        len = be16(j->stg + j->stg_pos);
        j->stg_pos += 2;
        if (len < 2u) return FIMG_E_JPEG_CORRUPT;
        j->seg_total = len - 2u;
        j->seg_left = len - 2u;
        j->seg_n = 0;
        j->dht_sub = 0;
        j->dqt_sub = 0;
        if ((j->marker == M_SOS && j->seg_total > sizeof j->seg) ||
            (j->marker == M_DRI && j->seg_total != 2u))
          return FIMG_E_JPEG_CORRUPT;
        j->state = J_SEG_DATA;
        break;
      }
      case J_SEG_DATA: {
        uint32_t k;
        if (j->seg_left == 0) {
          st = end_segment(ctx);
          if (st != FIMG_OK) return st;
          break;
        }
        if (j->stg_pos >= j->stg_len) return FIMG_OK;
        k = j->stg_len - j->stg_pos;
        if (k > j->seg_left) k = j->seg_left;
        st = seg_bytes(j, j->stg + j->stg_pos, k);
        if (st != FIMG_OK) return st;
        j->stg_pos += k;
        j->seg_left -= k;
        break;
      }
      case J_SCAN: {
        int need;
        st = decode_scan(ctx, &need);
        if (st != FIMG_OK) return st;
        if (need) return FIMG_OK;
        break;
      }
      case J_SCAN_SKIP:
        if (!skip_scan(j)) return FIMG_OK;
        break;
      default: /* J_DONE */
        return FIMG_OK;
    }
  }
}

fimg_status_t fimg_jpeg_feed(fimg_ctx_t *ctx, const uint8_t *p, size_t n,
                             size_t *used) {
  fimg_jpeg_t *j = &ctx->u.jpeg;
  size_t copied = 0;

  *used = 0;
  while (copied < n && ctx->phase == FIMG_PH_JPEG) {
    size_t k;
    fimg_status_t st;
    if (j->stg_pos > 0) { /* compact */
      uint32_t sh = j->stg_pos;
      memmove(j->stg, j->stg + sh, j->stg_len - sh);
      j->stg_len -= sh;
      j->stg_pos = 0;
      j->mscan = j->mscan > sh ? j->mscan - sh : 0;
    }
    k = FIMG_JPEG_STG_SIZE - j->stg_len;
    if (k == 0)
      return FIMG_E_INTERNAL; /* parser can always progress on a full buffer */
    if (k > n - copied) k = n - copied;
    memcpy(j->stg + j->stg_len, p + copied, k);
    j->stg_len += (uint32_t)k;
    copied += k;
    st = run(ctx);
    if (st != FIMG_OK) {
      *used = copied;
      return st;
    }
  }
  if (ctx->phase == FIMG_PH_DONE) {
    size_t trailing = j->stg_len - j->done_at;
    *used = copied - (trailing < copied ? trailing : copied);
  } else {
    *used = copied;
  }
  return FIMG_OK;
}
