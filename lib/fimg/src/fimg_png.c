// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Streaming PNG decoder (ISO/IEC 15948, non-interlaced).
 *
 * - Chunk parser fed byte by byte (any split): length, type, data, CRC-32.
 *   Every chunk CRC is verified (a mismatch is fatal, ancillary or not).
 *   IHDR / PLTE / tRNS are buffered and only applied once their CRC is good.
 *   IDAT data is inflated as it arrives (its CRC is checked at chunk end).
 * - Rules: IHDR first (13 bytes); PLTE before IDAT, at most once, 1..256
 *   entries, required for colour type 3 and forbidden for 0 / 4; IDAT chunks
 *   contiguous; IEND empty and last. Unknown critical chunks are refused,
 *   unknown ancillary chunks (tEXt, gAMA, APNG acTL/fcTL/fdAT, ...) skipped:
 *   an APNG therefore yields its default image. An invalid tRNS is ignored.
 * - The inflated size must be exactly height * (rowbytes + 1); one byte more
 *   is refused immediately (decompression bomb), fewer is refused at the end
 *   of the zlib stream. Data after the end of the zlib stream is refused.
 * - Unfiltering updates one paged scanline in place; each row is converted to
 * 8-bit luma (BT.601, Pillow's fixed point; 16-bit samples use their high byte;
 *   alpha and tRNS are composited over white; palette indices beyond PLTE
 *   are black) and pushed to the pixel pipeline.
 */
#include "fimg_internal.h"

enum { P_SIG = 0, P_HDR, P_DATA, P_CRC };

#define CT_IHDR 0x49484452u
#define CT_PLTE 0x504c5445u
#define CT_IDAT 0x49444154u
#define CT_IEND 0x49454e44u
#define CT_tRNS 0x74524e53u

static const uint8_t k_sig[8] = {0x89, 0x50, 0x4e, 0x47,
                                 0x0d, 0x0a, 0x1a, 0x0a};

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | p[3];
}

static uint32_t be16(const uint8_t *p) { return ((uint32_t)p[0] << 8) | p[1]; }

size_t fimg_png_heap_size(void) {
  return FIMG_ALIGN8(FIMG_INF_WSIZE) + FIMG_ALIGN8(FIMG_PNG_MAX_ROWBYTES) +
         FIMG_ALIGN8(FIMG_MAX_DIM);
}

void fimg_png_begin(fimg_ctx_t *ctx) {
  fimg_png_t *g = &ctx->u.png;
  memset(g, 0, sizeof *g);
  g->state = P_SIG;
}

/* ---------------------------------------------------------------------- */
/* rows                                                                     */
/* ---------------------------------------------------------------------- */

static uint32_t paeth(uint32_t a, uint32_t b, uint32_t c) {
  int32_t p = (int32_t)a + (int32_t)b - (int32_t)c;
  int32_t pa = p - (int32_t)a, pb = p - (int32_t)b, pc = p - (int32_t)c;
  if (pa < 0) pa = -pa;
  if (pb < 0) pb = -pb;
  if (pc < 0) pc = -pc;
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

static uint8_t *row_ptr(const fimg_png_t *g, uint32_t at) {
  return g->prev[at / FIMG_PNG_ROW_PAGE] + (at & (FIMG_PNG_ROW_PAGE - 1u));
}

static uint32_t row_sample(const fimg_png_t *g, uint32_t at, uint32_t bytes) {
  uint32_t value = *row_ptr(g, at);
  return bytes == 1 ? value : (value << 8) | *row_ptr(g, at + 1u);
}

/* The old upper-left byte must be saved before its row cell is overwritten.
 * bpp <= 8 for every accepted PNG; the ring is reset by the first bpp bytes. */
static void unfilter_byte(fimg_png_t *g, uint32_t at, uint8_t byte) {
  uint8_t *cell = row_ptr(g, at);
  uint32_t up = *cell;
  uint32_t left = at >= g->bpp ? *row_ptr(g, at - g->bpp) : 0;
  uint32_t upper_left = at >= g->bpp ? g->prior_up[at % g->bpp] : 0;
  g->prior_up[at % g->bpp] = (uint8_t)up;
  switch (g->filter) {
    case 1:
      byte = (uint8_t)(byte + left);
      break;
    case 2:
      byte = (uint8_t)(byte + up);
      break;
    case 3:
      byte = (uint8_t)(byte + ((left + up) >> 1));
      break;
    case 4:
      byte = (uint8_t)(byte + paeth(left, up, upper_left));
      break;
    default:
      break;
  }
  *cell = byte;
}

static void to_luma(fimg_png_t *g) {
  uint32_t bytes = g->depth == 16u ? 2u : 1u;
  for (uint32_t x = 0; x < g->w; x++) {
    uint32_t value;
    if (g->depth < 8u) {
      uint32_t bit = x * g->depth, mask = (1u << g->depth) - 1u;
      value = (*row_ptr(g, bit >> 3) >> (8u - g->depth - (bit & 7u))) & mask;
      g->luma[x] = g->ctype == 3u ? g->pal_luma[value]
                                  : (uint8_t)(g->has_key && value == g->key[0]
                                                  ? 255u
                                                  : value * (255u / mask));
      continue;
    }
    uint32_t at = x * g->channels * bytes;
    uint32_t a = row_sample(g, at, bytes), y = a >> (g->depth - 8u);
    switch (g->ctype) {
      case 0:
        if (g->has_key && a == g->key[0]) y = 255u;
        break;
      case 2: {
        uint32_t b = row_sample(g, at + bytes, bytes);
        uint32_t c = row_sample(g, at + 2u * bytes, bytes);
        y = g->has_key && a == g->key[0] && b == g->key[1] && c == g->key[2]
                ? 255u
                : fimg_rgb_luma(y, b >> (g->depth - 8u), c >> (g->depth - 8u));
        break;
      }
      case 3:
        y = g->pal_luma[a];
        break;
      case 4:
        y = fimg_over_white(y, *row_ptr(g, at + bytes));
        break;
      default:
        y = fimg_over_white(fimg_rgb_luma(y, *row_ptr(g, at + bytes),
                                          *row_ptr(g, at + 2u * bytes)),
                            *row_ptr(g, at + 3u * bytes));
        break;
    }
    g->luma[x] = (uint8_t)y;
  }
}

static fimg_status_t finish_row(fimg_ctx_t *ctx) {
  fimg_png_t *g = &ctx->u.png;
  if (g->filter > 4u) return FIMG_E_PNG_CORRUPT;
  to_luma(g);
  fimg_status_t st = fimg_pix_push(ctx, g->luma);
  if (st != FIMG_OK) return st;
  g->rows_done++;
  return FIMG_OK;
}

/* Move @p n freshly inflated bytes (window offset @p pos) into scanlines. */
static fimg_status_t consume(fimg_ctx_t *ctx, uint32_t pos, uint32_t n) {
  fimg_png_t *g = &ctx->u.png;
  const uint32_t full = g->rowbytes + 1u;

  uint32_t extra = 0;

  /* rows first, then the size error: the outcome must not depend on how
   * the input was chunked (errors are reported in stream order) */
  if (n > g->expected - g->inf_bytes) {
    extra = n - (g->expected - g->inf_bytes);
    n -= extra;
  }
  g->inf_bytes += n;
  while (n > 0) {
    uint8_t byte = *fimg_window_ptr(&g->inf, pos);
    if (g->row_fill == 0)
      g->filter = byte;
    else
      unfilter_byte(g, g->row_fill - 1u, byte);
    g->row_fill++;
    pos = (pos + 1u) & FIMG_INF_WMASK;
    n--;
    if (g->row_fill == full) {
      fimg_status_t st = finish_row(ctx);
      if (st != FIMG_OK) return st;
      g->row_fill = 0;
    }
  }
  return extra ? FIMG_E_PNG_DATA_SIZE
               : FIMG_OK; /* more data than IHDR allows */
}

static fimg_status_t idat_data(fimg_ctx_t *ctx, const uint8_t *p, size_t n) {
  fimg_png_t *g = &ctx->u.png;

  if (g->zdone)
    return n > 0 ? FIMG_E_PNG_CORRUPT
                 : FIMG_OK; /* data after the zlib stream */
  for (;;) {
    size_t used = 0;
    uint32_t produced = 0, start = g->inf.wpos;
    fimg_inf_result_t r =
        fimg_inflate(&g->inf, p, n, &used, FIMG_INF_WSIZE, &produced);
    p += used;
    n -= used;
    if (produced > 0) {
      fimg_status_t st = consume(ctx, start, produced);
      if (st != FIMG_OK) return st;
    }
    if ((int)r < 0) return FIMG_E_PNG_ZLIB;
    if (r == FIMG_INF_DONE) {
      g->zdone = 1;
      if (g->inf_bytes != g->expected) return FIMG_E_PNG_DATA_SIZE;
      return n > 0 ? FIMG_E_PNG_CORRUPT : FIMG_OK;
    }
    if (r == FIMG_INF_NEED_INPUT) return FIMG_OK;
  }
}

/* ---------------------------------------------------------------------- */
/* chunks                                                                   */
/* ---------------------------------------------------------------------- */

static int valid_type(uint32_t t) {
  for (int i = 0; i < 4; i++) {
    uint32_t c = (t >> (24 - 8 * i)) & 0xffu;
    if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z'))) return 0;
  }
  return 1;
}

/* Called once a chunk header is known, before its data. */
static fimg_status_t begin_chunk(fimg_png_t *g) {
  const uint32_t t = g->chunk_type, len = g->chunk_len;

  if (len > 0x7fffffffu || !valid_type(t)) return FIMG_E_PNG_CORRUPT;
  g->small_n = 0;
  g->skip_trns = 0;
  if (!g->seen_ihdr) {
    if (t != CT_IHDR || len != 13u) return FIMG_E_PNG_CORRUPT;
    return FIMG_OK;
  }
  if (t == CT_IHDR) return FIMG_E_PNG_CORRUPT;
  if (t != CT_IDAT && g->in_idat) {
    g->in_idat = 0;
    g->idat_done = 1;
    if (!g->zdone)
      return g->rows_done < g->h ? FIMG_E_PNG_DATA_SIZE : FIMG_E_PNG_ZLIB;
  }
  switch (t) {
    case CT_PLTE:
      if (g->seen_idat || g->seen_plte || g->ctype == 0u || g->ctype == 4u ||
          len == 0u || len % 3u != 0u || len > 768u)
        return FIMG_E_PNG_CORRUPT;
      return FIMG_OK;
    case CT_tRNS:
      if (g->seen_idat || g->seen_trns ||
          !((g->ctype == 3u && g->seen_plte && len <= g->pal_n) ||
            (g->ctype == 0u && len == 2u) || (g->ctype == 2u && len == 6u)))
        g->skip_trns = 1; /* invalid ancillary chunk: ignored */
      return FIMG_OK;
    case CT_IDAT:
      if (g->idat_done || (g->ctype == 3u && !g->seen_plte))
        return FIMG_E_PNG_CORRUPT;
      g->in_idat = 1;
      g->seen_idat = 1;
      return FIMG_OK;
    case CT_IEND:
      if (len != 0u || !g->seen_idat) return FIMG_E_PNG_CORRUPT;
      return FIMG_OK;
    default:
      if (!(t & 0x20000000u))
        return FIMG_E_PNG_UNSUPPORTED; /* unknown critical chunk */
      return FIMG_OK;
  }
}

static fimg_status_t chunk_data(fimg_ctx_t *ctx, const uint8_t *p, size_t n) {
  fimg_png_t *g = &ctx->u.png;
  switch (g->chunk_type) {
    case CT_IHDR:
    case CT_PLTE:
    case CT_tRNS:
      if (g->chunk_type == CT_tRNS && g->skip_trns) return FIMG_OK;
      if (n > sizeof g->small - g->small_n)
        return FIMG_E_INTERNAL; /* lengths are validated in begin_chunk */
      memcpy(g->small + g->small_n, p, n);
      g->small_n += (uint32_t)n;
      return FIMG_OK;
    case CT_IDAT:
      return idat_data(ctx, p, n);
    default:
      return FIMG_OK;
  }
}

static fimg_status_t parse_ihdr(fimg_ctx_t *ctx) {
  fimg_png_t *g = &ctx->u.png;
  const uint8_t *s = g->small;
  uint32_t w = be32(s), h = be32(s + 4), d = s[8], ct = s[9], bits;
  int ok;

  if (w == 0 || h == 0 || w > FIMG_MAX_DIM || h > FIMG_MAX_DIM)
    return FIMG_E_DIMENSIONS;
  switch (ct) {
    case 0:
      ok = d == 1 || d == 2 || d == 4 || d == 8 || d == 16;
      g->channels = 1;
      break;
    case 2:
      ok = d == 8 || d == 16;
      g->channels = 3;
      break;
    case 3:
      ok = d == 1 || d == 2 || d == 4 || d == 8;
      g->channels = 1;
      break;
    case 4:
      ok = d == 8 || d == 16;
      g->channels = 2;
      break;
    case 6:
      ok = d == 8 || d == 16;
      g->channels = 4;
      break;
    default:
      ok = 0;
      break;
  }
  if (!ok || s[10] != 0 || s[11] != 0) return FIMG_E_PNG_UNSUPPORTED;
  if (s[12] == 1) return FIMG_E_PNG_INTERLACED;
  if (s[12] != 0) return FIMG_E_PNG_UNSUPPORTED;

  g->w = w;
  g->h = h;
  g->depth = d;
  g->ctype = ct;
  bits = g->channels * d;
  g->rowbytes = (w * bits + 7u) / 8u;
  g->bpp = bits >= 8u ? bits / 8u : 1u;
  g->expected = h * (g->rowbytes + 1u);
  g->seen_ihdr = 1;
  memset(g->pal_luma, 0, sizeof g->pal_luma);

  g->page_size = (uint32_t)fimg_page_size(&ctx->cfg);
  uint8_t *pages[32];
  uint8_t *first = (uint8_t *)fimg_alloc(ctx, FIMG_QR_REUSE_BYTES);
  if (first == NULL) return FIMG_E_INTERNAL;
  size_t prefix = FIMG_QR_REUSE_BYTES / g->page_size;
  size_t count = FIMG_INF_WSIZE / g->page_size;
  for (size_t i = 0; i < count; i++) {
    pages[i] = i < prefix ? first + i * g->page_size
                          : (uint8_t *)fimg_alloc(ctx, g->page_size);
    if (pages[i] == NULL) return FIMG_E_INTERNAL;
  }
  for (size_t i = 0; i < FIMG_PNG_MAX_ROWBYTES / FIMG_PNG_ROW_PAGE; i++) {
    g->prev[i] = (uint8_t *)fimg_alloc(ctx, FIMG_PNG_ROW_PAGE);
    if (g->prev[i] == NULL) return FIMG_E_INTERNAL;
    memset(g->prev[i], 0, FIMG_PNG_ROW_PAGE);
  }
  g->luma = (uint8_t *)fimg_alloc(ctx, FIMG_MAX_DIM);
  if (g->luma == NULL) return FIMG_E_INTERNAL;
  fimg_inflate_init_pages(&g->inf, pages, g->page_size);
  return fimg_pix_setup(ctx, w, h);
}

/* Called after a chunk's CRC was verified. */
static fimg_status_t end_chunk(fimg_ctx_t *ctx) {
  fimg_png_t *g = &ctx->u.png;
  uint32_t i;

  switch (g->chunk_type) {
    case CT_IHDR:
      return parse_ihdr(ctx);
    case CT_PLTE:
      g->pal_n = g->chunk_len / 3u;
      for (i = 0; i < g->pal_n; i++)
        g->pal_luma[i] = (uint8_t)fimg_rgb_luma(
            g->small[3 * i], g->small[3 * i + 1], g->small[3 * i + 2]);
      g->seen_plte = 1;
      return FIMG_OK;
    case CT_tRNS:
      if (g->skip_trns) return FIMG_OK;
      g->seen_trns = 1;
      if (g->ctype == 3u) {
        for (i = 0; i < g->chunk_len; i++)
          g->pal_luma[i] =
              (uint8_t)fimg_over_white(g->pal_luma[i], g->small[i]);
      } else {
        g->has_key = 1;
        g->key[0] = (uint16_t)be16(g->small);
        if (g->ctype == 2u) {
          g->key[1] = (uint16_t)be16(g->small + 2);
          g->key[2] = (uint16_t)be16(g->small + 4);
        }
      }
      return FIMG_OK;
    case CT_IEND:
      if (g->rows_done != g->h) return FIMG_E_PNG_DATA_SIZE;
      if (!g->zdone) return FIMG_E_PNG_ZLIB;
      ctx->phase = FIMG_PH_DONE;
      return FIMG_OK;
    default:
      return FIMG_OK;
  }
}

fimg_status_t fimg_png_feed(fimg_ctx_t *ctx, const uint8_t *p, size_t n,
                            size_t *used) {
  fimg_png_t *g = &ctx->u.png;
  size_t i = 0;
  fimg_status_t st = FIMG_OK;

  while (i < n && ctx->phase == FIMG_PH_PNG) {
    switch (g->state) {
      case P_SIG:
        g->hdr[g->hdr_n++] = p[i++];
        if (g->hdr_n == 8u) {
          if (memcmp(g->hdr, k_sig, 8) != 0) {
            st = FIMG_E_NOT_IMAGE;
            goto out;
          }
          g->hdr_n = 0;
          g->state = P_HDR;
        }
        break;
      case P_HDR:
        g->hdr[g->hdr_n++] = p[i++];
        if (g->hdr_n == 8u) {
          g->hdr_n = 0;
          g->chunk_len = be32(g->hdr);
          g->chunk_type = be32(g->hdr + 4);
          g->chunk_left = g->chunk_len;
          g->crc = fimg_crc32(0, g->hdr + 4, 4);
          st = begin_chunk(g);
          if (st != FIMG_OK) goto out;
          g->state = g->chunk_left ? P_DATA : P_CRC;
        }
        break;
      case P_DATA: {
        size_t k = n - i;
        if (k > g->chunk_left) k = g->chunk_left;
        g->crc = fimg_crc32(g->crc, p + i, k);
        st = chunk_data(ctx, p + i, k);
        if (st != FIMG_OK) goto out;
        i += k;
        g->chunk_left -= (uint32_t)k;
        if (g->chunk_left == 0) g->state = P_CRC;
        break;
      }
      default: /* P_CRC */
        g->hdr[g->hdr_n++] = p[i++];
        if (g->hdr_n == 4u) {
          g->hdr_n = 0;
          if (be32(g->hdr) != g->crc) {
            st = FIMG_E_PNG_CRC;
            goto out;
          }
          st = end_chunk(ctx);
          if (st != FIMG_OK) goto out;
          g->state = P_HDR;
        }
        break;
    }
  }
out:
  *used = i;
  return st;
}
