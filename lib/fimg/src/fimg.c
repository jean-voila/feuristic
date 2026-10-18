// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Public API of lib/fimg: configuration, workspace, format sniffing, byte
 * accounting and dispatch to the PNG / JPEG decoders.
 */
#include "fimg_internal.h"

#define FIMG_MAGIC 0x46494d47u /* "FIMG" */

static const uint8_t k_png_sig[8] = {0x89, 0x50, 0x4e, 0x47,
                                     0x0d, 0x0a, 0x1a, 0x0a};
static const uint8_t k_jpg_sig[3] = {0xff, 0xd8,
                                     0xff}; /* SOI + start of the next marker */

void fimg_config_default(fimg_config_t *cfg) {
  if (cfg == NULL) return;
  memset(cfg, 0, sizeof *cfg);
  cfg->max_out_width = FIMG_DEFAULT_MAX_OUT_DIM;
  cfg->max_out_height = FIMG_DEFAULT_MAX_OUT_DIM;
  cfg->max_out_pixels = 0;
  cfg->max_file_bytes = FIMG_DEFAULT_MAX_FILE_BYTES;
  cfg->flags = 0;
}

static int config_valid(const fimg_config_t *cfg) {
  if (cfg == NULL) return 0;
  if (cfg->max_out_width < FIMG_MIN_OUT_DIM ||
      cfg->max_out_width > FIMG_MAX_DIM ||
      cfg->max_out_height < FIMG_MIN_OUT_DIM ||
      cfg->max_out_height > FIMG_MAX_DIM)
    return 0;
  if ((cfg->flags & ~(uint32_t)(FIMG_FLAG_STRICT_TRAILER | FIMG_FLAG_NO_PNG |
                                FIMG_FLAG_NO_JPEG)) != 0)
    return 0;
  if ((cfg->flags & (FIMG_FLAG_NO_PNG | FIMG_FLAG_NO_JPEG)) ==
      (FIMG_FLAG_NO_PNG | FIMG_FLAG_NO_JPEG))
    return 0;
  return 1;
}

size_t fimg_workspace_size(const fimg_config_t *cfg) {
  size_t dec = 0;
  if (!config_valid(cfg)) return 0;
  if (!(cfg->flags & FIMG_FLAG_NO_PNG)) dec = fimg_png_heap_size();
  if (!(cfg->flags & FIMG_FLAG_NO_JPEG) && fimg_jpeg_heap_size() > dec)
    dec = fimg_jpeg_heap_size();
  return 8u /* alignment slack */ + FIMG_ALIGN8(sizeof(fimg_ctx_t)) + dec +
         fimg_pix_heap_size(cfg);
}

size_t fimg_bitmap_size(const fimg_config_t *cfg) {
  if (!config_valid(cfg)) return 0;
  return (size_t)cfg->max_out_height * ((cfg->max_out_width + 7u) / 8u);
}

void *fimg_alloc(fimg_ctx_t *ctx, size_t n) {
  void *p;
  n = FIMG_ALIGN8(n);
  if (n > ctx->heap_size - ctx->heap_used) return NULL;
  p = ctx->heap + ctx->heap_used;
  ctx->heap_used += n;
  return p;
}

fimg_status_t fimg_init(fimg_ctx_t **out, void *workspace,
                        size_t workspace_size, const fimg_config_t *cfg,
                        uint8_t *bitmap, size_t bitmap_size) {
  uintptr_t base;
  size_t skip;
  fimg_ctx_t *ctx;

  if (out == NULL) return FIMG_E_PARAM;
  *out = NULL;
  if (workspace == NULL || bitmap == NULL || !config_valid(cfg))
    return FIMG_E_PARAM;
  if (workspace_size < fimg_workspace_size(cfg) ||
      bitmap_size < fimg_bitmap_size(cfg))
    return FIMG_E_WORKSPACE;

  base = (uintptr_t)workspace;
  skip = (size_t)((8u - (base & 7u)) & 7u);
  ctx = (fimg_ctx_t *)(void *)((uint8_t *)workspace + skip);
  memset(ctx, 0, sizeof *ctx);
  ctx->magic = FIMG_MAGIC;
  ctx->cfg = *cfg;
  ctx->max_pixels = cfg->max_out_pixels
                        ? cfg->max_out_pixels
                        : (uint32_t)cfg->max_out_width * cfg->max_out_height;
  ctx->max_file =
      cfg->max_file_bytes ? cfg->max_file_bytes : FIMG_DEFAULT_MAX_FILE_BYTES;
  ctx->status = FIMG_OK;
  ctx->phase = FIMG_PH_SNIFF;
  ctx->bitmap = bitmap;
  ctx->bitmap_size = bitmap_size;
  ctx->heap = (uint8_t *)ctx + FIMG_ALIGN8(sizeof *ctx);
  ctx->heap_size = workspace_size - skip - FIMG_ALIGN8(sizeof *ctx);
  ctx->heap_used = 0;
  *out = ctx;
  return FIMG_OK;
}

static fimg_status_t fail(fimg_ctx_t *ctx, fimg_status_t st) {
  ctx->status = st;
  return st;
}

/* Hand @p n bytes to the active decoder, enforcing the file size limit. */
static fimg_status_t dispatch(fimg_ctx_t *ctx, const uint8_t *p, size_t n) {
  while (n > 0 && ctx->phase != FIMG_PH_DONE) {
    size_t allow = ctx->max_file - ctx->bytes_in, k = n, used = 0;
    fimg_status_t st;
    if (allow == 0) return fail(ctx, FIMG_E_FILE_TOO_LARGE);
    if (k > allow) k = allow;
    if (ctx->phase == FIMG_PH_PNG)
      st = fimg_png_feed(ctx, p, k, &used);
    else
      st = fimg_jpeg_feed(ctx, p, k, &used);
    if (st != FIMG_OK) return fail(ctx, st);
    if (used > k) return fail(ctx, FIMG_E_INTERNAL);
    ctx->bytes_in += (uint32_t)used;
    p += used;
    n -= used;
    if (used < k && ctx->phase != FIMG_PH_DONE)
      return fail(
          ctx, FIMG_E_INTERNAL); /* decoders consume everything until the end */
  }
  if (n > 0 && (ctx->cfg.flags & FIMG_FLAG_STRICT_TRAILER))
    return fail(ctx, FIMG_E_TRAILING_DATA);
  return FIMG_OK;
}

fimg_status_t fimg_feed(fimg_ctx_t *ctx, const uint8_t *data, size_t len) {
  if (ctx == NULL || ctx->magic != FIMG_MAGIC) return FIMG_E_PARAM;
  if (ctx->status != FIMG_OK) return ctx->status;
  if (ctx->phase == FIMG_PH_FINISHED) return FIMG_E_STATE;
  if (len == 0) return FIMG_OK;
  if (data == NULL) return fail(ctx, FIMG_E_PARAM);

  if (ctx->phase == FIMG_PH_SNIFF) {
    while (len > 0 && ctx->phase == FIMG_PH_SNIFF) {
      uint8_t b = *data;
      uint32_t i = ctx->sniff_n;
      /* earlier bytes all matched one signature; the first byte tells which */
      int png_ok = !(ctx->cfg.flags & FIMG_FLAG_NO_PNG) && i < 8u &&
                   b == k_png_sig[i] &&
                   (i == 0 || ctx->sniff[0] == k_png_sig[0]);
      int jpg_ok = !(ctx->cfg.flags & FIMG_FLAG_NO_JPEG) && i < 3u &&
                   b == k_jpg_sig[i] &&
                   (i == 0 || ctx->sniff[0] == k_jpg_sig[0]);
      if (!png_ok && !jpg_ok) return fail(ctx, FIMG_E_NOT_IMAGE);
      ctx->sniff[ctx->sniff_n++] = b;
      data++;
      len--;
      if (png_ok && ctx->sniff_n == 8u) {
        ctx->format = FIMG_FORMAT_PNG;
        ctx->phase = FIMG_PH_PNG;
        fimg_png_begin(ctx);
      } else if (jpg_ok && ctx->sniff_n == 3u) {
        fimg_status_t st;
        ctx->format = FIMG_FORMAT_JPEG;
        ctx->phase = FIMG_PH_JPEG;
        st = fimg_jpeg_begin(ctx);
        if (st != FIMG_OK) return fail(ctx, st);
      }
    }
    if (ctx->phase == FIMG_PH_SNIFF) return FIMG_OK;
    /* replay the signature bytes through the decoder */
    {
      fimg_status_t st = dispatch(ctx, ctx->sniff, ctx->sniff_n);
      if (st != FIMG_OK) return st;
    }
  }
  if (len == 0) return FIMG_OK;
  if (ctx->phase == FIMG_PH_DONE) {
    if (ctx->cfg.flags & FIMG_FLAG_STRICT_TRAILER)
      return fail(ctx, FIMG_E_TRAILING_DATA);
    return FIMG_OK;
  }
  return dispatch(ctx, data, len);
}

fimg_status_t fimg_get_info(const fimg_ctx_t *ctx, fimg_info_t *info) {
  if (ctx == NULL || info == NULL || ctx->magic != FIMG_MAGIC)
    return FIMG_E_PARAM;
  memset(info, 0, sizeof *info);
  info->format = ctx->format;
  info->bytes_consumed = ctx->bytes_in;
  if (ctx->pix.ready) {
    info->src_width = ctx->pix.src_w;
    info->src_height = ctx->pix.src_h;
    info->scale = ctx->pix.f;
    info->out_width = ctx->pix.out_w;
    info->out_height = ctx->pix.out_h;
    info->stride = ctx->pix.stride;
    info->window = ctx->pix.k;
  }
  info->complete =
      ctx->status == FIMG_OK &&
      (ctx->phase == FIMG_PH_DONE || ctx->phase == FIMG_PH_FINISHED) &&
      fimg_pix_complete(ctx);
  return ctx->status;
}

fimg_status_t fimg_finish(fimg_ctx_t *ctx, fimg_info_t *info) {
  fimg_status_t st;
  if (ctx == NULL || ctx->magic != FIMG_MAGIC) {
    if (info != NULL) memset(info, 0, sizeof *info);
    return FIMG_E_PARAM;
  }
  if (ctx->status == FIMG_OK) {
    if (ctx->phase == FIMG_PH_SNIFF)
      ctx->status = FIMG_E_NOT_IMAGE;
    else if (ctx->phase == FIMG_PH_PNG || ctx->phase == FIMG_PH_JPEG)
      ctx->status = FIMG_E_TRUNCATED;
    else if (ctx->phase == FIMG_PH_DONE && !fimg_pix_complete(ctx))
      ctx->status = FIMG_E_INTERNAL;
  }
  ctx->phase = FIMG_PH_FINISHED;
  st = ctx->status;
  if (info != NULL) (void)fimg_get_info(ctx, info);
  return st;
}

fimg_category_t fimg_status_category(fimg_status_t st) {
  switch (st) {
    case FIMG_OK:
      return FIMG_CAT_OK;
    case FIMG_E_NOT_IMAGE:
      return FIMG_CAT_NOT_IMAGE;
    case FIMG_E_FILE_TOO_LARGE:
      return FIMG_CAT_FILE_TOO_LARGE;
    case FIMG_E_DIMENSIONS:
      return FIMG_CAT_DIMENSIONS;
    case FIMG_E_PNG_INTERLACED:
    case FIMG_E_PNG_UNSUPPORTED:
      return FIMG_CAT_PNG_UNSUPPORTED;
    case FIMG_E_JPEG_PROGRESSIVE:
    case FIMG_E_JPEG_EXTENDED:
    case FIMG_E_JPEG_LOSSLESS:
    case FIMG_E_JPEG_ARITHMETIC:
    case FIMG_E_JPEG_HIERARCHICAL:
    case FIMG_E_JPEG_COLOR:
    case FIMG_E_JPEG_SAMPLING:
    case FIMG_E_JPEG_MULTIFRAME:
      return FIMG_CAT_JPEG_UNSUPPORTED;
    case FIMG_E_PNG_CRC:
    case FIMG_E_PNG_CORRUPT:
    case FIMG_E_PNG_ZLIB:
    case FIMG_E_PNG_DATA_SIZE:
    case FIMG_E_JPEG_CORRUPT:
    case FIMG_E_JPEG_HUFFMAN:
    case FIMG_E_TRAILING_DATA:
      return FIMG_CAT_CORRUPT;
    case FIMG_E_TRUNCATED:
      return FIMG_CAT_TRUNCATED;
    default:
      return FIMG_CAT_INTERNAL;
  }
}

const char *fimg_status_name(fimg_status_t st) {
  static const char *const names[FIMG_STATUS_COUNT] = {
      "ok",
      "param",
      "workspace",
      "state",
      "not-image",
      "file-too-large",
      "dimensions",
      "truncated",
      "trailing-data",
      "png-interlaced",
      "png-unsupported",
      "png-crc",
      "png-corrupt",
      "png-zlib",
      "png-data-size",
      "jpeg-progressive",
      "jpeg-extended",
      "jpeg-lossless",
      "jpeg-arithmetic",
      "jpeg-hierarchical",
      "jpeg-color",
      "jpeg-sampling",
      "jpeg-multiframe",
      "jpeg-corrupt",
      "jpeg-huffman",
      "limit",
      "internal",
  };
  if ((unsigned)st >= (unsigned)FIMG_STATUS_COUNT) return "unknown";
  return names[st];
}

void fimg_secure_zero(void *p, size_t len) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  if (p == NULL) return;
  while (len--) *v++ = 0;
}
