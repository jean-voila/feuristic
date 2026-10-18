// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Shared harness for the lib/fimg libFuzzer targets.
 *
 * Input layout: byte 0 = options, bytes 1.. = the image file.
 *   bit 0-1: configuration (default 720x720, 100x90 + pixel cap, 1024x1024,
 *            strict trailer)
 *   bit 2-7: chunking seed (0 = whole file at once)
 * Each input is decoded twice (fuzzer-chosen chunking, then whole file)
 * and both runs must agree on the status, the info and the bitmap.
 */
#ifndef FIMG_FUZZ_COMMON_H
#define FIMG_FUZZ_COMMON_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fimg.h"

typedef struct {
  uint32_t rows;
  uint32_t width;
  int bad;
  uint8_t *luma; /* optional capture (FIMG_MAX_DIM^2) */
} fz_luma_t;

static void fz_luma_cb(void *user, uint32_t y, const uint8_t *row, uint32_t w) {
  fz_luma_t *l = (fz_luma_t *)user;
  if (y != l->rows || w == 0 || w > FIMG_MAX_DIM || y >= FIMG_MAX_DIM)
    l->bad = 1;
  else if (l->luma != NULL)
    memcpy(l->luma + (size_t)y * w, row, w);
  l->width = w;
  l->rows++;
}

static void fz_config(uint8_t opt, fimg_config_t *c) {
  fimg_config_default(c);
  switch (opt & 3u) {
    case 1:
      c->max_out_width = 100;
      c->max_out_height = 90;
      c->max_out_pixels = 5000;
      break;
    case 2:
      c->max_out_width = 1024;
      c->max_out_height = 1024;
      break;
    case 3:
      c->flags = FIMG_FLAG_STRICT_TRAILER;
      break;
    default:
      break;
  }
}

typedef struct {
  fimg_status_t st;
  fimg_info_t info;
  uint32_t bm_hash;
} fz_result_t;

static uint32_t fz_hash(const uint8_t *p, size_t n) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < n; i++) h = (h ^ p[i]) * 16777619u;
  return h;
}

static fimg_ctx_t
    *fz_last_ctx; /* context of the last decode (internal inspection) */

static void fz_decode(const uint8_t *data, size_t len, uint8_t opt,
                      uint32_t seed, fz_luma_t *lum, fz_result_t *res) {
  static uint8_t ws[160 * 1024];
  static uint8_t bm[131072];
  fimg_config_t c;
  fimg_ctx_t *ctx;
  size_t off = 0;
  fimg_status_t st;

  fz_config(opt, &c);
  c.luma_cb = fz_luma_cb;
  c.luma_cb_user = lum;
  if (fimg_workspace_size(&c) > sizeof ws || fimg_bitmap_size(&c) > sizeof bm)
    abort();
  st = fimg_init(&ctx, ws + (seed & 7u), sizeof ws - 8, &c, bm, sizeof bm);
  if (st != FIMG_OK) abort();
  while (off < len) {
    size_t n = len - off;
    if (seed != 0) {
      seed = seed * 1103515245u + 12345u;
      n = 1u + ((seed >> 16) % 97u) * ((seed >> 8) % 3u == 0 ? 37u : 1u);
      if (n > len - off) n = len - off;
    }
    st = fimg_feed(ctx, data + off, n);
    off += n;
    if (st != FIMG_OK) break;
  }
  res->st = fimg_finish(ctx, &res->info);
  fz_last_ctx = ctx;
  res->bm_hash = 0;
  if (res->st == FIMG_OK) {
    const fimg_info_t *in = &res->info;
    if (!in->complete || in->out_width == 0 ||
        in->out_width > c.max_out_width || in->out_height > c.max_out_height ||
        in->stride != (in->out_width + 7u) / 8u ||
        in->src_width > FIMG_MAX_DIM || in->src_height > FIMG_MAX_DIM ||
        in->out_width != (in->src_width + in->scale - 1u) / in->scale ||
        lum->rows != in->src_height || lum->width != in->src_width || lum->bad)
      abort();
    if (c.max_out_pixels && in->out_width * in->out_height > c.max_out_pixels)
      abort();
    res->bm_hash = fz_hash(bm, in->stride * in->out_height);
  }
  if (fimg_feed(ctx, data, len ? 1 : 0) == FIMG_OK && len)
    abort(); /* must be FIMG_E_STATE or the sticky error */
}

static void fz_run(const uint8_t *data, size_t len, fz_luma_t *lum_first) {
  fz_result_t a, b;
  fz_luma_t l2 = {0, 0, 0, NULL};
  uint8_t opt;
  if (len < 1) return;
  opt = data[0];
  data++;
  len--;
  fz_decode(data, len, opt, (uint32_t)(opt >> 2) * 2654435761u, lum_first, &a);
  fz_decode(data, len, opt, 0, &l2, &b);
  if (a.st != b.st) abort(); /* chunking changed the outcome */
  if (a.st == FIMG_OK &&
      (a.bm_hash != b.bm_hash || memcmp(&a.info, &b.info, sizeof a.info) != 0))
    abort();
}

#endif
