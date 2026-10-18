// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Unit tests of lib/fimg: API contract, configuration and workspace sizing,
 * file-size limit, trailing-data policy, scale-factor selection, binarizer
 * behaviour, checksums, the inflater's suspension paths and synthetic
 * worst-case streams (1024 x 1024 RGBA16 PNG, decompression bomb, huge
 * JPEG segments).
 */
#include <time.h>

#include "fimg.h"
#include "fimg_internal.h"
#include "test_util.h"

#ifndef FIMG_VECTORS_DIR
#define FIMG_VECTORS_DIR "vectors"
#endif

/* ---------------------------------------------------------------------- */
/* tiny PNG / deflate writers                                               */
/* ---------------------------------------------------------------------- */

typedef struct {
  uint8_t *p;
  size_t n, cap;
} buf_t;

static void put(buf_t *b, const void *d, size_t n) {
  if (b->n + n > b->cap) {
    b->cap = (b->n + n) * 2 + 1024;
    b->p = (uint8_t *)realloc(b->p, b->cap);
  }
  memcpy(b->p + b->n, d, n);
  b->n += n;
}

static void put32(buf_t *b, uint32_t v) {
  uint8_t x[4] = {(uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8),
                  (uint8_t)v};
  put(b, x, 4);
}

static void put_chunk(buf_t *b, const char *type, const uint8_t *d, size_t n) {
  uint32_t crc = fimg_crc32(0, (const uint8_t *)type, 4);
  crc = fimg_crc32(crc, d, n);
  put32(b, (uint32_t)n);
  put(b, type, 4);
  put(b, d, n);
  put32(b, crc);
}

typedef struct {
  buf_t *b;
  uint32_t acc, n;
} bits_t;

static void bits_put(bits_t *w, uint32_t v, uint32_t n) /* LSB first */
{
  for (uint32_t i = 0; i < n; i++) {
    w->acc |= ((v >> i) & 1u) << w->n;
    if (++w->n == 8) {
      uint8_t c = (uint8_t)w->acc;
      put(w->b, &c, 1);
      w->acc = w->n = 0;
    }
  }
}

static void bits_code(bits_t *w, uint32_t code,
                      uint32_t n) /* Huffman: MSB first */
{
  for (uint32_t i = n; i-- > 0;) bits_put(w, (code >> i) & 1u, 1);
}

/* zlib stream of @p total zero bytes using fixed-Huffman runs (dist 1, len
 * 258). */
static void zlib_zeros(buf_t *b, uint32_t total) {
  bits_t w = {b, 0, 0};
  uint8_t hdr[2] = {0x78, 0x01};
  uint32_t left = total, a = 1, s = 0;
  put(b, hdr, 2);
  bits_put(&w, 1, 1);
  bits_put(&w, 1, 2);
  if (left > 0) {
    bits_code(&w, 0x30, 8); /* literal 0 */
    left--;
  }
  while (left >= 258) {
    bits_code(&w, 0xc5, 8); /* length 258 */
    bits_code(&w, 0, 5);    /* distance 1 */
    left -= 258;
  }
  while (left--) bits_code(&w, 0x30, 8);
  bits_code(&w, 0, 7); /* end of block */
  if (w.n) bits_put(&w, 0, 8 - w.n);
  /* Adler-32 of zeros: a = 1, b = total mod 65521 */
  s = total % 65521u;
  put32(b, (s << 16) | a);
}

static void png_header(buf_t *b, uint32_t w, uint32_t h, uint8_t depth,
                       uint8_t ctype) {
  static const uint8_t sig[8] = {0x89, 'P', 'N', 'G', 0x0d, 0x0a, 0x1a, 0x0a};
  uint8_t ih[13] = {(uint8_t)(w >> 24),
                    (uint8_t)(w >> 16),
                    (uint8_t)(w >> 8),
                    (uint8_t)w,
                    (uint8_t)(h >> 24),
                    (uint8_t)(h >> 16),
                    (uint8_t)(h >> 8),
                    (uint8_t)h,
                    depth,
                    ctype,
                    0,
                    0,
                    0};
  put(b, sig, 8);
  put_chunk(b, "IHDR", ih, 13);
}

/* Gray 8-bit PNG from a pixel callback, stored (uncompressed) deflate blocks.
 */
static void png_gray(buf_t *b, uint32_t w, uint32_t h,
                     uint8_t (*px)(uint32_t, uint32_t)) {
  buf_t raw = {0}, z = {0};
  uint32_t a = 1, s = 0;
  size_t off = 0;
  uint8_t hdr[2] = {0x78, 0x01};
  for (uint32_t y = 0; y < h; y++) {
    uint8_t f = 0;
    put(&raw, &f, 1);
    for (uint32_t x = 0; x < w; x++) {
      uint8_t v = px(x, y);
      put(&raw, &v, 1);
    }
  }
  fimg_adler32(&a, &s, raw.p, raw.n);
  put(&z, hdr, 2);
  while (off < raw.n || off == 0) {
    size_t k = raw.n - off > 65535 ? 65535 : raw.n - off;
    uint8_t bh[5] = {(uint8_t)(off + k == raw.n), (uint8_t)k, (uint8_t)(k >> 8),
                     (uint8_t)~k, (uint8_t)(~k >> 8)};
    put(&z, bh, 5);
    put(&z, raw.p + off, k);
    off += k;
    if (k == 0) break;
  }
  put32(&z, (s << 16) | a);
  png_header(b, w, h, 8, 0);
  put_chunk(b, "IDAT", z.p, z.n);
  put_chunk(b, "IEND", NULL, 0);
  free(raw.p);
  free(z.p);
}

/* ---------------------------------------------------------------------- */
/* decode helper                                                            */
/* ---------------------------------------------------------------------- */

typedef struct {
  fimg_status_t st;
  fimg_info_t info;
  uint8_t *bm;
} out_t;

static void run(const uint8_t *d, size_t n, const fimg_config_t *cfg,
                size_t chunk, out_t *o) {
  size_t wsz = fimg_workspace_size(cfg), bsz = fimg_bitmap_size(cfg), off = 0;
  uint8_t *ws = (uint8_t *)malloc(wsz);
  fimg_ctx_t *ctx;
  fimg_status_t st;
  o->bm = (uint8_t *)malloc(bsz);
  st = fimg_init(&ctx, ws, wsz, cfg, o->bm, bsz);
  CHECK(st == FIMG_OK);
  while (st == FIMG_OK && off < n) {
    size_t k = n - off < chunk ? n - off : chunk;
    st = fimg_feed(ctx, d + off, k);
    off += k;
  }
  o->st = fimg_finish(ctx, &o->info);
  free(ws);
}

static int bit(const out_t *o, uint32_t x, uint32_t y) {
  return (o->bm[y * o->info.stride + x / 8] >> (7 - x % 8)) & 1;
}

/* ---------------------------------------------------------------------- */

static void test_config(void) {
  fimg_config_t c;
  fimg_ctx_t *ctx = (fimg_ctx_t *)(uintptr_t)1;
  static uint8_t ws[200000], bm[140000];

  fimg_config_default(&c);
  CHECK(c.max_out_width == 720 && c.max_out_height == 720 &&
        c.max_file_bytes == 262144);
  CHECK(fimg_bitmap_size(&c) == 720u * 90u);
  CHECK(fimg_bitmap_size(&c) <= 65536u);
  {
    size_t ws_all = fimg_workspace_size(&c);
    c.flags = FIMG_FLAG_NO_JPEG;
    size_t ws_png = fimg_workspace_size(&c);
    c.flags = FIMG_FLAG_NO_PNG;
    size_t ws_jpeg = fimg_workspace_size(&c);
    printf("workspace: default %zu B (PNG+JPEG), PNG only %zu, JPEG only %zu\n",
           ws_all, ws_png, ws_jpeg);
  }
  c.flags = FIMG_FLAG_NO_JPEG;
  CHECK(fimg_workspace_size(&c) <= 96u * 1024u);
  c.flags = FIMG_FLAG_NO_PNG;
  CHECK(fimg_workspace_size(&c) <= 64u * 1024u);
  c.flags = 0;
  printf("sizeof(fimg_ctx_t) = %zu B\n", sizeof(fimg_ctx_t));

  c.max_out_width = 1024;
  c.max_out_height = 1024;
  printf("workspace for 1024x1024 output: %zu B, bitmap %zu B\n",
         fimg_workspace_size(&c), fimg_bitmap_size(&c));
  c.max_out_width = 7;
  CHECK(fimg_workspace_size(&c) == 0 && fimg_bitmap_size(&c) == 0);
  c.max_out_width = 1025;
  CHECK(fimg_workspace_size(&c) == 0);
  fimg_config_default(&c);
  c.flags = 0x80;
  CHECK(fimg_workspace_size(&c) == 0);
  c.flags = FIMG_FLAG_NO_PNG | FIMG_FLAG_NO_JPEG;
  CHECK(fimg_workspace_size(&c) == 0);
  CHECK(fimg_workspace_size(NULL) == 0);

  fimg_config_default(&c);
  CHECK(fimg_init(NULL, ws, sizeof ws, &c, bm, sizeof bm) == FIMG_E_PARAM);
  CHECK(fimg_init(&ctx, NULL, sizeof ws, &c, bm, sizeof bm) == FIMG_E_PARAM &&
        ctx == NULL);
  CHECK(fimg_init(&ctx, ws, sizeof ws, NULL, bm, sizeof bm) == FIMG_E_PARAM);
  CHECK(fimg_init(&ctx, ws, sizeof ws, &c, NULL, sizeof bm) == FIMG_E_PARAM);
  CHECK(fimg_init(&ctx, ws, fimg_workspace_size(&c) - 1, &c, bm, sizeof bm) ==
        FIMG_E_WORKSPACE);
  CHECK(fimg_init(&ctx, ws, sizeof ws, &c, bm, fimg_bitmap_size(&c) - 1) ==
        FIMG_E_WORKSPACE);
  CHECK(fimg_init(&ctx, ws, fimg_workspace_size(&c), &c, bm,
                  fimg_bitmap_size(&c)) == FIMG_OK);
  CHECK(fimg_feed(NULL, bm, 1) == FIMG_E_PARAM);
  CHECK(fimg_finish(NULL, NULL) == FIMG_E_PARAM);
  CHECK(fimg_get_info(ctx, NULL) == FIMG_E_PARAM);
  CHECK(fimg_feed(ctx, NULL, 0) == FIMG_OK);
  CHECK(fimg_feed(ctx, NULL, 5) == FIMG_E_PARAM);
  CHECK(fimg_feed(ctx, bm, 1) == FIMG_E_PARAM); /* sticky */
  CHECK(fimg_finish(ctx, NULL) == FIMG_E_PARAM);

  /* empty stream, feed after finish */
  CHECK(fimg_init(&ctx, ws, sizeof ws, &c, bm, sizeof bm) == FIMG_OK);
  {
    fimg_info_t in;
    CHECK(fimg_finish(ctx, &in) == FIMG_E_NOT_IMAGE);
    CHECK(in.format == FIMG_FORMAT_UNKNOWN && !in.complete);
    CHECK(fimg_feed(ctx, bm, 1) == FIMG_E_NOT_IMAGE);
  }
  CHECK(fimg_init(&ctx, ws, sizeof ws, &c, bm, sizeof bm) == FIMG_OK);
  {
    static const uint8_t junk[] = {0x89, 'P', 'X'};
    CHECK(fimg_feed(ctx, junk, 2) == FIMG_OK);
    CHECK(fimg_feed(ctx, junk + 2, 1) == FIMG_E_NOT_IMAGE);
    CHECK(fimg_feed(ctx, junk, 1) == FIMG_E_NOT_IMAGE);
  }
}

static void test_status_names(void) {
  for (int i = 0; i < FIMG_STATUS_COUNT; i++) {
    const char *n = fimg_status_name((fimg_status_t)i);
    CHECK(n != NULL && strcmp(n, "unknown") != 0);
    for (int k = 0; k < i; k++)
      CHECK(strcmp(n, fimg_status_name((fimg_status_t)k)) != 0);
    CHECK((fimg_status_category((fimg_status_t)i) == FIMG_CAT_OK) ==
          (i == FIMG_OK));
  }
  CHECK(strcmp(fimg_status_name(FIMG_STATUS_COUNT), "unknown") == 0);
  CHECK(fimg_status_category(FIMG_E_PNG_INTERLACED) ==
        FIMG_CAT_PNG_UNSUPPORTED);
  CHECK(fimg_status_category(FIMG_E_JPEG_PROGRESSIVE) ==
        FIMG_CAT_JPEG_UNSUPPORTED);
  CHECK(fimg_status_category(FIMG_E_PNG_CRC) == FIMG_CAT_CORRUPT);
  CHECK(fimg_status_category(FIMG_E_JPEG_HUFFMAN) == FIMG_CAT_CORRUPT);
  CHECK(fimg_status_category(FIMG_E_TRUNCATED) == FIMG_CAT_TRUNCATED);
  CHECK(fimg_status_category(FIMG_E_DIMENSIONS) == FIMG_CAT_DIMENSIONS);
  CHECK(fimg_status_category(FIMG_E_FILE_TOO_LARGE) == FIMG_CAT_FILE_TOO_LARGE);
  CHECK(fimg_status_category(FIMG_E_LIMIT) == FIMG_CAT_INTERNAL);
}

static void test_checksums(void) {
  uint32_t a = 1, b = 0;
  CHECK(fimg_crc32(0, (const uint8_t *)"123456789", 9) == 0xcbf43926u);
  CHECK(fimg_crc32(fimg_crc32(0, (const uint8_t *)"1234", 4),
                   (const uint8_t *)"56789", 5) == 0xcbf43926u);
  fimg_adler32(&a, &b, (const uint8_t *)"Wikipedia", 9);
  CHECK(((b << 16) | a) == 0x11e60398u);
  {
    static uint8_t ff[100000];
    memset(ff, 0xff, sizeof ff);
    a = 1;
    b = 0;
    fimg_adler32(&a, &b, ff, sizeof ff);
    /* reference value computed with zlib.adler32(b"\xff" * 100000) */
    CHECK(((b << 16) | a) == 0x149a302cu);
    CHECK(a < 65521u && b < 65521u);
  }
  for (uint32_t x = 0; x <= 65535u; x++)
    CHECK_MSG(fimg_div255(x) == (2u * x + 255u) / 510u, "x=%u", x);
  CHECK(fimg_rgb_luma(255, 255, 255) == 255 && fimg_rgb_luma(0, 0, 0) == 0);
  CHECK(fimg_over_white(0, 0) == 255 && fimg_over_white(0, 255) == 0 &&
        fimg_over_white(100, 128) == 177);
}

static void test_inflate_suspend(void) {
  static uint8_t win[FIMG_INF_WSIZE];
  static fimg_inflate_t s;
  buf_t z = {0};
  uint32_t total = 0;
  size_t off = 0;
  fimg_inf_result_t r = FIMG_INF_NEED_INPUT;
  int calls = 0, bad = 0;

  zlib_zeros(&z, 1000000);
  fimg_inflate_init(&s, win);
  /* one input byte and at most 7 output bytes per call */
  while (r != FIMG_INF_DONE && r >= 0 && calls < 10000000) {
    size_t used = 0;
    uint32_t prod = 0, start = s.wpos;
    r = fimg_inflate(&s, z.p + off, off < z.n ? 1 : 0, &used, 7, &prod);
    for (uint32_t i = 0; i < prod; i++)
      bad += win[(start + i) & FIMG_INF_WMASK] != 0;
    off += used;
    total += prod;
    calls++;
  }
  CHECK(r == FIMG_INF_DONE && total == 1000000u && bad == 0 && off == z.n);
  {
    size_t used = 9;
    uint32_t prod = 9;
    CHECK(fimg_inflate(&s, z.p, z.n, &used, 100, &prod) == FIMG_INF_DONE &&
          used == 0 && prod == 0);
  }
  /* sticky error */
  fimg_inflate_init(&s, win);
  {
    static const uint8_t badhdr[] = {0x78, 0x9d, 0x01};
    size_t used;
    uint32_t prod;
    CHECK(fimg_inflate(&s, badhdr, 3, &used, 100, &prod) ==
          FIMG_INF_ERR_HEADER);
    CHECK(fimg_inflate(&s, z.p, z.n, &used, 100, &prod) ==
              FIMG_INF_ERR_HEADER &&
          used == 0);
  }
  free(z.p);
}

static uint8_t px_white(uint32_t x, uint32_t y) {
  (void)x;
  (void)y;
  return 250;
}
static uint8_t px_black(uint32_t x, uint32_t y) {
  (void)x;
  (void)y;
  return 10;
}
static uint8_t px_check40(uint32_t x, uint32_t y) {
  return ((x / 40 + y / 40) & 1) ? 230 : 20;
}
static uint8_t px_bigsquare(uint32_t x, uint32_t y) {
  return (x >= 100 && x < 300 && y >= 100 && y < 300) ? 15 : 240;
}
static uint8_t px_gradient_dots(uint32_t x, uint32_t y) {
  uint32_t bg = 60 + (x * 180) / 400; /* 60 .. 240 left to right */
  return ((x % 12) < 4 && (y % 12) < 4) ? (uint8_t)(bg / 4) : (uint8_t)bg;
}
static uint8_t px_xy(uint32_t x, uint32_t y) { return (uint8_t)(x ^ y); }

static void test_binarizer(void) {
  fimg_config_t c;
  buf_t b = {0};
  out_t o;
  uint32_t x, y, errs;

  fimg_config_default(&c);
  png_gray(&b, 300, 200, px_white);
  run(b.p, b.n, &c, 4096, &o);
  CHECK(o.st == FIMG_OK && o.info.out_width == 300 && o.info.scale == 1);
  errs = 0;
  for (y = 0; y < 200; y++)
    for (x = 0; x < 300; x++) errs += bit(&o, x, y);
  CHECK_MSG(errs == 0, "white: %u dark pixels", errs);
  free(o.bm);
  b.n = 0;

  /* uniformly dark image: no global contrast -> light (documented) */
  png_gray(&b, 64, 64, px_black);
  run(b.p, b.n, &c, 4096, &o);
  errs = 0;
  for (y = 0; y < 64; y++)
    for (x = 0; x < 64; x++) errs += bit(&o, x, y);
  CHECK(o.st == FIMG_OK && errs == 0);
  free(o.bm);
  b.n = 0;

  /* 40 px checkerboard, window 25: interiors are flat */
  png_gray(&b, 400, 400, px_check40);
  run(b.p, b.n, &c, 777, &o);
  errs = 0;
  for (y = 0; y < 400; y++)
    for (x = 0; x < 400; x++)
      errs += bit(&o, x, y) != (int)(((x / 40 + y / 40) & 1) == 0);
  CHECK_MSG(errs < 400u * 400u / 1000u, "checkerboard: %u errors", errs);
  free(o.bm);
  b.n = 0;

  /* dark square much larger than the window */
  png_gray(&b, 400, 400, px_bigsquare);
  run(b.p, b.n, &c, 1, &o);
  errs = 0;
  for (y = 0; y < 400; y++)
    for (x = 0; x < 400; x++)
      errs +=
          bit(&o, x, y) != (int)(x >= 100 && x < 300 && y >= 100 && y < 300);
  CHECK_MSG(errs == 0, "big square: %u errors", errs);
  free(o.bm);
  b.n = 0;

  /* dots on a strong horizontal illumination gradient */
  png_gray(&b, 400, 300, px_gradient_dots);
  run(b.p, b.n, &c, 999, &o);
  errs = 0;
  for (y = 0; y < 300; y++)
    for (x = 0; x < 400; x++)
      errs += bit(&o, x, y) != (int)((x % 12) < 4 && (y % 12) < 4);
  CHECK_MSG(errs < 400u * 300u / 200u, "gradient dots: %u errors", errs);
  free(o.bm);
  free(b.p);
}

static void test_scale(void) {
  static const struct {
    uint32_t w, h, mw, mh, mp, f, ow, oh;
  } cases[] = {
      {1024, 1024, 724, 724, 0, 2, 512, 512},
      {724, 724, 724, 724, 0, 1, 724, 724},
      {721, 720, 720, 720, 0, 2, 361, 360},
      {725, 1, 724, 724, 0, 2, 363, 1},
      {1, 1024, 724, 100, 0, 11, 1, 94},
      {1000, 1000, 1024, 1024, 10000, 10, 100, 100},
      {1, 1, 8, 8, 0, 1, 1, 1},
      {1024, 1024, 8, 8, 0, 128, 8, 8},
      {1023, 17, 724, 724, 0, 2, 512, 9},
      {1024, 1024, 1024, 1024, 0, 1, 1024, 1024},
      {999, 333, 100, 100, 5000, 10, 100, 34},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    fimg_config_t c;
    buf_t b = {0};
    out_t o;
    fimg_config_default(&c);
    c.max_out_width = (uint16_t)cases[i].mw;
    c.max_out_height = (uint16_t)cases[i].mh;
    c.max_out_pixels = cases[i].mp;
    png_gray(&b, cases[i].w, cases[i].h, px_xy);
    c.max_file_bytes = 4u << 20; /* stored deflate: larger than real files */
    run(b.p, b.n, &c, 65536, &o);
    CHECK_MSG(o.st == FIMG_OK && o.info.scale == cases[i].f &&
                  o.info.out_width == cases[i].ow &&
                  o.info.out_height == cases[i].oh &&
                  o.info.stride == (cases[i].ow + 7) / 8,
              "case %zu: st %s f %u out %ux%u", i, fimg_status_name(o.st),
              o.info.scale, o.info.out_width, o.info.out_height);
    CHECK(o.info.src_width == cases[i].w && o.info.src_height == cases[i].h &&
          o.info.complete);
    free(o.bm);
    free(b.p);
  }
}

static void test_file_limit(void) {
  fimg_config_t c;
  buf_t b = {0};
  out_t o;
  size_t n;

  fimg_config_default(&c);
  png_gray(&b, 40, 30, px_xy);
  n = b.n;
  c.max_file_bytes = (uint32_t)n;
  run(b.p, n, &c, 3, &o);
  CHECK(o.st == FIMG_OK && o.info.bytes_consumed == n);
  free(o.bm);
  c.max_file_bytes = (uint32_t)n - 1;
  run(b.p, n, &c, 3, &o);
  CHECK(o.st == FIMG_E_FILE_TOO_LARGE);
  free(o.bm);
  /* trailing bytes are not counted */
  put(&b, "trailing-garbage", 16);
  c.max_file_bytes = (uint32_t)n;
  run(b.p, b.n, &c, 5, &o);
  CHECK(o.st == FIMG_OK && o.info.bytes_consumed == n);
  free(o.bm);
  c.flags = FIMG_FLAG_STRICT_TRAILER;
  run(b.p, b.n, &c, 5, &o);
  CHECK(o.st == FIMG_E_TRAILING_DATA);
  free(o.bm);
  run(b.p, b.n, &c, b.n, &o);
  CHECK(o.st == FIMG_E_TRAILING_DATA);
  free(o.bm);
  /* format switches */
  c.flags = FIMG_FLAG_NO_PNG;
  run(b.p, n, &c, 5, &o);
  CHECK(o.st == FIMG_E_NOT_IMAGE);
  free(o.bm);
  free(b.p);

  /* 300 KiB ancillary chunk: refused at the default 256 KiB */
  {
    uint8_t *big = (uint8_t *)calloc(300 * 1024, 1);
    b.p = NULL;
    b.n = b.cap = 0;
    png_header(&b, 10, 10, 8, 0);
    put_chunk(&b, "tEXt", big, 300 * 1024);
    fimg_config_default(&c);
    run(b.p, b.n, &c, 512, &o);
    CHECK(o.st == FIMG_E_FILE_TOO_LARGE);
    CHECK(o.info.src_width == 10);
    free(o.bm);
    free(big);
    free(b.p);
  }
}

static void test_png_worst_case(void) {
  fimg_config_t c;
  buf_t b = {0}, z = {0};
  out_t o;
  clock_t t0;
  uint32_t dark = 0;

  /* 1024 x 1024 RGBA, 16 bit: 8 MiB of scanlines from ~50 KiB of deflate */
  zlib_zeros(&z, 1024u * (1024u * 8u + 1u));
  png_header(&b, 1024, 1024, 16, 6);
  put_chunk(&b, "IDAT", z.p, z.n);
  put_chunk(&b, "IEND", NULL, 0);
  fimg_config_default(&c);
  t0 = clock();
  run(b.p, b.n, &c, 64, &o);
  printf("1024x1024 RGBA16 PNG (8 MiB inflated, %zu B file): %.1f ms on host\n",
         b.n, 1e3 * (double)(clock() - t0) / CLOCKS_PER_SEC);
  CHECK(o.st == FIMG_OK && o.info.scale == 2 && o.info.out_width == 512);
  for (uint32_t y = 0; y < o.info.out_height; y++)
    for (uint32_t x = 0; x < o.info.out_width; x++)
      dark += (uint32_t)bit(&o, x, y);
  CHECK(dark == 0); /* fully transparent -> white */
  free(o.bm);

  /* one extra inflated byte: decompression bomb */
  b.n = 0;
  z.n = 0;
  zlib_zeros(&z, 1024u * (1024u * 8u + 1u) + 1u);
  png_header(&b, 1024, 1024, 16, 6);
  put_chunk(&b, "IDAT", z.p, z.n);
  put_chunk(&b, "IEND", NULL, 0);
  run(b.p, b.n, &c, 4096, &o);
  CHECK(o.st == FIMG_E_PNG_DATA_SIZE);
  free(o.bm);
  /* gigantic bomb: 2 GB of zeros claimed, refused after the expected size */
  b.n = 0;
  z.n = 0;
  zlib_zeros(&z, 60000000u);
  png_header(&b, 16, 16, 8, 0);
  put_chunk(&b, "IDAT", z.p, z.n);
  put_chunk(&b, "IEND", NULL, 0);
  c.max_file_bytes = 1u << 20;
  t0 = clock();
  run(b.p, b.n, &c, 4096, &o);
  CHECK(o.st == FIMG_E_PNG_DATA_SIZE);
  CHECK((double)(clock() - t0) / CLOCKS_PER_SEC < 2.0);
  free(o.bm);
  free(b.p);
  free(z.p);
}

static void test_jpeg_segments(void) {
  char path[512];
  size_t n;
  uint8_t *d;
  buf_t b = {0};
  fimg_config_t c;
  out_t ref, o;
  static uint8_t com[65533];

  snprintf(path, sizeof path, "%s/%s", FIMG_VECTORS_DIR, "jpg_420_q50.jpg");
  d = read_file(path, &n);
  CHECK(d != NULL);
  if (d == NULL) return;
  fimg_config_default(&c);
  run(d, n, &c, n, &ref);
  CHECK(ref.st == FIMG_OK);
  /* SOI + 3 maximal COM segments (> staging buffer) + rest of the file */
  put(&b, d, 2);
  memset(com, 0xff, sizeof com);
  for (int i = 0; i < 3; i++) {
    uint8_t hdr[4] = {0xff, 0xfe, 0xff, 0xff};
    put(&b, hdr, 4);
    put(&b, com, sizeof com);
  }
  /* fill bytes before the next marker */
  put(&b, "\xff\xff\xff", 3);
  put(&b, d + 2, n - 2);
  run(b.p, b.n, &c, 1000, &o);
  CHECK(o.st == FIMG_OK && o.info.out_width == ref.info.out_width);
  CHECK(o.st == FIMG_OK &&
        memcmp(o.bm, ref.bm, ref.info.stride * ref.info.out_height) == 0);
  free(o.bm);
  c.max_file_bytes = 8u << 20;
  run(b.p, b.n, &c, 1000, &o);
  CHECK(o.st == FIMG_OK);
  free(o.bm);
  fimg_config_default(&c);
  /* the 196 KiB of COM fit under 256 KiB; four segments do not */
  {
    buf_t b2 = {0};
    put(&b2, d, 2);
    for (int i = 0; i < 4; i++) {
      uint8_t hdr[4] = {0xff, 0xfe, 0xff, 0xff};
      put(&b2, hdr, 4);
      put(&b2, com, sizeof com);
    }
    put(&b2, d + 2, n - 2);
    run(b2.p, b2.n, &c, 4096, &o);
    CHECK(o.st == FIMG_E_FILE_TOO_LARGE);
    free(o.bm);
    free(b2.p);
  }
  free(ref.bm);
  free(b.p);
  free(d);
}

int main(void) {
  test_config();
  test_status_names();
  test_checksums();
  test_inflate_suspend();
  test_binarizer();
  test_scale();
  test_file_limit();
  test_png_worst_case();
  test_jpeg_segments();
  {
    uint8_t z[16];
    memset(z, 0xaa, sizeof z);
    fimg_secure_zero(z, sizeof z);
    for (size_t i = 0; i < sizeof z; i++) CHECK(z[i] == 0);
    fimg_secure_zero(NULL, 4);
  }
  return test_summary("fimg_unit");
}
