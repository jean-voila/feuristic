// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* End-to-end detection tests on images rendered by the test encoder:
 * scales, rotations, perspective, inversion, mirroring, noise, several
 * codes, decoys, no code, API contract, workspace alignment, budget. */

#include <math.h>
#include <string.h>

#include "fqr.h"
#include "fqr_internal.h"
#include "qrenc.h"
#include "tcheck.h"

TC_DEFINE_GLOBALS;

static uint8_t ws_buf[FQR_WORKSPACE_SIZE + 16];
static uint8_t grid[QE_GRID_BYTES], grid2[QE_GRID_BYTES];
static uint8_t pay[4][FQR_MAX_PAYLOAD_SIZE];

typedef struct {
  size_t n;
  fqr_status_t st;
  fqr_result_t r[4];
  fqr_stats_t stats;
} outcome_t;

static outcome_t run(const qe_img_t *img, fqr_polarity_t pol,
                     uint8_t max_codes) {
  outcome_t o;
  memset(&o, 0, sizeof o);
  for (int i = 0; i < 4; i++) {
    o.r[i].payload = pay[i];
    o.r[i].payload_cap = sizeof pay[i];
  }
  fqr_image_t im = {img->data, img->w, img->h, img->stride};
  fqr_options_t opt;
  memset(&opt, 0, sizeof opt);
  opt.polarity = pol;
  opt.max_codes = max_codes;
  opt.stats = &o.stats;
  o.st = fqr_decode(&im, ws_buf, sizeof ws_buf, &opt, o.r, 4, &o.n);
  return o;
}

static bool has_payload(const outcome_t *o, const uint8_t *p, size_t n) {
  for (size_t i = 0; i < o->n && i < 4; i++) {
    if (o->r[i].status == FQR_OK && o->r[i].payload_len == n &&
        memcmp(o->r[i].payload, p, n) == 0) {
      return true;
    }
  }
  return false;
}

static void make_msg(tc_rng_t *rng, uint8_t *msg, size_t n) {
  for (size_t i = 0; i < n; i++) {
    msg[i] = (uint8_t)(' ' + tc_below(rng, 95));
  }
}

/* Message length that lands on roughly version v at level lv. */
static size_t len_for_version(unsigned v, unsigned lv) {
  unsigned cap = qe_data_codewords(v, lv);
  size_t n = (cap * 8u - 4u - qe_count_bits(4, v)) / 8u;
  if (v <= 9 && n > 255) n = 255;
  return n;
}

static void test_axis_aligned(tc_rng_t *rng) {
  static const unsigned versions[] = {1,  2,  3,  4,  5,  6,  7, 9,
                                      10, 14, 20, 25, 27, 32, 40};
  uint8_t msg[3000];
  unsigned tried = 0, ok = 0;
  for (size_t vi = 0; vi < sizeof versions / sizeof versions[0]; vi++) {
    unsigned v = versions[vi];
    for (unsigned scale = 1; scale <= 8; scale++) {
      unsigned dim = 17 + 4 * v;
      uint32_t side = (dim + 8) * scale + 13;
      if (side > 1024) continue;
      unsigned lv = (v + scale) % 4;
      size_t n = len_for_version(v, lv);
      make_msg(rng, msg, n);
      unsigned ver;
      CHECK(qe_make_bytes(msg, n, v, lv, -1, grid, &ver));
      CHECK_EQ_INT(ver, v);
      qe_img_t img;
      CHECK(qe_img_alloc(&img, side, side));
      qe_render_scaled(&img, grid, QE_GRID_STRIDE, dim, 4 * scale + 5,
                       4 * scale + 7, scale, 4, false);
      outcome_t o = run(&img, FQR_POLARITY_AUTO, 0);
      tried++;
      bool good = o.st == FQR_OK && o.n == 1 && has_payload(&o, msg, n);
      ok += good;
      CHECK_MSG(good, "axis v%u scale %u: %s n=%zu", v, scale,
                fqr_status_str(o.st), o.n);
      if (good) {
        CHECK_EQ_INT(o.r[0].version, v);
        CHECK(!o.r[0].inverted && !o.r[0].mirrored);
        /* Corners within one module of the truth. */
        float x0 = (float)(4 * scale + 5), y0 = (float)(4 * scale + 7);
        CHECK(fabsf(o.r[0].corners[0].x - x0) < (float)scale + 1.0f);
        CHECK(fabsf(o.r[0].corners[0].y - y0) < (float)scale + 1.0f);
        CHECK(fabsf(o.r[0].corners[2].x - (x0 + (float)(dim * scale))) <
              (float)scale + 1.0f);
      }
      qe_img_free(&img);
    }
  }
  printf("axis-aligned: %u/%u\n", ok, tried);
}

/* Random geometry: returns success. */
static bool random_case(tc_rng_t *rng, unsigned v, float module_px, float angle,
                        float tx, float ty, bool invert, float noise,
                        bool mirror_img, bool verbose) {
  uint8_t msg[3000];
  unsigned lv = tc_below(rng, 4);
  size_t n = len_for_version(v, lv);
  make_msg(rng, msg, n);
  unsigned ver;
  if (!qe_make_bytes(msg, n, v, lv, (int)tc_below(rng, 8), grid, &ver))
    return false;
  unsigned dim = 17 + 4 * ver;
  float side = module_px * (float)dim;
  uint32_t W = (uint32_t)(side * 1.9f) + 40, H = W;
  if (W > 1024) W = H = 1024;
  qe_img_t img;
  if (!qe_img_alloc(&img, W, H)) return false;
  qe_img_fill(&img, 0);
  float corners[8];
  qe_corners(corners, (float)W / 2 + (tc_unit(rng) - 0.5f) * 10,
             (float)H / 2 + (tc_unit(rng) - 0.5f) * 10, side, angle, tx, ty);
  if (mirror_img) {
    for (int i = 0; i < 4; i++) corners[2 * i] = (float)W - corners[2 * i];
  }
  if (invert) qe_img_fill(&img, 1);
  qe_render(&img, grid, QE_GRID_STRIDE, dim, corners, 4, invert);
  if (noise > 0) {
    for (uint32_t y = 0; y < H; y++)
      for (uint32_t x = 0; x < W; x++)
        if (tc_unit(rng) < noise)
          qe_img_set(&img, x, y, !qe_img_get(&img, x, y));
  }
  outcome_t o = run(&img, FQR_POLARITY_AUTO, 0);
  bool good = o.st == FQR_OK && o.n == 1 && has_payload(&o, msg, n) &&
              o.r[0].inverted == invert && o.r[0].mirrored == mirror_img;
  if (!good && verbose) {
    printf(
        "  FAIL v%u mod=%.2f ang=%.1f tilt=(%.2f,%.2f) inv=%d noise=%.3f "
        "mir=%d -> %s n=%zu cands=%u triples=%u att=%u\n",
        ver, (double)module_px, (double)angle, (double)tx, (double)ty, invert,
        (double)noise, mirror_img, fqr_status_str(o.st), o.n,
        o.stats.finder_candidates, o.stats.triples_considered,
        o.stats.decode_attempts);
  }
  qe_img_free(&img);
  return good;
}

static void test_rotations(tc_rng_t *rng) {
  unsigned ok = 0, tried = 0;
  static const unsigned vs[] = {1, 2, 4, 7, 10};
  for (size_t vi = 0; vi < 5; vi++) {
    for (int ang = 0; ang < 360; ang += 15) {
      tried++;
      ok += random_case(rng, vs[vi], 4.0f, (float)ang, 0, 0, false, 0, false,
                        true);
    }
  }
  printf("rotations: %u/%u\n", ok, tried);
  CHECK_EQ_INT(ok, tried);
}

static void test_random_geometry(tc_rng_t *rng) {
  unsigned ok = 0, tried = 0;
  for (unsigned i = 0; i < 400; i++) {
    unsigned v = 1 + tc_below(rng, 14);
    float mp = 2.5f + tc_unit(rng) * 5.5f;
    float ang = tc_unit(rng) * 360.0f;
    float tx = (tc_unit(rng) - 0.5f) * 0.5f, ty = (tc_unit(rng) - 0.5f) * 0.5f;
    bool inv = (i % 5) == 0;
    tried++;
    ok += random_case(rng, v, mp, ang, tx, ty, inv, 0, false, true);
  }
  printf(
      "random geometry (v1-14, 2.5-8 px/module, any angle, tilt <= 0.25): "
      "%u/%u\n",
      ok, tried);
  CHECK(ok * 100u >= tried * 97u);
}

static void test_large_versions(tc_rng_t *rng) {
  unsigned ok = 0, tried = 0;
  for (unsigned i = 0; i < 40; i++) {
    unsigned v = 15 + tc_below(rng, 26);
    float mp = 3.0f + tc_unit(rng) * 1.5f;
    if (mp * (float)(17 + 4 * v) * 1.4f > 1000.0f)
      mp = 1000.0f / (1.4f * (float)(17 + 4 * v));
    float ang = tc_unit(rng) * 360.0f;
    float tx = (tc_unit(rng) - 0.5f) * 0.2f, ty = (tc_unit(rng) - 0.5f) * 0.2f;
    tried++;
    ok += random_case(rng, v, mp, ang, tx, ty, false, 0, false, true);
  }
  printf("large versions (v15-40, rotated, mild tilt): %u/%u\n", ok, tried);
  CHECK(ok * 100u >= tried * 90u);
}

static void test_noise_and_mirror(tc_rng_t *rng) {
  unsigned ok = 0, tried = 0;
  for (unsigned i = 0; i < 60; i++) {
    tried++;
    ok += random_case(rng, 1 + tc_below(rng, 8), 5.0f, tc_unit(rng) * 360, 0.1f,
                      -0.1f, false, 0.02f, false, true);
  }
  printf("salt&pepper 2%%: %u/%u\n", ok, tried);
  CHECK(ok * 100u >= tried * 90u);
  ok = tried = 0;
  for (unsigned i = 0; i < 30; i++) {
    tried++;
    ok += random_case(rng, 1 + tc_below(rng, 10), 4.0f, tc_unit(rng) * 360, 0,
                      0, i & 1, 0, true, true);
  }
  printf("mirrored images: %u/%u\n", ok, tried);
  CHECK_EQ_INT(ok, tried);
}

static void test_multiple(tc_rng_t *rng) {
  uint8_t m1[64], m2[64], m3[64];
  make_msg(rng, m1, 40);
  make_msg(rng, m2, 30);
  make_msg(rng, m3, 20);
  unsigned v1, v2, v3;
  static uint8_t grid3[QE_GRID_BYTES];
  CHECK(qe_make_bytes(m1, 40, 1, FQR_ECC_M, -1, grid, &v1));
  CHECK(qe_make_bytes(m2, 30, 1, FQR_ECC_Q, -1, grid2, &v2));
  CHECK(qe_make_bytes(m3, 20, 1, FQR_ECC_L, -1, grid3, &v3));
  qe_img_t img;
  CHECK(qe_img_alloc(&img, 600, 450));
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 17 + 4 * v1, 30, 30, 5, 4,
                   false);
  qe_render_scaled(&img, grid2, QE_GRID_STRIDE, 17 + 4 * v2, 330, 60, 6, 4,
                   false);
  outcome_t o = run(&img, FQR_POLARITY_AUTO, 0);
  CHECK_EQ_INT(o.n, 2);
  CHECK_EQ_INT(o.st, FQR_OK);
  CHECK(has_payload(&o, m1, 40) && has_payload(&o, m2, 30));
  /* fqr_decode_single refuses. */
  {
    fqr_result_t r;
    memset(&r, 0, sizeof r);
    r.payload = pay[0];
    r.payload_cap = sizeof pay[0];
    fqr_image_t im = {img.data, img.w, img.h, img.stride};
    CHECK_EQ_INT(fqr_decode_single(&im, ws_buf, sizeof ws_buf, NULL, &r),
                 FQR_ERR_MULTIPLE_CODES);
  }
  /* max_codes = 1 stops early. */
  o = run(&img, FQR_POLARITY_AUTO, 1);
  CHECK_EQ_INT(o.n, 1);
  /* Third code, rotated, plus counted-but-not-reported results. */
  float c[8];
  qe_corners(c, 150, 320, 140, 30, 0, 0);
  qe_render(&img, grid3, QE_GRID_STRIDE, 17 + 4 * v3, c, 4, false);
  o = run(&img, FQR_POLARITY_AUTO, 0);
  CHECK_EQ_INT(o.n, 3);
  CHECK(has_payload(&o, m3, 20));
  {
    fqr_result_t r[1];
    memset(r, 0, sizeof r);
    r[0].payload = pay[0];
    r[0].payload_cap = sizeof pay[0];
    size_t n = 0;
    fqr_image_t im = {img.data, img.w, img.h, img.stride};
    CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
                 FQR_OK);
    CHECK_EQ_INT(n, 3);
    CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, NULL, 0, &n),
                 FQR_OK);
    CHECK_EQ_INT(n, 3);
  }
  qe_img_free(&img);

  /* Same payload twice at two places: two distinct codes. */
  CHECK(qe_img_alloc(&img, 500, 260));
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 17 + 4 * v1, 30, 30, 5, 4,
                   false);
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 17 + 4 * v1, 300, 40, 5, 4,
                   false);
  o = run(&img, FQR_POLARITY_AUTO, 0);
  CHECK_EQ_INT(o.n, 2);
  qe_img_free(&img);

  /* Normal + inverted code: AUTO sees one, BOTH sees two. */
  CHECK(qe_img_alloc(&img, 600, 300));
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 17 + 4 * v1, 30, 30, 5, 4,
                   false);
  for (uint32_t y = 0; y < 300; y++)
    for (uint32_t x = 300; x < 600; x++) qe_img_set(&img, x, y, 1);
  qe_render_scaled(&img, grid2, QE_GRID_STRIDE, 17 + 4 * v2, 340, 40, 5, 4,
                   true);
  o = run(&img, FQR_POLARITY_AUTO, 0);
  CHECK_EQ_INT(o.n, 1);
  CHECK(has_payload(&o, m1, 40));
  o = run(&img, FQR_POLARITY_BOTH, 0);
  CHECK_EQ_INT(o.n, 2);
  CHECK(has_payload(&o, m2, 30));
  o = run(&img, FQR_POLARITY_INVERTED, 0);
  CHECK_EQ_INT(o.n, 1);
  CHECK(o.n == 1 && o.r[0].inverted);
  o = run(&img, FQR_POLARITY_NORMAL, 0);
  CHECK(o.n == 1 && !o.r[0].inverted);
  qe_img_free(&img);
}

static void test_no_code(tc_rng_t *rng) {
  qe_img_t img;
  CHECK(qe_img_alloc(&img, 301, 257));
  qe_img_fill(&img, 0);
  outcome_t o = run(&img, FQR_POLARITY_BOTH, 0);
  CHECK_EQ_INT(o.n, 0);
  CHECK_EQ_INT(o.st, FQR_ERR_NOT_FOUND);
  qe_img_fill(&img, 1);
  o = run(&img, FQR_POLARITY_BOTH, 0);
  CHECK_EQ_INT(o.st, FQR_ERR_NOT_FOUND);
  for (int k = 0; k < 6; k++) {
    float density = 0.1f + 0.15f * (float)k;
    for (uint32_t y = 0; y < img.h; y++)
      for (uint32_t x = 0; x < img.w; x++)
        qe_img_set(&img, x, y, tc_unit(rng) < density);
    o = run(&img, FQR_POLARITY_BOTH, 0);
    CHECK_EQ_INT(o.n, 0);
  }
  /* Checkerboards and stripes at several periods. */
  for (uint32_t p = 1; p <= 9; p += 2) {
    for (uint32_t y = 0; y < img.h; y++)
      for (uint32_t x = 0; x < img.w; x++)
        qe_img_set(&img, x, y, (int)(((x / p) + (y / p)) & 1));
    o = run(&img, FQR_POLARITY_BOTH, 0);
    CHECK_EQ_INT(o.n, 0);
    for (uint32_t y = 0; y < img.h; y++)
      for (uint32_t x = 0; x < img.w; x++)
        qe_img_set(&img, x, y, (int)((x / p) & 1));
    o = run(&img, FQR_POLARITY_BOTH, 0);
    CHECK_EQ_INT(o.n, 0);
  }
  qe_img_free(&img);

  /* Decoy: three finder patterns, data area random. */
  CHECK(qe_img_alloc(&img, 300, 300));
  for (unsigned r = 0; r < 25; r++)
    for (unsigned c = 0; c < 25; c++)
      qe_set(grid, QE_GRID_STRIDE, r, c, (int)(tc_rand(rng) & 1));
  {
    uint8_t m[8] = "decoy!!";
    unsigned v;
    CHECK(qe_make_bytes(m, 7, 2, FQR_ECC_L, 0, grid2, &v));
    /* keep only function patterns of the real symbol */
    for (unsigned r = 0; r < 25; r++)
      for (unsigned c = 0; c < 25; c++)
        if (fqr_is_function_module(2, r, c) && !(r == 8 || c == 8))
          qe_set(grid, QE_GRID_STRIDE, r, c,
                 qe_get(grid2, QE_GRID_STRIDE, r, c));
  }
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 25, 40, 40, 8, 4, false);
  o = run(&img, FQR_POLARITY_AUTO, 0);
  CHECK_EQ_INT(o.n, 0);
  CHECK_MSG(
      o.st == FQR_ERR_FORMAT || o.st == FQR_ERR_ECC || o.st == FQR_ERR_DATA,
      "decoy status %s", fqr_status_str(o.st));
  qe_img_free(&img);
}

static void test_api(tc_rng_t *rng) {
  uint8_t msg[40];
  make_msg(rng, msg, sizeof msg);
  unsigned v;
  CHECK(qe_make_bytes(msg, sizeof msg, 1, FQR_ECC_M, -1, grid, &v));
  qe_img_t img;
  CHECK(qe_img_alloc(&img, 203, 199)); /* width not a multiple of 8 */
  /* Garbage in the padding bits beyond the width must be ignored. */
  for (uint32_t y = 0; y < img.h; y++)
    img.data[y * img.stride + img.stride - 1] = 0x1F;
  qe_render_scaled(&img, grid, QE_GRID_STRIDE, 17 + 4 * v, 20, 20, 4, 4, false);
  fqr_image_t im = {img.data, img.w, img.h, img.stride};
  fqr_result_t r[2];
  size_t n = 99;
  memset(r, 0, sizeof r);
  r[0].payload = pay[0];
  r[0].payload_cap = sizeof pay[0];
  r[1].payload = pay[1];
  r[1].payload_cap = sizeof pay[1];

  /* Every workspace alignment. */
  for (int off = 0; off < 8; off++) {
    CHECK_EQ_INT(
        fqr_decode(&im, ws_buf + off, FQR_WORKSPACE_SIZE, NULL, r, 2, &n),
        FQR_OK);
    CHECK_EQ_INT(n, 1);
    CHECK(r[0].payload_len == sizeof msg &&
          memcmp(pay[0], msg, sizeof msg) == 0);
    CHECK_EQ_INT(r[1].status, FQR_ERR_NOT_FOUND);
    CHECK_EQ_INT(r[1].payload_len, 0);
  }
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, FQR_WORKSPACE_SIZE - 1, NULL, r, 2, &n),
               FQR_ERR_WORKSPACE);
  CHECK_EQ_INT(n, 0);
  CHECK_EQ_INT(fqr_decode(&im, NULL, FQR_WORKSPACE_SIZE, NULL, r, 2, &n),
               FQR_ERR_WORKSPACE);
  CHECK_EQ_INT(fqr_decode(NULL, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, r, 2, NULL),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, NULL, 2, &n),
               FQR_ERR_INVALID_ARG);
  fqr_image_t bad = im;
  bad.width = 0;
  CHECK_EQ_INT(fqr_decode(&bad, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  bad = im;
  bad.width = 1025;
  bad.stride = 200;
  CHECK_EQ_INT(fqr_decode(&bad, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  bad = im;
  bad.stride = 25;
  CHECK_EQ_INT(fqr_decode(&bad, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  bad = im;
  bad.data = NULL;
  CHECK_EQ_INT(fqr_decode(&bad, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  fqr_options_t opt;
  memset(&opt, 0, sizeof opt);
  opt.max_codes = FQR_MAX_CODES + 1;
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, &opt, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  memset(&opt, 0, sizeof opt);
  opt.polarity = (fqr_polarity_t)7;
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, &opt, r, 2, &n),
               FQR_ERR_INVALID_ARG);
  r[0].payload = NULL;
  r[0].payload_cap = 10;
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_INVALID_ARG);

  /* Buffer too small. */
  r[0].payload = pay[0];
  r[0].payload_cap = 7;
  memset(pay[0], 0xEE, 16);
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, r, 2, &n),
               FQR_ERR_BUFFER_TOO_SMALL);
  CHECK_EQ_INT(n, 1);
  CHECK_EQ_INT(r[0].status, FQR_ERR_BUFFER_TOO_SMALL);
  CHECK_EQ_INT(r[0].payload_len, sizeof msg);
  CHECK(memcmp(pay[0], msg, 7) == 0 && pay[0][7] == 0xEE);
  r[0].payload = NULL;
  r[0].payload_cap = 0;
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
               FQR_ERR_BUFFER_TOO_SMALL);

  /* Wider stride than needed. */
  {
    qe_img_t wide;
    CHECK(qe_img_alloc(&wide, 203 + 300, 199));
    for (uint32_t y = 0; y < 199; y++)
      for (uint32_t x = 0; x < 203 + 300; x++)
        qe_img_set(&wide, x, y, x < 203 ? qe_img_get(&img, x, y) : 1);
    fqr_image_t w2 = {wide.data, 203, 199, wide.stride};
    r[0].payload = pay[0];
    r[0].payload_cap = sizeof pay[0];
    CHECK_EQ_INT(fqr_decode(&w2, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
                 FQR_OK);
    qe_img_free(&wide);
  }
  /* Tiny budget: stops and says so. */
  memset(&opt, 0, sizeof opt);
  fqr_stats_t st;
  opt.stats = &st;
  opt.max_work = 1;
  CHECK_EQ_INT(fqr_decode(&im, ws_buf, sizeof ws_buf, &opt, r, 1, &n),
               FQR_ERR_NOT_FOUND);
  CHECK(st.budget_exhausted);
  /* Degenerate sizes. */
  {
    uint8_t one = 0x80;
    fqr_image_t t1 = {&one, 1, 1, 1};
    CHECK_EQ_INT(fqr_decode(&t1, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
                 FQR_ERR_NOT_FOUND);
  }
  qe_img_free(&img);
  {
    qe_img_t big;
    CHECK(qe_img_alloc(&big, 1024, 1024));
    fqr_image_t b2 = {big.data, 1024, 1024, big.stride};
    CHECK_EQ_INT(fqr_decode(&b2, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
                 FQR_ERR_NOT_FOUND);
    /* Version 40 at 5 px/module fills a 1024 image. */
    uint8_t m[2000];
    make_msg(rng, m, 1500);
    unsigned vv;
    CHECK(qe_make_bytes(m, 1500, 36, FQR_ECC_M, -1, grid, &vv));
    qe_render_scaled(&big, grid, QE_GRID_STRIDE, 17 + 4 * vv, 40, 40, 5, 4,
                     false);
    r[0].payload = pay[0];
    r[0].payload_cap = sizeof pay[0];
    CHECK_EQ_INT(fqr_decode(&b2, ws_buf, sizeof ws_buf, NULL, r, 1, &n),
                 FQR_OK);
    CHECK(n == 1 && r[0].payload_len == 1500 && memcmp(pay[0], m, 1500) == 0);
    qe_img_free(&big);
  }
}

int main(void) {
  tc_rng_t rng;
  tc_rng_seed(&rng, 0xDE7Eu);
  test_api(&rng);
  test_axis_aligned(&rng);
  test_rotations(&rng);
  test_multiple(&rng);
  test_no_code(&rng);
  test_noise_and_mirror(&rng);
  test_random_geometry(&rng);
  test_large_versions(&rng);
  return tc_report("test_detect");
}
