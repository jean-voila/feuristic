// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/* Scattered-workspace API rejection, ownership, and reinitialization. Image
 * output equivalence for the complete corpus lives in test_vectors.c. */
#include "fimg.h"
#include "fimg_internal.h"
#include "test_util.h"

typedef struct {
  fimg_config_t cfg;
  fimg_block_t blocks[FIMG_SCATTERED_MAX_BLOCKS];
  uint8_t *owned[FIMG_SCATTERED_MAX_BLOCKS];
  size_t sizes[FIMG_SCATTERED_MAX_BLOCKS];
  size_t count;
  uint8_t *bitmap;
  size_t bitmap_size;
} arena_t;

static void arena_open(arena_t *a, const fimg_config_t *cfg) {
  memset(a, 0, sizeof *a);
  a->cfg = *cfg;
  a->count = fimg_scattered_sizes(cfg, a->sizes, FIMG_SCATTERED_MAX_BLOCKS);
  CHECK(a->count > 0 && a->count <= FIMG_SCATTERED_MAX_BLOCKS);
  if (a->count == 0 || a->count > FIMG_SCATTERED_MAX_BLOCKS) exit(2);
  for (size_t i = 0; i < a->count; i++) {
    CHECK(a->sizes[i] > 0 && a->sizes[i] <= FIMG_SCATTERED_BLOCK_MAX);
    a->owned[i] = (uint8_t *)malloc(a->sizes[i] + 32);
    if (a->owned[i] == NULL) exit(2);
    memset(a->owned[i], 0xb7, a->sizes[i] + 32);
    a->blocks[i].ptr = a->owned[i] + 16;
    a->blocks[i].size = a->sizes[i];
    CHECK(((uintptr_t)a->blocks[i].ptr & 7u) == 0);
  }
  a->bitmap_size = fimg_bitmap_size(cfg);
  a->bitmap = (uint8_t *)malloc(a->bitmap_size + 16);
  if (a->bitmap == NULL) exit(2);
}

static void arena_close(arena_t *a) {
  for (size_t i = 0; i < a->count; i++) {
    for (size_t j = 0; j < 16; j++) {
      CHECK(a->owned[i][j] == 0xb7);
      CHECK(a->owned[i][16 + a->sizes[i] + j] == 0xb7);
    }
    fimg_secure_zero(a->owned[i], a->sizes[i] + 32);
    free(a->owned[i]);
  }
  fimg_secure_zero(a->bitmap, a->bitmap_size + 16);
  free(a->bitmap);
}

static void sizes_contract(void) {
  static const uint16_t dims[] = {8, 100, 320, 384, 720, 1024};
  static const uint32_t flags[] = {0, FIMG_FLAG_NO_PNG, FIMG_FLAG_NO_JPEG,
                                   FIMG_FLAG_STRICT_TRAILER};
  fimg_config_t cfg;
  size_t sizes[FIMG_SCATTERED_MAX_BLOCKS];
  CHECK(fimg_scattered_sizes(NULL, sizes, FIMG_SCATTERED_MAX_BLOCKS) == 0);
  for (size_t d = 0; d < sizeof dims / sizeof dims[0]; d++) {
    for (size_t f = 0; f < sizeof flags / sizeof flags[0]; f++) {
      size_t n;
      fimg_config_default(&cfg);
      cfg.max_out_width = dims[d];
      cfg.max_out_height = dims[d];
      cfg.flags = flags[f];
      n = fimg_scattered_sizes(&cfg, NULL, 0);
      CHECK(n > 0 && n <= FIMG_SCATTERED_MAX_BLOCKS);
      for (size_t i = 0; i < FIMG_SCATTERED_MAX_BLOCKS; i++)
        sizes[i] = SIZE_MAX;
      CHECK(fimg_scattered_sizes(&cfg, sizes, n - 1) == n);
      for (size_t i = 0; i < FIMG_SCATTERED_MAX_BLOCKS; i++)
        CHECK(sizes[i] == SIZE_MAX);
      CHECK(fimg_scattered_sizes(&cfg, sizes, FIMG_SCATTERED_MAX_BLOCKS) == n);
      CHECK(sizes[0] >= sizeof(fimg_ctx_t));
      for (size_t i = 0; i < n; i++) {
        CHECK(sizes[i] > 0 && sizes[i] <= FIMG_SCATTERED_BLOCK_MAX);
      }
      for (size_t i = n; i < FIMG_SCATTERED_MAX_BLOCKS; i++)
        CHECK(sizes[i] == SIZE_MAX);
    }
  }
  fimg_config_default(&cfg);
  cfg.max_out_width = 0;
  CHECK(fimg_scattered_sizes(&cfg, sizes, FIMG_SCATTERED_MAX_BLOCKS) == 0);
  fimg_config_default(&cfg);
  cfg.flags = FIMG_FLAG_NO_PNG | FIMG_FLAG_NO_JPEG;
  CHECK(fimg_scattered_sizes(&cfg, sizes, FIMG_SCATTERED_MAX_BLOCKS) == 0);
}

static void invalid_memory(void) {
  fimg_config_t cfg, bad;
  arena_t a;
  fimg_ctx_t *ctx = NULL;
  fimg_block_t saved;
  fimg_status_t st;
  fimg_config_default(&cfg);
  arena_open(&a, &cfg);

#define REJECT(want, array, nblocks, config, bm, bmsize)                \
  do {                                                                  \
    ctx = (fimg_ctx_t *)a.blocks[0].ptr;                                \
    st = fimg_init_scattered(&ctx, array, nblocks, config, bm, bmsize); \
    CHECK_MSG(st == want, "got %s expected %s", fimg_status_name(st),   \
              fimg_status_name(want));                                  \
    CHECK(ctx == NULL);                                                 \
  } while (0)

  CHECK(fimg_init_scattered(NULL, a.blocks, a.count, &cfg, a.bitmap,
                            a.bitmap_size) == FIMG_E_PARAM);
  REJECT(FIMG_E_PARAM, NULL, a.count, &cfg, a.bitmap, a.bitmap_size);
  REJECT(FIMG_E_PARAM, a.blocks, a.count, NULL, a.bitmap, a.bitmap_size);
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, NULL, a.bitmap_size);
  bad = cfg;
  bad.max_out_height = FIMG_MAX_DIM + 1;
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &bad, a.bitmap, a.bitmap_size);
  REJECT(FIMG_E_WORKSPACE, a.blocks, 0, &cfg, a.bitmap, a.bitmap_size);
  REJECT(FIMG_E_WORKSPACE, a.blocks, FIMG_SCATTERED_MAX_BLOCKS + 1, &cfg,
         a.bitmap, a.bitmap_size);
  REJECT(FIMG_E_WORKSPACE, a.blocks, a.count - 1, &cfg, a.bitmap,
         a.bitmap_size);
  REJECT(FIMG_E_WORKSPACE, a.blocks, a.count, &cfg, a.bitmap,
         a.bitmap_size - 1);
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, SIZE_MAX);
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, (uint8_t *)a.blocks,
         a.bitmap_size);

  saved = a.blocks[0];
  a.blocks[0].size = sizeof(fimg_ctx_t) - 1;
  REJECT(FIMG_E_WORKSPACE, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
  a.blocks[0] = saved;
  for (size_t i = 0; i < a.count; i++) {
    saved = a.blocks[i];
    a.blocks[i].ptr = NULL;
    REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
    a.blocks[i] = saved;
    a.blocks[i].ptr = (uint8_t *)saved.ptr + 1;
    REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
    a.blocks[i] = saved;
    a.blocks[i].size = SIZE_MAX;
    REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
    a.blocks[i] = saved;
  }
  saved = a.blocks[1];
  a.blocks[1].ptr = a.blocks[0].ptr;
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
  a.blocks[1].ptr = (uint8_t *)a.blocks[0].ptr + 8;
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
  a.blocks[1].ptr = a.blocks;
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
  a.blocks[1] = saved;
  REJECT(FIMG_E_PARAM, a.blocks, a.count, &cfg, (uint8_t *)a.blocks[1].ptr,
         a.bitmap_size);
  for (size_t i = 1; i < a.count; i++) a.blocks[i].size = 0;
  REJECT(FIMG_E_WORKSPACE, a.blocks, a.count, &cfg, a.bitmap, a.bitmap_size);
  for (size_t i = 1; i < a.count; i++) a.blocks[i].size = a.sizes[i];
#undef REJECT
  arena_close(&a);
}

static void reuse_and_independence(void) {
  fimg_config_t cfg;
  arena_t a, b;
  fimg_ctx_t *first = NULL, *second = NULL;
  fimg_info_t info;
  static const uint8_t bad_image[] = "not an image";
  fimg_config_default(&cfg);
  arena_open(&a, &cfg);
  arena_open(&b, &cfg);
  CHECK(fimg_init_scattered(&first, a.blocks, a.count, &cfg, a.bitmap,
                            a.bitmap_size) == FIMG_OK);
  CHECK(fimg_init_scattered(&second, b.blocks, b.count, &cfg, b.bitmap + 1,
                            b.bitmap_size) == FIMG_OK);
  CHECK(first != second);
  CHECK(fimg_feed(first, bad_image, sizeof bad_image) == FIMG_E_NOT_IMAGE);
  CHECK(fimg_finish(first, &info) == FIMG_E_NOT_IMAGE);
  CHECK(fimg_finish(second, &info) == FIMG_E_NOT_IMAGE);
  CHECK(fimg_init_scattered(&first, a.blocks, a.count, &cfg, a.bitmap,
                            a.bitmap_size) == FIMG_OK);
  CHECK(fimg_get_info(first, &info) == FIMG_OK);
  CHECK(info.format == FIMG_FORMAT_UNKNOWN && !info.complete);
  CHECK(fimg_init_scattered(&first, a.blocks, a.count, &first->cfg, a.bitmap,
                            a.bitmap_size) == FIMG_OK);
  CHECK(fimg_finish(first, &info) == FIMG_E_NOT_IMAGE);
  arena_close(&a);
  arena_close(&b);
}

static void put_be32(uint8_t *p, uint32_t value) {
  p[0] = (uint8_t)(value >> 24);
  p[1] = (uint8_t)(value >> 16);
  p[2] = (uint8_t)(value >> 8);
  p[3] = (uint8_t)value;
}

static void image_header_geometry(void) {
  static const uint16_t limits[][2] = {{8, 8},     {320, 320},   {384, 384},
                                       {720, 720}, {1024, 1024}, {8, 1024},
                                       {1024, 8}};
  static const uint32_t heights[] = {1, 1024};
  fimg_config_t cfg;
  arena_t a;
  uint8_t header[33] = {0x89, 'P', 'N', 'G', 13,  10,  26,  10,
                        0,    0,   0,   13,  'I', 'H', 'D', 'R'};
  header[24] = 8; /* grayscale, filter/compression methods zero */
  /* Every actual source width exercises worst-case plans whose configured
     width differs from the downscaled width. A valid IHDR must not exhaust
     the plan before any compressed data arrives. */
  for (size_t c = 0; c < sizeof limits / sizeof limits[0]; c++) {
    fimg_config_default(&cfg);
    cfg.max_out_width = limits[c][0];
    cfg.max_out_height = limits[c][1];
    arena_open(&a, &cfg);
    for (uint32_t width = 1; width <= FIMG_MAX_DIM; width++) {
      for (size_t h = 0; h < sizeof heights / sizeof heights[0]; h++) {
        fimg_ctx_t *ctx = NULL;
        fimg_status_t st;
        put_be32(header + 16, width);
        put_be32(header + 20, heights[h]);
        put_be32(header + 29, test_crc32(header + 12, 17));
        CHECK(fimg_init_scattered(&ctx, a.blocks, a.count, &cfg, a.bitmap,
                                  a.bitmap_size) == FIMG_OK);
        st = fimg_feed(ctx, header, sizeof header);
        CHECK_MSG(st == FIMG_OK, "cfg%ux%u src%ux%u: %s", cfg.max_out_width,
                  cfg.max_out_height, width, heights[h], fimg_status_name(st));
      }
    }
    arena_close(&a);
  }
}

int main(void) {
  sizes_contract();
  invalid_memory();
  reuse_and_independence();
  image_header_geometry();
  return test_summary("fimg_scattered");
}
