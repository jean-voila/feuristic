// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/* Minimal test helpers shared by the lib/fimg host tests. */
#ifndef FIMG_TEST_UTIL_H
#define FIMG_TEST_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int g_failures;
static int g_checks;

#define CHECK(cond)                                                            \
  do {                                                                         \
    g_checks++;                                                                \
    if (!(cond)) {                                                             \
      g_failures++;                                                            \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                          \
  } while (0)

#define CHECK_MSG(cond, ...)                                                   \
  do {                                                                         \
    g_checks++;                                                                \
    if (!(cond)) {                                                             \
      g_failures++;                                                            \
      fprintf(stderr, "%s:%d: CHECK failed: %s: ", __FILE__, __LINE__, #cond); \
      fprintf(stderr, __VA_ARGS__);                                            \
      fputc('\n', stderr);                                                     \
    }                                                                          \
  } while (0)

static inline int test_summary(const char *name) {
  printf("%s: %d checks, %d failures\n", name, g_checks, g_failures);
  return g_failures ? 1 : 0;
}

/* Read a whole file (malloc'd, caller frees). Returns NULL on error. */
static inline uint8_t *read_file(const char *path, size_t *len) {
  FILE *f = fopen(path, "rb");
  uint8_t *buf = NULL;
  long n;
  if (f == NULL) return NULL;
  if (fseek(f, 0, SEEK_END) == 0 && (n = ftell(f)) >= 0 &&
      fseek(f, 0, SEEK_SET) == 0) {
    buf = (uint8_t *)malloc((size_t)n + 1u);
    if (buf != NULL && fread(buf, 1, (size_t)n, f) != (size_t)n) {
      free(buf);
      buf = NULL;
    }
    *len = (size_t)n;
  }
  fclose(f);
  return buf;
}

static inline uint32_t test_crc32(const uint8_t *p, size_t n) {
  uint32_t c = 0xffffffffu;
  for (size_t i = 0; i < n; i++) {
    c ^= p[i];
    for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xedb88320u & (0u - (c & 1u)));
  }
  return ~c;
}

/* xorshift32 PRNG for reproducible chunk sizes */
static inline uint32_t test_rand(uint32_t *s) {
  uint32_t x = *s;
  x ^= x << 13;
  x ^= x >> 17;
  x ^= x << 5;
  *s = x;
  return x;
}

#endif
