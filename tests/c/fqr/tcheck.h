// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* Minimal test helpers for the lib/fqr host tests (hosted C99). */

#ifndef FQR_TCHECK_H
#define FQR_TCHECK_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

extern unsigned tc_checks;
extern unsigned tc_failures;

#define TC_DEFINE_GLOBALS \
  unsigned tc_checks = 0; \
  unsigned tc_failures = 0

#define CHECK(cond)                                                            \
  do {                                                                         \
    tc_checks++;                                                               \
    if (!(cond)) {                                                             \
      tc_failures++;                                                           \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #cond); \
    }                                                                          \
  } while (0)

#define CHECK_MSG(cond, ...)                                                   \
  do {                                                                         \
    tc_checks++;                                                               \
    if (!(cond)) {                                                             \
      tc_failures++;                                                           \
      fprintf(stderr, "%s:%d: CHECK failed: %s: ", __FILE__, __LINE__, #cond); \
      fprintf(stderr, __VA_ARGS__);                                            \
      fprintf(stderr, "\n");                                                   \
    }                                                                          \
  } while (0)

#define CHECK_EQ_INT(a, b)                                                \
  do {                                                                    \
    long long tc_a = (long long)(a), tc_b = (long long)(b);               \
    tc_checks++;                                                          \
    if (tc_a != tc_b) {                                                   \
      tc_failures++;                                                      \
      fprintf(stderr, "%s:%d: CHECK_EQ failed: %s (%lld) != %s (%lld)\n", \
              __FILE__, __LINE__, #a, tc_a, #b, tc_b);                    \
    }                                                                     \
  } while (0)

static inline int tc_report(const char *name) {
  printf("%s: %u checks, %u failures\n", name, tc_checks, tc_failures);
  return tc_failures == 0u ? 0 : 1;
}

/* Deterministic PRNG (xorshift64*), seedable from FQR_TEST_SEED. */
typedef struct {
  uint64_t s;
} tc_rng_t;

static inline void tc_rng_seed(tc_rng_t *r, uint64_t seed) {
  const char *env = getenv("FQR_TEST_SEED");
  if (env != NULL) {
    seed ^= strtoull(env, NULL, 0);
  }
  r->s = seed ? seed : 0x9E3779B97F4A7C15ull;
}

static inline uint32_t tc_rand(tc_rng_t *r) {
  r->s ^= r->s >> 12;
  r->s ^= r->s << 25;
  r->s ^= r->s >> 27;
  return (uint32_t)((r->s * 2685821657736338717ull) >> 32);
}

static inline uint32_t tc_below(tc_rng_t *r, uint32_t n) {
  return n ? tc_rand(r) % n : 0u;
}

static inline float tc_unit(tc_rng_t *r) {
  return (float)(tc_rand(r) >> 8) / 16777216.0f;
}

#endif /* FQR_TCHECK_H */
