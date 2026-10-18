// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* Reed-Solomon decoder tests: known answers, random errors up to and beyond
 * capacity, argument validation, transactional failure. */

#include <string.h>

#include "fqr_internal.h"
#include "qrenc.h"
#include "tcheck.h"

TC_DEFINE_GLOBALS;

/* RS-encode with the test encoder via a v1 symbol is awkward; use the
 * generic path: build a codeword with qe_codewords for a 1-block version. */
static void make_codeword(tc_rng_t *rng, uint8_t *blk, unsigned n,
                          unsigned ec) {
  /* Systematic encoding by polynomial division, bitwise GF arithmetic in
   * qrenc.c is static, so re-derive here with the library tables (the
   * decoder never uses this path). */
  uint8_t gen[32] = {1};
  unsigned deg = 0;
  for (unsigned i = 0; i < ec; i++) {
    uint8_t root = fqr_gf_exp[i];
    gen[deg + 1] = 0;
    for (unsigned k = deg + 1; k > 0; k--) {
      uint8_t a = gen[k - 1];
      uint8_t p =
          (a && root) ? fqr_gf_exp[fqr_gf_log[a] + fqr_gf_log[root]] : 0;
      gen[k] ^= p;
    }
    deg++;
  }
  unsigned nd = n - ec;
  for (unsigned i = 0; i < nd; i++) {
    blk[i] = (uint8_t)tc_rand(rng);
  }
  uint8_t rem[32] = {0};
  for (unsigned i = 0; i < nd; i++) {
    uint8_t f = (uint8_t)(blk[i] ^ rem[0]);
    memmove(rem, rem + 1, ec - 1);
    rem[ec - 1] = 0;
    for (unsigned k = 0; k < ec; k++) {
      uint8_t g = gen[k + 1];
      rem[k] ^= (f && g) ? fqr_gf_exp[fqr_gf_log[f] + fqr_gf_log[g]] : 0;
    }
  }
  memcpy(blk + nd, rem, ec);
}

static void test_known_answer(void) {
  /* Version 1-M "01234567" example of ISO/IEC 18004 Annex I:
   * data 10 20 0C 56 61 80 EC 11 EC 11 EC 11 EC 11 EC 11,
   * EC   A5 24 D4 C1 ED 36 C7 87 2C 55. */
  uint8_t blk[26] = {0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC,
                     0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xA5, 0x24,
                     0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55};
  uint8_t ref[26];
  memcpy(ref, blk, sizeof blk);
  CHECK_EQ_INT(fqr_rs_correct(blk, 26, 10, 5), 0);
  blk[0] ^= 0xFF;
  blk[7] ^= 0x01;
  blk[25] ^= 0x80;
  blk[12] ^= 0x33;
  CHECK_EQ_INT(fqr_rs_correct(blk, 26, 10, 5), 4);
  CHECK(memcmp(blk, ref, sizeof ref) == 0);
  /* The test encoder must reproduce the same EC codewords. */
  uint8_t out[26];
  CHECK_EQ_INT(qe_codewords(ref, 1, FQR_ECC_M, out), 26);
  CHECK(memcmp(out, ref, 26) == 0);
}

static void test_random(tc_rng_t *rng) {
  uint8_t blk[255], ref[255];
  unsigned ok = 0, detected = 0, miscorrected = 0;
  for (unsigned iter = 0; iter < 20000; iter++) {
    unsigned ec = 1 + tc_below(rng, 30);
    unsigned n = ec + 1 + tc_below(rng, 255 - ec);
    make_codeword(rng, blk, n, ec);
    memcpy(ref, blk, n);
    unsigned cap = ec / 2;
    bool beyond = (tc_rand(rng) & 3u) == 0u;
    unsigned ne =
        beyond ? cap + 1 + tc_below(rng, ec - cap + 2) : tc_below(rng, cap + 1);
    if (ne > n) {
      ne = n;
    }
    /* distinct random positions */
    unsigned pos[64];
    unsigned np = 0;
    while (np < ne) {
      unsigned p = tc_below(rng, n);
      bool dup = false;
      for (unsigned k = 0; k < np; k++) {
        dup = dup || pos[k] == p;
      }
      if (!dup) {
        pos[np++] = p;
        blk[p] ^= (uint8_t)(1 + tc_below(rng, 255));
      }
    }
    int rc = fqr_rs_correct(blk, n, ec, cap);
    if (ne <= cap) {
      CHECK_EQ_INT(rc, (int)ne);
      CHECK(memcmp(blk, ref, n) == 0);
      ok++;
    } else if (rc < 0) {
      detected++;
    } else {
      /* A miscorrection always lands on a valid codeword within cap. */
      CHECK(rc <= (int)cap);
      CHECK_EQ_INT(fqr_rs_correct(blk, n, ec, 0), 0);
      miscorrected++;
    }
  }
  printf(
      "rs random: %u corrected, %u beyond-capacity detected, %u miscorrected\n",
      ok, detected, miscorrected);
  /* Miscorrections must stay rare (they are dominated by tiny ec). */
  CHECK(miscorrected * 10u < detected + 1u);
}

static void test_limits(tc_rng_t *rng) {
  uint8_t blk[255], ref[255];
  /* max_err below ec/2 is honoured. */
  make_codeword(rng, blk, 100, 20);
  memcpy(ref, blk, 100);
  for (unsigned i = 0; i < 6; i++) {
    blk[i * 7] ^= 0x5A;
  }
  uint8_t save[255];
  memcpy(save, blk, 100);
  CHECK_EQ_INT(fqr_rs_correct(blk, 100, 20, 5), -1);
  CHECK(memcmp(blk, save, 100) == 0); /* failure leaves the block unchanged */
  CHECK_EQ_INT(fqr_rs_correct(blk, 100, 20, 6), 6);
  CHECK(memcmp(blk, ref, 100) == 0);
  /* Invalid arguments. */
  CHECK_EQ_INT(fqr_rs_correct(NULL, 10, 4, 2), -1);
  CHECK_EQ_INT(fqr_rs_correct(blk, 10, 0, 0), -1);
  CHECK_EQ_INT(fqr_rs_correct(blk, 10, 31, 2), -1);
  CHECK_EQ_INT(fqr_rs_correct(blk, 4, 4, 2), -1);
  CHECK_EQ_INT(fqr_rs_correct(blk, 256, 4, 2), -1);
  CHECK_EQ_INT(fqr_rs_correct(blk, 10, 4, 3), -1);
  /* max_err 0: only clean blocks pass. */
  make_codeword(rng, blk, 50, 10);
  CHECK_EQ_INT(fqr_rs_correct(blk, 50, 10, 0), 0);
  blk[3] ^= 1;
  CHECK_EQ_INT(fqr_rs_correct(blk, 50, 10, 0), -1);
  /* All-zero and all-0xFF garbage blocks never crash. */
  memset(blk, 0xFF, 255);
  (void)fqr_rs_correct(blk, 255, 30, 15);
  memset(blk, 0, 255);
  CHECK_EQ_INT(fqr_rs_correct(blk, 255, 30, 15), 0);
}

int main(void) {
  tc_rng_t rng;
  tc_rng_seed(&rng, 0x5EEDu);
  test_known_answer();
  test_random(&rng);
  test_limits(&rng);
  return tc_report("test_rs");
}
