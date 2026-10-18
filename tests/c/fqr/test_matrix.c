// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* Matrix-level decoding: BCH tables, function patterns, every
 * version x level x mask, mirroring, damage within/beyond RS capacity,
 * format/version information damage, API validation, random grids. */

#include <string.h>

#include "fqr.h"
#include "fqr_internal.h"
#include "qrenc.h"
#include "tcheck.h"

TC_DEFINE_GLOBALS;

static uint8_t ws[FQR_WORKSPACE_SIZE + 16];
static uint8_t grid[QE_GRID_BYTES];
static uint8_t payload[FQR_MAX_PAYLOAD_SIZE + 16];

static unsigned popc(uint32_t v) {
  unsigned n = 0;
  for (; v; v &= v - 1) n++;
  return n;
}

static void test_bch(void) {
  /* Format: every 15-bit word decodes iff within distance 3 of exactly
   * one codeword, and codewords are pairwise >= 7 apart. */
  for (unsigned a = 0; a < 32; a++) {
    for (unsigned b = a + 1; b < 32; b++) {
      CHECK(popc(fqr_format_codewords[a] ^ fqr_format_codewords[b]) >= 7u);
    }
  }
  for (uint32_t w = 0; w < 32768u; w++) {
    unsigned d;
    int r = fqr_bch_format(w, &d);
    unsigned best = 99;
    for (unsigned k = 0; k < 32; k++) {
      unsigned h = popc(w ^ fqr_format_codewords[k]);
      if (h < best) best = h;
    }
    CHECK_EQ_INT(d, best);
    CHECK((r >= 0) == (best <= 3u));
    if (r >= 0) {
      CHECK(popc(w ^ fqr_format_codewords[r]) <= 3u);
    }
  }
  /* Version: distance >= 8, up to 3 flips corrected, 4 flips detected. */
  for (unsigned a = 0; a < 34; a++) {
    for (unsigned b = a + 1; b < 34; b++) {
      CHECK(popc(fqr_version_codewords[a] ^ fqr_version_codewords[b]) >= 8u);
    }
    for (unsigned i = 0; i < 18; i++) {
      for (unsigned j = i + 1; j < 18; j++) {
        for (unsigned k = j + 1; k < 18; k++) {
          unsigned d;
          uint32_t w =
              fqr_version_codewords[a] ^ (1u << i) ^ (1u << j) ^ (1u << k);
          CHECK_EQ_INT(fqr_bch_version(w, &d), (int)a + 7);
          CHECK_EQ_INT(d, 3);
        }
      }
    }
    unsigned d;
    CHECK_EQ_INT(fqr_bch_version(fqr_version_codewords[a] ^ 0xFu, &d), -1);
  }
  /* Known values (ISO Tables C.1 and D.1). */
  CHECK_EQ_INT(fqr_format_codewords[0], 0x5412);
  CHECK_EQ_INT(fqr_format_codewords[(1 << 3) | 4], 0x662F); /* L, mask 4 */
  CHECK_EQ_INT(fqr_version_codewords[0], 0x07C94);
  CHECK_EQ_INT(fqr_version_codewords[33], 0x28C69);
}

static void test_function_map(void) {
  for (unsigned v = 1; v <= 40; v++) {
    unsigned size = 17 + 4 * v, n = 0;
    for (unsigned r = 0; r < size; r++) {
      for (unsigned c = 0; c < size; c++) {
        n += !fqr_is_function_module(v, r, c);
      }
    }
    CHECK_EQ_INT(n, fqr_total_codewords[v] * 8u + fqr_remainder_bits[v]);
    /* Data capacity sanity (ISO Table 7, byte mode not needed). */
  }
  CHECK_EQ_INT(qe_data_codewords(1, FQR_ECC_H), 9);
  CHECK_EQ_INT(qe_data_codewords(40, FQR_ECC_L), 2956);
  CHECK_EQ_INT(qe_data_codewords(40, FQR_ECC_H), 1276);
  CHECK_EQ_INT(qe_data_codewords(9, FQR_ECC_M), 182);
  CHECK(!fqr_is_function_module(0, 0, 0));
  CHECK(!fqr_is_function_module(1, 21, 0));
}

static fqr_status_t dec(const uint8_t *g, unsigned size, bool mirror,
                        fqr_result_t *r, size_t cap) {
  memset(r, 0, sizeof *r);
  r->payload = payload;
  r->payload_cap = cap;
  return fqr_decode_matrix(g, size, QE_GRID_STRIDE, mirror, ws + 3,
                           sizeof ws - 3, r);
}

static void transpose(uint8_t *g, unsigned size) {
  for (unsigned r = 0; r < size; r++) {
    for (unsigned c = r + 1; c < size; c++) {
      int a = qe_get(g, QE_GRID_STRIDE, r, c),
          b = qe_get(g, QE_GRID_STRIDE, c, r);
      qe_set(g, QE_GRID_STRIDE, r, c, b);
      qe_set(g, QE_GRID_STRIDE, c, r, a);
    }
  }
}

static void test_all_versions(tc_rng_t *rng) {
  static uint8_t data[3706], msg[3000];
  unsigned n_ok = 0;
  for (unsigned v = 1; v <= 40; v++) {
    for (unsigned lv = 0; lv < 4; lv++) {
      for (unsigned mask = 0; mask < 8; mask++) {
        unsigned cap = qe_data_codewords(v, lv);
        unsigned cbits = qe_count_bits(4, v);
        size_t n = (cap * 8u - 4u - cbits) / 8u;
        if (v <= 9 && n > 255) n = 255;
        if (mask & 1) n = tc_below(rng, (uint32_t)n + 1);
        for (size_t i = 0; i < n; i++) msg[i] = (uint8_t)tc_rand(rng);
        qe_bits_t b;
        qe_bits_init(&b);
        qe_seg_byte(&b, v, msg, n);
        CHECK(qe_finalize(&b, v, lv, data));
        qe_build(data, v, lv, mask, grid, QE_GRID_STRIDE);
        fqr_result_t r;
        fqr_status_t s = dec(grid, 17 + 4 * v, false, &r, sizeof payload);
        CHECK_MSG(s == FQR_OK, "v%u lv%u mask%u -> %s", v, lv, mask,
                  fqr_status_str(s));
        if (s == FQR_OK) {
          n_ok++;
          CHECK_EQ_INT(r.version, v);
          CHECK_EQ_INT(r.ecc_level, lv);
          CHECK_EQ_INT(r.mask, mask);
          CHECK_EQ_INT(r.corrected, 0);
          CHECK(!r.mirrored);
          CHECK(r.payload_len == n && memcmp(payload, msg, n) == 0);
        }
        /* Mirrored symbol. */
        if (mask == 2 || mask == 5) {
          transpose(grid, 17 + 4 * v);
          s = dec(grid, 17 + 4 * v, true, &r, sizeof payload);
          CHECK_MSG(s == FQR_OK && r.mirrored, "mirror v%u lv%u", v, lv);
          CHECK(r.payload_len == n && memcmp(payload, msg, n) == 0);
          s = dec(grid, 17 + 4 * v, false, &r, sizeof payload);
          CHECK(s != FQR_OK);
        }
      }
    }
  }
  printf("matrix: %u/1280 version/level/mask combinations decoded\n", n_ok);
}

static unsigned misdecode_p(unsigned v, unsigned lv) {
  if (v == 1) return lv == 0 ? 3 : (lv == 1 ? 2 : 1);
  if (v == 2 && lv == 0) return 2;
  if (v == 3 && lv == 0) return 1;
  return 0;
}

static void test_damage(tc_rng_t *rng) {
  static uint8_t data[3706], cw[3706], msg[3000];
  unsigned within_ok = 0, beyond_detected = 0, beyond_total = 0;
  for (unsigned iter = 0; iter < 600; iter++) {
    unsigned v = 1 + tc_below(rng, 40), lv = tc_below(rng, 4),
             mask = tc_below(rng, 8);
    unsigned cap = qe_data_codewords(v, lv);
    size_t n = (cap * 8u - 4u - qe_count_bits(4, v)) / 8u;
    if (v <= 9 && n > 255) n = 255;
    for (size_t i = 0; i < n; i++) msg[i] = (uint8_t)tc_rand(rng);
    qe_bits_t b;
    qe_bits_init(&b);
    qe_seg_byte(&b, v, msg, n);
    CHECK(qe_finalize(&b, v, lv, data));
    size_t ncw = qe_codewords(data, v, lv, cw);
    unsigned nb = fqr_num_blocks[lv][v], ec = fqr_ecc_per_block[lv][v];
    unsigned tmax = (ec - misdecode_p(v, lv)) / 2;
    unsigned total = fqr_total_codewords[v];
    bool beyond = (iter % 3) == 0;
    unsigned bad_block = tc_below(rng, nb);
    unsigned expected_corr = 0;
    for (unsigned j = 0; j < nb; j++) {
      unsigned blen = total / nb + (j >= nb - total % nb ? 1u : 0u);
      unsigned ne = (beyond && j == bad_block) ? tmax + 1 + tc_below(rng, 3)
                                               : tc_below(rng, tmax + 1);
      if (ne > blen) ne = blen;
      unsigned used[64];
      unsigned nu = 0;
      while (nu < ne) {
        unsigned off = tc_below(rng, blen);
        bool dup = false;
        for (unsigned k = 0; k < nu; k++) dup = dup || used[k] == off;
        if (dup) continue;
        used[nu++] = off;
        size_t idx = qe_interleaved_index(v, lv, j, off);
        CHECK(idx < ncw);
        cw[idx] ^= (uint8_t)(1 + tc_below(rng, 255));
      }
      expected_corr += ne;
    }
    qe_build_cw(cw, ncw, v, lv, mask, grid, QE_GRID_STRIDE);
    fqr_result_t r;
    fqr_status_t s = dec(grid, 17 + 4 * v, false, &r, sizeof payload);
    if (!beyond) {
      CHECK_MSG(s == FQR_OK, "v%u lv%u: %s", v, lv, fqr_status_str(s));
      CHECK_EQ_INT(r.corrected, expected_corr);
      CHECK_EQ_INT(r.ecc_capacity, tmax);
      CHECK(r.payload_len == n && memcmp(payload, msg, n) == 0);
      within_ok += (s == FQR_OK);
    } else {
      beyond_total++;
      if (s == FQR_ERR_ECC) {
        beyond_detected++;
      } else {
        /* A misdecode never yields the original message silently
         * with fewer corrections than injected. */
        CHECK(s != FQR_OK || r.corrected <= expected_corr);
      }
    }
  }
  printf("damage: %u within-capacity decoded, %u/%u beyond-capacity detected\n",
         within_ok, beyond_detected, beyond_total);
  CHECK(beyond_detected * 100u >= beyond_total * 95u);
}

static void test_format_version_damage(tc_rng_t *rng) {
  static uint8_t data[3706];
  const uint8_t msg[] =
      "otpauth://totp/feuristic:alice?secret=JBSWY3DPEHPK3PXP";
  for (unsigned v = 4; v <= 40; v += 3) {
    unsigned size = 17 + 4 * v;
    qe_bits_t b;
    qe_bits_init(&b);
    qe_seg_byte(&b, v, msg, sizeof msg - 1);
    CHECK(qe_finalize(&b, v, FQR_ECC_M, data));
    qe_build(data, v, FQR_ECC_M, 6, grid, QE_GRID_STRIDE);
    fqr_result_t r;
    /* 3 random flips in copy 1. */
    uint8_t g2[QE_GRID_BYTES];
    memcpy(g2, grid, sizeof g2);
    for (unsigned k = 0; k < 3; k++) {
      unsigned i = tc_below(rng, 6);
      qe_set(g2, QE_GRID_STRIDE, i, 8, !qe_get(g2, QE_GRID_STRIDE, i, 8));
    }
    CHECK_EQ_INT(dec(g2, size, false, &r, sizeof payload), FQR_OK);
    /* Copy 1 wiped -> copy 2 used. */
    memcpy(g2, grid, sizeof g2);
    /* (All-zero format bits are >= 5 away from every codeword.) */
    for (unsigned i = 0; i < 9; i++) {
      qe_set(g2, QE_GRID_STRIDE, i, 8, 0);
      qe_set(g2, QE_GRID_STRIDE, 8, i, 0);
    }
    CHECK_EQ_INT(dec(g2, size, false, &r, sizeof payload), FQR_OK);
    /* Both copies wiped -> format error. */
    for (unsigned i = 0; i < 8; i++) {
      qe_set(g2, QE_GRID_STRIDE, 8, size - 1 - i, 0);
      qe_set(g2, QE_GRID_STRIDE, size - 1 - i, 8, 0);
    }
    CHECK_EQ_INT(dec(g2, size, true, &r, sizeof payload), FQR_ERR_FORMAT);
    if (v >= 7) {
      /* One version copy destroyed: fine. Both rewritten to another
       * valid version: rejected. */
      memcpy(g2, grid, sizeof g2);
      for (unsigned i = 0; i < 18; i++) {
        qe_set(g2, QE_GRID_STRIDE, i / 3, size - 11 + i % 3,
               (int)(tc_rand(rng) & 1));
      }
      CHECK_EQ_INT(dec(g2, size, false, &r, sizeof payload), FQR_OK);
      uint32_t other = fqr_version_codewords[(v - 7 + 5) % 34];
      for (unsigned i = 0; i < 18; i++) {
        qe_set(g2, QE_GRID_STRIDE, i / 3, size - 11 + i % 3,
               (int)((other >> i) & 1));
        qe_set(g2, QE_GRID_STRIDE, size - 11 + i % 3, i / 3,
               (int)((other >> i) & 1));
      }
      CHECK_EQ_INT(dec(g2, size, false, &r, sizeof payload), FQR_ERR_FORMAT);
      /* Both copies unreadable (all-zero is >= 8 away from every
       * codeword): tolerated, the symbol size is authoritative. */
      for (unsigned i = 0; i < 18; i++) {
        qe_set(g2, QE_GRID_STRIDE, i / 3, size - 11 + i % 3, 0);
        qe_set(g2, QE_GRID_STRIDE, size - 11 + i % 3, i / 3, 0);
      }
      CHECK_EQ_INT(dec(g2, size, false, &r, sizeof payload), FQR_OK);
    }
    /* Payload buffer too small. */
    fqr_status_t s = dec(grid, size, false, &r, 10);
    CHECK_EQ_INT(s, FQR_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(r.status, FQR_ERR_BUFFER_TOO_SMALL);
    CHECK_EQ_INT(r.payload_len, sizeof msg - 1);
    CHECK(memcmp(payload, msg, 10) == 0);
  }
}

static void test_api(void) {
  fqr_result_t r;
  memset(&r, 0, sizeof r);
  memset(grid, 0, sizeof grid);
  CHECK_EQ_INT(fqr_decode_matrix(NULL, 21, 3, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 21, 3, false, ws, sizeof ws, NULL),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 22, 3, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 17, 3, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 181, 23, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 25, 3, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  CHECK_EQ_INT(fqr_decode_matrix(grid, 21, 3, false, NULL, sizeof ws, &r),
               FQR_ERR_WORKSPACE);
  CHECK_EQ_INT(
      fqr_decode_matrix(grid, 21, 3, false, ws, FQR_WORKSPACE_SIZE - 1, &r),
      FQR_ERR_WORKSPACE);
  r.payload = NULL;
  r.payload_cap = 5;
  CHECK_EQ_INT(fqr_decode_matrix(grid, 21, 3, false, ws, sizeof ws, &r),
               FQR_ERR_INVALID_ARG);
  r.payload_cap = 0;
  CHECK_EQ_INT(fqr_decode_matrix(grid, 21, 3, false, ws, sizeof ws, &r),
               FQR_ERR_FORMAT);
  CHECK_EQ_INT(fqr_workspace_size(), FQR_WORKSPACE_SIZE);
  for (int s = 0; s <= 9; s++) {
    CHECK(fqr_status_str((fqr_status_t)s) != NULL);
  }
}

static void test_random_grids(tc_rng_t *rng) {
  unsigned ok = 0;
  for (unsigned iter = 0; iter < 3000; iter++) {
    unsigned v = 1 + tc_below(rng, 40), size = 17 + 4 * v;
    for (size_t i = 0; i < sizeof grid; i++) grid[i] = (uint8_t)tc_rand(rng);
    /* Plant a valid format word half of the time to reach RS. */
    if (iter & 1) {
      uint32_t fmt = fqr_format_codewords[tc_below(rng, 32)];
      for (unsigned i = 0; i < 8; i++)
        qe_set(grid, QE_GRID_STRIDE, 8, size - 1 - i, (int)((fmt >> i) & 1));
      for (unsigned i = 8; i < 15; i++)
        qe_set(grid, QE_GRID_STRIDE, size - 15 + i, 8, (int)((fmt >> i) & 1));
    }
    fqr_result_t r;
    fqr_status_t s = dec(grid, size, true, &r, 64);
    CHECK(s == FQR_OK || s == FQR_ERR_FORMAT || s == FQR_ERR_ECC ||
          s == FQR_ERR_DATA || s == FQR_ERR_BUFFER_TOO_SMALL);
    ok += (s == FQR_OK);
  }
  printf("random grids: %u spurious decodes out of 3000\n", ok);
  CHECK(ok == 0);
}

int main(void) {
  tc_rng_t rng;
  tc_rng_seed(&rng, 0x3A7u);
  test_bch();
  test_function_map();
  test_all_versions(&rng);
  test_damage(&rng);
  test_format_version_damage(&rng);
  test_api();
  test_random_grids(&rng);
  return tc_report("test_matrix");
}
