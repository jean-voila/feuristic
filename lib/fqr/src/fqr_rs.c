// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Reed-Solomon error correction over GF(256), primitive polynomial 0x11D,
 * generator roots alpha^0 .. alpha^(ec-1) (ISO/IEC 18004 §7.5.2).
 *
 * Syndromes -> Berlekamp-Massey -> Chien search -> Forney. With b = 0 the
 * error magnitude is Y = X * Omega(X^-1) / Lambda'(X^-1). The corrected
 * block is re-checked (all syndromes zero) before success is reported.
 */

#include "fqr_internal.h"

#define POLY_CAP 64u /* >= 2 * (FQR_MAX_EC_PER_BLOCK + 1) */

static inline uint8_t gf_mul(uint8_t a, uint8_t b) {
  if (a == 0u || b == 0u) {
    return 0u;
  }
  return fqr_gf_exp[(unsigned)fqr_gf_log[a] + (unsigned)fqr_gf_log[b]];
}

static inline uint8_t gf_inv(uint8_t a) {
  /* a != 0 is guaranteed by every caller. */
  return fqr_gf_exp[255u - (unsigned)fqr_gf_log[a]];
}

/* alpha^e for any e >= 0. */
static inline uint8_t gf_pow_alpha(unsigned e) { return fqr_gf_exp[e % 255u]; }

/* Computes the ec syndromes; returns true if all are zero. */
static bool syndromes(const uint8_t *blk, unsigned n, unsigned ec, uint8_t *s) {
  bool zero = true;
  for (unsigned j = 0; j < ec; j++) {
    uint8_t aj = fqr_gf_exp[j];
    uint8_t acc = 0;
    for (unsigned k = 0; k < n; k++) {
      acc = (uint8_t)(gf_mul(acc, aj) ^ blk[k]);
    }
    s[j] = acc;
    if (acc != 0u) {
      zero = false;
    }
  }
  return zero;
}

int fqr_rs_correct(uint8_t *blk, unsigned n, unsigned ec, unsigned max_err) {
  uint8_t s[FQR_MAX_EC_PER_BLOCK];
  uint8_t lam[POLY_CAP];
  uint8_t prev[POLY_CAP];
  uint8_t tmp[POLY_CAP];
  uint8_t omega[POLY_CAP];
  uint16_t pos[FQR_MAX_EC_PER_BLOCK];
  uint8_t xs[FQR_MAX_EC_PER_BLOCK];
  uint8_t mags[FQR_MAX_EC_PER_BLOCK];

  if (blk == NULL || ec == 0u || ec > FQR_MAX_EC_PER_BLOCK || n <= ec ||
      n > 255u || max_err > ec / 2u) {
    return -1;
  }
  if (syndromes(blk, n, ec, s)) {
    return 0;
  }
  if (max_err == 0u) {
    return -1;
  }

  /* Berlekamp-Massey. lam = C(x), prev = B(x). Degrees stay <= ec. */
  memset(lam, 0, sizeof lam);
  memset(prev, 0, sizeof prev);
  lam[0] = 1u;
  prev[0] = 1u;
  unsigned L = 0, m = 1;
  uint8_t bcoef = 1u;
  for (unsigned r = 0; r < ec; r++) {
    uint8_t d = s[r];
    for (unsigned i = 1; i <= L; i++) {
      d ^= gf_mul(lam[i], s[r - i]);
    }
    if (d == 0u) {
      m++;
      continue;
    }
    uint8_t coef = gf_mul(d, gf_inv(bcoef));
    if (2u * L <= r) {
      memcpy(tmp, lam, sizeof tmp);
      for (unsigned i = 0; i + m < POLY_CAP && i <= ec; i++) {
        lam[i + m] ^= gf_mul(coef, prev[i]);
      }
      L = r + 1u - L;
      memcpy(prev, tmp, sizeof prev);
      bcoef = d;
      m = 1;
    } else {
      for (unsigned i = 0; i + m < POLY_CAP && i <= ec; i++) {
        lam[i + m] ^= gf_mul(coef, prev[i]);
      }
      m++;
    }
  }
  if (L == 0u || L > max_err) {
    return -1;
  }
  /* The locator must have exact degree L. */
  if (lam[L] == 0u) {
    return -1;
  }
  for (unsigned i = L + 1u; i < POLY_CAP; i++) {
    if (lam[i] != 0u) {
      return -1;
    }
  }

  /* Chien search: position k has locator X = alpha^(n-1-k). */
  unsigned nroots = 0;
  for (unsigned k = 0; k < n; k++) {
    unsigned e = n - 1u - k;
    uint8_t xinv = gf_pow_alpha(255u - e);
    uint8_t acc = 0, xp = 1u;
    for (unsigned i = 0; i <= L; i++) {
      acc ^= gf_mul(lam[i], xp);
      xp = gf_mul(xp, xinv);
    }
    if (acc == 0u) {
      if (nroots >= L) {
        return -1;
      }
      pos[nroots] = (uint16_t)k;
      xs[nroots] = gf_pow_alpha(e);
      nroots++;
    }
  }
  if (nroots != L) {
    return -1;
  }

  /* Omega(x) = S(x) * Lambda(x) mod x^ec (only degrees < L matter). */
  memset(omega, 0, sizeof omega);
  for (unsigned i = 0; i < L; i++) {
    uint8_t acc = 0;
    for (unsigned j = 0; j <= i; j++) {
      acc ^= gf_mul(s[j], lam[i - j]);
    }
    omega[i] = acc;
  }

  /* Forney. */
  for (unsigned r = 0; r < nroots; r++) {
    uint8_t x = xs[r];
    uint8_t xinv = gf_inv(x);
    uint8_t num = 0, xp = 1u;
    for (unsigned i = 0; i < L; i++) {
      num ^= gf_mul(omega[i], xp);
      xp = gf_mul(xp, xinv);
    }
    /* Lambda'(x) = sum over odd i of lam[i] x^(i-1). */
    uint8_t den = 0;
    uint8_t xinv2 = gf_mul(xinv, xinv);
    xp = 1u;
    for (unsigned i = 1; i <= L; i += 2u) {
      den ^= gf_mul(lam[i], xp);
      xp = gf_mul(xp, xinv2);
    }
    if (den == 0u) {
      return -1;
    }
    uint8_t mag = gf_mul(gf_mul(x, num), gf_inv(den));
    if (mag == 0u) {
      return -1;
    }
    mags[r] = mag;
  }

  /* Apply only once every magnitude is known, revert if the result does
   * not check, so that a failed call leaves the block unchanged. */
  for (unsigned r = 0; r < nroots; r++) {
    blk[pos[r]] ^= mags[r];
  }
  if (!syndromes(blk, n, ec, s)) {
    for (unsigned r = 0; r < nroots; r++) {
      blk[pos[r]] ^= mags[r];
    }
    return -1; /* defensive: never report a block that does not check */
  }
  return (int)nroots;
}
