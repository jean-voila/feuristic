// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// RSA wrapper over the vendored BearSSL i31 big-integer code. See frsa.h for
// the API contract and docs/developer/rsa.md for the design rationale.
//
// BearSSL i31 representation: x[0] is the "encoded" bit length
// ((k / 31) << 5) + (k % 31) of a k-bit integer, x[1..] hold 31-bit limbs,
// least significant first. Loop bounds of BearSSL routines depend on the
// announced bit length only, never on the values.

#include "frsa.h"

#include <string.h>

#include "frsa_sieve_table.h"
#include "inner.h"

// Words for one integer of up to 2048 bits (encoded bit length 2114 ->
// 67 limbs) plus header, plus room for a 1024x1024-bit product (69 limbs +
// header) and the (p-1)*k+1 intermediate of frsa_complete (34 + 2 limbs).
// Kept even so that every slot stays 64-bit aligned.
#define FRSA_WORDS 72

// Temporary space for br_i31_modpow_opt in frsa_modpow / frsa_mr_round:
// 612 = 9 * 68 = 17 * 36 words -> 3-bit window for 2048-bit moduli, 4-bit
// window for 1024-bit moduli (the key-generation case).
#define FRSA_MODPOW_TMP 612

// Temporary space for the short public-exponent exponentiations and the
// 2048-bit modular division inside frsa_private: 340 = 5 * 68 words
// (2-bit window) and >= 3 * 67 words for br_i31_moddiv.
#define FRSA_PUB_TMP 340

// Bytes of stack scrubbed after br_rsa_i31_private returns (its frame holds
// 1 + 8 * 70 words of CRT intermediates that BearSSL does not wipe).
#define FRSA_SCRUB_BYTES 2560

#if defined(__GNUC__) || defined(__clang__)
#define FRSA_NOINLINE __attribute__((noinline))
#else
#define FRSA_NOINLINE
#endif

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

static void frsa_wipe(void *buf, size_t len) {
  volatile uint8_t *v = (volatile uint8_t *)buf;
  while (len-- > 0) {
    *v++ = 0;
  }
}

// Overwrite the stack area just below the caller's frame, where the frames
// of the BearSSL routines it called used to live.
static FRSA_NOINLINE void frsa_scrub_stack(void) {
  volatile uint8_t area[FRSA_SCRUB_BYTES];
  size_t i;
  for (i = 0; i < sizeof area; i++) {
    area[i] = 0;
  }
}

// Strip leading zero bytes (lengths are public).
static size_t frsa_strip(const uint8_t **p, size_t len) {
  const uint8_t *q = *p;
  while (len > 0 && *q == 0) {
    q++;
    len--;
  }
  *p = q;
  return len;
}

// Constant-time equality of two byte strings of public length: 1 or 0.
static uint32_t frsa_ct_eq_bytes(const uint8_t *a, const uint8_t *b,
                                 size_t len) {
  uint32_t acc = 0;
  size_t i;
  for (i = 0; i < len; i++) {
    acc |= (uint32_t)(a[i] ^ b[i]);
  }
  return EQ0(acc);
}

// Constant-time equality of the value limbs of two i31 integers sharing the
// same announced bit length: 1 or 0.
static uint32_t frsa_ct_eq_i31(const uint32_t *a, const uint32_t *b) {
  size_t len = (a[0] + 31) >> 5;
  uint32_t acc = 0;
  size_t i;
  for (i = 1; i <= len; i++) {
    acc |= a[i] ^ b[i];
  }
  return EQ0(acc);
}

// Real bit length from a BearSSL encoded bit length.
static uint32_t frsa_real_bits(uint32_t ebits) {
  return (ebits >> 5) * 31 + (ebits & 31);
}

// Bit length of a minimally encoded big-endian integer (public data only).
static uint32_t frsa_bytes_bits(const uint8_t *x, size_t len) {
  uint32_t bits;
  uint8_t top;
  if (len == 0) {
    return 0;
  }
  bits = (uint32_t)(len - 1) * 8;
  for (top = x[0]; top != 0; top >>= 1) {
    bits++;
  }
  return bits;
}

// Big-endian encoding of e without leading zeros; returns the start offset.
static size_t frsa_encode_e(uint32_t e, uint8_t eb[4]) {
  size_t off = 0;
  br_enc32be(eb, e);
  while (off < 3 && eb[off] == 0) {
    off++;
  }
  return off;
}

static int frsa_e_valid(uint32_t e) { return e >= 3 && (e & 1) != 0; }

static void frsa_copy_i31(uint32_t *dst, const uint32_t *src) {
  memcpy(dst, src, (1 + ((src[0] + 31) >> 5)) * sizeof *src);
}

// ---------------------------------------------------------------------------
// frsa_complete
// ---------------------------------------------------------------------------

// d = e^-1 mod (a - 1) for an odd a (i31, announced length = true length)
// and an odd small e. Method (also used by BearSSL's key generator for the
// p = 3 mod 4 case, generalised here to any odd a):
//   r = (a-1) mod e, f = r^-1 mod e, k = e - f,
//   d = ((a-1) * k + 1) / e   (exact division; d < a - 1).
// Every step is constant time (br_divrem is a fixed 31-iteration loop,
// br_i31_moddiv is constant time, multiplications are 32x32->64).
// Returns 1 on success, 0 if gcd(e, a-1) != 1. `t` must hold at least
// 2 * FRSA_WORDS words.
static uint32_t frsa_inv_e_mod_am1(uint32_t *d, const uint32_t *a, uint32_t e,
                                   uint32_t *t) {
  size_t len = (a[0] + 31) >> 5;
  uint32_t E[4], Y[4], F[4];
  uint32_t mt[12];
  uint8_t eb[4];
  uint32_t r, rem, f, k, ok;
  uint64_t cc;
  size_t i;

  // r = (a - 1) mod e. a is odd: a - 1 only clears the low bit of limb 1.
  r = 0;
  for (i = len; i >= 1; i--) {
    uint32_t w = a[i] - (uint32_t)(i == 1);
    (void)br_divrem(r >> 1, (r << 31) | w, e, &rem);
    r = rem;
  }

  // f = 1 / r mod e (fails if gcd(r, e) != 1, which includes r == 0).
  br_enc32be(eb, e);
  br_i31_decode(E, eb, sizeof eb);
  br_i31_zero(Y, E[0]);
  Y[1] = r & 0x7FFFFFFF;
  br_i31_zero(F, E[0]);
  F[1] = 1;
  if (((E[0] + 31) >> 5) > 1) {
    Y[2] = r >> 31;
  }
  ok = br_i31_moddiv(F, Y, E, br_i31_ninv31(E[1]), mt);
  f = F[1];
  if (((E[0] + 31) >> 5) > 1) {
    f |= F[2] << 31;
  }
  k = e - f;

  // t = (a - 1) * k + 1, len + 2 limbs.
  cc = 1;
  for (i = 1; i <= len; i++) {
    uint32_t w = a[i] - (uint32_t)(i == 1);
    uint64_t z = (uint64_t)w * k + cc;
    t[i] = (uint32_t)z & 0x7FFFFFFF;
    cc = z >> 31;
  }
  t[len + 1] = (uint32_t)cc & 0x7FFFFFFF;
  t[len + 2] = (uint32_t)(cc >> 31);

  // Exact division by e, most significant limb first.
  rem = 0;
  for (i = len + 2; i >= 1; i--) {
    t[i] = br_divrem(rem >> 1, (rem << 31) | t[i], e, &rem);
  }
  ok &= EQ0(rem);
  ok &= EQ0(t[len + 1] | t[len + 2]);

  d[0] = a[0];
  memcpy(d + 1, t + 1, len * sizeof *d);

  frsa_wipe(Y, sizeof Y);
  frsa_wipe(F, sizeof F);
  frsa_wipe(mt, sizeof mt);
  frsa_wipe(t, (len + 3) * sizeof *t);
  return ok;
}

int frsa_complete(const uint8_t *p, size_t plen, const uint8_t *q, size_t qlen,
                  uint32_t e, uint8_t *n, size_t *nlen_out, uint8_t *dp,
                  uint8_t *dq, uint8_t *qinv, size_t *clen_out) {
  uint32_t P[FRSA_WORDS], Q[FRSA_WORDS], T[FRSA_WORDS], X[FRSA_WORDS];
  uint32_t t[3 * FRSA_WORDS];
  uint32_t ok, nbits;
  size_t nlen, clen, words;
  int ret = FRSA_ERR_PARAM;

  if (n == NULL || nlen_out == NULL || dp == NULL || dq == NULL ||
      qinv == NULL || clen_out == NULL) {
    return FRSA_ERR_PARAM;
  }
  memset(n, 0, FRSA_MAX_MODULUS_BYTES);
  memset(dp, 0, FRSA_MAX_FACTOR_BYTES);
  memset(dq, 0, FRSA_MAX_FACTOR_BYTES);
  memset(qinv, 0, FRSA_MAX_FACTOR_BYTES);
  *nlen_out = 0;
  *clen_out = 0;
  if (p == NULL || q == NULL || !frsa_e_valid(e)) {
    return FRSA_ERR_PARAM;
  }
  plen = frsa_strip(&p, plen);
  qlen = frsa_strip(&q, qlen);
  if (plen == 0 || qlen == 0 || plen > FRSA_MAX_FACTOR_BYTES ||
      qlen > FRSA_MAX_FACTOR_BYTES || (p[plen - 1] & 1) == 0 ||
      (q[qlen - 1] & 1) == 0) {
    return FRSA_ERR_PARAM;
  }

  br_i31_decode(P, p, plen);
  br_i31_decode(Q, q, qlen);

  // n = p * q
  memset(T, 0, sizeof T);
  br_i31_zero(T, P[0]);
  br_i31_mulacc(T, P, Q);
  words = (T[0] + 31) >> 5;
  nbits = frsa_real_bits(br_i31_bit_length(T + 1, words));
  nlen = (nbits + 7) >> 3;
  clen = (nlen + 1) >> 1;
  if (nbits < FRSA_MIN_MODULUS_BITS || nbits > FRSA_MAX_MODULUS_BITS ||
      plen > clen || qlen > clen) {
    goto out;
  }
  br_i31_encode(n, nlen, T);

  // dp, dq
  ok = frsa_inv_e_mod_am1(X, P, e, t);
  br_i31_encode(dp, clen, X);
  ok &= frsa_inv_e_mod_am1(X, Q, e, t);
  br_i31_encode(dq, clen, X);

  // qinv = 1 / (q mod p) mod p (fails if p == q or gcd(p, q) != 1)
  br_i31_decode_reduce(T, q, qlen, P);
  br_i31_zero(X, P[0]);
  X[1] = 1;
  ok &= br_i31_moddiv(X, T, P, br_i31_ninv31(P[1]), t);
  br_i31_encode(qinv, clen, X);

  if (ok != 1) {
    ret = FRSA_ERR_KEY;
    goto out;
  }
  *nlen_out = nlen;
  *clen_out = clen;
  ret = FRSA_OK;

out:
  if (ret != FRSA_OK) {
    frsa_wipe(n, FRSA_MAX_MODULUS_BYTES);
    frsa_wipe(dp, FRSA_MAX_FACTOR_BYTES);
    frsa_wipe(dq, FRSA_MAX_FACTOR_BYTES);
    frsa_wipe(qinv, FRSA_MAX_FACTOR_BYTES);
  }
  frsa_wipe(P, sizeof P);
  frsa_wipe(Q, sizeof Q);
  frsa_wipe(T, sizeof T);
  frsa_wipe(X, sizeof X);
  frsa_wipe(t, sizeof t);
  return ret;
}

// ---------------------------------------------------------------------------
// frsa_private
// ---------------------------------------------------------------------------

int frsa_private(const frsa_key *key, const uint8_t *in, size_t inlen,
                 const uint8_t *blind, size_t blindlen, uint8_t *out) {
  // Four integer slots reused across phases (see comments below), plus a
  // temporary area that also hosts the montymul destination of phase 3 and
  // the `chk` byte buffer whenever no exponentiation is running in it.
  uint32_t S0[FRSA_WORDS], S1[FRSA_WORDS], S2[FRSA_WORDS], S3[FRSA_WORDS];
  uint32_t tmp[FRSA_PUB_TMP];
  uint8_t buf[FRSA_MAX_MODULUS_BYTES];
  uint8_t *chk = (uint8_t *)tmp;
  uint8_t eb[4];
  const uint8_t *p, *q, *dp, *dq, *qinv, *n;
  size_t plen, qlen, dplen, dqlen, qinvlen, nlen, eoff, i;
  uint32_t nbits, n0i, ok, ok2, mask;
  br_rsa_private_key sk;
  int ret = FRSA_ERR_PARAM;

  if (key == NULL || in == NULL || out == NULL) {
    return FRSA_ERR_PARAM;
  }
  n = key->n;
  nlen = key->nlen;
  if (n == NULL || nlen == 0 || nlen > FRSA_MAX_MODULUS_BYTES) {
    return FRSA_ERR_PARAM;
  }
  if (inlen != nlen) {
    memset(out, 0, inlen <= nlen ? inlen : nlen);
    return FRSA_ERR_PARAM;
  }
  p = key->p;
  q = key->q;
  dp = key->dp;
  dq = key->dq;
  qinv = key->qinv;
  if (p == NULL || q == NULL || dp == NULL || dq == NULL || qinv == NULL ||
      n[0] == 0 || (n[nlen - 1] & 1) == 0 || !frsa_e_valid(key->e) ||
      (blind != NULL && blindlen < nlen)) {
    memset(out, 0, nlen);
    return FRSA_ERR_PARAM;
  }
  nbits = frsa_bytes_bits(n, nlen);
  plen = frsa_strip(&p, key->plen);
  qlen = frsa_strip(&q, key->qlen);
  dplen = frsa_strip(&dp, key->dplen);
  dqlen = frsa_strip(&dq, key->dqlen);
  qinvlen = frsa_strip(&qinv, key->qinvlen);
  if (nbits < FRSA_MIN_MODULUS_BITS || plen == 0 || qlen == 0 || dplen == 0 ||
      dqlen == 0 || qinvlen == 0 || plen > FRSA_MAX_FACTOR_BYTES ||
      qlen > FRSA_MAX_FACTOR_BYTES || dplen > FRSA_MAX_FACTOR_BYTES ||
      dqlen > FRSA_MAX_FACTOR_BYTES || qinvlen > FRSA_MAX_FACTOR_BYTES ||
      (p[plen - 1] & 1) == 0 || (q[qlen - 1] & 1) == 0) {
    memset(out, 0, nlen);
    return FRSA_ERR_PARAM;
  }
  eoff = frsa_encode_e(key->e, eb);

  // Phase 1: n == p * q (S0 = p, S1 = q, S2 = product).
  br_i31_decode(S0, p, plen);
  br_i31_decode(S1, q, qlen);
  memset(S2, 0, sizeof S2);
  br_i31_zero(S2, S0[0]);
  br_i31_mulacc(S2, S0, S1);
  if (frsa_real_bits(br_i31_bit_length(S2 + 1, (S2[0] + 31) >> 5)) != nbits) {
    ret = FRSA_ERR_KEY;
    goto out;
  }
  br_i31_encode(chk, nlen, S2);
  if (frsa_ct_eq_bytes(chk, n, nlen) != 1) {
    ret = FRSA_ERR_KEY;
    goto out;
  }

  // Phase 2: S0 = n, S2 = in mod n (rejects in >= n).
  br_i31_decode(S0, n, nlen);
  n0i = br_i31_ninv31(S0[1]);
  ok = br_i31_decode_mod(S2, in, nlen, S0);
  if (ok != 1) {
    ret = FRSA_ERR_PARAM;
    goto out;
  }

  // Phase 3 (optional): blinding. S1 = r, S3 = r^e, buf = in * r^e mod n.
  if (blind != NULL) {
    br_i31_decode_reduce(S1, blind, nlen, S0);
    frsa_copy_i31(S3, S1);
    ok &= br_i31_modpow_opt(S3, eb + eoff, sizeof eb - eoff, S0, n0i, tmp,
                            FRSA_PUB_TMP);
    br_i31_to_monty(S2, S0);
    br_i31_montymul(tmp, S2, S3, S0, n0i);  // (in * R) * r^e / R
    br_i31_encode(buf, nlen, tmp);
  } else {
    memcpy(buf, in, nlen);
  }

  // Phase 4: CRT private operation (BearSSL, constant time). It also checks
  // that buf < p * q and that p and q are odd.
  sk.n_bitlen = nbits;
  sk.p = (unsigned char *)(uintptr_t)p;
  sk.plen = plen;
  sk.q = (unsigned char *)(uintptr_t)q;
  sk.qlen = qlen;
  sk.dp = (unsigned char *)(uintptr_t)dp;
  sk.dplen = dplen;
  sk.dq = (unsigned char *)(uintptr_t)dq;
  sk.dqlen = dqlen;
  sk.iq = (unsigned char *)(uintptr_t)qinv;
  sk.iqlen = qinvlen;
  ok &= br_rsa_i31_private(buf, &sk);
  frsa_scrub_stack();

  // Phase 5: unblind. S2 = s' / r mod n.
  ok &= br_i31_decode_mod(S2, buf, nlen, S0);
  if (blind != NULL) {
    ok &= br_i31_moddiv(S2, S1, S0, n0i, tmp);
    br_i31_encode(buf, nlen, S2);
  }

  // Phase 6: fault check. S3 = s^e mod n must equal `in`.
  frsa_copy_i31(S3, S2);
  ok &= br_i31_modpow_opt(S3, eb + eoff, sizeof eb - eoff, S0, n0i, tmp,
                          FRSA_PUB_TMP);
  br_i31_encode(chk, nlen, S3);
  ok &= frsa_ct_eq_bytes(chk, in, nlen);
  // Second, independent evaluation of the comparison (a single skipped or
  // corrupted instruction must not be enough to release a faulty result).
  ok2 = frsa_ct_eq_bytes(in, chk, nlen);
  mask = (uint32_t)0 - (ok & ok2 & 1);
  for (i = 0; i < nlen; i++) {
    out[i] = (uint8_t)(buf[i] & mask);
  }
  if (ok != 1) {
    ret = FRSA_ERR_FAULT;
    goto out;
  }
  if (ok2 != 1 || mask != 0xFFFFFFFFu) {
    ret = FRSA_ERR_FAULT;
    goto out;
  }
  ret = FRSA_OK;

out:
  if (ret != FRSA_OK) {
    frsa_wipe(out, nlen);
  }
  frsa_wipe(S0, sizeof S0);
  frsa_wipe(S1, sizeof S1);
  frsa_wipe(S2, sizeof S2);
  frsa_wipe(S3, sizeof S3);
  frsa_wipe(tmp, sizeof tmp);
  frsa_wipe(buf, sizeof buf);
  frsa_wipe(&sk, sizeof sk);
  return ret;
}

// ---------------------------------------------------------------------------
// frsa_public
// ---------------------------------------------------------------------------

int frsa_public(const uint8_t *n, size_t nlen, uint32_t e, const uint8_t *in,
                size_t inlen, uint8_t *out) {
  br_rsa_public_key pk;
  uint8_t eb[4];
  size_t eoff;

  if (n == NULL || in == NULL || out == NULL || nlen == 0 ||
      nlen > FRSA_MAX_MODULUS_BYTES || inlen != nlen || n[0] == 0 ||
      (n[nlen - 1] & 1) == 0 || !frsa_e_valid(e) ||
      frsa_bytes_bits(n, nlen) < FRSA_MIN_MODULUS_BITS) {
    return FRSA_ERR_PARAM;
  }
  eoff = frsa_encode_e(e, eb);
  pk.n = (unsigned char *)(uintptr_t)n;
  pk.nlen = nlen;
  pk.e = eb + eoff;
  pk.elen = sizeof eb - eoff;
  if (out != in) {
    memmove(out, in, nlen);
  }
  if (br_rsa_i31_public(out, nlen, &pk) != 1) {
    memset(out, 0, nlen);
    return FRSA_ERR_PARAM;
  }
  return FRSA_OK;
}

// ---------------------------------------------------------------------------
// frsa_modpow
// ---------------------------------------------------------------------------

int frsa_modpow(const uint8_t *base, size_t baselen, const uint8_t *exp,
                size_t explen, const uint8_t *mod, size_t modlen,
                uint8_t *out) {
  uint32_t M[FRSA_WORDS], X[FRSA_WORDS];
  uint32_t tmp[FRSA_MODPOW_TMP];
  const uint8_t *m = mod;
  size_t mlen;
  uint32_t ok;

  if (mod == NULL || out == NULL || modlen == 0 ||
      modlen > FRSA_MAX_MODULUS_BYTES || baselen > FRSA_MAX_MODULUS_BYTES ||
      explen > FRSA_MAX_MODULUS_BYTES || (baselen > 0 && base == NULL) ||
      (explen > 0 && exp == NULL)) {
    return FRSA_ERR_PARAM;
  }
  mlen = frsa_strip(&m, modlen);
  if (mlen == 0 || (m[mlen - 1] & 1) == 0 || (mlen == 1 && m[0] < 3)) {
    memset(out, 0, modlen);
    return FRSA_ERR_PARAM;
  }
  br_i31_decode(M, m, mlen);
  if (baselen > 0) {
    br_i31_decode_reduce(X, base, baselen, M);
  } else {
    br_i31_zero(X, M[0]);
  }
  ok = br_i31_modpow_opt(X, exp, explen, M, br_i31_ninv31(M[1]), tmp,
                         FRSA_MODPOW_TMP);
  br_i31_encode(out, modlen, X);
  frsa_wipe(X, sizeof X);
  frsa_wipe(M, sizeof M);
  frsa_wipe(tmp, sizeof tmp);
  if (ok != 1) {
    frsa_wipe(out, modlen);
    return FRSA_ERR_FAULT;
  }
  return FRSA_OK;
}

// ---------------------------------------------------------------------------
// frsa_sieve
// ---------------------------------------------------------------------------

int frsa_sieve(const uint8_t *cand, size_t candlen) {
  uint32_t C[FRSA_WORDS], Y[FRSA_WORDS];
  uint32_t t[3 * FRSA_WORDS];
  const uint8_t *c = cand;
  uint32_t r;

  if (cand == NULL || candlen == 0 || candlen > FRSA_MAX_MODULUS_BYTES) {
    return FRSA_ERR_PARAM;
  }
  candlen = frsa_strip(&c, candlen);
  if (candlen == 0 || (c[candlen - 1] & 1) == 0 || (candlen == 1 && c[0] < 3)) {
    return 0;
  }
  br_i31_decode(C, c, candlen);
  br_i31_decode_reduce(Y, FRSA_SIEVE_PRODUCT, sizeof FRSA_SIEVE_PRODUCT, C);
  r = br_i31_moddiv(Y, Y, C, br_i31_ninv31(C[1]), t);
  frsa_wipe(C, sizeof C);
  frsa_wipe(Y, sizeof Y);
  frsa_wipe(t, sizeof t);
  return (int)r;
}

// ---------------------------------------------------------------------------
// frsa_mr_round
// ---------------------------------------------------------------------------

int frsa_mr_round(const uint8_t *w, size_t wlen, const uint8_t *b,
                  size_t blen) {
  uint32_t W[FRSA_WORDS], Z[FRSA_WORDS], ONE[FRSA_WORDS], MONE[FRSA_WORDS],
      T[FRSA_WORDS];
  uint32_t tmp[FRSA_MODPOW_TMP];
  uint8_t m[FRSA_MAX_MODULUS_BYTES];
  size_t s, mlen, i, len;
  unsigned bits, carry;
  uint32_t ok, w0i, acc;
  int ret = FRSA_ERR_PARAM;

  if (w == NULL || b == NULL || wlen == 0 || blen == 0 ||
      wlen > FRSA_MAX_MODULUS_BYTES || blen > FRSA_MAX_MODULUS_BYTES) {
    return FRSA_ERR_PARAM;
  }
  wlen = frsa_strip(&w, wlen);
  if (wlen == 0 || (w[wlen - 1] & 1) == 0 || (wlen == 1 && w[0] < 5)) {
    return FRSA_ERR_PARAM;
  }
  br_i31_decode(W, w, wlen);
  len = (W[0] + 31) >> 5;
  w0i = br_i31_ninv31(W[1]);

  // 1 < b < w - 1 (the base is public; plain comparisons are fine).
  if (br_i31_decode_mod(Z, b, blen, W) != 1) {
    goto out;
  }
  acc = 0;
  for (i = 2; i <= len; i++) {
    acc |= Z[i];
  }
  if (acc == 0 && Z[1] <= 1) {
    goto out;
  }
  frsa_copy_i31(MONE, W);
  MONE[1] -= 1;  // w odd: w - 1 only clears the low bit
  if (frsa_ct_eq_i31(Z, MONE)) {
    goto out;
  }

  // w - 1 = 2^s * m with m odd. Run time depends on s (documented).
  memcpy(m, w, wlen);
  m[wlen - 1] &= 0xFE;
  s = 0;
  for (i = wlen; i-- > 0;) {
    if (m[i] != 0) {
      unsigned v = m[i];
      while ((v & 1) == 0) {
        v >>= 1;
        s++;
      }
      break;
    }
    s += 8;
  }
  mlen = wlen - (s >> 3);
  bits = (unsigned)(s & 7);
  if (bits != 0) {
    carry = 0;
    for (i = 0; i < mlen; i++) {
      unsigned v = m[i];
      m[i] = (uint8_t)((v >> bits) | carry);
      carry = (v << (8 - bits)) & 0xFF;
    }
  }

  // z = b^m mod w
  ok = br_i31_modpow_opt(Z, m, mlen, W, w0i, tmp, FRSA_MODPOW_TMP);
  if (ok != 1) {
    ret = FRSA_ERR_FAULT;
    goto out;
  }
  br_i31_zero(ONE, W[0]);
  ONE[1] = 1;
  acc = frsa_ct_eq_i31(Z, ONE) | frsa_ct_eq_i31(Z, MONE);

  if (s > 1) {
    // Work in Montgomery form: compare against R mod w and -R mod w.
    br_i31_to_monty(Z, W);
    br_i31_to_monty(ONE, W);
    frsa_copy_i31(MONE, W);
    br_i31_sub(MONE, ONE, 1);
    for (i = 1; i < s; i++) {
      br_i31_montymul(T, Z, Z, W, w0i);
      memcpy(Z, T, (1 + len) * sizeof *Z);
      acc |= frsa_ct_eq_i31(Z, MONE);
    }
  }
  ret = (int)(acc & 1);

out:
  frsa_wipe(W, sizeof W);
  frsa_wipe(Z, sizeof Z);
  frsa_wipe(ONE, sizeof ONE);
  frsa_wipe(MONE, sizeof MONE);
  frsa_wipe(T, sizeof T);
  frsa_wipe(tmp, sizeof tmp);
  frsa_wipe(m, sizeof m);
  return ret;
}
