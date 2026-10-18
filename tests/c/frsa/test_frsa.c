// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Unit tests for lib/frsa (known answers, Wycheproof, CRT consistency,
// fault countermeasure, sieve and Miller-Rabin).

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "frsa.h"
#include "frsa_vectors.h"

static int g_failures = 0;
static int g_checks = 0;

#define CHECK(cond)                                                   \
  do {                                                                \
    g_checks++;                                                       \
    if (!(cond)) {                                                    \
      g_failures++;                                                   \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, \
              #cond);                                                 \
    }                                                                 \
  } while (0)

#define COUNT(a) (sizeof(a) / sizeof((a)[0]))

// xorshift64* -- deterministic test randomness (not cryptographic).
static uint64_t g_rng = 0x9E3779B97F4A7C15ull;
static void rnd(uint8_t *buf, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    g_rng ^= g_rng >> 12;
    g_rng ^= g_rng << 25;
    g_rng ^= g_rng >> 27;
    buf[i] = (uint8_t)((g_rng * 0x2545F4914F6CDD1Dull) >> 56);
  }
}

static int all_zero(const uint8_t *b, size_t len) {
  size_t i;
  for (i = 0; i < len; i++) {
    if (b[i] != 0) {
      return 0;
    }
  }
  return 1;
}

// Big-endian compare of equal-length strings (test helper, not CT).
static int lt_be(const uint8_t *a, const uint8_t *b, size_t len) {
  return memcmp(a, b, len) < 0;
}

static frsa_key key_from_kat(const kat_key *k) {
  frsa_key key;
  key.p = k->p;
  key.plen = k->plen;
  key.q = k->q;
  key.qlen = k->qlen;
  key.dp = k->dp;
  key.dplen = k->dplen;
  key.dq = k->dq;
  key.dqlen = k->dqlen;
  key.qinv = k->qinv;
  key.qinvlen = k->qinvlen;
  key.n = k->n;
  key.nlen = k->nlen;
  key.e = k->e;
  return key;
}

// Derived components for keys that only carry p, q, e.
typedef struct {
  uint8_t n[FRSA_MAX_MODULUS_BYTES];
  uint8_t dp[FRSA_MAX_FACTOR_BYTES];
  uint8_t dq[FRSA_MAX_FACTOR_BYTES];
  uint8_t qinv[FRSA_MAX_FACTOR_BYTES];
  size_t nlen, clen;
} derived;

static int derive(const uint8_t *p, size_t plen, const uint8_t *q, size_t qlen,
                  uint32_t e, derived *d, frsa_key *key) {
  int r = frsa_complete(p, plen, q, qlen, e, d->n, &d->nlen, d->dp, d->dq,
                        d->qinv, &d->clen);
  key->p = p;
  key->plen = plen;
  key->q = q;
  key->qlen = qlen;
  key->dp = d->dp;
  key->dplen = d->clen;
  key->dq = d->dq;
  key->dqlen = d->clen;
  key->qinv = d->qinv;
  key->qinvlen = d->clen;
  key->n = d->n;
  key->nlen = d->nlen;
  key->e = e;
  return r;
}

// ---------------------------------------------------------------------------

static void test_kat_complete(void) {
  size_t i;
  for (i = 0; i < COUNT(KAT_KEYS); i++) {
    const kat_key *k = &KAT_KEYS[i];
    derived d;
    frsa_key key;
    CHECK(derive(k->p, k->plen, k->q, k->qlen, k->e, &d, &key) == FRSA_OK);
    CHECK(d.nlen == k->nlen);
    CHECK(d.clen == k->dplen);
    CHECK(memcmp(d.n, k->n, k->nlen) == 0);
    CHECK(memcmp(d.dp, k->dp, k->dplen) == 0);
    CHECK(memcmp(d.dq, k->dq, k->dqlen) == 0);
    CHECK(memcmp(d.qinv, k->qinv, k->qinvlen) == 0);
  }
}

static void test_kat_private_public(void) {
  size_t i, j;
  for (i = 0; i < COUNT(KAT_KEYS); i++) {
    const kat_key *k = &KAT_KEYS[i];
    frsa_key key = key_from_kat(k);
    for (j = 0; j < k->nmsgs; j++) {
      const kat_msg *m = &k->msgs[j];
      uint8_t out[FRSA_MAX_MODULUS_BYTES], blind[FRSA_MAX_MODULUS_BYTES];
      uint8_t inplace[FRSA_MAX_MODULUS_BYTES];
      CHECK(frsa_private(&key, m->m, m->mlen, NULL, 0, out) == FRSA_OK);
      CHECK(memcmp(out, m->s, m->slen) == 0);
      rnd(blind, sizeof blind);
      memset(out, 0xAA, sizeof out);
      CHECK(frsa_private(&key, m->m, m->mlen, blind, k->nlen, out) == FRSA_OK);
      CHECK(memcmp(out, m->s, m->slen) == 0);
      memcpy(inplace, m->m, m->mlen);
      CHECK(frsa_private(&key, inplace, m->mlen, blind, k->nlen, inplace) ==
            FRSA_OK);
      CHECK(memcmp(inplace, m->s, m->slen) == 0);
      CHECK(frsa_public(k->n, k->nlen, k->e, m->s, m->slen, out) == FRSA_OK);
      CHECK(memcmp(out, m->m, m->mlen) == 0);
      // modpow cross-check: s^e mod n == m
      {
        uint8_t eb[4];
        eb[0] = (uint8_t)(k->e >> 24);
        eb[1] = (uint8_t)(k->e >> 16);
        eb[2] = (uint8_t)(k->e >> 8);
        eb[3] = (uint8_t)k->e;
        CHECK(frsa_modpow(m->s, m->slen, eb, 4, k->n, k->nlen, out) ==
              FRSA_OK);
        CHECK(memcmp(out, m->m, m->mlen) == 0);
      }
    }
  }
}

static void test_crt_consistency(void) {
  size_t i, j;
  for (i = 0; i < COUNT(KAT_KEYS); i++) {
    const kat_key *k = &KAT_KEYS[i];
    frsa_key key = key_from_kat(k);
    for (j = 0; j < 6; j++) {
      uint8_t in[FRSA_MAX_MODULUS_BYTES], s1[FRSA_MAX_MODULUS_BYTES];
      uint8_t s2[FRSA_MAX_MODULUS_BYTES], back[FRSA_MAX_MODULUS_BYTES];
      uint8_t blind[FRSA_MAX_MODULUS_BYTES];
      rnd(in, k->nlen);
      if (!lt_be(in, k->n, k->nlen)) {
        in[0] = 0;
      }
      rnd(blind, k->nlen);
      CHECK(frsa_private(&key, in, k->nlen, NULL, 0, s1) == FRSA_OK);
      CHECK(frsa_private(&key, in, k->nlen, blind, k->nlen, s2) == FRSA_OK);
      CHECK(memcmp(s1, s2, k->nlen) == 0);
      CHECK(frsa_public(k->n, k->nlen, k->e, s1, k->nlen, back) == FRSA_OK);
      CHECK(memcmp(back, in, k->nlen) == 0);
    }
    // the primes pass the sieve and a Miller-Rabin round
    {
      uint8_t b[2] = {0x01, 0x23};
      CHECK(frsa_sieve(k->p, k->plen) == 1);
      CHECK(frsa_sieve(k->q, k->qlen) == 1);
      CHECK(frsa_mr_round(k->p, k->plen, b, 2) == 1);
      CHECK(frsa_mr_round(k->q, k->qlen, b, 2) == 1);
      CHECK(frsa_sieve(k->n, k->nlen) == 1);
      CHECK(frsa_mr_round(k->n, k->nlen, b, 2) == 0);
    }
  }
}

static void test_wycheproof_decrypt(void) {
  size_t i, j;
  for (i = 0; i < COUNT(WP_DECRYPT); i++) {
    const wp_key *k = &WP_DECRYPT[i];
    derived d;
    frsa_key key;
    CHECK(derive(k->p, k->plen, k->q, k->qlen, k->e, &d, &key) == FRSA_OK);
    CHECK(d.nlen == k->nlen && memcmp(d.n, k->n, k->nlen) == 0);
    for (j = 0; j < k->ncases; j++) {
      const wp_case *c = &k->cases[j];
      uint8_t out[FRSA_MAX_MODULUS_BYTES + 8], back[FRSA_MAX_MODULUS_BYTES];
      uint8_t blind[FRSA_MAX_MODULUS_BYTES];
      int r;
      rnd(blind, sizeof blind);
      memset(out, 0xAA, sizeof out);
      r = frsa_private(&key, c->in, c->inlen, blind, k->nlen, out);
      if (c->valid_format) {
        CHECK(r == FRSA_OK);
        CHECK(frsa_public(k->n, k->nlen, k->e, out, k->nlen, back) ==
              FRSA_OK);
        CHECK(memcmp(back, c->in, k->nlen) == 0);
        if (r != FRSA_OK) {
          fprintf(stderr, "  wycheproof decrypt tcId %d\n", c->tc);
        }
      } else {
        CHECK(r == FRSA_ERR_PARAM);
        CHECK(all_zero(out, c->inlen < k->nlen ? c->inlen : k->nlen));
      }
    }
  }
}

static void test_wycheproof_sign(void) {
  size_t i, j;
  for (i = 0; i < COUNT(WP_SIGN); i++) {
    const wp_key *k = &WP_SIGN[i];
    frsa_key key;
    key.p = k->p;
    key.plen = k->plen;
    key.q = k->q;
    key.qlen = k->qlen;
    key.dp = k->dp;
    key.dplen = k->dplen;
    key.dq = k->dq;
    key.dqlen = k->dqlen;
    key.qinv = k->qinv;
    key.qinvlen = k->qinvlen;
    key.n = k->n;
    key.nlen = k->nlen;
    key.e = k->e;
    for (j = 0; j < k->ncases; j++) {
      const wp_case *c = &k->cases[j];
      uint8_t out[FRSA_MAX_MODULUS_BYTES];
      CHECK(frsa_private(&key, c->in, c->inlen, NULL, 0, out) == FRSA_OK);
      CHECK(c->outlen == k->nlen && memcmp(out, c->out, c->outlen) == 0);
    }
  }
}

// Find a 2048-bit KAT key (fault tests).
static const kat_key *big_key(void) {
  size_t i;
  for (i = 0; i < COUNT(KAT_KEYS); i++) {
    if (KAT_KEYS[i].nlen == 256 && KAT_KEYS[i].e == 65537) {
      return &KAT_KEYS[i];
    }
  }
  return &KAT_KEYS[0];
}

static void expect_fail(const frsa_key *key, const uint8_t *in, size_t inlen,
                        const uint8_t *blind, size_t blindlen, int expected) {
  uint8_t out[FRSA_MAX_MODULUS_BYTES];
  memset(out, 0xAA, sizeof out);
  CHECK(frsa_private(key, in, inlen, blind, blindlen, out) == expected);
  CHECK(all_zero(out, key->nlen <= inlen ? key->nlen : inlen));
}

static void test_fault_countermeasure(void) {
  const kat_key *k = big_key();
  const kat_msg *m = &k->msgs[0];
  uint8_t dp[FRSA_MAX_FACTOR_BYTES], dq[FRSA_MAX_FACTOR_BYTES];
  uint8_t qinv[FRSA_MAX_FACTOR_BYTES], p[FRSA_MAX_FACTOR_BYTES];
  uint8_t n[FRSA_MAX_MODULUS_BYTES + 1], in[FRSA_MAX_MODULUS_BYTES];
  uint8_t blind[FRSA_MAX_MODULUS_BYTES];
  frsa_key key;
  size_t bit;

  rnd(blind, sizeof blind);

  // Corrupted dp / dq / qinv: the CRT result is wrong, the verification
  // s^e == m catches it, the output is wiped (Bellcore-style fault).
  for (bit = 0; bit < 8 * k->dplen; bit += 97) {
    key = key_from_kat(k);
    memcpy(dp, k->dp, k->dplen);
    dp[k->dplen - 1 - bit / 8] ^= (uint8_t)(1u << (bit % 8));
    key.dp = dp;
    expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_FAULT);
    expect_fail(&key, m->m, m->mlen, blind, k->nlen, FRSA_ERR_FAULT);
  }
  key = key_from_kat(k);
  memcpy(dq, k->dq, k->dqlen);
  dq[0] ^= 0x40;
  key.dq = dq;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_FAULT);
  key = key_from_kat(k);
  memcpy(qinv, k->qinv, k->qinvlen);
  qinv[k->qinvlen / 2] ^= 0x01;
  key.qinv = qinv;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_FAULT);
  // Wrong public exponent: verification fails.
  key = key_from_kat(k);
  key.e = 3;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_FAULT);
  // Zero blinding factor is not invertible: fail closed.
  key = key_from_kat(k);
  {
    uint8_t zero[FRSA_MAX_MODULUS_BYTES];
    memset(zero, 0, sizeof zero);
    expect_fail(&key, m->m, m->mlen, zero, k->nlen, FRSA_ERR_FAULT);
    // blind == n is 0 mod n as well
    expect_fail(&key, m->m, m->mlen, k->n, k->nlen, FRSA_ERR_FAULT);
  }
  // n inconsistent with p*q.
  key = key_from_kat(k);
  memcpy(n, k->n, k->nlen);
  n[k->nlen / 2] ^= 0x10;
  key.n = n;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_KEY);
  key = key_from_kat(k);
  memcpy(p, k->p, k->plen);
  p[k->plen - 1] ^= 0x02;  // still odd
  key.p = p;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_KEY);
  // Parameter errors.
  key = key_from_kat(k);
  p[k->plen - 1] = (uint8_t)(k->p[k->plen - 1] ^ 0x01);  // even p
  memcpy(p, k->p, k->plen - 1);
  key.p = p;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_PARAM);
  key = key_from_kat(k);
  expect_fail(&key, k->n, k->nlen, NULL, 0, FRSA_ERR_PARAM);  // in == n
  memcpy(in, k->n, k->nlen);
  in[k->nlen - 1] = (uint8_t)(in[k->nlen - 1] + 1);  // n + 1 (n odd)
  expect_fail(&key, in, k->nlen, NULL, 0, FRSA_ERR_PARAM);
  memset(in, 0xFF, sizeof in);
  expect_fail(&key, in, k->nlen, NULL, 0, FRSA_ERR_PARAM);
  expect_fail(&key, m->m, m->mlen - 1, NULL, 0, FRSA_ERR_PARAM);
  expect_fail(&key, m->m, m->mlen, blind, k->nlen - 1, FRSA_ERR_PARAM);
  key.e = 65536;
  expect_fail(&key, m->m, m->mlen, NULL, 0, FRSA_ERR_PARAM);
  key = key_from_kat(k);
  n[0] = 0;
  memcpy(n + 1, k->n, k->nlen);
  key.n = n;
  key.nlen = k->nlen + 1;  // non-minimal n
  {
    uint8_t in2[FRSA_MAX_MODULUS_BYTES + 1];
    uint8_t out2[FRSA_MAX_MODULUS_BYTES + 1];
    in2[0] = 0;
    memcpy(in2 + 1, m->m, m->mlen);
    CHECK(frsa_private(&key, in2, key.nlen, NULL, 0, out2) == FRSA_ERR_PARAM);
  }
  CHECK(frsa_private(NULL, m->m, m->mlen, NULL, 0, in) == FRSA_ERR_PARAM);
  // After all this, the untouched key still works.
  key = key_from_kat(k);
  {
    uint8_t out[FRSA_MAX_MODULUS_BYTES];
    CHECK(frsa_private(&key, m->m, m->mlen, blind, k->nlen, out) == FRSA_OK);
    CHECK(memcmp(out, m->s, m->slen) == 0);
  }
}

static void test_public_errors(void) {
  const kat_key *k = big_key();
  uint8_t out[FRSA_MAX_MODULUS_BYTES], n[FRSA_MAX_MODULUS_BYTES];
  CHECK(frsa_public(k->n, k->nlen, 65537, k->n, k->nlen, out) ==
        FRSA_ERR_PARAM);
  CHECK(frsa_public(k->n, k->nlen, 65536, k->msgs[0].m, k->nlen, out) ==
        FRSA_ERR_PARAM);
  CHECK(frsa_public(k->n, k->nlen, 1, k->msgs[0].m, k->nlen, out) ==
        FRSA_ERR_PARAM);
  CHECK(frsa_public(k->n, k->nlen, 65537, k->msgs[0].m, k->nlen - 1, out) ==
        FRSA_ERR_PARAM);
  memcpy(n, k->n, k->nlen);
  n[k->nlen - 1] &= 0xFE;
  CHECK(frsa_public(n, k->nlen, 65537, k->msgs[0].m, k->nlen, out) ==
        FRSA_ERR_PARAM);
  CHECK(frsa_public(k->n, 32, 65537, k->msgs[0].m, 32, out) ==
        FRSA_ERR_PARAM);  // < 512 bits
}

static void test_modpow(void) {
  size_t i;
  uint8_t out[FRSA_MAX_MODULUS_BYTES + 8];
  uint8_t big[FRSA_MAX_MODULUS_BYTES + 1];
  uint8_t m3 = 3, m1 = 1, m4 = 4, two = 2;
  for (i = 0; i < COUNT(MP_CASES); i++) {
    const mp_case *c = &MP_CASES[i];
    memset(out, 0xAA, sizeof out);
    CHECK(frsa_modpow(c->b, c->blen, c->x, c->xlen, c->m, c->mlen, out) ==
          FRSA_OK);
    CHECK(c->rlen == c->mlen && memcmp(out, c->r, c->rlen) == 0);
    if (memcmp(out, c->r, c->rlen) != 0) {
      fprintf(stderr, "  modpow case %u\n", (unsigned)i);
    }
  }
  memset(big, 0x01, sizeof big);
  CHECK(frsa_modpow(&two, 1, &two, 1, &m1, 1, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(&two, 1, &two, 1, &m4, 1, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(&two, 1, &two, 1, &m3, 0, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(&two, 1, &two, 1, big, sizeof big, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(big, sizeof big, &two, 1, &m3, 1, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(&two, 1, big, sizeof big, &m3, 1, out) == FRSA_ERR_PARAM);
  CHECK(frsa_modpow(NULL, 0, NULL, 0, &m3, 1, out) == FRSA_OK);
  CHECK(out[0] == 1);  // 0^0 mod 3 == 1 (empty exponent)
  memset(big, 0, sizeof big);
  CHECK(frsa_modpow(&two, 1, &two, 1, big, 8, out) == FRSA_ERR_PARAM);
}

static void test_sieve(void) {
  size_t i;
  uint8_t big[FRSA_MAX_MODULUS_BYTES + 1];
  for (i = 0; i < COUNT(SV_CASES); i++) {
    const sv_case *c = &SV_CASES[i];
    int r = frsa_sieve(c->c, c->clen);
    CHECK(r == c->expected);
    if (r != c->expected) {
      fprintf(stderr, "  sieve case %u: got %d\n", (unsigned)i, r);
    }
  }
  memset(big, 0x01, sizeof big);
  CHECK(frsa_sieve(big, sizeof big) == FRSA_ERR_PARAM);
  CHECK(frsa_sieve(big, 0) == FRSA_ERR_PARAM);
  CHECK(frsa_sieve(NULL, 1) == FRSA_ERR_PARAM);
}

static void test_mr(void) {
  size_t i;
  int composite_hits = 0;
  uint8_t w[2] = {0x02, 0x33};  // 563, prime
  uint8_t b[2];
  for (i = 0; i < COUNT(MR_CASES); i++) {
    const mr_case *c = &MR_CASES[i];
    int r = frsa_mr_round(c->w, c->wlen, c->b, c->blen);
    CHECK(r == c->expected);
    if (r != c->expected) {
      fprintf(stderr, "  mr case %u: got %d\n", (unsigned)i, r);
    }
    composite_hits += (r == 0);
  }
  CHECK(composite_hits > 0);
  b[0] = 0;
  b[1] = 1;  // b = 1
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  b[1] = 0;  // b = 0
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  b[0] = 0x02;
  b[1] = 0x32;  // b = w - 1
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  b[1] = 0x33;  // b = w
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  b[1] = 0x31;  // b = w - 2: valid
  CHECK(frsa_mr_round(w, 2, b, 2) == 1);
  b[0] = 0;
  b[1] = 2;
  w[1] = 0x34;  // even w
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  w[0] = 0;
  w[1] = 3;  // w = 3 too small
  CHECK(frsa_mr_round(w, 2, b, 2) == FRSA_ERR_PARAM);
  CHECK(frsa_mr_round(w, 0, b, 2) == FRSA_ERR_PARAM);
}

static void test_complete_errors(void) {
  size_t i;
  for (i = 0; i < COUNT(CE_CASES); i++) {
    const ce_case *c = &CE_CASES[i];
    derived d;
    int r;
    memset(&d, 0xAA, sizeof d);
    r = frsa_complete(c->p, c->plen, c->q, c->qlen, c->e, d.n, &d.nlen, d.dp,
                      d.dq, d.qinv, &d.clen);
    CHECK(r == c->expected);
    if (r != c->expected) {
      fprintf(stderr, "  complete case %u: got %d\n", (unsigned)i, r);
    }
    if (r != FRSA_OK) {
      CHECK(all_zero(d.n, sizeof d.n) && all_zero(d.dp, sizeof d.dp));
      CHECK(all_zero(d.dq, sizeof d.dq) && all_zero(d.qinv, sizeof d.qinv));
      CHECK(d.nlen == 0 && d.clen == 0);
    }
  }
  {
    derived d;
    CHECK(frsa_complete(NULL, 0, NULL, 0, 3, d.n, &d.nlen, d.dp, d.dq,
                        d.qinv, &d.clen) == FRSA_ERR_PARAM);
  }
}

int main(void) {
  test_kat_complete();
  test_kat_private_public();
  test_crt_consistency();
  test_wycheproof_decrypt();
  test_wycheproof_sign();
  test_fault_countermeasure();
  test_public_errors();
  test_modpow();
  test_sieve();
  test_mr();
  test_complete_errors();
  printf("frsa: %d checks, %d failures\n", g_checks, g_failures);
  return g_failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}
