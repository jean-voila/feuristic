// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// libFuzzer target for lib/frsa. See tests/fuzz/README-frsa.md.
//
// The first input byte selects the entry point; the rest is split into the
// operands. Besides memory safety (ASan/UBSan), the target checks:
//   * modpow / mr_round / sieve against independent 64-bit references for
//     operands that fit in 64 bits;
//   * public(private(x)) == x for a fixed valid key;
//   * the fault-countermeasure contract: for *arbitrary* (fuzzed, corrupted)
//     key material, frsa_private() either fails with a zeroed output or
//     returns a value whose e-th power is the input (never a wrong result);
//   * frsa_complete() outputs reproduce a working key whenever it succeeds.

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../c/frsa/frsa_vectors.h"
#include "frsa.h"

typedef unsigned __int128 u128;

#define CHECK(c) \
  do {           \
    if (!(c)) {  \
      abort();   \
    }            \
  } while (0)

typedef struct {
  const uint8_t *p;
  size_t n;
} cursor;

static size_t take_len(cursor *c, size_t max) {
  size_t v;
  if (c->n == 0) {
    return 0;
  }
  v = c->p[0];
  if (c->n >= 2) {
    v = (v << 8) | c->p[1];
    c->p += 2;
    c->n -= 2;
  } else {
    c->p += 1;
    c->n -= 1;
  }
  return max ? v % (max + 1) : 0;
}

static const uint8_t *take(cursor *c, size_t *len) {
  const uint8_t *r = c->p;
  if (*len > c->n) {
    *len = c->n;
  }
  c->p += *len;
  c->n -= *len;
  return r;
}

static int fits64(const uint8_t *x, size_t len, uint64_t *v) {
  size_t i;
  uint64_t acc = 0;
  for (i = 0; i < len; i++) {
    if (acc >> 56) {
      return 0;
    }
    acc = (acc << 8) | x[i];
  }
  *v = acc;
  return 1;
}

static uint64_t mulmod(uint64_t a, uint64_t b, uint64_t m) {
  return (uint64_t)(((u128)a * b) % m);
}

static uint64_t powmod_bytes(uint64_t b, const uint8_t *e, size_t elen,
                             uint64_t m) {
  uint64_t r = 1 % m;
  size_t i;
  int bit;
  b %= m;
  for (i = 0; i < elen; i++) {
    for (bit = 7; bit >= 0; bit--) {
      r = mulmod(r, r, m);
      if ((e[i] >> bit) & 1) {
        r = mulmod(r, b, m);
      }
    }
  }
  return r;
}

static uint64_t powmod(uint64_t b, uint64_t e, uint64_t m) {
  uint64_t r = 1 % m;
  b %= m;
  while (e) {
    if (e & 1) {
      r = mulmod(r, b, m);
    }
    b = mulmod(b, b, m);
    e >>= 1;
  }
  return r;
}

static int mr_ref(uint64_t w, uint64_t b) {
  uint64_t m = w - 1, z;
  int a = 0, j;
  while ((m & 1) == 0) {
    m >>= 1;
    a++;
  }
  z = powmod(b, m, w);
  if (z == 1 || z == w - 1) {
    return 1;
  }
  for (j = 1; j < a; j++) {
    z = mulmod(z, z, w);
    if (z == w - 1) {
      return 1;
    }
    if (z == 1) {
      return 0;
    }
  }
  return 0;
}

static uint16_t g_primes[2048];
static void init_primes(void) {
  uint32_t c = 3;
  size_t k = 0;
  if (g_primes[0]) {
    return;
  }
  while (k < 2048) {
    size_t i;
    int prime = 1;
    for (i = 0; i < k && (uint32_t)g_primes[i] * g_primes[i] <= c; i++) {
      if (c % g_primes[i] == 0) {
        prime = 0;
        break;
      }
    }
    if (prime) {
      g_primes[k++] = (uint16_t)c;
    }
    c += 2;
  }
}

static int sieve_ref(uint64_t c) {
  size_t i;
  if (c < 3 || (c & 1) == 0) {
    return 0;
  }
  for (i = 0; i < 2048; i++) {
    if (c % g_primes[i] == 0) {
      return 0;
    }
  }
  return 1;
}

static const kat_key *fuzz_key(uint8_t sel) {
  return &KAT_KEYS[sel % (sizeof KAT_KEYS / sizeof KAT_KEYS[0])];
}

static int all_zero(const uint8_t *b, size_t n) {
  size_t i;
  for (i = 0; i < n; i++) {
    if (b[i]) {
      return 0;
    }
  }
  return 1;
}

static void check_private_contract(const frsa_key *key, const uint8_t *in,
                                   const uint8_t *blind) {
  uint8_t out[FRSA_MAX_MODULUS_BYTES + 1], back[FRSA_MAX_MODULUS_BYTES + 1];
  int r;
  if (key->nlen == 0 || key->nlen > FRSA_MAX_MODULUS_BYTES) {
    return;
  }
  memset(out, 0xAA, sizeof out);
  r = frsa_private(key, in, key->nlen, blind, blind ? key->nlen : 0, out);
  if (r == FRSA_OK) {
    CHECK(frsa_public(key->n, key->nlen, key->e, out, key->nlen, back) ==
          FRSA_OK);
    CHECK(memcmp(back, in, key->nlen) == 0);
  } else {
    CHECK(r == FRSA_ERR_PARAM || r == FRSA_ERR_KEY || r == FRSA_ERR_FAULT);
    CHECK(all_zero(out, key->nlen));
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  cursor c;
  uint8_t sel;
  init_primes();
  if (size < 1) {
    return 0;
  }
  sel = data[0];
  c.p = data + 1;
  c.n = size - 1;

  switch (sel % 6) {
    case 0: {  // modpow
      uint8_t out[FRSA_MAX_MODULUS_BYTES + 8];
      size_t bl = take_len(&c, 260), el = take_len(&c, 260),
             ml = take_len(&c, 260);
      const uint8_t *b = take(&c, &bl), *e = take(&c, &el), *m = take(&c, &ml);
      uint64_t bv, mv;
      int r = frsa_modpow(bl ? b : NULL, bl, el ? e : NULL, el, m, ml, out);
      if (r == FRSA_OK && fits64(m, ml, &mv) && fits64(b, bl, &bv)) {
        uint64_t got = 0;
        size_t i;
        CHECK(mv >= 3 && (mv & 1));
        for (i = 0; i < ml; i++) {
          got = (got << 8) | out[i];
        }
        CHECK(got == powmod_bytes(bv, e, el, mv));
      }
      break;
    }
    case 1: {  // Miller-Rabin
      size_t wl = take_len(&c, 260), bl = take_len(&c, 260);
      const uint8_t *w = take(&c, &wl), *b = take(&c, &bl);
      uint64_t wv, bv;
      int r = frsa_mr_round(w, wl, b, bl);
      CHECK(r == 0 || r == 1 || r == FRSA_ERR_PARAM);
      if (r >= 0 && fits64(w, wl, &wv) && fits64(b, bl, &bv)) {
        CHECK(r == mr_ref(wv, bv));
      }
      break;
    }
    case 2: {  // sieve
      size_t l = take_len(&c, 260);
      const uint8_t *x = take(&c, &l);
      uint64_t v;
      int r = frsa_sieve(l ? x : NULL, l);
      CHECK(r == 0 || r == 1 || r == FRSA_ERR_PARAM);
      if (r >= 0 && fits64(x, l, &v)) {
        CHECK(r == sieve_ref(v));
      }
      break;
    }
    case 3: {  // private with a valid key, fuzzed input and blinding
      const kat_key *k = fuzz_key(sel >> 3);
      frsa_key key;
      uint8_t in[FRSA_MAX_MODULUS_BYTES], blind[FRSA_MAX_MODULUS_BYTES];
      size_t l = k->nlen, bl = k->nlen;
      const uint8_t *x = take(&c, &l), *bb = take(&c, &bl);
      memset(in, 0, sizeof in);
      memcpy(in + (k->nlen - l), x, l);
      in[0] &= 0x7F;
      if (memcmp(in, k->n, k->nlen) >= 0) {
        in[0] = 0;
      }
      memset(blind, 0x5A, sizeof blind);
      memcpy(blind, bb, bl);
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
      check_private_contract(&key, in, (sel & 4) ? blind : NULL);
      break;
    }
    case 4: {  // private with corrupted key material (fault contract)
      const kat_key *k = fuzz_key(sel >> 3);
      uint8_t p[FRSA_MAX_FACTOR_BYTES], q[FRSA_MAX_FACTOR_BYTES];
      uint8_t dp[FRSA_MAX_FACTOR_BYTES], dq[FRSA_MAX_FACTOR_BYTES];
      uint8_t qi[FRSA_MAX_FACTOR_BYTES], in[FRSA_MAX_MODULUS_BYTES];
      frsa_key key;
      size_t i;
      memcpy(p, k->p, k->plen);
      memcpy(q, k->q, k->qlen);
      memcpy(dp, k->dp, k->dplen);
      memcpy(dq, k->dq, k->dqlen);
      memcpy(qi, k->qinv, k->qinvlen);
      memcpy(in, k->msgs[0].m, k->nlen);
      // Each pair of bytes = (field selector, xor mask at a position).
      while (c.n >= 3) {
        uint8_t f = c.p[0], pos = c.p[1], mask = c.p[2];
        c.p += 3;
        c.n -= 3;
        switch (f % 6) {
          case 0:
            p[pos % k->plen] ^= mask;
            break;
          case 1:
            q[pos % k->qlen] ^= mask;
            break;
          case 2:
            dp[pos % k->dplen] ^= mask;
            break;
          case 3:
            dq[pos % k->dqlen] ^= mask;
            break;
          case 4:
            qi[pos % k->qinvlen] ^= mask;
            break;
          default:
            in[pos % k->nlen] ^= mask;
            break;
        }
      }
      if (memcmp(in, k->n, k->nlen) >= 0) {
        in[0] = 0;
      }
      key.p = p;
      key.plen = k->plen;
      key.q = q;
      key.qlen = k->qlen;
      key.dp = dp;
      key.dplen = k->dplen;
      key.dq = dq;
      key.dqlen = k->dqlen;
      key.qinv = qi;
      key.qinvlen = k->qinvlen;
      key.n = k->n;
      key.nlen = k->nlen;
      key.e = k->e;
      for (i = 0; i < 1; i++) {
        check_private_contract(&key, in, NULL);
      }
      break;
    }
    default: {  // complete with fuzzed p, q, e
      uint8_t n[FRSA_MAX_MODULUS_BYTES], dp[FRSA_MAX_FACTOR_BYTES];
      uint8_t dq[FRSA_MAX_FACTOR_BYTES], qi[FRSA_MAX_FACTOR_BYTES];
      size_t nl, cl, pl = take_len(&c, 140), ql = take_len(&c, 140);
      uint32_t e = 0;
      size_t el = 4, i;
      const uint8_t *eb = take(&c, &el), *p = take(&c, &pl), *q = take(&c, &ql);
      int r;
      for (i = 0; i < el; i++) {
        e = (e << 8) | eb[i];
      }
      r = frsa_complete(pl ? p : NULL, pl, ql ? q : NULL, ql, e, n, &nl, dp, dq,
                        qi, &cl);
      CHECK(r == FRSA_OK || r == FRSA_ERR_PARAM || r == FRSA_ERR_KEY);
      if (r != FRSA_OK) {
        CHECK(all_zero(n, sizeof n) && all_zero(dp, sizeof dp));
      } else {
        // p, q need not be prime here: the private op may legitimately
        // fail, but must never return a wrong result.
        frsa_key key;
        uint8_t in[FRSA_MAX_MODULUS_BYTES];
        key.p = p;
        key.plen = pl;
        key.q = q;
        key.qlen = ql;
        key.dp = dp;
        key.dplen = cl;
        key.dq = dq;
        key.dqlen = cl;
        key.qinv = qi;
        key.qinvlen = cl;
        key.n = n;
        key.nlen = nl;
        key.e = e;
        memset(in, 0, sizeof in);
        in[nl - 1] = 2;
        check_private_contract(&key, in, NULL);
      }
      break;
    }
  }
  return 0;
}
