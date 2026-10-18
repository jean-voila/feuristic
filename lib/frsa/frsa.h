// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// frsa -- RSA (up to 2048-bit moduli) for feuristic, built on the vendored
// BearSSL "i31" big-integer code (lib/third_party/bearssl, MIT licence).
//
// Conventions
// -----------
// * Every integer is an unsigned big-endian byte string (pointer + length).
// * All buffers are provided by the caller; nothing is allocated. Output
//   buffer sizes are documented per function (use the FRSA_MAX_* macros).
// * Secret-dependent work (private operation, CRT completion, prime tests on
//   candidates) is constant-time with respect to the *values* involved; only
//   lengths (byte/bit sizes of moduli and exponents) may leak. The one
//   documented exception is frsa_mr_round(), whose run time also depends on
//   v2(w-1), the number of trailing zero bits of candidate-1 (the feuristic
//   key generator only tests candidates w = 3 mod 4, where v2(w-1) = 1).
// * Temporaries are wiped before returning, on success and on failure.
// * Thread-safety: functions are reentrant (state lives on the stack).
//   Peak stack usage is below 6 KiB on Cortex-M (see docs/developer/rsa.md).
//
// Return values: FRSA_OK (0) or a negative FRSA_ERR_* code. Predicates
// (frsa_sieve, frsa_mr_round) return 1 (true), 0 (false) or FRSA_ERR_*.

#ifndef FRSA_H
#define FRSA_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Largest supported modulus. Primes are at most half of it.
#define FRSA_MAX_MODULUS_BITS 2048
#define FRSA_MAX_MODULUS_BYTES (FRSA_MAX_MODULUS_BITS / 8)  // 256
#define FRSA_MAX_FACTOR_BYTES (FRSA_MAX_MODULUS_BYTES / 2)  // 128
// Smallest modulus accepted by complete/private/public.
#define FRSA_MIN_MODULUS_BITS 512

#define FRSA_OK 0
#define FRSA_ERR_PARAM (-1)  // malformed / out-of-range argument
#define FRSA_ERR_KEY (-2)    // inconsistent or unusable key material
#define FRSA_ERR_FAULT (-3)  // internal consistency check failed (fault?)

// RSA private key in CRT form. All fields are big-endian; leading zero bytes
// are tolerated except in `n`, which must be minimally encoded (n[0] != 0)
// and is the length reference of the private operation.
typedef struct {
  const uint8_t *p;
  size_t plen;
  const uint8_t *q;
  size_t qlen;
  const uint8_t *dp;  // d mod (p - 1)
  size_t dplen;
  const uint8_t *dq;  // d mod (q - 1)
  size_t dqlen;
  const uint8_t *qinv;  // q^-1 mod p
  size_t qinvlen;
  const uint8_t *n;  // p * q (checked by frsa_private)
  size_t nlen;
  uint32_t e;  // public exponent (odd, >= 3)
} frsa_key;

// Compute the derived CRT components from (p, q, e).
//
//   p, q    distinct odd primes, each at most FRSA_MAX_FACTOR_BYTES bytes once
//           leading zeros are stripped; FRSA_MIN_MODULUS_BITS <= bits(p*q)
//           <= FRSA_MAX_MODULUS_BITS; each stripped factor must fit in
//           (nlen + 1) / 2 bytes (balanced keys).
//   e       odd public exponent, 3 <= e <= 2^32 - 1, gcd(e, (p-1)(q-1)) = 1.
//
// Outputs (on FRSA_OK):
//   n       FRSA_MAX_MODULUS_BYTES-byte buffer; receives *nlen_out bytes
//           (minimal encoding of p*q).
//   dp, dq, qinv  FRSA_MAX_FACTOR_BYTES-byte buffers; each receives
//           *clen_out = (*nlen_out + 1) / 2 bytes, left-padded with zeros.
//
// Errors: FRSA_ERR_PARAM (sizes, parity, e), FRSA_ERR_KEY (e not invertible
// modulo p-1 or q-1, q not invertible modulo p, e.g. p == q). On error every
// output buffer is zeroed.
//
// Constant time with respect to the values of p and q (their bit lengths
// leak). The primality of p and q is NOT checked here.
int frsa_complete(const uint8_t *p, size_t plen, const uint8_t *q, size_t qlen,
                  uint32_t e, uint8_t *n, size_t *nlen_out, uint8_t *dp,
                  uint8_t *dq, uint8_t *qinv, size_t *clen_out);

// Raw RSA private operation out = in^d mod n via CRT (BearSSL
// br_rsa_i31_private, constant time), with:
//   * a consistency check n == p * q before use;
//   * optional multiplicative blinding: when `blind` is non-NULL it must hold
//     at least key->nlen fresh random bytes; r = blind mod n is used to
//     compute ((in * r^e)^d) / r, which decorrelates the exponentiation
//     input from `in` (side-channel hardening against chosen-input power
//     analysis). Pass NULL to disable.
//   * a fault-attack countermeasure: out^e mod n is recomputed and compared
//     (constant time) with `in`; on mismatch the result is wiped and
//     FRSA_ERR_FAULT is returned (fail closed). The check is evaluated twice
//     and both results must agree before `out` is released.
//
//   in      exactly key->nlen bytes, numerically < n.
//   out     key->nlen bytes. May alias `in`. Zeroed on any error.
int frsa_private(const frsa_key *key, const uint8_t *in, size_t inlen,
                 const uint8_t *blind, size_t blindlen, uint8_t *out);

// Raw RSA public operation out = in^e mod n (BearSSL br_rsa_i31_public).
//   n       odd, minimally encoded (n[0] != 0), 512..2048 bits.
//   e       odd, >= 3.
//   in      exactly nlen bytes, numerically < n.
//   out     nlen bytes (may alias `in`).
int frsa_public(const uint8_t *n, size_t nlen, uint32_t e, const uint8_t *in,
                size_t inlen, uint8_t *out);

// out = base^exp mod mod, for an odd modulus 3 <= mod < 2^2048.
//   base    any value, 0..FRSA_MAX_MODULUS_BYTES bytes (reduced mod `mod`).
//   exp     0..FRSA_MAX_MODULUS_BYTES bytes (an empty exponent yields 1).
//   mod     1..FRSA_MAX_MODULUS_BYTES bytes (leading zeros allowed).
//   out     modlen bytes, left-padded with zeros. Must not alias inputs.
// Constant time with respect to the values of base, exp and mod (only
// modlen, the bit length of mod and explen leak). Sliding window of up to
// 4 bits (5 for small moduli) over BearSSL br_i31_modpow_opt.
int frsa_modpow(const uint8_t *base, size_t baselen, const uint8_t *exp,
                size_t explen, const uint8_t *mod, size_t modlen, uint8_t *out);

// Trial division of an odd prime candidate by the first 2048 odd primes
// (3 .. 17881), done in constant time as a single gcd test:
// gcd(candidate, prod(primes)) == 1 (BearSSL br_i31_moddiv).
// Returns 1 if no table prime divides the candidate, 0 otherwise (including
// even candidates, candidates < 3 and candidates that *are* table primes),
// FRSA_ERR_PARAM if candlen is 0 or > FRSA_MAX_MODULUS_BYTES.
int frsa_sieve(const uint8_t *cand, size_t candlen);

// One Miller-Rabin round (FIPS 186-5 B.3.1, steps 4.x) on the odd candidate
// w with base b, 1 < b < w - 1. Uses constant-time modular exponentiation.
// Returns 1 ("probably prime" for this base), 0 (composite) or
// FRSA_ERR_PARAM (w even or < 5, b out of range, sizes > 256 bytes).
int frsa_mr_round(const uint8_t *w, size_t wlen, const uint8_t *b, size_t blen);

#ifdef __cplusplus
}
#endif

#endif  // FRSA_H
