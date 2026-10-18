<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# RSA-2048 in feuristic

RSA-2048 is **mandatory for PIV** (spec F04, §6.2: RSA-2048 in the usual PIV
signature/authentication slots) and an **optional compatibility profile for
OpenPGP** (§6.1). trezor-crypto has no RSA, so feuristic vendors a small,
audited big-integer core (BearSSL "i31") and wraps it.

```
 apps/card/piv, apps/card/openpgp
          │  generate(), pkcs1v15_*(), digest_info()
          ▼
 src/feuristic/core/rsa.py            key generation (FIPS 186-5 A.1.3), PKCS#1 v1.5
          │  rsa_complete / rsa_private / rsa_public / rsa_modpow / rsa_sieve / rsa_mr_round
          ▼
 src/feuristic/platform/crypto.py     facade (host: CPython ints + `cryptography`)
          │  firmware only
          ▼
 firmware/upymod/modfeuristic_native  MicroPython C module `feuristic_native`
          ▼
 lib/frsa (GPL-3.0-only)              CRT completion, fault check, blinding, sieve, MR
          ▼
 lib/third_party/bearssl (MIT)        i31 arithmetic, br_rsa_i31_private/public, modpow, moddiv
```

## 1. Vendored code (provenance)

BearSSL 0.6 (latest release, 2018-08-14), archive SHA-256
`6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14`, verified
against FreeBSD ports and nixpkgs. 22 source files + headers, **unmodified**;
the list and the update procedure are in
`lib/third_party/bearssl/README.feuristic.md`. Why BearSSL: constant-time by
design (documented per function), no allocation, small (≈ 6 KB of code for
the subset), MIT licence, generic C (no assembly to audit), and RSA CRT code
that tolerates `p < q` and non-reduced `qinv`.

## 2. `lib/frsa` API

Header: `lib/frsa/frsa.h`. Big-endian byte strings, caller-provided buffers,
no allocation, every temporary wiped (volatile writes) on every path.

| function | purpose | buffers |
|---|---|---|
| `frsa_complete(p, q, e → n, dp, dq, qinv)` | derive CRT components | `n`: 256 B, others 128 B; outputs `nlen`, `clen = (nlen+1)/2` |
| `frsa_private(key, in, blind, out)` | CRT private op + checks | `in`/`out`: `nlen` B; `blind`: ≥ `nlen` random bytes or NULL |
| `frsa_public(n, e, in, out)` | `in^e mod n` | `nlen` B |
| `frsa_modpow(base, exp, mod, out)` | `base^exp mod mod`, odd mod | `out`: `len(mod)` B |
| `frsa_sieve(cand)` | trial division by 2048 odd primes | — |
| `frsa_mr_round(w, b)` | one Miller–Rabin round | — |

Limits: modulus 512…2048 bits, primes ≤ 1024 bits (balanced: each factor
fits in `(nlen+1)/2` bytes), `e` odd with `3 ≤ e < 2^32` (≥ 2^16 + 1 for key
generation), `modpow`/`sieve`/`mr_round` operands ≤ 256 bytes. Return codes:
`FRSA_OK`, `FRSA_ERR_PARAM`, `FRSA_ERR_KEY`, `FRSA_ERR_FAULT` (predicates
return 1/0 or an error).

**CRT completion** (`frsa_complete`): `n = p·q` (`br_i31_mulacc`),
`qinv = q⁻¹ mod p` (`br_i31_moddiv`, also rejects `p = q`), and
`dp = e⁻¹ mod (p−1)` without ever dividing by `p−1` (even modulus):
`r = (p−1) mod e`, `f = r⁻¹ mod e` (moddiv modulo the odd `e`),
`dp = ((p−1)(e−f) + 1) / e` (exact division by a word). All divisions use
BearSSL's constant-time `br_divrem`; nothing uses the variable-time hardware
divider or `__aeabi_uldivmod`.

## 3. Side channels

* **Timing.** All private-key arithmetic is BearSSL i31 code, whose loop
  counts depend only on *announced bit lengths*. Leaked: byte/bit lengths of
  `p`, `q`, `dp`, `dq`, `n`, `e` (public in practice). Window lookups in
  `br_i31_modpow_opt` scan all table entries with masks; conditional copies
  use `CCOPY`. frsa adds only constant-time code (mask comparisons, masked
  output copy).
* **Multiplier.** `MUL31` compiles to `UMULL`/`UMLAL`, which have a fixed
  latency on Cortex-M4 (BearSSL "Constant-Time Mul" table: M4 = constant
  time) and on the Cortex-M33 with the DSP extension (STM32U585), per the ARM
  TRMs. `BR_CT_MUL31` (needed on Cortex-M3) is therefore left off.
  *To be confirmed on hardware* with a DWT cycle-counter test (see §8).
* **Power / EM (DPA).** `rsa_private` from the firmware always uses
  multiplicative **blinding**: `r` = fresh random (`rng_fill_buffer`),
  computes `((in · r^e)^d) / r mod n`, so the exponentiation input is
  uniformly random and unknown to an attacker who chooses `in` (defeats
  chosen-input correlation on `x mod p`, e.g. on the PIV/OpenPGP decipher
  path). There is no exponent blinding (would need `φ(n)` multiples and a
  longer exponent, +6 % time); the threat model accepts that a lab attacker
  with physical access and many traces is out of scope for the MCU (as for
  every trezor-crypto key on this device).
* **Key generation.** Candidates rejected by the sieve or by Miller–Rabin
  are discarded and never reused, so timing on them is harmless. For the
  accepted prime: the sieve is a single constant-time gcd; the MR round is a
  constant-time modpow; the only data-dependent loop in `frsa_mr_round` is
  the `s−1` squarings where `s = v2(w−1)`, and the generator forces
  `w ≡ 3 (mod 4)` (`s = 1`, no loop). Python-level big-int operations on the
  final primes (`gcd(e, p−1)`, `|p−q|`, the `d > 2^(nlen/2)` check) run on
  MicroPython's mpz code, whose timing depends on operand *lengths* rather
  than values; this is a one-off local operation with no attacker-chosen
  input.
* **PKCS#1 v1.5 decryption.** `pkcs1v15_decrypt_unpad` examines every byte
  with mask arithmetic and takes a single valid/invalid decision; callers
  must map failure to one status word (Bleichenbacher). It is Python code, so
  "constant time" means "no secret-dependent branches", not cycle-exact.

## 4. Fault attacks

A single fault in one CRT half yields `s` with `s ≡ m^d (mod p)` but not
`(mod q)`, and `gcd(s^e − m, n)` reveals `q` (Boneh–DeMillo–Lipton /
Bellcore). `frsa_private`:

1. checks `n == p·q` (stored key consistency) before using the key;
2. computes the CRT result (BearSSL, which also checks `in < p·q` and odd
   primes), unblinds it (`br_i31_moddiv`, which fails on non-invertible `r`);
3. **verifies `s^e mod n == in`** (constant-time compare) before releasing
   anything;
4. evaluates the comparison twice, independently, combines both with the
   status of every previous step into a mask, copies `out = buf & mask`, and
   then re-tests both flags with separate branches — a single skipped
   instruction cannot release an unverified result;
5. on any failure wipes `out` and returns `FRSA_ERR_FAULT` (`None` at the
   Python level → `CryptoError`).

Tests corrupt `dp`, `dq`, `qinv`, `e`, `n`, `p` and the blinding factor and
require fail-closed behaviour; the fuzz target checks the contract "`FRSA_OK`
⇒ `out^e == in`" for arbitrarily corrupted key material. The verification
costs one public operation (≈ 5 % of a private op with `e = 65537`).

BearSSL's own stack frame (CRT intermediates) is not wiped by BearSSL;
`frsa_private` scrubs that stack area after the call
(`frsa_scrub_stack`).

## 5. Key generation (FIPS 186-5)

`feuristic.core.rsa.generate(bits=2048, e=65537, progress, yield_fn)`
implements **FIPS 186-5 Appendix A.1.3** (random probable primes):

| step | implementation |
|---|---|
| 1–2 | `nlen ∈ {2048}` (1024 for host tests only); `2^16 < e < 2^32`, odd |
| 4.2 / 5.2 | `random_bytes(nlen/16, strong=True)` (TRNG ⊕ Optiga on device) |
| 4.3 / 5.3 | candidate forced odd — and `≡ 3 (mod 4)` (see deviations) |
| 4.4 / 5.4 | `p ≥ √2·2^(nlen/2−1)` by setting the two top bits |
| 5.4 | `|p − q| > 2^(nlen/2 − 100)`, otherwise a new `q` is drawn |
| 4.5 / 5.5 | `gcd(p−1, e) = 1` |
| 4.6 / 5.6 | Miller–Rabin (B.3.1) with random bases `1 < b < w−1` drawn by rejection from `nlen/2`-bit strings; **5 rounds** for 1024-bit primes (Table B.1, probable primes without Lucas test); 7 rounds for the 512-bit primes of test keys (FIPS 186-4 Table C.3 row) |
| A.1.1 | `d > 2^(nlen/2)` checked without computing `d` (if `d ≤ 2^(nlen/2) < 2(p−1)` then `d ∈ {dp, dp+p−1}`; the candidate also congruent to `dq` mod `q−1` would be `d`) |
| — | trial division by the first 2048 odd primes before MR (performance only) |
| — | pairwise consistency test (sign/verify a random block) before returning |

Deviations, deliberate and documented:

* Top two bits **forced** instead of rejection sampling (step 4.4). Common
  practice (OpenSSL, BearSSL); it also guarantees `nlen`-bit moduli.
* Candidates forced `≡ 3 (mod 4)`: removes one bit of choice per prime
  (≈1021 random bits remain) so that the MR round runs in time independent of
  the candidate. The output is uniform over primes `≡ 3 (mod 4)` in range.
* Returned keys have `p > q` (PIV/OpenPGP importers are happier).

**Before a FIPS claim**, re-check the MR round count against the
published Table B.1 of FIPS 186-5 for the targeted error probability (the
constant is `_MR_ROUNDS` in `core/rsa.py`).

Each native call is bounded; `await yield_fn()` runs after **every** native
call, and `progress(f)` reports a monotonic fraction (`p` search 0→0.45, `q`
search 0.45→0.9, completion and PCT → 1.0; inside a search the fraction is
`t/(t+E)` with `t` candidates tried and `E` the expected count).

## 6. Timing estimates

### Method

1. **Operation counts are measured**, not guessed: a scratch build of the
   unmodified BearSSL files with counters in `br_i31_montymul`,
   `br_i31_muladd_small` and `br_i31_moddiv` runs each frsa entry point on
   the KAT keys (host).
2. **Cycles per operation**: the Montgomery inner loop (4× unrolled in
   BearSSL 0.6) compiled by `arm-none-eabi-gcc -O2 -mcpu=cortex-m4` is
   analysed with `llvm-mca -mcpu=cortex-m4`: 63 cycles per 4 limbs ⇒
   **≈ 16 cycles per limb-step** (3 LDR, 1 STR, UMULL, UMLAL, 4 ADD/ADC,
   masks). A montymul on `L` limbs costs ≈ `16 L² + 45 L` cycles
   (L = 34 for 1024-bit, 67 for 2048-bit moduli): ≈ 20 k cycles (1024-bit),
   ≈ 75 k cycles (2048-bit). `br_i31_muladd_small` ≈ 12 L + 250 cycles
   (constant-time `br_divrem`), `br_i31_moddiv` (1024-bit) ≈ 0.3 M cycles.
   Window lookups, `CCOPY` and copies are added per window (≈ 2.6 k cycles).
3. Flash wait states are hidden by the F4 ART accelerator / U5 ICACHE for
   these small loops; data are in SRAM. The Cortex-M33 is assumed to run the
   same cycle count (same 3-stage pipeline class, 1-cycle `UMLAL` with DSP);
   its clock is 160 MHz instead of 168 MHz.
4. Cross-check: BearSSL's published i31 figure on i386 (86 RSA-2048
   private ops/s at 3.1 GHz ≈ 36 M cycles) is consistent with the
   ≈ 57 M cycles predicted here for a CPU with fewer registers and `-O2`
   code on a 3-stage pipeline.

Expected accuracy: ±25 %. To be replaced by DWT measurements on hardware.

### Results

| operation | montymuls (measured) | ≈ cycles | T2B1 M4 @168 MHz | T3B1 M33 @160 MHz |
|---|---|---|---|---|
| `modpow` 1024-bit mod, 1024-bit exp (4-bit window) | 1 294 | 27.2 M | **≈ 162 ms** | ≈ 170 ms |
| `rsa_mr_round` 1024-bit, `w ≡ 3 mod 4` | 1 294 | 27.2 M | ≈ 162 ms | ≈ 170 ms |
| CRT private 2048, no blinding (+ verify) | 2 783 | 59 M | ≈ 351 ms | ≈ 369 ms |
| CRT private 2048, blinded (+ verify) — **firmware path** | 2 822 + 1 moddiv | 62.6 M | **≈ 373 ms** | ≈ 391 ms |
| public 2048, e = 65537 | 38 | 3.0 M | ≈ 18 ms | ≈ 19 ms |
| `rsa_sieve` 1024-bit | 792 muladd + 1 moddiv | 0.85 M | ≈ 5 ms | ≈ 5.3 ms |
| `rsa_complete` 2048 | 3 moddiv | 0.4 M | ≈ 2.4 ms | ≈ 2.5 ms |

(Host reference, Apple Silicon: modpow 1.6 ms, private 4.0 ms.)

**Expected key generation time (RSA-2048).** Per 1024-bit prime: the prime
density among odd candidates gives `E = ln(2^1024)/2 ≈ 355` candidates;
trial division by the odd primes up to 17 881 lets a fraction
`∏(1 − 1/p) ≈ 2e^−γ / ln 17881 ≈ 0.115` through (Mertens), i.e. ≈ 40.7
candidates reach Miller–Rabin; composites fail the first round (≈ 39.7
rounds) and the prime takes 5 rounds ⇒ ≈ 44.7 MR rounds ≈ 7.2 s, plus 355 ×
(5 ms sieve + ≈ 3 ms Python/RNG overhead) ≈ 2.8 s. Two primes + completion +
pairwise test (one private op): **≈ 20 s on the M4, ≈ 21 s on the M33**
(expected value). The number of candidates is geometric, so the total
follows ≈ Gamma(2): P90 ≈ 39 s, P99 ≈ 66 s on the M4. The strong-RNG cost
(Optiga round-trip) is the main uncertainty in the overhead term.

### The ~150 ms budget per native call

The firmware keeps USB alive by running native code in short slices and
yielding to the scheduler between them (`yield_fn`). Budget rationale:
CTAPHID keep-alives are expected every ≤ 100 ms by some hosts during long
operations, and button/UI polling should not stall visibly; ~150 ms is the
longest slice that keeps both acceptable.

* sieve, complete, public: far below the budget.
* `modpow` / `rsa_mr_round` (1024-bit): **≈ 160 ms — at the limit** of the
  budget (within the estimate's uncertainty). If hardware measurements show
  more than ~170 ms, options in order of preference: compile
  `i31_montmul.c` with `-O3 -funroll-loops`/place it in RAM (CCM on F4), use a
  5-bit window (needs 2.3 KB more stack), or split one MR round over two
  native calls (requires exposing an intermediate state).
* **CRT private op: ≈ 375 ms on the M4 (≈ 390 ms on the M33) — exceeds the
  budget.** It is a single operation that cannot be split without exposing
  CRT intermediates; callers (PIV GENERAL AUTHENTICATE, OpenPGP PSO) must send
  a CCID time extension (`RDR_to_PC_DataBlock` with `bStatus` time-extension)
  *before* calling `crypto.rsa_private`, and no CTAPHID transaction is active
  in that context. The HID FIFO simply NAKs during the call.

## 7. Memory

| | value |
|---|---|
| code (Cortex-M4, gcc -O2) | BearSSL subset ≈ 6.0 KB + frsa ≈ 7.4 KB (incl. 3.2 KB sieve table) |
| peak stack `rsa_private` | ≈ 5.5 KB (frsa 2.9 KB + BearSSL 2.3 KB + callees) |
| peak stack `modpow`/`mr_round` | ≈ 3.2 / 4.4 KB |
| heap | outputs only (`bytes` objects); no allocation in C |

The coreapp stack is 16 KiB; the module never nests these calls.

## 8. Tests and verification

* `tests/c/frsa` (CTest, ASan/UBSan): 13 generated KAT keys (512…2048 bits,
  `e` ∈ {3, 17, 65537, 2^31−1, 2^31+1, 2^32−1}, `p < q`, 1023/2047-bit
  moduli), Wycheproof RSAES-PKCS1 2048 keys incl. the 32 Montgomery
  edge-case keys, Wycheproof RSASSA-PKCS1 signature generation (1024/2048),
  CRT consistency (blinded vs unblinded vs public), fault countermeasure,
  modpow vectors (moduli 3 … 2^2048), sieve and Miller–Rabin vectors
  (Carmichael numbers incl. a ~900-bit Chernick number, strong pseudoprimes
  to base 2, Jaeschke's ψ numbers, Mersenne primes, primes with large
  `v2(p−1)`), `frsa_complete` error cases. 1 785 checks.
  Vectors: `tests/c/frsa/gen_vectors.py` (seeded, reproducible) →
  `frsa_vectors.h`; Wycheproof subset: `tests/vectors/rsa/wycheproof_rsa.json`
  (C2SP/wycheproof @ `7a325932231bd7a724c791c8b0d65ea4d6d2f435`, extracted by
  `tests/vectors/rsa/extract_wycheproof.py`; SHA-256 of the source files
  recorded inside).
* `tests/fuzz/frsa_fuzz.c` (libFuzzer + ASan/UBSan, see
  `tests/fuzz/README-frsa.md`).
* `tests/host/rsa` (pytest): key generation with deterministic RNG,
  validation by `cryptography`, FIPS checks, callbacks, padding round trips
  and malformed inputs, Wycheproof decryption/signature, firmware dispatch
  contract (`feuristic_native.rsa_private` receives `e` and `n`).
* **Still to do on hardware:** DWT cycle counts for the table above;
  constant-time check of `frsa_private`/`frsa_modpow` with fixed-vs-random
  inputs (dudect-style) on both MCUs; a firmware build of
  `feuristic_native`.

## 9. References

* FIPS 186-5, *Digital Signature Standard*, App. A.1.1, A.1.3, B.3.1, Table B.1.
* NIST SP 800-56B Rev. 2, §6.4.1.1 (pairwise consistency).
* RFC 8017 (PKCS #1 v2.2), §7.2, §8.2, §9.2.
* D. Boneh, R. DeMillo, R. Lipton, *On the Importance of Checking
  Cryptographic Computations for Faults*, EUROCRYPT 1997.
* T. Pornin, BearSSL documentation: "Constant-Time Crypto", "Constant-Time
  Mul", "Big Integer Design", "Speed Benchmarks" (bearssl.org).
* G. Jaeschke, *On strong pseudoprimes to several bases*, Math. Comp. 1993.
