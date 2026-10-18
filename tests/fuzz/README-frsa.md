<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# `frsa_fuzz` — libFuzzer target for `lib/frsa`

`frsa_fuzz.c` drives every `frsa_*` entry point. The first input byte selects
the operation (`sel % 6`); the remaining bytes give operand lengths and data.

| sel % 6 | operation | oracle |
|---|---|---|
| 0 | `frsa_modpow` | 128-bit reference when base and modulus fit in 64 bits |
| 1 | `frsa_mr_round` | 64-bit reference Miller–Rabin (FIPS 186-5 B.3.1) |
| 2 | `frsa_sieve` | trial division by the same 2048 odd primes |
| 3 | `frsa_private`, valid key, fuzzed input/blinding | `public(private(x)) == x` |
| 4 | `frsa_private`, **corrupted** p/q/dp/dq/qinv/input | fault contract: `FRSA_OK` ⇒ `out^e == in`, otherwise `out` is zeroed |
| 5 | `frsa_complete`, fuzzed p/q/e | outputs zeroed on error; on success the derived key never yields a wrong result |

Keys come from `tests/c/frsa/frsa_vectors.h` (generated KAT keys).

## Build and run

```sh
LLVM=/opt/homebrew/opt/llvm/bin   # or your distribution's clang
B=lib/third_party/bearssl
$LLVM/clang -g -O1 -fsanitize=fuzzer,address,undefined \
  -fno-sanitize-recover=undefined \
  -Ilib/frsa -isystem $B/src -isystem $B/inc \
  tests/fuzz/frsa_fuzz.c lib/frsa/frsa.c \
  $B/src/int/*.c $B/src/codec/ccopy.c $B/src/rsa/*.c \
  -o build/frsa_fuzz
mkdir -p tests/fuzz/corpus-out/frsa
build/frsa_fuzz -max_len=800 -max_total_time=60 tests/fuzz/corpus-out/frsa
```

`-max_len=800` covers the largest operands (three 256-byte values plus
length prefixes). Private-key operations cost a few milliseconds each on a
desktop, so expect ~700 exec/s.

## Results

Initial campaign (2026-10-17, Apple Silicon, Homebrew clang 23.1, ASan+UBSan): 300 s,
203 684 executions, 686 corpus units, no crash, no oracle failure.
