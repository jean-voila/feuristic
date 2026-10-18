<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->
<!-- This README is feuristic's; the vendored files keep their MIT licence (LICENSE.txt). -->

# BearSSL subset vendored for feuristic

| | |
|---|---|
| Project | BearSSL — <https://bearssl.org/> (Thomas Pornin) |
| Version | **0.6** (latest release, 2018-08-14) |
| Archive | <https://bearssl.org/bearssl-0.6.tar.gz> (765 094 bytes) |
| SHA-256 | `6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14` |
| Checksum cross-checks | FreeBSD ports `security/bearssl/distinfo` (same SHA-256 and size); nixpkgs `pkgs/by-name/be/bearssl` (nix-base32 `057zhgy9w4y8z2996r0pq5k2k39lpvmmvz4df8db8qa9f6hvn1b7` = same SHA-256). No upstream signature is published. |
| Licence | MIT, see `LICENSE.txt` (unchanged) |
| Imported | 2026-10-17 |
| Modifications | **none** — every file below is byte-identical to the archive |

## Files kept

Only the "i31" big-integer code (31-bit limbs, 32×32→64 multiplications) and
the two raw RSA primitives built on it. No TLS, X.509, hash, PRNG or padding
code is compiled.

Compiled sources (22):

* `src/codec/ccopy.c` — `br_ccopy` (constant-time conditional copy)
* `src/int/i31_add.c`, `i31_sub.c`, `i31_bitlen.c`, `i31_decode.c`,
  `i31_decmod.c`, `i31_decred.c`, `i31_encode.c`, `i31_iszero.c`,
  `i31_rshift.c`, `i31_reduce.c`, `i31_muladd.c`, `i31_mulacc.c`,
  `i31_ninv31.c`, `i31_montmul.c`, `i31_tmont.c`, `i31_fmont.c`,
  `i31_modpow2.c` (`br_i31_modpow_opt`), `i31_moddiv.c` (constant-time
  modular division / inversion)
* `src/int/i32_div32.c` — `br_divrem` (constant-time 64/32 division)
* `src/rsa/rsa_i31_priv.c` — `br_rsa_i31_private` (CRT, constant time)
* `src/rsa/rsa_i31_pub.c` — `br_rsa_i31_public`

Headers:

* `src/inner.h`, `src/config.h` — internal declarations and the build
  configuration (default: every option off; feuristic needs none);
* `inc/*.h` — all public headers. `inner.h` includes `bearssl.h`, which
  includes every public header, so they are kept verbatim; they only contain
  declarations (no code is compiled from them).

## Build notes

* `lib/frsa/CMakeLists.txt` builds these files as the `frsa_bearssl` static
  library with `-Wall -Wextra -pedantic` (no `-Werror`, third-party code);
  `frsa.c` includes the BearSSL headers as system headers so feuristic's
  stricter warning set applies to feuristic code only. The firmware build
  (upstream `build.rs`) is described in
  `firmware/upymod/modfeuristic_native/README.md`.
* Leave `BR_CT_MUL31` **off**: Cortex-M4 and Cortex-M33 `UMULL`/`UMLAL` have
  a fixed latency, so the plain `MUL31` macro is already constant time.
* The files compile cleanly with clang (host, `-std=c99 -pedantic`) and
  `arm-none-eabi-gcc` (Cortex-M4/M33, `-O2`). Code size on Cortex-M4:
  ≈ 6.0 KB for this subset + ≈ 7.4 KB for `frsa.c` (incl. the 3.2 KB sieve
  table).

## Updating

Download the new release, verify its SHA-256 against independent sources,
copy the same file list over, run the frsa C tests, fuzz target and
`tests/host/rsa`, and update this file. Prefer upstream fixes over local
patches; if a local patch ever becomes necessary, list it here.
