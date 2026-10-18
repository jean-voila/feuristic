<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# `feuristic_native` — MicroPython C module (RSA)

Unprivileged coreapp module exposing the RSA primitives of `lib/frsa`
(itself built on the vendored BearSSL subset in `lib/third_party/bearssl`).
Python never imports it directly: `src/feuristic/platform/crypto.py` is the
only caller (`rsa_complete`, `rsa_private`, `rsa_public`, `rsa_modpow`,
`rsa_sieve`, `rsa_mr_round`). Design, timings and security notes:
`docs/developer/rsa.md`.

| File | Purpose |
|---|---|
| `modfeuristic_native.c` | the module (upstream `///` stub comments, `MP_REGISTER_MODULE`) |
| `mocks/feuristic_native.pyi` | type stub (same text as the `///` comments) |

## Registering the module in the upstream build (lead / patch series)

The module is compiled *inside* the upstream `upymod` crate, like
`modtrezorcrypto`. A patch in `patches/` must:

1. **Expose the sources** to the upstream tree with relative symlinks
   (same mechanism as `core/src/feuristic`), e.g.

   ```
   core/embed/upymod/modfeuristic_native -> ../../../../../firmware/upymod/modfeuristic_native
   core/embed/upymod/frsa                -> ../../../../../lib/frsa
   core/embed/upymod/bearssl             -> ../../../../../lib/third_party/bearssl
   ```

2. **Add the sources and include paths** in
   `core/embed/upymod/build.rs`, next to `modtrezorcrypto`:

   ```rust
   lib.add_sources([
       "modfeuristic_native/modfeuristic_native.c",
       "frsa/frsa.c",
   ]);
   lib.add_private_include("frsa");
   // BearSSL internal headers: frsa.c includes "inner.h"
   lib.add_private_include("bearssl/src");
   lib.add_private_include("bearssl/inc");
   ```

   and the BearSSL subset (22 files, list identical to
   `lib/frsa/CMakeLists.txt` `FRSA_BEARSSL_SOURCES`):

   ```rust
   lib.add_sources_in_dir("bearssl/src", [
       "codec/ccopy.c",
       "int/i31_add.c", "int/i31_bitlen.c", "int/i31_decmod.c",
       "int/i31_decode.c", "int/i31_decred.c", "int/i31_encode.c",
       "int/i31_fmont.c", "int/i31_iszero.c", "int/i31_moddiv.c",
       "int/i31_modpow2.c", "int/i31_montmul.c", "int/i31_mulacc.c",
       "int/i31_muladd.c", "int/i31_ninv31.c", "int/i31_reduce.c",
       "int/i31_rshift.c", "int/i31_sub.c", "int/i31_tmont.c",
       "int/i32_div32.c",
       "rsa/rsa_i31_priv.c", "rsa/rsa_i31_pub.c",
   ]);
   ```

   (adapt to the exact `xbuild` helpers available at the pinned upstream
   tag; `add_sources_in_dir_with_attrs(..., "-O2")` is recommended for the
   BearSSL `int/` files so `-Os` does not slow down the Montgomery loop —
   the cycle estimates in `docs/developer/rsa.md` assume `-O2`).

   BearSSL must be compiled **without** `BR_CT_MUL31` (the Cortex-M4 and
   M33 `UMULL`/`UMLAL` are constant time; the option only slows things
   down) and with its default `config.h` (no changes needed).

3. **Register the module.** Nothing else is required: `MP_REGISTER_MODULE(
   MP_QSTR_feuristic_native, mp_module_feuristic_native)` at the end of
   `modfeuristic_native.c` is collected by the upstream `build_genhdr()`
   step (it preprocesses every source with `-DNO_QSTR`, extracts
   `MP_REGISTER_MODULE` into `moduledefs.collected.h` and every
   `MP_QSTR_xxx` into `qstrdefs.collected.h`). The source therefore only
   has to be in `lib.add_sources(...)` **before** `build_genhdr()` runs —
   which is the case for everything added in the `upymod` library setup.
   New qstrs used: `feuristic_native`, `rsa_complete`, `rsa_private`,
   `rsa_public`, `modpow`, `rsa_sieve`, `rsa_mr_round`.

4. **Stubs.** Copy (or symlink) `mocks/feuristic_native.pyi` into
   `core/mocks/generated/` if the upstream `make mocks`/pyright checks are
   used on feuristic code. The `///` comments follow the upstream
   `core/tools/build_mocks` format (`package: feuristic_native`).

5. **Emulator.** The module builds unchanged for the unix emulator
   (`rng_fill_buffer` is provided there too).

## Dependencies on upstream

* `py/obj.h`, `py/objint.h`, `py/objstr.h`, `py/runtime.h` (MicroPython);
* `<sys/rng.h>` → `rng_fill_buffer()` for the blinding factor (fresh per
  call; the blinding value is not secret-critical, so the fast TRNG/DRBG is
  used rather than the Optiga-mixed `rng_fill_buffer_strong`).

## Stack and time budget (coreapp stack is 16 KiB)

| call | peak C stack (gcc -O2, M4) | time M4 @168 MHz (est.) |
|---|---|---|
| `rsa_private` 2048 | ≈ 5.5 KiB | ≈ 370 ms |
| `modpow` / `rsa_mr_round` 1024 | ≈ 4.4 KiB | ≈ 160 ms |
| `rsa_public` 2048 | ≈ 2.3 KiB | ≈ 18 ms |
| `rsa_sieve` 1024 | ≈ 1.6 KiB | ≈ 5 ms |
| `rsa_complete` 2048 | ≈ 2.4 KiB | ≈ 3 ms |

The module was syntax-checked on the host against the pinned upstream
MicroPython headers (`mpycross_include/mpconfigport.h`, shimmed
`genhdr/qstrdefs.generated.h`), but it has not been built inside the
firmware yet.
