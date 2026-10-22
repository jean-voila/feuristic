---
title: Build feuristic from source
description: Build feuristic firmware for Trezor Safe 3 T2B1 and T3B1 from source on a pinned trezor-firmware release with the feuristic patch series.
---

<!-- SPDX-License-Identifier: GPL-3.0-only -->
<!-- Copyright (C) 2026 The feuristic contributors -->

# Building feuristic

Status: development candidate. Passing builds and emulator tests do not qualify
real Safe 3 hardware. Hardware gates are [R01–R16](../acceptance/README.md).
Run commands from the repository root unless a block explicitly changes it.

## Inputs and checkout policy

The superproject pins `upstream/trezor-firmware` to unmodified `core/v2.12.5`.
feuristic changes live in [patches/series](../../patches/series); application
sources are symlinked into that tree. Keep `uv.lock`, the upstream lockfiles,
the Git submodule reference and patch hashes with the build record.

Work on the currently checked-out branch. Do not create/switch a branch or
worktree merely to build. `make setup`, `make patches` and
`tools/ci/fetch-upstream.sh` call `tools/upstream.py apply`: that script resets
and checks out the submodule branch `feuristic/patched`. Consequently, use
that preparation workflow only in a fresh build checkout where this effect
is intended and authorized. Do not run it over a working submodule or as a
routine repair. In an already prepared checkout, inspect instead:

```sh
git status --short
uv run python tools/upstream.py status
make patches-check
```

`patches-check` only refuses a staged submodule reference; it does not prove
that the worktree is clean or that patch contents were reviewed.

## Supported build environments

CI uses Ubuntu 24.04 and the upstream pinned Nix shell. Install Git, Nix and
Python 3, then prepare the fresh checkout as described above:

```sh
tools/ci/fetch-upstream.sh
tools/ci/nix-build.sh firmware t2b1
tools/ci/collect-firmware.sh T2B1
tools/ci/nix-build.sh firmware t3b1
tools/ci/collect-firmware.sh T3B1
```

The helper enters `nix-shell`, runs `uv sync --frozen`, and invokes `xtask`.
This is the reference environment for release/reproducibility evidence.

For local macOS development, the existing [tools/env.sh](../../tools/env.sh)
selects Rust `nightly-2026-03-16`, the upstream virtualenv, Apple libclang and,
when installed, `/opt/homebrew/opt/arm-gcc-bin@14/bin`. Provide Rust/rustup,
ARM GNU GCC/binutils, libclang, SDL2 for the emulator, CMake and `uv`.
The script does not install them. Linux users must make their own compatible
compiler/libclang paths available or use the Nix workflow.

On a fresh checkout whose preparation is authorized:

```sh
make setup
```

This fetches the required nested submodules and synchronizes both Python
environments. With preparation already complete:

```sh
make firmware MODEL=T2B1
make firmware MODEL=T3B1
make emu MODEL=T3B1
```

Output paths:

| Output | Path |
|---|---|
| Hardware binary | `upstream/trezor-firmware/core/build-xtask/artifacts/T2B1/firmware.bin` or `T3B1/firmware.bin` |
| Named candidate | `dist/feuristic-<VERSION>-<MODEL>-<gitsha12>.bin` |
| SHA-256 sidecar | same name plus `.sha256` |
| Emulator | `upstream/trezor-firmware/core/build-xtask/artifacts/<MODEL>/firmware-emu` |

`VERSION` comes from `src/feuristic/version.py`. A dirty working tree is not
encoded in the filename: only distribute a recorded source state with its
actual diff if it was not clean. Two different dirty builds can otherwise
have identical names.

## Debug and qualification builds

```sh
make firmware-debug MODEL=T2B1
make emu MODEL=T2B1
make emu-run MODEL=T2B1
```

`firmware-debug` sets `--pyopt=false --debug-link`; its filename ends in
`-DEBUG.bin`. `DEBUG=1` is not the selector. Emulator builds include debuglink,
assertions and testing storage. Hardware `make firmware` excludes debuglink
and uses optimized Python, but **still uses upstream development signing
keys by default**. See [release policy](release.md) before calling it a public
release. Check the final USB descriptors, not only the filename.

Local checks:

```sh
make lint
make test-host
make test-c
make test-functional
make sbom
```

Build the emulator before `test-functional`; otherwise tests may be skipped.
For T2B1 select its executable through `FEURISTIC_EMU`, as explained in
[testing.md](testing.md). There is no `make nix-firmware` target; use
`tools/ci/nix-build.sh`.

## Build failures

A missing `xtask` normally means the upstream `.venv` was not synchronized or
`tools/env.sh` was not sourced by the command. Missing Rust target/libclang
and missing ARM compiler are toolchain issues, not reasons to change firmware
features. Preserve the full build log and inspect the first actual error.
Never increase hardware RAM declarations to fix a linker error. Keep the ELF,
linker map, flash/RAM report and stack/heap measurements with R04/R16 evidence.
The large emulator heap does not establish a hardware memory fit.
