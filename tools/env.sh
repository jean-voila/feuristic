# SPDX-License-Identifier: GPL-3.0-only
# Source this file to get the local (non-Nix) firmware build environment on macOS:
#   source tools/env.sh
# CI and reproducible builds use upstream's Nix shell instead (see docs/developer/building.md).
# shellcheck shell=bash
if [ -n "${BASH_SOURCE[0]:-}" ]; then
  _FEU_SELF="${BASH_SOURCE[0]}"
else
  # zsh: path of the sourced file
  _FEU_SELF="$(eval 'echo ${(%):-%x}')"
fi
_FEU_ROOT="$(cd "$(dirname "$_FEU_SELF")/.." && pwd)"
export FEURISTIC_ROOT="$_FEU_ROOT"
export RUST_TOOLCHAIN="${RUST_TOOLCHAIN:-nightly-2026-03-16}"
_rust_bin="$HOME/.rustup/toolchains/${RUST_TOOLCHAIN}-$(uname -m | sed 's/arm64/aarch64/')-apple-darwin/bin"
[ -d "$_rust_bin" ] && export PATH="$_rust_bin:$PATH"
[ -d /opt/homebrew/opt/arm-gcc-bin@14/bin ] && export PATH="/opt/homebrew/opt/arm-gcc-bin@14/bin:$PATH"
export PATH="$_FEU_ROOT/upstream/trezor-firmware/.venv/bin:$PATH"
[ -f /Library/Developer/CommandLineTools/usr/lib/libclang.dylib ] && export LIBCLANG_PATH=/Library/Developer/CommandLineTools/usr/lib
# Apple clang is newer than upstream's pinned clang and flags two benign warnings
export CFLAGS_aarch64_apple_darwin="-Wno-gnu-folding-constant -Wno-double-promotion"
unset _rust_bin _FEU_ROOT _FEU_SELF
