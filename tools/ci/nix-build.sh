#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Build inside upstream's pinned Nix environment (reproducible toolchain).
#   tools/ci/nix-build.sh firmware t2b1 [extra xtask args]
#   tools/ci/nix-build.sh emulator t3b1
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
WHAT=$1
MODEL=$2
shift 2
case "$WHAT" in
  firmware) ARGS="build firmware -m $MODEL $*" ;;
  emulator) ARGS="build firmware --emulator -m $MODEL --debug-link --disable-animation $*" ;;
  *) echo "usage: $0 firmware|emulator <model>" >&2; exit 2 ;;
esac
cd "$ROOT/upstream/trezor-firmware"
nix-shell --run "uv sync --frozen && source .venv/bin/activate && cd core && xtask $ARGS"
