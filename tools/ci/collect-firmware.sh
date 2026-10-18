#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copy the built firmware to dist/ with a versioned name and a SHA-256 sum.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODEL=$1
SUFFIX=${2:-}
VERSION=$(python3 -c "import sys; sys.path.insert(0,'$ROOT/src'); from feuristic.version import VERSION; print(VERSION)")
REV=$(git -C "$ROOT" rev-parse --short=12 HEAD)
SRC=$ROOT/upstream/trezor-firmware/core/build-xtask/artifacts/$MODEL/firmware.bin
NAME=feuristic-$VERSION-$MODEL-$REV$SUFFIX.bin
mkdir -p "$ROOT/dist"
cp "$SRC" "$ROOT/dist/$NAME"
if command -v sha256sum > /dev/null; then
  (cd "$ROOT/dist" && sha256sum "$NAME" > "$NAME.sha256")
else
  (cd "$ROOT/dist" && shasum -a 256 "$NAME" > "$NAME.sha256")
fi
cat "$ROOT/dist/$NAME.sha256"
