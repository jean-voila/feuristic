#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Build the firmware twice from clean trees and compare the hashes.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
MODEL=$1
model=$(echo "$MODEL" | tr '[:upper:]' '[:lower:]')
BIN=$ROOT/upstream/trezor-firmware/core/build-xtask/artifacts/$MODEL/firmware.bin
hashes=()
for i in 1 2; do
  rm -rf "$ROOT/upstream/trezor-firmware/core/build-xtask"
  "$ROOT/tools/ci/nix-build.sh" firmware "$model"
  hashes+=("$(sha256sum "$BIN" | cut -d' ' -f1)")
  echo "build $i: ${hashes[-1]}"
done
if [ "${hashes[0]}" != "${hashes[1]}" ]; then
  echo "NOT REPRODUCIBLE: ${hashes[0]} != ${hashes[1]}" >&2
  exit 1
fi
echo "reproducible: ${hashes[0]}"
