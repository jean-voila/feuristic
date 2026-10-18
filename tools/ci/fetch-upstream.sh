#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Fetch the pinned upstream tree and only the nested submodules the feuristic
# firmware needs (shallow), then apply the feuristic patch series.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"
git submodule update --init --depth 1 upstream/trezor-firmware
cd upstream/trezor-firmware
git submodule update --init --depth 1 \
  vendor/micropython vendor/QR-Code-generator vendor/secp256k1-zkp vendor/cmsis_device_u5 \
  vendor/cmsis_5 vendor/stm32u5xx_hal_driver vendor/mldsa-native vendor/libtropic \
  vendor/sphincsplus vendor/ts-tvl vendor/nanopb
(cd vendor/micropython && git submodule update --init --depth 1 lib/stm32lib)
cd "$ROOT"
python3 tools/upstream.py apply
