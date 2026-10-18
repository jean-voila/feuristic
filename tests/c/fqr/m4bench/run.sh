#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Instruction counts of lib/fqr on an emulated Cortex-M4F (QEMU mps2-an386).
# Needs: Arm GNU toolchain (arm-none-eabi-gcc with newlib headers),
# qemu-system-arm, uv. Usage: tests/c/fqr/m4bench/run.sh [build-dir]
set -eu
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
OUT=${1:-$ROOT/build/fqr-m4bench}
CC=${ARM_CC:-arm-none-eabi-gcc}
mkdir -p "$OUT"
uv run python "$HERE/embed_images.py" "$OUT/images.h" \
  "$ROOT/tests/c/fqr/vectors" \
  perf_photo_v10_724 perf_v40_724 perf_oled_v9_724 oled_v9_p1_nrm_0 persp_011 \
  multi_two_rotated perf_noise_724:both perf_hostile_finders_724:both damage_beyond_02 none_blank
"$CC" -std=c99 -mcpu=cortex-m4 -mthumb -mfloat-abi=hard -mfpu=fpv4-sp-d16 -O2 \
  -ffreestanding -ffunction-sections -fdata-sections -nostartfiles \
  -I"$ROOT/lib/fqr/include" -I"$OUT" -T "$HERE/link.ld" -Wl,--gc-sections \
  "$HERE/m4bench.c" "$ROOT"/lib/fqr/src/*.c -o "$OUT/m4bench.elf" -lc
qemu-system-arm -M mps2-an386 -nographic -semihosting -icount shift=0 \
  -kernel "$OUT/m4bench.elf"
