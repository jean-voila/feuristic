#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Compile every portable library for both Safe 3 MCUs with -Werror.
set -euo pipefail
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
CC=${ARM_CC:-arm-none-eabi-gcc}
WARN=(-std=c99 -Wall -Wextra -Werror -pedantic -Wshadow -Wstrict-prototypes -Wmissing-prototypes -Wvla -Wcast-align)
OUT=$(mktemp -d)
for cpu in cortex-m4:fpv4-sp-d16 cortex-m33:fpv5-sp-d16; do
  core=${cpu%%:*}
  fpu=${cpu##*:}
  flags=(-mthumb "-mcpu=$core" "-mfpu=$fpu" -mfloat-abi=hard -Os -ffunction-sections -fdata-sections)
  for lib in fqr fimg fmsc frsa; do
    d=$ROOT/lib/$lib
    [ -d "$d" ] || continue
    if [ -d "$d/src" ]; then srcs=("$d"/src/*.c); else srcs=("$d"/*.c); fi
    inc=(-I"$d" -I"$d/include" -I"$d/src" -I"$ROOT/lib/third_party/bearssl/inc" -I"$ROOT/lib/third_party/bearssl/src")
    for s in "${srcs[@]}"; do
      "$CC" "${flags[@]}" "${WARN[@]}" "${inc[@]}" -c "$s" -o "$OUT/$(basename "$s").o"
    done
    echo "ok: $lib ($core)"
  done
done
arm-none-eabi-size -t "$OUT"/*.o | tail -1
