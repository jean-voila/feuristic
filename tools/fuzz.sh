#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Build every libFuzzer target in tests/fuzz and run each one for N seconds.
#   tools/fuzz.sh [seconds] [target-filter]
# Environment: CLANG (default: Homebrew LLVM clang, else clang), FUZZ_JOBS.
# Targets are named <lib>_<what>_fuzz.c or <lib>_fuzz.c; <lib> is a directory
# of lib/. Crashes are written to build/fuzz/artifacts/ and fail the script.
set -euo pipefail
SECONDS_PER_TARGET=${1:-60}
FILTER=${2:-}
ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=$ROOT/build/fuzz
mkdir -p "$OUT/artifacts"
if [ -z "${CLANG:-}" ]; then
  if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then CLANG=/opt/homebrew/opt/llvm/bin/clang; else CLANG=clang; fi
fi
CFLAGS=(-std=c99 -g -O1 "-fsanitize=fuzzer,address,undefined" -fno-sanitize-recover=all -Wall -Wextra)

lib_sources() {
  local lib=$1
  local d=$ROOT/lib/$lib
  if [ -d "$d/src" ]; then ls "$d"/src/*.c; else ls "$d"/*.c; fi
  if [ "$lib" = frsa ]; then
    local b=$ROOT/lib/third_party/bearssl/src
    ls "$b"/codec/ccopy.c "$b"/int/i31_*.c "$b"/int/i32_div32.c "$b"/rsa/rsa_i31_priv.c "$b"/rsa/rsa_i31_pub.c
  fi
}

lib_includes() {
  local lib=$1
  local d=$ROOT/lib/$lib
  echo "-I$d -I$d/include -I$d/src"
  if [ "$lib" = frsa ]; then
    echo "-I$ROOT/lib/third_party/bearssl/inc -I$ROOT/lib/third_party/bearssl/src"
  fi
}

status=0
for src in "$ROOT"/tests/fuzz/*_fuzz.c; do
  name=$(basename "$src" .c)
  [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]] && continue
  lib=${name%%_*}
  [ -d "$ROOT/lib/$lib" ] || continue
  extra=()
  [[ "$name" == *inflate* ]] && extra+=(-lz)
  # shellcheck disable=SC2046
  "$CLANG" "${CFLAGS[@]}" $(lib_includes "$lib") $(lib_sources "$lib") "$src" "${extra[@]}" -o "$OUT/$name"
  corpus=$ROOT/tests/fuzz/corpus/${name%_fuzz}
  [ -d "$corpus" ] || corpus=$ROOT/tests/fuzz/corpus/$lib
  work=$OUT/corpus-$name
  mkdir -p "$work"
  echo "== $name (${SECONDS_PER_TARGET}s)"
  if ! "$OUT/$name" -max_total_time="$SECONDS_PER_TARGET" -artifact_prefix="$OUT/artifacts/$name-" \
      -print_final_stats=1 "$work" ${corpus:+$( [ -d "$corpus" ] && echo "$corpus")} > "$OUT/$name.log" 2>&1; then
    echo "!! $name found a problem, see $OUT/$name.log"
    tail -30 "$OUT/$name.log"
    status=1
  else
    grep -E "stat::number_of_executed_units|Done" "$OUT/$name.log" | tail -2
  fi
done
exit $status
