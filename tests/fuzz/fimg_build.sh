#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Build the lib/fimg libFuzzer targets (see README-fimg.md).
#   tests/fuzz/fimg_build.sh [outdir]       (default: build/fuzz-fimg)
# Environment: CLANG (default: Homebrew LLVM clang, else clang),
#              JPEG_PREFIX (libjpeg-turbo prefix for the differential JPEG target).
set -eu
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
OUT=${1:-$ROOT/build/fuzz-fimg}
if [ -z "${CLANG:-}" ]; then
  if [ -x /opt/homebrew/opt/llvm/bin/clang ]; then CLANG=/opt/homebrew/opt/llvm/bin/clang; else CLANG=clang; fi
fi
mkdir -p "$OUT"
SRC="$ROOT/lib/fimg/src/fimg.c $ROOT/lib/fimg/src/fimg_inflate.c $ROOT/lib/fimg/src/fimg_jpeg.c $ROOT/lib/fimg/src/fimg_pix.c $ROOT/lib/fimg/src/fimg_png.c"
CFLAGS="-std=c99 -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all -I$ROOT/lib/fimg/include -I$ROOT/lib/fimg/src -Wall -Wextra -Werror"
$CLANG $CFLAGS $SRC "$ROOT/tests/fuzz/fimg_png_fuzz.c" -o "$OUT/fimg_png_fuzz"
$CLANG $CFLAGS $SRC "$ROOT/tests/fuzz/fimg_jpeg_fuzz.c" -o "$OUT/fimg_jpeg_fuzz"
$CLANG $CFLAGS $SRC "$ROOT/tests/fuzz/fimg_inflate_fuzz.c" -lz -o "$OUT/fimg_inflate_fuzz"
JPEG_PREFIX=${JPEG_PREFIX:-/opt/homebrew/opt/jpeg-turbo}
if [ -f "$JPEG_PREFIX/include/jpeglib.h" ]; then
  $CLANG $CFLAGS -DFIMG_FUZZ_LIBJPEG -I"$JPEG_PREFIX/include" $SRC "$ROOT/tests/fuzz/fimg_jpeg_fuzz.c" \
    "$JPEG_PREFIX/lib/libjpeg.a" -o "$OUT/fimg_jpeg_diff_fuzz"
fi
echo "fuzzers built in $OUT"
