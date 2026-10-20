// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * libFuzzer target: differential test of the lib/fimg inflater against zlib.
 * Byte 0 selects the input chunk size and the per-call output limit; the
 * rest is a zlib stream. Both decoders must agree on success / failure and,
 * on success, on every output byte (output capped at 4 MiB).
 * Build: link with -lz.
 */
#include <stdlib.h>
#include <string.h>
#include <zlib.h>

#include "fimg_internal.h"

#define CAP (4u << 20)

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static uint8_t first[FIMG_INF_PAGE_SIZE], second[FIMG_INF_PAGE_SIZE];
  static uint8_t ours[CAP], theirs[CAP];
  static fimg_inflate_t s;
  size_t off = 0, chunk;
  uint32_t total = 0, outmax;
  fimg_inf_result_t r = FIMG_INF_NEED_INPUT;
  int our_ok, their_ok, capped = 0;
  z_stream zs;
  int zr;

  if (size < 1) return 0;
  chunk = 1u + (data[0] & 15u) * 61u;
  outmax = (data[0] & 0x10u) ? 1u + (data[0] >> 5) * 37u : FIMG_INF_WSIZE;
  data++;
  size--;

  fimg_inflate_init_paged(&s, first, second);
  for (;;) {
    size_t n = size - off < chunk ? size - off : chunk, used = 0;
    uint32_t prod = 0, start = s.wpos;
    r = fimg_inflate(&s, data + off, n, &used, outmax, &prod);
    if (used > n || prod > outmax) abort();
    off += used;
    for (uint32_t i = 0; i < prod; i++) {
      if (total < CAP)
        ours[total] = *fimg_window_ptr(&s, (start + i) & FIMG_INF_WMASK);
      total++;
    }
    if (total >= CAP) {
      capped = 1;
      break;
    }
    if (r < 0 || r == FIMG_INF_DONE) break;
    if (r == FIMG_INF_NEED_INPUT && off == size) break;
    if (r == FIMG_INF_NEED_INPUT && used == 0 && n > 0)
      abort(); /* must consume what it is given */
  }
  if (capped) return 0;
  our_ok = r == FIMG_INF_DONE;

  memset(&zs, 0, sizeof zs);
  if (inflateInit(&zs) != Z_OK) abort();
  zs.next_in = (Bytef *)(uintptr_t)data;
  zs.avail_in = (uInt)size;
  zs.next_out = theirs;
  zs.avail_out = CAP;
  zr = inflate(&zs, Z_FINISH);
  their_ok = zr == Z_STREAM_END;
  if (zr == Z_BUF_ERROR && zs.avail_out == 0) {
    inflateEnd(&zs);
    return 0; /* output cap reached */
  }
  if (our_ok != their_ok) abort();
  if (our_ok) {
    if (zs.total_out != total || memcmp(ours, theirs, total) != 0) abort();
    if (zs.total_in != off)
      abort(); /* both stop right after the Adler-32 trailer */
  }
  inflateEnd(&zs);
  return 0;
}
