// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * libFuzzer target for lib/fqr. See tests/fuzz/README-fqr.md.
 *
 * Input layout:
 *   byte 0      mode: 0..2 image decoder, 3 matrix decoder, 4 segment parser
 *               (value % 5)
 *   image mode  bytes 1-2 width, 3-4 height (little endian, reduced to
 *               1..1024), byte 5 extra stride (0..7 bytes), byte 6 option
 *               flags (polarity, max_codes, no_mirror, payload capacity),
 *               rest = bitmap rows (zero padded when short)
 *   matrix mode byte 1 version, byte 2 flags, rest = module rows
 *   segments    byte 1 version, byte 2 capacity, rest = data codewords
 *
 * The bitmap is copied into an exactly sized heap buffer so that any
 * out-of-bounds read is caught by AddressSanitizer.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fqr.h"
#include "fqr_internal.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

static uint8_t ws[FQR_WORKSPACE_SIZE + 7];
static uint8_t payload[2][FQR_MAX_PAYLOAD_SIZE + 1];

static void check_result(const fqr_result_t *r, fqr_status_t st) {
  if (st == FQR_OK || st == FQR_ERR_BUFFER_TOO_SMALL) {
    if (r->status == FQR_OK && r->payload_len > r->payload_cap) {
      abort();
    }
    if (r->version < 1 || r->version > 40 || r->mask > 7 || r->ecc_level > 3) {
      abort();
    }
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size < 3) {
    return 0;
  }
  unsigned mode = data[0] % 5u;
  if (mode <= 2u) {
    if (size < 7) {
      return 0;
    }
    uint32_t w =
        1u + ((uint32_t)data[1] | ((uint32_t)data[2] << 8)) % FQR_MAX_IMAGE_DIM;
    uint32_t h =
        1u + ((uint32_t)data[3] | ((uint32_t)data[4] << 8)) % FQR_MAX_IMAGE_DIM;
    size_t stride = (w + 7u) / 8u + (data[5] & 7u);
    uint8_t flags = data[6];
    const uint8_t *bits = data + 7;
    size_t nbits = size - 7;
    /* Keep each run bounded: cap the image area by the input size. */
    size_t need = (h - 1u) * stride + (w + 7u) / 8u;
    if (need > nbits * 4u + 4096u) {
      return 0;
    }
    uint8_t *img = malloc(need);
    if (img == NULL) {
      return 0;
    }
    for (size_t i = 0; i < need; i++) {
      img[i] = i < nbits ? bits[i] : 0u;
    }
    fqr_image_t im = {img, w, h, stride};
    fqr_options_t opt;
    fqr_stats_t stats;
    memset(&opt, 0, sizeof opt);
    opt.polarity = (fqr_polarity_t)(flags & 3u);
    opt.max_codes = (uint8_t)((flags >> 2) & 7u); /* 0 = default */
    opt.no_mirror = (flags & 0x20u) != 0u;
    opt.stats = &stats;
    fqr_result_t res[2];
    memset(res, 0, sizeof res);
    size_t cap = (flags & 0x40u) ? 16u : FQR_MAX_PAYLOAD_SIZE;
    res[0].payload = payload[0];
    res[0].payload_cap = cap;
    res[1].payload = payload[1];
    res[1].payload_cap = cap;
    size_t n = 99;
    /* Misaligned workspace on purpose. */
    void *wsp = ws + (data[0] / 5u) % 8u;
    fqr_status_t st;
    if (flags & 0x80u) {
      st = fqr_decode_single(&im, wsp, FQR_WORKSPACE_SIZE, &opt, &res[0]);
      n = (st == FQR_OK || st == FQR_ERR_BUFFER_TOO_SMALL) ? 1u : 0u;
    } else {
      st = fqr_decode(&im, wsp, FQR_WORKSPACE_SIZE, &opt, res, 2, &n);
    }
    if (n > FQR_MAX_CODES) {
      abort();
    }
    for (size_t i = 0; i < n && i < 2u; i++) {
      check_result(&res[i], st);
    }
    free(img);
  } else if (mode == 3u) {
    unsigned version = 1u + data[1] % 40u;
    unsigned dim = 17u + 4u * version;
    size_t stride = (dim + 7u) / 8u;
    size_t need = stride * dim;
    uint8_t *grid = malloc(need);
    if (grid == NULL) {
      return 0;
    }
    for (size_t i = 0; i < need; i++) {
      grid[i] = (3u + i < size) ? data[3 + i] : 0u;
    }
    fqr_result_t r;
    memset(&r, 0, sizeof r);
    r.payload = payload[0];
    r.payload_cap = (data[2] & 1u) ? 8u : FQR_MAX_PAYLOAD_SIZE;
    fqr_status_t st = fqr_decode_matrix(grid, dim, stride, (data[2] & 2u) != 0u,
                                        ws, FQR_WORKSPACE_SIZE, &r);
    check_result(&r, st);
    free(grid);
  } else {
    unsigned version = 1u + data[1] % 40u;
    size_t n = size - 3;
    if (n > FQR_MAX_CODEWORDS) {
      n = FQR_MAX_CODEWORDS;
    }
    uint8_t *cw = malloc(n ? n : 1u);
    if (cw == NULL) {
      return 0;
    }
    memcpy(cw, data + 3, n);
    fqr_result_t r;
    memset(&r, 0, sizeof r);
    size_t cap = data[2];
    uint8_t *out = malloc(cap ? cap : 1u);
    r.payload = cap ? out : NULL;
    r.payload_cap = cap;
    bool overflow = false;
    fqr_stage_t s = fqr_parse_segments(cw, n, version, &r, &overflow);
    if (s == FQR_STAGE_OK && overflow != (r.payload_len > cap)) {
      abort();
    }
    free(out);
    free(cw);
  }
  return 0;
}
