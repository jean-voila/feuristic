// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * libFuzzer target: lib/fimg on PNG-shaped input.
 * Unless bit 7 of the option byte is set, every chunk CRC of the input is
 * recomputed first so that mutations reach IHDR validation, inflate and
 * unfiltering instead of dying at the first CRC check (the library itself is
 * unmodified; bit 7 keeps the CRC-failure paths covered).
 */
#include "fimg_fuzz_common.h"

static uint32_t crc32_ref(uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  while (n--) {
    crc ^= *p++;
    for (int k = 0; k < 8; k++)
      crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
  }
  return ~crc;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  uint8_t *buf;
  fz_luma_t lum = {0, 0, 0, NULL};
  if (size < 1 || size > 300 * 1024) return 0;
  buf = (uint8_t *)malloc(size);
  memcpy(buf, data, size);
  if (!(buf[0] & 0x80u) && size > 9) {
    size_t i = 9; /* option byte + PNG signature */
    while (i + 12 <= size) {
      uint32_t len = ((uint32_t)buf[i] << 24) | ((uint32_t)buf[i + 1] << 16) |
                     ((uint32_t)buf[i + 2] << 8) | buf[i + 3];
      uint32_t crc;
      if (len > size - i - 12) break;
      crc = crc32_ref(0, buf + i + 4, 4 + (size_t)len);
      buf[i + 8 + len] = (uint8_t)(crc >> 24);
      buf[i + 9 + len] = (uint8_t)(crc >> 16);
      buf[i + 10 + len] = (uint8_t)(crc >> 8);
      buf[i + 11 + len] = (uint8_t)crc;
      i += 12 + (size_t)len;
    }
  }
  fz_run(buf, size, &lum);
  free(buf);
  return 0;
}
