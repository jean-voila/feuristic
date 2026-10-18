// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

#include "host_sim.h"

#include <stdlib.h>
#include <string.h>

static void sim_read_sector(void *user, uint32_t lba, uint8_t *out) {
  host_t *h = user;
  if (scsi_read10(h, lba, 1, out) != 0) {
    memset(out, 0, 512);
  }
}

bool sim_mount(sim_t *s, host_t *h) {
  memset(s, 0, sizeof *s);
  s->h = h;
  s->max_cmd_sectors = 128;
  if (!fr_mount(&s->fr, sim_read_sector, h)) {
    fprintf(stderr, "sim_mount: %s\n", s->fr.error);
    return false;
  }
  memcpy(s->fat, s->fr.fat, FMSC_FAT_BYTES);
  memcpy(s->fat_flushed, s->fat, FMSC_FAT_BYTES);
  memcpy(s->root, s->fr.root, FMSC_ROOT_BYTES);
  memcpy(s->root_flushed, s->root, FMSC_ROOT_BYTES);
  return true;
}

void sim_unmount(sim_t *s) { fr_unmount(&s->fr); }

uint32_t sim_lba(uint32_t cluster) { return FMSC_DATA_LBA + (cluster - 2u) * 8u; }

uint32_t sim_fat_get(const sim_t *s, uint32_t c) {
  const uint32_t off = c + c / 2u;
  const uint32_t v = (uint32_t)s->fat[off] | ((uint32_t)s->fat[off + 1] << 8);
  return (c & 1u) ? v >> 4 : v & 0xFFFu;
}

void sim_fat_set(sim_t *s, uint32_t c, uint32_t v) {
  const uint32_t off = c + c / 2u;
  if (c & 1u) {
    s->fat[off] = (uint8_t)((s->fat[off] & 0x0F) | ((v & 0x0F) << 4));
    s->fat[off + 1] = (uint8_t)(v >> 4);
  } else {
    s->fat[off] = (uint8_t)v;
    s->fat[off + 1] = (uint8_t)((s->fat[off + 1] & 0xF0) | ((v >> 8) & 0x0F));
  }
}

uint32_t sim_alloc(sim_t *s, uint32_t n) {
  uint32_t run = 0;
  for (uint32_t c = 2; c <= FMSC_LAST_CLUSTER; c++) {
    run = sim_fat_get(s, c) == 0 ? run + 1 : 0;
    if (run == n) {
      const uint32_t start = c + 1 - n;
      for (uint32_t i = 0; i < n; i++) {
        sim_fat_set(s, start + i, i + 1 < n ? start + i + 1 : 0xFFF);
      }
      return start;
    }
  }
  abort();
}

void sim_chain(sim_t *s, const uint32_t *list, uint32_t n) {
  for (uint32_t i = 0; i < n; i++) {
    sim_fat_set(s, list[i], i + 1 < n ? list[i + 1] : 0xFFF);
  }
}

void sim_free_chain(sim_t *s, uint32_t c) {
  uint32_t guard = 0;
  while (c >= 2 && c <= FMSC_LAST_CLUSTER && guard++ < 5000) {
    const uint32_t next = sim_fat_get(s, c);
    sim_fat_set(s, c, 0);
    c = next;
  }
}

static uint8_t sfn_sum(const uint8_t *n) {
  uint8_t sum = 0;
  for (int i = 0; i < 11; i++) sum = (uint8_t)(((sum & 1) << 7) + (sum >> 1) + n[i]);
  return sum;
}

int sim_add_entry(sim_t *s, const char *long_name, const char *short11, uint8_t attr,
                  uint32_t cluster, uint32_t size) {
  const size_t ln = long_name != NULL ? strlen(long_name) : 0;
  const int nlfn = (int)((ln + 12) / 13);
  const int need = nlfn + 1;
  int run = 0;
  int start = -1;
  for (int i = 0; i < (int)FMSC_ROOT_ENTRIES; i++) {
    const uint8_t b = s->root[32 * i];
    run = (b == 0 || b == 0xE5) ? run + 1 : 0;
    if (run == need) {
      start = i + 1 - need;
      break;
    }
  }
  if (start < 0) return -1;
  const uint8_t sum = sfn_sum((const uint8_t *)short11);
  for (int k = nlfn; k >= 1; k--) {
    uint8_t *e = s->root + 32 * (start + (nlfn - k));
    memset(e, 0, 32);
    e[0] = (uint8_t)(k | (k == nlfn ? 0x40 : 0));
    e[11] = 0x0F;
    e[13] = sum;
    static const int offs[13] = {1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30};
    for (int j = 0; j < 13; j++) {
      const size_t pos = (size_t)(k - 1) * 13 + (size_t)j;
      const unsigned ch = pos < ln ? (unsigned char)long_name[pos] : pos == ln ? 0u : 0xFFFFu;
      e[offs[j]] = (uint8_t)ch;
      e[offs[j] + 1] = (uint8_t)(ch >> 8);
    }
  }
  const int idx = start + nlfn;
  uint8_t *e = s->root + 32 * idx;
  memset(e, 0, 32);
  memcpy(e, short11, 11);
  e[11] = attr;
  e[16] = 0x21;  // date 2026-01-01
  e[17] = 0x5C;
  sim_set_entry(s, idx, cluster, size);
  return idx;
}

void sim_set_entry(sim_t *s, int idx, uint32_t cluster, uint32_t size) {
  uint8_t *e = s->root + 32 * idx;
  e[26] = (uint8_t)cluster;
  e[27] = (uint8_t)(cluster >> 8);
  e[28] = (uint8_t)size;
  e[29] = (uint8_t)(size >> 8);
  e[30] = (uint8_t)(size >> 16);
  e[31] = (uint8_t)(size >> 24);
}

void sim_delete_entry(sim_t *s, int idx) {
  s->root[32 * idx] = 0xE5;
  for (int i = idx - 1; i >= 0 && (s->root[32 * i + 11] & 0x3F) == 0x0F; i--) {
    s->root[32 * i] = 0xE5;
  }
}

static void write_fat_copy(sim_t *s, uint32_t base, bool merged) {
  if (merged) {
    sim_write(s, base, FMSC_FAT_SECTORS, s->fat);
    return;
  }
  for (uint32_t k = 0; k < FMSC_FAT_SECTORS; k++) {
    if (memcmp(s->fat + k * 512, s->fat_flushed + k * 512, 512) != 0) {
      sim_write(s, base + k, 1, s->fat + k * 512);
    }
  }
}

void sim_flush_fat(sim_t *s, bool fat2_first, bool merged) {
  if (fat2_first) {
    write_fat_copy(s, FMSC_FAT2_LBA, merged);
    write_fat_copy(s, FMSC_FAT1_LBA, merged);
  } else {
    write_fat_copy(s, FMSC_FAT1_LBA, merged);
    write_fat_copy(s, FMSC_FAT2_LBA, merged);
  }
  memcpy(s->fat_flushed, s->fat, FMSC_FAT_BYTES);
}

void sim_flush_root(sim_t *s) {
  for (uint32_t k = 0; k < FMSC_ROOT_SECTORS; k++) {
    if (memcmp(s->root + k * 512, s->root_flushed + k * 512, 512) != 0) {
      sim_write(s, FMSC_ROOT_LBA + k, 1, s->root + k * 512);
    }
  }
  memcpy(s->root_flushed, s->root, FMSC_ROOT_BYTES);
}

void sim_write(sim_t *s, uint32_t lba, uint32_t count, const uint8_t *data) {
  while (count > 0) {
    const uint32_t n = count > s->max_cmd_sectors ? s->max_cmd_sectors : count;
    const int st = scsi_write10(s->h, lba, (uint16_t)n, data);
    CHECK_EQ(st, 0);
    lba += n;
    count -= n;
    data += (size_t)n * 512;
  }
}

void sim_write_file(sim_t *s, uint32_t cluster, const uint8_t *data, uint32_t size,
                    bool whole_clusters) {
  uint32_t sectors = (size + 511) / 512;
  if (whole_clusters) sectors = (sectors + 7) / 8 * 8;
  uint8_t *tmp = calloc(sectors, 512);
  memcpy(tmp, data, size);
  sim_write(s, sim_lba(cluster), sectors, tmp);
  free(tmp);
}

void make_image(uint8_t *buf, uint32_t size, uint32_t seed, bool jpeg) {
  uint32_t x = seed * 2654435761u + 12345u;
  for (uint32_t i = 0; i < size; i++) {
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    buf[i] = (uint8_t)(x >> 7);
  }
  for (uint32_t i = 4096; i < size; i += 4096) buf[i] = 0x42;
  static const uint8_t png[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
  static const uint8_t jpg[4] = {0xFF, 0xD8, 0xFF, 0xE0};
  if (jpeg) {
    memcpy(buf, jpg, size < 4 ? size : 4);
  } else {
    memcpy(buf, png, size < 8 ? size : 8);
  }
}
