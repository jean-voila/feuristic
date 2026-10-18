// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

#include "fat_reader.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint32_t u16(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8);
}
static uint32_t u32(const uint8_t *p) { return u16(p) | (u16(p + 2) << 16); }

static bool fail(fr_vol_t *fr, const char *msg) {
  snprintf(fr->error, sizeof fr->error, "%s", msg);
  return false;
}

bool fr_mount(fr_vol_t *fr, fr_read_fn read, void *user) {
  memset(fr, 0, sizeof *fr);
  fr->read = read;
  fr->user = user;
  uint8_t bs[512];
  read(user, 0, bs);
  if (bs[510] != 0x55 || bs[511] != 0xAA) return fail(fr, "no 55AA signature");
  if (!((bs[0] == 0xEB && bs[2] == 0x90) || bs[0] == 0xE9))
    return fail(fr, "bad jump");
  fr->bytes_per_sector = u16(bs + 11);
  fr->sectors_per_cluster = bs[13];
  fr->reserved = u16(bs + 14);
  fr->num_fats = bs[16];
  fr->root_entries = u16(bs + 17);
  fr->total_sectors = u16(bs + 19) != 0 ? u16(bs + 19) : u32(bs + 32);
  fr->fat_size = u16(bs + 22);
  if (fr->bytes_per_sector != 512) return fail(fr, "sector size");
  const uint32_t spc = fr->sectors_per_cluster;
  if (spc == 0 || (spc & (spc - 1)) != 0)
    return fail(fr, "sectors per cluster");
  if (fr->reserved == 0 || fr->num_fats == 0 || fr->fat_size == 0)
    return fail(fr, "bpb zero");
  if ((fr->root_entries * 32) % 512 != 0)
    return fail(fr, "root entries alignment");
  if (bs[21] != 0xF8 && bs[21] < 0xF0) return fail(fr, "media");
  if (bs[38] != 0x29) return fail(fr, "no extended boot signature");
  fr->volume_id = u32(bs + 39);
  memcpy(fr->label, bs + 43, 11);
  memcpy(fr->fs_type, bs + 54, 8);
  fr->fat_lba = fr->reserved;
  fr->root_lba = fr->fat_lba + fr->num_fats * fr->fat_size;
  fr->data_lba = fr->root_lba + fr->root_entries * 32 / 512;
  if (fr->data_lba >= fr->total_sectors) return fail(fr, "no data area");
  fr->cluster_count = (fr->total_sectors - fr->data_lba) / spc;
  if (fr->cluster_count < 4085) {
    fr->fat_bits = 12;
  } else if (fr->cluster_count < 65525) {
    fr->fat_bits = 16;
  } else {
    return fail(fr, "FAT32 not supported");
  }
  const uint32_t need =
      (fr->cluster_count + 2) * (uint32_t)fr->fat_bits / 8 + 1;
  if (fr->fat_size * 512 < need) return fail(fr, "FAT too small");
  fr->fat = calloc(fr->fat_size, 512);
  fr->fat2 = calloc(fr->fat_size, 512);
  fr->root = calloc(fr->root_entries, 32);
  for (uint32_t i = 0; i < fr->fat_size; i++) {
    read(user, fr->fat_lba + i, fr->fat + i * 512);
    if (fr->num_fats > 1)
      read(user, fr->fat_lba + fr->fat_size + i, fr->fat2 + i * 512);
  }
  for (uint32_t i = 0; i < fr->root_entries * 32 / 512; i++) {
    read(user, fr->root_lba + i, fr->root + i * 512);
  }
  if (fr->num_fats > 1 && memcmp(fr->fat, fr->fat2, fr->fat_size * 512) != 0)
    return fail(fr, "FAT copies differ");
  if (fr_fat_get(fr, 0) != (0xF00u | bs[21]) && fr->fat_bits == 12)
    return fail(fr, "FAT[0] != media");
  return true;
}

void fr_unmount(fr_vol_t *fr) {
  free(fr->fat);
  free(fr->fat2);
  free(fr->root);
  fr->fat = fr->fat2 = fr->root = NULL;
}

uint32_t fr_fat_get(const fr_vol_t *fr, uint32_t c) {
  if (fr->fat_bits == 16) return u16(fr->fat + 2 * c);
  const uint32_t off = c * 3 / 2;
  const uint32_t v = u16(fr->fat + off);
  return (c % 2 == 0) ? (v & 0xFFF) : (v >> 4);
}

static uint8_t sfn_sum(const uint8_t *n) {
  uint8_t s = 0;
  for (int i = 0; i < 11; i++)
    s = (uint8_t)(((s & 1) ? 0x80 : 0) + (s >> 1) + n[i]);
  return s;
}

int fr_list(const fr_vol_t *fr, const uint8_t *dir, size_t entries,
            fr_entry_t *out, int max) {
  (void)fr;
  int count = 0;
  char lfn[256];
  int lfn_valid = 0;
  uint8_t lfn_sum = 0;
  int lfn_expect = 0;
  memset(lfn, 0, sizeof lfn);
  for (size_t i = 0; i < entries; i++) {
    const uint8_t *e = dir + 32 * i;
    if (e[0] == 0) break;
    if (e[0] == 0xE5) {
      lfn_valid = 0;
      continue;
    }
    if ((e[11] & 0x3F) == 0x0F) {
      const int ord = e[0] & 0x1F;
      if (e[0] & 0x40) {
        memset(lfn, 0, sizeof lfn);
        lfn_valid = 1;
        lfn_sum = e[13];
        lfn_expect = ord;
      } else if (!lfn_valid || ord != lfn_expect || e[13] != lfn_sum) {
        lfn_valid = 0;
        continue;
      }
      if (ord < 1 || ord > 19) {
        lfn_valid = 0;
        continue;
      }
      static const int offs[13] = {1,  3,  5,  7,  9,  14, 16,
                                   18, 20, 22, 24, 28, 30};
      for (int k = 0; k < 13; k++) {
        const uint32_t ch = u16(e + offs[k]);
        const int pos = (ord - 1) * 13 + k;
        if (ch == 0 || ch == 0xFFFF) continue;
        lfn[pos] = ch < 0x80 ? (char)ch : '?';
      }
      lfn_expect = ord - 1;
      continue;
    }
    if (count >= max) break;
    fr_entry_t *o = &out[count++];
    memset(o, 0, sizeof *o);
    int n = 0;
    for (int k = 0; k < 8 && e[k] != ' '; k++) o->short_name[n++] = (char)e[k];
    if (e[8] != ' ') {
      o->short_name[n++] = '.';
      for (int k = 8; k < 11 && e[k] != ' '; k++)
        o->short_name[n++] = (char)e[k];
    }
    if (lfn_valid && lfn_expect == 0 && lfn_sum == sfn_sum(e)) {
      memcpy(o->long_name, lfn, sizeof lfn - 1);
    }
    lfn_valid = 0;
    o->attr = e[11];
    o->cluster = u16(e + 26) | (u16(e + 20) << 16);
    o->size = u32(e + 28);
  }
  return count;
}

size_t fr_read_chain(const fr_vol_t *fr, uint32_t c, uint8_t *buf, size_t max) {
  size_t got = 0;
  const uint32_t csize = fr->sectors_per_cluster * 512;
  uint32_t guard = 0;
  while (c >= 2 && c < fr->cluster_count + 2 && got + csize <= max &&
         guard++ < fr->cluster_count) {
    for (uint32_t s = 0; s < fr->sectors_per_cluster; s++) {
      fr->read(fr->user, fr->data_lba + (c - 2) * fr->sectors_per_cluster + s,
               buf + got + s * 512);
    }
    got += csize;
    c = fr_fat_get(fr, c);
  }
  return got;
}

bool fr_check_chains(fr_vol_t *fr) {
  const uint32_t n = fr->cluster_count + 2;
  uint8_t *seen = calloc(n, 1);
  bool ok = true;
  // Every cluster has at most one predecessor and links stay in range.
  for (uint32_t c = 2; c < n && ok; c++) {
    const uint32_t v = fr_fat_get(fr, c);
    if (v == 0 || v >= 0xFF7) continue;
    if (v < 2 || v >= n) {
      ok = fail(fr, "link out of range");
    } else if (seen[v]++) {
      ok = fail(fr, "cross-linked cluster");
    }
  }
  free(seen);
  return ok;
}
