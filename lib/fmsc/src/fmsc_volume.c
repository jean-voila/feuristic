// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Virtual FAT12 volume: generated boot sector, RAM FAT (one copy serving both
// FAT1 and FAT2), RAM root directory, generated pre-created files and a small
// LRU cache for non-image data clusters written by the host.

#include <string.h>

#include "fmsc_internal.h"

// Fixed timestamp of the pre-created entries: 2026-01-01 00:00:00.
#define FMSC_DOS_DATE ((uint16_t)(((2026u - 1980u) << 9) | (1u << 5) | 1u))
#define FMSC_DOS_TIME ((uint16_t)0u)

#define ATTR_RO 0x01u
#define ATTR_HIDDEN 0x02u
#define ATTR_VOLUME 0x08u
#define ATTR_DIR 0x10u
#define ATTR_ARCHIVE 0x20u
#define ATTR_LFN 0x0Fu
#define NTRES_LOWER_BASE 0x08u

#define GEN_FSEVENTSD 0x01u
#define GEN_README 0x02u

void fmsc_secure_zero(void *p, size_t n) {
  volatile uint8_t *v = (volatile uint8_t *)p;
  while (n-- > 0u) {
    *v++ = 0u;
  }
}

// --- directory entry builders ----------------------------------------------

static void put_dirent(uint8_t *e, const char *name11, uint8_t attr,
                       uint8_t ntres, uint16_t cluster, uint32_t size) {
  memset(e, 0, 32);
  memcpy(e, name11, 11);
  e[11] = attr;
  e[12] = ntres;
  fmsc_put_le16(e + 14, FMSC_DOS_TIME);
  fmsc_put_le16(e + 16, FMSC_DOS_DATE);
  fmsc_put_le16(e + 18, FMSC_DOS_DATE);
  fmsc_put_le16(e + 22, FMSC_DOS_TIME);
  fmsc_put_le16(e + 24, FMSC_DOS_DATE);
  fmsc_put_le16(e + 26, cluster);
  fmsc_put_le32(e + 28, size);
}

static uint8_t lfn_checksum(const uint8_t *name11) {
  uint8_t sum = 0;
  for (size_t i = 0; i < 11u; i++) {
    sum = (uint8_t)((uint8_t)((sum & 1u) << 7) + (uint8_t)(sum >> 1) + name11[i]);
  }
  return sum;
}

static size_t lfn_char_offset(size_t j) {
  if (j < 5u) {
    return 1u + 2u * j;
  }
  if (j < 11u) {
    return 14u + 2u * (j - 5u);
  }
  return 28u + 2u * (j - 11u);
}

// Writes the LFN entries for an ASCII long name (<= 26 chars here) followed
// by nothing; returns the number of 32-byte entries written.
static size_t put_lfn(uint8_t *dst, const char *lname, const char *short11) {
  const size_t n = strlen(lname);
  const size_t count = (n + 12u) / 13u;
  const uint8_t csum = lfn_checksum((const uint8_t *)short11);
  for (size_t k = count; k >= 1u; k--) {
    uint8_t *e = dst + 32u * (count - k);
    memset(e, 0, 32);
    e[0] = (uint8_t)(k | (k == count ? 0x40u : 0u));
    e[11] = ATTR_LFN;
    e[13] = csum;
    for (size_t j = 0; j < 13u; j++) {
      const size_t pos = (k - 1u) * 13u + j;
      uint16_t ch;
      if (pos < n) {
        ch = (uint8_t)lname[pos];
      } else if (pos == n) {
        ch = 0x0000u;
      } else {
        ch = 0xFFFFu;
      }
      fmsc_put_le16(e + lfn_char_offset(j), ch);
    }
  }
  return count;
}

// --- FAT ----------------------------------------------------------------------

uint16_t fmsc_fat_get(const fmsc_ctx_t *ctx, uint32_t cluster) {
  if (cluster > FMSC_LAST_CLUSTER) {
    return 0xFF7u;  // treat out-of-volume links as "bad"
  }
  const size_t off = (size_t)cluster + (size_t)(cluster / 2u);
  const uint16_t v = fmsc_le16(ctx->fat + off);
  return (cluster & 1u) ? (uint16_t)(v >> 4) : (uint16_t)(v & 0x0FFFu);
}

static void fat_set(fmsc_ctx_t *ctx, uint32_t cluster, uint16_t value) {
  const size_t off = (size_t)cluster + (size_t)(cluster / 2u);
  uint8_t *p = ctx->fat + off;
  value &= 0x0FFFu;
  if (cluster & 1u) {
    p[0] = (uint8_t)((p[0] & 0x0Fu) | (uint8_t)((value & 0x0Fu) << 4));
    p[1] = (uint8_t)(value >> 4);
  } else {
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)((p[1] & 0xF0u) | (uint8_t)(value >> 8));
  }
}

// --- initial layout ---------------------------------------------------------

void fmsc_vol_init(fmsc_ctx_t *ctx) {
  memset(ctx->fat, 0, sizeof ctx->fat);
  fat_set(ctx, 0, 0xFF8u);  // media descriptor 0xF8
  fat_set(ctx, 1, 0xFFFu);
  fat_set(ctx, FMSC_FSEVENTSD_CLUSTER, 0xFFFu);
  ctx->gen_valid = GEN_FSEVENTSD;
  if (ctx->readme_len > 0u) {
    fat_set(ctx, FMSC_README_CLUSTER, 0xFFFu);
    ctx->gen_valid |= GEN_README;
  }

  uint8_t *r = ctx->root;
  memset(r, 0, sizeof ctx->root);
  size_t i = 0;
  put_dirent(r + 32u * i++, FMSC_VOLUME_LABEL, ATTR_VOLUME, 0, 0, 0);
  put_dirent(r + 32u * i++, "README  TXT", ATTR_RO | ATTR_ARCHIVE, 0,
             ctx->readme_len > 0u ? (uint16_t)FMSC_README_CLUSTER : 0u,
             ctx->readme_len);
  // macOS junk suppression (same approach as CircuitPython).
  i += put_lfn(r + 32u * i, ".metadata_never_index", "METADA~1   ");
  put_dirent(r + 32u * i++, "METADA~1   ", ATTR_HIDDEN | ATTR_ARCHIVE, 0, 0, 0);
  i += put_lfn(r + 32u * i, ".Trashes", "TRASHE~1   ");
  put_dirent(r + 32u * i++, "TRASHE~1   ", ATTR_HIDDEN | ATTR_ARCHIVE, 0, 0, 0);
  i += put_lfn(r + 32u * i, ".fseventsd", "FSEVEN~1   ");
  put_dirent(r + 32u * i++, "FSEVEN~1   ", ATTR_HIDDEN | ATTR_DIR, 0,
             FMSC_FSEVENTSD_CLUSTER, 0);
}

static void gen_boot(const fmsc_ctx_t *ctx, uint8_t *o) {
  memset(o, 0, FMSC_SECTOR_SIZE);
  o[0] = 0xEBu;  // jmp short 0x3E ; nop
  o[1] = 0x3Cu;
  o[2] = 0x90u;
  memcpy(o + 3, "MSDOS5.0", 8);
  fmsc_put_le16(o + 11, FMSC_SECTOR_SIZE);
  o[13] = FMSC_SECTORS_PER_CLUSTER;
  fmsc_put_le16(o + 14, FMSC_RESERVED_SECTORS);
  o[16] = FMSC_NUM_FATS;
  fmsc_put_le16(o + 17, FMSC_ROOT_ENTRIES);
  fmsc_put_le16(o + 19, (uint16_t)FMSC_TOTAL_SECTORS);
  o[21] = 0xF8u;
  fmsc_put_le16(o + 22, FMSC_FAT_SECTORS);
  fmsc_put_le16(o + 24, 32u);  // sectors per track (CHS is meaningless here)
  fmsc_put_le16(o + 26, 64u);  // heads
  o[36] = 0x80u;               // drive number
  o[38] = 0x29u;               // extended boot signature
  fmsc_put_le32(o + 39, ctx->volume_id);
  memcpy(o + 43, FMSC_VOLUME_LABEL, 11);
  memcpy(o + 54, "FAT12   ", 8);
  o[62] = 0xFAu;  // cli
  o[63] = 0xF4u;  // hlt
  o[64] = 0xEBu;  // jmp $-1
  o[65] = 0xFDu;
  o[510] = 0x55u;
  o[511] = 0xAAu;
}

static void gen_cluster_sector(const fmsc_ctx_t *ctx, uint16_t cluster,
                               uint32_t s, uint8_t *out) {
  memset(out, 0, FMSC_SECTOR_SIZE);
  if (cluster == FMSC_FSEVENTSD_CLUSTER) {
    if (s == 0u) {
      put_dirent(out, ".          ", ATTR_DIR, 0, FMSC_FSEVENTSD_CLUSTER, 0);
      put_dirent(out + 32, "..         ", ATTR_DIR, 0, 0, 0);
      put_dirent(out + 64, "NO_LOG     ", ATTR_ARCHIVE, NTRES_LOWER_BASE, 0, 0);
    }
  } else if (cluster == FMSC_README_CLUSTER) {
    const size_t off = (size_t)s * FMSC_SECTOR_SIZE;
    if (off < ctx->readme_len) {
      size_t n = ctx->readme_len - off;
      if (n > FMSC_SECTOR_SIZE) {
        n = FMSC_SECTOR_SIZE;
      }
      memcpy(out, ctx->readme + off, n);
    }
  }
}

static bool gen_has(const fmsc_ctx_t *ctx, uint16_t cluster) {
  if (cluster == FMSC_FSEVENTSD_CLUSTER) {
    return (ctx->gen_valid & GEN_FSEVENTSD) != 0u;
  }
  if (cluster == FMSC_README_CLUSTER) {
    return (ctx->gen_valid & GEN_README) != 0u;
  }
  return false;
}

static void gen_clear(fmsc_ctx_t *ctx, uint16_t cluster) {
  if (cluster == FMSC_FSEVENTSD_CLUSTER) {
    ctx->gen_valid = (uint8_t)(ctx->gen_valid & ~GEN_FSEVENTSD);
  } else if (cluster == FMSC_README_CLUSTER) {
    ctx->gen_valid = (uint8_t)(ctx->gen_valid & ~GEN_README);
  }
}

// --- cluster cache ----------------------------------------------------------

static int cache_find(const fmsc_ctx_t *ctx, uint16_t cluster) {
  for (size_t i = 0; i < ctx->cache_n; i++) {
    if (ctx->cache[i].used && ctx->cache[i].cluster == cluster) {
      return (int)i;
    }
  }
  return -1;
}

static uint8_t *cache_data(const fmsc_ctx_t *ctx, size_t i) {
  return ctx->cache_mem + i * FMSC_CLUSTER_SIZE;
}

static bool is_dot_entry(const uint8_t *d) {
  static const char dot[] = ".          ";
  return memcmp(d, dot, 11) == 0 && (d[11] & ATTR_DIR) != 0u;
}

// Choose a slot for a new cluster. Non-directory data never evicts a
// directory cluster; in that case -1 (write dropped).
static int cache_alloc(fmsc_ctx_t *ctx, bool want_dir) {
  int best = -1;
  int best_dir = -1;
  for (size_t i = 0; i < ctx->cache_n; i++) {
    const fmsc_cache_slot_t *c = &ctx->cache[i];
    if (!c->used) {
      return (int)i;
    }
    if (c->is_dir) {
      if (best_dir < 0 || c->stamp < ctx->cache[best_dir].stamp) {
        best_dir = (int)i;
      }
    } else if (best < 0 || c->stamp < ctx->cache[best].stamp) {
      best = (int)i;
    }
  }
  if (best < 0 && want_dir) {
    best = best_dir;
  }
  if (best >= 0) {
    ctx->stats.cache_evictions++;
    fmsc_secure_zero(cache_data(ctx, (size_t)best), FMSC_CLUSTER_SIZE);
    ctx->cache[best].used = 0;
  }
  return best;
}

static bool all_zero(const uint8_t *d, size_t n) {
  uint8_t acc = 0;
  for (size_t i = 0; i < n; i++) {
    acc |= d[i];
  }
  return acc == 0u;
}

void fmsc_cache_invalidate(fmsc_ctx_t *ctx, uint16_t cluster) {
  const int i = cache_find(ctx, cluster);
  if (i >= 0) {
    fmsc_secure_zero(cache_data(ctx, (size_t)i), FMSC_CLUSTER_SIZE);
    memset(&ctx->cache[i], 0, sizeof ctx->cache[i]);
  }
  gen_clear(ctx, cluster);
}

void fmsc_cache_write(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *data) {
  const uint16_t cluster = fmsc_lba_cluster(lba);
  const uint32_t s = fmsc_lba_sector_in_cluster(lba);
  int i = cache_find(ctx, cluster);
  if (i < 0) {
    const bool gen = gen_has(ctx, cluster);
    if (!gen && all_zero(data, FMSC_SECTOR_SIZE)) {
      return;  // unknown clusters already read as zeros
    }
    const bool want_dir = (s == 0u) && is_dot_entry(data);
    i = cache_alloc(ctx, want_dir);
    if (i < 0) {
      ctx->stats.cache_dropped++;
      return;
    }
    uint8_t *c = cache_data(ctx, (size_t)i);
    if (gen) {
      for (uint32_t k = 0; k < FMSC_SECTORS_PER_CLUSTER; k++) {
        gen_cluster_sector(ctx, cluster, k, c + k * FMSC_SECTOR_SIZE);
      }
      gen_clear(ctx, cluster);
    } else {
      memset(c, 0, FMSC_CLUSTER_SIZE);
    }
    ctx->cache[i].used = 1;
    ctx->cache[i].cluster = cluster;
  }
  uint8_t *c = cache_data(ctx, (size_t)i);
  memcpy(c + s * FMSC_SECTOR_SIZE, data, FMSC_SECTOR_SIZE);
  const uint8_t was_dir = ctx->cache[i].is_dir;
  ctx->cache[i].is_dir = is_dot_entry(c) ? 1u : 0u;
  ctx->cache[i].stamp = ++ctx->cache_clock;
  if (was_dir || ctx->cache[i].is_dir) {
    ctx->meta_dirty = 1;  // a (sub)directory changed
  }
}

const uint8_t *fmsc_cache_dir_cluster(const fmsc_ctx_t *ctx, size_t i) {
  if (i >= ctx->cache_n || !ctx->cache[i].used || !ctx->cache[i].is_dir) {
    return NULL;
  }
  return cache_data(ctx, i);
}

// --- sector I/O -------------------------------------------------------------

void fmsc_vol_read(fmsc_ctx_t *ctx, uint32_t lba, uint8_t *out) {
  if (lba == 0u) {
    gen_boot(ctx, out);
  } else if (lba < FMSC_FAT2_LBA) {
    memcpy(out, ctx->fat + (lba - FMSC_FAT1_LBA) * FMSC_SECTOR_SIZE, FMSC_SECTOR_SIZE);
  } else if (lba < FMSC_ROOT_LBA) {
    memcpy(out, ctx->fat + (lba - FMSC_FAT2_LBA) * FMSC_SECTOR_SIZE, FMSC_SECTOR_SIZE);
  } else if (lba < FMSC_DATA_LBA) {
    memcpy(out, ctx->root + (lba - FMSC_ROOT_LBA) * FMSC_SECTOR_SIZE, FMSC_SECTOR_SIZE);
  } else if (lba < FMSC_TOTAL_SECTORS) {
    const uint16_t cluster = fmsc_lba_cluster(lba);
    const uint32_t s = fmsc_lba_sector_in_cluster(lba);
    const int i = cache_find(ctx, cluster);
    if (i >= 0) {
      ctx->cache[i].stamp = ++ctx->cache_clock;
      memcpy(out, cache_data(ctx, (size_t)i) + s * FMSC_SECTOR_SIZE, FMSC_SECTOR_SIZE);
    } else if (gen_has(ctx, cluster)) {
      gen_cluster_sector(ctx, cluster, s, out);
    } else {
      memset(out, 0, FMSC_SECTOR_SIZE);  // image data is never stored
    }
  } else {
    memset(out, 0, FMSC_SECTOR_SIZE);
  }
}

void fmsc_vol_write(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *data) {
  fmsc_trk_note_write(ctx);
  if (lba == 0u) {
    // Boot sector writes (e.g. the Linux "dirty" state byte) are accepted and
    // ignored: the BPB is generated.
    return;
  }
  if (lba < FMSC_FAT2_LBA) {
    const uint32_t k = lba - FMSC_FAT1_LBA;
    memcpy(ctx->fat + k * FMSC_SECTOR_SIZE, data, FMSC_SECTOR_SIZE);
    ctx->fat1_written = (uint16_t)(ctx->fat1_written | (1u << k));
    ctx->meta_dirty = 1;
    return;
  }
  if (lba < FMSC_ROOT_LBA) {
    // FAT2 is a mirror of the single RAM copy. Last writer wins (hosts that
    // write FAT2 before FAT1 are handled); a FAT2 sector that differs from
    // the FAT1 sector just written is a divergence and is counted.
    const uint32_t k = lba - FMSC_FAT2_LBA;
    uint8_t *p = ctx->fat + k * FMSC_SECTOR_SIZE;
    if (memcmp(p, data, FMSC_SECTOR_SIZE) != 0) {
      if (ctx->fat1_written & (1u << k)) {
        ctx->stats.fat_mirror_diverged++;
      }
      memcpy(p, data, FMSC_SECTOR_SIZE);
      ctx->meta_dirty = 1;
    }
    ctx->fat1_written = (uint16_t)(ctx->fat1_written & ~(1u << k));
    return;
  }
  if (lba < FMSC_DATA_LBA) {
    memcpy(ctx->root + (lba - FMSC_ROOT_LBA) * FMSC_SECTOR_SIZE, data, FMSC_SECTOR_SIZE);
    ctx->meta_dirty = 1;
    return;
  }
  if (lba < FMSC_TOTAL_SECTORS) {
    fmsc_trk_data_sector(ctx, lba, data);
  }
}

void fmsc_volume_read(fmsc_ctx_t *ctx, uint32_t lba, uint8_t out[512]) {
  if (ctx == NULL || out == NULL) {
    return;
  }
  fmsc_vol_read(ctx, lba, out);
}
