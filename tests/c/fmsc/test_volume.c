// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Virtual FAT12 volume: validity checked with an independent FAT reader,
// pre-created files, FAT mirroring, cluster cache, image dump for fsck.

#include <stdlib.h>
#include <string.h>

#include "fat_reader.h"
#include "tharness.h"

static host_t *mk(void) {
  host_t *h = host_new();
  host_open(h);
  host_clear_ua(h);
  return h;
}

static void vol_read(void *user, uint32_t lba, uint8_t *out) {
  host_t *h = user;
  fmsc_volume_read(&h->ctx, lba, out);
}

static const fr_entry_t *find(const fr_entry_t *e, int n,
                              const char *short_name) {
  for (int i = 0; i < n; i++) {
    if (strcmp(e[i].short_name, short_name) == 0) return &e[i];
  }
  return NULL;
}

static void test_geometry(void) {
  host_t *h = mk();
  fr_vol_t fr;
  CHECK(fr_mount(&fr, vol_read, h));
  CHECK_EQ(fr.bytes_per_sector, 512);
  CHECK_EQ(fr.sectors_per_cluster, 8);
  CHECK_EQ(fr.reserved, 1);
  CHECK_EQ(fr.num_fats, 2);
  CHECK_EQ(fr.root_entries, 64);
  CHECK_EQ(fr.total_sectors, FMSC_TOTAL_SECTORS);
  CHECK_EQ(fr.fat_size, FMSC_FAT_SECTORS);
  CHECK_EQ(fr.fat_bits, 12);
  CHECK_EQ(fr.cluster_count, FMSC_CLUSTER_COUNT);
  CHECK(fr.cluster_count <= 4084);     // Microsoft FAT12 rule
  CHECK(fr.cluster_count + 2 < 4086);  // BSD fsck_msdos FAT12 rule
  CHECK_EQ(fr.fat_lba, FMSC_FAT1_LBA);
  CHECK_EQ(fr.root_lba, FMSC_ROOT_LBA);
  CHECK_EQ(fr.data_lba, FMSC_DATA_LBA);
  CHECK(strcmp(fr.label, "FEURISTIC  ") == 0);
  CHECK(strcmp(fr.fs_type, "FAT12   ") == 0);
  CHECK_EQ(fr.volume_id, 0x20261017u);
  CHECK(fr_check_chains(&fr));
  // Capacity reported by SCSI matches the BPB.
  uint8_t b[8];
  const uint8_t rc[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  const xfer_t r = host_bot(h, rc, 10, true, 8, NULL, b);
  CHECK(r.csw_ok);
  CHECK_EQ(((uint32_t)b[0] << 24 | (uint32_t)b[1] << 16 | (uint32_t)b[2] << 8 |
            b[3]) +
               1,
           fr.total_sectors);
  fr_unmount(&fr);
  host_free(h);
}

static void test_root_contents(void) {
  host_t *h = mk();
  fr_vol_t fr;
  CHECK(fr_mount(&fr, vol_read, h));
  fr_entry_t e[64];
  const int n = fr_list(&fr, fr.root, 64, e, 64);
  CHECK_EQ(n, 5);
  CHECK(e[0].attr == 0x08 && strcmp(e[0].short_name, "FEURISTI.C") == 0);
  const fr_entry_t *rd = find(e, n, "README.TXT");
  CHECK(rd != NULL);
  if (rd != NULL) {
    CHECK_EQ(rd->size, strlen(h->readme));
    CHECK_EQ(rd->cluster, FMSC_README_CLUSTER);
    CHECK(rd->attr & 0x01);
    uint8_t *buf = calloc(1, 8192);
    const size_t got = fr_read_chain(&fr, rd->cluster, buf, 8192);
    CHECK_EQ(got, 4096);
    CHECK(memcmp(buf, h->readme, rd->size) == 0);
    CHECK_EQ(buf[rd->size], 0);
    free(buf);
  }
  const fr_entry_t *md = find(e, n, "METADA~1");
  CHECK(md != NULL && strcmp(md->long_name, ".metadata_never_index") == 0 &&
        md->size == 0 && md->cluster == 0 && (md->attr & 0x02));
  const fr_entry_t *tr = find(e, n, "TRASHE~1");
  CHECK(tr != NULL && strcmp(tr->long_name, ".Trashes") == 0 &&
        !(tr->attr & 0x10));
  const fr_entry_t *fs = find(e, n, "FSEVEN~1");
  CHECK(fs != NULL && strcmp(fs->long_name, ".fseventsd") == 0 &&
        (fs->attr & 0x10) && fs->cluster == FMSC_FSEVENTSD_CLUSTER);
  if (fs != NULL) {
    uint8_t dir[4096];
    CHECK_EQ(fr_read_chain(&fr, fs->cluster, dir, sizeof dir), 4096);
    fr_entry_t d[8];
    const int dn = fr_list(&fr, dir, 128, d, 8);
    CHECK_EQ(dn, 3);
    CHECK(strcmp(d[0].short_name, ".") == 0 &&
          d[0].cluster == FMSC_FSEVENTSD_CLUSTER);
    CHECK(strcmp(d[1].short_name, "..") == 0 && d[1].cluster == 0);
    CHECK(strcmp(d[2].short_name, "NO_LOG") == 0 && d[2].size == 0);
    CHECK_EQ(dir[64 + 12], 0x08);  // lowercase base name flag: "no_log"
  }
  // Free space: every other cluster is free.
  uint32_t used = 0;
  for (uint32_t c = 2; c < fr.cluster_count + 2; c++)
    used += fr_fat_get(&fr, c) != 0;
  CHECK_EQ(used, 2);
  CHECK_EQ(fr_fat_get(&fr, 0), 0xFF8);
  CHECK_EQ(fr_fat_get(&fr, 1), 0xFFF);
  fr_unmount(&fr);
  host_free(h);
}

static void test_empty_readme(void) {
  host_t *h = host_new();
  h->readme = NULL;
  host_open(h);
  fr_vol_t fr;
  CHECK(fr_mount(&fr, vol_read, h));
  fr_entry_t e[64];
  const int n = fr_list(&fr, fr.root, 64, e, 64);
  const fr_entry_t *rd = find(e, n, "README.TXT");
  CHECK(rd != NULL && rd->size == 0 && rd->cluster == 0);
  CHECK_EQ(fr_fat_get(&fr, FMSC_README_CLUSTER), 0);
  fr_unmount(&fr);
  host_free(h);
}

static void test_fat_mirror(void) {
  host_t *h = mk();
  uint8_t sec[512], back[512];
  fmsc_volume_read(&h->ctx, FMSC_FAT1_LBA, sec);
  sec[100] = 0x5A;
  CHECK_EQ(scsi_write10(h, FMSC_FAT1_LBA, 1, sec), 0);
  CHECK_EQ(scsi_read10(h, FMSC_FAT2_LBA, 1, back), 0);
  CHECK(memcmp(sec, back, 512) == 0);  // FAT2 mirrors the single copy
  CHECK_EQ(scsi_write10(h, FMSC_FAT2_LBA, 1, sec), 0);  // identical mirror
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.fat_mirror_diverged, 0);
  // FAT2 written first with new content: an update, not a divergence.
  sec[101] = 0x33;
  CHECK_EQ(scsi_write10(h, FMSC_FAT2_LBA + 1, 1, sec), 0);
  CHECK_EQ(scsi_write10(h, FMSC_FAT1_LBA + 1, 1, sec), 0);
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.fat_mirror_diverged, 0);
  fmsc_volume_read(&h->ctx, FMSC_FAT1_LBA + 1, back);
  CHECK(memcmp(sec, back, 512) == 0);
  // FAT1 then a different FAT2: divergence counted, last writer wins.
  sec[102] = 0x01;
  CHECK_EQ(scsi_write10(h, FMSC_FAT1_LBA + 2, 1, sec), 0);
  sec[102] = 0x02;
  CHECK_EQ(scsi_write10(h, FMSC_FAT2_LBA + 2, 1, sec), 0);
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.fat_mirror_diverged, 1);
  fmsc_volume_read(&h->ctx, FMSC_FAT1_LBA + 2, back);
  CHECK_EQ(back[102], 0x02);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_root_and_boot_writes(void) {
  host_t *h = mk();
  uint8_t sec[512], back[512], boot[512];
  fmsc_volume_read(&h->ctx, FMSC_ROOT_LBA + 3, sec);
  memcpy(sec + 32, "HELLO   TXT", 11);
  CHECK_EQ(scsi_write10(h, FMSC_ROOT_LBA + 3, 1, sec), 0);
  fmsc_volume_read(&h->ctx, FMSC_ROOT_LBA + 3, back);
  CHECK(memcmp(sec, back, 512) == 0);
  fmsc_volume_read(&h->ctx, 0, boot);
  memset(sec, 0xEE, sizeof sec);
  CHECK_EQ(scsi_write10(h, 0, 1, sec), 0);  // ignored, BPB generated
  fmsc_volume_read(&h->ctx, 0, back);
  CHECK(memcmp(boot, back, 512) == 0);
  fmsc_volume_read(&h->ctx, FMSC_TOTAL_SECTORS + 5, back);
  uint8_t zero[512];
  memset(zero, 0, sizeof zero);
  CHECK(memcmp(back, zero, 512) == 0);
  host_free(h);
}

static void fill(uint8_t *b, uint8_t v) {
  memset(b, v, 512);
  b[0] = 'X';  // never an image signature / foreign marker
}

static void test_cache_lru(void) {
  host_t *h = host_new();
  h->cache_clusters = 2;
  host_open(h);
  host_clear_ua(h);
  uint8_t s[512], back[512], zero[512];
  memset(zero, 0, sizeof zero);
  const uint32_t l1 = FMSC_DATA_LBA + 10 * 8, l2 = FMSC_DATA_LBA + 20 * 8,
                 l3 = FMSC_DATA_LBA + 30 * 8;
  fill(s, 1);
  CHECK_EQ(scsi_write10(h, l1, 1, s), 0);
  fill(s, 2);
  CHECK_EQ(scsi_write10(h, l2 + 3, 1, s), 0);  // partial cluster
  fmsc_volume_read(&h->ctx, l1, back);
  CHECK_EQ(back[5], 1);  // touch l1: l2 becomes LRU
  fill(s, 3);
  CHECK_EQ(scsi_write10(h, l3, 1, s), 0);
  fmsc_volume_read(&h->ctx, l2 + 3, back);
  CHECK(memcmp(back, zero, 512) == 0);  // evicted
  fmsc_volume_read(&h->ctx, l1, back);
  CHECK_EQ(back[5], 1);
  fmsc_volume_read(&h->ctx, l3, back);
  CHECK_EQ(back[5], 3);
  fmsc_volume_read(&h->ctx, l3 + 1, back);
  CHECK(memcmp(back, zero, 512) == 0);  // rest of the cluster is zero
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_evictions, 1);
  // All-zero writes to unknown clusters are not cached.
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 40 * 8, 1, zero), 0);
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_evictions, 1);
  host_free(h);
}

static void test_cache_keeps_directories(void) {
  host_t *h = host_new();
  h->cache_clusters = 2;
  host_open(h);
  host_clear_ua(h);
  uint8_t d[512], s[512], back[512];
  memset(d, 0, sizeof d);
  memcpy(d, ".          ", 11);
  d[11] = 0x10;
  memcpy(d + 32, "..         ", 11);
  d[32 + 11] = 0x10;
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 50 * 8, 1, d), 0);
  d[26] = 61;
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 60 * 8, 1, d), 0);
  fill(s, 9);
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 70 * 8, 1, s), 0);  // dropped
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_dropped, 1);
  CHECK_EQ(st.cache_evictions, 0);
  fmsc_volume_read(&h->ctx, FMSC_DATA_LBA + 50 * 8, back);
  CHECK(back[0] == '.' && back[11] == 0x10);
  fmsc_volume_read(&h->ctx, FMSC_DATA_LBA + 60 * 8, back);
  CHECK(back[0] == '.' && back[26] == 61);
  // A third directory evicts the least recently used directory.
  d[26] = 81;
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 80 * 8, 1, d), 0);
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_evictions, 1);
  host_free(h);
}

static void test_generated_overwrite(void) {
  host_t *h = mk();
  uint8_t s[512], back[512];
  const uint32_t lba = FMSC_DATA_LBA + (FMSC_README_CLUSTER - 2) * 8;
  fill(s, 0x61);
  CHECK_EQ(scsi_write10(h, lba + 1, 1, s), 0);  // second sector of README
  fmsc_volume_read(&h->ctx, lba, back);
  CHECK(memcmp(back, h->readme, 16) == 0);  // first sector still generated
  fmsc_volume_read(&h->ctx, lba + 1, back);
  CHECK_EQ(back[3], 0x61);
  host_free(h);
  // Without a cache, writes are dropped and generated content stays.
  h = host_new();
  h->cache_clusters = 0;
  host_open(h);
  host_clear_ua(h);
  CHECK_EQ(scsi_write10(h, lba, 1, s), 0);
  fmsc_volume_read(&h->ctx, lba, back);
  CHECK(memcmp(back, h->readme, 16) == 0);
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_dropped, 1);
  host_free(h);
}

static void test_wipe(void) {
  host_t *h = mk();
  uint8_t s[512];
  fill(s, 0x77);
  CHECK_EQ(scsi_write10(h, FMSC_DATA_LBA + 9 * 8, 1, s), 0);
  fmsc_wipe(&h->ctx);
  bool zero = true;
  for (size_t i = 0; i < sizeof h->cache_mem; i++)
    zero = zero && h->cache_mem[i] == 0;
  for (size_t i = 0; i < sizeof h->reorder_mem; i++)
    zero = zero && h->reorder_mem[i] == 0;
  const uint8_t *raw = (const uint8_t *)&h->ctx;
  for (size_t i = 0; i < sizeof h->ctx; i++) zero = zero && raw[i] == 0;
  CHECK(zero);
  host_open(h);  // reusable after re-init
  CHECK_EQ(scsi_tur(h), 1);
  host_free(h);
}

static void test_ram_budget(void) {
  fprintf(stderr, "    sizeof(fmsc_ctx_t) = %zu bytes\n", sizeof(fmsc_ctx_t));
  CHECK(sizeof(fmsc_ctx_t) <= 24u * 1024u);
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--dump") == 0) {
    // Dump the generated volume (for fsck_msdos / fsck.vfat).
    host_t *h = mk();
    FILE *f = fopen(argv[2], "wb");
    if (f == NULL) return 2;
    uint8_t s[512];
    for (uint32_t lba = 0; lba < FMSC_TOTAL_SECTORS; lba++) {
      fmsc_volume_read(&h->ctx, lba, s);
      if (fwrite(s, 1, 512, f) != 512) return 2;
    }
    fclose(f);
    host_free(h);
    return 0;
  }
  RUN(test_geometry);
  RUN(test_root_contents);
  RUN(test_empty_readme);
  RUN(test_fat_mirror);
  RUN(test_root_and_boot_writes);
  RUN(test_cache_lru);
  RUN(test_cache_keeps_directories);
  RUN(test_generated_overwrite);
  RUN(test_wipe);
  RUN(test_ram_budget);
  return t_finish("test_volume");
}
