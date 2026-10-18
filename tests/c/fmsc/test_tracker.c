// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Import stream tracker driven by a host-OS write-pattern simulator:
// Windows-, macOS- and Linux-like sequences, LFN, several files, overwrite,
// delete, oversize, fragmentation, reordering, eject, bus reset.
// Every scenario asserts *when* stream_complete fires (exactly once) and that
// the delivered byte stream equals the file.

#include <stdlib.h>
#include <string.h>

#include "host_sim.h"
#include "tharness.h"

static host_t *mk_cfg(size_t reorder, uint32_t quiet, uint32_t settle) {
  host_t *h = host_new();
  h->reorder_sectors = reorder;
  h->quiet_ms = quiet;
  h->settle_ms = settle;
  host_open(h);
  host_clear_ua(h);
  return h;
}

static host_t *mk(void) { return mk_cfg(16, 2000, 15000); }

static uint32_t nclusters(uint32_t size) { return (size + 4095) / 4096; }

static bool completed_with(host_t *h, uint32_t id, const uint8_t *img,
                           uint32_t size) {
  rec_stream_t *s = host_stream(h, id);
  if (s == NULL || !s->completed || s->errored || s->terminal_events != 1)
    return false;
  if (s->size != size || s->len < size) return false;
  return memcmp(s->data, img, size) == 0;
}

static bool errored_with(host_t *h, uint32_t id, fmsc_stream_error_t reason) {
  rec_stream_t *s = host_stream(h, id);
  return s != NULL && s->errored && !s->completed && s->error == reason &&
         s->terminal_events == 1;
}

static void finish(host_t *h, sim_t *s) {
  CHECK_EQ(h->violations, 0);
  sim_unmount(s);
  host_free(h);
}

// ---------------------------------------------------------------------------

static void test_windows_metadata_first(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 30001;
  uint8_t *img = malloc(size);
  make_image(img, size, 1, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_add_entry(&s, "qr.png", "QR      PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, img, size, false);
  CHECK_EQ(h->n_completed, 0);  // no synchronisation yet
  CHECK_EQ(scsi_sync(h), 0);
  CHECK_EQ(h->n_completed, 1);
  CHECK(completed_with(h, 1, img, size));
  rec_stream_t *r = host_stream(h, 1);
  CHECK(strcmp(r->name.short_name, "QR.PNG") == 0);
  CHECK(strcmp(r->name.long_name, "qr.png") == 0);
  CHECK_EQ(scsi_sync(h), 0);
  host_advance(h, 20000);
  CHECK_EQ(h->n_completed, 1);  // exactly once
  CHECK_EQ(h->n_errors, 0);
  free(img);
  finish(h, &s);
}

static void test_windows_data_first_quiet(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 4096 * 5;
  uint8_t *img = malloc(size);
  make_image(img, size, 2, true);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, size, false);
  sim_flush_fat(&s, true, false);  // FAT2 first
  sim_add_entry(&s, NULL, "SCAN    JPG", 0x20, c, size);
  sim_flush_root(&s);
  host_advance(h, 1900);
  CHECK_EQ(h->n_completed, 0);
  host_advance(h, 200);
  CHECK_EQ(h->n_completed, 1);
  CHECK(completed_with(h, 1, img, size));
  CHECK(strcmp(host_stream(h, 1)->name.short_name, "SCAN.JPG") == 0);
  CHECK(strcmp(host_stream(h, 1)->name.long_name, "") == 0);
  free(img);
  finish(h, &s);
}

static void test_macos_sequence(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 54321;
  uint8_t *img = malloc(size);
  make_image(img, size, 3, false);
  // 1. Entry created with size 0 and no cluster.
  const int idx = sim_add_entry(&s, "QR Code.png", "QRCODE~1PNG", 0x20, 0, 0);
  sim_flush_root(&s);
  // 2. Data (page-cache writeback: whole clusters).
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, size, true);
  // 3. FAT, then the entry update.
  sim_flush_fat(&s, false, false);
  sim_set_entry(&s, idx, c, size);
  sim_flush_root(&s);
  // 4. AppleDouble "._QR Code.png" right after the image.
  uint8_t ad[4096];
  memset(ad, 0, sizeof ad);
  const uint8_t magic[8] = {0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00};
  memcpy(ad, magic, 8);
  memcpy(ad + 50, "com.apple.quarantine", 20);
  const uint32_t cad = sim_alloc(&s, 1);
  CHECK_EQ(cad, c + nclusters(size));
  sim_write_file(&s, cad, ad, 4096, true);
  sim_add_entry(&s, "._QR Code.png", "_QRCOD~1PNG", 0x22, cad, 4096);
  // 5. .DS_Store and .fseventsd activity.
  uint8_t ds[8192];
  memset(ds, 0x11, sizeof ds);
  const uint8_t bud[8] = {0x00, 0x00, 0x00, 0x01, 0x42, 0x75, 0x64, 0x31};
  memcpy(ds, bud, 8);
  const uint32_t cds = sim_alloc(&s, 2);
  sim_write_file(&s, cds, ds, sizeof ds, true);
  sim_add_entry(&s, ".DS_Store", "DS_STO~1   ", 0x22, cds, sizeof ds);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(h->n_completed, 0);
  host_advance(h, 2100);  // quiet period
  CHECK_EQ(h->n_completed, 1);
  CHECK(completed_with(h, 1, img, size));
  CHECK(strcmp(host_stream(h, 1)->name.long_name, "QR Code.png") == 0);
  CHECK(strcmp(host_stream(h, 1)->name.short_name, "QRCODE~1.PNG") == 0);
  CHECK_EQ(h->n_started, 1);  // AppleDouble / .DS_Store never mistaken
  // AppleDouble data was kept (readable back), and so was .DS_Store.
  uint8_t back[512];
  fmsc_volume_read(&h->ctx, sim_lba(cad), back);
  CHECK(memcmp(back, magic, 8) == 0);
  fmsc_volume_read(&h->ctx, sim_lba(cds), back);
  CHECK(memcmp(back, bud, 8) == 0);
  CHECK_EQ(scsi_sync(h), 0);
  host_advance(h, 30000);
  CHECK_EQ(h->n_completed, 1);
  CHECK_EQ(h->n_errors, 0);
  free(img);
  finish(h, &s);
}

static void test_linux_writeback_two_files(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  s.max_cmd_sectors = 240;
  const uint32_t sa = 10000, sb = 70000;
  uint8_t *a = malloc(sa), *b = malloc(sb);
  make_image(a, sa, 4, false);
  make_image(b, sb, 5, true);
  const uint32_t ca = sim_alloc(&s, nclusters(sa));
  const uint32_t cb = sim_alloc(&s, nclusters(sb));
  CHECK_EQ(cb, ca + nclusters(sa));
  sim_add_entry(&s, "first.png", "FIRST   PNG", 0x20, ca, sa);
  sim_add_entry(&s, "second.jpg", "SECOND  JPG", 0x20, cb, sb);
  // One ascending sweep covering both files' data (page granularity).
  const uint32_t total = (nclusters(sa) + nclusters(sb)) * 4096;
  uint8_t *sweep = calloc(1, total);
  memcpy(sweep, a, sa);
  memcpy(sweep + nclusters(sa) * 4096, b, sb);
  sim_write(&s, sim_lba(ca), total / 512, sweep);
  // Metadata: FAT1+FAT2 as whole copies, then the root directory.
  sim_flush_fat(&s, false, true);
  sim_flush_root(&s);
  CHECK_EQ(h->n_completed, 0);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK_EQ(h->n_completed, 2);
  CHECK(completed_with(h, 1, a, sa));
  CHECK(completed_with(h, 2, b, sb));
  free(a);
  free(b);
  free(sweep);
  finish(h, &s);
}

static void test_lfn_names(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const char *names[2] = {"Mon QR code (sauvegarde) 01.png",
                          "A very long file name that goes beyond sixty-three "
                          "characters - frame 07.png"};
  for (uint32_t i = 0; i < 2; i++) {
    const uint32_t size = 2000 + i;
    uint8_t img[4096];
    make_image(img, size, 10 + i, false);
    const uint32_t c = sim_alloc(&s, 1);
    sim_write_file(&s, c, img, size, false);
    sim_flush_fat(&s, false, false);
    char short11[12];
    snprintf(short11, sizeof short11, "LONGNA~%uPNG", (unsigned)(i + 1));
    sim_add_entry(&s, names[i], short11, 0x20, c, size);
    sim_flush_root(&s);
    CHECK_EQ(scsi_sync(h), 0);
    CHECK(completed_with(h, i + 1, img, size));
  }
  CHECK(strcmp(host_stream(h, 1)->name.long_name, names[0]) == 0);
  CHECK_EQ(strlen(host_stream(h, 2)->name.long_name), FMSC_LONG_NAME_MAX);
  CHECK(strncmp(host_stream(h, 2)->name.long_name, names[1],
                FMSC_LONG_NAME_MAX) == 0);
  finish(h, &s);
}

static void test_multiple_sequential(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  for (uint32_t i = 0; i < 6; i++) {
    const uint32_t size = 3000 + i * 9000;
    uint8_t *img = malloc(size);
    make_image(img, size, 20 + i, (i & 1) != 0);
    const uint32_t c = sim_alloc(&s, nclusters(size));
    char short11[12];
    snprintf(short11, sizeof short11, "FRAME%03u%s", (unsigned)i,
             (i & 1) ? "JPG" : "PNG");
    sim_add_entry(&s, NULL, short11, 0x20, c, size);
    sim_flush_fat(&s, false, false);
    sim_flush_root(&s);
    sim_write_file(&s, c, img, size, false);
    host_advance(h, 2500);
    CHECK_EQ(h->n_completed, (int)i + 1);
    CHECK(completed_with(h, i + 1, img, size));
    free(img);
  }
  CHECK_EQ(h->n_errors, 0);
  finish(h, &s);
}

static void test_overwrite_after_complete(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 9000;
  uint8_t a[9000], b[9000];
  make_image(a, size, 30, false);
  make_image(b, size, 31, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  const int idx = sim_add_entry(&s, "qr.png", "QR      PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, a, size, false);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, a, size));
  // Windows "replace": truncate (entry size 0, chain freed), re-allocate.
  sim_free_chain(&s, c);
  sim_set_entry(&s, idx, 0, 0);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  const uint32_t c2 = sim_alloc(&s, nclusters(size));
  CHECK_EQ(c2, c);
  sim_set_entry(&s, idx, c2, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c2, b, size, false);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 2, b, size));
  // Same file copied again with identical content: a new stream, complete.
  sim_write_file(&s, c2, b, size, false);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 3, b, size));
  CHECK_EQ(h->n_errors, 0);
  finish(h, &s);
}

static void test_linux_overwrite_bigger_stale_entry(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t sa = 6000, sb = 20000;
  uint8_t a[6000], b[20000];
  make_image(a, sa, 32, false);
  make_image(b, sb, 33, false);
  const uint32_t c = sim_alloc(&s, nclusters(sa));
  const int idx = sim_add_entry(&s, "qr.png", "QR      PNG", 0x20, c, sa);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, a, sa, true);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, a, sa));
  // cp b.png qr.png: data written first while the old entry (6000 bytes,
  // same first cluster) is still on the medium.
  sim_free_chain(&s, c);
  const uint32_t c2 = sim_alloc(&s, nclusters(sb));
  CHECK_EQ(c2, c);
  sim_set_entry(&s, idx, c2, sb);
  sim_write_file(&s, c2, b, sb, true);
  sim_flush_fat(&s, false, true);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 2, b, sb));
  CHECK_EQ(h->n_errors, 0);
  finish(h, &s);
}

static void test_overwrite_mid_transfer(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 40000;
  uint8_t *a = malloc(size), *b = malloc(size);
  make_image(a, size, 40, false);
  make_image(b, size, 41, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, a, 16384, false);  // half of A
  sim_write_file(&s, c, b, size, false);   // B over the same clusters
  CHECK(errored_with(h, 1, FMSC_SERR_OVERWRITTEN));
  sim_add_entry(&s, NULL, "B       PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 2, b, size));
  free(a);
  free(b);
  finish(h, &s);
}

static void test_delete_before_complete(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 20000;
  uint8_t img[20000];
  make_image(img, size, 50, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  const int idx = sim_add_entry(&s, "gone.png", "GONE    PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, img, 8192, false);
  sim_delete_entry(&s, idx);
  sim_free_chain(&s, c);
  sim_flush_root(&s);
  sim_flush_fat(&s, false, false);
  CHECK(errored_with(h, 1, FMSC_SERR_DELETED));
  CHECK_EQ(h->n_completed, 0);
  finish(h, &s);
}

static void test_too_large(void) {
  // (a) metadata first: reported as soon as the data starts.
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t big = 300000;
  uint8_t *img = malloc(big);
  make_image(img, big, 60, true);
  uint32_t c = sim_alloc(&s, nclusters(big));
  sim_add_entry(&s, "photo.jpg", "PHOTO   JPG", 0x20, c, big);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, img, big, false);
  CHECK(errored_with(h, 1, FMSC_SERR_TOO_LARGE));
  CHECK(host_stream(h, 1)->len <= FMSC_MAX_FILE_SIZE);
  CHECK_EQ(h->n_started, 1);
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_evictions, 0);  // the tail was swallowed, not cached
  finish(h, &s);
  // (b) data first: reported when the metadata arrives.
  h = mk();
  CHECK(sim_mount(&s, h));
  c = sim_alloc(&s, nclusters(big));
  sim_write_file(&s, c, img, big, true);
  CHECK_EQ(h->n_errors, 0);
  CHECK_EQ(host_stream(h, 1)->len, FMSC_MAX_FILE_SIZE);
  sim_flush_fat(&s, false, false);
  sim_add_entry(&s, "photo.jpg", "PHOTO   JPG", 0x20, c, big);
  sim_flush_root(&s);
  CHECK(errored_with(h, 1, FMSC_SERR_TOO_LARGE));
  finish(h, &s);
  // (c) exactly 256 KiB is accepted.
  h = mk();
  CHECK(sim_mount(&s, h));
  c = sim_alloc(&s, 64);
  sim_write_file(&s, c, img, FMSC_MAX_FILE_SIZE, false);
  sim_flush_fat(&s, false, false);
  sim_add_entry(&s, NULL, "MAX     JPG", 0x20, c, FMSC_MAX_FILE_SIZE);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, FMSC_MAX_FILE_SIZE));
  free(img);
  finish(h, &s);
}

static void test_fragmented(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 3 * 4096;
  uint8_t img[3 * 4096];
  make_image(img, size, 70, false);
  const uint32_t base = sim_alloc(&s, 4);  // reserve 4, re-chain around a hole
  const uint32_t list[3] = {base, base + 1, base + 3};
  sim_fat_set(&s, base + 2, 0xFFF);  // occupied by "another file"
  sim_chain(&s, list, 3);
  for (int k = 0; k < 3; k++)
    sim_write_file(&s, list[k], img + k * 4096, 4096, false);
  sim_add_entry(&s, NULL, "FRAG    PNG", 0x20, base, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  host_advance(h, 2500);
  CHECK_EQ(h->n_errors, 0);  // quiet period never decides a failure
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(errored_with(h, 1, FMSC_SERR_FRAGMENTED));
  CHECK_EQ(h->n_completed, 0);
  finish(h, &s);
}

static void test_fat_entry_straddling_sectors(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  // Cluster 341's FAT12 entry occupies bytes 511..512: across FAT sectors.
  const uint32_t start = 338, n = 8, size = n * 4096;
  uint8_t *img = malloc(size);
  make_image(img, size, 75, false);
  uint32_t list[8];
  for (uint32_t i = 0; i < n; i++) list[i] = start + i;
  sim_chain(&s, list, n);
  sim_write_file(&s, start, img, size, false);
  sim_add_entry(&s, NULL, "EDGE    PNG", 0x20, start, size);
  sim_flush_root(&s);
  sim_flush_fat(&s, false, false);  // one command per FAT sector
  CHECK_EQ(h->n_errors, 0);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  free(img);
  finish(h, &s);
}

static void test_out_of_order_within_budget(void) {
  host_t *h = mk_cfg(16, 2000, 15000);
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 5 * 4096;
  uint8_t *img = malloc(size);
  make_image(img, size, 80, false);
  const uint32_t c = sim_alloc(&s, 5);
  // Cluster 0 in order, cluster 1 sector by sector in reverse order, then
  // clusters 2, 4, 3 (whole-cluster reordering).
  sim_write(&s, sim_lba(c), 8, img);
  for (int k = 15; k >= 8; k--)
    sim_write(&s, sim_lba(c) + (uint32_t)k, 1, img + k * 512);
  CHECK_EQ(host_stream(h, 1)->len, 16 * 512);
  const int order[3] = {2, 4, 3};
  for (int k = 0; k < 3; k++) {
    const uint32_t cl = (uint32_t)order[k];
    sim_write(&s, sim_lba(c + cl), 8, img + cl * 4096);
  }
  CHECK_EQ(host_stream(h, 1)->len, size);
  sim_add_entry(&s, NULL, "OOO     PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK_EQ(h->n_errors, 0);
  free(img);
  finish(h, &s);
}

static void test_out_of_order_beyond_budget(void) {
  host_t *h = mk_cfg(4, 2000, 15000);
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 4 * 4096;
  uint8_t *img = malloc(size);
  make_image(img, size, 81, false);
  const uint32_t c = sim_alloc(&s, 4);
  sim_write(&s, sim_lba(c), 8, img);
  sim_write(&s, sim_lba(c + 2), 8,
            img + 2 * 4096);  // 8 sectors ahead > 4 slots
  CHECK(errored_with(h, 1, FMSC_SERR_GAP));
  sim_write(&s, sim_lba(c + 1), 8, img + 4096);
  sim_write(&s, sim_lba(c + 3), 8, img + 3 * 4096);
  sim_add_entry(&s, NULL, "GAP     PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK_EQ(h->n_completed, 0);
  CHECK_EQ(h->n_started, 1);
  // Zero reorder budget: any reordering is a gap.
  finish(h, &s);
  h = mk_cfg(0, 2000, 15000);
  CHECK(sim_mount(&s, h));
  sim_write(&s, sim_lba(c), 1, img);
  sim_write(&s, sim_lba(c) + 2, 1, img + 1024);
  CHECK(errored_with(h, 1, FMSC_SERR_GAP));
  free(img);
  finish(h, &s);
}

static void test_missing_data_settle(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 10000;
  uint8_t img[10000];
  make_image(img, size, 90, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, 9000, false);  // last sectors never written
  sim_add_entry(&s, NULL, "MISS    PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);  // a sync is not final for missing data
  host_advance(h, 2500);
  CHECK_EQ(h->n_errors, 0);
  CHECK_EQ(h->n_completed, 0);
  host_advance(h, 13000);
  CHECK(errored_with(h, 1, FMSC_SERR_MISSING_DATA));
  finish(h, &s);
}

static void test_quiet_needs_metadata(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 7000;
  uint8_t img[7000];
  make_image(img, size, 91, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, size, false);
  host_advance(h, 60000);  // Linux-like 30 s writeback delay: keep waiting
  CHECK_EQ(h->n_completed + h->n_errors, 0);
  sim_flush_fat(&s, false, false);
  sim_add_entry(&s, NULL, "LATE    PNG", 0x20, c, size);
  sim_flush_root(&s);
  host_advance(h, 1500);
  CHECK_EQ(h->n_completed, 0);
  host_advance(h, 600);
  CHECK(completed_with(h, 1, img, size));
  finish(h, &s);
}

static void test_eject_paths(void) {
  // Eject before completion: INCOMPLETE, then the EJECTED event.
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 12000;
  uint8_t img[12000];
  make_image(img, size, 100, false);
  uint32_t c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, size, false);
  CHECK_EQ(scsi_start_stop(h, true, false), 0);
  CHECK(errored_with(h, 1, FMSC_SERR_INCOMPLETE));
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 1);
  CHECK_EQ(scsi_tur(h), 1);
  uint8_t k, a, q;
  CHECK_EQ(scsi_sense(h, &k, &a, &q), 0);
  CHECK(k == 2 && a == 0x3A && q == 0);
  host_advance(h, 60000);
  CHECK_EQ(h->n_completed, 0);
  finish(h, &s);
  // Eject right after a complete copy without sync: eject completes it.
  h = mk();
  CHECK(sim_mount(&s, h));
  c = sim_alloc(&s, nclusters(size));
  sim_write_file(&s, c, img, size, false);
  sim_flush_fat(&s, false, false);
  sim_add_entry(&s, NULL, "EJ      PNG", 0x20, c, size);
  sim_flush_root(&s);
  CHECK_EQ(scsi_prevent(h, false), 0);
  CHECK_EQ(scsi_start_stop(h, true, false), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 1);
  finish(h, &s);
}

static void test_bus_reset_mid_transfer(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 32768;
  uint8_t *img = malloc(size);
  make_image(img, size, 110, false);
  const uint32_t c = sim_alloc(&s, 8);
  // WRITE(10) of 64 sectors interrupted after 300 packets (37.5 sectors).
  const uint32_t lba = sim_lba(c);
  const uint8_t cdb[10] = {0x2A,
                           0,
                           (uint8_t)(lba >> 24),
                           (uint8_t)(lba >> 16),
                           (uint8_t)(lba >> 8),
                           (uint8_t)lba,
                           0,
                           0,
                           64,
                           0};
  uint8_t cbw[31];
  host_build_cbw(cbw, 999, size, 0, 0, 10, cdb);
  host_send_out(h, cbw, 31);
  for (uint32_t i = 0; i < 300; i++) host_send_out(h, img + i * 64, 64);
  host_reset_recovery(h);
  CHECK_EQ(host_count_events(h, FMSC_EVT_HOST_RESET), 1);
  // The host retries the whole command.
  CHECK_EQ(scsi_write10(h, lba, 64, img), 0);
  sim_add_entry(&s, NULL, "RESET   PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK_EQ(h->n_errors, 0);
  free(img);
  finish(h, &s);
}

static void test_consumer_busy(void) {
  host_t *h = mk();
  h->refuse_streams = true;
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 16384;
  uint8_t img[16384];
  make_image(img, size, 120, false);
  const uint32_t c = sim_alloc(&s, 4);
  sim_write_file(&s, c, img, size, false);
  CHECK(errored_with(h, 1, FMSC_SERR_BUSY));
  CHECK(host_stream(h, 1)->len == 0);
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.cache_evictions + st.cache_dropped, 0);  // tail swallowed
  uint8_t back[512];
  fmsc_volume_read(&h->ctx, sim_lba(c) + 9, back);
  CHECK_EQ(back[3], 0);  // image data is never stored
  h->refuse_streams = false;
  sim_write_file(&s, c, img, size, false);  // copied again later
  sim_add_entry(&s, NULL, "AGAIN   PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 2, img, size));
  finish(h, &s);
}

static void test_overlapping_streams(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 8192;
  uint8_t a[8192], b[8192], d[8192];
  make_image(a, size, 130, false);
  make_image(b, size, 131, false);
  make_image(d, size, 132, false);
  const uint32_t ca = sim_alloc(&s, 2), cb = sim_alloc(&s, 2),
                 cd = sim_alloc(&s, 2);
  sim_write_file(&s, ca, a, size, false);
  sim_write_file(&s, cb, b, size, false);  // A now waits for its metadata
  sim_add_entry(&s, NULL, "A       PNG", 0x20, ca, size);
  sim_add_entry(&s, NULL, "B       PNG", 0x20, cb, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, a, size));
  CHECK(completed_with(h, 2, b, size));
  // Three files before any metadata: the oldest pending one is superseded.
  const uint32_t ce = sim_alloc(&s, 2), cf = sim_alloc(&s, 2);
  sim_write_file(&s, cd, d, size, false);
  sim_write_file(&s, ce, a, size, false);
  sim_write_file(&s, cf, b, size, false);
  CHECK(errored_with(h, 3, FMSC_SERR_SUPERSEDED));
  sim_add_entry(&s, NULL, "E       PNG", 0x20, ce, size);
  sim_add_entry(&s, NULL, "F       PNG", 0x20, cf, size);
  sim_add_entry(&s, NULL, "D       PNG", 0x20, cd, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 4, a, size));
  CHECK(completed_with(h, 5, b, size));
  CHECK_EQ(h->n_completed, 4);
  finish(h, &s);
}

static void test_subdirectory(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t dcl = sim_alloc(&s, 1);
  uint8_t dir[4096];
  memset(dir, 0, sizeof dir);
  memcpy(dir, ".          ", 11);
  dir[11] = 0x10;
  dir[26] = (uint8_t)dcl;
  dir[27] = (uint8_t)(dcl >> 8);
  memcpy(dir + 32, "..         ", 11);
  dir[43] = 0x10;
  sim_write(&s, sim_lba(dcl), 8, dir);
  sim_add_entry(&s, "Import", "IMPORT     ", 0x10, dcl, 0);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  const uint32_t size = 15000;
  uint8_t img[15000];
  make_image(img, size, 140, true);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  uint8_t *e = dir + 64;
  memcpy(e, "INSIDE  JPG", 11);
  e[11] = 0x20;
  e[26] = (uint8_t)c;
  e[27] = (uint8_t)(c >> 8);
  sim_write(&s, sim_lba(dcl), 1, dir);  // entry, size 0
  sim_write_file(&s, c, img, size, false);
  sim_flush_fat(&s, false, false);
  e[28] = (uint8_t)size;
  e[29] = (uint8_t)(size >> 8);
  sim_write(&s, sim_lba(dcl), 1, dir);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK(strcmp(host_stream(h, 1)->name.short_name, "INSIDE.JPG") == 0);
  finish(h, &s);
}

static void test_windows_junk(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  // "System Volume Information" + IndexerVolumeGuid (Windows on insertion).
  const uint32_t svi = sim_alloc(&s, 1), guid = sim_alloc(&s, 1);
  uint8_t dir[512];
  memset(dir, 0, sizeof dir);
  memcpy(dir, ".          ", 11);
  dir[11] = 0x10;
  memcpy(dir + 32, "..         ", 11);
  dir[43] = 0x10;
  memcpy(dir + 64, "INDEXE~1   ", 11);
  dir[64 + 11] = 0x20;
  dir[64 + 26] = (uint8_t)guid;
  dir[64 + 28] = 76;
  sim_write(&s, sim_lba(svi), 1, dir);
  uint8_t g[512];
  memset(g, 0, sizeof g);
  for (int i = 0; i < 76; i += 2) g[i] = (uint8_t)"{1234-5678}"[i % 11];
  sim_write(&s, sim_lba(guid), 1, g);
  sim_add_entry(&s, "System Volume Information", "SYSTEM~1   ", 0x16, svi, 0);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  const uint32_t size = 5000;
  uint8_t img[5000];
  make_image(img, size, 150, false);
  const uint32_t c = sim_alloc(&s, 2);
  sim_add_entry(&s, NULL, "WIN     PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, img, size, false);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK_EQ(h->n_started, 1);
  uint8_t back[512];
  fmsc_volume_read(&h->ctx, sim_lba(svi), back);
  CHECK(memcmp(back, dir, 512) == 0);
  fmsc_volume_read(&h->ctx, sim_lba(guid), back);
  CHECK(memcmp(back, g, 512) == 0);
  finish(h, &s);
}

static void test_slack_bytes(void) {
  host_t *h = mk();
  sim_t s;
  CHECK(sim_mount(&s, h));
  const uint32_t size = 1000;
  uint8_t img[1000];
  make_image(img, size, 160, false);
  const uint32_t c = sim_alloc(&s, 1);
  sim_write_file(&s, c, img, size, true);  // 4096 bytes on the wire
  sim_flush_fat(&s, false, false);
  sim_add_entry(&s, NULL, "SMALL   PNG", 0x20, c, size);
  sim_flush_root(&s);
  CHECK_EQ(scsi_sync(h), 0);
  CHECK(completed_with(h, 1, img, size));
  CHECK(host_stream(h, 1)->len >= size);
  finish(h, &s);
}

// Dump the volume after a realistic session, for fsck_msdos / fsck.vfat.
static int dump_session(const char *path) {
  host_t *h = mk();
  sim_t s;
  if (!sim_mount(&s, h)) return 2;
  const uint32_t size = 20000;
  uint8_t img[20000];
  make_image(img, size, 170, false);
  const uint32_t c = sim_alloc(&s, nclusters(size));
  sim_add_entry(&s, "Mon QR code.png", "MONQRC~1PNG", 0x20, c, size);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  sim_write_file(&s, c, img, size, false);
  const uint32_t dcl = sim_alloc(&s, 1);
  uint8_t dir[4096];
  memset(dir, 0, sizeof dir);
  memcpy(dir, ".          ", 11);
  dir[11] = 0x10;
  dir[26] = (uint8_t)dcl;
  memcpy(dir + 32, "..         ", 11);
  dir[43] = 0x10;
  sim_write(&s, sim_lba(dcl), 8, dir);
  sim_add_entry(&s, "Dossier", "DOSSIER    ", 0x10, dcl, 0);
  sim_flush_fat(&s, false, false);
  sim_flush_root(&s);
  (void)scsi_sync(h);
  FILE *f = fopen(path, "wb");
  if (f == NULL) return 2;
  uint8_t sec[512];
  for (uint32_t lba = 0; lba < FMSC_TOTAL_SECTORS; lba++) {
    fmsc_volume_read(&h->ctx, lba, sec);
    if (fwrite(sec, 1, 512, f) != 512) return 2;
  }
  fclose(f);
  const int ok = h->n_completed == 1 && h->violations == 0;
  sim_unmount(&s);
  host_free(h);
  return ok ? 0 : 1;
}

int main(int argc, char **argv) {
  if (argc == 3 && strcmp(argv[1], "--dump-session") == 0) {
    return dump_session(argv[2]);
  }
  RUN(test_windows_metadata_first);
  RUN(test_windows_data_first_quiet);
  RUN(test_macos_sequence);
  RUN(test_linux_writeback_two_files);
  RUN(test_lfn_names);
  RUN(test_multiple_sequential);
  RUN(test_overwrite_after_complete);
  RUN(test_linux_overwrite_bigger_stale_entry);
  RUN(test_overwrite_mid_transfer);
  RUN(test_delete_before_complete);
  RUN(test_too_large);
  RUN(test_fragmented);
  RUN(test_fat_entry_straddling_sectors);
  RUN(test_out_of_order_within_budget);
  RUN(test_out_of_order_beyond_budget);
  RUN(test_missing_data_settle);
  RUN(test_quiet_needs_metadata);
  RUN(test_eject_paths);
  RUN(test_bus_reset_mid_transfer);
  RUN(test_consumer_busy);
  RUN(test_overlapping_streams);
  RUN(test_subdirectory);
  RUN(test_windows_junk);
  RUN(test_slack_bytes);
  return t_finish("test_tracker");
}
