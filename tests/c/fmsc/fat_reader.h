// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Minimal, independent FAT12/16 reader used to validate the virtual volume
// produced by lib/fmsc. Written from the Microsoft FAT specification; it does
// not share code with the library under test.

#ifndef FMSC_FAT_READER_H
#define FMSC_FAT_READER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef void (*fr_read_fn)(void *user, uint32_t lba, uint8_t *out512);

typedef struct {
  fr_read_fn read;
  void *user;
  // BPB
  uint32_t bytes_per_sector, sectors_per_cluster, reserved, num_fats;
  uint32_t root_entries, total_sectors, fat_size;
  uint32_t fat_lba, root_lba, data_lba, cluster_count;
  int fat_bits;  // 12 or 16 by the cluster-count rule
  uint32_t volume_id;
  char label[12];
  char fs_type[9];
  uint8_t *fat;    // FAT1 (fat_size sectors)
  uint8_t *fat2;   // FAT2
  uint8_t *root;   // root directory
  char error[128];
} fr_vol_t;

typedef struct {
  char short_name[13];
  char long_name[256];
  uint8_t attr;
  uint32_t cluster;
  uint32_t size;
} fr_entry_t;

/// Parse and validate the boot sector, load both FATs and the root dir.
/// Returns false with fr->error set on any inconsistency.
bool fr_mount(fr_vol_t *fr, fr_read_fn read, void *user);
void fr_unmount(fr_vol_t *fr);
uint32_t fr_fat_get(const fr_vol_t *fr, uint32_t cluster);
/// Live entries of a directory buffer (LFN assembled). Returns the count.
int fr_list(const fr_vol_t *fr, const uint8_t *dir, size_t entries, fr_entry_t *out,
            int max);
/// Read a whole directory cluster chain into `buf` (max bytes); returns bytes.
size_t fr_read_chain(const fr_vol_t *fr, uint32_t cluster, uint8_t *buf, size_t max);
/// Verify that every allocated chain terminates and no cluster is shared.
bool fr_check_chains(fr_vol_t *fr);

#endif  // FMSC_FAT_READER_H
