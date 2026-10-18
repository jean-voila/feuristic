// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Host-OS write-pattern simulator: a host-side model of the FAT12 volume
// (its own FAT and root directory copies, loaded through SCSI READ(10)) and
// primitives to emit the write sequences of Windows, macOS and Linux through
// SCSI WRITE(10) commands on the fake USB host.

#ifndef FMSC_HOST_SIM_H
#define FMSC_HOST_SIM_H

#include <stdbool.h>
#include <stdint.h>

#include "fat_reader.h"
#include "tharness.h"

typedef struct {
  host_t *h;
  fr_vol_t fr;
  uint8_t fat[FMSC_FAT_BYTES];
  uint8_t fat_flushed[FMSC_FAT_BYTES];
  uint8_t root[FMSC_ROOT_BYTES];
  uint8_t root_flushed[FMSC_ROOT_BYTES];
  uint16_t max_cmd_sectors;  // WRITE(10) chunking (Linux 240, Windows 128)
} sim_t;

/// Mount: read the boot sector, FAT and root directory over SCSI.
bool sim_mount(sim_t *s, host_t *h);
void sim_unmount(sim_t *s);

uint32_t sim_lba(uint32_t cluster);
uint32_t sim_fat_get(const sim_t *s, uint32_t c);
void sim_fat_set(sim_t *s, uint32_t c, uint32_t v);
/// First-fit contiguous allocation of n clusters (chain + EOC in the model).
uint32_t sim_alloc(sim_t *s, uint32_t n);
/// Explicit chain (for fragmented files).
void sim_chain(sim_t *s, const uint32_t *list, uint32_t n);
void sim_free_chain(sim_t *s, uint32_t start);

/// Add a root directory entry (+ LFN when long_name != NULL). `short11` is
/// the 11-byte 8.3 name. Returns the index of the short entry.
int sim_add_entry(sim_t *s, const char *long_name, const char *short11,
                  uint8_t attr, uint32_t cluster, uint32_t size);
void sim_set_entry(sim_t *s, int idx, uint32_t cluster, uint32_t size);
void sim_delete_entry(sim_t *s, int idx);

/// Write the changed FAT sectors: FAT1 then FAT2 (or FAT2 first), one
/// command per sector or all sectors of a copy in one command (`merged`).
void sim_flush_fat(sim_t *s, bool fat2_first, bool merged);
void sim_flush_root(sim_t *s);
/// Write `count` sectors from `data`, chunked by max_cmd_sectors.
void sim_write(sim_t *s, uint32_t lba, uint32_t count, const uint8_t *data);
/// Write a file's data at `cluster` (contiguous); `whole_clusters` pads the
/// last cluster like a page-cache writeback.
void sim_write_file(sim_t *s, uint32_t cluster, const uint8_t *data,
                    uint32_t size, bool whole_clusters);

/// Deterministic fake image: PNG/JPEG signature + pseudo-random bytes. Bytes
/// at cluster boundaries are forced to 0x42 so that no accidental signature
/// or marker appears at a cluster start.
void make_image(uint8_t *buf, uint32_t size, uint32_t seed, bool jpeg);

#endif  // FMSC_HOST_SIM_H
