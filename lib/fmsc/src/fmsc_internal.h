// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Internal interfaces between the fmsc layers. Not part of the public API.

#ifndef FMSC_INTERNAL_H
#define FMSC_INTERNAL_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "fmsc.h"

// --- byte helpers ----------------------------------------------------------

static inline uint16_t fmsc_le16(const uint8_t *p) {
  return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}
static inline uint32_t fmsc_le32(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}
static inline uint16_t fmsc_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}
static inline uint32_t fmsc_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}
static inline void fmsc_put_le16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
}
static inline void fmsc_put_le32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}
static inline void fmsc_put_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}
static inline void fmsc_put_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

/// Zeroize memory in a way the compiler cannot elide.
void fmsc_secure_zero(void *p, size_t n);

// --- geometry helpers --------------------------------------------------------

static inline uint32_t fmsc_cluster_lba(uint32_t cluster) {
  return FMSC_DATA_LBA + (cluster - FMSC_FIRST_CLUSTER) * FMSC_SECTORS_PER_CLUSTER;
}
static inline uint16_t fmsc_lba_cluster(uint32_t lba) {
  return (uint16_t)(FMSC_FIRST_CLUSTER +
                    (lba - FMSC_DATA_LBA) / FMSC_SECTORS_PER_CLUSTER);
}
static inline uint32_t fmsc_lba_sector_in_cluster(uint32_t lba) {
  return (lba - FMSC_DATA_LBA) % FMSC_SECTORS_PER_CLUSTER;
}

// --- SCSI medium state -------------------------------------------------------

#define FMSC_MEDIUM_READY 0u
#define FMSC_MEDIUM_STOPPED 1u
#define FMSC_MEDIUM_EJECTED 2u

// --- volume (fmsc_volume.c) --------------------------------------------------

/// Build the FAT and the root directory.
void fmsc_vol_init(fmsc_ctx_t *ctx);
/// Read a sector of the virtual volume (lba < FMSC_TOTAL_SECTORS).
void fmsc_vol_read(fmsc_ctx_t *ctx, uint32_t lba, uint8_t *out);
/// Host write of one sector (lba < FMSC_TOTAL_SECTORS).
void fmsc_vol_write(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *data);
/// FAT12 entry of `cluster` from the RAM FAT copy.
uint16_t fmsc_fat_get(const fmsc_ctx_t *ctx, uint32_t cluster);
/// Non-image data sector: keep it in the cluster cache when possible.
void fmsc_cache_write(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *data);
/// Forget a cached cluster (it now belongs to an image stream).
void fmsc_cache_invalidate(fmsc_ctx_t *ctx, uint16_t cluster);
/// Cached directory-like cluster number `i` (0..cache_n-1) or NULL.
const uint8_t *fmsc_cache_dir_cluster(const fmsc_ctx_t *ctx, size_t i);

// --- tracker (fmsc_tracker.c) ------------------------------------------------

typedef enum {
  FMSC_TRIG_NONE = 0,  // metadata changed: record entries, early errors
  FMSC_TRIG_SYNC,      // SYNCHRONIZE CACHE
  FMSC_TRIG_QUIET,     // quiet period elapsed (positive outcome only)
  FMSC_TRIG_SETTLE,    // settle period elapsed (negative verdicts final)
  FMSC_TRIG_EJECT,     // medium ejected: complete or abandon everything
} fmsc_trigger_t;

/// A data-area sector written by the host.
void fmsc_trk_data_sector(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *data);
/// Any host write to the volume (timestamps the quiet/settle timers).
void fmsc_trk_note_write(fmsc_ctx_t *ctx);
/// End of a WRITE(10) command (or its abort).
void fmsc_trk_write_end(fmsc_ctx_t *ctx);
/// Evaluate every stream for completion.
void fmsc_trk_evaluate(fmsc_ctx_t *ctx, fmsc_trigger_t trig);
/// Quiet / settle timers.
void fmsc_trk_poll(fmsc_ctx_t *ctx);

// --- SCSI (fmsc_scsi.c) ------------------------------------------------------

#define FMSC_XDIR_NONE 0u
#define FMSC_XDIR_IN 1u
#define FMSC_XDIR_OUT 2u
#define FMSC_XSRC_BUF 0u
#define FMSC_XSRC_SECTORS 1u

#define FMSC_PENDING_EJECTED 0x01u
#define FMSC_PENDING_STOPPED 0x02u

/// Execute the CDB in ctx->cdb. Sets x_dir, x_len, x_status, x_src, x_lba
/// and, for buffered data-in, buf/buf_len.
void fmsc_scsi_execute(fmsc_ctx_t *ctx);

#endif  // FMSC_INTERNAL_H
