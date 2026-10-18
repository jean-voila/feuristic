// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Test harness for lib/fmsc: a tiny check framework and a fake USB host that
// drives the BOT engine packet by packet, records every callback and checks
// the engine's endpoint discipline.

#ifndef FMSC_THARNESS_H
#define FMSC_THARNESS_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "fmsc.h"

// --- check framework
// -----------------------------------------------------------

extern int t_failures;
extern int t_checks;

#define CHECK(c)                                                            \
  do {                                                                      \
    t_checks++;                                                             \
    if (!(c)) {                                                             \
      t_failures++;                                                         \
      fprintf(stderr, "%s:%d: CHECK failed: %s\n", __FILE__, __LINE__, #c); \
    }                                                                       \
  } while (0)

#define CHECK_EQ(a, b)                                                     \
  do {                                                                     \
    const long long t_a_ = (long long)(a);                                 \
    const long long t_b_ = (long long)(b);                                 \
    t_checks++;                                                            \
    if (t_a_ != t_b_) {                                                    \
      t_failures++;                                                        \
      fprintf(stderr, "%s:%d: CHECK_EQ failed: %s == %s (%lld vs %lld)\n", \
              __FILE__, __LINE__, #a, #b, t_a_, t_b_);                     \
    }                                                                      \
  } while (0)

#define RUN(fn)                     \
  do {                              \
    fprintf(stderr, "  %s\n", #fn); \
    fn();                           \
  } while (0)

int t_finish(const char *suite);

// --- fake host
// -------------------------------------------------------------------

#define HOST_MAX_STREAMS 64
#define HOST_STALL (-1)
#define HOST_NODATA (-2)

typedef struct {
  bool started;
  bool completed;
  bool errored;
  int terminal_events;  // complete + error callbacks (must be <= 1)
  fmsc_stream_error_t error;
  uint32_t size;
  fmsc_file_name_t name;
  uint8_t *data;  // FMSC_MAX_FILE_SIZE bytes
  uint32_t len;   // contiguous bytes received
  bool order_violation;
} rec_stream_t;

typedef struct {
  // configuration (set before host_open)
  size_t cache_clusters;
  size_t reorder_sectors;
  uint32_t quiet_ms;
  uint32_t settle_ms;
  const char *readme;
  bool refuse_streams;

  fmsc_ctx_t ctx;
  uint8_t cache_mem[FMSC_CACHE_MAX_CLUSTERS * FMSC_CLUSTER_SIZE];
  uint8_t reorder_mem[FMSC_REORDER_MAX_SECTORS * FMSC_SECTOR_SIZE];

  uint8_t in_pkt[64];
  size_t in_len;
  bool in_pending;
  bool stalled[2];
  int violations;  // engine broke the endpoint discipline
  uint32_t tag;
  uint32_t now;

  rec_stream_t streams[HOST_MAX_STREAMS];
  int n_started, n_completed, n_errors;
  int events[64];
  int n_events;
} host_t;

typedef struct {
  bool csw_ok;       // a well-formed 13-byte CSW with matching tag arrived
  uint8_t status;    // bCSWStatus
  uint32_t residue;  // dCSWDataResidue
  uint32_t got;      // data-in bytes received
  bool in_stalled;   // IN halted during the transfer
  bool out_stalled;  // OUT halted during the transfer
} xfer_t;

/// Allocate + configure (defaults: 4 cache clusters, 16 reorder sectors,
/// quiet 2000 ms, settle 15000 ms).
host_t *host_new(void);
/// Initialise the fmsc context with the host's configuration.
void host_open(host_t *h);
/// Clear the power-on UNIT ATTENTION like a real host (TUR + REQUEST SENSE).
void host_clear_ua(host_t *h);
void host_free(host_t *h);

/// Read one IN packet: length, HOST_STALL or HOST_NODATA.
int host_read_in(host_t *h, uint8_t *buf);
/// Send one OUT packet (returns false when OUT is halted).
bool host_send_out(host_t *h, const uint8_t *pkt, size_t len);
void host_clear_halt(host_t *h, fmsc_ep_t ep);
/// Bulk-Only reset + clear both halts.
void host_reset_recovery(host_t *h);
/// Advance the clock and poll.
void host_advance(host_t *h, uint32_t ms);

/// Full BOT transaction. `xfer_len` is dCBWDataTransferLength.
xfer_t host_bot(host_t *h, const uint8_t *cdb, uint8_t cdb_len, bool dir_in,
                uint32_t xfer_len, const uint8_t *out_data, uint8_t *in_data);
/// Raw CBW builder (31 bytes).
void host_build_cbw(uint8_t cbw[31], uint32_t tag, uint32_t xfer_len,
                    uint8_t flags, uint8_t lun, uint8_t cb_len,
                    const uint8_t *cdb);

// SCSI helpers (status 0 = GOOD).
int scsi_tur(host_t *h);
int scsi_sense(host_t *h, uint8_t *key, uint8_t *asc, uint8_t *ascq);
int scsi_read10(host_t *h, uint32_t lba, uint16_t count, uint8_t *out);
int scsi_write10(host_t *h, uint32_t lba, uint16_t count, const uint8_t *data);
int scsi_sync(host_t *h);
int scsi_start_stop(host_t *h, bool loej, bool start);
int scsi_prevent(host_t *h, bool prevent);

/// Stream record by id (NULL if out of range).
rec_stream_t *host_stream(host_t *h, uint32_t id);
/// Number of events of the given kind.
int host_count_events(const host_t *h, fmsc_event_t ev);

#endif  // FMSC_THARNESS_H
