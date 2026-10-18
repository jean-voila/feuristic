// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// fmsc -- USB Mass Storage logic of the temporary "Importer un QR /
// Restaurer" mode (cahier des charges §3.3, architecture §4/§5).
//
// The device enumerates as an MSC-only device (Bulk-Only Transport, one LUN)
// exposing a small *virtual* FAT12 volume. The host copies PNG/JPEG images
// onto it; image data is NOT stored: it is handed to a consumer (the streaming
// image decoder, lib/fimg) *while it is being written*, and the consumer is
// told when the file has been completely written and synchronised.
//
// Layers (all in this library, all unprivileged):
//   * BOT transport  (USB MSC Bulk-Only Transport 1.0, 64-byte packets)
//   * SCSI           (SPC-4/SBC-3 subset used by Windows, macOS and Linux)
//   * virtual FAT12  (generated boot sector / FAT / root directory)
//   * stream tracker (detects image writes, forwards them, detects completion)
//
// Conventions
// -----------
// * Freestanding C99, no allocation, no recursion. The caller owns every
//   byte of memory: the fmsc_ctx_t (about 11 KiB, see FMSC_CTX_RAM_BYTES in
//   docs/developer/lib-fmsc.md) plus optional cache and reorder buffers.
// * Single-threaded. Every entry point must be called from the same thread.
// * Callbacks are invoked synchronously from inside the entry points. They
//   must be short and must NOT call back into fmsc, with one exception:
//   fmsc_on_in_ready() may be called from inside send_in() (it is deferred).
//   Any other re-entrant call is ignored and counted in fmsc_stats_t.
// * All multi-byte protocol fields are decoded byte-wise (no unaligned
//   access, no type punning).
//
// Glue contract (kernel MSC class + coreapp module)
// -------------------------------------------------
//   OUT packet received            -> fmsc_on_out_packet()
//   IN packet consumed by the host -> fmsc_on_in_ready()
//   CLEAR_FEATURE(ENDPOINT_HALT)   -> fmsc_on_clear_halt()
//   Bulk-Only Mass Storage Reset   -> fmsc_bot_reset()   (also on USB bus reset)
//   Get Max LUN                    -> answer fmsc_get_max_lun() (always 0)
//   periodically (>= every 100 ms) -> fmsc_poll(now_ms)
//   cb.send_in(): queue one IN packet (<= 64 bytes, copied by the glue).
//       fmsc never calls it again before fmsc_on_in_ready().
//   cb.stall(ep): set ENDPOINT_HALT on the bulk IN or OUT endpoint.

#ifndef FMSC_H
#define FMSC_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// Volume geometry (fixed; see docs/developer/lib-fmsc.md "Volume layout")
// ---------------------------------------------------------------------------

#define FMSC_SECTOR_SIZE 512u
#define FMSC_PACKET_SIZE 64u
#define FMSC_SECTORS_PER_CLUSTER 8u
#define FMSC_CLUSTER_SIZE (FMSC_SECTOR_SIZE * FMSC_SECTORS_PER_CLUSTER)  // 4096
// 4080 data clusters: below the Microsoft FAT12 limit (< 4085) *and* the
// BSD/macOS fsck_msdos limit (clusters + 2 < 4086).
#define FMSC_CLUSTER_COUNT 4080u
#define FMSC_FIRST_CLUSTER 2u
#define FMSC_LAST_CLUSTER (FMSC_FIRST_CLUSTER + FMSC_CLUSTER_COUNT - 1u)  // 4081
#define FMSC_RESERVED_SECTORS 1u
#define FMSC_NUM_FATS 2u
#define FMSC_FAT_SECTORS 12u  // ceil((4082 * 1.5) / 512)
#define FMSC_FAT_BYTES (FMSC_FAT_SECTORS * FMSC_SECTOR_SIZE)
#define FMSC_ROOT_ENTRIES 64u
#define FMSC_ROOT_SECTORS 4u  // 64 * 32 / 512
#define FMSC_ROOT_BYTES (FMSC_ROOT_SECTORS * FMSC_SECTOR_SIZE)
#define FMSC_FAT1_LBA 1u
#define FMSC_FAT2_LBA (FMSC_FAT1_LBA + FMSC_FAT_SECTORS)   // 13
#define FMSC_ROOT_LBA (FMSC_FAT2_LBA + FMSC_FAT_SECTORS)   // 25
#define FMSC_DATA_LBA (FMSC_ROOT_LBA + FMSC_ROOT_SECTORS)  // 29
#define FMSC_TOTAL_SECTORS \
  (FMSC_DATA_LBA + FMSC_CLUSTER_COUNT * FMSC_SECTORS_PER_CLUSTER)  // 32669

/// FAT volume label (11 bytes, space padded). The spec name
/// "FEURISTIC-IMPORT" (16 chars) does not fit the FAT 8.3 label field; it is
/// used verbatim as the SCSI INQUIRY product string instead.
#define FMSC_VOLUME_LABEL "FEURISTIC  "
#define FMSC_INQUIRY_VENDOR "FEURISTC"           // 8 chars
#define FMSC_INQUIRY_PRODUCT "FEURISTIC-IMPORT"  // 16 chars

/// Pre-created files: cluster of the `.fseventsd` directory and of README.TXT.
#define FMSC_FSEVENTSD_CLUSTER 2u
#define FMSC_README_CLUSTER 3u

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Largest accepted image file (spec §3.3: 256 KiB).
#define FMSC_MAX_FILE_SIZE (256u * 1024u)
#define FMSC_MAX_FILE_SECTORS (FMSC_MAX_FILE_SIZE / FMSC_SECTOR_SIZE)  // 512
/// README.TXT is at most one cluster.
#define FMSC_README_MAX FMSC_CLUSTER_SIZE
/// Upper bound of the caller-provided cluster cache (clusters).
#define FMSC_CACHE_MAX_CLUSTERS 16u
/// Upper bound of the caller-provided reorder buffer (sectors).
#define FMSC_REORDER_MAX_SECTORS 64u
/// A sector this many sectors (or fewer) ahead of a stream's frontier is
/// considered an out-of-order piece of that stream.
#define FMSC_REORDER_WINDOW 128u
/// Number of simultaneously tracked streams (one receiving + one waiting
/// for its metadata/synchronisation).
#define FMSC_MAX_STREAMS 2u
/// Longest long file name kept (ASCII-folded; longer names are truncated).
#define FMSC_LONG_NAME_MAX 63u
/// Longest VPD page 0x80 unit serial number.
#define FMSC_SERIAL_MAX 32u

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Return codes of fmsc_init().
typedef enum {
  FMSC_OK = 0,
  FMSC_ERR_PARAM = -1,  ///< NULL pointer, size above a limit, bad string
} fmsc_status_t;

/// Bulk endpoints of the MSC interface.
typedef enum {
  FMSC_EP_IN = 0,
  FMSC_EP_OUT = 1,
} fmsc_ep_t;

/// Session events (cb.event).
typedef enum {
  /// START STOP UNIT with LoEj=1, Start=0 accepted. Emitted after the CSW
  /// has been consumed by the host, so the glue may tear the interface down
  /// right away. The medium stays absent until the next fmsc_init().
  FMSC_EVT_EJECTED = 1,
  /// START STOP UNIT with LoEj=0, Start=0 (e.g. udisks "power off"). The
  /// unit reports NOT READY until a START. Policy is the application's.
  FMSC_EVT_STOPPED = 2,
  /// fmsc_bot_reset() was called (Bulk-Only reset / bus reset).
  FMSC_EVT_HOST_RESET = 3,
} fmsc_event_t;

/// Why a stream was abandoned (cb.stream_error). A stream that received an
/// error never completes; its id is never reused.
typedef enum {
  FMSC_SERR_BUSY = 1,         ///< cb.stream_start() refused it
  FMSC_SERR_SUPERSEDED = 2,   ///< evicted by newer streams before completion
  FMSC_SERR_OVERWRITTEN = 3,  ///< its first sector was rewritten (new stream)
  FMSC_SERR_REWRITE = 4,      ///< already-delivered data rewritten, differs
  FMSC_SERR_GAP = 5,          ///< out-of-order data beyond the reorder budget
  FMSC_SERR_TOO_LARGE = 6,    ///< directory entry size > FMSC_MAX_FILE_SIZE
  FMSC_SERR_FRAGMENTED = 7,   ///< FAT chain not contiguous
  FMSC_SERR_MISSING_DATA = 8, ///< metadata complete but bytes never written
  FMSC_SERR_DELETED = 9,      ///< its directory entry was deleted
  FMSC_SERR_INCOMPLETE = 10,  ///< medium ejected before completion
} fmsc_stream_error_t;

/// Name of a completed file.
typedef struct {
  char short_name[13];                      ///< "IMG_0001.PNG", NUL-terminated
  char long_name[FMSC_LONG_NAME_MAX + 1u];  ///< ASCII-folded LFN or ""
} fmsc_file_name_t;

/// Callbacks. `user` is passed back unchanged. Only send_in and stall are
/// mandatory; a NULL optional callback is a no-op (stream_start NULL =
/// accept every stream).
typedef struct {
  void *user;
  /// Queue one bulk IN packet (1..64 bytes). The glue copies it.
  void (*send_in)(void *user, const uint8_t *data, size_t len);
  /// Halt (STALL) a bulk endpoint until the host clears it.
  void (*stall)(void *user, fmsc_ep_t ep);
  /// A new image stream begins. Return false to refuse it (e.g. the decoder
  /// is still busy with another stream): the stream then gets
  /// FMSC_SERR_BUSY and its data is dropped.
  bool (*stream_start)(void *user, uint32_t stream_id);
  /// Next bytes of a stream, strictly in order, without gaps, offsets
  /// starting at 0. Delivered in whole sectors: the final bytes may extend
  /// past the file size (sector/cluster slack, or data of an unrelated file
  /// written contiguously before the metadata). The size passed to
  /// stream_complete() is authoritative; bytes at or past it must be
  /// ignored. offset + len never exceeds FMSC_MAX_FILE_SIZE.
  void (*stream_data)(void *user, uint32_t stream_id, uint32_t offset,
                      const uint8_t *data, size_t len);
  /// The file is completely written and synchronised: a live directory entry
  /// references the stream's first cluster with size 1..FMSC_MAX_FILE_SIZE,
  /// the FAT chain is contiguous and terminated, every byte [0, size) was
  /// delivered, and a SYNCHRONIZE CACHE / quiet period / eject occurred
  /// afterwards. Emitted at most once per stream id.
  void (*stream_complete)(void *user, uint32_t stream_id,
                          const fmsc_file_name_t *name, uint32_t size);
  /// The stream is abandoned (see fmsc_stream_error_t).
  void (*stream_error)(void *user, uint32_t stream_id,
                       fmsc_stream_error_t reason);
  /// Session event (see fmsc_event_t).
  void (*event)(void *user, fmsc_event_t ev);
} fmsc_callbacks_t;

/// Session configuration. Pointed-to memory must stay valid until
/// fmsc_wipe(); fmsc_wipe() zeroizes the cache and reorder buffers.
typedef struct {
  /// Cluster cache for non-image data written by the host (directories of
  /// new subfolders, .DS_Store, "System Volume Information", ...):
  /// cache_clusters * FMSC_CLUSTER_SIZE bytes, 0..FMSC_CACHE_MAX_CLUSTERS.
  uint8_t *cache_mem;
  size_t cache_clusters;
  /// Reorder buffer for out-of-order image sectors:
  /// reorder_sectors * FMSC_SECTOR_SIZE bytes, 0..FMSC_REORDER_MAX_SECTORS.
  uint8_t *reorder_mem;
  size_t reorder_sectors;
  /// README.TXT content (0..FMSC_README_MAX bytes, may be NULL if 0).
  const uint8_t *readme;
  size_t readme_len;
  /// FAT volume serial number (BPB_VolID).
  uint32_t volume_id;
  /// VPD 0x80 unit serial number: printable ASCII, <= FMSC_SERIAL_MAX
  /// chars, NUL-terminated; NULL means "0". Avoid device-unique values.
  const char *serial;
  /// INQUIRY product revision: printable ASCII, <= 4 chars; NULL = "0001".
  const char *revision;
  /// No write for this long completes a ready stream (0 = disabled; then
  /// only SYNCHRONIZE CACHE or eject complete). Suggested: 2000.
  uint32_t quiet_ms;
  /// No write for this long makes "fragmented" / "missing data" verdicts
  /// final (0 = only at SYNCHRONIZE CACHE / eject). Suggested: 15000.
  uint32_t settle_ms;
} fmsc_config_t;

/// Diagnostic counters (never reset except by fmsc_init()).
typedef struct {
  uint32_t invalid_cbw;          ///< CBW not valid (signature/length)
  uint32_t phase_errors;         ///< CSWs sent with status 2
  uint32_t discarded_packets;    ///< OUT packets received in a wrong state
  uint32_t reentrant_calls;      ///< ignored re-entrant API calls
  uint32_t fat_mirror_diverged;  ///< FAT2 sector written != FAT1 sector
  uint32_t cache_evictions;      ///< cached clusters evicted
  uint32_t cache_dropped;        ///< non-image writes that could not be kept
  uint32_t streams_started;
  uint32_t streams_completed;
  uint32_t streams_failed;
} fmsc_stats_t;

// ---------------------------------------------------------------------------
// Context (allocate statically; treat every field as private)
// ---------------------------------------------------------------------------

/// @cond PRIVATE
typedef struct {
  uint32_t id;         // 0 = free slot
  uint32_t start_lba;  // first sector (cluster aligned)
  uint32_t next_lba;   // frontier: first sector not delivered yet
  uint32_t file_size;  // from the directory entry (when entry_seen)
  uint16_t start_cluster;
  uint8_t receiving;   // accepts sectors at its frontier
  uint8_t entry_seen;  // a live (non-stale) directory entry was matched
  uint8_t stale;       // a finished file's entry referenced start_cluster
  uint32_t stale_size; // ... with this size when the stream started
  fmsc_file_name_t name;
  uint16_t sum[FMSC_MAX_FILE_SECTORS];  // checksum of each delivered sector
} fmsc_stream_t;

typedef struct {
  uint32_t lba;
  uint8_t used;
} fmsc_reorder_slot_t;

typedef struct {
  uint32_t stamp;  // LRU clock
  uint16_t cluster;
  uint8_t used;
  uint8_t is_dir;  // sector 0 starts with a "." directory entry
} fmsc_cache_slot_t;

typedef struct fmsc_ctx {
  // configuration
  fmsc_callbacks_t cb;
  uint8_t *cache_mem;
  uint8_t *reorder_mem;
  const uint8_t *readme;
  uint16_t readme_len;
  uint8_t cache_n;
  uint8_t reorder_n;
  uint32_t volume_id;
  uint32_t quiet_ms;
  uint32_t settle_ms;
  char serial[FMSC_SERIAL_MAX + 1u];
  char revision[4];

  // volume
  uint8_t fat[FMSC_FAT_BYTES];
  uint8_t root[FMSC_ROOT_BYTES];
  uint16_t fat1_written;  // bit k: FAT1 sector k written since FAT2 sector k
  uint8_t gen_valid;      // bit0: .fseventsd cluster, bit1: README cluster
  uint32_t cache_clock;
  fmsc_cache_slot_t cache[FMSC_CACHE_MAX_CLUSTERS];

  // tracker
  fmsc_stream_t st[FMSC_MAX_STREAMS];
  fmsc_reorder_slot_t ro[FMSC_REORDER_MAX_SECTORS];
  uint16_t foreign[4];
  uint8_t foreign_pos;
  uint16_t done_cluster[4];  // start clusters of finished streams ...
  uint32_t done_size[4];     // ... and their last known file sizes
  uint8_t done_pos;
  uint8_t skip_active;
  uint32_t skip_next;
  uint32_t next_stream_id;
  uint32_t now_ms;
  uint32_t last_write_ms;
  uint8_t quiet_done;
  uint8_t settle_done;
  uint8_t meta_dirty;

  // SCSI
  uint8_t sense_key;
  uint8_t sense_asc;
  uint8_t sense_ascq;
  uint8_t ua_pending;
  uint8_t prevent;
  uint8_t medium;          // 0 ready, 1 stopped, 2 ejected
  uint8_t pending_events;  // emitted once the CSW is consumed

  // BOT
  uint8_t state;
  uint8_t in_busy;
  uint8_t depth;
  uint8_t csw_sent;
  uint8_t cbw_flags;
  uint8_t cb_len;
  uint8_t cdb[16];
  uint32_t tag;
  uint32_t h_remaining;  // bytes left of dCBWDataTransferLength
  uint32_t d_remaining;  // bytes left of the device's intended transfer
  uint8_t x_dir;         // device intent: 0 none, 1 in, 2 out
  uint8_t x_status;      // SCSI status for the CSW (0 good, 1 failed)
  uint8_t x_src;         // data-in source: 0 buffer, 1 sectors
  uint32_t x_len;        // device intended length
  uint32_t x_lba;        // READ/WRITE current LBA
  uint16_t buf_pos;
  uint16_t buf_len;
  uint8_t buf[FMSC_SECTOR_SIZE];
  uint8_t csw[13];

  fmsc_stats_t stats;
} fmsc_ctx_t;
/// @endcond

// ---------------------------------------------------------------------------
// API
// ---------------------------------------------------------------------------

/// Initialise a session: zeroes `ctx`, builds the FAT, the root directory and
/// sets a pending UNIT ATTENTION (power-on reset). The BOT engine expects a
/// CBW. The IN endpoint is assumed idle.
/// @return FMSC_OK, or FMSC_ERR_PARAM (ctx left zeroed).
fmsc_status_t fmsc_init(fmsc_ctx_t *ctx, const fmsc_config_t *cfg,
                        const fmsc_callbacks_t *cb);

/// One bulk OUT packet (0..64 bytes) from the host.
void fmsc_on_out_packet(fmsc_ctx_t *ctx, const uint8_t *pkt, size_t len);

/// The previously queued IN packet was consumed; the next one may be queued.
void fmsc_on_in_ready(fmsc_ctx_t *ctx);

/// The host cleared ENDPOINT_HALT on a bulk endpoint.
void fmsc_on_clear_halt(fmsc_ctx_t *ctx, fmsc_ep_t ep);

/// Time base for the quiet/settle completion rules. `now_ms` is a free
/// running millisecond counter (wrap-around safe). Writes are timestamped
/// with the last value passed here.
void fmsc_poll(fmsc_ctx_t *ctx, uint32_t now_ms);

/// Bulk-Only Mass Storage Reset (class request 0xFF) or USB bus reset:
/// aborts the current command and waits for a CBW. The glue flushes the
/// endpoints. Streams are kept (hosts retry the interrupted command).
void fmsc_bot_reset(fmsc_ctx_t *ctx);

/// Get Max LUN (class request 0xFE): always 0 (one logical unit).
uint8_t fmsc_get_max_lun(void);

/// True once the medium was ejected (START STOP UNIT LoEj).
bool fmsc_is_ejected(const fmsc_ctx_t *ctx);

/// Read one 512-byte sector of the virtual volume as the host would see it
/// (diagnostics, emulator, tests). lba >= FMSC_TOTAL_SECTORS yields zeros.
void fmsc_volume_read(fmsc_ctx_t *ctx, uint32_t lba, uint8_t out[512]);

/// Copy the diagnostic counters.
void fmsc_get_stats(const fmsc_ctx_t *ctx, fmsc_stats_t *out);

/// Zeroize all session state: the context, the cache and the reorder buffer.
/// No callback is invoked. The context must be re-initialised before reuse.
void fmsc_wipe(fmsc_ctx_t *ctx);

#ifdef __cplusplus
}
#endif

#endif  // FMSC_H
