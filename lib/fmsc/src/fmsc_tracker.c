// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Import stream tracker: detects image files in the stream of host sector
// writes, forwards their bytes in order to the consumer and decides when a
// file is completely written and synchronised. See docs/developer/lib-fmsc.md
// ("Tracker algorithm") for the rationale of every rule below.

#include <string.h>

#include "fmsc_internal.h"

#define ATTR_VOLUME 0x08u
#define ATTR_DIR 0x10u
#define ATTR_LFN_MASK 0x3Fu
#define ATTR_LFN 0x0Fu
#define FAT_EOC_MIN 0xFF8u
#define LFN_MAX_ORDINAL 20u

typedef enum { CHAIN_OK, CHAIN_PENDING, CHAIN_FRAGMENTED } chain_t;

// --- content classification ------------------------------------------------

// 16-bit fold of FNV-1a over a sector. Only used to recognise identical
// rewrites of already-delivered sectors (bus-reset retries); the host controls
// the data anyway, so this is not a security boundary.
static uint16_t sector_sum(const uint8_t *d) {
  uint32_t h = 2166136261u;
  for (size_t i = 0; i < FMSC_SECTOR_SIZE; i++) {
    h ^= d[i];
    h *= 16777619u;
  }
  return (uint16_t)(h ^ (h >> 16));
}

static bool is_image_signature(const uint8_t *d) {
  static const uint8_t png[8] = {0x89u, 0x50u, 0x4Eu, 0x47u,
                                 0x0Du, 0x0Au, 0x1Au, 0x0Au};
  if (memcmp(d, png, sizeof png) == 0) {
    return true;
  }
  return d[0] == 0xFFu && d[1] == 0xD8u && d[2] == 0xFFu;  // JPEG SOI + marker
}

// First sector of a cluster that certainly does not belong to an image:
// AppleDouble/AppleSingle (macOS "._name"), .DS_Store ("Bud1"), OLE compound
// file (Thumbs.db), or the "." entry of a new directory.
static bool is_foreign_marker(const uint8_t *d) {
  static const uint8_t dsstore[8] = {0x00u, 0x00u, 0x00u, 0x01u,
                                     0x42u, 0x75u, 0x64u, 0x31u};
  static const uint8_t ole[8] = {0xD0u, 0xCFu, 0x11u, 0xE0u,
                                 0xA1u, 0xB1u, 0x1Au, 0xE1u};
  if (d[0] == 0x00u && d[1] == 0x05u && d[2] == 0x16u &&
      (d[3] == 0x07u || d[3] == 0x00u) && d[4] == 0x00u &&
      (d[5] == 0x01u || d[5] == 0x02u) && d[6] == 0x00u && d[7] == 0x00u) {
    return true;
  }
  if (memcmp(d, dsstore, 8) == 0 || memcmp(d, ole, 8) == 0) {
    return true;
  }
  static const char dot[] = ".          ";
  return memcmp(d, dot, 11) == 0 && (d[11] & ATTR_DIR) != 0u;
}

// --- small helpers -----------------------------------------------------------

static bool foreign_has(const fmsc_ctx_t *ctx, uint16_t c) {
  for (size_t i = 0; i < 4u; i++) {
    if (ctx->foreign[i] == c) {
      return true;
    }
  }
  return false;
}

static void foreign_add(fmsc_ctx_t *ctx, uint16_t c) {
  if (!foreign_has(ctx, c)) {
    ctx->foreign[ctx->foreign_pos] = c;
    ctx->foreign_pos = (uint8_t)((ctx->foreign_pos + 1u) & 3u);
  }
}

static void foreign_remove(fmsc_ctx_t *ctx, uint16_t c) {
  for (size_t i = 0; i < 4u; i++) {
    if (ctx->foreign[i] == c) {
      ctx->foreign[i] = 0;
    }
  }
}

static fmsc_stream_t *receiving_stream(fmsc_ctx_t *ctx) {
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    if (ctx->st[i].id != 0u && ctx->st[i].receiving) {
      return &ctx->st[i];
    }
  }
  return NULL;
}

static bool any_stream(const fmsc_ctx_t *ctx) {
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    if (ctx->st[i].id != 0u) {
      return true;
    }
  }
  return false;
}

static void reorder_clear(fmsc_ctx_t *ctx) {
  for (size_t i = 0; i < ctx->reorder_n; i++) {
    if (ctx->ro[i].used) {
      fmsc_secure_zero(ctx->reorder_mem + i * FMSC_SECTOR_SIZE,
                       FMSC_SECTOR_SIZE);
      ctx->ro[i].used = 0;
      ctx->ro[i].lba = 0;
    }
  }
}

static void stop_receiving(fmsc_ctx_t *ctx, fmsc_stream_t *st) {
  if (st->receiving) {
    st->receiving = 0;
    reorder_clear(ctx);
  }
}

// Remember where a finished stream lived: a later stream on the same
// cluster may meet that file's directory entry before its own (overwrite).
static void remember_finished(fmsc_ctx_t *ctx, const fmsc_stream_t *st) {
  if (st->entry_seen || st->stale) {
    ctx->done_cluster[ctx->done_pos] = st->start_cluster;
    ctx->done_size[ctx->done_pos] = st->file_size;
    ctx->done_pos = (uint8_t)((ctx->done_pos + 1u) & 3u);
  }
}

static bool finished_match(const fmsc_ctx_t *ctx, uint16_t cluster,
                           uint32_t size) {
  for (size_t i = 0; i < 4u; i++) {
    if (ctx->done_cluster[i] == cluster && ctx->done_size[i] == size) {
      return true;
    }
  }
  return false;
}

static void stream_free(fmsc_ctx_t *ctx, fmsc_stream_t *st) {
  stop_receiving(ctx, st);
  remember_finished(ctx, st);
  fmsc_secure_zero(st, sizeof *st);
}

static void stream_fail(fmsc_ctx_t *ctx, fmsc_stream_t *st,
                        fmsc_stream_error_t reason) {
  const uint32_t id = st->id;
  const bool was_receiving = st->receiving != 0u;
  const uint32_t frontier = st->next_lba;
  stream_free(ctx, st);
  if (was_receiving) {
    // Swallow the rest of its contiguous writes instead of thrashing the
    // cluster cache with image data.
    ctx->skip_active = 1;
    ctx->skip_next = frontier;
  }
  ctx->stats.streams_failed++;
  if (ctx->cb.stream_error != NULL) {
    ctx->cb.stream_error(ctx->cb.user, id, reason);
  }
}

static uint32_t stream_limit(const fmsc_stream_t *st) {
  uint32_t lim = st->start_lba + FMSC_MAX_FILE_SECTORS;
  if (lim > FMSC_TOTAL_SECTORS) {
    lim = FMSC_TOTAL_SECTORS;
  }
  return lim;
}

// --- directory parsing
// ---------------------------------------------------------

static uint8_t lfn_checksum(const uint8_t *name11) {
  uint8_t sum = 0;
  for (size_t i = 0; i < 11u; i++) {
    sum =
        (uint8_t)((uint8_t)((sum & 1u) << 7) + (uint8_t)(sum >> 1) + name11[i]);
  }
  return sum;
}

static char fold_char(uint16_t ch, bool lower) {
  if (ch < 0x20u || ch > 0x7Eu) {
    return '?';
  }
  if (lower && ch >= 'A' && ch <= 'Z') {
    ch = (uint16_t)(ch + ('a' - 'A'));
  }
  return (char)ch;
}

static void format_short_name(const uint8_t *e, char out[13]) {
  size_t o = 0;
  size_t base_len = 8;
  while (base_len > 0u && e[base_len - 1u] == ' ') {
    base_len--;
  }
  size_t ext_len = 3;
  while (ext_len > 0u && e[8u + ext_len - 1u] == ' ') {
    ext_len--;
  }
  const bool lower_base = (e[12] & 0x08u) != 0u;
  const bool lower_ext = (e[12] & 0x10u) != 0u;
  for (size_t i = 0; i < base_len; i++) {
    const uint8_t ch = (i == 0u && e[0] == 0x05u) ? 0xE5u : e[i];
    out[o++] = fold_char(ch, lower_base);
  }
  if (ext_len > 0u) {
    out[o++] = '.';
    for (size_t i = 0; i < ext_len; i++) {
      out[o++] = fold_char(e[8u + i], lower_ext);
    }
  }
  out[o] = '\0';
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

// Long name of the short entry at index `idx` of `buf`, from the LFN entries
// physically preceding it in the same buffer. Malformed sets yield "".
static void extract_long_name(const uint8_t *buf, size_t idx, char *out) {
  char tmp[FMSC_LONG_NAME_MAX + 1u];
  memset(tmp, 0, sizeof tmp);
  out[0] = '\0';
  const uint8_t csum = lfn_checksum(buf + 32u * idx);
  size_t ord = 1;
  size_t j = idx;
  bool done = false;
  bool terminated = false;
  size_t name_len = 0;
  while (j > 0u && ord <= LFN_MAX_ORDINAL) {
    const uint8_t *e = buf + 32u * (j - 1u);
    if ((e[11] & ATTR_LFN_MASK) != ATTR_LFN || e[0] == 0xE5u) {
      break;
    }
    if ((size_t)(e[0] & 0x1Fu) != ord || e[13] != csum) {
      return;
    }
    for (size_t k = 0; k < 13u; k++) {
      const size_t pos = (ord - 1u) * 13u + k;
      const uint16_t ch = fmsc_le16(e + lfn_char_offset(k));
      if (terminated) {
        continue;
      }
      if (ch == 0x0000u || ch == 0xFFFFu) {
        terminated = true;
        name_len = pos;
        continue;
      }
      if (pos < FMSC_LONG_NAME_MAX) {
        tmp[pos] = fold_char(ch, false);
      }
    }
    if (e[0] & 0x40u) {
      done = true;
      break;
    }
    ord++;
    j--;
  }
  if (!done) {
    return;
  }
  if (!terminated) {
    name_len = ord * 13u;
  }
  if (name_len > FMSC_LONG_NAME_MAX) {
    name_len = FMSC_LONG_NAME_MAX;
  }
  memcpy(out, tmp, name_len);
  out[name_len] = '\0';
}

// Scans `n` directory entries for a file whose first cluster is `cluster`.
static bool scan_dir(const uint8_t *buf, size_t n, uint16_t cluster,
                     uint32_t *size, fmsc_file_name_t *name, bool *deleted) {
  for (size_t i = 0; i < n; i++) {
    const uint8_t *e = buf + 32u * i;
    if (e[0] == 0x00u) {
      break;  // end of directory
    }
    const uint8_t attr = e[11];
    if ((attr & ATTR_LFN_MASK) == ATTR_LFN) {
      continue;
    }
    if ((attr & (ATTR_VOLUME | ATTR_DIR)) != 0u) {
      continue;
    }
    if (fmsc_le16(e + 20) != 0u || fmsc_le16(e + 26) != cluster) {
      continue;
    }
    if (e[0] == 0xE5u) {
      *deleted = true;
      continue;
    }
    *size = fmsc_le32(e + 28);
    format_short_name(e, name->short_name);
    extract_long_name(buf, i, name->long_name);
    return true;
  }
  return false;
}

static bool find_entry(const fmsc_ctx_t *ctx, uint16_t cluster, uint32_t *size,
                       fmsc_file_name_t *name, bool *deleted) {
  *deleted = false;
  if (scan_dir(ctx->root, FMSC_ROOT_ENTRIES, cluster, size, name, deleted)) {
    return true;
  }
  for (size_t i = 0; i < ctx->cache_n; i++) {
    const uint8_t *d = fmsc_cache_dir_cluster(ctx, i);
    if (d != NULL &&
        scan_dir(d, FMSC_CLUSTER_SIZE / 32u, cluster, size, name, deleted)) {
      return true;
    }
  }
  return false;
}

static chain_t chain_check(const fmsc_ctx_t *ctx, uint32_t start, uint32_t n) {
  if (start < FMSC_FIRST_CLUSTER || n == 0u ||
      start + n - 1u > FMSC_LAST_CLUSTER) {
    return CHAIN_FRAGMENTED;
  }
  for (uint32_t i = 0; i < n; i++) {
    const uint16_t v = fmsc_fat_get(ctx, start + i);
    if (v == 0u) {
      return CHAIN_PENDING;  // not written yet
    }
    if (i + 1u < n) {
      if (v == start + i + 1u) {
        continue;
      }
      if (v >= FAT_EOC_MIN) {
        return CHAIN_PENDING;  // chain shorter than the size: FAT lags
      }
      return CHAIN_FRAGMENTED;
    }
    if (v >= FAT_EOC_MIN) {
      return CHAIN_OK;
    }
    if (v >= FMSC_FIRST_CLUSTER && v <= FMSC_LAST_CLUSTER) {
      return CHAIN_PENDING;  // chain longer than the size: size lags
    }
    return CHAIN_FRAGMENTED;
  }
  return CHAIN_PENDING;  // not reached
}

// --- completion ------------------------------------------------------------

static void stream_complete(fmsc_ctx_t *ctx, fmsc_stream_t *st) {
  const uint32_t id = st->id;
  const uint32_t size = st->file_size;
  fmsc_file_name_t name = st->name;
  stream_free(ctx, st);
  ctx->stats.streams_completed++;
  if (ctx->cb.stream_complete != NULL) {
    ctx->cb.stream_complete(ctx->cb.user, id, &name, size);
  }
  fmsc_secure_zero(&name, sizeof name);
}

static void eval_stream(fmsc_ctx_t *ctx, fmsc_stream_t *st,
                        fmsc_trigger_t trig) {
  const bool eject = trig == FMSC_TRIG_EJECT;
  const bool decisive =
      trig == FMSC_TRIG_SYNC || trig == FMSC_TRIG_SETTLE || eject;
  fmsc_file_name_t name;
  uint32_t size = 0;
  bool deleted = false;
  memset(&name, 0, sizeof name);

  if (!find_entry(ctx, st->start_cluster, &size, &name, &deleted)) {
    if (st->entry_seen && deleted) {
      stream_fail(ctx, st, FMSC_SERR_DELETED);
    } else if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  // An entry of a previously finished file on the same cluster, unchanged
  // since this stream started, may describe the *previous* file (overwrite
  // with data written before metadata). It may confirm a completion but
  // never justifies a negative verdict.
  const bool stale = st->stale != 0u && size == st->stale_size;
  if (!stale) {
    st->stale = 0;
    st->entry_seen = 1;
  }
  st->file_size = size;
  st->name = name;

  if (size > FMSC_MAX_FILE_SIZE) {
    if (!stale) {
      stream_fail(ctx, st, FMSC_SERR_TOO_LARGE);
    } else if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  if (size == 0u) {
    if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  const uint32_t clusters = (size + FMSC_CLUSTER_SIZE - 1u) / FMSC_CLUSTER_SIZE;
  const chain_t ch = chain_check(ctx, st->start_cluster, clusters);
  if (ch == CHAIN_FRAGMENTED) {
    if (decisive && !stale) {
      stream_fail(ctx, st, FMSC_SERR_FRAGMENTED);
    } else if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  if (ch == CHAIN_PENDING) {
    if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  const uint32_t delivered = (st->next_lba - st->start_lba) * FMSC_SECTOR_SIZE;
  if (delivered < size) {
    if ((trig == FMSC_TRIG_SETTLE || eject) && !stale) {
      stream_fail(ctx, st, FMSC_SERR_MISSING_DATA);
    } else if (eject) {
      stream_fail(ctx, st, FMSC_SERR_INCOMPLETE);
    }
    return;
  }
  if (trig == FMSC_TRIG_NONE) {
    return;
  }
  stream_complete(ctx, st);
}

void fmsc_trk_evaluate(fmsc_ctx_t *ctx, fmsc_trigger_t trig) {
  // Oldest stream first, so that completions are reported in copy order.
  uint32_t ids[FMSC_MAX_STREAMS];
  size_t n = 0;
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    if (ctx->st[i].id != 0u) {
      ids[n++] = ctx->st[i].id;
    }
  }
  for (size_t a = 1; a < n; a++) {
    for (size_t b = a; b > 0u && ids[b - 1u] > ids[b]; b--) {
      const uint32_t t = ids[b];
      ids[b] = ids[b - 1u];
      ids[b - 1u] = t;
    }
  }
  for (size_t k = 0; k < n; k++) {
    for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
      if (ctx->st[i].id == ids[k]) {
        eval_stream(ctx, &ctx->st[i], trig);
        break;
      }
    }
  }
}

// --- data path
// ------------------------------------------------------------------

static void deliver(fmsc_ctx_t *ctx, fmsc_stream_t *st, uint32_t lba,
                    const uint8_t *d) {
  const uint32_t idx = lba - st->start_lba;
  const uint16_t c = fmsc_lba_cluster(lba);
  st->sum[idx] = sector_sum(d);
  st->next_lba = lba + 1u;
  fmsc_cache_invalidate(ctx, c);
  foreign_remove(ctx, c);
  if (ctx->cb.stream_data != NULL) {
    ctx->cb.stream_data(ctx->cb.user, st->id, idx * FMSC_SECTOR_SIZE, d,
                        FMSC_SECTOR_SIZE);
  }
}

static void drain(fmsc_ctx_t *ctx, fmsc_stream_t *st) {
  bool progress = true;
  while (progress && st->id != 0u && st->receiving &&
         st->next_lba < stream_limit(st)) {
    progress = false;
    for (size_t i = 0; i < ctx->reorder_n; i++) {
      if (ctx->ro[i].used && ctx->ro[i].lba == st->next_lba) {
        uint8_t *p = ctx->reorder_mem + i * FMSC_SECTOR_SIZE;
        ctx->ro[i].used = 0;
        deliver(ctx, st, ctx->ro[i].lba, p);
        fmsc_secure_zero(p, FMSC_SECTOR_SIZE);
        ctx->ro[i].lba = 0;
        progress = true;
        break;
      }
    }
  }
}

static bool reorder_put(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *d) {
  int free_slot = -1;
  for (size_t i = 0; i < ctx->reorder_n; i++) {
    if (ctx->ro[i].used && ctx->ro[i].lba == lba) {
      memcpy(ctx->reorder_mem + i * FMSC_SECTOR_SIZE, d, FMSC_SECTOR_SIZE);
      return true;
    }
    if (!ctx->ro[i].used && free_slot < 0) {
      free_slot = (int)i;
    }
  }
  if (free_slot < 0) {
    return false;
  }
  memcpy(ctx->reorder_mem + (size_t)free_slot * FMSC_SECTOR_SIZE, d,
         FMSC_SECTOR_SIZE);
  ctx->ro[free_slot].used = 1;
  ctx->ro[free_slot].lba = lba;
  return true;
}

static void new_stream(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *d) {
  const uint16_t c = fmsc_lba_cluster(lba);
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    if (ctx->st[i].id != 0u && ctx->st[i].start_cluster == c) {
      stream_fail(ctx, &ctx->st[i], FMSC_SERR_OVERWRITTEN);
    }
  }
  ctx->skip_active = 0;
  fmsc_cache_invalidate(ctx, c);
  foreign_remove(ctx, c);

  const uint32_t id = ctx->next_stream_id++;
  if (ctx->next_stream_id == 0u) {
    ctx->next_stream_id = 1u;
  }
  ctx->stats.streams_started++;
  if (ctx->cb.stream_start != NULL && !ctx->cb.stream_start(ctx->cb.user, id)) {
    ctx->stats.streams_failed++;
    ctx->skip_active = 1;
    ctx->skip_next = lba + 1u;
    if (ctx->cb.stream_error != NULL) {
      ctx->cb.stream_error(ctx->cb.user, id, FMSC_SERR_BUSY);
    }
    return;
  }

  fmsc_stream_t *rx = receiving_stream(ctx);
  if (rx != NULL) {
    stop_receiving(ctx, rx);  // it keeps waiting for its metadata
  }
  fmsc_stream_t *slot = NULL;
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    if (ctx->st[i].id == 0u) {
      slot = &ctx->st[i];
      break;
    }
  }
  if (slot == NULL) {
    slot = &ctx->st[0];
    for (size_t i = 1; i < FMSC_MAX_STREAMS; i++) {
      if (ctx->st[i].id < slot->id) {
        slot = &ctx->st[i];
      }
    }
    stream_fail(ctx, slot, FMSC_SERR_SUPERSEDED);
  }
  memset(slot, 0, sizeof *slot);
  slot->id = id;
  slot->start_lba = lba;
  slot->next_lba = lba;
  slot->start_cluster = c;
  slot->receiving = 1;
  {
    uint32_t size = 0;
    bool deleted = false;
    fmsc_file_name_t name;
    if (find_entry(ctx, c, &size, &name, &deleted) &&
        finished_match(ctx, c, size)) {
      slot->stale = 1;
      slot->stale_size = size;
    }
    fmsc_secure_zero(&name, sizeof name);
  }
  deliver(ctx, slot, lba, d);
  // Metadata written before the data (Windows): learn it now, which also
  // reports an oversized file right away.
  eval_stream(ctx, slot, FMSC_TRIG_NONE);
}

void fmsc_trk_data_sector(fmsc_ctx_t *ctx, uint32_t lba, const uint8_t *d) {
  const uint16_t c = fmsc_lba_cluster(lba);
  const uint32_t s = fmsc_lba_sector_in_cluster(lba);

  // 1. Rewrite of already-delivered data (bus-reset retry, overwrite).
  for (size_t i = 0; i < FMSC_MAX_STREAMS; i++) {
    fmsc_stream_t *st = &ctx->st[i];
    if (st->id == 0u || lba < st->start_lba || lba >= st->next_lba) {
      continue;
    }
    if (st->sum[lba - st->start_lba] == sector_sum(d)) {
      return;  // identical: nothing to do
    }
    if (lba == st->start_lba && is_image_signature(d)) {
      new_stream(ctx, lba, d);  // the file was overwritten
      return;
    }
    stream_fail(ctx, st, FMSC_SERR_REWRITE);
    break;  // treat the sector as a fresh write below
  }

  fmsc_stream_t *rx = receiving_stream(ctx);
  // 2. Cluster-start classification.
  if (s == 0u) {
    if (is_image_signature(d)) {
      new_stream(ctx, lba, d);
      return;
    }
    if (is_foreign_marker(d)) {
      foreign_add(ctx, c);
      if (rx != NULL && lba == rx->next_lba) {
        stop_receiving(ctx, rx);  // another file follows: stream data ended
      }
      if (ctx->skip_active && lba == ctx->skip_next) {
        ctx->skip_active = 0;
      }
      fmsc_cache_write(ctx, lba, d);
      return;
    }
  }
  if (foreign_has(ctx, c)) {
    fmsc_cache_write(ctx, lba, d);
    return;
  }
  // 3. Continuation of the receiving stream.
  if (rx != NULL) {
    const uint32_t lim = stream_limit(rx);
    if (lba == rx->next_lba) {
      if (lba < lim) {
        deliver(ctx, rx, lba, d);
        drain(ctx, rx);
        return;
      }
      // Contiguous data beyond FMSC_MAX_FILE_SIZE: stop delivering and wait
      // for the directory entry to tell whether the file is too large.
      stop_receiving(ctx, rx);
      ctx->skip_active = 1;
      ctx->skip_next = lba + 1u;
      return;
    }
    if (lba > rx->next_lba && lba < lim &&
        lba - rx->next_lba <= FMSC_REORDER_WINDOW) {
      if (!reorder_put(ctx, lba, d)) {
        stream_fail(ctx, rx, FMSC_SERR_GAP);
      }
      return;
    }
  }
  // 4. Tail of a refused / failed / oversized stream.
  if (ctx->skip_active && lba == ctx->skip_next) {
    ctx->skip_next++;
    return;
  }
  // 5. Anything else is ordinary (non-image) data.
  fmsc_cache_write(ctx, lba, d);
}

void fmsc_trk_note_write(fmsc_ctx_t *ctx) {
  ctx->last_write_ms = ctx->now_ms;
  ctx->quiet_done = 0;
  ctx->settle_done = 0;
}

void fmsc_trk_write_end(fmsc_ctx_t *ctx) {
  if (ctx->meta_dirty) {
    ctx->meta_dirty = 0;
    fmsc_trk_evaluate(ctx, FMSC_TRIG_NONE);
  }
}

void fmsc_trk_poll(fmsc_ctx_t *ctx) {
  if (!any_stream(ctx)) {
    return;
  }
  const uint32_t elapsed = ctx->now_ms - ctx->last_write_ms;
  if (!ctx->quiet_done && ctx->quiet_ms != 0u && elapsed >= ctx->quiet_ms) {
    ctx->quiet_done = 1;
    fmsc_trk_evaluate(ctx, FMSC_TRIG_QUIET);
  }
  if (!ctx->settle_done && ctx->settle_ms != 0u && elapsed >= ctx->settle_ms) {
    ctx->settle_done = 1;
    fmsc_trk_evaluate(ctx, FMSC_TRIG_SETTLE);
  }
}
