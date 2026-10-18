// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// USB Mass Storage Class Bulk-Only Transport 1.0 engine and public entry
// points. Packet level: one 64-byte bulk packet at a time in each direction.
//
// State machine (see docs/developer/lib-fmsc.md):
//
//   IDLE --valid CBW--> DATA_OUT --all data--> CSW --CSW consumed--> IDLE
//        |              DATA_IN  --all data--> CSW
//        |                       --short (Hi>Di)--> WAIT_CLEAR_IN --clear--> CSW
//        |--CBW not valid--> NEED_RESET --fmsc_bot_reset()--> IDLE

#include <string.h>

#include "fmsc_internal.h"

#define BOT_IDLE 0u
#define BOT_DATA_OUT 1u
#define BOT_DATA_IN 2u
#define BOT_WAIT_CLEAR_IN 3u
#define BOT_CSW 4u
#define BOT_NEED_RESET 5u

#define CBW_SIGNATURE 0x43425355u
#define CSW_SIGNATURE 0x53425355u
#define CBW_LEN 31u
#define CSW_LEN 13u
#define CSW_PHASE_ERROR 2u

// --- helpers ---------------------------------------------------------------

static void do_stall(fmsc_ctx_t *ctx, fmsc_ep_t ep) { ctx->cb.stall(ctx->cb.user, ep); }

static void prepare_csw(fmsc_ctx_t *ctx, uint8_t status, uint32_t residue) {
  fmsc_put_le32(ctx->csw, CSW_SIGNATURE);
  fmsc_put_le32(ctx->csw + 4, ctx->tag);
  fmsc_put_le32(ctx->csw + 8, residue);
  ctx->csw[12] = status;
  ctx->csw_sent = 0;
  if (status == CSW_PHASE_ERROR) {
    ctx->stats.phase_errors++;
  }
}

// CSW right away (the IN pipe is not halted).
static void csw_now(fmsc_ctx_t *ctx, uint8_t status, uint32_t residue) {
  prepare_csw(ctx, status, residue);
  ctx->state = BOT_CSW;
}

// Halt IN; the CSW follows once the host has cleared the halt.
static void csw_after_in_stall(fmsc_ctx_t *ctx, uint8_t status, uint32_t residue) {
  prepare_csw(ctx, status, residue);
  ctx->state = BOT_WAIT_CLEAR_IN;
  do_stall(ctx, FMSC_EP_IN);
}

// Halt OUT and queue the CSW on IN.
static void csw_after_out_stall(fmsc_ctx_t *ctx, uint8_t status, uint32_t residue) {
  do_stall(ctx, FMSC_EP_OUT);
  csw_now(ctx, status, residue);
}

static void emit_pending_events(fmsc_ctx_t *ctx) {
  const uint8_t ev = ctx->pending_events;
  ctx->pending_events = 0;
  if (ctx->cb.event == NULL) {
    return;
  }
  if (ev & FMSC_PENDING_STOPPED) {
    ctx->cb.event(ctx->cb.user, FMSC_EVT_STOPPED);
  }
  if (ev & FMSC_PENDING_EJECTED) {
    ctx->cb.event(ctx->cb.user, FMSC_EVT_EJECTED);
  }
}

static void enter_need_reset(fmsc_ctx_t *ctx) {
  ctx->stats.invalid_cbw++;
  ctx->state = BOT_NEED_RESET;
  do_stall(ctx, FMSC_EP_IN);
  do_stall(ctx, FMSC_EP_OUT);
}

// Push IN packets while the endpoint is free.
static void pump(fmsc_ctx_t *ctx) {
  while (!ctx->in_busy) {
    if (ctx->state == BOT_DATA_IN) {
      if (ctx->d_remaining == 0u) {
        if (ctx->h_remaining > 0u) {
          // Case 5 (Hi > Di) or 4 with data: halt IN, residue in the CSW.
          csw_after_in_stall(ctx, ctx->x_status, ctx->h_remaining);
          return;
        }
        csw_now(ctx, ctx->x_status, 0);
        continue;
      }
      size_t avail;
      if (ctx->x_src == FMSC_XSRC_SECTORS) {
        if (ctx->buf_pos >= FMSC_SECTOR_SIZE) {
          fmsc_vol_read(ctx, ctx->x_lba++, ctx->buf);
          ctx->buf_pos = 0;
        }
        avail = FMSC_SECTOR_SIZE - ctx->buf_pos;
      } else {
        avail = (size_t)ctx->buf_len - ctx->buf_pos;
      }
      size_t n = FMSC_PACKET_SIZE;
      if (n > ctx->d_remaining) {
        n = ctx->d_remaining;
      }
      if (n > avail) {
        n = avail;
      }
      if (n == 0u) {  // defensive: inconsistent source, end the data phase
        ctx->d_remaining = 0;
        continue;
      }
      const uint8_t *p = ctx->buf + ctx->buf_pos;
      ctx->buf_pos = (uint16_t)(ctx->buf_pos + n);
      ctx->d_remaining -= (uint32_t)n;
      ctx->h_remaining -= (uint32_t)n;
      ctx->in_busy = 1;
      ctx->cb.send_in(ctx->cb.user, p, n);
    } else if (ctx->state == BOT_CSW) {
      if (!ctx->csw_sent) {
        ctx->csw_sent = 1;
        ctx->in_busy = 1;
        ctx->cb.send_in(ctx->cb.user, ctx->csw, CSW_LEN);
      } else {
        ctx->state = BOT_IDLE;
        ctx->csw_sent = 0;
        emit_pending_events(ctx);
        return;
      }
    } else {
      return;
    }
  }
}

// BOT §6.7: reconcile the host's expectation (h bytes, direction) with the
// device's intent (ctx->x_dir / x_len) -- the thirteen cases.
static void reconcile(fmsc_ctx_t *ctx, uint32_t h, bool host_in) {
  const uint32_t d = ctx->x_len;
  const uint8_t dir = d == 0u ? (uint8_t)FMSC_XDIR_NONE : ctx->x_dir;
  ctx->h_remaining = h;
  ctx->d_remaining = 0;
  if (h == 0u) {
    if (dir == FMSC_XDIR_NONE) {
      csw_now(ctx, ctx->x_status, 0);  // case 1
    } else {
      csw_now(ctx, CSW_PHASE_ERROR, 0);  // cases 2, 3
    }
  } else if (host_in) {
    if (dir == FMSC_XDIR_OUT || (dir == FMSC_XDIR_IN && d > h)) {
      csw_after_in_stall(ctx, CSW_PHASE_ERROR, h);  // cases 8, 7
    } else if (dir == FMSC_XDIR_NONE) {
      csw_after_in_stall(ctx, ctx->x_status, h);  // case 4
    } else {
      ctx->state = BOT_DATA_IN;  // cases 5, 6
      ctx->d_remaining = d;
    }
  } else {
    if (dir == FMSC_XDIR_IN || (dir == FMSC_XDIR_OUT && d > h)) {
      csw_after_out_stall(ctx, CSW_PHASE_ERROR, h);  // cases 10, 13
    } else if (dir == FMSC_XDIR_NONE) {
      csw_after_out_stall(ctx, ctx->x_status, h);  // case 9
    } else {
      ctx->state = BOT_DATA_OUT;  // cases 11, 12
      ctx->d_remaining = d;
      ctx->buf_pos = 0;
    }
  }
}

static void handle_cbw(fmsc_ctx_t *ctx, const uint8_t *pkt, size_t len) {
  if (len != CBW_LEN || fmsc_le32(pkt) != CBW_SIGNATURE) {
    enter_need_reset(ctx);  // §6.6.1 CBW not valid
    return;
  }
  ctx->tag = fmsc_le32(pkt + 4);
  const uint32_t h = fmsc_le32(pkt + 8);
  const uint8_t flags = pkt[12];
  const uint8_t lun = pkt[13];
  const uint8_t cblen = pkt[14];
  const bool host_in = (flags & 0x80u) != 0u;
  ctx->cbw_flags = flags;
  const bool meaningful = (flags & 0x7Fu) == 0u && lun == 0u && cblen >= 1u &&
                          cblen <= 16u;
  if (!meaningful) {
    // Valid but not meaningful (reserved bits, LUN != 0, CB length): phase
    // error, which makes the host perform a reset recovery.
    ctx->h_remaining = h;
    if (h == 0u) {
      csw_now(ctx, CSW_PHASE_ERROR, 0);
    } else if (host_in) {
      csw_after_in_stall(ctx, CSW_PHASE_ERROR, h);
    } else {
      csw_after_out_stall(ctx, CSW_PHASE_ERROR, h);
    }
    return;
  }
  memset(ctx->cdb, 0, sizeof ctx->cdb);
  memcpy(ctx->cdb, pkt + 15, cblen);
  ctx->cb_len = cblen;
  fmsc_scsi_execute(ctx);
  reconcile(ctx, h, host_in);
}

static void handle_data_out(fmsc_ctx_t *ctx, const uint8_t *pkt, size_t len) {
  const uint32_t take = len > ctx->h_remaining ? ctx->h_remaining : (uint32_t)len;
  const uint32_t use = take > ctx->d_remaining ? ctx->d_remaining : take;
  uint32_t off = 0;
  while (off < use) {
    uint32_t chunk = FMSC_SECTOR_SIZE - ctx->buf_pos;
    if (chunk > use - off) {
      chunk = use - off;
    }
    memcpy(ctx->buf + ctx->buf_pos, pkt + off, chunk);
    ctx->buf_pos = (uint16_t)(ctx->buf_pos + chunk);
    off += chunk;
    if (ctx->buf_pos == FMSC_SECTOR_SIZE) {
      fmsc_vol_write(ctx, ctx->x_lba++, ctx->buf);
      ctx->buf_pos = 0;
    }
  }
  ctx->d_remaining -= use;
  ctx->h_remaining -= take;
  if (ctx->d_remaining == 0u) {
    fmsc_trk_write_end(ctx);
    fmsc_secure_zero(ctx->buf, sizeof ctx->buf);
    if (ctx->h_remaining > 0u) {
      csw_after_out_stall(ctx, ctx->x_status, ctx->h_remaining);  // case 11
    } else {
      csw_now(ctx, ctx->x_status, 0);  // case 12
    }
  } else if (len < FMSC_PACKET_SIZE) {
    // Short packet: the host ended its transfer before the length it
    // announced. The partial sector is dropped.
    fmsc_trk_write_end(ctx);
    fmsc_secure_zero(ctx->buf, sizeof ctx->buf);
    ctx->buf_pos = 0;
    csw_now(ctx, CSW_PHASE_ERROR, ctx->h_remaining);
  }
}

static bool enter(fmsc_ctx_t *ctx) {
  if (ctx->depth != 0u) {
    ctx->stats.reentrant_calls++;
    return false;
  }
  ctx->depth = 1;
  return true;
}

static void leave(fmsc_ctx_t *ctx) { ctx->depth = 0; }

static bool printable(const char *s, size_t max) {
  size_t n = 0;
  while (s[n] != '\0') {
    if (n >= max || s[n] < 0x20 || s[n] > 0x7E) {
      return false;
    }
    n++;
  }
  return true;
}

// --- public API --------------------------------------------------------------

fmsc_status_t fmsc_init(fmsc_ctx_t *ctx, const fmsc_config_t *cfg,
                        const fmsc_callbacks_t *cb) {
  if (ctx == NULL) {
    return FMSC_ERR_PARAM;
  }
  fmsc_secure_zero(ctx, sizeof *ctx);
  if (cfg == NULL || cb == NULL || cb->send_in == NULL || cb->stall == NULL) {
    return FMSC_ERR_PARAM;
  }
  if (cfg->cache_clusters > FMSC_CACHE_MAX_CLUSTERS ||
      (cfg->cache_clusters > 0u && cfg->cache_mem == NULL) ||
      cfg->reorder_sectors > FMSC_REORDER_MAX_SECTORS ||
      (cfg->reorder_sectors > 0u && cfg->reorder_mem == NULL) ||
      cfg->readme_len > FMSC_README_MAX ||
      (cfg->readme_len > 0u && cfg->readme == NULL)) {
    return FMSC_ERR_PARAM;
  }
  const char *serial = cfg->serial != NULL ? cfg->serial : "0";
  const char *rev = cfg->revision != NULL ? cfg->revision : "0001";
  if (!printable(serial, FMSC_SERIAL_MAX) || serial[0] == '\0' ||
      !printable(rev, 4)) {
    return FMSC_ERR_PARAM;
  }
  ctx->cb = *cb;
  ctx->cache_mem = cfg->cache_mem;
  ctx->cache_n = (uint8_t)cfg->cache_clusters;
  ctx->reorder_mem = cfg->reorder_mem;
  ctx->reorder_n = (uint8_t)cfg->reorder_sectors;
  ctx->readme = cfg->readme;
  ctx->readme_len = (uint16_t)cfg->readme_len;
  ctx->volume_id = cfg->volume_id;
  ctx->quiet_ms = cfg->quiet_ms;
  ctx->settle_ms = cfg->settle_ms;
  memcpy(ctx->serial, serial, strlen(serial));
  memset(ctx->revision, ' ', sizeof ctx->revision);
  memcpy(ctx->revision, rev, strlen(rev));
  if (ctx->cache_n > 0u) {
    fmsc_secure_zero(ctx->cache_mem, (size_t)ctx->cache_n * FMSC_CLUSTER_SIZE);
  }
  if (ctx->reorder_n > 0u) {
    fmsc_secure_zero(ctx->reorder_mem, (size_t)ctx->reorder_n * FMSC_SECTOR_SIZE);
  }
  fmsc_vol_init(ctx);
  ctx->ua_pending = 1;
  ctx->next_stream_id = 1;
  ctx->quiet_done = 1;
  ctx->settle_done = 1;
  ctx->state = BOT_IDLE;
  return FMSC_OK;
}

void fmsc_on_out_packet(fmsc_ctx_t *ctx, const uint8_t *pkt, size_t len) {
  if (ctx == NULL || (pkt == NULL && len > 0u) || !enter(ctx)) {
    return;
  }
  if (len > FMSC_PACKET_SIZE) {
    // The kernel class never delivers more: treat as a transport violation.
    if (ctx->state != BOT_NEED_RESET) {
      enter_need_reset(ctx);
    } else {
      ctx->stats.discarded_packets++;
    }
  } else if (ctx->state == BOT_IDLE) {
    handle_cbw(ctx, pkt, len);
  } else if (ctx->state == BOT_DATA_OUT) {
    handle_data_out(ctx, pkt, len);
  } else {
    // NEED_RESET, or stray data after an OUT halt / during data-in or CSW:
    // a well-behaved host never sends these; drop them.
    ctx->stats.discarded_packets++;
  }
  pump(ctx);
  leave(ctx);
}

void fmsc_on_in_ready(fmsc_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  ctx->in_busy = 0;
  if (ctx->depth != 0u) {
    return;  // called from send_in(): the running pump() continues
  }
  ctx->depth = 1;
  pump(ctx);
  leave(ctx);
}

void fmsc_on_clear_halt(fmsc_ctx_t *ctx, fmsc_ep_t ep) {
  if (ctx == NULL || !enter(ctx)) {
    return;
  }
  if (ctx->state == BOT_NEED_RESET) {
    do_stall(ctx, ep);  // §6.6.1: stay halted until a reset recovery
  } else if (ctx->state == BOT_WAIT_CLEAR_IN && ep == FMSC_EP_IN) {
    ctx->state = BOT_CSW;
    ctx->csw_sent = 0;
    pump(ctx);
  }
  leave(ctx);
}

void fmsc_poll(fmsc_ctx_t *ctx, uint32_t now_ms) {
  if (ctx == NULL || !enter(ctx)) {
    return;
  }
  ctx->now_ms = now_ms;
  if (ctx->medium != FMSC_MEDIUM_EJECTED) {
    fmsc_trk_poll(ctx);
  }
  leave(ctx);
}

void fmsc_bot_reset(fmsc_ctx_t *ctx) {
  if (ctx == NULL || !enter(ctx)) {
    return;
  }
  if (ctx->state == BOT_DATA_OUT) {
    fmsc_trk_write_end(ctx);
  }
  ctx->state = BOT_IDLE;
  ctx->in_busy = 0;
  ctx->csw_sent = 0;
  ctx->buf_pos = 0;
  ctx->buf_len = 0;
  ctx->h_remaining = 0;
  ctx->d_remaining = 0;
  ctx->x_len = 0;
  ctx->x_dir = FMSC_XDIR_NONE;
  fmsc_secure_zero(ctx->buf, sizeof ctx->buf);
  emit_pending_events(ctx);
  if (ctx->cb.event != NULL) {
    ctx->cb.event(ctx->cb.user, FMSC_EVT_HOST_RESET);
  }
  leave(ctx);
}

uint8_t fmsc_get_max_lun(void) { return 0u; }

bool fmsc_is_ejected(const fmsc_ctx_t *ctx) {
  return ctx != NULL && ctx->medium == FMSC_MEDIUM_EJECTED;
}

void fmsc_get_stats(const fmsc_ctx_t *ctx, fmsc_stats_t *out) {
  if (ctx != NULL && out != NULL) {
    *out = ctx->stats;
  }
}

void fmsc_wipe(fmsc_ctx_t *ctx) {
  if (ctx == NULL) {
    return;
  }
  if (ctx->depth != 0u) {
    ctx->stats.reentrant_calls++;  // never free state under a running call
    return;
  }
  if (ctx->cache_mem != NULL && ctx->cache_n > 0u) {
    fmsc_secure_zero(ctx->cache_mem, (size_t)ctx->cache_n * FMSC_CLUSTER_SIZE);
  }
  if (ctx->reorder_mem != NULL && ctx->reorder_n > 0u) {
    fmsc_secure_zero(ctx->reorder_mem, (size_t)ctx->reorder_n * FMSC_SECTOR_SIZE);
  }
  fmsc_secure_zero(ctx, sizeof *ctx);
}
