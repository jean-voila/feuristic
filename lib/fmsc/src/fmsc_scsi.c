// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// SCSI command set (SPC-4 / SBC-3 subset) of the import volume. Each command
// only *describes* its data phase (direction, length, source); fmsc_bot.c
// reconciles it with the host's expectation (BOT §6.7) and moves the bytes.

#include <string.h>

#include "fmsc_internal.h"

// Operation codes.
#define OP_TEST_UNIT_READY 0x00u
#define OP_REQUEST_SENSE 0x03u
#define OP_INQUIRY 0x12u
#define OP_MODE_SENSE6 0x1Au
#define OP_START_STOP_UNIT 0x1Bu
#define OP_PREVENT_ALLOW 0x1Eu
#define OP_READ_FORMAT_CAPACITIES 0x23u
#define OP_READ_CAPACITY10 0x25u
#define OP_READ10 0x28u
#define OP_WRITE10 0x2Au
#define OP_VERIFY10 0x2Fu
#define OP_SYNCHRONIZE_CACHE10 0x35u
#define OP_MODE_SENSE10 0x5Au

// Sense keys / additional sense codes.
#define SK_NO_SENSE 0x00u
#define SK_NOT_READY 0x02u
#define SK_ILLEGAL_REQUEST 0x05u
#define SK_UNIT_ATTENTION 0x06u
#define ASC_LUN_NOT_READY 0x04u
#define ASCQ_INIT_CMD_REQUIRED 0x02u
#define ASC_INVALID_OPCODE 0x20u
#define ASC_LBA_OUT_OF_RANGE 0x21u
#define ASC_INVALID_FIELD_IN_CDB 0x24u
#define ASC_POWER_ON_RESET 0x29u
#define ASC_SAVING_NOT_SUPPORTED 0x39u
#define ASC_MEDIUM_NOT_PRESENT 0x3Au
#define ASC_REMOVAL_PREVENTED 0x53u
#define ASCQ_REMOVAL_PREVENTED 0x02u

#define STATUS_GOOD 0u
#define STATUS_CHECK 1u

#define MODE_PAGE_CACHING 0x08u
#define MODE_PAGE_ALL 0x3Fu
#define CACHING_PAGE_LEN 20u

static void check(fmsc_ctx_t *ctx, uint8_t key, uint8_t asc, uint8_t ascq) {
  ctx->sense_key = key;
  ctx->sense_asc = asc;
  ctx->sense_ascq = ascq;
  ctx->x_dir = FMSC_XDIR_NONE;
  ctx->x_len = 0;
  ctx->x_status = STATUS_CHECK;
}

static void invalid_field(fmsc_ctx_t *ctx) {
  check(ctx, SK_ILLEGAL_REQUEST, ASC_INVALID_FIELD_IN_CDB, 0);
}

// Data-in from ctx->buf: min(actual, allocation length).
static void respond(fmsc_ctx_t *ctx, size_t actual, uint32_t alloc) {
  const uint32_t n = actual < alloc ? (uint32_t)actual : alloc;
  ctx->buf_len = (uint16_t)n;
  ctx->buf_pos = 0;
  ctx->x_src = FMSC_XSRC_BUF;
  ctx->x_dir = n > 0u ? FMSC_XDIR_IN : FMSC_XDIR_NONE;
  ctx->x_len = n;
}

// Medium-access commands: NOT READY when ejected / stopped.
static bool medium_ready(fmsc_ctx_t *ctx) {
  if (ctx->medium == FMSC_MEDIUM_EJECTED) {
    check(ctx, SK_NOT_READY, ASC_MEDIUM_NOT_PRESENT, 0);
    return false;
  }
  if (ctx->medium == FMSC_MEDIUM_STOPPED) {
    check(ctx, SK_NOT_READY, ASC_LUN_NOT_READY, ASCQ_INIT_CMD_REQUIRED);
    return false;
  }
  return true;
}

static bool lba_range_ok(fmsc_ctx_t *ctx, uint32_t lba, uint32_t count) {
  if (lba >= FMSC_TOTAL_SECTORS || count > FMSC_TOTAL_SECTORS - lba) {
    check(ctx, SK_ILLEGAL_REQUEST, ASC_LBA_OUT_OF_RANGE, 0);
    return false;
  }
  return true;
}

static void pad_copy(uint8_t *dst, const char *src, size_t n) {
  memset(dst, ' ', n);
  const size_t l = strlen(src);
  memcpy(dst, src, l < n ? l : n);
}

static void cmd_inquiry(fmsc_ctx_t *ctx) {
  const uint8_t *cdb = ctx->cdb;
  const uint32_t alloc = fmsc_be16(cdb + 3);
  uint8_t *b = ctx->buf;
  memset(b, 0, 64);
  if ((cdb[1] & 0xFEu) != 0u) {  // CMDDT (obsolete) / reserved bits
    invalid_field(ctx);
    return;
  }
  if ((cdb[1] & 0x01u) == 0u) {
    if (cdb[2] != 0u) {
      invalid_field(ctx);
      return;
    }
    b[0] = 0x00u;  // direct-access block device, LU present
    b[1] = 0x80u;  // removable medium
    b[2] = 0x04u;  // SPC-2
    b[3] = 0x02u;  // response data format 2
    b[4] = 31u;    // additional length (36 - 5)
    pad_copy(b + 8, FMSC_INQUIRY_VENDOR, 8);
    pad_copy(b + 16, FMSC_INQUIRY_PRODUCT, 16);
    memcpy(b + 32, ctx->revision, 4);
    respond(ctx, 36, alloc);
    return;
  }
  switch (cdb[2]) {
    case 0x00u:  // supported VPD pages
      b[1] = 0x00u;
      b[3] = 2u;
      b[4] = 0x00u;
      b[5] = 0x80u;
      respond(ctx, 6, alloc);
      return;
    case 0x80u: {  // unit serial number
      const size_t n = strlen(ctx->serial);
      b[1] = 0x80u;
      b[3] = (uint8_t)n;
      memcpy(b + 4, ctx->serial, n);
      respond(ctx, 4u + n, alloc);
      return;
    }
    default:
      invalid_field(ctx);
      return;
  }
}

static void cmd_request_sense(fmsc_ctx_t *ctx) {
  const uint8_t *cdb = ctx->cdb;
  if ((cdb[1] & 0x01u) != 0u) {  // DESC: descriptor format not supported
    invalid_field(ctx);
    return;
  }
  uint8_t key = ctx->sense_key;
  uint8_t asc = ctx->sense_asc;
  uint8_t ascq = ctx->sense_ascq;
  if (key == SK_NO_SENSE && asc == 0u) {
    if (ctx->ua_pending) {
      ctx->ua_pending = 0;
      key = SK_UNIT_ATTENTION;
      asc = ASC_POWER_ON_RESET;
      ascq = 0;
    } else if (ctx->medium == FMSC_MEDIUM_EJECTED) {
      key = SK_NOT_READY;
      asc = ASC_MEDIUM_NOT_PRESENT;
      ascq = 0;
    } else if (ctx->medium == FMSC_MEDIUM_STOPPED) {
      key = SK_NOT_READY;
      asc = ASC_LUN_NOT_READY;
      ascq = ASCQ_INIT_CMD_REQUIRED;
    }
  }
  uint8_t *b = ctx->buf;
  memset(b, 0, 18);
  b[0] = 0x70u;  // current error, fixed format
  b[2] = key;
  b[7] = 10u;    // additional sense length
  b[12] = asc;
  b[13] = ascq;
  ctx->sense_key = SK_NO_SENSE;
  ctx->sense_asc = 0;
  ctx->sense_ascq = 0;
  respond(ctx, 18, cdb[4]);
}

static void cmd_mode_sense(fmsc_ctx_t *ctx, bool ten) {
  const uint8_t *cdb = ctx->cdb;
  const uint8_t pc = (uint8_t)(cdb[2] >> 6);
  const uint8_t page = (uint8_t)(cdb[2] & 0x3Fu);
  const uint8_t subpage = cdb[3];
  const uint32_t alloc = ten ? fmsc_be16(cdb + 7) : cdb[4];
  if (pc == 3u) {
    check(ctx, SK_ILLEGAL_REQUEST, ASC_SAVING_NOT_SUPPORTED, 0);
    return;
  }
  if ((page != MODE_PAGE_CACHING && page != MODE_PAGE_ALL) ||
      (subpage != 0u && subpage != 0xFFu)) {
    invalid_field(ctx);
    return;
  }
  uint8_t *b = ctx->buf;
  const size_t hdr = ten ? 8u : 4u;
  memset(b, 0, hdr + CACHING_PAGE_LEN);
  uint8_t *p = b + hdr;
  p[0] = MODE_PAGE_CACHING;
  p[1] = CACHING_PAGE_LEN - 2u;
  if (pc != 1u) {    // current / default values; changeable mask is all 0
    p[2] = 0x04u;    // WCE: hosts then send SYNCHRONIZE CACHE on flush
  }
  const size_t total = hdr + CACHING_PAGE_LEN;
  if (ten) {
    fmsc_put_be16(b, (uint16_t)(total - 2u));  // device-specific 0: no WP
  } else {
    b[0] = (uint8_t)(total - 1u);
  }
  respond(ctx, total, alloc);
}

static void cmd_start_stop(fmsc_ctx_t *ctx) {
  const uint8_t *cdb = ctx->cdb;
  const uint8_t power = (uint8_t)(cdb[4] >> 4);
  const bool loej = (cdb[4] & 0x02u) != 0u;
  const bool start = (cdb[4] & 0x01u) != 0u;
  if (power != 0u) {
    return;  // power conditions: accepted, no effect (LOEJ/START ignored)
  }
  if (ctx->medium == FMSC_MEDIUM_EJECTED) {
    if (start) {  // START / LOAD: the medium never comes back
      check(ctx, SK_NOT_READY, ASC_MEDIUM_NOT_PRESENT, 0);
    }
    return;  // repeated eject / stop: idempotent, no new event
  }
  if (start) {
    ctx->medium = FMSC_MEDIUM_READY;  // START (or LOAD of a present medium)
    return;
  }
  if (loej) {
    if (ctx->prevent) {
      check(ctx, SK_ILLEGAL_REQUEST, ASC_REMOVAL_PREVENTED, ASCQ_REMOVAL_PREVENTED);
      return;
    }
    // The host flushed and released the medium: final verdict on streams.
    fmsc_trk_evaluate(ctx, FMSC_TRIG_EJECT);
    ctx->medium = FMSC_MEDIUM_EJECTED;
    ctx->pending_events |= FMSC_PENDING_EJECTED;
    return;
  }
  if (ctx->medium == FMSC_MEDIUM_READY) {
    ctx->medium = FMSC_MEDIUM_STOPPED;
    ctx->pending_events |= FMSC_PENDING_STOPPED;
  }
}

static void cmd_rw10(fmsc_ctx_t *ctx, bool write) {
  const uint8_t *cdb = ctx->cdb;
  if ((cdb[1] >> 5) != 0u) {  // RDPROTECT / WRPROTECT: no protection info
    invalid_field(ctx);
    return;
  }
  if (!medium_ready(ctx)) {
    return;
  }
  const uint32_t lba = fmsc_be32(cdb + 2);
  const uint32_t count = fmsc_be16(cdb + 7);
  if (!lba_range_ok(ctx, lba, count)) {
    return;
  }
  ctx->x_lba = lba;
  ctx->x_len = count * FMSC_SECTOR_SIZE;
  ctx->buf_pos = FMSC_SECTOR_SIZE;  // read: refill before first packet
  ctx->buf_len = FMSC_SECTOR_SIZE;
  ctx->x_src = FMSC_XSRC_SECTORS;
  if (count == 0u) {
    ctx->x_dir = FMSC_XDIR_NONE;
  } else {
    ctx->x_dir = write ? FMSC_XDIR_OUT : FMSC_XDIR_IN;
  }
  if (write) {
    ctx->buf_pos = 0;
  }
}

void fmsc_scsi_execute(fmsc_ctx_t *ctx) {
  const uint8_t *cdb = ctx->cdb;
  const uint8_t op = cdb[0];
  ctx->x_dir = FMSC_XDIR_NONE;
  ctx->x_len = 0;
  ctx->x_status = STATUS_GOOD;
  ctx->x_src = FMSC_XSRC_BUF;

  if (op != OP_REQUEST_SENSE) {
    ctx->sense_key = SK_NO_SENSE;
    ctx->sense_asc = 0;
    ctx->sense_ascq = 0;
  }

  size_t need;
  switch (op) {
    case OP_TEST_UNIT_READY:
    case OP_REQUEST_SENSE:
    case OP_INQUIRY:
    case OP_MODE_SENSE6:
    case OP_START_STOP_UNIT:
    case OP_PREVENT_ALLOW:
      need = 6;
      break;
    case OP_READ_FORMAT_CAPACITIES:
    case OP_READ_CAPACITY10:
    case OP_READ10:
    case OP_WRITE10:
    case OP_VERIFY10:
    case OP_SYNCHRONIZE_CACHE10:
    case OP_MODE_SENSE10:
      need = 10;
      break;
    default:
      check(ctx, SK_ILLEGAL_REQUEST, ASC_INVALID_OPCODE, 0);
      return;
  }
  if (ctx->cb_len < need) {
    invalid_field(ctx);
    return;
  }
  if ((cdb[need - 1u] & 0x04u) != 0u) {  // NACA not supported
    invalid_field(ctx);
    return;
  }
  if (ctx->ua_pending && op != OP_INQUIRY && op != OP_REQUEST_SENSE) {
    ctx->ua_pending = 0;
    check(ctx, SK_UNIT_ATTENTION, ASC_POWER_ON_RESET, 0);
    return;
  }

  switch (op) {
    case OP_TEST_UNIT_READY:
      (void)medium_ready(ctx);
      return;
    case OP_REQUEST_SENSE:
      cmd_request_sense(ctx);
      return;
    case OP_INQUIRY:
      cmd_inquiry(ctx);
      return;
    case OP_MODE_SENSE6:
      cmd_mode_sense(ctx, false);
      return;
    case OP_MODE_SENSE10:
      cmd_mode_sense(ctx, true);
      return;
    case OP_START_STOP_UNIT:
      cmd_start_stop(ctx);
      return;
    case OP_PREVENT_ALLOW:
      ctx->prevent = (uint8_t)(cdb[4] & 0x01u);
      return;
    case OP_READ_FORMAT_CAPACITIES: {
      if (!medium_ready(ctx)) {
        return;
      }
      uint8_t *b = ctx->buf;
      memset(b, 0, 12);
      b[3] = 8u;  // capacity list length
      fmsc_put_be32(b + 4, FMSC_TOTAL_SECTORS);
      b[8] = 0x02u;  // formatted media
      b[10] = (uint8_t)(FMSC_SECTOR_SIZE >> 8);
      b[11] = (uint8_t)FMSC_SECTOR_SIZE;
      respond(ctx, 12, fmsc_be16(cdb + 7));
      return;
    }
    case OP_READ_CAPACITY10: {
      if ((cdb[8] & 0x01u) == 0u && fmsc_be32(cdb + 2) != 0u) {
        invalid_field(ctx);  // LBA must be 0 when PMI = 0
        return;
      }
      if (!medium_ready(ctx)) {
        return;
      }
      fmsc_put_be32(ctx->buf, FMSC_TOTAL_SECTORS - 1u);
      fmsc_put_be32(ctx->buf + 4, FMSC_SECTOR_SIZE);
      respond(ctx, 8, 8);
      return;
    }
    case OP_READ10:
      cmd_rw10(ctx, false);
      return;
    case OP_WRITE10:
      cmd_rw10(ctx, true);
      return;
    case OP_VERIFY10: {
      if ((cdb[1] >> 5) != 0u || (cdb[1] & 0x06u) != 0u) {
        invalid_field(ctx);  // VRPROTECT / BYTCHK: data not kept, cannot compare
        return;
      }
      if (!medium_ready(ctx)) {
        return;
      }
      (void)lba_range_ok(ctx, fmsc_be32(cdb + 2), fmsc_be16(cdb + 7));
      return;
    }
    case OP_SYNCHRONIZE_CACHE10: {
      if (!medium_ready(ctx)) {
        return;
      }
      const uint32_t lba = fmsc_be32(cdb + 2);
      const uint32_t count = fmsc_be16(cdb + 7);
      if (lba >= FMSC_TOTAL_SECTORS || count > FMSC_TOTAL_SECTORS - lba) {
        check(ctx, SK_ILLEGAL_REQUEST, ASC_LBA_OUT_OF_RANGE, 0);
        return;
      }
      fmsc_trk_evaluate(ctx, FMSC_TRIG_SYNC);
      return;
    }
    default:
      return;  // not reached: filtered above
  }
}
