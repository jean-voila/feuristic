// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// libFuzzer target for lib/fmsc: random sequences of raw BOT packets, endpoint
// events, resets, clock ticks and *structured* SCSI transactions (valid CBWs
// carrying crafted FAT / directory / image sectors) so that the stream
// tracker is reached in depth. The harness plays the USB glue and checks the
// engine's contract; any violation traps.
//
// Build (see tests/fuzz/README-fmsc.md):
//   clang -fsanitize=fuzzer,address,undefined -Ilib/fmsc/include
//     tests/fuzz/fmsc_fuzz.c lib/fmsc/src/*.c -o fmsc_fuzz
// With -DFMSC_FUZZ_REPLAY_MAIN=1 a plain main() replays files/directories.

#ifdef FMSC_FUZZ_REPLAY_MAIN
#define _POSIX_C_SOURCE 200809L  // opendir() under -std=c99
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "fmsc.h"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

#define FAIL() __builtin_trap()
#define TRACKED 512u

typedef struct {
  const uint8_t *p;
  size_t n;
} input_t;

static uint8_t take(input_t *in) {
  if (in->n == 0u) return 0;
  in->n--;
  return *in->p++;
}

typedef struct {
  uint8_t started, terminal;
  uint32_t delivered;
} trk_t;

typedef struct {
  fmsc_ctx_t ctx;
  uint8_t cache[4 * FMSC_CLUSTER_SIZE];
  uint8_t reorder[8 * FMSC_SECTOR_SIZE];
  uint8_t pkt[64];
  size_t pkt_len;
  bool pending;
  bool stalled[2];
  bool refuse;
  uint32_t now;
  uint32_t last_id;
  trk_t s[TRACKED];
} fz_t;

static fz_t g;
static unsigned long n_started, n_completed, n_failed;  // replay statistics

// --- glue callbacks with contract checks -------------------------------------

static void f_send_in(void *u, const uint8_t *d, size_t n) {
  fz_t *f = u;
  if (f->pending || n == 0u || n > 64u) FAIL();
  memcpy(f->pkt, d, n);
  f->pkt_len = n;
  f->pending = true;
}

static void f_stall(void *u, fmsc_ep_t ep) {
  fz_t *f = u;
  if (ep != FMSC_EP_IN && ep != FMSC_EP_OUT) FAIL();
  if (ep == FMSC_EP_IN && f->pending) FAIL();
  f->stalled[ep] = true;
}

static trk_t *rec(fz_t *f, uint32_t id) {
  return id - 1u < TRACKED ? &f->s[id - 1u] : NULL;
}

static bool f_start(void *u, uint32_t id) {
  fz_t *f = u;
  if (id <= f->last_id) FAIL();  // ids strictly increase
  f->last_id = id;
  n_started++;
  trk_t *t = rec(f, id);
  if (t != NULL) t->started = 1;
  return !f->refuse;
}

static void f_data(void *u, uint32_t id, uint32_t off, const uint8_t *d,
                   size_t n) {
  fz_t *f = u;
  (void)d;
  trk_t *t = rec(f, id);
  if (n == 0u || (size_t)off + n > FMSC_MAX_FILE_SIZE) FAIL();
  if (t != NULL) {
    if (!t->started || t->terminal || off != t->delivered) FAIL();
    t->delivered += (uint32_t)n;
  }
}

static void f_complete(void *u, uint32_t id, const fmsc_file_name_t *nm,
                       uint32_t size) {
  fz_t *f = u;
  trk_t *t = rec(f, id);
  if (size == 0u || size > FMSC_MAX_FILE_SIZE) FAIL();
  if (memchr(nm->short_name, 0, sizeof nm->short_name) == NULL) FAIL();
  if (memchr(nm->long_name, 0, sizeof nm->long_name) == NULL) FAIL();
  if (t != NULL) {
    if (!t->started || t->terminal || t->delivered < size) FAIL();
    t->terminal = 1;
  }
  n_completed++;
}

static void f_error(void *u, uint32_t id, fmsc_stream_error_t r) {
  fz_t *f = u;
  trk_t *t = rec(f, id);
  if (r < FMSC_SERR_BUSY || r > FMSC_SERR_INCOMPLETE) FAIL();
  if (t != NULL) {
    if (!t->started || t->terminal) FAIL();
    t->terminal = 1;
  }
  n_failed++;
}

static void f_event(void *u, fmsc_event_t ev) {
  (void)u;
  if (ev != FMSC_EVT_EJECTED && ev != FMSC_EVT_STOPPED &&
      ev != FMSC_EVT_HOST_RESET)
    FAIL();
}

// --- host side --------------------------------------------------------------

static int read_in(fz_t *f) {
  if (f->stalled[FMSC_EP_IN]) return -1;
  if (!f->pending) return -2;
  f->pending = false;
  const int n = (int)f->pkt_len;
  fmsc_on_in_ready(&f->ctx);
  return n;
}

static void clear(fz_t *f, fmsc_ep_t ep) {
  f->stalled[ep] = false;
  fmsc_on_clear_halt(&f->ctx, ep);
}

static void put32le(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)v;
  p[1] = (uint8_t)(v >> 8);
  p[2] = (uint8_t)(v >> 16);
  p[3] = (uint8_t)(v >> 24);
}

// Crafted sector content (kinds chosen by the input).
static void make_sector(input_t *in, uint8_t kind, uint32_t seed, uint8_t *s) {
  uint32_t x = seed * 2654435761u + 1u;
  memset(s, 0, 512);
  switch (kind % 8u) {
    case 0:
      break;
    case 1:
    case 2:
    case 3:
      for (size_t i = 0; i < 512; i++) {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        s[i] = (uint8_t)x;
      }
      if (kind % 8u == 1u) {
        const uint8_t png[8] = {0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A};
        memcpy(s, png, 8);
      } else if (kind % 8u == 2u) {
        s[0] = 0xFF;
        s[1] = 0xD8;
        s[2] = 0xFF;
      }
      break;
    case 4: {  // directory sector: entries pointing at hot clusters
      for (size_t e = 0; e < 16; e++) {
        uint8_t *d = s + 32 * e;
        const uint8_t sel = take(in);
        if (sel % 5u == 0u) {  // LFN entry
          d[0] = (uint8_t)((sel >> 3) | 0x40);
          d[11] = 0x0F;
          d[13] = take(in);
          for (size_t k = 1; k < 32; k += 2) d[k] = (uint8_t)('a' + (k % 26));
          continue;
        }
        memcpy(d, "IMG     PNG", 11);
        d[0] = sel % 7u == 1u ? 0xE5 : (uint8_t)('A' + sel % 26u);
        d[11] = (uint8_t)(sel % 3u == 0u ? 0x20 : (sel & 0x3Fu));
        d[12] = take(in);
        const uint16_t c = (uint16_t)(4u + take(in) % 40u);
        d[26] = (uint8_t)c;
        d[27] = (uint8_t)(c >> 8);
        put32le(d + 28, (uint32_t)take(in) * 1100u + take(in));
      }
      break;
    }
    case 5: {  // FAT sector with a contiguous chain (and a twist)
      const uint32_t start = 4u + take(in) % 40u;
      const uint32_t n = 1u + take(in) % 70u;
      for (uint32_t c = 0; c < 341; c++) {
        uint32_t v = 0;
        if (c == 0) v = 0xFF8;
        if (c == 1 || c == 2 || c == 3) v = 0xFFF;
        if (c >= start && c < start + n)
          v = c + 1u < start + n ? c + 1u : 0xFFF;
        if (c == start + n / 2u && (take(in) & 7u) == 0u) v = take(in);
        const uint32_t off = c + c / 2u;
        if (off + 1u >= 512u) break;
        if (c & 1u) {
          s[off] = (uint8_t)((s[off] & 0x0F) | ((v & 0x0F) << 4));
          s[off + 1] = (uint8_t)(v >> 4);
        } else {
          s[off] = (uint8_t)v;
          s[off + 1] = (uint8_t)((s[off + 1] & 0xF0) | ((v >> 8) & 0x0F));
        }
      }
      break;
    }
    case 6: {
      const uint8_t ad[8] = {0x00, 0x05, 0x16, 0x07, 0x00, 0x02, 0x00, 0x00};
      memcpy(s, ad, 8);
      break;
    }
    default:  // dot directory
      memcpy(s, ".          ", 11);
      s[11] = 0x10;
      memcpy(s + 32, "..         ", 11);
      s[43] = 0x10;
      break;
  }
}

// One complete BOT transaction with a well-formed CBW.
static void transaction(fz_t *f, input_t *in, const uint8_t *cdb, uint8_t cblen,
                        bool dir_in, uint32_t xfer, uint8_t kind,
                        uint32_t seed) {
  static uint32_t tag;
  uint8_t cbw[31];
  memset(cbw, 0, sizeof cbw);
  put32le(cbw, 0x43425355u);
  put32le(cbw + 4, ++tag);
  put32le(cbw + 8, xfer);
  cbw[12] = dir_in ? 0x80 : 0x00;
  cbw[14] = cblen;
  memcpy(cbw + 15, cdb, cblen);
  if (f->stalled[FMSC_EP_OUT]) return;
  fmsc_on_out_packet(&f->ctx, cbw, sizeof cbw);
  uint8_t sec[512];
  uint32_t done = 0;
  if (dir_in) {
    for (uint32_t i = 0; i < 4096u && done < xfer; i++) {
      const int n = read_in(f);
      if (n < 0) break;
      done += (uint32_t)n;
      if (n < 64) break;
    }
  } else {
    for (uint32_t i = 0; i < 4096u && done < xfer && !f->stalled[FMSC_EP_OUT];
         i++) {
      const uint32_t in_sec = done % 512u;
      if (in_sec == 0u)
        make_sector(in, i == 0u ? kind : (kind % 8u == 1u ? 3u : kind),
                    seed + i, sec);
      const uint32_t n = xfer - done < 64u ? xfer - done : 64u;
      fmsc_on_out_packet(&f->ctx, sec + in_sec, n);
      done += n;
    }
  }
  if (f->stalled[FMSC_EP_IN]) clear(f, FMSC_EP_IN);
  if (f->stalled[FMSC_EP_OUT]) clear(f, FMSC_EP_OUT);
  int n = read_in(f);
  if (n == -1) {
    clear(f, FMSC_EP_IN);
    n = read_in(f);
  }
  (void)n;
}

static uint32_t pick_lba(input_t *in) {
  const uint8_t r = take(in);
  const uint32_t v = (uint32_t)take(in) | ((uint32_t)take(in) << 8);
  switch (r % 5u) {
    case 0:
      return 1u + v % 24u;  // FAT1 / FAT2
    case 1:
      return FMSC_ROOT_LBA + v % 4u;  // root directory
    case 2:
      return FMSC_DATA_LBA + 16u + v % (48u * 8u);  // hot clusters 4..51
    case 3:
      return FMSC_DATA_LBA + 16u + (v % 48u) * 8u;  // cluster starts
    default:
      return v % (FMSC_TOTAL_SECTORS + 8u);
  }
}

static void run(const uint8_t *data, size_t size) {
  fz_t *f = &g;
  memset(f, 0, sizeof *f);
  input_t in = {data, size};
  fmsc_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  const uint8_t knobs = take(&in);
  cfg.cache_mem = f->cache;
  cfg.cache_clusters = knobs & 3u;
  cfg.reorder_mem = f->reorder;
  cfg.reorder_sectors = (knobs >> 2) & 7u;
  cfg.readme = (const uint8_t *)"README\r\n";
  cfg.readme_len = 8;
  cfg.quiet_ms = (knobs & 0x20u) ? 0u : 500u;
  cfg.settle_ms = (knobs & 0x40u) ? 0u : 3000u;
  f->refuse = (knobs & 0x80u) != 0u && (knobs & 1u);
  fmsc_callbacks_t cb;
  memset(&cb, 0, sizeof cb);
  cb.user = f;
  cb.send_in = f_send_in;
  cb.stall = f_stall;
  cb.stream_start = f_start;
  cb.stream_data = f_data;
  cb.stream_complete = f_complete;
  cb.stream_error = f_error;
  cb.event = f_event;
  if (fmsc_init(&f->ctx, &cfg, &cb) != FMSC_OK) FAIL();

  for (unsigned steps = 0; in.n > 0u && steps < 2000u; steps++) {
    const uint8_t op = take(&in);
    switch (op % 12u) {
      case 0: {  // raw OUT packet
        uint8_t pkt[64];
        const size_t n = take(&in) % 65u;
        for (size_t i = 0; i < n; i++) pkt[i] = take(&in);
        if (!f->stalled[FMSC_EP_OUT]) fmsc_on_out_packet(&f->ctx, pkt, n);
        break;
      }
      case 1:
        (void)read_in(f);
        break;
      case 2:
        clear(f, FMSC_EP_IN);
        break;
      case 3:
        clear(f, FMSC_EP_OUT);
        break;
      case 4:
        fmsc_bot_reset(&f->ctx);
        f->pending = false;
        f->stalled[0] = f->stalled[1] = false;
        break;
      case 5:
        f->now += (uint32_t)take(&in) * 40u;
        fmsc_poll(&f->ctx, f->now);
        break;
      case 6:
      case 7: {  // WRITE(10) with crafted sectors
        const uint32_t lba = pick_lba(&in);
        const uint8_t cnt = (uint8_t)(1u + take(&in) % 16u);
        const uint8_t kind = take(&in);
        const uint8_t cdb[10] = {0x2A,
                                 0,
                                 (uint8_t)(lba >> 24),
                                 (uint8_t)(lba >> 16),
                                 (uint8_t)(lba >> 8),
                                 (uint8_t)lba,
                                 0,
                                 0,
                                 cnt,
                                 0};
        const uint8_t skew = take(&in);
        uint32_t xfer = (uint32_t)cnt * 512u;
        if ((skew & 0x0Fu) == 0u)
          xfer += (uint32_t)(skew >> 4) * 64u;  // Ho > Do
        transaction(f, &in, cdb, 10, (skew & 0xF0u) == 0x10u, xfer, kind,
                    f->now + op);
        break;
      }
      case 8: {  // READ(10)
        const uint32_t lba = pick_lba(&in);
        const uint8_t cnt = (uint8_t)(take(&in) % 9u);
        const uint8_t cdb[10] = {0x28,
                                 0,
                                 (uint8_t)(lba >> 24),
                                 (uint8_t)(lba >> 16),
                                 (uint8_t)(lba >> 8),
                                 (uint8_t)lba,
                                 0,
                                 0,
                                 cnt,
                                 0};
        transaction(f, &in, cdb, 10, true, (uint32_t)cnt * 512u, 0, 0);
        break;
      }
      case 9: {  // arbitrary CDB, arbitrary expectation
        uint8_t cdb[16];
        for (size_t i = 0; i < 16; i++) cdb[i] = take(&in);
        static const uint8_t ops[] = {0x00, 0x03, 0x12, 0x1A, 0x1B, 0x1E, 0x23,
                                      0x25, 0x2F, 0x35, 0x5A, 0xA0, 0x9E};
        if (cdb[15] & 1u) cdb[0] = ops[cdb[0] % sizeof ops];
        const uint8_t cblen = (uint8_t)(1u + take(&in) % 16u);
        const uint32_t xfer = take(&in) % 3u == 0u ? 0u : take(&in);
        transaction(f, &in, cdb, cblen, (take(&in) & 1u) != 0u, xfer, 0, 0);
        break;
      }
      case 10: {  // SYNCHRONIZE CACHE / START STOP UNIT / PREVENT
        const uint8_t sel = take(&in);
        uint8_t cdb[10];
        memset(cdb, 0, sizeof cdb);
        if (sel % 3u == 0u) {
          cdb[0] = 0x35;
          transaction(f, &in, cdb, 10, false, 0, 0, 0);
        } else if (sel % 3u == 1u) {
          cdb[0] = 0x1B;
          cdb[4] = (uint8_t)(sel >> 2);
          transaction(f, &in, cdb, 6, false, 0, 0, 0);
        } else {
          cdb[0] = 0x1E;
          cdb[4] = (uint8_t)(sel >> 2);
          transaction(f, &in, cdb, 6, false, 0, 0, 0);
        }
        break;
      }
      default: {  // diagnostic reads never fault
        uint8_t s[512];
        fmsc_volume_read(&f->ctx, pick_lba(&in), s);
        break;
      }
    }
  }
  fmsc_wipe(&f->ctx);
  const uint8_t *raw = (const uint8_t *)&f->ctx;
  for (size_t i = 0; i < sizeof f->ctx; i++) {
    if (raw[i] != 0u) FAIL();
  }
  for (size_t i = 0; i < sizeof f->cache; i++) {
    if (f->cache[i] != 0u) FAIL();
  }
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  run(data, size);
  return 0;
}

#ifdef FMSC_FUZZ_REPLAY_MAIN
#include <dirent.h>
#include <stdio.h>

static int replay_file(const char *path) {
  FILE *fp = fopen(path, "rb");
  if (fp == NULL) return 1;
  static uint8_t buf[1 << 20];
  const size_t n = fread(buf, 1, sizeof buf, fp);
  fclose(fp);
  run(buf, n);
  return 0;
}

int main(int argc, char **argv) {
  int files = 0;
  for (int a = 1; a < argc; a++) {
    DIR *d = opendir(argv[a]);
    if (d == NULL) {
      if (replay_file(argv[a]) != 0) return 1;
      files++;
      continue;
    }
    struct dirent *e;
    while ((e = readdir(d)) != NULL) {
      if (e->d_name[0] == '.') continue;
      char path[4096];
      snprintf(path, sizeof path, "%s/%s", argv[a], e->d_name);
      if (replay_file(path) != 0) return 1;
      files++;
    }
    closedir(d);
  }
  printf(
      "fmsc_fuzz_replay: %d inputs OK (streams: %lu started, %lu completed, "
      "%lu failed)\n",
      files, n_started, n_completed, n_failed);
  return files > 0 ? 0 : 1;
}
#endif
