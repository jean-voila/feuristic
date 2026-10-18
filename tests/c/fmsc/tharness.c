// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

#include "tharness.h"

#include <stdlib.h>
#include <string.h>

int t_failures = 0;
int t_checks = 0;

int t_finish(const char *suite) {
  fprintf(stderr, "%s: %d checks, %d failures\n", suite, t_checks, t_failures);
  return t_failures == 0 ? 0 : 1;
}

// --- callbacks -------------------------------------------------------------

static void cb_send_in(void *user, const uint8_t *data, size_t len) {
  host_t *h = user;
  if (h->in_pending || len == 0u || len > 64u || h->stalled[FMSC_EP_IN]) {
    h->violations++;
    fprintf(stderr, "violation: send_in pending=%d len=%zu stalled=%d\n",
            h->in_pending, len, h->stalled[FMSC_EP_IN]);
  }
  if (len <= 64u) {
    memcpy(h->in_pkt, data, len);
    h->in_len = len;
  }
  h->in_pending = true;
}

static void cb_stall(void *user, fmsc_ep_t ep) {
  host_t *h = user;
  if (ep == FMSC_EP_IN && h->in_pending) {
    h->violations++;
    fprintf(stderr, "violation: IN stalled with a queued packet\n");
  }
  h->stalled[ep] = true;
}

static bool cb_stream_start(void *user, uint32_t id) {
  host_t *h = user;
  rec_stream_t *s = host_stream(h, id);
  if (s == NULL || s->started) {
    h->violations++;
    return false;
  }
  s->started = true;
  h->n_started++;
  if (h->refuse_streams) {
    return false;
  }
  s->data = calloc(1, FMSC_MAX_FILE_SIZE);
  return true;
}

static void cb_stream_data(void *user, uint32_t id, uint32_t off, const uint8_t *d,
                           size_t len) {
  host_t *h = user;
  rec_stream_t *s = host_stream(h, id);
  if (s == NULL || s->data == NULL || s->terminal_events != 0) {
    h->violations++;
    return;
  }
  if (off != s->len || (size_t)off + len > FMSC_MAX_FILE_SIZE) {
    s->order_violation = true;
    h->violations++;
    return;
  }
  memcpy(s->data + off, d, len);
  s->len += (uint32_t)len;
}

static void cb_stream_complete(void *user, uint32_t id, const fmsc_file_name_t *name,
                               uint32_t size) {
  host_t *h = user;
  rec_stream_t *s = host_stream(h, id);
  if (s == NULL || !s->started) {
    h->violations++;
    return;
  }
  s->terminal_events++;
  if (s->terminal_events > 1) {
    h->violations++;
  }
  s->completed = true;
  s->size = size;
  s->name = *name;
  h->n_completed++;
}

static void cb_stream_error(void *user, uint32_t id, fmsc_stream_error_t reason) {
  host_t *h = user;
  rec_stream_t *s = host_stream(h, id);
  if (s == NULL || !s->started) {
    h->violations++;
    return;
  }
  s->terminal_events++;
  if (s->terminal_events > 1) {
    h->violations++;
  }
  s->errored = true;
  s->error = reason;
  h->n_errors++;
}

static void cb_event(void *user, fmsc_event_t ev) {
  host_t *h = user;
  if (h->n_events < 64) {
    h->events[h->n_events++] = (int)ev;
  }
}

// --- host lifecycle ---------------------------------------------------------

host_t *host_new(void) {
  host_t *h = calloc(1, sizeof *h);
  if (h == NULL) {
    abort();
  }
  h->cache_clusters = 4;
  h->reorder_sectors = 16;
  h->quiet_ms = 2000;
  h->settle_ms = 15000;
  h->readme = "LISEZMOI / README\r\nCopiez une image PNG ou JPEG du QR code ici.\r\n"
              "Copy one PNG or JPEG image of the QR code here.\r\n";
  return h;
}

void host_open(host_t *h) {
  fmsc_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  cfg.cache_mem = h->cache_mem;
  cfg.cache_clusters = h->cache_clusters;
  cfg.reorder_mem = h->reorder_mem;
  cfg.reorder_sectors = h->reorder_sectors;
  cfg.readme = (const uint8_t *)h->readme;
  cfg.readme_len = h->readme != NULL ? strlen(h->readme) : 0u;
  cfg.volume_id = 0x20261017u;
  cfg.serial = "FEUR0001";
  cfg.revision = "0.1";
  cfg.quiet_ms = h->quiet_ms;
  cfg.settle_ms = h->settle_ms;
  fmsc_callbacks_t cb;
  memset(&cb, 0, sizeof cb);
  cb.user = h;
  cb.send_in = cb_send_in;
  cb.stall = cb_stall;
  cb.stream_start = cb_stream_start;
  cb.stream_data = cb_stream_data;
  cb.stream_complete = cb_stream_complete;
  cb.stream_error = cb_stream_error;
  cb.event = cb_event;
  if (fmsc_init(&h->ctx, &cfg, &cb) != FMSC_OK) {
    fprintf(stderr, "fmsc_init failed\n");
    abort();
  }
  h->now = 1000;
  fmsc_poll(&h->ctx, h->now);
}

void host_clear_ua(host_t *h) {
  uint8_t k, a, q;
  (void)scsi_tur(h);
  (void)scsi_sense(h, &k, &a, &q);
}

void host_free(host_t *h) {
  for (size_t i = 0; i < HOST_MAX_STREAMS; i++) {
    free(h->streams[i].data);
  }
  fmsc_wipe(&h->ctx);
  free(h);
}

rec_stream_t *host_stream(host_t *h, uint32_t id) {
  if (id == 0u || id > HOST_MAX_STREAMS) {
    return NULL;
  }
  return &h->streams[id - 1u];
}

int host_count_events(const host_t *h, fmsc_event_t ev) {
  int n = 0;
  for (int i = 0; i < h->n_events; i++) {
    n += h->events[i] == (int)ev;
  }
  return n;
}

// --- endpoints --------------------------------------------------------------

int host_read_in(host_t *h, uint8_t *buf) {
  if (h->stalled[FMSC_EP_IN]) {
    return HOST_STALL;
  }
  if (!h->in_pending) {
    return HOST_NODATA;
  }
  const size_t n = h->in_len;
  memcpy(buf, h->in_pkt, n);
  h->in_pending = false;
  fmsc_on_in_ready(&h->ctx);
  return (int)n;
}

bool host_send_out(host_t *h, const uint8_t *pkt, size_t len) {
  if (h->stalled[FMSC_EP_OUT]) {
    return false;
  }
  fmsc_on_out_packet(&h->ctx, pkt, len);
  return true;
}

void host_clear_halt(host_t *h, fmsc_ep_t ep) {
  h->stalled[ep] = false;
  fmsc_on_clear_halt(&h->ctx, ep);
}

void host_reset_recovery(host_t *h) {
  fmsc_bot_reset(&h->ctx);
  h->in_pending = false;  // the glue flushes the FIFOs
  host_clear_halt(h, FMSC_EP_IN);
  host_clear_halt(h, FMSC_EP_OUT);
}

void host_advance(host_t *h, uint32_t ms) {
  // Poll every 100 ms like the firmware loop.
  while (ms > 0u) {
    const uint32_t step = ms > 100u ? 100u : ms;
    h->now += step;
    ms -= step;
    fmsc_poll(&h->ctx, h->now);
  }
}

void host_build_cbw(uint8_t cbw[31], uint32_t tag, uint32_t xfer_len, uint8_t flags,
                    uint8_t lun, uint8_t cb_len, const uint8_t *cdb) {
  memset(cbw, 0, 31);
  cbw[0] = 0x55;
  cbw[1] = 0x53;
  cbw[2] = 0x42;
  cbw[3] = 0x43;
  cbw[4] = (uint8_t)tag;
  cbw[5] = (uint8_t)(tag >> 8);
  cbw[6] = (uint8_t)(tag >> 16);
  cbw[7] = (uint8_t)(tag >> 24);
  cbw[8] = (uint8_t)xfer_len;
  cbw[9] = (uint8_t)(xfer_len >> 8);
  cbw[10] = (uint8_t)(xfer_len >> 16);
  cbw[11] = (uint8_t)(xfer_len >> 24);
  cbw[12] = flags;
  cbw[13] = lun;
  cbw[14] = cb_len;
  memcpy(cbw + 15, cdb, cb_len > 16 ? 16 : cb_len);
}

static uint32_t rd32le(const uint8_t *p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
         ((uint32_t)p[3] << 24);
}

xfer_t host_bot(host_t *h, const uint8_t *cdb, uint8_t cdb_len, bool dir_in,
                uint32_t xfer_len, const uint8_t *out_data, uint8_t *in_data) {
  xfer_t r;
  memset(&r, 0, sizeof r);
  uint8_t cbw[31];
  const uint32_t tag = ++h->tag;
  host_build_cbw(cbw, tag, xfer_len, dir_in ? 0x80 : 0x00, 0, cdb_len, cdb);
  host_send_out(h, cbw, 31);
  uint8_t pkt[64];
  if (xfer_len > 0u) {
    if (dir_in) {
      while (r.got < xfer_len) {
        const int n = host_read_in(h, pkt);
        if (n == HOST_STALL) {
          r.in_stalled = true;
          break;
        }
        if (n == HOST_NODATA) {
          h->violations++;  // the device must answer or stall
          fprintf(stderr, "violation: no data-in and no stall\n");
          break;
        }
        uint32_t take = (uint32_t)n;
        if (take > xfer_len - r.got) {
          take = xfer_len - r.got;
          h->violations++;
        }
        if (in_data != NULL) {
          memcpy(in_data + r.got, pkt, take);
        }
        r.got += take;
        if (n < 64) {
          break;  // short packet ends the transfer
        }
      }
      if (r.in_stalled) {
        host_clear_halt(h, FMSC_EP_IN);
      }
    } else {
      for (uint32_t off = 0; off < xfer_len; off += 64u) {
        const uint32_t n = xfer_len - off > 64u ? 64u : xfer_len - off;
        if (!host_send_out(h, out_data != NULL ? out_data + off : pkt, n)) {
          r.out_stalled = true;
          break;
        }
      }
      if (h->stalled[FMSC_EP_OUT]) {
        r.out_stalled = true;
        host_clear_halt(h, FMSC_EP_OUT);
      }
    }
  }
  int n = host_read_in(h, pkt);
  if (n == HOST_STALL) {
    r.in_stalled = true;
    host_clear_halt(h, FMSC_EP_IN);
    n = host_read_in(h, pkt);
  }
  if (n == 13 && rd32le(pkt) == 0x53425355u && rd32le(pkt + 4) == tag) {
    r.csw_ok = true;
    r.residue = rd32le(pkt + 8);
    r.status = pkt[12];
  }
  return r;
}

// --- SCSI helpers ------------------------------------------------------------

static int status_of(host_t *h, const xfer_t *r) {
  if (!r->csw_ok) {
    h->violations++;
    fprintf(stderr, "violation: no valid CSW\n");
    return -1;
  }
  return r->status;
}

int scsi_tur(host_t *h) {
  const uint8_t cdb[6] = {0x00, 0, 0, 0, 0, 0};
  const xfer_t r = host_bot(h, cdb, 6, false, 0, NULL, NULL);
  return status_of(h, &r);
}

int scsi_sense(host_t *h, uint8_t *key, uint8_t *asc, uint8_t *ascq) {
  const uint8_t cdb[6] = {0x03, 0, 0, 0, 18, 0};
  uint8_t d[18];
  memset(d, 0, sizeof d);
  const xfer_t r = host_bot(h, cdb, 6, true, 18, NULL, d);
  *key = (uint8_t)(d[2] & 0x0F);
  *asc = d[12];
  *ascq = d[13];
  return status_of(h, &r);
}

int scsi_read10(host_t *h, uint32_t lba, uint16_t count, uint8_t *out) {
  const uint8_t cdb[10] = {0x28, 0, (uint8_t)(lba >> 24), (uint8_t)(lba >> 16),
                           (uint8_t)(lba >> 8), (uint8_t)lba, 0,
                           (uint8_t)(count >> 8), (uint8_t)count, 0};
  const xfer_t r = host_bot(h, cdb, 10, true, (uint32_t)count * 512u, NULL, out);
  return status_of(h, &r);
}

int scsi_write10(host_t *h, uint32_t lba, uint16_t count, const uint8_t *data) {
  const uint8_t cdb[10] = {0x2A, 0, (uint8_t)(lba >> 24), (uint8_t)(lba >> 16),
                           (uint8_t)(lba >> 8), (uint8_t)lba, 0,
                           (uint8_t)(count >> 8), (uint8_t)count, 0};
  const xfer_t r = host_bot(h, cdb, 10, false, (uint32_t)count * 512u, data, NULL);
  return status_of(h, &r);
}

int scsi_sync(host_t *h) {
  const uint8_t cdb[10] = {0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  const xfer_t r = host_bot(h, cdb, 10, false, 0, NULL, NULL);
  return status_of(h, &r);
}

int scsi_start_stop(host_t *h, bool loej, bool start) {
  const uint8_t cdb[6] = {0x1B, 0, 0, 0, (uint8_t)((loej ? 2 : 0) | (start ? 1 : 0)), 0};
  const xfer_t r = host_bot(h, cdb, 6, false, 0, NULL, NULL);
  return status_of(h, &r);
}

int scsi_prevent(host_t *h, bool prevent) {
  const uint8_t cdb[6] = {0x1E, 0, 0, 0, (uint8_t)(prevent ? 1 : 0), 0};
  const xfer_t r = host_bot(h, cdb, 6, false, 0, NULL, NULL);
  return status_of(h, &r);
}
