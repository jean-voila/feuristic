// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// Bulk-Only Transport conformance: CBW validation, the 13 host/device cases
// of BOT 1.0 §6.7, residues, stalls, reset recovery, re-entrancy.

#include <stdlib.h>
#include <string.h>

#include "tharness.h"

static host_t *mk(void) {
  host_t *h = host_new();
  host_open(h);
  host_clear_ua(h);
  return h;
}

static const uint8_t CDB_TUR[6] = {0x00, 0, 0, 0, 0, 0};

static void inquiry_cdb(uint8_t cdb[6], uint8_t alloc) {
  memset(cdb, 0, 6);
  cdb[0] = 0x12;
  cdb[4] = alloc;
}

static void rw_cdb(uint8_t cdb[10], uint8_t op, uint32_t lba, uint16_t n) {
  memset(cdb, 0, 10);
  cdb[0] = op;
  cdb[2] = (uint8_t)(lba >> 24);
  cdb[3] = (uint8_t)(lba >> 16);
  cdb[4] = (uint8_t)(lba >> 8);
  cdb[5] = (uint8_t)lba;
  cdb[7] = (uint8_t)(n >> 8);
  cdb[8] = (uint8_t)n;
}

static void test_init_params(void) {
  fmsc_ctx_t *ctx = calloc(1, sizeof *ctx);
  fmsc_config_t cfg;
  fmsc_callbacks_t cb;
  memset(&cfg, 0, sizeof cfg);
  memset(&cb, 0, sizeof cb);
  CHECK_EQ(fmsc_init(NULL, &cfg, &cb), FMSC_ERR_PARAM);
  CHECK_EQ(fmsc_init(ctx, NULL, &cb), FMSC_ERR_PARAM);
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);  // no send_in/stall
  host_t *h = host_new();
  host_open(h);  // valid baseline
  cb = h->ctx.cb;
  cfg.cache_clusters = 1;  // without memory
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  cfg.cache_clusters = FMSC_CACHE_MAX_CLUSTERS + 1;
  cfg.cache_mem = h->cache_mem;
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  memset(&cfg, 0, sizeof cfg);
  cfg.reorder_sectors = FMSC_REORDER_MAX_SECTORS + 1;
  cfg.reorder_mem = h->reorder_mem;
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  memset(&cfg, 0, sizeof cfg);
  cfg.readme_len = FMSC_README_MAX + 1;
  cfg.readme = h->cache_mem;
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  memset(&cfg, 0, sizeof cfg);
  cfg.readme_len = 3;  // NULL text
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  memset(&cfg, 0, sizeof cfg);
  cfg.serial = "bad\x01serial";
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  cfg.serial = "";
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  cfg.serial = "012345678901234567890123456789012";  // 33 chars
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  cfg.serial = NULL;
  cfg.revision = "12345";
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_ERR_PARAM);
  cfg.revision = NULL;
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_OK);  // minimal config is valid
  CHECK_EQ(fmsc_get_max_lun(), 0);
  fmsc_wipe(ctx);
  free(ctx);
  host_free(h);
}

static void test_case1_hn_dn(void) {
  host_t *h = mk();
  const xfer_t r = host_bot(h, CDB_TUR, 6, false, 0, NULL, NULL);
  CHECK(r.csw_ok);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 0);
  CHECK(!r.in_stalled && !r.out_stalled);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case2_hn_di(void) {
  host_t *h = mk();
  uint8_t cdb[6];
  inquiry_cdb(cdb, 36);
  const xfer_t r = host_bot(h, cdb, 6, true, 0, NULL, NULL);
  CHECK(r.csw_ok);
  CHECK_EQ(r.status, 2);
  CHECK_EQ(r.residue, 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case3_hn_do(void) {
  host_t *h = mk();
  uint8_t cdb[10];
  rw_cdb(cdb, 0x2A, 100, 1);
  const xfer_t r = host_bot(h, cdb, 10, false, 0, NULL, NULL);
  CHECK(r.csw_ok);
  CHECK_EQ(r.status, 2);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case4_hi_dn(void) {
  host_t *h = mk();
  const xfer_t r = host_bot(h, CDB_TUR, 6, true, 64, NULL, NULL);
  CHECK(r.csw_ok);
  CHECK(r.in_stalled);
  CHECK_EQ(r.got, 0);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 64);
  // Failing command with data expected: READ beyond the end.
  uint8_t cdb[10];
  rw_cdb(cdb, 0x28, FMSC_TOTAL_SECTORS, 1);
  const xfer_t r2 = host_bot(h, cdb, 10, true, 512, NULL, NULL);
  CHECK(r2.csw_ok);
  CHECK(r2.in_stalled);
  CHECK_EQ(r2.status, 1);
  CHECK_EQ(r2.residue, 512);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case5_hi_gt_di(void) {
  host_t *h = mk();
  uint8_t cdb[6];
  uint8_t buf[255];
  inquiry_cdb(cdb, 255);
  const xfer_t r = host_bot(h, cdb, 6, true, 255, NULL, buf);
  CHECK(r.csw_ok);
  CHECK_EQ(r.got, 36);
  CHECK(r.in_stalled);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 255 - 36);
  // Exact multiple of the packet size: still stall + residue.
  const uint8_t sense[6] = {0x03, 0, 0, 0, 64, 0};
  uint8_t sb[128];
  const xfer_t r2 = host_bot(h, sense, 6, true, 128, NULL, sb);
  CHECK(r2.csw_ok);
  CHECK_EQ(r2.got, 18);
  CHECK_EQ(r2.residue, 128 - 18);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case6_hi_eq_di(void) {
  host_t *h = mk();
  uint8_t cdb[6];
  uint8_t buf[36];
  inquiry_cdb(cdb, 36);
  const xfer_t r = host_bot(h, cdb, 6, true, 36, NULL, buf);
  CHECK(r.csw_ok);
  CHECK_EQ(r.got, 36);
  CHECK(!r.in_stalled);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 0);
  // Multi-packet READ(10): 4 sectors = 32 packets, identical to the volume.
  uint8_t rd[2048];
  uint8_t ref[512];
  uint8_t c10[10];
  rw_cdb(c10, 0x28, 0, 4);
  const xfer_t r2 = host_bot(h, c10, 10, true, 2048, NULL, rd);
  CHECK(r2.csw_ok);
  CHECK_EQ(r2.got, 2048);
  CHECK_EQ(r2.residue, 0);
  for (uint32_t i = 0; i < 4; i++) {
    fmsc_volume_read(&h->ctx, i, ref);
    CHECK(memcmp(rd + i * 512, ref, 512) == 0);
  }
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case7_hi_lt_di(void) {
  host_t *h = mk();
  uint8_t cdb[10];
  uint8_t buf[512];
  rw_cdb(cdb, 0x28, 0, 2);
  const xfer_t r = host_bot(h, cdb, 10, true, 512, NULL, buf);
  CHECK(r.csw_ok);
  CHECK_EQ(r.status, 2);
  CHECK(r.in_stalled);
  host_reset_recovery(h);
  CHECK_EQ(scsi_tur(h), 0);  // usable again after reset recovery
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case8_hi_do(void) {
  host_t *h = mk();
  uint8_t cdb[10];
  uint8_t buf[512];
  rw_cdb(cdb, 0x2A, 100, 1);
  const xfer_t r = host_bot(h, cdb, 10, true, 512, NULL, buf);
  CHECK(r.csw_ok);
  CHECK_EQ(r.status, 2);
  CHECK(r.in_stalled);
  CHECK_EQ(r.got, 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case9_ho_dn(void) {
  host_t *h = mk();
  uint8_t data[64];
  memset(data, 0xAB, sizeof data);
  const xfer_t r = host_bot(h, CDB_TUR, 6, false, 64, data, NULL);
  CHECK(r.csw_ok);
  CHECK(r.out_stalled);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 64);
  // WRITE beyond the end (CHECK CONDITION, no data accepted).
  uint8_t cdb[10];
  uint8_t sec[512];
  memset(sec, 0x5A, sizeof sec);
  rw_cdb(cdb, 0x2A, FMSC_TOTAL_SECTORS - 1, 2);
  const xfer_t r2 = host_bot(h, cdb, 10, false, 1024, sec, NULL);
  CHECK(r2.csw_ok);
  CHECK(r2.out_stalled);
  CHECK_EQ(r2.status, 1);
  CHECK_EQ(r2.residue, 1024);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case10_ho_di(void) {
  host_t *h = mk();
  uint8_t cdb[6];
  uint8_t data[36];
  memset(data, 0, sizeof data);
  inquiry_cdb(cdb, 36);
  const xfer_t r = host_bot(h, cdb, 6, false, 36, data, NULL);
  CHECK(r.csw_ok);
  CHECK(r.out_stalled);
  CHECK_EQ(r.status, 2);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case11_ho_gt_do(void) {
  host_t *h = mk();
  uint8_t cdb[10];
  uint8_t data[1024];
  memset(data, 0x77, sizeof data);
  const uint32_t lba = FMSC_DATA_LBA + 100 * 8;  // an unused cluster
  rw_cdb(cdb, 0x2A, lba, 1);
  const xfer_t r = host_bot(h, cdb, 10, false, 1024, data, NULL);
  CHECK(r.csw_ok);
  CHECK(r.out_stalled);
  CHECK_EQ(r.status, 0);
  CHECK_EQ(r.residue, 512);
  uint8_t back[512];
  fmsc_volume_read(&h->ctx, lba, back);
  CHECK(memcmp(back, data, 512) == 0);  // cached non-image data
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case12_ho_eq_do(void) {
  host_t *h = mk();
  uint8_t data[512];
  memset(data, 0x31, sizeof data);
  const uint32_t lba = FMSC_DATA_LBA + 200 * 8;
  CHECK_EQ(scsi_write10(h, lba, 1, data), 0);
  uint8_t back[512];
  CHECK_EQ(scsi_read10(h, lba, 1, back), 0);
  CHECK(memcmp(back, data, 512) == 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_case13_ho_lt_do(void) {
  host_t *h = mk();
  uint8_t cdb[10];
  uint8_t data[512];
  memset(data, 0x44, sizeof data);
  const uint32_t lba = FMSC_DATA_LBA + 300 * 8;
  rw_cdb(cdb, 0x2A, lba, 2);
  const xfer_t r = host_bot(h, cdb, 10, false, 512, data, NULL);
  CHECK(r.csw_ok);
  CHECK(r.out_stalled);
  CHECK_EQ(r.status, 2);
  uint8_t back[512];
  fmsc_volume_read(&h->ctx, lba, back);
  uint8_t zero[512];
  memset(zero, 0, sizeof zero);
  CHECK(memcmp(back, zero, 512) == 0);  // nothing written
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void expect_need_reset(host_t *h) {
  CHECK(h->stalled[FMSC_EP_IN]);
  CHECK(h->stalled[FMSC_EP_OUT]);
  // A clear-halt without reset leaves the pipes halted (§6.6.1).
  host_clear_halt(h, FMSC_EP_IN);
  CHECK(h->stalled[FMSC_EP_IN]);
  host_clear_halt(h, FMSC_EP_OUT);
  CHECK(h->stalled[FMSC_EP_OUT]);
  // Packets are ignored until the reset recovery.
  uint8_t cbw[31];
  host_build_cbw(cbw, 7, 0, 0, 0, 6, CDB_TUR);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  CHECK(!h->in_pending);
  host_reset_recovery(h);
  CHECK(!h->stalled[FMSC_EP_IN] && !h->stalled[FMSC_EP_OUT]);
  CHECK_EQ(scsi_tur(h), 0);
  CHECK_EQ(host_count_events(h, FMSC_EVT_HOST_RESET), 1);
}

static void test_invalid_cbw_signature(void) {
  host_t *h = mk();
  uint8_t cbw[31];
  host_build_cbw(cbw, 1, 0, 0, 0, 6, CDB_TUR);
  cbw[3] = 0x44;
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  expect_need_reset(h);
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.invalid_cbw, 1);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_invalid_cbw_length(void) {
  const size_t lens[] = {0, 13, 30, 32, 64};
  for (size_t i = 0; i < sizeof lens / sizeof lens[0]; i++) {
    host_t *h = mk();
    uint8_t pkt[64];
    memset(pkt, 0, sizeof pkt);
    host_build_cbw(pkt, 1, 0, 0, 0, 6, CDB_TUR);
    fmsc_on_out_packet(&h->ctx, pkt, lens[i]);
    expect_need_reset(h);
    host_free(h);
  }
  host_t *h = mk();
  uint8_t big[65];
  memset(big, 0, sizeof big);
  fmsc_on_out_packet(&h->ctx, big, sizeof big);  // oversized
  expect_need_reset(h);
  host_free(h);
}

static void test_not_meaningful_cbw(void) {
  struct {
    uint8_t flags, lun, cblen;
    bool in;
    uint32_t len;
  } cases[] = {
      {0x00, 1, 6, false, 0},   {0x80, 1, 6, true, 36},  {0x00, 0, 0, false, 0},
      {0x00, 0, 17, false, 64}, {0x80, 0, 31, true, 8},  {0x81, 0, 6, true, 36},
      {0x00, 0x10, 6, false, 0},
  };
  for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
    host_t *h = mk();
    uint8_t cbw[31];
    uint8_t cdb[16];
    memset(cdb, 0, sizeof cdb);
    inquiry_cdb(cdb, 36);
    host_build_cbw(cbw, 0x1234, cases[i].len, cases[i].flags, cases[i].lun, cases[i].cblen,
                   cdb);
    fmsc_on_out_packet(&h->ctx, cbw, 31);
    if (cases[i].len > 0) {
      CHECK(h->stalled[cases[i].in ? FMSC_EP_IN : FMSC_EP_OUT]);
      host_clear_halt(h, cases[i].in ? FMSC_EP_IN : FMSC_EP_OUT);
    }
    uint8_t pkt[64];
    CHECK_EQ(host_read_in(h, pkt), 13);
    CHECK_EQ(pkt[12], 2);  // phase error
    CHECK(pkt[4] == 0x34 && pkt[5] == 0x12);
    host_reset_recovery(h);
    CHECK_EQ(scsi_tur(h), 0);
    CHECK_EQ(h->violations, 0);
    host_free(h);
  }
}

static void test_short_packet_in_data_out(void) {
  host_t *h = mk();
  uint8_t cbw[31];
  uint8_t cdb[10];
  rw_cdb(cdb, 0x2A, FMSC_DATA_LBA + 400 * 8, 2);
  host_build_cbw(cbw, 9, 1024, 0, 0, 10, cdb);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  uint8_t pkt[64];
  memset(pkt, 0x11, sizeof pkt);
  for (int i = 0; i < 3; i++) fmsc_on_out_packet(&h->ctx, pkt, 64);
  fmsc_on_out_packet(&h->ctx, pkt, 20);  // short: host ended early
  CHECK_EQ(host_read_in(h, pkt), 13);
  CHECK_EQ(pkt[12], 2);
  host_reset_recovery(h);
  CHECK_EQ(scsi_tur(h), 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_stray_packets_discarded(void) {
  host_t *h = mk();
  uint8_t cbw[31];
  uint8_t cdb[6];
  inquiry_cdb(cdb, 36);
  host_build_cbw(cbw, 5, 36, 0x80, 0, 6, cdb);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  uint8_t junk[64];
  memset(junk, 0xEE, sizeof junk);
  fmsc_on_out_packet(&h->ctx, junk, 64);  // during data-in
  uint8_t pkt[64];
  CHECK_EQ(host_read_in(h, pkt), 36);
  fmsc_on_out_packet(&h->ctx, junk, 64);  // during CSW
  CHECK_EQ(host_read_in(h, pkt), 13);
  CHECK_EQ(pkt[12], 0);
  fmsc_stats_t st;
  fmsc_get_stats(&h->ctx, &st);
  CHECK_EQ(st.discarded_packets, 2);
  CHECK_EQ(scsi_tur(h), 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_reset_mid_data_in(void) {
  host_t *h = mk();
  uint8_t cbw[31];
  uint8_t cdb[10];
  rw_cdb(cdb, 0x28, 0, 8);
  host_build_cbw(cbw, 3, 4096, 0x80, 0, 10, cdb);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  uint8_t pkt[64];
  for (int i = 0; i < 10; i++) CHECK_EQ(host_read_in(h, pkt), 64);
  host_reset_recovery(h);
  CHECK_EQ(scsi_tur(h), 0);
  uint8_t sec[512];
  CHECK_EQ(scsi_read10(h, 0, 1, sec), 0);
  CHECK(sec[510] == 0x55 && sec[511] == 0xAA);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

// --- re-entrancy: send_in() completing synchronously -------------------------

typedef struct {
  fmsc_ctx_t *ctx;
  uint8_t out[8192];
  size_t len;
  int calls;
  int stalls;
} sync_glue_t;

static void sync_send(void *user, const uint8_t *d, size_t n) {
  sync_glue_t *g = user;
  memcpy(g->out + g->len, d, n);
  g->len += n;
  g->calls++;
  fmsc_on_in_ready(g->ctx);  // completes immediately
}

static void sync_stall(void *user, fmsc_ep_t ep) {
  sync_glue_t *g = user;
  (void)ep;
  g->stalls++;
}

static void sync_reenter_event(void *user, fmsc_event_t ev) {
  sync_glue_t *g = user;
  (void)ev;
  fmsc_poll(g->ctx, 0);  // forbidden: ignored and counted
  fmsc_wipe(g->ctx);     // forbidden: ignored and counted
}

static void test_reentrant_in_ready(void) {
  sync_glue_t *g = calloc(1, sizeof *g);
  fmsc_ctx_t *ctx = calloc(1, sizeof *ctx);
  g->ctx = ctx;
  fmsc_config_t cfg;
  memset(&cfg, 0, sizeof cfg);
  fmsc_callbacks_t cb;
  memset(&cb, 0, sizeof cb);
  cb.user = g;
  cb.send_in = sync_send;
  cb.stall = sync_stall;
  cb.event = sync_reenter_event;
  CHECK_EQ(fmsc_init(ctx, &cfg, &cb), FMSC_OK);
  uint8_t cbw[31];
  uint8_t cdb[10];
  rw_cdb(cdb, 0x28, 0, 4);
  // UA first: the read fails with CHECK CONDITION.
  host_build_cbw(cbw, 1, 2048, 0x80, 0, 10, cdb);
  fmsc_on_out_packet(ctx, cbw, 31);
  CHECK_EQ(g->stalls, 1);
  fmsc_on_clear_halt(ctx, FMSC_EP_IN);
  CHECK_EQ(g->len, 13);
  g->len = 0;
  host_build_cbw(cbw, 2, 2048, 0x80, 0, 10, cdb);
  fmsc_on_out_packet(ctx, cbw, 31);
  CHECK_EQ(g->len, 2048 + 13);  // all data + CSW in one call chain
  CHECK_EQ(g->out[2048 + 12], 0);
  uint8_t ref[512];
  fmsc_volume_read(ctx, 0, ref);
  CHECK(memcmp(g->out, ref, 512) == 0);
  // Re-entrant calls of other entry points are ignored and counted.
  fmsc_stats_t st;
  fmsc_get_stats(ctx, &st);
  CHECK_EQ(st.reentrant_calls, 0);
  fmsc_bot_reset(ctx);  // HOST_RESET event re-enters
  fmsc_get_stats(ctx, &st);
  CHECK_EQ(st.reentrant_calls, 2);
  host_build_cbw(cbw, 3, 0, 0, 0, 6, CDB_TUR);
  g->len = 0;
  fmsc_on_out_packet(ctx, cbw, 31);  // still alive after the ignored wipe
  CHECK_EQ(g->len, 13);
  fmsc_wipe(ctx);
  const uint8_t *raw = (const uint8_t *)ctx;
  bool zero = true;
  for (size_t i = 0; i < sizeof *ctx; i++) zero = zero && raw[i] == 0;
  CHECK(zero);
  free(ctx);
  free(g);
}

int main(void) {
  RUN(test_init_params);
  RUN(test_case1_hn_dn);
  RUN(test_case2_hn_di);
  RUN(test_case3_hn_do);
  RUN(test_case4_hi_dn);
  RUN(test_case5_hi_gt_di);
  RUN(test_case6_hi_eq_di);
  RUN(test_case7_hi_lt_di);
  RUN(test_case8_hi_do);
  RUN(test_case9_ho_dn);
  RUN(test_case10_ho_di);
  RUN(test_case11_ho_gt_do);
  RUN(test_case12_ho_eq_do);
  RUN(test_case13_ho_lt_do);
  RUN(test_invalid_cbw_signature);
  RUN(test_invalid_cbw_length);
  RUN(test_not_meaningful_cbw);
  RUN(test_short_packet_in_data_out);
  RUN(test_stray_packets_discarded);
  RUN(test_reset_mid_data_in);
  RUN(test_reentrant_in_ready);
  return t_finish("test_bot");
}
