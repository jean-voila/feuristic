// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
//
// SCSI command set: one test per command, sense data, unit attention,
// eject / stop semantics.

#include <stdlib.h>
#include <string.h>

#include "tharness.h"

static host_t *mk(void) {
  host_t *h = host_new();
  host_open(h);
  host_clear_ua(h);
  return h;
}

static uint32_t be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void expect_sense(host_t *h, uint8_t key, uint8_t asc, uint8_t ascq) {
  uint8_t k = 0xFF, a = 0xFF, q = 0xFF;
  CHECK_EQ(scsi_sense(h, &k, &a, &q), 0);
  CHECK_EQ(k, key);
  CHECK_EQ(a, asc);
  CHECK_EQ(q, ascq);
}

// Generic data-in command; returns status, fills `got`.
static int cmd_in(host_t *h, const uint8_t *cdb, uint8_t len, uint32_t xfer, uint8_t *buf,
                  uint32_t *got) {
  const xfer_t r = host_bot(h, cdb, len, true, xfer, NULL, buf);
  CHECK(r.csw_ok);
  if (got != NULL) *got = r.got;
  return r.csw_ok ? r.status : -1;
}

static int cmd_none(host_t *h, const uint8_t *cdb, uint8_t len) {
  const xfer_t r = host_bot(h, cdb, len, false, 0, NULL, NULL);
  CHECK(r.csw_ok);
  return r.csw_ok ? r.status : -1;
}

static void test_unit_attention(void) {
  host_t *h = host_new();
  host_open(h);
  uint8_t cdb[6] = {0x12, 0, 0, 0, 36, 0};
  uint8_t buf[64];
  // INQUIRY does not report (nor clear) the unit attention.
  CHECK_EQ(cmd_in(h, cdb, 6, 36, buf, NULL), 0);
  CHECK_EQ(scsi_tur(h), 1);
  expect_sense(h, 0x06, 0x29, 0x00);
  CHECK_EQ(scsi_tur(h), 0);
  expect_sense(h, 0x00, 0x00, 0x00);
  host_free(h);
  // REQUEST SENSE as first command reports the UA and clears it.
  h = host_new();
  host_open(h);
  expect_sense(h, 0x06, 0x29, 0x00);
  CHECK_EQ(scsi_tur(h), 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_inquiry_standard(void) {
  host_t *h = mk();
  uint8_t cdb[6] = {0x12, 0, 0, 0, 96, 0};
  uint8_t b[96];
  uint32_t got = 0;
  CHECK_EQ(cmd_in(h, cdb, 6, 96, b, &got), 0);
  CHECK_EQ(got, 36);
  CHECK_EQ(b[0], 0x00);
  CHECK_EQ(b[1], 0x80);
  CHECK_EQ(b[3] & 0x0F, 2);
  CHECK_EQ(b[4], 31);
  CHECK(memcmp(b + 8, "FEURISTC", 8) == 0);
  CHECK(memcmp(b + 16, "FEURISTIC-IMPORT", 16) == 0);
  CHECK(memcmp(b + 32, "0.1 ", 4) == 0);
  // Allocation length smaller than the data.
  cdb[4] = 5;
  CHECK_EQ(cmd_in(h, cdb, 6, 5, b, &got), 0);
  CHECK_EQ(got, 5);
  // Allocation length 0: no data phase (case 4 with 36-byte host buffer).
  cdb[4] = 0;
  CHECK_EQ(cmd_in(h, cdb, 6, 36, b, &got), 0);
  CHECK_EQ(got, 0);
  // EVPD = 0 with a page code / CMDDT set: invalid field.
  const uint8_t bad1[6] = {0x12, 0, 0x80, 0, 36, 0};
  CHECK_EQ(cmd_in(h, bad1, 6, 36, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  const uint8_t bad2[6] = {0x12, 0x02, 0, 0, 36, 0};
  CHECK_EQ(cmd_in(h, bad2, 6, 36, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_inquiry_vpd(void) {
  host_t *h = mk();
  uint8_t b[64];
  uint32_t got = 0;
  const uint8_t p0[6] = {0x12, 1, 0x00, 0, 64, 0};
  CHECK_EQ(cmd_in(h, p0, 6, 64, b, &got), 0);
  CHECK_EQ(got, 6);
  CHECK_EQ(b[1], 0x00);
  CHECK_EQ(b[3], 2);
  CHECK_EQ(b[4], 0x00);
  CHECK_EQ(b[5], 0x80);
  const uint8_t p80[6] = {0x12, 1, 0x80, 0, 64, 0};
  CHECK_EQ(cmd_in(h, p80, 6, 64, b, &got), 0);
  CHECK_EQ(got, 4 + 8);
  CHECK_EQ(b[1], 0x80);
  CHECK_EQ(b[3], 8);
  CHECK(memcmp(b + 4, "FEUR0001", 8) == 0);
  const uint8_t p83[6] = {0x12, 1, 0x83, 0, 64, 0};
  CHECK_EQ(cmd_in(h, p83, 6, 64, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_request_sense_format(void) {
  host_t *h = mk();
  const uint8_t bad[6] = {0xFF, 0, 0, 0, 0, 0};
  CHECK_EQ(cmd_none(h, bad, 6), 1);
  const uint8_t rs[6] = {0x03, 0, 0, 0, 252, 0};
  uint8_t b[252];
  uint32_t got = 0;
  CHECK_EQ(cmd_in(h, rs, 6, 252, b, &got), 0);
  CHECK_EQ(got, 18);
  CHECK_EQ(b[0], 0x70);
  CHECK_EQ(b[2], 0x05);
  CHECK_EQ(b[7], 10);
  CHECK_EQ(b[12], 0x20);
  CHECK_EQ(b[13], 0x00);
  // Sense is consumed.
  expect_sense(h, 0, 0, 0);
  // DESC=1 is not supported.
  const uint8_t desc[6] = {0x03, 1, 0, 0, 18, 0};
  CHECK_EQ(cmd_in(h, desc, 6, 18, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_invalid_opcodes(void) {
  host_t *h = mk();
  const uint8_t ops[] = {0xA0, 0x9E, 0x15, 0x55, 0x08, 0x0A, 0x04, 0xA1, 0x85, 0x4A, 0xFF};
  for (size_t i = 0; i < sizeof ops; i++) {
    uint8_t cdb[12];
    memset(cdb, 0, sizeof cdb);
    cdb[0] = ops[i];
    CHECK_EQ(cmd_none(h, cdb, 12), 1);
    expect_sense(h, 0x05, 0x20, 0x00);
  }
  // CB length shorter than the opcode's CDB.
  const uint8_t rd[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 1, 0};
  CHECK_EQ(cmd_in(h, rd, 6, 512, NULL, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  // NACA bit in the control byte.
  const uint8_t naca[6] = {0x00, 0, 0, 0, 0, 0x04};
  CHECK_EQ(cmd_none(h, naca, 6), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_read_capacity(void) {
  host_t *h = mk();
  uint8_t cdb[10] = {0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  uint8_t b[8];
  uint32_t got = 0;
  CHECK_EQ(cmd_in(h, cdb, 10, 8, b, &got), 0);
  CHECK_EQ(got, 8);
  CHECK_EQ(be32(b), FMSC_TOTAL_SECTORS - 1);
  CHECK_EQ(be32(b + 4), 512);
  cdb[5] = 1;  // LBA != 0 with PMI = 0
  CHECK_EQ(cmd_in(h, cdb, 10, 8, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  cdb[8] = 1;  // PMI = 1: accepted
  CHECK_EQ(cmd_in(h, cdb, 10, 8, b, NULL), 0);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_read_format_capacities(void) {
  host_t *h = mk();
  const uint8_t cdb[10] = {0x23, 0, 0, 0, 0, 0, 0, 0, 0xFC, 0};
  uint8_t b[252];
  uint32_t got = 0;
  CHECK_EQ(cmd_in(h, cdb, 10, 252, b, &got), 0);
  CHECK_EQ(got, 12);
  CHECK_EQ(b[3], 8);
  CHECK_EQ(be32(b + 4), FMSC_TOTAL_SECTORS);
  CHECK_EQ(b[8], 0x02);
  CHECK_EQ((b[9] << 16) | (b[10] << 8) | b[11], 512);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_mode_sense(void) {
  host_t *h = mk();
  uint8_t b[255];
  uint32_t got = 0;
  uint8_t c6[6] = {0x1A, 0, 0x3F, 0, 192, 0};
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, &got), 0);
  CHECK_EQ(got, 24);
  CHECK_EQ(b[0], 23);
  CHECK_EQ(b[2] & 0x80, 0);  // not write protected
  CHECK_EQ(b[3], 0);         // no block descriptor
  CHECK_EQ(b[4], 0x08);
  CHECK_EQ(b[5], 0x12);
  CHECK_EQ(b[6] & 0x04, 0x04);  // WCE
  c6[2] = 0x08;
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, &got), 0);
  CHECK_EQ(got, 24);
  c6[2] = 0x48;  // changeable values
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, &got), 0);
  CHECK_EQ(b[6], 0);
  c6[2] = 0xC8;  // saved values
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, NULL), 1);
  expect_sense(h, 0x05, 0x39, 0x00);
  c6[2] = 0x1C;  // unsupported page
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  c6[2] = 0x3F;
  c6[3] = 0xFF;  // all subpages
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, &got), 0);
  c6[3] = 0x01;
  CHECK_EQ(cmd_in(h, c6, 6, 192, b, NULL), 1);
  c6[3] = 0;
  c6[4] = 4;  // header only
  CHECK_EQ(cmd_in(h, c6, 6, 4, b, &got), 0);
  CHECK_EQ(got, 4);
  const uint8_t c10[10] = {0x5A, 0, 0x3F, 0, 0, 0, 0, 0, 0xFF, 0};
  CHECK_EQ(cmd_in(h, c10, 10, 255, b, &got), 0);
  CHECK_EQ(got, 28);
  CHECK_EQ((b[0] << 8) | b[1], 26);
  CHECK_EQ(b[3] & 0x80, 0);
  CHECK_EQ((b[6] << 8) | b[7], 0);
  CHECK_EQ(b[8], 0x08);
  CHECK_EQ(b[10] & 0x04, 0x04);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_read_write_range(void) {
  host_t *h = mk();
  uint8_t sec[512];
  CHECK_EQ(scsi_read10(h, FMSC_TOTAL_SECTORS - 1, 1, sec), 0);
  CHECK_EQ(scsi_read10(h, FMSC_TOTAL_SECTORS, 1, sec), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  uint8_t two[1024];
  CHECK_EQ(scsi_read10(h, FMSC_TOTAL_SECTORS - 1, 2, two), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  CHECK_EQ(scsi_read10(h, 0xFFFFFFFFu, 1, sec), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  memset(sec, 0x12, sizeof sec);
  CHECK_EQ(scsi_write10(h, FMSC_TOTAL_SECTORS, 1, sec), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  // Zero-length transfers are valid no-ops.
  const uint8_t r0[10] = {0x28, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK_EQ(cmd_none(h, r0, 10), 0);
  const uint8_t w0[10] = {0x2A, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK_EQ(cmd_none(h, w0, 10), 0);
  // RDPROTECT / WRPROTECT.
  const uint8_t rp[10] = {0x28, 0x20, 0, 0, 0, 0, 0, 0, 1, 0};
  CHECK_EQ(cmd_in(h, rp, 10, 512, sec, NULL), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_verify_and_sync(void) {
  host_t *h = mk();
  uint8_t v[10] = {0x2F, 0, 0, 0, 0, 0, 0, 0, 8, 0};
  CHECK_EQ(cmd_none(h, v, 10), 0);
  v[1] = 0x02;  // BYTCHK
  CHECK_EQ(cmd_none(h, v, 10), 1);
  expect_sense(h, 0x05, 0x24, 0x00);
  v[1] = 0;
  v[2] = 0xFF;  // beyond the end
  CHECK_EQ(cmd_none(h, v, 10), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  CHECK_EQ(scsi_sync(h), 0);
  const uint8_t s2[10] = {0x35, 0, 0, 0, 0x7F, 0x9C, 0, 0, 2, 0};  // lba 32668, 2 blocks
  CHECK_EQ(cmd_none(h, s2, 10), 1);
  expect_sense(h, 0x05, 0x21, 0x00);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_eject(void) {
  host_t *h = mk();
  CHECK_EQ(scsi_prevent(h, true), 0);
  CHECK_EQ(scsi_start_stop(h, true, false), 1);
  expect_sense(h, 0x05, 0x53, 0x02);
  CHECK(!fmsc_is_ejected(&h->ctx));
  CHECK_EQ(scsi_prevent(h, false), 0);
  // The EJECTED event is emitted only once the CSW is consumed.
  const uint8_t cdb[6] = {0x1B, 0, 0, 0, 0x02, 0};
  uint8_t cbw[31];
  host_build_cbw(cbw, 77, 0, 0, 0, 6, cdb);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 0);
  uint8_t pkt[64];
  CHECK_EQ(host_read_in(h, pkt), 13);
  CHECK_EQ(pkt[12], 0);
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 1);
  CHECK(fmsc_is_ejected(&h->ctx));
  CHECK_EQ(scsi_tur(h), 1);
  expect_sense(h, 0x02, 0x3A, 0x00);
  expect_sense(h, 0x02, 0x3A, 0x00);  // persistent condition
  uint8_t sec[512];
  CHECK_EQ(scsi_read10(h, 0, 1, sec), 1);
  CHECK_EQ(scsi_write10(h, 100, 1, sec), 1);
  CHECK_EQ(scsi_sync(h), 1);
  const uint8_t inq[6] = {0x12, 0, 0, 0, 36, 0};
  CHECK_EQ(cmd_in(h, inq, 6, 36, sec, NULL), 0);  // INQUIRY still answers
  CHECK_EQ(scsi_start_stop(h, true, true), 1);    // cannot reload
  CHECK_EQ(scsi_start_stop(h, true, false), 0);   // repeated eject: no-op
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 1);
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_stop_start(void) {
  host_t *h = mk();
  CHECK_EQ(scsi_start_stop(h, false, false), 0);
  CHECK_EQ(host_count_events(h, FMSC_EVT_STOPPED), 1);
  CHECK(!fmsc_is_ejected(&h->ctx));
  CHECK_EQ(scsi_tur(h), 1);
  expect_sense(h, 0x02, 0x04, 0x02);
  CHECK_EQ(scsi_start_stop(h, false, true), 0);
  CHECK_EQ(scsi_tur(h), 0);
  // Power condition != 0: accepted, no effect.
  const uint8_t pc[6] = {0x1B, 0, 0, 0, 0x32, 0};
  CHECK_EQ(cmd_none(h, pc, 6), 0);
  CHECK_EQ(scsi_tur(h), 0);
  CHECK(!fmsc_is_ejected(&h->ctx));
  CHECK_EQ(h->violations, 0);
  host_free(h);
}

static void test_eject_during_bot_reset(void) {
  host_t *h = mk();
  const uint8_t cdb[6] = {0x1B, 0, 0, 0, 0x02, 0};
  uint8_t cbw[31];
  host_build_cbw(cbw, 5, 0, 0, 0, 6, cdb);
  fmsc_on_out_packet(&h->ctx, cbw, 31);
  host_reset_recovery(h);  // CSW never read: the event is still delivered
  CHECK_EQ(host_count_events(h, FMSC_EVT_EJECTED), 1);
  CHECK(fmsc_is_ejected(&h->ctx));
  host_free(h);
}

int main(void) {
  RUN(test_unit_attention);
  RUN(test_inquiry_standard);
  RUN(test_inquiry_vpd);
  RUN(test_request_sense_format);
  RUN(test_invalid_opcodes);
  RUN(test_read_capacity);
  RUN(test_read_format_capacities);
  RUN(test_mode_sense);
  RUN(test_read_write_range);
  RUN(test_verify_and_sync);
  RUN(test_eject);
  RUN(test_stop_start);
  RUN(test_eject_during_bot_reset);
  return t_finish("test_scsi");
}
