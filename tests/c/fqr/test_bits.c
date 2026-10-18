// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/* Bit-stream (data segment) parser tests. */

#include <string.h>

#include "fqr_internal.h"
#include "qrenc.h"
#include "tcheck.h"

TC_DEFINE_GLOBALS;

static uint8_t out[8192];

/* Parses stream b (padded with zero bits to whole bytes, plus extra pad
 * bytes) for version v; returns stage, fills r. */
static fqr_stage_t parse(const qe_bits_t *b, unsigned v, fqr_result_t *r,
                         size_t cap, bool *overflow) {
  static uint8_t data[4096];
  size_t nbytes = (b->nbits + 7u) / 8u;
  memset(data, 0, sizeof data);
  memcpy(data, b->buf, nbytes);
  memset(r, 0, sizeof *r);
  memset(out, 0xA5, sizeof out);
  r->payload = cap ? out : NULL;
  r->payload_cap = cap;
  return fqr_parse_segments(data, nbytes, v, r, overflow);
}

static void expect(const qe_bits_t *b, unsigned v, const char *want,
                   size_t wlen) {
  fqr_result_t r;
  bool of;
  fqr_stage_t s = parse(b, v, &r, sizeof out, &of);
  CHECK_EQ_INT(s, FQR_STAGE_OK);
  CHECK(!of);
  CHECK_EQ_INT(r.payload_len, wlen);
  CHECK(r.payload_len == wlen && memcmp(out, want, wlen) == 0);
}

static void expect_fail(const qe_bits_t *b, unsigned v) {
  fqr_result_t r;
  bool of;
  CHECK_EQ_INT(parse(b, v, &r, sizeof out, &of), FQR_STAGE_DATA);
}

static void test_numeric(void) {
  qe_bits_t b;
  qe_bits_init(&b);
  qe_seg_numeric(&b, 1, "01234567", 8);
  expect(&b, 1, "01234567", 8);
  for (size_t n = 0; n <= 10; n++) {
    const char *d = "9876543210";
    qe_bits_init(&b);
    qe_seg_numeric(&b, 5, d, n);
    expect(&b, 5, d, n);
  }
  /* Version groups: 12-bit count at v10, 14-bit at v27. */
  qe_bits_init(&b);
  qe_seg_numeric(&b, 10, "123", 3);
  CHECK_EQ_INT(b.nbits, 4 + 12 + 10);
  expect(&b, 10, "123", 3);
  qe_bits_init(&b);
  qe_seg_numeric(&b, 27, "12", 2);
  CHECK_EQ_INT(b.nbits, 4 + 14 + 7);
  expect(&b, 27, "12", 2);
  /* Invalid group values. */
  qe_bits_init(&b);
  qe_put(&b, 1, 4);
  qe_put(&b, 3, 10);
  qe_put(&b, 1000, 10);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 1, 4);
  qe_put(&b, 2, 10);
  qe_put(&b, 100, 7);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 1, 4);
  qe_put(&b, 1, 10);
  qe_put(&b, 10, 4);
  expect_fail(&b, 1);
  /* Count exceeding the stream. */
  qe_bits_init(&b);
  qe_put(&b, 1, 4);
  qe_put(&b, 1023, 10);
  qe_put(&b, 123, 10);
  expect_fail(&b, 1);
}

static void test_alnum(void) {
  qe_bits_t b;
  qe_bits_init(&b);
  qe_seg_alnum(&b, 1, "AC-42", 5);
  expect(&b, 1, "AC-42", 5);
  const char *all = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
  qe_bits_init(&b);
  qe_seg_alnum(&b, 3, all, 45);
  expect(&b, 3, all, 45);
  qe_bits_init(&b);
  qe_put(&b, 2, 4);
  qe_put(&b, 2, 9);
  qe_put(&b, 2025, 11);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 2, 4);
  qe_put(&b, 1, 9);
  qe_put(&b, 45, 6);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 2, 4);
  qe_put(&b, 300, 9);
  expect_fail(&b, 1);
}

static void test_byte(void) {
  uint8_t all[256];
  for (unsigned i = 0; i < 256; i++) {
    all[i] = (uint8_t)i;
  }
  qe_bits_t b;
  qe_bits_init(&b);
  qe_seg_byte(&b, 10, all, 256);
  expect(&b, 10, (const char *)all, 256);
  qe_bits_init(&b);
  qe_seg_byte(&b, 1, all, 0);
  expect(&b, 1, "", 0);
  qe_bits_init(&b);
  qe_put(&b, 4, 4);
  qe_put(&b, 3, 8);
  qe_put(&b, 0x41, 8);
  qe_put(&b, 0x42, 8);
  /* Only 2 bytes + partial: the padded byte stream provides 0 bits for
   * the 3rd byte only if the buffer is long enough -> exact-length test. */
  {
    static uint8_t data[3];
    fqr_result_t r;
    bool of;
    memcpy(data, b.buf, 3);
    memset(&r, 0, sizeof r);
    r.payload = out;
    r.payload_cap = sizeof out;
    CHECK_EQ_INT(fqr_parse_segments(data, 3, 1, &r, &of), FQR_STAGE_DATA);
  }
}

static void test_kanji(void) {
  /* ISO example "点茗" = 0x935F 0xE4AA. */
  const uint8_t sj[4] = {0x93, 0x5F, 0xE4, 0xAA};
  qe_bits_t b;
  qe_bits_init(&b);
  qe_seg_kanji(&b, 1, sj, 2);
  CHECK_EQ_INT(b.nbits, 4 + 8 + 26);
  /* ISO/IEC 18004 §7.4.6 example bit pattern for these two characters. */
  {
    qe_bits_t ref;
    qe_bits_init(&ref);
    qe_put(&ref, 8, 4);
    qe_put(&ref, 2, 8);
    qe_put(&ref, 0x0D9F, 13); /* 0x935F - 0x8140 = 0x121F -> 0x12*0xC0+0x1F */
    qe_put(&ref, 0x1AAA, 13); /* 0xE4AA - 0xC140 = 0x236A -> 0x23*0xC0+0x6A */
    CHECK(memcmp(ref.buf, b.buf, (b.nbits + 7) / 8) == 0);
  }
  expect(&b, 1, (const char *)sj, 4);
  /* Boundary characters. */
  const uint8_t edges[8] = {0x81, 0x40, 0x9F, 0xFC, 0xE0, 0x40, 0xEB, 0xBF};
  qe_bits_init(&b);
  qe_seg_kanji(&b, 2, edges, 4);
  expect(&b, 2, (const char *)edges, 8);
  /* 13-bit value outside Shift JIS. */
  qe_bits_init(&b);
  qe_put(&b, 8, 4);
  qe_put(&b, 1, 8);
  qe_put(&b, 0x17D, 13); /* -> 0x82FD */
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 8, 4);
  qe_put(&b, 1, 8);
  qe_put(&b, 0x1FFF, 13); /* -> 0xEBBF, last valid */
  expect(&b, 1, "\xEB\xBF", 2);
  qe_bits_init(&b);
  qe_put(&b, 8, 4);
  qe_put(&b, 1, 8);
  qe_put(&b, 0x00BF, 13); /* trail 0xFF */
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 8, 4);
  qe_put(&b, 200, 8);
  expect_fail(&b, 1);
}

static void test_eci(void) {
  qe_bits_t b;
  fqr_result_t r;
  bool of;
  qe_bits_init(&b);
  qe_seg_eci(&b, 26);
  qe_seg_byte(&b, 1, (const uint8_t *)"\xc3\xa9", 2);
  qe_seg_eci(&b, 1000);
  qe_seg_byte(&b, 1, (const uint8_t *)"x", 1);
  qe_seg_eci(&b, 999999);
  CHECK_EQ_INT(parse(&b, 3, &r, sizeof out, &of), FQR_STAGE_OK);
  CHECK_EQ_INT(r.eci_count, 3);
  CHECK_EQ_INT(r.eci[0].designator, 26);
  CHECK_EQ_INT(r.eci[0].offset, 0);
  CHECK_EQ_INT(r.eci[1].designator, 1000);
  CHECK_EQ_INT(r.eci[1].offset, 2);
  CHECK_EQ_INT(r.eci[2].designator, 999999);
  CHECK_EQ_INT(r.eci[2].offset, 3);
  CHECK((r.modes & (FQR_MODE_ECI | FQR_MODE_BYTE)) ==
        (FQR_MODE_ECI | FQR_MODE_BYTE));
  CHECK_EQ_INT(r.payload_len, 3);
  /* More than FQR_MAX_ECI: counted, first four kept. */
  qe_bits_init(&b);
  for (unsigned i = 0; i < 6; i++) {
    qe_seg_eci(&b, i + 3);
  }
  CHECK_EQ_INT(parse(&b, 1, &r, sizeof out, &of), FQR_STAGE_OK);
  CHECK_EQ_INT(r.eci_count, 6);
  CHECK_EQ_INT(r.eci[3].designator, 6);
  /* Invalid designators. */
  qe_bits_init(&b);
  qe_put(&b, 7, 4);
  qe_put(&b, 0xC00000u | 1000000u, 24);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 7, 4);
  qe_put(&b, 0xE0, 8);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_put(&b, 7, 4);
  qe_put(&b, 0x80, 8); /* truncated 2-byte form */
  {
    static uint8_t data[2];
    memcpy(data, b.buf, 2);
    memset(&r, 0, sizeof r);
    CHECK_EQ_INT(fqr_parse_segments(data, 2, 1, &r, &of), FQR_STAGE_DATA);
  }
}

static void test_sa_fnc1(void) {
  qe_bits_t b;
  fqr_result_t r;
  bool of;
  qe_bits_init(&b);
  qe_seg_sa(&b, 2, 5, 0x9C);
  qe_seg_byte(&b, 1, (const uint8_t *)"abc", 3);
  CHECK_EQ_INT(parse(&b, 1, &r, sizeof out, &of), FQR_STAGE_OK);
  CHECK(r.structured_append.present);
  CHECK_EQ_INT(r.structured_append.index, 2);
  CHECK_EQ_INT(r.structured_append.total, 5);
  CHECK_EQ_INT(r.structured_append.parity, 0x9C);
  CHECK(r.modes & FQR_MODE_STRUCTURED_APPEND);
  qe_bits_init(&b);
  qe_seg_sa(&b, 15, 16, 0);
  CHECK_EQ_INT(parse(&b, 1, &r, sizeof out, &of), FQR_STAGE_OK);
  qe_bits_init(&b);
  qe_seg_sa(&b, 3, 2, 0); /* index >= total */
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_seg_sa(&b, 0, 2, 0);
  qe_seg_sa(&b, 1, 2, 0);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_seg_byte(&b, 1, (const uint8_t *)"a", 1);
  qe_seg_sa(&b, 0, 2, 0);
  expect_fail(&b, 1);

  /* FNC1 first position: '%' conventions in alphanumeric mode. */
  qe_bits_init(&b);
  qe_fnc1_first(&b);
  qe_seg_alnum(&b, 2, "%%A%B%", 6);
  qe_seg_numeric(&b, 2, "12", 2);
  CHECK_EQ_INT(parse(&b, 2, &r, sizeof out, &of), FQR_STAGE_OK);
  CHECK_EQ_INT(r.payload_len, 7);
  CHECK(memcmp(out,
               "%A\x1D"
               "B\x1D"
               "12",
               7) == 0);
  CHECK(r.modes & FQR_MODE_FNC1_FIRST);
  /* Without FNC1 '%' is literal. */
  qe_bits_init(&b);
  qe_seg_alnum(&b, 2, "%%A", 3);
  expect(&b, 2, "%%A", 3);
  /* FNC1 second position. */
  qe_bits_init(&b);
  qe_fnc1_second(&b, 37);
  qe_seg_alnum(&b, 2, "AB%", 3);
  CHECK_EQ_INT(parse(&b, 2, &r, sizeof out, &of), FQR_STAGE_OK);
  CHECK_EQ_INT(r.fnc1_app_indicator, 37);
  CHECK(r.modes & FQR_MODE_FNC1_SECOND);
  CHECK(r.payload_len == 3 && memcmp(out, "AB\x1D", 3) == 0);
  /* Misplaced FNC1. */
  qe_bits_init(&b);
  qe_seg_byte(&b, 1, (const uint8_t *)"a", 1);
  qe_fnc1_first(&b);
  expect_fail(&b, 1);
  qe_bits_init(&b);
  qe_fnc1_first(&b);
  qe_fnc1_second(&b, 1);
  expect_fail(&b, 1);
}

static void test_terminator_and_modes(void) {
  qe_bits_t b;
  qe_bits_init(&b);
  qe_seg_byte(&b, 1, (const uint8_t *)"hi", 2);
  qe_put(&b, 0, 4);
  qe_put(&b, 0xF, 4); /* garbage after terminator is ignored */
  expect(&b, 1, "hi", 2);
  /* Fewer than 4 bits left acts as terminator. */
  {
    static uint8_t data[3];
    fqr_result_t r;
    bool of;
    qe_bits_init(&b);
    qe_put(&b, 4, 4);
    qe_put(&b, 1, 8);
    qe_put(&b, 'z', 8);
    qe_put(&b, 0x7, 4);
    memcpy(data, b.buf, 3);
    memset(&r, 0, sizeof r);
    r.payload = out;
    r.payload_cap = 10;
    /* 24 bits: mode(4)+count(8)+byte(8) = 20, then "0111"(ECI) with 0
     * bits left for its designator -> malformed. */
    CHECK_EQ_INT(fqr_parse_segments(data, 3, 1, &r, &of), FQR_STAGE_DATA);
    qe_bits_init(&b);
    qe_put(&b, 4, 4);
    qe_put(&b, 1, 8);
    qe_put(&b, 'z', 8);
    qe_put(&b, 0x0, 2);
    memcpy(data, b.buf, 3);
    CHECK_EQ_INT(fqr_parse_segments(data, 3, 1, &r, &of), FQR_STAGE_OK);
    CHECK_EQ_INT(r.payload_len, 1);
  }
  static const unsigned bad[] = {6, 10, 11, 12, 13, 14, 15};
  for (unsigned i = 0; i < sizeof bad / sizeof bad[0]; i++) {
    qe_bits_init(&b);
    qe_put(&b, bad[i], 4);
    qe_put(&b, 0xFFFF, 16);
    expect_fail(&b, 1);
  }
  /* Empty stream: valid empty payload. */
  qe_bits_init(&b);
  qe_put(&b, 0, 8);
  expect(&b, 1, "", 0);
  /* Invalid version argument. */
  {
    fqr_result_t r;
    bool of;
    CHECK_EQ_INT(parse(&b, 0, &r, sizeof out, &of), FQR_STAGE_DATA);
    CHECK_EQ_INT(parse(&b, 41, &r, sizeof out, &of), FQR_STAGE_DATA);
  }
}

static void test_overflow(void) {
  qe_bits_t b;
  fqr_result_t r;
  bool of;
  qe_bits_init(&b);
  qe_seg_byte(&b, 2, (const uint8_t *)"0123456789", 10);
  CHECK_EQ_INT(parse(&b, 2, &r, 4, &of), FQR_STAGE_OK);
  CHECK(of);
  CHECK_EQ_INT(r.payload_len, 10);
  CHECK(memcmp(out, "0123", 4) == 0);
  CHECK_EQ_INT(out[4], 0xA5); /* nothing written past the capacity */
  CHECK_EQ_INT(parse(&b, 2, &r, 0, &of), FQR_STAGE_OK); /* count-only */
  CHECK(of);
  CHECK_EQ_INT(r.payload_len, 10);
  CHECK_EQ_INT(parse(&b, 2, &r, 10, &of), FQR_STAGE_OK);
  CHECK(!of);
}

/* Random valid segment sequences against an expected byte string. */
static void test_random(tc_rng_t *rng) {
  static char expect_buf[8192];
  for (unsigned iter = 0; iter < 3000; iter++) {
    unsigned v = 1 + tc_below(rng, 40);
    qe_bits_t b;
    qe_bits_init(&b);
    size_t elen = 0;
    unsigned nseg = 1 + tc_below(rng, 6);
    for (unsigned s = 0; s < nseg; s++) {
      char tmp[64];
      size_t n = tc_below(rng, 40);
      switch (tc_below(rng, 4)) {
        case 0:
          for (size_t i = 0; i < n; i++)
            tmp[i] = (char)('0' + tc_below(rng, 10));
          qe_seg_numeric(&b, v, tmp, n);
          break;
        case 1:
          for (size_t i = 0; i < n; i++)
            tmp[i] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"[tc_below(
                rng, 45)];
          qe_seg_alnum(&b, v, tmp, n);
          break;
        case 2:
          for (size_t i = 0; i < n; i++) tmp[i] = (char)tc_rand(rng);
          qe_seg_byte(&b, v, (const uint8_t *)tmp, n);
          break;
        default:
          n &= ~(size_t)1;
          for (size_t i = 0; i < n; i += 2) {
            unsigned hi = tc_below(rng, 2)
                              ? 0x81 + tc_below(rng, 0x9F - 0x81 + 1)
                              : 0xE0 + tc_below(rng, 0xEA - 0xE0 + 1);
            tmp[i] = (char)hi;
            tmp[i + 1] = (char)(0x40 + tc_below(rng, 0xFC - 0x40 + 1));
          }
          qe_seg_kanji(&b, v, (const uint8_t *)tmp, n / 2);
          break;
      }
      memcpy(expect_buf + elen, tmp, n);
      elen += n;
    }
    expect(&b, v, expect_buf, elen);
  }
  /* Random garbage never crashes and respects the capacity. */
  for (unsigned iter = 0; iter < 20000; iter++) {
    static uint8_t data[512];
    size_t n = tc_below(rng, sizeof data);
    for (size_t i = 0; i < n; i++) {
      data[i] = (uint8_t)tc_rand(rng);
    }
    fqr_result_t r;
    bool of;
    size_t cap = tc_below(rng, 64);
    memset(&r, 0, sizeof r);
    memset(out, 0xA5, 128);
    r.payload = out;
    r.payload_cap = cap;
    fqr_stage_t s = fqr_parse_segments(data, n, 1 + tc_below(rng, 40), &r, &of);
    CHECK(s == FQR_STAGE_OK || s == FQR_STAGE_DATA);
    CHECK_EQ_INT(out[cap], 0xA5);
    if (s == FQR_STAGE_OK) {
      CHECK(of == (r.payload_len > cap));
    }
  }
}

int main(void) {
  tc_rng_t rng;
  tc_rng_seed(&rng, 0xB175u);
  test_numeric();
  test_alnum();
  test_byte();
  test_kanji();
  test_eci();
  test_sa_fnc1();
  test_terminator_and_modes();
  test_overflow();
  test_random(&rng);
  return tc_report("test_bits");
}
