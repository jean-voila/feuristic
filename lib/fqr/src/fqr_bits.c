// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * QR data bit-stream parser (ISO/IEC 18004 §7.4).
 *
 * Every declared character count is validated against the number of bits
 * actually remaining before any data is read, and every value read is
 * range-checked (numeric groups <= 999, alphanumeric pairs < 2025, ...).
 * Output is bounded by the caller's capacity; the required length is still
 * computed so that the caller can report it.
 */

#include "fqr_internal.h"

typedef struct {
  const uint8_t *buf;
  size_t nbits;
  size_t pos;
} bitreader_t;

static inline size_t br_avail(const bitreader_t *br) {
  return br->nbits - br->pos;
}

/* Reads n <= 24 bits; the caller has checked br_avail() >= n. */
static uint32_t br_read(bitreader_t *br, unsigned n) {
  uint32_t v = 0;
  for (unsigned i = 0; i < n; i++) {
    size_t p = br->pos++;
    v = (v << 1) | ((uint32_t)(br->buf[p >> 3] >> (7u - (p & 7u))) & 1u);
  }
  return v;
}

typedef struct {
  uint8_t *out;
  size_t cap;
  size_t len; /* bytes produced (may exceed cap: then nothing more is stored) */
} sink_t;

static inline void sink_put(sink_t *s, uint8_t byte) {
  if (s->len < s->cap) {
    s->out[s->len] = byte;
  }
  if (s->len < SIZE_MAX) {
    s->len++;
  }
}

static const char ALNUM[45] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E',
    'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z', ' ', '$', '%', '*', '+', '-', '.', '/', ':',
};

/* Character count indicator length (ISO Table 3), by version group. */
static unsigned count_bits(unsigned mode, unsigned version) {
  static const uint8_t numeric[3] = {10u, 12u, 14u};
  static const uint8_t alnum[3] = {9u, 11u, 13u};
  static const uint8_t byte[3] = {8u, 16u, 16u};
  static const uint8_t kanji[3] = {8u, 10u, 12u};
  unsigned g = version <= 9u ? 0u : (version <= 26u ? 1u : 2u);
  switch (mode) {
    case 1u:
      return numeric[g];
    case 2u:
      return alnum[g];
    case 4u:
      return byte[g];
    default:
      return kanji[g];
  }
}

/* Alphanumeric output with the FNC1 '%' convention (ISO/IEC 18004 §7.4.8.4:
 * in FNC1 mode "%%" encodes '%' and a lone '%' encodes GS, 0x1D). */
typedef struct {
  bool fnc1;
  bool pending_pct;
} alnum_state_t;

static void alnum_put(sink_t *s, alnum_state_t *st, char ch) {
  if (!st->fnc1) {
    sink_put(s, (uint8_t)ch);
    return;
  }
  if (st->pending_pct) {
    st->pending_pct = false;
    if (ch == '%') {
      sink_put(s, (uint8_t)'%');
      return;
    }
    sink_put(s, 0x1Du);
  }
  if (ch == '%') {
    st->pending_pct = true;
  } else {
    sink_put(s, (uint8_t)ch);
  }
}

static void alnum_flush(sink_t *s, alnum_state_t *st) {
  if (st->pending_pct) {
    st->pending_pct = false;
    sink_put(s, 0x1Du);
  }
}

fqr_stage_t fqr_parse_segments(const uint8_t *data, size_t ndata,
                               unsigned version, fqr_result_t *res,
                               bool *overflow) {
  bitreader_t br = {data, ndata * 8u, 0u};
  sink_t sink = {res->payload, res->payload == NULL ? 0u : res->payload_cap,
                 0u};
  alnum_state_t ast = {false, false};
  bool data_seen = false;

  *overflow = false;
  res->modes = 0;
  res->eci_count = 0;
  memset(res->eci, 0, sizeof res->eci);
  memset(&res->structured_append, 0, sizeof res->structured_append);
  res->fnc1_app_indicator = 0;
  res->payload_len = 0;

  if (version < FQR_VERSION_MIN || version > FQR_VERSION_MAX ||
      ndata > FQR_MAX_CODEWORDS) {
    return FQR_STAGE_DATA;
  }

  for (;;) {
    if (br_avail(&br) < 4u) {
      break; /* implicit terminator (ISO §7.4.9) */
    }
    unsigned mode = (unsigned)br_read(&br, 4u);
    if (mode == 0u) {
      break; /* terminator; padding that follows is ignored */
    }
    switch (mode) {
      case 1u: { /* numeric */
        unsigned cb = count_bits(1u, version);
        if (br_avail(&br) < cb) {
          return FQR_STAGE_DATA;
        }
        uint32_t n = br_read(&br, cb);
        size_t need = (size_t)(n / 3u) * 10u +
                      ((n % 3u) == 2u ? 7u : ((n % 3u) == 1u ? 4u : 0u));
        if (br_avail(&br) < need) {
          return FQR_STAGE_DATA;
        }
        while (n >= 3u) {
          uint32_t v = br_read(&br, 10u);
          if (v > 999u) {
            return FQR_STAGE_DATA;
          }
          sink_put(&sink, (uint8_t)('0' + v / 100u));
          sink_put(&sink, (uint8_t)('0' + (v / 10u) % 10u));
          sink_put(&sink, (uint8_t)('0' + v % 10u));
          n -= 3u;
        }
        if (n == 2u) {
          uint32_t v = br_read(&br, 7u);
          if (v > 99u) {
            return FQR_STAGE_DATA;
          }
          sink_put(&sink, (uint8_t)('0' + v / 10u));
          sink_put(&sink, (uint8_t)('0' + v % 10u));
        } else if (n == 1u) {
          uint32_t v = br_read(&br, 4u);
          if (v > 9u) {
            return FQR_STAGE_DATA;
          }
          sink_put(&sink, (uint8_t)('0' + v));
        }
        res->modes |= FQR_MODE_NUMERIC;
        data_seen = true;
        break;
      }
      case 2u: { /* alphanumeric */
        unsigned cb = count_bits(2u, version);
        if (br_avail(&br) < cb) {
          return FQR_STAGE_DATA;
        }
        uint32_t n = br_read(&br, cb);
        size_t need = (size_t)(n / 2u) * 11u + (size_t)(n % 2u) * 6u;
        if (br_avail(&br) < need) {
          return FQR_STAGE_DATA;
        }
        while (n >= 2u) {
          uint32_t v = br_read(&br, 11u);
          if (v >= 45u * 45u) {
            return FQR_STAGE_DATA;
          }
          alnum_put(&sink, &ast, ALNUM[v / 45u]);
          alnum_put(&sink, &ast, ALNUM[v % 45u]);
          n -= 2u;
        }
        if (n == 1u) {
          uint32_t v = br_read(&br, 6u);
          if (v >= 45u) {
            return FQR_STAGE_DATA;
          }
          alnum_put(&sink, &ast, ALNUM[v]);
        }
        alnum_flush(&sink, &ast);
        res->modes |= FQR_MODE_ALPHANUMERIC;
        data_seen = true;
        break;
      }
      case 4u: { /* byte */
        unsigned cb = count_bits(4u, version);
        if (br_avail(&br) < cb) {
          return FQR_STAGE_DATA;
        }
        uint32_t n = br_read(&br, cb);
        if (br_avail(&br) / 8u < n) {
          return FQR_STAGE_DATA;
        }
        for (uint32_t i = 0; i < n; i++) {
          sink_put(&sink, (uint8_t)br_read(&br, 8u));
        }
        res->modes |= FQR_MODE_BYTE;
        data_seen = true;
        break;
      }
      case 8u: { /* kanji -> Shift JIS (ISO §7.4.6) */
        unsigned cb = count_bits(8u, version);
        if (br_avail(&br) < cb) {
          return FQR_STAGE_DATA;
        }
        uint32_t n = br_read(&br, cb);
        if (br_avail(&br) / 13u < n) {
          return FQR_STAGE_DATA;
        }
        for (uint32_t i = 0; i < n; i++) {
          uint32_t v = br_read(&br, 13u);
          uint32_t hi = v / 0xC0u, lo = v % 0xC0u;
          uint32_t sj = (hi << 8) | lo;
          sj += (sj < 0x1F00u) ? 0x8140u : 0xC140u;
          /* Valid encoder output lies in 0x8140-0x9FFC or 0xE040-0xEBBF
           * with a trail byte 0x40-0xFC. */
          uint32_t trail = sj & 0xFFu;
          if (trail < 0x40u || trail > 0xFCu ||
              !((sj >= 0x8140u && sj <= 0x9FFCu) ||
                (sj >= 0xE040u && sj <= 0xEBBFu))) {
            return FQR_STAGE_DATA;
          }
          sink_put(&sink, (uint8_t)(sj >> 8));
          sink_put(&sink, (uint8_t)trail);
        }
        res->modes |= FQR_MODE_KANJI;
        data_seen = true;
        break;
      }
      case 7u: { /* ECI (ISO §7.4.2.2) */
        if (br_avail(&br) < 8u) {
          return FQR_STAGE_DATA;
        }
        uint32_t b0 = br_read(&br, 8u);
        uint32_t designator;
        if ((b0 & 0x80u) == 0u) {
          designator = b0;
        } else if ((b0 & 0xC0u) == 0x80u) {
          if (br_avail(&br) < 8u) {
            return FQR_STAGE_DATA;
          }
          designator = ((b0 & 0x3Fu) << 8) | br_read(&br, 8u);
        } else if ((b0 & 0xE0u) == 0xC0u) {
          if (br_avail(&br) < 16u) {
            return FQR_STAGE_DATA;
          }
          designator = ((b0 & 0x1Fu) << 16) | br_read(&br, 16u);
          if (designator > 999999u) {
            return FQR_STAGE_DATA;
          }
        } else {
          return FQR_STAGE_DATA;
        }
        if (res->eci_count < FQR_MAX_ECI) {
          res->eci[res->eci_count].designator = designator;
          res->eci[res->eci_count].offset = sink.len;
        }
        if (res->eci_count < UINT8_MAX) {
          res->eci_count++;
        }
        res->modes |= FQR_MODE_ECI;
        break;
      }
      case 3u: { /* structured append header: once, before any data */
        if (br_avail(&br) < 16u || res->structured_append.present ||
            data_seen) {
          return FQR_STAGE_DATA;
        }
        uint32_t idx = br_read(&br, 4u);
        uint32_t tot = br_read(&br, 4u) + 1u;
        uint32_t par = br_read(&br, 8u);
        if (idx >= tot) {
          return FQR_STAGE_DATA;
        }
        res->structured_append.present = true;
        res->structured_append.index = (uint8_t)idx;
        res->structured_append.total = (uint8_t)tot;
        res->structured_append.parity = (uint8_t)par;
        res->modes |= FQR_MODE_STRUCTURED_APPEND;
        break;
      }
      case 5u: /* FNC1, first position */
        if ((res->modes & FQR_MODE_FNC1_SECOND) != 0u || data_seen) {
          return FQR_STAGE_DATA;
        }
        res->modes |= FQR_MODE_FNC1_FIRST;
        ast.fnc1 = true;
        break;
      case 9u: /* FNC1, second position + application indicator */
        if (br_avail(&br) < 8u || (res->modes & FQR_MODE_FNC1_FIRST) != 0u ||
            data_seen) {
          return FQR_STAGE_DATA;
        }
        res->fnc1_app_indicator = (uint8_t)br_read(&br, 8u);
        res->modes |= FQR_MODE_FNC1_SECOND;
        ast.fnc1 = true;
        break;
      default:
        /* 0110, 1010-1111 are undefined in QR Model 2; 1101 (GB 2312
         * Hanzi) is outside ISO/IEC 18004 and rejected too. */
        return FQR_STAGE_DATA;
    }
  }

  res->payload_len = sink.len;
  *overflow = sink.len > sink.cap;
  return FQR_STAGE_OK;
}
