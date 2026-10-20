// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * Resumable zlib (RFC 1950) / deflate (RFC 1951) inflater.
 *
 * Written from the RFCs for feuristic; the validation rules deliberately
 * mirror zlib's inflate so that the two can be fuzzed differentially:
 *   - zlib header: CM = 8, CINFO <= 7, FCHECK, FDICT rejected;
 *   - code-length code must be complete; literal/length and distance codes
 *     must be complete except for a single code of length 1; an all-zero
 *     distance code is accepted (and fails if ever used);
 *   - HLIT <= 286, HDIST <= 30, end-of-block code required, repeat code 16
 *     not first, repeats may not overflow;
 *   - literal/length 286/287 and distance 30/31 are invalid;
 *   - a distance may not reach before the first output byte (any distance
 *     up to 32768 is otherwise allowed, whatever CINFO says, like zlib);
 *   - the Adler-32 trailer is verified.
 *
 * The decoder is a byte-resumable state machine: every state first makes
 * sure the bits it needs are available and otherwise returns
 * FIMG_INF_NEED_INPUT without consuming them, so input can be cut anywhere.
 * Output goes into the 32 KiB window, which doubles as the output ring;
 * the caller bounds each call with out_max and drains the window between
 * calls. No recursion, no allocation.
 */
#include "fimg_internal.h"

enum {
  S_ZHDR = 0,
  S_BLOCK,
  S_STORED_LEN,
  S_STORED_NLEN,
  S_STORED_COPY,
  S_DYN_HDR,
  S_DYN_CLEN,
  S_DYN_LENS,
  S_DYN_REP,
  S_CODES,
  S_LENEXT,
  S_DIST,
  S_DISTEXT,
  S_COPY,
  S_TRAILER,
  S_DONE,
  S_ERROR
};

static const uint16_t k_lbase[29] = {
    3,  4,  5,  6,  7,  8,  9,  10, 11,  13,  15,  17,  19,  23, 27,
    31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
static const uint8_t k_lext[29] = {0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
                                   2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
static const uint16_t k_dbase[30] = {
    1,    2,    3,    4,    5,    7,    9,    13,    17,    25,
    33,   49,   65,   97,   129,  193,  257,  385,   513,   769,
    1025, 1537, 2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577};
static const uint8_t k_dext[30] = {0, 0, 0,  0,  1,  1,  2,  2,  3,  3,
                                   4, 4, 5,  5,  6,  6,  7,  7,  8,  8,
                                   9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
static const uint8_t k_clorder[19] = {16, 17, 18, 0, 8,  7, 9,  6, 10, 5,
                                      11, 4,  12, 3, 13, 2, 14, 1, 15};

/* ---------------------------------------------------------------------- */
/* checksums                                                                */
/* ---------------------------------------------------------------------- */

static const uint32_t k_crc_nibble[16] = {
    0x00000000u, 0x1db71064u, 0x3b6e20c8u, 0x26d930acu,
    0x76dc4190u, 0x6b6b51f4u, 0x4db26158u, 0x5005713cu,
    0xedb88320u, 0xf00f9344u, 0xd6d6a3e8u, 0xcb61b38cu,
    0x9b64c2b0u, 0x86d3d2d4u, 0xa00ae278u, 0xbdbdf21cu};

uint32_t fimg_crc32(uint32_t crc, const uint8_t *p, size_t n) {
  crc = ~crc;
  for (size_t i = 0; i < n; i++) {
    crc ^= p[i];
    crc = (crc >> 4) ^ k_crc_nibble[crc & 15u];
    crc = (crc >> 4) ^ k_crc_nibble[crc & 15u];
  }
  return ~crc;
}

void fimg_adler32(uint32_t *a, uint32_t *b, const uint8_t *p, size_t n) {
  uint32_t sa = *a, sb = *b;
  while (n > 0) {
    size_t k = n < 5552u ? n : 5552u; /* largest run without 32-bit overflow */
    n -= k;
    while (k--) {
      sa += *p++;
      sb += sa;
    }
    sa %= 65521u;
    sb %= 65521u;
  }
  *a = sa;
  *b = sb;
}

/* ---------------------------------------------------------------------- */
/* Huffman tables                                                           */
/* ---------------------------------------------------------------------- */

/*
 * Build a canonical decoding table from @p n code lengths (0..15).
 * @p is_clen selects the code-length-code rules (must be complete).
 * Returns 0 on success, -1 for an over-subscribed or forbidden incomplete set.
 */
static int huff_build(fimg_huff_t *h, const uint8_t *lens, uint32_t n,
                      int is_clen) {
  uint16_t offs[FIMG_INF_MAXBITS + 2u];
  uint16_t next[FIMG_INF_MAXBITS + 1u];
  uint32_t len, sym, maxlen = 0;
  int32_t left;

  memset(h->count, 0, sizeof h->count);
  memset(h->fast, 0, sizeof h->fast);
  for (sym = 0; sym < n; sym++) h->count[lens[sym]]++;
  if (h->count[0] == n)
    return 0; /* no codes at all: valid, but any decode fails */

  left = 1;
  for (len = 1; len <= FIMG_INF_MAXBITS; len++) {
    left <<= 1;
    left -= (int32_t)h->count[len];
    if (left < 0) return -1; /* over-subscribed */
    if (h->count[len] != 0) maxlen = len;
  }
  if (left > 0 && (is_clen || maxlen != 1))
    return -1; /* incomplete (only a single 1-bit code may be) */

  offs[1] = 0;
  for (len = 1; len <= FIMG_INF_MAXBITS; len++)
    offs[len + 1] = (uint16_t)(offs[len] + h->count[len]);
  for (sym = 0; sym < n; sym++)
    if (lens[sym] != 0) h->symbol[offs[lens[sym]]++] = (uint16_t)sym;

  /* canonical codes (RFC 1951 3.2.2), bit-reversed into the fast table */
  {
    uint32_t code = 0;
    for (len = 1; len <= FIMG_INF_MAXBITS; len++) {
      next[len] = (uint16_t)code;
      code = (code + h->count[len]) << 1;
    }
  }
  for (sym = 0; sym < n; sym++) {
    uint32_t l = lens[sym];
    uint32_t c, rev, i;
    if (l == 0) continue;
    c = next[l]++;
    if (l > FIMG_INF_FAST_BITS) continue;
    rev = 0;
    for (i = 0; i < l; i++) rev |= ((c >> i) & 1u) << (l - 1u - i);
    for (i = rev; i < (1u << FIMG_INF_FAST_BITS); i += (1u << l))
      h->fast[i] = (uint16_t)((l << 9) | sym);
  }
  return 0;
}

/* Pull input bytes until at least @p want (<= 24) bits are buffered. */
static int need_bits(fimg_inflate_t *s, const uint8_t *in, size_t in_len,
                     size_t *pos, uint32_t want) {
  while (s->bitcnt < want) {
    if (*pos >= in_len) return 0;
    s->bitbuf |= (uint32_t)in[(*pos)++] << s->bitcnt;
    s->bitcnt += 8u;
  }
  return 1;
}

static uint32_t take_bits(fimg_inflate_t *s, uint32_t n) {
  uint32_t v = s->bitbuf & ((1u << n) - 1u);
  s->bitbuf >>= n;
  s->bitcnt -= n;
  return v;
}

/*
 * Decode one symbol. Returns the symbol (>= 0), -1 if more input is needed
 * (nothing consumed), -2 for an invalid code.
 */
static int32_t huff_decode(fimg_inflate_t *s, const fimg_huff_t *h,
                           const uint8_t *in, size_t in_len, size_t *pos) {
  uint32_t e, len, code, first, index, avail;

  (void)need_bits(s, in, in_len, pos, FIMG_INF_MAXBITS);
  e = h->fast[s->bitbuf & ((1u << FIMG_INF_FAST_BITS) - 1u)];
  if (e != 0) {
    len = e >> 9;
    if (len <= s->bitcnt) {
      s->bitbuf >>= len;
      s->bitcnt -= len;
      return (int32_t)(e & 511u);
    }
    return -1; /* short code but not enough bits yet */
  }
  /* slow canonical walk (codes longer than FAST_BITS, or invalid) */
  avail = s->bitcnt < FIMG_INF_MAXBITS ? s->bitcnt : FIMG_INF_MAXBITS;
  code = first = index = 0;
  for (len = 1; len <= avail; len++) {
    uint32_t count = h->count[len];
    code |= (s->bitbuf >> (len - 1u)) & 1u;
    if (code - first < count) { /* code >= first holds by construction */
      s->bitbuf >>= len;
      s->bitcnt -= len;
      return (int32_t)h->symbol[index + (code - first)];
    }
    index += count;
    first += count;
    first <<= 1;
    code <<= 1;
  }
  return (avail < FIMG_INF_MAXBITS) ? -1 : -2;
}

static void load_fixed(fimg_inflate_t *s) {
  uint32_t i;
  for (i = 0; i < 144; i++) s->lens[i] = 8;
  for (; i < 256; i++) s->lens[i] = 9;
  for (; i < 280; i++) s->lens[i] = 7;
  for (; i < 288; i++) s->lens[i] = 8;
  (void)huff_build(&s->lencode, s->lens, 288, 0);
  for (i = 0; i < 32; i++) s->lens[i] = 5;
  (void)huff_build(&s->distcode, s->lens, 32, 0);
  s->tables = 1;
}

void fimg_inflate_init_paged(fimg_inflate_t *s, uint8_t *first,
                             uint8_t *second) {
  memset(s, 0, sizeof *s);
  s->win[0] = first;
  s->win[1] = second;
  s->adler_a = 1;
  s->state = S_ZHDR;
}

void fimg_inflate_init(fimg_inflate_t *s, uint8_t *window) {
  fimg_inflate_init_paged(s, window, window + FIMG_INF_PAGE_SIZE);
}

static void window_adler(fimg_inflate_t *s, uint32_t at, uint32_t n) {
  while (n != 0) {
    uint32_t k = FIMG_INF_PAGE_SIZE - (at & FIMG_INF_PAGE_MASK);
    if (k > n) k = n;
    fimg_adler32(&s->adler_a, &s->adler_b, fimg_window_ptr(s, at), k);
    at = (at + k) & FIMG_INF_WMASK;
    n -= k;
  }
}

fimg_inf_result_t fimg_inflate(fimg_inflate_t *s, const uint8_t *in,
                               size_t in_len, size_t *in_used, uint32_t out_max,
                               uint32_t *produced) {
  size_t pos = 0;
  uint32_t out = 0, flushed = 0;
  const uint32_t start = s->wpos;
  fimg_inf_result_t r = FIMG_INF_NEED_INPUT;
  int32_t sym;

  if (out_max > FIMG_INF_WSIZE) out_max = FIMG_INF_WSIZE;

#define NEED(n)                                 \
  do {                                          \
    if (!need_bits(s, in, in_len, &pos, (n))) { \
      r = FIMG_INF_NEED_INPUT;                  \
      goto leave;                               \
    }                                           \
  } while (0)
#define FAIL(code)            \
  do {                        \
    s->state = S_ERROR;       \
    s->err = (int32_t)(code); \
    r = (code);               \
    goto leave;               \
  } while (0)

  for (;;) {
    switch (s->state) {
      case S_ZHDR: {
        uint32_t cmf, flg;
        NEED(16);
        cmf = take_bits(s, 8);
        flg = take_bits(s, 8);
        if ((cmf & 15u) != 8u || (cmf >> 4) > 7u ||
            ((cmf << 8) | flg) % 31u != 0u)
          FAIL(FIMG_INF_ERR_HEADER);
        if (flg & 0x20u) FAIL(FIMG_INF_ERR_DICT);
        s->state = S_BLOCK;
        break;
      }
      case S_BLOCK: {
        uint32_t type;
        NEED(3);
        s->last = take_bits(s, 1);
        type = take_bits(s, 2);
        if (type == 0) {
          take_bits(s, s->bitcnt & 7u); /* align to a byte boundary */
          s->state = S_STORED_LEN;
        } else if (type == 1) {
          if (s->tables != 1) load_fixed(s);
          s->state = S_CODES;
        } else if (type == 2) {
          s->state = S_DYN_HDR;
        } else {
          FAIL(FIMG_INF_ERR_BLOCK);
        }
        break;
      }
      case S_STORED_LEN:
        NEED(16);
        s->len = take_bits(s, 16);
        s->state = S_STORED_NLEN;
        break;
      case S_STORED_NLEN:
        NEED(16);
        if ((take_bits(s, 16) ^ 0xffffu) != s->len) FAIL(FIMG_INF_ERR_STORED);
        s->state = S_STORED_COPY;
        break;
      case S_STORED_COPY:
        while (s->len > 0) {
          if (out >= out_max) {
            r = FIMG_INF_OUT_FULL;
            goto leave;
          }
          if (s->bitcnt >= 8u) {
            *fimg_window_ptr(s, s->wpos) = (uint8_t)take_bits(s, 8);
            s->wpos = (s->wpos + 1u) & FIMG_INF_WMASK;
            out++;
            s->total++;
            s->len--;
          } else {
            size_t k = s->len;
            if (pos >= in_len) {
              r = FIMG_INF_NEED_INPUT;
              goto leave;
            }
            if (k > in_len - pos) k = in_len - pos;
            if (k > out_max - out) k = out_max - out;
            if (k > FIMG_INF_PAGE_SIZE - (s->wpos & FIMG_INF_PAGE_MASK))
              k = FIMG_INF_PAGE_SIZE - (s->wpos & FIMG_INF_PAGE_MASK);
            memcpy(fimg_window_ptr(s, s->wpos), in + pos, k);
            pos += k;
            s->wpos = (s->wpos + (uint32_t)k) & FIMG_INF_WMASK;
            out += (uint32_t)k;
            s->total += (uint32_t)k;
            s->len -= (uint32_t)k;
          }
        }
        s->state = s->last ? S_TRAILER : S_BLOCK;
        break;
      case S_DYN_HDR:
        NEED(14);
        s->nlen = take_bits(s, 5) + 257u;
        s->ndist = take_bits(s, 5) + 1u;
        s->ncode = take_bits(s, 4) + 4u;
        if (s->nlen > 286u || s->ndist > 30u) FAIL(FIMG_INF_ERR_TREE);
        s->idx = 0;
        s->tables = 2;
        s->state = S_DYN_CLEN;
        break;
      case S_DYN_CLEN:
        while (s->idx < s->ncode) {
          NEED(3);
          s->lens[k_clorder[s->idx++]] = (uint8_t)take_bits(s, 3);
        }
        while (s->idx < 19u) s->lens[k_clorder[s->idx++]] = 0;
        if (huff_build(&s->lencode, s->lens, 19, 1) != 0)
          FAIL(FIMG_INF_ERR_TREE);
        s->idx = 0;
        s->state = S_DYN_LENS;
        break;
      case S_DYN_LENS:
        while (s->idx < s->nlen + s->ndist) {
          sym = huff_decode(s, &s->lencode, in, in_len, &pos);
          if (sym == -1) {
            r = FIMG_INF_NEED_INPUT;
            goto leave;
          }
          if (sym < 0) FAIL(FIMG_INF_ERR_TREE);
          if (sym < 16) {
            s->lens[s->idx++] = (uint8_t)sym;
          } else {
            if (sym == 16 && s->idx == 0) FAIL(FIMG_INF_ERR_TREE);
            s->sym = (uint32_t)sym;
            s->state = S_DYN_REP;
            break;
          }
        }
        if (s->state == S_DYN_REP) break;
        if (s->lens[256] == 0) FAIL(FIMG_INF_ERR_TREE);
        if (huff_build(&s->lencode, s->lens, s->nlen, 0) != 0 ||
            huff_build(&s->distcode, s->lens + s->nlen, s->ndist, 0) != 0)
          FAIL(FIMG_INF_ERR_TREE);
        s->state = S_CODES;
        break;
      case S_DYN_REP: {
        uint32_t rep, val;
        if (s->sym == 16) {
          NEED(2);
          rep = 3u + take_bits(s, 2);
          val = s->lens[s->idx - 1u];
        } else if (s->sym == 17) {
          NEED(3);
          rep = 3u + take_bits(s, 3);
          val = 0;
        } else {
          NEED(7);
          rep = 11u + take_bits(s, 7);
          val = 0;
        }
        if (s->idx + rep > s->nlen + s->ndist) FAIL(FIMG_INF_ERR_TREE);
        while (rep--) s->lens[s->idx++] = (uint8_t)val;
        s->state = S_DYN_LENS;
        break;
      }
      case S_CODES:
        for (;;) {
          if (out >= out_max) {
            r = FIMG_INF_OUT_FULL;
            goto leave;
          }
          sym = huff_decode(s, &s->lencode, in, in_len, &pos);
          if (sym < 256) {
            if (sym == -1) {
              r = FIMG_INF_NEED_INPUT;
              goto leave;
            }
            if (sym < 0) FAIL(FIMG_INF_ERR_CODE);
            *fimg_window_ptr(s, s->wpos) = (uint8_t)sym;
            s->wpos = (s->wpos + 1u) & FIMG_INF_WMASK;
            out++;
            s->total++;
            continue;
          }
          break;
        }
        if (sym == 256) {
          s->state = s->last ? S_TRAILER : S_BLOCK;
          break;
        }
        if (sym > 285) FAIL(FIMG_INF_ERR_CODE);
        s->sym = (uint32_t)sym - 257u;
        s->state = S_LENEXT;
        break;
      case S_LENEXT: {
        uint32_t eb = k_lext[s->sym];
        NEED(eb);
        s->len = k_lbase[s->sym] + (eb ? take_bits(s, eb) : 0u);
        s->state = S_DIST;
        break;
      }
      case S_DIST:
        sym = huff_decode(s, &s->distcode, in, in_len, &pos);
        if (sym == -1) {
          r = FIMG_INF_NEED_INPUT;
          goto leave;
        }
        if (sym < 0 || sym >= 30) FAIL(FIMG_INF_ERR_CODE);
        s->sym = (uint32_t)sym;
        s->state = S_DISTEXT;
        break;
      case S_DISTEXT: {
        uint32_t eb = k_dext[s->sym];
        NEED(eb);
        s->dist = k_dbase[s->sym] + (eb ? take_bits(s, eb) : 0u);
        if (s->total < FIMG_INF_WSIZE && s->dist > s->total)
          FAIL(FIMG_INF_ERR_DIST);
        s->state = S_COPY;
        break;
      }
      case S_COPY: {
        uint32_t k = s->len, from;
        if (k > out_max - out) k = out_max - out;
        from = (s->wpos - s->dist) & FIMG_INF_WMASK;
        out += k;
        s->total += k;
        s->len -= k;
        while (k--) {
          *fimg_window_ptr(s, s->wpos) = *fimg_window_ptr(s, from);
          s->wpos = (s->wpos + 1u) & FIMG_INF_WMASK;
          from = (from + 1u) & FIMG_INF_WMASK;
        }
        if (s->len > 0) {
          r = FIMG_INF_OUT_FULL;
          goto leave;
        }
        s->state = S_CODES;
        break;
      }
      case S_TRAILER:
        take_bits(s, s->bitcnt & 7u);
        while (s->hdr_n < 4u) {
          NEED(8);
          s->hdr = (s->hdr << 8) | take_bits(s, 8);
          s->hdr_n++;
        }
        /* bring the checksum up to date with this call's output */
        {
          uint32_t p0 = (start + flushed) & FIMG_INF_WMASK, n = out - flushed;
          window_adler(s, p0, n);
          flushed = out;
        }
        if (((s->adler_b << 16) | s->adler_a) != s->hdr)
          FAIL(FIMG_INF_ERR_ADLER);
        s->state = S_DONE;
        break;
      case S_DONE:
        r = FIMG_INF_DONE;
        goto leave;
      default: /* S_ERROR: sticky */
        r = (fimg_inf_result_t)s->err;
        goto leave;
    }
  }

leave:
  if (out > flushed) {
    uint32_t p0 = (start + flushed) & FIMG_INF_WMASK, n = out - flushed;
    window_adler(s, p0, n);
  }
  if (s->total > 0x7fffffffu)
    s->total = 0x40000000u; /* only "has 32 KiB of history" matters */
  *in_used = pos;
  *produced = out;
  return r;
#undef NEED
#undef FAIL
}
