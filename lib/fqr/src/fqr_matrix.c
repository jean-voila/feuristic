// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Decoding of a sampled module grid: format information (BCH(15,5), both
 * copies), version information (BCH(18,6), both copies, v >= 7), data
 * unmasking and codeword extraction in placement order, block
 * de-interleaving, Reed-Solomon correction, then segment parsing.
 */

#include "fqr_internal.h"

static unsigned popcount32(uint32_t v) {
  unsigned n = 0;
  while (v != 0u) {
    v &= v - 1u;
    n++;
  }
  return n;
}

int fqr_bch_format(uint32_t bits, unsigned *dist) {
  unsigned best = 99u;
  int best_d = -1;
  for (unsigned d = 0; d < 32u; d++) {
    unsigned h = popcount32((bits ^ fqr_format_codewords[d]) & 0x7FFFu);
    if (h < best) {
      best = h;
      best_d = (int)d;
    }
  }
  *dist = best;
  return best <= 3u ? best_d : -1;
}

int fqr_bch_version(uint32_t bits, unsigned *dist) {
  unsigned best = 99u;
  int best_v = -1;
  for (unsigned i = 0; i < 34u; i++) {
    unsigned h = popcount32((bits ^ fqr_version_codewords[i]) & 0x3FFFFu);
    if (h < best) {
      best = h;
      best_v = (int)i + 7;
    }
  }
  *dist = best;
  return best <= 3u ? best_v : -1;
}

/* Per-axis alignment membership: index of the alignment coordinate within
 * +/-2 modules of each row/column, or 0xFF. */
typedef struct {
  unsigned version;
  unsigned size;
  unsigned na;
  uint8_t amem[FQR_MAX_MODULES];
} fnmap_t;

static void fnmap_init(fnmap_t *f, unsigned version) {
  f->version = version;
  f->size = 17u + 4u * version;
  f->na = fqr_align_count(version);
  memset(f->amem, 0xFF, sizeof f->amem);
  for (unsigned i = 0; i < f->na; i++) {
    unsigned p = fqr_align_pos[version][i];
    for (unsigned d = p - 2u; d <= p + 2u && d < f->size; d++) {
      f->amem[d] = (uint8_t)i;
    }
  }
}

static bool fnmap_is_function(const fnmap_t *f, unsigned r, unsigned c) {
  unsigned s = f->size;
  if (r < 9u && (c < 9u || c >= s - 8u)) {
    return true;
  }
  if (r >= s - 8u && c < 9u) {
    return true;
  }
  if (r == 6u || c == 6u) {
    return true;
  }
  if (f->version >= 7u) {
    if (r < 6u && c >= s - 11u && c < s - 8u) {
      return true;
    }
    if (c < 6u && r >= s - 11u && r < s - 8u) {
      return true;
    }
  }
  unsigned ai = f->amem[r], aj = f->amem[c];
  if (ai != 0xFFu && aj != 0xFFu) {
    unsigned last = f->na - 1u;
    bool corner = (ai == 0u && aj == 0u) || (ai == 0u && aj == last) ||
                  (ai == last && aj == 0u);
    return !corner;
  }
  return false;
}

bool fqr_is_function_module(unsigned version, unsigned r, unsigned c) {
  fnmap_t f;
  if (version < FQR_VERSION_MIN || version > FQR_VERSION_MAX) {
    return false;
  }
  fnmap_init(&f, version);
  if (r >= f.size || c >= f.size) {
    return false;
  }
  return fnmap_is_function(&f, r, c);
}

typedef struct {
  const uint8_t *g;
  size_t stride;
  bool mirrored;
} gridview_t;

static inline unsigned gv_get(const gridview_t *v, unsigned r, unsigned c) {
  if (v->mirrored) {
    unsigned t = r;
    r = c;
    c = t;
  }
  return (unsigned)(v->g[(size_t)r * v->stride + (c >> 3)] >> (7u - (c & 7u))) &
         1u;
}

static bool mask_bit(unsigned mask, unsigned r, unsigned c) {
  switch (mask) {
    case 0u:
      return ((r + c) & 1u) == 0u;
    case 1u:
      return (r & 1u) == 0u;
    case 2u:
      return (c % 3u) == 0u;
    case 3u:
      return ((r + c) % 3u) == 0u;
    case 4u:
      return (((r / 2u) + (c / 3u)) & 1u) == 0u;
    case 5u:
      return ((r * c) % 2u + (r * c) % 3u) == 0u;
    case 6u:
      return ((((r * c) % 2u) + ((r * c) % 3u)) & 1u) == 0u;
    default:
      return ((((r + c) % 2u) + ((r * c) % 3u)) & 1u) == 0u;
  }
}

/* Reads both format copies; returns the 5 data bits or -1. */
static int read_format(const gridview_t *v, unsigned size) {
  uint32_t a = 0, b = 0;
  for (unsigned i = 0; i <= 5u; i++) {
    a |= (uint32_t)gv_get(v, i, 8u) << i;
  }
  a |= (uint32_t)gv_get(v, 7u, 8u) << 6;
  a |= (uint32_t)gv_get(v, 8u, 8u) << 7;
  a |= (uint32_t)gv_get(v, 8u, 7u) << 8;
  for (unsigned i = 9u; i < 15u; i++) {
    a |= (uint32_t)gv_get(v, 8u, 14u - i) << i;
  }
  for (unsigned i = 0; i < 8u; i++) {
    b |= (uint32_t)gv_get(v, 8u, size - 1u - i) << i;
  }
  for (unsigned i = 8u; i < 15u; i++) {
    b |= (uint32_t)gv_get(v, size - 15u + i, 8u) << i;
  }
  unsigned da, db;
  int fa = fqr_bch_format(a, &da);
  int fb = fqr_bch_format(b, &db);
  if (fa >= 0 && (fb < 0 || da <= db)) {
    return fa;
  }
  return fb;
}

/* Returns the version read from either copy (best distance), or -1. */
static int read_version(const gridview_t *v, unsigned size) {
  uint32_t a = 0, b = 0;
  for (unsigned i = 0; i < 18u; i++) {
    a |= (uint32_t)gv_get(v, i / 3u, size - 11u + i % 3u) << i;
    b |= (uint32_t)gv_get(v, size - 11u + i % 3u, i / 3u) << i;
  }
  unsigned da, db;
  int va = fqr_bch_version(a, &da);
  int vb = fqr_bch_version(b, &db);
  if (va >= 0 && (vb < 0 || da <= db)) {
    return va;
  }
  return vb;
}

/* Iterator over de-interleaved destinations (ISO §7.6). */
typedef struct {
  unsigned nb, n_short, short_len, ec, d_short, d_max;
  unsigned phase, i, j;
} deint_t;

static unsigned blk_start(const deint_t *d, unsigned j) {
  return j * d->short_len + (j > d->n_short ? j - d->n_short : 0u);
}

static unsigned blk_data(const deint_t *d, unsigned j) {
  return d->d_short + (j >= d->n_short ? 1u : 0u);
}

/* Returns the destination of the next codeword, or -1 when done. */
static int deint_next(deint_t *d) {
  for (;;) {
    if (d->phase == 0u) {
      if (d->i >= d->d_max) {
        d->phase = 1u;
        d->i = 0u;
        d->j = 0u;
        continue;
      }
      if (d->j >= d->nb) {
        d->j = 0u;
        d->i++;
        continue;
      }
      unsigned j = d->j++;
      if (d->i < blk_data(d, j)) {
        return (int)(blk_start(d, j) + d->i);
      }
    } else {
      if (d->j >= d->nb) {
        d->j = 0u;
        d->i++;
      }
      if (d->i >= d->ec) {
        return -1;
      }
      unsigned j = d->j++;
      return (int)(blk_start(d, j) + blk_data(d, j) + d->i);
    }
  }
}

/* ISO/IEC 18004 Table 9 footnote: misdecode protection codewords p. */
static unsigned misdecode_p(unsigned version, unsigned level) {
  if (version == 1u) {
    return level == FQR_ECC_L ? 3u : (level == FQR_ECC_M ? 2u : 1u);
  }
  if (version == 2u && level == FQR_ECC_L) {
    return 2u;
  }
  if (version == 3u && level == FQR_ECC_L) {
    return 1u;
  }
  return 0u;
}

fqr_stage_t fqr_decode_grid(const uint8_t *grid, size_t stride, unsigned size,
                            bool mirrored, uint8_t *cw, fqr_result_t *res,
                            bool *overflow, fqr_stats_t *st) {
  gridview_t gv = {grid, stride, mirrored};
  fnmap_t fm;

  *overflow = false;
  if (size < 21u || size > FQR_MAX_MODULES || (size - 17u) % 4u != 0u) {
    return FQR_STAGE_FORMAT;
  }
  unsigned version = (size - 17u) / 4u;

  int fmt = read_format(&gv, size);
  if (fmt < 0) {
    return FQR_STAGE_FORMAT;
  }
  unsigned level = fqr_level_from_bits((unsigned)fmt >> 3);
  unsigned mask = (unsigned)fmt & 7u;

  if (version >= 7u) {
    int rv = read_version(&gv, size);
    if (rv >= 0 && (unsigned)rv != version) {
      return FQR_STAGE_FORMAT;
    }
    /* Unreadable version information is tolerated: the size is known
     * and Reed-Solomon validates everything that follows. */
  }

  /* Block structure. */
  unsigned total = fqr_total_codewords[version];
  deint_t di;
  di.nb = fqr_num_blocks[level][version];
  di.ec = fqr_ecc_per_block[level][version];
  di.short_len = total / di.nb;
  di.n_short = di.nb - total % di.nb;
  di.d_short = di.short_len - di.ec;
  di.d_max = di.d_short + (di.n_short < di.nb ? 1u : 0u);
  di.phase = 0u;
  di.i = 0u;
  di.j = 0u;

  /* Extract codewords in placement order, unmasking data modules. */
  fnmap_init(&fm, version);
  unsigned bitn = 0, k = 0, acc = 0;
  for (unsigned right = size - 1u; right >= 1u && right < size; right -= 2u) {
    if (right == 6u) {
      right = 5u;
    }
    bool upward = ((right + 1u) & 2u) == 0u;
    for (unsigned vert = 0; vert < size; vert++) {
      unsigned r = upward ? size - 1u - vert : vert;
      for (unsigned jj = 0; jj < 2u; jj++) {
        unsigned c = right - jj;
        if (fnmap_is_function(&fm, r, c)) {
          continue;
        }
        if (k >= total) {
          continue; /* remainder bits */
        }
        unsigned bit = gv_get(&gv, r, c) ^ (mask_bit(mask, r, c) ? 1u : 0u);
        acc = (acc << 1) | bit;
        if (++bitn == 8u) {
          int dst = deint_next(&di);
          if (dst < 0 || (unsigned)dst >= total) {
            return FQR_STAGE_FORMAT; /* cannot happen with valid tables */
          }
          cw[dst] = (uint8_t)acc;
          acc = 0;
          bitn = 0;
          k++;
        }
      }
    }
    if (right == 1u) {
      break;
    }
  }
  if (k != total) {
    return FQR_STAGE_FORMAT;
  }

  /* Reed-Solomon per block, then compact the data codewords. */
  unsigned p = misdecode_p(version, level);
  unsigned max_err = (di.ec - p) / 2u;
  unsigned corrected = 0;
  unsigned out = 0;
  for (unsigned j = 0; j < di.nb; j++) {
    unsigned start = blk_start(&di, j);
    unsigned dlen = blk_data(&di, j);
    unsigned n = dlen + di.ec;
    st->rs_blocks++;
    int rc = fqr_rs_correct(cw + start, n, di.ec, max_err);
    if (rc < 0) {
      return FQR_STAGE_ECC;
    }
    corrected += (unsigned)rc;
    memmove(cw + out, cw + start, dlen);
    out += dlen;
  }

  res->version = (uint8_t)version;
  res->ecc_level = (uint8_t)level;
  res->mask = (uint8_t)mask;
  res->mirrored = mirrored;
  res->corrected = (uint16_t)corrected;
  res->ecc_capacity = (uint16_t)max_err;
  return fqr_parse_segments(cw, out, version, res, overflow);
}
