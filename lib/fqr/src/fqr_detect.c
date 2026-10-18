// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Detection pipeline and public API.
 *
 *  1. Finder candidates for one polarity (fqr_finder.c).
 *  2. Finder triples scored for "right isosceles triangle with similar
 *     module sizes"; the best FQR_MAX_TRIPLES are tried in order.
 *  3. Per triple: module size (black-white-black runs), symbol size from
 *     geometry and from counting both timing patterns; a short list of
 *     candidate sizes is tried. Versions >= 7 are confirmed (or corrected)
 *     by the BCH-protected version information.
 *  4. Per size: affine transform from the three finder centres, bottom-right
 *     alignment pattern search, homography, grid sampling, matrix decoding
 *     (and transposed for mirrored symbols). Versions >= 7 that fail get a
 *     second chance with piecewise homographies anchored on every located
 *     alignment pattern (lens distortion, curved screens).
 *  5. Distinctness: a code whose centre lies inside an already decoded code
 *     is a duplicate; candidates inside decoded codes are retired.
 */

#include "fqr_internal.h"

#include <stdint.h>

typedef struct {
  fqr_ws_t *ws;
  fqr_bm_t bm;
  fqr_stats_t *st;
  uint32_t work;
  uint32_t max_work;
  bool try_mirror;
  fqr_result_t *results;
  size_t max_results;
  size_t n_found;
  size_t max_codes;
  fqr_stage_t best_stage;
  bool any_overflow;
  bool stop;
  bool jitter_done; /* corner jitter already tried for the current triple */
} ctx_t;

static bool budget_left(ctx_t *cx) {
  if (cx->work >= cx->max_work) {
    cx->st->budget_exhausted = true;
    cx->stop = true;
    return false;
  }
  return true;
}

/* ------------------------------------------------------------------------ */
/* Small geometry helpers                                                   */
/* ------------------------------------------------------------------------ */

static float cross3(fqr_point_t a, fqr_point_t b, fqr_point_t p) {
  return (b.x - a.x) * (p.y - a.y) - (b.y - a.y) * (p.x - a.x);
}

static bool point_in_quad(const fqr_quad_t *q, float x, float y) {
  fqr_point_t p = {x, y};
  bool pos = false, neg = false;
  for (unsigned i = 0; i < 4u; i++) {
    float c = cross3(q->q[i], q->q[(i + 1u) & 3u], p);
    if (c > 0.0f) {
      pos = true;
    } else if (c < 0.0f) {
      neg = true;
    }
  }
  return !(pos && neg);
}

static bool inside_found(const ctx_t *cx, float x, float y) {
  for (uint32_t i = 0; i < cx->ws->n_found; i++) {
    if (point_in_quad(&cx->ws->found[i], x, y)) {
      return true;
    }
  }
  return false;
}

/* ------------------------------------------------------------------------ */
/* Triples                                                                  */
/* ------------------------------------------------------------------------ */

static void insert_triple(fqr_ws_t *ws, uint8_t a, uint8_t b, uint8_t c,
                          float score) {
  uint32_t n = ws->n_triples;
  if (n == FQR_MAX_TRIPLES && score >= ws->triples[n - 1u].score) {
    return;
  }
  uint32_t i = (n < FQR_MAX_TRIPLES) ? n : n - 1u;
  while (i > 0u && ws->triples[i - 1u].score > score) {
    ws->triples[i] = ws->triples[i - 1u];
    i--;
  }
  ws->triples[i].a = a;
  ws->triples[i].b = b;
  ws->triples[i].c = c;
  ws->triples[i].score = score;
  if (n < FQR_MAX_TRIPLES) {
    ws->n_triples = n + 1u;
  }
}

/* Scores (i, j, k) and inserts it oriented as (top-left, top-right,
 * bottom-left). */
static void consider_triple(ctx_t *cx, uint8_t i, uint8_t j, uint8_t k) {
  const fqr_cand_t *c = cx->ws->cands.c;
  uint8_t idx[3] = {i, j, k};
  float d01 = fqr_dist(c[i].x, c[i].y, c[j].x, c[j].y);
  float d02 = fqr_dist(c[i].x, c[i].y, c[k].x, c[k].y);
  float d12 = fqr_dist(c[j].x, c[j].y, c[k].x, c[k].y);
  /* Corner B is opposite the longest side. */
  uint8_t B, A, C;
  float legA, legC;
  if (d12 >= d01 && d12 >= d02) {
    B = idx[0];
    A = idx[1];
    C = idx[2];
    legA = d01;
    legC = d02;
  } else if (d02 >= d01 && d02 >= d12) {
    B = idx[1];
    A = idx[0];
    C = idx[2];
    legA = d01;
    legC = d12;
  } else {
    B = idx[2];
    A = idx[0];
    C = idx[1];
    legA = d02;
    legC = d12;
  }
  float msmin = fqr_minf(fqr_minf(c[i].ms, c[j].ms), c[k].ms);
  float msmax = fqr_maxf(fqr_maxf(c[i].ms, c[j].ms), c[k].ms);
  if (!(msmin > 0.0f) || msmax > 2.5f * msmin) {
    return;
  }
  float lmin = fqr_minf(legA, legC), lmax = fqr_maxf(legA, legC);
  if (!(lmin > 0.0f) || lmax > 2.0f * lmin) {
    return;
  }
  float msavg = (c[i].ms + c[j].ms + c[k].ms) / 3.0f;
  float modules = (legA + legC) / (2.0f * msavg);
  if (modules < 9.0f || modules > 200.0f) {
    return;
  }
  float bax = c[A].x - c[B].x, bay = c[A].y - c[B].y;
  float bcx = c[C].x - c[B].x, bcy = c[C].y - c[B].y;
  float cosang = (bax * bcx + bay * bcy) / (legA * legC);
  if (fqr_absf(cosang) > 0.6f) {
    return;
  }
  float score = fqr_absf(cosang) * 2.0f + (lmax / lmin - 1.0f) +
                0.5f * (msmax / msmin - 1.0f);
  if (c[i].count < 2u || c[j].count < 2u || c[k].count < 2u) {
    score += 0.3f;
  }
  /* Orientation: with y pointing down, (TR - TL) x (BL - TL) > 0. */
  float z = bax * bcy - bay * bcx;
  cx->st->triples_considered++;
  if (z > 0.0f) {
    insert_triple(cx->ws, B, A, C, score);
  } else {
    insert_triple(cx->ws, B, C, A, score);
  }
}

static void build_triples(ctx_t *cx) {
  fqr_ws_t *ws = cx->ws;
  uint8_t pool[FQR_TRIPLE_POOL];
  uint32_t np = 0;
  bool taken[FQR_MAX_CANDIDATES];
  memset(taken, 0, sizeof taken);
  ws->n_triples = 0;
  /* Pool: the FQR_TRIPLE_POOL candidates with the highest counts. */
  while (np < FQR_TRIPLE_POOL) {
    int best = -1;
    for (uint32_t i = 0; i < ws->cands.n; i++) {
      if (taken[i] || (ws->cands.c[i].flags & FQR_CAND_USED) != 0u) {
        continue;
      }
      if (best < 0 || ws->cands.c[i].count > ws->cands.c[best].count) {
        best = (int)i;
      }
    }
    if (best < 0) {
      break;
    }
    taken[best] = true;
    pool[np++] = (uint8_t)best;
  }
  for (uint32_t a = 0; a < np; a++) {
    for (uint32_t b = a + 1u; b < np; b++) {
      for (uint32_t c = b + 1u; c < np; c++) {
        consider_triple(cx, pool[a], pool[b], pool[c]);
      }
    }
  }
}

/* ------------------------------------------------------------------------ */
/* Sampling                                                                 */
/* ------------------------------------------------------------------------ */

static int sample_module(const fqr_bm_t *b, const fqr_xform_t *t, float u,
                         float v, bool majority) {
  float x, y;
  if (!majority) {
    return fqr_xform_apply(t, u, v, &x, &y) ? fqr_px_f(b, x, y) : 0;
  }
  static const float off[5][2] = {{0.0f, 0.0f},
                                  {-0.22f, -0.22f},
                                  {0.22f, -0.22f},
                                  {-0.22f, 0.22f},
                                  {0.22f, 0.22f}};
  int dark = 0;
  for (unsigned i = 0; i < 5u; i++) {
    if (fqr_xform_apply(t, u + off[i][0], v + off[i][1], &x, &y)) {
      dark += fqr_px_f(b, x, y);
    }
  }
  return dark >= 3;
}

/* Samples rows [r0, r1] x cols [c0, c1] of the grid with transform t. */
static void sample_region(ctx_t *cx, const fqr_xform_t *t, unsigned r0,
                          unsigned r1, unsigned c0, unsigned c1,
                          bool majority) {
  uint8_t *g = cx->ws->grid;
  for (unsigned r = r0; r <= r1; r++) {
    uint8_t *row = g + (size_t)r * FQR_GRID_STRIDE;
    for (unsigned c = c0; c <= c1; c++) {
      uint8_t m = (uint8_t)(0x80u >> (c & 7u));
      if (sample_module(&cx->bm, t, (float)c + 0.5f, (float)r + 0.5f,
                        majority)) {
        row[c >> 3] |= m;
      } else {
        row[c >> 3] &= (uint8_t)~m;
      }
    }
  }
  uint32_t n = (r1 - r0 + 1u) * (c1 - c0 + 1u);
  cx->st->modules_sampled += n;
  cx->work += majority ? 2u * n : n;
}

/* Reads version information through t: returns 7..40 or -1. *strong is
 * set when the reading is trustworthy enough to override the size estimate:
 * both copies agree, or one copy is within distance 1. (A random 18-bit
 * word lies within distance 3 of some codeword with probability ~13 %.) */
static int sample_version(ctx_t *cx, const fqr_xform_t *t, unsigned dim,
                          bool majority, bool *strong) {
  uint32_t a = 0, b = 0;
  for (unsigned i = 0; i < 18u; i++) {
    float u1 = (float)(dim - 11u + i % 3u) + 0.5f, v1 = (float)(i / 3u) + 0.5f;
    a |= (uint32_t)sample_module(&cx->bm, t, u1, v1, majority) << i;
    b |= (uint32_t)sample_module(&cx->bm, t, v1, u1, majority) << i;
  }
  cx->work += 36u;
  unsigned da, db;
  int va = fqr_bch_version(a, &da);
  int vb = fqr_bch_version(b, &db);
  int v = (va >= 0 && (vb < 0 || da <= db)) ? va : vb;
  *strong =
      (va >= 0 && va == vb) || (va >= 0 && da <= 1u) || (vb >= 0 && db <= 1u);
  return v;
}

/*
 * Cheap plausibility test before any expensive work: the two timing
 * patterns (row 6 and column 6 between the separators) must mostly
 * alternate. Only modules within TIMING_END of the finder patterns are
 * tested (mid-span samples may drift by a module before the transform has
 * been refined). With tl_only, just the modules next to the top-left
 * finder are used: they are accurate even with the pre-alignment
 * transform under strong perspective. Rejects most junk finder triples and
 * wrong sizes for at most 4 * TIMING_END samples instead of d^2.
 */
#define TIMING_END 6u
static bool timing_plausible(ctx_t *cx, const fqr_xform_t *t, unsigned dim,
                             bool majority, bool tl_only) {
  unsigned good = 0, total = 0;
  unsigned last = dim - 9u; /* timing modules: 8 .. dim - 9 */
  for (unsigned i = 8u; i <= last; i++) {
    bool near_tl = i < 8u + TIMING_END;
    bool near_end = i + TIMING_END > last;
    if (!near_tl && (tl_only || !near_end)) {
      continue;
    }
    int expect = (i & 1u) == 0u;
    good +=
        sample_module(&cx->bm, t, (float)i + 0.5f, 6.5f, majority) == expect;
    good +=
        sample_module(&cx->bm, t, 6.5f, (float)i + 0.5f, majority) == expect;
    total += 2u;
  }
  cx->work += total;
  /* tl_only: >= 2/3 (8 of 12); both ends: >= 60 %. */
  return tl_only ? 3u * good >= 2u * total : 10u * good >= 6u * total;
}

/* ------------------------------------------------------------------------ */
/* Decoding one candidate geometry                                          */
/* ------------------------------------------------------------------------ */

typedef struct {
  fqr_point_t tl, tr, bl;
  fqr_point_t br; /* estimated centre of a virtual 4th finder pattern */
  bool have_br;
  float ms;
} geom_t;

static fqr_result_t *result_slot(ctx_t *cx, fqr_result_t *tmp) {
  if (cx->n_found < cx->max_results) {
    return &cx->results[cx->n_found];
  }
  memset(tmp, 0, sizeof *tmp);
  return tmp;
}

static void note_stage(ctx_t *cx, fqr_stage_t s) {
  if (s == FQR_STAGE_FORMAT) {
    cx->st->fail_format++;
  } else if (s == FQR_STAGE_ECC) {
    cx->st->fail_ecc++;
  } else if (s == FQR_STAGE_DATA) {
    cx->st->fail_data++;
  }
  if (s > cx->best_stage) {
    cx->best_stage = s;
  }
}

/* Decodes the current grid (and its transpose). */
static fqr_stage_t decode_current_grid(ctx_t *cx, unsigned dim,
                                       fqr_result_t *res, bool *overflow) {
  cx->st->decode_attempts++;
  /* Extraction, de-interleaving, RS and parsing: about half the cost of
   * sampling the grid (both orientations included). */
  cx->work += (dim * dim) / 2u + 64u;
  fqr_stage_t s = fqr_decode_grid(cx->ws->grid, FQR_GRID_STRIDE, dim, false,
                                  cx->ws->cw, res, overflow, cx->st);
  if (s != FQR_STAGE_OK && cx->try_mirror && s <= FQR_STAGE_ECC) {
    note_stage(cx, s);
    s = fqr_decode_grid(cx->ws->grid, FQR_GRID_STRIDE, dim, true, cx->ws->cw,
                        res, overflow, cx->st);
  }
  if (s != FQR_STAGE_OK) {
    note_stage(cx, s);
  }
  return s;
}

/* Piecewise sampling anchored on every alignment pattern (v >= 7). */
static bool sample_piecewise(ctx_t *cx, const fqr_xform_t *h, unsigned version,
                             float ms, bool majority) {
  fqr_ws_t *ws = cx->ws;
  unsigned na = fqr_align_count(version);
  unsigned dim = 17u + 4u * version;
  const uint8_t *pos = fqr_align_pos[version];
  unsigned located = 0;
  for (unsigned i = 0; i < na; i++) {
    for (unsigned j = 0; j < na; j++) {
      unsigned k = i * na + j;
      float mu = (float)pos[j] + 0.5f, mv = (float)pos[i] + 0.5f;
      float px, py;
      ws->align_ok[k] = 0u;
      if (!fqr_xform_apply(h, mu, mv, &px, &py)) {
        return false;
      }
      bool corner = (i == 0u && j == 0u) || (i == 0u && j == na - 1u) ||
                    (i == na - 1u && j == 0u);
      /* Shift the prediction by the displacement of located neighbours. */
      float dx = 0.0f, dy = 0.0f;
      unsigned nn = 0;
      if (j > 0u && ws->align_ok[k - 1u] == 2u) {
        float qx, qy;
        if (fqr_xform_apply(h, (float)pos[j - 1u] + 0.5f, mv, &qx, &qy)) {
          dx += ws->align[k - 1u].x - qx;
          dy += ws->align[k - 1u].y - qy;
          nn++;
        }
      }
      if (i > 0u && ws->align_ok[k - na] == 2u) {
        float qx, qy;
        if (fqr_xform_apply(h, mu, (float)pos[i - 1u] + 0.5f, &qx, &qy)) {
          dx += ws->align[k - na].x - qx;
          dy += ws->align[k - na].y - qy;
          nn++;
        }
      }
      if (nn > 0u) {
        dx /= (float)nn;
        dy /= (float)nn;
      }
      ws->align[k].x = px + dx;
      ws->align[k].y = py + dy;
      ws->align_ok[k] = 1u;
      if (corner) {
        continue;
      }
      /* Search with the shifted prediction expressed as a translated map. */
      fqr_xform_t ht = *h;
      ht.m[0] += dx * ht.m[6];
      ht.m[1] += dx * ht.m[7];
      ht.m[2] += dx * ht.m[8];
      ht.m[3] += dy * ht.m[6];
      ht.m[4] += dy * ht.m[7];
      ht.m[5] += dy * ht.m[8];
      fqr_point_t f;
      if (fqr_find_alignment(&cx->bm, &ht, mu, mv, ms, 2.5f, &f)) {
        ws->align[k] = f;
        ws->align_ok[k] = 2u;
        located++;
      }
    }
  }
  if (located == 0u) {
    return false;
  }
  for (unsigned i = 0; i + 1u < na; i++) {
    for (unsigned j = 0; j + 1u < na; j++) {
      float src[8] = {
          (float)pos[j] + 0.5f,      (float)pos[i] + 0.5f,
          (float)pos[j + 1u] + 0.5f, (float)pos[i] + 0.5f,
          (float)pos[j + 1u] + 0.5f, (float)pos[i + 1u] + 0.5f,
          (float)pos[j] + 0.5f,      (float)pos[i + 1u] + 0.5f,
      };
      const fqr_point_t *p00 = &ws->align[i * na + j];
      const fqr_point_t *p01 = &ws->align[i * na + j + 1u];
      const fqr_point_t *p11 = &ws->align[(i + 1u) * na + j + 1u];
      const fqr_point_t *p10 = &ws->align[(i + 1u) * na + j];
      float dst[8] = {p00->x, p00->y, p01->x, p01->y,
                      p11->x, p11->y, p10->x, p10->y};
      fqr_xform_t t;
      if (!fqr_xform_quad(&t, src, dst)) {
        return false;
      }
      unsigned r0 = (i == 0u) ? 0u : pos[i];
      unsigned r1 = (i + 2u == na) ? dim - 1u : (unsigned)pos[i + 1u] - 1u;
      unsigned c0 = (j == 0u) ? 0u : pos[j];
      unsigned c1 = (j + 2u == na) ? dim - 1u : (unsigned)pos[j + 1u] - 1u;
      sample_region(cx, &t, r0, r1, c0, c1, majority);
    }
  }
  return true;
}

typedef struct {
  fqr_stage_t stage;
  int suggest_dim; /* > 0: version information says the size is this */
} attempt_t;

static void finish_success(ctx_t *cx, const fqr_xform_t *h, unsigned dim,
                           fqr_result_t *res, bool overflow) {
  float corners_uv[4][2] = {{0.0f, 0.0f},
                            {(float)dim, 0.0f},
                            {(float)dim, (float)dim},
                            {0.0f, (float)dim}};
  fqr_quad_t q;
  for (unsigned i = 0; i < 4u; i++) {
    if (!fqr_xform_apply(h, corners_uv[i][0], corners_uv[i][1], &q.q[i].x,
                         &q.q[i].y)) {
      q.q[i].x = q.q[i].y = 0.0f;
    }
  }
  float mx, my;
  if (!fqr_xform_apply(h, (float)dim / 2.0f, (float)dim / 2.0f, &mx, &my)) {
    mx = my = -1.0f;
  }
  /* Duplicate of an already decoded code? */
  bool dup = inside_found(cx, mx, my);
  for (uint32_t i = 0; i < cx->ws->n_found && !dup; i++) {
    const fqr_quad_t *f = &cx->ws->found[i];
    float fx = (f->q[0].x + f->q[1].x + f->q[2].x + f->q[3].x) / 4.0f;
    float fy = (f->q[0].y + f->q[1].y + f->q[2].y + f->q[3].y) / 4.0f;
    dup = point_in_quad(&q, fx, fy);
  }
  /* Retire finder candidates covered by this code either way. */
  for (uint32_t i = 0; i < cx->ws->cands.n; i++) {
    fqr_cand_t *c = &cx->ws->cands.c[i];
    if (point_in_quad(&q, c->x, c->y)) {
      c->flags |= FQR_CAND_USED;
    }
  }
  if (dup) {
    return;
  }
  if (cx->ws->n_found < FQR_MAX_CODES) {
    cx->ws->found[cx->ws->n_found++] = q;
  }
  res->inverted = cx->bm.inv != 0u;
  res->status = overflow ? FQR_ERR_BUFFER_TOO_SMALL : FQR_OK;
  if (res->mirrored) {
    /* Grid was read transposed: the symbol's top-right is our bottom-left. */
    fqr_point_t t = q.q[1];
    q.q[1] = q.q[3];
    q.q[3] = t;
  }
  memcpy(res->corners, q.q, sizeof q.q);
  if (cx->n_found < cx->max_results && overflow) {
    cx->any_overflow = true;
  }
  cx->n_found++;
  if (cx->n_found >= cx->max_codes) {
    cx->stop = true;
  }
}

/* Samples with t and decodes; returns the stage reached. */
static fqr_stage_t sample_and_decode(ctx_t *cx, const fqr_xform_t *t,
                                     unsigned dim, bool majority,
                                     fqr_result_t *res, bool *overflow) {
  sample_region(cx, t, 0u, dim - 1u, 0u, dim - 1u, majority);
  return decode_current_grid(cx, dim, res, overflow);
}

static attempt_t attempt_dim(ctx_t *cx, const geom_t *g, unsigned dim) {
  attempt_t out = {FQR_STAGE_NONE, 0};
  unsigned version = (dim - 17u) / 4u;
  float d = (float)dim;
  float src[8] = {3.5f,     3.5f,     d - 3.5f, 3.5f,
                  d - 3.5f, d - 3.5f, 3.5f,     d - 3.5f};
  float dst_aff[8] = {g->tl.x,
                      g->tl.y,
                      g->tr.x,
                      g->tr.y,
                      g->tr.x + g->bl.x - g->tl.x,
                      g->tr.y + g->bl.y - g->tl.y,
                      g->bl.x,
                      g->bl.y};
  fqr_xform_t haff, h0, h;
  if (!fqr_xform_quad(&haff, src, dst_aff)) {
    return out;
  }
  /* h0: perspective estimate from the fitted finder edges if available. */
  h0 = haff;
  bool have_persp = false;
  if (g->have_br) {
    float dst[8] = {g->tl.x, g->tl.y, g->tr.x, g->tr.y,
                    g->br.x, g->br.y, g->bl.x, g->bl.y};
    have_persp = fqr_xform_quad(&h0, src, dst);
    if (!have_persp) {
      h0 = haff;
    }
  }
  h = h0;
  bool majority = g->ms >= 3.0f;
  /* The timing patterns lie next to the three finders, where h0 is
   * accurate: test them before any expensive search. */
  if (!timing_plausible(cx, &h0, dim, majority, true)) {
    out.stage = FQR_STAGE_FORMAT;
    note_stage(cx, FQR_STAGE_FORMAT);
    return out;
  }
  bool have_align = false;
  if (version >= 2u) {
    static const float radii[3] = {4.0f, 8.0f, 16.0f};
    for (unsigned i = 0; i < 3u && !have_align; i++) {
      fqr_point_t a;
      if (fqr_find_alignment(&cx->bm, &h0, d - 6.5f, d - 6.5f, g->ms, radii[i],
                             &a)) {
        float src2[8] = {3.5f,     3.5f,     d - 3.5f, 3.5f,
                         d - 6.5f, d - 6.5f, 3.5f,     d - 3.5f};
        float dst2[8] = {g->tl.x, g->tl.y, g->tr.x, g->tr.y,
                         a.x,     a.y,     g->bl.x, g->bl.y};
        have_align = fqr_xform_quad(&h, src2, dst2);
        if (!have_align) {
          h = h0;
        }
      }
    }
  }
  if (!timing_plausible(cx, &h, dim, majority, false) &&
      (!have_align || !timing_plausible(cx, &h0, dim, majority, false))) {
    out.stage = FQR_STAGE_FORMAT;
    note_stage(cx, FQR_STAGE_FORMAT);
    return out;
  }
  if (version >= 7u) {
    bool strong = false;
    int v = sample_version(cx, &h, dim, majority, &strong);
    if (v > 0 && (unsigned)v != version) {
      /* The grid decoder would reject this size anyway; only a
       * trustworthy reading may redirect the search. */
      out.stage = FQR_STAGE_FORMAT;
      out.suggest_dim = strong ? 17 + 4 * v : 0;
      note_stage(cx, FQR_STAGE_FORMAT);
      return out;
    }
  }
  fqr_result_t tmp;
  fqr_result_t *res = result_slot(cx, &tmp);
  bool overflow = false;

  /* Ladder: best transform first, then the alternatives. */
  fqr_stage_t s = sample_and_decode(cx, &h, dim, majority, res, &overflow);
  if (s != FQR_STAGE_OK && s <= FQR_STAGE_ECC && version >= 7u &&
      budget_left(cx) && sample_piecewise(cx, &h, version, g->ms, majority)) {
    fqr_stage_t s2 = decode_current_grid(cx, dim, res, &overflow);
    s = s2 > s ? s2 : s;
  }
  if (s != FQR_STAGE_OK && s <= FQR_STAGE_ECC && have_align &&
      budget_left(cx)) {
    /* The alignment hit may have been a look-alike. */
    fqr_stage_t s2 = sample_and_decode(cx, &h0, dim, majority, res, &overflow);
    if (s2 == FQR_STAGE_OK) {
      h = h0;
    }
    s = s2 > s ? s2 : s;
  }
  if (s != FQR_STAGE_OK && s <= FQR_STAGE_ECC && have_persp && version < 7u &&
      budget_left(cx)) {
    /* The edge-based corner estimate may be off: plain affine. */
    fqr_stage_t s2 =
        sample_and_decode(cx, &haff, dim, majority, res, &overflow);
    if (s2 == FQR_STAGE_OK) {
      h = haff;
    }
    s = s2 > s ? s2 : s;
  }
  if (s == FQR_STAGE_ECC && version < 7u && !cx->jitter_done) {
    cx->jitter_done = true;
    /* The format information was read, so the geometry is nearly right.
     * Small symbols are cheap to sample: jitter the 4th correspondence
     * (alignment centre or estimated corner) by up to one module and
     * let Reed-Solomon decide. Nearest offsets first. */
    static const int8_t jit[16][2] = {
        {2, 0}, {-2, 0}, {0, 2}, {0, -2}, {2, 2}, {-2, 2}, {2, -2}, {-2, -2},
        {4, 0}, {-4, 0}, {0, 4}, {0, -4}, {4, 4}, {-4, 4}, {4, -4}, {-4, -4},
    };
    float su = have_align ? d - 6.5f : d - 3.5f;
    float bx, by, ex, ey, fx, fy;
    if (fqr_xform_apply(&h, su, su, &bx, &by) &&
        fqr_xform_apply(&h, su + 1.0f, su, &ex, &ey) &&
        fqr_xform_apply(&h, su, su + 1.0f, &fx, &fy)) {
      for (unsigned k = 0; k < 16u && s != FQR_STAGE_OK; k++) {
        if (cx->work + dim * dim > cx->max_work) {
          cx->st->budget_exhausted = true;
          break;
        }
        float ju = (float)jit[k][0] / 4.0f, jv = (float)jit[k][1] / 4.0f;
        float src3[8] = {3.5f, 3.5f, d - 3.5f, 3.5f, su, su, 3.5f, d - 3.5f};
        float dst3[8] = {g->tl.x,
                         g->tl.y,
                         g->tr.x,
                         g->tr.y,
                         bx + ju * (ex - bx) + jv * (fx - bx),
                         by + ju * (ey - by) + jv * (fy - by),
                         g->bl.x,
                         g->bl.y};
        fqr_xform_t hj;
        if (!fqr_xform_quad(&hj, src3, dst3)) {
          continue;
        }
        fqr_stage_t s2 =
            sample_and_decode(cx, &hj, dim, majority, res, &overflow);
        if (s2 == FQR_STAGE_OK) {
          h = hj;
        }
        s = s2 > s ? s2 : s;
      }
    }
  }
  out.stage = s;
  if (s == FQR_STAGE_OK) {
    if (res == &tmp) {
      tmp.payload = NULL;
    }
    finish_success(cx, &h, dim, res, overflow);
  }
  return out;
}

/* Estimates the centre of the (virtual) bottom-right finder pattern as the
 * intersection of the module row through the bottom-left finder and the
 * module column through the top-right finder, using the directions fitted
 * on those finders' edges (projective lines stay straight). */
static void estimate_br(ctx_t *cx, geom_t *g, float msb, float msc) {
  float dtr = fqr_dist(g->tl.x, g->tl.y, g->tr.x, g->tr.y);
  float dbl = fqr_dist(g->tl.x, g->tl.y, g->bl.x, g->bl.y);
  float u[2] = {(g->tr.x - g->tl.x) / dtr, (g->tr.y - g->tl.y) / dtr};
  float v[2] = {(g->bl.x - g->tl.x) / dbl, (g->bl.y - g->tl.y) / dbl};
  float hu_tr[2], hv_tr[2], hu_bl[2], hv_bl[2];
  g->have_br = false;
  unsigned m1 =
      fqr_finder_axes(&cx->bm, g->tr.x, g->tr.y, msb, u, v, hu_tr, hv_tr);
  unsigned m2 =
      fqr_finder_axes(&cx->bm, g->bl.x, g->bl.y, msc, u, v, hu_bl, hv_bl);
  if ((m1 & 2u) == 0u || (m2 & 1u) == 0u) {
    return;
  }
  /* BL + s * hu_bl = TR + t * hv_tr */
  float den = hu_bl[0] * hv_tr[1] - hu_bl[1] * hv_tr[0];
  if (!(fqr_absf(den) > 0.2f)) {
    return;
  }
  float qx = g->tr.x - g->bl.x, qy = g->tr.y - g->bl.y;
  float sp = (qx * hv_tr[1] - qy * hv_tr[0]) / den;
  float bx = g->bl.x + sp * hu_bl[0], by = g->bl.y + sp * hu_bl[1];
  float ax = g->tr.x + g->bl.x - g->tl.x, ay = g->tr.y + g->bl.y - g->tl.y;
  if (!fqr_finite(bx) || !fqr_finite(by) ||
      fqr_dist(bx, by, ax, ay) > 0.3f * (dtr + dbl) / 2.0f) {
    return;
  }
  g->br.x = bx;
  g->br.y = by;
  g->have_br = true;
}

static unsigned fix_dim(int32_t d, unsigned *alt) {
  *alt = 0u;
  if (d < 21) {
    d = 21;
  }
  if (d > (int32_t)FQR_MAX_MODULES) {
    d = (int32_t)FQR_MAX_MODULES;
  }
  switch (d & 3) {
    case 0:
      return (unsigned)d + 1u;
    case 2:
      return (unsigned)d - 1u;
    case 3:
      *alt = (unsigned)d + 2u <= FQR_MAX_MODULES ? (unsigned)d + 2u : 0u;
      return (unsigned)d - 2u;
    default:
      return (unsigned)d;
  }
}

static bool valid_dim(int32_t d) {
  return d >= 21 && d <= (int32_t)FQR_MAX_MODULES && (d - 17) % 4 == 0;
}

static void push_dim(unsigned *list, unsigned *n, unsigned cap, int32_t d) {
  if (!valid_dim(d)) {
    return;
  }
  for (unsigned i = 0; i < *n; i++) {
    if (list[i] == (unsigned)d) {
      return;
    }
  }
  if (*n < cap) {
    list[(*n)++] = (unsigned)d;
  }
}

static void try_triple(ctx_t *cx, const fqr_triple_t *t) {
  const fqr_cand_t *c = cx->ws->cands.c;
  geom_t g = {0};
  g.tl.x = c[t->a].x;
  g.tl.y = c[t->a].y;
  g.tr.x = c[t->b].x;
  g.tr.y = c[t->b].y;
  g.bl.x = c[t->c].x;
  g.bl.y = c[t->c].y;

  float msc = (c[t->a].ms + c[t->b].ms + c[t->c].ms) / 3.0f;
  float m1 = fqr_module_size_between(&cx->bm, g.tl.x, g.tl.y, g.tr.x, g.tr.y);
  float m2 = fqr_module_size_between(&cx->bm, g.tl.x, g.tl.y, g.bl.x, g.bl.y);
  float ms;
  if (m1 > 0.0f && m2 > 0.0f) {
    ms = (m1 + m2) / 2.0f;
  } else if (m1 > 0.0f) {
    ms = m1;
  } else if (m2 > 0.0f) {
    ms = m2;
  } else {
    ms = msc;
  }
  if (!(ms > 0.5f * msc && ms < 2.0f * msc)) {
    ms = msc;
  }
  if (!(ms >= 0.5f && ms < 512.0f)) {
    return;
  }
  g.ms = ms;
  cx->jitter_done = false;
  estimate_br(cx, &g, c[t->b].ms, c[t->c].ms);

  float dtr = fqr_dist(g.tl.x, g.tl.y, g.tr.x, g.tr.y);
  float dbl = fqr_dist(g.tl.x, g.tl.y, g.bl.x, g.bl.y);
  unsigned alt;
  unsigned dgeo = fix_dim(fqr_roundi((dtr + dbl) / (2.0f * ms)) + 7, &alt);

  /* Timing pattern counts (row 6 and column 6). */
  float ux = (g.tr.x - g.tl.x) / dtr, uy = (g.tr.y - g.tl.y) / dtr;
  float vx = (g.bl.x - g.tl.x) / dbl, vy = (g.bl.y - g.tl.y) / dbl;
  float ma = c[t->a].ms, mb = c[t->b].ms, mc = c[t->c].ms;
  int32_t dtop = -1, dleft = -1;
  if (ms >= 1.5f) {
    uint32_t t1 = fqr_count_transitions(
        &cx->bm, g.tl.x + 3.0f * ma * vx, g.tl.y + 3.0f * ma * vy,
        g.tr.x + 3.0f * mb * vx, g.tr.y + 3.0f * mb * vy, 0.45f * ms);
    uint32_t t2 = fqr_count_transitions(
        &cx->bm, g.tl.x + 3.0f * ma * ux, g.tl.y + 3.0f * ma * uy,
        g.bl.x + 3.0f * mc * ux, g.bl.y + 3.0f * mc * uy, 0.45f * ms);
    dtop = (int32_t)t1 + 13;
    dleft = (int32_t)t2 + 13;
  }

  unsigned dims[8];
  unsigned nd = 0;
  if (valid_dim(dtop) && dtop == dleft) {
    push_dim(dims, &nd, 8u, dtop);
  }
  push_dim(dims, &nd, 8u, (int32_t)dgeo);
  if (alt != 0u) {
    push_dim(dims, &nd, 8u, (int32_t)alt);
  }
  if (fqr_absf(msc - ms) > 0.15f * ms) {
    /* Run-based and finder-based module sizes disagree (noise, blur):
     * also try the size implied by the finder estimate. */
    unsigned alt2;
    push_dim(
        dims, &nd, 8u,
        (int32_t)fix_dim(fqr_roundi((dtr + dbl) / (2.0f * msc)) + 7, &alt2));
  }
  if (valid_dim(dtop) && fqr_absf((float)dtop - (float)dgeo) <= 12.0f) {
    push_dim(dims, &nd, 8u, dtop);
  }
  if (valid_dim(dleft) && fqr_absf((float)dleft - (float)dgeo) <= 12.0f) {
    push_dim(dims, &nd, 8u, dleft);
  }
  push_dim(dims, &nd, 8u, (int32_t)dgeo - 4);
  push_dim(dims, &nd, 8u, (int32_t)dgeo + 4);

  unsigned attempts = 0;
  for (unsigned i = 0; i < nd && attempts < 6u; i++) {
    /* Do not start an attempt that would exceed the budget. */
    if (cx->work + dims[i] * dims[i] > cx->max_work) {
      cx->st->budget_exhausted = true;
      cx->stop = true;
      return;
    }
    attempts++;
    attempt_t r = attempt_dim(cx, &g, dims[i]);
    if (r.stage == FQR_STAGE_OK) {
      return;
    }
    if (r.suggest_dim > 0 && nd < 8u) {
      /* Version information disagrees with the estimate: try its
       * size next (if not already tried). */
      bool seen = false;
      for (unsigned k = 0; k <= i; k++) {
        seen = seen || dims[k] == (unsigned)r.suggest_dim;
      }
      if (!seen) {
        for (unsigned k = nd; k > i + 1u; k--) {
          dims[k] = dims[k - 1u];
        }
        dims[i + 1u] = (unsigned)r.suggest_dim;
        nd++;
      }
    }
    if (cx->stop) {
      return;
    }
  }
}

static void run_scan(ctx_t *cx, uint8_t inv, uint8_t filter) {
  fqr_ws_t *ws = cx->ws;
  cx->bm.filter = filter;
  cx->bm.inv = inv;
  cx->bm.inv_byte = inv ? 0xFFu : 0x00u;
  fqr_find_candidates(&cx->bm, &ws->cands, ws->rowbuf);
  /* Candidates inside codes found by an earlier pass are retired. */
  for (uint32_t i = 0; i < ws->cands.n; i++) {
    if (inside_found(cx, ws->cands.c[i].x, ws->cands.c[i].y)) {
      ws->cands.c[i].flags |= FQR_CAND_USED;
    }
  }
  build_triples(cx);
  for (uint32_t i = 0; i < ws->n_triples && !cx->stop; i++) {
    const fqr_triple_t *t = &ws->triples[i];
    const fqr_cand_t *c = ws->cands.c;
    if (((c[t->a].flags | c[t->b].flags | c[t->c].flags) & FQR_CAND_USED) !=
        0u) {
      continue;
    }
    if (!budget_left(cx)) {
      break;
    }
    try_triple(cx, t);
  }
}

/* One polarity: raw scan, then (if it found nothing) a scan of the
 * majority-filtered image for salt-and-pepper noise. */
static void run_pass(ctx_t *cx, uint8_t inv) {
  size_t before = cx->n_found;
  fqr_stage_t prev_best = cx->best_stage;
  cx->best_stage = FQR_STAGE_NONE;
  run_scan(cx, inv, 0u);
  fqr_stage_t raw_best = cx->best_stage;
  if (prev_best > cx->best_stage) {
    cx->best_stage = prev_best;
  }
  /* If the raw scan located a symbol well enough to read its format
   * information, its finders were fine: the filtered scan would only
   * repeat the same failing attempts. */
  if (cx->n_found == before && raw_best < FQR_STAGE_ECC &&
      !cx->st->budget_exhausted) {
    cx->stop = false;
    run_scan(cx, inv, 1u);
  }
  cx->bm.filter = 0u;
}

/* ------------------------------------------------------------------------ */
/* Public API                                                               */
/* ------------------------------------------------------------------------ */

size_t fqr_workspace_size(void) { return FQR_WORKSPACE_SIZE; }

const char *fqr_status_str(fqr_status_t status) {
  switch (status) {
    case FQR_OK:
      return "ok";
    case FQR_ERR_INVALID_ARG:
      return "invalid argument";
    case FQR_ERR_WORKSPACE:
      return "workspace too small";
    case FQR_ERR_NOT_FOUND:
      return "no QR code found";
    case FQR_ERR_FORMAT:
      return "QR code format information unreadable";
    case FQR_ERR_ECC:
      return "QR code too damaged (error correction failed)";
    case FQR_ERR_DATA:
      return "QR code data malformed";
    case FQR_ERR_BUFFER_TOO_SMALL:
      return "payload buffer too small";
    case FQR_ERR_MULTIPLE_CODES:
      return "more than one QR code";
    default:
      return "unknown status";
  }
}

static fqr_ws_t *align_ws(void *workspace, size_t ws_size) {
  if (workspace == NULL || ws_size < FQR_WORKSPACE_SIZE) {
    return NULL;
  }
  uintptr_t p = (uintptr_t)workspace;
  uintptr_t a = (p + 7u) & ~(uintptr_t)7u;
  return (fqr_ws_t *)(void *)((uint8_t *)workspace + (a - p));
}

static void clear_result_outputs(fqr_result_t *r) {
  uint8_t *payload = r->payload;
  size_t cap = r->payload_cap;
  memset(r, 0, sizeof *r);
  r->payload = payload;
  r->payload_cap = cap;
  r->status = FQR_ERR_NOT_FOUND;
}

static fqr_status_t stage_to_status(fqr_stage_t s) {
  switch (s) {
    case FQR_STAGE_FORMAT:
      return FQR_ERR_FORMAT;
    case FQR_STAGE_ECC:
      return FQR_ERR_ECC;
    case FQR_STAGE_DATA:
      return FQR_ERR_DATA;
    case FQR_STAGE_OK:
      return FQR_OK;
    default:
      return FQR_ERR_NOT_FOUND;
  }
}

fqr_status_t fqr_decode(const fqr_image_t *img, void *workspace, size_t ws_size,
                        const fqr_options_t *opts, fqr_result_t *results,
                        size_t max_results, size_t *n_found) {
  fqr_stats_t dummy;
  static const fqr_options_t defaults = {FQR_POLARITY_AUTO, 0u, false, 0u,
                                         NULL};

  if (n_found != NULL) {
    *n_found = 0;
  }
  if (opts == NULL) {
    opts = &defaults;
  }
  fqr_stats_t *st = opts->stats != NULL ? opts->stats : &dummy;
  memset(st, 0, sizeof *st);
  if (img == NULL || n_found == NULL ||
      (results == NULL && max_results != 0u) || img->data == NULL ||
      img->width == 0u || img->height == 0u || img->width > FQR_MAX_IMAGE_DIM ||
      img->height > FQR_MAX_IMAGE_DIM || img->stride < (img->width + 7u) / 8u ||
      img->stride > 65536u || opts->max_codes > FQR_MAX_CODES ||
      (unsigned)opts->polarity > (unsigned)FQR_POLARITY_INVERTED) {
    return FQR_ERR_INVALID_ARG;
  }
  for (size_t i = 0; i < max_results; i++) {
    if (results[i].payload == NULL && results[i].payload_cap != 0u) {
      return FQR_ERR_INVALID_ARG;
    }
  }
  fqr_ws_t *ws = align_ws(workspace, ws_size);
  if (ws == NULL) {
    return FQR_ERR_WORKSPACE;
  }
  for (size_t i = 0; i < max_results; i++) {
    clear_result_outputs(&results[i]);
  }

  ctx_t cx;
  memset(&cx, 0, sizeof cx);
  cx.ws = ws;
  ws->n_found = 0;
  ws->n_triples = 0;
  ws->cands.n = 0;
  cx.st = st;
  cx.bm.data = img->data;
  cx.bm.w = (int32_t)img->width;
  cx.bm.h = (int32_t)img->height;
  cx.bm.stride = img->stride;
  cx.bm.st = st;
  cx.bm.work = &cx.work;
  cx.max_work = opts->max_work != 0u ? opts->max_work : FQR_DEFAULT_WORK;
  cx.try_mirror = !opts->no_mirror;
  cx.results = results;
  cx.max_results = max_results;
  cx.max_codes =
      opts->max_codes != 0u ? opts->max_codes : FQR_DEFAULT_MAX_CODES;
  cx.best_stage = FQR_STAGE_NONE;

  switch (opts->polarity) {
    case FQR_POLARITY_NORMAL:
      run_pass(&cx, 0u);
      break;
    case FQR_POLARITY_INVERTED:
      run_pass(&cx, 1u);
      break;
    case FQR_POLARITY_BOTH:
      run_pass(&cx, 0u);
      if (cx.n_found < cx.max_codes && !st->budget_exhausted) {
        cx.stop = false;
        run_pass(&cx, 1u);
      }
      break;
    default:
      run_pass(&cx, 0u);
      if (cx.n_found == 0u && !st->budget_exhausted) {
        cx.stop = false;
        run_pass(&cx, 1u);
      }
      break;
  }

  *n_found = cx.n_found;
  /* Slots not holding a reported code may contain partial output of
   * failed attempts: reset them. */
  for (size_t i = cx.n_found; i < max_results; i++) {
    clear_result_outputs(&results[i]);
  }
  if (cx.n_found == 0u) {
    fqr_status_t s = stage_to_status(cx.best_stage);
    return s == FQR_OK ? FQR_ERR_NOT_FOUND : s;
  }
  return cx.any_overflow ? FQR_ERR_BUFFER_TOO_SMALL : FQR_OK;
}

fqr_status_t fqr_decode_single(const fqr_image_t *img, void *workspace,
                               size_t ws_size, const fqr_options_t *opts,
                               fqr_result_t *result) {
  fqr_options_t o;
  size_t n = 0;
  if (result == NULL) {
    return FQR_ERR_INVALID_ARG;
  }
  if (opts != NULL) {
    o = *opts;
  } else {
    memset(&o, 0, sizeof o);
  }
  o.max_codes = 2u;
  fqr_status_t s = fqr_decode(img, workspace, ws_size, &o, result, 1u, &n);
  if (n > 1u) {
    return FQR_ERR_MULTIPLE_CODES;
  }
  return s;
}

fqr_status_t fqr_decode_matrix(const uint8_t *modules, uint32_t size,
                               size_t stride, bool try_mirror, void *workspace,
                               size_t ws_size, fqr_result_t *result) {
  fqr_stats_t st;
  if (modules == NULL || result == NULL || size < 21u ||
      size > FQR_MAX_MODULES || (size - 17u) % 4u != 0u ||
      stride < (size + 7u) / 8u ||
      (result->payload == NULL && result->payload_cap != 0u)) {
    return FQR_ERR_INVALID_ARG;
  }
  fqr_ws_t *ws = align_ws(workspace, ws_size);
  if (ws == NULL) {
    return FQR_ERR_WORKSPACE;
  }
  clear_result_outputs(result);
  memset(&st, 0, sizeof st);
  bool overflow = false;
  fqr_stage_t s = fqr_decode_grid(modules, stride, size, false, ws->cw, result,
                                  &overflow, &st);
  if (s != FQR_STAGE_OK && s <= FQR_STAGE_ECC && try_mirror) {
    fqr_stage_t s2 = fqr_decode_grid(modules, stride, size, true, ws->cw,
                                     result, &overflow, &st);
    if (s2 == FQR_STAGE_OK || s2 > s) {
      s = s2;
    }
  }
  if (s != FQR_STAGE_OK) {
    uint8_t *p = result->payload;
    size_t cap = result->payload_cap;
    clear_result_outputs(result);
    result->payload = p;
    result->payload_cap = cap;
    result->status = stage_to_status(s);
    return stage_to_status(s);
  }
  result->status = overflow ? FQR_ERR_BUFFER_TOO_SMALL : FQR_OK;
  return result->status;
}
