// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Alignment pattern search.
 *
 * Rows of a square region around the predicted centre are scanned from the
 * middle outwards for light/dark/light runs of about one module; each hit
 * is re-centred by vertical and horizontal cross-checks and then verified
 * against the complete 5x5 alignment template, sampled with the local
 * module basis of the current transform (data modules frequently mimic a
 * 1:1:1 run, the template does not). The best candidate (fewest template
 * mismatches, then closest to the prediction) wins.
 */

#include "fqr_internal.h"

#define ALIGN_MAX_EVAL 48u
#define ALIGN_MAX_MISMATCH 3u

typedef struct {
  const fqr_bm_t *b;
  uint32_t lo, hi; /* accepted run length range, pixels */
} runspec_t;

static bool run_ok(const runspec_t *rs, uint32_t n) {
  return n >= rs->lo && n <= rs->hi;
}

/* Cross-check along (dx, dy) through (x, y): dark centre, light ring on both
 * sides, each bounded by dark. Returns the refined centre coordinate along
 * the walk axis, or a negative value. */
static float cross_check(const runspec_t *rs, int32_t x, int32_t y, int32_t dx,
                         int32_t dy) {
  const fqr_bm_t *b = rs->b;
  uint32_t c_neg = 0, c_pos = 0, l_neg = 0, l_pos = 0;
  int32_t px, py;
  if (!fqr_px(b, x, y)) {
    return -1.0f;
  }
  px = x;
  py = y;
  while (fqr_px(b, px, py) && c_neg <= rs->hi) {
    c_neg++;
    px -= dx;
    py -= dy;
  }
  while (!fqr_px(b, px, py) && l_neg <= rs->hi) {
    if (px < 0 || py < 0 || px >= b->w || py >= b->h) {
      return -1.0f;
    }
    l_neg++;
    px -= dx;
    py -= dy;
  }
  px = x + dx;
  py = y + dy;
  while (fqr_px(b, px, py) && c_pos <= rs->hi) {
    c_pos++;
    px += dx;
    py += dy;
  }
  int32_t end = (dx != 0) ? px : py;
  while (!fqr_px(b, px, py) && l_pos <= rs->hi) {
    if (px < 0 || py < 0 || px >= b->w || py >= b->h) {
      return -1.0f;
    }
    l_pos++;
    px += dx;
    py += dy;
  }
  b->st->crosscheck_pixels += c_neg + c_pos + l_neg + l_pos;
  uint32_t c = c_neg + c_pos;
  if (!run_ok(rs, c) || !run_ok(rs, l_neg) || !run_ok(rs, l_pos)) {
    return -1.0f;
  }
  return (float)end - (float)c / 2.0f;
}

/* Number of template mismatches at (cx, cy) with module basis (ux,uy),(vx,vy).
 */
static unsigned template_mismatch(const fqr_bm_t *b, float cx, float cy,
                                  float ux, float uy, float vx, float vy) {
  unsigned bad = 0;
  for (int dy = -2; dy <= 2; dy++) {
    for (int dx = -2; dx <= 2; dx++) {
      int ring = (dx < 0 ? -dx : dx) > (dy < 0 ? -dy : dy)
                     ? (dx < 0 ? -dx : dx)
                     : (dy < 0 ? -dy : dy);
      int expect = ring != 1;
      float x = cx + (float)dx * ux + (float)dy * vx;
      float y = cy + (float)dx * uy + (float)dy * vy;
      if (fqr_px_f(b, x, y) != expect) {
        bad++;
      }
    }
  }
  return bad;
}

bool fqr_find_alignment(const fqr_bm_t *b, const fqr_xform_t *t, float mu,
                        float mv, float ms, float radius, fqr_point_t *out) {
  float px, py, ax, ay, bx, by;
  if (!fqr_xform_apply(t, mu, mv, &px, &py) ||
      !fqr_xform_apply(t, mu + 1.0f, mv, &ax, &ay) ||
      !fqr_xform_apply(t, mu, mv + 1.0f, &bx, &by)) {
    return false;
  }
  float ux = ax - px, uy = ay - py, vx = bx - px, vy = by - py;
  if (!(ms > 0.5f && ms < 512.0f) || !(radius > 0.0f && radius < 64.0f)) {
    return false;
  }
  float r = radius * ms;
  int32_t x0 = fqr_floori(fqr_maxf(0.0f, px - r));
  int32_t x1 = fqr_floori(fqr_minf((float)(b->w - 1), px + r));
  int32_t y0 = fqr_floori(fqr_maxf(0.0f, py - r));
  int32_t y1 = fqr_floori(fqr_minf((float)(b->h - 1), py + r));
  if (x0 < 0 || y0 < 0 || x1 < x0 || y1 < y0 || x1 >= b->w || y1 >= b->h) {
    return false;
  }
  runspec_t rs;
  rs.b = b;
  rs.lo = (uint32_t)fqr_maxf(1.0f, 0.45f * ms);
  rs.hi = (uint32_t)(1.8f * ms + 1.0f);
  if (rs.hi < rs.lo + 1u) {
    rs.hi = rs.lo + 1u;
  }

  /* Budget accounting: one unit per 8 pixels of search area. */
  *b->work +=
      (uint32_t)(((uint32_t)(x1 - x0 + 1) * (uint32_t)(y1 - y0 + 1)) / 8u);

  int32_t yc = fqr_floori(py);
  if (yc < y0) {
    yc = y0;
  }
  if (yc > y1) {
    yc = y1;
  }
  float best_score = 1e30f;
  unsigned best_bad = 99u;
  fqr_point_t best = {0.0f, 0.0f};
  unsigned evals = 0;
  int32_t span = (y1 - y0) + 1;
  for (int32_t k = 0; k < 2 * span && evals < ALIGN_MAX_EVAL; k++) {
    int32_t off = (k & 1) ? -((k + 1) / 2) : (k / 2);
    int32_t y = yc + off;
    if (y < y0 || y > y1) {
      continue;
    }
    /* Run-length scan of the row segment: window light, dark, light. */
    fqr_runs_t runs;
    fqr_runs_reset(&runs);
    int color = fqr_px(b, x0, y);
    int32_t start = x0;
    for (int32_t x = x0; x <= x1 + 1 && evals < ALIGN_MAX_EVAL; x++) {
      int v = (x <= x1) ? fqr_px(b, x, y) : !color;
      if (v == color) {
        continue;
      }
      fqr_runs_push(&runs, (uint32_t)(x - start));
      /* The completed run was light and preceded by dark, light, dark. */
      if (color == 0 && runs.n >= 4u && x <= x1 && run_ok(&rs, runs.r[5]) &&
          run_ok(&rs, runs.r[6]) && run_ok(&rs, runs.r[7])) {
        float cx = (float)(x - (int32_t)runs.r[7]) - (float)runs.r[6] / 2.0f;
        float cy = cross_check(&rs, fqr_floori(cx), y, 0, 1);
        if (cy >= 0.0f) {
          float cx2 = cross_check(&rs, fqr_floori(cx), fqr_floori(cy), 1, 0);
          if (cx2 >= 0.0f) {
            evals++;
            unsigned bad = template_mismatch(b, cx2, cy, ux, uy, vx, vy);
            float d = fqr_dist(cx2, cy, px, py) / ms;
            float score = (float)bad + 0.25f * d;
            if (bad <= ALIGN_MAX_MISMATCH && score < best_score) {
              best_score = score;
              best_bad = bad;
              best.x = cx2;
              best.y = cy;
            }
          }
        }
      }
      color = v;
      start = x;
    }
    if (best_bad == 0u && best_score < 0.5f) {
      break; /* perfect match next to the prediction */
    }
  }
  if (best_bad > ALIGN_MAX_MISMATCH) {
    return false;
  }
  *out = best;
  return true;
}
