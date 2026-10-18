// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Finder pattern detection (after ZXing's FinderPatternFinder).
 *
 * Every image row is run-length encoded; each window of five runs
 * dark/light/dark/light/dark matching 1:1:3:1:1 is cross-checked
 * vertically, horizontally (re-centring each time) and diagonally. A
 * confirmed centre is merged with a nearby candidate of similar module
 * size or stored as a new one. All walks are bounded by the run lengths
 * of the triggering pattern, so the total cost is O(width * height).
 */

#include "fqr_internal.h"

/* 1:1:3:1:1 with tolerance 50 % of a module per run (integer arithmetic:
 * |total/7 - c| < total/14  <=>  2|total - 7c| < total). Runs are at most
 * FQR_MAX_IMAGE_DIM pixels, so 32-bit arithmetic cannot overflow. */
static bool ratio_ok(const uint32_t r[5])
{
    /* Fast reject: the centre run (3 modules) dominates every other run. */
    if (r[2] < r[0] || r[2] < r[1] || r[2] < r[3] || r[2] < r[4]) {
        return false;
    }
    int32_t total = (int32_t)(r[0] + r[1] + r[2] + r[3] + r[4]);
    if (total < 7 || r[0] == 0u || r[1] == 0u || r[3] == 0u || r[4] == 0u) {
        return false;
    }
    for (unsigned i = 0; i < 5u; i++) {
        int32_t mult = (i == 2u) ? 3 : 1;
        int32_t diff = mult * total - 7 * (int32_t)r[i];
        if (diff < 0) {
            diff = -diff;
        }
        if (2 * diff >= mult * total) {
            return false;
        }
    }
    return true;
}

/* Looser variant used for the diagonal check (ZXing: variance m / 1.333):
 * |total/7 - c| < 0.75 * total/7  <=>  4|total - 7c| < 3 total. */
static bool ratio_ok_diag(const uint32_t r[5])
{
    int32_t total = (int32_t)(r[0] + r[1] + r[2] + r[3] + r[4]);
    if (total < 7 || r[0] == 0u || r[1] == 0u || r[2] == 0u || r[3] == 0u || r[4] == 0u) {
        return false;
    }
    for (unsigned i = 0; i < 5u; i++) {
        int32_t mult = (i == 2u) ? 3 : 1;
        int32_t diff = mult * total - 7 * (int32_t)r[i];
        if (diff < 0) {
            diff = -diff;
        }
        if (4 * diff >= 3 * mult * total) {
            return false;
        }
    }
    return true;
}

static float center_from_end(const uint32_t r[5], int32_t end)
{
    return (float)(end - (int32_t)r[4] - (int32_t)r[3]) - (float)r[2] / 2.0f;
}

/*
 * Walk along (dx, dy) from (x, y) collecting the runs of the pattern on
 * one side. Returns false if the walk leaves the image or a run exceeds
 * max_count. counts[0] receives the centre run part (including the start
 * pixel when include_start), counts[1] the light ring, counts[2] the outer
 * dark ring.
 */
static bool walk_side(const fqr_bm_t *b, int32_t x, int32_t y, int32_t dx, int32_t dy,
                      uint32_t max_count, uint32_t counts[3], bool allow_edge_outer, bool tol)
{
    /* tol: modules are large (>= 4 px), so a single pixel of the wrong
     * colour followed by the expected one is noise, counted as expected. */
    static const int want[3] = {1, 0, 1};
    uint32_t limit[3] = {4u * max_count + 8u, max_count, max_count};
    counts[0] = counts[1] = counts[2] = 0;
    for (unsigned s = 0; s < 3u; s++) {
        for (;;) {
            if (x < 0 || y < 0 || x >= b->w || y >= b->h) {
                if (s < 2u || !allow_edge_outer) {
                    return false;
                }
                break;
            }
            int p = fqr_px(b, x, y);
            if (p != want[s]) {
                if (!(tol && counts[s] > 0u && fqr_px(b, x + dx, y + dy) == want[s])) {
                    break;
                }
            }
            if (++counts[s] > limit[s]) {
                return false;
            }
            x += dx;
            y += dy;
        }
        if (s > 0u && counts[s] == 0u) {
            return false;
        }
    }
    b->st->crosscheck_pixels += counts[0] + counts[1] + counts[2];
    return true;
}

/* Vertical cross-check through column cx starting at row cy.
 * Returns the refined centre row or a negative value. */
static float cross_vertical(const fqr_bm_t *b, int32_t cy, int32_t cx, uint32_t max_count,
                            uint32_t orig_total)
{
    uint32_t up[3], dn[3];
    bool tol = orig_total >= 28u;
    if (!fqr_px(b, cx, cy)) {
        return -1.0f;
    }
    if (!walk_side(b, cx, cy, 0, -1, max_count, up, true, tol) ||
        !walk_side(b, cx, cy + 1, 0, 1, max_count, dn, true, tol)) {
        return -1.0f;
    }
    uint32_t r[5] = {up[2], up[1], up[0] + dn[0], dn[1], dn[2]};
    uint32_t total = r[0] + r[1] + r[2] + r[3] + r[4];
    uint32_t d = total > orig_total ? total - orig_total : orig_total - total;
    if (5u * d >= 2u * orig_total || !ratio_ok(r)) {
        return -1.0f;
    }
    int32_t end = cy + 1 + (int32_t)(dn[0] + dn[1] + dn[2]);
    return center_from_end(r, end);
}

static float cross_horizontal(const fqr_bm_t *b, int32_t cx, int32_t cy, uint32_t max_count,
                              uint32_t orig_total)
{
    uint32_t lf[3], rt[3];
    bool tol = orig_total >= 28u;
    if (!fqr_px(b, cx, cy)) {
        return -1.0f;
    }
    if (!walk_side(b, cx, cy, -1, 0, max_count, lf, true, tol) ||
        !walk_side(b, cx + 1, cy, 1, 0, max_count, rt, true, tol)) {
        return -1.0f;
    }
    uint32_t r[5] = {lf[2], lf[1], lf[0] + rt[0], rt[1], rt[2]};
    uint32_t total = r[0] + r[1] + r[2] + r[3] + r[4];
    uint32_t d = total > orig_total ? total - orig_total : orig_total - total;
    if (5u * d >= orig_total || !ratio_ok(r)) {
        return -1.0f;
    }
    int32_t end = cx + 1 + (int32_t)(rt[0] + rt[1] + rt[2]);
    return center_from_end(r, end);
}

static bool cross_diagonal(const fqr_bm_t *b, int32_t cx, int32_t cy, uint32_t max_count,
                           uint32_t orig_total)
{
    uint32_t ul[3], dr[3];
    bool tol = orig_total >= 28u;
    if (!fqr_px(b, cx, cy)) {
        return false;
    }
    if (!walk_side(b, cx, cy, -1, -1, 2u * max_count, ul, false, tol) ||
        !walk_side(b, cx + 1, cy + 1, 1, 1, 2u * max_count, dr, false, tol)) {
        return false;
    }
    uint32_t r[5] = {ul[2], ul[1], ul[0] + dr[0], dr[1], dr[2]};
    return ratio_ok_diag(r);
}

static void add_candidate(const fqr_bm_t *b, fqr_cand_list_t *list, float x, float y, float ms,
                          int32_t row)
{
    for (uint32_t i = 0; i < list->n; i++) {
        fqr_cand_t *c = &list->c[i];
        if (fqr_absf(y - c->y) <= ms && fqr_absf(x - c->x) <= ms) {
            float diff = fqr_absf(ms - c->ms);
            if (diff <= 1.0f || diff <= c->ms) {
                float n = (float)c->count;
                c->x = (c->x * n + x) / (n + 1.0f);
                c->y = (c->y * n + y) / (n + 1.0f);
                c->ms = (c->ms * n + ms) / (n + 1.0f);
                if (c->count < UINT16_MAX) {
                    c->count++;
                }
                return;
            }
        }
    }
    if (list->n >= FQR_MAX_CANDIDATES) {
        /* Drop finished single-observation candidates (rows well above the
         * current one can never be confirmed again). */
        uint32_t w = 0;
        for (uint32_t i = 0; i < list->n; i++) {
            fqr_cand_t *c = &list->c[i];
            bool stale = c->count <= 1u && c->y + 4.0f * c->ms < (float)row;
            if (!stale) {
                list->c[w++] = *c;
            }
        }
        list->n = w;
        if (list->n >= FQR_MAX_CANDIDATES) {
            return;
        }
    }
    fqr_cand_t *c = &list->c[list->n++];
    c->x = x;
    c->y = y;
    c->ms = ms;
    c->count = 1u;
    c->flags = 0u;
    b->st->finder_candidates++;
}

static void handle_possible_center(const fqr_bm_t *b, fqr_cand_list_t *list, const uint32_t r[5],
                                   int32_t row, int32_t end)
{
    uint32_t total = r[0] + r[1] + r[2] + r[3] + r[4];
    float cx = center_from_end(r, end);
    float cy = cross_vertical(b, row, fqr_floori(cx), r[2], total);
    if (cy < 0.0f) {
        return;
    }
    cx = cross_horizontal(b, fqr_floori(cx), fqr_floori(cy), r[2], total);
    if (cx < 0.0f) {
        return;
    }
    if (!cross_diagonal(b, fqr_floori(cx), fqr_floori(cy), r[2], total)) {
        return;
    }
    b->st->finder_hits++;
    add_candidate(b, list, cx, cy, (float)total / 7.0f, row);
}

/* Logical byte i of row y: inverted, out-of-image bits cleared. */
static inline uint32_t row_byte(const fqr_bm_t *b, int32_t y, int32_t i, int32_t nbytes)
{
    if (y < 0 || y >= b->h || i < 0 || i >= nbytes) {
        return 0u;
    }
    uint32_t v = (uint32_t)(b->data[(size_t)y * b->stride + (size_t)i] ^ b->inv_byte);
    if (i == nbytes - 1 && (b->w & 7) != 0) {
        v &= 0xFFu << (8u - ((uint32_t)b->w & 7u));
    }
    return v & 0xFFu;
}

void fqr_filter_row(const fqr_bm_t *b, int32_t y, uint8_t *out)
{
    int32_t nb = (b->w + 7) / 8;
    for (int32_t i = 0; i < nb; i++) {
        uint32_t s[3], c[3];
        for (int k = 0; k < 3; k++) {
            int32_t r = y - 1 + k;
            uint32_t cur = row_byte(b, r, i, nb);
            uint32_t l = ((cur >> 1) | (row_byte(b, r, i - 1, nb) << 7)) & 0xFFu; /* pixel x-1 */
            uint32_t rr = ((cur << 1) | (row_byte(b, r, i + 1, nb) >> 7)) & 0xFFu; /* pixel x+1 */
            s[k] = l ^ cur ^ rr;
            c[k] = (l & cur) | (rr & (l ^ cur));
        }
        /* total = 4*C1 + 2*C0 + 2*S1 + S0 with C = c0+c1+c2, S = s0+s1+s2. */
        uint32_t s0 = s[0] ^ s[1] ^ s[2];
        uint32_t s1 = (s[0] & s[1]) | (s[2] & (s[0] ^ s[1]));
        uint32_t c0 = c[0] ^ c[1] ^ c[2];
        uint32_t c1 = (c[0] & c[1]) | (c[2] & (c[0] ^ c[1]));
        uint32_t u0 = c0 ^ s1, u1 = c0 & s1;
        uint32_t ge5 = (c1 & u1) | ((c1 ^ u1) & (u0 | s0));
        if (i == nb - 1 && (b->w & 7) != 0) {
            ge5 &= 0xFFu << (8u - ((uint32_t)b->w & 7u));
        }
        out[i] = (uint8_t)ge5;
    }
}

void fqr_find_candidates(const fqr_bm_t *b, fqr_cand_list_t *list, uint8_t *rowbuf)
{
    /* Row decoding view: raw rows with inversion, or pre-filtered rows. */
    const uint8_t rinv_byte = b->filter ? 0u : b->inv_byte;
    const unsigned rinv = b->filter ? 0u : b->inv;
    list->n = 0;
    for (int32_t y = 0; y < b->h; y++) {
        const uint8_t *row = b->data + (size_t)y * b->stride;
        if (b->filter) {
            fqr_filter_row(b, y, rowbuf);
            row = rowbuf;
        }
        fqr_runs_t runs;
        fqr_runs_reset(&runs);
        int32_t x = 0;
        int color = (int)(((unsigned)(row[0] >> 7) & 1u) ^ rinv);
        int32_t start = 0;
        while (x < b->w) {
            /* Advance to the end of the current run, 8 pixels at a time
             * when a whole byte has the run's colour. */
            uint8_t same = color ? 0xFFu : 0x00u;
            while (x < b->w) {
                if ((x & 7) == 0 && x + 8 <= b->w &&
                    (uint8_t)(row[(uint32_t)x >> 3] ^ rinv_byte) == same) {
                    x += 8;
                    continue;
                }
                int v = (int)(((unsigned)(row[(uint32_t)x >> 3] >> (7u - ((uint32_t)x & 7u))) & 1u) ^ rinv);
                if (v != color) {
                    break;
                }
                x++;
            }
            fqr_runs_push(&runs, (uint32_t)(x - start));
            /* Runs alternate, so r[3], r[5] and r[7] share the colour of the
             * run just completed: test dark-ending windows. */
            if (runs.n >= 5u && color == 1 && ratio_ok(&runs.r[3])) {
                handle_possible_center(b, list, &runs.r[3], y, x);
            }
            color ^= 1;
            start = x;
        }
        b->st->pixels_scanned += (uint32_t)b->w;
    }
}

/*
 * Bresenham walk from (fx, fy) towards (tx, ty) counting dark, light, dark
 * runs; returns the distance to the end of the outer dark run (i.e. the
 * outer edge of the finder pattern) or a negative value.
 */
static float bwb_run(const fqr_bm_t *b, int32_t fx, int32_t fy, int32_t tx, int32_t ty)
{
    bool steep = (ty > fy ? ty - fy : fy - ty) > (tx > fx ? tx - fx : fx - tx);
    if (steep) {
        int32_t t = fx; fx = fy; fy = t;
        t = tx; tx = ty; ty = t;
    }
    int32_t dx = tx > fx ? tx - fx : fx - tx;
    int32_t dy = ty > fy ? ty - fy : fy - ty;
    int32_t err = -dx / 2;
    int32_t xstep = fx < tx ? 1 : -1;
    int32_t ystep = fy < ty ? 1 : -1;
    int state = 0;
    int32_t xlimit = tx + xstep;
    for (int32_t x = fx, y = fy; x != xlimit; x += xstep) {
        int32_t rx = steep ? y : x;
        int32_t ry = steep ? x : y;
        /* state 0 and 2 expect dark, 1 expects light. */
        if ((state == 1) == (fqr_px(b, rx, ry) != 0)) {
            if (state == 2) {
                return fqr_dist((float)x, (float)y, (float)fx, (float)fy);
            }
            state++;
        }
        err += dy;
        if (err > 0) {
            if (y == ty) {
                break;
            }
            y += ystep;
            err -= dx;
        }
    }
    if (state == 2) {
        return fqr_dist((float)(tx + xstep), (float)ty, (float)fx, (float)fy);
    }
    return -1.0f;
}

static float bwb_both_ways(const fqr_bm_t *b, float fxf, float fyf, float txf, float tyf)
{
    int32_t fx = fqr_floori(fxf), fy = fqr_floori(fyf), tx = fqr_floori(txf), ty = fqr_floori(tyf);
    if (fx < 0 || fy < 0 || fx >= b->w || fy >= b->h) {
        return -1.0f;
    }
    tx = tx < 0 ? 0 : (tx >= b->w ? b->w - 1 : tx);
    ty = ty < 0 ? 0 : (ty >= b->h ? b->h - 1 : ty);
    float r1 = bwb_run(b, fx, fy, tx, ty);
    /* Other direction, clipped to the image. */
    float ox = (float)fx - (float)(tx - fx);
    float oy = (float)fy - (float)(ty - fy);
    float scale = 1.0f;
    if (ox < 0.0f) {
        scale = (float)fx / ((float)fx - ox);
    } else if (ox > (float)(b->w - 1)) {
        scale = (float)(b->w - 1 - fx) / (ox - (float)fx);
    }
    if (oy < 0.0f) {
        scale = fqr_minf(scale, (float)fy / ((float)fy - oy));
    } else if (oy > (float)(b->h - 1)) {
        scale = fqr_minf(scale, (float)(b->h - 1 - fy) / (oy - (float)fy));
    }
    ox = (float)fx + (ox - (float)fx) * scale;
    oy = (float)fy + (oy - (float)fy) * scale;
    float r2 = bwb_run(b, fx, fy, fqr_floori(ox), fqr_floori(oy));
    if (r1 < 0.0f || r2 < 0.0f) {
        return -1.0f;
    }
    return r1 + r2 - 1.0f;
}

float fqr_module_size_between(const fqr_bm_t *b, float ax, float ay, float bx, float by)
{
    float e1 = bwb_both_ways(b, ax, ay, bx, by);
    float e2 = bwb_both_ways(b, bx, by, ax, ay);
    if (e1 < 0.0f && e2 < 0.0f) {
        return -1.0f;
    }
    if (e1 < 0.0f) {
        return e2 / 7.0f;
    }
    if (e2 < 0.0f) {
        return e1 / 7.0f;
    }
    return (e1 + e2) / 14.0f;
}

uint32_t fqr_count_transitions(const fqr_bm_t *b, float x0, float y0, float x1, float y1,
                               float min_run)
{
    float len = fqr_dist(x0, y0, x1, y1);
    if (!(len >= 1.0f && len < 4096.0f)) {
        return 0u;
    }
    uint32_t n = (uint32_t)len + 1u;
    float sx = (x1 - x0) / (float)n, sy = (y1 - y0) / (float)n;
    uint32_t thr = (uint32_t)fqr_maxf(1.0f, min_run + 0.5f);
    int color = fqr_px_f(b, x0, y0);
    uint32_t pending = 0, trans = 0;
    for (uint32_t i = 1; i <= n; i++) {
        int v = fqr_px_f(b, x0 + sx * (float)i, y0 + sy * (float)i);
        if (v == color) {
            pending = 0;
        } else if (++pending >= thr) {
            color = v;
            pending = 0;
            trans++;
        }
    }
    b->st->crosscheck_pixels += n;
    return trans;
}

/* Casts one ray from (cx, cy) along (dx, dy) (unit vector) and returns the
 * point where the outer dark ring of the finder pattern ends. */
static bool ray_boundary(const fqr_bm_t *b, float cx, float cy, float dx, float dy, float maxd,
                         float ms, float *px, float *py)
{
    static const int want[4] = {1, 0, 1, 0};
    const float step = 0.5f;
    const unsigned deb = ms >= 4.0f ? 3u : (ms >= 2.5f ? 2u : 1u);
    unsigned state = 0, agree = 0;
    unsigned n = (unsigned)(maxd / step);
    for (unsigned i = 1; i <= n; i++) {
        float t = (float)i * step;
        int p = fqr_px_f(b, cx + dx * t, cy + dy * t);
        if (state + 1u < 4u && p == want[state + 1u]) {
            if (++agree >= deb) {
                state++;
                agree = 0;
                if (state == 3u) {
                    float tb = t - (float)(deb - 1u) * step;
                    *px = cx + dx * tb;
                    *py = cy + dy * tb;
                    b->st->crosscheck_pixels += i;
                    *b->work += i / 4u;
                    return true;
                }
            }
        } else {
            agree = 0;
        }
    }
    b->st->crosscheck_pixels += n;
    *b->work += n / 4u;
    return false;
}

/* Principal direction of a point set (unit vector), false if degenerate. */
static bool fit_direction(const float *xs, const float *ys, unsigned n, float d[2])
{
    if (n < 3u) {
        return false;
    }
    float mx = 0.0f, my = 0.0f;
    for (unsigned i = 0; i < n; i++) {
        mx += xs[i];
        my += ys[i];
    }
    mx /= (float)n;
    my /= (float)n;
    float a = 0.0f, bb = 0.0f, c = 0.0f;
    for (unsigned i = 0; i < n; i++) {
        float ex = xs[i] - mx, ey = ys[i] - my;
        a += ex * ex;
        bb += ex * ey;
        c += ey * ey;
    }
    float h = (a - c) / 2.0f;
    float lam = (a + c) / 2.0f + fqr_sqrtf(h * h + bb * bb);
    float e1x = bb, e1y = lam - a, e2x = lam - c, e2y = bb;
    float n1 = e1x * e1x + e1y * e1y, n2 = e2x * e2x + e2y * e2y;
    float vx = n1 >= n2 ? e1x : e2x, vy = n1 >= n2 ? e1y : e2y;
    float nn = fqr_sqrtf(vx * vx + vy * vy);
    if (!(nn > 1e-6f)) {
        return false;
    }
    /* The spread along the line must dominate the spread across it. */
    float lam2 = (a + c) - lam;
    if (!(lam > 4.0f * lam2)) {
        return false;
    }
    d[0] = vx / nn;
    d[1] = vy / nn;
    return true;
}

unsigned fqr_finder_axes(const fqr_bm_t *b, float cx, float cy, float ms, const float u[2],
                         const float v[2], float hu[2], float hv[2])
{
    enum { RAYS = 9 };
    float side_dir[4][2];
    bool side_ok[4];
    hu[0] = u[0];
    hu[1] = u[1];
    hv[0] = v[0];
    hv[1] = v[1];
    if (!(ms >= 1.0f && ms < 200.0f)) {
        return 0u;
    }
    for (unsigned s = 0; s < 4u; s++) {
        /* Sides: +u, -u (edges along v), +v, -v (edges along u). */
        const float *nrm = (s < 2u) ? u : v;
        const float *tan = (s < 2u) ? v : u;
        float sg = (s & 1u) ? -1.0f : 1.0f;
        float xs[RAYS], ys[RAYS];
        unsigned np = 0;
        for (unsigned k = 0; k < RAYS; k++) {
            float tk = -0.6f + 0.15f * (float)k;
            float dx = sg * nrm[0] + tk * tan[0], dy = sg * nrm[1] + tk * tan[1];
            float len = fqr_sqrtf(dx * dx + dy * dy);
            if (!(len > 0.1f)) {
                continue;
            }
            dx /= len;
            dy /= len;
            float px, py;
            if (ray_boundary(b, cx, cy, dx, dy, 6.0f * ms * len, ms, &px, &py)) {
                /* Outer edge expected at 3.5 modules along the normal. */
                float along = ((px - cx) * nrm[0] + (py - cy) * nrm[1]) * sg;
                if (along > 2.5f * ms && along < 5.0f * ms) {
                    xs[np] = px;
                    ys[np] = py;
                    np++;
                }
            }
        }
        side_ok[s] = fit_direction(xs, ys, np, side_dir[s]);
        if (side_ok[s]) {
            /* Orient along the tangent axis. */
            if (side_dir[s][0] * tan[0] + side_dir[s][1] * tan[1] < 0.0f) {
                side_dir[s][0] = -side_dir[s][0];
                side_dir[s][1] = -side_dir[s][1];
            }
            /* Reject fits deviating more than ~37 degrees from the guess. */
            if (side_dir[s][0] * tan[0] + side_dir[s][1] * tan[1] < 0.8f) {
                side_ok[s] = false;
            }
        }
    }
    unsigned res = 0;
    for (unsigned pair = 0; pair < 2u; pair++) {
        unsigned s0 = pair * 2u, s1 = s0 + 1u;
        float dx = 0.0f, dy = 0.0f;
        if (side_ok[s0]) {
            dx += side_dir[s0][0];
            dy += side_dir[s0][1];
        }
        if (side_ok[s1]) {
            dx += side_dir[s1][0];
            dy += side_dir[s1][1];
        }
        float len = fqr_sqrtf(dx * dx + dy * dy);
        if (!(len > 0.5f)) {
            continue;
        }
        /* Edges of the +/-u sides run along v and vice versa. */
        float *out = (pair == 0u) ? hv : hu;
        out[0] = dx / len;
        out[1] = dy / len;
        res |= (pair == 0u) ? 2u : 1u;
    }
    return res;
}
