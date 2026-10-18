// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/*
 * Geometry helpers: square root without libm and quad-to-quad projective
 * transforms (Heckbert's closed form: square -> quad, its adjugate for
 * quad -> square, then the product), all in single precision.
 */

#include "fqr_internal.h"

float fqr_sqrtf(float x)
{
    if (!(x > 0.0f) || !fqr_finite(x)) {
        return 0.0f;
    }
    /* Initial guess from the exponent bits, then Newton iterations. */
    uint32_t i;
    memcpy(&i, &x, sizeof i);
    i = 0x1fbd1df5u + (i >> 1);
    float y;
    memcpy(&y, &i, sizeof y);
    y = 0.5f * (y + x / y);
    y = 0.5f * (y + x / y);
    y = 0.5f * (y + x / y);
    return y;
}

/* Square (0,0),(1,0),(1,1),(0,1) -> quad p[0..3]. */
static bool square_to_quad(float m[9], const float p[8])
{
    float x0 = p[0], y0 = p[1], x1 = p[2], y1 = p[3];
    float x2 = p[4], y2 = p[5], x3 = p[6], y3 = p[7];
    float dx3 = x0 - x1 + x2 - x3;
    float dy3 = y0 - y1 + y2 - y3;
    if (fqr_absf(dx3) < 1e-6f && fqr_absf(dy3) < 1e-6f) {
        m[0] = x1 - x0; m[1] = x3 - x0; m[2] = x0;
        m[3] = y1 - y0; m[4] = y3 - y0; m[5] = y0;
        m[6] = 0.0f;    m[7] = 0.0f;    m[8] = 1.0f;
        return true;
    }
    float dx1 = x1 - x2, dx2 = x3 - x2, dy1 = y1 - y2, dy2 = y3 - y2;
    float den = dx1 * dy2 - dx2 * dy1;
    if (!(fqr_absf(den) > 1e-9f) || !fqr_finite(den)) {
        return false;
    }
    float g = (dx3 * dy2 - dx2 * dy3) / den;
    float h = (dx1 * dy3 - dx3 * dy1) / den;
    m[0] = x1 - x0 + g * x1; m[1] = x3 - x0 + h * x3; m[2] = x0;
    m[3] = y1 - y0 + g * y1; m[4] = y3 - y0 + h * y3; m[5] = y0;
    m[6] = g;                m[7] = h;                m[8] = 1.0f;
    return true;
}

/* Adjugate (inverse up to scale). */
static void adjugate(float r[9], const float a[9])
{
    r[0] = a[4] * a[8] - a[5] * a[7];
    r[1] = a[2] * a[7] - a[1] * a[8];
    r[2] = a[1] * a[5] - a[2] * a[4];
    r[3] = a[5] * a[6] - a[3] * a[8];
    r[4] = a[0] * a[8] - a[2] * a[6];
    r[5] = a[2] * a[3] - a[0] * a[5];
    r[6] = a[3] * a[7] - a[4] * a[6];
    r[7] = a[1] * a[6] - a[0] * a[7];
    r[8] = a[0] * a[4] - a[1] * a[3];
}

static void mul3(float r[9], const float a[9], const float b[9])
{
    for (unsigned i = 0; i < 3u; i++) {
        for (unsigned j = 0; j < 3u; j++) {
            r[i * 3u + j] = a[i * 3u] * b[j] + a[i * 3u + 1u] * b[3u + j] + a[i * 3u + 2u] * b[6u + j];
        }
    }
}

bool fqr_xform_quad(fqr_xform_t *t, const float src[8], const float dst[8])
{
    float s2q_src[9], q2s_src[9], s2q_dst[9];
    for (unsigned i = 0; i < 8u; i++) {
        if (!fqr_in_range(src[i], -1.0e5f, 1.0e5f) || !fqr_in_range(dst[i], -1.0e5f, 1.0e5f)) {
            return false;
        }
    }
    if (!square_to_quad(s2q_src, src) || !square_to_quad(s2q_dst, dst)) {
        return false;
    }
    adjugate(q2s_src, s2q_src);
    mul3(t->m, s2q_dst, q2s_src);
    /* Normalise the scale so that the largest coefficient is 1. */
    float mx = 0.0f;
    for (unsigned i = 0; i < 9u; i++) {
        if (!fqr_finite(t->m[i])) {
            return false;
        }
        mx = fqr_maxf(mx, fqr_absf(t->m[i]));
    }
    if (!(mx > 1e-30f)) {
        return false;
    }
    float inv = 1.0f / mx;
    for (unsigned i = 0; i < 9u; i++) {
        t->m[i] *= inv;
    }
    /* Reject (near-)singular maps: the Jacobian determinant must not vanish. */
    float det = t->m[0] * (t->m[4] * t->m[8] - t->m[5] * t->m[7]) -
                t->m[1] * (t->m[3] * t->m[8] - t->m[5] * t->m[6]) +
                t->m[2] * (t->m[3] * t->m[7] - t->m[4] * t->m[6]);
    return fqr_finite(det) && fqr_absf(det) > 1e-12f;
}

bool fqr_xform_apply(const fqr_xform_t *t, float u, float v, float *x, float *y)
{
    const float *m = t->m;
    float w = m[6] * u + m[7] * v + m[8];
    if (!(fqr_absf(w) > 1e-12f)) {
        return false;
    }
    float xx = (m[0] * u + m[1] * v + m[2]) / w;
    float yy = (m[3] * u + m[4] * v + m[5]) / w;
    if (!fqr_in_range(xx, -1.0e6f, 1.0e6f) || !fqr_in_range(yy, -1.0e6f, 1.0e6f)) {
        return false;
    }
    *x = xx;
    *y = yy;
    return true;
}
