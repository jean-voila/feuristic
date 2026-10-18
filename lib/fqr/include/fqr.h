// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors

/**
 * @file fqr.h
 * @brief Freestanding QR code (Model 2, versions 1-40) detector and decoder.
 *
 * lib/fqr locates and decodes QR codes in a binarized 1-bit-per-pixel
 * bitmap. It is written for hostile input on a microcontroller:
 *
 *  - freestanding C99, no allocation, no recursion, no VLAs;
 *  - all working memory comes from a caller-provided workspace of
 *    ::FQR_WORKSPACE_SIZE bytes (independent of the image size);
 *  - every count read from the image is bounds-checked before use;
 *  - total work is bounded by a budget (see fqr_options_t::max_work).
 *
 * The decoder is reentrant: it keeps no global mutable state. Two calls
 * may run concurrently provided they use distinct workspaces.
 *
 * Typical use (the image importer wants exactly one code):
 * @code
 *   static uint8_t ws[FQR_WORKSPACE_SIZE];
 *   uint8_t payload[FQR_MAX_PAYLOAD_SIZE];
 *   fqr_result_t res = { .payload = payload, .payload_cap = sizeof payload };
 *   fqr_image_t img = { .data = bits, .width = w, .height = h, .stride = (w + 7) / 8 };
 *   fqr_status_t st = fqr_decode_single(&img, ws, sizeof ws, NULL, &res);
 *   if (st == FQR_OK) { use(res.payload, res.payload_len); }
 * @endcode
 *
 * See docs/developer/lib-fqr.md for the algorithm, limits and failure modes.
 */

#ifndef FQR_H
#define FQR_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Library interface version (incremented on incompatible API changes). */
#define FQR_API_VERSION 1

/** Largest accepted image width or height, in pixels. */
#define FQR_MAX_IMAGE_DIM 1024u

/** Smallest / largest QR Model 2 version. */
#define FQR_VERSION_MIN 1u
#define FQR_VERSION_MAX 40u

/** Side length in modules of the largest symbol (version 40). */
#define FQR_MAX_MODULES 177u

/**
 * Largest possible decoded payload, in bytes: version 40-L holding 7089
 * numeric digits (one output byte per digit).
 */
#define FQR_MAX_PAYLOAD_SIZE 7089u

/** Hard upper bound for fqr_options_t::max_codes. */
#define FQR_MAX_CODES 8u

/** Default number of distinct codes searched for before stopping. */
#define FQR_DEFAULT_MAX_CODES 4u

/** Number of ECI designators recorded per result (more are counted only). */
#define FQR_MAX_ECI 4u

/**
 * Required workspace size in bytes, including worst-case alignment slack.
 * It does not depend on the image size. fqr_workspace_size() returns the
 * same value; the library statically asserts that its internal layout fits.
 */
#define FQR_WORKSPACE_SIZE 12288u

/** Status codes. Values are stable (they may be logged or shown as codes). */
typedef enum {
    FQR_OK = 0,                   /**< At least one code decoded completely. */
    FQR_ERR_INVALID_ARG = 1,      /**< NULL pointer, bad dimensions or stride, bad option. */
    FQR_ERR_WORKSPACE = 2,        /**< Workspace NULL or smaller than FQR_WORKSPACE_SIZE. */
    FQR_ERR_NOT_FOUND = 3,        /**< No plausible QR code (finder pattern triple) located. */
    FQR_ERR_FORMAT = 4,           /**< Located, but format/version information unreadable. */
    FQR_ERR_ECC = 5,              /**< Located, but Reed-Solomon decoding failed (too damaged). */
    FQR_ERR_DATA = 6,             /**< Error-corrected, but the bit stream is malformed. */
    FQR_ERR_BUFFER_TOO_SMALL = 7, /**< A decoded payload did not fit its caller buffer. */
    FQR_ERR_MULTIPLE_CODES = 8,   /**< fqr_decode_single(): more than one distinct code. */
} fqr_status_t;

/** Error correction level (public numbering, not the format-information bits). */
typedef enum {
    FQR_ECC_L = 0, /**< ~7 % recovery. */
    FQR_ECC_M = 1, /**< ~15 % recovery. */
    FQR_ECC_Q = 2, /**< ~25 % recovery. */
    FQR_ECC_H = 3, /**< ~30 % recovery. */
} fqr_ecc_level_t;

/** Bits of fqr_result_t::modes: data segment modes seen in the symbol. */
enum {
    FQR_MODE_NUMERIC = 1u << 0,
    FQR_MODE_ALPHANUMERIC = 1u << 1,
    FQR_MODE_BYTE = 1u << 2,
    FQR_MODE_KANJI = 1u << 3,
    FQR_MODE_ECI = 1u << 4,
    FQR_MODE_STRUCTURED_APPEND = 1u << 5,
    FQR_MODE_FNC1_FIRST = 1u << 6,
    FQR_MODE_FNC1_SECOND = 1u << 7,
};

/** Polarity passes (fqr_options_t::polarity). */
typedef enum {
    /** Normal pass; inverted pass only if the normal pass found nothing. */
    FQR_POLARITY_AUTO = 0,
    /** Both passes always (finds a mix of normal and inverted codes). */
    FQR_POLARITY_BOTH = 1,
    /** Dark modules on a light background only. */
    FQR_POLARITY_NORMAL = 2,
    /** Light modules on a dark background only. */
    FQR_POLARITY_INVERTED = 3,
} fqr_polarity_t;

/**
 * Input bitmap: 1 bit per pixel, rows top to bottom, most significant bit
 * first within each byte, bit value 1 = dark. Bits beyond @c width in each
 * row are ignored. The buffer must hold at least
 * <tt>(height - 1) * stride + (width + 7) / 8</tt> bytes.
 */
typedef struct {
    const uint8_t *data; /**< Pixel bits. */
    uint32_t width;      /**< 1 .. FQR_MAX_IMAGE_DIM. */
    uint32_t height;     /**< 1 .. FQR_MAX_IMAGE_DIM. */
    size_t stride;       /**< Bytes per row, >= (width + 7) / 8. */
} fqr_image_t;

/** A point in image coordinates (pixel (x, y) covers [x, x+1) x [y, y+1)). */
typedef struct {
    float x;
    float y;
} fqr_point_t;

/** One Extended Channel Interpretation segment header. */
typedef struct {
    uint32_t designator; /**< ECI assignment number, 0 .. 999999. */
    size_t offset;       /**< Payload offset from which it applies. */
} fqr_eci_t;

/** Structured Append header (ISO/IEC 18004 §8). */
typedef struct {
    bool present;   /**< A header was found. */
    uint8_t index;  /**< Position of this symbol, 0 .. 15. */
    uint8_t total;  /**< Number of symbols in the sequence, 1 .. 16. */
    uint8_t parity; /**< XOR of all data bytes of the whole message. */
} fqr_structured_append_t;

/**
 * Decoding result for one QR code.
 *
 * The caller fills in @c payload and @c payload_cap before the call; all
 * other fields are outputs. Bytes are copied raw: byte segments verbatim,
 * numeric and alphanumeric as ASCII, kanji as Shift JIS byte pairs. No NUL
 * terminator is appended. ECI headers are reported, never applied.
 */
typedef struct {
    /* --- inputs --- */
    uint8_t *payload;   /**< Caller buffer receiving the payload (may be NULL if cap is 0). */
    size_t payload_cap; /**< Capacity of @c payload in bytes. */

    /* --- outputs --- */
    fqr_status_t status; /**< FQR_OK, or FQR_ERR_BUFFER_TOO_SMALL for this code. */
    size_t payload_len;  /**< Bytes written; if too small: bytes required. */
    uint8_t version;     /**< 1 .. 40. */
    uint8_t ecc_level;   /**< fqr_ecc_level_t. */
    uint8_t mask;        /**< Data mask pattern 0 .. 7. */
    bool inverted;       /**< Found in the inverted (light-on-dark) pass. */
    bool mirrored;       /**< Symbol was mirrored (transposed). */
    uint16_t modes;      /**< FQR_MODE_* bitmask. */
    uint8_t eci_count;   /**< ECI headers seen (only FQR_MAX_ECI stored). */
    fqr_eci_t eci[FQR_MAX_ECI];
    fqr_structured_append_t structured_append;
    uint8_t fnc1_app_indicator; /**< Application indicator if FQR_MODE_FNC1_SECOND. */
    uint16_t corrected;         /**< Codewords corrected by Reed-Solomon. */
    uint16_t ecc_capacity;      /**< Correctable codewords per block (worst block). */
    /** Outer symbol corners in the image: top-left, top-right, bottom-right,
     *  bottom-left (in symbol orientation). All zero for fqr_decode_matrix(). */
    fqr_point_t corners[4];
} fqr_result_t;

/** Optional counters (instrumentation, tests, performance estimates). */
typedef struct {
    uint32_t pixels_scanned;     /**< Pixels visited by the row scanner. */
    uint32_t crosscheck_pixels;  /**< Pixels visited by finder cross-checks. */
    uint32_t finder_hits;        /**< Confirmed finder centre observations. */
    uint32_t finder_candidates;  /**< Distinct finder candidates (all passes). */
    uint32_t triples_considered; /**< Geometrically plausible finder triples. */
    uint32_t decode_attempts;    /**< Grid sampling + decoding attempts. */
    uint32_t modules_sampled;    /**< Modules sampled through a transform. */
    uint32_t fail_format;        /**< Attempts failing at format/version info. */
    uint32_t fail_ecc;           /**< Attempts failing Reed-Solomon. */
    uint32_t fail_data;          /**< Attempts failing bit-stream parsing. */
    uint32_t rs_blocks;          /**< Reed-Solomon blocks processed. */
    bool budget_exhausted;       /**< Work budget hit before the search ended. */
} fqr_stats_t;

/** Options. A NULL options pointer means: all fields zero (defaults). */
typedef struct {
    fqr_polarity_t polarity; /**< Default FQR_POLARITY_AUTO. */
    /** Stop after this many distinct codes (1 .. FQR_MAX_CODES; 0 = default 4). */
    uint8_t max_codes;
    /** Do not retry with a transposed grid (mirrored symbols). */
    bool no_mirror;
    /**
     * Work budget in units of ~1 sampled module (0 = default, about
     * 4 million: roughly 0.5 s on a 168 MHz Cortex-M4F). When exhausted
     * the search stops and returns what was found so far.
     */
    uint32_t max_work;
    fqr_stats_t *stats; /**< Optional; zeroed and filled if non-NULL. */
} fqr_options_t;

/** @return FQR_WORKSPACE_SIZE. */
size_t fqr_workspace_size(void);

/** @return a static English description of @p status (never NULL). */
const char *fqr_status_str(fqr_status_t status);

/**
 * Locate and decode QR codes in a 1-bpp image.
 *
 * Distinct codes are counted (codes are distinct when their locations do
 * not overlap). The search stops after fqr_options_t::max_codes codes.
 *
 * @param img         Input bitmap (not modified).
 * @param workspace   At least FQR_WORKSPACE_SIZE bytes, any alignment.
 * @param ws_size     Size of @p workspace.
 * @param opts        Options or NULL for defaults.
 * @param results     Array of @p max_results results (may be NULL if 0);
 *                    each element's payload/payload_cap must be set.
 * @param max_results Number of entries in @p results. Codes beyond it are
 *                    still decoded and counted, but not reported.
 * @param n_found     Out: number of distinct valid codes (always written,
 *                    0 on error).
 * @return FQR_OK if n_found >= 1 and every reported payload fit;
 *         FQR_ERR_BUFFER_TOO_SMALL if n_found >= 1 but a reported payload did
 *         not fit (see each result's status);
 *         otherwise (n_found == 0) the most advanced failure reached:
 *         FQR_ERR_NOT_FOUND < FQR_ERR_FORMAT < FQR_ERR_ECC < FQR_ERR_DATA;
 *         or FQR_ERR_INVALID_ARG / FQR_ERR_WORKSPACE.
 */
fqr_status_t fqr_decode(const fqr_image_t *img, void *workspace, size_t ws_size,
                        const fqr_options_t *opts, fqr_result_t *results,
                        size_t max_results, size_t *n_found);

/**
 * Convenience wrapper for "exactly one code" policies: searches for up to
 * two codes and fails with FQR_ERR_MULTIPLE_CODES if two distinct codes are
 * found. fqr_options_t::max_codes is ignored.
 */
fqr_status_t fqr_decode_single(const fqr_image_t *img, void *workspace, size_t ws_size,
                               const fqr_options_t *opts, fqr_result_t *result);

/**
 * Decode an already sampled module matrix (no detection). Useful for tests
 * and for callers that sample grids themselves.
 *
 * @param modules  Module bits, row-major, MSB first, 1 = dark;
 *                 row r starts at byte r * stride.
 * @param size     Side in modules: 21 .. 177 and size % 4 == 1.
 * @param stride   Bytes per row, >= (size + 7) / 8.
 * @param try_mirror Also try the transposed matrix if the first read fails.
 * @return FQR_OK, FQR_ERR_FORMAT, FQR_ERR_ECC, FQR_ERR_DATA,
 *         FQR_ERR_BUFFER_TOO_SMALL, FQR_ERR_INVALID_ARG or FQR_ERR_WORKSPACE.
 */
fqr_status_t fqr_decode_matrix(const uint8_t *modules, uint32_t size, size_t stride,
                               bool try_mirror, void *workspace, size_t ws_size,
                               fqr_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* FQR_H */
