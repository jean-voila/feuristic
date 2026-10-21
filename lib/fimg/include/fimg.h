// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/**
 * @file fimg.h
 * @brief Streaming PNG / baseline-JPEG decoder producing a binarized 1-bpp
 *        bitmap for the QR decoder (lib/fqr).
 *
 * fimg turns an image byte stream that arrives in arbitrary chunks (USB
 * mass-storage writes) into a bounded 1-bit-per-pixel bitmap, without ever
 * holding the file or a full-frame colour buffer in memory:
 *
 *     bytes -> sniff (PNG signature / JPEG SOI)
 *           -> PNG: chunks + CRC-32 -> inflate (zlib) -> unfilter -> luma
 *              JPEG: markers -> Huffman -> dequant -> integer IDCT -> luma (Y)
 *           -> integer box downscaler (factor from the header dimensions)
 *           -> single-pass adaptive binarizer (sliding local mean + global
 *              fallback for flat regions)
 *           -> 1-bpp bitmap (row-major, MSB first, bit = 1 is dark)
 *
 * Usage:
 * @code
 *   fimg_config_t cfg;
 *   fimg_config_default(&cfg);                // 720 x 720 output max
 *   size_t ws_size = fimg_workspace_size(&cfg);
 *   size_t bm_size = fimg_bitmap_size(&cfg);
 *   // ... obtain ws (ws_size bytes) and bm (bm_size bytes) from the caller ...
 *   fimg_ctx_t *ctx;
 *   fimg_status_t st = fimg_init(&ctx, ws, ws_size, &cfg, bm, bm_size);
 *   while (st == FIMG_OK && more_data)
 *       st = fimg_feed(ctx, chunk, chunk_len);      // any chunk size
 *   fimg_info_t info;
 *   st = fimg_finish(ctx, &info);                    // always call it
 *   if (st == FIMG_OK)
 *       // bitmap: info.out_width x info.out_height, info.stride bytes/row
 *   fimg_secure_zero(ws, ws_size);                   // image may hold secrets
 *   fimg_secure_zero(bm, bm_size);
 * @endcode
 *
 * The library is freestanding C99: no allocation, no recursion, no VLA, no
 * global mutable state (several contexts may coexist). All memory comes from
 * the caller-provided workspace and bitmap.
 */
#ifndef FIMG_H
#define FIMG_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Library interface version (incremented on incompatible API changes). */
#define FIMG_API_VERSION 1

/** Largest accepted source image width or height, in pixels. */
#define FIMG_MAX_DIM 1024u

/** Default (and recommended) limit on the image file size, in bytes. */
#define FIMG_DEFAULT_MAX_FILE_BYTES (256u * 1024u)

/** Default maximum output width / height (bitmap of at most 64 KiB). */
#define FIMG_DEFAULT_MAX_OUT_DIM 720u

/** Smallest accepted value for fimg_config_t::max_out_width / height. */
#define FIMG_MIN_OUT_DIM 8u

/**
 * @name Configuration flags (fimg_config_t::flags)
 * @{
 */
/** Treat any byte after the PNG IEND chunk / JPEG EOI marker as an error
 *  (FIMG_E_TRAILING_DATA). Default: such bytes are discarded unread, because
 *  mass-storage hosts commonly write whole clusters past the end of file. */
#define FIMG_FLAG_STRICT_TRAILER 0x01u
/** Refuse PNG input (FIMG_E_NOT_IMAGE); shrinks the workspace. */
#define FIMG_FLAG_NO_PNG 0x02u
/** Refuse JPEG input (FIMG_E_NOT_IMAGE); shrinks the workspace. */
#define FIMG_FLAG_NO_JPEG 0x04u
/** @} */

/**
 * Status codes. Every code maps to one user-facing category, see
 * fimg_status_category() and docs/developer/lib-fimg.md for wording.
 * Errors are sticky: once a call returned an error, every later call on the
 * same context returns the same error.
 */
typedef enum {
  FIMG_OK = 0, /**< Success / more input accepted. */
  /* -- API usage ------------------------------------------------------ */
  FIMG_E_PARAM = 1,     /**< NULL pointer or invalid configuration. */
  FIMG_E_WORKSPACE = 2, /**< Workspace or bitmap buffer too small. */
  FIMG_E_STATE = 3,     /**< Call after fimg_finish(). */
  /* -- generic input errors ------------------------------------------- */
  FIMG_E_NOT_IMAGE = 4, /**< Neither a PNG nor a JPEG (or format disabled). */
  FIMG_E_FILE_TOO_LARGE =
      5, /**< More than max_file_bytes before the end of the image. */
  FIMG_E_DIMENSIONS = 6, /**< Width or height is 0 or above FIMG_MAX_DIM. */
  FIMG_E_TRUNCATED = 7,  /**< Stream ended before the end of the image. */
  FIMG_E_TRAILING_DATA =
      8, /**< Bytes after the end (FIMG_FLAG_STRICT_TRAILER only). */
  /* -- PNG ------------------------------------------------------------ */
  FIMG_E_PNG_INTERLACED = 9,   /**< Adam7 interlaced PNG (unsupported). */
  FIMG_E_PNG_UNSUPPORTED = 10, /**< Invalid colour type / bit depth / method,
                                  unknown critical chunk. */
  FIMG_E_PNG_CRC = 11,         /**< A chunk CRC-32 does not match. */
  FIMG_E_PNG_CORRUPT =
      12, /**< Chunk structure, order or length invalid, bad filter type. */
  FIMG_E_PNG_ZLIB =
      13, /**< Invalid zlib/deflate stream or Adler-32 mismatch. */
  FIMG_E_PNG_DATA_SIZE = 14, /**< Decompressed size differs from IHDR
                                (decompression bomb / short data). */
  /* -- JPEG ----------------------------------------------------------- */
  FIMG_E_JPEG_PROGRESSIVE = 15, /**< Progressive JPEG (SOF2). */
  FIMG_E_JPEG_EXTENDED =
      16, /**< Extended sequential (SOF1) or sample precision other than 8. */
  FIMG_E_JPEG_LOSSLESS = 17,   /**< Lossless JPEG (SOF3/7/11/15, JPEG-LS). */
  FIMG_E_JPEG_ARITHMETIC = 18, /**< Arithmetic coding (SOF9..15, DAC). */
  FIMG_E_JPEG_HIERARCHICAL =
      19, /**< Hierarchical / differential JPEG (SOF5..7, DHP, EXP). */
  FIMG_E_JPEG_COLOR =
      20, /**< Unsupported colour model (CMYK, RGB, not 1 or 3 components). */
  FIMG_E_JPEG_SAMPLING = 21,   /**< Unsupported chroma subsampling factors. */
  FIMG_E_JPEG_MULTIFRAME = 22, /**< More than one frame (second SOF). */
  FIMG_E_JPEG_CORRUPT = 23, /**< Marker / segment / table structure invalid. */
  FIMG_E_JPEG_HUFFMAN = 24, /**< Invalid entropy-coded data. */
  /* -- internal ------------------------------------------------------- */
  FIMG_E_LIMIT = 25, /**< An internal limit was exceeded (see documentation). */
  FIMG_E_INTERNAL = 26, /**< Internal consistency check failed (bug). */
  FIMG_STATUS_COUNT = 27
} fimg_status_t;

/** User-facing categories (one message per category). */
typedef enum {
  FIMG_CAT_OK = 0,
  FIMG_CAT_NOT_IMAGE,       /**< "Not a PNG or JPEG image." */
  FIMG_CAT_FILE_TOO_LARGE,  /**< "File larger than 256 KiB." */
  FIMG_CAT_DIMENSIONS,      /**< "Image larger than 1024 x 1024." */
  FIMG_CAT_PNG_UNSUPPORTED, /**< "Unsupported PNG variant (e.g. interlaced)." */
  FIMG_CAT_JPEG_UNSUPPORTED, /**< "Unsupported JPEG variant (e.g. progressive)."
                              */
  FIMG_CAT_CORRUPT,          /**< "Damaged image file." */
  FIMG_CAT_TRUNCATED,        /**< "Incomplete image file." */
  FIMG_CAT_INTERNAL /**< "Internal error." (API misuse, limits, bugs) */
} fimg_category_t;

/** Detected input format. */
typedef enum {
  FIMG_FORMAT_UNKNOWN = 0,
  FIMG_FORMAT_PNG = 1,
  FIMG_FORMAT_JPEG = 2
} fimg_format_t;

/**
 * Optional callback receiving every decoded full-resolution luma row (before
 * downscaling). Intended for tests and diagnostics; pass NULL in production.
 * @param user  fimg_config_t::luma_cb_user
 * @param y     row index (0 .. src_height-1), strictly increasing
 * @param luma  @p width bytes, 0 = black .. 255 = white
 * @param width source width
 */
typedef void (*fimg_luma_cb_t)(void *user, uint32_t y, const uint8_t *luma,
                               uint32_t width);

/** Decoder configuration. Initialise with fimg_config_default(). */
typedef struct {
  /** Maximum output bitmap width, FIMG_MIN_OUT_DIM .. FIMG_MAX_DIM. */
  uint16_t max_out_width;
  /** Maximum output bitmap height, FIMG_MIN_OUT_DIM .. FIMG_MAX_DIM. */
  uint16_t max_out_height;
  /** Maximum output pixel count (0 = max_out_width * max_out_height). */
  uint32_t max_out_pixels;
  /** Maximum image file size in bytes (0 = FIMG_DEFAULT_MAX_FILE_BYTES). */
  uint32_t max_file_bytes;
  /** FIMG_FLAG_* bit set. */
  uint32_t flags;
  /** Optional full-resolution luma row callback (NULL in production). */
  fimg_luma_cb_t luma_cb;
  /** Opaque pointer handed to @ref luma_cb. */
  void *luma_cb_user;
} fimg_config_t;

/** Information about the image and the produced bitmap. */
typedef struct {
  fimg_format_t format; /**< Detected format (UNKNOWN before sniffing). */
  uint32_t src_width;   /**< Source width (0 until the header is parsed). */
  uint32_t src_height;  /**< Source height (0 until the header is parsed). */
  uint32_t scale; /**< Integer box-downscale factor (>= 1, 0 until known). */
  uint32_t out_width;  /**< Bitmap width = ceil(src_width / scale). */
  uint32_t out_height; /**< Bitmap height = ceil(src_height / scale). */
  size_t stride;       /**< Bitmap bytes per row = ceil(out_width / 8). */
  uint32_t window;     /**< Binarizer window side, in output pixels. */
  uint32_t
      bytes_consumed; /**< Image bytes consumed (trailing bytes excluded). */
  bool complete;      /**< true once the whole image was decoded. */
} fimg_info_t;

/** Opaque decoder context (lives inside the caller's workspace). */
typedef struct fimg_ctx fimg_ctx_t;

/**
 * Fill @p cfg with defaults: 720 x 720 output (bitmap 64800 B <= 64 KiB), 256
 * KiB file limit, no flags, no callback.
 */
void fimg_config_default(fimg_config_t *cfg);

/**
 * Workspace size in bytes required by fimg_init() for @p cfg (worst case over
 * every accepted image). Returns 0 if @p cfg is invalid. With the default
 * configuration PNG dominates. Sizes depend on the pointer ABI; query this
 * function rather than hardcoding a platform-specific byte count.
 */
size_t fimg_workspace_size(const fimg_config_t *cfg);

/**
 * Size in bytes of the output bitmap buffer needed for @p cfg in the worst
 * case: max_out_height * ceil(max_out_width / 8). Returns 0 if invalid.
 */
size_t fimg_bitmap_size(const fimg_config_t *cfg);

/**
 * Initialise a decoder.
 * @param[out] out        receives the context pointer (inside @p workspace)
 * @param workspace       caller memory, any alignment, >=
 * fimg_workspace_size(cfg) bytes
 * @param workspace_size  size of @p workspace
 * @param cfg             configuration (copied)
 * @param bitmap          output bitmap buffer
 * @param bitmap_size     >= fimg_bitmap_size(cfg)
 * @return FIMG_OK, FIMG_E_PARAM or FIMG_E_WORKSPACE.
 */
fimg_status_t fimg_init(fimg_ctx_t **out, void *workspace,
                        size_t workspace_size, const fimg_config_t *cfg,
                        uint8_t *bitmap, size_t bitmap_size);

/** Largest individual scratch block in the scattered allocator. */
#define FIMG_SCATTERED_BLOCK_MAX 16384u
/** Maximum descriptors needed for any valid configuration. */
#define FIMG_SCATTERED_MAX_BLOCKS 104u

/** Caller-owned, 8-byte-aligned, mutually disjoint scratch buffer. */
typedef struct {
  void *ptr;
  size_t size;
} fimg_block_t;

/**
 * Query the complete worst-case scratch plan. Element zero contains the
 * context; remaining buffers are individually <= FIMG_SCATTERED_BLOCK_MAX.
 * Returns 0 for an invalid configuration, otherwise the descriptor count.
 * Writes all sizes only when sizes != NULL and capacity >= the returned
 * count; an insufficient output array is left untouched. No allocation.
 */
size_t fimg_scattered_sizes(const fimg_config_t *cfg, size_t *sizes,
                            size_t capacity);

/**
 * Initialise without a large contiguous scratch allocation. The caller
 * preallocates the buffers reported by fimg_scattered_sizes(), preserving
 * the descriptors and every buffer until the decoder is no longer used.
 * Bitmap remains contiguous and disjoint from every block. Blocks must not
 * overlap one another or the descriptor array. Initialization checks all
 * required capacities before returning FIMG_OK. No hidden allocation/free.
 * Reinitializing reuses the same buffers; the caller owns wiping/freeing.
 * Returns FIMG_E_PARAM for invalid/overlapping/unaligned memory and
 * FIMG_E_WORKSPACE for insufficient buffers. Existing contiguous API remains
 * available with identical image/limit semantics.
 */
fimg_status_t fimg_init_scattered(fimg_ctx_t **out, fimg_block_t *blocks,
                                  size_t count, const fimg_config_t *cfg,
                                  uint8_t *bitmap, size_t bitmap_size);

/**
 * Feed the next @p len bytes of the file (any length, including 0).
 * @return FIMG_OK while the stream is acceptable so far, otherwise a sticky
 *         error. A FIMG_OK result does not mean the image is complete.
 */
fimg_status_t fimg_feed(fimg_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * Signal the end of the file. Returns FIMG_OK if a complete image was
 * decoded and the bitmap is fully written, FIMG_E_TRUNCATED if the stream
 * stopped early, or the sticky error. @p info (may be NULL) is filled in all
 * cases with whatever is known. Further fimg_feed() calls return FIMG_E_STATE.
 */
fimg_status_t fimg_finish(fimg_ctx_t *ctx, fimg_info_t *info);

/** Current information (valid at any time; dimensions once the header is
 * parsed). */
fimg_status_t fimg_get_info(const fimg_ctx_t *ctx, fimg_info_t *info);

/** Map a status code to its user-facing category. */
fimg_category_t fimg_status_category(fimg_status_t st);

/** Short stable English identifier of a status ("png-crc", ...), for logs. */
const char *fimg_status_name(fimg_status_t st);

/**
 * Zero @p len bytes at @p p in a way the compiler cannot elide. Call it on the
 * workspace and the bitmap after use: they hold an image of a secret.
 */
void fimg_secure_zero(void *p, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* FIMG_H */
