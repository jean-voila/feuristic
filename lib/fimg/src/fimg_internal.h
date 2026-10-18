// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/**
 * @file fimg_internal.h
 * @brief Internal structures of lib/fimg. Not part of the public API; unit
 *        tests include it to exercise the inflater and the pixel pipeline.
 */
#ifndef FIMG_INTERNAL_H
#define FIMG_INTERNAL_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "fimg.h"

/** Compile-time assertion usable at file scope (C99). */
#define FIMG_STATIC_ASSERT(name, cond) \
  typedef char fimg_static_assert_##name[(cond) ? 1 : -1]

/* The IDCT and a few descaling steps rely on arithmetic right shift of
 * negative signed integers (implementation-defined in C99, arithmetic on
 * every supported compiler: GCC, Clang, armcc). Refuse to build otherwise. */
FIMG_STATIC_ASSERT(arithmetic_shift, ((-8) >> 1) == -4);

/* ======================================================================== */
/* zlib / deflate inflater (fimg_inflate.c)                                  */
/* ======================================================================== */

#define FIMG_INF_WSIZE 32768u /**< LZ77 window (also the output ring). */
#define FIMG_INF_WMASK (FIMG_INF_WSIZE - 1u)
#define FIMG_INF_FAST_BITS 9u /**< First-level Huffman lookup bits. */
#define FIMG_INF_MAXBITS 15u

/** Canonical Huffman decoding table (puff-style + fast lookup). */
typedef struct {
  uint16_t count[FIMG_INF_MAXBITS + 1u]; /**< Codes per length. */
  uint16_t symbol[288];                  /**< Symbols in canonical order. */
  uint16_t
      fast[1u << FIMG_INF_FAST_BITS]; /**< (len << 9) | sym, 0 = slow path. */
} fimg_huff_t;

/** Inflater results (negative values are errors). */
typedef enum {
  FIMG_INF_NEED_INPUT = 0,  /**< All input consumed, stream not finished. */
  FIMG_INF_OUT_FULL = 1,    /**< out_max bytes produced; call again. */
  FIMG_INF_DONE = 2,        /**< Stream finished, Adler-32 verified. */
  FIMG_INF_ERR_HEADER = -1, /**< Bad zlib header (method, window, check). */
  FIMG_INF_ERR_DICT = -2,   /**< Preset dictionary requested. */
  FIMG_INF_ERR_BLOCK = -3,  /**< Invalid block type (3). */
  FIMG_INF_ERR_STORED = -4, /**< Stored block LEN/NLEN mismatch. */
  FIMG_INF_ERR_TREE = -5,   /**< Invalid dynamic Huffman description. */
  FIMG_INF_ERR_CODE = -6,   /**< Invalid literal/length or distance code. */
  FIMG_INF_ERR_DIST = -7,   /**< Distance beyond the start of the output. */
  FIMG_INF_ERR_ADLER = -8   /**< Adler-32 mismatch. */
} fimg_inf_result_t;

/** Resumable zlib stream inflater state. */
typedef struct {
  uint8_t *win;    /**< FIMG_INF_WSIZE bytes; output is written here. */
  uint32_t wpos;   /**< Next write position in @ref win. */
  uint32_t total;  /**< Total bytes produced. */
  uint32_t bitbuf; /**< LSB-first bit accumulator. */
  uint32_t bitcnt; /**< Valid bits in @ref bitbuf (<= 31). */
  uint32_t state;  /**< Internal state machine position. */
  uint32_t last;   /**< BFINAL of the current block. */
  uint32_t len;    /**< Stored bytes left / pending match length. */
  uint32_t dist;   /**< Pending match distance. */
  uint32_t sym;    /**< Pending length/distance symbol. */
  uint32_t nlen, ndist, ncode, idx; /**< Dynamic header parsing. */
  uint32_t adler_a, adler_b;        /**< Running Adler-32. */
  uint32_t hdr;                     /**< Header / trailer byte accumulator. */
  uint32_t hdr_n;                   /**< Bytes accumulated in @ref hdr. */
  uint32_t tables;      /**< 0 none, 1 fixed tables loaded, 2 dynamic. */
  int32_t err;          /**< Sticky error code (state S_ERROR). */
  uint8_t lens[320];    /**< Code lengths (litlen + dist). */
  fimg_huff_t lencode;  /**< Literal/length (or code-length) table. */
  fimg_huff_t distcode; /**< Distance table. */
} fimg_inflate_t;

/** Initialise @p s with a caller-owned FIMG_INF_WSIZE-byte window. */
void fimg_inflate_init(fimg_inflate_t *s, uint8_t *window);

/**
 * Inflate from @p in. Produces at most @p out_max (<= FIMG_INF_WSIZE) bytes,
 * written into the window starting at the value of s->wpos on entry
 * (wrapping). The caller must consume them before the next call.
 * @param[out] in_used  input bytes consumed
 * @param[out] produced output bytes produced
 */
fimg_inf_result_t fimg_inflate(fimg_inflate_t *s, const uint8_t *in,
                               size_t in_len, size_t *in_used, uint32_t out_max,
                               uint32_t *produced);

/** CRC-32 (ISO-HDLC / PNG) update; start with crc = 0. */
uint32_t fimg_crc32(uint32_t crc, const uint8_t *p, size_t n);

/** Adler-32 update on (a, b); start with a = 1, b = 0. */
void fimg_adler32(uint32_t *a, uint32_t *b, const uint8_t *p, size_t n);

/* ======================================================================== */
/* Pixel pipeline: box downscaler + adaptive binarizer (fimg_pix.c)          */
/* ======================================================================== */

#define FIMG_BIN_RMIN 4u /**< Minimum binarizer window radius. */
#define FIMG_BIN_RDIV \
  32u /**< radius = max(out_w, out_h) / RDIV (window ~ 1/16). */
#define FIMG_BIN_RMAX 63u /**< Maximum radius (keeps sums in 32 bits). */

typedef struct {
  uint32_t src_w, src_h; /**< Source dimensions. */
  uint32_t f;            /**< Box factor. */
  uint32_t out_w, out_h; /**< Output dimensions. */
  uint32_t stride;       /**< Bitmap stride. */
  uint32_t src_rows;     /**< Source rows received. */
  uint32_t band_rows;    /**< Source rows accumulated in the current band. */
  uint32_t *acc;         /**< out_w column accumulators (f > 1). */
  uint8_t *ring;         /**< K rows of out_w luma. */
  uint16_t *colsum;      /**< Column sums over rows [lo, rows_in). */
  uint16_t *colsq;       /**< Column sums of round(v^2 / 256). */
  uint32_t r, k;         /**< Window radius and ring height (2r+1). */
  uint32_t rows_in;      /**< Output rows pushed into the ring. */
  uint32_t lo;           /**< First row included in colsum. */
  uint32_t rows_out;     /**< Output rows binarized. */
  uint32_t hist[256];    /**< Histogram of output luma seen so far. */
  uint32_t gthresh;      /**< Global threshold (intermeans). */
  uint32_t gcontrast;    /**< Global contrast (mean_hi - mean_lo). */
  uint32_t gmlo;         /**< Global mean of the dark class. */
  uint8_t *bitmap;
  int ready; /**< Set up (dimensions known). */
} fimg_pix_t;

/* ======================================================================== */
/* PNG decoder (fimg_png.c)                                                  */
/* ======================================================================== */

#define FIMG_PNG_MAX_ROWBYTES (FIMG_MAX_DIM * 8u)

typedef struct {
  uint32_t state; /**< Chunk parser state. */
  uint8_t hdr[8]; /**< Signature / chunk header accumulator. */
  uint32_t hdr_n;
  uint32_t chunk_len, chunk_left, chunk_type;
  uint32_t crc;       /**< Running CRC of type + data. */
  uint8_t small[768]; /**< IHDR / PLTE / tRNS payload buffer. */
  uint32_t small_n;
  /* chunk sequence */
  uint8_t seen_ihdr, seen_plte, seen_trns, in_idat, idat_done, seen_idat;
  uint8_t zdone;
  uint8_t skip_trns; /**< Current tRNS chunk is invalid and ignored. */
  /* IHDR */
  uint32_t w, h, depth, ctype, channels, bpp, rowbytes;
  uint32_t pal_n;
  uint8_t pal_luma[256]; /**< Palette luma, alpha composited on white. */
  uint8_t has_key;       /**< tRNS colour key for types 0 / 2. */
  uint16_t key[3];
  /* scanlines */
  uint8_t *win, *cur, *prev, *luma;
  uint32_t row_fill; /**< Bytes in @ref cur (filter byte included). */
  uint32_t rows_done;
  uint32_t expected;  /**< h * (rowbytes + 1). */
  uint32_t inf_bytes; /**< Inflated bytes so far. */
  fimg_inflate_t inf;
} fimg_png_t;

/* ======================================================================== */
/* JPEG decoder (fimg_jpeg.c)                                                */
/* ======================================================================== */

#define FIMG_JPEG_STG_SIZE 4096u /**< Input staging buffer. */
#define FIMG_JPEG_MCU_WORST \
  2560u /**< Worst-case bytes of one MCU (6 blocks). */
#define FIMG_JPEG_LOOKAHEAD 8u
#define FIMG_JPEG_MAX_BLOCKS 6u

typedef struct {
  uint16_t look[1u << FIMG_JPEG_LOOKAHEAD]; /**< (len << 8) | sym, 0 = slow. */
  int32_t
      maxcode[18]; /**< Largest code of length l (-1 if none); [17] sentinel. */
  int32_t valoff[17]; /**< vals index = code + valoff[l]. */
  uint8_t vals[256];
  uint8_t defined;
} fimg_jhuff_t;

typedef struct {
  uint8_t id, h, v, tq, td, ta, scanned;
  int32_t pred;
} fimg_jcomp_t;

typedef struct {
  uint32_t state;     /**< Marker parser state. */
  uint32_t marker;    /**< Current marker code. */
  uint32_t seg_left;  /**< Bytes left in the current segment. */
  uint32_t seg_total; /**< Payload length of the current segment. */
  uint8_t soi_seen;
  uint8_t seg[24]; /**< SOF / SOS / DRI / APP14 payload buffer. */
  uint32_t seg_n;
  /* DHT incremental parser */
  uint32_t dht_sub, dht_tc, dht_th, dht_total, dht_got;
  uint8_t dht_counts[17];
  fimg_jhuff_t *dht_tab; /**< NULL when discarding (Th > 1). */
  /* DQT incremental parser */
  uint32_t dqt_sub, dqt_pq, dqt_tq, dqt_got;
  uint16_t qt[4][64]; /**< Quantisation tables, zig-zag order. */
  uint8_t qt_defined[4];
  fimg_jhuff_t dc[2], ac[2];
  /* frame */
  fimg_jcomp_t comp[3];
  uint32_t ncomp, w, h, hmax, vmax;
  uint8_t have_sof, adobe_seen, adobe_transform, jfif_seen, color_checked,
      y_done;
  uint32_t restart_interval;
  /* scan */
  uint32_t scan_decode; /**< 1: this scan contains Y and is decoded. */
  uint32_t nblocks;     /**< Blocks per MCU. */
  uint8_t blk_comp[FIMG_JPEG_MAX_BLOCKS];
  uint8_t blk_x[FIMG_JPEG_MAX_BLOCKS], blk_y[FIMG_JPEG_MAX_BLOCKS];
  uint32_t mcus_x, mcus_y, mcu_x, mcu_y, band_h;
  uint32_t rst_left, rst_next;
  /* bit reader */
  uint32_t bitbuf; /**< MSB-aligned bit accumulator. */
  int32_t bitcnt;  /**< Valid bits (real + fake). */
  int32_t fake;    /**< Zero bits inserted after a marker. */
  uint8_t marker_hit, starved;
  /* staging */
  uint8_t *stg;
  uint32_t stg_len, stg_pos;
  uint32_t mscan;   /**< Scanned for markers up to here. */
  uint32_t mfound;  /**< 1 if a marker lies in [stg_pos, mscan). */
  uint32_t done_at; /**< stg index just after EOI. */
  /* output */
  uint8_t *rowbuf; /**< band_h x rowbuf_w luma. */
  uint32_t rowbuf_w;
  int32_t coef[64];
  int32_t ws[64];
  /** Diagnostic: number of clamps that engaged (coefficient / IDCT
   *  overflow guards, out-of-range samples). Always 0 for valid 8-bit
   *  streams; when non-zero libjpeg's output may differ (it wraps). */
  uint32_t sat;
} fimg_jpeg_t;

/* ======================================================================== */
/* Context                                                                   */
/* ======================================================================== */

enum {
  FIMG_PH_SNIFF = 0,
  FIMG_PH_PNG,
  FIMG_PH_JPEG,
  FIMG_PH_DONE,
  FIMG_PH_FINISHED
};

struct fimg_ctx {
  uint32_t magic;
  fimg_config_t cfg;
  uint32_t max_pixels, max_file;
  fimg_status_t status;
  uint32_t phase;
  fimg_format_t format;
  uint8_t sniff[8];
  uint32_t sniff_n;
  uint32_t bytes_in; /**< Image bytes consumed. */
  uint8_t *bitmap;
  size_t bitmap_size;
  uint8_t *heap; /**< Bump allocator over the rest of the workspace. */
  size_t heap_size, heap_used;
  fimg_pix_t pix;
  union {
    fimg_png_t png;
    fimg_jpeg_t jpeg;
  } u;
};

#define FIMG_ALIGN8(x) (((x) + 7u) & ~(size_t)7u)

/** Bump-allocate @p n bytes (8-aligned) from the workspace; NULL if exhausted.
 */
void *fimg_alloc(fimg_ctx_t *ctx, size_t n);

/** Heap bytes needed by the pixel pipeline for @p cfg (validated). */
size_t fimg_pix_heap_size(const fimg_config_t *cfg);
/** Set up the pipeline for a w x h source (allocates from the heap). */
fimg_status_t fimg_pix_setup(fimg_ctx_t *ctx, uint32_t w, uint32_t h);
/** Push the next full-resolution luma row (src_w bytes). */
fimg_status_t fimg_pix_push(fimg_ctx_t *ctx, const uint8_t *row);
/** true once every output row has been written to the bitmap. */
int fimg_pix_complete(const fimg_ctx_t *ctx);

size_t fimg_png_heap_size(void);
void fimg_png_begin(fimg_ctx_t *ctx);
fimg_status_t fimg_png_feed(fimg_ctx_t *ctx, const uint8_t *p, size_t n,
                            size_t *used);

size_t fimg_jpeg_heap_size(void);
fimg_status_t fimg_jpeg_begin(fimg_ctx_t *ctx);
fimg_status_t fimg_jpeg_feed(fimg_ctx_t *ctx, const uint8_t *p, size_t n,
                             size_t *used);

/** Exact rounded x / 255 for 0 <= x <= 65535. */
static inline uint32_t fimg_div255(uint32_t x) {
  return (x + 128u + ((x + 128u) >> 8)) >> 8;
}

/** ITU-R BT.601 luma, same fixed point as Pillow's RGB -> L conversion. */
static inline uint32_t fimg_rgb_luma(uint32_t r, uint32_t g, uint32_t b) {
  return (r * 19595u + g * 38470u + b * 7471u + 0x8000u) >> 16;
}

/** Composite luma @p y with alpha @p a (0..255) over a white background. */
static inline uint32_t fimg_over_white(uint32_t y, uint32_t a) {
  return fimg_div255(y * a + 255u * (255u - a));
}

#endif /* FIMG_INTERNAL_H */
