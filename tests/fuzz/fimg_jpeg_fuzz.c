// SPDX-License-Identifier: GPL-3.0-only
// Copyright (C) 2026 The feuristic contributors
/*
 * libFuzzer target: lib/fimg on JPEG-shaped input.
 *
 * With -DFIMG_FUZZ_LIBJPEG (link libjpeg-turbo), every input that fimg
 * decodes successfully is also decoded by libjpeg-turbo to grayscale (islow
 * IDCT); when libjpeg reports neither an error nor a warning, the two luma
 * planes must be identical (fimg's IDCT is bit-exact with libjpeg's).
 */
#include "fimg_fuzz_common.h"
#include "fimg_internal.h"

#ifdef FIMG_FUZZ_LIBJPEG
#include <jpeglib.h>
#include <setjmp.h>
#include <stdio.h>

typedef struct {
  struct jpeg_error_mgr pub;
  jmp_buf jb;
  int warnings;
} fz_jerr_t;

static void fz_jerror_exit(j_common_ptr c) {
  longjmp(((fz_jerr_t *)c->err)->jb, 1);
}

static void fz_jemit(j_common_ptr c, int level) {
  if (level < 0) ((fz_jerr_t *)c->err)->warnings++;
}

static void fz_jout(j_common_ptr c) { (void)c; }

static void diff_libjpeg(const uint8_t *data, size_t len, const uint8_t *luma,
                         uint32_t w, uint32_t h) {
  struct jpeg_decompress_struct cinfo;
  fz_jerr_t jerr;
  static uint8_t row[FIMG_MAX_DIM];
  volatile int mismatch = 0;

  cinfo.err = jpeg_std_error(&jerr.pub);
  jerr.pub.error_exit = fz_jerror_exit;
  jerr.pub.emit_message = fz_jemit;
  jerr.pub.output_message = fz_jout;
  jerr.warnings = 0;
  if (setjmp(jerr.jb)) {
    jpeg_destroy_decompress(&cinfo);
    return; /* libjpeg refused what fimg accepted: allowed (stricter libjpeg
               checks) */
  }
  jpeg_create_decompress(&cinfo);
  jpeg_mem_src(&cinfo, data, (unsigned long)len);
  jpeg_read_header(&cinfo, TRUE);
  cinfo.out_color_space = JCS_GRAYSCALE;
  cinfo.dct_method = JDCT_ISLOW;
  cinfo.do_fancy_upsampling = FALSE;
  jpeg_start_decompress(&cinfo);
  if (cinfo.output_width != w || cinfo.output_height != h) abort();
  while (cinfo.output_scanline < cinfo.output_height) {
    JSAMPROW rp = row;
    uint32_t y = cinfo.output_scanline;
    jpeg_read_scanlines(&cinfo, &rp, 1);
    if (memcmp(row, luma + (size_t)y * w, w) != 0) mismatch = 1;
  }
  jpeg_finish_decompress(&cinfo);
  if (jerr.warnings == 0 && mismatch) abort();
  jpeg_destroy_decompress(&cinfo);
}
#endif

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  static uint8_t luma[FIMG_MAX_DIM * FIMG_MAX_DIM];
  fz_luma_t lum = {0, 0, 0, luma};
  if (size < 1 || size > 300 * 1024) return 0;
  fz_run(data, size, &lum);
#ifdef FIMG_FUZZ_LIBJPEG
  {
    fz_result_t r;
    fz_luma_t l2 = {0, 0, 0, luma};
    fz_decode(data + 1, size - 1, data[0] & 1u, 0, &l2, &r);
    if (r.st == FIMG_OK && r.info.format == FIMG_FORMAT_JPEG &&
        fz_last_ctx->u.jpeg.sat == 0)
      diff_libjpeg(data + 1, size - 1, luma, r.info.src_width,
                   r.info.src_height);
  }
#endif
  return 0;
}
