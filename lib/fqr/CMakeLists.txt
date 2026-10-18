# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# lib/fqr: freestanding QR code detector + decoder on a 1-bpp bitmap.

add_library(fqr STATIC
  src/fqr_align.c
  src/fqr_bits.c
  src/fqr_detect.c
  src/fqr_finder.c
  src/fqr_geom.c
  src/fqr_matrix.c
  src/fqr_rs.c
  src/fqr_tables.c
)
target_include_directories(fqr PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
# Extra flags: keep the code single-precision only (Cortex-M4F FPU).
set(FQR_EXTRA_WARNINGS -Wdouble-promotion -Wfloat-conversion -Wundef -Wcast-qual)
target_compile_options(fqr PRIVATE ${FEURISTIC_WARNINGS} ${FQR_EXTRA_WARNINGS})
set_target_properties(fqr PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
