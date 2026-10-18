# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# lib/fimg: streaming PNG / baseline-JPEG decoders + binarizer (freestanding C99).
add_library(fimg STATIC
  src/fimg.c
  src/fimg_inflate.c
  src/fimg_jpeg.c
  src/fimg_pix.c
  src/fimg_png.c
)
target_include_directories(fimg PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
target_compile_options(fimg PRIVATE ${FEURISTIC_WARNINGS})
set_target_properties(fimg PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
