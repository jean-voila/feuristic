# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Host tests of lib/fqr. Test code is hosted C99 (stdio, malloc, libm); it
# may include the library's internal headers to unit-test internals.

set(FQR_SRC_DIR ${FEURISTIC_ROOT}/lib/fqr/src)

add_library(fqr_testsupport STATIC qrenc.c)
target_include_directories(fqr_testsupport PUBLIC ${CMAKE_CURRENT_SOURCE_DIR} ${FQR_SRC_DIR})
target_link_libraries(fqr_testsupport PUBLIC fqr)
target_compile_options(fqr_testsupport PRIVATE ${FEURISTIC_WARNINGS})
if(NOT APPLE)
  target_link_libraries(fqr_testsupport PUBLIC m)
endif()

foreach(t test_rs test_bits test_matrix test_detect)
  add_executable(fqr_${t} ${t}.c)
  target_link_libraries(fqr_${t} PRIVATE fqr_testsupport)
  target_compile_options(fqr_${t} PRIVATE ${FEURISTIC_WARNINGS})
  add_test(NAME fqr_${t} COMMAND fqr_${t})
endforeach()
set_tests_properties(fqr_test_detect PROPERTIES TIMEOUT 600)

# Corpus of rendered images (committed under vectors/, regenerated with
# gen_vectors.py). The runner is also the benchmark tool (--bench).
add_executable(fqr_vectors test_vectors.c)
target_link_libraries(fqr_vectors PRIVATE fqr_testsupport)
target_compile_options(fqr_vectors PRIVATE ${FEURISTIC_WARNINGS})
add_test(NAME fqr_vectors
         COMMAND fqr_vectors ${CMAKE_CURRENT_SOURCE_DIR}/vectors/manifest.txt)
set_tests_properties(fqr_vectors PROPERTIES TIMEOUT 600)

# Optional large generated set:
#   uv run python tests/c/fqr/gen_vectors.py --large --out build/fqr-large
#   cmake ... -DFQR_EXTRA_VECTORS=$PWD/build/fqr-large/manifest.txt
set(FQR_EXTRA_VECTORS "" CACHE FILEPATH "Optional extra lib/fqr vector manifest")
if(FQR_EXTRA_VECTORS)
  add_test(NAME fqr_vectors_extra COMMAND fqr_vectors ${FQR_EXTRA_VECTORS})
  set_tests_properties(fqr_vectors_extra PROPERTIES TIMEOUT 3600)
endif()
