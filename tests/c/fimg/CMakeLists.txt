# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Host tests of lib/fimg. Vectors: tests/c/fimg/vectors (gen_vectors.py).
set(FIMG_TEST_DIR ${CMAKE_CURRENT_SOURCE_DIR})

foreach(t fimg_test_unit fimg_test_vectors)
  string(REPLACE "fimg_test_" "test_" src ${t})
  add_executable(${t} ${src}.c)
  target_link_libraries(${t} PRIVATE fimg)
  # unit tests reach the internal API (inflater, pixel pipeline)
  target_include_directories(${t} PRIVATE ${FEURISTIC_ROOT}/lib/fimg/src)
  target_compile_options(${t} PRIVATE ${FEURISTIC_WARNINGS})
  target_compile_definitions(${t} PRIVATE FIMG_VECTORS_DIR="${FIMG_TEST_DIR}/vectors")
endforeach()

add_test(NAME fimg_unit COMMAND fimg_test_unit)
add_test(NAME fimg_vectors COMMAND fimg_test_vectors ${FIMG_TEST_DIR}/vectors)
set_tests_properties(fimg_vectors PROPERTIES TIMEOUT 900)
