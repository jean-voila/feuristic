# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# frsa: RSA wrapper (feuristic, GPL-3.0-only) over a vendored BearSSL subset
# (lib/third_party/bearssl, MIT). Included by tests/c/CMakeLists.txt.

set(FRSA_BEARSSL_DIR ${CMAKE_CURRENT_LIST_DIR}/../third_party/bearssl)

# Vendored BearSSL: compiled unmodified, in its own target, with relaxed
# warnings (upstream code style is not ours to change). -Werror is kept off
# here so that a new compiler warning in third-party code never blocks the
# build; our own code below keeps the full FEURISTIC_WARNINGS set.
set(FRSA_BEARSSL_SOURCES
  ${FRSA_BEARSSL_DIR}/src/codec/ccopy.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_add.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_bitlen.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_decmod.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_decode.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_decred.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_encode.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_fmont.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_iszero.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_moddiv.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_modpow2.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_montmul.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_mulacc.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_muladd.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_ninv31.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_reduce.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_rshift.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_sub.c
  ${FRSA_BEARSSL_DIR}/src/int/i31_tmont.c
  ${FRSA_BEARSSL_DIR}/src/int/i32_div32.c
  ${FRSA_BEARSSL_DIR}/src/rsa/rsa_i31_priv.c
  ${FRSA_BEARSSL_DIR}/src/rsa/rsa_i31_pub.c
)
add_library(frsa_bearssl STATIC ${FRSA_BEARSSL_SOURCES})
target_include_directories(frsa_bearssl
  PRIVATE ${FRSA_BEARSSL_DIR}/src
  PUBLIC ${FRSA_BEARSSL_DIR}/inc)
target_compile_options(frsa_bearssl PRIVATE -Wall -Wextra -pedantic)

add_library(frsa STATIC ${CMAKE_CURRENT_LIST_DIR}/frsa.c)
target_include_directories(frsa PUBLIC ${CMAKE_CURRENT_LIST_DIR})
# BearSSL internal headers are included as system headers so that the
# stricter feuristic warnings apply to frsa.c only.
target_include_directories(frsa SYSTEM PRIVATE
  ${FRSA_BEARSSL_DIR}/src ${FRSA_BEARSSL_DIR}/inc)
target_compile_options(frsa PRIVATE ${FEURISTIC_WARNINGS})
target_link_libraries(frsa PRIVATE frsa_bearssl)
