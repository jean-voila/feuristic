# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# lib/fmsc: USB MSC Bulk-Only Transport + SCSI + virtual FAT12 volume +
# streaming image-import tracker (freestanding C99).

add_library(fmsc STATIC
  ${CMAKE_CURRENT_LIST_DIR}/src/fmsc_bot.c
  ${CMAKE_CURRENT_LIST_DIR}/src/fmsc_scsi.c
  ${CMAKE_CURRENT_LIST_DIR}/src/fmsc_tracker.c
  ${CMAKE_CURRENT_LIST_DIR}/src/fmsc_volume.c
)
target_include_directories(fmsc PUBLIC ${CMAKE_CURRENT_LIST_DIR}/include)
set(FMSC_EXTRA_WARNINGS -Wundef -Wcast-qual -Wconversion -Wsign-conversion)
if(CMAKE_C_COMPILER_ID MATCHES "GNU")
  list(APPEND FMSC_EXTRA_WARNINGS -Wlogical-op -Wduplicated-cond)
endif()
target_compile_options(fmsc PRIVATE ${FEURISTIC_WARNINGS} ${FMSC_EXTRA_WARNINGS}
  -ffreestanding)
set_target_properties(fmsc PROPERTIES C_STANDARD 99 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)
