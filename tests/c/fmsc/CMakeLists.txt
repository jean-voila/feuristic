# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors
#
# Tests of lib/fmsc (included by tests/c/CMakeLists.txt).

add_library(fmsc_testlib STATIC tharness.c fat_reader.c host_sim.c)
target_link_libraries(fmsc_testlib PUBLIC fmsc)
target_include_directories(fmsc_testlib PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(fmsc_testlib PRIVATE ${FEURISTIC_WARNINGS})

foreach(t test_bot test_scsi test_volume test_tracker)
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${t}.c)
    add_executable(fmsc_${t} ${t}.c)
    target_link_libraries(fmsc_${t} PRIVATE fmsc_testlib)
    target_compile_options(fmsc_${t} PRIVATE ${FEURISTIC_WARNINGS})
    add_test(NAME fmsc_${t} COMMAND fmsc_${t})
  endif()
endforeach()

# Optional: check the generated volume (empty, and after a simulated session)
# with the platform's FAT checker. Skipped when none is installed.
find_program(FMSC_FSCK_MSDOS fsck_msdos PATHS /sbin /usr/sbin NO_DEFAULT_PATH)
find_program(FMSC_FSCK_VFAT NAMES fsck.vfat fsck.fat)
if(FMSC_FSCK_MSDOS)
  set(FMSC_FSCK_CMD "${FMSC_FSCK_MSDOS} -n")
elseif(FMSC_FSCK_VFAT)
  set(FMSC_FSCK_CMD "${FMSC_FSCK_VFAT} -n")
endif()
if(FMSC_FSCK_CMD)
  add_test(NAME fmsc_fsck_empty COMMAND sh -c
    "$<TARGET_FILE:fmsc_test_volume> --dump fmsc_empty.img && ${FMSC_FSCK_CMD} fmsc_empty.img"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
  add_test(NAME fmsc_fsck_session COMMAND sh -c
    "$<TARGET_FILE:fmsc_test_tracker> --dump-session fmsc_session.img && ${FMSC_FSCK_CMD} fmsc_session.img"
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
endif()

# Regression replay of the libFuzzer corpus (no libFuzzer needed).
set(FMSC_FUZZ_DIR ${FEURISTIC_ROOT}/tests/fuzz)
if(EXISTS ${FMSC_FUZZ_DIR}/fmsc_fuzz.c)
  add_executable(fmsc_fuzz_replay ${FMSC_FUZZ_DIR}/fmsc_fuzz.c)
  target_compile_definitions(fmsc_fuzz_replay PRIVATE FMSC_FUZZ_REPLAY_MAIN=1)
  target_link_libraries(fmsc_fuzz_replay PRIVATE fmsc)
  target_compile_options(fmsc_fuzz_replay PRIVATE ${FEURISTIC_WARNINGS})
  add_test(NAME fmsc_fuzz_corpus_replay
    COMMAND fmsc_fuzz_replay ${FMSC_FUZZ_DIR}/corpus/fmsc)
endif()
