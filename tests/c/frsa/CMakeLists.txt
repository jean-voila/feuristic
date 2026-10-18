# SPDX-License-Identifier: GPL-3.0-only
# Copyright (C) 2026 The feuristic contributors

add_executable(test_frsa test_frsa.c)
target_compile_options(test_frsa PRIVATE ${FEURISTIC_WARNINGS})
target_include_directories(test_frsa PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(test_frsa PRIVATE frsa)
add_test(NAME frsa COMMAND test_frsa)
set_tests_properties(frsa PROPERTIES TIMEOUT 600)
