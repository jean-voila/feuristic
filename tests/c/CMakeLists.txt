# SPDX-License-Identifier: GPL-3.0-only
# Host build of the portable C libraries (lib/) and their unit tests.
#
#   cmake -S tests/c -B build/c -DFEURISTIC_SANITIZE=ON
#   cmake --build build/c -j && ctest --test-dir build/c --output-on-failure
cmake_minimum_required(VERSION 3.20)
project(feuristic_c_tests C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

option(FEURISTIC_SANITIZE "Build with AddressSanitizer + UndefinedBehaviorSanitizer" OFF)
option(FEURISTIC_COVERAGE "Build with coverage instrumentation" OFF)

set(FEURISTIC_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/../..)
set(FEURISTIC_WARNINGS -Wall -Wextra -Werror -pedantic -Wshadow -Wstrict-prototypes
    -Wmissing-prototypes -Wcast-align -Wpointer-arith -Wvla -Wformat=2)

if(FEURISTIC_SANITIZE)
  add_compile_options(-fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  add_link_options(-fsanitize=address,undefined)
endif()
if(FEURISTIC_COVERAGE)
  add_compile_options(--coverage -O0)
  add_link_options(--coverage)
endif()

enable_testing()

# Each library directory provides lib/<name>/CMakeLists.txt (the library) and
# tests/c/<name>/CMakeLists.txt (its tests). Missing ones are skipped so that
# libraries can be developed independently.
foreach(lib fqr fimg fmsc frsa)
  if(EXISTS ${FEURISTIC_ROOT}/lib/${lib}/CMakeLists.txt)
    add_subdirectory(${FEURISTIC_ROOT}/lib/${lib} ${CMAKE_BINARY_DIR}/lib/${lib})
  endif()
  if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/${lib}/CMakeLists.txt)
    add_subdirectory(${lib})
  endif()
endforeach()
