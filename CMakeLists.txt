# Copyright 2016 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

cmake_minimum_required(VERSION 3.5)
project(LibProtobufMutator CXX)

enable_language(C)
enable_language(CXX)

option(LIB_PROTO_MUTATOR_WITH_ASAN "Enable address sanitizer" ON)
set(LIB_PROTO_MUTATOR_FUZZER_LIBRARIES "" CACHE STRING "Fuzzing engine libs")

# External dependencies
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

# External dependencies
include(ProcessorCount)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

find_package(Threads)

find_package(LibLZMA)
include_directories(${LIBLZMA_INCLUDE_DIRS})

find_package(ZLIB)
include_directories(${ZLIB_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 11)

include_directories(${PROJECT_SOURCE_DIR})

set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
check_cxx_compiler_flag(-fsanitize=address LIB_PROTO_MUTATOR_HAS_SANITIZE_ADDRESS)
check_cxx_compiler_flag("-fsanitize=address -fsanitize-address-use-after-scope"
                        LIB_PROTO_MUTATOR_HAS_SANITIZE_SCOPE)
unset(CMAKE_REQUIRED_FLAGS)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=")
check_cxx_compiler_flag(-fsanitize-coverage= LIB_PROTO_MUTATOR_HAS_COVERAGE)
unset(CMAKE_REQUIRED_FLAGS)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=trace-pc-guard")
check_cxx_compiler_flag(-fsanitize-coverage=trace-pc-guard LIB_PROTO_MUTATOR_HAS_TRACE_PC)
unset(CMAKE_REQUIRED_FLAGS)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=trace-cmp")
check_cxx_compiler_flag(-fsanitize-coverage=trace-cmp LIB_PROTO_MUTATOR_HAS_TRACE_CMP)
unset(CMAKE_REQUIRED_FLAGS)

set(EXTRA_FLAGS "-fno-exceptions -Werror -Wall")
if (LIB_PROTO_MUTATOR_WITH_ASAN)
  if (LIB_PROTO_MUTATOR_HAS_SANITIZE_ADDRESS)
    set(EXTRA_FLAGS "${EXTRA_FLAGS} -fsanitize=address")
    if (LIB_PROTO_MUTATOR_HAS_SANITIZE_SCOPE)
      set(EXTRA_FLAGS "${EXTRA_FLAGS} -fsanitize-address-use-after-scope")
    endif()
  endif()
endif()

if (LIB_PROTO_MUTATOR_HAS_TRACE_PC)
  list(APPEND SANITIZE_COVERAGE_OPTIONS trace-pc-guard)
endif()
if (LIB_PROTO_MUTATOR_HAS_TRACE_CMP)
  list(APPEND SANITIZE_COVERAGE_OPTIONS trace-cmp)
endif()

if (SANITIZE_COVERAGE_OPTIONS)
  foreach(OPT ${SANITIZE_COVERAGE_OPTIONS})
    set(FUZZING_FLAGS "${FUZZING_FLAGS},${OPT}")
  endforeach()
  string(SUBSTRING ${FUZZING_FLAGS} 1 -1 FUZZING_FLAGS)
  set(NO_FUZZING_FLAGS "-fno-sanitize-coverage=${FUZZING_FLAGS}")
  set(FUZZING_FLAGS "-fsanitize-coverage=${FUZZING_FLAGS}")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_FLAGS}")

set(PROTOBUF_CFLAGS "${CMAKE_C_FLAGS} ${NO_FUZZING_FLAGS} -w")
set(PROTOBUF_CXXFLAGS "${CMAKE_CXX_FLAGS} ${NO_FUZZING_FLAGS} -w")
include(protobuf)

enable_testing()

include(googletest)

ProcessorCount(CPU_COUNT)
add_custom_target(check
                  COMMAND ${CMAKE_CTEST_COMMAND} -j${CPU_COUNT} --output-on-failure)

add_subdirectory(src)

if ("${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES}" STREQUAL "" AND
    NOT "${FUZZING_FLAGS}" STREQUAL "")
  include(libfuzzer)
endif()

if (NOT "${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES}" STREQUAL "")
  add_subdirectory(examples)
endif()

