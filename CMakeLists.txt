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

# External dependencies
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake/external)

# External dependencies
include(ProcessorCount)
include(CheckCCompilerFlag)
include(CheckCXXCompilerFlag)

find_package(Threads REQUIRED)

find_package(LibLZMA REQUIRED)
include_directories(${LIBLZMA_INCLUDE_DIRS})

find_package(ZLIB REQUIRED)
include_directories(${ZLIB_INCLUDE_DIRS})

set(CMAKE_CXX_STANDARD 11)

option(LIB_PROTO_MUTATOR_WITH_ASAN "Enable address sanitizer" ON)

include_directories(${PROJECT_SOURCE_DIR})

set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
check_cxx_compiler_flag(-fsanitize=address LIB_PROTO_MUTATOR_HAS_SANITIZE_ADDRESS)
check_cxx_compiler_flag("-fsanitize=address -fsanitize-address-use-after-scope"
                        LIB_PROTO_MUTATOR_HAS_SANITIZE_SCOPE)
unset(CMAKE_REQUIRED_FLAGS)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=trace-pc-guard")
check_cxx_compiler_flag(-fsanitize-coverage=trace-pc-guard LIB_PROTO_MUTATOR_HAS_TRACE_PC)
unset(CMAKE_REQUIRED_FLAGS)

set(CMAKE_REQUIRED_FLAGS "-fsanitize-coverage=trace-cmp")
check_cxx_compiler_flag(-fsanitize-coverage=trace-cmp LIB_PROTO_MUTATOR_HAS_TRACE_CMP)
unset(CMAKE_REQUIRED_FLAGS)

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
  set(FUZZING_FLAGS "-fsanitize-coverage=${FUZZING_FLAGS}")
endif()

set(EXTRA_FLAGS "-fno-exceptions -Werror -Wall")
if (LIB_PROTO_MUTATOR_WITH_ASAN)
  if (LIB_PROTO_MUTATOR_HAS_SANITIZE_ADDRESS)
    set(EXTRA_FLAGS "${EXTRA_FLAGS} -fsanitize=address")
    if (LIB_PROTO_MUTATOR_HAS_SANITIZE_SCOPE)
      set(EXTRA_FLAGS "${EXTRA_FLAGS} -fsanitize-address-use-after-scope")
    endif()
  endif()
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_FLAGS}")

include(googletest)
include(protobuf)

# Libraries
add_library(protobuf-mutator
            src/libfuzzer_protobuf_mutator.cc
            src/protobuf_mutator.cc)
target_link_libraries(protobuf-mutator
                      ${PROTOBUF_LIBRARY})

# Tests
enable_testing()
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS src/protobuf_mutator.proto)
add_executable(protobuf_mutator_test
               src/protobuf_mutator_test.cc
               src/weighted_reservoir_sampler_test.cc
               ${PROTO_SRCS})
target_link_libraries(protobuf_mutator_test
                      protobuf-mutator
                      ${ZLIB_LIBRARIES}
                      ${PROTOBUF_LIBRARY}
                      ${GTEST_BOTH_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT})

ProcessorCount(CPU_COUNT)
math(EXPR TEST_SHARDS_COUNT 2*${CPU_COUNT})
math(EXPR TEST_SHARDS_MAX ${TEST_SHARDS_COUNT}-1)
foreach(SHARD RANGE ${TEST_SHARDS_MAX})
  add_test(test.protobuf_mutator_test_${SHARD} protobuf_mutator_test --gtest_color=yes AUTO)
  set_property(
      TEST test.protobuf_mutator_test_${SHARD}
      APPEND PROPERTY ENVIRONMENT
      GTEST_SHARD_INDEX=${SHARD}
      GTEST_TOTAL_SHARDS=${TEST_SHARDS_COUNT})
endforeach(SHARD)

add_custom_target(check
                  COMMAND ${CMAKE_CTEST_COMMAND} -j${CPU_COUNT} --output-on-failure
                  DEPENDS protobuf_mutator_test)

# Examples
if (NOT ${FUZZING_FLAGS} STREQUAL "")
  include(libfuzzer)

  protobuf_generate_cpp(LIB_FUZZER_EXAMPLE_PROTO_SRCS
                        LIB_FUZZER_EXAMPLE_PROTO_HDRS
                        examples/libfuzzer/libfuzzer_example.proto)
  add_executable(libfuzzer_example
                 examples/libfuzzer/libfuzzer_example.cc
                 ${LIB_FUZZER_EXAMPLE_PROTO_SRCS})
  target_link_libraries(libfuzzer_example
                        protobuf-mutator
                        ${LIBFUZZER_LIBRARIES}
                        ${CMAKE_THREAD_LIBS_INIT})
  set_property(TARGET libfuzzer_example
               PROPERTY COMPILE_FLAGS ${FUZZING_FLAGS})
  set_property(TARGET libfuzzer_example
               PROPERTY LINK_FLAGS ${FUZZING_FLAGS})
  target_sources(protobuf_mutator_test
                 PRIVATE examples/libfuzzer/libfuzzer_example_test.cc)
  add_dependencies(protobuf_mutator_test libfuzzer_example)

  set(LIBXML2_FLAGS "${EXTRA_FLAGS} ${FUZZING_FLAGS} -w")
  include(libxml2)

  protobuf_generate_cpp(LIBXML2_EXAMPLE_PROTO_SRCS
                        LIBXML2_EXAMPLE_PROTO_HDRS
                        examples/libxml2/xml.proto)
  add_library(libxml2_example_proto
              examples/libxml2/xml_writer.cc
              ${LIBXML2_EXAMPLE_PROTO_SRCS})
  target_link_libraries(libxml2_example_proto
                        protobuf-mutator)

  add_executable(libxml2_example
                 examples/libxml2/libxml2_example.cc)
  target_link_libraries(libxml2_example
                        protobuf-mutator
                        libxml2_example_proto
                        ${LIBFUZZER_LIBRARIES}
                        ${CMAKE_THREAD_LIBS_INIT}
                        ${LIBXML2_LIBRARIES}
                        ${ZLIB_LIBRARIES}
                        ${LIBLZMA_LIBRARIES})
  set_property(TARGET libxml2_example
               PROPERTY LINK_FLAGS ${FUZZING_FLAGS})


  add_executable(proto_to_xml
                 examples/libxml2/proto_to_xml.cc
                 ${LIBXML2_EXAMPLE_PROTO_SRCS})
  target_link_libraries(proto_to_xml
                        libxml2_example_proto)

  target_sources(protobuf_mutator_test
                 PRIVATE examples/libxml2/libxml2_example_test.cc)
  add_dependencies(protobuf_mutator_test libxml2_example)
endif()
