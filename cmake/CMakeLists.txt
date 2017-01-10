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
set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/external)

# External dependencies
include(googletest)
include(protobuf)
include(zlib)
include(libfuzzer)
include(ProcessorCount)

find_package (Threads)

set(CMAKE_CXX_STANDARD 11)
set(EXTRA_FLAGS "-fno-exceptions -Werror -Wall")
option(LIB_PROTO_MUTATOR_ASAN "Enable address sanitizer" ON)
if (LIB_PROTO_MUTATOR_ASAN)
  set (EXTRA_FLAGS "${EXTRA_FLAGS} -O1 -fsanitize=address,undefined,leak -fsanitize-address-use-after-scope")
endif()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${EXTRA_FLAGS}")

# Libraries
add_library(protobuf-mutator ../protobuf_mutator.cc)
target_link_libraries(protobuf-mutator
                      ${PROTOBUF_LIBRARY})

add_library(libfuzzer-protobuf-mutator ../libfuzzer_protobuf_mutator.cc)
target_link_libraries(libfuzzer-protobuf-mutator
                      protobuf-mutator)

# Examples
protobuf_generate_cpp(LIB_FUZZER_PROTO_SRCS LIB_FUZZER_PROTO_HDRS ../libfuzzer_example.proto)
add_executable(libfuzzer_example
               ../libfuzzer_example.cc
               ${LIB_FUZZER_PROTO_SRCS})
set_property(TARGET libfuzzer_example
             PROPERTY COMPILE_FLAGS "-fsanitize-coverage=trace-pc-guard")
set_property(TARGET libfuzzer_example
             PROPERTY LINK_FLAGS "-fsanitize-coverage=trace-pc-guard")
target_link_libraries(libfuzzer_example
                      libfuzzer-protobuf-mutator
                      ${LIBFUZZER_LIBRARIES})

# Tests
enable_testing()
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ../protobuf_mutator.proto)
add_executable(protobuf_mutator_test
               ../libfuzzer_example_test.cc
               ../protobuf_mutator_test.cc
               ../weighted_reservoir_sampler_test.cc
               ${PROTO_SRCS})
target_link_libraries(protobuf_mutator_test
                      protobuf-mutator
                      ${ZLIB_LIBRARIES}
                      ${PROTOBUF_LIBRARY}
                      ${GTEST_BOTH_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT})
add_dependencies(protobuf_mutator_test libfuzzer_example)

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

