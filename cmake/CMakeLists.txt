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

find_package (Threads)

#set(CMAKE_INCLUDE_CURRENT_DIR ON)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-exceptions")

add_library(protobuf-mutator ../protobuf_mutator.cc)
target_link_libraries(protobuf-mutator
                      ${PROTOBUF_LIBRARY})

protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ../protobuf_mutator.proto)
#message (--3333- ${PROTO_SRCS})

enable_testing()
add_executable(protobuf_mutator_test ../protobuf_mutator_test.cc ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(protobuf_mutator_test
                      protobuf-mutator
                      ${ZLIB_LIBRARIES}
                      ${PROTOBUF_LIBRARY}
                      ${GTEST_BOTH_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT})

#GTEST_ADD_TESTS(protobuf_mutator_test --gtest_color=yes AUTO)
add_test(test.protobuf_mutator_test protobuf_mutator_test --gtest_color=yes AUTO)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND} --verbose
                  DEPENDS protobuf_mutator_test)
