# Copyright 2017 Google Inc. All rights reserved.
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

protobuf_generate_cpp(LIB_FUZZER_EXAMPLE_PROTO_SRCS
                      LIB_FUZZER_EXAMPLE_PROTO_HDRS
                      libfuzzer_example.proto)
add_executable(libfuzzer_example
               libfuzzer_example.cc
               ${LIB_FUZZER_EXAMPLE_PROTO_SRCS})
target_link_libraries(libfuzzer_example
                      protobuf-mutator
                      ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES})
set_property(TARGET libfuzzer_example
             PROPERTY COMPILE_FLAGS ${FUZZING_FLAGS})
set_property(TARGET libfuzzer_example
             PROPERTY LINK_FLAGS ${FUZZING_FLAGS})

add_executable(libfuzzer_example_test
               libfuzzer_example_test.cc)
add_dependencies(libfuzzer_example_test libfuzzer_example)
target_link_libraries(libfuzzer_example_test
                      ${GTEST_BOTH_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT})
add_test(test.libfuzzer_example_test libfuzzer_example_test --gtest_color=yes AUTO)

add_dependencies(check libfuzzer_example_test)
