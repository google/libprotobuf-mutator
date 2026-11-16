# Copyright 2026 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

protobuf_generate_cpp(DEPTH_GUARD_PROTO_SRCS
                      DEPTH_GUARD_PROTO_HDRS
                      depth_guard.proto)

add_library(depth-guard-proto
            ${DEPTH_GUARD_PROTO_SRCS})
set_property(TARGET depth-guard-proto
             PROPERTY COMPILE_FLAGS "${NO_FUZZING_FLAGS}")

add_executable(depth_guard_fuzzer
               depth_guard_fuzzer.cc)
target_link_libraries(depth_guard_fuzzer
                      depth-guard-proto
                      protobuf-mutator-libfuzzer
                      ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES})
set_property(TARGET depth_guard_fuzzer
             PROPERTY COMPILE_FLAGS "${FUZZING_FLAGS}")
set_property(TARGET depth_guard_fuzzer
             PROPERTY LINK_FLAGS "${FUZZING_FLAGS_BINARY}")
