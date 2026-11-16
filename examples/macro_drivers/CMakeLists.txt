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

protobuf_generate_cpp(MACRO_DRIVERS_PROTO_SRCS
                      MACRO_DRIVERS_PROTO_HDRS
                      macro_drivers.proto)

add_library(macro-drivers-proto
            ${MACRO_DRIVERS_PROTO_SRCS})
set_property(TARGET macro-drivers-proto
             PROPERTY COMPILE_FLAGS "${NO_FUZZING_FLAGS}")

add_executable(macro_drivers_fuzzer
               macro_drivers_fuzzer.cc)
target_link_libraries(macro_drivers_fuzzer
                      macro-drivers-proto
                      protobuf-mutator-libfuzzer
                      ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES})
set_property(TARGET macro_drivers_fuzzer
             PROPERTY COMPILE_FLAGS "${FUZZING_FLAGS}")
set_property(TARGET macro_drivers_fuzzer
             PROPERTY LINK_FLAGS "${FUZZING_FLAGS_BINARY}")
