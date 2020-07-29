// Copyright 2019 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "port/gtest.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/mutator_test_proto2.pb.h"

static bool reached = false;
static bool postprocessed = false;

protobuf_mutator::libfuzzer::PostProcessorRegistration<protobuf_mutator::Msg>
    reg = {[](protobuf_mutator::Msg* message, unsigned int seed) {
      static unsigned int first_seed = seed;
      EXPECT_EQ(seed, first_seed);
      postprocessed = true;
    }};

DEFINE_TEXT_PROTO_FUZZER(const protobuf_mutator::Msg& message) {
  reached = true;
  EXPECT_TRUE(message.IsInitialized());
  EXPECT_TRUE(postprocessed);
}

TEST(LibFuzzerTest, LLVMFuzzerTestOneInput) {
  for (int i = 0; i < 10; ++i) {
    reached = false;
    postprocessed = false;
    LLVMFuzzerTestOneInput((const uint8_t*)"", 0);
    EXPECT_TRUE(reached);
  }
}
