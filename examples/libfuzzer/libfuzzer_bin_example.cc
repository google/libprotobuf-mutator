// Copyright 2017 Google Inc. All rights reserved.
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

#include <cstddef>
#include <cstdint>

#include "examples/libfuzzer/libfuzzer_example.pb.h"
#include "src/binary_format.h"
#include "src/libfuzzer/libfuzzer_mutator.h"

using libfuzzer_example::Msg;
protobuf_mutator::protobuf::LogSilencer log_silincer;

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  return protobuf_mutator::libfuzzer::MutateBinaryMessage<Msg>(data, size,
                                                               max_size, seed);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return protobuf_mutator::libfuzzer::CrossOverBinaryMessages<Msg>(
      data1, size1, data2, size2, out, max_out_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Msg message;
  protobuf_mutator::ParseBinaryMessage(data, size, &message);

  // Emulate a bug.
  if (message.optional_string() == "FooBar" &&
      message.optional_uint64() == 17 &&
      !std::isnan(message.optional_float()) &&
      fabs(message.optional_float()) > 1000 &&
      fabs(message.optional_float()) < 1E10) {
    abort();
  }

  return 0;
}
