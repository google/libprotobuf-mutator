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

#include "libfuzzer_example.pb.h"  // NOLINT
#include "src/libfuzzer_protobuf_mutator.h"

using libfuzzer_example::Msg;

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  libfuzzer_example::Msg message;
  return protobuf_mutator::MutateTextMessage(data, size, max_size, seed,
                                             &message);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  libfuzzer_example::Msg message;
  protobuf_mutator::ParseTextMessage(data, size, &message);

  // Emulate a bug.
  if (message.optional_uint64() > 100 &&
      !std::isnan(message.optional_float()) &&
      fabs(message.optional_float()) > 1000 &&
      fabs(message.optional_float()) < 1E10) {
    abort();
  }

  return 0;
}
