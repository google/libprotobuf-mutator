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

#include "src/libfuzzer/libfuzzer_macro.h"

#include <utility>

#include "src/libfuzzer/libfuzzer_mutator.h"
#include "src/mutation_io.h"

namespace protobuf_mutator {
namespace libfuzzer {

namespace {

Mutator* GetMutator() {
  static Mutator mutator;
  return &mutator;
}

}  // namespace

size_t CustomProtoMutator(bool binary, uint8_t* data, size_t size,
                          size_t max_size, unsigned int seed,
                          protobuf::Message* input) {
  GetMutator()->Seed(seed);
  return MutateMessage(binary, GetMutator(), data, size, max_size, input);
}

size_t CustomProtoCrossOver(bool binary, const uint8_t* data1, size_t size1,
                            const uint8_t* data2, size_t size2, uint8_t* out,
                            size_t max_out_size, unsigned int seed,
                            protobuf::Message* input1,
                            protobuf::Message* input2) {
  GetMutator()->Seed(seed);
  return CrossOverMessages(binary, GetMutator(), data1, size1, data2, size2,
                           out, max_out_size, input1, input2);
}

bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    protobuf::Message* input) {
  return protobuf_mutator::LoadProtoInput(binary, data, size, GetMutator(),
                                          input);
}

void RegisterPostProcessor(
    const protobuf::Descriptor* desc,
    std::function<void(protobuf::Message* message, unsigned int seed)>
        callback) {
  GetMutator()->RegisterPostProcessor(desc, std::move(callback));
}

}  // namespace libfuzzer
}  // namespace protobuf_mutator
