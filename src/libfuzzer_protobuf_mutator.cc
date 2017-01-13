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

#include "libfuzzer_protobuf_mutator.h"

#include <string.h>
#include <cassert>
#include <string>

extern "C" size_t LLVMFuzzerMutate(uint8_t*, size_t, size_t);

namespace protobuf_mutator {

namespace {

template <class T>
T MutateValue(T v) {
  size_t size =
      LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&v), sizeof(v), sizeof(v));
  memset(reinterpret_cast<uint8_t*>(&v) + size, 0, sizeof(v) - size);
  return v;
}
}

int32_t LibFuzzerProtobufMutator::MutateInt32(int32_t value) {
  return MutateValue(value);
}

int64_t LibFuzzerProtobufMutator::MutateInt64(int64_t value) {
  return MutateValue(value);
}

uint32_t LibFuzzerProtobufMutator::MutateUInt32(uint32_t value) {
  return MutateValue(value);
}

uint64_t LibFuzzerProtobufMutator::MutateUInt64(uint64_t value) {
  return MutateValue(value);
}

float LibFuzzerProtobufMutator::MutateFloat(float value) {
  return MutateValue(value);
}

double LibFuzzerProtobufMutator::MutateDouble(double value) {
  return MutateValue(value);
}

std::string LibFuzzerProtobufMutator::MutateString(const std::string& value,
                                                   size_t allowed_growth) {
  std::string result = value;
  result.resize(value.size() + allowed_growth);
  if (result.empty()) return result;
  result.resize(LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&result[0]),
                                 value.size(), result.size()));
  return result;
}

}  // namespace protobuf_mutator
