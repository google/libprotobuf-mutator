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

#include "src/libfuzzer_protobuf_mutator.h"

#include <string.h>
#include <cassert>
#include <string>

#include "src/port/protobuf.h"
#include "src/protobuf_mutator.h"

using protobuf::Message;
using protobuf::TextFormat;

extern "C" size_t LLVMFuzzerMutate(uint8_t*, size_t, size_t)
    __attribute__((weak));

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
                                                   size_t size_increase_hint) {
  // Randomly return empty strings as LLVMFuzzerMutate does not produce them.
  if (!std::uniform_int_distribution<uint8_t>(0, 20)(*random())) return {};
  std::string result = value;
  result.resize(value.size() + size_increase_hint);
  if (result.empty()) return result;
  result.resize(LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&result[0]),
                                 value.size(), result.size()));
  return result;
}

bool ParseTextMessage(const uint8_t* data, size_t size, Message* output) {
  return ParseTextMessage({data, data + size}, output);
}

bool ParseTextMessage(const std::string& data, protobuf::Message* output) {
  output->Clear();
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  return parser.ParseFromString(data, output);
}

size_t SaveMessageAsText(const Message& message, uint8_t* data,
                         size_t max_size) {
  std::string result = SaveMessageAsText(message);
  if (result.size() <= max_size) {
    memcpy(data, result.data(), result.size());
    return result.size();
  }
  return 0;
}

std::string SaveMessageAsText(const protobuf::Message& message) {
  return PrintMessageToString(message);
}

size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed, Message* prototype) {
  assert(size <= max_size);
  protobuf_mutator::LibFuzzerProtobufMutator mutator(seed);
  for (int i = 0; i < 100; ++i) {
    ParseTextMessage(data, size, prototype);
    mutator.Mutate(prototype, max_size - size);
    if (size_t new_size = SaveMessageAsText(*prototype, data, max_size)) {
      assert(new_size <= max_size);
      return new_size;
    }
  }
  return 0;
}

}  // namespace protobuf_mutator
