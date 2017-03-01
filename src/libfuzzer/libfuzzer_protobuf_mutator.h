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

#ifndef SRC_LIBFUZZER_LIBFUZZER_PROTOBUF_MUTATOR_H_
#define SRC_LIBFUZZER_LIBFUZZER_PROTOBUF_MUTATOR_H_

#include <string>

#include "src/protobuf_mutator.h"

namespace protobuf_mutator {

// Overrides ProtobufMutator::Mutate* methods with implementation which
// uses libFuzzer library. ProtobufMutator has very basic implementation of this
// methods.
class LibFuzzerProtobufMutator : public ProtobufMutator {
 public:
  explicit LibFuzzerProtobufMutator(uint32_t seed) : ProtobufMutator(seed) {}

 protected:
  int32_t MutateInt32(int32_t value) override;
  int64_t MutateInt64(int64_t value) override;
  uint32_t MutateUInt32(uint32_t value) override;
  uint64_t MutateUInt64(uint64_t value) override;
  float MutateFloat(float value) override;
  double MutateDouble(double value) override;
  std::string MutateString(const std::string& value,
                           size_t size_increase_hint) override;
};

namespace internal {
size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed, protobuf::Message* message);
size_t CrossOverTextMessages(const uint8_t* data1, size_t size1,
                             const uint8_t* data2, size_t size2, uint8_t* out,
                             size_t max_out_size, unsigned int seed,
                             protobuf::Message* message1,
                             protobuf::Message* message2);
size_t MutateBinaryMessage(uint8_t* data, size_t size, size_t max_size,
                           unsigned int seed, protobuf::Message* message);
size_t CrossOverBinaryMessages(const uint8_t* data1, size_t size1,
                               const uint8_t* data2, size_t size2, uint8_t* out,
                               size_t max_out_size, unsigned int seed,
                               protobuf::Message* message1,
                               protobuf::Message* message2);
}  // namespace internal

// Mutates proto serialized as text.
template <class MessageType>
size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed) {
  MessageType message;
  return internal::MutateTextMessage(data, size, max_size, seed, &message);
}

// Crossover two protos serialized as text.
template <class MessageType>
size_t CrossOverTextMessages(const uint8_t* data1, size_t size1,
                             const uint8_t* data2, size_t size2, uint8_t* out,
                             size_t max_out_size, unsigned int seed) {
  MessageType message1;
  MessageType message2;
  return internal::CrossOverTextMessages(data1, size1, data2, size2, out,
                                         max_out_size, seed, &message1,
                                         &message2);
}

// Mutates proto serialized as binary.
template <class MessageType>
size_t MutateBinaryMessage(uint8_t* data, size_t size, size_t max_size,
                           unsigned int seed) {
  MessageType message;
  return internal::MutateBinaryMessage(data, size, max_size, seed, &message);
}

// Crossover two protos serialized as binary.
template <class MessageType>
size_t CrossOverBinaryMessages(const uint8_t* data1, size_t size1,
                               const uint8_t* data2, size_t size2, uint8_t* out,
                               size_t max_out_size, unsigned int seed) {
  MessageType message1;
  MessageType message2;
  return internal::CrossOverBinaryMessages(data1, size1, data2, size2, out,
                                           max_out_size, seed, &message1,
                                           &message2);
}

}  // namespace protobuf_mutator

#endif  // SRC_LIBFUZZER_LIBFUZZER_PROTOBUF_MUTATOR_H_
