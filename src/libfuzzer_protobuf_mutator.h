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

#ifndef LIBFUZZER_PROTOBUF_MUTATOR_H_
#define LIBFUZZER_PROTOBUF_MUTATOR_H_

#include <string>

#include "protobuf_mutator.h"

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
                           size_t allowed_growth) override;
};

// TODO(vitalybuka): Helpers do define LLVMFuzzerCustomMutator.

}  // namespace protobuf_mutator

#endif  // LIBFUZZER_PROTOBUF_MUTATOR_H_
