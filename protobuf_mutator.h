// Copyright 2016 Google Inc. All rights reserved.
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

#ifndef LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
#define LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <random>

namespace google {
namespace protobuf {
class Message;
class FieldDescriptor;
class EnumValueDescriptor;
}
}

class ProtobufMutator {
 public:
  using RandomEngine = std::minstd_rand0;

  class Customization {
   public:
    virtual ~Customization() = default;

    virtual size_t MutateBytes(void* data, size_t size, size_t max_size) = 0;
  };

  ProtobufMutator(uint32_t seed, bool keep_initialized,
                  Customization* customization = nullptr);

  bool Mutate(google::protobuf::Message* message, size_t current_size,
              size_t max_size);
  bool CrossOver(const google::protobuf::Message& with,
                 google::protobuf::Message* message);

  void InitializeMessage(google::protobuf::Message* message, int max_depth);

 private:
  bool keep_initialized_ = false;
  RandomEngine random_;
  Customization* customization_ = nullptr;
  std::unique_ptr<ProtobufMutator::Customization> defaults_;
};

#endif  // LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
