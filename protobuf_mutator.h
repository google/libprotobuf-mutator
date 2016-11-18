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
  ProtobufMutator(uint32_t seed, bool always_initialized);
  virtual ~ProtobufMutator();

  bool Mutate(google::protobuf::Message* message);
  bool CrossOver(const google::protobuf::Message& with,
                 google::protobuf::Message* message);

  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           int32_t* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           int64_t* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           uint32_t* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           uint64_t* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           double* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           float* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           bool* value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           const google::protobuf::EnumValueDescriptor** value);
  virtual bool MutateField(const google::protobuf::FieldDescriptor& field,
                           google::protobuf::Message* value);

  void InitializeMessage(google::protobuf::Message* message);

 private:
  // Returns true with probability n/m;
  bool GetRandom(size_t n, size_t m);
  size_t GetRandomIndex(size_t count);

  bool always_initialized_ = true;
  std::mt19937_64 rng_;
};

#endif  // LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
