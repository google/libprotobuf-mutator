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

#include <stdint.h>

class Message;
class FieldDescriptor;
class EnumValueDescriptor;


class ProtobufMutator {
 public:
  ProtobufMutator(uint32_t seed);
  virtual ~ProtobufMutator();

  bool Mutate(Message* proto);
  bool CrossOver(const Message& with, Message* proto);

  virtual bool MutateField(const FieldDescriptor& field, int32_t* value);
  virtual bool MutateField(const FieldDescriptor& field, int64_t* value);
  virtual bool MutateField(const FieldDescriptor& field, uint32_t* value);
  virtual bool MutateField(const FieldDescriptor& field, uint64_t* value);
  virtual bool MutateField(const FieldDescriptor& field, double* value);
  virtual bool MutateField(const FieldDescriptor& field, float* value);
  virtual bool MutateField(const FieldDescriptor& field, bool* value);
  virtual bool MutateField(const FieldDescriptor& field, const EnumValueDescriptor** value);
  virtual bool MutateField(const FieldDescriptor& field, Message* value);

 private:
};

#endif  // LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
