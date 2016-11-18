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

#include "protobuf_mutator.h"

#include <iostream>
#include <map>
#include <string>

#include "google/protobuf/message.h"

using google::protobuf::Message;
using google::protobuf::FieldDescriptor;
using google::protobuf::EnumValueDescriptor;
using google::protobuf::Descriptor;
using google::protobuf::Reflection;
using google::protobuf::OneofDescriptor;

namespace {

const size_t kAddWeight = 1;
const size_t kDeleteWeight = 1;
const size_t kUpdateWeight = 4;
const size_t kSwapWeight = 4;
const size_t kReplaceWeight = 1;

enum class Mutation {
  Add,
  Delete,
  Update,
  Swap,
  // Replace,
};

std::map<std::string, int> stat;

}  // namespace

ProtobufMutator::ProtobufMutator(uint32_t seed, bool always_initialized)
    : rng_(seed), always_initialized_(always_initialized) {}

ProtobufMutator::~ProtobufMutator() {
  for (const auto& p : stat) {
    std::cout << p.first << "\t" << p.second << std::endl;
  }
}

bool ProtobufMutator::Mutate(Message* message) {
  // size

  const Descriptor* descriptor = message->GetDescriptor();
  const Reflection* reflection = message->GetReflection();
  // reflection->ListFields

  size_t current_weight = 0;
  const FieldDescriptor* selected_field = nullptr;
  Mutation mutation = {};

  // Pick field to mutate.
  for (int i = 0; i < descriptor->field_count(); ++i) {
    const FieldDescriptor* field = descriptor->field(i);
    stat[field->full_name()];

    // Select entire oneof group with probability of single field.
    if (field->containing_oneof() && field->index_in_oneof() != 0) continue;

    if (GetRandom(1, ++current_weight)) selected_field = field;

    // assert(!field->is_repeated() || !field->containing_oneof());
    // assert(field->is_optional() || !field->containing_oneof());
    // assert(!field->is_required() || !field->containing_oneof());

    // if (field->is_required()) {

    // } else if field->is_optional() {

    // } else if field->is_optional() {

    // if (field->is_repeated() ||
    //     (!field->is_repeated() && !reflection->HasField(*message, field)) ||
    //     (!field->is_repeated() && !reflection->HasField(*message, field))) {

    // }
  }

  current_weight = 0;

  if (const OneofDescriptor* oneof = selected_field->containing_oneof()) {
    selected_field = reflection->GetOneofFieldDescriptor(*message, oneof);
    if (!selected_field) {
      // std::cout << GetRandomIndex(oneof->field_count());
      selected_field = oneof->field(GetRandomIndex(oneof->field_count()));
    }
  } else {
    switch (selected_field->label()) {
      case FieldDescriptor::LABEL_REQUIRED:
        break;
      case FieldDescriptor::LABEL_OPTIONAL:
        break;
      case FieldDescriptor::LABEL_REPEATED:
        break;
      default:
        assert(!"Unknown label");
    }
  }

  stat[selected_field->full_name()]++;

  // for (int i = 0; i < descriptor->field_count(); ++i) {
  //   const FieldDescriptor* field = descriptor->field(i);

  //   switch(field->type()) {
  //     case FieldDescriptor::TYPE_DOUBLE:
  //     case FieldDescriptor::TYPE_FLOAT:
  //     case FieldDescriptor::TYPE_INT64:
  //     case FieldDescriptor::TYPE_UINT64:
  //     case FieldDescriptor::TYPE_INT32:
  //     case FieldDescriptor::TYPE_FIXED64:
  //     case FieldDescriptor::TYPE_FIXED32:
  //     case FieldDescriptor::TYPE_BOOL:
  //     case FieldDescriptor::TYPE_STRING:
  //     case FieldDescriptor::TYPE_GROUP:
  //     case FieldDescriptor::TYPE_MESSAGE:
  //     case FieldDescriptor::TYPE_BYTES:
  //     case FieldDescriptor::TYPE_UINT32:
  //     case FieldDescriptor::TYPE_ENUM:
  //     case FieldDescriptor::TYPE_SFIXED32:
  //     case FieldDescriptor::TYPE_SFIXED64:
  //     case FieldDescriptor::TYPE_SINT32:
  //     case FieldDescriptor::TYPE_SINT64:
  //       break;
  //     default:
  //       assert(!"Unknown type");
  //   };

  //   printf("%s %s %d", field->type_name(), field->full_name().c_str(),
  //   field->type());
  //   if (field->is_repeated()) {
  //     int s = reflection->FieldSize(*message, field);
  //     printf(" %d", s);
  //   } else {
  //     if (reflection->HasField(*message, field)) {
  //     }
  //   }
  //   printf("\n");
  // }

  return false;
}

bool ProtobufMutator::CrossOver(const Message& with, Message* message) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field, int32_t* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field,
                                  int64_t* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field,
                                  uint32_t* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field,
                                  uint64_t* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field, double* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field, float* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field, bool* value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field,
                                  const EnumValueDescriptor** value) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field,
                                  Message* value) {
  return false;
}

bool ProtobufMutator::GetRandom(size_t n, size_t m) {
  assert(n <= m);
  return std::uniform_int_distribution<size_t>(1, m)(rng_) <= n;
}

size_t ProtobufMutator::GetRandomIndex(size_t count) {
  assert(count > 0);
  return std::uniform_int_distribution<size_t>(0, count - 1)(rng_);
}
