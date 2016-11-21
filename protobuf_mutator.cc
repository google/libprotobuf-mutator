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
#include "google/protobuf/text_format.h"

using google::protobuf::Descriptor;
using google::protobuf::EnumDescriptor;
using google::protobuf::EnumValueDescriptor;
using google::protobuf::FieldDescriptor;
using google::protobuf::Message;
using google::protobuf::OneofDescriptor;
using google::protobuf::Reflection;
using google::protobuf::TextFormat;

namespace {

const size_t kMaxStackSize = 32;

const size_t kAddWeight = 1;
const size_t kDeleteWeight = 1;
const size_t kUpdateWeight = 4;
const size_t kSwapWeight = 4;
const size_t kReplaceWeight = 1;

enum class Mutation {
  None,
  Add,
  AddRepeated,
  Mutate,
  MutateRepeated,
  Delete,
  DeleteRepeated,
  // Mutate,
  // Swap,
  // Replace,
};

std::map<std::string, int> stat;

class FieldMutator {
 public:
  FieldMutator(ProtobufMutator* mutator, Message* message,
               const FieldDescriptor& field, std::mt19937_64* rng)
      : mutator_(mutator), message_(message), field_(field), rng_(rng) {}

  bool CreateField(size_t additional_size);
  bool CreateRepeatedField(size_t additional_size);
  bool MutateField(size_t additional_size);

  // bool MutateRepeatedField(size_t additional_size)

  bool DeleteField();
  bool DeleteRepeatedField();

 private:
  template <class T>
  T Mutate(T v) {
    size_t s = mutator_->Mutate(&v, sizeof(v), sizeof(v));
    assert(s <= sizeof(v));
    memset(reinterpret_cast<uint8_t*>(&v) + s, 0, sizeof(v) - s);
    return v;
  }

  bool MutateBool(bool v);
  const EnumValueDescriptor* MutateEnum(const EnumValueDescriptor* v);
  std::string MutateString(const std::string& v, size_t additional_size);

  ProtobufMutator* mutator_;
  Message* message_;
  const FieldDescriptor& field_;
  std::mt19937_64* rng_;
};

bool FieldMutator::MutateBool(bool v) {
  return std::uniform_int_distribution<int>(0, 1)(*rng_) != 0;
}

const EnumValueDescriptor* FieldMutator::MutateEnum(
    const EnumValueDescriptor* v) {
  const EnumDescriptor* type = v->type();
  return type->value(
      std::uniform_int_distribution<int>(0, type->value_count() - 1)(*rng_));
}

std::string FieldMutator::MutateString(const std::string& v,
                                       size_t additional_size) {
  std::string result;
  size_t max_size = additional_size + v.size();
  if (!max_size) return result;
  result.resize(max_size);
  result.resize(mutator_->Mutate(&result[0], result.size(), max_size));
  return result;
}

bool FieldMutator::CreateField(size_t additional_size) {
  const Reflection* reflection = message_->GetReflection();

  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      reflection->SetInt32(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_int32()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_INT64:
      reflection->SetInt64(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_int64()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_UINT32:
      reflection->SetUInt32(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_uint32()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_UINT64:
      reflection->SetUInt64(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_uint64()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_DOUBLE:
      reflection->SetDouble(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_double()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_FLOAT:
      reflection->SetFloat(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_float()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_BOOL:
      reflection->SetBool(
          message_, &field_,
          Mutate(field_.has_default_value() && field_.default_value_bool()));
      break;
    case FieldDescriptor::CPPTYPE_ENUM:
      reflection->SetEnum(message_, &field_,
                          MutateEnum(field_.has_default_value()
                                         ? field_.default_value_enum()
                                         : field_.enum_type()->value(0)));
      break;
    case FieldDescriptor::CPPTYPE_STRING:
      reflection->SetString(message_, &field_,
                            MutateString(field_.has_default_value()
                                             ? field_.default_value_string()
                                             : std::string(),
                                         additional_size));
      break;
    case FieldDescriptor::CPPTYPE_MESSAGE: {
      Message* new_message = reflection->MutableMessage(message_, &field_);
      new_message->Clear();
      mutator_->Mutate(new_message, 0, additional_size);
      break;
    }
    default:
      assert(!"Unknown type");
      return false;
  };
  return true;
}

bool FieldMutator::CreateRepeatedField(size_t additional_size) {
  const Reflection* reflection = message_->GetReflection();

  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      reflection->AddInt32(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_int32()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_INT64:
      reflection->AddInt64(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_int64()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_UINT32:
      reflection->AddUInt32(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_uint32()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_UINT64:
      reflection->AddUInt64(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_uint64()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_DOUBLE:
      reflection->AddDouble(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_double()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_FLOAT:
      reflection->AddFloat(
          message_, &field_,
          Mutate(field_.has_default_value() ? field_.default_value_float()
                                            : 0));
      break;
    case FieldDescriptor::CPPTYPE_BOOL:
      reflection->AddBool(
          message_, &field_,
          Mutate(field_.has_default_value() && field_.default_value_bool()));
      break;
    case FieldDescriptor::CPPTYPE_ENUM:
      reflection->AddEnum(message_, &field_,
                          MutateEnum(field_.has_default_value()
                                         ? field_.default_value_enum()
                                         : field_.enum_type()->value(0)));
      break;
    case FieldDescriptor::CPPTYPE_STRING:
      reflection->AddString(message_, &field_,
                            MutateString(field_.has_default_value()
                                             ? field_.default_value_string()
                                             : std::string(),
                                         additional_size));
      break;
    case FieldDescriptor::CPPTYPE_MESSAGE: {
      Message* new_message = reflection->AddMessage(message_, &field_);
      mutator_->Mutate(new_message, 0, additional_size);
      break;
    }
    default:
      assert(!"Unknown type");
      return false;
  };
  return true;
}

bool FieldMutator::MutateField(size_t additional_size) {
  const Reflection* reflection = message_->GetReflection();

  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      reflection->SetInt32(message_, &field_,
                           Mutate(reflection->GetInt32(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_INT64:
      reflection->SetInt64(message_, &field_,
                           Mutate(reflection->GetInt64(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_UINT32:
      reflection->SetUInt32(message_, &field_,
                            Mutate(reflection->GetUInt32(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_UINT64:
      reflection->SetUInt64(message_, &field_,
                            Mutate(reflection->GetUInt64(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_DOUBLE:
      reflection->SetDouble(message_, &field_,
                            Mutate(reflection->GetDouble(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_FLOAT:
      reflection->SetFloat(message_, &field_,
                           Mutate(reflection->GetFloat(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_BOOL:
      reflection->SetBool(message_, &field_,
                          MutateBool(reflection->GetBool(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_ENUM:
      reflection->SetEnum(message_, &field_,
                          MutateEnum(reflection->GetEnum(*message_, &field_)));
      break;
    case FieldDescriptor::CPPTYPE_STRING:
      reflection->SetString(
          message_, &field_,
          MutateString(reflection->GetString(*message_, &field_),
                       additional_size));
      break;
    case FieldDescriptor::CPPTYPE_MESSAGE:
      mutator_->Mutate(reflection->MutableMessage(message_, &field_), 0,
                       additional_size);
      break;
    default:
      assert(!"Unknown type");
      return false;
  };
  return true;
}

// bool FieldMutator::MutateRepeatedField() {
//   const Reflection* reflection = message_->GetReflection();

//   switch (field_.cpp_type()) {
//     case FieldDescriptor::CPPTYPE_INT32:
//       reflection->AddInt32(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_int32() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_INT64:
//       reflection->AddInt64(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_int64() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_UINT32:
//       reflection->AddUInt32(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_uint32() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_UINT64:
//       reflection->AddUInt64(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_uint64() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_DOUBLE:
//       reflection->AddDouble(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_double() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_FLOAT:
//       reflection->AddFloat(
//           message_, &field_,
//           field_.has_default_value() ? field_.default_value_float() : 0);
//       break;
//     case FieldDescriptor::CPPTYPE_BOOL:
//       reflection->AddBool(message_, &field_, field_.has_default_value() &&
//                                                  field_.default_value_bool());
//       break;
//     case FieldDescriptor::CPPTYPE_ENUM:
//       reflection->AddEnum(message_, &field_,
//                           field_.has_default_value()
//                               ? field_.default_value_enum()
//                               : field_.enum_type()->value(0));
//       break;
//     case FieldDescriptor::CPPTYPE_STRING:
//       reflection->AddString(message_, &field_,
//                             field_.has_default_value()
//                                 ? field_.default_value_string()
//                                 : std::string());
//       break;
//     case FieldDescriptor::CPPTYPE_MESSAGE:
//       reflection->AddMessage(message_, &field_);
//       break;
//     default:
//       assert(!"Unknown type");
//       return false;
//   };
//   return true;
// }

bool FieldMutator::DeleteField() {
  message_->GetReflection()->ClearField(message_, &field_);
  return true;
}

bool FieldMutator::DeleteRepeatedField() {
  message_->GetReflection()->RemoveLast(message_, &field_);
  return true;
}

class WeightedReservoirSampler {
 public:
  explicit WeightedReservoirSampler(std::mt19937_64* rng) : rng_(rng) {}

  bool Pick(int weight) {
    total_weight_ += weight;
    if (weight == total_weight_) return true;
    assert(weight < total_weight_);
    return std::uniform_int_distribution<int>(1, total_weight_)(*rng_) <=
           weight;
  }

 private:
  int total_weight_ = 0;
  std::mt19937_64* rng_;
};

class ScopedStackUpdater {
 public:
  ScopedStackUpdater(
      std::vector<std::pair<const google::protobuf::FieldDescriptor*, int>>*
          stack,
      const google::protobuf::FieldDescriptor* field, int index)
      : stack_(stack) {
    stack_->push_back({field, index});
  }

  ~ScopedStackUpdater() { stack_->pop_back(); }

 private:
  std::vector<std::pair<const google::protobuf::FieldDescriptor*, int>>* stack_;
};

}  // namespace

ProtobufMutator::ProtobufMutator(uint32_t seed, bool always_initialized)
    : rng_(seed), always_initialized_(always_initialized) {}

ProtobufMutator::~ProtobufMutator() {
  // for (const auto& p : stat) {
  //   std::cout << p.first << "\t" << p.second << std::endl;
  // }
}

bool ProtobufMutator::Mutate(Message* message, size_t current_size,
                             size_t max_size) {
  // size

  const Descriptor* descriptor = message->GetDescriptor();
  const Reflection* reflection = message->GetReflection();
  // reflection->ListFields

  const FieldDescriptor* selected_field = nullptr;

  // Pick field to mutate.
  {
    WeightedReservoirSampler field_sampler(&rng_);
    for (int i = 0; i < descriptor->field_count(); ++i) {
      const FieldDescriptor* field = descriptor->field(i);
      stat[field->full_name()];

      // Select entire oneof group with probability of single field.
      if (field->containing_oneof() && field->index_in_oneof() != 0) continue;

      if (field_sampler.Pick(1)) selected_field = field;

      // assert(!field->is_repeated() || !field->containing_oneof());
      // assert(field->is_optional() || !field->containing_oneof());
      // assert(!field->is_required() || !field->containing_oneof());

      // if (field->is_required()) {

      // } else if field->is_optional() {

      // } else if field->is_optional() {

      // if (field->is_repeated() ||
      //     (!field->is_repeated() && !reflection->HasField(*message, field))
      //     ||
      //     (!field->is_repeated() && !reflection->HasField(*message, field)))
      //     {

      // }
    }
  }

  assert(selected_field);

  Mutation mutation = Mutation::None;
  int selected_index = 0;

  WeightedReservoirSampler mutation_sampler(&rng_);
  if (const OneofDescriptor* oneof = selected_field->containing_oneof()) {
    if (mutation_sampler.Pick(1)) {
      selected_field = oneof->field(GetRandomIndex(oneof->field_count()));
      mutation = Mutation::Add;
    }

    if (const FieldDescriptor* active_field =
            reflection->GetOneofFieldDescriptor(*message, oneof)) {
      // if (Pick(oneof->field_count())) {
      //   selected_field = active_field;
      //   mutation = Mutation::Mutate;
      // }
      if (mutation_sampler.Pick(1)) {
        selected_field = active_field;
        mutation = Mutation::Delete;
      }
    }
  } else {
    if (selected_field->is_repeated()) {
      if (mutation_sampler.Pick(1)) mutation = Mutation::AddRepeated;
      if (int field_size = reflection->FieldSize(*message, selected_field)) {
        selected_index = GetRandomIndex(field_size);
        if (mutation_sampler.Pick(1)) mutation = Mutation::DeleteRepeated;
        if (mutation_sampler.Pick(field_size))
          mutation = Mutation::MutateRepeated;
      }
    } else {
      if (reflection->HasField(*message, selected_field)) {
        if ((!selected_field->is_required() || always_initialized_) &&
            mutation_sampler.Pick(1))
          mutation = Mutation::Delete;
        if (mutation_sampler.Pick(1)) mutation = Mutation::Mutate;
      } else {
        if (mutation_sampler.Pick(1)) mutation = Mutation::Add;
      }
    }

    // if (!reflection->FieldSize(*message, selected_field)) {
    //   mutation = Mutation::AddRepeated;
    // } else if (!selected_field->is_repeated() && !)) {

    // }
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

  FieldMutator field_mutator(this, message, *selected_field, &rng_);
  size_t additional_size = (max_size - current_size) / 2;

  {
    ScopedStackUpdater stack_updated(&stack_, selected_field, selected_index);
    if (stack_.size() > kMaxStackSize) return false;

    assert(selected_field);
    switch (mutation) {
      case Mutation::None:
        break;
      case Mutation::Add:
        if (!field_mutator.CreateField(additional_size)) return false;
        break;
      case Mutation::AddRepeated:
        if (!field_mutator.CreateRepeatedField(additional_size)) return false;
        break;
      case Mutation::Mutate:
        if (!field_mutator.MutateField(additional_size)) return false;
        break;
      case Mutation::MutateRepeated:
        // if (!field_mutator.MutateRepeatedField()) return false;
        break;
      case Mutation::Delete:
        if (!field_mutator.DeleteField()) return false;
        break;
      case Mutation::DeleteRepeated:
        if (!field_mutator.DeleteRepeatedField()) return false;
        break;
      default:
        assert(!"unexpected mutation");
    }
  }

  if (stack_.empty() && always_initialized_ && !message->IsInitialized()) {
    InitializeMessage(message);

    std::string tmp_out;
    TextFormat::PrintToString(*message, &tmp_out);
    //    std::cout << tmp_out << " INIT \n";

    message->CheckInitialized();
  }

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

void ProtobufMutator::InitializeMessage(Message* message) {
  const Descriptor* descriptor = message->GetDescriptor();
  const Reflection* reflection = message->GetReflection();
  for (int i = 0; i < descriptor->field_count(); ++i) {
    const FieldDescriptor* field = descriptor->field(i);
    if (field->is_required()) {
      if (!reflection->HasField(*message, field)) {
        ScopedStackUpdater stack_updated(&stack_, field, 0);
        if (stack_.size() > kMaxStackSize) return;
        FieldMutator field_mutator(this, message, *field, &rng_);
        field_mutator.CreateField(0);
      }
    }

    if (field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE) {
      if (field->is_repeated()) {
        const int field_size = reflection->FieldSize(*message, field);
        for (int j = 0; j < field_size; ++j) {
          Message* nested_message =
              reflection->MutableRepeatedMessage(message, field, j);
          if (!nested_message->IsInitialized()) {
            ScopedStackUpdater stack_updated(&stack_, field, j);
            if (stack_.size() > kMaxStackSize) return;
            InitializeMessage(nested_message);
          }
        }
      } else if (reflection->HasField(*message, field)) {
        Message* nested_message = reflection->MutableMessage(message, field);
        if (!nested_message->IsInitialized()) {
          ScopedStackUpdater stack_updated(&stack_, field, 0);
          if (stack_.size() > kMaxStackSize) return;
          InitializeMessage(nested_message);
        }
      }
    }
  }
}

size_t ProtobufMutator::Mutate(void* data, size_t size, size_t max_size) {
  size_t new_size = GetRandomIndex(max_size + 1);
  std::uniform_int_distribution<uint8_t> distrib(0, 255);
  uint8_t* bytes = reinterpret_cast<uint8_t*>(data);
  for (int i = 0; i < new_size; ++i) bytes[i] = distrib(rng_);
  return new_size;
}

size_t ProtobufMutator::GetRandomIndex(size_t count) {
  assert(count > 0);
  return std::uniform_int_distribution<size_t>(0, count - 1)(rng_);
}
