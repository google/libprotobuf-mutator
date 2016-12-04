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

#include <algorithm>
#include <iostream>
#include <map>
#include <random>
#include <string>

#include "google/protobuf/message.h"
#include "google/protobuf/text_format.h"
#include "weighted_reservoir_sampler.h"

using google::protobuf::Descriptor;
using google::protobuf::EnumDescriptor;
using google::protobuf::EnumValueDescriptor;
using google::protobuf::FieldDescriptor;
using google::protobuf::Message;
using google::protobuf::OneofDescriptor;
using google::protobuf::Reflection;
using google::protobuf::TextFormat;

namespace {

const int kMaxInitializeDepth = 32;

enum class Mutation {
  None,
  Add,     // Adds new field with default value.
  Mutate,  // Mutates field contents.
  Delete,  // Deletes field.

  // TODO:
  Clone,  // Adds new field with value copied from another field.
  Copy,   // Copy values copied from another field.
  Swap,   // Swap values of two fields.
};

// Flips random bit in the buffer.
void FlipBit(size_t size, uint8_t* bytes,
             ProtobufMutator::RandomEngine* random) {
  size_t bit = std::uniform_int_distribution<size_t>(0, size * 8 - 1)(*random);
  bytes[bit / 8] ^= (1u << (bit % 8));
}

// Flips random bit in the value.
template <class T>
T FlipBit(T value, ProtobufMutator::RandomEngine* random) {
  FlipBit(sizeof(value), reinterpret_cast<uint8_t*>(&value), random);
  return value;
}

// Return random integer from [0, count)
size_t GetRandomIndex(ProtobufMutator::RandomEngine* random, size_t count) {
  assert(count > 0);
  return std::uniform_int_distribution<size_t>(0, count - 1)(*random);
}

// Helper to mutate fields of proto message.
class FieldMutator {
 public:
  FieldMutator(size_t allowed_growth, ProtobufMutator* mutator,
               ProtobufMutator::RandomEngine* random, Message* message,
               const FieldDescriptor& field)
      : allowed_growth_(allowed_growth),
        mutator_(mutator),
        message_(message),
        field_(field),
        random_(random) {
    assert(mutator_);
    assert(message_);
    assert(random_);
  }

  void CreateDefaultField();
  void MutateField();
  void DeleteField();

 private:
  void CreateDefaultRepeatedField();
  void AddDefaultRepeatedField();
  void MutateRepeatedField();
  void DeleteRepeatedField();

  size_t allowed_growth_;
  ProtobufMutator* mutator_;
  Message* message_;
  const FieldDescriptor& field_;
  ProtobufMutator::RandomEngine* random_;
};

void FieldMutator::CreateDefaultField() {
  if (field_.is_repeated()) return CreateDefaultRepeatedField();
  const Reflection* reflection = message_->GetReflection();

  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      return reflection->SetInt32(message_, &field_,
                                  field_.default_value_int32());
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->SetInt64(message_, &field_,
                                  field_.default_value_int64());
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->SetUInt32(message_, &field_,
                                   field_.default_value_uint32());
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->SetUInt64(message_, &field_,
                                   field_.default_value_uint64());
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->SetDouble(message_, &field_,
                                   field_.default_value_double());
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->SetFloat(message_, &field_,
                                  field_.default_value_float());
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->SetBool(message_, &field_,
                                 field_.default_value_bool());
    case FieldDescriptor::CPPTYPE_ENUM:
      return reflection->SetEnum(message_, &field_,
                                 field_.default_value_enum());
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->SetString(message_, &field_,
                                   field_.default_value_string());
    case FieldDescriptor::CPPTYPE_MESSAGE: {
      return reflection->MutableMessage(message_, &field_)->Clear();
    }
    default:
      assert(!"Unknown type");
  };
}

void FieldMutator::CreateDefaultRepeatedField() {
  assert(field_.is_repeated());
  const Reflection* reflection = message_->GetReflection();
  AddDefaultRepeatedField();
  int field_size = reflection->FieldSize(*message_, &field_);
  if (field_size == 1) return;

  int index = GetRandomIndex(random_, field_size);
  // API has only method to add field to the end of the list. So we add field
  // and move it into the middle.
  for (int i = field_size - 1; i > index; --i)
    reflection->SwapElements(message_, &field_, i, i - 1);
}

void FieldMutator::AddDefaultRepeatedField() {
  assert(field_.is_repeated());

  const Reflection* reflection = message_->GetReflection();

  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      return reflection->AddInt32(message_, &field_,
                                  field_.default_value_int32());
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->AddInt64(message_, &field_,
                                  field_.default_value_int64());
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->AddUInt32(message_, &field_,
                                   field_.default_value_uint32());
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->AddUInt64(message_, &field_,
                                   field_.default_value_uint64());
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->AddDouble(message_, &field_,
                                   field_.default_value_double());
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->AddFloat(message_, &field_,
                                  field_.default_value_float());
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->AddBool(message_, &field_,
                                 field_.default_value_bool());
    case FieldDescriptor::CPPTYPE_ENUM:
      return reflection->AddEnum(message_, &field_,
                                 field_.default_value_enum());
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->AddString(message_, &field_,
                                   field_.default_value_string());
    case FieldDescriptor::CPPTYPE_MESSAGE: {
      reflection->AddMessage(message_, &field_);
      return;
    }
    default:
      assert(!"Unknown type");
  };
}

void FieldMutator::MutateField() {
  if (field_.is_repeated()) return MutateRepeatedField();
  const Reflection* reflection = message_->GetReflection();
  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      return reflection->SetInt32(
          message_, &field_,
          mutator_->MutateInt32(reflection->GetInt32(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->SetInt64(
          message_, &field_,
          mutator_->MutateInt64(reflection->GetInt64(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->SetUInt32(
          message_, &field_,
          mutator_->MutateUInt32(reflection->GetUInt32(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->SetUInt64(
          message_, &field_,
          mutator_->MutateUInt64(reflection->GetUInt64(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->SetDouble(
          message_, &field_,
          mutator_->MutateDouble(reflection->GetDouble(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->SetFloat(
          message_, &field_,
          mutator_->MutateFloat(reflection->GetFloat(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->SetBool(
          message_, &field_,
          mutator_->MutateBool(reflection->GetBool(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_ENUM: {
      const EnumValueDescriptor* value =
          reflection->GetEnum(*message_, &field_);
      const EnumDescriptor* type = value->type();
      return reflection->SetEnum(message_, &field_,
                                 type->value(mutator_->MutateEnum(
                                     value->index(), type->value_count())));
    }
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->SetString(
          message_, &field_,
          mutator_->MutateString(reflection->GetString(*message_, &field_),
                                 allowed_growth_));
    case FieldDescriptor::CPPTYPE_MESSAGE:
      assert(!"Don't mutate messages");
      return;
    default:
      assert(!"Unknown type");
  };
}

void FieldMutator::MutateRepeatedField() {
  assert(field_.is_repeated());
  const Reflection* reflection = message_->GetReflection();

  int index =
      GetRandomIndex(random_, reflection->FieldSize(*message_, &field_));
  switch (field_.cpp_type()) {
    case FieldDescriptor::CPPTYPE_INT32:
      return reflection->SetRepeatedInt32(
          message_, &field_, index,
          mutator_->MutateInt32(
              reflection->GetRepeatedInt32(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->SetRepeatedInt64(
          message_, &field_, index,
          mutator_->MutateInt64(
              reflection->GetRepeatedInt64(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->SetRepeatedUInt32(
          message_, &field_, index,
          mutator_->MutateUInt32(
              reflection->GetRepeatedUInt32(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->SetRepeatedUInt64(
          message_, &field_, index,
          mutator_->MutateUInt64(
              reflection->GetRepeatedUInt64(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->SetRepeatedDouble(
          message_, &field_, index,
          mutator_->MutateDouble(
              reflection->GetRepeatedDouble(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->SetRepeatedFloat(
          message_, &field_, index,
          mutator_->MutateFloat(
              reflection->GetRepeatedFloat(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->SetRepeatedBool(
          message_, &field_, index,
          mutator_->MutateBool(
              reflection->GetRepeatedBool(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_ENUM: {
      const EnumValueDescriptor* value =
          reflection->GetRepeatedEnum(*message_, &field_, index);
      const EnumDescriptor* type = value->type();
      return reflection->SetRepeatedEnum(
          message_, &field_, index,
          type->value(
              mutator_->MutateEnum(value->index(), type->value_count())));
    }
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->SetRepeatedString(
          message_, &field_, index,
          mutator_->MutateString(
              reflection->GetRepeatedString(*message_, &field_, index),
              allowed_growth_));
    case FieldDescriptor::CPPTYPE_MESSAGE:
      assert(!"Don't mutate messages");
      return;
    default:
      assert(!"Unknown type");
  };
}

void FieldMutator::DeleteField() {
  if (field_.is_repeated()) return DeleteRepeatedField();
  message_->GetReflection()->ClearField(message_, &field_);
}

void FieldMutator::DeleteRepeatedField() {
  assert(field_.is_repeated());
  const Reflection* reflection = message_->GetReflection();
  int field_size = reflection->FieldSize(*message_, &field_);
  int index = GetRandomIndex(random_, field_size);
  // API has only method to delete the last message, so we move method from the
  // middle to the end.
  for (int i = index + 1; i < field_size; ++i)
    reflection->SwapElements(message_, &field_, i, i - 1);
  reflection->RemoveLast(message_, &field_);
}

// Selects random field and mutation from the given proto message.
class MutationSampler {
 public:
  MutationSampler(bool keep_initialized, float current_usage,
                  ProtobufMutator::RandomEngine* random, Message* message)
      : keep_initialized_(keep_initialized), random_(random), sampler_(random) {
    if (current_usage > 0.5) {
      // Avoid adding new field and prefer deleting fields if we getting close
      // to the limit.
      add_weight_ *= 1 - current_usage;
      delete_weight_ *= current_usage;
    }
    Sample(message);
  }

  // Returns selected field.
  const FieldDescriptor* field() const { return sampler_.GetSelected().field; }

  // Returns the message containing selected field.
  Message* message() const { return sampler_.GetSelected().message; }

  // Returns selected mutation.
  Mutation mutation() const { return sampler_.GetSelected().mutation; }

 private:
  void Sample(Message* message) {
    const Descriptor* descriptor = message->GetDescriptor();
    const Reflection* reflection = message->GetReflection();

    int field_count = descriptor->field_count();
    for (int i = 0; i < field_count; ++i) {
      const FieldDescriptor* field = descriptor->field(i);
      if (const OneofDescriptor* oneof = field->containing_oneof()) {
        // Handle entire oneof group on the first field.
        if (field->index_in_oneof() == 0) {
          sampler_.Try(
              add_weight_,

              {message,
               oneof->field(GetRandomIndex(random_, oneof->field_count())),
               Mutation::Add});

          if (const FieldDescriptor* field =
                  reflection->GetOneofFieldDescriptor(*message, oneof)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE)
              sampler_.Try(kMutateWeight, {message, field, Mutation::Mutate});
            sampler_.Try(delete_weight_, {message, field, Mutation::Delete});
          }
        }
      } else {
        if (field->is_repeated()) {
          sampler_.Try(add_weight_, {message, field, Mutation::Add});

          if (reflection->FieldSize(*message, field)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE)
              sampler_.Try(kMutateWeight, {message, field, Mutation::Mutate});
            sampler_.Try(delete_weight_, {message, field, Mutation::Delete});
          }
        } else {
          if (reflection->HasField(*message, field)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE)
              sampler_.Try(kMutateWeight, {message, field, Mutation::Mutate});
            if ((!field->is_required() || !keep_initialized_))
              sampler_.Try(delete_weight_, {message, field, Mutation::Delete});
          } else {
            sampler_.Try(add_weight_, {message, field, Mutation::Add});
          }
        }
      }

      if (field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE) {
        if (field->is_repeated()) {
          const int field_size = reflection->FieldSize(*message, field);
          for (int j = 0; j < field_size; ++j)
            Sample(reflection->MutableRepeatedMessage(message, field, j));
        } else if (reflection->HasField(*message, field)) {
          Sample(reflection->MutableMessage(message, field));
        }
      }
    }
  }

  bool keep_initialized_ = false;
  const uint64_t kMutateWeight = 1000000;

  // Adding and deleting are intrusive and expensive mutations, we'd like to do
  // them less often that field mutations.
  uint64_t add_weight_ = kMutateWeight / 10;
  uint64_t delete_weight_ = kMutateWeight / 10;

  ProtobufMutator::RandomEngine* random_;

  struct Result {
    Message* message;
    const FieldDescriptor* field;
    Mutation mutation;
  };
  WeightedReservoirSampler<Result, ProtobufMutator::RandomEngine> sampler_;
};

}  // namespace

ProtobufMutator::ProtobufMutator(uint32_t seed, bool keep_initialized)
    : random_(seed), keep_initialized_(keep_initialized) {}

bool ProtobufMutator::Mutate(Message* message, size_t current_size,
                             size_t max_size) {
  assert(max_size);
  MutationSampler mutation(
      keep_initialized_, current_size / std::max<float>(current_size, max_size),
      &random_, message);
  if (mutation.mutation() == Mutation::None) {
    return false;
  }
  assert(mutation.field());
  assert(mutation.message());

  size_t allowed_growth = (std::max(max_size, current_size) - current_size) / 4;
  FieldMutator field_mutator(allowed_growth, this, &random_, mutation.message(),
                             *mutation.field());

  switch (mutation.mutation()) {
    case Mutation::None:
      break;
    case Mutation::Add:
      field_mutator.CreateDefaultField();
      break;
    case Mutation::Mutate:
      field_mutator.MutateField();
      break;
    case Mutation::Delete:
      field_mutator.DeleteField();
      break;
    default:
      assert(!"unexpected mutation");
  }

  if (keep_initialized_ && !message->IsInitialized()) {
    InitializeMessage(message, kMaxInitializeDepth);
    assert(message->IsInitialized());
  }

  return false;
}

bool ProtobufMutator::CrossOver(const Message& with, Message* message) {
  // TODO
  return false;
}

void ProtobufMutator::InitializeMessage(Message* message, int max_depth) {
  assert(keep_initialized_);
  const Descriptor* descriptor = message->GetDescriptor();
  const Reflection* reflection = message->GetReflection();
  for (int i = 0; i < descriptor->field_count(); ++i) {
    const FieldDescriptor* field = descriptor->field(i);
    if (field->is_required() && !reflection->HasField(*message, field)) {
      FieldMutator field_mutator(0, this, &random_, message, *field);
      field_mutator.CreateDefaultField();
    }

    if (max_depth > 0 &&
        field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE) {
      if (field->is_repeated()) {
        const int field_size = reflection->FieldSize(*message, field);
        for (int j = 0; j < field_size; ++j) {
          Message* nested_message =
              reflection->MutableRepeatedMessage(message, field, j);
          if (!nested_message->IsInitialized())
            InitializeMessage(nested_message, max_depth - 1);
        }
      } else if (reflection->HasField(*message, field)) {
        Message* nested_message = reflection->MutableMessage(message, field);
        if (!nested_message->IsInitialized())
          InitializeMessage(nested_message, max_depth - 1);
      }
    }
  }
}

int32_t ProtobufMutator::MutateInt32(int32_t value) {
  return FlipBit(value, &random_);
}

int64_t ProtobufMutator::MutateInt64(int64_t value) {
  return FlipBit(value, &random_);
}

uint32_t ProtobufMutator::MutateUInt32(uint32_t value) {
  return FlipBit(value, &random_);
}

uint64_t ProtobufMutator::MutateUInt64(uint64_t value) {
  return FlipBit(value, &random_);
}

float ProtobufMutator::MutateFloat(float value) {
  return FlipBit(value, &random_);
}

double ProtobufMutator::MutateDouble(double value) {
  return FlipBit(value, &random_);
}

bool ProtobufMutator::MutateBool(bool value) {
  return std::uniform_int_distribution<uint8_t>(0, 1)(random_);
}

size_t ProtobufMutator::MutateEnum(size_t index, size_t item_count) {
  return (index +
          std::uniform_int_distribution<uint8_t>(1, item_count - 1)(random_)) %
         item_count;
}

std::string ProtobufMutator::MutateString(const std::string& value,
                                          size_t allowed_growth) {
  std::string result = value;
  size_t max_size = result.size() + allowed_growth;
  int min_diff = result.empty() ? 0 : -1;
  int max_diff = allowed_growth ? 1 : 0;
  int diff = std::uniform_int_distribution<int>(min_diff, max_diff)(random_);
  result.resize(result.size() + diff, 0);
  if (!result.empty())
    FlipBit(result.size(), reinterpret_cast<uint8_t*>(&result[0]), &random_);
  return result;
}
