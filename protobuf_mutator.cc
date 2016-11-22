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
  Add,
  Mutate,
  Delete,
};

class ProtobufMutatorDefaults : public ProtobufMutator::Customization {
 public:
  explicit ProtobufMutatorDefaults(uint32_t seed) : rng_(seed) {}

  size_t MutateBytes(void* data, size_t size, size_t max_size) override {
    size_t new_size = std::uniform_int_distribution<size_t>(0, max_size)(rng_);
    std::uniform_int_distribution<uint8_t> distrib(0, 255);
    uint8_t* bytes = reinterpret_cast<uint8_t*>(data);
    // for (int i = 0; i < new_size; ++i) bytes[i] = distrib(rng_);
    std::generate(bytes, bytes + new_size, std::bind(distrib, rng_));
    return new_size;
  }

 private:
  std::mt19937_64 rng_;
};

size_t GetRandomIndex(ProtobufMutator::RandomEngine* random, size_t count) {
  assert(count > 0);
  return std::uniform_int_distribution<size_t>(0, count - 1)(*random);
}

class FieldMutator {
 public:
  FieldMutator(size_t allowed_growth,
               ProtobufMutator::Customization* customization,
               ProtobufMutator::RandomEngine* random, Message* message,
               const FieldDescriptor& field)
      : allowed_growth_(allowed_growth),
        customization_(customization),
        message_(message),
        field_(field),
        random_(random) {
    assert(customization_);
    assert(message_);
    assert(random_);
  }

  void CreateDefaultField();
  void MutateField();
  void DeleteField();

 private:
  void CreateDefaultRepeatedField();
  void MutateRepeatedField();
  void DeleteRepeatedField();

  template <class T>
  T Mutate(T v) {
    size_t s = customization_->MutateBytes(&v, sizeof(v), sizeof(v));
    assert(s <= sizeof(v));
    memset(reinterpret_cast<uint8_t*>(&v) + s, 0, sizeof(v) - s);
    return v;
  }

  bool MutateBool(bool v);
  const EnumValueDescriptor* MutateEnum(const EnumValueDescriptor* v);
  std::string MutateString(const std::string& v, size_t allowed_growth);

  size_t allowed_growth_;
  ProtobufMutator::Customization* customization_;
  Message* message_;
  const FieldDescriptor& field_;
  ProtobufMutator::RandomEngine* random_;
};

bool FieldMutator::MutateBool(bool v) {
  return std::uniform_int_distribution<int>(0, 1)(*random_) != 0;
}

const EnumValueDescriptor* FieldMutator::MutateEnum(
    const EnumValueDescriptor* v) {
  const EnumDescriptor* type = v->type();
  return type->value(GetRandomIndex(random_, type->value_count()));
}

std::string FieldMutator::MutateString(const std::string& v,
                                       size_t allowed_growth) {
  std::string result;
  size_t max_size = allowed_growth + v.size();
  if (!max_size) return result;
  result.resize(max_size);
  result.resize(
      customization_->MutateBytes(&result[0], result.size(), max_size));
  return result;
}

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
          message_, &field_, Mutate(reflection->GetInt32(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->SetInt64(
          message_, &field_, Mutate(reflection->GetInt64(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->SetUInt32(
          message_, &field_, Mutate(reflection->GetUInt32(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->SetUInt64(
          message_, &field_, Mutate(reflection->GetUInt64(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->SetDouble(
          message_, &field_, Mutate(reflection->GetDouble(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->SetFloat(
          message_, &field_, Mutate(reflection->GetFloat(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->SetBool(
          message_, &field_,
          MutateBool(reflection->GetBool(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_ENUM:
      return reflection->SetEnum(
          message_, &field_,
          MutateEnum(reflection->GetEnum(*message_, &field_)));
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->SetString(
          message_, &field_,
          MutateString(reflection->GetString(*message_, &field_),
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
          Mutate(reflection->GetRepeatedInt32(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_INT64:
      return reflection->SetRepeatedInt64(
          message_, &field_, index,
          Mutate(reflection->GetRepeatedInt64(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_UINT32:
      return reflection->SetRepeatedUInt32(
          message_, &field_, index,
          Mutate(reflection->GetRepeatedUInt32(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_UINT64:
      return reflection->SetRepeatedUInt64(
          message_, &field_, index,
          Mutate(reflection->GetRepeatedUInt64(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_DOUBLE:
      return reflection->SetRepeatedDouble(
          message_, &field_, index,
          Mutate(reflection->GetRepeatedDouble(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_FLOAT:
      return reflection->SetRepeatedFloat(
          message_, &field_, index,
          Mutate(reflection->GetRepeatedFloat(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_BOOL:
      return reflection->SetRepeatedBool(
          message_, &field_, index,
          MutateBool(reflection->GetRepeatedBool(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_ENUM:
      return reflection->SetRepeatedEnum(
          message_, &field_, index,
          MutateEnum(reflection->GetRepeatedEnum(*message_, &field_, index)));
    case FieldDescriptor::CPPTYPE_STRING:
      return reflection->SetRepeatedString(
          message_, &field_, index,
          MutateString(reflection->GetRepeatedString(*message_, &field_, index),
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
  message_->GetReflection()->RemoveLast(message_, &field_);
}

class WeightedReservoirSampler {
 public:
  explicit WeightedReservoirSampler(ProtobufMutator::RandomEngine* random)
      : random_(random) {}

  bool Pick(uint64_t weight) {
    if (weight == 0) return false;
    total_weight_ += weight;
    if (weight == total_weight_) return true;
    return std::uniform_int_distribution<uint64_t>(
               1, total_weight_)(*random_) <= weight;
  }

  ProtobufMutator::RandomEngine* random() { return random_; }

 private:
  uint64_t total_weight_ = 0;
  ProtobufMutator::RandomEngine* random_;
};

class MutationSampler {
 public:
  MutationSampler(bool keep_initialized, float current_usage,
                  ProtobufMutator::RandomEngine* random, Message* message)
      : keep_initialized_(keep_initialized), sampler_(random) {
    if (current_usage > 0.5) {
      // Prefer deleting fields if we getting close to the limit.
      add_weight_ *= 1 - current_usage;
      delete_weight_ *= current_usage;
    }
    Sample(message);
  }

  void Sample(Message* message) {
    const Descriptor* descriptor = message->GetDescriptor();
    const Reflection* reflection = message->GetReflection();

    int field_count = descriptor->field_count();
    for (int i = 0; i < field_count; ++i) {
      const FieldDescriptor* field = descriptor->field(i);
      if (const OneofDescriptor* oneof = field->containing_oneof()) {
        // Handle entire oneof group on the first field.
        if (field->index_in_oneof() == 0) {
          if (sampler_.Pick(add_weight_)) {
            SetAddField(message, oneof->field(GetRandomIndex(
                                     sampler_.random(), oneof->field_count())));
          }

          if (const FieldDescriptor* field =
                  reflection->GetOneofFieldDescriptor(*message, oneof)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE &&
                sampler_.Pick(kMutateWeight)) {
              SetMutateField(message, field);
            }
            if (sampler_.Pick(delete_weight_)) SetDeleteField(message, field);
          }
        }
      } else {
        if (field->is_repeated()) {
          if (sampler_.Pick(add_weight_)) SetAddField(message, field);

          if (reflection->FieldSize(*message, field)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE &&
                sampler_.Pick(kMutateWeight)) {
              SetMutateField(message, field);
            }
            if (sampler_.Pick(delete_weight_)) SetDeleteField(message, field);
          }
        } else {
          if (reflection->HasField(*message, field)) {
            if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE &&
                sampler_.Pick(kMutateWeight)) {
              SetMutateField(message, field);
            }
            if ((!field->is_required() || !keep_initialized_) &&
                sampler_.Pick(delete_weight_)) {
              SetDeleteField(message, field);
            }
          } else {
            if (sampler_.Pick(add_weight_)) SetAddField(message, field);
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

  Message* message() const { return result_.message; }
  const FieldDescriptor* field() const { return result_.field; }
  Mutation mutation() const { return result_.mutation; }

 private:
  void SetAddField(Message* message, const FieldDescriptor* field) {
    result_.message = message;
    result_.field = field;
    result_.mutation = Mutation::Add;
  }

  void SetMutateField(Message* message, const FieldDescriptor* field) {
    result_.message = message;
    result_.field = field;
    result_.mutation = Mutation::Mutate;
  }

  void SetDeleteField(Message* message, const FieldDescriptor* field) {
    result_.message = message;
    result_.field = field;
    result_.mutation = Mutation::Delete;
  }

  bool keep_initialized_ = false;
  const uint64_t kMutateWeight = 1000000;
  uint64_t add_weight_ = kMutateWeight / 10;
  uint64_t delete_weight_ = kMutateWeight / 10;
  WeightedReservoirSampler sampler_;

  struct {
    Message* message = nullptr;
    const FieldDescriptor* field = nullptr;
    Mutation mutation = Mutation::None;
  } result_;
};

}  // namespace

ProtobufMutator::ProtobufMutator(uint32_t seed, bool keep_initialized,
                                 Customization* customization)
    : random_(seed),
      keep_initialized_(keep_initialized),
      customization_(customization) {
  if (!customization_) {
    defaults_.reset(new ProtobufMutatorDefaults(seed));
    customization_ = defaults_.get();
  }
}

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

  size_t allowed_growth =
      (std::max(max_size, current_size) - current_size) / 4;
  FieldMutator field_mutator(allowed_growth, customization_, &random_,
                             mutation.message(), *mutation.field());

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
  return false;
}

void ProtobufMutator::InitializeMessage(Message* message, int max_depth) {
  assert(keep_initialized_);
  const Descriptor* descriptor = message->GetDescriptor();
  const Reflection* reflection = message->GetReflection();
  for (int i = 0; i < descriptor->field_count(); ++i) {
    const FieldDescriptor* field = descriptor->field(i);
    if (field->is_required() && !reflection->HasField(*message, field)) {
      FieldMutator field_mutator(0, customization_, &random_, message, *field);
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
