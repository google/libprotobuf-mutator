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

#ifndef SRC_FIELD_INSTANCE_H_
#define SRC_FIELD_INSTANCE_H_

#include <memory>
#include <string>

#include <google/protobuf/message.h>

namespace protobuf_mutator {

// Helper class for common protobuf fields operations.
class FieldInstance {
 public:
  static const size_t kInvalidIndex = -1;

  struct Enum {
    size_t index;
    size_t count;
  };

  FieldInstance()
      : message_(nullptr), descriptor_(nullptr), index_(kInvalidIndex) {}

  FieldInstance(google::protobuf::Message* message,
                const google::protobuf::FieldDescriptor* field, size_t index)
      : message_(message), descriptor_(field), index_(index) {
    assert(message_);
    assert(descriptor_);
    assert(index_ != kInvalidIndex);
    assert(descriptor_->is_repeated());
  }

  FieldInstance(google::protobuf::Message* msg,
                const google::protobuf::FieldDescriptor* f)
      : message_(msg), descriptor_(f), index_(kInvalidIndex) {
    assert(message_);
    assert(descriptor_);
    assert(!descriptor_->is_repeated());
  }

  void Delete() const {
    if (!is_repeated()) return reflection().ClearField(message_, descriptor_);
    int field_size = reflection().FieldSize(*message_, descriptor_);
    // API has only method to delete the last message, so we move method from
    // the
    // middle to the end.
    for (int i = index_ + 1; i < field_size; ++i)
      reflection().SwapElements(message_, descriptor_, i, i - 1);
    reflection().RemoveLast(message_, descriptor_);
  }

  void GetDefault(int32_t* out) const {
    *out = descriptor_->default_value_int32();
  }

  void GetDefault(int64_t* out) const {
    *out = descriptor_->default_value_int64();
  }

  void GetDefault(uint32_t* out) const {
    *out = descriptor_->default_value_uint32();
  }

  void GetDefault(uint64_t* out) const {
    *out = descriptor_->default_value_uint64();
  }

  void GetDefault(double* out) const {
    *out = descriptor_->default_value_double();
  }

  void GetDefault(float* out) const {
    *out = descriptor_->default_value_float();
  }

  void GetDefault(bool* out) const { *out = descriptor_->default_value_bool(); }

  void GetDefault(Enum* out) const {
    const google::protobuf::EnumValueDescriptor* value =
        descriptor_->default_value_enum();
    const google::protobuf::EnumDescriptor* type = value->type();
    *out = {static_cast<size_t>(value->index()),
            static_cast<size_t>(type->value_count())};
  }

  void GetDefault(std::string* out) const {
    *out = descriptor_->default_value_string();
  }

  void GetDefault(std::unique_ptr<google::protobuf::Message>* out) const {
    out->reset();
  }

  template <class T>
  void Create(const T& value) const {
    if (!is_repeated()) return Store(value);
    InsertRepeated(value);
  }

  void Load(int32_t* value) const {
    *value = is_repeated()
                 ? reflection().GetRepeatedInt32(*message_, descriptor_, index_)
                 : reflection().GetInt32(*message_, descriptor_);
  }

  void Load(int64_t* value) const {
    *value = is_repeated()
                 ? reflection().GetRepeatedInt64(*message_, descriptor_, index_)
                 : reflection().GetInt64(*message_, descriptor_);
  }

  void Load(uint32_t* value) const {
    *value =
        is_repeated()
            ? reflection().GetRepeatedUInt32(*message_, descriptor_, index_)
            : reflection().GetUInt32(*message_, descriptor_);
  }

  void Load(uint64_t* value) const {
    *value =
        is_repeated()
            ? reflection().GetRepeatedUInt64(*message_, descriptor_, index_)
            : reflection().GetUInt64(*message_, descriptor_);
  }

  void Load(double* value) const {
    *value =
        is_repeated()
            ? reflection().GetRepeatedDouble(*message_, descriptor_, index_)
            : reflection().GetDouble(*message_, descriptor_);
  }

  void Load(float* value) const {
    *value = is_repeated()
                 ? reflection().GetRepeatedFloat(*message_, descriptor_, index_)
                 : reflection().GetFloat(*message_, descriptor_);
  }

  void Load(bool* value) const {
    *value = is_repeated()
                 ? reflection().GetRepeatedBool(*message_, descriptor_, index_)
                 : reflection().GetBool(*message_, descriptor_);
  }

  void Load(Enum* value) const {
    const google::protobuf::EnumValueDescriptor* value_descriptor =
        is_repeated()
            ? reflection().GetRepeatedEnum(*message_, descriptor_, index_)
            : reflection().GetEnum(*message_, descriptor_);
    *value = {static_cast<size_t>(value_descriptor->index()),
              static_cast<size_t>(value_descriptor->type()->value_count())};
  }

  void Load(std::string* value) const {
    *value =
        is_repeated()
            ? reflection().GetRepeatedString(*message_, descriptor_, index_)
            : reflection().GetString(*message_, descriptor_);
  }

  void Load(std::unique_ptr<google::protobuf::Message>* value) const {
    const google::protobuf::Message& source =
        is_repeated()
            ? reflection().GetRepeatedMessage(*message_, descriptor_, index_)
            : reflection().GetMessage(*message_, descriptor_);
    value->reset(source.New());
    (*value)->CopyFrom(source);
  }

  void Store(int32_t value) const {
    if (is_repeated())
      reflection().SetRepeatedInt32(message_, descriptor_, index_, value);
    else
      reflection().SetInt32(message_, descriptor_, value);
  }

  void Store(int64_t value) const {
    if (is_repeated())
      reflection().SetRepeatedInt64(message_, descriptor_, index_, value);
    else
      reflection().SetInt64(message_, descriptor_, value);
  }

  void Store(uint32_t value) const {
    if (is_repeated())
      reflection().SetRepeatedUInt32(message_, descriptor_, index_, value);
    else
      reflection().SetUInt32(message_, descriptor_, value);
  }

  void Store(uint64_t value) const {
    if (is_repeated())
      reflection().SetRepeatedUInt64(message_, descriptor_, index_, value);
    else
      reflection().SetUInt64(message_, descriptor_, value);
  }

  void Store(double value) const {
    if (is_repeated())
      reflection().SetRepeatedDouble(message_, descriptor_, index_, value);
    else
      reflection().SetDouble(message_, descriptor_, value);
  }

  void Store(float value) const {
    if (is_repeated())
      reflection().SetRepeatedFloat(message_, descriptor_, index_, value);
    else
      reflection().SetFloat(message_, descriptor_, value);
  }

  void Store(bool value) const {
    if (is_repeated())
      reflection().SetRepeatedBool(message_, descriptor_, index_, value);
    else
      reflection().SetBool(message_, descriptor_, value);
  }

  void Store(const Enum& value) const {
    assert(value.index < value.count);
    const google::protobuf::EnumValueDescriptor* enum_value =
        descriptor_->enum_type()->value(value.index);
    if (is_repeated())
      reflection().SetRepeatedEnum(message_, descriptor_, index_, enum_value);
    else
      reflection().SetEnum(message_, descriptor_, enum_value);
  }

  void Store(const std::string& value) const {
    if (is_repeated())
      reflection().SetRepeatedString(message_, descriptor_, index_, value);
    else
      reflection().SetString(message_, descriptor_, value);
  }

  void Store(const std::unique_ptr<google::protobuf::Message>& value) const {
    google::protobuf::Message* mutable_message =
        is_repeated()
            ? reflection().MutableRepeatedMessage(message_, descriptor_, index_)
            : reflection().MutableMessage(message_, descriptor_);
    mutable_message->Clear();
    if (value) mutable_message->CopyFrom(*value);
  }

  google::protobuf::FieldDescriptor::CppType cpp_type() const {
    return descriptor_->cpp_type();
  }

  const google::protobuf::EnumDescriptor* enum_type() const {
    return descriptor_->enum_type();
  }

  const google::protobuf::Descriptor* message_type() const {
    return descriptor_->message_type();
  }

  template <class Transformation>
  void Apply(const Transformation& transformation) const {
    assert(descriptor_);
    using google::protobuf::FieldDescriptor;
    switch (cpp_type()) {
      case FieldDescriptor::CPPTYPE_INT32:
        return transformation.template Apply<int32_t>(*this);
      case FieldDescriptor::CPPTYPE_INT64:
        return transformation.template Apply<int64_t>(*this);
      case FieldDescriptor::CPPTYPE_UINT32:
        return transformation.template Apply<uint32_t>(*this);
      case FieldDescriptor::CPPTYPE_UINT64:
        return transformation.template Apply<uint64_t>(*this);
      case FieldDescriptor::CPPTYPE_DOUBLE:
        return transformation.template Apply<double>(*this);
      case FieldDescriptor::CPPTYPE_FLOAT:
        return transformation.template Apply<float>(*this);
      case FieldDescriptor::CPPTYPE_BOOL:
        return transformation.template Apply<bool>(*this);
      case FieldDescriptor::CPPTYPE_ENUM:
        return transformation.template Apply<FieldInstance::Enum>(*this);
      case FieldDescriptor::CPPTYPE_STRING:
        return transformation.template Apply<std::string>(*this);
      case FieldDescriptor::CPPTYPE_MESSAGE:
        return transformation
            .template Apply<std::unique_ptr<google::protobuf::Message>>(*this);
      default:
        assert(!"Unknown type");
    }
  }

 private:
  template <class T>
  void InsertRepeated(const T& value) const {
    PushBackRepeated(value);
    size_t field_size = reflection().FieldSize(*message_, descriptor_);
    if (field_size == 1) return;
    // API has only method to add field to the end of the list. So we add
    // descriptor_
    // and move it into the middle.
    for (size_t i = field_size - 1; i > index_; --i)
      reflection().SwapElements(message_, descriptor_, i, i - 1);
  }

  bool is_repeated() const { return descriptor_->is_repeated(); }

  void PushBackRepeated(int32_t value) const {
    assert(is_repeated());
    reflection().AddInt32(message_, descriptor_, value);
  }

  void PushBackRepeated(int64_t value) const {
    assert(is_repeated());
    reflection().AddInt64(message_, descriptor_, value);
  }

  void PushBackRepeated(uint32_t value) const {
    assert(is_repeated());
    reflection().AddUInt32(message_, descriptor_, value);
  }

  void PushBackRepeated(uint64_t value) const {
    assert(is_repeated());
    reflection().AddUInt64(message_, descriptor_, value);
  }

  void PushBackRepeated(double value) const {
    assert(is_repeated());
    reflection().AddDouble(message_, descriptor_, value);
  }

  void PushBackRepeated(float value) const {
    assert(is_repeated());
    reflection().AddFloat(message_, descriptor_, value);
  }

  void PushBackRepeated(bool value) const {
    assert(is_repeated());
    reflection().AddBool(message_, descriptor_, value);
  }

  void PushBackRepeated(const Enum& value) const {
    assert(value.index < value.count);
    const google::protobuf::EnumValueDescriptor* enum_value =
        descriptor_->enum_type()->value(value.index);
    assert(is_repeated());
    reflection().AddEnum(message_, descriptor_, enum_value);
  }

  void PushBackRepeated(const std::string& value) const {
    assert(is_repeated());
    reflection().AddString(message_, descriptor_, value);
  }

  void PushBackRepeated(
      const std::unique_ptr<google::protobuf::Message>& value) const {
    assert(is_repeated());
    google::protobuf::Message* mutable_message =
        reflection().AddMessage(message_, descriptor_);
    mutable_message->Clear();
    if (value) mutable_message->CopyFrom(*value);
  }

  const google::protobuf::Reflection& reflection() const {
    return *message_->GetReflection();
  }

  google::protobuf::Message* message_;
  const google::protobuf::FieldDescriptor* descriptor_;
  size_t index_;
};

}  // namespace protobuf_mutator

#endif  // SRC_FIELD_INSTANCE_H_
