#include "src/aflplusplus/aflplusplus_mutator.h"

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
#include <sanitizer/msan_interface.h>
#endif
#endif
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <algorithm>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "afl/alloc-inl.h"
#include "afl/config.h"
#include "port/protobuf.h"
#include "src/aflplusplus/aflplusplus_mutate_wrapper.h"
#include "src/mutation_io.h"

#define DEFINE_MUTATE_METHOD(Type, Name)   \
  Type Mutator::Mutate##Name(Type value) { \
    return MutateValue(value, afl_, this); \
  }

namespace protobuf_mutator {
namespace aflplusplus {

namespace {

using protobuf::Descriptor;
using protobuf::FieldDescriptor;
using protobuf::Message;
using protobuf::Reflection;

constexpr size_t kNoUnit = static_cast<size_t>(-1);
constexpr size_t kTrimGiveUpMin = 32;

class TrimWalker {
 public:
  explicit TrimWalker(size_t target) : target_(target) {}

  bool Walk(Message* message) {
    const Descriptor* descriptor = message->GetDescriptor();
    const Reflection* reflection = message->GetReflection();
    for (int i = 0; i < descriptor->field_count(); ++i) {
      const FieldDescriptor* field = descriptor->field(i);
      const bool is_message =
          field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE;
      if (field->is_repeated()) {
        for (int j = 0; j < reflection->FieldSize(*message, field); ++j) {
          if (Take()) {
            RemoveRepeated(reflection, message, field, j);
            return true;
          }
          if (is_message &&
              Walk(reflection->MutableRepeatedMessage(message, field, j)))
            return true;
        }
      } else if (reflection->HasField(*message, field)) {
        if (!field->is_required() && Take()) {
          reflection->ClearField(message, field);
          return true;
        }
        if (is_message && Walk(reflection->MutableMessage(message, field)))
          return true;
      }
    }
    return false;
  }

  size_t count() const { return index_; }

 private:
  bool Take() { return index_++ == target_; }

  static void RemoveRepeated(const Reflection* reflection, Message* message,
                             const FieldDescriptor* field, int index) {
    const int field_size = reflection->FieldSize(*message, field);
    for (int i = index + 1; i < field_size; ++i)
      reflection->SwapElements(message, field, i, i - 1);
    reflection->RemoveLast(message, field);
  }

  const size_t target_;
  size_t index_ = 0;
};

size_t CountTrimUnits(Message* message) {
  TrimWalker walker(kNoUnit);
  walker.Walk(message);
  return walker.count();
}

class ValueWalker {
 public:
  explicit ValueWalker(size_t target) : target_(target) {}

  bool Walk(Message* message) {
    const Descriptor* descriptor = message->GetDescriptor();
    const Reflection* reflection = message->GetReflection();
    for (int i = 0; i < descriptor->field_count(); ++i) {
      const FieldDescriptor* field = descriptor->field(i);
      const bool is_string =
          field->cpp_type() == FieldDescriptor::CPPTYPE_STRING;
      const bool is_message =
          field->cpp_type() == FieldDescriptor::CPPTYPE_MESSAGE;
      if (field->is_repeated()) {
        for (int j = 0; j < reflection->FieldSize(*message, field); ++j) {
          if (is_string) {
            if (Take(message, field, j)) return true;
          } else if (is_message &&
                     Walk(reflection->MutableRepeatedMessage(message, field,
                                                             j))) {
            return true;
          }
        }
      } else if (reflection->HasField(*message, field)) {
        if (is_string) {
          if (Take(message, field, -1)) return true;
        } else if (is_message &&
                   Walk(reflection->MutableMessage(message, field))) {
          return true;
        }
      }
    }
    return false;
  }

  size_t count() const { return index_; }

  std::string Get() const {
    const Reflection* reflection = message_->GetReflection();
    return element_ < 0
               ? reflection->GetString(*message_, field_)
               : reflection->GetRepeatedString(*message_, field_, element_);
  }

  void Set(const std::string& value) const {
    const Reflection* reflection = message_->GetReflection();
    if (element_ < 0)
      reflection->SetString(message_, field_, value);
    else
      reflection->SetRepeatedString(message_, field_, element_, value);
  }

  bool EnforceUtf8() const { return RequiresUtf8Validation(*field_); }

 private:
  bool Take(Message* message, const FieldDescriptor* field, int element) {
    if (index_++ != target_) return false;
    message_ = message;
    field_ = field;
    element_ = element;
    return true;
  }

  const size_t target_;
  size_t index_ = 0;
  Message* message_ = nullptr;
  const FieldDescriptor* field_ = nullptr;
  int element_ = -1;
};

size_t CountTrimValues(Message* message) {
  ValueWalker walker(kNoUnit);
  walker.Walk(message);
  return walker.count();
}

size_t NextPow2(size_t value) {
  size_t result = 1;
  while (result < value) result <<= 1;
  return result;
}

size_t ShrinkStart(size_t length) {
  return std::max<size_t>(NextPow2(length) / TRIM_START_STEPS, TRIM_MIN_BYTES);
}

size_t ShrinkEnd(size_t length) {
  return std::max<size_t>(NextPow2(length) / TRIM_END_STEPS, TRIM_MIN_BYTES);
}

size_t CountShrinkSteps(Message* message) {
  const size_t values = CountTrimValues(message);
  size_t steps = 0;
  for (size_t i = 0; i < values; ++i) {
    ValueWalker walker(i);
    if (!walker.Walk(message)) break;
    const size_t length = walker.Get().size();
    const size_t end = ShrinkEnd(length);
    for (size_t len = ShrinkStart(length); len >= end; len >>= 1)
      for (size_t pos = len; pos < length; pos += len) ++steps;
  }
  return steps;
}

constexpr int kMaxNesting = 100;

bool TooDeep(const Message& message, int budget) {
  if (budget < 0) return true;
  const Reflection* reflection = message.GetReflection();
  std::vector<const FieldDescriptor*> fields;
  reflection->ListFields(message, &fields);
  for (const FieldDescriptor* field : fields) {
    if (field->cpp_type() != FieldDescriptor::CPPTYPE_MESSAGE) continue;
    if (field->is_repeated()) {
      for (int i = 0; i < reflection->FieldSize(message, field); ++i) {
        if (TooDeep(reflection->GetRepeatedMessage(message, field, i),
                    budget - 1))
          return true;
      }
    } else if (TooDeep(reflection->GetMessage(message, field), budget - 1)) {
      return true;
    }
  }
  return false;
}

int ClampToInt(size_t value) {
  return static_cast<int>(
      std::min<size_t>(value, static_cast<size_t>(INT_MAX)));
}

template <class T>
T MutateValue(T v, void* afl, Mutator* mutator) {
  size_t size = aflplusplus_mutate_wrapper(
      afl, reinterpret_cast<uint8_t*>(&v), sizeof(v), mutator->GetRandom(1, 16),
      0 /*is_text*/, mutator->GetRandom(0, 1) /*is_exploration*/, nullptr, 0,
      sizeof(v));

  if (size < sizeof(v))
    memset(reinterpret_cast<uint8_t*>(&v) + size, 0, sizeof(v) - size);

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
  __msan_unpoison(&v, sizeof(v));
#endif
#endif

  return v;
}

}  // namespace

Mutator* Mutator::Create(void* afl_state, unsigned int seed, bool binary) {
  const char* only = getenv("AFL_CUSTOM_MUTATOR_ONLY");
  if (!only || !*only) {
    fprintf(stderr,
            "[-] protobuf-mutator-aflplusplus: set AFL_CUSTOM_MUTATOR_ONLY=1, "
            "the other mutation stages produce inputs this mutator cannot "
            "parse.\n");
    exit(1);
  }

  std::unique_ptr<Mutator> mutator(new Mutator(afl_state, binary));
  if (!mutator->Reserve(MAX_FILE)) {
    perror("afl_custom_init");
    return nullptr;
  }
  mutator->Seed(seed);
  return mutator.release();
}

Mutator::Mutator(void* afl_state, bool binary)
    : afl_(afl_state), binary_(binary) {}

Mutator::~Mutator() {
  if (out_buf_) afl_free(out_buf_);
  if (trim_buf_) afl_free(trim_buf_);
}

bool Mutator::Reserve(size_t size) {
  return afl_realloc(reinterpret_cast<void**>(&out_buf_),
                     std::max<size_t>(size, MAX_FILE)) != nullptr;
}

size_t Mutator::CopyToTrimBuffer(const std::string& data, uint8_t** out_buf) {
  if (!afl_realloc(reinterpret_cast<void**>(&trim_buf_),
                   std::max<size_t>(data.size(), 1)))
    return 0;
  memcpy(trim_buf_, data.data(), data.size());
  *out_buf = trim_buf_;
  return data.size();
}

size_t Mutator::Fuzz(const uint8_t* buf, size_t buf_size, uint8_t** out_buf,
                     const uint8_t* add_buf, size_t add_buf_size,
                     size_t max_size, protobuf::Message* input1,
                     protobuf::Message* input2) {
  *out_buf = const_cast<uint8_t*>(buf);

  size_t new_size = 0;
  if (!add_buf || !add_buf_size || GetRandom(1, 10) <= 5) {
    memcpy(out_buf_, buf, buf_size);
    new_size =
        MutateMessage(binary_, this, out_buf_, buf_size, max_size, input1);
  } else {
    new_size = CrossOverMessages(binary_, this, buf, buf_size, add_buf,
                                 add_buf_size, out_buf_, max_size, input1,
                                 input2);
  }

  if (!new_size) return 0;
  if (GetCache()->LoadIfSame(out_buf_, new_size, input1)) {
    if (TooDeep(*input1, kMaxNesting)) return 0;
    GetCache()->Store(out_buf_, new_size, input1);
  }

  *out_buf = out_buf_;
  return new_size;
}

int Mutator::InitTrim(const uint8_t* buf, size_t buf_size,
                      protobuf::Message* scratch) {
  trim_index_ = 0;
  trim_steps_ = 0;
  trim_progress_ = 0;
  trim_give_up_ = 0;
  trim_had_success_ = false;
  trim_exhausted_ = false;
  shrinking_ = false;
  shrink_index_ = 0;
  shrink_remove_len_ = 0;
  shrink_min_len_ = 0;
  shrink_remove_pos_ = 0;
  if (!ParseMessage(binary_, buf, buf_size, scratch)) return 0;

  if (!trim_message_) trim_message_.reset(scratch->New());
  if (!trim_candidate_) trim_candidate_.reset(scratch->New());
  trim_message_->GetReflection()->Swap(trim_message_.get(), scratch);

  trim_serialized_ = SaveMessage(binary_, *trim_message_);
  if (trim_serialized_.empty()) return 0;
  if (trim_serialized_.size() > buf_size)
    trim_serialized_.assign(reinterpret_cast<const char*>(buf), buf_size);

  trim_steps_ = CountTrimUnits(trim_message_.get()) +
                CountShrinkSteps(trim_message_.get());
  trim_give_up_ = std::max<size_t>(kTrimGiveUpMin, trim_steps_ / 4);
  return ClampToInt(trim_steps_);
}

bool Mutator::BuildDropCandidate() {
  if (shrinking_) return false;
  trim_candidate_->CopyFrom(*trim_message_);
  TrimWalker walker(trim_index_);
  if (walker.Walk(trim_candidate_.get())) return true;
  shrinking_ = true;
  return false;
}

bool Mutator::BuildShrinkCandidate() {
  const size_t values = CountTrimValues(trim_message_.get());
  while (shrink_index_ < values) {
    ValueWalker walker(shrink_index_);
    if (!walker.Walk(trim_message_.get())) break;

    const std::string value = walker.Get();
    if (!shrink_remove_len_) {
      shrink_remove_len_ = ShrinkStart(value.size());
      shrink_min_len_ = ShrinkEnd(value.size());
      shrink_remove_pos_ = shrink_remove_len_;
    }

    while (shrink_remove_len_ >= shrink_min_len_) {
      if (shrink_remove_pos_ >= value.size()) {
        shrink_remove_len_ >>= 1;
        shrink_remove_pos_ = shrink_remove_len_;
        continue;
      }

      const size_t cut =
          std::min(shrink_remove_len_, value.size() - shrink_remove_pos_);
      std::string shorter = value.substr(0, shrink_remove_pos_) +
                            value.substr(shrink_remove_pos_ + cut);
      if (walker.EnforceUtf8() && !IsValidUtf8(shorter)) {
        shrink_remove_pos_ += shrink_remove_len_;
        continue;
      }

      trim_candidate_->CopyFrom(*trim_message_);
      ValueWalker setter(shrink_index_);
      if (!setter.Walk(trim_candidate_.get())) return false;
      setter.Set(shorter);
      return true;
    }

    ++shrink_index_;
    shrink_remove_len_ = 0;
  }
  return false;
}

size_t Mutator::Trim(uint8_t** out_buf) {
  trim_candidate_serialized_.clear();
  if (trim_message_ && !trim_exhausted_) {
    if (BuildDropCandidate() || BuildShrinkCandidate()) {
      trim_candidate_serialized_ = SaveMessage(binary_, *trim_candidate_);
      if (trim_candidate_serialized_.size() >= trim_serialized_.size())
        trim_candidate_serialized_.clear();
    } else {
      trim_exhausted_ = true;
    }
  }

  if (trim_candidate_serialized_.empty())
    return CopyToTrimBuffer(trim_serialized_, out_buf);
  return CopyToTrimBuffer(trim_candidate_serialized_, out_buf);
}

int Mutator::PostTrim(bool success) {
  if (success && !trim_candidate_serialized_.empty()) {
    trim_message_->GetReflection()->Swap(trim_message_.get(),
                                         trim_candidate_.get());
    trim_serialized_.swap(trim_candidate_serialized_);
    trim_had_success_ = true;
  } else if (shrinking_) {
    shrink_remove_pos_ += shrink_remove_len_;
  } else {
    ++trim_index_;
  }

  ++trim_progress_;
  if (!trim_had_success_ && trim_progress_ >= trim_give_up_)
    trim_exhausted_ = true;

  if (!trim_message_ || trim_exhausted_ || trim_progress_ >= trim_steps_)
    return ClampToInt(trim_steps_);
  return ClampToInt(trim_progress_);
}

int64_t Mutator::GetRandom(size_t min, size_t max) {
  return std::uniform_int_distribution<int64_t>(min, max)(*random());
}

DEFINE_MUTATE_METHOD(int32_t, Int32)
DEFINE_MUTATE_METHOD(int64_t, Int64)
DEFINE_MUTATE_METHOD(uint32_t, UInt32)
DEFINE_MUTATE_METHOD(uint64_t, UInt64)
DEFINE_MUTATE_METHOD(float, Float)
DEFINE_MUTATE_METHOD(double, Double)

std::string Mutator::MutateString(const std::string& value,
                                  int size_increase_hint) {
  if (!std::uniform_int_distribution<uint16_t>(0, 20)(*random())) return {};

  std::string result = value;
  int new_size = static_cast<int>(value.size()) + size_increase_hint;
  result.resize(std::max(1, new_size));

  result.resize(aflplusplus_mutate_wrapper(
      afl_, reinterpret_cast<uint8_t*>(&result[0]),
      value.size() ? value.size() : 1, GetRandom(1, 16), 0 /*is_text*/,
      GetRandom(0, 1) /*is_exploration*/, nullptr, 0, result.size()));

#if defined(__has_feature)
#if __has_feature(memory_sanitizer)
  __msan_unpoison(&result[0], result.size());
#endif
#endif
  return result;
}

}  // namespace aflplusplus
}  // namespace protobuf_mutator
