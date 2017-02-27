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

#include "src/libfuzzer_protobuf_mutator.h"

#include <string.h>
#include <cassert>
#include <memory>
#include <string>

#include "port/protobuf.h"
#include "src/protobuf_mutator.h"

extern "C" size_t LLVMFuzzerMutate(uint8_t*, size_t, size_t)
    __attribute__((weak));

namespace protobuf_mutator {

using protobuf::Message;
using protobuf::TextFormat;

namespace {

template <class T>
T MutateValue(T v) {
  size_t size =
      LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&v), sizeof(v), sizeof(v));
  memset(reinterpret_cast<uint8_t*>(&v) + size, 0, sizeof(v) - size);
  return v;
}

class InputReader {
 public:
  InputReader(const uint8_t* data, size_t size) : data_(data), size_(size) {}
  virtual ~InputReader() = default;

  virtual bool Read(protobuf::Message* message) const = 0;

  const uint8_t* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  const uint8_t* data_;
  size_t size_;
};

class OutputWriter {
 public:
  OutputWriter(uint8_t* data, size_t size) : data_(data), size_(size) {}
  virtual ~OutputWriter() = default;

  virtual size_t Write(const protobuf::Message& message) = 0;

  uint8_t* data() const { return data_; }
  size_t size() const { return size_; }

 private:
  uint8_t* data_;
  size_t size_;
};

class TextInputReader : public InputReader {
 public:
  using InputReader::InputReader;

  bool Read(protobuf::Message* message) const override {
    return ParseTextMessage(data(), size(), message);
  }
};

class TextOutputWriter : public OutputWriter {
 public:
  using OutputWriter::OutputWriter;

  size_t Write(const protobuf::Message& message) override {
    return SaveMessageAsText(message, data(), size());
  }
};

class BinaryInputReader : public InputReader {
 public:
  using InputReader::InputReader;

  bool Read(protobuf::Message* message) const override {
    return ParseBinaryMessage(data(), size(), message);
  }
};

class BinaryOutputWriter : public OutputWriter {
 public:
  using OutputWriter::OutputWriter;

  size_t Write(const protobuf::Message& message) override {
    return SaveMessageAsBinary(message, data(), size());
  }
};

size_t MutateMessage(unsigned int seed, const InputReader& input,
                     OutputWriter* output, Message* message) {
  protobuf_mutator::LibFuzzerProtobufMutator mutator(seed);
  for (int i = 0; i < 100; ++i) {
    input.Read(message);
    mutator.Mutate(message, output->size() > input.size()
                                ? (output->size() - input.size())
                                : 0);
    if (size_t new_size = output->Write(*message)) {
      assert(new_size <= output->size());
      return new_size;
    }
  }
  return 0;
}

size_t CrossOverMessages(unsigned int seed, const InputReader& input1,
                         const InputReader& input2, OutputWriter* output,
                         protobuf::Message* message1,
                         protobuf::Message* message2) {
  protobuf_mutator::LibFuzzerProtobufMutator mutator(seed);
  input2.Read(message2);
  for (int i = 0; i < 100; ++i) {
    input1.Read(message1);
    mutator.CrossOver(*message2, message1);
    if (size_t new_size = output->Write(*message1)) {
      assert(new_size <= output->size());
      return new_size;
    }
  }
  return 0;
}

}  // namespace

int32_t LibFuzzerProtobufMutator::MutateInt32(int32_t value) {
  return MutateValue(value);
}

int64_t LibFuzzerProtobufMutator::MutateInt64(int64_t value) {
  return MutateValue(value);
}

uint32_t LibFuzzerProtobufMutator::MutateUInt32(uint32_t value) {
  return MutateValue(value);
}

uint64_t LibFuzzerProtobufMutator::MutateUInt64(uint64_t value) {
  return MutateValue(value);
}

float LibFuzzerProtobufMutator::MutateFloat(float value) {
  return MutateValue(value);
}

double LibFuzzerProtobufMutator::MutateDouble(double value) {
  return MutateValue(value);
}

std::string LibFuzzerProtobufMutator::MutateString(const std::string& value,
                                                   size_t size_increase_hint) {
  // Randomly return empty strings as LLVMFuzzerMutate does not produce them.
  if (!std::uniform_int_distribution<uint8_t>(0, 20)(*random())) return {};
  std::string result = value;
  result.resize(value.size() + size_increase_hint);
  if (result.empty()) return result;
  result.resize(LLVMFuzzerMutate(reinterpret_cast<uint8_t*>(&result[0]),
                                 value.size(), result.size()));
  return result;
}

bool ParseTextMessage(const uint8_t* data, size_t size, Message* output) {
  return ParseTextMessage({data, data + size}, output);
}

bool ParseTextMessage(const std::string& data, protobuf::Message* output) {
  output->Clear();
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  return parser.ParseFromString(data, output);
}

size_t SaveMessageAsText(const Message& message, uint8_t* data,
                         size_t max_size) {
  std::string result = SaveMessageAsText(message);
  if (result.size() <= max_size) {
    memcpy(data, result.data(), result.size());
    return result.size();
  }
  return 0;
}

std::string SaveMessageAsText(const protobuf::Message& message) {
  return MessageToTextString(message);
}

bool ParseBinaryMessage(const uint8_t* data, size_t size, Message* output) {
  return ParseBinaryMessage({data, data + size}, output);
}

bool ParseBinaryMessage(const std::string& data, protobuf::Message* output) {
  output->Clear();
  return output->ParsePartialFromString(data);
}

size_t SaveMessageAsBinary(const Message& message, uint8_t* data,
                           size_t max_size) {
  std::string result = SaveMessageAsBinary(message);
  if (result.size() <= max_size) {
    memcpy(data, result.data(), result.size());
    return result.size();
  }
  return 0;
}

std::string SaveMessageAsBinary(const protobuf::Message& message) {
  return MessageToBinaryString(message);
}

namespace internal {

size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed, protobuf::Message* message) {
  TextInputReader input(data, size);
  TextOutputWriter output(data, max_size);
  return MutateMessage(seed, input, &output, message);
}

size_t CrossOverTextMessages(const uint8_t* data1, size_t size1,
                             const uint8_t* data2, size_t size2, uint8_t* out,
                             size_t max_out_size, unsigned int seed,
                             protobuf::Message* message1,
                             protobuf::Message* message2) {
  TextInputReader input1(data1, size1);
  TextInputReader input2(data2, size2);
  TextOutputWriter output(out, max_out_size);
  return CrossOverMessages(seed, input1, input2, &output, message1, message2);
}

size_t MutateBinaryMessage(uint8_t* data, size_t size, size_t max_size,
                           unsigned int seed, protobuf::Message* message) {
  BinaryInputReader input(data, size);
  BinaryOutputWriter output(data, max_size);
  return MutateMessage(seed, input, &output, message);
}

size_t CrossOverBinaryMessages(const uint8_t* data1, size_t size1,
                               const uint8_t* data2, size_t size2, uint8_t* out,
                               size_t max_out_size, unsigned int seed,
                               protobuf::Message* message1,
                               protobuf::Message* message2) {
  BinaryInputReader input1(data1, size1);
  BinaryInputReader input2(data2, size2);
  BinaryOutputWriter output(out, max_out_size);
  return CrossOverMessages(seed, input1, input2, &output, message1, message2);
}

}  // namespace internal

}  // namespace protobuf_mutator
