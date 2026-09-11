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

#include "src/mutation_io.h"

#include <algorithm>
#include <cassert>

#include "src/binary_format.h"
#include "src/text_format.h"

#ifdef LIB_PROTO_MUTATOR_QUIET
#if GOOGLE_PROTOBUF_VERSION >= 4022000
#include "absl/base/log_severity.h"
#include "absl/log/globals.h"
#else
#include "google/protobuf/stubs/logging.h"
#endif
#endif

namespace protobuf_mutator {

#ifdef LIB_PROTO_MUTATOR_QUIET
namespace {

bool SilenceProtobufLog() {
#if GOOGLE_PROTOBUF_VERSION >= 4022000
  absl::SetMinLogLevel(absl::LogSeverityAtLeast::kInfinity);
#else
  protobuf::SetLogHandler(nullptr);
#endif
  return true;
}

bool protobuf_log_silenced = SilenceProtobufLog();

}  // namespace
#endif

bool TextInputReader::Read(protobuf::Message* message) const {
  return ParseTextMessage(data(), size(), message);
}

size_t TextOutputWriter::Write(const protobuf::Message& message) {
  return SaveMessageAsText(message, data(), size());
}

bool BinaryInputReader::Read(protobuf::Message* message) const {
  return ParseBinaryMessage(data(), size(), message);
}

size_t BinaryOutputWriter::Write(const protobuf::Message& message) {
  return SaveMessageAsBinary(message, data(), size());
}

bool ParseMessage(bool binary, const uint8_t* data, size_t size,
                  protobuf::Message* message) {
  return binary ? ParseBinaryMessage(data, size, message)
                : ParseTextMessage(data, size, message);
}

std::string SaveMessage(bool binary, const protobuf::Message& message) {
  return binary ? SaveMessageAsBinary(message) : SaveMessageAsText(message);
}

void LastMutationCache::Store(const uint8_t* data, size_t size,
                              protobuf::Message* message) {
  if (!message_) message_.reset(message->New());
  message->GetReflection()->Swap(message, message_.get());
  data_.assign(data, data + size);
}

bool LastMutationCache::LoadIfSame(const uint8_t* data, size_t size,
                                   protobuf::Message* message) {
  if (!message_ || size != data_.size() ||
      !std::equal(data_.begin(), data_.end(), data))
    return false;

  message->GetReflection()->Swap(message, message_.get());
  message_.reset();
  return true;
}

LastMutationCache* GetCache() {
  static LastMutationCache cache;
  return &cache;
}

size_t GetMaxSize(const InputReader& input, const OutputWriter& output,
                  const protobuf::Message& message) {
  size_t max_size = message.ByteSizeLong() + output.size();
  max_size -= std::min(max_size, input.size());
  return max_size;
}

namespace {

size_t MutateMessage(Mutator* mutator, const InputReader& input,
                     OutputWriter* output, protobuf::Message* message) {
  input.Read(message);
  mutator->Mutate(message, GetMaxSize(input, *output, *message));
  if (size_t new_size = output->Write(*message)) {
    assert(new_size <= output->size());
    GetCache()->Store(output->data(), new_size, message);
    return new_size;
  }
  return 0;
}

size_t CrossOverMessages(Mutator* mutator, const InputReader& input1,
                         const InputReader& input2, OutputWriter* output,
                         protobuf::Message* message1,
                         protobuf::Message* message2) {
  input1.Read(message1);
  input2.Read(message2);
  mutator->CrossOver(*message2, message1,
                     GetMaxSize(input1, *output, *message1));
  if (size_t new_size = output->Write(*message1)) {
    assert(new_size <= output->size());
    GetCache()->Store(output->data(), new_size, message1);
    return new_size;
  }
  return 0;
}

template <class Reader, class Writer>
size_t MutateFormattedMessage(Mutator* mutator, uint8_t* data, size_t size,
                              size_t max_size, protobuf::Message* message) {
  Reader input(data, size);
  Writer output(data, max_size);
  return MutateMessage(mutator, input, &output, message);
}

template <class Reader, class Writer>
size_t CrossOverFormattedMessages(Mutator* mutator, const uint8_t* data1,
                                  size_t size1, const uint8_t* data2,
                                  size_t size2, uint8_t* out,
                                  size_t max_out_size,
                                  protobuf::Message* message1,
                                  protobuf::Message* message2) {
  Reader input1(data1, size1);
  Reader input2(data2, size2);
  Writer output(out, max_out_size);
  return CrossOverMessages(mutator, input1, input2, &output, message1,
                           message2);
}

}  // namespace

size_t MutateMessage(bool binary, Mutator* mutator, uint8_t* data, size_t size,
                     size_t max_size, protobuf::Message* message) {
  auto mutate =
      binary ? &MutateFormattedMessage<BinaryInputReader, BinaryOutputWriter>
             : &MutateFormattedMessage<TextInputReader, TextOutputWriter>;
  return mutate(mutator, data, size, max_size, message);
}

size_t CrossOverMessages(bool binary, Mutator* mutator, const uint8_t* data1,
                         size_t size1, const uint8_t* data2, size_t size2,
                         uint8_t* out, size_t max_out_size,
                         protobuf::Message* message1,
                         protobuf::Message* message2) {
  auto cross =
      binary
          ? &CrossOverFormattedMessages<BinaryInputReader, BinaryOutputWriter>
          : &CrossOverFormattedMessages<TextInputReader, TextOutputWriter>;
  return cross(mutator, data1, size1, data2, size2, out, max_out_size, message1,
               message2);
}

bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    Mutator* mutator, protobuf::Message* input) {
  if (GetCache()->LoadIfSame(data, size, input)) return true;
  if (!ParseMessage(binary, data, size, input)) return false;
  mutator->Seed(size);
  mutator->Fix(input);
  return true;
}

}  // namespace protobuf_mutator
