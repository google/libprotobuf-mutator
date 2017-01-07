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

#include <cstddef>
#include <cstdint>

#include "google/protobuf/text_format.h"
#include "libfuzzer_example.pb.h"
#include "libfuzzer_protobuf_mutator.h"

using google::protobuf::Message;
using google::protobuf::TextFormat;
using protobuf_mutator::LibFuzzerProtobufMutator;
using libfuzzer_example::Msg;

namespace {

void Parse(const uint8_t* data, size_t size, Message* output) {
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  parser.ParseFromString({data, data + size}, output);
}
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  LibFuzzerProtobufMutator mutator(seed);
  assert(size <= max_size);

  for (int i = 0; i < 100; ++i) {
    Msg message;
    Parse(data, size, &message);
    mutator.Mutate(&message, max_size - size);
    std::string result;
    if (TextFormat::PrintToString(message, &result) &&
        result.size() <= max_size) {
      memcpy(data, result.data(), result.size());
      return result.size();
    }
  }

  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  Msg message;
  Parse(data, size, &message);

  // Emulate a bug.
  if (message.optional_uint64() > 100 &&
      !std::isnan(message.optional_float()) &&
      fabs(message.optional_float()) > 1000 &&
      fabs(message.optional_float()) < 1E10) {
    abort();
  }

  return 0;
}
