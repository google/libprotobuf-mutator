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

#include "src/text_format.h"

#include "port/protobuf.h"

namespace protobuf_mutator {

using protobuf::Message;
using protobuf::TextFormat;

bool ParseTextMessage(const uint8_t* data, size_t size, Message* output) {
  return ParseTextMessage({reinterpret_cast<const char*>(data), size}, output);
}

bool ParseTextMessage(const std::string& data, protobuf::Message* output) {
  output->Clear();
  TextFormat::Parser parser;
#if GOOGLE_PROTOBUF_VERSION >= 3008000  // commit d8c2501b43c1b56e3efa74048a18f8ce06ba07fe of >=3.8.0
  parser.SetRecursionLimit(100);
#endif
  parser.AllowPartialMessage(true);
#if GOOGLE_PROTOBUF_VERSION >= 3008000  // commit 176f7db11d8242b36a3ea6abb1cc436fca5bf75d of >=3.8.0
  parser.AllowUnknownField(true);
#endif
  if (!parser.ParseFromString(data, output)) {
    output->Clear();
    return false;
  }
  return true;
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
  std::string tmp;
  if (!protobuf::TextFormat::PrintToString(message, &tmp)) tmp.clear();
  return tmp;
}

}  // namespace protobuf_mutator
