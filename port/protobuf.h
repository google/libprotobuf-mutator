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

#ifndef PORT_PROTOBUF_H_
#define PORT_PROTOBUF_H_

#include <string>

#include "google/protobuf/message.h"
#include "google/protobuf/stubs/common.h"
#include "google/protobuf/stubs/logging.h"
#include "google/protobuf/text_format.h"
#include "google/protobuf/util/message_differencer.h"

namespace protobuf_mutator {

namespace protobuf = google::protobuf;

inline std::string MessageToTextString(const protobuf::Message& message) {
  std::string tmp;
  if (!protobuf::TextFormat::PrintToString(message, &tmp)) return {};
  return tmp;
}
}  // namespace protobuf_mutator

#endif  // PORT_PROTOBUF_H_
