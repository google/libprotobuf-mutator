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

#include <cmath>

#include "examples/libfuzzer/libfuzzer_example.pb.h"
#include "port/protobuf.h"
#include "src/libfuzzer/libfuzzer_macro.h"

protobuf_mutator::protobuf::LogSilencer log_silincer;

DEFINE_PROTO_FUZZER(const libfuzzer_example::Msg& message) {
  static PostProcessorRegistration reg = {
      [](libfuzzer_example::Msg* message, unsigned int seed) {
        if (seed % 2) {
          message->set_optional_uint64(
              std::hash<std::string>{}(message->optional_string()));
        }

        if (message->has_any()) {
          auto* any = message->mutable_any();

          // Guide mutator to usefull 'Any' types.
          static const char* const expected_types[] = {
              "type.googleapis.com/google.protobuf.DescriptorProto",
              "type.googleapis.com/google.protobuf.FileDescriptorProto",
          };

          if (!std::count(std::begin(expected_types), std::end(expected_types),
                          any->type_url())) {
            const size_t num =
                (std::end(expected_types) - std::begin(expected_types));
            any->set_type_url(expected_types[seed % num]);
          }
        }
      }};

  protobuf_mutator::protobuf::FileDescriptorProto file;

  // Emulate a bug.
  if (message.optional_uint64() ==
          std::hash<std::string>{}(message.optional_string()) &&
      message.optional_string() == "abcdefghijklmnopqrstuvwxyz" &&
      !std::isnan(message.optional_float()) &&
      std::fabs(message.optional_float()) > 1000 &&
      message.any().UnpackTo(&file) && !file.name().empty()) {
    std::cerr << message.DebugString() << "\n";
    abort();
  }
}
