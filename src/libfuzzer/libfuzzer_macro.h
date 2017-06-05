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

#ifndef SRC_LIBFUZZER_LIBFUZZER_MACRO_H_
#define SRC_LIBFUZZER_LIBFUZZER_MACRO_H_

#include <stddef.h>
#include <cstdint>

#include "port/protobuf.h"

// Defines custom mutator, crossover and test function.
#define DEFINE_PROTO_FUZZER(Proto) DEFINE_TEXT_PROTO_FUZZER(Proto)

// Defines custom mutator, crossover and test function for messages serialized
// as binary.
#define DEFINE_BINARY_PROTO_FUZZER(Proto) DEFINE_PROTO_FUZZER_PARAM(true, Proto)

// Defines custom mutator, crossover and test function for messages serialized
// as text.
#define DEFINE_TEXT_PROTO_FUZZER(Proto) DEFINE_PROTO_FUZZER_PARAM(false, Proto)

// Usage: define the following alongside your LLVMFuzzerTestOneInputwhich to
//        parse input with proto2::TextFormat::ParseFromString.
//  DEFINE_CUSTOM_PROTO_MUTATOR(YourMessageType)
#define DEFINE_CUSTOM_PROTO_MUTATOR(Proto) \
  DEFINE_CUSTOM_PROTO_MUTATOR_PARAM(false, Proto)

// Usage: define the following alongside your LLVMFuzzerTestOneInput to parse
//        input with proto2::Message::ParseFromString.
//  DEFINE_CUSTOM_PROTO_MUTATOR_PARAM(YourMessageType)
#define DEFINE_CUSTOM_BINARY_PROTO_MUTATOR(Proto) \
  DEFINE_CUSTOM_PROTO_MUTATOR_PARAM(true, Proto)

// Usage: Implementation of DEFINE_CUSTOM_PROTO_MUTATOR and
// DEFINE_CUSTOM_BINARY_PROTO_MUTATOR.
// |use_binary| if true, mutator will parse and serialize proto as binary, if
// it false human-readable text format will be used.
#define DEFINE_CUSTOM_PROTO_MUTATOR_PARAM(use_binary, Proto)                   \
  extern "C" size_t LLVMFuzzerCustomMutator(                                   \
      uint8_t* data, size_t size, size_t max_size, unsigned int seed) {        \
    using protobuf_mutator::libfuzzer::internal::CustomProtoMutator;           \
    Proto input;                                                               \
    return CustomProtoMutator(use_binary, data, size, max_size, seed, &input); \
  }                                                                            \
  extern "C" size_t LLVMFuzzerCustomCrossOver(                                 \
      const uint8_t* data1, size_t size1, const uint8_t* data2, size_t size2,  \
      uint8_t* out, size_t max_out_size, unsigned int seed) {                  \
    using protobuf_mutator::libfuzzer::internal::CustomProtoCrossOver;         \
    Proto input1;                                                              \
    Proto input2;                                                              \
    return CustomProtoCrossOver(use_binary, data1, size1, data2, size2, out,   \
                                max_out_size, seed, &input1, &input2);         \
  }

// Usage: Implementation of DEFINE_PROTO_FUZZER and DEFINE_BINARY_PROTO_FUZZER.
// |use_binary| if true, fuzzer will parse and serialize proto as binary, if
// it false human-readable text format will be used.
#define DEFINE_PROTO_FUZZER_PARAM(use_binary, arg_decralation)                 \
  static void TestOneProtoInput(arg_decralation);                              \
  using FuzzerProtoType = std::remove_const<std::remove_reference<             \
      std::function<decltype(TestOneProtoInput)>::argument_type>::type>::type; \
  DEFINE_CUSTOM_PROTO_MUTATOR_PARAM(use_binary, FuzzerProtoType)               \
  extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {    \
    using protobuf_mutator::libfuzzer::internal::LoadProtoInput;               \
    FuzzerProtoType input;                                                     \
    if (LoadProtoInput(use_binary, data, size, &input))                        \
      TestOneProtoInput(input);                                                \
    return 0;                                                                  \
  }                                                                            \
  static void TestOneProtoInput(arg_decralation)

namespace protobuf_mutator {
namespace libfuzzer {
namespace internal {

size_t CustomProtoMutator(bool binary, uint8_t* data, size_t size,
                          size_t max_size, unsigned int seed,
                          protobuf::Message* input);
size_t CustomProtoCrossOver(bool binary, const uint8_t* data1, size_t size1,
                            const uint8_t* data2, size_t size2, uint8_t* out,
                            size_t max_out_size, unsigned int seed,
                            protobuf::Message* input1,
                            protobuf::Message* input2);
bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    protobuf::Message* input);

}  // namespace internal
}  // namespace libfuzzer
}  // namespace protobuf_mutator

#endif  // SRC_LIBFUZZER_LIBFUZZER_MACRO_H_
