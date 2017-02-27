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

#ifndef SRC_XML_LIBFUZZER_XML_MUTATOR_H_
#define SRC_XML_LIBFUZZER_XML_MUTATOR_H_

#include <string>

namespace protobuf_mutator {
namespace xml {

// Parses proto from text same way as |MutateTextMessage|.
// libFuzzer expects user will define LLVMFuzzerTestOneInput and
// LLVMFuzzerCustomMutator. It's important that both of them use same
// serialization format.
// Returns true of the data contains XML proto. If the data is not proto,
// function assumes that the data is raw XML, stores it in |xml| and returns
// false.
bool ParseTextMessage(const uint8_t* data, size_t size, std::string* xml,
                      int* options);

// Mutates proto with XML serialized as text.
size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed);

}  // namespace xml
}  // namespace protobuf_mutator

#endif  // SRC_XML_LIBFUZZER_XML_MUTATOR_H_
