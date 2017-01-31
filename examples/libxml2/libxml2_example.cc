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

#include "libxml/parser.h"

#include "google/protobuf/stubs/logging.h"

#include "src/xml/libfuzzer_xml_mutator.h"

namespace {
google::protobuf::LogSilencer log_silincer;
void ignore(void* ctx, const char* msg, ...) {}
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  return protobuf_mutator::xml::MutateTextMessage(data, size, max_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int options = 0;
  std::string xml;
  protobuf_mutator::xml::ParseTextMessage(data, size, &xml, &options);

  // Network requests are too slow.
  options |= XML_PARSE_NONET;
  // There is a known hang with this option enabled.
  // options &= ~XML_PARSE_NOENT;

  xmlSetGenericErrorFunc(nullptr, &ignore);
  if (auto doc = xmlReadMemory(xml.c_str(), static_cast<int>(xml.size()), "",
                               nullptr, options)) {
    xmlFreeDoc(doc);
  }

  return 0;
}
