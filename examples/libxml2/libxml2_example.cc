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

#include "port/protobuf.h"
#include "src/xml/libfuzzer_xml_mutator.h"

namespace {
protobuf_mutator::protobuf::LogSilencer log_silincer;
void ignore(void* ctx, const char* msg, ...) {}
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  return protobuf_mutator::xml::MutateTextMessage(data, size, max_size, seed);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return protobuf_mutator::xml::CrossOverTextMessages(
      data1, size1, data2, size2, out, max_out_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int options = 0;
  std::string xml;
  protobuf_mutator::xml::ParseTextMessage(data, size, &xml, &options);

  // Network requests are too slow.
  options |= XML_PARSE_NONET;
  // These flags can cause network or file access and hangs.
  options &= ~(XML_PARSE_NOENT | XML_PARSE_HUGE | XML_PARSE_DTDVALID |
               XML_PARSE_DTDLOAD | XML_PARSE_DTDATTR);

  xmlSetGenericErrorFunc(nullptr, &ignore);
  if (auto doc = xmlReadMemory(xml.c_str(), static_cast<int>(xml.size()), "",
                               nullptr, options)) {
    xmlFreeDoc(doc);
  }

  return 0;
}
