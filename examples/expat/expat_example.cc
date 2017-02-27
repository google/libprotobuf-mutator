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

#include <vector>

#include "expat.h"  // NOLINT

#include "port/protobuf.h"
#include "src/xml/libfuzzer_xml_mutator.h"

namespace {
protobuf::LogSilencer log_silincer;
std::vector<const char*> kEncodings = {{"UTF-16", "UTF-8", "ISO-8859-1",
                                        "US-ASCII", "UTF-16BE", "UTF-16LE",
                                        "INVALIDENCODING"}};
}

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
// Experimental
#ifdef LIB_PROTO_MUTATOR_XML2_NO_FLATTENING
  if (seed % 33 == 0) {
    ++seed;
  }
#endif  // LIB_PROTO_MUTATOR_XML2_NO_FLATTENING

  return protobuf_mutator::xml::MutateTextMessage(data, size, max_size, seed);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return protobuf_mutator::xml::CrossOverTextMessages(
      data1, size1, data2, size2, out, max_out_size, seed);
}

// Entry point for LibFuzzer.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  int options = 0;
  std::string xml;
  protobuf_mutator::xml::ParseTextMessage(data, size, &xml, &options);

  int use_ns = options % 2;
  options /= 2;
  auto enc = kEncodings[options % kEncodings.size()];
  XML_Parser parser =
      use_ns ? XML_ParserCreateNS(enc, '\n') : XML_ParserCreate(enc);
  XML_Parse(parser, xml.data(), xml.size(), true);
  XML_ParserFree(parser);
  return 0;
}
