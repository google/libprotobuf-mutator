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

#include "src/xml/libfuzzer_xml_mutator.h"

#include "src/libfuzzer_protobuf_mutator.h"
#include "src/xml/xml_writer.h"
#include "src/xml/xml.pb.h"

using protobuf_mutator::xml::Input;

namespace protobuf_mutator {
namespace xml {

bool ParseTextMessage(const uint8_t* data, size_t size, std::string* xml,
                      int* options) {
  Input message;
  if (!protobuf_mutator::ParseTextMessage(data, size, &message)) return false;
  *xml = MessageToXml(message.document());
  *options = message.options();
  return true;
}

size_t MutateTextMessage(uint8_t* data, size_t size, size_t max_size,
                         unsigned int seed) {
  Input message;
  // If the data is a proto we can convert it to XML and store as a content
  // field. This mutation allows to grow coverage faster.
  if (seed % 33 == 0) {
    protobuf_mutator::ParseTextMessage(data, size, &message);
    message.mutable_document()->Clear();
    message.mutable_document()->mutable_element()->add_content()->set_char_data(
        MessageToXml(message.document()));
    if (size_t new_size =
            protobuf_mutator::SaveMessageAsText(message, data, max_size)) {
      size = new_size;
    }
  }

  return protobuf_mutator::MutateTextMessage(data, size, max_size, seed,
                                             &message);
}

size_t CrossOverTextMessages(const uint8_t* data1, size_t size1,
                             const uint8_t* data2, size_t size2, uint8_t* out,
                             size_t max_out_size, unsigned int seed) {
  Input message;
  return protobuf_mutator::CrossOverTextMessages(
      data1, size1, data2, size2, out, max_out_size, seed, &message);
}

}  // namespace xml
}  // namespace protobuf_mutator
