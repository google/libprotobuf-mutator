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
#include "src/xml/xml.pb.h"
#include "src/xml/xml_writer.h"

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
  return protobuf_mutator::MutateTextMessage<Input>(data, size, max_size, seed);
}

size_t CrossOverTextMessages(const uint8_t* data1, size_t size1,
                             const uint8_t* data2, size_t size2, uint8_t* out,
                             size_t max_out_size, unsigned int seed) {
  // If the data is a proto we can convert it to XML and store as a content
  // field.
  if (seed % 33 == 0) {
    Input message1;
    protobuf_mutator::ParseTextMessage(data1, size1, &message1);
    Input message2;
    protobuf_mutator::ParseTextMessage(data2, size2, &message2);
    for (int i = 0; i < 2; ++i) {
      message1.mutable_document()
          ->mutable_element()
          ->add_content()
          ->set_char_data(MessageToXml(message2.document()));
      if (size_t new_size = protobuf_mutator::SaveMessageAsText(message1, out,
                                                                max_out_size)) {
        return new_size;
      }
      message1.Clear();
    }
    return 0;
  }

  return protobuf_mutator::CrossOverTextMessages<Input>(
      data1, size1, data2, size2, out, max_out_size, seed);
}

}  // namespace xml
}  // namespace protobuf_mutator
