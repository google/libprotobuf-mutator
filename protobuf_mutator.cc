// Copyright 2016 Google Inc. All rights reserved.
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

#include "protobuf_mutator.h"

class Message;

ProtobufMutator::ProtobufMutator(uint32_t seed) {

}

ProtobufMutator::~ProtobufMutator() {

}

bool ProtobufMutator::Mutate(Message* proto) {
  return false;
}
  
bool ProtobufMutator::CrossOver(const Message& with, Message* proto) {
  return false;
}

bool ProtobufMutator::MutateField(const FieldDescriptor& field, int32_t* value) {
  return false;
}

