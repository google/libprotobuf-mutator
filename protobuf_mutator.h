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

#ifndef LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
#define LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <random>

namespace google {
namespace protobuf {
class Message;
}
}

// Randomly makes incremental change in the given protobuf.
// Usage example:
//    ProtobufMutator mutator(1);
//    MyMessage message;
//    message.ParseFromString(encoded_message);
//    mutator.Mutate(&message, encoded_message.size(), 10000);
//
// Class implements very basic mutations on simple type, so for better results
// users should override ProtobufMutator::Mutate* methods with more useful
// logic.
class ProtobufMutator {
 public:
  using RandomEngine = std::minstd_rand0;

  // seed: value to initialize random number generator.
  // keep_initialized: if true code will make sure that produced protobuf is in
  // initialized state.
  explicit ProtobufMutator(uint32_t seed, bool keep_initialized = true);

  // message: message to mutate.
  // current_size: size of the protobuf in serialized state.
  // max_size: maximum size of the protobuf in serialized state.
  // current_size and max_size can be calculated for any serialization format,
  // the only requirement that both calculated from the same format.
  // Method does not guarantee that results is smaller than max_size, it will
  // just reduce probabilities of mutations which can cause increase the size
  // over the limit. E.g. if we close to the limit, it will avoid adding
  // creating new fields. Called could repeat mutation if result was larger than
  // requested.
  bool Mutate(google::protobuf::Message* message, size_t current_size,
              size_t max_size);

  // TODO: implement
  bool CrossOver(const google::protobuf::Message& with,
                 google::protobuf::Message* message);

  virtual int32_t MutateInt32(int32_t value);
  virtual int64_t MutateInt64(int64_t value);
  virtual uint32_t MutateUInt32(uint32_t value);
  virtual uint64_t MutateUInt64(uint64_t value);
  virtual float MutateFloat(float value);
  virtual double MutateDouble(double value);
  virtual bool MutateBool(bool value);
  virtual size_t MutateEnum(size_t index, size_t item_count);
  virtual std::string MutateString(const std::string& value,
                                   size_t allowed_growth);

  // TODO: Allow user to control proto level mutations:
  //   * Callbacks to recursive traversal.
  //   * Callbacks for particular proto level mutations.

 private:
  void InitializeMessage(google::protobuf::Message* message, int max_depth);

  bool keep_initialized_ = false;
  RandomEngine random_;
};

#endif  // LIBPROTOBUG_MUTATOR_PROTOBUG_MUTATOR_H
