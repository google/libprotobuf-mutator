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
#include "google/protobuf/text_format.h"
#include "gtest/gtest.h"

#include "protobuf_mutator.pb.h"

using google::protobuf::TextFormat;
using protobuf_mutator::Msg;
using protobuf_mutator::Msg2;
using protobuf_mutator::Msg3;

struct RequiredDoubleHelper {
  std::vector<double> kValues = {-1.1, 2.7, 322};
};

class ProtobufMutatorTest : public testing::Test {
 public:
  void SetUp() override {}

  void TearDown() override {}

  Msg& Reset() {
    message_.Clear();

    EXPECT_FALSE(message_.IsInitialized());

    message_.set_required_double(1.3);
    message_.set_required_float(-5.1);
    message_.set_required_int32(553);
    message_.set_required_int64(543);
    message_.set_required_uint32(326);
    message_.set_required_uint64(635);
    message_.set_required_sint32(993);
    message_.set_required_sint64(696);
    message_.set_required_fixed32(545);
    message_.set_required_fixed64(775);
    message_.set_required_sfixed32(112);
    message_.set_required_sfixed64(444);
    message_.set_required_bool(true);
    message_.set_required_string("abc");
    message_.set_required_bytes("ABC");
    message_.set_required_enum(Msg::ENUM_4);
    message_.mutable_required_msg()->set_optional_int64(65);

    message_.set_optional_double(-51.3);
    message_.set_optional_float(55.1);
    message_.set_optional_int32(5553);
    message_.set_optional_int64(-5543);
    message_.set_optional_uint32(5326);
    message_.set_optional_uint64(5635);
    message_.set_optional_sint32(5993);
    message_.set_optional_sint64(5696);
    message_.set_optional_fixed32(5545);
    message_.set_optional_fixed64(5775);
    message_.set_optional_sfixed32(-5112);
    message_.set_optional_sfixed64(5444);
    message_.set_optional_bool(false);
    message_.set_optional_string("asd");
    message_.set_optional_bytes("ASD");
    message_.set_optional_enum(Msg::ENUM_7);

    for (int i = 0; i < 3; ++i) {
      message_.add_repeated_double(-51.3);
      message_.add_repeated_float(55.1);
      message_.add_repeated_int32(5553);
      message_.add_repeated_int64(-5543);
      message_.add_repeated_uint32(5326);
      message_.add_repeated_uint64(5635);
      message_.add_repeated_sint32(5993);
      message_.add_repeated_sint64(5696);
      message_.add_repeated_fixed32(5545);
      message_.add_repeated_fixed64(5775);
      message_.add_repeated_sfixed32(-5112);
      message_.add_repeated_sfixed64(5444);
      message_.add_repeated_bool(false);
      message_.add_repeated_string("asd");
      message_.add_repeated_bytes("ASD");
      message_.add_repeated_enum(Msg::ENUM_7);
    }

    // message_.mutable_optional_msg()->MergeFrom(message_);

    // message_.mutable_optional_msg();

    message_.set_oneof_double(-51.3);
    message_.set_oneof_float(55.1);
    message_.set_oneof_int32(5553);
    message_.set_oneof_int64(-5543);
    message_.set_oneof_uint32(5326);
    message_.set_oneof_uint64(5635);
    message_.set_oneof_sint32(5993);
    message_.set_oneof_sint64(5696);
    message_.set_oneof_fixed32(5545);
    message_.set_oneof_fixed64(5775);
    message_.set_oneof_sfixed32(-5112);
    message_.set_oneof_sfixed64(5444);
    message_.set_oneof_bool(false);
    message_.set_oneof_string("asd");
    message_.set_oneof_bytes("ASD");
    message_.set_oneof_enum(Msg::ENUM_7);

    (*message_.mutable_map())["A"] = 3;
    (*message_.mutable_map())["B"] = 2;
    (*message_.mutable_map())["C"] = 1;

    message_.mutable_group()->set_required_bool(true);

    EXPECT_TRUE(message_.IsInitialized());

    return message_;
  }

 protected:
  Msg message_;
  ProtobufMutator mutator_ = {17, false};
};

TEST_F(ProtobufMutatorTest, Empty) {
  std::string tmp_out;
  EXPECT_TRUE(TextFormat::PrintToString(message_, &tmp_out));
  EXPECT_EQ(tmp_out, "");

  Msg tmp;
  EXPECT_FALSE(TextFormat::ParseFromString(tmp_out, &tmp));
}

TEST_F(ProtobufMutatorTest, Default) {
  Reset();
  std::string tmp_out;
  EXPECT_TRUE(TextFormat::PrintToString(message_, &tmp_out));
  EXPECT_NE(tmp_out, "");

  Msg tmp;
  EXPECT_TRUE(TextFormat::ParseFromString(tmp_out, &tmp));
}

TEST_F(ProtobufMutatorTest, Large) {
  // Reset();
  // mutator_.Mutate(&message_);

  std::string tmp_out;
  for (int i = 0; i < 10000; ++i) {
    mutator_.Mutate(&message_, tmp_out.size(), 30000);
    std::string prev = tmp_out;
    EXPECT_TRUE(TextFormat::PrintToString(message_, &tmp_out));
    if (tmp_out.size() > 35000) {
      std::cout << prev << "\n";
      std::cout << tmp_out << "\n";
      assert(0);
    }
    std::cout << "SIZE: " << tmp_out.size() << "\n";
  }

  std::cout << tmp_out << "\n";
  std::cout << "SIZE: " << tmp_out.size() << "\n";
}

// TEST_F(ProtobufMutatorTest, Message) {
//   // Reset();
//   // mutator_.Mutate(&message_);

//   Msg2 message;

//   for (int i = 0; i < 1000; ++i) mutator_.Mutate(&message, 0, 100);

//   std::string tmp_out;
//   EXPECT_TRUE(TextFormat::PrintToString(message, &tmp_out));
//   std::cout << tmp_out << "\n";
//   std::cout << "SIZE: " << tmp_out.size() << "\n";
// }

// TEST_F(ProtobufMutatorTest, Grop) {
//   // Reset();
//   // mutator_.Mutate(&message_);

//   Msg3 message;

//   for (int i = 0; i < 1000; ++i) mutator_.Mutate(&message, 0, 100);

//   std::string tmp_out;
//   EXPECT_TRUE(TextFormat::PrintToString(message, &tmp_out));
//   std::cout << tmp_out << "\n";
//   std::cout << "SIZE: " << tmp_out.size() << "\n";
// }
