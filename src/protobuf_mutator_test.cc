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

#include "src/protobuf_mutator.h"

#include <algorithm>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "google/protobuf/text_format.h"
#include "google/protobuf/util/message_differencer.h"
#include "gtest/gtest.h"
#include "src/protobuf_mutator.pb.h"

using google::protobuf::TextFormat;
using google::protobuf::util::MessageDifferencer;
using testing::Test;
using testing::TestWithParam;
using testing::ValuesIn;
using testing::WithParamInterface;

namespace protobuf_mutator {

const char kMessages[] = R"(
  required_msg {}
  optional_msg {}
  repeated_msg {}
  repeated_msg {required_sint32: 56}
  repeated_msg {}
  repeated_msg {
    required_msg {}
    optional_msg {}
    repeated_msg {}
    repeated_msg { required_int32: 67 }
    repeated_msg {}
  }
)";

const char kRequiredFields[] = R"(
  required_double: 1.26685288449177e-313
  required_float: 5.9808638e-39
  required_int32: 67
  required_int64: 5285068
  required_uint32: 14486213
  required_uint64: 520229415
  required_sint32: 56
  required_sint64: -6057486163525532641
  required_fixed32: 8812173
  required_fixed64: 273731277756
  required_sfixed32: 43142
  required_sfixed64: 132
  required_bool: false
  required_string: "qwert"
  required_bytes: "asdf"
)";

const char kOptionalFields[] = R"(
  optional_double: 1.93177850152856e-314
  optional_float: 4.7397519e-41
  optional_int32: 40020
  optional_int64: 10
  optional_uint32: 40
  optional_uint64: 159
  optional_sint32: 44015
  optional_sint64: 17493625000076
  optional_fixed32: 193
  optional_fixed64: 8542688694448488723
  optional_sfixed32: 4926
  optional_sfixed64: 60
  optional_bool: false
  optional_string: "QWERT"
  optional_bytes: "ASDF"
  optional_enum: ENUM_5
)";

const char kRepeatedFields[] = R"(
  repeated_double: 1.93177850152856e-314
  repeated_double: 1.26685288449177e-313
  repeated_float: 4.7397519e-41
  repeated_float: 5.9808638e-39
  repeated_int32: 40020
  repeated_int32: 67
  repeated_int64: 10
  repeated_int64: 5285068
  repeated_uint32: 40
  repeated_uint32: 14486213
  repeated_uint64: 159
  repeated_uint64: 520229415
  repeated_sint32: 44015
  repeated_sint32: 56
  repeated_sint64: 17493625000076
  repeated_sint64: -6057486163525532641
  repeated_fixed32: 193
  repeated_fixed32: 8812173
  repeated_fixed64: 8542688694448488723
  repeated_fixed64: 273731277756
  repeated_sfixed32: 4926
  repeated_sfixed32: 43142
  repeated_sfixed64: 60
  repeated_sfixed64: 132
  repeated_bool: false
  repeated_bool: true
  repeated_string: "QWERT"
  repeated_string: "qwert"
  repeated_bytes: "ASDF"
  repeated_bytes: "asdf"
  repeated_enum: ENUM_5
  repeated_enum: ENUM_4
)";

const char kRequiredNestedFields[] = R"(
  required_int32: 123
  optional_msg {
    required_double: 1.26685288449177e-313
    required_float: 5.9808638e-39
    required_int32: 67
    required_int64: 5285068
    required_uint32: 14486213
    required_uint64: 520229415
    required_sint32: 56
    required_sint64: -6057486163525532641
    required_fixed32: 8812173
    required_fixed64: 273731277756
    required_sfixed32: 43142
    required_sfixed64: 132
    required_bool: false
    required_string: "qwert"
    required_bytes: "asdf"
  }
)";

const char kOptionalNestedFields[] = R"(
  required_int32: 123
  optional_msg {
    optional_double: 1.93177850152856e-314
    optional_float: 4.7397519e-41
    optional_int32: 40020
    optional_int64: 10
    optional_uint32: 40
    optional_uint64: 159
    optional_sint32: 44015
    optional_sint64: 17493625000076
    optional_fixed32: 193
    optional_fixed64: 8542688694448488723
    optional_sfixed32: 4926
    optional_sfixed64: 60
    optional_bool: false
    optional_string: "QWERT"
    optional_bytes: "ASDF"
    optional_enum: ENUM_5
  }
)";

const char kRepeatedNestedFields[] = R"(
  required_int32: 123
  optional_msg {
    repeated_double: 1.93177850152856e-314
    repeated_double: 1.26685288449177e-313
    repeated_float: 4.7397519e-41
    repeated_float: 5.9808638e-39
    repeated_int32: 40020
    repeated_int32: 67
    repeated_int64: 10
    repeated_int64: 5285068
    repeated_uint32: 40
    repeated_uint32: 14486213
    repeated_uint64: 159
    repeated_uint64: 520229415
    repeated_sint32: 44015
    repeated_sint32: 56
    repeated_sint64: 17493625000076
    repeated_sint64: -6057486163525532641
    repeated_fixed32: 193
    repeated_fixed32: 8812173
    repeated_fixed64: 8542688694448488723
    repeated_fixed64: 273731277756
    repeated_sfixed32: 4926
    repeated_sfixed32: 43142
    repeated_sfixed64: 60
    repeated_sfixed64: 132
    repeated_bool: false
    repeated_bool: true
    repeated_string: "QWERT"
    repeated_string: "qwert"
    repeated_bytes: "ASDF"
    repeated_bytes: "asdf"
    repeated_enum: ENUM_5
    repeated_enum: ENUM_4
  }
)";

class TestProtobufMutator : public ProtobufMutator {
 public:
  explicit TestProtobufMutator(bool keep_initialized)
      : ProtobufMutator(17), random_(13) {
    keep_initialized_ = keep_initialized;
  }

  float MutateFloat(float value) override {
    // Hack for tests. It's hard compare reals generated using random mutations.
    return std::uniform_int_distribution<uint8_t>(-10, 10)(random_);
  }

  double MutateDouble(double value) override { return MutateFloat(value); }

 private:
  RandomEngine random_;
};

std::vector<std::string> Split(const std::string& str) {
  std::istringstream iss(str);
  std::vector<std::string> result;
  for (std::string line; std::getline(iss, line, '\n');) result.push_back(line);
  return result;
}

std::vector<std::pair<const char*, size_t>> GetFieldTestParams(
    const std::vector<const char*>& tests) {
  std::vector<std::pair<const char*, size_t>> results;
  for (auto t : tests) {
    auto lines = Split(t);
    for (size_t i = 0; i != lines.size(); ++i) {
      if (lines[i].find(':') != std::string::npos) results.push_back({t, i});
    }
  }
  return results;
}

std::vector<std::pair<const char*, size_t>> GetMessageTestParams(
    const std::vector<const char*>& tests) {
  std::vector<std::pair<const char*, size_t>> results;
  for (auto t : tests) {
    auto lines = Split(t);
    for (size_t i = 0; i != lines.size(); ++i) {
      if (lines[i].find("{}") != std::string::npos) results.push_back({t, i});
    }
  }
  return results;
}

void LoadMessage(const std::string& text_message, Msg* message) {
  message->Clear();
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  EXPECT_TRUE(parser.ParseFromString(text_message, message));
}

bool LoadWithoutLine(const std::string& text_message, size_t line,
                     Msg* message) {
  std::ostringstream oss;
  auto lines = Split(text_message);
  for (size_t i = 0; i != lines.size(); ++i) {
    if (i != line) oss << lines[i] << '\n';
  }
  message->Clear();
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  return parser.ParseFromString(oss.str(), message);
}

bool LoadWithChangedLine(const std::string& text_message, size_t line,
                         Msg* message, int value) {
  auto lines = Split(text_message);
  std::ostringstream oss;
  for (size_t i = 0; i != lines.size(); ++i) {
    if (i != line) {
      oss << lines[i] << '\n';
    } else {
      std::string s = lines[i];
      s.resize(s.find(':') + 2);

      if (lines[i].back() == '\"') {
        // strings
        s += value ? "\"\\" + std::to_string(value) + "\"" : "\"\"";
      } else if (lines[i].back() == 'e') {
        // bools
        s += value ? "true" : "false";
      } else {
        s += std::to_string(value);
      }
      oss << s << '\n';
    }
  }
  message->Clear();
  TextFormat::Parser parser;
  parser.AllowPartialMessage(true);
  return parser.ParseFromString(oss.str(), message);
}

bool Mutate(const Msg& from, const Msg& to) {
  EXPECT_FALSE(MessageDifferencer::Equals(from, to));

  TestProtobufMutator mutator(false);

  for (int j = 0; j < 1000000; ++j) {
    Msg message;
    message.CopyFrom(from);
    mutator.Mutate(&message, 1000);
    if (MessageDifferencer::Equals(message, to)) return true;
  }
  return false;
}

class ProtobufMutatorTest {
 protected:
  std::string test_message_;
  size_t field_;
  Msg from_;
  Msg to_;
};

class ProtobufMutatorFieldTest
    : public ProtobufMutatorTest,
      public TestWithParam<std::pair<const char*, size_t>> {
 protected:
  void SetUp() override {
    test_message_ = GetParam().first;
    field_ = GetParam().second;
  }
};

INSTANTIATE_TEST_CASE_P(AllTest, ProtobufMutatorFieldTest,
                        ValuesIn(GetFieldTestParams(
                            {kRequiredFields, kOptionalFields, kRepeatedFields,
                             kRequiredNestedFields, kOptionalNestedFields,
                             kRepeatedNestedFields})));

TEST_P(ProtobufMutatorFieldTest, Initialized) {
  LoadWithoutLine(test_message_, field_, &from_);
  TestProtobufMutator mutator(true);
  mutator.Mutate(&from_, 1000);
  EXPECT_TRUE(from_.IsInitialized());
}

TEST_P(ProtobufMutatorFieldTest, DeleteField) {
  LoadMessage(test_message_, &from_);
  LoadWithoutLine(test_message_, field_, &to_);
  EXPECT_TRUE(Mutate(from_, to_));
}

TEST_P(ProtobufMutatorFieldTest, InsertField) {
  LoadWithoutLine(test_message_, field_, &from_);
  LoadWithChangedLine(test_message_, field_, &to_, 0);
  EXPECT_TRUE(Mutate(from_, to_));
}

TEST_P(ProtobufMutatorFieldTest, ChangeField) {
  LoadWithChangedLine(test_message_, field_, &from_, 0);
  LoadWithChangedLine(test_message_, field_, &to_, 1);
  EXPECT_TRUE(Mutate(from_, to_));
  EXPECT_TRUE(Mutate(to_, from_));
}

TEST_P(ProtobufMutatorFieldTest, CopyField) {
  Msg msg1;
  LoadWithChangedLine(test_message_, field_, &msg1, 7);

  Msg msg2;
  LoadWithChangedLine(test_message_, field_, &msg2, 0);

  from_.add_repeated_msg()->CopyFrom(msg1);
  from_.add_repeated_msg()->CopyFrom(msg2);

  to_.add_repeated_msg()->CopyFrom(msg1);
  to_.add_repeated_msg()->CopyFrom(msg1);
  EXPECT_TRUE(Mutate(from_, to_));

  to_.Clear();
  to_.add_repeated_msg()->CopyFrom(msg2);
  to_.add_repeated_msg()->CopyFrom(msg2);
  EXPECT_TRUE(Mutate(from_, to_));
}

class ProtobufMutatorMessagesTest
    : public ProtobufMutatorTest,
      public TestWithParam<std::pair<const char*, size_t>> {
 protected:
  void SetUp() override {
    test_message_ = GetParam().first;
    field_ = GetParam().second;
  }
};

INSTANTIATE_TEST_CASE_P(AllTest, ProtobufMutatorMessagesTest,
                        ValuesIn(GetMessageTestParams({kMessages})));

TEST_P(ProtobufMutatorMessagesTest, DeletedMessage) {
  LoadMessage(test_message_, &from_);
  LoadWithoutLine(test_message_, field_, &to_);
  EXPECT_TRUE(Mutate(from_, to_));
}

TEST_P(ProtobufMutatorMessagesTest, InsertMessage) {
  LoadWithoutLine(test_message_, field_, &from_);
  LoadMessage(test_message_, &to_);
  EXPECT_TRUE(Mutate(from_, to_));
}

TEST(ProtobufMutatorMessagesTest, SmallBenchmark) {
  TestProtobufMutator mutator(false);
  for (int i = 0; i < 100000; ++i) {
    Msg message;
    for (int j = 0; j < 20; ++j) {
      mutator.Mutate(&message, 1000);
    }
  }
}

// TODO(vitalybuka): Better benchmark.

TEST(ProtobufMutatorMessagesTest, SizeControl) {
  const size_t kIterations = 10000;

  auto loop = [&](bool control) {
    Msg message;
    std::string str;
    TestProtobufMutator mutator(false);
    const size_t kTargetSize = 1000;
    size_t overflows = 0;
    for (size_t j = 0; j < kIterations; ++j) {
      Msg message2;
      message2.CopyFrom(message);
      mutator.Mutate(&message2,
                     control ? kTargetSize - std::min(str.size(), kTargetSize)
                             : kTargetSize);
      std::string str2;
      EXPECT_TRUE(TextFormat::PrintToString(message2, &str2));
      if (str2.size() > kTargetSize) {
        ++overflows;
      } else if (str2.size() > kTargetSize - 150 || str2.size() > str.size()) {
        message.CopyFrom(message2);
        str = str2;
      }
    }
    return overflows;
  };

  EXPECT_GT(loop(false), kIterations * 0.2);
  EXPECT_LE(loop(true), kIterations * 0.05);
}

// TODO(vitalybuka): Special tests for oneof.

TEST(ProtobufMutatorMessagesTest, UsageExample) {
  SmallMessage message;
  TestProtobufMutator mutator(false);

  // Test that we can generate all variation of the message.
  std::set<std::string> mutations;
  for (int j = 0; j < 1000; ++j) {
    mutator.Mutate(&message, 1000);
    std::string str;
    EXPECT_TRUE(TextFormat::PrintToString(message, &str));
    mutations.insert(str);
  }

  // 3 states for boolean and 5 for enum, including missing fields.
  EXPECT_EQ(3u * 5u, mutations.size());
}

}  // namespace protobuf_mutator
