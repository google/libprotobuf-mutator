#include <stdlib.h>

#include <memory>
#include <string>
#include <vector>

#include "port/gtest.h"
#include "port/protobuf.h"
#include "src/aflplusplus/aflplusplus_macro.h"
#include "src/mutation_io.h"
#include "src/mutator.h"
#include "src/mutator_test_proto2.pb.h"

extern "C" {
#include "config.h"
#include "types.h"
#include "afl-fuzz.h"
}

using ::testing::StrictMock;

static class MockFuzzer* mock_fuzzer;

class MockFuzzer {
 public:
  MockFuzzer() { mock_fuzzer = this; }
  ~MockFuzzer() { mock_fuzzer = nullptr; }
  MOCK_METHOD(void, TestOneInput, (const protobuf_mutator::Msg& message));
};

DEFINE_TEXT_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY(protobuf_mutator::Msg)

DEFINE_TEXT_AFLPLUSPLUS_PROTO_FUZZER(const protobuf_mutator::Msg& message) {
  mock_fuzzer->TestOneInput(message);
}

MATCHER(IsInitialized, "") { return arg.IsInitialized(); }

namespace {

std::string MakeMessage() {
  protobuf_mutator::Msg message;
  message.set_optional_int32(42);
  message.set_optional_string("trim me");
  message.add_repeated_int32(1);
  message.add_repeated_int32(2);
  message.add_repeated_string("first");
  message.add_repeated_msg()->set_optional_int64(3);

  protobuf_mutator::Mutator fixer;
  fixer.Seed(1);
  fixer.Fix(&message);

  return protobuf_mutator::SaveMessage(false, message);
}

class AflplusplusTest : public testing::Test {
 protected:
  void SetUp() override {
    setenv("AFL_CUSTOM_MUTATOR_ONLY", "1", 1);

    afl_.reset(new afl_state_t());
    afl_->fixed_seed = 1;
    rand_set_seed(afl_.get(), 1);

    mutator_ = afl_custom_init(afl_.get(), 7);
    ASSERT_TRUE(mutator_);
  }

  void TearDown() override { afl_custom_deinit(mutator_); }

  size_t Fuzz(unsigned char* buf, size_t buf_size, unsigned char** out_buf,
              unsigned char* add_buf, size_t add_buf_size, size_t max_size) {
    for (int i = 0; i < 100; ++i) {
      if (size_t size = afl_custom_fuzz(mutator_, buf, buf_size, out_buf,
                                        add_buf, add_buf_size, max_size))
        return size;
    }
    return 0;
  }

  std::unique_ptr<afl_state_t> afl_;
  void* mutator_ = nullptr;
};

TEST_F(AflplusplusTest, LLVMFuzzerTestOneInput) {
  StrictMock<MockFuzzer> mock;
  EXPECT_CALL(mock, TestOneInput(IsInitialized()));
  LLVMFuzzerTestOneInput(reinterpret_cast<const uint8_t*>(""), 0);
}

TEST_F(AflplusplusTest, AflCustomFuzz) {
  StrictMock<MockFuzzer> mock;
  EXPECT_CALL(mock, TestOneInput(IsInitialized()));

  unsigned char buf[4096] = {};
  unsigned char* out = nullptr;
  size_t size = Fuzz(buf, 0, &out, nullptr, 0, sizeof(buf));
  ASSERT_GT(size, 0U);
  ASSERT_TRUE(out);
  LLVMFuzzerTestOneInput(out, size);
}

TEST_F(AflplusplusTest, AflCustomFuzzWithSpliceBuffer) {
  const int kRuns = 20;
  std::string seed = MakeMessage();
  std::string splice = MakeMessage();

  StrictMock<MockFuzzer> mock;
  EXPECT_CALL(mock, TestOneInput(IsInitialized())).Times(kRuns);

  std::vector<unsigned char> buf(seed.begin(), seed.end());
  buf.resize(4096);
  for (int i = 0; i < kRuns; ++i) {
    unsigned char* out = nullptr;
    size_t size =
        Fuzz(buf.data(), seed.size(), &out,
             reinterpret_cast<unsigned char*>(&splice[0]), splice.size(),
             buf.size());
    ASSERT_GT(size, 0U);
    ASSERT_TRUE(out);
    LLVMFuzzerTestOneInput(out, size);
  }
}

TEST_F(AflplusplusTest, AflCustomTrim) {
  std::string data = MakeMessage();
  std::vector<unsigned char> buf(data.begin(), data.end());

  int steps = afl_custom_init_trim(mutator_, buf.data(), buf.size());
  ASSERT_GT(steps, 0);

  unsigned char* out = nullptr;
  size_t size = afl_custom_trim(mutator_, &out);
  ASSERT_TRUE(out);
  ASSERT_GT(size, 0U);
  EXPECT_LT(size, buf.size());

  int next = afl_custom_post_trim(mutator_, 1);
  EXPECT_GE(next, 0);
  EXPECT_LE(next, steps);
}

TEST_F(AflplusplusTest, AflCustomTrimTerminates) {
  std::string data = MakeMessage();
  std::vector<unsigned char> buf(data.begin(), data.end());

  int steps = afl_custom_init_trim(mutator_, buf.data(), buf.size());
  ASSERT_GT(steps, 0);

  size_t previous = buf.size();
  int cur = 0;
  int iterations = 0;
  while (cur < steps) {
    unsigned char* out = nullptr;
    size_t size = afl_custom_trim(mutator_, &out);
    ASSERT_TRUE(out);
    ASSERT_GT(size, 0U);
    EXPECT_LE(size, previous);
    previous = size;

    cur = afl_custom_post_trim(mutator_, 1);
    ASSERT_GE(cur, 0);
    ASSERT_LE(++iterations, steps);
  }
  EXPECT_LT(previous, buf.size());
}

TEST_F(AflplusplusTest, AflCustomTrimRejectsEverything) {
  std::string data = MakeMessage();
  std::vector<unsigned char> buf(data.begin(), data.end());

  int steps = afl_custom_init_trim(mutator_, buf.data(), buf.size());
  ASSERT_GT(steps, 0);

  int cur = 0;
  int iterations = 0;
  while (cur < steps) {
    unsigned char* out = nullptr;
    ASSERT_GT(afl_custom_trim(mutator_, &out), 0U);
    ASSERT_TRUE(out);
    cur = afl_custom_post_trim(mutator_, 0);
    ASSERT_GE(cur, 0);
    ASSERT_LE(++iterations, steps);
  }

  unsigned char* out = nullptr;
  size_t size = afl_custom_trim(mutator_, &out);
  ASSERT_TRUE(out);
  EXPECT_EQ(data, std::string(reinterpret_cast<char*>(out), size));
}

TEST_F(AflplusplusTest, AflCustomFuzzDropsTooDeepMutations) {
  protobuf_mutator::Msg message;
  protobuf_mutator::Msg* deepest = &message;
  for (int i = 0; i < 100; ++i) deepest = deepest->mutable_optional_msg();
  std::string seed = protobuf_mutator::SaveMessage(false, message);

  const int kRuns = 200;
  std::vector<unsigned char> buf(seed.begin(), seed.end());
  buf.resize(1 << 20);

  int dropped = 0;
  for (int i = 0; i < kRuns; ++i) {
    unsigned char* out = nullptr;
    size_t size = afl_custom_fuzz(mutator_, buf.data(), seed.size(), &out,
                                  nullptr, 0, buf.size());
    if (!size) {
      ++dropped;
      continue;
    }
    ASSERT_TRUE(out);
    protobuf_mutator::Msg parsed;
    EXPECT_TRUE(protobuf_mutator::ParseMessage(false, out, size, &parsed))
        << "mutation " << i << " of " << size << " bytes does not parse back";
  }

  EXPECT_GT(dropped, 0);
}

TEST_F(AflplusplusTest, AflCustomTrimShrinksStringValues) {
  protobuf_mutator::Msg message;
  message.set_optional_string("keep" + std::string(500, 'x'));
  protobuf_mutator::Mutator fixer;
  fixer.Seed(1);
  fixer.Fix(&message);
  const std::string data = protobuf_mutator::SaveMessage(false, message);

  std::vector<unsigned char> buf(data.begin(), data.end());
  int steps = afl_custom_init_trim(mutator_, buf.data(), buf.size());
  ASSERT_GT(steps, 0);

  std::string last = data;
  int cur = 0;
  int iterations = 0;
  while (cur < steps) {
    unsigned char* out = nullptr;
    size_t size = afl_custom_trim(mutator_, &out);
    ASSERT_TRUE(out);

    protobuf_mutator::Msg candidate;
    const bool keeps_prefix =
        protobuf_mutator::ParseMessage(false, out, size, &candidate) &&
        candidate.optional_string().compare(0, 4, "keep") == 0;
    if (keeps_prefix) last.assign(reinterpret_cast<char*>(out), size);

    cur = afl_custom_post_trim(mutator_, keeps_prefix);
    ASSERT_GE(cur, 0);
    ASSERT_LT(++iterations, 100000);
  }

  protobuf_mutator::Msg trimmed;
  ASSERT_TRUE(protobuf_mutator::ParseMessage(
      false, reinterpret_cast<const uint8_t*>(last.data()), last.size(),
      &trimmed));
  EXPECT_EQ("keep", trimmed.optional_string());
  EXPECT_LT(last.size(), data.size());
}

}  // namespace
