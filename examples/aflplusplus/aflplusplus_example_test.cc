#include <dlfcn.h>
#include <stdlib.h>

#include <memory>
#include <string>

#include "google/protobuf/dynamic_message.h"
#include "port/gtest.h"
#include "port/protobuf.h"
#include "src/mutation_io.h"

extern "C" {
#include "config.h"
#include "types.h"
#include "afl-fuzz.h"
}

namespace {

using CustomInit = void* (*)(void*, unsigned int);
using CustomFuzz = size_t (*)(void*, unsigned char*, size_t, unsigned char**,
                              unsigned char*, size_t, size_t);
using CustomDeinit = void (*)(void*);

class AflplusplusExampleTest : public testing::Test {
 protected:
  static void SetUpTestSuite() {
    handle_ =
        dlopen(AFLPLUSPLUS_EXAMPLE_MUTATOR_PATH, RTLD_NOW | RTLD_NODELETE);
    ASSERT_TRUE(handle_) << dlerror();
  }

  void SetUp() override {
    setenv("AFL_CUSTOM_MUTATOR_ONLY", "1", 1);
    afl_.reset(new afl_state_t());
    afl_->fixed_seed = 1;
    rand_set_seed(afl_.get(), 1);
  }

  template <class T>
  static T Symbol(const char* name) {
    return reinterpret_cast<T>(dlsym(handle_, name));
  }

  static void* handle_;
  std::unique_ptr<afl_state_t> afl_;
};

void* AflplusplusExampleTest::handle_ = nullptr;

TEST_F(AflplusplusExampleTest, ExportsCustomMutatorApi) {
  for (const char* name :
       {"afl_custom_init", "afl_custom_fuzz", "afl_custom_deinit",
        "afl_custom_init_trim", "afl_custom_trim", "afl_custom_post_trim"}) {
    EXPECT_TRUE(dlsym(handle_, name)) << "missing symbol " << name;
  }
}

TEST_F(AflplusplusExampleTest, ProducesParseableMessages) {
  auto init = Symbol<CustomInit>("afl_custom_init");
  auto fuzz = Symbol<CustomFuzz>("afl_custom_fuzz");
  auto deinit = Symbol<CustomDeinit>("afl_custom_deinit");
  ASSERT_TRUE(init);
  ASSERT_TRUE(fuzz);
  ASSERT_TRUE(deinit);

  const protobuf_mutator::protobuf::Descriptor* descriptor =
      protobuf_mutator::protobuf::DescriptorPool::generated_pool()
          ->FindMessageTypeByName("aflplusplus_example.Msg");
  ASSERT_TRUE(descriptor);
  protobuf_mutator::protobuf::DynamicMessageFactory factory;
  std::unique_ptr<protobuf_mutator::protobuf::Message> message(
      factory.GetPrototype(descriptor)->New());

  void* mutator = init(afl_.get(), 1);
  ASSERT_TRUE(mutator);

  unsigned char buf[4096] = {};
  int produced = 0;
  for (int i = 0; i < 100; ++i) {
    unsigned char* out = nullptr;
    size_t size = fuzz(mutator, buf, 0, &out, nullptr, 0, sizeof(buf));
    if (!size) continue;
    ASSERT_TRUE(out);
    ++produced;
    EXPECT_TRUE(protobuf_mutator::ParseMessage(false, out, size, message.get()));
  }
  EXPECT_GT(produced, 0);

  deinit(mutator);
}

}  // namespace
