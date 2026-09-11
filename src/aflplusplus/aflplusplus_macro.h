#ifndef SRC_AFLPLUSPLUS_AFLPLUSPLUS_MACRO_H_
#define SRC_AFLPLUSPLUS_AFLPLUSPLUS_MACRO_H_

#include <stddef.h>
#include <stdint.h>

#include "port/protobuf.h"
#include "src/mutation_io.h"

// Defines the whole afl-fuzz custom mutator interface for the given protobuf
// message type. Put this in a single translation unit, build it as a shared
// object and point AFL_CUSTOM_MUTATOR_LIBRARY at it. The fuzz target has to be
// defined with the matching macro below, text with text, binary with binary.
#define DEFINE_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY(Proto) \
  DEFINE_TEXT_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY(Proto)
// Text serialization is easier to read; binary makes mutations faster.
#define DEFINE_TEXT_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY(Proto) \
  DEFINE_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY_IMPL(false, Proto)
#define DEFINE_BINARY_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY(Proto) \
  DEFINE_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY_IMPL(true, Proto)

// Defines the fuzz target entry point.
#define DEFINE_AFLPLUSPLUS_PROTO_FUZZER(arg) \
  DEFINE_TEXT_AFLPLUSPLUS_PROTO_FUZZER(arg)
#define DEFINE_TEXT_AFLPLUSPLUS_PROTO_FUZZER(arg) \
  DEFINE_AFLPLUSPLUS_PROTO_FUZZER_IMPL(false, arg)
#define DEFINE_BINARY_AFLPLUSPLUS_PROTO_FUZZER(arg) \
  DEFINE_AFLPLUSPLUS_PROTO_FUZZER_IMPL(true, arg)

#define DEFINE_AFLPLUSPLUS_CUSTOM_INIT_IMPL(use_binary)              \
  extern "C" void* afl_custom_init(void* afl, unsigned int seed) {   \
    return protobuf_mutator::aflplusplus::CreateMutator(afl, seed,   \
                                                        use_binary); \
  }

#define DEFINE_AFLPLUSPLUS_CUSTOM_DEINIT_IMPL            \
  extern "C" void afl_custom_deinit(void* data) {        \
    protobuf_mutator::aflplusplus::DestroyMutator(data); \
  }

#define DEFINE_AFLPLUSPLUS_CUSTOM_FUZZ_IMPL(Proto)                          \
  extern "C" size_t afl_custom_fuzz(                                        \
      void* data, unsigned char* buf, size_t buf_size,                      \
      unsigned char** out_buf, unsigned char* add_buf, size_t add_buf_size, \
      size_t max_size) {                                                    \
    Proto input1;                                                           \
    Proto input2;                                                           \
    return protobuf_mutator::aflplusplus::CustomProtoFuzz(                  \
        data, buf, buf_size, out_buf, add_buf, add_buf_size, max_size,      \
        &input1, &input2);                                                  \
  }

#define DEFINE_AFLPLUSPLUS_CUSTOM_TRIM_IMPL(Proto)                         \
  extern "C" int afl_custom_init_trim(void* data, unsigned char* buf,      \
                                      size_t buf_size) {                   \
    Proto input;                                                           \
    return protobuf_mutator::aflplusplus::CustomProtoInitTrim(             \
        data, buf, buf_size, &input);                                      \
  }                                                                        \
  extern "C" size_t afl_custom_trim(void* data, unsigned char** out_buf) { \
    return protobuf_mutator::aflplusplus::CustomProtoTrim(data, out_buf);  \
  }                                                                        \
  extern "C" int afl_custom_post_trim(void* data, unsigned char success) { \
    return protobuf_mutator::aflplusplus::CustomProtoPostTrim(data,        \
                                                              success);    \
  }

#define DEFINE_AFLPLUSPLUS_PROTO_MUTATOR_LIBRARY_IMPL(use_binary, Proto) \
  DEFINE_AFLPLUSPLUS_CUSTOM_INIT_IMPL(use_binary)                        \
  DEFINE_AFLPLUSPLUS_CUSTOM_FUZZ_IMPL(Proto)                             \
  DEFINE_AFLPLUSPLUS_CUSTOM_TRIM_IMPL(Proto)                             \
  DEFINE_AFLPLUSPLUS_CUSTOM_DEINIT_IMPL

#define DEFINE_AFLPLUSPLUS_PROTO_FUZZER_IMPL(use_binary, arg)               \
  static void TestOneProtoInput(arg);                                       \
  using FuzzerProtoType = protobuf_mutator::macro_internal::                \
      GetFirstParam<decltype(&TestOneProtoInput)>::type;                    \
  extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) { \
    FuzzerProtoType input;                                                  \
    if (protobuf_mutator::aflplusplus::LoadProtoInput(use_binary, data,     \
                                                      size, &input))        \
      TestOneProtoInput(input);                                             \
    return 0;                                                               \
  }                                                                         \
  static void TestOneProtoInput(arg)

namespace protobuf_mutator {
namespace aflplusplus {

void* CreateMutator(void* afl, unsigned int seed, bool binary);
void DestroyMutator(void* data);
size_t CustomProtoFuzz(void* data, uint8_t* buf, size_t buf_size,
                       uint8_t** out_buf, uint8_t* add_buf, size_t add_buf_size,
                       size_t max_size, protobuf::Message* input1,
                       protobuf::Message* input2);
int CustomProtoInitTrim(void* data, uint8_t* buf, size_t buf_size,
                        protobuf::Message* scratch);
size_t CustomProtoTrim(void* data, uint8_t** out_buf);
int CustomProtoPostTrim(void* data, unsigned char success);

bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    protobuf::Message* input);

}  // namespace aflplusplus
}  // namespace protobuf_mutator

#endif  // SRC_AFLPLUSPLUS_AFLPLUSPLUS_MACRO_H_
