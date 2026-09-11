#include "src/aflplusplus/aflplusplus_macro.h"

#include "src/aflplusplus/aflplusplus_mutator.h"
#include "src/mutation_io.h"
#include "src/mutator.h"

namespace protobuf_mutator {
namespace aflplusplus {

namespace {

Mutator* AsMutator(void* data) { return static_cast<Mutator*>(data); }


protobuf_mutator::Mutator* GetMutator() {
  static protobuf_mutator::Mutator mutator;
  return &mutator;
}

}  // namespace

void* CreateMutator(void* afl, unsigned int seed, bool binary) {
  return Mutator::Create(afl, seed, binary);
}

void DestroyMutator(void* data) { delete AsMutator(data); }

size_t CustomProtoFuzz(void* data, uint8_t* buf, size_t buf_size,
                       uint8_t** out_buf, uint8_t* add_buf, size_t add_buf_size,
                       size_t max_size, protobuf::Message* input1,
                       protobuf::Message* input2) {
  return AsMutator(data)->Fuzz(buf, buf_size, out_buf, add_buf, add_buf_size,
                               max_size, input1, input2);
}

int CustomProtoInitTrim(void* data, uint8_t* buf, size_t buf_size,
                        protobuf::Message* scratch) {
  return AsMutator(data)->InitTrim(buf, buf_size, scratch);
}

size_t CustomProtoTrim(void* data, uint8_t** out_buf) {
  return AsMutator(data)->Trim(out_buf);
}

int CustomProtoPostTrim(void* data, unsigned char success) {
  return AsMutator(data)->PostTrim(success != 0);
}

bool LoadProtoInput(bool binary, const uint8_t* data, size_t size,
                    protobuf::Message* input) {
  return protobuf_mutator::LoadProtoInput(binary, data, size,
                                          GetMutator(), input);
}

}  // namespace aflplusplus
}  // namespace protobuf_mutator
