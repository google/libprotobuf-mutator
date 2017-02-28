# libprotobuf-mutator

## Overview
libprotobuf-mutator is a library to randomly mutate
[protobuffers](https://github.com/google/protobuf). <BR>
It could be used together with guided
fuzzing engines, such as [libFuzzer](http://libfuzzer.info).

## Quick start on Debian/Ubuntu

Install prerequisites:

```
sudo apt-get update
sudo apt-get install binutils cmake ninja-build liblzma-dev libz-dev docbook2x
```

Compile and test everything:

```
mkdir build
cd build
cmake .. -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
ninja check
```

Clang is only needed for libFuzzer integration.

## Usage

To use libprotobuf-mutator simply include
[protobuf_mutator.h](/src/protobuf_mutator.h) and
[protobuf_mutator.cc](/src/protobuf_mutator.cc) into your build files.

The `ProtobufMutator` class implements mutations of the protobuf
tree structure and mutations of individual fields.
The field mutation logic is very basic --
for better results you should override the `ProtobufMutator::Mutate*`
methods with more sophisticated logic, e.g.
using [libFuzzer](http://libfuzzer.info)'s mutators.

To apply one mutation to a protobuf object do the following:
```
class MyProtobufMutator : public ProtobufMutator {
 public:
  MyProtobufMutator(uint32_t seed) : ProtobufMutator(seed) {}
  // Optionally redefine the Mutate* methods to perform more sophisticated mutations.
}
void Mutate(MyMessage* message) {
  MyProtobufMutator mutator(my_random_seed);
  mutator.Mutate(message, 200);
}
```

See also the `ProtobufMutatorMessagesTest.UsageExample` test from
[protobuf_mutator_test.cc](/src/protobuf_mutator_test.cc).

## Integrating with libFuzzer
LibFuzzerProtobufMutator can help to integrate with libFuzzer. For example 

```
#include "libfuzzer_protobuf_mutator.h"

extern "C" size_t LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
                                          size_t max_size, unsigned int seed) {
  return protobuf_mutator::MutateTextMessage<MyMessageType>(
      data, size, max_size, seed);
}

extern "C" size_t LLVMFuzzerCustomCrossOver(const uint8_t* data1, size_t size1,
                                            const uint8_t* data2, size_t size2,
                                            uint8_t* out, size_t max_out_size,
                                            unsigned int seed) {
  return protobuf_mutator::CrossOverTextMessages<MyMessageType>(
      data1, size1, data2, size2, out, max_out_size, seed);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  MyMessageType message;
  protobuf_mutator::ParseTextMessage(data, size, &message);
  
  // Code which needs to be fuzzed.
  ConsumeMyMessageType(message);
  return 0;
}
```

Please see [libfuzzer_example.cc](/examples/libfuzzer/libfuzzer_example.cc) as an example.
