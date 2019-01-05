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
sudo apt-get install binutils cmake ninja-build liblzma-dev libz-dev pkg-config
```

Compile and test everything:

```
mkdir build
cd build
cmake .. -GNinja -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DCMAKE_BUILD_TYPE=Debug
ninja check
```

Clang is only needed for libFuzzer integration. <BR>
By default, the system-installed version of
[protobuf](https://github.com/google/protobuf) is used.  However, on some
systems, the system version is too old.  You can pass
`LIB_PROTO_MUTATOR_DOWNLOAD_PROTOBUF=ON` to cmake to automatically download and
build a working version of protobuf.

Installation:

```
ninja
sudo ninja install
```

This installs the headers, pkg-config, and static library.
By default the headers are put in `/usr/local/include/libprotobuf-mutator`.

## Usage

To use libprotobuf-mutator simply include
[mutator.h](/src/mutator.h) and
[mutator.cc](/src/mutator.cc) into your build files.

The `ProtobufMutator` class implements mutations of the protobuf
tree structure and mutations of individual fields.
The field mutation logic is very basic --
for better results you should override the `ProtobufMutator::Mutate*`
methods with more sophisticated logic, e.g.
using [libFuzzer](http://libfuzzer.info)'s mutators.

To apply one mutation to a protobuf object do the following:

```
class MyProtobufMutator : public protobuf_mutator::Mutator {
 public:
  MyProtobufMutator(uint32_t seed) : protobuf_mutator::Mutator(seed) {}
  // Optionally redefine the Mutate* methods to perform more sophisticated mutations.
}
void Mutate(MyMessage* message) {
  MyProtobufMutator mutator(my_random_seed);
  mutator.Mutate(message, 200);
}
```

See also the `ProtobufMutatorMessagesTest.UsageExample` test from
[mutator_test.cc](/src/mutator_test.cc).

## Integrating with libFuzzer
LibFuzzerProtobufMutator can help to integrate with libFuzzer. For example 

```
#include "src/libfuzzer/libfuzzer_macro.h"

DEFINE_PROTO_FUZZER(const MyMessageType& input) {
  // Code which needs to be fuzzed.
  ConsumeMyMessageType(input);
}
```

Please see [libfuzzer_example.cc](/examples/libfuzzer/libfuzzer_example.cc) as an example.

## UTF-8 strings
"proto2" and "proto3" handle invalid UTF-8 strings differently. In both cases
string should be UTF-8, however only "proto3" enforces that. So if fuzzer is
applied to "proto2" type libprotobuf-mutator will generate any strings including
invalid UTF-8. If it's a "proto3" message type, only valid UTF-8 will be used.

## Users of the library
* [Chromium](https://cs.chromium.org/search/?q=DEFINE_.*._PROTO_FUZZER%5C\()
* [Envoy](https://github.com/envoyproxy/envoy/search?q=DEFINE_TEXT_PROTO_FUZZER+OR+DEFINE_PROTO_FUZZER+OR+DEFINE_BINARY_PROTO_FUZZER&unscoped_q=DEFINE_TEXT_PROTO_FUZZER+OR+DEFINE_PROTO_FUZZER+OR+DEFINE_BINARY_PROTO_FUZZER&type=Code)
* [LLVM](https://github.com/llvm-mirror/clang/search?q=DEFINE_TEXT_PROTO_FUZZER+OR+DEFINE_PROTO_FUZZER+OR+DEFINE_BINARY_PROTO_FUZZER&unscoped_q=DEFINE_TEXT_PROTO_FUZZER+OR+DEFINE_PROTO_FUZZER+OR+DEFINE_BINARY_PROTO_FUZZER&type=Code)

## Bugs found with help of the library

### Chromium
* [AppCache exploit](http://www.powerofcommunity.net/poc2018/ned.pdf) ([Actual still restricted bug](https://bugs.chromium.org/p/chromium/issues/detail?id=888926))
* [Stack Buffer Overflow in QuicClientPromisedInfo](https://bugs.chromium.org/p/chromium/issues/detail?id=777728)
* [null dereference in sqlite3ExprCompare](https://bugs.chromium.org/p/chromium/issues/detail?id=911251)
### Envoy
* [strftime overflow](https://github.com/envoyproxy/envoy/pull/4321)
* [Heap-use-after-free in Envoy::Upstream::SubsetLoadBalancer::updateFallbackSubset](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=8028)
* [Heap-use-after-free in Envoy::Secret::SecretManagerImpl](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=11231)
* [Heap-buffer-overflow in Envoy::Http::HeaderString](https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=10038)

## Related materials
* [Attacking Chrome IPC: Reliably finding bugs to escape the Chrome sandbox](https://media.ccc.de/v/35c3-9579-attacking_chrome_ipc)
* [Structure-aware fuzzing for Clang and LLVM with libprotobuf-mutator](https://www.youtube.com/watch?v=U60hC16HEDY)
