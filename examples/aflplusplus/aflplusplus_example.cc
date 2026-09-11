#include <stdlib.h>

#include <iostream>

#include "examples/aflplusplus/aflplusplus_example.pb.h"
#include "src/aflplusplus/aflplusplus_macro.h"

DEFINE_AFLPLUSPLUS_PROTO_FUZZER(const aflplusplus_example::Msg& message) {
  if (message.optional_string() == "afl" && message.nested_size() > 2 &&
      message.nested(0).optional_uint64() == 0xdeadbeef) {
    std::cerr << message.DebugString() << "\n";
    abort();
  }
}
