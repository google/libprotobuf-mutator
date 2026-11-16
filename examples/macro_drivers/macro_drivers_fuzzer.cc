// Copyright 2026 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
////////////////////////////////////////////////////////////////////////////////
//
// Fuzzes the libFuzzer macro driver layer that every DEFINE_PROTO_FUZZER
// consumer runs, through its public API:
// - CustomProtoMutator / CustomProtoCrossOver with ample and tiny max_size
//   (tiny sizes drive the SaveMessageAs{Binary,Text} buffer-cap return-0
//   branches, unmeasured by any corpus-replay coverage run);
// - LoadProtoInput for binary and text, with valid input, garbage input
//   (parse-failure branches) and the same buffer the mutator just produced
//   (LastMutationCache Store/LoadIfSame hit path);
// - protobuf_mutator::libfuzzer::Mutator (the LLVMFuzzerMutate-backed
//   mutator subclass) in a Mutate/CrossOver campaign alternating ample and
//   tiny max_size_hint (tiny hints drive the Delete-only branch and the
//   Copy/Clone exhaustion paths in MutateImpl).
//
// The test function holds no assertions; any sanitizer finding is a genuine
// bug in the library or in protobuf itself.

#include <algorithm>
#include <string>
#include <vector>

#include "google/protobuf/text_format.h"
#include "examples/macro_drivers/macro_drivers.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/libfuzzer/libfuzzer_mutator.h"

namespace {
using protobuf_mutator::macro_drivers::Msg;

// Volatile sink keeps computations observable without adding assertions.
volatile uint64_t g_sink;

uint64_t WalkMsg(const Msg& msg) {
  uint64_t h = 0;
  h += static_cast<uint64_t>(static_cast<uint32_t>(msg.i32()));
  h += msg.u32();
  h += msg.u64();
  h += msg.b();
  h += static_cast<uint64_t>(msg.kind());
  h += msg.s().size();
  for (int64_t v : msg.rep_i64()) h += static_cast<uint64_t>(v);
  return h;
}

std::string ToText(const Msg& msg) {
  std::string text;
  google::protobuf::TextFormat::PrintToString(msg, &text);
  return text;
}
}  // namespace

DEFINE_BINARY_PROTO_FUZZER(const protobuf_mutator::macro_drivers::Msg& input) {
  protobuf_mutator::libfuzzer::Mutator mutator;
  Msg msg = input;
  const uint64_t seed = WalkMsg(input) ^ input.ByteSizeLong();

  // Campaign through the libfuzzer::Mutator subclass (LLVMFuzzerMutate
  // overrides); alternating tiny hints drives the MutateImpl small-budget
  // and Copy/Clone exhaustion branches.
  for (int i = 0; i < 8; ++i) {
    mutator.Seed(static_cast<uint32_t>(seed) ^
                 (static_cast<uint32_t>(i) * 0x9E3779B9u));
    size_t hint = (i % 4 == 3) ? 12 : 4096;
    mutator.Mutate(&msg, hint);
    g_sink ^= WalkMsg(msg);
    if (i % 4 == 2) {
      Msg other = msg;
      mutator.CrossOver(input, &other, (i % 8 == 6) ? 12 : 4096);
      g_sink ^= WalkMsg(other);
    }
  }

  // Drive the macro layer directly: mutate and crossover through
  // CustomProtoMutator / CustomProtoCrossOver in both serialization formats
  // with schedule-driven max_size (ample and tiny, so the save-cap
  // return-0 branches stay exercised), then replay through LoadProtoInput
  // (cache-hit) plus garbage inputs (parse-failure). The schedule is
  // input-dependent (derived from the same shape hash as the campaign seed)
  // so distinct corpus units drive distinct driver paths.
  Msg m2 = input;
  std::string blob = m2.SerializeAsString();
  std::vector<uint8_t> bin(4096, 0);
  std::copy(blob.begin(), blob.end(), bin.begin());
  std::string text = ToText(m2);
  std::vector<uint8_t> txt(4096, 0);
  std::copy(text.begin(), text.end(), txt.begin());
  std::vector<uint8_t> out(4096, 0);
  static const size_t kCaps[4] = {4096, 3, 17, 512};

  for (int i = 0; i < 4; ++i) {
    const uint64_t sched = seed >> (i * 7);
    const bool binary = (sched & 1) != 0;
    std::vector<uint8_t>& buf = binary ? bin : txt;
    const size_t in_size = binary ? blob.size() : text.size();
    size_t n = protobuf_mutator::libfuzzer::CustomProtoMutator(
        binary, buf.data(), in_size, kCaps[(sched >> 3) & 3],
        static_cast<unsigned>(sched), &m2);
    if (i == 0) {
      // Tiny max_size drives the SaveMessageAs* buffer-cap return-0 branch.
      protobuf_mutator::libfuzzer::CustomProtoMutator(
          binary, buf.data(), in_size, 3, static_cast<unsigned>(sched), &m2);
      protobuf_mutator::libfuzzer::CustomProtoCrossOver(
          binary, buf.data(), in_size, buf.data(), in_size, out.data(),
          out.size(), static_cast<unsigned>(sched), &m2, &msg);
    }
    // Replay the mutated buffer through the same format: parse success and,
    // when the engine last stored this buffer, the LastMutationCache hit.
    protobuf_mutator::libfuzzer::LoadProtoInput(binary, buf.data(), n, &msg);
    g_sink ^= WalkMsg(msg) ^ n;
  }

  // Garbage inputs drive the parse-failure branches of both formats. The
  // bytes are input-derived so corpus diversity translates into diverse
  // parser-failure shapes instead of one fixed sequence.
  std::vector<uint8_t> garbage(24, 0);
  uint64_t g = seed ^ 0x5851f42d4c957f2dULL;
  for (size_t i = 0; i < garbage.size(); ++i) {
    g = g * 6364136223846793005ULL + 1442695040888963407ULL;
    static const uint8_t kBytes[] = {0xff, 0x01, 0x7f, '#',  '!',   '\n',
                                     0x80, 0x02, '?',  '\\', '{',   '}',
                                     '"',  ' ',  0x00, ':'};
    garbage[i] = kBytes[g % sizeof(kBytes)];
  }
  protobuf_mutator::libfuzzer::LoadProtoInput(true, garbage.data(),
                                              garbage.size(), &msg);
  protobuf_mutator::libfuzzer::LoadProtoInput(false, garbage.data(),
                                              garbage.size(), &msg);
  protobuf_mutator::libfuzzer::LoadProtoInput(false, txt.data(), text.size(),
                                              &msg);
  protobuf_mutator::libfuzzer::LoadProtoInput(true, txt.data(), text.size(),
                                              &msg);

  g_sink ^= msg.ByteSizeLong() ^ m2.ByteSizeLong();
}
