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
// Long UTF-8 mutation campaign: every Mutate call on this schema mutates
// UTF-8 validated proto3 strings, so FixUtf8String walks large random
// buffers every iteration. The fixer's per-sequence branches (2-byte
// reshaping, 3-byte surrogate redistribution, 4-byte out-of-range redraw)
// are pure pointer/integer arithmetic over attacker-controlled bytes; this
// harness holds them under sustained sanitised pressure. No assertions:
// any sanitizer finding is a genuine bug in the library.

#include <string>

#include "examples/utf8_fix/utf8_fix.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/mutator.h"

namespace {
using protobuf_mutator::utf8fix::Texts;

volatile uint64_t g_sink;

uint64_t WalkTexts(const Texts& texts) {
  uint64_t h = texts.text().size();
  for (const std::string& s : texts.rep_text()) h += s.size() + 1;
  h += texts.more().size();
  return h;
}
}  // namespace

DEFINE_BINARY_PROTO_FUZZER(const protobuf_mutator::utf8fix::Texts& input) {
  protobuf_mutator::Mutator mutator;
  Texts msg = input;

  // Input-dependent campaign schedule: distinct corpus units drive distinct
  // campaign lengths, per-iteration size hints and crossover points, so the
  // UTF-8 fixer keeps seeing new buffer shapes instead of a fixed schedule.
  const uint64_t sched = WalkTexts(input) ^ input.ByteSizeLong();
  const int iterations = 32 + static_cast<int>(sched % 97);  // 32..128
  static const size_t kHints[4] = {16384, 8192, 4096, 2048};

  for (int i = 0; i < iterations; ++i) {
    mutator.Seed(static_cast<uint32_t>(sched >> ((i * 5) % 32)) ^
                 (static_cast<uint32_t>(i) * 0x9E3779B9u));
    mutator.Mutate(&msg, kHints[(sched >> ((i * 3) % 30)) & 3]);
    g_sink ^= WalkTexts(msg);
    if (((sched >> (i % 26)) & 1) && i % 10 == 9) {
      Texts other = input;
      mutator.CrossOver(msg, &other, kHints[(sched >> ((i * 7) % 28)) & 3]);
      g_sink ^= WalkTexts(other);
    }
  }
  g_sink ^= msg.ByteSizeLong();
}
