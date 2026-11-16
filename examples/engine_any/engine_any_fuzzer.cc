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
// Fuzzes libprotobuf-mutator's Any and post-processor machinery:
// - DEFINE_TEXT_PROTO_FUZZER drives the text serialization path
//   (src/text_format.cc) that the binary-format targets never touch;
// - google.protobuf.Any fields (singular + repeated) drive UnpackAny /
//   UnpackIfAny / CastToAny and the Any repack branch of PostProcessing::Run
//   (src/mutator.cc), including type_url strings the mutator fills with
//   arbitrary bytes;
// - PostProcessorRegistration callbacks drive RegisterPostProcessor and the
//   post-processor dispatch inside PostProcessing::Run, following the same
//   pattern as LPM's own examples/libfuzzer harness (without its emulated
//   abort: findings here are real findings);
// - a required proto2 field drives the keep_initialized default-creation
//   path and the required-field gating in the mutation sampler.
//
// The test function only unpacks and reads the message; any sanitizer
// finding is a genuine bug in the library or in protobuf itself.

#include <cstring>
#include <string>

#include "examples/engine_any/engine_any.pb.h"
#include "google/protobuf/any.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/mutator.h"

namespace {
using protobuf_mutator::libfuzzer::PostProcessorRegistration;
using protobuf_mutator::engine_any::Holder;
using protobuf_mutator::engine_any::Inner;
using protobuf_mutator::engine_any::Payload;

// Volatile sink keeps the walk observable without adding assertions.
volatile uint64_t g_sink;

const char kPayloadTypeUrl[] =
    "type.googleapis.com/protobuf_mutator.engine_any.Payload";
const char kInnerTypeUrl[] =
    "type.googleapis.com/protobuf_mutator.engine_any.Inner";

// Guide the mutator to Any payloads it can actually unpack and repack,
// alternating between the two resolvable types (seed-dependent, so distinct
// corpus units favour distinct payloads), while still letting mutated
// type_urls resolve to nothing (the failure path is exercised too).
protobuf_mutator::libfuzzer::PostProcessorRegistration<google::protobuf::Any> reg_any = {
    [](google::protobuf::Any* any, unsigned int seed) {
      if (any->type_url().empty())
        any->set_type_url((seed & 1) ? kPayloadTypeUrl : kInnerTypeUrl);
    }};

protobuf_mutator::libfuzzer::PostProcessorRegistration<Payload> reg_payload = {
    [](Payload* payload, unsigned int) {
      if (payload->name().empty()) payload->set_name("seed");
    }};

uint64_t WalkPayload(const Payload& payload) {
  return payload.name().size() + static_cast<uint64_t>(payload.id());
}

uint64_t WalkAny(const google::protobuf::Any& any) {
  Payload payload;
  if (any.UnpackTo(&payload)) return WalkPayload(payload) + 0x9E37u;
  return any.type_url().size() + any.value().size();
}

uint64_t WalkHolder(const Holder& holder) {
  uint64_t h = holder.label().size();
  if (holder.has_any()) h += WalkAny(holder.any());
  for (const google::protobuf::Any& any : holder.rep_any()) h += WalkAny(any);
  if (holder.has_inner()) {
    h += holder.inner().tag().size();
    for (const Payload& payload : holder.inner().rep_payload())
      h += WalkPayload(payload) + 1;
  }
  double d = holder.ratio();
  uint64_t bits;
  memcpy(&bits, &d, sizeof(bits));
  h += bits;
  for (uint64_t v : holder.rep_u64()) h += v;
  return h;
}
}  // namespace

DEFINE_TEXT_PROTO_FUZZER(const protobuf_mutator::engine_any::Holder& input) {
  // In-body mutation campaign over the public API: makes the Any/required
  // specific mutation paths (UnpackAny during Mutate, required-field sampler
  // gating, Any repack inside PostProcessing::Run) visible to coverage
  // guidance and to the official coverage measurement. The schedule is
  // input-dependent so distinct corpus units drive distinct mutation
  // sequences.
  protobuf_mutator::Mutator mutator;
  Holder msg = input;
  const uint64_t sched = WalkHolder(input) ^ input.ByteSizeLong();
  const int iterations = 8 + static_cast<int>(sched % 25);  // 8..32
  static const size_t kHints[4] = {4096, 512, 64, 12};

  for (int i = 0; i < iterations; ++i) {
    mutator.Seed(static_cast<uint32_t>(sched >> ((i * 5) % 32)) ^
                 (static_cast<uint32_t>(i) * 0x9E3779B9u));
    mutator.Mutate(&msg, kHints[(sched >> ((i * 3) % 30)) & 3]);
    g_sink ^= WalkHolder(msg);
    if (i % 8 == 7) mutator.Fix(&msg);  // re-init mid-campaign: post-processor
    if (((sched >> (i % 26)) & 1) && i % 4 == 2) {  // dispatch on evolved state
      Holder other = input;
      mutator.CrossOver(msg, &other, kHints[(sched >> ((i * 7) % 28)) & 3]);
      g_sink ^= WalkHolder(other);
    }
  }
  g_sink ^= msg.ByteSizeLong();
}
