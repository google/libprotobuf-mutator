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
// Fuzzes libprotobuf-mutator's own mutation engine over a proto schema that
// exercises every protobuf C++ field type: singular and repeated int32/int64/
// uint32/uint64/float/double/bool/enum, UTF-8 validated strings, bytes,
// oneofs with scalar and message alternatives, and nested/recursive messages.
//
// Binary wire format (DEFINE_BINARY_PROTO_FUZZER) drives ParseBinaryMessage /
// SaveMessageAsBinary (src/binary_format.cc), while the custom mutator and
// crossover callbacks exercise the engine core (src/mutator.cc,
// src/field_instance.h, src/utf8_fix.cc, src/weighted_reservoir_sampler.h)
// across all the field types the xml.proto-based production targets never
// instantiate (proto2, TEXT format, strings/bool/uint32 only).
//
// The test function only round-trips the message through protobuf's public
// serialization surface; it holds no assertions, so any sanitizer finding is
// a genuine bug in the library or in protobuf itself.

#include <cstring>
#include <string>

#include "examples/engine_types/engine_types.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/mutator.h"

namespace {
// Depth bound mirrors protobuf's own wire-parse recursion limit.
constexpr int kMaxWalkDepth = 128;

// Volatile sink keeps the walk observable to the optimizer without adding
// assertions or tripwires.
volatile uint64_t g_sink;

using protobuf_mutator::engine_types::Leaf;
using protobuf_mutator::engine_types::Mid;
using protobuf_mutator::engine_types::Node;
using protobuf_mutator::engine_types::Root;

uint64_t WalkLeaf(const Leaf& leaf) {
  uint64_t h = 0;
  h += static_cast<uint64_t>(static_cast<uint32_t>(leaf.i32()));
  h += static_cast<uint64_t>(leaf.i64());
  h += leaf.u32();
  h += leaf.u64();
  float f = leaf.f32();
  uint32_t fbits;
  memcpy(&fbits, &f, sizeof(fbits));
  h += fbits;
  double d = leaf.f64();
  uint64_t dbits;
  memcpy(&dbits, &d, sizeof(dbits));
  h += dbits;
  h += static_cast<uint64_t>(leaf.b());
  h += static_cast<uint64_t>(leaf.kind());
  h += leaf.utf8().size();
  h += leaf.blob().size();
  for (int32_t v : leaf.rep_i32())
    h += static_cast<uint64_t>(static_cast<uint32_t>(v));
  for (int64_t v : leaf.rep_i64()) h += static_cast<uint64_t>(v);
  for (uint32_t v : leaf.rep_u32()) h += v;
  for (uint64_t v : leaf.rep_u64()) h += v;
  for (float v : leaf.rep_f32()) {
    uint32_t bits;
    memcpy(&bits, &v, sizeof(bits));
    h += bits;
  }
  for (double v : leaf.rep_f64()) {
    uint64_t bits;
    memcpy(&bits, &v, sizeof(bits));
    h += bits;
  }
  h += leaf.rep_b().size();
  h += leaf.rep_kind().size();
  for (const std::string& s : leaf.rep_utf8()) h += s.size();
  for (const std::string& s : leaf.rep_blob()) h += s.size();
  return h;
}

uint64_t WalkMid(const Mid& mid, int depth) {
  uint64_t h = 0;
  if (mid.has_leaf()) h += WalkLeaf(mid.leaf());
  for (const Leaf& leaf : mid.rep_leaf()) h += WalkLeaf(leaf);
  switch (mid.choice_case()) {
    case Mid::kOI32:
      h += static_cast<uint64_t>(static_cast<uint32_t>(mid.o_i32()));
      break;
    case Mid::kOU64:
      h += mid.o_u64();
      break;
    case Mid::kOF64: {
      double d = mid.o_f64();
      uint64_t bits;
      memcpy(&bits, &d, sizeof(bits));
      h += bits;
      break;
    }
    case Mid::kOKind:
      h += static_cast<uint64_t>(mid.o_kind());
      break;
    case Mid::kOUtf8:
      h += mid.o_utf8().size();
      break;
    case Mid::kOLeaf:
      h += WalkLeaf(mid.o_leaf());
      break;
    case Mid::CHOICE_NOT_SET:
      break;
  }
  return h;
}

uint64_t WalkNode(const Node& node, int depth) {
  uint64_t h = 0;
  if (depth <= 0) return h;
  if (node.has_child()) h += WalkNode(node.child(), depth - 1) + 1;
  if (node.has_leaf()) h += WalkLeaf(node.leaf());
  if (node.has_mid()) h += WalkMid(node.mid(), depth - 1);
  return h;
}

uint64_t WalkRoot(const Root& root, int depth) {
  uint64_t h = 0;
  if (root.has_node()) h += WalkNode(root.node(), depth);
  for (const Node& node : root.rep_node()) h += WalkNode(node, depth);
  if (root.has_leaf()) h += WalkLeaf(root.leaf());
  for (const Leaf& leaf : root.rep_leaf()) h += WalkLeaf(leaf);
  if (root.has_mid()) h += WalkMid(root.mid(), depth);
  return h;
}
}  // namespace

DEFINE_BINARY_PROTO_FUZZER(const protobuf_mutator::engine_types::Root& input) {
  // Drive the library's public mutation API directly: Mutator::Mutate /
  // CrossOver over a message parsed from attacker-controlled wire bytes.
  // This puts the engine's per-type mutation paths (mutator.cc,
  // field_instance.h, utf8_fix.cc, weighted_reservoir_sampler.h) inside the
  // fuzz target's execution, so coverage-guided fuzzing and coverage
  // measurement both see them.
  protobuf_mutator::Mutator mutator;
  Root msg = input;

  // Input-dependent campaign schedule: distinct inputs drive distinct
  // iteration counts, per-iteration size hints, seeds and crossover points,
  // so the corpus retains inputs whose schedules reach engine paths that
  // fixed schedules never explore.
  const uint64_t sched = WalkRoot(input, 8) ^ input.ByteSizeLong();
  const int iterations = 8 + static_cast<int>(sched % 25);  // 8..32
  static const size_t kHints[4] = {4096, 512, 64, 12};

  for (int i = 0; i < iterations; ++i) {
    mutator.Seed(static_cast<uint32_t>(sched >> ((i * 5) % 32)) ^
                 (static_cast<uint32_t>(i) * 0x9E3779B9u));
    mutator.Mutate(&msg, kHints[(sched >> ((i * 3) % 30)) & 3]);
    // Walk the mutated message: input-dependent features let the corpus
    // retain shapes whose mutations produce diverse field structures.
    g_sink ^= WalkRoot(msg, kMaxWalkDepth);
    if (((sched >> (i % 26)) & 1) && i % 4 == 2) {
      Root other = input;
      mutator.CrossOver(msg, &other, kHints[(sched >> ((i * 7) % 28)) & 3]);
      g_sink ^= WalkRoot(other, kMaxWalkDepth);
    }
  }
  g_sink ^= msg.ByteSizeLong();
}
