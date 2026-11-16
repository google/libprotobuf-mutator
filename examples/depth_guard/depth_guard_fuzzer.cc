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
// Fuzzes the mutator engine's deep-nesting guards. Builds a message chain
// deeper than Mutator's kMaxInitializeDepth (200) deterministically, with a
// google.protobuf.Any parked deep in the chain, then runs Fix/Mutate through
// the public API: the post-processing walker must trim the deep optional
// fields and clear the deep Any instead of overflowing the stack, on every
// call, under sanitizers.
//
// Any payloads get their type_url pointed at the Node type via a
// post-processor registered on the campaign mutator, so the walker actually
// unpacks, walks and repacks the deep Any before clearing it.
//
// The test function holds no assertions; any sanitizer finding is a genuine
// bug in the library or in protobuf itself.

#include <string>

#include "google/protobuf/any.pb.h"
#include "examples/depth_guard/depth_guard.pb.h"
#include "src/libfuzzer/libfuzzer_macro.h"
#include "src/mutator.h"

namespace {
using protobuf_mutator::depth::Node;

// Walk bound above the deepest chain we build (protobuf's parse recursion
// limit is 100; chains are built in memory up to ~240).
constexpr int kMaxWalkDepth = 256;

// Volatile sink keeps computations observable without adding assertions.
volatile uint64_t g_sink;

uint64_t WalkNode(const Node& node, int depth) {
  uint64_t h = 0;
  if (depth <= 0) return h;
  h += node.data().size();
  if (node.has_payload()) h += node.payload().type_url().size() + 1;
  if (node.has_child()) h += WalkNode(node.child(), depth - 1) + 1;
  return h;
}

// Depth-first builder: returns the innermost node of a chain of length n.
Node* BuildChain(Node* root, int n) {
  Node* cur = root;
  for (int i = 0; i < n; ++i) cur = cur->mutable_child();
  return cur;
}
}  // namespace

DEFINE_BINARY_PROTO_FUZZER(const protobuf_mutator::depth::Node& input) {
  protobuf_mutator::Mutator mutator;

  // Park a resolvable Any deep in the chain: the walker must unpack, walk,
  // repack and then clear it when it sits beyond the depth guard.
  mutator.RegisterPostProcessor(
      google::protobuf::Any::descriptor(),
      [](google::protobuf::Message* message, unsigned int) {
        auto* any = google::protobuf::DownCastMessage<google::protobuf::Any>(
            message);
        if (any->type_url().empty())
          any->set_type_url("type.googleapis.com/protobuf_mutator.depth.Node");
      });

  // Input-dependent schedule: chain depth spans 100..239 (both sides of the
  // 200 guard) and the mutation campaign length varies, so distinct corpus
  // units exercise the depth guards at different margins.
  const uint64_t sched =
      WalkNode(input, kMaxWalkDepth) ^ input.ByteSizeLong();
  const int depth = 100 + static_cast<int>(sched % 140);       // 100..239
  const int iterations = 8 + static_cast<int>((sched >> 8) % 25);  // 8..32

  Node msg = input;
  Node* deep = BuildChain(&msg, depth);
  Node inner;
  inner.set_data("deep");
  deep->mutable_payload()->PackFrom(inner);

  mutator.Fix(&msg);
  for (int i = 0; i < iterations; ++i) {
    mutator.Seed(static_cast<uint32_t>(sched >> ((i * 5) % 32)) ^
                 (static_cast<uint32_t>(i) * 0x9E3779B9u));
    mutator.Mutate(&msg, 1 << 20);
  }
  g_sink ^= WalkNode(msg, kMaxWalkDepth) ^ msg.ByteSizeLong();
}
