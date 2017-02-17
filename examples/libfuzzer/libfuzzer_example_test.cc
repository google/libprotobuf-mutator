// Copyright 2017 Google Inc. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <stdlib.h>
#include <sys/wait.h>

#include "gtest/gtest.h"

const int kDefaultLibFuzzerError = 77;

TEST(LibFuzzerExampleTest, Crash) {
  char dir_template[] = "/tmp/libfuzzer_example_test_XXXXXX";
  auto dir = mkdtemp(dir_template);
  ASSERT_TRUE(dir);

  std::string cmd = "./libfuzzer_example -max_len=150 -artifact_prefix=" +
                    std::string(dir) + "/ " + dir + "/";
  int retvalue = std::system(cmd.c_str());
  EXPECT_EQ(kDefaultLibFuzzerError, WSTOPSIG(retvalue));

  // Cleanup.
  EXPECT_EQ(0, std::system((std::string("rm -rf ") + dir).c_str()));
}
