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

#include <dirent.h>
#include <memory>
#include "gtest/gtest.h"

namespace {

size_t CountFilesInDir(const std::string& path) {
  size_t res = 0;
  std::unique_ptr<DIR, decltype(&closedir)> dir(opendir(path.c_str()),
                                                &closedir);
  if (!dir) return 0;
  while (readdir(dir.get())) {
    ++res;
  }
  if (res <= 2) return 0;
  res -= 2;  // . and ..
  return res;
}

}  // namespace

TEST(ExpatExampleTest, Crash) {
  char dir_template[] = "/tmp/libxml2_example_test_XXXXXX";
  auto dir = mkdtemp(dir_template);
  ASSERT_TRUE(dir);

  EXPECT_EQ(0, CountFilesInDir(dir));

  std::string cmd =
      "./expat_example -max_len=500 -runs=10000 -artifact_prefix=" +
      std::string(dir) + "/ " + dir + "/";
  EXPECT_EQ(0, std::system(cmd.c_str()));

  EXPECT_GT(CountFilesInDir(dir), 100);

  // Cleanup.
  EXPECT_EQ(0, std::system((std::string("rm -rf ") + dir).c_str()));
}
