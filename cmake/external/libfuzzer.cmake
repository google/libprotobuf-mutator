# Copyright 2017 Google Inc. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set(LIBFUZZER_TARGET external.libfuzzer)
set(LIBFUZZER_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${LIBFUZZER_TARGET})

list(APPEND LIBFUZZER_LIBRARIES Fuzzer)

foreach(lib IN LISTS LIBFUZZER_LIBRARIES)
  set(CUR_LIB ${LIBFUZZER_INSTALL_DIR}/src/${LIBFUZZER_TARGET}-build/lib${lib}.a)
  list(APPEND LIBFUZZER_BUILD_BYPRODUCTS ${CUR_LIB})

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION ${CUR_LIB})
  add_dependencies(${lib} ${LIBFUZZER_TARGET})
endforeach(lib)

list(APPEND LIBFUZZER_LIBRARIES pthread)

include (ExternalProject)
ExternalProject_Add(${LIBFUZZER_TARGET}
    PREFIX ${LIBFUZZER_TARGET}
    GIT_REPOSITORY https://chromium.googlesource.com/chromium/llvm-project/llvm/lib/Fuzzer
    GIT_TAG master
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND CXX=${CMAKE_CXX_COMPILER} ${LIBFUZZER_INSTALL_DIR}/src/${LIBFUZZER_TARGET}/build.sh
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBFUZZER_BUILD_BYPRODUCTS}
)
