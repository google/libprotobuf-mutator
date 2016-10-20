# Copyright 2016 Google Inc. All rights reserved.
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

include (ExternalProject)
include (FindGTest)

set(GTEST_TARGET external.googletest)
set(GTEST_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${GTEST_TARGET})
list(APPEND GTEST_LIBS gtest gtest_main)

foreach(lib IN LISTS GTEST_LIBS)
  list(APPEND GTEST_BUILD_BYPRODUCTS ${GTEST_INSTALL_DIR}/lib/lib${lib}.a)

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
               ${GTEST_INSTALL_DIR}/lib/lib${lib}.a)
  add_dependencies(${lib} ${GTEST_TARGET})
endforeach(lib)

ExternalProject_Add(${GTEST_TARGET}
    PREFIX ${GTEST_TARGET}
    #GIT_REPOSITORY https://github.com/google/googletest.git
    GIT_REPOSITORY /usr/local/google/home/vitalybuka/src/googletest/.git
    GIT_TAG master
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${GTEST_INSTALL_DIR}
    BUILD_BYPRODUCTS ${GTEST_BUILD_BYPRODUCTS}
)

include_directories(${GTEST_INSTALL_DIR}/include)
