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

set(ZLIB_TARGET external.zlib)
set(ZLIB_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${ZLIB_TARGET})

set(ZLIB_INCLUDE_DIRS ${ZLIB_INSTALL_DIR}/include)
include_directories(${ZLIB_INCLUDE_DIRS})

list(APPEND ZLIB_LIBRARIES z)

foreach(lib IN LISTS ZLIB_LIBRARIES)
  list(APPEND ZLIB_BUILD_BYPRODUCTS ${ZLIB_INSTALL_DIR}/lib/lib${lib}.a)

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
               ${ZLIB_INSTALL_DIR}/lib/lib${lib}.a)
  add_dependencies(${lib} ${ZLIB_TARGET})
endforeach(lib)

include (ExternalProject)
ExternalProject_Add(${ZLIB_TARGET}
    PREFIX ${ZLIB_TARGET}
    GIT_REPOSITORY https://github.com/madler/zlib
    GIT_TAG master
    CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=${ZLIB_INSTALL_DIR}
    BUILD_BYPRODUCTS ${ZLIB_BUILD_BYPRODUCTS}
)
