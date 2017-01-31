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

include (FindProtobuf)

set(PROTOBUF_TARGET external.protobuf)
set(PROTOFUB_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${PROTOBUF_TARGET})

set(PROTOBUF_INCLUDE_DIR ${PROTOFUB_INSTALL_DIR}/include)
include_directories(${PROTOBUF_INCLUDE_DIR})
include_directories(${CMAKE_CURRENT_BINARY_DIR})

IF(CMAKE_BUILD_TYPE MATCHES Debug)
  set(PROTOBUF_LIBRARY protobufd)
ELSE()
  set(PROTOBUF_LIBRARY protobuf)
ENDIF()

foreach(lib ${PROTOBUF_LIBRARY})
  list(APPEND PROTOFUB_BUILD_BYPRODUCTS ${PROTOFUB_INSTALL_DIR}/lib/lib${lib}.a)

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
               ${PROTOFUB_INSTALL_DIR}/lib/lib${lib}.a)
  add_dependencies(${lib} ${PROTOBUF_TARGET})
endforeach(lib)

set(PROTOBUF_PROTOC_EXECUTABLE ${PROTOFUB_INSTALL_DIR}/bin/protoc)
list(APPEND PROTOFUB_BUILD_BYPRODUCTS ${PROTOBUF_PROTOC_EXECUTABLE})

include (ExternalProject)
ExternalProject_Add(${PROTOBUF_TARGET}
    PREFIX ${PROTOBUF_TARGET}
    GIT_REPOSITORY https://github.com/google/protobuf.git
    GIT_TAG master
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ${CMAKE_COMMAND} ${PROTOFUB_INSTALL_DIR}/src/${PROTOBUF_TARGET}/cmake
        -G${CMAKE_GENERATOR}
        -DCMAKE_INSTALL_PREFIX=${PROTOFUB_INSTALL_DIR}
        -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_C_COMPILER:FILEPATH=${CMAKE_C_COMPILER}
        -DCMAKE_CXX_COMPILER:FILEPATH=${CMAKE_CXX_COMPILER}
        -Dprotobuf_BUILD_TESTS=OFF
    BUILD_BYPRODUCTS ${PROTOFUB_BUILD_BYPRODUCTS}
)

# cmake 3.7 uses Protobuf_ when 3.5 PROTOBUF_ prefixes.
set(Protobuf_INCLUDE_DIR ${PROTOBUF_INCLUDE_DIR})
set(Protobuf_PROTOC_EXECUTABLE ${PROTOBUF_PROTOC_EXECUTABLE})
