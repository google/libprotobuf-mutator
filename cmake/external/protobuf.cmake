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

#set(PROTOBUF_INCLUDE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf/src)
#set(PROTOBUF_URL https://github.com/mrry/protobuf.git)  # Includes MSVC fix.
#set(PROTOBUF_TAG 1d2c7b6c7376f396c8c7dd9b6afd2d4f83f3cb05)
#
#if(WIN32)
#  set(protobuf_STATIC_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf/${CMAKE_BUILD_TYPE}/libprotobuf.lib)
#  set(PROTOBUF_PROTOC_EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf/${CMAKE_BUILD_TYPE}/protoc.exe)
#  set(PROTOBUF_ADDITIONAL_CMAKE_OPTIONS  -Dprotobuf_MSVC_STATIC_RUNTIME:BOOL=OFF -A x64)
#else()
#  set(protobuf_STATIC_LIBRARIES ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf/libprotobuf.a)
#  set(PROTOBUF_PROTOC_EXECUTABLE ${CMAKE_CURRENT_BINARY_DIR}/protobuf/src/protobuf/protoc)
#endif()
#
#ExternalProject_Add(protobuf
#    PREFIX protobuf
#    DEPENDS zlib
#    GIT_REPOSITORY ${PROTOBUF_URL}
#    GIT_TAG ${PROTOBUF_TAG}
#    DOWNLOAD_DIR "${DOWNLOAD_LOCATION}"
#    BUILD_IN_SOURCE 1
#    SOURCE_DIR ${CMAKE_BINARY_DIR}/protobuf/src/protobuf
#    CONFIGURE_COMMAND ${CMAKE_COMMAND} cmake/
#        -Dprotobuf_BUILD_TESTS=OFF
#        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
#        ${PROTOBUF_ADDITIONAL_CMAKE_OPTIONS}
#    INSTALL_COMMAND ""
#    CMAKE_CACHE_ARGS
#        -DCMAKE_BUILD_TYPE:STRING=Release
#        -DCMAKE_VERBOSE_MAKEFILE:BOOL=OFF
#        -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON
#  -DZLIB_ROOT:STRING=${ZLIB_INSTALL}
#)

#find_package(Protobuf REQUIRED)

set(PROTOBUF_TARGET external.protobuf)
set(PROTOFUB_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${PROTOBUF_TARGET})
list(APPEND PROTOFUB_LIBRARIES protofub)

foreach(lib IN LISTS GTEST_BOTH_LIBRARIES)
  list(APPEND PROTOFUB_BUILD_BYPRODUCTS ${PROTOFUB_INSTALL_DIR}/lib/lib${lib}.a)

  add_library(${lib} STATIC IMPORTED)
  set_property(TARGET ${lib} PROPERTY IMPORTED_LOCATION
               ${PROTOFUB_INSTALL_DIR}/lib/lib${lib}.a)
  add_dependencies(${lib} googletest)
endforeach(lib)


set(PROTOBUF_BUILD_DIR protobuf/src/external.protobuf/)

ExternalProject_Add(external.protobuf
    PREFIX protobuf
    #GIT_REPOSITORY https://github.com/google/protobuf.git
    GIT_REPOSITORY /usr/local/google/home/vitalybuka/src/protobuf/.git
    GIT_TAG master
    #INSTALL_COMMAND ""
    BUILD_IN_SOURCE 1
    CONFIGURE_COMMAND ${CMAKE_COMMAND} cmake/
        -G${CMAKE_GENERATOR}
        -DCMAKE_INSTALL_PREFIX=${PROTOFUB_INSTALL_DIR}
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -Dprotobuf_BUILD_TESTS=OFF
    BUILD_BYPRODUCTS ${PROTOBUF_BUILD_DIR}/libz.a
)

#set(PROTOBUF_SRC_ROOT_FOLDER protobuf/src/external.protobuf/)
#find_package(Protobuf REQUIRED)
#include(FindProtobuf.cmake)
#message(----------------- ${PROTOBUF_INCLUDE_DIRS})

#ExternalProject_Get_Property(zlib source_dir)
#include_directories(${source_dir})

#add_library(z STATIC IMPORTED)
#set_property(TARGET z PROPERTY IMPORTED_LOCATION ${GTEST_LIB_DIR}/libgtest.a)
#add_dependencies(z zlib)

