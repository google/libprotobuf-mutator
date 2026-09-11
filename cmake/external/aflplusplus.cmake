set(AFLPLUSPLUS_TARGET external.aflplusplus)
set(AFLPLUSPLUS_INSTALL_DIR ${CMAKE_CURRENT_BINARY_DIR}/${AFLPLUSPLUS_TARGET})

set(AFLPLUSPLUS_INCLUDE_DIRS ${AFLPLUSPLUS_INSTALL_DIR}/include
                             ${AFLPLUSPLUS_INSTALL_DIR}/include/afl)
set(AFLPLUSPLUS_PERFORMANCE_SOURCE
    ${AFLPLUSPLUS_INSTALL_DIR}/src/afl-performance.c)

file(MAKE_DIRECTORY ${AFLPLUSPLUS_INCLUDE_DIRS})

function(check_aflplusplus_version expected)
  if (LIB_PROTO_MUTATOR_AFLPLUSPLUS_SKIP_VERSION_CHECK)
    return()
  endif()

  find_program(AFLPLUSPLUS_FUZZ_BINARY afl-fuzz)
  if (NOT AFLPLUSPLUS_FUZZ_BINARY)
    return()
  endif()

  execute_process(COMMAND ${AFLPLUSPLUS_FUZZ_BINARY} --version
                  OUTPUT_VARIABLE binary_version
                  OUTPUT_STRIP_TRAILING_WHITESPACE
                  ERROR_QUIET)
  string(REGEX REPLACE "^afl-fuzz" "" binary_version "${binary_version}")
  string(REGEX REPLACE "^(\\+\\+|v)" "" binary_version "${binary_version}")
  string(REGEX REPLACE "^(\\+\\+|v)" "" expected "${expected}")

  if (NOT binary_version STREQUAL expected)
    message(FATAL_ERROR
            "AFLplusplus headers are ${expected} but ${AFLPLUSPLUS_FUZZ_BINARY}"
            " is ${binary_version}. The mutator reads afl_state_t out of the"
            " pointer afl-fuzz passes it, and that struct differs between"
            " releases, so both have to come from one revision. Point"
            " LIB_PROTO_MUTATOR_AFLPLUSPLUS_SOURCE_DIR at the checkout this"
            " afl-fuzz was built from, put the matching afl-fuzz first on PATH,"
            " or set LIB_PROTO_MUTATOR_AFLPLUSPLUS_SKIP_VERSION_CHECK=ON.")
  endif()
endfunction()

if (LIB_PROTO_MUTATOR_AFLPLUSPLUS_SOURCE_DIR)
  get_filename_component(AFLPLUSPLUS_SOURCE_DIR
                         "${LIB_PROTO_MUTATOR_AFLPLUSPLUS_SOURCE_DIR}" ABSOLUTE)
  if (NOT EXISTS ${AFLPLUSPLUS_SOURCE_DIR}/include/afl-mutations.h)
    message(FATAL_ERROR
            "LIB_PROTO_MUTATOR_AFLPLUSPLUS_SOURCE_DIR=${AFLPLUSPLUS_SOURCE_DIR}"
            " is not an AFLplusplus checkout")
  endif()

  file(STRINGS ${AFLPLUSPLUS_SOURCE_DIR}/include/config.h
       AFLPLUSPLUS_VERSION_LINE REGEX "^#define VERSION ")
  string(REGEX REPLACE "^#define VERSION[ \t]+\"([^\"]*)\".*$" "\\1"
         AFLPLUSPLUS_VERSION "${AFLPLUSPLUS_VERSION_LINE}")
  message(STATUS "AFLplusplus ${AFLPLUSPLUS_VERSION} "
                 "from ${AFLPLUSPLUS_SOURCE_DIR}")
  check_aflplusplus_version("${AFLPLUSPLUS_VERSION}")

  set(AFLPLUSPLUS_DOWNLOAD_ARGS
      SOURCE_DIR ${AFLPLUSPLUS_SOURCE_DIR}
      DOWNLOAD_COMMAND "")
else()
  if (LIB_PROTO_MUTATOR_AFLPLUSPLUS_TAG MATCHES "^v?[0-9]")
    check_aflplusplus_version("${LIB_PROTO_MUTATOR_AFLPLUSPLUS_TAG}")
  endif()

  set(AFLPLUSPLUS_DOWNLOAD_ARGS
      GIT_REPOSITORY ${LIB_PROTO_MUTATOR_AFLPLUSPLUS_REPOSITORY}
      GIT_TAG ${LIB_PROTO_MUTATOR_AFLPLUSPLUS_TAG}
      GIT_SHALLOW ON
      GIT_PROGRESS ON
  )
endif()

# AFL++ has no build system we could reuse here: only the headers and
# rand_next() from src/afl-performance.c are needed, so install just those.
include (ExternalProject)
if (POLICY CMP0097)
  cmake_policy(SET CMP0097 NEW)
endif()
ExternalProject_Add(${AFLPLUSPLUS_TARGET}
    PREFIX ${AFLPLUSPLUS_TARGET}
    ${AFLPLUSPLUS_DOWNLOAD_ARGS}
    GIT_SUBMODULES ""
    UPDATE_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ${CMAKE_COMMAND} -E copy_directory
                        <SOURCE_DIR>/include
                        ${AFLPLUSPLUS_INSTALL_DIR}/include/afl
            COMMAND ${CMAKE_COMMAND} -E copy
                        <SOURCE_DIR>/src/afl-performance.c
                        ${AFLPLUSPLUS_PERFORMANCE_SOURCE}
    BUILD_BYPRODUCTS ${AFLPLUSPLUS_PERFORMANCE_SOURCE}
)
