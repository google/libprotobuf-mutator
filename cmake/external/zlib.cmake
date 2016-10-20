include (ExternalProject)

set(ZLIB_LIB_DIR zlib/src/zlib-build/)

ExternalProject_Add(zlib
    PREFIX zlib
    GIT_REPOSITORY https://github.com/madler/zlib
    GIT_TAG master
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${ZLIB_LIB_DIR}/libz.a
)

ExternalProject_Get_Property(zlib source_dir)
include_directories(${source_dir})

add_library(z STATIC IMPORTED)
set_property(TARGET z PROPERTY IMPORTED_LOCATION ${GTEST_LIB_DIR}/libgtest.a)
add_dependencies(z zlib)
