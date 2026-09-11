protobuf_generate_cpp(AFLPLUSPLUS_EXAMPLE_PROTO_SRCS
                      AFLPLUSPLUS_EXAMPLE_PROTO_HDRS
                      aflplusplus_example.proto)

add_library(aflplusplus-example-proto
            ${AFLPLUSPLUS_EXAMPLE_PROTO_SRCS})
set_property(TARGET aflplusplus-example-proto
             PROPERTY COMPILE_FLAGS ${NO_FUZZING_FLAGS})

add_library(aflplusplus_example_mutator MODULE
            aflplusplus_example_mutator.cc)
target_link_libraries(aflplusplus_example_mutator
                      aflplusplus-example-proto
                      protobuf-mutator-aflplusplus)
set_target_properties(aflplusplus_example_mutator PROPERTIES
                      PREFIX ""
                      COMPILE_FLAGS "${NO_FUZZING_FLAGS}")

add_executable(aflplusplus_example
               aflplusplus_example.cc)
target_link_libraries(aflplusplus_example
                      aflplusplus-example-proto
                      protobuf-mutator-aflplusplus
                      ${LIB_PROTO_MUTATOR_FUZZER_LIBRARIES})
set_property(TARGET aflplusplus_example
             PROPERTY COMPILE_FLAGS)
set_property(TARGET aflplusplus_example
             PROPERTY LINK_FLAGS ${FUZZING_FLAGS_BINARY})

add_executable(aflplusplus_example_test
               aflplusplus_example_test.cc)
add_dependencies(aflplusplus_example_test
                 aflplusplus_example
                 aflplusplus_example_mutator)
target_include_directories(aflplusplus_example_test PRIVATE
                           ${AFLPLUSPLUS_INCLUDE_DIRS})
target_compile_definitions(aflplusplus_example_test PRIVATE
    AFLPLUSPLUS_EXAMPLE_MUTATOR_PATH="$<TARGET_FILE:aflplusplus_example_mutator>")
target_link_libraries(aflplusplus_example_test
                      protobuf-mutator
                      protobuf-mutator-aflplusplus
                      ${GTEST_BOTH_LIBRARIES}
                      ${CMAKE_THREAD_LIBS_INIT}
                      ${CMAKE_DL_LIBS})
set_target_properties(aflplusplus_example_test PROPERTIES
                      COMPILE_FLAGS "${NO_FUZZING_FLAGS}")
add_test(test.aflplusplus_example_test aflplusplus_example_test --gtest_color=yes AUTO)
if(LIB_PROTO_MUTATOR_TESTING)
  add_dependencies(check aflplusplus_example_test)
endif()
