set_source_files_properties(${AFLPLUSPLUS_PERFORMANCE_SOURCE} PROPERTIES
                            GENERATED TRUE
                            COMPILE_FLAGS "-w")

add_library(protobuf-mutator-aflplusplus
            aflplusplus_macro.cc
            aflplusplus_mutator.cc
            aflplusplus_mutate_wrapper.c
            ${AFLPLUSPLUS_PERFORMANCE_SOURCE})
add_dependencies(protobuf-mutator-aflplusplus ${AFLPLUSPLUS_TARGET})
target_include_directories(protobuf-mutator-aflplusplus PRIVATE
                           ${AFLPLUSPLUS_INCLUDE_DIRS})
target_link_libraries(protobuf-mutator-aflplusplus
                      protobuf-mutator
                      ${Protobuf_LIBRARIES})
set_target_properties(protobuf-mutator-aflplusplus PROPERTIES
                      COMPILE_FLAGS "${NO_FUZZING_FLAGS}"
                      SOVERSION 0)
target_compile_features(protobuf-mutator-aflplusplus PUBLIC cxx_std_14)

if (LIB_PROTO_MUTATOR_TESTING)
  add_executable(aflplusplus_test
                 aflplusplus_test.cc)
  add_dependencies(aflplusplus_test ${AFLPLUSPLUS_TARGET})
  target_include_directories(aflplusplus_test PRIVATE
                             ${AFLPLUSPLUS_INCLUDE_DIRS})
  target_link_libraries(aflplusplus_test
                        protobuf-mutator
                        protobuf-mutator-aflplusplus
                        mutator-test-proto
                        ${GTEST_BOTH_LIBRARIES}
                        ${CMAKE_THREAD_LIBS_INIT})
  set_target_properties(aflplusplus_test PROPERTIES
                        COMPILE_FLAGS "${NO_FUZZING_FLAGS}")
  add_test(test.protobuf_aflplusplus_test aflplusplus_test --gtest_color=yes AUTO)
  add_dependencies(check aflplusplus_test)
endif()

install(TARGETS protobuf-mutator-aflplusplus
        EXPORT libprotobuf-mutatorTargets
        ARCHIVE DESTINATION ${LIB_DIR}
        LIBRARY DESTINATION ${LIB_DIR}
        INCLUDES DESTINATION include/libprotobuf-mutator include/libprotobuf-mutator/src)
