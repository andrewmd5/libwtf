find_package(GTest QUIET)
if(NOT GTest_FOUND)
    
    include(FetchContent)
    
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        v1.14.0
        GIT_SHALLOW    TRUE
    )
    
    
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    set(BUILD_GMOCK OFF CACHE BOOL "" FORCE)
    set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
    
    FetchContent_MakeAvailable(googletest)
endif()


set(TEST_SOURCES
    test_init.c
)


add_executable(wtf_tests
    ${TEST_SOURCES}
    test_main.c
)

target_include_directories(wtf_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
)

target_link_libraries(wtf_tests
    PRIVATE
        $<IF:$<TARGET_EXISTS:wtf_shared>,wtf_shared,wtf_static>
        $<IF:$<TARGET_EXISTS:GTest::gtest>,GTest::gtest,gtest>
        $<IF:$<TARGET_EXISTS:GTest::gtest_main>,GTest::gtest_main,gtest_main>
)


set_target_properties(wtf_tests PROPERTIES
    LINKER_LANGUAGE CXX
)


include(GoogleTest)
if(TARGET GTest::gtest)
    gtest_discover_tests(wtf_tests)
else()
    add_test(NAME wtf_tests COMMAND wtf_tests)
endif()



if(UNIX AND NOT APPLE)
    find_program(VALGRIND valgrind)
    if(VALGRIND)
        add_test(NAME wtf_tests_valgrind
            COMMAND ${VALGRIND} 
                --tool=memcheck 
                --leak-check=full 
                --error-exitcode=1 
                $<TARGET_FILE:wtf_tests>
        )
        set_tests_properties(wtf_tests_valgrind PROPERTIES
            TIMEOUT 300
        )
    endif()
endif()




if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    file(COPY certs DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()


add_custom_target(test_unit
    COMMAND ${CMAKE_CTEST_COMMAND} -L "unit"
    DEPENDS wtf_tests
    COMMENT "Running unit tests"
)

add_custom_target(test_integration
    COMMAND ${CMAKE_CTEST_COMMAND} -L "integration"
    DEPENDS wtf_tests
    COMMENT "Running integration tests"
)