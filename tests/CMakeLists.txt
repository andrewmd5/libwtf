set(INSTALL_GTEST OFF CACHE BOOL "Disable GoogleTest install rules" FORCE)
set(BUILD_GMOCK OFF CACHE BOOL "Disable GoogleMock" FORCE)
set(gtest_force_shared_crt ON CACHE BOOL "Use shared CRT with MSVC" FORCE)

add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../deps/googletest
    ${CMAKE_CURRENT_BINARY_DIR}/googletest
    EXCLUDE_FROM_ALL
)

include(GoogleTest)

if(WTF_BUILD_CPP)
    add_executable(wtf_cpp_tests cpp/test_wrapper.cc cpp/header_tu.cc)
    target_include_directories(wtf_cpp_tests PRIVATE "${PROJECT_SOURCE_DIR}/include")
    target_compile_features(wtf_cpp_tests PRIVATE cxx_std_23)
    target_compile_definitions(wtf_cpp_tests PRIVATE WTF_EXPORTS)
    target_link_libraries(wtf_cpp_tests PRIVATE GTest::gtest_main)
    gtest_discover_tests(wtf_cpp_tests PROPERTIES LABELS "unit;cpp")

    add_executable(wtf_cpp_integration_tests cpp/test_integration.cc)
    target_compile_definitions(wtf_cpp_integration_tests PRIVATE
        WTF_TEST_CERT_DIR="${PROJECT_SOURCE_DIR}/certs")
    target_link_libraries(wtf_cpp_integration_tests PRIVATE WebTransport::cpp GTest::gtest_main)
    gtest_discover_tests(wtf_cpp_integration_tests
        PROPERTIES LABELS "integration;cpp" TIMEOUT 15)
endif()

if(APPLE)
    add_executable(wtf_backend_roundtrip network/roundtrip.c)
    target_link_libraries(wtf_backend_roundtrip PRIVATE wtf)
endif()

if(WTF_QUIC_BACKEND STREQUAL "network")
    set(WTF_NETWORK_TEST_SOURCES ${WTF_BACKEND_SOURCES})
    list(TRANSFORM WTF_NETWORK_TEST_SOURCES PREPEND "${PROJECT_SOURCE_DIR}/")
    add_executable(wtf_network_backend_tests network/backend.c ${WTF_NETWORK_TEST_SOURCES}
        "${PROJECT_SOURCE_DIR}/src/log.c" "${PROJECT_SOURCE_DIR}/src/cert.c")
    target_include_directories(wtf_network_backend_tests PRIVATE $<TARGET_PROPERTY:wtf,INCLUDE_DIRECTORIES>)
    target_compile_options(wtf_network_backend_tests PRIVATE -fblocks)
    target_link_libraries(wtf_network_backend_tests PRIVATE ${MSQUIC_LIBRARIES} ${PLATFORM_LIBS})
    add_test(NAME wtf_network_backend_tests COMMAND wtf_network_backend_tests
        "${PROJECT_SOURCE_DIR}/certs/localhost.crt"
        "${PROJECT_SOURCE_DIR}/certs/localhost.key")
    set_tests_properties(wtf_network_backend_tests PROPERTIES LABELS "integration;network" TIMEOUT 15)
endif()

# Compile the implementation into this executable to exercise internal ownership
# with a mock MsQuic API, without exposing private symbols from the shared library.
set(WTF_REGRESSION_SOURCES)
foreach(WTF_SOURCE IN LISTS WTF_SOURCES)
    get_filename_component(WTF_REGRESSION_SOURCE "${WTF_SOURCE}" ABSOLUTE BASE_DIR "${PROJECT_SOURCE_DIR}")
    list(APPEND WTF_REGRESSION_SOURCES "${WTF_REGRESSION_SOURCE}")
endforeach()
add_executable(wtf_regression_tests
    regression/test_lifetime.cc
    regression/echo_harness.c
    ${WTF_REGRESSION_SOURCES}
)
target_include_directories(wtf_regression_tests PRIVATE $<TARGET_PROPERTY:wtf,INCLUDE_DIRECTORIES>)
target_compile_definitions(wtf_regression_tests PRIVATE WTF_EXPORTS)
if(WTF_QUIC_BACKEND STREQUAL "network")
    target_compile_options(wtf_regression_tests PRIVATE $<$<COMPILE_LANGUAGE:C>:-fblocks>)
    set_source_files_properties("${PROJECT_SOURCE_DIR}/src/quic/network_credentials.c"
        PROPERTIES COMPILE_OPTIONS "-Wno-deprecated-declarations")
endif()
if(WTF_ENABLE_LOGGING)
    target_compile_definitions(wtf_regression_tests PRIVATE WTF_ENABLE_LOGGING=1)
endif()
target_link_libraries(wtf_regression_tests PRIVATE GTest::gtest_main ${MSQUIC_LIBRARIES} ${PLATFORM_LIBS})
if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf_regression_tests PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf_regression_tests PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()
gtest_discover_tests(wtf_regression_tests PROPERTIES LABELS "unit;regression")

set(WTF_UNIT_TEST_SOURCES
    unit/test_public_api.cc
    unit/test_varint.cc
    unit/test_utils.cc
    unit/test_settings.cc
    unit/test_draft_negotiation.cc
    ../src/log.c
    ../src/varint.c
    ../src/utils.c
    ../src/settings.c
    ../src/draft.c
)

add_executable(wtf_unit_tests ${WTF_UNIT_TEST_SOURCES})

target_include_directories(wtf_unit_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../src
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_BINARY_DIR}/../include
        ${CMAKE_CURRENT_SOURCE_DIR}/../deps/tinycthreads
        ${CMAKE_CURRENT_SOURCE_DIR}/../deps/ls-qpack
        ${CMAKE_CURRENT_SOURCE_DIR}/../deps/xxhash
        ${CMAKE_CURRENT_SOURCE_DIR}/../deps/verstable
)

target_include_directories(wtf_unit_tests SYSTEM PRIVATE ${MSQUIC_INCLUDE_DIRS})

target_link_libraries(wtf_unit_tests PRIVATE GTest::gtest_main ${PLATFORM_LIBS})

if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf_unit_tests PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf_unit_tests PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()

gtest_discover_tests(wtf_unit_tests
    PROPERTIES
        LABELS "unit;regression"
)

add_executable(wtf_public_api_tests public/test_public_api.cc)

target_include_directories(wtf_public_api_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_BINARY_DIR}/../include
)

target_compile_definitions(wtf_public_api_tests
    PRIVATE
        WTF_TEST_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../certs"
)

target_link_libraries(wtf_public_api_tests PRIVATE GTest::gtest_main wtf ${PLATFORM_LIBS})

if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf_public_api_tests PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf_public_api_tests PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()

gtest_discover_tests(wtf_public_api_tests
    PROPERTIES
        LABELS "unit;public-api;regression"
)

add_executable(wtf_e2e_tests test_e2e.c)

target_include_directories(wtf_e2e_tests
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_BINARY_DIR}/../include
)

target_compile_definitions(wtf_e2e_tests
    PRIVATE
        WTF_TEST_CERT_DIR="${CMAKE_CURRENT_SOURCE_DIR}/../certs"
)

target_link_libraries(wtf_e2e_tests PRIVATE wtf ${PLATFORM_LIBS})

if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf_e2e_tests PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf_e2e_tests PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()

add_test(NAME wtf_e2e_tests COMMAND wtf_e2e_tests)
set_tests_properties(wtf_e2e_tests PROPERTIES LABELS "integration;e2e" TIMEOUT 30)

add_executable(wtf_browser_interop_server browser_chrome/server.c)

target_include_directories(wtf_browser_interop_server
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/../include
        ${CMAKE_CURRENT_BINARY_DIR}/../include
)

target_link_libraries(wtf_browser_interop_server PRIVATE wtf ${PLATFORM_LIBS})

if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf_browser_interop_server PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf_browser_interop_server PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()

find_program(UV_EXECUTABLE uv)
if(UV_EXECUTABLE)
    add_test(
        NAME wtf_browser_chrome_interop
        COMMAND
            ${UV_EXECUTABLE}
            run
            --frozen
            python
            interop.py
            --server-binary $<TARGET_FILE:wtf_browser_interop_server>
            --cert ${CMAKE_CURRENT_SOURCE_DIR}/../certs/localhost.crt
            --key ${CMAKE_CURRENT_SOURCE_DIR}/../certs/localhost.key
            --hash ${CMAKE_CURRENT_SOURCE_DIR}/../certs/fingerprint.hex
    )
    set_tests_properties(wtf_browser_chrome_interop PROPERTIES
        LABELS "browser;interop;integration"
        SKIP_RETURN_CODE 77
        TIMEOUT 90
        WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}/browser_chrome
        ENVIRONMENT "UV_PROJECT_ENVIRONMENT=${CMAKE_CURRENT_BINARY_DIR}/browser_chrome_venv"
    )
else()
    message(WARNING "uv not found; Chrome WebTransport interop test will not be registered")
endif()

add_custom_target(test_unit
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L unit
    DEPENDS wtf_unit_tests wtf_public_api_tests wtf_regression_tests
    COMMENT "Running GoogleTest unit and regression tests"
)

add_custom_target(test_integration
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L integration
    DEPENDS wtf_e2e_tests wtf_browser_interop_server
    COMMENT "Running integration and interop tests"
)

add_custom_target(test_all
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
    DEPENDS wtf_unit_tests wtf_public_api_tests wtf_regression_tests wtf_e2e_tests wtf_browser_interop_server
    COMMENT "Running all tests"
)

set(WTF_REPORT_DIR ${CMAKE_BINARY_DIR}/reports)

add_custom_target(test_report
    COMMAND ${CMAKE_COMMAND} -E make_directory ${WTF_REPORT_DIR}/tests
    COMMAND $<TARGET_FILE:wtf_unit_tests>
            --gtest_output=xml:${WTF_REPORT_DIR}/tests/wtf_unit_tests.xml
    COMMAND $<TARGET_FILE:wtf_public_api_tests>
            --gtest_output=xml:${WTF_REPORT_DIR}/tests/wtf_public_api_tests.xml
    COMMAND $<TARGET_FILE:wtf_regression_tests>
            --gtest_output=xml:${WTF_REPORT_DIR}/tests/wtf_regression_tests.xml
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -L integration
    DEPENDS wtf_unit_tests wtf_public_api_tests wtf_regression_tests wtf_e2e_tests wtf_browser_interop_server
    COMMENT "Writing test reports to ${WTF_REPORT_DIR}/tests"
)

find_program(GCOVR_EXECUTABLE gcovr)
if(WTF_ENABLE_COVERAGE AND GCOVR_EXECUTABLE)
    add_custom_target(coverage
        COMMAND ${CMAKE_COMMAND} -E make_directory ${WTF_REPORT_DIR}/coverage
        COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure
        COMMAND ${GCOVR_EXECUTABLE}
                --root ${CMAKE_CURRENT_SOURCE_DIR}/..
                --filter ${CMAKE_CURRENT_SOURCE_DIR}/../src
                --exclude ${CMAKE_CURRENT_SOURCE_DIR}/../deps
                --exclude ${CMAKE_CURRENT_SOURCE_DIR}/../msquic
                --xml-pretty
                --xml ${WTF_REPORT_DIR}/coverage/coverage.xml
                --html-details ${WTF_REPORT_DIR}/coverage/index.html
                --print-summary
        DEPENDS wtf_unit_tests wtf_public_api_tests wtf_regression_tests wtf_e2e_tests wtf_browser_interop_server
        COMMENT "Writing coverage reports to ${WTF_REPORT_DIR}/coverage"
    )
elseif(WTF_ENABLE_COVERAGE)
    message(WARNING "gcovr not found; coverage target will fail until gcovr is installed")
    add_custom_target(coverage
        COMMAND ${CMAKE_COMMAND} -E echo
                "gcovr not found. Install gcovr and reconfigure to generate coverage reports."
        COMMAND ${CMAKE_COMMAND} -E false
        COMMENT "Coverage reports require gcovr"
    )
endif()
