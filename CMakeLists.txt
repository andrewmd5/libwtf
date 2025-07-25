cmake_minimum_required(VERSION 4.0)


include(cmake/GetGitVersion.cmake)
get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})


project(wtf 
    VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH}
    DESCRIPTION "High-Performance WebTransport Library"
    LANGUAGES C CXX)


set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)


if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/output)

foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
    string(TOUPPER ${CONFIG} CONFIG_UPPER)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/output/${CONFIG})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/output/${CONFIG})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${CMAKE_BINARY_DIR}/output/${CONFIG})
endforeach()

option(WTF_BUILD_TESTS "Build tests" OFF)
option(WTF_BUILD_SAMPLES "Build sample applications" OFF)
option(WTF_ENABLE_LOGGING "Enable logging support" ON)


include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycthreads
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/ls-qpack
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/verstable
)


set(WTF_VERSION ${GIT_VERSION})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/wtf_version.h
    @ONLY
)


include_directories(${CMAKE_CURRENT_BINARY_DIR}/include)


if(MSVC)
    add_compile_options(/W3)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(/Od /Zi /RTC1 /MDd)
        add_link_options(/DEBUG:FULL)
    else()
        add_compile_options(/O2 /DNDEBUG /GL /MD)
        add_link_options(/LTCG)
    endif()
else()
    add_compile_options(-Wall -Wextra)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_compile_options(-g -O0 -DDEBUG -fno-omit-frame-pointer)
        if(APPLE)
            add_compile_options(-fno-limit-debug-info -gdwarf-4)
            add_link_options(-Wl,-no_compact_unwind)
        endif()
    else()
        add_compile_options(-O2 -DNDEBUG )
        add_link_options(-flto)
        if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
            add_compile_options(-fuse-linker-plugin -ffat-lto-objects)
            add_link_options(-fuse-linker-plugin)
        endif()
    endif()
endif()


include(FetchContent)

message(STATUS "Fetching MsQuic from GitHub...")


set(QUIC_BUILD_TOOLS OFF CACHE BOOL "Don't build MsQuic tools")
set(QUIC_BUILD_TEST OFF CACHE BOOL "Don't build MsQuic tests")
set(QUIC_BUILD_PERF OFF CACHE BOOL "Don't build MsQuic perf tools")
add_compile_definitions(
    QUIC_API_ENABLE_PREVIEW_FEATURES=1
)


if(WTF_ENABLE_LOGGING OR CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(QUIC_ENABLE_LOGGING ON CACHE BOOL "Enable MsQuic logging")
    set(QUIC_LOGGING_TYPE "stdout" CACHE STRING "Set MsQuic logging output to stdout")
    message(STATUS "MsQuic logging enabled with stdout output")
else()
    set(QUIC_ENABLE_LOGGING OFF CACHE BOOL "Disable MsQuic logging")
endif()


if(WIN32)
    set(QUIC_TLS_LIB "schannel" CACHE STRING "Use Schannel on Windows")
else()
    set(QUIC_TLS_LIB "openssl" CACHE STRING "Use OpenSSL on non-Windows")
endif()

FetchContent_Declare(
        msquic
        GIT_REPOSITORY https://github.com/microsoft/msquic.git
        GIT_TAG        main
        GIT_SHALLOW    TRUE
        GIT_PROGRESS   TRUE
    )

FetchContent_MakeAvailable(msquic)


set(MSQUIC_LIBRARIES msquic)
set(MSQUIC_INCLUDE_DIRS ${msquic_SOURCE_DIR}/src/inc)

if(WIN32)
    set(PLATFORM_LIBS ws2_32 iphlpapi bcrypt)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        list(APPEND PLATFORM_LIBS dbghelp)
    endif()
else()
    find_package(Threads REQUIRED)
    set(PLATFORM_LIBS Threads::Threads)
    if(NOT APPLE)
        list(APPEND PLATFORM_LIBS rt)
    endif()
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
            list(APPEND PLATFORM_LIBS dl)
        endif()
        if(APPLE)
            list(APPEND PLATFORM_LIBS "-framework CoreFoundation")
        endif()
    endif()
endif()


set(WTF_SOURCES
    deps/tinycthreads/tinycthread.c
    deps/ls-qpack/lsqpack.c
    deps/xxhash/xxhash.c
    src/wtf.c
)

set(WTF_HEADERS
    deps/verstable/verstable.h
    include/wtf.h
    deps/tinycthreads/tinycthread.h
    deps/ls-qpack/lsqpack.h
    deps/xxhash/xxhash.h
    deps/ls-qpack/lsxpack_header.h
    deps/ls-qpack/huff-tables.h
    ${CMAKE_CURRENT_BINARY_DIR}/include/wtf_version.h
)



add_library(wtf SHARED ${WTF_SOURCES})

set_target_properties(wtf PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
)

if(WIN32)
    set_target_properties(wtf PROPERTIES
        WINDOWS_EXPORT_ALL_SYMBOLS ON
        ARCHIVE_OUTPUT_NAME wtf
        RUNTIME_OUTPUT_NAME wtf
    )
endif()

target_include_directories(wtf
    PUBLIC 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}/include>
        $<INSTALL_INTERFACE:include>
    PRIVATE
        ${MSQUIC_INCLUDE_DIRS}
)

if(WIN32 OR EMSCRIPTEN)
    target_include_directories(wtf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/wincompat
    )
endif()

target_include_directories(wtf PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycthreads
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/ls-qpack
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash
    ${CMAKE_CURRENT_SOURCE_DIR}/deps/verstable
)

target_link_libraries(wtf
    PRIVATE
        ${MSQUIC_LIBRARIES}
        ${PLATFORM_LIBS}
)

if(WTF_ENABLE_LOGGING)
    target_compile_definitions(wtf PRIVATE WTF_ENABLE_LOGGING=1)
endif()

add_library(WebTransport::wtf ALIAS wtf)

if(WTF_BUILD_SAMPLES AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/samples")
    add_subdirectory(samples)
endif()

if(WTF_BUILD_TESTS AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/tests")
    enable_testing()
    add_subdirectory(tests)
endif()


include(GNUInstallDirs)

install(FILES include/wtf.h
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS wtf
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

message(STATUS "")
message(STATUS "WebTransport Library Configuration:")
message(STATUS "  Git Version:       ${GIT_VERSION}")
message(STATUS "  Project Version:   ${PROJECT_VERSION}")
message(STATUS "  Build type:        ${CMAKE_BUILD_TYPE}")
message(STATUS "  Library type:      SHARED")
message(STATUS "  Output directory:  ${CMAKE_BINARY_DIR}/output")
message(STATUS "  Tests:             ${WTF_BUILD_TESTS}")
message(STATUS "  Samples:           ${WTF_BUILD_SAMPLES}")
message(STATUS "  Logging:           ${WTF_ENABLE_LOGGING}")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
message(STATUS "  Debug symbols:     ON")
message(STATUS "  Stack traces:      ON")
message(STATUS "  Optimizations:     OFF")
message(STATUS "  LTO:               OFF")
if(APPLE)
message(STATUS "  macOS debug mode:  ENHANCED")
endif()
else()
message(STATUS "  Optimizations:     ON")
message(STATUS "  LTO:               ON")
endif()
if(WTF_ENABLE_LOGGING OR CMAKE_BUILD_TYPE STREQUAL "Debug")
message(STATUS "  MsQuic Logging:    ON (stdout)")
else()
message(STATUS "  MsQuic Logging:    OFF")
endif()
if(WIN32)
message(STATUS "  Windows DLL Export: ON")
endif()
message(STATUS "")