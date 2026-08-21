if("${CMAKE_HOST_SYSTEM_NAME}" STREQUAL "Windows")
    cmake_minimum_required(VERSION 3.20)
else()
    cmake_minimum_required(VERSION 3.16)
endif()

include(cmake/GetGitVersion.cmake)
get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

project(wtf 
    VERSION ${GIT_VERSION_MAJOR}.${GIT_VERSION_MINOR}.${GIT_VERSION_PATCH}
    DESCRIPTION "A fast WebTransport library"
    LANGUAGES C CXX)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_CONFIGURATION_TYPES "Debug;Release;RelWithDebInfo" CACHE STRING "Available build configurations" FORCE)
endif()

set(CMAKE_SKIP_BUILD_RPATH FALSE)
set(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
set(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
set(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)

set(WTF_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/output CACHE STRING "Output directory for build artifacts")

if(CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
    foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
        string(TOUPPER ${CONFIG} CONFIG_UPPER)
        set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
        set(CMAKE_LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
        set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG})
    endforeach()
else()
    set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
    set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
    set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR})
endif()

option(WTF_BUILD_TESTS "Build tests" OFF)
option(WTF_BUILD_SAMPLES "Build sample applications" OFF)
option(WTF_ENABLE_LOGGING "Enable logging support" ON)
option(WTF_USE_EXTERNAL_MSQUIC "Use an external msquic installation" OFF)
option(WTF_APPLY_BUNDLED_MSQUIC_PATCHES "Apply libwtf patches to the bundled msquic submodule" ON)
option(WTF_ENABLE_COVERAGE "Build tests with coverage instrumentation" OFF)
option(BUILD_SHARED_LIBS "Build shared libraries" ON)

if(WTF_ENABLE_COVERAGE)
    if(NOT WTF_BUILD_TESTS)
        message(FATAL_ERROR "WTF_ENABLE_COVERAGE requires WTF_BUILD_TESTS=ON")
    endif()
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang" AND CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
        set(WTF_COVERAGE_COMPILE_OPTIONS --coverage -O0 -g)
        set(WTF_COVERAGE_LINK_OPTIONS --coverage)
    else()
        message(FATAL_ERROR "WTF_ENABLE_COVERAGE currently supports GCC/Clang builds")
    endif()
endif()

set(WTF_VERSION ${GIT_VERSION})
configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/version.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/include/wtf_version.h
    @ONLY
)

set(WTF_LIBRARY_NAME "wtf")
set(WTF_VERSION_MAJOR ${GIT_VERSION_MAJOR})
set(WTF_VERSION_MINOR ${GIT_VERSION_MINOR})
set(WTF_VERSION_PATCH ${GIT_VERSION_PATCH})

if(WIN32)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /NODEFAULTLIB:libucrt.lib /DEFAULTLIB:ucrt.lib")
    add_compile_definitions(WIN32_LEAN_AND_MEAN)
    if(HAS_SPECTRE)
        add_compile_options(/Qspectre)
    endif()
    add_compile_options(/W3)
    add_compile_options(/std:c11 /experimental:c11atomics) # fix "C atomic support is not enabled"
    add_compile_options(/wd28020)                          # see https://github.com/microsoft/msquic/issues/6234
    
    add_compile_options(
        $<$<CONFIG:Debug>:/Od>
        $<$<CONFIG:Debug>:/Zi>
        $<$<CONFIG:Debug>:/RTC1>
        $<$<CONFIG:Release>:/O2>
        $<$<CONFIG:Release>:/DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:/O2>
        $<$<CONFIG:RelWithDebInfo>:/Zi>
        $<$<CONFIG:RelWithDebInfo>:/DNDEBUG>
    )
    
    add_link_options($<$<CONFIG:Debug>:/DEBUG:FULL>)
    
    set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /GL /Zi")
    set(CMAKE_C_FLAGS_RELWITHDEBINFO "${CMAKE_C_FLAGS_RELWITHDEBINFO} /GL /Zi")
    set(CMAKE_CXX_FLAGS_RELWITHDEBINFO "${CMAKE_CXX_FLAGS_RELWITHDEBINFO} /GL /Zi")
    
    set(CMAKE_SHARED_LINKER_FLAGS_RELEASE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_SHARED_LINKER_FLAGS_RELWITHDEBINFO} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
    set(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} /LTCG /IGNORE:4075 /DEBUG /OPT:REF /OPT:ICF")
else()
    add_compile_options(-Wall -Wextra)
    add_compile_options(
        $<$<CONFIG:Debug>:-g>
        $<$<CONFIG:Debug>:-O0>
        $<$<CONFIG:Debug>:-DDEBUG>
        $<$<CONFIG:Debug>:-fno-omit-frame-pointer>
        $<$<CONFIG:Release>:-O2>
        $<$<CONFIG:Release>:-DNDEBUG>
        $<$<CONFIG:RelWithDebInfo>:-O2>
        $<$<CONFIG:RelWithDebInfo>:-g>
        $<$<CONFIG:RelWithDebInfo>:-DNDEBUG>
    )
    
    if(APPLE)
        add_compile_options(
            $<$<CONFIG:Debug>:-fno-limit-debug-info>
            $<$<CONFIG:Debug>:-gdwarf-4>
            $<$<CONFIG:RelWithDebInfo>:-fno-limit-debug-info>
            $<$<CONFIG:RelWithDebInfo>:-gdwarf-4>
        )
        add_link_options(
            $<$<CONFIG:Debug>:-Wl,-no_compact_unwind>
            $<$<CONFIG:RelWithDebInfo>:-Wl,-no_compact_unwind>
        )
    endif()
    
    add_link_options(
        $<$<CONFIG:Release>:-flto>
        $<$<CONFIG:RelWithDebInfo>:-flto>
    )
    
    if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
        add_compile_options(
            $<$<CONFIG:Release>:-fuse-linker-plugin>
            $<$<CONFIG:Release>:-ffat-lto-objects>
            $<$<CONFIG:RelWithDebInfo>:-fuse-linker-plugin>
            $<$<CONFIG:RelWithDebInfo>:-ffat-lto-objects>
        )
        add_link_options(
            $<$<CONFIG:Release>:-fuse-linker-plugin>
            $<$<CONFIG:RelWithDebInfo>:-fuse-linker-plugin>
        )
    endif()
endif()


if(WTF_USE_EXTERNAL_MSQUIC)
    find_package(msquic CONFIG REQUIRED)
    set(MSQUIC_LIBRARIES msquic)
else()
    set(CMAKE_POLICY_DEFAULT_CMP0077 NEW)
    
    if(WIN32)
        set(QUIC_TLS_LIB "schannel" CACHE STRING "Use Schannel on Windows")
    else()
        set(QUIC_TLS_LIB "openssl" CACHE STRING "Use OpenSSL on non-Windows")
    endif()
    
    set(QUIC_BUILD_SHARED ON CACHE BOOL "Builds MsQuic as a dynamic library")
    set(QUIC_BUILD_TOOLS OFF CACHE BOOL "Don't build MsQuic tools")
    set(QUIC_BUILD_TEST OFF CACHE BOOL "Don't build MsQuic tests")
    set(QUIC_BUILD_PERF OFF CACHE BOOL "Don't build MsQuic perf tools")
    
    if(CMAKE_CONFIGURATION_TYPES)
        set(QUIC_OUTPUT_DIR ${WTF_OUTPUT_DIR}/$<CONFIG> CACHE STRING "Output directory for MsQuic artifacts")
    else()
        set(QUIC_OUTPUT_DIR ${WTF_OUTPUT_DIR} CACHE STRING "Output directory for MsQuic artifacts")
    endif()
    
    if(WTF_ENABLE_LOGGING)
          set(QUIC_ENABLE_LOGGING OFF CACHE BOOL "Explicitly disable MsQuic logging")
    else()
        set(QUIC_ENABLE_LOGGING OFF CACHE BOOL "Explicitly disable MsQuic logging")
    endif()
    
    add_compile_definitions(QUIC_API_ENABLE_PREVIEW_FEATURES=1)

    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        add_compile_options(-Wno-invalid-unevaluated-string)
    endif()

    set(WTF_MSQUIC_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/msquic)

    # Patch the msquic submodule in place. Submodule dirtiness is silenced via
    # `submodule.msquic.ignore = dirty` in .gitmodules, so the patched working
    # tree never shows up as a change in this repo or its parents.
    if(WTF_APPLY_BUNDLED_MSQUIC_PATCHES)
        find_package(Git QUIET)
        if(NOT Git_FOUND)
            message(FATAL_ERROR "Git is required to apply bundled MsQuic patches")
        endif()

        set(WTF_BUNDLED_MSQUIC_PATCHES
            ${CMAKE_CURRENT_SOURCE_DIR}/cmake/patches/msquic/reliable-reset-draft07.patch
        )

        foreach(WTF_BUNDLED_MSQUIC_PATCH IN LISTS WTF_BUNDLED_MSQUIC_PATCHES)
            execute_process(
                COMMAND ${GIT_EXECUTABLE} apply --reverse --check ${WTF_BUNDLED_MSQUIC_PATCH}
                WORKING_DIRECTORY ${WTF_MSQUIC_SOURCE_DIR}
                RESULT_VARIABLE WTF_BUNDLED_MSQUIC_PATCH_ALREADY_APPLIED
                OUTPUT_QUIET
                ERROR_QUIET
            )

            if(WTF_BUNDLED_MSQUIC_PATCH_ALREADY_APPLIED EQUAL 0)
                message(STATUS "Bundled MsQuic patch already applied: ${WTF_BUNDLED_MSQUIC_PATCH}")
            else()
                execute_process(
                    COMMAND ${GIT_EXECUTABLE} apply --check ${WTF_BUNDLED_MSQUIC_PATCH}
                    WORKING_DIRECTORY ${WTF_MSQUIC_SOURCE_DIR}
                    RESULT_VARIABLE WTF_BUNDLED_MSQUIC_PATCH_CAN_APPLY
                    OUTPUT_QUIET
                    ERROR_QUIET
                )
                if(NOT WTF_BUNDLED_MSQUIC_PATCH_CAN_APPLY EQUAL 0)
                    message(FATAL_ERROR
                        "Bundled MsQuic patch no longer applies cleanly: "
                        "${WTF_BUNDLED_MSQUIC_PATCH}. Update or remove the patch."
                    )
                endif()
                execute_process(
                    COMMAND ${GIT_EXECUTABLE} apply ${WTF_BUNDLED_MSQUIC_PATCH}
                    WORKING_DIRECTORY ${WTF_MSQUIC_SOURCE_DIR}
                    RESULT_VARIABLE WTF_BUNDLED_MSQUIC_PATCH_RESULT
                )
                if(NOT WTF_BUNDLED_MSQUIC_PATCH_RESULT EQUAL 0)
                    message(FATAL_ERROR "Failed to apply bundled MsQuic patch: ${WTF_BUNDLED_MSQUIC_PATCH}")
                endif()
                message(STATUS "Applied bundled MsQuic patch: ${WTF_BUNDLED_MSQUIC_PATCH}")
            endif()
        endforeach()
    endif()

    add_subdirectory(${WTF_MSQUIC_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/_deps/msquic-build)
    
    if(TARGET msquic)
        if(CMAKE_CONFIGURATION_TYPES)
            foreach(CONFIG ${CMAKE_CONFIGURATION_TYPES})
                string(TOUPPER ${CONFIG} CONFIG_UPPER)
                set_target_properties(msquic PROPERTIES
                    RUNTIME_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
                    LIBRARY_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
                    ARCHIVE_OUTPUT_DIRECTORY_${CONFIG_UPPER} ${WTF_OUTPUT_DIR}/${CONFIG}
                )
            endforeach()
        else()
            set_target_properties(msquic PROPERTIES
                RUNTIME_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
                LIBRARY_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
                ARCHIVE_OUTPUT_DIRECTORY ${WTF_OUTPUT_DIR}
            )
        endif()
    endif()
    
    set(MSQUIC_LIBRARIES msquic)
    set(MSQUIC_INCLUDE_DIRS ${CMAKE_CURRENT_SOURCE_DIR}/msquic/src/inc)
endif()

if(WIN32)
    set(PLATFORM_LIBS ws2_32 iphlpapi bcrypt crypt32)
    set(PLATFORM_LIBS ${PLATFORM_LIBS} $<$<CONFIG:Debug>:dbghelp>)
else()
    find_package(Threads REQUIRED)
    if(NOT APPLE)
        find_package(OpenSSL REQUIRED)
    endif()
    set(PLATFORM_LIBS Threads::Threads)
    if(NOT APPLE)
        list(APPEND PLATFORM_LIBS rt m OpenSSL::Crypto)
    else()
        list(APPEND PLATFORM_LIBS "-framework Security" "-framework CoreFoundation")
    endif()

    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        set(PLATFORM_LIBS ${PLATFORM_LIBS} $<$<CONFIG:Debug>:dl>)
    endif()
endif()

if(WIN32)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/export/windows/wtf.def.in
        ${CMAKE_CURRENT_BINARY_DIR}/wtf.def
        @ONLY
    )
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/cmake/export/windows/wtf.rc.in
        ${CMAKE_CURRENT_BINARY_DIR}/wtf.rc
        @ONLY
    )
    set(WTF_EXPORT_SOURCES ${CMAKE_CURRENT_BINARY_DIR}/wtf.rc)
else()
    set(WTF_EXPORT_SOURCES "")
endif()

set(WTF_SOURCES
    deps/tinycthreads/tinycthread.c
    deps/ls-qpack/lsqpack.c
    deps/xxhash/xxhash.c
    src/log.c
    src/qpack.c
    src/varint.c
    src/utils.c
    src/datagram.c
    src/stream.c
    src/session.c   
    src/settings.c
    src/draft.c
    src/cert.c
    src/conn.c
    src/http3.c
    src/client.c
    src/server.c
    src/context.c
    ${WTF_EXPORT_SOURCES}
)

set(WTF_PUBLIC_HEADERS
    include/wtf.h
)

add_library(wtf ${WTF_SOURCES})

set_target_properties(wtf PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION ${PROJECT_VERSION_MAJOR}
    PUBLIC_HEADER "${WTF_PUBLIC_HEADERS}"
)

if(WIN32)
    set_target_properties(wtf PROPERTIES
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
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/tinycthreads
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/ls-qpack
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/xxhash
        ${CMAKE_CURRENT_SOURCE_DIR}/deps/verstable
        ${MSQUIC_INCLUDE_DIRS}
)

if(WIN32 OR EMSCRIPTEN)
    target_include_directories(wtf PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/wincompat
    )
endif()

target_link_libraries(wtf
    PRIVATE
        ${MSQUIC_LIBRARIES}
        ${PLATFORM_LIBS}
)

if(WTF_ENABLE_COVERAGE)
    target_compile_options(wtf PRIVATE ${WTF_COVERAGE_COMPILE_OPTIONS})
    target_link_options(wtf PRIVATE ${WTF_COVERAGE_LINK_OPTIONS})
endif()

if(WTF_ENABLE_LOGGING)
    target_compile_definitions(wtf PRIVATE WTF_ENABLE_LOGGING=1)
endif()

target_compile_definitions(wtf PRIVATE WTF_EXPORTS)

if(NOT WIN32)
    target_compile_options(wtf PRIVATE -fvisibility=hidden)
    target_compile_options(wtf PRIVATE -fvisibility-inlines-hidden)
    set_target_properties(wtf PROPERTIES
        C_VISIBILITY_PRESET hidden
        CXX_VISIBILITY_PRESET hidden
        VISIBILITY_INLINES_HIDDEN YES
    )
endif()

if(BUILD_SHARED_LIBS)
    if(WIN32)
        set_target_properties(wtf PROPERTIES
            LINK_FLAGS "/DEF:${CMAKE_CURRENT_BINARY_DIR}/wtf.def"
        )
    elseif(APPLE)
        set_target_properties(wtf PROPERTIES
            LINK_FLAGS "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/cmake/export/darwin/exports.txt -Wl,-dead_strip -Wl,-x"
        )
    elseif(UNIX)
        set_target_properties(wtf PROPERTIES
            LINK_FLAGS "-Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/cmake/export/linux/exports.txt -Wl,--gc-sections -Wl,--strip-all"
        )
    endif()
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

install(FILES ${WTF_PUBLIC_HEADERS}
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(TARGETS wtf
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)
