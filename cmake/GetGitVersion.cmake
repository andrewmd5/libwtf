# GetGitVersion.cmake
# - Returns a version string from Git tags and extracts version components
#
# This function inspects the git tags for the project and returns the full tag string
# along with extracted major, minor, and patch version components
#
# get_git_version(<var> [WORKING_DIRECTORY <dir>])
#
# Sets the following variables in parent scope:
#   <var>        - Full git version string (e.g., "v1.2.3-alpha.1-5-g1a2b3c4d-dirty")
#   <var>_MAJOR  - Major version number (e.g., "1")
#   <var>_MINOR  - Minor version number (e.g., "2") 
#   <var>_PATCH  - Patch version number (e.g., "3")
#
# - Example
#
# include(GetGitVersion)
# get_git_version(GIT_VERSION WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
# # Results in:
# # GIT_VERSION = "v1.2.3-alpha.1-5-g1a2b3c4d-dirty"
# # GIT_VERSION_MAJOR = "1"
# # GIT_VERSION_MINOR = "2"
# # GIT_VERSION_PATCH = "3"

find_package(Git QUIET)

if(__get_git_version)
    return()
endif()
set(__get_git_version INCLUDED)

function(get_git_version var)
    # Parse arguments
    cmake_parse_arguments(GGV "" "WORKING_DIRECTORY" "" ${ARGN})
    
    # Use provided working directory or default to current source dir
    if(GGV_WORKING_DIRECTORY)
        set(WORK_DIR ${GGV_WORKING_DIRECTORY})
    else()
        set(WORK_DIR ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    
    if(GIT_EXECUTABLE)
        # Get the full git describe output - prioritize any version-like tags
        execute_process(
            COMMAND ${GIT_EXECUTABLE} describe --tags --long --dirty --abbrev=8
            WORKING_DIRECTORY ${WORK_DIR}
            RESULT_VARIABLE status
            OUTPUT_VARIABLE GIT_VERSION
            ERROR_QUIET
        )
        
        if(${status})
            # If no tags found, try to get commit hash only
            execute_process(
                COMMAND ${GIT_EXECUTABLE} rev-parse --short=8 HEAD
                WORKING_DIRECTORY ${WORK_DIR}
                RESULT_VARIABLE status2
                OUTPUT_VARIABLE GIT_COMMIT
                ERROR_QUIET
            )
            
            if(${status2})
                set(GIT_VERSION "v0.0.0")
            else()
                string(STRIP "${GIT_COMMIT}" GIT_COMMIT)
                
                # Check if working directory is dirty
                execute_process(
                    COMMAND ${GIT_EXECUTABLE} diff-index --quiet HEAD --
                    WORKING_DIRECTORY ${WORK_DIR}
                    RESULT_VARIABLE is_dirty
                    ERROR_QUIET
                )
                
                if(is_dirty)
                    set(GIT_VERSION "v0.0.0-g${GIT_COMMIT}-dirty")
                else()
                    set(GIT_VERSION "v0.0.0-g${GIT_COMMIT}")
                endif()
            endif()
        else()
            string(STRIP "${GIT_VERSION}" GIT_VERSION)
        endif()
    else()
        # Git not found, use default version
        set(GIT_VERSION "v0.0.0")
    endif()
    
    message(STATUS "Git Version: ${GIT_VERSION}")
    
    # Extract major, minor, patch from the version string
    # Look for pattern like v1.2.3 at the beginning, handling various formats
    if(GIT_VERSION MATCHES "^v?([0-9]+)\\.([0-9]+)\\.([0-9]+)")
        set(VERSION_MAJOR ${CMAKE_MATCH_1})
        set(VERSION_MINOR ${CMAKE_MATCH_2})
        set(VERSION_PATCH ${CMAKE_MATCH_3})
    else()
        # Fallback to 0.0.0 if no semantic version found
        set(VERSION_MAJOR "0")
        set(VERSION_MINOR "0")
        set(VERSION_PATCH "0")
    endif()
    
    # Set all variables in parent scope
    set(${var} ${GIT_VERSION} PARENT_SCOPE)
    set(${var}_MAJOR ${VERSION_MAJOR} PARENT_SCOPE)
    set(${var}_MINOR ${VERSION_MINOR} PARENT_SCOPE)
    set(${var}_PATCH ${VERSION_PATCH} PARENT_SCOPE)
    
    message(STATUS "Version Components - Major: ${VERSION_MAJOR}, Minor: ${VERSION_MINOR}, Patch: ${VERSION_PATCH}")
    
endfunction()