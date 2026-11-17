# Echo Server
add_executable(wtf_echo_server
    echo_server.c
)

add_executable(wtf_echo_client
    echo_client.c
)

target_link_libraries(wtf_echo_server
    PRIVATE
        wtf
)

target_link_libraries(wtf_echo_client
    PRIVATE
        wtf
)

if(WTF_BUILD_CPP)
    add_executable(wtf_echo_cpp echo_cpp.cc)
    target_link_libraries(wtf_echo_cpp PRIVATE WebTransport::cpp)
endif()

# Copy certificates if they exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    file(COPY certs DESTINATION ${CMAKE_BINARY_DIR})
endif()

# Install sample executables
install(TARGETS 
    wtf_echo_server
    wtf_echo_client
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)
