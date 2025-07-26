# Echo Server
add_executable(wtf_echo_server
    echo_server.c
)

target_link_libraries(wtf_echo_server
    PRIVATE
        wtf
)

# Echo Client
add_executable(wtf_echo_client
    echo_client.c
)

target_link_libraries(wtf_echo_client
    PRIVATE
        wtf
)

# Chat Application
add_executable(wtf_chat
    chat.c
)

target_link_libraries(wtf_chat
    PRIVATE
        wtf
)

# Copy certificates if they exist
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    file(COPY certs DESTINATION ${CMAKE_BINARY_DIR})
endif()

# Install sample executables
install(TARGETS 
    wtf_echo_server
    wtf_echo_client
    wtf_chat
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)