add_executable(wtf_echo_server
    echo_server.c
)

target_link_libraries(wtf_echo_server
    PRIVATE
        $<IF:$<TARGET_EXISTS:wtf_shared>,wtf_shared,wtf_static>
)


add_executable(wtf_echo_client
    echo_client.c
)

target_link_libraries(wtf_echo_client
    PRIVATE
        $<IF:$<TARGET_EXISTS:wtf_shared>,wtf_shared,wtf_static>
)


add_executable(wtf_chat
    chat.c
)

target_link_libraries(wtf_chat
    PRIVATE
        $<IF:$<TARGET_EXISTS:wtf_shared>,wtf_shared,wtf_static>
)


if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/certs")
    file(COPY certs DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
endif()


install(TARGETS 
    wtf_echo_server 
    wtf_echo_client 
    wtf_chat
    DESTINATION ${CMAKE_INSTALL_BINDIR}
)