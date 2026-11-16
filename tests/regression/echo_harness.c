/* Compile the real sample callbacks into the transport regression tests. */
#define main wtf_echo_server_main
#include "../../samples/echo_server.c"
#undef main

void wtf_test_echo_session(wtf_session_t* session)
{
    wtf_session_event_t event = {.type = WTF_SESSION_EVENT_CONNECTED, .session = session};
    session_callback(&event);
}

void wtf_test_echo_stream(wtf_session_t* session, wtf_stream_t* stream)
{
    wtf_session_event_t event = {
        .type = WTF_SESSION_EVENT_STREAM_OPENED,
        .session = session,
        .user_context = wtf_session_get_context(session),
        .stream_opened = {.stream = stream, .stream_type = WTF_STREAM_BIDIRECTIONAL}};
    session_callback(&event);
}

wtf_result_t wtf_test_echo_send(wtf_stream_t* stream, const void* data, size_t length)
{
    return echo_stream_send(wtf_stream_get_context(stream), data, length);
}

size_t wtf_test_echo_queued(void)
{
    return atomic_load(&g_queued_bytes);
}

void wtf_test_echo_disconnected(const wtf_session_event_t* event)
{
    session_callback(event);
}
