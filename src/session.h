#ifndef WTF_SESSION_H
#define WTF_SESSION_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

wtf_session* wtf_session_create(wtf_connection* conn, wtf_http3_stream* connect_stream);
void wtf_session_destroy(wtf_session* session);
void wtf_session_add_ref(wtf_session* session);
void wtf_session_release(wtf_session* session);
void wtf_session_retire(wtf_session* session);
void wtf_session_shutdown(wtf_session* session, uint32_t error_code, const char* reason);
wtf_result_t wtf_session_send_capsule(wtf_session* session, uint64_t type, const uint8_t* data,
                                      size_t length);

bool wtf_session_process_datagram(wtf_session* session, const uint8_t* data, size_t length);
bool wtf_session_process_capsule(wtf_session* session, const wtf_capsule* capsule);
bool wtf_session_accept_incoming_data(wtf_session* session, uint64_t length);
bool wtf_session_reserve_outgoing_stream(wtf_session* session, wtf_stream_type_t type);
void wtf_session_release_outgoing_stream(wtf_session* session, wtf_stream_type_t type);
void wtf_session_replenish_local_stream_credit(wtf_session* session, wtf_stream_type_t type);
bool wtf_session_reserve_outgoing_data(wtf_session* session, uint64_t length);
void wtf_session_release_outgoing_data(wtf_session* session, uint64_t length);
void wtf_session_fail_flow_control(wtf_session* session);
void wtf_session_cleanup_datagram_send_context(wtf_internal_send_context* send_ctx);

#ifdef __cplusplus
}
#endif
#endif  // WTF_SESSION_H
