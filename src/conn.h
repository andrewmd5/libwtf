#ifndef WTF_CONN_H
#define WTF_CONN_H
#include "types.h"
#ifdef __cplusplus
extern "C" {
#endif

QUIC_CONNECTION_CALLBACK wtf_connection_callback;

wtf_connection* wtf_connection_create(wtf_server* server, HQUIC quic_connection);
wtf_connection* wtf_connection_create_client(wtf_client* client, HQUIC quic_connection);
void wtf_connection_destroy(wtf_connection* conn);
void wtf_connection_add_ref(wtf_connection* conn);
void wtf_connection_release(wtf_connection* conn);
void wtf_connection_close_transport(wtf_connection* conn, bool shutdown);
wtf_result_t wtf_connection_get_statistics(wtf_connection* conn, QUIC_STATISTICS_V2* stats,
                                            uint32_t* size);
wtf_session* wtf_connection_find_session(wtf_connection* conn, uint64_t session_id);
bool wtf_connection_uses_webtransport_flow_control(const wtf_connection* conn);
bool wtf_connection_uses_original_draft02(const wtf_connection* conn);

bool wtf_connection_associate_stream_with_session(wtf_connection* conn, wtf_http3_stream* h3_stream,
                                                  wtf_session* session);

#ifdef __cplusplus
}
#endif
#endif  // WTF_CONN_H
