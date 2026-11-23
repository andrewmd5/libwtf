#ifndef WTF_CLIENT_H
#define WTF_CLIENT_H

#include "types.h"

#ifdef __cplusplus
extern "C" {
#endif

bool wtf_client_has_pinned_server_certificate(const wtf_client* client);
bool wtf_client_validate_pinned_server_certificate(wtf_client* client,
                                                   const QUIC_BUFFER* certificate);
void wtf_client_mark_transport_ready(wtf_client* client);
void wtf_client_note_session_closed(wtf_client* client, const wtf_session* session);
void wtf_client_fail_pending_sessions(wtf_client* client, wtf_result_t result, const char* reason);

#ifdef __cplusplus
}
#endif

#endif  // WTF_CLIENT_H
