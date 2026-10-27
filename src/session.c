#include "session.h"

#include "client.h"
#include "conn.h"
#include "log.h"
#include "stream.h"
#include "utils.h"
#include "varint.h"

#define WTF_MAX_FLOW_CONTROL_VALUE (1ULL << 60)

bool wtf_session_process_datagram(wtf_session* session, const uint8_t* data, size_t length)
{
    if (!session || (!data && length > 0))
        return false;

    if (session->destroyed || session->state == WTF_SESSION_CLOSED) {
        return false;
    }

    if (length > UINT32_MAX) {
        return false;
    }

    if (session->callback) {
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_DATAGRAM_RECEIVED,
            .session = (wtf_session_t*)session,
            .user_context = session->user_context,
            .datagram_received = {.length = (uint32_t)length, .data = (const uint8_t*)data}};
        session->callback(&event);
    }
    return true;
}

static void wtf_session_retire(wtf_session* session)
{
    if (!session || !session->connection || session->retired) {
        return;
    }

    wtf_connection* conn = session->connection;
    mtx_lock(&conn->sessions_mutex);
    if (!session->retired) {
        session_map_erase(&conn->sessions, session->id);
        session->retired = true;
        session->next_closed = conn->closed_sessions;
        conn->closed_sessions = session;
        if (conn->role == WTF_ENDPOINT_CLIENT) {
            wtf_client_note_session_closed(conn->client);
        }
    }
    mtx_unlock(&conn->sessions_mutex);
}

static void wtf_session_abort_streams(wtf_session* session, uint64_t error_code)
{
    if (!session) {
        return;
    }

    size_t stream_count = 0;
    wtf_stream** streams = NULL;

    mtx_lock(&session->streams_mutex);
    stream_count = stream_map_size(&session->streams);
    if (stream_count > 0) {
        streams = malloc(sizeof(wtf_stream*) * stream_count);
        if (streams) {
            size_t stream_index = 0;
            for (stream_map_itr itr = stream_map_first(&session->streams);
                 !stream_map_is_end(itr) && stream_index < stream_count;
                 itr = stream_map_next(itr)) {
                wtf_stream* stream = itr.data->val;
                wtf_stream_add_ref(stream);
                streams[stream_index++] = stream;
            }
            stream_count = stream_index;
        } else {
            for (stream_map_itr itr = stream_map_first(&session->streams);
                 !stream_map_is_end(itr); itr = stream_map_next(itr)) {
                wtf_stream* stream = itr.data->val;
                if (stream->quic_stream && session->connection && session->connection->context) {
                    session->connection->context->quic_api->StreamShutdown(
                        stream->quic_stream,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND
                            | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                        error_code);
                }
            }
            stream_count = 0;
        }
    }
    mtx_unlock(&session->streams_mutex);

    for (size_t i = 0; i < stream_count; i++) {
        wtf_stream* stream = streams[i];
        if (stream->quic_stream && session->connection && session->connection->context) {
            session->connection->context->quic_api->StreamShutdown(
                stream->quic_stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                error_code);
        }
        wtf_stream_release(stream);
    }

    free(streams);
}

static bool wtf_session_uses_flow_control(const wtf_session* session)
{
    return session && wtf_connection_uses_webtransport_flow_control(session->connection);
}

static bool wtf_session_decode_flow_control_value(wtf_session* session,
                                                  const wtf_capsule* capsule, uint64_t* value)
{
    if (!session || !capsule || !value || !capsule->data || capsule->length == 0) {
        return false;
    }

    size_t offset = 0;
    if (!wtf_varint_decode((size_t)capsule->length, capsule->data, &offset, value)
        || offset != capsule->length || *value > WTF_MAX_FLOW_CONTROL_VALUE) {
        WTF_LOG_ERROR(session->connection->context, "flow",
                      "Invalid flow-control capsule value for session %llu",
                      (unsigned long long)session->id);
        return false;
    }

    return true;
}

static wtf_result_t wtf_session_send_flow_control_capsule(wtf_session* session, uint64_t type,
                                                          uint64_t value)
{
    uint8_t payload[8];
    uint8_t* end = wtf_varint_encode(value, payload);
    if (!end) {
        return WTF_ERROR_INTERNAL;
    }
    return wtf_session_send_capsule(session, type, payload, (size_t)(end - payload));
}

void wtf_session_fail_flow_control(wtf_session* session)
{
    if (!session || session->destroyed || session->state == WTF_SESSION_CLOSED) {
        return;
    }

    WTF_LOG_ERROR(session->connection->context, "flow",
                  "Closing session %llu due to WebTransport flow-control violation",
                  (unsigned long long)session->id);

    session->state = WTF_SESSION_CLOSED;
    wtf_session_abort_streams(session, WTF_WEBTRANSPORT_FLOW_CONTROL_ERROR);
    wtf_session_retire(session);

    if (session->callback) {
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_DISCONNECTED,
            .session = (wtf_session_t*)session,
            .user_context = session->user_context,
            .disconnected = {.error_code = 0, .reason = "flow control error"}};
        session->callback(&event);
    }
}

bool wtf_session_accept_incoming_data(wtf_session* session, uint64_t length)
{
    if (!session) {
        return false;
    }

    if (!wtf_session_uses_flow_control(session) || length == 0) {
        return true;
    }

    bool accepted = false;
    bool should_send_update = false;
    uint64_t update_limit = 0;
    uint64_t blocked_limit = 0;
    uint64_t window = session->connection ? session->connection->local_settings.wt_initial_max_data
                                          : 0;
    mtx_lock(&session->streams_mutex);
    if (length <= session->local_max_data
        && session->received_data <= session->local_max_data - length) {
        session->received_data += length;
        accepted = true;
        if (window > 0 && session->local_max_data >= session->received_data) {
            uint64_t remaining = session->local_max_data - session->received_data;
            uint64_t threshold = window / 2;
            if (threshold == 0) {
                threshold = 1;
            }

            if (remaining <= threshold) {
                if (session->received_data > WTF_MAX_FLOW_CONTROL_VALUE - window) {
                    update_limit = WTF_MAX_FLOW_CONTROL_VALUE;
                } else {
                    update_limit = session->received_data + window;
                }

                if (update_limit > session->local_max_data) {
                    session->local_max_data = update_limit;
                    should_send_update = true;
                }
            }
        }
    } else {
        blocked_limit = session->local_max_data;
    }
    mtx_unlock(&session->streams_mutex);

    if (!accepted) {
        wtf_session_send_flow_control_capsule(session, WTF_CAPSULE_WT_DATA_BLOCKED, blocked_limit);
    } else if (should_send_update) {
        wtf_session_send_flow_control_capsule(session, WTF_CAPSULE_WT_MAX_DATA, update_limit);
    }

    return accepted;
}

bool wtf_session_reserve_outgoing_stream(wtf_session* session, wtf_stream_type_t type)
{
    if (!session) {
        return false;
    }

    bool reserved = false;
    mtx_lock(&session->streams_mutex);

    if (wtf_session_uses_flow_control(session)) {
        uint64_t* count = type == WTF_STREAM_BIDIRECTIONAL ? &session->outgoing_streams_bidi
                                                           : &session->outgoing_streams_uni;
        uint64_t limit = type == WTF_STREAM_BIDIRECTIONAL ? session->remote_max_streams_bidi
                                                          : session->remote_max_streams_uni;
        if (*count < limit) {
            (*count)++;
            session->pending_stream_count++;
            reserved = true;
        }
    } else if (stream_map_size(&session->streams) + session->pending_stream_count
               < session->max_streams) {
        session->pending_stream_count++;
        reserved = true;
    }

    mtx_unlock(&session->streams_mutex);

    if (!reserved && wtf_session_uses_flow_control(session)) {
        uint64_t limit = type == WTF_STREAM_BIDIRECTIONAL ? session->remote_max_streams_bidi
                                                          : session->remote_max_streams_uni;
        wtf_session_send_flow_control_capsule(
            session,
            type == WTF_STREAM_BIDIRECTIONAL ? WTF_CAPSULE_WT_STREAMS_BLOCKED_BIDI
                                             : WTF_CAPSULE_WT_STREAMS_BLOCKED_UNI,
            limit);
    }

    return reserved;
}

void wtf_session_release_outgoing_stream(wtf_session* session, wtf_stream_type_t type)
{
    if (!session) {
        return;
    }

    mtx_lock(&session->streams_mutex);
    if (session->pending_stream_count > 0) {
        session->pending_stream_count--;
    }

    if (wtf_session_uses_flow_control(session)) {
        uint64_t* count = type == WTF_STREAM_BIDIRECTIONAL ? &session->outgoing_streams_bidi
                                                           : &session->outgoing_streams_uni;
        if (*count > 0) {
            (*count)--;
        }
    }
    mtx_unlock(&session->streams_mutex);
}

void wtf_session_replenish_local_stream_credit(wtf_session* session, wtf_stream_type_t type)
{
    if (!session || !wtf_session_uses_flow_control(session)) {
        return;
    }

    uint64_t new_limit = 0;
    uint64_t capsule_type = type == WTF_STREAM_BIDIRECTIONAL ? WTF_CAPSULE_WT_MAX_STREAMS_BIDI
                                                             : WTF_CAPSULE_WT_MAX_STREAMS_UNI;
    bool should_send_update = false;

    mtx_lock(&session->streams_mutex);
    size_t active_streams = stream_map_size(&session->streams) + session->pending_stream_count;
    if (active_streams < session->max_streams) {
        uint64_t available = session->max_streams - active_streams;
        uint64_t incoming_count = type == WTF_STREAM_BIDIRECTIONAL
            ? session->incoming_streams_bidi
            : session->incoming_streams_uni;
        uint64_t* limit = type == WTF_STREAM_BIDIRECTIONAL ? &session->local_max_streams_bidi
                                                           : &session->local_max_streams_uni;

        if (incoming_count > WTF_MAX_FLOW_CONTROL_VALUE - available) {
            new_limit = WTF_MAX_FLOW_CONTROL_VALUE;
        } else {
            new_limit = incoming_count + available;
        }

        if (new_limit > *limit) {
            *limit = new_limit;
            should_send_update = true;
        }
    }
    mtx_unlock(&session->streams_mutex);

    if (should_send_update) {
        wtf_session_send_flow_control_capsule(session, capsule_type, new_limit);
    }
}

bool wtf_session_reserve_outgoing_data(wtf_session* session, uint64_t length)
{
    if (!session) {
        return false;
    }

    if (!wtf_session_uses_flow_control(session) || length == 0) {
        return true;
    }

    bool reserved = false;
    mtx_lock(&session->streams_mutex);
    if (length <= session->remote_max_data && session->sent_data <= session->remote_max_data - length) {
        session->sent_data += length;
        reserved = true;
    }
    mtx_unlock(&session->streams_mutex);

    if (!reserved) {
        wtf_session_send_flow_control_capsule(session, WTF_CAPSULE_WT_DATA_BLOCKED,
                                             session->remote_max_data);
    }

    return reserved;
}

void wtf_session_release_outgoing_data(wtf_session* session, uint64_t length)
{
    if (!session || !wtf_session_uses_flow_control(session) || length == 0) {
        return;
    }

    mtx_lock(&session->streams_mutex);
    if (session->sent_data >= length) {
        session->sent_data -= length;
    } else {
        session->sent_data = 0;
    }
    mtx_unlock(&session->streams_mutex);
}

void wtf_session_add_ref(wtf_session* session)
{
    if (!session) {
        return;
    }
    atomic_fetch_add_explicit(&session->ref_count, 1, memory_order_relaxed);
}

static void wtf_session_dispose(wtf_session* session)
{
    if (!session) {
        return;
    }

    if (session->destroyed) {
        return;
    }
    session->destroyed = true;

    mtx_lock(&session->streams_mutex);
    for (stream_map_itr itr = stream_map_first(&session->streams); !stream_map_is_end(itr);
         itr = stream_map_next(itr)) {
        wtf_stream_destroy(itr.data->val);
    }
    stream_map_cleanup(&session->streams);
    mtx_unlock(&session->streams_mutex);
}

void wtf_session_release(wtf_session* session)
{
    if (!session) {
        return;
    }

    if (atomic_fetch_sub_explicit(&session->ref_count, 1, memory_order_acq_rel) != 1) {
        return;
    }

    wtf_session_dispose(session);

    if (session->close_reason) {
        free(session->close_reason);
    }

    wtf_connection* conn = session->connection;
    session->connection = NULL;
    mtx_destroy(&session->streams_mutex);
    free(session);
    wtf_connection_release(conn);
}

void wtf_session_destroy(wtf_session* session)
{
    if (!session) {
        return;
    }

    wtf_session_dispose(session);
    wtf_session_release(session);
}

void wtf_session_ref(wtf_session_t* session)
{
    wtf_session_add_ref((wtf_session*)session);
}

void wtf_session_unref(wtf_session_t* session)
{
    wtf_session_release((wtf_session*)session);
}

wtf_result_t wtf_session_send_capsule(wtf_session* session, uint64_t type, const uint8_t* data,
                                      size_t length)
{
    if (!session || session->destroyed || !session->connection || session->connection->destroyed
        || !session->connect_stream || !session->connect_stream->quic_stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    size_t type_size = wtf_varint_size(type);
    size_t length_size = wtf_varint_size(length);
    size_t capsule_size = type_size + length_size + length;
    size_t total_size = wtf_varint_size(WTF_FRAME_DATA) + wtf_varint_size(capsule_size)
        + capsule_size;

    wtf_internal_send_context* send_ctx = NULL;
    uint8_t* capsule_data = NULL;
    wtf_result_t context_result = wtf_internal_send_context_create(total_size, &send_ctx,
                                                                   &capsule_data);
    if (context_result != WTF_SUCCESS) {
        return context_result;
    }

    uint8_t* current_pos = capsule_data;
    uint8_t* buffer_end = capsule_data + total_size;

    current_pos = wtf_varint_encode(WTF_FRAME_DATA, current_pos);
    current_pos = wtf_varint_encode(capsule_size, current_pos);
    current_pos = wtf_varint_encode(type, current_pos);
    if (current_pos > buffer_end) {
        wtf_internal_send_context_destroy(send_ctx);
        return WTF_ERROR_INTERNAL;
    }

    current_pos = wtf_varint_encode(length, current_pos);
    if (current_pos > buffer_end) {
        wtf_internal_send_context_destroy(send_ctx);
        return WTF_ERROR_INTERNAL;
    }

    if (data && length > 0) {
        memcpy(current_pos, data, length);
    }

    QUIC_STATUS status = session->connection->context->quic_api->StreamSend(
        session->connect_stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1,
        QUIC_SEND_FLAG_NONE, send_ctx);

    if (QUIC_FAILED(status)) {
        wtf_internal_send_context_destroy(send_ctx);
        return wtf_quic_status_to_result(status);
    }

    return WTF_SUCCESS;
}

bool wtf_session_process_capsule(wtf_session* session, const wtf_capsule* capsule)
{
    if (!session || !capsule)
        return false;

    if (session->destroyed) {
        return false;
    }

    WTF_LOG_TRACE(session->connection->context, "capsule",
                  "Processing capsule type %llu, length %llu for session %llu",
                  (unsigned long long)capsule->type, (unsigned long long)capsule->length,
                  (unsigned long long)session->id);

    switch (capsule->type) {
        case WTF_CAPSULE_DATAGRAM: {
            return true;
        }

        case WTF_CAPSULE_WT_MAX_DATA: {
            uint64_t max_data = 0;
            if (!wtf_session_decode_flow_control_value(session, capsule, &max_data)) {
                wtf_session_fail_flow_control(session);
                return false;
            }

            bool valid = true;
            mtx_lock(&session->streams_mutex);
            if (max_data < session->remote_max_data) {
                valid = false;
            } else {
                session->remote_max_data = max_data;
            }
            mtx_unlock(&session->streams_mutex);

            if (!valid) {
                WTF_LOG_ERROR(session->connection->context, "flow",
                              "WT_MAX_DATA decreased for session %llu",
                              (unsigned long long)session->id);
                wtf_session_fail_flow_control(session);
                return false;
            }
            return true;
        }

        case WTF_CAPSULE_WT_MAX_STREAMS_BIDI:
        case WTF_CAPSULE_WT_MAX_STREAMS_UNI: {
            uint64_t max_streams = 0;
            if (!wtf_session_decode_flow_control_value(session, capsule, &max_streams)) {
                wtf_session_fail_flow_control(session);
                return false;
            }

            bool is_bidi = capsule->type == WTF_CAPSULE_WT_MAX_STREAMS_BIDI;
            bool valid = true;
            mtx_lock(&session->streams_mutex);
            uint64_t* limit = is_bidi ? &session->remote_max_streams_bidi
                                      : &session->remote_max_streams_uni;
            if (max_streams < *limit) {
                valid = false;
            } else {
                *limit = max_streams;
            }
            mtx_unlock(&session->streams_mutex);

            if (!valid) {
                WTF_LOG_ERROR(session->connection->context, "flow",
                              "WT_MAX_STREAMS decreased for session %llu",
                              (unsigned long long)session->id);
                wtf_session_fail_flow_control(session);
                return false;
            }
            return true;
        }

        case WTF_CAPSULE_WT_DATA_BLOCKED:
        case WTF_CAPSULE_WT_STREAMS_BLOCKED_BIDI:
        case WTF_CAPSULE_WT_STREAMS_BLOCKED_UNI: {
            uint64_t blocked_at = 0;
            if (!wtf_session_decode_flow_control_value(session, capsule, &blocked_at)) {
                wtf_session_fail_flow_control(session);
                return false;
            }
            WTF_LOG_DEBUG(session->connection->context, "flow",
                          "Peer blocked on capsule type %llu at limit %llu for session %llu",
                          (unsigned long long)capsule->type, (unsigned long long)blocked_at,
                          (unsigned long long)session->id);
            return true;
        }

        case WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION: {
            WTF_LOG_INFO(session->connection->context, "session",
                         "Session %llu received DRAIN capsule", (unsigned long long)session->id);

            if (session->state == WTF_SESSION_CONNECTED) {
                session->state = WTF_SESSION_DRAINING;

                if (session->callback) {
                    wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                                 .session = (wtf_session_t*)session,
                                                 .user_context = session->user_context};
                    session->callback(&event);
                }
            } else {
                WTF_LOG_TRACE(session->connection->context, "session",
                              "Ignoring DRAIN capsule - session %llu is in state %d",
                              (unsigned long long)session->id, session->state);
            }

            return true;
        }

        case WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION: {
            if (capsule->length < WTF_CLOSE_ERROR_CODE_LENGTH) {
                WTF_LOG_ERROR(session->connection->context, "capsule",
                              "CLOSE capsule too short: %llu bytes",
                              (unsigned long long)capsule->length);
                return false;
            }

            uint32_t error_code = 0;
            if (capsule->data && capsule->length >= 4) {
                error_code = (uint32_t)(((uint32_t)capsule->data[0] << 24)
                                        | ((uint32_t)capsule->data[1] << 16)
                                        | ((uint32_t)capsule->data[2] << 8)
                                        | (uint32_t)capsule->data[3]);
            }

            char* reason = NULL;
            size_t reason_len = (size_t)capsule->length - WTF_CLOSE_ERROR_CODE_LENGTH;
            if (reason_len > 0 && capsule->data) {
                if (reason_len > WTF_MAX_CLOSE_REASON_LENGTH) {
                    reason_len = WTF_MAX_CLOSE_REASON_LENGTH;
                }
                reason = wtf_strndup(
                    (const char*)(capsule->data + WTF_CLOSE_ERROR_CODE_LENGTH), reason_len);
                if (!reason) {
                    WTF_LOG_ERROR(session->connection->context, "session",
                                  "Failed to allocate CLOSE capsule reason");
                    return false;
                }
            }

            WTF_LOG_INFO(session->connection->context, "session",
                         "Session %llu received CLOSE capsule: error=%u, reason='%s'",
                         (unsigned long long)session->id, error_code, reason ? reason : "");

            session->close_error_code = error_code;
            if (session->close_reason) {
                free(session->close_reason);
            }
            session->close_reason = reason;
            session->state = WTF_SESSION_CLOSED;
            wtf_session_abort_streams(session, WTF_WEBTRANSPORT_SESSION_GONE);
            wtf_session_retire(session);

            if (session->callback) {
                wtf_session_event_t event = {
                    .type = WTF_SESSION_EVENT_DISCONNECTED,
                    .session = (wtf_session_t*)session,
                    .user_context = session->user_context,
                    .disconnected = {.error_code = error_code, .reason = reason}};
                session->callback(&event);
            }

            return true;
        }

        default:

            WTF_LOG_DEBUG(session->connection->context, "capsule",
                          "Ignoring unknown capsule type %llu", (unsigned long long)capsule->type);
            return true;
    }
}

wtf_session* wtf_session_create(wtf_connection* conn, wtf_http3_stream* connect_stream)
{
    if (!conn || !connect_stream)
        return NULL;

    wtf_session* session = malloc(sizeof(wtf_session));
    if (!session) {
        return NULL;
    }

    memset(session, 0, sizeof(*session));
    atomic_init(&session->ref_count, 1);
    session->connection = conn;
    session->connect_stream = connect_stream;
    session->state = WTF_SESSION_HANDSHAKING;
    session->id = connect_stream->id;
    session->max_streams = conn->max_streams_per_session;
    if (session->max_streams == 0) {
        session->max_streams = WTF_DEFAULT_MAX_STREAMS_PER_SESSION;
    }
    session->local_max_streams_bidi = conn->local_settings.wt_initial_max_streams_bidi;
    session->local_max_streams_uni = conn->local_settings.wt_initial_max_streams_uni;
    session->remote_max_streams_bidi = conn->peer_settings.wt_initial_max_streams_bidi;
    session->remote_max_streams_uni = conn->peer_settings.wt_initial_max_streams_uni;
    session->local_max_data = conn->local_settings.wt_initial_max_data;
    session->remote_max_data = conn->peer_settings.wt_initial_max_data;

    stream_map_init(&session->streams);

    if (mtx_init(&session->streams_mutex, mtx_plain) != thrd_success) {
        stream_map_cleanup(&session->streams);
        free(session);
        return NULL;
    }

    wtf_connection_add_ref(conn);
    return session;
}

wtf_result_t wtf_session_close(wtf_session_t* session, uint32_t error_code, const char* reason)
{
    if (!session) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed || !sess->connection || sess->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (sess->state == WTF_SESSION_CLOSED) {
        return WTF_ERROR_INVALID_STATE;
    }

    WTF_LOG_INFO(sess->connection->context, "session",
                 "Closing session %llu with error %u: %s", (unsigned long long)sess->id, error_code,
                 reason ? reason : "");

    size_t reason_len = 0;
    char* close_reason = NULL;
    if (reason) {
        reason_len = strlen(reason);
        if (reason_len > WTF_MAX_CLOSE_REASON_LENGTH) {
            WTF_LOG_WARN(sess->connection->context, "session",
                         "Close reason truncated from %zu to %zu bytes", reason_len,
                         (size_t)WTF_MAX_CLOSE_REASON_LENGTH);
            reason_len = WTF_MAX_CLOSE_REASON_LENGTH;
        }

        close_reason = wtf_strndup(reason, reason_len);
        if (!close_reason) {
            return WTF_ERROR_OUT_OF_MEMORY;
        }
    }

    sess->state = WTF_SESSION_CLOSED;
    sess->close_error_code = error_code;

    if (sess->close_reason) {
        free(sess->close_reason);
    }
    sess->close_reason = close_reason;

    uint8_t close_data[WTF_CLOSE_ERROR_CODE_LENGTH + WTF_MAX_CLOSE_REASON_LENGTH];
    uint32_t close_len = WTF_CLOSE_ERROR_CODE_LENGTH;

    close_data[0] = (uint8_t)(error_code >> 24);
    close_data[1] = (uint8_t)(error_code >> 16);
    close_data[2] = (uint8_t)(error_code >> 8);
    close_data[3] = (uint8_t)(error_code);

    if (reason_len > 0) {
        memcpy(close_data + WTF_CLOSE_ERROR_CODE_LENGTH, reason, reason_len);
        close_len += (uint32_t)reason_len;
    }

    wtf_result_t result = wtf_session_send_capsule(sess, WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION,
                                                   close_data, close_len);

    if (result == WTF_SUCCESS && sess->connect_stream && sess->connect_stream->quic_stream) {
        WTF_LOG_DEBUG(sess->connection->context, "session",
                      "Sending FIN on CONNECT stream after CLOSE_WEBTRANSPORT_SESSION");

        QUIC_STATUS status = sess->connection->context->quic_api->StreamSend(
            sess->connect_stream->quic_stream, NULL, 0, QUIC_SEND_FLAG_FIN, NULL);

        if (QUIC_FAILED(status)) {
            WTF_LOG_WARN(sess->connection->context, "session",
                         "Failed to send FIN after CLOSE capsule: 0x%x", status);
        }
    }

    wtf_session_abort_streams(sess, WTF_WEBTRANSPORT_SESSION_GONE);
    wtf_session_retire(sess);

    if (sess->callback) {
        wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DISCONNECTED,
                                     .session = session,
                                     .user_context = sess->user_context,
                                     .disconnected = {.error_code = error_code, .reason = reason}};
        sess->callback(&event);
    }

    return result;
}

void wtf_session_cleanup_datagram_send_context(wtf_internal_send_context* send_ctx)
{
    wtf_session* session = NULL;
    if (send_ctx && send_ctx->owns_session_ref) {
        session = send_ctx->session;
        send_ctx->owns_session_ref = false;
        send_ctx->session = NULL;
    }

    wtf_internal_send_context_destroy(send_ctx);

    if (session) {
        wtf_session_release(session);
    }
}

static wtf_result_t wtf_session_send_datagram_internal(wtf_session* session,
                                                       const wtf_buffer_t* data,
                                                       uint32_t buffer_count,
                                                       void* operation_context,
                                                       bool copy_payload)
{
    wtf_result_t result = WTF_SUCCESS;
    wtf_internal_send_context* send_ctx = NULL;
    wtf_connection* conn = NULL;

    if (!session || !data || buffer_count == 0) {
        result = WTF_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if (buffer_count > WTF_MAX_SEND_BUFFERS) {
        result = WTF_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }

    if (session->destroyed || !session->connection || session->connection->destroyed) {
        result = WTF_ERROR_INVALID_STATE;
        goto cleanup;
    }

    size_t total_data_size = 0;
    for (uint32_t i = 0; i < buffer_count; i++) {
        if (data[i].data == NULL && data[i].length > 0) {
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup;
        }
        if (total_data_size > SIZE_MAX - data[i].length) {
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup;
        }
        total_data_size += data[i].length;
    }

    if (session->state != WTF_SESSION_CONNECTED) {
        result = WTF_ERROR_INVALID_STATE;
        goto cleanup;
    }

    conn = session->connection;
    if (!conn->peer_settings.h3_datagram_enabled) {
        result = WTF_ERROR_PROTOCOL_VIOLATION;
        goto cleanup;
    }

    if (!atomic_load_explicit(&conn->datagram_send_enabled, memory_order_acquire)) {
        result = WTF_ERROR_PROTOCOL_VIOLATION;
        goto cleanup;
    }

    uint64_t quarter_stream_id = session->id / 4;
    size_t header_size = wtf_varint_size(quarter_stream_id);
    if (header_size > SIZE_MAX - total_data_size) {
        result = WTF_ERROR_INVALID_PARAMETER;
        goto cleanup;
    }
    size_t total_size = header_size + total_data_size;

    uint32_t max_datagram_size = atomic_load_explicit(&conn->max_datagram_size,
                                                      memory_order_acquire);
    if (max_datagram_size == 0 || total_size > max_datagram_size) {
        result = WTF_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    if (header_size > WTF_INLINE_SEND_STORAGE) {
        result = WTF_ERROR_BUFFER_TOO_SMALL;
        goto cleanup;
    }

    send_ctx = calloc(1, sizeof(wtf_internal_send_context));
    if (!send_ctx) {
        result = WTF_ERROR_OUT_OF_MEMORY;
        goto cleanup;
    }

    uint32_t total_buffer_count = buffer_count + 1;
    if (total_buffer_count <= WTF_INLINE_SEND_BUFFERS) {
        send_ctx->buffers = send_ctx->inline_buffers;
        send_ctx->buffers_inline = true;
        memset(send_ctx->inline_buffers, 0, sizeof(send_ctx->inline_buffers));
    } else {
        send_ctx->buffers = calloc(total_buffer_count, sizeof(wtf_buffer_t));
        if (!send_ctx->buffers) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
    }

    uint8_t* header_buffer = send_ctx->inline_data;

    send_ctx->session = session;
    wtf_session_add_ref(session);
    send_ctx->owns_session_ref = true;
    send_ctx->internal_send = false;
    send_ctx->owns_buffer_data = copy_payload;
    send_ctx->app_buffer_offset = 1;
    send_ctx->operation_context = operation_context;
    send_ctx->count = total_buffer_count;

    send_ctx->buffers[0].data = header_buffer;
    send_ctx->buffers[0].length = (uint32_t)header_size;

    // Encode quarter stream ID into header buffer
    uint8_t* end_pos = wtf_varint_encode(quarter_stream_id, header_buffer);
    if ((size_t) (end_pos - header_buffer) != header_size) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup;
    }

    for (uint32_t i = 0; i < buffer_count; i++) {
        send_ctx->buffers[i + 1].length = data[i].length;

        if (data[i].length == 0) {
            send_ctx->buffers[i + 1].data = copy_payload ? NULL : data[i].data;
            continue;
        }

        if (!copy_payload) {
            send_ctx->buffers[i + 1].data = data[i].data;
            continue;
        }

        uint8_t* payload_copy = malloc(data[i].length);
        if (!payload_copy) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup;
        }
        memcpy(payload_copy, data[i].data, data[i].length);
        send_ctx->buffers[i + 1].data = payload_copy;
    }

    QUIC_STATUS status = conn->context->quic_api->DatagramSend(
        conn->quic_connection, (QUIC_BUFFER*)send_ctx->buffers, total_buffer_count,
        QUIC_SEND_FLAG_NONE, send_ctx);

    if (QUIC_SUCCEEDED(status)) {
        return WTF_SUCCESS;
    }

    result = wtf_quic_status_to_result(status);
    goto cleanup;

cleanup:
    if (send_ctx) {
        wtf_session_cleanup_datagram_send_context(send_ctx);
    }
    return result;
}

wtf_result_t wtf_session_send_datagram(wtf_session_t* session, const wtf_buffer_t* data,
                                       uint32_t buffer_count, void* operation_context)
{
    return wtf_session_send_datagram_internal((wtf_session*)session, data, buffer_count,
                                             operation_context, false);
}

wtf_result_t wtf_session_send_datagram_copy(wtf_session_t* session, const void* data,
                                            size_t length)
{
    if (!session || (!data && length > 0)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (length > UINT32_MAX) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_buffer_t buffer = {.length = (uint32_t)length, .data = (const uint8_t*)data};
    return wtf_session_send_datagram_internal((wtf_session*)session, &buffer, 1, NULL, true);
}

wtf_result_t wtf_session_create_stream(wtf_session_t* session, wtf_stream_type_t type,
                                       wtf_stream_t** stream)
{
    if (!session || !stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
    *stream = NULL;

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed || !sess->connection || sess->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (sess->state != WTF_SESSION_CONNECTED) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (!wtf_session_reserve_outgoing_stream(sess, type)) {
        WTF_LOG_WARN(sess->connection->context, "stream",
                     "Session %llu has reached stream limit %u", (unsigned long long)sess->id,
                     sess->max_streams);
        return WTF_ERROR_FLOW_CONTROL;
    }

    WTF_LOG_DEBUG(sess->connection->context, "stream",
                  "Creating %s WebTransport stream on session %llu",
                  type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional",
                  (unsigned long long)sess->id);

    wtf_stream* wt_stream = wtf_stream_create(sess, UINT64_MAX, type);
    if (!wt_stream) {
        wtf_session_release_outgoing_stream(sess, type);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    wtf_connection* conn = sess->connection;

    uint32_t stream_open_flags = QUIC_STREAM_OPEN_FLAG_NONE;
    if (type == WTF_STREAM_UNIDIRECTIONAL) {
        stream_open_flags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
    }

    HQUIC quic_stream;
    QUIC_STATUS status = conn->context->quic_api->StreamOpen(
        conn->quic_connection, stream_open_flags, wtf_upgraded_stream_callback, wt_stream,
        &quic_stream);

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(conn->context, "stream",
                      "StreamOpen failed for WebTransport %s stream on session %llu: 0x%x",
                      type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional",
                      (unsigned long long)sess->id, status);
        wtf_session_release_outgoing_stream(sess, type);
        wtf_stream_destroy(wt_stream);
        return wtf_quic_status_to_result(status);
    }

    wt_stream->quic_stream = quic_stream;
    wtf_stream_add_ref(wt_stream);

    wtf_result_t start_result = wtf_stream_start(wt_stream);
    if (start_result != WTF_SUCCESS) {
        WTF_LOG_ERROR(conn->context, "stream",
                      "Failed to start WebTransport stream with header: %s",
                      wtf_result_to_string(start_result));
        wtf_session_release_outgoing_stream(sess, type);
        wtf_stream_destroy(wt_stream);
        return start_result;
    }

    WTF_LOG_DEBUG(conn->context, "stream",
                  "WebTransport %s stream created and started on session %llu",
                  type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional",
                  (unsigned long long)sess->id);

    *stream = (wtf_stream_t*)wt_stream;
    return WTF_SUCCESS;
}

wtf_result_t wtf_session_drain(wtf_session_t* session)
{
    if (!session) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed || !sess->connection || sess->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (sess->state != WTF_SESSION_CONNECTED) {
        return WTF_ERROR_INVALID_STATE;
    }

    WTF_LOG_INFO(sess->connection->context, "session", "Draining session %llu",
                 (unsigned long long)sess->id);

    sess->state = WTF_SESSION_DRAINING;

    if (sess->callback) {
        wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                     .session = session,
                                     .user_context = sess->user_context};
        sess->callback(&event);
    }

    return wtf_session_send_capsule(sess, WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION, NULL, 0);
}

wtf_stream_t* wtf_session_find_stream_by_id(wtf_session_t* session, uint64_t stream_id)
{
    if (!session)
        return NULL;

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed) {
        return NULL;
    }

    mtx_lock(&sess->streams_mutex);

    stream_map_itr itr = stream_map_get(&sess->streams, stream_id);
    wtf_stream* stream = NULL;
    if (!stream_map_is_end(itr)) {
        stream = itr.data->val;
        if (stream->destroyed) {
            stream = NULL;
        } else {
            wtf_stream_add_ref(stream);
        }
    }

    mtx_unlock(&sess->streams_mutex);
    return (wtf_stream_t*)stream;
}

wtf_result_t wtf_session_get_peer_address(wtf_session_t* session, void* address_buffer,
                                          size_t* buffer_size)
{
    if (!session || !buffer_size) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed || !sess->connection || sess->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (*buffer_size < sizeof(sess->connection->peer_address)) {
        *buffer_size = sizeof(sess->connection->peer_address);
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }

    if (address_buffer) {
        memcpy(address_buffer, &sess->connection->peer_address,
               sizeof(sess->connection->peer_address));
    }
    *buffer_size = sizeof(sess->connection->peer_address);

    return WTF_SUCCESS;
}

uint32_t wtf_session_get_max_datagram_size(wtf_session_t* session)
{
    if (!session) {
        return 0;
    }

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed || !sess->connection || sess->connection->destroyed) {
        return 0;
    }

    size_t header_size = wtf_varint_size(sess->id / 4);
    if (!atomic_load_explicit(&sess->connection->datagram_send_enabled, memory_order_acquire)) {
        return 0;
    }

    uint32_t max_datagram_size = atomic_load_explicit(&sess->connection->max_datagram_size,
                                                      memory_order_acquire);
    if (max_datagram_size <= header_size) {
        return 0;
    }

    return (uint32_t)(max_datagram_size - header_size);
}

void wtf_session_set_callback(wtf_session_t* session, wtf_session_callback_t callback,
                              void* user_context)
{
    if (!session) {
        return;
    }

    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed) {
        return;
    }
    sess->callback = callback;
    sess->user_context = user_context;
}

void wtf_session_set_context(wtf_session_t* session, void* user_context)
{
    if (!session) {
        return;
    }
    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed) {
        return;
    }
    sess->user_context = user_context;
}

void* wtf_session_get_context(wtf_session_t* session)
{
    if (!session) {
        return NULL;
    }
    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed) {
        return NULL;
    }
    return sess->user_context;
}

wtf_session_state_t wtf_session_get_state(wtf_session_t* session)
{
    if (!session)
        return WTF_SESSION_CLOSED;
    wtf_session* sess = (wtf_session*)session;
    if (sess->destroyed) {
        return WTF_SESSION_CLOSED;
    }
    return sess->state;
}
