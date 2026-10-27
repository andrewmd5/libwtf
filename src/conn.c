#include "conn.h"

#include "client.h"
#include "datagram.h"
#include "http3.h"
#include "log.h"
#include "qpack.h"
#include "session.h"
#include "settings.h"
#include "stream.h"
#include "utils.h"

bool wtf_connection_associate_stream_with_session(wtf_connection* conn, wtf_http3_stream* h3_stream,
                                                  wtf_session* session)
{
    if (!conn || !h3_stream || !session)
        return false;

    uint64_t stream_id = h3_stream->id;
    uint64_t session_id = session->id;
    wtf_stream_type_t stream_type = WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)
        ? WTF_STREAM_UNIDIRECTIONAL
        : WTF_STREAM_BIDIRECTIONAL;

    mtx_lock(&session->streams_mutex);
    stream_map_itr existing_itr = stream_map_get(&session->streams, stream_id);
    if (!stream_map_is_end(existing_itr)) {
        mtx_unlock(&session->streams_mutex);
        WTF_LOG_TRACE(conn->context, "stream",
                      "Stream %llu already associated with session %llu",
                      (unsigned long long)stream_id, (unsigned long long)session_id);
        return true;
    }

    mtx_unlock(&session->streams_mutex);

    wtf_stream* wt_stream = wtf_stream_create(session, stream_id, stream_type);
    if (!wt_stream) {
        WTF_LOG_ERROR(conn->context, "stream",
                      "Failed to create WebTransport stream for stream %llu",
                      (unsigned long long)stream_id);
        return false;
    }

    if (session->callback) {
        wt_stream->callback = NULL;
        wt_stream->user_context = session->user_context;
    }

    mtx_lock(&session->streams_mutex);
    existing_itr = stream_map_get(&session->streams, stream_id);
    if (!stream_map_is_end(existing_itr)) {
        mtx_unlock(&session->streams_mutex);
        WTF_LOG_TRACE(conn->context, "stream",
                      "Stream %llu already associated with session %llu",
                      (unsigned long long)stream_id, (unsigned long long)session_id);
        wtf_stream_destroy(wt_stream);
        return true;
    }

    bool limit_reached = false;
    bool flow_control_violation = false;
    bool counted_incoming_stream = false;
    size_t active_streams = stream_map_size(&session->streams) + session->pending_stream_count;

    if (active_streams >= session->max_streams) {
        limit_reached = true;
    } else if (wtf_connection_uses_webtransport_flow_control(session->connection)) {
        uint64_t* count = stream_type == WTF_STREAM_BIDIRECTIONAL
            ? &session->incoming_streams_bidi
            : &session->incoming_streams_uni;
        uint64_t limit = stream_type == WTF_STREAM_BIDIRECTIONAL
            ? session->local_max_streams_bidi
            : session->local_max_streams_uni;
        if (*count >= limit) {
            limit_reached = true;
            flow_control_violation = true;
        } else {
            (*count)++;
            counted_incoming_stream = true;
        }
    } else {
        limit_reached = false;
    }

    if (limit_reached) {
        mtx_unlock(&session->streams_mutex);
        WTF_LOG_WARN(conn->context, "stream",
                     "Session %llu reached stream limit before associating stream %llu",
                     (unsigned long long)session_id, (unsigned long long)stream_id);
        wtf_stream_destroy(wt_stream);
        if (flow_control_violation) {
            wtf_session_fail_flow_control(session);
        }
        if (h3_stream->quic_stream) {
            conn->context->quic_api->StreamShutdown(
                h3_stream->quic_stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                flow_control_violation ? WTF_WEBTRANSPORT_FLOW_CONTROL_ERROR
                                       : WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED);
        }
        return false;
    }

    stream_map_itr itr = stream_map_insert(&session->streams, stream_id, wt_stream);
    if (stream_map_is_end(itr)) {
        if (counted_incoming_stream) {
            if (stream_type == WTF_STREAM_BIDIRECTIONAL && session->incoming_streams_bidi > 0) {
                session->incoming_streams_bidi--;
            } else if (stream_type == WTF_STREAM_UNIDIRECTIONAL
                       && session->incoming_streams_uni > 0) {
                session->incoming_streams_uni--;
            }
        }
        mtx_unlock(&session->streams_mutex);
        WTF_LOG_ERROR(conn->context, "stream", "Failed to add stream to map");
        wtf_stream_destroy(wt_stream);
        return false;
    }
    wtf_stream_add_ref(wt_stream);
    mtx_unlock(&session->streams_mutex);

    if (h3_stream->quic_stream) {
        wt_stream->quic_stream = h3_stream->quic_stream;

        bool is_connect_stream = (h3_stream->id == session->connect_stream->id);

        if (!is_connect_stream) {
            conn->context->quic_api->SetCallbackHandler(
                h3_stream->quic_stream, wtf_upgraded_stream_callback, wt_stream);
            wtf_stream_add_ref(wt_stream);
            h3_stream->quic_stream = NULL;
            h3_stream->callback_transferred = true;

            WTF_LOG_DEBUG(conn->context, "stream",
                          "Transferred QUIC handle and switched callback for "
                          "WebTransport stream %llu",
                          (unsigned long long)stream_id);
        } else {
            WTF_LOG_DEBUG(conn->context, "stream",
                          "Transferred QUIC handle from CONNECT stream %llu "
                          "(preserving wtf_stream_callback)",
                          (unsigned long long)stream_id);
        }
    }

    WTF_LOG_DEBUG(conn->context, "stream",
                  "Created and associated WebTransport stream %llu (%s) with session %llu",
                  (unsigned long long)stream_id,
                  stream_type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional",
                  (unsigned long long)session_id);

    if (session->callback) {
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_STREAM_OPENED,
            .session = (wtf_session_t*)session,
            .user_context = session->user_context,
            .stream_opened = {.stream = (wtf_stream_t*)wt_stream, .stream_type = stream_type}};
        session->callback(&event);
    }

    wtf_stream_release(wt_stream);
    return true;
}

bool wtf_connection_uses_webtransport_flow_control(const wtf_connection* conn)
{
    return conn && conn->webtransport_flow_control_enabled;
}

static wtf_connection* wtf_connection_create_common(wtf_context* context, HQUIC quic_connection,
                                                    wtf_endpoint_role_t role,
                                                    wtf_webtransport_draft_t requested_draft,
                                                    uint32_t max_sessions,
                                                    uint32_t max_streams_per_session,
                                                    uint64_t max_data_per_session)
{
    wtf_connection* conn = malloc(sizeof(wtf_connection));
    if (!conn) {
        return NULL;
    }

    memset(conn, 0, sizeof(*conn));
    uint64_t connection_id = 0;
    if (!wtf_random_uint64(&connection_id)) {
        free(conn);
        return NULL;
    }
    atomic_init(&conn->ref_count, 1);
    conn->id = connection_id;
    conn->quic_connection = quic_connection;
    conn->context = context;
    conn->role = role;
    conn->requested_webtransport_draft = requested_draft;
    conn->state = WTF_CONNECTION_STATE_HANDSHAKING;
    conn->max_sessions = max_sessions > 0 ? max_sessions : WTF_DEFAULT_MAX_SESSIONS;
    conn->max_streams_per_session = max_streams_per_session > 0
        ? max_streams_per_session
        : WTF_DEFAULT_MAX_STREAMS_PER_SESSION;
    conn->max_data_per_session = max_data_per_session > 0 ? max_data_per_session
                                                          : WTF_DEFAULT_MAX_DATA_PER_SESSION;
    atomic_init(&conn->datagram_send_enabled, false);
    atomic_init(&conn->max_datagram_size, 0);

    wtf_settings_init(&conn->local_settings);
    wtf_settings_init(&conn->peer_settings);
    conn->local_settings.h3_datagram_enabled = true;
    conn->local_settings.h3_datagram_rfc_enabled = true;
    conn->local_settings.h3_datagram_draft04_enabled = true;
    conn->local_settings.enable_connect_protocol = true;
    conn->local_settings.enable_webtransport = true;
    conn->local_settings.enable_webtransport_draft02 = true;
    conn->local_settings.enable_webtransport_draft07 = true;
    conn->local_settings.enable_webtransport_draft15 = true;
    conn->local_settings.webtransport_max_sessions = conn->max_sessions;
    conn->local_settings.wt_initial_max_streams_bidi = conn->max_streams_per_session;
    conn->local_settings.wt_initial_max_streams_uni
        = conn->local_settings.wt_initial_max_streams_bidi;
    conn->local_settings.wt_initial_max_data = conn->max_data_per_session;

    session_map_init(&conn->sessions);
    http3_stream_map_init(&conn->streams);

    if (mtx_init(&conn->streams_mutex, mtx_plain) != thrd_success) {
        session_map_cleanup(&conn->sessions);
        http3_stream_map_cleanup(&conn->streams);
        free(conn);
        return NULL;
    }

    if (mtx_init(&conn->sessions_mutex, mtx_plain) != thrd_success) {
        mtx_destroy(&conn->streams_mutex);
        session_map_cleanup(&conn->sessions);
        http3_stream_map_cleanup(&conn->streams);
        free(conn);
        return NULL;
    }

    if (!wtf_qpack_preinit(&conn->qpack, WTF_QPACK_DYNAMIC_TABLE_SIZE,
                           WTF_QPACK_MAX_BLOCKED_STREAMS)) {
        mtx_destroy(&conn->sessions_mutex);
        mtx_destroy(&conn->streams_mutex);
        session_map_cleanup(&conn->sessions);
        http3_stream_map_cleanup(&conn->streams);
        free(conn);
        return NULL;
    }

    if (quic_connection && context && context->quic_api) {
        uint32_t addr_size = sizeof(conn->peer_address);
        context->quic_api->GetParam(quic_connection, QUIC_PARAM_CONN_REMOTE_ADDRESS, &addr_size,
                                    &conn->peer_address);
    }
    return conn;
}

wtf_connection* wtf_connection_create(wtf_server* server, HQUIC quic_connection)
{
    if (!server || !server->context) {
        return NULL;
    }

    wtf_connection* conn = wtf_connection_create_common(
        server->context, quic_connection, WTF_ENDPOINT_SERVER, server->config.draft,
        server->config.max_sessions_per_connection, server->config.max_streams_per_session,
        server->config.max_data_per_session);
    if (!conn) {
        return NULL;
    }

    conn->server = server;
    conn->connection_validator = server->config.connection_validator;
    conn->session_callback = server->config.session_callback;
    conn->user_context = server->config.user_context;
    return conn;
}

wtf_connection* wtf_connection_create_client(wtf_client* client, HQUIC quic_connection)
{
    if (!client || !client->context) {
        return NULL;
    }

    uint32_t max_sessions = client->config.allow_pooling
        ? (client->config.max_sessions_per_connection > 0
               ? client->config.max_sessions_per_connection
               : WTF_DEFAULT_MAX_SESSIONS)
        : 1;
    wtf_connection* conn = wtf_connection_create_common(
        client->context, quic_connection, WTF_ENDPOINT_CLIENT, client->config.draft, max_sessions,
        client->config.max_streams_per_session, client->config.max_data_per_session);
    if (!conn) {
        return NULL;
    }

    conn->client = client;
    conn->session_callback = client->config.session_callback;
    conn->user_context = client->config.user_context;
    return conn;
}

void wtf_connection_add_ref(wtf_connection* conn)
{
    if (!conn) {
        return;
    }
    atomic_fetch_add_explicit(&conn->ref_count, 1, memory_order_relaxed);
}

static void wtf_connection_dispose(wtf_connection* conn)
{
    if (!conn) {
        return;
    }

    if (conn->destroyed) {
        return;
    }
    conn->destroyed = true;

    mtx_lock(&conn->sessions_mutex);
    for (session_map_itr itr = session_map_first(&conn->sessions); !session_map_is_end(itr);
         itr = session_map_next(itr)) {
        wtf_session_destroy(itr.data->val);
    }
    session_map_cleanup(&conn->sessions);

    wtf_session* closed_session = conn->closed_sessions;
    conn->closed_sessions = NULL;
    while (closed_session) {
        wtf_session* next = closed_session->next_closed;
        closed_session->next_closed = NULL;
        wtf_session_destroy(closed_session);
        closed_session = next;
    }
    mtx_unlock(&conn->sessions_mutex);

    mtx_lock(&conn->streams_mutex);
    for (http3_stream_map_itr itr = http3_stream_map_first(&conn->streams);
         !http3_stream_map_is_end(itr); itr = http3_stream_map_next(itr)) {
        wtf_http3_stream_destroy(itr.data->val);
    }
    http3_stream_map_cleanup(&conn->streams);
    mtx_unlock(&conn->streams_mutex);

    wtf_qpack_cleanup(&conn->qpack);
}

void wtf_connection_release(wtf_connection* conn)
{
    if (!conn) {
        return;
    }

    if (atomic_fetch_sub_explicit(&conn->ref_count, 1, memory_order_acq_rel) != 1) {
        return;
    }

    wtf_connection_dispose(conn);
    mtx_destroy(&conn->sessions_mutex);
    mtx_destroy(&conn->streams_mutex);
    free(conn);
}

void wtf_connection_destroy(wtf_connection* conn)
{
    if (!conn) {
        return;
    }

    wtf_connection_dispose(conn);
    wtf_connection_release(conn);
}

QUIC_STATUS QUIC_API wtf_connection_callback(HQUIC Connection, void* Context,
                                             QUIC_CONNECTION_EVENT* Event)
{
    wtf_connection* conn = (wtf_connection*)Context;

    if (!conn || !conn->context) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_CONNECTION_EVENT_CONNECTED: {
            WTF_LOG_INFO(conn->context, "conn",
                         "Connection established - starting HTTP/3 handshake");

            if (Event->CONNECTED.NegotiatedAlpnLength > 0 && Event->CONNECTED.NegotiatedAlpn) {
                char alpn_str[256];
                size_t copy_len = min(Event->CONNECTED.NegotiatedAlpnLength, sizeof(alpn_str) - 1);
                memcpy(alpn_str, Event->CONNECTED.NegotiatedAlpn, copy_len);
                alpn_str[copy_len] = '\0';
                WTF_LOG_TRACE(conn->context, "conn", "Negotiated ALPN: %s", alpn_str);
            }

            if (Event->CONNECTED.SessionResumed) {
                WTF_LOG_TRACE(conn->context, "conn", "Session resumed");
            }

            if (!wtf_http3_create_control_stream(conn)) {
                WTF_LOG_ERROR(conn->context, "conn", "Failed to create control stream");
                conn->context->quic_api->ConnectionShutdown(
                    Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, WTF_H3_INTERNAL_ERROR);
                return QUIC_STATUS_SUCCESS;
            }

            if (!wtf_http3_create_qpack_streams(conn)) {
                WTF_LOG_ERROR(conn->context, "conn", "Failed to create QPACK streams");
                conn->context->quic_api->ConnectionShutdown(
                    Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, WTF_H3_INTERNAL_ERROR);
                return QUIC_STATUS_SUCCESS;
            }

            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
            WTF_LOG_DEBUG(conn->context, "conn", "Peer started new stream");

            wtf_http3_stream* stream = wtf_http3_stream_create(
                conn, Event->PEER_STREAM_STARTED.Stream, UINT64_MAX);
            if (!stream) {
                WTF_LOG_ERROR(conn->context, "conn",
                              "Failed to create peer stream context");
                conn->context->quic_api->StreamShutdown(
                    Event->PEER_STREAM_STARTED.Stream,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                    WTF_H3_INTERNAL_ERROR);
                return QUIC_STATUS_SUCCESS;
            }

            conn->context->quic_api->SetCallbackHandler(Event->PEER_STREAM_STARTED.Stream,
                                                                wtf_http3_stream_callback, stream);
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {
            const uint8_t* data = Event->DATAGRAM_RECEIVED.Buffer->Buffer;
            uint32_t length = Event->DATAGRAM_RECEIVED.Buffer->Length;

            wtf_datagram_process(conn, data, length, true);
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {
            if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext) {
                wtf_internal_send_context* send_ctx
                    = (wtf_internal_send_context*)Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext;
                if (send_ctx) {
                    wtf_session* session = send_ctx->session;

                    if (session && session->callback) {
                        uint32_t app_offset = send_ctx->app_buffer_offset;
                        if (app_offset > send_ctx->count) {
                            app_offset = send_ctx->count;
                        }
                        wtf_session_event_t event = {
                            .type = WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE,
                            .session = session,
                            .user_context = session->user_context,
                            .datagram_send_state_changed = {
                                .buffers = send_ctx->count > app_offset
                                    ? &send_ctx->buffers[app_offset]
                                    : NULL,
                                .buffer_count = send_ctx->count - app_offset,
                                .state = (wtf_datagram_send_state_t)
                                             Event->DATAGRAM_SEND_STATE_CHANGED.State,
                                .operation_context = send_ctx->operation_context}};
                        session->callback(&event);
                    }

                    if (QUIC_DATAGRAM_SEND_STATE_IS_FINAL(
                            Event->DATAGRAM_SEND_STATE_CHANGED.State)) {
                        wtf_session_cleanup_datagram_send_context(send_ctx);
                    }
                }
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {
            if (conn->role == WTF_ENDPOINT_CLIENT && conn->client
                && wtf_client_has_pinned_server_certificate(conn->client)) {
                const QUIC_BUFFER* certificate
                    = (const QUIC_BUFFER*)Event->PEER_CERTIFICATE_RECEIVED.Certificate;
                if (!wtf_client_validate_pinned_server_certificate(conn->client, certificate)) {
                    WTF_LOG_ERROR(conn->context, "client",
                                  "Server certificate did not match pinned certificate");
                    return QUIC_STATUS_INTERNAL_ERROR;
                }
            }
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
        case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
            const bool transport_shutdown =
                Event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT;
            uint64_t error_code = Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
            QUIC_STATUS status = QUIC_STATUS_SUCCESS;
            const char* source = "peer application";
            if (transport_shutdown) {
                error_code = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.ErrorCode;
                status = Event->SHUTDOWN_INITIATED_BY_TRANSPORT.Status;
                source = "transport";
            }
            WTF_LOG_INFO(conn->context, "conn",
                         "Connection shutdown initiated: source=%s, status=0x%x, error=0x%llx",
                         source, (unsigned int)status, (unsigned long long)error_code);

            conn->state = WTF_CONNECTION_STATE_CLOSING;

            size_t session_count = 0;
            wtf_session** sessions = NULL;

            mtx_lock(&conn->sessions_mutex);
            session_count = session_map_size(&conn->sessions);
            if (session_count > 0) {
                sessions = malloc(sizeof(wtf_session*) * session_count);
                if (sessions) {
                    size_t session_index = 0;
                    for (session_map_itr itr = session_map_first(&conn->sessions);
                         !session_map_is_end(itr) && session_index < session_count;
                         itr = session_map_next(itr)) {
                        wtf_session* session = itr.data->val;
                        wtf_session_add_ref(session);
                        sessions[session_index++] = session;
                    }
                    session_count = session_index;
                } else {
                    session_count = 0;
                }
            }
            mtx_unlock(&conn->sessions_mutex);

            for (size_t i = 0; i < session_count; i++) {
                wtf_session* session = sessions[i];
                if (session->state != WTF_SESSION_CONNECTED) {
                    continue;
                }
                session->state = WTF_SESSION_CLOSED;
                if (!session->callback) {
                    continue;
                }
                wtf_session_event_t event = {
                    .type = WTF_SESSION_EVENT_DISCONNECTED,
                    .session = (wtf_session_t*)session,
                    .user_context = session->user_context,
                    .disconnected = {.error_code = (uint32_t)error_code,
                                     .reason = "Connection shutdown"}};
                session->callback(&event);
            }

            for (size_t i = 0; i < session_count; i++) {
                wtf_session_release(sessions[i]);
            }
            free(sessions);

            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
            WTF_LOG_INFO(conn->context, "conn", "Connection shutdown complete");

            conn->state = WTF_CONNECTION_STATE_CLOSED;

            char reason[512] = {0};
            uint32_t reason_length = sizeof(reason);
            if (conn->quic_connection &&
                QUIC_SUCCEEDED(conn->context->quic_api->GetParam(
                    conn->quic_connection, QUIC_PARAM_CONN_CLOSE_REASON_PHRASE,
                    &reason_length, reason))) {
                reason[sizeof(reason) - 1] = '\0';
                WTF_LOG_INFO(conn->context, "conn", "Connection shutdown reason: %s", reason);
            }
            if (conn->quic_connection && !Event->SHUTDOWN_COMPLETE.AppCloseInProgress) {
                conn->context->quic_api->ConnectionClose(conn->quic_connection);
            }
            conn->quic_connection = NULL;

            if (conn->role == WTF_ENDPOINT_SERVER && conn->server) {
                wtf_server* server = conn->server;
                bool release_map_ref = false;
                mtx_lock(&server->connections_mutex);
                connection_map_itr itr = connection_map_get(&server->connections, conn->id);
                if (!connection_map_is_end(itr)) {
                    connection_map_erase(&server->connections, conn->id);
                    release_map_ref = true;
                }
                cnd_broadcast(&server->connections_drained);
                mtx_unlock(&server->connections_mutex);

                if (release_map_ref) {
                    wtf_connection_release(conn);
                }

                wtf_connection_destroy(conn);
            } else if (conn->role == WTF_ENDPOINT_CLIENT && conn->client) {
                wtf_client* client = conn->client;
                mtx_lock(&client->mutex);
                client->quic_connection = NULL;
                client->state = WTF_CLIENT_CLOSED;
                cnd_broadcast(&client->connected);
                mtx_unlock(&client->mutex);
                wtf_client_fail_pending_sessions(client, WTF_ERROR_CONNECTION_ABORTED,
                                                 "Connection shutdown");
                wtf_connection_release(conn);
            }
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED: {
            WTF_LOG_INFO(conn->context, "conn", "Ideal processor changed to %d",
                         Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor);
            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {
            bool send_enabled = Event->DATAGRAM_STATE_CHANGED.SendEnabled ? true : false;
            uint32_t max_send_length = send_enabled ? Event->DATAGRAM_STATE_CHANGED.MaxSendLength
                                                    : 0;
            atomic_store_explicit(&conn->datagram_send_enabled, send_enabled,
                                  memory_order_release);
            atomic_store_explicit(&conn->max_datagram_size, max_send_length,
                                  memory_order_release);
            WTF_LOG_DEBUG(conn->context, "datagram",
                          "Datagram send state changed: enabled=%d max_send_length=%u",
                          Event->DATAGRAM_STATE_CHANGED.SendEnabled,
                          Event->DATAGRAM_STATE_CHANGED.MaxSendLength);
            return QUIC_STATUS_SUCCESS;
        }

#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        case QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED: {
            conn->reliable_reset_negotiation_complete = true;
            conn->reliable_reset_negotiated
                = Event->RELIABLE_RESET_NEGOTIATED.IsNegotiated ? true : false;
            WTF_LOG_DEBUG(conn->context, "conn", "Reliable reset negotiated: %s",
                          conn->reliable_reset_negotiated ? "yes" : "no");

            if (!conn->reliable_reset_negotiated
                && conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_15) {
                WTF_LOG_ERROR(conn->context, "conn",
                              "Draft-15 WebTransport selected without reliable reset");
                conn->context->quic_api->ConnectionShutdown(
                    conn->quic_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTF_WEBTRANSPORT_REQUIREMENTS_NOT_MET);
            }
            return QUIC_STATUS_SUCCESS;
        }
#endif

        case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED: {
            WTF_LOG_DEBUG(conn->context, "conn", "Resumption ticket received");

            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE: {
            if (!wtf_connection_uses_webtransport_flow_control(conn)) {
                return QUIC_STATUS_SUCCESS;
            }

            uint64_t uni_available = Event->STREAMS_AVAILABLE.UnidirectionalCount;
            uint64_t bidi_available = Event->STREAMS_AVAILABLE.BidirectionalCount;

            size_t session_count = 0;
            wtf_session** sessions = NULL;
            mtx_lock(&conn->sessions_mutex);
            session_count = session_map_size(&conn->sessions);
            if (session_count > 0) {
                sessions = malloc(sizeof(wtf_session*) * session_count);
                if (sessions) {
                    size_t session_index = 0;
                    for (session_map_itr itr = session_map_first(&conn->sessions);
                         !session_map_is_end(itr) && session_index < session_count;
                         itr = session_map_next(itr)) {
                        wtf_session_add_ref(itr.data->val);
                        sessions[session_index++] = itr.data->val;
                    }
                    session_count = session_index;
                } else {
                    session_count = 0;
                }
            }
            mtx_unlock(&conn->sessions_mutex);

            for (size_t i = 0; i < session_count; i++) {
                wtf_session* session = sessions[i];
                mtx_lock(&session->streams_mutex);
                uint64_t uni_limit = session->outgoing_streams_uni + uni_available;
                if (uni_limit > session->remote_max_streams_uni) {
                    session->remote_max_streams_uni = uni_limit;
                }
                uint64_t bidi_limit = session->outgoing_streams_bidi + bidi_available;
                if (bidi_limit > session->remote_max_streams_bidi) {
                    session->remote_max_streams_bidi = bidi_limit;
                }
                mtx_unlock(&session->streams_mutex);
                wtf_session_release(session);
            }
            free(sessions);
            return QUIC_STATUS_SUCCESS;
        }

        default:
            WTF_LOG_DEBUG(conn->context, "conn", "Unhandled connection event: %d",
                          Event->Type);
            return QUIC_STATUS_SUCCESS;
    }
}

wtf_session* wtf_connection_find_session(wtf_connection* conn, uint64_t session_id)
{
    if (!conn || conn->destroyed)
        return NULL;

    mtx_lock(&conn->sessions_mutex);

    session_map_itr itr = session_map_get(&conn->sessions, session_id);
    wtf_session* session = NULL;
    if (!session_map_is_end(itr)) {
        session = itr.data->val;
        if (session->destroyed) {
            session = NULL;
        } else {
            wtf_session_add_ref(session);
        }
    }

    mtx_unlock(&conn->sessions_mutex);
    return session;
}
