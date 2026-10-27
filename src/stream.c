#include "stream.h"

#include "log.h"
#include "session.h"
#include "utils.h"
#include "varint.h"

wtf_stream* wtf_stream_create(wtf_session* session, uint64_t stream_id, wtf_stream_type_t type)
{
    if (!session) {
        return NULL;
    }

    wtf_stream* stream = malloc(sizeof(wtf_stream));
    if (!stream) {
        return NULL;
    }

    memset(stream, 0, sizeof(*stream));
    stream->stream_id = stream_id;
    stream->session = session;
    stream->type = type;
    stream->state = WTF_INTERNAL_STREAM_STATE_IDLE;
    stream->priority = 0;
    stream->receive_enabled = true;
    atomic_init(&stream->ref_count, 1);

    if (mtx_init(&stream->mutex, mtx_plain) != thrd_success) {
        free(stream);
        return NULL;
    }

    wtf_session_add_ref(session);
    return stream;
}

void wtf_stream_add_ref(wtf_stream* stream)
{
    if (!stream) {
        return;
    }
    atomic_fetch_add_explicit(&stream->ref_count, 1, memory_order_relaxed);
}

static void wtf_stream_dispose(wtf_stream* stream)
{
    if (!stream) {
        return;
    }

    if (stream->destroyed) {
        return;
    }
    stream->destroyed = true;

    if (stream->quic_stream && stream->session && stream->session->connection
        && stream->session->connection->context) {
        stream->session->connection->context->quic_api->StreamClose(stream->quic_stream);
        stream->quic_stream = NULL;
    }
}

void wtf_stream_release(wtf_stream* stream)
{
    if (!stream) {
        return;
    }

    if (atomic_fetch_sub_explicit(&stream->ref_count, 1, memory_order_acq_rel) != 1) {
        return;
    }

    wtf_stream_dispose(stream);
    wtf_session* session = stream->session;
    stream->session = NULL;
    mtx_destroy(&stream->mutex);
    free(stream);
    wtf_session_release(session);
}

void wtf_stream_destroy(wtf_stream* stream)
{
    if (!stream) {
        return;
    }

    wtf_stream_dispose(stream);
    wtf_stream_release(stream);
}

void wtf_stream_ref(wtf_stream_t* stream)
{
    wtf_stream_add_ref((wtf_stream*)stream);
}

void wtf_stream_unref(wtf_stream_t* stream)
{
    wtf_stream_release((wtf_stream*)stream);
}

static wtf_result_t wtf_stream_encode_header(wtf_stream* stream, uint8_t* header,
                                             size_t header_size, size_t* header_length)
{
    uint8_t* current_pos = header;
    uint8_t* header_end = header + header_size;

    if (stream->type == WTF_STREAM_UNIDIRECTIONAL) {
        current_pos = wtf_varint_encode(WTF_STREAM_TYPE_UNI_WEBTRANSPORT_STREAM, current_pos);
        if (current_pos > header_end) {
            return WTF_ERROR_BUFFER_TOO_SMALL;
        }
        current_pos = wtf_varint_encode(stream->session->id, current_pos);
        if (current_pos > header_end) {
            return WTF_ERROR_BUFFER_TOO_SMALL;
        }
    } else {
        current_pos = wtf_varint_encode(WTF_FRAME_BIDIR_WEBTRANSPORT_STREAM, current_pos);
        if (current_pos > header_end) {
            return WTF_ERROR_BUFFER_TOO_SMALL;
        }
        current_pos = wtf_varint_encode(stream->session->id, current_pos);
        if (current_pos > header_end) {
            return WTF_ERROR_BUFFER_TOO_SMALL;
        }
    }

    *header_length = current_pos - header;
    return WTF_SUCCESS;
}

static wtf_result_t wtf_stream_send_header(wtf_stream* stream, HQUIC Stream, QUIC_SEND_FLAGS flags)
{
    uint8_t header[32];
    size_t header_length = 0;

    wtf_result_t encode_result = wtf_stream_encode_header(
        stream, header, sizeof(header), &header_length);
    if (encode_result != WTF_SUCCESS) {
        return encode_result;
    }

    if (header_length == 0) {
        return WTF_SUCCESS;
    }

    wtf_internal_send_context* send_ctx = calloc(1, sizeof(wtf_internal_send_context));
    if (!send_ctx) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    memcpy(send_ctx->inline_data, header, header_length);

    send_ctx->buffers = send_ctx->inline_buffers;
    send_ctx->count = 1;
    send_ctx->session = stream->session;
    send_ctx->internal_send = true;
    send_ctx->owns_buffer_data = false;
    send_ctx->buffers_inline = true;
    send_ctx->app_buffer_offset = 0;
    send_ctx->operation_context = NULL;
    send_ctx->inline_buffers[0].data = send_ctx->inline_data;
    send_ctx->inline_buffers[0].length = (uint32_t)header_length;

    wtf_connection* conn = stream->session->connection;
    QUIC_STATUS status = conn->context->quic_api->StreamSend(
        Stream, (QUIC_BUFFER*)send_ctx->inline_buffers, 1, flags, send_ctx);

    if (QUIC_SUCCEEDED(status)) {
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        if (conn->reliable_reset_negotiated) {
            const uint64_t reliable_offset = header_length;
            status = conn->context->quic_api->SetParam(
                Stream, QUIC_PARAM_STREAM_RELIABLE_OFFSET,
                sizeof(reliable_offset), &reliable_offset);
            if (QUIC_FAILED(status)) {
                WTF_LOG_ERROR(conn->context, "webtransport",
                              "Failed to protect WebTransport header: 0x%x", status);
                return wtf_quic_status_to_result(status);
            }
        }
#endif
        WTF_LOG_TRACE(conn->context, "webtransport", "WebTransport stream %llu header sent",
                      (unsigned long long)stream->stream_id);
        return WTF_SUCCESS;
    }

    WTF_LOG_ERROR(conn->context, "webtransport",
                  "Failed to send WebTransport stream header: 0x%x", status);

    free(send_ctx);
    return wtf_quic_status_to_result(status);
}

wtf_result_t wtf_stream_start(wtf_stream* stream)
{
    if (!stream || !stream->quic_stream || !stream->session || !stream->session->connection) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    return wtf_stream_send_header(stream, stream->quic_stream, QUIC_SEND_FLAG_START);
}

static bool wtf_stream_update_session_map(wtf_stream* stream, uint64_t stream_id)
{
    mtx_lock(&stream->session->streams_mutex);

    if (stream->session->pending_stream_count > 0) {
        stream->session->pending_stream_count--;
    }

    stream_map_itr itr = stream_map_insert(&stream->session->streams, stream_id, stream);
    bool success = !stream_map_is_end(itr);
    if (success) {
        wtf_stream_add_ref(stream);
    }

    mtx_unlock(&stream->session->streams_mutex);
    return success;
}

static void wtf_stream_notify_opened(wtf_stream* stream)
{
    if (!stream->session->callback) {
        return;
    }

    wtf_session_event_t event = {
        .type = WTF_SESSION_EVENT_STREAM_OPENED,
        .session = stream->session,
        .user_context = stream->session->user_context,
        .stream_opened = {.stream = (wtf_stream_t*)stream, .stream_type = stream->type}};

    stream->session->callback(&event);
}

static void wtf_stream_handle_reset(wtf_stream* stream, QUIC_UINT62 error_code)
{
    if (!stream) {
        return;
    }

    mtx_lock(&stream->mutex);
    stream->state = WTF_INTERNAL_STREAM_STATE_RESET;
    mtx_unlock(&stream->mutex);

    if (stream->callback) {
        wtf_stream_event_t event = {
            .type = WTF_STREAM_EVENT_ABORTED,
            .stream = (wtf_stream_t*)stream,
            .user_context = stream->user_context,
            .aborted = {.error_code = wtf_map_h3_error_to_webtransport(error_code)}};
        stream->callback(&event);
    }
}

static bool wtf_stream_should_receive(wtf_stream* stream)
{
    mtx_lock(&stream->mutex);
    bool should_receive = stream->receive_enabled
        && stream->state != WTF_INTERNAL_STREAM_STATE_CLOSED
        && stream->state != WTF_INTERNAL_STREAM_STATE_RESET;
    mtx_unlock(&stream->mutex);
    return should_receive;
}

void wtf_stream_deliver_peer_closed(wtf_stream* stream)
{
    if (!stream) {
        return;
    }

    bool should_notify = false;

    mtx_lock(&stream->mutex);
    if (!stream->peer_closed_notified) {
        stream->peer_closed_notified = true;
        if (stream->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
            stream->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
        } else if (stream->state != WTF_INTERNAL_STREAM_STATE_CLOSED
                   && stream->state != WTF_INTERNAL_STREAM_STATE_RESET) {
            stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
        }
        should_notify = true;
    }
    mtx_unlock(&stream->mutex);

    if (should_notify && stream->callback) {
        wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_PEER_CLOSED,
                                    .stream = (wtf_stream_t*)stream,
                                    .user_context = stream->user_context};
        stream->callback(&event);
    }
}

bool wtf_stream_deliver_received(wtf_stream* stream, const wtf_buffer_t* buffers,
                                 uint32_t buffer_count, uint64_t total_length, bool peer_fin)
{
    if (!stream) {
        return false;
    }

    if (total_length > 0) {
        if (!buffers || buffer_count == 0) {
            return false;
        }

        if (!wtf_stream_should_receive(stream)) {
            if (peer_fin) {
                wtf_stream_deliver_peer_closed(stream);
            }
            return true;
        }

        if (!wtf_session_accept_incoming_data(stream->session, total_length)) {
            wtf_session_fail_flow_control(stream->session);
            return true;
        }

        if (stream->callback) {
            wtf_stream_event_t event = {
                .type = WTF_STREAM_EVENT_DATA_RECEIVED,
                .stream = (wtf_stream_t*)stream,
                .user_context = stream->user_context,
                .data_received = {.buffers = buffers, .buffer_count = buffer_count}};
            stream->callback(&event);
        }
    }

    if (peer_fin) {
        wtf_stream_deliver_peer_closed(stream);
    }

    return true;
}

static void wtf_stream_cleanup_send_context(wtf_stream* stream, wtf_internal_send_context* send_ctx,
                                            bool cancelled)
{
    if (!send_ctx) {
        return;
    }

    if (send_ctx->flow_control_length > 0) {
        wtf_session_release_outgoing_data(send_ctx->session, send_ctx->flow_control_length);
        send_ctx->flow_control_length = 0;
    }

    uint32_t app_offset = send_ctx->app_buffer_offset;
    if (app_offset > send_ctx->count) {
        app_offset = send_ctx->count;
    }

    if (!send_ctx->internal_send && stream->callback) {
        wtf_stream_event_t event = {
            .type = WTF_STREAM_EVENT_SEND_COMPLETE,
            .stream = (wtf_stream_t*)stream,
            .user_context = stream->user_context,
            .send_complete = {.buffers = send_ctx->buffers + app_offset,
                              .buffer_count = send_ctx->count - app_offset,
                              .cancelled = cancelled,
                              .operation_context = send_ctx->operation_context}};
        stream->callback(&event);
    }

    wtf_internal_send_context_destroy(send_ctx);
}

static QUIC_STATUS wtf_handle_stream_start_complete(wtf_stream* stream, HQUIC Stream,
                                                    QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->session->connection;

    WTF_LOG_DEBUG(conn->context, "webtransport",
                  "WebTransport stream start complete, status=0x%x", Event->START_COMPLETE.Status);

    if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
        WTF_LOG_ERROR(conn->context, "webtransport",
                      "WebTransport stream start failed: 0x%x", Event->START_COMPLETE.Status);
        wtf_session_release_outgoing_stream(stream->session, stream->type);
        return QUIC_STATUS_SUCCESS;
    }

    uint64_t stream_id = Event->START_COMPLETE.ID;

    mtx_lock(&stream->mutex);
    stream->stream_id = stream_id;
    stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
    mtx_unlock(&stream->mutex);

    if (!wtf_stream_update_session_map(stream, stream_id)) {
        WTF_LOG_ERROR(conn->context, "webtransport",
                      "Failed to add WebTransport stream to session map");
        conn->context->quic_api->StreamShutdown(
            Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
    }

    WTF_LOG_DEBUG(conn->context, "webtransport", "WebTransport stream %llu (%s) ready",
                  (unsigned long long)stream_id,
                  stream->type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional");

    wtf_stream_notify_opened(stream);
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_receive(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->session->connection;

    WTF_LOG_DEBUG(conn->context, "webtransport",
                  "WebTransport stream data received on stream %llu",
                  (unsigned long long)stream->stream_id);

    bool fin = (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;

    uint64_t total_length = 0;
    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
        if (total_length > UINT64_MAX - Event->RECEIVE.Buffers[i].Length) {
            wtf_session_fail_flow_control(stream->session);
            return QUIC_STATUS_SUCCESS;
        }
        total_length += Event->RECEIVE.Buffers[i].Length;
    }

    wtf_stream_deliver_received(stream, (const wtf_buffer_t*)Event->RECEIVE.Buffers,
                                Event->RECEIVE.BufferCount, total_length, fin);

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_send_complete(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    WTF_LOG_DEBUG(stream->session->connection->context, "webtransport",
                  "WebTransport stream send complete on stream %llu",
                  (unsigned long long)stream->stream_id);

    wtf_internal_send_context* send_ctx
        = (wtf_internal_send_context*)Event->SEND_COMPLETE.ClientContext;
    if (send_ctx) {
        wtf_stream_cleanup_send_context(stream, send_ctx, Event->SEND_COMPLETE.Canceled);
    }

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_peer_shutdown(wtf_stream* stream)
{
    WTF_LOG_DEBUG(stream->session->connection->context, "webtransport",
                  "WebTransport stream peer send shutdown on stream %llu",
                  (unsigned long long)stream->stream_id);

    wtf_stream_deliver_peer_closed(stream);

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_peer_aborted(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    QUIC_UINT62 error_code = Event->PEER_SEND_ABORTED.ErrorCode;

    WTF_LOG_DEBUG(stream->session->connection->context, "webtransport",
                  "WebTransport stream peer send aborted on stream %llu: 0x%x",
                  (unsigned long long)stream->stream_id, error_code);

    wtf_stream_handle_reset(stream, error_code);
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_shutdown_complete(wtf_stream* stream)
{
    WTF_LOG_DEBUG(stream->session->connection->context, "webtransport",
                  "WebTransport stream shutdown complete on stream %llu",
                  (unsigned long long)stream->stream_id);

    if (stream->callback) {
        wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_CLOSED,
                                    .stream = (wtf_stream_t*)stream,
                                    .user_context = stream->user_context};
        stream->callback(&event);
    }

    bool release_map_ref = false;
    bool peer_initiated_stream = stream->session->connection->role == WTF_ENDPOINT_SERVER
        ? WTF_STREAM_IS_CLIENT_INITIATED(stream->stream_id)
        : !WTF_STREAM_IS_CLIENT_INITIATED(stream->stream_id);
    wtf_stream_type_t stream_type = stream->type;
    mtx_lock(&stream->session->streams_mutex);
    if (!stream->session->destroyed) {
        stream_map_itr itr = stream_map_get(&stream->session->streams, stream->stream_id);
        if (!stream_map_is_end(itr)) {
            stream_map_erase(&stream->session->streams, stream->stream_id);
            release_map_ref = true;
        }
    }
    mtx_unlock(&stream->session->streams_mutex);

    if (release_map_ref && peer_initiated_stream) {
        wtf_session_replenish_local_stream_credit(stream->session, stream_type);
    }

    if (release_map_ref) {
        wtf_stream_release(stream);
    }
    wtf_stream_destroy(stream);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API wtf_upgraded_stream_callback(HQUIC Stream, void* Context,
                                                  QUIC_STREAM_EVENT* Event)
{
    wtf_stream* wt_stream = (wtf_stream*)Context;

    if (!wt_stream || !wt_stream->session || !wt_stream->session->connection
        || !wt_stream->session->connection->context) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            return wtf_handle_stream_start_complete(wt_stream, Stream, Event);

        case QUIC_STREAM_EVENT_RECEIVE:
            return wtf_handle_stream_receive(wt_stream, Event);

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            return wtf_handle_stream_send_complete(wt_stream, Event);

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
            return wtf_handle_stream_peer_shutdown(wt_stream);

        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
            return wtf_handle_stream_peer_aborted(wt_stream, Event);

        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            WTF_LOG_DEBUG(wt_stream->session->connection->context, "webtransport",
                          "WebTransport stream send shutdown complete on stream %llu",
                          (unsigned long long)wt_stream->stream_id);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            return wtf_handle_stream_shutdown_complete(wt_stream);

        default:
            WTF_LOG_DEBUG(wt_stream->session->connection->context, "webtransport",
                          "Unhandled WebTransport stream event: %d", Event->Type);
            return QUIC_STATUS_SUCCESS;
    }
}

void wtf_stream_set_context(wtf_stream_t* stream, void* user_context)
{
    if (!stream) {
        return;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return;
    }
    strm->user_context = user_context;
}

void* wtf_stream_get_context(wtf_stream_t* stream)
{
    if (!stream) {
        return NULL;
    }
    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return NULL;
    }
    return strm->user_context;
}


void wtf_stream_set_callback(wtf_stream_t* stream, wtf_stream_callback_t callback)
{
    if (!stream) {
        return;
    }
    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return;
    }
    strm->callback = callback;
}

wtf_result_t wtf_stream_set_priority(wtf_stream_t* stream, uint16_t priority)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed || !strm->quic_stream || !strm->session || strm->session->destroyed
        || !strm->session->connection || strm->session->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    strm->priority = priority;

    QUIC_STATUS status = strm->session->connection->context->quic_api->SetParam(
        strm->quic_stream, QUIC_PARAM_STREAM_PRIORITY, sizeof(priority), &priority);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(strm->session->connection->context, "stream",
                      "SetParam failed for WebTransport stream: 0x%x", status);
        return wtf_quic_status_to_result(status);
    }

    return WTF_SUCCESS;
}

wtf_result_t wtf_stream_set_receive_enabled(wtf_stream_t* stream, bool enabled)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed || !strm->session || strm->session->destroyed
        || !strm->session->connection || strm->session->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    mtx_lock(&strm->mutex);
    strm->receive_enabled = enabled;
    mtx_unlock(&strm->mutex);

    if (strm->quic_stream && strm->session && strm->session->connection
        && strm->session->connection->context) {
        strm->session->connection->context->quic_api->StreamReceiveSetEnabled(
            strm->quic_stream, enabled ? TRUE : FALSE);
    }

    return WTF_SUCCESS;
}

static wtf_result_t wtf_stream_validate_send_params(wtf_stream* stream, const wtf_buffer_t* buffers,
                                                    uint32_t buffer_count)
{
    if (!stream || !buffers || buffer_count == 0) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (buffer_count > WTF_MAX_SEND_BUFFERS) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (stream->destroyed || !stream->session || stream->session->destroyed
        || !stream->session->connection || stream->session->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    for (uint32_t i = 0; i < buffer_count; i++) {
        if (!buffers[i].data && buffers[i].length > 0) {
            return WTF_ERROR_INVALID_PARAMETER;
        }
    }

    if (stream->state == WTF_INTERNAL_STREAM_STATE_CLOSED
        || stream->state == WTF_INTERNAL_STREAM_STATE_RESET) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (!stream->session || !stream->session->connection) {
        return WTF_ERROR_INVALID_STATE;
    }

    if (!stream->quic_stream) {
        return WTF_ERROR_INVALID_STATE;
    }

    return WTF_SUCCESS;
}

static void wtf_stream_free_prepared_buffers(wtf_internal_send_context* send_ctx,
                                             uint32_t buffer_count, bool owns_buffer_data)
{
    if (!send_ctx || !send_ctx->buffers) {
        return;
    }

    if (owns_buffer_data) {
        for (uint32_t i = 0; i < buffer_count; i++) {
            free((void*)send_ctx->buffers[i].data);
        }
    }
    if (!send_ctx->buffers_inline) {
        free(send_ctx->buffers);
    }
    send_ctx->buffers = NULL;
    send_ctx->buffers_inline = false;
    send_ctx->count = 0;
}

static wtf_result_t wtf_stream_prepare_send_buffers(const wtf_buffer_t* buffers,
                                                    uint32_t buffer_count, bool copy_payload,
                                                    wtf_internal_send_context* send_ctx,
                                                    uint64_t* total_length)
{
    if (buffer_count <= WTF_INLINE_SEND_BUFFERS) {
        send_ctx->buffers = send_ctx->inline_buffers;
        send_ctx->buffers_inline = true;
        memset(send_ctx->inline_buffers, 0, sizeof(send_ctx->inline_buffers));
    } else {
        send_ctx->buffers = calloc(buffer_count, sizeof(wtf_buffer_t));
        if (!send_ctx->buffers) {
            return WTF_ERROR_OUT_OF_MEMORY;
        }
    }

    uint64_t total = 0;
    for (uint32_t i = 0; i < buffer_count; i++) {
        if (total > UINT64_MAX - buffers[i].length) {
            wtf_stream_free_prepared_buffers(send_ctx, buffer_count, copy_payload);
            return WTF_ERROR_INVALID_PARAMETER;
        }
        total += buffers[i].length;

        send_ctx->buffers[i].length = buffers[i].length;
        if (buffers[i].length == 0) {
            send_ctx->buffers[i].data = copy_payload ? NULL : buffers[i].data;
            continue;
        }

        if (!copy_payload) {
            send_ctx->buffers[i].data = buffers[i].data;
            continue;
        }

        uint8_t* data_copy = malloc(buffers[i].length);
        if (!data_copy) {
            wtf_stream_free_prepared_buffers(send_ctx, buffer_count, true);
            return WTF_ERROR_OUT_OF_MEMORY;
        }

        memcpy(data_copy, buffers[i].data, buffers[i].length);
        send_ctx->buffers[i].data = data_copy;
    }

    *total_length = total;
    return WTF_SUCCESS;
}

static wtf_result_t wtf_stream_send_internal(wtf_stream* stream, const wtf_buffer_t* buffers,
                                             uint32_t buffer_count, bool fin,
                                             void* operation_context, bool copy_payload)
{
    wtf_result_t validation_result = wtf_stream_validate_send_params(stream, buffers, buffer_count);
    if (validation_result != WTF_SUCCESS) {
        return validation_result;
    }

    wtf_internal_send_context* send_ctx = calloc(1, sizeof(wtf_internal_send_context));
    if (!send_ctx) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    uint64_t total_length = 0;
    wtf_result_t prepare_result = wtf_stream_prepare_send_buffers(
        buffers, buffer_count, copy_payload, send_ctx, &total_length);
    if (prepare_result != WTF_SUCCESS) {
        free(send_ctx);
        return prepare_result;
    }

    send_ctx->count = buffer_count;
    send_ctx->session = stream->session;
    send_ctx->internal_send = false;
    send_ctx->owns_buffer_data = copy_payload;
    send_ctx->app_buffer_offset = 0;
    send_ctx->operation_context = operation_context;

    QUIC_SEND_FLAGS flags = QUIC_SEND_FLAG_NONE;
    if (fin) {
        flags |= QUIC_SEND_FLAG_FIN;
    }

    if (!wtf_session_reserve_outgoing_data(stream->session, total_length)) {
        wtf_stream_free_prepared_buffers(send_ctx, buffer_count, copy_payload);
        free(send_ctx);
        return WTF_ERROR_FLOW_CONTROL;
    }
    send_ctx->flow_control_length = total_length;

    wtf_connection* conn = stream->session->connection;
    QUIC_STATUS status = conn->context->quic_api->StreamSend(
        stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, buffer_count, flags, send_ctx);

    if (QUIC_SUCCEEDED(status)) {
        mtx_lock(&stream->mutex);
        if (fin) {
            stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;
        }
        mtx_unlock(&stream->mutex);
        return WTF_SUCCESS;
    }

    wtf_stream_free_prepared_buffers(send_ctx, buffer_count, copy_payload);
    free(send_ctx);
    wtf_session_release_outgoing_data(stream->session, total_length);
    return wtf_quic_status_to_result(status);
}

wtf_result_t wtf_stream_send(wtf_stream* stream, const wtf_buffer_t* buffers, uint32_t buffer_count,
                             bool fin, void* operation_context)
{
    return wtf_stream_send_internal(stream, buffers, buffer_count, fin, operation_context, false);
}

wtf_result_t wtf_stream_send_copy(wtf_stream_t* stream, const void* data, size_t length, bool fin)
{
    if (!stream || (!data && length > 0)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (length > UINT32_MAX) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (length == 0) {
        if (fin) {
            return wtf_stream_close(stream);
        }
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_buffer_t buffer = {.length = (uint32_t)length, .data = (const uint8_t*)data};
    return wtf_stream_send_internal((wtf_stream*)stream, &buffer, 1, fin, NULL, true);
}

wtf_result_t wtf_stream_abort(wtf_stream_t* stream, uint32_t error_code)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed || !strm->session || strm->session->destroyed
        || !strm->session->connection || strm->session->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    WTF_LOG_DEBUG(strm->session->connection->context, "stream",
                  "Aborting stream %llu with error %u", (unsigned long long)strm->stream_id,
                  error_code);

    mtx_lock(&strm->mutex);
    strm->state = WTF_INTERNAL_STREAM_STATE_RESET;
    mtx_unlock(&strm->mutex);

    if (strm->quic_stream) {
        wtf_connection* conn = strm->session->connection;
        conn->context->quic_api->StreamShutdown(
            strm->quic_stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            wtf_map_webtransport_error_to_h3(error_code));
    }

    if (strm->callback) {
        wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_ABORTED,
                                    .stream = stream,
                                    .user_context = strm->user_context,
                                    .aborted = {.error_code = error_code}};
        strm->callback(&event);
    }

    return WTF_SUCCESS;
}

wtf_result_t wtf_stream_close(wtf_stream_t* stream)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed || !strm->session || strm->session->destroyed
        || !strm->session->connection || strm->session->connection->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    mtx_lock(&strm->mutex);
    if (strm->state == WTF_INTERNAL_STREAM_STATE_CLOSED
        || strm->state == WTF_INTERNAL_STREAM_STATE_RESET) {
        mtx_unlock(&strm->mutex);
        return WTF_ERROR_INVALID_STATE;
    }

    strm->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;
    mtx_unlock(&strm->mutex);

    if (!strm->quic_stream || !strm->session || !strm->session->connection) {
        return WTF_ERROR_INVALID_STATE;
    }

    wtf_connection* conn = strm->session->connection;
    QUIC_STATUS status = conn->context->quic_api->StreamSend(
        strm->quic_stream, NULL, 0, QUIC_SEND_FLAG_FIN, NULL);

    if (QUIC_FAILED(status)) {
        mtx_lock(&strm->mutex);
        if (strm->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
            strm->state = WTF_INTERNAL_STREAM_STATE_OPEN;
        }
        mtx_unlock(&strm->mutex);
        return wtf_quic_status_to_result(status);
    }

    return WTF_SUCCESS;
}

wtf_result_t wtf_stream_get_id(wtf_stream_t* stream, uint64_t* stream_id)
{
    if (!stream || !stream_id) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return WTF_ERROR_INVALID_STATE;
    }

    *stream_id = strm->stream_id;
    return WTF_SUCCESS;
}

wtf_stream_type_t wtf_stream_get_type(wtf_stream_t* stream)
{
    if (!stream)
        return WTF_STREAM_BIDIRECTIONAL;

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return WTF_STREAM_BIDIRECTIONAL;
    }
    return strm->type;
}

wtf_stream_state_t wtf_stream_get_state(wtf_stream_t* stream)
{
    if (!stream)
        return WTF_STREAM_CLOSED;

    wtf_stream* strm = (wtf_stream*)stream;
    if (strm->destroyed) {
        return WTF_STREAM_CLOSED;
    }

    mtx_lock(&strm->mutex);
    wtf_internal_stream_state_t internal_state = strm->state;
    mtx_unlock(&strm->mutex);

    switch (internal_state) {
        case WTF_INTERNAL_STREAM_STATE_IDLE:
        case WTF_INTERNAL_STREAM_STATE_OPEN:
        case WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE:
            return WTF_STREAM_OPEN;
        case WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL:
            return WTF_STREAM_CLOSING;
        case WTF_INTERNAL_STREAM_STATE_CLOSED:
        case WTF_INTERNAL_STREAM_STATE_RESET:
        default:
            return WTF_STREAM_CLOSED;
    }
}
