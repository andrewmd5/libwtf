#include "stream.h"

#include "log.h"
#include "utils.h"
#include "varint.h"

static bool wtf_stream_parse_unidirectional_header(const uint8_t* data, size_t data_len,
                                                   uint64_t* session_id)
{
    if (data_len < 2) {
        return false;
    }

    uint16_t offset = 0;
    uint64_t stream_type;

    if (!wtf_varint_decode((uint16_t)data_len, data, &offset, &stream_type)) {
        return false;
    }

    if (stream_type != WTF_STREAM_TYPE_UNI_WEBTRANSPORT_STREAM) {
        return false;
    }

    if (!wtf_varint_decode((uint16_t)data_len, data, &offset, session_id)) {
        return false;
    }

    return true;
}

static bool wtf_stream_parse_bidirectional_header(const uint8_t* data, size_t data_len,
                                                  uint64_t* session_id)
{
    if (data_len < 2) {
        return false;
    }

    uint16_t offset = 0;
    uint64_t frame_type;

    if (!wtf_varint_decode((uint16_t)data_len, data, &offset, &frame_type)) {
        return false;
    }

    if (frame_type != WTF_FRAME_BIDIR_WEBTRANSPORT_STREAM) {
        return false;
    }

    if (!wtf_varint_decode((uint16_t)data_len, data, &offset, session_id)) {
        return false;
    }

    return true;
}

bool wtf_stream_belongs_to_session(uint64_t stream_id, uint64_t session_id,
                                   const uint8_t* stream_data, size_t data_len)
{
    uint64_t parsed_session_id = 0;
    bool parse_success = false;

    if (WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)) {
        parse_success = wtf_stream_parse_unidirectional_header(
            stream_data, data_len, &parsed_session_id);
    } else {
        parse_success = wtf_stream_parse_bidirectional_header(
            stream_data, data_len, &parsed_session_id);
    }

    return parse_success && (parsed_session_id == session_id);
}

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

    if (mtx_init(&stream->mutex, mtx_plain) != thrd_success) {
        free(stream);
        return NULL;
    }

    return stream;
}

void wtf_stream_destroy(wtf_stream* stream)
{
    if (!stream) {
        return;
    }

    mtx_destroy(&stream->mutex);
    free(stream);
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

static wtf_result_t wtf_stream_send_header(wtf_stream* stream, HQUIC Stream)
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

    wtf_buffer_t* header_buffer = malloc(sizeof(wtf_buffer_t));
    if (!header_buffer) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* header_data = malloc(header_length);
    if (!header_data) {
        free(header_buffer);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    memcpy(header_data, header, header_length);

    header_buffer->data = header_data;
    header_buffer->length = (uint32_t)header_length;

    wtf_internal_send_context* send_ctx = malloc(sizeof(wtf_internal_send_context));
    if (!send_ctx) {
        free(header_data);
        free(header_buffer);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    send_ctx->buffers = header_buffer;
    send_ctx->count = 1;
    send_ctx->internal_send = true;

    wtf_connection* conn = stream->session->connection;
    QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
        Stream, (QUIC_BUFFER*)header_buffer, 1, QUIC_SEND_FLAG_NONE, send_ctx);

    if (QUIC_SUCCEEDED(status)) {
        WTF_LOG_INFO(conn->server->context, "webtransport", "WebTransport stream %llu header sent",
                     (unsigned long long)stream->stream_id);
        return WTF_SUCCESS;
    }

    WTF_LOG_ERROR(conn->server->context, "webtransport",
                  "Failed to send WebTransport stream header: 0x%x", status);

    free(header_data);
    free(header_buffer);
    free(send_ctx);
    return wtf_quic_status_to_result(status);
}

static bool wtf_stream_update_session_map(wtf_stream* stream, uint64_t stream_id)
{
    mtx_lock(&stream->session->streams_mutex);

    if (stream_map_get(&stream->session->streams, UINT64_MAX).data != NULL) {
        stream_map_erase(&stream->session->streams, UINT64_MAX);
    }

    stream_map_itr itr = stream_map_insert(&stream->session->streams, stream_id, stream);
    bool success = !stream_map_is_end(itr);

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
        .user_context = stream->user_context,
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

static void wtf_stream_update_state_on_shutdown(wtf_stream* stream)
{
    mtx_lock(&stream->mutex);
    if (stream->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
        stream->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
    } else {
        stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
    }
    mtx_unlock(&stream->mutex);
}

static void wtf_stream_cleanup_send_context(wtf_stream* stream, wtf_internal_send_context* send_ctx,
                                            bool cancelled)
{
    if (!send_ctx) {
        return;
    }

    if (!send_ctx->internal_send && stream->callback) {
        wtf_stream_event_t event = {
            .type = WTF_STREAM_EVENT_SEND_COMPLETE,
            .stream = (wtf_stream_t*)stream,
            .user_context = stream->user_context,
            .send_complete = {.buffers = send_ctx->buffers,
                              .buffer_count = send_ctx->count,
                              .user_context = send_ctx->user_context,
                              .cancelled = cancelled}};
        stream->callback(&event);
    } else {
        for (uint32_t i = 0; i < send_ctx->count; i++) {
            if (send_ctx->buffers[i].data) {
                free(send_ctx->buffers[i].data);
            }
        }
    }

    free(send_ctx->buffers);
    free(send_ctx);
}

static QUIC_STATUS wtf_handle_stream_start_complete(wtf_stream* stream, HQUIC Stream,
                                                    QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->session->connection;

    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream start complete, status=0x%x", Event->START_COMPLETE.Status);

    if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "WebTransport stream start failed: 0x%x", Event->START_COMPLETE.Status);
        return QUIC_STATUS_SUCCESS;
    }

    uint64_t stream_id = Event->START_COMPLETE.ID;

    mtx_lock(&stream->mutex);
    stream->stream_id = stream_id;
    stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
    mtx_unlock(&stream->mutex);

    if (!wtf_stream_update_session_map(stream, stream_id)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "Failed to add WebTransport stream to session map");
        conn->server->context->quic_api->StreamShutdown(
            Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
    }

    wtf_result_t header_result = wtf_stream_send_header(stream, Stream);
    if (header_result != WTF_SUCCESS) {
        WTF_LOG_ERROR(conn->server->context, "webtransport", "Failed to send stream header");
        conn->server->context->quic_api->StreamShutdown(
            Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
    }

    WTF_LOG_INFO(conn->server->context, "webtransport", "WebTransport stream %llu (%s) ready",
                 (unsigned long long)stream_id,
                 stream->type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional");

    wtf_stream_notify_opened(stream);
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_receive(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->session->connection;

    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream data received on stream %llu",
                  (unsigned long long)stream->stream_id);

    if (!wtf_stream_should_receive(stream)) {
        return QUIC_STATUS_SUCCESS;
    }

    bool fin = (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;

    if (stream->callback) {
        wtf_stream_event_t event = {
            .type = WTF_STREAM_EVENT_DATA_RECEIVED,
            .stream = (wtf_stream_t*)stream,
            .user_context = stream->user_context,
            .data_received = {.buffers = (wtf_buffer_t*)Event->RECEIVE.Buffers,
                              .buffer_count = Event->RECEIVE.BufferCount,
                              .fin = fin}};
        stream->callback(&event);
    }

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_send_complete(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    WTF_LOG_DEBUG(stream->session->connection->server->context, "webtransport",
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
    WTF_LOG_DEBUG(stream->session->connection->server->context, "webtransport",
                  "WebTransport stream peer send shutdown on stream %llu",
                  (unsigned long long)stream->stream_id);

    wtf_stream_update_state_on_shutdown(stream);

    if (stream->callback) {
        wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_PEER_CLOSED,
                                    .stream = (wtf_stream_t*)stream,
                                    .user_context = stream->user_context};
        stream->callback(&event);
    }

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_peer_aborted(wtf_stream* stream, QUIC_STREAM_EVENT* Event)
{
    QUIC_UINT62 error_code = Event->PEER_SEND_ABORTED.ErrorCode;

    WTF_LOG_DEBUG(stream->session->connection->server->context, "webtransport",
                  "WebTransport stream peer send aborted on stream %llu: 0x%x",
                  (unsigned long long)stream->stream_id, error_code);

    wtf_stream_handle_reset(stream, error_code);
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_shutdown_complete(wtf_stream* stream)
{
    WTF_LOG_DEBUG(stream->session->connection->server->context, "webtransport",
                  "WebTransport stream shutdown complete on stream %llu",
                  (unsigned long long)stream->stream_id);

    if (stream->callback) {
        wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_CLOSED,
                                    .stream = (wtf_stream_t*)stream,
                                    .user_context = stream->user_context};
        stream->callback(&event);
    }

    mtx_lock(&stream->session->streams_mutex);
    stream_map_erase(&stream->session->streams, stream->stream_id);
    mtx_unlock(&stream->session->streams_mutex);

    wtf_stream_destroy(stream);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API wtf_upgraded_stream_callback(HQUIC Stream, void* Context,
                                                  QUIC_STREAM_EVENT* Event)
{
    wtf_stream* wt_stream = (wtf_stream*)Context;

    if (!wt_stream || !wt_stream->session || !wt_stream->session->connection
        || !wt_stream->session->connection->server
        || !wt_stream->session->connection->server->context) {
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
            WTF_LOG_DEBUG(wt_stream->session->connection->server->context, "webtransport",
                          "WebTransport stream send shutdown complete on stream %llu",
                          (unsigned long long)wt_stream->stream_id);
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            return wtf_handle_stream_shutdown_complete(wt_stream);

        default:
            WTF_LOG_DEBUG(wt_stream->session->connection->server->context, "webtransport",
                          "Unhandled WebTransport stream event: %d", Event->Type);
            return QUIC_STATUS_SUCCESS;
    }
}

void wtf_stream_set_context(wtf_stream_t* stream, void* user_context)
{
    if (!stream) {
        return;
    }
    ((wtf_stream*)stream)->user_context = user_context;
}

void* wtf_stream_get_context(wtf_stream_t* stream)
{
    if (!stream) {
        return NULL;
    }
    return ((wtf_stream*)stream)->user_context;
}


void wtf_stream_set_callback(wtf_stream_t* stream, wtf_stream_callback_t callback)
{
    if (!stream) {
        return;
    }
    ((wtf_stream*)stream)->callback = callback;
}

wtf_result_t wtf_stream_set_priority(wtf_stream_t* stream, uint16_t priority)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    stream->priority = priority;

    QUIC_STATUS status = stream->session->connection->server->context->quic_api->SetParam(
        stream->quic_stream, QUIC_PARAM_STREAM_PRIORITY, sizeof(priority), &priority);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(stream->session->connection->server->context, "stream",
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

    mtx_lock(&strm->mutex);
    strm->receive_enabled = enabled;
    mtx_unlock(&strm->mutex);

    return WTF_SUCCESS;
}

static wtf_result_t wtf_stream_validate_send_params(wtf_stream* stream, const wtf_buffer_t* buffers,
                                                    uint32_t buffer_count)
{
    if (!stream || !buffers || buffer_count == 0) {
        return WTF_ERROR_INVALID_PARAMETER;
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

wtf_result_t wtf_stream_send(wtf_stream* stream, const wtf_buffer_t* buffers, uint32_t buffer_count,
                             bool fin, void* user_context)
{
    wtf_result_t validation_result = wtf_stream_validate_send_params(stream, buffers, buffer_count);
    if (validation_result != WTF_SUCCESS) {
        return validation_result;
    }

    wtf_internal_send_context* send_ctx = malloc(sizeof(wtf_internal_send_context));
    if (!send_ctx) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    wtf_buffer_t* internal_buffers = malloc(sizeof *buffers * buffer_count);
    if (!internal_buffers) {
        free(send_ctx);
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    memcpy(internal_buffers, buffers, sizeof *buffers * buffer_count);

    send_ctx->buffers = internal_buffers;
    send_ctx->count = buffer_count;
    send_ctx->user_context = user_context;
    send_ctx->internal_send = false;

    QUIC_SEND_FLAGS flags = QUIC_SEND_FLAG_NONE;
    if (fin) {
        flags |= QUIC_SEND_FLAG_FIN;
    }

    // WARN: QUIC_BUFFER cast below is not quite safe, this should be really done differently, 
    //       either QUIC_BUFFER is to use used directly or there should be a static assert
    //       of some way to ensure the match. So far this runs on affinity assumption.

    wtf_connection* conn = stream->session->connection;
    QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
        stream->quic_stream, (QUIC_BUFFER*)internal_buffers, buffer_count, flags, send_ctx);

    if (QUIC_SUCCEEDED(status)) {
        stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
        if (fin) {
            stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;
        }
        return WTF_SUCCESS;
    }

    free(send_ctx->buffers);
    free(send_ctx);
    return wtf_quic_status_to_result(status);
}

wtf_result_t wtf_stream_abort(wtf_stream_t* stream, uint32_t error_code)
{
    if (!stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_stream* strm = (wtf_stream*)stream;

    WTF_LOG_DEBUG(strm->session->connection->server->context, "stream",
                  "Aborting stream %llu with error %u", (unsigned long long)strm->stream_id,
                  error_code);

    mtx_lock(&strm->mutex);
    strm->state = WTF_INTERNAL_STREAM_STATE_RESET;
    mtx_unlock(&strm->mutex);

    if (strm->quic_stream) {
        wtf_connection* conn = strm->session->connection;
        conn->server->context->quic_api->StreamShutdown(
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

    mtx_lock(&strm->mutex);
    if (strm->state == WTF_INTERNAL_STREAM_STATE_CLOSED
        || strm->state == WTF_INTERNAL_STREAM_STATE_RESET) {
        mtx_unlock(&strm->mutex);
        return WTF_ERROR_INVALID_STATE;
    }

    strm->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;
    mtx_unlock(&strm->mutex);

    wtf_buffer_t empty_buffer = {0, NULL};
    return wtf_stream_send(strm, &empty_buffer, 1, true, NULL);
}

wtf_result_t wtf_stream_get_id(wtf_stream_t* stream, uint64_t* stream_id)
{
    if (!stream || !stream_id) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *stream_id = ((wtf_stream*)stream)->stream_id;
    return WTF_SUCCESS;
}

wtf_stream_type_t wtf_stream_get_type(wtf_stream_t* stream)
{
    if (!stream)
        return WTF_STREAM_BIDIRECTIONAL;
    return ((wtf_stream*)stream)->type;
}

wtf_stream_state_t wtf_stream_get_state(wtf_stream_t* stream)
{
    if (!stream)
        return WTF_STREAM_CLOSED;

    wtf_stream* strm = (wtf_stream*)stream;

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
