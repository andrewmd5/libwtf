#include "http3.h"

#include "client.h"
#include "conn.h"
#include "draft.h"
#include "log.h"
#include "qpack.h"
#include "session.h"
#include "settings.h"
#include "stream.h"
#include "utils.h"
#include "varint.h"

typedef struct {
    wtf_varint_t type;
    wtf_varint_t length;
    size_t header_size;
    bool complete;
} wtf_frame_info;

typedef enum {
    WTF_FRAME_RESULT_SUCCESS,
    WTF_FRAME_RESULT_NEED_MORE_DATA,
    WTF_FRAME_RESULT_INVALID_FRAME,
    WTF_FRAME_RESULT_PROTOCOL_ERROR
} wtf_frame_result_t;

typedef enum {
    WTF_CAPSULE_PARSE_COMPLETE,
    WTF_CAPSULE_PARSE_NEED_MORE_DATA,
    WTF_CAPSULE_PARSE_ERROR
} wtf_capsule_parse_result_t;

static bool wtf_emit_stream_data_event(wtf_stream* stream, const uint8_t* data, size_t length,
                                       bool fin);
static wtf_result_t wtf_http3_send_response(wtf_http3_stream* stream, uint16_t status_code,
                                            const wtf_connection_response_t* response);
static wtf_result_t wtf_http3_flush_qpack_encoder_stream(wtf_connection* conn);
static bool wtf_http3_client_start_connect_stream(wtf_http3_stream* stream);
static wtf_result_t wtf_http3_client_send_connect_request(wtf_http3_stream* stream);
static wtf_result_t wtf_session_establish(wtf_http3_stream* stream,
                                          const wtf_connect_response* response);
static wtf_result_t wtf_http3_finish_connect_request(
    wtf_http3_stream* stream, wtf_connection_decision_t decision,
    const wtf_connection_response_t* response);
static bool wtf_http3_process_connect_response(wtf_http3_stream* stream,
                                               wtf_connect_response* response);
static bool wtf_http3_process_complete_connect_request(wtf_http3_stream* stream,
                                                       wtf_connect_request* request);

static size_t wtf_http3_stream_buffer_limit(const wtf_http3_stream* stream)
{
    size_t limit = WTF_MAX_STREAM_BUFFER_SIZE;
    if (stream && stream->connection && stream->connection->local_settings.max_field_section_size) {
        limit = stream->connection->local_settings.max_field_section_size;
    }
    return limit > WTF_MAX_STREAM_BUFFER_SIZE ? WTF_MAX_STREAM_BUFFER_SIZE : limit;
}

static bool wtf_http3_stream_buffer_reserve(wtf_http3_stream* stream, size_t length)
{
    if (!stream) {
        return false;
    }

    size_t limit = wtf_http3_stream_buffer_limit(stream);
    if (length > limit) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "Buffered stream data exceeds limit: %zu > %zu", length, limit);
        return false;
    }

    if (length <= stream->buffered_data_capacity) {
        return true;
    }

    size_t new_capacity = stream->buffered_data_capacity ? stream->buffered_data_capacity : 256;
    while (new_capacity < length) {
        if (new_capacity > limit / 2) {
            new_capacity = limit;
            break;
        }
        new_capacity *= 2;
    }

    uint8_t* buffer = realloc(stream->buffered_data, new_capacity);
    if (!buffer) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "Failed to grow stream buffer to %zu bytes", new_capacity);
        return false;
    }

    stream->buffered_data = buffer;
    stream->buffered_data_capacity = new_capacity;
    return true;
}

static void wtf_http3_shutdown_connection(wtf_connection* conn, uint64_t error_code)
{
    if (!conn || !conn->context || !conn->context->quic_api
        || !conn->quic_connection) {
        return;
    }

    conn->context->quic_api->ConnectionShutdown(
        conn->quic_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, error_code);
}

static void wtf_http3_abort_stream(wtf_http3_stream* stream, uint64_t error_code)
{
    if (!stream || !stream->connection || !stream->connection->context
        || !stream->connection->context->quic_api
        || !stream->quic_stream) {
        return;
    }

    stream->connection->context->quic_api->StreamShutdown(
        stream->quic_stream,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
        error_code);
    stream->state = WTF_INTERNAL_STREAM_STATE_RESET;
}

static bool wtf_http3_is_valid_session_id(uint64_t session_id)
{
    return session_id <= WTF_VARINT_MAX && !WTF_STREAM_IS_UNIDIRECTIONAL(session_id)
        && WTF_STREAM_IS_CLIENT_INITIATED(session_id);
}

static bool wtf_http3_validate_session_id_or_shutdown(wtf_connection* conn, uint64_t session_id,
                                                      const char* context)
{
    if (wtf_http3_is_valid_session_id(session_id)) {
        return true;
    }

    WTF_LOG_ERROR(conn->context, "webtransport",
                  "Invalid WebTransport session ID %llu received in %s",
                  (unsigned long long)session_id, context ? context : "WebTransport data");
    wtf_http3_shutdown_connection(conn, WTF_H3_ID_ERROR);
    return false;
}

static bool wtf_http3_stream_buffer_replace(wtf_http3_stream* stream, const uint8_t* data,
                                            size_t length)
{
    if (length == 0) {
        stream->buffered_data_length = 0;
        return true;
    }

    if (!data || !wtf_http3_stream_buffer_reserve(stream, length)) {
        return false;
    }

    memmove(stream->buffered_data, data, length);
    stream->buffered_data_length = length;
    return true;
}

static bool wtf_http3_stream_buffer_append(wtf_http3_stream* stream, const uint8_t* data,
                                           size_t length)
{
    if (!stream || (!data && length > 0)) {
        return false;
    }
    if (length == 0) {
        return true;
    }
    if (stream->buffered_data_length > SIZE_MAX - length) {
        return false;
    }

    size_t new_length = stream->buffered_data_length + length;
    if (!wtf_http3_stream_buffer_reserve(stream, new_length)) {
        return false;
    }

    memcpy(stream->buffered_data + stream->buffered_data_length, data, length);
    stream->buffered_data_length = new_length;
    return true;
}

static uint32_t wtf_http3_pending_connect_limit(const wtf_connection* conn)
{
    uint32_t session_limit = conn && conn->max_sessions ? conn->max_sessions
                                                        : WTF_DEFAULT_MAX_SESSIONS;
    return min(session_limit, WTF_MAX_PENDING_CONNECT_REQUESTS);
}

static bool wtf_http3_connect_processing_ready(const wtf_connection* conn)
{
    return conn && conn->local_settings.settings_sent && conn->peer_settings.settings_received
        && conn->selected_webtransport_draft != WTF_WEBTRANSPORT_DRAFT_NONE;
}

static void wtf_http3_clear_pending_connect_headers(wtf_http3_stream* stream)
{
    if (!stream || !stream->has_pending_connect_header_block) {
        return;
    }

    free(stream->pending_connect_header_block);
    stream->pending_connect_header_block = NULL;
    stream->pending_connect_header_length = 0;
    stream->has_pending_connect_header_block = false;

    if (stream->connection && stream->connection->pending_connect_count > 0) {
        stream->connection->pending_connect_count--;
    }
}

static bool wtf_http3_queue_connect_headers(wtf_http3_stream* stream, const uint8_t* data,
                                            uint32_t length)
{
    if (!stream || !stream->connection || !data || length == 0) {
        return false;
    }

    size_t limit = wtf_http3_stream_buffer_limit(stream);
    if (length > limit) {
        WTF_LOG_ERROR(stream->connection->context, "connect",
                      "CONNECT header block exceeds buffer limit: %u > %zu", length, limit);
        return false;
    }

    uint8_t* copy = malloc(length);
    if (!copy) {
        WTF_LOG_ERROR(stream->connection->context, "connect",
                      "Failed to buffer CONNECT header block");
        return false;
    }
    memcpy(copy, data, length);

    wtf_connection* conn = stream->connection;
    bool queued = false;

    mtx_lock(&conn->streams_mutex);
    uint32_t pending_limit = wtf_http3_pending_connect_limit(conn);
    if (stream->has_pending_connect_header_block) {
        WTF_LOG_ERROR(conn->context, "connect",
                      "Duplicate pending CONNECT headers on stream %llu",
                      (unsigned long long)stream->id);
    } else if (conn->pending_connect_count >= pending_limit) {
        WTF_LOG_WARN(conn->context, "connect",
                     "Pending CONNECT limit reached (%u) - rejecting stream %llu",
                     pending_limit, (unsigned long long)stream->id);
    } else {
        stream->pending_connect_header_block = copy;
        stream->pending_connect_header_length = length;
        stream->has_pending_connect_header_block = true;
        conn->pending_connect_count++;
        queued = true;
    }
    mtx_unlock(&conn->streams_mutex);

    if (!queued) {
        free(copy);
        return false;
    }

    WTF_LOG_DEBUG(conn->context, "connect",
                  "Buffered CONNECT headers on stream %llu pending SETTINGS",
                  (unsigned long long)stream->id);
    return true;
}

wtf_http3_stream* wtf_http3_stream_create(wtf_connection* conn, HQUIC quic_stream,
                                          uint64_t stream_id)
{
    wtf_http3_stream* stream = malloc(sizeof(wtf_http3_stream));
    if (!stream) {
        return NULL;
    }

    memset(stream, 0, sizeof(*stream));
    atomic_init(&stream->ref_count, 1);
    stream->id = stream_id;
    stream->quic_stream = quic_stream;
    stream->connection = conn;
    stream->state = WTF_INTERNAL_STREAM_STATE_IDLE;
    wtf_connection_add_ref(conn);

    // Only add to streams map if it's not a placeholder stream
    if (stream_id != UINT64_MAX) {
        mtx_lock(&conn->streams_mutex);
        http3_stream_map_itr itr = http3_stream_map_insert(&conn->streams, stream_id, stream);
        if (http3_stream_map_is_end(itr)) {
            mtx_unlock(&conn->streams_mutex);
            wtf_connection_release(conn);
            free(stream);
            return NULL;
        }
        mtx_unlock(&conn->streams_mutex);
    }

    return stream;
}

void wtf_http3_stream_add_ref(wtf_http3_stream* stream)
{
    if (!stream) {
        return;
    }
    atomic_fetch_add_explicit(&stream->ref_count, 1, memory_order_relaxed);
}

static void wtf_http3_stream_dispose(wtf_http3_stream* stream)
{
    if (!stream) {
        return;
    }

    if (stream->destroyed) {
        return;
    }
    stream->destroyed = true;

    if (stream->quic_stream && stream->connection && stream->connection->context) {
        stream->connection->context->quic_api->StreamClose(stream->quic_stream);
        stream->quic_stream = NULL;
    }

    if (stream->header_buffer) {
        free(stream->header_buffer);
    }
    if (stream->buffered_data) {
        free(stream->buffered_data);
    }
    wtf_http3_clear_pending_connect_headers(stream);
    if (stream->capsule_buffer && stream->capsule_buffer != stream->capsule_inline) {
        free(stream->capsule_buffer);
    }

    if (stream->webtransport_session) {
        if (stream->webtransport_session->connect_stream == stream) {
            stream->webtransport_session->connect_stream = NULL;
        }
        wtf_session_release(stream->webtransport_session);
        stream->webtransport_session = NULL;
    }
}

void wtf_http3_stream_release(wtf_http3_stream* stream)
{
    if (!stream) {
        return;
    }

    if (atomic_fetch_sub_explicit(&stream->ref_count, 1, memory_order_acq_rel) != 1) {
        return;
    }

    wtf_http3_stream_dispose(stream);
    wtf_connection* conn = stream->connection;
    stream->connection = NULL;
    free(stream);
    wtf_connection_release(conn);
}

void wtf_http3_stream_destroy(wtf_http3_stream* stream)
{
    if (!stream) {
        return;
    }

    wtf_http3_stream_dispose(stream);
    wtf_http3_stream_release(stream);
}

static size_t wtf_connection_response_header_bytes(const wtf_connection_response_t* response)
{
    if (!response) {
        return 0;
    }

    size_t total = 0;
    for (size_t i = 0; i < response->header_count; i++) {
        total += strlen(response->headers[i].name) + strlen(response->headers[i].value);
    }
    return total;
}

static void wtf_connection_response_cleanup(wtf_connection_response_t* response)
{
    if (!response) {
        return;
    }

    for (size_t i = 0; i < response->header_count; i++) {
        free((void*)response->headers[i].name);
        free((void*)response->headers[i].value);
    }
    free(response->headers);
    memset(response, 0, sizeof(*response));
}

wtf_result_t wtf_connection_response_add_header(wtf_connection_response_t* response,
                                                const char* name, const char* value)
{
    if (!response || !name || !value || name[0] == ':' || name[0] == '\0') {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (response->header_count >= WTF_MAX_CONNECT_RESPONSE_HEADERS) {
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }

    size_t current_bytes = wtf_connection_response_header_bytes(response);
    size_t added_bytes = strlen(name) + strlen(value);
    if (added_bytes > WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES
        || current_bytes + added_bytes > WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES) {
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }

    if (response->header_count == response->header_capacity) {
        size_t new_capacity = response->header_capacity == 0 ? 4 : response->header_capacity * 2;
        if (new_capacity > WTF_MAX_CONNECT_RESPONSE_HEADERS) {
            new_capacity = WTF_MAX_CONNECT_RESPONSE_HEADERS;
        }
        wtf_http_header_t* headers = realloc(response->headers, new_capacity * sizeof(*headers));
        if (!headers) {
            return WTF_ERROR_OUT_OF_MEMORY;
        }
        response->headers = headers;
        response->header_capacity = new_capacity;
    }

    char* copied_name = wtf_strdup(name);
    char* copied_value = wtf_strdup(value);
    if (!copied_name || !copied_value) {
        free(copied_name);
        free(copied_value);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    response->headers[response->header_count++] = (wtf_http_header_t){
        .name = copied_name,
        .value = copied_value,
    };
    return WTF_SUCCESS;
}

static wtf_connection_request_handle* wtf_connection_request_handle_create(
    wtf_http3_stream* stream)
{
    if (!stream) {
        return NULL;
    }

    wtf_connection_request_handle* handle = calloc(1, sizeof(*handle));
    if (!handle) {
        return NULL;
    }

    if (mtx_init(&handle->mutex, mtx_plain) != thrd_success) {
        free(handle);
        return NULL;
    }

    atomic_init(&handle->ref_count, 1);
    handle->stream = stream;
    wtf_http3_stream_add_ref(stream);
    return handle;
}

void wtf_connection_request_ref(wtf_connection_request_handle_t* handle)
{
    if (!handle) {
        return;
    }

    atomic_fetch_add_explicit(&handle->ref_count, 1, memory_order_relaxed);
}

void wtf_connection_request_unref(wtf_connection_request_handle_t* handle)
{
    if (!handle) {
        return;
    }

    if (atomic_fetch_sub_explicit(&handle->ref_count, 1, memory_order_acq_rel) != 1) {
        return;
    }

    wtf_connection_response_cleanup(&handle->response);
    wtf_http3_stream_release(handle->stream);
    mtx_destroy(&handle->mutex);
    free(handle);
}

wtf_result_t wtf_connection_request_add_response_header(wtf_connection_request_handle_t* handle,
                                                        const char* name, const char* value)
{
    if (!handle) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    mtx_lock(&handle->mutex);
    if (handle->completed) {
        mtx_unlock(&handle->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    wtf_result_t result = wtf_connection_response_add_header(&handle->response, name, value);
    mtx_unlock(&handle->mutex);
    return result;
}

wtf_result_t wtf_connection_request_complete(wtf_connection_request_handle_t* handle,
                                             wtf_connection_decision_t decision)
{
    if (!handle || decision == WTF_CONNECTION_DEFER) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    mtx_lock(&handle->mutex);
    if (handle->completed) {
        mtx_unlock(&handle->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    handle->completed = true;
    mtx_unlock(&handle->mutex);

    wtf_result_t result = wtf_http3_finish_connect_request(
        handle->stream, decision, &handle->response);
    wtf_connection_request_unref(handle);
    return result;
}

static void wtf_http3_stream_retire_transferred(wtf_http3_stream* stream)
{
    if (!stream || !stream->callback_transferred) {
        return;
    }

    wtf_connection* conn = stream->connection;
    bool release_map_ref = false;

    if (conn && !conn->destroyed && stream->id != UINT64_MAX) {
        mtx_lock(&conn->streams_mutex);
        http3_stream_map_itr itr = http3_stream_map_get(&conn->streams, stream->id);
        if (!http3_stream_map_is_end(itr) && itr.data->val == stream) {
            http3_stream_map_erase(&conn->streams, stream->id);
            release_map_ref = true;
        }
        mtx_unlock(&conn->streams_mutex);
    }

    if (release_map_ref) {
        wtf_http3_stream_release(stream);
    }
    wtf_http3_stream_destroy(stream);
}

bool wtf_http3_create_control_stream(wtf_connection* conn)
{
    WTF_LOG_INFO(conn->context, "http3", "Creating control stream...");

    // Control streams are NOT associated with WebTransport sessions
    wtf_http3_stream* stream = wtf_http3_stream_create(conn, NULL, UINT64_MAX);
    if (!stream) {
        WTF_LOG_ERROR(conn->context, "conn", "Failed to create control stream context");
        return false;
    }

    stream->type = WTF_STREAM_TYPE_CONTROL;
    // Control stream is connection infrastructure, not session-specific
    conn->control_stream = stream;

    HQUIC control_stream;
    QUIC_STATUS status = conn->context->quic_api->StreamOpen(
        conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, wtf_http3_stream_callback,
        stream, &control_stream);

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(conn->context, "conn", "Failed to create control stream: 0x%x",
                      status);
        conn->control_stream = NULL;
        wtf_http3_stream_destroy(stream);
        return false;
    }

    stream->quic_stream = control_stream;

    status = conn->context->quic_api->StreamStart(
        control_stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
        WTF_LOG_ERROR(conn->context, "conn", "StreamStart failed for control stream: 0x%x",
                      status);
        conn->control_stream = NULL;
        wtf_http3_stream_destroy(stream);
        return false;
    }

    WTF_LOG_INFO(conn->context, "http3", "Control stream creation initiated");
    return true;
}

bool wtf_http3_create_qpack_streams(wtf_connection* conn)
{
    WTF_LOG_INFO(conn->context, "http3", "Creating QPACK streams...");

    // QPACK encoder stream - connection infrastructure, not session-specific
    wtf_http3_stream* enc_stream = wtf_http3_stream_create(conn, NULL, UINT64_MAX);
    if (!enc_stream) {
        WTF_LOG_ERROR(conn->context, "conn", "Failed to create encoder stream context");
        return false;
    }

    enc_stream->type = WTF_STREAM_TYPE_QPACK_ENCODER;
    conn->qpack_encoder_stream = enc_stream;

    HQUIC encoder_stream = NULL;
    QUIC_STATUS status = conn->context->quic_api->StreamOpen(
        conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, wtf_http3_stream_callback,
        enc_stream, &encoder_stream);

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(conn->context, "conn", "StreamOpen failed for encoder stream: 0x%x",
                      status);
        conn->qpack_encoder_stream = NULL;
        wtf_http3_stream_destroy(enc_stream);
        return false;
    }

    enc_stream->quic_stream = encoder_stream;

    status = conn->context->quic_api->StreamStart(
        encoder_stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
        WTF_LOG_ERROR(conn->context, "conn", "StreamStart failed for encoder stream: 0x%x",
                      status);
        conn->qpack_encoder_stream = NULL;
        wtf_http3_stream_destroy(enc_stream);
        return false;
    }

    WTF_LOG_DEBUG(conn->context, "http3", "QPACK encoder stream creation initiated");

    // QPACK decoder stream - connection infrastructure, not session-specific
    wtf_http3_stream* dec_stream = wtf_http3_stream_create(conn, NULL, UINT64_MAX);
    if (!dec_stream) {
        WTF_LOG_ERROR(conn->context, "conn", "Failed to create decoder stream context");
        return false;
    }

    dec_stream->type = WTF_STREAM_TYPE_QPACK_DECODER;
    conn->qpack_decoder_stream = dec_stream;

    HQUIC decoder_stream = NULL;
    status = conn->context->quic_api->StreamOpen(
        conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL, wtf_http3_stream_callback,
        dec_stream, &decoder_stream);

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(conn->context, "conn", "StreamOpen failed for decoder stream: 0x%x",
                      status);
        conn->qpack_decoder_stream = NULL;
        wtf_http3_stream_destroy(dec_stream);
        return false;
    }

    dec_stream->quic_stream = decoder_stream;

    status = conn->context->quic_api->StreamStart(
        decoder_stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
        WTF_LOG_ERROR(conn->context, "conn", "StreamStart failed for decoder stream: 0x%x",
                      status);
        conn->qpack_decoder_stream = NULL;
        wtf_http3_stream_destroy(dec_stream);
        return false;
    }

    WTF_LOG_DEBUG(conn->context, "http3", "QPACK decoder stream creation initiated");
    WTF_LOG_INFO(conn->context, "http3", "QPACK streams creation initiated successfully");
    return true;
}

static bool wtf_http3_parse_frame_header(const uint8_t* data, size_t length, size_t offset,
                                         wtf_frame_info* frame)
{
    if (!data || !frame) {
        return false;
    }

    size_t decode_offset = offset;

    if (!wtf_varint_decode(length, data, &decode_offset, &frame->type)
        || !wtf_varint_decode(length, data, &decode_offset, &frame->length)) {
        frame->complete = false;
        return false;
    }

    frame->header_size = decode_offset - offset;
    frame->complete = true;
    return true;
}

static bool wtf_http3_validate_settings(wtf_connection* conn)
{
    if (!conn) {
        return false;
    }

    if (conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_NONE) {
        WTF_LOG_TRACE(conn->context, "settings",
                      "No supported WebTransport draft enabled by peer");
        return false;
    }

    conn->webtransport_flow_control_enabled = false;

    switch (conn->selected_webtransport_draft) {
        case WTF_WEBTRANSPORT_DRAFT_15: {
            if (conn->role == WTF_ENDPOINT_CLIENT && !conn->peer_settings.enable_connect_protocol) {
                WTF_LOG_TRACE(conn->context, "settings",
                              "CONNECT protocol not enabled by draft-15 peer");
                return false;
            }

            if (!conn->peer_settings.h3_datagram_rfc_enabled) {
                WTF_LOG_TRACE(conn->context, "settings",
                              "RFC H3 datagrams not enabled by draft-15 peer");
                return false;
            }

            bool has_all_flow_control = conn->peer_settings.wt_initial_max_data_received
                && conn->peer_settings.wt_initial_max_streams_bidi_received
                && conn->peer_settings.wt_initial_max_streams_uni_received;
            bool has_any_flow_control = conn->peer_settings.wt_initial_max_data_received
                || conn->peer_settings.wt_initial_max_streams_bidi_received
                || conn->peer_settings.wt_initial_max_streams_uni_received;

            if (!has_all_flow_control) {
                if (conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_AUTO
                    && !has_any_flow_control) {
                    WTF_LOG_DEBUG(conn->context, "settings",
                                  "Draft-15 peer omitted WT flow-control settings; "
                                  "using transport stream and data limits");
                    return true;
                }

                WTF_LOG_TRACE(conn->context, "settings",
                              "Draft-15 peer missing required WT flow-control settings");
                return false;
            }

            conn->webtransport_flow_control_enabled = true;
            return true;
        }

        case WTF_WEBTRANSPORT_DRAFT_07:
            if (conn->role == WTF_ENDPOINT_CLIENT && !conn->peer_settings.enable_connect_protocol) {
                WTF_LOG_TRACE(conn->context, "settings",
                              "CONNECT protocol not enabled by peer");
                return false;
            }
            if (!conn->peer_settings.h3_datagram_rfc_enabled) {
                WTF_LOG_TRACE(conn->context, "settings",
                              "RFC H3 datagrams not enabled by peer");
                return false;
            }
            return true;

        case WTF_WEBTRANSPORT_DRAFT_02:
            if (!conn->peer_settings.h3_datagram_enabled) {
                WTF_LOG_TRACE(conn->context, "settings",
                              "H3 datagrams not enabled by draft-02 peer");
                return false;
            }
            return true;

        case WTF_WEBTRANSPORT_DRAFT_NONE:
        default:
            return false;
    }
}

static bool wtf_http3_is_supported_webtransport_protocol(const char* protocol)
{
    return protocol
        && (strcmp(protocol, WTF_WEBTRANSPORT_PROTOCOL_DRAFT15) == 0
            || strcmp(protocol, WTF_WEBTRANSPORT_PROTOCOL_DRAFT02) == 0);
}

static bool wtf_http3_protocol_matches_selected_draft(const wtf_connection* conn,
                                                      const char* protocol)
{
    if (!conn || !protocol) {
        return false;
    }

    switch (conn->selected_webtransport_draft) {
        case WTF_WEBTRANSPORT_DRAFT_15:
            return strcmp(protocol, WTF_WEBTRANSPORT_PROTOCOL_DRAFT15) == 0
                || (conn->role == WTF_ENDPOINT_SERVER
                    && strcmp(protocol, WTF_WEBTRANSPORT_PROTOCOL_DRAFT02) == 0);
        case WTF_WEBTRANSPORT_DRAFT_07:
        case WTF_WEBTRANSPORT_DRAFT_02:
            return strcmp(protocol, WTF_WEBTRANSPORT_PROTOCOL_DRAFT02) == 0;
        case WTF_WEBTRANSPORT_DRAFT_NONE:
        default:
            return false;
    }
}

static bool wtf_http3_process_pending_connects(wtf_connection* conn)
{
    if (!conn || !wtf_http3_connect_processing_ready(conn) || conn->pending_connect_count == 0) {
        return true;
    }

    wtf_http3_stream* pending[WTF_MAX_PENDING_CONNECT_REQUESTS] = {0};
    size_t pending_count = 0;

    mtx_lock(&conn->streams_mutex);
    for (http3_stream_map_itr itr = http3_stream_map_first(&conn->streams);
         !http3_stream_map_is_end(itr) && pending_count < ARRAYSIZE(pending);
         itr = http3_stream_map_next(itr)) {
        wtf_http3_stream* stream = itr.data->val;
        if (stream && stream->has_pending_connect_header_block) {
            wtf_http3_stream_add_ref(stream);
            pending[pending_count++] = stream;
        }
    }
    mtx_unlock(&conn->streams_mutex);

    for (size_t i = 0; i < pending_count; i++) {
        wtf_http3_stream* stream = pending[i];
        wtf_connect_request request = {0};

        WTF_LOG_DEBUG(conn->context, "connect",
                      "Processing buffered CONNECT headers on stream %llu",
                      (unsigned long long)stream->id);

        wtf_result_t parse_result = wtf_qpack_parse_connect_headers(
            conn->context, stream, stream->pending_connect_header_block,
            stream->pending_connect_header_length, &request);
        wtf_http3_clear_pending_connect_headers(stream);

        if (parse_result == WTF_SUCCESS) {
            wtf_http3_process_complete_connect_request(stream, &request);
        } else {
            WTF_LOG_ERROR(conn->context, "connect",
                          "Buffered CONNECT headers failed to decode on stream %llu",
                          (unsigned long long)stream->id);
            wtf_connect_request_cleanup(&request);
            wtf_http3_send_response(stream, 400, NULL);
        }

        wtf_http3_stream_release(stream);
    }

    return true;
}

static bool wtf_http3_handle_settings_exchange(wtf_connection* conn)
{
    if (!conn) {
        return false;
    }

    if (conn->role == WTF_ENDPOINT_CLIENT) {
        wtf_client_mark_transport_ready(conn->client);
        return wtf_http3_client_drain_pending_connects(conn);
    }

    return wtf_http3_process_pending_connects(conn);
}

static wtf_frame_result_t wtf_http3_process_settings_frame(wtf_http3_stream* stream,
                                                           const uint8_t* data, size_t data_len)
{
    if (!stream || !data) {
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    // SETTINGS frames can only be sent on control streams
    if (stream->type != WTF_STREAM_TYPE_CONTROL) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "SETTINGS frame received on non-control stream %llu",
                      (unsigned long long)stream->id);
        return WTF_FRAME_RESULT_PROTOCOL_ERROR;
    }

    if (!wtf_settings_decode_frame(stream->connection, data, data_len)) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "Failed to decode SETTINGS frame on stream %llu",
                      (unsigned long long)stream->id);
        wtf_http3_shutdown_connection(stream->connection, WTF_H3_SETTINGS_ERROR);
        return WTF_FRAME_RESULT_SUCCESS;
    }

    stream->connection->selected_webtransport_draft = wtf_draft_select(
        stream->connection->role, stream->connection->requested_webtransport_draft,
        &stream->connection->peer_settings);

    if (!wtf_http3_validate_settings(stream->connection)) {
        WTF_LOG_ERROR(stream->connection->context, "settings",
                      "Peer SETTINGS do not meet WebTransport requirements");
        wtf_http3_shutdown_connection(stream->connection, WTF_WEBTRANSPORT_REQUIREMENTS_NOT_MET);
        return WTF_FRAME_RESULT_SUCCESS;
    }

    stream->connection->peer_settings.settings_received = true;

    if (!wtf_qpack_init_encoder(stream->connection->context, &stream->connection->qpack)) {
        WTF_LOG_ERROR(stream->connection->context, "settings",
                      "Failed to initialize QPACK encoder");
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    if (wtf_http3_flush_qpack_encoder_stream(stream->connection) != WTF_SUCCESS) {
        WTF_LOG_ERROR(stream->connection->context, "qpack",
                      "Failed to flush initial QPACK encoder updates");
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    if (!wtf_http3_handle_settings_exchange(stream->connection)) {
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    return WTF_FRAME_RESULT_SUCCESS;
}

static wtf_result_t wtf_http3_requeue_qpack_encoder_data(wtf_connection* conn, const uint8_t* data,
                                                         size_t length)
{
    if (!conn || !data || length == 0) {
        return WTF_SUCCESS;
    }

    wtf_result_t result = WTF_SUCCESS;
    mtx_lock(&conn->qpack.mutex);
    if (conn->qpack.tsu_buf_sz + length <= sizeof(conn->qpack.tsu_buf)) {
        memmove(conn->qpack.tsu_buf + length, conn->qpack.tsu_buf, conn->qpack.tsu_buf_sz);
        memcpy(conn->qpack.tsu_buf, data, length);
        conn->qpack.tsu_buf_sz += length;
    } else {
        result = WTF_ERROR_BUFFER_TOO_SMALL;
    }
    mtx_unlock(&conn->qpack.mutex);
    return result;
}

static wtf_result_t wtf_http3_flush_qpack_encoder_stream(wtf_connection* conn)
{
    if (!conn || !conn->context || !conn->context->quic_api) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_http3_stream* encoder_stream = NULL;
    mtx_lock(&conn->streams_mutex);
    if (conn->qpack_encoder_stream && conn->qpack_encoder_stream->quic_stream
        && conn->qpack_encoder_stream->state == WTF_INTERNAL_STREAM_STATE_OPEN) {
        encoder_stream = conn->qpack_encoder_stream;
        wtf_http3_stream_add_ref(encoder_stream);
    }
    mtx_unlock(&conn->streams_mutex);

    if (!encoder_stream) {
        return WTF_SUCCESS;
    }

    mtx_lock(&conn->qpack.mutex);
    if (!conn->qpack.initialized || conn->qpack.tsu_buf_sz == 0) {
        mtx_unlock(&conn->qpack.mutex);
        wtf_http3_stream_release(encoder_stream);
        return WTF_SUCCESS;
    }

    size_t length = conn->qpack.tsu_buf_sz;
    if (length > UINT32_MAX) {
        mtx_unlock(&conn->qpack.mutex);
        wtf_http3_stream_release(encoder_stream);
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }

    wtf_internal_send_context* send_ctx = NULL;
    uint8_t* payload = NULL;
    wtf_result_t context_result = wtf_internal_send_context_create(length, &send_ctx, &payload);
    if (context_result != WTF_SUCCESS) {
        mtx_unlock(&conn->qpack.mutex);
        wtf_http3_stream_release(encoder_stream);
        return context_result;
    }

    memcpy(payload, conn->qpack.tsu_buf, length);
    conn->qpack.tsu_buf_sz = 0;
    mtx_unlock(&conn->qpack.mutex);

    QUIC_STATUS status = conn->context->quic_api->StreamSend(
        encoder_stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1, QUIC_SEND_FLAG_NONE,
        send_ctx);

    if (QUIC_FAILED(status)) {
        wtf_result_t result = wtf_quic_status_to_result(status);
        wtf_http3_requeue_qpack_encoder_data(conn, payload, length);
        wtf_internal_send_context_destroy(send_ctx);
        wtf_http3_stream_release(encoder_stream);
        return result;
    }

    WTF_LOG_DEBUG(conn->context, "qpack", "Sent %zu bytes on QPACK encoder stream", length);
    wtf_http3_stream_release(encoder_stream);
    return WTF_SUCCESS;
}

static wtf_frame_result_t wtf_http3_process_goaway_frame(wtf_http3_stream* stream,
                                                         const uint8_t* data, size_t data_len)
{
    if (!stream || !data) {
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    // GOAWAY frames can only be sent on control streams
    if (stream->type != WTF_STREAM_TYPE_CONTROL) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "GOAWAY frame received on non-control stream %llu",
                      (unsigned long long)stream->id);
        return WTF_FRAME_RESULT_PROTOCOL_ERROR;
    }

    size_t offset = 0;
    uint64_t stream_id;

    if (!wtf_varint_decode(data_len, data, &offset, &stream_id)) {
        WTF_LOG_ERROR(stream->connection->context, "http3",
                      "Failed to decode GOAWAY stream ID");
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    WTF_LOG_INFO(stream->connection->context, "http3", "Received GOAWAY for stream ID %llu",
                 (unsigned long long)stream_id);

    stream->connection->state = WTF_CONNECTION_STATE_CLOSING;

    wtf_connection* conn = stream->connection;
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
                if (session->state == WTF_SESSION_CONNECTED) {
                    sessions[session_index++] = session;
                    session->state = WTF_SESSION_DRAINING;
                }
            }
            session_count = session_index;
        } else {
            session_count = 0;
        }
    }
    mtx_unlock(&conn->sessions_mutex);

    for (size_t i = 0; i < session_count; i++) {
        wtf_session* session = sessions[i];
        WTF_LOG_INFO(conn->context, "session", "Draining session %llu due to GOAWAY",
                     (unsigned long long)session->id);

        wtf_session_send_capsule(session, WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION, NULL, 0);

        if (session->callback) {
            wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                         .session = (wtf_session_t*)session,
                                         .user_context = session->user_context};
            session->callback(&event);
        }
    }

    free(sessions);
    return WTF_FRAME_RESULT_SUCCESS;
}

static wtf_capsule_parse_result_t wtf_http3_parse_capsule(wtf_http3_stream* stream,
                                                          const uint8_t* data, size_t length,
                                                          wtf_capsule* capsule, size_t* consumed)
{
    if (!stream || !data || !capsule || !consumed || length == 0) {
        return WTF_CAPSULE_PARSE_ERROR;
    }

    size_t offset = 0;
    *consumed = 0;

    if (!stream->capsule_header_complete) {
        bool complete = false;
        while (offset < length && stream->capsule_header_length < sizeof(stream->capsule_header)) {
            stream->capsule_header[stream->capsule_header_length++] = data[offset++];
            size_t header_offset = 0;
            if (wtf_varint_decode(stream->capsule_header_length, stream->capsule_header,
                                  &header_offset, &stream->capsule_type)
                && wtf_varint_decode(stream->capsule_header_length, stream->capsule_header,
                                     &header_offset, &stream->capsule_length)) {
                complete = true;
                break;
            }
        }
        *consumed = offset;
        if (!complete) {
            if (stream->capsule_header_length == sizeof(stream->capsule_header)) {
                return WTF_CAPSULE_PARSE_ERROR;
            }
            return WTF_CAPSULE_PARSE_NEED_MORE_DATA;
        }

        stream->capsule_header_complete = true;
        stream->capsule_bytes_read = 0;

        if (stream->capsule_length > 0) {
            if (stream->capsule_length > WTF_MAX_DATAGRAM_SIZE) {
                WTF_LOG_ERROR(stream->connection->context, "capsule",
                              "Capsule too large: %llu bytes",
                              (unsigned long long)stream->capsule_length);
                return WTF_CAPSULE_PARSE_ERROR;
            }

            if (stream->capsule_buffer && stream->capsule_buffer != stream->capsule_inline) {
                free(stream->capsule_buffer);
            }

            if (stream->capsule_length <= sizeof(stream->capsule_inline)) {
                stream->capsule_buffer = stream->capsule_inline;
            } else {
                stream->capsule_buffer = malloc((size_t)stream->capsule_length);
                if (!stream->capsule_buffer) {
                    return WTF_CAPSULE_PARSE_ERROR;
                }
            }
        }
    }

    size_t available_data = length - offset;
    size_t bytes_needed = (size_t)stream->capsule_length - stream->capsule_bytes_read;
    size_t bytes_to_copy = min(available_data, bytes_needed);

    if (bytes_to_copy > 0 && stream->capsule_buffer) {
        memcpy(stream->capsule_buffer + stream->capsule_bytes_read, data + offset, bytes_to_copy);
        stream->capsule_bytes_read += bytes_to_copy;
    }

    *consumed = offset + bytes_to_copy;

    if (stream->capsule_bytes_read >= (size_t)stream->capsule_length) {
        capsule->type = stream->capsule_type;
        capsule->length = stream->capsule_length;
        capsule->data = stream->capsule_buffer;

        stream->capsule_header_complete = false;
        stream->capsule_header_length = 0;
        stream->capsule_length = 0;
        stream->capsule_bytes_read = 0;
        stream->capsule_buffer = NULL;

        return WTF_CAPSULE_PARSE_COMPLETE;
    }

    return WTF_CAPSULE_PARSE_NEED_MORE_DATA;
}

static wtf_frame_result_t wtf_http3_process_webtransport_capsules(
    wtf_http3_stream* stream, const uint8_t* data, size_t length)
{
    if (!stream->webtransport_session
        || stream->webtransport_session->state != WTF_SESSION_CONNECTED) {
        return WTF_FRAME_RESULT_SUCCESS;
    }

    size_t offset = 0;
    while (offset < length) {
        wtf_capsule capsule;
        size_t consumed = 0;
        wtf_capsule_parse_result_t result = wtf_http3_parse_capsule(
            stream, data + offset, length - offset, &capsule, &consumed);
        if (result == WTF_CAPSULE_PARSE_ERROR || consumed == 0) {
            return WTF_FRAME_RESULT_INVALID_FRAME;
        }
        offset += consumed;
        if (result == WTF_CAPSULE_PARSE_COMPLETE) {
            bool processed = wtf_session_process_capsule(stream->webtransport_session, &capsule);
            if (capsule.data && capsule.data != stream->capsule_inline) {
                free(capsule.data);
            }
            if (!processed) {
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }
        }
    }
    return WTF_FRAME_RESULT_SUCCESS;
}

static wtf_frame_result_t wtf_http3_process_headers_frame(wtf_http3_stream* stream,
                                                          const uint8_t* data, uint32_t length,
                                                          wtf_connect_request* pending_request,
                                                          bool* has_connect_headers)
{
    // HEADERS frames should only be processed on bidirectional streams (CONNECT requests)
    if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        if (stream->connection->role == WTF_ENDPOINT_CLIENT) {
            if ((stream->flags & WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT) == 0) {
                WTF_LOG_ERROR(stream->connection->context, "http3",
                              "Unexpected response HEADERS on non-CONNECT client stream %llu",
                              (unsigned long long)stream->id);
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }

            wtf_connect_response response = {0};
            wtf_result_t parse_result = wtf_qpack_parse_response_headers(
                stream->connection->context, stream, data, length, &response);
            if (parse_result != WTF_SUCCESS) {
                return WTF_FRAME_RESULT_INVALID_FRAME;
            }

            bool processed = wtf_http3_process_connect_response(stream, &response);
            wtf_connect_response_cleanup(&response);
            return processed ? WTF_FRAME_RESULT_SUCCESS : WTF_FRAME_RESULT_PROTOCOL_ERROR;
        }

        if (!wtf_http3_connect_processing_ready(stream->connection)) {
            return wtf_http3_queue_connect_headers(stream, data, length)
                ? WTF_FRAME_RESULT_SUCCESS
                : WTF_FRAME_RESULT_PROTOCOL_ERROR;
        }

        wtf_context* ctx = stream->connection->context;
        if (wtf_qpack_parse_connect_headers(ctx, stream, data, length, pending_request)
            == WTF_SUCCESS) {
            if (has_connect_headers) {
                *has_connect_headers = true;
            }
            return WTF_FRAME_RESULT_SUCCESS;
        }
        return WTF_FRAME_RESULT_INVALID_FRAME;
    }

    WTF_LOG_ERROR(stream->connection->context, "http3",
                  "HEADERS frame received on unidirectional stream %llu",
                  (unsigned long long)stream->id);
    return WTF_FRAME_RESULT_PROTOCOL_ERROR;
}

static wtf_frame_result_t wtf_http3_process_single_frame(
    wtf_http3_stream* stream, const wtf_frame_info* frame, const uint8_t* frame_data,
    wtf_connect_request* pending_request, bool* has_connect_headers)
{
    switch (frame->type) {
        case WTF_FRAME_SETTINGS:
            // SETTINGS frames only valid on control streams
            if (stream->type != WTF_STREAM_TYPE_CONTROL) {
                WTF_LOG_ERROR(stream->connection->context, "http3",
                              "SETTINGS frame received on non-control stream %llu",
                              (unsigned long long)stream->id);
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }
            return wtf_http3_process_settings_frame(stream, frame_data, (size_t)frame->length);

        case WTF_FRAME_HEADERS: {
            wtf_frame_result_t result = wtf_http3_process_headers_frame(
                stream, frame_data, (uint32_t)frame->length, pending_request,
                has_connect_headers);
            return result;
        }

        case WTF_FRAME_DATA:
            // DATA frames only valid on bidirectional streams
            if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
                WTF_LOG_ERROR(stream->connection->context, "http3",
                              "DATA frame received on unidirectional stream %llu",
                              (unsigned long long)stream->id);
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }
            return wtf_http3_process_webtransport_capsules(stream, frame_data,
                                                            (size_t)frame->length);

        case WTF_FRAME_GOAWAY:
            // GOAWAY frames only valid on control streams
            if (stream->type == WTF_STREAM_TYPE_CONTROL) {
                return wtf_http3_process_goaway_frame(stream, frame_data, (uint32_t)frame->length);
            } else {
                WTF_LOG_ERROR(stream->connection->context, "http3",
                              "GOAWAY frame received on non-control stream %llu",
                              (unsigned long long)stream->id);
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }

        default:
            // Unknown frame types are ignored per HTTP/3 spec
            WTF_LOG_DEBUG(stream->connection->context, "http3",
                          "Ignoring unknown frame type %llu on stream %llu",
                          (unsigned long long)frame->type, (unsigned long long)stream->id);
            return WTF_FRAME_RESULT_SUCCESS;
    }
}

static wtf_frame_result_t wtf_http3_process_frames(
    wtf_http3_stream* stream, const uint8_t* data, uint32_t length, uint32_t offset,
    wtf_connect_request* pending_request, bool* has_connect_headers)
{
    size_t processed_bytes = offset;

    while (processed_bytes < length) {
        if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id) && processed_bytes == offset
            && !stream->is_webtransport) {
            wtf_varint_t signal_value;
            size_t signal_offset = processed_bytes;
            size_t signal_start = processed_bytes;

            if (wtf_varint_decode(length, data, &signal_offset, &signal_value)) {
                if (signal_value == WTF_FRAME_BIDIR_WEBTRANSPORT_STREAM) {
                    processed_bytes = signal_offset;

                    WTF_LOG_DEBUG(stream->connection->context, "webtransport",
                                  "WebTransport stream signal (0x41) detected on stream %llu",
                                  (unsigned long long)stream->id);


                    wtf_varint_t session_id;
                    size_t session_offset = processed_bytes;

                    if (wtf_varint_decode(length, data, &session_offset, &session_id)) {
                        processed_bytes = session_offset;

                        if (!wtf_http3_validate_session_id_or_shutdown(
                                stream->connection, session_id, "bidirectional stream header")) {
                            return WTF_FRAME_RESULT_SUCCESS;
                        }

                        WTF_LOG_DEBUG(stream->connection->context, "webtransport",
                                      "WebTransport stream %llu associated with session %llu",
                                      (unsigned long long)stream->id,
                                      (unsigned long long)session_id);


                        wtf_session* session = wtf_connection_find_session(stream->connection,
                                                                           session_id);
                        if (session) {
                            if (wtf_connection_associate_stream_with_session(stream->connection, stream,
                                                                             session)) {
                                stream->webtransport_session = session;
                            } else {
                                wtf_session_release(session);
                                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
                            }
                        } else {
                            WTF_LOG_WARN(stream->connection->context, "webtransport",
                                         "Rejecting WebTransport stream %llu for unknown session %llu",
                                         (unsigned long long)stream->id,
                                         (unsigned long long)session_id);
                            wtf_http3_abort_stream(stream, WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED);
                            return WTF_FRAME_RESULT_SUCCESS;
                        }

                        stream->is_webtransport = true;

                        if (processed_bytes < length) {
                            wtf_session* session = stream->webtransport_session;
                            if (session) {
                                mtx_lock(&session->streams_mutex);
                                stream_map_itr wt_itr = stream_map_get(&session->streams,
                                                                       stream->id);
                                wtf_stream* wt_stream = !stream_map_is_end(wt_itr)
                                    ? wt_itr.data->val
                                    : NULL;
                                mtx_unlock(&session->streams_mutex);

                                if (wt_stream) {
                                    wtf_emit_stream_data_event(wt_stream, data + processed_bytes,
                                                               length - processed_bytes, false);
                                }
                            }
                        }

                        return WTF_FRAME_RESULT_SUCCESS;
                    } else {
                        // Need more data to parse session ID - buffer the signal and partial
                        // session ID
                        size_t remaining = length - signal_start;
                        if (remaining > 0
                            && !wtf_http3_stream_buffer_replace(stream, data + signal_start,
                                                                remaining)) {
                            return WTF_FRAME_RESULT_PROTOCOL_ERROR;
                        }
                        break;
                    }
                }
            } else {
                // Need more data to parse signal
                size_t remaining = length - processed_bytes;
                if (remaining > 0
                    && !wtf_http3_stream_buffer_replace(stream, data + processed_bytes,
                                                        remaining)) {
                    return WTF_FRAME_RESULT_PROTOCOL_ERROR;
                }
                break;
            }
        }

        // Regular HTTP/3 frame parsing
        wtf_frame_info frame;
        size_t frame_start = processed_bytes;

        if (!wtf_http3_parse_frame_header(data, length, processed_bytes, &frame)) {
            size_t remaining = length - frame_start;
            if (remaining > 0
                && !wtf_http3_stream_buffer_replace(stream, data + frame_start, remaining)) {
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }
            break;
        }

        size_t frame_header_end = processed_bytes + frame.header_size;

        if (frame.length > SIZE_MAX - frame_header_end || frame_header_end + frame.length > length) {
            size_t remaining = length - frame_start;
            if (remaining > 0
                && !wtf_http3_stream_buffer_replace(stream, data + frame_start, remaining)) {
                return WTF_FRAME_RESULT_PROTOCOL_ERROR;
            }
            break;
        }

        wtf_frame_result_t result = wtf_http3_process_single_frame(
            stream, &frame, data + frame_header_end, pending_request, has_connect_headers);

        if (result != WTF_FRAME_RESULT_SUCCESS) {
            return result;
        }

        processed_bytes = frame_header_end + frame.length;
    }

    return WTF_FRAME_RESULT_SUCCESS;
}

static const char* wtf_http3_protocol_for_draft(wtf_webtransport_draft_t draft)
{
    return draft == WTF_WEBTRANSPORT_DRAFT_15 ? WTF_WEBTRANSPORT_PROTOCOL_DRAFT15
                                              : WTF_WEBTRANSPORT_PROTOCOL_DRAFT02;
}

static const char* wtf_http3_connect_protocol_for_connection(const wtf_connection* conn)
{
    if (!conn) {
        return WTF_WEBTRANSPORT_PROTOCOL_DRAFT15;
    }

    if (conn->role == WTF_ENDPOINT_CLIENT
        && conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_15
        && conn->requested_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_AUTO
        && conn->peer_settings.enable_webtransport_draft02) {
        return WTF_WEBTRANSPORT_PROTOCOL_DRAFT02;
    }

    return wtf_http3_protocol_for_draft(conn->selected_webtransport_draft);
}

static int wtf_http3_qpack_static_status_index(uint16_t status_code)
{
    switch (status_code) {
        case 200:
            return LSQPACK_TNV_STATUS_200;
        case 400:
            return LSQPACK_TNV_STATUS_400;
        case 403:
            return LSQPACK_TNV_STATUS_403;
        case 500:
            return LSQPACK_TNV_STATUS_500;
        case 503:
            return LSQPACK_TNV_STATUS_503;
        default:
            return -1;
    }
}

static bool wtf_http3_qpack_encode_header_field(
    wtf_connection* conn, const char* name, const char* value, uint8_t* enc_stream_buf,
    size_t enc_stream_capacity, size_t* enc_stream_total, uint8_t* header_block,
    size_t header_block_capacity, size_t qpack_prefix_len, size_t* header_payload_len)
{
    if (!conn || !name || !value || !enc_stream_buf || !enc_stream_total || !header_block
        || !header_payload_len) {
        return false;
    }

    size_t name_len = strlen(name);
    size_t value_len = strlen(value);
    if (name_len > UINT16_MAX || value_len > UINT16_MAX || name_len > SIZE_MAX - value_len) {
        return false;
    }

    size_t storage_len = name_len + value_len;
    char stack_storage[1024];
    char* header_storage = stack_storage;
    bool heap_storage = false;

    if (storage_len > sizeof(stack_storage)) {
        header_storage = malloc(storage_len);
        if (!header_storage) {
            return false;
        }
        heap_storage = true;
    }

    memcpy(header_storage, name, name_len);
    memcpy(header_storage + name_len, value, value_len);

    struct lsxpack_header header;
    memset(&header, 0, sizeof(header));
    header.buf = header_storage;
    header.name_offset = 0;
    header.name_len = (lsxpack_strlen_t)name_len;
    header.val_offset = (lsxpack_strlen_t)name_len;
    header.val_len = (lsxpack_strlen_t)value_len;

    if (*enc_stream_total > enc_stream_capacity
        || qpack_prefix_len > header_block_capacity
        || *header_payload_len > header_block_capacity - qpack_prefix_len) {
        if (heap_storage) {
            free(header_storage);
        }
        return false;
    }

    size_t enc_stream_size = enc_stream_capacity - *enc_stream_total;
    size_t block_size = header_block_capacity - qpack_prefix_len - *header_payload_len;
    enum lsqpack_enc_status status = lsqpack_enc_encode(
        &conn->qpack.encoder, enc_stream_buf + *enc_stream_total, &enc_stream_size,
        header_block + qpack_prefix_len + *header_payload_len, &block_size, &header,
        (enum lsqpack_enc_flags)0);

    if (heap_storage) {
        free(header_storage);
    }

    if (status != LQES_OK) {
        return false;
    }

    *enc_stream_total += enc_stream_size;
    *header_payload_len += block_size;
    return true;
}

static void wtf_http3_client_fail_session(wtf_http3_stream* stream, wtf_result_t result,
                                          const char* reason,
                                          const wtf_connect_response* response)
{
    if (!stream || !stream->webtransport_session) {
        return;
    }

    wtf_session* session = stream->webtransport_session;
    if (session->state == WTF_SESSION_CLOSED) {
        return;
    }

    session->state = WTF_SESSION_CLOSED;
    if (stream->connection && stream->connection->role == WTF_ENDPOINT_CLIENT) {
        wtf_client_note_session_closed(stream->connection->client);
    }
    if (session->id != UINT64_MAX && stream->connection) {
        mtx_lock(&stream->connection->sessions_mutex);
        session_map_erase(&stream->connection->sessions, session->id);
        mtx_unlock(&stream->connection->sessions_mutex);
    }

    if (session->callback) {
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_DISCONNECTED,
            .session = (wtf_session_t*)session,
            .user_context = session->user_context,
            .disconnected = {
                .error_code = (uint32_t)result,
                .reason = reason,
                .status_code = response ? response->status_code : 0,
                .headers = response ? response->headers : NULL,
                .header_count = response ? response->header_count : 0,
            },
        };
        session->callback(&event);
    }
}

static wtf_result_t wtf_http3_encode_connect_request(wtf_http3_stream* stream,
                                                     uint8_t** request_data,
                                                     uint32_t* request_length)
{
    if (!stream || !stream->connection || !stream->connection->client || !request_data
        || !request_length) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_connection* conn = stream->connection;
    wtf_client* client = conn->client;
    const wtf_client_config_t* config = &client->config;

    for (size_t i = 0; i < config->header_count; i++) {
        if (!config->headers[i].name || !config->headers[i].value
            || config->headers[i].name[0] == ':') {
            return WTF_ERROR_INVALID_PARAMETER;
        }
    }

    uint8_t header_block[4096];
    uint32_t header_block_len = 0;

    mtx_lock(&conn->qpack.mutex);
    if (!conn->qpack.initialized || lsqpack_enc_start_header(&conn->qpack.encoder, 0, stream->id)
                                      != 0) {
        mtx_unlock(&conn->qpack.mutex);
        return WTF_ERROR_INVALID_STATE;
    }

    uint8_t enc_stream_buf[512];
    size_t enc_stream_total = 0;
    size_t qpack_prefix_len = 2;
    size_t header_payload_len = 0;
    bool encode_ok = true;

    encode_ok = wtf_http3_qpack_encode_header_field(
        conn, ":method", WTF_CONNECT_METHOD, enc_stream_buf, sizeof(enc_stream_buf),
        &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
        &header_payload_len);
    encode_ok = encode_ok && wtf_http3_qpack_encode_header_field(
        conn, ":protocol", wtf_http3_connect_protocol_for_connection(conn), enc_stream_buf,
        sizeof(enc_stream_buf), &enc_stream_total, header_block, sizeof(header_block),
        qpack_prefix_len, &header_payload_len);
    encode_ok = encode_ok && wtf_http3_qpack_encode_header_field(
        conn, ":scheme", WTF_HTTPS_SCHEME, enc_stream_buf, sizeof(enc_stream_buf),
        &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
        &header_payload_len);
    encode_ok = encode_ok && wtf_http3_qpack_encode_header_field(
        conn, ":authority", client->authority, enc_stream_buf, sizeof(enc_stream_buf),
        &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
        &header_payload_len);
    encode_ok = encode_ok && wtf_http3_qpack_encode_header_field(
        conn, ":path", client->path, enc_stream_buf, sizeof(enc_stream_buf),
        &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
        &header_payload_len);

    if (encode_ok && config->origin) {
        encode_ok = wtf_http3_qpack_encode_header_field(
            conn, "origin", config->origin, enc_stream_buf, sizeof(enc_stream_buf),
            &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
            &header_payload_len);
    }

    if (encode_ok && conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_02) {
        encode_ok = wtf_http3_qpack_encode_header_field(
            conn, WTF_WEBTRANSPORT_DRAFT02_REQUEST_HEADER,
            WTF_WEBTRANSPORT_DRAFT02_REQUEST_VALUE, enc_stream_buf, sizeof(enc_stream_buf),
            &enc_stream_total, header_block, sizeof(header_block), qpack_prefix_len,
            &header_payload_len);
    }

    for (size_t i = 0; encode_ok && i < config->header_count; i++) {
        encode_ok = wtf_http3_qpack_encode_header_field(
            conn, config->headers[i].name, config->headers[i].value, enc_stream_buf,
            sizeof(enc_stream_buf), &enc_stream_total, header_block, sizeof(header_block),
            qpack_prefix_len, &header_payload_len);
    }

    if (encode_ok) {
        enum lsqpack_enc_header_flags hflags;
        ssize_t pref_sz = lsqpack_enc_end_header(&conn->qpack.encoder, header_block,
                                                qpack_prefix_len, &hflags);
        if (pref_sz >= 0) {
            header_block_len = (uint32_t)(pref_sz + header_payload_len);
            if (enc_stream_total > 0 && enc_stream_total <= sizeof(enc_stream_buf)
                && conn->qpack.tsu_buf_sz + enc_stream_total <= sizeof(conn->qpack.tsu_buf)) {
                memcpy(conn->qpack.tsu_buf + conn->qpack.tsu_buf_sz, enc_stream_buf,
                       enc_stream_total);
                conn->qpack.tsu_buf_sz += enc_stream_total;
            } else if (enc_stream_total > 0) {
                encode_ok = false;
            }
        } else {
            encode_ok = false;
        }
    }

    mtx_unlock(&conn->qpack.mutex);

    if (!encode_ok || header_block_len == 0) {
        return WTF_ERROR_INTERNAL;
    }

    wtf_result_t flush_result = wtf_http3_flush_qpack_encoder_stream(conn);
    if (flush_result != WTF_SUCCESS) {
        return flush_result;
    }

    size_t frame_len = wtf_varint_size(WTF_FRAME_HEADERS) + wtf_varint_size(header_block_len)
        + header_block_len;
    uint8_t* data = malloc(frame_len);
    if (!data) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* current = data;
    current = wtf_varint_encode(WTF_FRAME_HEADERS, current);
    current = wtf_varint_encode(header_block_len, current);
    memcpy(current, header_block, header_block_len);
    current += header_block_len;

    *request_data = data;
    *request_length = (uint32_t)(current - data);
    return WTF_SUCCESS;
}

static bool wtf_http3_client_create_session_for_stream(wtf_http3_stream* stream)
{
    if (!stream || !stream->connection || !stream->connection->client) {
        return false;
    }

    wtf_connection* conn = stream->connection;
    wtf_session* session = stream->webtransport_session;
    if (!session) {
        session = wtf_session_create(conn, stream);
        if (!session) {
            return false;
        }

        session->callback = conn->session_callback;
        session->user_context = conn->user_context;
        stream->webtransport_session = session;
        wtf_session_add_ref(session);
    }

    if (stream->id == UINT64_MAX) {
        return false;
    }

    session->id = stream->id;
    session->connect_stream = stream;

    mtx_lock(&conn->sessions_mutex);
    session_map_itr existing = session_map_get(&conn->sessions, session->id);
    if (!session_map_is_end(existing)) {
        mtx_unlock(&conn->sessions_mutex);
        return existing.data->val == session;
    }

    session_map_itr itr = session_map_insert(&conn->sessions, session->id, session);
    if (session_map_is_end(itr)) {
        mtx_unlock(&conn->sessions_mutex);
        return false;
    }
    mtx_unlock(&conn->sessions_mutex);
    return true;
}

wtf_result_t wtf_http3_client_open_session(wtf_client* client, wtf_session** out_session)
{
    if (!client || !out_session) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *out_session = NULL;

    mtx_lock(&client->mutex);
    wtf_connection* conn = client->connection;
    if (!conn || client->state == WTF_CLIENT_CLOSING || client->state == WTF_CLIENT_CLOSED) {
        mtx_unlock(&client->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    if (!client->config.allow_pooling && client->opened_session_count > 0) {
        mtx_unlock(&client->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    if (client->opened_session_count >= conn->max_sessions) {
        mtx_unlock(&client->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    client->opened_session_count++;
    mtx_unlock(&client->mutex);

    wtf_http3_stream* stream = wtf_http3_stream_create(conn, NULL, UINT64_MAX);
    if (!stream) {
        mtx_lock(&client->mutex);
        if (client->opened_session_count > 0) {
            client->opened_session_count--;
        }
        mtx_unlock(&client->mutex);
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    stream->flags |= WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT;

    wtf_session* session = wtf_session_create(conn, stream);
    if (!session) {
        wtf_http3_stream_destroy(stream);
        mtx_lock(&client->mutex);
        if (client->opened_session_count > 0) {
            client->opened_session_count--;
        }
        mtx_unlock(&client->mutex);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    session->callback = conn->session_callback;
    session->user_context = conn->user_context;
    stream->webtransport_session = session;
    wtf_session_add_ref(session);

    bool ready = false;
    mtx_lock(&client->mutex);
    ready = (client->flags & WTF_CLIENT_FLAG_TRANSPORT_READY) != 0;
    if (!ready) {
        stream->next_client_pending_connect = NULL;
        if (client->pending_connect_tail) {
            client->pending_connect_tail->next_client_pending_connect = stream;
        } else {
            client->pending_connect_head = stream;
        }
        client->pending_connect_tail = stream;
        client->pending_connect_count++;
    }
    mtx_unlock(&client->mutex);

    if (ready && !wtf_http3_client_start_connect_stream(stream)) {
        wtf_http3_client_fail_session(stream, WTF_ERROR_INTERNAL, "Failed to start CONNECT stream",
                                      NULL);
        wtf_http3_stream_destroy(stream);
        return WTF_ERROR_INTERNAL;
    }

    wtf_session_add_ref(session);
    *out_session = session;
    return WTF_SUCCESS;
}

static wtf_result_t wtf_http3_client_send_connect_request(wtf_http3_stream* stream)
{
    if (!stream || !stream->connection || !stream->quic_stream) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    if (!wtf_http3_client_create_session_for_stream(stream)) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* request_data = NULL;
    uint32_t request_length = 0;
    wtf_result_t encode_result = wtf_http3_encode_connect_request(
        stream, &request_data, &request_length);
    if (encode_result != WTF_SUCCESS) {
        return encode_result;
    }

    wtf_internal_send_context* send_ctx = NULL;
    wtf_result_t context_result = wtf_internal_send_context_take_buffer(
        request_data, request_length, &send_ctx);
    if (context_result != WTF_SUCCESS) {
        return context_result;
    }

    QUIC_STATUS quic_status = stream->connection->context->quic_api->StreamSend(
        stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1, QUIC_SEND_FLAG_NONE, send_ctx);
    if (QUIC_FAILED(quic_status)) {
        wtf_internal_send_context_destroy(send_ctx);
        return wtf_quic_status_to_result(quic_status);
    }

    stream->flags |= WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT_SENT;
    WTF_LOG_INFO(stream->connection->context, "connect",
                 "Client CONNECT sent on stream %llu using draft-%02u",
                 (unsigned long long)stream->id,
                 (unsigned)stream->connection->selected_webtransport_draft);
    return WTF_SUCCESS;
}

static bool wtf_http3_client_start_connect_stream(wtf_http3_stream* stream)
{
    if (!stream || !stream->connection || !stream->connection->client) {
        return false;
    }

    wtf_connection* conn = stream->connection;
    HQUIC quic_stream = NULL;
    QUIC_STATUS status = conn->context->quic_api->StreamOpen(
        conn->quic_connection, QUIC_STREAM_OPEN_FLAG_NONE, wtf_http3_stream_callback, stream,
        &quic_stream);
    if (QUIC_FAILED(status)) {
        wtf_result_t result = wtf_quic_status_to_result(status);
        WTF_LOG_ERROR(conn->context, "connect", "Client CONNECT StreamOpen failed: 0x%x", status);
        wtf_http3_client_fail_session(stream, result, "CONNECT StreamOpen failed", NULL);
        return false;
    }

    stream->quic_stream = quic_stream;

    status = conn->context->quic_api->StreamStart(quic_stream, QUIC_STREAM_START_FLAG_NONE);
    if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
        wtf_result_t result = wtf_quic_status_to_result(status);
        WTF_LOG_ERROR(conn->context, "connect", "Client CONNECT StreamStart failed: 0x%x",
                      status);
        wtf_http3_client_fail_session(stream, result, "CONNECT StreamStart failed", NULL);
        return false;
    }

    return true;
}

bool wtf_http3_client_drain_pending_connects(wtf_connection* conn)
{
    if (!conn || !conn->client) {
        return false;
    }

    wtf_client* client = conn->client;
    wtf_http3_stream* head = NULL;

    mtx_lock(&client->mutex);
    head = client->pending_connect_head;
    client->pending_connect_head = NULL;
    client->pending_connect_tail = NULL;
    client->pending_connect_count = 0;
    mtx_unlock(&client->mutex);

    while (head) {
        wtf_http3_stream* next = head->next_client_pending_connect;
        head->next_client_pending_connect = NULL;
        if (!wtf_http3_client_start_connect_stream(head)) {
            wtf_http3_stream_destroy(head);
        }
        head = next;
    }

    return true;
}

static bool wtf_http3_process_connect_response(wtf_http3_stream* stream,
                                               wtf_connect_response* response)
{
    if (!stream || !stream->connection || !stream->connection->client || !response
        || !stream->webtransport_session) {
        return false;
    }

    wtf_connection* conn = stream->connection;
    if (!response->valid) {
        wtf_http3_client_fail_session(stream, WTF_ERROR_PROTOCOL_VIOLATION,
                                      "Invalid CONNECT response", response);
        return false;
    }

    if (response->status_code < 200 || response->status_code > 299) {
        WTF_LOG_WARN(conn->context, "connect", "WebTransport CONNECT rejected: HTTP %u",
                     response->status_code);
        wtf_http3_client_fail_session(stream, WTF_ERROR_REJECTED, "CONNECT rejected", response);
        return true;
    }

    if (conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_02
        && (!response->draft_header
            || strcmp(response->draft_header, WTF_WEBTRANSPORT_DRAFT02_RESPONSE_VALUE) != 0)) {
        WTF_LOG_ERROR(conn->context, "connect",
                      "Draft-02 CONNECT response missing selected draft header");
        wtf_http3_client_fail_session(stream, WTF_ERROR_PROTOCOL_VIOLATION,
                                      "Invalid draft-02 CONNECT response", response);
        return true;
    }

    if (wtf_session_establish(stream, response) != WTF_SUCCESS) {
        wtf_http3_client_fail_session(stream, WTF_ERROR_INTERNAL, "Failed to establish session",
                                      response);
        return false;
    }

    return true;
}

static wtf_result_t wtf_http3_encode_response(wtf_http3_stream* stream, uint16_t status_code,
                                              const wtf_connection_response_t* response,
                                              uint8_t** response_data, uint32_t* response_length)
{
    if (!stream || !stream->connection || !response_data || !response_length || status_code < 100
        || status_code > 599) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_connection* conn = stream->connection;
    uint32_t max_response_size = WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES + 1024;
    uint8_t* data = malloc(max_response_size);
    if (!data) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    uint8_t* current_pos = data;
    current_pos = wtf_varint_encode(WTF_FRAME_HEADERS, current_pos);

    uint8_t header_data[WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES + 512];
    uint32_t header_data_len = 0;
    bool encode_ok = false;

    if (conn->qpack.initialized) {
        mtx_lock(&conn->qpack.mutex);
        char status_value[4];
        snprintf(status_value, sizeof(status_value), "%u", status_code);

        typedef struct {
            const char* name;
            const char* value;
        } wtf_response_header;
        wtf_response_header response_headers[2 + WTF_MAX_CONNECT_RESPONSE_HEADERS] = {
            {":status", status_value},
        };
        size_t response_header_count = 1;

        if (conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_02) {
            response_headers[response_header_count++] = (wtf_response_header){
                WTF_WEBTRANSPORT_DRAFT02_RESPONSE_HEADER,
                WTF_WEBTRANSPORT_DRAFT02_RESPONSE_VALUE,
            };
        }

        bool headers_valid = true;
        if (response) {
            for (size_t i = 0; i < response->header_count; i++) {
                if (!response->headers[i].name || !response->headers[i].value
                    || response->headers[i].name[0] == ':'
                    || response_header_count >= ARRAYSIZE(response_headers)) {
                    headers_valid = false;
                    break;
                }
                response_headers[response_header_count++] = (wtf_response_header){
                    response->headers[i].name,
                    response->headers[i].value,
                };
            }
        }

        if (headers_valid && lsqpack_enc_start_header(&conn->qpack.encoder, 0, stream->id) == 0) {
            uint8_t enc_stream_buf[WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES];
            size_t enc_stream_total = 0;
            size_t qpack_prefix_len = 2;
            size_t header_block_len = 0;
            encode_ok = true;

            for (size_t i = 0; i < response_header_count; i++) {
                const char* name = response_headers[i].name;
                const char* value = response_headers[i].value;
                size_t name_len = strlen(name);
                size_t value_len = strlen(value);
                char header_buf[1024];

                if (name_len + value_len > sizeof(header_buf)) {
                    encode_ok = false;
                    break;
                }

                struct lsxpack_header header;
                memset(&header, 0, sizeof(header));
                header.buf = header_buf;
                header.name_offset = 0;
                header.name_len = (lsxpack_strlen_t)name_len;
                header.val_offset = (lsxpack_strlen_t)name_len;
                header.val_len = (lsxpack_strlen_t)value_len;
                memcpy(header.buf, name, name_len);
                memcpy(header.buf + name_len, value, value_len);
                if (strcmp(name, ":status") == 0) {
                    int static_index = wtf_http3_qpack_static_status_index(status_code);
                    if (static_index >= 0) {
                        header.qpack_index = (uint8_t)static_index;
                        header.flags = (enum lsxpack_flag)(
                            header.flags | LSXPACK_QPACK_IDX | LSXPACK_VAL_MATCHED);
                    }
                }

                size_t enc_stream_size = sizeof(enc_stream_buf) - enc_stream_total;
                size_t header_len = sizeof(header_data) - qpack_prefix_len - header_block_len;
                if (lsqpack_enc_encode(&conn->qpack.encoder, enc_stream_buf + enc_stream_total,
                                       &enc_stream_size,
                                       header_data + qpack_prefix_len + header_block_len,
                                       &header_len, &header, (enum lsqpack_enc_flags)0)
                    != LQES_OK) {
                    encode_ok = false;
                    break;
                }

                enc_stream_total += enc_stream_size;
                header_block_len += header_len;
            }

            if (encode_ok) {
                enum lsqpack_enc_header_flags hflags;
                ssize_t pref_sz = lsqpack_enc_end_header(&conn->qpack.encoder, header_data,
                                                        qpack_prefix_len, &hflags);
                if (pref_sz >= 0) {
                    header_data_len = (uint32_t)(pref_sz + header_block_len);
                    if (enc_stream_total > 0 && enc_stream_total <= sizeof(enc_stream_buf)) {
                        if (conn->qpack.tsu_buf_sz + enc_stream_total
                            <= sizeof(conn->qpack.tsu_buf)) {
                            memcpy(conn->qpack.tsu_buf + conn->qpack.tsu_buf_sz, enc_stream_buf,
                                   enc_stream_total);
                            conn->qpack.tsu_buf_sz += enc_stream_total;
                        } else {
                            encode_ok = false;
                        }
                    }
                } else {
                    encode_ok = false;
                }
            }
        }
        mtx_unlock(&conn->qpack.mutex);
    }

    if (!encode_ok || header_data_len == 0) {
        free(data);
        return WTF_ERROR_INTERNAL;
    }

    wtf_result_t flush_result = wtf_http3_flush_qpack_encoder_stream(conn);
    if (flush_result != WTF_SUCCESS) {
        free(data);
        return flush_result;
    }

    current_pos = wtf_varint_encode(header_data_len, current_pos);

    if (current_pos - data + header_data_len > max_response_size) {
        free(data);
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }

    memcpy(current_pos, header_data, header_data_len);
    current_pos += header_data_len;

    *response_data = data;
    *response_length = (uint32_t)(current_pos - data);
    return WTF_SUCCESS;
}

static wtf_result_t wtf_http3_send_response(wtf_http3_stream* stream, uint16_t status_code,
                                            const wtf_connection_response_t* response)
{
    if (!stream || !stream->connection) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* response_data = NULL;
    uint32_t response_length = 0;

    wtf_result_t encode_result = wtf_http3_encode_response(
        stream, status_code, response, &response_data, &response_length);
    if (encode_result != WTF_SUCCESS) {
        WTF_LOG_ERROR(stream->connection->context, "connect",
                      "Failed to encode status code %u", status_code);
        return encode_result;
    }

    wtf_internal_send_context* send_ctx = NULL;
    wtf_result_t context_result = wtf_internal_send_context_take_buffer(
        response_data, response_length, &send_ctx);
    if (context_result != WTF_SUCCESS) {
        return context_result;
    }

    QUIC_STATUS quic_status = stream->connection->context->quic_api->StreamSend(
        stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1, QUIC_SEND_FLAG_NONE, send_ctx);

    if (QUIC_FAILED(quic_status)) {
        WTF_LOG_ERROR(stream->connection->context, "connect", "StreamSend failed: 0x%x",
                      quic_status);
        wtf_internal_send_context_destroy(send_ctx);
        return wtf_quic_status_to_result(quic_status);
    }

    return WTF_SUCCESS;
}

static wtf_result_t wtf_session_establish(wtf_http3_stream* stream,
                                          const wtf_connect_response* response)
{
    if (!stream || !stream->webtransport_session) {
        return WTF_ERROR_INVALID_STATE;
    }

    wtf_session* session = stream->webtransport_session;
    session->state = WTF_SESSION_CONNECTED;
    session->id = stream->id;

    WTF_LOG_INFO(stream->connection->context, "webtransport",
                 "WebTransport session %llu established on CONNECT stream %llu",
                 (unsigned long long)session->id, (unsigned long long)stream->id);

    if (session->callback) {
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_CONNECTED,
            .session = (wtf_session_t*)session,
            .user_context = session->user_context,
            .connected = {
                .status_code = response ? response->status_code : 0,
                .headers = response ? response->headers : NULL,
                .header_count = response ? response->header_count : 0,
            },
        };
        session->callback(&event);
    }

    return WTF_SUCCESS;
}

static wtf_result_t wtf_http3_finish_connect_request(
    wtf_http3_stream* stream, wtf_connection_decision_t decision,
    const wtf_connection_response_t* response)
{
    if (!stream || !stream->connection || decision == WTF_CONNECTION_DEFER) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_connection* conn = stream->connection;
    if (decision == WTF_CONNECTION_REJECT) {
        WTF_LOG_INFO(conn->context, "connect", "Connection rejected by validator");
        return wtf_http3_send_response(stream, 403, response);
    }
    if (decision != WTF_CONNECTION_ACCEPT) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_session* session = wtf_session_create(conn, stream);
    if (!session) {
        WTF_LOG_ERROR(conn->context, "connect", "Failed to allocate session");
        return wtf_http3_send_response(stream, 500, NULL);
    }

    session->id = stream->id;
    session->callback = conn->session_callback;
    session->user_context = conn->user_context;

    mtx_lock(&conn->sessions_mutex);
    session_map_itr itr = session_map_insert(&conn->sessions, session->id, session);
    if (session_map_is_end(itr)) {
        mtx_unlock(&conn->sessions_mutex);
        WTF_LOG_ERROR(conn->context, "connect", "Failed to add session to map");
        wtf_session_destroy(session);
        return wtf_http3_send_response(stream, 500, NULL);
    }
    mtx_unlock(&conn->sessions_mutex);

    stream->webtransport_session = session;
    wtf_session_add_ref(session);

    wtf_result_t response_result = wtf_http3_send_response(stream, 200, response);
    if (response_result != WTF_SUCCESS) {
        WTF_LOG_ERROR(conn->context, "connect", "Failed to send CONNECT response");
        mtx_lock(&conn->sessions_mutex);
        session_map_erase(&conn->sessions, session->id);
        mtx_unlock(&conn->sessions_mutex);
        stream->webtransport_session = NULL;
        wtf_session_release(session);
        wtf_session_destroy(session);
        return response_result;
    }

    wtf_result_t establish_result = wtf_session_establish(stream, NULL);
    if (establish_result == WTF_SUCCESS) {
        WTF_LOG_INFO(conn->context, "connect", "WebTransport session established");
    }
    return establish_result;
}

static bool wtf_http3_process_complete_connect_request(wtf_http3_stream* stream,
                                                       wtf_connect_request* request)
{
    if (!stream || !request) {
        return false;
    }

    wtf_connection* conn = stream->connection;
    bool success = false;

    WTF_LOG_INFO(conn->context, "connect",
                 "Processing complete CONNECT request on stream %llu",
                 (unsigned long long)stream->id);

    if (!wtf_http3_connect_processing_ready(conn)) {
        WTF_LOG_ERROR(conn->context, "connect",
                      "CONNECT request processed before WebTransport negotiation completed");
        wtf_http3_send_response(stream, 503, NULL);
        goto cleanup;
    }

    if (!request->valid) {
        WTF_LOG_ERROR(conn->context, "connect", "Invalid CONNECT request");
        wtf_http3_send_response(stream, 400, NULL);
        goto cleanup;
    }

    if (!request->method || strcmp(request->method, WTF_CONNECT_METHOD) != 0
        || !wtf_http3_is_supported_webtransport_protocol(request->protocol)
        || !wtf_http3_protocol_matches_selected_draft(conn, request->protocol) || !request->scheme
        || strcmp(request->scheme, WTF_HTTPS_SCHEME) != 0 || !request->authority
        || request->authority[0] == '\0' || !request->path || request->path[0] == '\0') {
        WTF_LOG_ERROR(conn->context, "connect", "Invalid CONNECT request");
        wtf_http3_send_response(stream, 400, NULL);
        goto cleanup;
    }

    if (conn->selected_webtransport_draft == WTF_WEBTRANSPORT_DRAFT_02 && !request->origin) {
        WTF_LOG_ERROR(conn->context, "connect",
                      "Draft-02 WebTransport CONNECT request missing Origin");
        wtf_http3_send_response(stream, 400, NULL);
        goto cleanup;
    }

    WTF_LOG_INFO(conn->context, "connect",
                 "Valid WebTransport CONNECT request received using :protocol=%s",
                 request->protocol);

    wtf_connection_request_handle* handle = wtf_connection_request_handle_create(stream);
    if (!handle) {
        WTF_LOG_ERROR(conn->context, "connect", "Failed to allocate validation handle");
        wtf_http3_send_response(stream, 500, NULL);
        goto cleanup;
    }

    wtf_connection_decision_t decision = WTF_CONNECTION_ACCEPT;
    if (request->origin && !conn->connection_validator) {
        WTF_LOG_ERROR(conn->context, "connect",
                      "Origin present but no connection validator is configured");
        decision = WTF_CONNECTION_REJECT;
    } else if (conn->connection_validator) {
        wtf_connection_request_t conn_request = {
            .origin = request->origin,
            .path = request->path,
            .authority = request->authority,
            .headers = request->headers,
            .header_count = request->header_count,
            .peer_address = &conn->peer_address,
            .address_length = sizeof(conn->peer_address),
            .handle = handle};

        decision = conn->connection_validator(&conn_request, &handle->response,
                                              conn->user_context);
    }

    if (decision == WTF_CONNECTION_DEFER) {
        success = true;
        goto cleanup;
    }

    wtf_result_t finish_result = wtf_http3_finish_connect_request(
        stream, decision, &handle->response);
    wtf_connection_request_unref(handle);
    if (finish_result == WTF_SUCCESS) {
        success = true;
    }

cleanup:
    wtf_connect_request_cleanup(request);

    return success;
}

static bool wtf_http3_parse_uni_stream_type(wtf_http3_stream* stream, const uint8_t* data,
                                            size_t length, uint32_t* offset)
{
    if (stream->type != 0)
        return true;

    wtf_varint_t stream_type;
    size_t type_offset = *offset;

    if (!wtf_varint_decode(length, data, &type_offset, &stream_type)) {
        if (!wtf_http3_stream_buffer_replace(stream, data, length)) {
            return false;
        }
        *offset = (uint32_t)length;
        return true;
    }

    stream->type = stream_type;
    *offset = type_offset;

    switch (stream_type) {
        case WTF_STREAM_TYPE_CONTROL:
            stream->connection->peer_control_stream = stream;
            WTF_LOG_INFO(stream->connection->context, "http3",
                         "Peer control stream identified: %llu", (unsigned long long)stream->id);
            break;
        case WTF_STREAM_TYPE_QPACK_ENCODER:
            stream->connection->peer_encoder_stream = stream;
            WTF_LOG_DEBUG(stream->connection->context, "http3",
                          "Peer QPACK encoder stream identified: %llu",
                          (unsigned long long)stream->id);
            break;
        case WTF_STREAM_TYPE_QPACK_DECODER:
            stream->connection->peer_decoder_stream = stream;
            WTF_LOG_DEBUG(stream->connection->context, "http3",
                          "Peer QPACK decoder stream identified: %llu",
                          (unsigned long long)stream->id);
            break;
        case WTF_STREAM_TYPE_UNI_WEBTRANSPORT_STREAM:
            stream->is_webtransport = true;
            WTF_LOG_DEBUG(stream->connection->context, "http3",
                          "WebTransport unidirectional stream identified: %llu",
                          (unsigned long long)stream->id);
            break;
        default:
            WTF_LOG_DEBUG(stream->connection->context, "http3",
                          "Unknown unidirectional stream type %llu on stream %llu",
                          (unsigned long long)stream_type, (unsigned long long)stream->id);
            break;
    }
    return true;
}

static bool wtf_http3_use_buffered_stream_data(wtf_http3_stream* stream, const uint8_t** data,
                                               uint32_t* length)
{
    if (stream->buffered_data_length == 0) {
        return true;
    }

    if (stream->buffered_data_length > SIZE_MAX - *length) {
        return false;
    }

    size_t combined_length = stream->buffered_data_length + *length;
    if (combined_length > UINT32_MAX) {
        return false;
    }

    if (!wtf_http3_stream_buffer_append(stream, *data, *length)) {
        return false;
    }

    *data = stream->buffered_data;
    *length = (uint32_t)combined_length;
    stream->buffered_data_length = 0;
    return true;
}

static bool wtf_emit_stream_data_event(wtf_stream* stream, const uint8_t* data, size_t length,
                                       bool fin)
{
    if (!stream || (!data && length > 0))
        return false;
    if (length > UINT32_MAX)
        return false;

    wtf_buffer_t receive_buffer = {.length = (uint32_t)length, .data = data};
    return wtf_stream_deliver_received(stream, length > 0 ? &receive_buffer : NULL,
                                       length > 0 ? 1 : 0, length, fin);
}

static bool wtf_associate_webtransport_session(wtf_http3_stream* stream, const uint8_t* data,
                                               uint32_t length, uint32_t* offset)
{
    if (stream->webtransport_session) {
        return true;
    }

    wtf_varint_t session_id;
    size_t session_offset = *offset;

    if (!wtf_varint_decode(length, data, &session_offset, &session_id)) {
        // Buffer incomplete data
        size_t remaining = length - *offset;
        if (remaining > 0
            && !wtf_http3_stream_buffer_replace(stream, data + *offset, remaining)) {
            return false;
        }
        return true;
    }

    *offset = session_offset;

    if (!wtf_http3_validate_session_id_or_shutdown(stream->connection, session_id,
                                                   "unidirectional stream header")) {
        return true;
    }

    wtf_session* session = wtf_connection_find_session(stream->connection, session_id);
    if (!session) {
        WTF_LOG_WARN(stream->connection->context, "webtransport",
                     "Rejecting WebTransport stream %llu for unknown session %llu",
                     (unsigned long long)stream->id, (unsigned long long)session_id);
        wtf_http3_abort_stream(stream, WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED);
        return true;
    }

    if (!wtf_connection_associate_stream_with_session(stream->connection, stream, session)) {
        wtf_session_release(session);
        return false;
    }

    stream->webtransport_session = session;
    return true;
}

static bool wtf_process_webtransport_stream_data(wtf_http3_stream* stream, const uint8_t* data,
                                                 uint32_t length, uint32_t* offset, bool fin)
{
    // Check if this is a WebTransport stream
    bool is_webtransport_stream = false;

    if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        is_webtransport_stream = (stream->type == WTF_STREAM_TYPE_UNI_WEBTRANSPORT_STREAM);
    } else {
        is_webtransport_stream = (stream->is_webtransport && stream->webtransport_session);
    }

    if (!is_webtransport_stream) {
        return false;
    }

    // For bidirectional WebTransport streams
    if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        if ((*offset < length || fin) && stream->webtransport_session) {
            wtf_session* session = stream->webtransport_session;
            mtx_lock(&session->streams_mutex);
            stream_map_itr wt_itr = stream_map_get(&session->streams, stream->id);
            wtf_stream* wt_stream = !stream_map_is_end(wt_itr) ? wt_itr.data->val : NULL;
            mtx_unlock(&session->streams_mutex);

            if (wt_stream) {
                return wtf_emit_stream_data_event(wt_stream, data + *offset, length - *offset, fin);
            }
        }
        return true;
    }

    // For unidirectional WebTransport streams, need to associate with session first
    if (!wtf_associate_webtransport_session(stream, data, length, offset)) {
        return false;
    }

    if ((*offset < length || fin) && stream->webtransport_session) {
        wtf_session* session = stream->webtransport_session;
        mtx_lock(&session->streams_mutex);
        stream_map_itr wt_itr = stream_map_get(&session->streams, stream->id);
        wtf_stream* wt_stream = !stream_map_is_end(wt_itr) ? wt_itr.data->val : NULL;
        mtx_unlock(&session->streams_mutex);

        if (wt_stream) {
            return wtf_emit_stream_data_event(wt_stream, data + *offset, length - *offset, fin);
        }
    }

    return true;
}

static bool wtf_http3_process_qpack_data(wtf_http3_stream* stream, const uint8_t* data,
                                         uint32_t length, uint32_t offset)
{
    wtf_context* context = stream->connection->context;
    wtf_qpack_context* qpack_context = &stream->connection->qpack;

    if (stream->type == WTF_STREAM_TYPE_QPACK_ENCODER && offset < length) {
        return wtf_qpack_process_encoder(context, qpack_context, data + offset, length - offset);
    } else if (stream->type == WTF_STREAM_TYPE_QPACK_DECODER && offset < length) {
        return wtf_qpack_process_decoder(context, qpack_context, data + offset, length - offset);
    }

    return true;
}

static bool wtf_http3_should_process_frames(wtf_http3_stream* stream)
{
    if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        // Only control streams process HTTP/3 frames on unidirectional streams
        return (stream->type == WTF_STREAM_TYPE_CONTROL);
    } else {
        // Only non-WebTransport bidirectional streams process HTTP/3 frames
        return !stream->is_webtransport;
    }
}

static bool wtf_http3_process_stream_receive(wtf_http3_stream* stream, const QUIC_BUFFER* buffer,
                                             bool fin)
{
    const uint8_t* data = buffer->Buffer;
    uint32_t length = buffer->Length;
    uint32_t offset = 0;

    if (!data || length == 0) {
        if (fin) {
            static const uint8_t empty_data = 0;
            const uint8_t* fin_data = data ? data : &empty_data;
            return wtf_process_webtransport_stream_data(stream, fin_data, 0, &offset, true);
        }
        return true;
    }

    // Continue parsing from the stream's reusable fragment buffer when prior data was incomplete.
    if (!wtf_http3_use_buffered_stream_data(stream, &data, &length)) {
        return false;
    }

    // Handle unidirectional stream type parsing
    if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        if (!wtf_http3_parse_uni_stream_type(stream, data, length, &offset)) {
            return false;  // Need more data
        }

        // Process QPACK streams (these are infrastructure, not user-visible)
        if (!wtf_http3_process_qpack_data(stream, data, length, offset)) {
            return false;
        }

        // QPACK streams are fully handled above, don't process further
        if (stream->type == WTF_STREAM_TYPE_QPACK_ENCODER
            || stream->type == WTF_STREAM_TYPE_QPACK_DECODER) {
            return true;
        }
    }

    // Handle WebTransport stream data (user-visible streams)
    if (wtf_process_webtransport_stream_data(stream, data, length, &offset, fin)) {
        return true;
    }

    // Process HTTP/3 frames (only on appropriate streams)
    if (!wtf_http3_should_process_frames(stream)) {
        return true;
    }

    wtf_connect_request pending_connect_request = {0};
    bool has_connect_headers = false;

    wtf_frame_result_t frame_result = wtf_http3_process_frames(
        stream, data, length, offset, &pending_connect_request, &has_connect_headers);

    if (frame_result != WTF_FRAME_RESULT_SUCCESS) {
        // Clean up pending request on error
        wtf_connect_request_cleanup(&pending_connect_request);
        return false;
    }

    // Process complete CONNECT requests (creates user-visible sessions)
    if (has_connect_headers) {
        return wtf_http3_process_complete_connect_request(stream, &pending_connect_request);
    }

    wtf_connect_request_cleanup(&pending_connect_request);
    return true;
}

static QUIC_STATUS wtf_handle_stream_start_complete(wtf_http3_stream* stream,
                                                    QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->connection;

    WTF_LOG_DEBUG(conn->context, "stream", "Stream start complete, status=0x%x",
                  Event->START_COMPLETE.Status);

    if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
        WTF_LOG_ERROR(conn->context, "stream", "Stream start failed: 0x%x",
                      Event->START_COMPLETE.Status);
        return QUIC_STATUS_SUCCESS;
    }

    stream->id = Event->START_COMPLETE.ID;
    stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;

    // Add to connection stream map
    mtx_lock(&conn->streams_mutex);
    http3_stream_map_itr itr = http3_stream_map_insert(&conn->streams, stream->id, stream);
    if (http3_stream_map_is_end(itr)) {
        WTF_LOG_ERROR(conn->context, "stream",
                      "Failed to add stream to map after START_COMPLETE");
    } else {
        wtf_http3_stream_add_ref(stream);
    }
    mtx_unlock(&conn->streams_mutex);

    WTF_LOG_INFO(conn->context, "stream", "Stream ID ready: %llu, type: %llu",
                 (unsigned long long)stream->id, (unsigned long long)stream->type);

    if ((stream->flags & WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT) != 0
        && (stream->flags & WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT_SENT) == 0) {
        wtf_result_t result = wtf_http3_client_send_connect_request(stream);
        if (result != WTF_SUCCESS) {
            WTF_LOG_ERROR(conn->context, "connect", "Failed to send client CONNECT: %s",
                          wtf_result_to_string(result));
            wtf_http3_client_fail_session(stream, result, "Failed to send CONNECT", NULL);
            if (stream->quic_stream) {
                conn->context->quic_api->StreamShutdown(
                    stream->quic_stream,
                    QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                    WTF_H3_INTERNAL_ERROR);
            }
        }
        return QUIC_STATUS_SUCCESS;
    }

    // Send stream type for infrastructure streams (not user-visible)
    if (stream->type == WTF_STREAM_TYPE_CONTROL || stream->type == WTF_STREAM_TYPE_QPACK_ENCODER
        || stream->type == WTF_STREAM_TYPE_QPACK_DECODER) {
        uint8_t data[16];
        uint8_t* current_pos = data;
        uint8_t* buffer_end = data + sizeof(data);

        // Encode stream type
        current_pos = wtf_varint_encode(stream->type, current_pos);
        if (current_pos > buffer_end) {
            WTF_LOG_ERROR(conn->context, "stream", "Failed to encode stream type");
            conn->context->quic_api->StreamShutdown(
                stream->quic_stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                WTF_H3_FRAME_ERROR);
            return QUIC_STATUS_SUCCESS;
        }

        if (stream->type == WTF_STREAM_TYPE_CONTROL) {
            WTF_LOG_INFO(conn->context, "http3",
                         "Control stream ready - sending server SETTINGS");
        }

        wtf_internal_send_context* send_ctx = NULL;
        wtf_result_t context_result = wtf_internal_send_context_create_copy(
            data, (size_t)(current_pos - data), &send_ctx);
        if (context_result != WTF_SUCCESS) {
            WTF_LOG_ERROR(conn->context, "stream", "Failed to allocate stream type send context");
            conn->context->quic_api->StreamShutdown(
                stream->quic_stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                WTF_H3_FRAME_ERROR);
            return QUIC_STATUS_SUCCESS;
        }

        QUIC_STATUS status = conn->context->quic_api->StreamSend(
            stream->quic_stream, (QUIC_BUFFER*)send_ctx->buffers, 1, QUIC_SEND_FLAG_NONE,
            send_ctx);

        if (QUIC_SUCCEEDED(status)) {
            WTF_LOG_INFO(conn->context, "http3", "Stream type %llu sent on stream %llu",
                         (unsigned long long)stream->type, (unsigned long long)stream->id);
            if (stream->type == WTF_STREAM_TYPE_CONTROL && !conn->local_settings.settings_sent) {
                if (!wtf_settings_send(conn)) {
                    WTF_LOG_ERROR(conn->context, "settings",
                                  "Failed to send initial server SETTINGS");
                    conn->context->quic_api->StreamShutdown(
                        stream->quic_stream,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND
                            | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                        WTF_H3_INTERNAL_ERROR);
                    return QUIC_STATUS_SUCCESS;
                }
            } else if (stream->type == WTF_STREAM_TYPE_QPACK_ENCODER) {
                wtf_result_t flush_result = wtf_http3_flush_qpack_encoder_stream(conn);
                if (flush_result != WTF_SUCCESS) {
                    WTF_LOG_ERROR(conn->context, "qpack",
                                  "Failed to flush QPACK encoder stream: %s",
                                  wtf_result_to_string(flush_result));
                    conn->context->quic_api->StreamShutdown(
                        stream->quic_stream,
                        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND
                            | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                        WTF_QPACK_ENCODER_STREAM_ERROR);
                    return QUIC_STATUS_SUCCESS;
                }
            }
        } else {
            WTF_LOG_ERROR(conn->context, "stream",
                          "Failed to send stream type and data: 0x%x", status);
            wtf_internal_send_context_destroy(send_ctx);
            conn->context->quic_api->StreamShutdown(
                stream->quic_stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                WTF_H3_INTERNAL_ERROR);
            return QUIC_STATUS_SUCCESS;
        }
    }

    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_receive(wtf_http3_stream* stream, HQUIC Stream,
                                             QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->connection;

    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(conn->context, "stream", "Failed to get stream ID for receive: 0x%x",
                      status);
        conn->context->quic_api->StreamShutdown(
            Stream, QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
    }

    if (stream->id == UINT64_MAX) {
        stream->id = stream_id;

        mtx_lock(&conn->streams_mutex);
        http3_stream_map_itr itr = http3_stream_map_insert(&conn->streams, stream_id, stream);
        if (http3_stream_map_is_end(itr)) {
            mtx_unlock(&conn->streams_mutex);
            WTF_LOG_ERROR(conn->context, "stream",
                          "Failed to add peer stream to map with stream ID %llu",
                          (unsigned long long)stream_id);
            conn->context->quic_api->StreamShutdown(
                Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                WTF_H3_INTERNAL_ERROR);
            return QUIC_STATUS_SUCCESS;
        }
        wtf_http3_stream_add_ref(stream);
        mtx_unlock(&conn->streams_mutex);

        WTF_LOG_DEBUG(conn->context, "stream", "Updated peer stream with ID %llu",
                      (unsigned long long)stream_id);
    }

    bool is_fin = (Event->RECEIVE.Flags & QUIC_RECEIVE_FLAG_FIN) != 0;

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
        bool buffer_has_fin = is_fin && i + 1 == Event->RECEIVE.BufferCount;
        if (!wtf_http3_process_stream_receive(stream, &Event->RECEIVE.Buffers[i],
                                              buffer_has_fin)) {
            WTF_LOG_ERROR(conn->context, "stream",
                          "Failed to process stream data on stream %llu",
                          (unsigned long long)stream_id);

            uint64_t error_code = WTF_H3_GENERAL_PROTOCOL_ERROR;
            if (WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)) {
                switch (stream->type) {
                    case WTF_STREAM_TYPE_CONTROL:
                        error_code = WTF_H3_CLOSED_CRITICAL_STREAM;
                        break;
                    case WTF_STREAM_TYPE_QPACK_ENCODER:
                        error_code = WTF_QPACK_ENCODER_STREAM_ERROR;
                        break;
                    case WTF_STREAM_TYPE_QPACK_DECODER:
                        error_code = WTF_QPACK_DECODER_STREAM_ERROR;
                        break;
                    default:
                        error_code = WTF_H3_FRAME_ERROR;
                        break;
                }
            } else {
                error_code = WTF_H3_MESSAGE_ERROR;
            }

            conn->context->quic_api->StreamShutdown(
                Stream,
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND | QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
                error_code);

            // Critical streams require connection shutdown
            if (stream->type == WTF_STREAM_TYPE_CONTROL) {
                WTF_LOG_ERROR(conn->context, "stream",
                              "Critical control stream error - closing connection");
                conn->context->quic_api->ConnectionShutdown(
                    conn->quic_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTF_H3_CLOSED_CRITICAL_STREAM);
            }

            return QUIC_STATUS_SUCCESS;
        }
    }

    if (stream->callback_transferred) {
        wtf_http3_stream_retire_transferred(stream);
        return QUIC_STATUS_SUCCESS;
    }

    if (is_fin) {
        if (stream->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
            stream->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
        } else {
            stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
        }
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS wtf_handle_stream_shutdown_events(wtf_http3_stream* stream, HQUIC Stream,
                                                     QUIC_STREAM_EVENT* Event)
{
    wtf_connection* conn = stream->connection;
    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);

    wtf_http3_stream* stream_to_destroy = NULL;
    if (Event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        stream_to_destroy = stream;
    }
    bool release_map_ref = false;

    if (QUIC_SUCCEEDED(status)) {
        mtx_lock(&conn->streams_mutex);
        http3_stream_map_itr itr = http3_stream_map_get(&conn->streams, stream_id);
        if (!http3_stream_map_is_end(itr)) {
            wtf_http3_stream* current = itr.data->val;

            switch (Event->Type) {
                case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
                    if (current->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
                        current->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
                    } else {
                        current->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
                    }
                    WTF_LOG_DEBUG(conn->context, "stream",
                                  "Peer send shutdown on stream %llu",
                                  (unsigned long long)stream_id);
                    break;

                case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
                    current->state = WTF_INTERNAL_STREAM_STATE_RESET;
                    WTF_LOG_DEBUG(conn->context, "stream",
                                  "Peer send aborted on stream %llu",
                                  (unsigned long long)stream_id);
                    break;

                case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
                    WTF_LOG_DEBUG(conn->context, "stream", "Stream %llu shutdown complete",
                                  (unsigned long long)stream_id);

                    if (current->id != UINT64_MAX && !conn->destroyed) {
                        http3_stream_map_itr itr = http3_stream_map_get(&conn->streams, stream_id);
                        if (!http3_stream_map_is_end(itr)) {
                            http3_stream_map_erase(&conn->streams, stream_id);
                            release_map_ref = true;
                        }
                    }

                    // Clear connection references for infrastructure streams
                    if (current == conn->control_stream) {
                        conn->control_stream = NULL;
                    } else if (current == conn->peer_control_stream) {
                        conn->peer_control_stream = NULL;
                    } else if (current == conn->qpack_encoder_stream) {
                        conn->qpack_encoder_stream = NULL;
                    } else if (current == conn->qpack_decoder_stream) {
                        conn->qpack_decoder_stream = NULL;
                    } else if (current == conn->peer_encoder_stream) {
                        conn->peer_encoder_stream = NULL;
                    } else if (current == conn->peer_decoder_stream) {
                        conn->peer_decoder_stream = NULL;
                    }

                    stream_to_destroy = current;
                    break;

                default:
                    break;
            }
        }
        mtx_unlock(&conn->streams_mutex);
    }

    if (stream_to_destroy) {
        if (stream_to_destroy->webtransport_session
            && stream_to_destroy->webtransport_session->connect_stream == stream_to_destroy) {
            stream_to_destroy->webtransport_session->connect_stream = NULL;
        }

        if (release_map_ref) {
            wtf_http3_stream_release(stream_to_destroy);
        }
        wtf_http3_stream_destroy(stream_to_destroy);
    }

    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API wtf_http3_stream_callback(HQUIC Stream, void* Context,
                                               QUIC_STREAM_EVENT* Event)
{
    wtf_http3_stream* stream = (wtf_http3_stream*)Context;

    if (!stream || !stream->connection || !stream->connection->context) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_STREAM_EVENT_START_COMPLETE:
            return wtf_handle_stream_start_complete(stream, Event);

        case QUIC_STREAM_EVENT_RECEIVE:
            return wtf_handle_stream_receive(stream, Stream, Event);

        case QUIC_STREAM_EVENT_SEND_COMPLETE:
            if (Event->SEND_COMPLETE.ClientContext) {
                wtf_internal_send_context_destroy(
                    (wtf_internal_send_context*)Event->SEND_COMPLETE.ClientContext);
            }
            return QUIC_STATUS_SUCCESS;

        case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN:
        case QUIC_STREAM_EVENT_PEER_SEND_ABORTED:
        case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
            return wtf_handle_stream_shutdown_events(stream, Stream, Event);

        case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
            WTF_LOG_DEBUG(stream->connection->context, "stream",
                          "Send shutdown complete on stream %llu", (unsigned long long)stream->id);
            return QUIC_STATUS_SUCCESS;

        default:
            WTF_LOG_DEBUG(stream->connection->context, "stream",
                          "Unhandled stream event %d on stream %llu", Event->Type,
                          (unsigned long long)stream->id);
            return QUIC_STATUS_SUCCESS;
    }
}
