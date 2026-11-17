#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include "network_internal.h"

static void network_stream_receive(network_stream* stream);

static void network_stream_unlink(network_stream* stream)
{
    network_connection* parent = (network_connection*)stream->handle.parent;
    network_stream_map_erase(&parent->streams, (uintptr_t)stream);
}

static void network_stream_replenish_credit(network_stream* stream)
{
    network_connection* parent = (network_connection*)stream->handle.parent;
    if (parent->state != NETWORK_CONNECTION_READY
        || (stream->origin != NETWORK_STREAM_PEER_BIDI
            && stream->origin != NETWORK_STREAM_PEER_UNI)) {
        return;
    }
    nw_protocol_metadata_t metadata = stream->metadata;
    if (!metadata) {
        return;
    }
    if (stream->origin == NETWORK_STREAM_PEER_BIDI) {
        if (parent->local_max_streams_bidi < QUIC_UINT62_MAX) {
            nw_quic_set_local_max_streams_bidirectional(metadata, ++parent->local_max_streams_bidi);
        }
    } else {
        if (parent->local_max_streams_uni < QUIC_UINT62_MAX) {
            nw_quic_set_local_max_streams_unidirectional(metadata, ++parent->local_max_streams_uni);
        }
    }
}

void network_stream_cancel(network_stream* stream)
{
    if (stream->state >= NETWORK_STREAM_CANCELLING) {
        return;
    }
    if (stream->connection) {
        network_stream_replenish_credit(stream);
        stream->state = NETWORK_STREAM_CANCELLING;
        nw_connection_cancel(stream->connection);
        return;
    }
    stream->state = NETWORK_STREAM_CANCELLED;
    /* Keep table iteration stable while a connection cancels its streams. */
    network_handle_retain((HQUIC)stream);
    dispatch_async(stream->handle.queue, ^{
        network_stream_finish(stream);
        network_handle_release((HQUIC)stream);
    });
}

void network_stream_finish(network_stream* stream)
{
    if (stream->sends.count || stream->state == NETWORK_STREAM_COMPLETE) {
        return;
    }
    network_handle_retain((HQUIC)stream);
    if (stream->send_state == NETWORK_SEND_FIN_PENDING
        || stream->send_state == NETWORK_SEND_ABORT_PENDING) {
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE};
        event.SEND_SHUTDOWN_COMPLETE.Graceful = stream->send_state == NETWORK_SEND_FIN_PENDING;
        if (event.SEND_SHUTDOWN_COMPLETE.Graceful) {
            stream->send_state = NETWORK_SEND_FINISHED;
        } else {
            stream->send_state = NETWORK_SEND_ABORTED;
        }
        network_emit_stream(stream, &event);
    }
    if (stream->send_state == NETWORK_SEND_FINISHED
        && stream->receive_state == NETWORK_RECEIVE_FINISHED) {
        network_stream_cancel(stream);
    }
    if (stream->state == NETWORK_STREAM_CANCELLED) {
        stream->state = NETWORK_STREAM_COMPLETE;
        network_connection* parent = (network_connection*)stream->handle.parent;
        network_stream_unlink(stream);
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE};
        event.SHUTDOWN_COMPLETE.ConnectionShutdown = parent->state
            >= NETWORK_CONNECTION_LOCAL_CLOSE;
        event.SHUTDOWN_COMPLETE.AppCloseInProgress = stream->handle.state != NETWORK_HANDLE_OPEN;
        network_emit_stream(stream, &event);
        if (stream->origin == NETWORK_STREAM_PEER_PENDING) {
            network_handle_close((HQUIC)stream);
        }
        network_connection_finish(parent);
    }
    network_handle_release((HQUIC)stream);
}

static void network_stream_receive_error(network_stream* stream)
{
    network_connection* parent = (network_connection*)stream->handle.parent;
    nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(
        stream->connection, network_quic_definition());
    uint64_t code = UINT64_MAX;
    if (metadata) {
        code = nw_quic_get_stream_application_error(metadata);
        nw_release(metadata);
    }
    stream->receive_state = NETWORK_RECEIVE_ABORTED;
    if (stream->send_state < NETWORK_SEND_FINISHED) {
        stream->send_state = NETWORK_SEND_ABORT_PENDING;
    }
    if (code != UINT64_MAX && parent->state < NETWORK_CONNECTION_LOCAL_CLOSE) {
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED};
        event.PEER_SEND_ABORTED.ErrorCode = code;
        network_emit_stream(stream, &event);
    }
    network_stream_cancel(stream);
}

static void network_stream_deliver_receive(
    network_stream* stream, dispatch_data_t content, network_delivery_kind kind)
{
    if (stream->handle.state != NETWORK_HANDLE_OPEN || stream->state != NETWORK_STREAM_READY) {
        return;
    }
    if (content) {
        const void* bytes;
        size_t length;
        dispatch_data_t mapped = dispatch_data_create_map(content, &bytes, &length);
        if (length) {
            QUIC_BUFFER buffer = {(uint32_t)length, (uint8_t*)bytes};
            QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_RECEIVE};
            event.RECEIVE.AbsoluteOffset = stream->received_bytes;
            event.RECEIVE.TotalBufferLength = length;
            event.RECEIVE.BufferCount = 1;
            event.RECEIVE.Buffers = &buffer;
            if (kind == NETWORK_DELIVERY_FIN) {
                event.RECEIVE.Flags = QUIC_RECEIVE_FLAG_FIN;
            }
            stream->received_bytes += length;
            network_emit_stream(stream, &event);
        }
        dispatch_release(mapped);
    }
    if (stream->handle.state != NETWORK_HANDLE_OPEN) {
        return;
    }
    if (kind == NETWORK_DELIVERY_ERROR) {
        network_stream_receive_error(stream);
        return;
    }
    if (kind == NETWORK_DELIVERY_FIN) {
        stream->receive_state = NETWORK_RECEIVE_FINISHED;
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN};
        network_emit_stream(stream, &event);
        network_stream_finish(stream);
        return;
    }
    network_stream_receive(stream);
}

static void network_stream_receive(network_stream* stream)
{
    if (stream->handle.state != NETWORK_HANDLE_OPEN || stream->state != NETWORK_STREAM_READY
        || stream->receive_state != NETWORK_RECEIVE_IDLE) {
        return;
    }
    stream->receive_state = NETWORK_RECEIVE_PENDING;
    network_handle_retain((HQUIC)stream);
    nw_connection_receive(stream->connection, 1, NETWORK_RECEIVE_SIZE,
        ^(dispatch_data_t content, nw_content_context_t context, bool complete, nw_error_t error) {
            (void)context;
            network_delivery_kind kind = NETWORK_DELIVERY_DATA;
            if (complete) {
                kind = NETWORK_DELIVERY_FIN;
            }
            if (error) {
                kind = NETWORK_DELIVERY_ERROR;
            }
            if (stream->receive_state == NETWORK_RECEIVE_PAUSING) {
                stream->receive_state = NETWORK_RECEIVE_PAUSED;
                stream->deferred_kind = kind;
                if (content) {
                    stream->deferred_data = content;
                    dispatch_retain(content);
                }
            } else if (stream->receive_state == NETWORK_RECEIVE_PENDING) {
                stream->receive_state = NETWORK_RECEIVE_IDLE;
                network_stream_deliver_receive(stream, content, kind);
            }
            network_handle_release((HQUIC)stream);
        });
}

static void network_stream_ready(network_stream* stream)
{
    stream->state = NETWORK_STREAM_READY;
    nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(
        stream->connection, network_quic_definition());
    if (!metadata) {
        network_stream_cancel(stream);
        return;
    }
    uint64_t id = nw_quic_get_stream_id(metadata);
    stream->metadata = metadata;
    atomic_store_explicit(&stream->id, id, memory_order_release);
    if (stream->reliable_offset != UINT64_MAX && wtf_network_supports_reliable_reset()) {
        nw_quic_set_stream_reset_stream_at_reliable_size(metadata, stream->reliable_offset);
    }
    if (stream->origin == NETWORK_STREAM_PEER_PENDING) {
        QUIC_CONNECTION_EVENT event = {.Type = QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED};
        event.PEER_STREAM_STARTED.Stream = (HQUIC)stream;
        stream->origin = NETWORK_STREAM_PEER_BIDI;
        if (id & 2) {
            stream->origin = NETWORK_STREAM_PEER_UNI;
            stream->send_state = NETWORK_SEND_FINISHED;
            event.PEER_STREAM_STARTED.Flags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
        }
        QUIC_STATUS status = network_emit_connection(
            (network_connection*)stream->handle.parent, &event);
        if (QUIC_FAILED(status) || !stream->handle.callback) {
            network_handle_close((HQUIC)stream);
            return;
        }
    } else {
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_START_COMPLETE};
        event.START_COMPLETE.Status = QUIC_STATUS_SUCCESS;
        event.START_COMPLETE.ID = id;
        event.START_COMPLETE.PeerAccepted = true;
        network_emit_stream(stream, &event);
    }
    network_stream_receive(stream);
}

static void network_stream_attach(network_stream* stream)
{
    stream->state = NETWORK_STREAM_STARTING;
    network_handle_retain((HQUIC)stream);
    nw_connection_set_queue(stream->connection, stream->handle.queue);
    nw_connection_set_state_changed_handler(
        stream->connection, ^(nw_connection_state_t state, nw_error_t error) {
            if (state == nw_connection_state_ready && stream->state == NETWORK_STREAM_STARTING
                && stream->handle.state == NETWORK_HANDLE_OPEN) {
                network_stream_ready(stream);
            } else if (state == nw_connection_state_failed) {
                if (stream->state == NETWORK_STREAM_STARTING
                    && stream->origin != NETWORK_STREAM_PEER_PENDING) {
                    QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_START_COMPLETE};
                    event.START_COMPLETE.Status = network_error_status(error);
                    network_emit_stream(stream, &event);
                }
                network_stream_cancel(stream);
            } else if (state == nw_connection_state_cancelled) {
                if (stream->state != NETWORK_STREAM_COMPLETE) {
                    stream->state = NETWORK_STREAM_CANCELLED;
                }
                if (stream->send_state == NETWORK_SEND_OPEN) {
                    stream->send_state = NETWORK_SEND_ABORT_PENDING;
                }
                nw_connection_set_state_changed_handler(stream->connection, NULL);
                network_stream_finish(stream);
                network_handle_release((HQUIC)stream);
            }
        });
    nw_connection_start(stream->connection);
}

static network_stream* network_stream_create(network_connection* connection)
{
    network_stream* stream = (network_stream*)network_handle_create(
        NETWORK_STREAM, sizeof(*stream), (HQUIC)connection);
    if (stream) {
        atomic_init(&stream->id, UINT64_MAX);
        stream->reliable_offset = UINT64_MAX;
        stream->priority = 0x7fff;
        stream->send_context = NW_CONNECTION_DEFAULT_STREAM_CONTEXT;
        nw_retain(stream->send_context);
        network_stream_map_itr entry = network_stream_map_insert(
            &connection->streams, (uintptr_t)stream, stream);
        if (network_stream_map_is_end(entry)) {
            network_handle_release((HQUIC)stream);
            return NULL;
        }
    }
    return stream;
}

void network_stream_accept(network_connection* connection, nw_connection_t incoming)
{
    network_stream* stream = network_stream_create(connection);
    if (!stream) {
        nw_connection_cancel(incoming);
        return;
    }
    stream->origin = NETWORK_STREAM_PEER_PENDING;
    stream->connection = nw_retain(incoming);
    network_stream_attach(stream);
}

QUIC_STATUS network_stream_open(HQUIC parent,
    QUIC_STREAM_OPEN_FLAGS flags,
    QUIC_STREAM_CALLBACK_HANDLER callback,
    void* context,
    HQUIC* out)
{
    if (!parent || !callback || !out) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (flags & ~QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(parent, ^{
        network_connection* connection = (network_connection*)parent;
        if (parent->state != NETWORK_HANDLE_OPEN
            || connection->state >= NETWORK_CONNECTION_LOCAL_CLOSE) {
            return;
        }
        network_stream* stream = network_stream_create(connection);
        if (!stream) {
            status = QUIC_STATUS_OUT_OF_MEMORY;
            return;
        }
        stream->handle.callback = callback;
        stream->handle.context = context;
        stream->origin = NETWORK_STREAM_LOCAL_BIDI;
        if (flags & QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL) {
            stream->origin = NETWORK_STREAM_LOCAL_UNI;
            stream->receive_state = NETWORK_RECEIVE_FINISHED;
        }
        *out = (HQUIC)stream;
        status = QUIC_STATUS_SUCCESS;
    });
    return status;
}

QUIC_STATUS network_stream_start(HQUIC handle, QUIC_STREAM_START_FLAGS flags)
{
    if (!handle) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (flags != QUIC_STREAM_START_FLAG_NONE) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    network_stream* stream = (network_stream*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        network_connection* parent = (network_connection*)handle->parent;
        if (handle->state != NETWORK_HANDLE_OPEN || stream->state != NETWORK_STREAM_CREATED
            || parent->state != NETWORK_CONNECTION_READY) {
            return;
        }
        nw_protocol_options_t options = NULL;
        if (stream->origin == NETWORK_STREAM_LOCAL_UNI) {
            options = nw_quic_create_options();
            if (!options) {
                status = QUIC_STATUS_OUT_OF_MEMORY;
                return;
            }
            nw_quic_set_stream_is_unidirectional(options, true);
        }
        stream->connection = nw_connection_group_extract_connection(parent->group, NULL, options);
        if (options) {
            nw_release(options);
        }
        if (!stream->connection) {
            status = QUIC_STATUS_OUT_OF_MEMORY;
            return;
        }
        network_stream_attach(stream);
        status = QUIC_STATUS_SUCCESS;
    });
    return status;
}

QUIC_STATUS network_stream_send(
    HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count, QUIC_SEND_FLAGS flags, void* context)
{
    if (!handle) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    const QUIC_SEND_FLAGS supported_flags = QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN
        | QUIC_SEND_FLAG_ALLOW_0_RTT | QUIC_SEND_FLAG_DELAY_SEND;
    if (flags & ~supported_flags) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    network_stream* stream = (network_stream*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (stream->state == NETWORK_STREAM_CREATED && (flags & QUIC_SEND_FLAG_START)) {
            status = network_stream_start(handle, QUIC_STREAM_START_FLAG_NONE);
            if (QUIC_FAILED(status)) {
                return;
            }
        }
        network_connection* parent = (network_connection*)handle->parent;
        if (handle->state != NETWORK_HANDLE_OPEN || !stream->connection
            || parent->handle.state != NETWORK_HANDLE_OPEN
            || parent->state != NETWORK_CONNECTION_READY
            || stream->state >= NETWORK_STREAM_CANCELLING
            || stream->send_state != NETWORK_SEND_OPEN) {
            status = QUIC_STATUS_INVALID_STATE;
            return;
        }
        size_t length;
        status = network_send_validate(buffers, count, NETWORK_SEND_LIMIT, &length);
        if (QUIC_FAILED(status)) {
            return;
        }
        network_send_operation* operation = network_send_reserve(handle, context, length);
        if (!operation) {
            status = QUIC_STATUS_OUT_OF_MEMORY;
            return;
        }
        dispatch_data_t data = network_send_data(operation, buffers, count, length);
        if (!data) {
            network_send_abandon(operation);
            status = QUIC_STATUS_OUT_OF_MEMORY;
            return;
        }
        if (flags & QUIC_SEND_FLAG_FIN) {
            stream->send_state = NETWORK_SEND_FIN_PENDING;
        }
        nw_connection_send(stream->connection, data, stream->send_context,
            stream->send_state == NETWORK_SEND_FIN_PENDING, ^(nw_error_t error) {
                network_send_complete(operation, error);
            });
        dispatch_release(data);
    });
    return status;
}

QUIC_STATUS network_stream_shutdown(
    HQUIC handle, QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    if (!handle || !flags) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (flags == QUIC_STREAM_SHUTDOWN_FLAG_GRACEFUL) {
        return network_stream_send(handle, NULL, 0, QUIC_SEND_FLAG_FIN, NULL);
    }
    if (flags != QUIC_STREAM_SHUTDOWN_FLAG_ABORT) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    network_stream* stream = (network_stream*)handle;
    network_run(handle, ^{
        if (stream->connection) {
            nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(
                stream->connection, network_quic_definition());
            if (metadata) {
                nw_quic_set_stream_application_error(metadata, code);
                nw_release(metadata);
            }
        }
        stream->send_state = NETWORK_SEND_ABORT_PENDING;
        stream->receive_state = NETWORK_RECEIVE_ABORTED;
        network_stream_cancel(stream);
    });
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS network_stream_set_parameter(
    network_stream* stream, uint32_t parameter, uint32_t size, const void* buffer)
{
    switch (parameter) {
        case QUIC_PARAM_STREAM_PRIORITY: {
            if (size != sizeof(stream->priority)) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            uint16_t priority;
            memcpy(&priority, buffer, size);
            if (priority == stream->priority) {
                return QUIC_STATUS_SUCCESS;
            }
            if (stream->send_context == NW_CONNECTION_DEFAULT_STREAM_CONTEXT) {
                nw_content_context_t context = nw_content_context_create("libwtf.stream");
                if (!context) {
                    return QUIC_STATUS_OUT_OF_MEMORY;
                }
                nw_content_context_set_is_final(context, true);
                nw_release(stream->send_context);
                stream->send_context = context;
            }
            stream->priority = priority;
            nw_content_context_set_relative_priority(
                stream->send_context, (double)stream->priority / UINT16_MAX);
            return QUIC_STATUS_SUCCESS;
        }
        case QUIC_PARAM_STREAM_RELIABLE_OFFSET: {
            if (size != sizeof(stream->reliable_offset)) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            if (!wtf_network_supports_reliable_reset()) {
                return QUIC_STATUS_NOT_SUPPORTED;
            }
            uint64_t offset;
            memcpy(&offset, buffer, size);
            if (offset > QUIC_UINT62_MAX) {
                return QUIC_STATUS_INVALID_PARAMETER;
            }
            stream->reliable_offset = offset;
            if (stream->state == NETWORK_STREAM_READY && stream->metadata) {
                nw_quic_set_stream_reset_stream_at_reliable_size(stream->metadata, offset);
            } else if (stream->connection) {
                nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(
                    stream->connection, network_quic_definition());
                if (metadata) {
                    nw_quic_set_stream_reset_stream_at_reliable_size(metadata, offset);
                    nw_release(metadata);
                }
            }
            return QUIC_STATUS_SUCCESS;
        }
        default:
            return QUIC_STATUS_NOT_SUPPORTED;
    }
}

QUIC_STATUS network_stream_receive_enabled(HQUIC handle, BOOLEAN enabled)
{
    if (!handle) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_stream* stream = (network_stream*)handle;
    network_run(handle, ^{
        if (!enabled) {
            if (stream->receive_state == NETWORK_RECEIVE_PENDING) {
                stream->receive_state = NETWORK_RECEIVE_PAUSING;
            } else if (stream->receive_state == NETWORK_RECEIVE_IDLE) {
                stream->receive_state = NETWORK_RECEIVE_PAUSED;
            }
            return;
        }
        if (stream->receive_state == NETWORK_RECEIVE_PAUSING) {
            stream->receive_state = NETWORK_RECEIVE_PENDING;
        } else if (stream->receive_state == NETWORK_RECEIVE_PAUSED) {
            stream->receive_state = NETWORK_RECEIVE_IDLE;
            dispatch_data_t data = stream->deferred_data;
            network_delivery_kind kind = stream->deferred_kind;
            stream->deferred_data = NULL;
            stream->deferred_kind = NETWORK_DELIVERY_NONE;
            network_stream_deliver_receive(stream, data, kind);
            if (data) {
                dispatch_release(data);
            }
        }
    });
    return QUIC_STATUS_SUCCESS;
}

/* ConnectionClose must retire application stream contexts before returning,
 * while Network's cancellation and buffer completions can finish later. */
void network_stream_detach(network_stream* stream)
{
    stream->receive_state = NETWORK_RECEIVE_ABORTED;
    stream->send_state = NETWORK_SEND_ABORTED;
    network_send_cancel_all((HQUIC)stream);
    network_stream_cancel(stream);
    stream->state = NETWORK_STREAM_COMPLETE;
    network_stream_unlink(stream);
    QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE};
    event.SHUTDOWN_COMPLETE.ConnectionShutdown = true;
    network_emit_stream(stream, &event);
    if (stream->origin == NETWORK_STREAM_PEER_PENDING) {
        network_handle_close((HQUIC)stream);
    }
}

void network_stream_close(network_stream* stream)
{
    if (stream->state == NETWORK_STREAM_COMPLETE) {
        return;
    }
    network_send_cancel_all((HQUIC)stream);
    stream->receive_state = NETWORK_RECEIVE_ABORTED;
    network_stream_unlink(stream);
    network_stream_cancel(stream);
}

void network_stream_dispose(network_stream* stream)
{
    if (stream->metadata) {
        nw_release(stream->metadata);
    }
    if (stream->connection) {
        nw_release(stream->connection);
    }
    if (stream->send_context) {
        nw_release(stream->send_context);
    }
    if (stream->deferred_data) {
        dispatch_release(stream->deferred_data);
    }
}
#endif
