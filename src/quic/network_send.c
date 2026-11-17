#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include "network_internal.h"

static network_send_queue* network_send_get_queue(HQUIC owner)
{
    if (owner->kind == NETWORK_STREAM) {
        return &((network_stream*)owner)->sends;
    }
    return &((network_connection*)owner)->sends;
}

static void network_send_indicate(network_send_operation* operation, bool cancelled)
{
    if (operation->completion == NETWORK_SEND_COMPLETED) {
        return;
    }
    operation->completion = NETWORK_SEND_COMPLETED;
    if (operation->owner->kind == NETWORK_STREAM) {
        QUIC_STREAM_EVENT event = {.Type = QUIC_STREAM_EVENT_SEND_COMPLETE};
        event.SEND_COMPLETE.Canceled = cancelled;
        event.SEND_COMPLETE.ClientContext = operation->context;
        network_emit_stream((network_stream*)operation->owner, &event);
        return;
    }
    QUIC_CONNECTION_EVENT event = {.Type = QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED};
    event.DATAGRAM_SEND_STATE_CHANGED.ClientContext = operation->context;
    event.DATAGRAM_SEND_STATE_CHANGED.State = (QUIC_DATAGRAM_SEND_STATE)WTF_DATAGRAM_SEND_UNTRACKED;
    if (cancelled) {
        event.DATAGRAM_SEND_STATE_CHANGED.State = QUIC_DATAGRAM_SEND_CANCELED;
    }
    network_emit_connection((network_connection*)operation->owner, &event);
}

network_send_operation* network_send_reserve(HQUIC owner, void* context, size_t length)
{
    network_send_queue* queue = network_send_get_queue(owner);
    size_t charge = length;
    if (charge < NETWORK_MIN_SEND_CHARGE) {
        charge = NETWORK_MIN_SEND_CHARGE;
    }
    if (queue->count >= NETWORK_PENDING_SEND_LIMIT
        || charge > NETWORK_SEND_LIMIT - queue->charged_bytes) {
        return NULL;
    }
    network_send_operation* operation = malloc(sizeof(*operation) + length);
    if (!operation) {
        return NULL;
    }
    memset(operation, 0, sizeof(*operation));
    operation->owner = network_handle_retain(owner);
    operation->context = context;
    operation->charge = charge;
    operation->pending_callbacks = 2;
    if (owner->kind == NETWORK_STREAM) {
        network_connection* connection = (network_connection*)owner->parent;
        const QUIC_SETTINGS* settings = &connection->configuration->settings;
        if (settings->IsSet.SendBufferingEnabled && !settings->SendBufferingEnabled) {
            operation->mode = NETWORK_SEND_ON_RELEASE;
        }
    }
    operation->next = queue->first;
    operation->previous = &queue->first;
    if (queue->first) {
        queue->first->previous = &operation->next;
    }
    queue->first = operation;
    queue->count++;
    queue->charged_bytes += charge;
    return operation;
}

static void network_send_unlink(network_send_operation* operation)
{
    network_send_queue* queue = network_send_get_queue(operation->owner);
    *operation->previous = operation->next;
    if (operation->next) {
        operation->next->previous = operation->previous;
    }
    queue->count--;
    queue->charged_bytes -= operation->charge;
}

void network_send_abandon(network_send_operation* operation)
{
    HQUIC owner = operation->owner;
    network_send_unlink(operation);
    free(operation);
    network_handle_release(owner);
}

static void network_send_callback_finished(network_send_operation* operation)
{
    operation->pending_callbacks--;
    if (operation->pending_callbacks) {
        return;
    }
    HQUIC owner = operation->owner;
    network_send_unlink(operation);
    network_send_indicate(operation, QUIC_FAILED(operation->status));
    if (owner->kind == NETWORK_STREAM) {
        network_stream_finish((network_stream*)owner);
    } else {
        network_connection_finish((network_connection*)owner);
    }
    free(operation);
    network_handle_release(owner);
}

void network_send_complete(network_send_operation* operation, nw_error_t error)
{
    operation->status = QUIC_STATUS_SUCCESS;
    if (error) {
        operation->status = network_error_status(error);
    }
    if (operation->mode == NETWORK_SEND_ON_PROCESS || error) {
        network_send_indicate(operation, error != NULL);
    }
    if (error && operation->owner->kind == NETWORK_STREAM) {
        network_stream* stream = (network_stream*)operation->owner;
        if (stream->send_state == NETWORK_SEND_FIN_PENDING) {
            stream->send_state = NETWORK_SEND_ABORT_PENDING;
        }
        network_stream_cancel(stream);
    }
    network_send_callback_finished(operation);
}

void network_send_cancel_all(HQUIC owner)
{
    for (network_send_operation* operation = network_send_get_queue(owner)->first; operation;
        operation = operation->next) {
        network_send_indicate(operation, true);
    }
}

QUIC_STATUS network_send_validate(
    const QUIC_BUFFER* buffers, uint32_t count, size_t limit, size_t* length)
{
    *length = 0;
    if (count && !buffers) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    for (uint32_t i = 0; i < count; ++i) {
        if ((!buffers[i].Buffer && buffers[i].Length) || buffers[i].Length > limit - *length) {
            return QUIC_STATUS_INVALID_PARAMETER;
        }
        *length += buffers[i].Length;
    }
    return QUIC_STATUS_SUCCESS;
}

dispatch_data_t network_send_data(
    network_send_operation* operation, const QUIC_BUFFER* buffers, uint32_t count, size_t length)
{
    if (!length) {
        network_send_callback_finished(operation);
        dispatch_retain(dispatch_data_empty);
        return dispatch_data_empty;
    }
    uint8_t* copy = (uint8_t*)(operation + 1);
    size_t offset = 0;
    for (uint32_t i = 0; i < count; ++i) {
        if (buffers[i].Length) {
            memcpy(copy + offset, buffers[i].Buffer, buffers[i].Length);
            offset += buffers[i].Length;
        }
    }
    return dispatch_data_create(copy, length, operation->owner->queue, ^{
        network_send_callback_finished(operation);
    });
}
#endif
