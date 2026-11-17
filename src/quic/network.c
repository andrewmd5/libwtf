/*
 * Network.framework implementation of the MsQuic API used by libwtf.
 * Build: -DWTF_QUIC_BACKEND=network (macOS 15+).
 * Requires the MsQuic submodule for headers.
 */
#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)

    #include "network_internal.h"

static char network_queue_key;

bool wtf_network_supports_reliable_reset(void)
{
    return nw_quic_set_reset_stream_at_enabled != NULL
        && nw_quic_get_reset_stream_at_supported != NULL
        && nw_quic_set_stream_reset_stream_at_reliable_size != NULL;
}

bool wtf_network_supports_early_data(void)
{
    return sec_protocol_options_set_tls_early_data_enabled != NULL
        && nw_quic_connection_set_session_state != NULL
        && nw_quic_connection_set_session_state_update_block != NULL
        && nw_quic_stream_copy_shared_connection_options != NULL;
}

nw_protocol_definition_t network_quic_definition(void)
{
    static dispatch_once_t once;
    static nw_protocol_definition_t definition;
    dispatch_once(&once, ^{
        definition = nw_protocol_copy_quic_definition();
    });
    return definition;
}

static dispatch_queue_t network_queue_create(void)
{
    dispatch_queue_t queue = dispatch_queue_create("libwtf.network", DISPATCH_QUEUE_SERIAL);
    dispatch_queue_set_specific(queue, &network_queue_key, queue, NULL);
    return queue;
}

void network_run(HQUIC handle, dispatch_block_t work)
{
    if (dispatch_get_specific(&network_queue_key) == handle->queue) {
        work();
        return;
    }
    dispatch_queue_t queue = handle->queue;
    dispatch_retain(queue);
    dispatch_sync(queue, work);
    dispatch_release(queue);
}

HQUIC network_handle_create(network_handle_kind kind, size_t size, HQUIC parent)
{
    HQUIC handle = calloc(1, size);
    if (!handle) {
        return NULL;
    }
    atomic_init(&handle->references, 1);
    handle->kind = kind;
    handle->state = NETWORK_HANDLE_OPEN;
    handle->parent = network_handle_retain(parent);
    if (!parent) {
        ((network_registration*)handle)->drain = dispatch_group_create();
        ((network_registration*)handle)->session_queue = network_session_queue_create();
        if (!((network_registration*)handle)->session_queue) {
            dispatch_release(((network_registration*)handle)->drain);
            free(handle);
            return NULL;
        }
    } else if (parent->kind == NETWORK_REGISTRATION) {
        dispatch_group_enter(((network_registration*)parent)->drain);
    }
    switch (kind) {
        case NETWORK_REGISTRATION:
        case NETWORK_CONNECTION:
            handle->queue = network_queue_create();
            break;
        default:
            handle->queue = parent->queue;
            break;
    }
    if (kind == NETWORK_CONNECTION) {
        network_stream_map_init(&((network_connection*)handle)->streams);
    }
    return handle;
}

HQUIC network_handle_retain(HQUIC handle)
{
    if (handle) {
        atomic_fetch_add_explicit(&handle->references, 1, memory_order_relaxed);
    }
    return handle;
}

void network_handle_release(HQUIC handle)
{
    if (!handle) {
        return;
    }
    if (atomic_fetch_sub_explicit(&handle->references, 1, memory_order_acq_rel) != 1) {
        return;
    }
    switch (handle->kind) {
        case NETWORK_CONFIGURATION:
            network_configuration_dispose((network_configuration*)handle);
            break;
        case NETWORK_LISTENER:
            network_listener_dispose((network_listener*)handle);
            break;
        case NETWORK_CONNECTION:
            network_connection_dispose((network_connection*)handle);
            dispatch_release(handle->queue);
            break;
        case NETWORK_STREAM:
            network_stream_dispose((network_stream*)handle);
            break;
        case NETWORK_REGISTRATION:
            dispatch_release(((network_registration*)handle)->session_queue);
            dispatch_release(((network_registration*)handle)->drain);
            dispatch_release(handle->queue);
            break;
    }
    if (handle->parent && handle->parent->kind == NETWORK_REGISTRATION) {
        dispatch_group_leave(((network_registration*)handle->parent)->drain);
    }
    network_handle_release(handle->parent);
    free(handle);
}

void network_handle_close(HQUIC handle)
{
    if (!handle) {
        return;
    }
    network_run(handle, ^{
        if (handle->state != NETWORK_HANDLE_OPEN) {
            return;
        }
        handle->state = NETWORK_HANDLE_CLOSING;
        switch (handle->kind) {
            case NETWORK_CONFIGURATION:
                break;
            case NETWORK_LISTENER:
                network_listener_close((network_listener*)handle);
                break;
            case NETWORK_CONNECTION:
                network_connection_close((network_connection*)handle);
                break;
            case NETWORK_STREAM:
                network_stream_close((network_stream*)handle);
                break;
            case NETWORK_REGISTRATION:
                break;
        }
        handle->callback = NULL;
        handle->context = NULL;
        handle->state = NETWORK_HANDLE_CLOSED;
        network_handle_release(handle);
    });
}

wtf_context_t* network_logging_context(HQUIC handle)
{
    while (handle && handle->parent) {
        handle = handle->parent;
    }
    if (!handle) {
        return NULL;
    }
    return handle->context;
}

QUIC_STATUS network_error_status(nw_error_t error)
{
    if (!error) {
        return QUIC_STATUS_ABORTED;
    }
    if (nw_error_get_error_domain(error) == nw_error_domain_tls) {
        return QUIC_STATUS_TLS_ERROR;
    }
    int code = nw_error_get_error_code(error);
    if (code <= 0) {
        return QUIC_STATUS_ABORTED;
    }
    return (QUIC_STATUS)code;
}

QUIC_STATUS network_emit_connection(network_connection* connection, QUIC_CONNECTION_EVENT* event)
{
    HQUIC handle = &connection->handle;
    if (handle->state == NETWORK_HANDLE_CLOSED || !handle->callback) {
        return QUIC_STATUS_SUCCESS;
    }
    network_handle_retain(handle);
    QUIC_CONNECTION_CALLBACK_HANDLER callback = (QUIC_CONNECTION_CALLBACK_HANDLER)handle->callback;
    QUIC_STATUS status = callback(handle, handle->context, event);
    network_handle_release(handle);
    return status;
}

QUIC_STATUS network_emit_stream(network_stream* stream, QUIC_STREAM_EVENT* event)
{
    HQUIC handle = &stream->handle;
    if (handle->state == NETWORK_HANDLE_CLOSED || !handle->callback) {
        return QUIC_STATUS_SUCCESS;
    }
    network_handle_retain(handle);
    QUIC_STREAM_CALLBACK_HANDLER callback = (QUIC_STREAM_CALLBACK_HANDLER)handle->callback;
    QUIC_STATUS status = callback(handle, handle->context, event);
    network_handle_release(handle);
    return status;
}

static void network_set_context(HQUIC handle, void* context)
{
    if (handle) {
        network_run(handle, ^{
            handle->context = context;
        });
    }
}

static void* network_get_context(HQUIC handle)
{
    if (!handle) {
        return NULL;
    }
    __block void* context;
    network_run(handle, ^{
        context = handle->context;
    });
    return context;
}

static void network_set_callback(HQUIC handle, void* callback, void* context)
{
    if (handle) {
        network_run(handle, ^{
            handle->callback = callback;
            handle->context = context;
        });
    }
}

static QUIC_STATUS network_registration_open(const QUIC_REGISTRATION_CONFIG* config, HQUIC* out)
{
    (void)config;
    if (!out) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    *out = network_handle_create(NETWORK_REGISTRATION, sizeof(network_registration), NULL);
    if (!*out) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    return QUIC_STATUS_SUCCESS;
}

static void network_registration_close(HQUIC handle)
{
    if (!handle) {
        return;
    }
    network_registration* registration = (network_registration*)handle;
    network_run(handle, ^{
        handle->state = NETWORK_HANDLE_CLOSED;
        handle->context = NULL;
    });
    /* Outside callbacks, match MsQuic's synchronous registration teardown.
     * A callback cannot wait for its own outstanding operation to finish. */
    if (!dispatch_get_specific(&network_queue_key)) {
        dispatch_group_wait(registration->drain, DISPATCH_TIME_FOREVER);
    }
    network_handle_release(handle);
}

static QUIC_STATUS network_copy_parameter(
    const void* value, uint32_t required, uint32_t* size, void* buffer)
{
    if (*size < required) {
        *size = required;
        return QUIC_STATUS_BUFFER_TOO_SMALL;
    }
    if (!buffer) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    memcpy(buffer, value, required);
    *size = required;
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS network_get_parameter(
    HQUIC handle, uint32_t parameter, uint32_t* size, void* buffer)
{
    if (!handle || !size) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (handle->kind == NETWORK_STREAM && parameter == QUIC_PARAM_STREAM_ID) {
        network_stream* stream = (network_stream*)handle;
        uint64_t id = atomic_load_explicit(&stream->id, memory_order_acquire);
        if (id == UINT64_MAX) {
            return QUIC_STATUS_INVALID_STATE;
        }
        return network_copy_parameter(&id, sizeof(id), size, buffer);
    }
    if (handle->kind == NETWORK_STREAM) {
        network_stream* stream = (network_stream*)handle;
        __block QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
        network_run(handle, ^{
            if (parameter == QUIC_PARAM_STREAM_PRIORITY) {
                status = network_copy_parameter(
                    &stream->priority, sizeof(stream->priority), size, buffer);
            } else if (parameter == QUIC_PARAM_STREAM_RELIABLE_OFFSET
                && stream->reliable_offset != UINT64_MAX) {
                uint64_t offset = stream->reliable_offset;
                if (stream->state == NETWORK_STREAM_READY && stream->metadata
                    && nw_quic_get_stream_reset_stream_at_reliable_size) {
                    offset = nw_quic_get_stream_reset_stream_at_reliable_size(stream->metadata);
                }
                status = network_copy_parameter(&offset, sizeof(offset), size, buffer);
            }
        });
        return status;
    }
    if (handle->kind != NETWORK_CONNECTION) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    network_connection* connection = (network_connection*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_NOT_SUPPORTED;
    network_run(handle, ^{
        switch (parameter) {
            case QUIC_PARAM_CONN_REMOTE_ADDRESS:
                network_connection_read_address(connection);
                if (connection->address.Ip.sa_family != AF_INET
                    && connection->address.Ip.sa_family != AF_INET6) {
                    break;
                }
                status = network_copy_parameter(
                    &connection->address, sizeof(connection->address), size, buffer);
                break;
            case QUIC_PARAM_CONN_CLOSE_REASON_PHRASE: {
                const char* reason = connection->close_reason;
                if (!reason) {
                    reason = "";
                }
                status = network_copy_parameter(reason, (uint32_t)strlen(reason) + 1, size, buffer);
                break;
            }
            default:
                break;
        }
    });
    return status;
}

static QUIC_STATUS network_set_parameter(
    HQUIC handle, uint32_t parameter, uint32_t size, const void* buffer)
{
    if (!handle || !buffer) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (handle->kind != NETWORK_STREAM) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (handle->state == NETWORK_HANDLE_OPEN) {
            status = network_stream_set_parameter((network_stream*)handle, parameter, size, buffer);
        }
    });
    return status;
}

static const QUIC_API_TABLE network_api = {
    .SetContext = network_set_context,
    .GetContext = network_get_context,
    .SetCallbackHandler = network_set_callback,
    .SetParam = network_set_parameter,
    .GetParam = network_get_parameter,
    .RegistrationOpen = network_registration_open,
    .RegistrationClose = network_registration_close,
    .ConfigurationOpen = network_configuration_open,
    .ConfigurationClose = network_handle_close,
    .ConfigurationLoadCredential = network_configuration_load,
    .ListenerOpen = network_listener_open,
    .ListenerStart = network_listener_start,
    .ListenerStop = network_listener_stop,
    .ListenerClose = network_handle_close,
    .ConnectionOpen = network_connection_open,
    .ConnectionStart = network_connection_start,
    .ConnectionSetConfiguration = network_connection_configure,
    .ConnectionShutdown = network_connection_shutdown,
    .ConnectionClose = network_handle_close,
    .StreamOpen = network_stream_open,
    .StreamStart = network_stream_start,
    .StreamSend = network_stream_send,
    .StreamShutdown = network_stream_shutdown,
    .StreamClose = network_handle_close,
    .StreamReceiveSetEnabled = network_stream_receive_enabled,
    .DatagramSend = network_datagram_send,
};

QUIC_STATUS MsQuicOpenVersion(uint32_t version, const void** api)
{
    if (version != 2 || !api) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    *api = &network_api;
    return QUIC_STATUS_SUCCESS;
}

void MsQuicClose(const void* api)
{
    (void)api;
}

#endif
