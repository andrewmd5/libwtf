#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include "network_internal.h"

QUIC_STATUS network_listener_open(
    HQUIC registration, QUIC_LISTENER_CALLBACK_HANDLER callback, void* context, HQUIC* out)
{
    if (!registration || !callback || !out) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    HQUIC handle = network_handle_create(NETWORK_LISTENER, sizeof(network_listener), registration);
    if (!handle) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    handle->callback = callback;
    handle->context = context;
    *out = handle;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS wtf_network_listener_set_configuration(HQUIC handle, HQUIC configuration)
{
    if (!handle || !configuration || handle->kind != NETWORK_LISTENER
        || configuration->kind != NETWORK_CONFIGURATION) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_listener* listener = (network_listener*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (listener->state != NETWORK_LISTENER_CREATED || listener->configuration) {
            return;
        }
        listener->configuration = (network_configuration*)network_handle_retain(configuration);
        status = QUIC_STATUS_SUCCESS;
    });
    return status;
}

static void network_listener_accept_connection(
    network_listener* listener, nw_connection_group_t group)
{
    HQUIC handle = &listener->handle;
    if (handle->state != NETWORK_HANDLE_OPEN || listener->state != NETWORK_LISTENER_READY) {
        nw_connection_group_cancel(group);
        return;
    }
    network_connection* connection = (network_connection*)network_handle_create(
        NETWORK_CONNECTION, sizeof(*connection), handle->parent);
    if (!connection) {
        nw_connection_group_cancel(group);
        return;
    }
    connection->configuration = (network_configuration*)network_handle_retain(
        (HQUIC)listener->configuration);
    connection->group = nw_retain(group);
    network_handle_retain((HQUIC)connection);
    QUIC_NEW_CONNECTION_INFO info = {0};
    info.RemoteAddress = &connection->address;
    QUIC_LISTENER_EVENT event = {.Type = QUIC_LISTENER_EVENT_NEW_CONNECTION};
    event.NEW_CONNECTION.Info = &info;
    event.NEW_CONNECTION.Connection = (HQUIC)connection;
    QUIC_STATUS status = ((QUIC_LISTENER_CALLBACK_HANDLER)handle->callback)(
        handle, handle->context, &event);
    network_run((HQUIC)connection, ^{
        if (QUIC_FAILED(status)) {
            network_handle_close((HQUIC)connection);
        } else if (connection->handle.state == NETWORK_HANDLE_OPEN) {
            network_connection_start_group(connection);
        }
    });
    network_handle_release((HQUIC)connection);
}

QUIC_STATUS network_listener_start(
    HQUIC handle, const QUIC_BUFFER* alpns, uint32_t count, const QUIC_ADDR* address)
{
    if (!handle || !address || !alpns || !count) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_listener* listener = (network_listener*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (handle->state != NETWORK_HANDLE_OPEN || listener->state != NETWORK_LISTENER_CREATED) {
            return;
        }
        network_configuration* configuration = listener->configuration;
        if (!configuration || !configuration->identity) {
            return;
        }
        listener->startup = dispatch_semaphore_create(0);
        listener->startup_status = QUIC_STATUS_PENDING;
        char port[8];
        snprintf(port, sizeof(port), "%u", QuicAddrGetPort(address));
        nw_parameters_t parameters = network_parameters_create(NULL, configuration, NULL, 0);
        if (!QuicAddrIsWildCard(address)) {
            nw_endpoint_t endpoint = nw_endpoint_create_address((const struct sockaddr*)address);
            nw_parameters_set_local_endpoint(parameters, endpoint);
            nw_release(endpoint);
        }
        listener->listener = nw_listener_create_with_port(port, parameters);
        nw_release(parameters);
        if (!listener->listener) {
            status = QUIC_STATUS_INVALID_PARAMETER;
            return;
        }
        listener->state = NETWORK_LISTENER_STARTING;
        network_handle_retain(handle);
        nw_listener_set_queue(listener->listener, handle->queue);
        nw_listener_set_new_connection_group_handler(
            listener->listener, ^(nw_connection_group_t group) {
                network_listener_accept_connection(listener, group);
            });
        nw_listener_set_state_changed_handler(
            listener->listener, ^(nw_listener_state_t state, nw_error_t error) {
                if (state == nw_listener_state_ready
                    && listener->state == NETWORK_LISTENER_STARTING) {
                    listener->state = NETWORK_LISTENER_READY;
                    listener->startup_status = QUIC_STATUS_SUCCESS;
                    dispatch_semaphore_signal(listener->startup);
                } else if (state == nw_listener_state_failed) {
                    listener->startup_status = network_error_status(error);
                    WTF_LOG_ERROR(network_logging_context(handle), "network.listener",
                        "Listener failed: 0x%x", listener->startup_status);
                    dispatch_semaphore_signal(listener->startup);
                    listener->state = NETWORK_LISTENER_STOPPING;
                    nw_listener_cancel(listener->listener);
                } else if (state == nw_listener_state_cancelled) {
                    listener->state = NETWORK_LISTENER_STOPPED;
                    if (handle->state == NETWORK_HANDLE_OPEN && handle->callback) {
                        QUIC_LISTENER_EVENT event = {.Type = QUIC_LISTENER_EVENT_STOP_COMPLETE};
                        ((QUIC_LISTENER_CALLBACK_HANDLER)handle->callback)(
                            handle, handle->context, &event);
                    }
                    nw_listener_set_state_changed_handler(listener->listener, NULL);
                    nw_listener_set_new_connection_group_handler(listener->listener, NULL);
                    network_handle_release(handle);
                }
            });
        nw_listener_start(listener->listener);
        status = QUIC_STATUS_SUCCESS;
    });
    if (QUIC_FAILED(status)) {
        return status;
    }
    if (dispatch_semaphore_wait(
            listener->startup, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
        network_listener_stop(handle);
        return QUIC_STATUS_CONNECTION_TIMEOUT;
    }
    network_run(handle, ^{
        status = listener->startup_status;
    });
    return status;
}

void network_listener_stop(HQUIC handle)
{
    if (handle) {
        network_run(handle, ^{
            network_listener_close((network_listener*)handle);
        });
    }
}

void network_listener_close(network_listener* listener)
{
    if (listener->listener && listener->state < NETWORK_LISTENER_STOPPING) {
        listener->state = NETWORK_LISTENER_STOPPING;
        nw_listener_cancel(listener->listener);
    }
}

void network_listener_dispose(network_listener* listener)
{
    if (listener->listener) {
        nw_release(listener->listener);
    }
    if (listener->startup) {
        dispatch_release(listener->startup);
    }
    network_handle_release((HQUIC)listener->configuration);
}
#endif
