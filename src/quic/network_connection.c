#if defined(__APPLE__) && defined(WTF_QUIC_BACKEND_NETWORK)
    #include "network_internal.h"

static void network_connection_stop_handshake_timer(network_connection* connection)
{
    dispatch_source_t timer = connection->handshake_timer;
    if (!timer) {
        return;
    }
    connection->handshake_timer = NULL;
    dispatch_source_cancel(timer);
    dispatch_release(timer);
}

static void network_connection_start_handshake_timer(network_connection* connection)
{
    uint64_t timeout = connection->configuration->settings.HandshakeIdleTimeoutMs;
    if (!connection->configuration->settings.IsSet.HandshakeIdleTimeoutMs || !timeout) {
        return;
    }
    network_handle_retain((HQUIC)connection);
    dispatch_source_t timer = dispatch_source_create(
        DISPATCH_SOURCE_TYPE_TIMER, 0, 0, connection->handle.queue);
    connection->handshake_timer = timer;
    uint64_t interval = INT64_MAX;
    if (timeout <= INT64_MAX / NSEC_PER_MSEC) {
        interval = timeout * NSEC_PER_MSEC;
    }
    dispatch_source_set_timer(
        timer, dispatch_time(DISPATCH_TIME_NOW, (int64_t)interval), DISPATCH_TIME_FOREVER, 0);
    dispatch_source_set_cancel_handler(timer, ^{
        network_handle_release((HQUIC)connection);
    });
    dispatch_source_set_event_handler(timer, ^{
        network_connection_stop_handshake_timer(connection);
        if (connection->state != NETWORK_CONNECTION_STARTING
            || connection->handle.state != NETWORK_HANDLE_OPEN) {
            return;
        }
        connection->state = NETWORK_CONNECTION_REMOTE_CLOSE;
        QUIC_CONNECTION_EVENT event = {
            .Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT};
        event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = QUIC_STATUS_CONNECTION_TIMEOUT;
        network_emit_connection(connection, &event);
        nw_connection_group_cancel(connection->group);
    });
    dispatch_resume(timer);
}

void network_connection_read_address(network_connection* connection)
{
    if (!connection->group) {
        return;
    }
    if (connection->datagram) {
        nw_path_t path = nw_connection_copy_current_path(connection->datagram);
        if (path) {
            nw_endpoint_t endpoint = nw_path_copy_effective_remote_endpoint(path);
            if (endpoint) {
                const struct sockaddr* address = nw_endpoint_get_address(endpoint);
                if (address && address->sa_family == AF_INET) {
                    memcpy(&connection->address, address, sizeof(struct sockaddr_in));
                } else if (address && address->sa_family == AF_INET6) {
                    memcpy(&connection->address, address, sizeof(struct sockaddr_in6));
                }
                nw_release(endpoint);
            }
            nw_release(path);
            if (connection->address.Ip.sa_family) {
                return;
            }
        }
    }
    nw_group_descriptor_t descriptor = nw_connection_group_copy_descriptor(connection->group);
    nw_group_descriptor_enumerate_endpoints(descriptor, ^bool(nw_endpoint_t endpoint) {
        const struct sockaddr* address = nw_endpoint_get_address(endpoint);
        if (!address) {
            return true;
        }
        if (address->sa_family == AF_INET) {
            memcpy(&connection->address, address, sizeof(struct sockaddr_in));
            return false;
        }
        if (address->sa_family == AF_INET6) {
            memcpy(&connection->address, address, sizeof(struct sockaddr_in6));
            return false;
        }
        return true;
    });
    nw_release(descriptor);
}

static void network_connection_indicate_shutdown(network_connection* connection, nw_error_t error)
{
    if (connection->state != NETWORK_CONNECTION_READY
        && connection->state != NETWORK_CONNECTION_STARTING) {
        return;
    }
    connection->state = NETWORK_CONNECTION_REMOTE_CLOSE;
    QUIC_CONNECTION_EVENT event = {.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT};
    event.SHUTDOWN_INITIATED_BY_TRANSPORT.Status = network_error_status(error);
    nw_protocol_metadata_t metadata = connection->metadata;
    if (metadata) {
        uint64_t code = nw_quic_get_application_error(metadata);
        const char* reason = nw_quic_get_application_error_reason(metadata);
        if (reason) {
            free(connection->close_reason);
            connection->close_reason = strdup(reason);
        }
        if (code != UINT64_MAX) {
            event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
            event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = code;
            connection->close_code = code;
        }
    }
    network_emit_connection(connection, &event);
}

void network_connection_finish(network_connection* connection)
{
    if (connection->state != NETWORK_CONNECTION_DRAINING
        || network_stream_map_size(&connection->streams) || connection->sends.count) {
        return;
    }
    connection->state = NETWORK_CONNECTION_COMPLETE;
    QUIC_CONNECTION_EVENT event = {.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE};
    event.SHUTDOWN_COMPLETE.AppCloseInProgress = connection->handle.state != NETWORK_HANDLE_OPEN;
    network_emit_connection(connection, &event);
}

static void network_connection_receive_datagram(network_connection* connection)
{
    if (connection->handle.state != NETWORK_HANDLE_OPEN
        || connection->state != NETWORK_CONNECTION_READY
        || connection->datagram_state != NETWORK_DATAGRAM_READY) {
        return;
    }
    network_handle_retain((HQUIC)connection);
    nw_connection_receive_message(connection->datagram,
        ^(dispatch_data_t content, nw_content_context_t context, bool complete, nw_error_t error) {
            (void)context;
            (void)complete;
            if (connection->handle.state == NETWORK_HANDLE_OPEN && content) {
                const void* bytes;
                size_t length;
                dispatch_data_t mapped = dispatch_data_create_map(content, &bytes, &length);
                QUIC_BUFFER buffer = {(uint32_t)length, (uint8_t*)bytes};
                QUIC_CONNECTION_EVENT event = {.Type = QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED};
                event.DATAGRAM_RECEIVED.Buffer = &buffer;
                network_emit_connection(connection, &event);
                dispatch_release(mapped);
            }
            if (!error) {
                network_connection_receive_datagram(connection);
            }
            network_handle_release((HQUIC)connection);
        });
}

static void network_connection_open_datagram(network_connection* connection)
{
    nw_protocol_options_t options = nw_quic_create_options();
    nw_quic_set_stream_is_datagram(options, true);
    connection->datagram = nw_connection_group_extract_connection(connection->group, NULL, options);
    nw_release(options);
    if (!connection->datagram) {
        return;
    }
    connection->datagram_state = NETWORK_DATAGRAM_STARTING;
    network_handle_retain((HQUIC)connection);
    nw_connection_set_queue(connection->datagram, connection->handle.queue);
    nw_connection_set_state_changed_handler(
        connection->datagram, ^(nw_connection_state_t state, nw_error_t error) {
            (void)error;
            if (state == nw_connection_state_ready
                && connection->state == NETWORK_CONNECTION_READY) {
                connection->datagram_state = NETWORK_DATAGRAM_READY;
                nw_protocol_metadata_t metadata = nw_connection_copy_protocol_metadata(
                    connection->datagram, network_quic_definition());
                if (metadata) {
                    connection->datagram_size = nw_quic_get_stream_usable_datagram_frame_size(
                        metadata);
                    nw_release(metadata);
                }
                QUIC_CONNECTION_EVENT event = {
                    .Type = QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED};
                event.DATAGRAM_STATE_CHANGED.SendEnabled = connection->datagram_size > 0;
                event.DATAGRAM_STATE_CHANGED.MaxSendLength = connection->datagram_size;
                network_emit_connection(connection, &event);
                network_connection_receive_datagram(connection);
            } else if (state == nw_connection_state_failed) {
                nw_connection_cancel(connection->datagram);
            } else if (state == nw_connection_state_cancelled) {
                connection->datagram_state = NETWORK_DATAGRAM_CLOSED;
                nw_connection_set_state_changed_handler(connection->datagram, NULL);
                network_handle_release((HQUIC)connection);
            }
        });
    nw_connection_start(connection->datagram);
}

static void network_connection_cancel_streams(network_connection* connection)
{
    for (network_stream_map_itr entry = network_stream_map_first(&connection->streams);
        !network_stream_map_is_end(entry); entry = network_stream_map_next(entry)) {
        network_stream* stream = entry.data->val;
        stream->receive_state = NETWORK_RECEIVE_ABORTED;
        if (stream->send_state == NETWORK_SEND_OPEN
            || stream->send_state == NETWORK_SEND_FIN_PENDING) {
            stream->send_state = NETWORK_SEND_ABORT_PENDING;
        }
        network_stream_cancel(stream);
    }
}

void network_connection_start_group(network_connection* connection)
{
    connection->state = NETWORK_CONNECTION_STARTING;
    network_handle_retain((HQUIC)connection);
    nw_connection_group_set_queue(connection->group, connection->handle.queue);
    nw_connection_group_set_new_connection_handler(connection->group, ^(nw_connection_t incoming) {
        if (connection->handle.state != NETWORK_HANDLE_OPEN
            || connection->state >= NETWORK_CONNECTION_LOCAL_CLOSE) {
            nw_connection_cancel(incoming);
            return;
        }
        network_stream_accept(connection, incoming);
    });
    nw_connection_group_set_state_changed_handler(
        connection->group, ^(nw_connection_group_state_t state, nw_error_t error) {
            if (state == nw_connection_group_state_ready
                && connection->state == NETWORK_CONNECTION_STARTING
                && connection->handle.state == NETWORK_HANDLE_OPEN) {
                connection->state = NETWORK_CONNECTION_READY;
                connection->local_max_streams_bidi
                    = connection->configuration->settings.PeerBidiStreamCount;
                connection->local_max_streams_uni
                    = connection->configuration->settings.PeerUnidiStreamCount;
                network_connection_stop_handshake_timer(connection);
                connection->metadata = nw_connection_group_copy_protocol_metadata(
                    connection->group, network_quic_definition());
                if (connection->metadata) {
                    nw_retain(connection->metadata);
                }
                network_connection_read_address(connection);
                if (connection->configuration->settings.DatagramReceiveEnabled) {
                    network_connection_open_datagram(connection);
                }
                QUIC_CONNECTION_EVENT event = {
                    .Type = QUIC_CONNECTION_EVENT_RELIABLE_RESET_NEGOTIATED};
                nw_protocol_metadata_t metadata = connection->metadata;
                if (metadata) {
                    if (wtf_network_supports_reliable_reset()) {
                        event.RELIABLE_RESET_NEGOTIATED.IsNegotiated
                            = nw_quic_get_reset_stream_at_supported(metadata);
                    }
                }
                network_emit_connection(connection, &event);
                if (connection->state != NETWORK_CONNECTION_READY) {
                    return;
                }
                event = (QUIC_CONNECTION_EVENT) {.Type = QUIC_CONNECTION_EVENT_CONNECTED};
                if (connection->metadata) {
                    sec_protocol_metadata_t tls = nw_quic_copy_sec_protocol_metadata(
                        connection->metadata);
                    if (tls) {
                        if (sec_protocol_metadata_get_session_resumed) {
                            event.CONNECTED.SessionResumed
                                = sec_protocol_metadata_get_session_resumed(tls);
                        }
                        WTF_LOG_TRACE(network_logging_context((HQUIC)connection),
                            "network.connection", "Connected: resumed=%u early_data=%u",
                            event.CONNECTED.SessionResumed,
                            sec_protocol_metadata_get_early_data_accepted(tls));
                        nw_release(tls);
                    }
                }
                event.CONNECTED.NegotiatedAlpn = (uint8_t*)connection->configuration->alpn;
                event.CONNECTED.NegotiatedAlpnLength = (uint8_t)strlen(
                    connection->configuration->alpn);
                network_emit_connection(connection, &event);
                return;
            }
            if (state != nw_connection_group_state_failed
                && state != nw_connection_group_state_cancelled) {
                return;
            }
            network_connection_stop_handshake_timer(connection);
            network_connection_indicate_shutdown(connection, error);
            if (connection->datagram) {
                nw_connection_cancel(connection->datagram);
            }
            network_connection_cancel_streams(connection);
            if (state == nw_connection_group_state_failed) {
                nw_connection_group_cancel(connection->group);
                return;
            }
            connection->state = NETWORK_CONNECTION_DRAINING;
            nw_connection_group_set_state_changed_handler(connection->group, NULL);
            nw_connection_group_set_new_connection_handler(connection->group, NULL);
            network_connection_finish(connection);
            network_handle_release((HQUIC)connection);
        });
    network_connection_start_handshake_timer(connection);
    nw_connection_group_start(connection->group);
}

QUIC_STATUS network_connection_open(
    HQUIC registration, QUIC_CONNECTION_CALLBACK_HANDLER callback, void* context, HQUIC* out)
{
    if (!registration || !callback || !out) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    HQUIC handle = network_handle_create(
        NETWORK_CONNECTION, sizeof(network_connection), registration);
    if (!handle) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    }
    handle->callback = callback;
    handle->context = context;
    *out = handle;
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS network_connection_configure(HQUIC handle, HQUIC configuration)
{
    if (!handle || !configuration) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_connection* connection = (network_connection*)handle;
    if ((HQUIC)connection->configuration != configuration) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS network_connection_start(
    HQUIC handle, HQUIC configuration, QUIC_ADDRESS_FAMILY family, const char* host, uint16_t port)
{
    (void)family;
    if (!handle || !configuration || !host) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    network_connection* connection = (network_connection*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (handle->state != NETWORK_HANDLE_OPEN
            || connection->state != NETWORK_CONNECTION_CREATED) {
            return;
        }
        connection->configuration = (network_configuration*)network_handle_retain(configuration);
        char service[8];
        snprintf(service, sizeof(service), "%u", port);
        nw_endpoint_t endpoint = nw_endpoint_create_host(host, service);
        nw_group_descriptor_t descriptor = nw_group_descriptor_create_multiplex(endpoint);
        nw_parameters_t parameters = network_parameters_create(
            connection, connection->configuration, host, port);
        connection->group = nw_connection_group_create(descriptor, parameters);
        nw_release(parameters);
        nw_release(descriptor);
        nw_release(endpoint);
        if (!connection->group) {
            network_handle_release((HQUIC)connection->configuration);
            connection->configuration = NULL;
            status = QUIC_STATUS_OUT_OF_MEMORY;
            return;
        }
        network_connection_start_group(connection);
        status = QUIC_STATUS_SUCCESS;
    });
    return status;
}

void network_connection_shutdown(
    HQUIC handle, QUIC_CONNECTION_SHUTDOWN_FLAGS flags, QUIC_UINT62 code)
{
    (void)flags;
    if (!handle) {
        return;
    }
    network_connection* connection = (network_connection*)handle;
    network_run(handle, ^{
        if (connection->state >= NETWORK_CONNECTION_LOCAL_CLOSE) {
            return;
        }
        connection->state = NETWORK_CONNECTION_LOCAL_CLOSE;
        connection->close_code = code;
        if (!connection->group) {
            connection->state = NETWORK_CONNECTION_DRAINING;
            network_connection_cancel_streams(connection);
            network_connection_finish(connection);
            return;
        }
        nw_protocol_metadata_t metadata = connection->metadata;
        if (metadata) {
            /* Network's implementation requires a non-null reason string. */
            nw_quic_set_application_error(metadata, code, "");
        }
        nw_connection_group_cancel(connection->group);
    });
}

void network_connection_close(network_connection* connection)
{
    connection->state = NETWORK_CONNECTION_LOCAL_CLOSE;
    network_connection_stop_handshake_timer(connection);
    network_send_cancel_all((HQUIC)connection);
    while (network_stream_map_size(&connection->streams)) {
        network_stream_map_itr entry = network_stream_map_first(&connection->streams);
        network_stream* stream = entry.data->val;
        network_stream_map_erase_itr(&connection->streams, entry);
        network_handle_retain((HQUIC)stream);
        network_stream_detach(stream);
        network_handle_release((HQUIC)stream);
    }
    if (connection->datagram) {
        nw_connection_cancel(connection->datagram);
    }
    if (connection->group) {
        nw_connection_group_cancel(connection->group);
    }
}

void network_connection_dispose(network_connection* connection)
{
    if (connection->group) {
        nw_release(connection->group);
    }
    if (connection->datagram) {
        nw_release(connection->datagram);
    }
    if (connection->metadata) {
        nw_release(connection->metadata);
    }
    network_stream_map_cleanup(&connection->streams);
    network_handle_release((HQUIC)connection->configuration);
    free(connection->close_reason);
}

QUIC_STATUS network_datagram_send(
    HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count, QUIC_SEND_FLAGS flags, void* context)
{
    if (!handle || !buffers || !count) {
        return QUIC_STATUS_INVALID_PARAMETER;
    }
    if (flags != QUIC_SEND_FLAG_NONE) {
        return QUIC_STATUS_NOT_SUPPORTED;
    }
    network_connection* connection = (network_connection*)handle;
    __block QUIC_STATUS status = QUIC_STATUS_INVALID_STATE;
    network_run(handle, ^{
        if (handle->state != NETWORK_HANDLE_OPEN
            || connection->datagram_state != NETWORK_DATAGRAM_READY) {
            return;
        }
        size_t length;
        status = network_send_validate(buffers, count, connection->datagram_size, &length);
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
        nw_connection_send(connection->datagram, data, NW_CONNECTION_DEFAULT_MESSAGE_CONTEXT, true,
            ^(nw_error_t error) {
                network_send_complete(operation, error);
            });
        dispatch_release(data);
    });
    return status;
}
#endif
