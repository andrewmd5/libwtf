#include <stdio.h>
#include <time.h>

#include "quic/network_internal.h"

typedef struct {
    dispatch_semaphore_t connected;
    dispatch_semaphore_t closed;
    dispatch_semaphore_t received;
    dispatch_semaphore_t stream_closed;
    dispatch_semaphore_t sent;
    bool resumed;
    bool early_data;
} network_test_connection;

static const QUIC_API_TABLE* network_test_api;
static HQUIC network_test_configuration;
static uint8_t network_test_payload = 0x5a;
static QUIC_BUFFER network_test_pending_buffer = {1, &network_test_payload};

static void network_test_check(QUIC_STATUS status, const char* operation)
{
    if (QUIC_FAILED(status)) {
        fprintf(stderr, "%s failed: 0x%x\n", operation, status);
        exit(1);
    }
}

static void network_test_wait(dispatch_semaphore_t semaphore, const char* operation)
{
    if (dispatch_semaphore_wait(semaphore, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) {
        fprintf(stderr, "%s timed out\n", operation);
        exit(1);
    }
}

static QUIC_STATUS QUIC_API network_test_stream_event(
    HQUIC handle, void* context, QUIC_STREAM_EVENT* event)
{
    network_test_connection* client = context;
    if (event->Type == QUIC_STREAM_EVENT_RECEIVE) {
        if (event->RECEIVE.TotalBufferLength != 1 || event->RECEIVE.BufferCount != 1
            || event->RECEIVE.Buffers[0].Buffer[0] != network_test_payload) {
            fprintf(stderr, "unexpected stream payload\n");
            exit(1);
        }
    } else if (event->Type == QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN) {
        if (client) {
            dispatch_semaphore_signal(client->received);
        } else {
            network_connection* parent = (network_connection*)handle->parent;
            if (parent->state != NETWORK_CONNECTION_READY) {
                return QUIC_STATUS_SUCCESS;
            }
            HQUIC reply = handle;
            QUIC_SEND_FLAGS flags = QUIC_SEND_FLAG_FIN;
            if (((network_stream*)handle)->origin == NETWORK_STREAM_PEER_UNI) {
                network_test_check(network_test_api->StreamOpen(handle->parent,
                                       QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                                       network_test_stream_event, NULL, &reply),
                    "open reply stream");
                flags |= QUIC_SEND_FLAG_START;
            }
            QUIC_BUFFER buffer = {1, &network_test_payload};
            network_test_check(
                network_test_api->StreamSend(reply, &buffer, 1, flags, NULL), "reply");
        }
    } else if (event->Type == QUIC_STREAM_EVENT_SEND_COMPLETE && client) {
        dispatch_semaphore_signal(client->sent);
    } else if (event->Type == QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE) {
        network_test_api->StreamClose(handle);
        if (client) {
            dispatch_semaphore_signal(client->stream_closed);
        }
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API network_test_connection_event(
    HQUIC handle, void* context, QUIC_CONNECTION_EVENT* event)
{
    network_test_connection* client = context;
    if (event->Type == QUIC_CONNECTION_EVENT_CONNECTED && client) {
        client->resumed = event->CONNECTED.SessionResumed;
        network_connection* connection = (network_connection*)handle;
        sec_protocol_metadata_t tls = nw_quic_copy_sec_protocol_metadata(connection->metadata);
        if (tls) {
            client->early_data = sec_protocol_metadata_get_early_data_accepted(tls);
            nw_release(tls);
        }
        dispatch_semaphore_signal(client->connected);
    } else if (event->Type == QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED) {
        network_test_api->SetCallbackHandler(
            event->PEER_STREAM_STARTED.Stream, network_test_stream_event, client);
    } else if (event->Type == QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE) {
        network_test_api->ConnectionClose(handle);
        if (client) {
            dispatch_semaphore_signal(client->closed);
        }
    }
    return QUIC_STATUS_SUCCESS;
}

static QUIC_STATUS QUIC_API network_test_listener_event(
    HQUIC listener, void* context, QUIC_LISTENER_EVENT* event)
{
    (void)listener;
    (void)context;
    if (event->Type == QUIC_LISTENER_EVENT_NEW_CONNECTION) {
        HQUIC connection = event->NEW_CONNECTION.Connection;
        network_test_api->SetCallbackHandler(connection, network_test_connection_event, NULL);
        return network_test_api->ConnectionSetConfiguration(connection, network_test_configuration);
    }
    return QUIC_STATUS_SUCCESS;
}

int main(int argc, char** argv)
{
    if (argc != 3) {
        return 2;
    }
    if (!wtf_network_supports_early_data()) {
        puts("SKIP: native session-state APIs unavailable");
        return 0;
    }
    HQUIC registration;
    network_test_check(MsQuicOpen2(&network_test_api), "open API");
    network_test_check(network_test_api->RegistrationOpen(NULL, &registration), "registration");
    QUIC_SETTINGS settings = {0};
    settings.ServerResumptionLevel = QUIC_SERVER_RESUME_AND_ZERORTT;
    settings.IsSet.ServerResumptionLevel = true;
    settings.PeerBidiStreamCount = 4;
    settings.IsSet.PeerBidiStreamCount = true;
    settings.PeerUnidiStreamCount = 4;
    settings.IsSet.PeerUnidiStreamCount = true;
    settings.HandshakeIdleTimeoutMs = 3000;
    settings.IsSet.HandshakeIdleTimeoutMs = true;
    settings.SendBufferingEnabled = false;
    settings.IsSet.SendBufferingEnabled = true;
    QUIC_BUFFER alpn = {2, (uint8_t*)"h3"};
    network_test_check(network_test_api->ConfigurationOpen(registration, &alpn, 1, &settings,
                           sizeof(settings), NULL, &network_test_configuration),
        "server configuration");
    QUIC_CERTIFICATE_FILE certificate = {argv[2], argv[1]};
    QUIC_CREDENTIAL_CONFIG credentials = {0};
    credentials.Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
    credentials.CertificateFile = &certificate;
    network_test_check(
        network_test_api->ConfigurationLoadCredential(network_test_configuration, &credentials),
        "server credentials");
    HQUIC listener;
    network_test_check(
        network_test_api->ListenerOpen(registration, network_test_listener_event, NULL, &listener),
        "listener");
    network_test_check(wtf_network_listener_set_configuration(listener, network_test_configuration),
        "listener configuration");
    QUIC_ADDR address = {0};
    address.Ipv4.sin_family = AF_INET;
    address.Ipv4.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    network_test_check(network_test_api->ListenerStart(listener, &alpn, 1, &address), "listen");
    uint16_t port = nw_listener_get_port(((network_listener*)listener)->listener);

    HQUIC client_configuration;
    network_test_check(network_test_api->ConfigurationOpen(registration, &alpn, 1, &settings,
                           sizeof(settings), NULL, &client_configuration),
        "client configuration");
    credentials = (QUIC_CREDENTIAL_CONFIG) {0};
    credentials.Flags = QUIC_CREDENTIAL_FLAG_CLIENT
        | QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    network_test_check(
        network_test_api->ConfigurationLoadCredential(client_configuration, &credentials),
        "client credentials");

    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        network_test_connection client = {0};
        client.connected = dispatch_semaphore_create(0);
        client.closed = dispatch_semaphore_create(0);
        client.received = dispatch_semaphore_create(0);
        client.stream_closed = dispatch_semaphore_create(0);
        client.sent = dispatch_semaphore_create(0);
        HQUIC connection;
        network_test_check(network_test_api->ConnectionOpen(
                               registration, network_test_connection_event, &client, &connection),
            "open connection");
        network_test_check(network_test_api->ConnectionStart(connection, client_configuration,
                               QUIC_ADDRESS_FAMILY_UNSPEC, "localhost", port),
            "start connection");
        network_test_wait(client.connected, "connect");
        if (client.resumed != (attempt == 1) || client.early_data != (attempt == 1)) {
            fprintf(stderr, "attempt=%u resumed=%u early_data=%u\n", attempt, client.resumed,
                client.early_data);
            return 1;
        }
        HQUIC open_stream;
        network_test_check(network_test_api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_NONE,
                               network_test_stream_event, &client, &open_stream),
            "open long-lived stream");
        uint16_t priority = 0x1234;
        network_test_check(network_test_api->SetParam(open_stream, QUIC_PARAM_STREAM_PRIORITY,
                               sizeof(priority), &priority),
            "stream priority");
        QUIC_BUFFER open_buffer = {1, &network_test_payload};
        network_test_check(
            network_test_api->StreamSend(open_stream, &open_buffer, 1, QUIC_SEND_FLAG_START, NULL),
            "send without FIN");
        network_test_wait(client.sent, "completion without FIN");
        network_test_check(
            network_test_api->StreamSend(open_stream, NULL, 0, QUIC_SEND_FLAG_FIN, NULL),
            "finish long-lived stream");
        network_test_wait(client.received, "long-lived stream echo");
        network_test_wait(client.sent, "FIN completion");
        network_test_wait(client.stream_closed, "long-lived stream close");
        for (unsigned transfer = 0; transfer < 32; ++transfer) {
            HQUIC stream;
            QUIC_STREAM_OPEN_FLAGS flags = QUIC_STREAM_OPEN_FLAG_NONE;
            if (transfer % 2) {
                flags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
            }
            network_test_check(network_test_api->StreamOpen(
                                   connection, flags, network_test_stream_event, &client, &stream),
                "open stream");
            QUIC_BUFFER buffer = {1, &network_test_payload};
            network_test_check(network_test_api->StreamSend(stream, &buffer, 1,
                                   QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN, NULL),
                "send stream");
        }
        for (unsigned transfer = 0; transfer < 32; ++transfer) {
            network_test_wait(client.received, "stream echo");
            network_test_wait(client.sent, "send completion");
            network_test_wait(client.stream_closed, "stream close");
            if (transfer % 2) {
                network_test_wait(client.stream_closed, "reply stream close");
            }
        }
        /* TLS tickets arrive after the handshake. */
        struct timespec delay = {.tv_sec = 1};
        nanosleep(&delay, NULL);
        if (attempt == 0) {
            network_test_api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
            network_test_wait(client.closed, "close");
        } else {
            for (unsigned pending = 0; pending < 32; ++pending) {
                HQUIC stream;
                network_test_check(
                    network_test_api->StreamOpen(connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
                        network_test_stream_event, &client, &stream),
                    "open pending stream");
                network_test_check(
                    network_test_api->StreamSend(stream, &network_test_pending_buffer, 1,
                        QUIC_SEND_FLAG_START | QUIC_SEND_FLAG_FIN, NULL),
                    "send pending stream");
            }
            network_test_api->ConnectionClose(connection);
        }
        dispatch_release(client.connected);
        dispatch_release(client.closed);
        dispatch_release(client.received);
        dispatch_release(client.stream_closed);
        dispatch_release(client.sent);
    }
    network_test_api->ConfigurationClose(client_configuration);
    network_test_api->ListenerClose(listener);
    network_test_api->ConfigurationClose(network_test_configuration);
    network_test_api->RegistrationClose(registration);
    MsQuicClose(network_test_api);
    puts("PASS: stream credit replenished; second connection resumed with 0-RTT accepted");
    return 0;
}
