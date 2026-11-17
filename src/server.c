#include "types.h"

#ifdef _WIN32
    #include <winsock2.h>
#else
    #include <arpa/inet.h>
#endif

#include "conn.h"
#include "log.h"
#include "utils.h"
#ifdef WTF_QUIC_BACKEND_NETWORK
    #include "quic/network.h"
#endif

static void wtf_quic_addr_set_family(QUIC_ADDR* address, QUIC_ADDRESS_FAMILY family)
{
#ifdef _WIN32
    address->si_family = family;
#else
    address->Ip.sa_family = family;
#endif
}

static void wtf_quic_addr_set_port(QUIC_ADDR* address, uint16_t port)
{
    uint16_t network_port = htons(port);
#ifdef _WIN32
    if (address->si_family == QUIC_ADDRESS_FAMILY_INET) {
        address->Ipv4.sin_port = network_port;
    } else {
        address->Ipv6.sin6_port = network_port;
    }
#else
    if (address->Ip.sa_family == QUIC_ADDRESS_FAMILY_INET) {
        address->Ipv4.sin_port = network_port;
    } else {
        address->Ipv6.sin6_port = network_port;
    }
#endif
}

static QUIC_STATUS QUIC_API wtf_listener_callback(HQUIC Listener WTF_MAYBE_UNUSED, void* Context,
                                                  QUIC_LISTENER_EVENT* Event)
{
    wtf_server* server = (wtf_server*)Context;

    if (!server || !server->context) {
        return QUIC_STATUS_INTERNAL_ERROR;
    }

    switch (Event->Type) {
        case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
            WTF_LOG_INFO(server->context, "server", "New connection received");

            wtf_connection* conn = wtf_connection_create(server, Event->NEW_CONNECTION.Connection);
            if (!conn) {
                WTF_LOG_ERROR(server->context, "server", "Failed to create connection context");
                server->context->quic_api->ConnectionShutdown(
                    Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTF_H3_INTERNAL_ERROR);
                return QUIC_STATUS_SUCCESS;
            }

            mtx_lock(&server->connections_mutex);
            connection_map_itr itr = connection_map_insert(&server->connections, conn->id, conn);
            if (connection_map_is_end(itr)) {
                mtx_unlock(&server->connections_mutex);
                WTF_LOG_ERROR(server->context, "listener", "Failed to add connection to map");
                wtf_connection_destroy(conn);
                server->context->quic_api->ConnectionShutdown(
                    Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTF_H3_INTERNAL_ERROR);
                return QUIC_STATUS_SUCCESS;
            }
            mtx_unlock(&server->connections_mutex);

            server->context->quic_api->SetCallbackHandler(Event->NEW_CONNECTION.Connection,
                                                          wtf_connection_callback, conn);
            wtf_connection_add_ref(conn);

            QUIC_STATUS status = server->context->quic_api->ConnectionSetConfiguration(
                Event->NEW_CONNECTION.Connection, server->configuration);

            if (QUIC_FAILED(status)) {
                WTF_LOG_ERROR(server->context, "server",
                              "Failed to set connection configuration: 0x%x", status);
                server->context->quic_api->ConnectionShutdown(
                    Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                    WTF_H3_INTERNAL_ERROR);
            }

            return QUIC_STATUS_SUCCESS;
        }

        case QUIC_LISTENER_EVENT_STOP_COMPLETE: {
            WTF_LOG_INFO(server->context, "server", "Listener stopped");
            return QUIC_STATUS_SUCCESS;
        }

        default:
            return QUIC_STATUS_SUCCESS;
    }
}

static void wtf_cleanup_server_cred_config(wtf_server* srv)
{
    if (!srv || !srv->cred_config)
        return;

    QUIC_CREDENTIAL_CONFIG* cred_config = srv->cred_config;

    switch (cred_config->Type) {
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
            if (cred_config->CertificateFile) {
                free((void*)cred_config->CertificateFile->CertificateFile);
                free((void*)cred_config->CertificateFile->PrivateKeyFile);
                free(cred_config->CertificateFile);
            }
            break;

        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
            if (cred_config->CertificateFileProtected) {
                free((void*)cred_config->CertificateFileProtected->CertificateFile);
                free((void*)cred_config->CertificateFileProtected->PrivateKeyFile);
                if (cred_config->CertificateFileProtected->PrivateKeyPassword) {
                    size_t pwd_len = strlen(
                        cred_config->CertificateFileProtected->PrivateKeyPassword);
                    memset((void*)cred_config->CertificateFileProtected->PrivateKeyPassword, 0,
                           pwd_len);
                    free((void*)cred_config->CertificateFileProtected->PrivateKeyPassword);
                }
                free(cred_config->CertificateFileProtected);
            }
            break;

        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            if (cred_config->CertificateHash) {
                free(cred_config->CertificateHash);
            }
            break;

        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            if (cred_config->CertificateHashStore) {
                free(cred_config->CertificateHashStore);
            }
            break;

        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
            if (cred_config->CertificatePkcs12) {
                if (cred_config->CertificatePkcs12->Asn1Blob) {
                    memset((void*)cred_config->CertificatePkcs12->Asn1Blob, 0,
                           cred_config->CertificatePkcs12->Asn1BlobLength);
                    free((void*)cred_config->CertificatePkcs12->Asn1Blob);
                }
                if (cred_config->CertificatePkcs12->PrivateKeyPassword) {
                    size_t pwd_len = strlen(cred_config->CertificatePkcs12->PrivateKeyPassword);
                    memset((void*)cred_config->CertificatePkcs12->PrivateKeyPassword, 0, pwd_len);
                    free((void*)cred_config->CertificatePkcs12->PrivateKeyPassword);
                }
                free(cred_config->CertificatePkcs12);
            }
            break;

        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
            break;

        case QUIC_CREDENTIAL_TYPE_NONE:
        default:
            break;
    }

    if (cred_config->Principal) {
        free((void*)cred_config->Principal);
    }
    if (cred_config->CaCertificateFile) {
        free((void*)cred_config->CaCertificateFile);
    }

    free(srv->cred_config);
    srv->cred_config = NULL;
}

static void wtf_cleanup_server_config(wtf_server* srv)
{
    if (!srv) {
        return;
    }

    if (srv->config.host) {
        free((void*)srv->config.host);
        srv->config.host = NULL;
    }
}

wtf_result_t wtf_server_start(wtf_server_t* server)
{
    if (!server) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_server* srv = server;

    mtx_lock(&srv->mutex);

    if (srv->state != WTF_SERVER_STOPPED) {
        mtx_unlock(&srv->mutex);
        return WTF_ERROR_INVALID_STATE;
    }

    srv->state = WTF_SERVER_STARTING;

    WTF_LOG_INFO(srv->context, "server", "Starting WebTransport server on port %u",
                 srv->config.port);

    QUIC_STATUS status = srv->context->quic_api->ListenerOpen(
        srv->context->registration, wtf_listener_callback, srv, &srv->listener);
#ifdef WTF_QUIC_BACKEND_NETWORK
    if (QUIC_SUCCEEDED(status)) {
        status = wtf_network_listener_set_configuration(srv->listener, srv->configuration);
        if (QUIC_FAILED(status)) {
            srv->context->quic_api->ListenerClose(srv->listener);
            srv->listener = NULL;
        }
    }
#endif

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(srv->context, "server", "ListenerOpen failed: 0x%x", status);
        srv->state = WTF_SERVER_STOPPED;
        mtx_unlock(&srv->mutex);
        return wtf_quic_status_to_result(status);
    }

    QUIC_ADDR address = {0};
    wtf_quic_addr_set_family(&address, QUIC_ADDRESS_FAMILY_UNSPEC);


    if (srv->config.host) {
        if (inet_pton(AF_INET, srv->config.host, &((struct sockaddr_in*)&address)->sin_addr) == 1) {
            wtf_quic_addr_set_family(&address, QUIC_ADDRESS_FAMILY_INET);
        } else if (inet_pton(AF_INET6, srv->config.host,
                             &((struct sockaddr_in6*)&address)->sin6_addr)
                   == 1) {
            wtf_quic_addr_set_family(&address, QUIC_ADDRESS_FAMILY_INET6);
        }
    }

    wtf_quic_addr_set_port(&address, srv->config.port);

    const char* alpn = WTF_ALPN;
    QUIC_BUFFER alpn_buffer = {(uint32_t)strlen(alpn), (uint8_t*)alpn};

    status = srv->context->quic_api->ListenerStart(srv->listener, &alpn_buffer, 1, &address);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(srv->context, "server", "ListenerStart failed: 0x%x", status);
        srv->context->quic_api->ListenerClose(srv->listener);
        srv->listener = NULL;
        srv->state = WTF_SERVER_STOPPED;
        mtx_unlock(&srv->mutex);
        return wtf_quic_status_to_result(status);
    }

    srv->state = WTF_SERVER_LISTENING;
    mtx_unlock(&srv->mutex);

    WTF_LOG_INFO(srv->context, "server", "WebTransport server started successfully on port %u",
                 srv->config.port);

    return WTF_SUCCESS;
}

wtf_result_t wtf_server_stop(wtf_server_t* server)
{
    if (!server) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_server* srv = server;

    if (!srv->context) {
        return WTF_ERROR_INVALID_STATE;
    }

    mtx_lock(&srv->mutex);

    if (srv->state != WTF_SERVER_LISTENING) {
        mtx_unlock(&srv->mutex);
        return WTF_ERROR_INVALID_STATE;
    }

    srv->state = WTF_SERVER_STOPPING;

    WTF_LOG_INFO(srv->context, "server", "Stopping WebTransport server");

    if (srv->listener) {
        srv->context->quic_api->ListenerStop(srv->listener);
        srv->context->quic_api->ListenerClose(srv->listener);
        srv->listener = NULL;
    }

    srv->state = WTF_SERVER_STOPPED;
    mtx_unlock(&srv->mutex);

    WTF_LOG_INFO(srv->context, "server", "WebTransport server stopped");

    return WTF_SUCCESS;
}

wtf_server_state_t wtf_server_get_state(wtf_server_t* server)
{
    if (!server) {
        return WTF_SERVER_STOPPED;
    }

    wtf_server* srv = server;

    mtx_lock(&srv->mutex);
    wtf_server_state_t state = srv->state;
    mtx_unlock(&srv->mutex);

    return state;
}

wtf_result_t wtf_server_create(wtf_context_t* context, const wtf_server_config_t* config,
                               wtf_server_t** server)
{
    wtf_result_t result = WTF_SUCCESS;
    wtf_context* ctx = NULL;
    wtf_server_t* srv = NULL;
    QUIC_STATUS status;

    if (!context || !config || !server) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
#ifdef WTF_QUIC_BACKEND_NETWORK
    if (config->draft == WTF_WEBTRANSPORT_DRAFT_15 && !wtf_network_supports_reliable_reset()) {
        return WTF_ERROR_NOT_SUPPORTED;
    }
    if (config && config->enable_0rtt && !wtf_network_supports_early_data()) {
        return WTF_ERROR_NOT_SUPPORTED;
    }
#endif

    ctx = context;

    mtx_lock(&ctx->mutex);

    if (ctx->server) {
        result = WTF_ERROR_INVALID_STATE;
        goto cleanup_unlock_context;
    }

    srv = malloc(sizeof(wtf_server_t));
    if (!srv) {
        result = WTF_ERROR_OUT_OF_MEMORY;
        goto cleanup_unlock_context;
    }

    memset(srv, 0, sizeof(*srv));
    srv->context = ctx;
    srv->config = *config;
    srv->state = WTF_SERVER_STOPPED;

    if (config->host) {
        srv->config.host = wtf_strdup(config->host);
        if (!srv->config.host) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_server;
        }
    }

    connection_map_init(&srv->connections);

    if (mtx_init(&srv->mutex, mtx_plain) != thrd_success) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup_connection_map;
    }

    if (mtx_init(&srv->connections_mutex, mtx_plain) != thrd_success) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup_server_mutex;
    }

    if (cnd_init(&srv->connections_drained) != thrd_success) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup_connections_mutex;
    }

    QUIC_SETTINGS settings = {0};
    settings.IdleTimeoutMs = config->idle_timeout_ms > 0
        ? config->idle_timeout_ms
        : WTF_DEFAULT_IDLE_TIMEOUT_MS;
    settings.IsSet.IdleTimeoutMs = TRUE;
    settings.HandshakeIdleTimeoutMs = config->handshake_timeout_ms > 0
        ? config->handshake_timeout_ms
        : WTF_DEFAULT_HANDSHAKE_TIMEOUT_MS;
    settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
    settings.ServerResumptionLevel = config->enable_0rtt
        ? QUIC_SERVER_RESUME_AND_ZERORTT
        : QUIC_SERVER_RESUME_ONLY;
    settings.IsSet.ServerResumptionLevel = TRUE;
    settings.DatagramReceiveEnabled = TRUE;
    settings.IsSet.DatagramReceiveEnabled = TRUE;
    uint32_t peer_stream_count = config->max_streams_per_session > 0
        ? config->max_streams_per_session
        : WTF_DEFAULT_MAX_STREAMS_PER_SESSION;
    settings.PeerBidiStreamCount = peer_stream_count;
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = peer_stream_count;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    if (config->send_buffering != WTF_SEND_BUFFERING_DEFAULT) {
        settings.SendBufferingEnabled =
            config->send_buffering == WTF_SEND_BUFFERING_ENABLED ? TRUE : FALSE;
        settings.IsSet.SendBufferingEnabled = TRUE;
    }
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    settings.ReliableResetEnabled = TRUE;
    settings.IsSet.ReliableResetEnabled = TRUE;
#endif

    uint32_t stream_recv_window = config->stream_recv_window > 0
        ? config->stream_recv_window
        : WTF_DEFAULT_STREAM_RECV_WINDOW;
    uint64_t max_data_per_session = config->max_data_per_session > 0
        ? config->max_data_per_session
        : WTF_DEFAULT_MAX_DATA_PER_SESSION;
    uint64_t conn_flow_control_window = config->conn_flow_control_window > 0
        ? config->conn_flow_control_window
        : max_data_per_session;
    if (conn_flow_control_window < WTF_DEFAULT_CONN_FLOW_CONTROL_WINDOW) {
        conn_flow_control_window = WTF_DEFAULT_CONN_FLOW_CONTROL_WINDOW;
    }
    if (conn_flow_control_window > UINT32_MAX) {
        conn_flow_control_window = UINT32_MAX;
    }

    settings.StreamRecvWindowDefault = stream_recv_window;
    settings.IsSet.StreamRecvWindowDefault = TRUE;
    settings.ConnFlowControlWindow = (uint32_t)conn_flow_control_window;
    settings.IsSet.ConnFlowControlWindow = TRUE;

    if (config->cert_config == NULL) {
        WTF_LOG_ERROR(ctx, "server", "Certificate configuration is required");
        result = WTF_ERROR_INVALID_PARAMETER;
        goto cleanup_connections_drained;
    }

    srv->cred_config = malloc(sizeof(QUIC_CREDENTIAL_CONFIG));
    if (!srv->cred_config) {
        result = WTF_ERROR_OUT_OF_MEMORY;
        goto cleanup_connections_drained;
    }

    memset(srv->cred_config, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
    srv->cred_config->Flags = QUIC_CREDENTIAL_FLAG_NONE;

    switch (config->cert_config->cert_type) {
        case WTF_CERT_TYPE_NONE:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_NONE;
            srv->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;
            break;

        case WTF_CERT_TYPE_FILE:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
            srv->cred_config->CertificateFile = malloc(sizeof(QUIC_CERTIFICATE_FILE));
            if (!srv->cred_config->CertificateFile) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }

            memset(srv->cred_config->CertificateFile, 0, sizeof(QUIC_CERTIFICATE_FILE));
            if (!config->cert_config->cert_data.file.cert_path
                || !config->cert_config->cert_data.file.key_path
                || !wtf_path_valid(config->cert_config->cert_data.file.cert_path)
                || !wtf_path_valid(config->cert_config->cert_data.file.key_path)) {
                WTF_LOG_ERROR(ctx, "server", "Invalid certificate or key file path");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }

            srv->cred_config->CertificateFile->CertificateFile = wtf_strdup(
                config->cert_config->cert_data.file.cert_path);
            srv->cred_config->CertificateFile->PrivateKeyFile = wtf_strdup(
                config->cert_config->cert_data.file.key_path);

            if (!srv->cred_config->CertificateFile->CertificateFile
                || !srv->cred_config->CertificateFile->PrivateKeyFile) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }
            break;

        case WTF_CERT_TYPE_FILE_PROTECTED:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
            srv->cred_config->CertificateFileProtected = malloc(
                sizeof(QUIC_CERTIFICATE_FILE_PROTECTED));
            if (!srv->cred_config->CertificateFileProtected) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }
            memset(srv->cred_config->CertificateFileProtected, 0,
                   sizeof(QUIC_CERTIFICATE_FILE_PROTECTED));

            if (!config->cert_config->cert_data.protected_file.cert_path
                || !config->cert_config->cert_data.protected_file.key_path
                || !config->cert_config->cert_data.protected_file.password
                || !wtf_path_valid(config->cert_config->cert_data.protected_file.cert_path)
                || !wtf_path_valid(config->cert_config->cert_data.protected_file.key_path)) {
                WTF_LOG_ERROR(ctx, "server",
                              "Invalid certificate or key file path, or missing "
                              "password for protected certificate");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }

            srv->cred_config->CertificateFileProtected->CertificateFile = wtf_strdup(
                config->cert_config->cert_data.protected_file.cert_path);
            srv->cred_config->CertificateFileProtected->PrivateKeyFile = wtf_strdup(
                config->cert_config->cert_data.protected_file.key_path);
            srv->cred_config->CertificateFileProtected->PrivateKeyPassword = wtf_strdup(
                config->cert_config->cert_data.protected_file.password);

            if (!srv->cred_config->CertificateFileProtected->CertificateFile
                || !srv->cred_config->CertificateFileProtected->PrivateKeyFile
                || !srv->cred_config->CertificateFileProtected->PrivateKeyPassword) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }
            break;

        case WTF_CERT_TYPE_HASH:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
            srv->cred_config->CertificateHash = malloc(sizeof(QUIC_CERTIFICATE_HASH));
            if (!srv->cred_config->CertificateHash) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }

            if (!wtf_parse_thumbprint(config->cert_config->cert_data.hash.thumbprint,
                                      srv->cred_config->CertificateHash->ShaHash)) {
                WTF_LOG_ERROR(ctx, "server", "Invalid certificate thumbprint format");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }
            break;

        case WTF_CERT_TYPE_HASH_STORE:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
            srv->cred_config->CertificateHashStore = malloc(sizeof(QUIC_CERTIFICATE_HASH_STORE));
            if (!srv->cred_config->CertificateHashStore) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }

            if (!config->cert_config->cert_data.hash_store.store_name) {
                WTF_LOG_ERROR(ctx, "server", "Certificate store name is required");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }

            srv->cred_config->CertificateHashStore->Flags = 0;  // Default flags

            if (!wtf_parse_thumbprint(config->cert_config->cert_data.hash_store.thumbprint,
                                      srv->cred_config->CertificateHashStore->ShaHash)) {
                WTF_LOG_ERROR(ctx, "server", "Invalid certificate thumbprint format");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }

            wtf_strncpy(srv->cred_config->CertificateHashStore->StoreName,
                        config->cert_config->cert_data.hash_store.store_name,
                        sizeof(srv->cred_config->CertificateHashStore->StoreName));
            break;

        case WTF_CERT_TYPE_CONTEXT:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
            srv->cred_config->CertificateContext
                = (QUIC_CERTIFICATE*)config->cert_config->cert_data.context;
            break;

        case WTF_CERT_TYPE_PKCS12:
            srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
            srv->cred_config->CertificatePkcs12 = malloc(sizeof(QUIC_CERTIFICATE_PKCS12));
            if (!srv->cred_config->CertificatePkcs12) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }
            memset(srv->cred_config->CertificatePkcs12, 0, sizeof(QUIC_CERTIFICATE_PKCS12));

            if (!config->cert_config->cert_data.pkcs12.data
                || config->cert_config->cert_data.pkcs12.data_size == 0) {
                WTF_LOG_ERROR(ctx, "server", "Invalid PKCS#12 certificate data");
                result = WTF_ERROR_INVALID_PARAMETER;
                goto cleanup_cred_config;
            }

            srv->cred_config->CertificatePkcs12->Asn1Blob = malloc(
                config->cert_config->cert_data.pkcs12.data_size);
            if (!srv->cred_config->CertificatePkcs12->Asn1Blob) {
                result = WTF_ERROR_OUT_OF_MEMORY;
                goto cleanup_cred_config;
            }

            memcpy((void*)srv->cred_config->CertificatePkcs12->Asn1Blob,
                   config->cert_config->cert_data.pkcs12.data,
                   config->cert_config->cert_data.pkcs12.data_size);
            srv->cred_config->CertificatePkcs12->Asn1BlobLength
                = (uint32_t)config->cert_config->cert_data.pkcs12.data_size;
            if (config->cert_config->cert_data.pkcs12.password) {
                srv->cred_config->CertificatePkcs12->PrivateKeyPassword = wtf_strdup(
                    config->cert_config->cert_data.pkcs12.password);
                if (!srv->cred_config->CertificatePkcs12->PrivateKeyPassword) {
                    result = WTF_ERROR_OUT_OF_MEMORY;
                    goto cleanup_cred_config;
                }
            }
            break;

        default:
            WTF_LOG_ERROR(ctx, "server", "Invalid certificate type: %d",
                          config->cert_config->cert_type);
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
    }

    if (config->cert_config->principal) {
        srv->cred_config->Principal = wtf_strdup(config->cert_config->principal);
        if (!srv->cred_config->Principal) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
    }

    if (config->cert_config->ca_cert_file) {
        srv->cred_config->CaCertificateFile = wtf_strdup(config->cert_config->ca_cert_file);
        if (!srv->cred_config->CaCertificateFile) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        srv->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    }

    const char* alpn = WTF_ALPN;
    QUIC_BUFFER alpn_buffer = {(uint32_t)strlen(alpn), (uint8_t*)alpn};

    status = ctx->quic_api->ConfigurationOpen(ctx->registration, &alpn_buffer, 1, &settings,
                                              sizeof(settings), NULL, &srv->configuration);

    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(ctx, "server", "ConfigurationOpen failed: 0x%x", status);
        result = wtf_quic_status_to_result(status);
        goto cleanup_cred_config;
    }

    status = ctx->quic_api->ConfigurationLoadCredential(srv->configuration, srv->cred_config);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(ctx, "server", "ConfigurationLoadCredential failed: 0x%x", status);
        result = wtf_quic_status_to_result(status);
        goto cleanup_configuration;
    }

    ctx->server = srv;
    mtx_unlock(&ctx->mutex);

    WTF_LOG_INFO(ctx, "server", "WebTransport server created successfully");

    *server = srv;
    return WTF_SUCCESS;

cleanup_configuration:
    ctx->quic_api->ConfigurationClose(srv->configuration);

cleanup_cred_config:
    wtf_cleanup_server_cred_config(srv);

cleanup_connections_drained:
    cnd_destroy(&srv->connections_drained);

cleanup_connections_mutex:
    mtx_destroy(&srv->connections_mutex);

cleanup_server_mutex:
    mtx_destroy(&srv->mutex);

cleanup_connection_map:
    connection_map_cleanup(&srv->connections);

cleanup_server:
    wtf_cleanup_server_config(srv);
    free(srv);

cleanup_unlock_context:
    mtx_unlock(&ctx->mutex);
    return result;
}

void wtf_server_destroy(wtf_server_t* server)
{
    if (!server) {
        return;
    }

    wtf_server* srv = server;
    wtf_context* ctx = srv->context;

    WTF_LOG_INFO(ctx, "server", "Destroying WebTransport server");

    if (srv->state == WTF_SERVER_LISTENING) {
        wtf_server_stop(server);
    }

    size_t connection_count = 0;
    wtf_connection** connections = NULL;

    mtx_lock(&srv->connections_mutex);
    srv->destroying = true;
    connection_count = connection_map_size(&srv->connections);
    if (connection_count > 0) {
        connections = malloc(sizeof(*connections) * connection_count);
        if (connections) {
            size_t index = 0;
            for (connection_map_itr itr = connection_map_first(&srv->connections);
                 !connection_map_is_end(itr) && index < connection_count;
                 itr = connection_map_next(itr)) {
                wtf_connection* conn = itr.data->val;
                wtf_connection_add_ref(conn);
                connections[index++] = conn;
            }
            connection_count = index;
        }
    }
    mtx_unlock(&srv->connections_mutex);

    if (connections) {
        for (size_t i = 0; i < connection_count; i++) {
            wtf_connection* conn = connections[i];
            HQUIC connection = conn->quic_connection;
            if (connection && ctx && ctx->quic_api) {
                ctx->quic_api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
                ctx->quic_api->ConnectionClose(connection);
                conn->quic_connection = NULL;
            }
            wtf_connection_release(conn);
        }
        free(connections);
    } else if (connection_count > 0) {
        mtx_lock(&srv->connections_mutex);
        while (connection_map_size(&srv->connections) > 0) {
            cnd_wait(&srv->connections_drained, &srv->connections_mutex);
        }
        mtx_unlock(&srv->connections_mutex);
    }

    mtx_lock(&srv->connections_mutex);
    while (connection_map_size(&srv->connections) > 0) {
        connection_map_itr itr = connection_map_first(&srv->connections);
        if (connection_map_is_end(itr)) {
            break;
        }
        wtf_connection* conn = itr.data->val;
        connection_map_erase(&srv->connections, conn->id);
        wtf_connection_release(conn);
    }

    connection_map_cleanup(&srv->connections);
    mtx_unlock(&srv->connections_mutex);

    if (srv->configuration) {
        ctx->quic_api->ConfigurationClose(srv->configuration);
        srv->configuration = NULL;
    }

    wtf_cleanup_server_cred_config(srv);
    wtf_cleanup_server_config(srv);

    if (ctx) {
        mtx_lock(&ctx->mutex);
        if (ctx->server == srv) {
            ctx->server = NULL;
        }
        mtx_unlock(&ctx->mutex);
    }

    cnd_destroy(&srv->connections_drained);
    mtx_destroy(&srv->connections_mutex);
    mtx_destroy(&srv->mutex);

    free(server);
}
