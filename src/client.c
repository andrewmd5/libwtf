#include "types.h"

#include "cert.h"
#include "client.h"
#include "conn.h"
#include "http3.h"
#include "log.h"
#include "session.h"
#include "utils.h"

static bool wtf_client_valid_draft(wtf_webtransport_draft_t draft)
{
    return draft == WTF_WEBTRANSPORT_DRAFT_AUTO || draft == WTF_WEBTRANSPORT_DRAFT_02
        || draft == WTF_WEBTRANSPORT_DRAFT_07 || draft == WTF_WEBTRANSPORT_DRAFT_15;
}

static bool wtf_client_valid_congestion_control(wtf_congestion_control_t congestion_control)
{
    return congestion_control == WTF_CONGESTION_CONTROL_DEFAULT
        || congestion_control == WTF_CONGESTION_CONTROL_THROUGHPUT
        || congestion_control == WTF_CONGESTION_CONTROL_LOW_LATENCY;
}

static char* wtf_format_authority(const char* host, uint16_t port, bool ipv6_literal)
{
    int len = snprintf(NULL, 0, ipv6_literal ? "[%s]:%u" : "%s:%u", host, port);
    if (len <= 0) {
        return NULL;
    }

    char* authority = malloc((size_t)len + 1);
    if (!authority) {
        return NULL;
    }

    snprintf(authority, (size_t)len + 1, ipv6_literal ? "[%s]:%u" : "%s:%u", host, port);
    return authority;
}

static wtf_result_t wtf_parse_client_url(const char* url, char** host, uint16_t* port,
                                         char** authority, char** path)
{
    if (!url || !host || !port || !authority || !path) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *host = NULL;
    *authority = NULL;
    *path = NULL;
    *port = 0;

    const char scheme[] = "https://";
    size_t scheme_len = sizeof(scheme) - 1;
    if (strncmp(url, scheme, scheme_len) != 0 || strchr(url, '#')) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    const char* cursor = url + scheme_len;
    const char* authority_end = strpbrk(cursor, "/?");
    if (!authority_end) {
        authority_end = url + strlen(url);
    }
    if (authority_end == cursor || memchr(cursor, '@', (size_t)(authority_end - cursor))) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    bool ipv6_literal = false;
    const char* host_start = cursor;
    const char* host_end = NULL;
    const char* port_start = NULL;

    if (*cursor == '[') {
        ipv6_literal = true;
        host_start = cursor + 1;
        host_end = memchr(host_start, ']', (size_t)(authority_end - host_start));
        if (!host_end || host_end == host_start || host_end + 1 >= authority_end
            || host_end[1] != ':') {
            return WTF_ERROR_INVALID_PARAMETER;
        }
        port_start = host_end + 2;
    } else {
        const char* colon = memchr(cursor, ':', (size_t)(authority_end - cursor));
        if (!colon || colon == cursor || colon + 1 >= authority_end) {
            return WTF_ERROR_INVALID_PARAMETER;
        }
        host_end = colon;
        port_start = colon + 1;
    }

    uint32_t parsed_port = 0;
    for (const char* p = port_start; p < authority_end; p++) {
        if (*p < '0' || *p > '9') {
            return WTF_ERROR_INVALID_PARAMETER;
        }
        parsed_port = parsed_port * 10u + (uint32_t)(*p - '0');
        if (parsed_port > UINT16_MAX) {
            return WTF_ERROR_INVALID_PARAMETER;
        }
    }
    if (parsed_port == 0) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    char* parsed_host = wtf_strndup(host_start, (size_t)(host_end - host_start));
    if (!parsed_host) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    char* parsed_authority = wtf_format_authority(parsed_host, (uint16_t)parsed_port, ipv6_literal);
    if (!parsed_authority) {
        free(parsed_host);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    char* parsed_path = NULL;
    if (*authority_end == '\0') {
        parsed_path = wtf_strdup("/");
    } else if (*authority_end == '?') {
        size_t query_len = strlen(authority_end);
        parsed_path = malloc(query_len + 2);
        if (parsed_path) {
            parsed_path[0] = '/';
            memcpy(parsed_path + 1, authority_end, query_len + 1);
        }
    } else {
        parsed_path = wtf_strdup(authority_end);
    }

    if (!parsed_path) {
        free(parsed_authority);
        free(parsed_host);
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    *host = parsed_host;
    *authority = parsed_authority;
    *path = parsed_path;
    *port = (uint16_t)parsed_port;
    return WTF_SUCCESS;
}

static void wtf_cleanup_client_cred_config(wtf_client* client)
{
    if (!client || !client->cred_config) {
        return;
    }

    if (client->cred_config->CaCertificateFile) {
        free((void*)client->cred_config->CaCertificateFile);
    }

    free(client->cred_config);
    client->cred_config = NULL;
}

static void wtf_cleanup_client_config(wtf_client* client)
{
    if (!client) {
        return;
    }

    free((void*)client->config.url);
    free((void*)client->config.origin);
    free((void*)client->config.ca_cert_file);
    free((void*)client->config.pinned_server_certificate_file);

    for (size_t i = 0; i < client->config.header_count; i++) {
        free((void*)client->config.headers[i].name);
        free((void*)client->config.headers[i].value);
    }
    free((void*)client->config.headers);

    free(client->host);
    free(client->authority);
    free(client->path);
    client->host = NULL;
    client->authority = NULL;
    client->path = NULL;

    memset(&client->config, 0, sizeof(client->config));
    client->pinned_server_certificate_present = false;
    memset(client->pinned_server_certificate_sha256, 0,
           sizeof(client->pinned_server_certificate_sha256));
}

static wtf_result_t wtf_client_load_pinned_server_certificate(wtf_client* client,
                                                              const char* path);

static wtf_result_t wtf_copy_client_headers(wtf_client* client, const wtf_client_config_t* config)
{
    if (config->header_count == 0) {
        client->config.headers = NULL;
        client->config.header_count = 0;
        return WTF_SUCCESS;
    }

    if (!config->headers) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_http_header_t* headers = calloc(config->header_count, sizeof(*headers));
    if (!headers) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    for (size_t i = 0; i < config->header_count; i++) {
        if (!config->headers[i].name || !config->headers[i].value
            || config->headers[i].name[0] == ':') {
            for (size_t j = 0; j < i; j++) {
                free((void*)headers[j].name);
                free((void*)headers[j].value);
            }
            free(headers);
            return WTF_ERROR_INVALID_PARAMETER;
        }

        headers[i].name = wtf_strdup(config->headers[i].name);
        headers[i].value = wtf_strdup(config->headers[i].value);
        if (!headers[i].name || !headers[i].value) {
            for (size_t j = 0; j <= i; j++) {
                free((void*)headers[j].name);
                free((void*)headers[j].value);
            }
            free(headers);
            return WTF_ERROR_OUT_OF_MEMORY;
        }
    }

    client->config.headers = headers;
    client->config.header_count = config->header_count;
    return WTF_SUCCESS;
}

static wtf_result_t wtf_copy_client_config(wtf_client* client, const wtf_client_config_t* config)
{
    if (!client || !config || !config->url || !wtf_client_valid_draft(config->draft)
        || !wtf_client_valid_congestion_control(config->congestion_control)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
    if ((config->skip_certificate_validation
         && (config->ca_cert_file || config->pinned_server_certificate_file))
        || (config->ca_cert_file && config->pinned_server_certificate_file)) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    client->config = *config;
    client->config.url = wtf_strdup(config->url);
    client->config.origin = config->origin ? wtf_strdup(config->origin) : NULL;
    client->config.ca_cert_file = config->ca_cert_file ? wtf_strdup(config->ca_cert_file) : NULL;
    client->config.pinned_server_certificate_file = config->pinned_server_certificate_file
        ? wtf_strdup(config->pinned_server_certificate_file)
        : NULL;
    client->config.headers = NULL;
    client->config.header_count = 0;

    if (!client->config.url || (config->origin && !client->config.origin)
        || (config->ca_cert_file && !client->config.ca_cert_file)
        || (config->pinned_server_certificate_file
            && !client->config.pinned_server_certificate_file)) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    wtf_result_t result = wtf_parse_client_url(
        config->url, &client->host, &client->port, &client->authority, &client->path);
    if (result != WTF_SUCCESS) {
        return result;
    }

    result = wtf_copy_client_headers(client, config);
    if (result != WTF_SUCCESS) {
        return result;
    }

    if (client->config.pinned_server_certificate_file) {
        result = wtf_client_load_pinned_server_certificate(
            client, client->config.pinned_server_certificate_file);
        if (result != WTF_SUCCESS) {
            return result;
        }
    }

    return WTF_SUCCESS;
}

static wtf_result_t wtf_client_load_pinned_server_certificate(wtf_client* client,
                                                              const char* path)
{
    if (!client || !path) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    uint8_t* der = NULL;
    size_t der_len = 0;
    wtf_result_t result = wtf_cert_load_der_from_file(path, &der, &der_len);
    if (result != WTF_SUCCESS) {
        return result;
    }

    bool hashed = wtf_cert_sha256(der, der_len, client->pinned_server_certificate_sha256);
    free(der);
    if (!hashed) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    client->pinned_server_certificate_present = true;
    return WTF_SUCCESS;
}

bool wtf_client_has_pinned_server_certificate(const wtf_client* client)
{
    return client && client->pinned_server_certificate_present;
}

bool wtf_client_validate_pinned_server_certificate(wtf_client* client,
                                                   const QUIC_BUFFER* certificate)
{
    if (!client || !client->pinned_server_certificate_present) {
        return true;
    }

    if (!certificate || !certificate->Buffer || certificate->Length == 0) {
        return false;
    }

    uint8_t received_hash[WTF_CERT_SHA256_SIZE];
    if (!wtf_cert_sha256(certificate->Buffer, certificate->Length, received_hash)) {
        return false;
    }

    return memcmp(received_hash, client->pinned_server_certificate_sha256,
                  WTF_CERT_SHA256_SIZE)
        == 0;
}

void wtf_client_mark_transport_ready(wtf_client* client)
{
    if (!client) {
        return;
    }

    mtx_lock(&client->mutex);
    if (client->state == WTF_CLIENT_CONNECTING || client->state == WTF_CLIENT_DISCONNECTED) {
        client->state = WTF_CLIENT_CONNECTED;
    }
    client->flags |= WTF_CLIENT_FLAG_TRANSPORT_READY;
    cnd_broadcast(&client->connected);
    mtx_unlock(&client->mutex);
}

void wtf_client_note_session_closed(wtf_client* client)
{
    if (!client) {
        return;
    }

    mtx_lock(&client->mutex);
    if (client->opened_session_count > 0) {
        client->opened_session_count--;
    }
    mtx_unlock(&client->mutex);
}

void wtf_client_fail_pending_sessions(wtf_client* client, wtf_result_t result, const char* reason)
{
    if (!client) {
        return;
    }

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
        wtf_session* session = head->webtransport_session;
        if (session && session->state != WTF_SESSION_CLOSED) {
            session->state = WTF_SESSION_CLOSED;
            wtf_client_note_session_closed(client);
            if (session->callback) {
                wtf_session_event_t event = {
                    .type = WTF_SESSION_EVENT_DISCONNECTED,
                    .session = (wtf_session_t*)session,
                    .user_context = session->user_context,
                    .disconnected = {.error_code = (uint32_t)result, .reason = reason}};
                session->callback(&event);
            }
        }
        wtf_http3_stream_destroy(head);
        head = next;
    }
}

static wtf_result_t wtf_client_start_connection(wtf_client* cli)
{
    wtf_context* ctx = cli->context;
    wtf_connection* conn = wtf_connection_create_client(cli, NULL);
    if (!conn) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    QUIC_STATUS status = ctx->quic_api->ConnectionOpen(
        ctx->registration, wtf_connection_callback, conn, &cli->quic_connection);
    if (QUIC_FAILED(status)) {
        wtf_connection_destroy(conn);
        return wtf_quic_status_to_result(status);
    }

    conn->quic_connection = cli->quic_connection;
    cli->connection = conn;
    wtf_connection_add_ref(conn);

    status = ctx->quic_api->ConnectionStart(cli->quic_connection, cli->configuration,
                                            QUIC_ADDRESS_FAMILY_UNSPEC, cli->host,
                                            cli->port);
    if (QUIC_FAILED(status)) {
        ctx->quic_api->ConnectionClose(cli->quic_connection);
        cli->quic_connection = NULL;
        cli->connection = NULL;
        wtf_connection_release(conn);
        wtf_connection_destroy(conn);
        return wtf_quic_status_to_result(status);
    }

    cli->flags |= WTF_CLIENT_FLAG_TRANSPORT_STARTED;
    return WTF_SUCCESS;
}

wtf_result_t wtf_client_create(wtf_context_t* context, const wtf_client_config_t* config,
                               wtf_client_t** client)
{
    if (!context || !config || !client) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *client = NULL;
    wtf_context* ctx = context;
    wtf_result_t result = WTF_SUCCESS;
    QUIC_STATUS status = QUIC_STATUS_SUCCESS;

    mtx_lock(&ctx->mutex);
    if (ctx->client) {
        mtx_unlock(&ctx->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    mtx_unlock(&ctx->mutex);

    wtf_client* cli = calloc(1, sizeof(*cli));
    if (!cli) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }

    cli->context = ctx;
    cli->state = WTF_CLIENT_DISCONNECTED;

    result = wtf_copy_client_config(cli, config);
    if (result != WTF_SUCCESS) {
        goto cleanup_client;
    }

    if (mtx_init(&cli->mutex, mtx_plain) != thrd_success) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup_config;
    }

    if (cnd_init(&cli->connected) != thrd_success) {
        result = WTF_ERROR_INTERNAL;
        goto cleanup_mutex;
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
    settings.DatagramReceiveEnabled = TRUE;
    settings.IsSet.DatagramReceiveEnabled = TRUE;

    uint32_t max_sessions = config->allow_pooling
        ? (config->max_sessions_per_connection > 0 ? config->max_sessions_per_connection
                                                   : WTF_DEFAULT_MAX_SESSIONS)
        : 1;
    uint32_t max_streams_per_session = config->max_streams_per_session > 0
        ? config->max_streams_per_session
        : WTF_DEFAULT_MAX_STREAMS_PER_SESSION;
    uint32_t peer_stream_count = max_streams_per_session;
    if (max_sessions > 1 && peer_stream_count <= UINT16_MAX / max_sessions) {
        peer_stream_count *= max_sessions;
    } else if (max_sessions > 1) {
        peer_stream_count = UINT16_MAX;
    }
    if (peer_stream_count > UINT16_MAX) {
        peer_stream_count = UINT16_MAX;
    }
    settings.PeerBidiStreamCount = (uint16_t)peer_stream_count;
    settings.IsSet.PeerBidiStreamCount = TRUE;
    settings.PeerUnidiStreamCount = (uint16_t)peer_stream_count;
    settings.IsSet.PeerUnidiStreamCount = TRUE;
    if (config->send_buffering != WTF_SEND_BUFFERING_DEFAULT) {
        settings.SendBufferingEnabled =
            config->send_buffering == WTF_SEND_BUFFERING_ENABLED ? TRUE : FALSE;
        settings.IsSet.SendBufferingEnabled = TRUE;
    }
    settings.PacingEnabled = TRUE;
    settings.IsSet.PacingEnabled = TRUE;
    settings.MigrationEnabled = config->enable_migration ? TRUE : FALSE;
    settings.IsSet.MigrationEnabled = TRUE;
    if (config->congestion_control == WTF_CONGESTION_CONTROL_THROUGHPUT) {
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
        settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_BBR;
#else
        settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
#endif
        settings.IsSet.CongestionControlAlgorithm = TRUE;
    } else if (config->congestion_control == WTF_CONGESTION_CONTROL_LOW_LATENCY) {
        settings.CongestionControlAlgorithm = QUIC_CONGESTION_CONTROL_ALGORITHM_CUBIC;
        settings.IsSet.CongestionControlAlgorithm = TRUE;
        settings.MaxWorkerQueueDelayUs = 1000;
        settings.IsSet.MaxWorkerQueueDelayUs = TRUE;
    }

    uint32_t stream_recv_window = config->stream_recv_window > 0
        ? config->stream_recv_window
        : WTF_DEFAULT_STREAM_RECV_WINDOW;
    uint64_t max_data_per_session = config->max_data_per_session > 0
        ? config->max_data_per_session
        : WTF_DEFAULT_MAX_DATA_PER_SESSION;
    uint64_t conn_flow_control_window = config->conn_flow_control_window > 0
        ? config->conn_flow_control_window
        : max_data_per_session * max_sessions;
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
#ifdef QUIC_API_ENABLE_PREVIEW_FEATURES
    settings.ReliableResetEnabled = TRUE;
    settings.IsSet.ReliableResetEnabled = TRUE;
#endif

    cli->cred_config = calloc(1, sizeof(*cli->cred_config));
    if (!cli->cred_config) {
        result = WTF_ERROR_OUT_OF_MEMORY;
        goto cleanup_cond;
    }

    cli->cred_config->Type = QUIC_CREDENTIAL_TYPE_NONE;
    cli->cred_config->Flags = QUIC_CREDENTIAL_FLAG_CLIENT;
    if (config->skip_certificate_validation || cli->pinned_server_certificate_present) {
        cli->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_NO_CERTIFICATE_VALIDATION;
    }
    if (cli->pinned_server_certificate_present) {
        cli->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_INDICATE_CERTIFICATE_RECEIVED
            | QUIC_CREDENTIAL_FLAG_USE_PORTABLE_CERTIFICATES;
    }
    if (cli->config.ca_cert_file) {
        cli->cred_config->CaCertificateFile = wtf_strdup(cli->config.ca_cert_file);
        if (!cli->cred_config->CaCertificateFile) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred;
        }
        cli->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
    }

    const char* alpn = WTF_ALPN;
    QUIC_BUFFER alpn_buffer = {(uint32_t)strlen(alpn), (uint8_t*)alpn};
    status = ctx->quic_api->ConfigurationOpen(ctx->registration, &alpn_buffer, 1, &settings,
                                              sizeof(settings), NULL, &cli->configuration);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(ctx, "client", "ConfigurationOpen failed: 0x%x", status);
        result = wtf_quic_status_to_result(status);
        goto cleanup_cred;
    }

    status = ctx->quic_api->ConfigurationLoadCredential(cli->configuration, cli->cred_config);
    if (QUIC_FAILED(status)) {
        WTF_LOG_ERROR(ctx, "client", "ConfigurationLoadCredential failed: 0x%x", status);
        result = wtf_quic_status_to_result(status);
        goto cleanup_configuration;
    }

    mtx_lock(&ctx->mutex);
    ctx->client = cli;
    mtx_unlock(&ctx->mutex);

    *client = cli;
    return WTF_SUCCESS;

cleanup_configuration:
    ctx->quic_api->ConfigurationClose(cli->configuration);
    cli->configuration = NULL;

cleanup_cred:
    wtf_cleanup_client_cred_config(cli);

cleanup_cond:
    cnd_destroy(&cli->connected);

cleanup_mutex:
    mtx_destroy(&cli->mutex);

cleanup_config:
    wtf_cleanup_client_config(cli);

cleanup_client:
    free(cli);
    return result;
}

wtf_result_t wtf_client_open(wtf_client_t* client, wtf_session_t** session)
{
    if (!client || !session) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    *session = NULL;
    wtf_client* cli = client;
    if (!cli->context || !cli->configuration) {
        return WTF_ERROR_INVALID_STATE;
    }

    mtx_lock(&cli->mutex);
    if (cli->state == WTF_CLIENT_CLOSING || cli->state == WTF_CLIENT_CLOSED) {
        mtx_unlock(&cli->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    if (!cli->config.allow_pooling && cli->opened_session_count > 0) {
        mtx_unlock(&cli->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    bool start_connection = cli->connection == NULL;
    if (start_connection) {
        cli->state = WTF_CLIENT_CONNECTING;
        cli->flags = WTF_CLIENT_FLAG_NONE;
    }
    mtx_unlock(&cli->mutex);

    if (start_connection) {
        wtf_result_t result = wtf_client_start_connection(cli);
        if (result != WTF_SUCCESS) {
            mtx_lock(&cli->mutex);
            cli->state = WTF_CLIENT_CLOSED;
            mtx_unlock(&cli->mutex);
            return result;
        }
    }

    return wtf_http3_client_open_session(cli, (wtf_session**)session);
}

wtf_result_t wtf_client_connect(wtf_client_t* client, wtf_session_t** session)
{
    return wtf_client_open(client, session);
}

wtf_result_t wtf_client_disconnect(wtf_client_t* client, uint32_t error_code, const char* reason)
{
    if (!client) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    wtf_client* cli = client;
    mtx_lock(&cli->mutex);
    if (cli->state == WTF_CLIENT_DISCONNECTED || cli->state == WTF_CLIENT_CLOSED) {
        mtx_unlock(&cli->mutex);
        return WTF_ERROR_INVALID_STATE;
    }
    cli->state = WTF_CLIENT_CLOSING;
    HQUIC connection = cli->quic_connection;
    mtx_unlock(&cli->mutex);

    const char* shutdown_reason = reason ? reason : "Connection shutdown";
    wtf_client_fail_pending_sessions(cli, WTF_ERROR_CONNECTION_ABORTED, shutdown_reason);

    if (connection && cli->context && cli->context->quic_api) {
        cli->context->quic_api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
                                                   wtf_map_webtransport_error_to_h3(error_code));
    }

    return WTF_SUCCESS;
}

wtf_client_state_t wtf_client_get_state(wtf_client_t* client)
{
    if (!client) {
        return WTF_CLIENT_CLOSED;
    }

    wtf_client* cli = client;
    mtx_lock(&cli->mutex);
    wtf_client_state_t state = cli->state;
    mtx_unlock(&cli->mutex);
    return state;
}

void wtf_client_destroy(wtf_client_t* client)
{
    if (!client) {
        return;
    }

    wtf_client* cli = client;
    wtf_context* ctx = cli->context;

    wtf_client_fail_pending_sessions(cli, WTF_ERROR_CONNECTION_ABORTED, "Client destroyed");

    mtx_lock(&cli->mutex);
    HQUIC connection = cli->quic_connection;
    if (connection && cli->state != WTF_CLIENT_CLOSED) {
        cli->state = WTF_CLIENT_CLOSING;
        cli->quic_connection = NULL;
    }
    mtx_unlock(&cli->mutex);

    if (connection && ctx && ctx->quic_api) {
        ctx->quic_api->ConnectionShutdown(connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
        ctx->quic_api->ConnectionClose(connection);
    }

    if (cli->connection) {
        wtf_connection_destroy(cli->connection);
        cli->connection = NULL;
    }

    if (cli->configuration && ctx && ctx->quic_api) {
        ctx->quic_api->ConfigurationClose(cli->configuration);
        cli->configuration = NULL;
    }

    wtf_cleanup_client_cred_config(cli);
    wtf_cleanup_client_config(cli);

    if (ctx) {
        mtx_lock(&ctx->mutex);
        if (ctx->client == cli) {
            ctx->client = NULL;
        }
        mtx_unlock(&ctx->mutex);
    }

    cnd_destroy(&cli->connected);
    mtx_destroy(&cli->mutex);
    free(cli);
}
