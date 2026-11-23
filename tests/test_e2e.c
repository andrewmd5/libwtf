#include "wtf.h"

#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#endif

#ifndef WTF_TEST_CERT_DIR
    #define WTF_TEST_CERT_DIR "certs"
#endif

#define WTF_E2E_PORT 44443

typedef enum {
    E2E_ENDPOINT_CLIENT,
    E2E_ENDPOINT_SERVER
} e2e_endpoint_t;

typedef struct {
    atomic_int client_connected;
    atomic_int client_disconnected;
    atomic_int server_connected;
    atomic_int server_disconnected;
    atomic_int client_seen_auth_response;
    atomic_int client_seen_auth_rejection;
    atomic_int server_seen_auth_header;
    atomic_uint client_max_datagram_size;
    atomic_uint server_max_datagram_size;
    atomic_uintptr_t deferred_handle;
} e2e_state_t;

typedef struct {
    e2e_state_t* state;
    e2e_endpoint_t endpoint;
} e2e_callback_context_t;

static void sleep_ms(unsigned milliseconds)
{
#ifdef _WIN32
    Sleep(milliseconds);
#else
    struct timespec delay = {
        .tv_sec = (time_t)(milliseconds / 1000),
        .tv_nsec = (long)((milliseconds % 1000) * 1000000),
    };
    nanosleep(&delay, NULL);
#endif
}

static bool has_header(const wtf_http_header_t* headers, size_t count,
                       const char* name, const char* value)
{
    for (size_t i = 0; i < count; i++) {
        if (headers[i].name && headers[i].value && strcmp(headers[i].name, name) == 0
            && strcmp(headers[i].value, value) == 0) {
            return true;
        }
    }
    return false;
}

static void e2e_session_callback(const wtf_session_event_t* event)
{
    if (!event || !event->user_context) {
        return;
    }

    e2e_callback_context_t* callback_context = event->user_context;
    e2e_state_t* state = callback_context->state;

    switch (event->type) {
        case WTF_SESSION_EVENT_CONNECTED:
            if (callback_context->endpoint == E2E_ENDPOINT_CLIENT) {
                atomic_store(&state->client_max_datagram_size,
                             wtf_session_get_max_datagram_size(event->session));
                if (event->connected.status_code == 200
                    && has_header(event->connected.headers, event->connected.header_count,
                                  "x-auth-result", "ok")) {
                    atomic_store(&state->client_seen_auth_response, 1);
                }
                atomic_fetch_add(&state->client_connected, 1);
            } else {
                atomic_store(&state->server_max_datagram_size,
                             wtf_session_get_max_datagram_size(event->session));
                atomic_fetch_add(&state->server_connected, 1);
            }
            break;

        case WTF_SESSION_EVENT_DISCONNECTED:
            if (callback_context->endpoint == E2E_ENDPOINT_CLIENT) {
                if (event->disconnected.status_code == 403
                    && event->disconnected.error_code == WTF_ERROR_REJECTED
                    && has_header(event->disconnected.headers, event->disconnected.header_count,
                                  "x-auth-result", "denied")) {
                    atomic_store(&state->client_seen_auth_rejection, 1);
                }
                atomic_fetch_add(&state->client_disconnected, 1);
            } else {
                atomic_fetch_add(&state->server_disconnected, 1);
            }
            break;

        default:
            break;
    }
}

static wtf_connection_decision_t e2e_connection_validator(
    const wtf_connection_request_t* request, wtf_connection_response_t* response,
    void* user_data)
{
    e2e_callback_context_t* callback_context = user_data;
    e2e_state_t* state = callback_context ? callback_context->state : NULL;
    if (!request || !has_header(request->headers, request->header_count,
                                "authorization", "Bearer libwtf-e2e")) {
        return WTF_CONNECTION_ACCEPT;
    }

    if (state) {
        atomic_store(&state->server_seen_auth_header, 1);
        uintptr_t expected = 0;
        if (request->handle
            && atomic_compare_exchange_strong(&state->deferred_handle, &expected,
                                              (uintptr_t)request->handle)) {
            return WTF_CONNECTION_DEFER;
        }
    }

    if (wtf_connection_response_add_header(response, "x-auth-result", "ok") != WTF_SUCCESS) {
        return WTF_CONNECTION_REJECT;
    }
    return WTF_CONNECTION_ACCEPT;
}

static void e2e_log_callback(wtf_log_level_t level, const char* component, const char* file,
                             int line, const char* message, void* user_context)
{
    const char* label = user_context ? user_context : "e2e";
    fprintf(stderr, "[%s:%d] %s %s:%d %s\n", label, (int)level,
            component ? component : "log", file ? file : "-", line, message ? message : "");
}

static int wait_for_counts(e2e_state_t* state, int client_target, int server_target)
{
    for (int i = 0; i < 100; i++) {
        int client_connected = atomic_load(&state->client_connected);
        int server_connected = atomic_load(&state->server_connected);
        if (client_connected >= client_target && server_connected >= server_target) {
            return 0;
        }
        sleep_ms(50);
    }

    fprintf(stderr, "e2e: timed out waiting for client=%d server=%d, got client=%d server=%d\n",
            client_target, server_target, atomic_load(&state->client_connected),
            atomic_load(&state->server_connected));
    return 1;
}

static int validate_session_max_datagram_size(const char* label, wtf_session_t* session)
{
    uint32_t max_size = wtf_session_get_max_datagram_size(session);
    if (max_size == 0) {
        fprintf(stderr, "e2e: %s max datagram size was unavailable\n", label);
        return 1;
    }
    if (max_size > 65535) {
        fprintf(stderr, "e2e: %s max datagram size was unexpectedly large: %u\n", label,
                max_size);
        return 1;
    }
    return 0;
}

static int validate_connection_stats(wtf_session_t* session)
{
    static const struct {
        const char* key;
        bool must_be_nonzero;
    } stats[] = {
        {"quic.smoothed_rtt_us", true},
        {"quic.min_rtt_us", true},
        {"quic.rtt_variance_us", false},
        {"quic.congestion_window_bytes", true},
        {"quic.path_mtu_bytes", true},
        {"quic.congestion_events", false},
        {"quic.packets_sent", true},
        {"quic.packets_lost", false},
        {"quic.bytes_sent", true},
        {"quic.bytes_received", true},
    };

    for (size_t i = 0; i < sizeof(stats) / sizeof(stats[0]); ++i) {
        uint64_t value = 0;
        wtf_result_t result = wtf_session_get_stat(session, stats[i].key, &value);
#ifdef WTF_QUIC_BACKEND_NETWORK
        bool valid = result == WTF_ERROR_NOT_SUPPORTED;
#else
        bool valid = result == WTF_SUCCESS && (!stats[i].must_be_nonzero || value != 0);
#endif
        if (!valid) {
            fprintf(stderr, "e2e: unexpected statistic %s: %s (%llu)\n", stats[i].key,
                    wtf_result_to_string(result), (unsigned long long)value);
            return 1;
        }
    }
    return 0;
}

static int make_cert_path(char* buffer, size_t buffer_length, const char* filename)
{
    int len = snprintf(buffer, buffer_length, "%s/%s", WTF_TEST_CERT_DIR, filename);
    if (len < 0 || (size_t)len >= buffer_length) {
        fprintf(stderr, "e2e: certificate path too long\n");
        return 1;
    }
    return 0;
}

static int complete_deferred_auth(e2e_state_t* state, wtf_connection_decision_t decision)
{
    for (int i = 0; i < 100; i++) {
        uintptr_t handle_value = atomic_exchange(&state->deferred_handle, 0);
        if (handle_value == 0) {
            sleep_ms(50);
            continue;
        }

        wtf_connection_request_handle_t* handle = (wtf_connection_request_handle_t*)handle_value;
        bool connected_before_decision = atomic_load(&state->client_connected) != 0
            || atomic_load(&state->server_connected) != 0;
        const char* auth_result = decision == WTF_CONNECTION_ACCEPT ? "ok" : "denied";
        wtf_result_t header_result = wtf_connection_request_add_response_header(
            handle, "x-auth-result", auth_result);
        wtf_result_t result = wtf_connection_request_complete(handle, decision);
        if (connected_before_decision) {
            fprintf(stderr, "e2e: session connected before deferred auth completed\n");
            return 1;
        }
        if (header_result != WTF_SUCCESS) {
            fprintf(stderr, "e2e: deferred response header failed: %s\n",
                    wtf_result_to_string(header_result));
            return 1;
        }
        if (result != WTF_SUCCESS) {
            fprintf(stderr, "e2e: deferred auth completion failed: %s\n",
                    wtf_result_to_string(result));
            return 1;
        }
        return 0;
    }

    fprintf(stderr, "e2e: timed out waiting for deferred auth request\n");
    return 1;
}

static int validate_deferred_rejection(e2e_state_t* state)
{
    for (int i = 0; i < 100 && atomic_load(&state->client_disconnected) == 0; i++) {
        sleep_ms(50);
    }
    if (!atomic_load(&state->client_seen_auth_rejection)) {
        fprintf(stderr, "e2e: client did not receive the deferred 403 with its auth response header\n");
        return 1;
    }
    if (atomic_load(&state->client_connected) != 0 || atomic_load(&state->server_connected) != 0) {
        fprintf(stderr, "e2e: a rejected request established a session\n");
        return 1;
    }
    return 0;
}

static int validate_deferred_acceptance(e2e_state_t* state, wtf_session_t* session)
{
    if (wait_for_counts(state, 1, 1)) {
        return 1;
    }
    if (!atomic_load(&state->client_seen_auth_response)) {
        fprintf(stderr, "e2e: client did not receive the deferred 200 with its auth response header\n");
        return 1;
    }
    if (atomic_load(&state->server_max_datagram_size) == 0) {
        fprintf(stderr, "e2e: server max datagram size was unavailable\n");
        return 1;
    }
    if (validate_session_max_datagram_size("dedicated client", session)) {
        return 1;
    }
    return validate_connection_stats(session);
}

static int run_dedicated_pinned_client(wtf_context_t* context, e2e_state_t* state,
                                       const char* url, const char* pinned_cert_file,
                                       wtf_connection_decision_t decision)
{
    atomic_store(&state->server_seen_auth_header, 0);
    e2e_callback_context_t client_events = {
        .state = state,
        .endpoint = E2E_ENDPOINT_CLIENT,
    };
    wtf_http_header_t headers[] = {
        {.name = "authorization", .value = "Bearer libwtf-e2e"},
    };
    wtf_client_config_t client_config = {
        .url = url,
        .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
        .allow_pooling = false,
        .require_unreliable = true,
        .headers = headers,
        .header_count = 1,
        .pinned_server_certificate_file = pinned_cert_file,
        .session_callback = e2e_session_callback,
        .user_context = &client_events,
    };

    wtf_client_t* client = NULL;
    wtf_result_t result = wtf_client_create(context, &client_config, &client);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: pinned client create failed: %s\n", wtf_result_to_string(result));
        return 1;
    }

    wtf_session_t* session = NULL;
    result = wtf_client_open(client, &session);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: pinned client connect failed: %s\n", wtf_result_to_string(result));
        wtf_client_destroy(client);
        return 1;
    }

    int failure = complete_deferred_auth(state, decision);
    if (!failure && atomic_load(&state->server_seen_auth_header) == 0) {
        fprintf(stderr, "e2e: server did not observe authorization header\n");
        failure = 1;
    }
    if (!failure) {
        failure = decision == WTF_CONNECTION_ACCEPT ? validate_deferred_acceptance(state, session)
                                                    : validate_deferred_rejection(state);
    }
    wtf_client_disconnect(client, 0, "pinned phase complete");
    wtf_client_destroy(client);
    uint64_t value = 0;
    if (!failure && decision == WTF_CONNECTION_ACCEPT
        && wtf_session_get_stat(session, "quic.packets_sent", &value)
            != WTF_ERROR_INVALID_STATE) {
        fprintf(stderr, "e2e: connection statistics remained available after client teardown\n");
        failure = 1;
    }
    wtf_session_unref(session);
    return failure;
}

static int run_pooled_client(wtf_context_t* context, e2e_state_t* state, const char* url,
                             const char* pinned_cert_file)
{
    e2e_callback_context_t client_events = {
        .state = state,
        .endpoint = E2E_ENDPOINT_CLIENT,
    };
    wtf_client_config_t client_config = {
        .url = url,
        .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
        .allow_pooling = true,
        .require_unreliable = true,
        .pinned_server_certificate_file = pinned_cert_file,
        .max_sessions_per_connection = 2,
        .session_callback = e2e_session_callback,
        .user_context = &client_events,
    };

    wtf_client_t* client = NULL;
    wtf_result_t result = wtf_client_create(context, &client_config, &client);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: pooled client create failed: %s\n", wtf_result_to_string(result));
        return 1;
    }

    wtf_session_t* first_session = NULL;
    wtf_session_t* second_session = NULL;
    result = wtf_client_open(client, &first_session);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: first pooled connect failed: %s\n", wtf_result_to_string(result));
        wtf_client_destroy(client);
        return 1;
    }

    result = wtf_client_open(client, &second_session);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: second pooled connect failed: %s\n", wtf_result_to_string(result));
        wtf_session_unref(first_session);
        wtf_client_destroy(client);
        return 1;
    }

    int failure = wait_for_counts(state, 3, 3);
    if (!failure) {
        failure = validate_session_max_datagram_size("first pooled client", first_session);
    }
    if (!failure) {
        failure = validate_session_max_datagram_size("second pooled client", second_session);
    }
    if (!failure && atomic_load(&state->client_max_datagram_size) == 0) {
        fprintf(stderr, "e2e: client max datagram size was unavailable\n");
        failure = 1;
    }
    if (!failure && atomic_load(&state->server_max_datagram_size) == 0) {
        fprintf(stderr, "e2e: pooled server max datagram size was unavailable\n");
        failure = 1;
    }
    wtf_session_unref(first_session);
    wtf_session_unref(second_session);
    wtf_client_disconnect(client, 0, "pooled phase complete");
    wtf_client_destroy(client);
    return failure;
}

int main(void)
{
    char cert_path[512];
    char key_path[512];
    if (make_cert_path(cert_path, sizeof(cert_path), "localhost.crt") != 0
        || make_cert_path(key_path, sizeof(key_path), "localhost.key") != 0) {
        return 1;
    }

    e2e_state_t state;
    atomic_init(&state.client_connected, 0);
    atomic_init(&state.client_disconnected, 0);
    atomic_init(&state.server_connected, 0);
    atomic_init(&state.server_disconnected, 0);
    atomic_init(&state.client_seen_auth_response, 0);
    atomic_init(&state.client_seen_auth_rejection, 0);
    atomic_init(&state.server_seen_auth_header, 0);
    atomic_init(&state.client_max_datagram_size, 0);
    atomic_init(&state.server_max_datagram_size, 0);
    atomic_init(&state.deferred_handle, 0);

    e2e_callback_context_t server_events = {
        .state = &state,
        .endpoint = E2E_ENDPOINT_SERVER,
    };
    wtf_context_config_t context_config = {
        .log_level = WTF_LOG_LEVEL_ERROR,
        .log_callback = e2e_log_callback,
        .log_user_context = "e2e",
    };
    wtf_context_t* context = NULL;
    wtf_result_t result = wtf_context_create(&context_config, &context);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: context create failed: %s\n", wtf_result_to_string(result));
        return 1;
    }

    wtf_certificate_config_t cert_config = {
        .cert_type = WTF_CERT_TYPE_FILE,
        .cert_data.file = {
            .cert_path = cert_path,
            .key_path = key_path,
        },
    };
    wtf_server_config_t server_config = {
        .host = "127.0.0.1",
        .port = WTF_E2E_PORT,
        .cert_config = &cert_config,
        .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
        .max_sessions_per_connection = 4,
        .connection_validator = e2e_connection_validator,
        .session_callback = e2e_session_callback,
        .user_context = &server_events,
    };

    wtf_server_t* server = NULL;
    result = wtf_server_create(context, &server_config, &server);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: server create failed: %s\n", wtf_result_to_string(result));
        wtf_context_destroy(context);
        return 1;
    }

    result = wtf_server_start(server);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "e2e: server start failed: %s\n", wtf_result_to_string(result));
        wtf_server_destroy(server);
        wtf_context_destroy(context);
        return 1;
    }

    char url[128];
    snprintf(url, sizeof(url), "https://127.0.0.1:%u/", WTF_E2E_PORT);

    int failure = run_dedicated_pinned_client(context, &state, url, cert_path,
                                              WTF_CONNECTION_REJECT);
    if (!failure) {
        failure = run_dedicated_pinned_client(context, &state, url, cert_path,
                                              WTF_CONNECTION_ACCEPT);
    }
    if (!failure) {
        failure = run_pooled_client(context, &state, url, cert_path);
    }

    wtf_server_stop(server);
    wtf_server_destroy(server);
    wtf_context_destroy(context);
    return failure;
}
