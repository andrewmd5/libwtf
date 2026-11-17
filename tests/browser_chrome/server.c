#include "wtf.h"

#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
    #include <windows.h>
#endif

#define BROWSER_INTEROP_DEFAULT_PORT 12345
#define BROWSER_INTEROP_DEFAULT_STREAMS 5
#define BROWSER_INTEROP_DEFAULT_BYTES (1024 * 1024)
#define BROWSER_INTEROP_DEFAULT_TIMEOUT_MS 30000

typedef enum {
    SEND_MARK_NONE,
    SEND_MARK_BIDI,
    SEND_MARK_DONE
} send_mark_t;

typedef struct {
    atomic_int sessions_connected;
    atomic_int datagram_echoed;
    atomic_int bidi_echoed;
    atomic_int done_echoed;
    atomic_int uni_streams_completed;
    atomic_int failures;
    _Atomic(wtf_stream_t*) pending_done;
    uint32_t expected_uni_streams;
    size_t expected_uni_bytes;
    bool verbose;
} interop_state_t;

typedef struct {
    interop_state_t* state;
    wtf_stream_type_t stream_type;
    size_t bytes_received;
    uint8_t prefix[64];
    size_t prefix_length;
    bool completed;
} stream_context_t;

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

static void fail_interop(interop_state_t* state, const char* reason)
{
    if (reason) {
        fprintf(stderr, "browser interop: %s\n", reason);
    }
    if (state) {
        atomic_fetch_add(&state->failures, 1);
    }
}

static bool bytes_equal(const uint8_t* data, size_t length, const char* expected)
{
    size_t expected_length = strlen(expected);
    return length == expected_length && memcmp(data, expected, expected_length) == 0;
}

static void append_prefix(stream_context_t* stream_ctx, const uint8_t* data, size_t length)
{
    if (!stream_ctx || !data || length == 0 || stream_ctx->prefix_length >= sizeof(stream_ctx->prefix)) {
        return;
    }

    size_t available = sizeof(stream_ctx->prefix) - stream_ctx->prefix_length;
    size_t to_copy = length < available ? length : available;
    memcpy(stream_ctx->prefix + stream_ctx->prefix_length, data, to_copy);
    stream_ctx->prefix_length += to_copy;
}

static bool validate_pattern(stream_context_t* stream_ctx, const uint8_t* data, size_t length)
{
    if (!stream_ctx || !data) {
        return false;
    }

    for (size_t i = 0; i < length; i++) {
        uint8_t expected = (uint8_t)((stream_ctx->bytes_received + i) & 0xffu);
        if (data[i] != expected) {
            return false;
        }
    }
    return true;
}

static send_mark_t classify_control_message(const stream_context_t* stream_ctx)
{
    if (!stream_ctx) {
        return SEND_MARK_NONE;
    }
    if (bytes_equal(stream_ctx->prefix, stream_ctx->prefix_length, "chrome-bidi")) {
        return SEND_MARK_BIDI;
    }
    if (bytes_equal(stream_ctx->prefix, stream_ctx->prefix_length, "chrome-done")) {
        return SEND_MARK_DONE;
    }
    return SEND_MARK_NONE;
}

/* The final echo is an application barrier across independent QUIC streams. */
static void browser_interop_finish_done_echo(interop_state_t* state)
{
    if (atomic_load(&state->uni_streams_completed) < (int)state->expected_uni_streams) {
        return;
    }
    wtf_stream_t* stream = atomic_exchange(&state->pending_done, NULL);
    if (!stream) {
        return;
    }
    wtf_result_t result = wtf_stream_close(stream);
    if (result != WTF_SUCCESS) {
        fail_interop(state, wtf_result_to_string(result));
    } else {
        atomic_store(&state->done_echoed, 1);
    }
    wtf_stream_unref(stream);
}

static void stream_callback(const wtf_stream_event_t* event)
{
    if (!event || !event->stream) {
        return;
    }

    stream_context_t* stream_ctx = event->user_context;
    interop_state_t* state = stream_ctx ? stream_ctx->state : NULL;

    switch (event->type) {
        case WTF_STREAM_EVENT_DATA_RECEIVED: {
            size_t total_length = 0;
            for (uint32_t i = 0; i < event->data_received.buffer_count; i++) {
                total_length += event->data_received.buffers[i].length;
            }

            if (stream_ctx && stream_ctx->stream_type == WTF_STREAM_UNIDIRECTIONAL) {
                for (uint32_t i = 0; i < event->data_received.buffer_count; i++) {
                    const wtf_buffer_t* buffer = &event->data_received.buffers[i];
                    if (!validate_pattern(stream_ctx, buffer->data, buffer->length)) {
                        fail_interop(state, "unidirectional stream data pattern mismatch");
                        return;
                    }
                    stream_ctx->bytes_received += buffer->length;
                }
                break;
            }

            if (total_length == 0) {
                break;
            }

            uint8_t* echo = malloc(total_length);
            if (!echo) {
                fail_interop(state, "out of memory echoing bidirectional stream");
                return;
            }

            size_t offset = 0;
            for (uint32_t i = 0; i < event->data_received.buffer_count; i++) {
                const wtf_buffer_t* buffer = &event->data_received.buffers[i];
                append_prefix(stream_ctx, buffer->data, buffer->length);
                memcpy(echo + offset, buffer->data, buffer->length);
                offset += buffer->length;
            }
            stream_ctx->bytes_received += total_length;

            wtf_result_t result = wtf_stream_send_copy(event->stream, echo, total_length, false);
            free(echo);
            if (result != WTF_SUCCESS) {
                fail_interop(state, wtf_result_to_string(result));
                return;
            }
            break;
        }

        case WTF_STREAM_EVENT_SEND_COMPLETE: {
            if (event->send_complete.cancelled) {
                fail_interop(state, "stream send was cancelled");
            }
            break;
        }

        case WTF_STREAM_EVENT_CLOSED:
            free(stream_ctx);
            break;

        case WTF_STREAM_EVENT_ABORTED:
            fail_interop(state, "stream aborted");
            break;

        case WTF_STREAM_EVENT_PEER_CLOSED:
            if (!stream_ctx || stream_ctx->completed) {
                break;
            }

            stream_ctx->completed = true;
            if (stream_ctx->stream_type == WTF_STREAM_UNIDIRECTIONAL) {
                if (!state) {
                    fail_interop(NULL, "missing interop state");
                    return;
                }
                if (stream_ctx->bytes_received != state->expected_uni_bytes) {
                    fail_interop(state, "unidirectional stream length mismatch");
                    return;
                }
                atomic_fetch_add(&state->uni_streams_completed, 1);
                browser_interop_finish_done_echo(state);
                if (state->verbose) {
                    fprintf(stderr, "browser interop: completed uni stream %d/%u\n",
                            atomic_load(&state->uni_streams_completed),
                            state->expected_uni_streams);
                }
                break;
            }

            send_mark_t mark = classify_control_message(stream_ctx);
            if (state && mark == SEND_MARK_DONE) {
                wtf_stream_ref(event->stream);
                atomic_store(&state->pending_done, event->stream);
                browser_interop_finish_done_echo(state);
                break;
            }
            wtf_result_t result = wtf_stream_close(event->stream);
            if (result != WTF_SUCCESS) {
                fail_interop(state, wtf_result_to_string(result));
                return;
            }
            if (state && mark == SEND_MARK_BIDI) {
                atomic_store(&state->bidi_echoed, 1);
            }
            break;
        default:
            break;
    }
}

static void session_callback(const wtf_session_event_t* event)
{
    if (!event || !event->session) {
        return;
    }

    interop_state_t* state = event->user_context;

    switch (event->type) {
        case WTF_SESSION_EVENT_CONNECTED:
            atomic_fetch_add(&state->sessions_connected, 1);
            break;

        case WTF_SESSION_EVENT_STREAM_OPENED: {
            stream_context_t* stream_ctx = calloc(1, sizeof(*stream_ctx));
            if (!stream_ctx) {
                fail_interop(state, "out of memory allocating stream context");
                return;
            }
            stream_ctx->state = state;
            stream_ctx->stream_type = event->stream_opened.stream_type;
            wtf_stream_set_context(event->stream_opened.stream, stream_ctx);
            wtf_stream_set_callback(event->stream_opened.stream, stream_callback);
            break;
        }

        case WTF_SESSION_EVENT_DATAGRAM_RECEIVED: {
            if (!bytes_equal(event->datagram_received.data, event->datagram_received.length,
                             "chrome-datagram")) {
                fail_interop(state, "unexpected datagram payload");
                return;
            }

            wtf_result_t result = wtf_session_send_datagram_copy(
                event->session, event->datagram_received.data, event->datagram_received.length);
            if (result != WTF_SUCCESS) {
                fail_interop(state, wtf_result_to_string(result));
                return;
            }
            if (state) {
                atomic_store(&state->datagram_echoed, 1);
            }
            break;
        }

        case WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE:
            if (WTF_DATAGRAM_SEND_STATE_IS_FINAL(event->datagram_send_state_changed.state)) {
                if (event->datagram_send_state_changed.state == WTF_DATAGRAM_SEND_ACKNOWLEDGED
                    || event->datagram_send_state_changed.state
                        == WTF_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS) {
                    atomic_store(&state->datagram_echoed, 1);
                }
            }
            break;

        case WTF_SESSION_EVENT_DISCONNECTED:
        default:
            break;
    }
}

static wtf_connection_decision_t connection_validator(
    const wtf_connection_request_t* request, wtf_connection_response_t* response,
    void* user_context)
{
    interop_state_t* state = user_context;
    if (state && state->verbose) {
        fprintf(stderr, "browser interop: CONNECT %s%s\n",
                request && request->authority ? request->authority : "",
                request && request->path ? request->path : "");
    }

    wtf_connection_response_add_header(response, "x-libwtf-browser-interop", "ok");
    return WTF_CONNECTION_ACCEPT;
}

static void log_callback(wtf_log_level_t level, const char* component, const char* file,
                         int line, const char* message, void* user_context)
{
    interop_state_t* state = user_context;
    if (!state || !state->verbose) {
        return;
    }
    fprintf(stderr, "[libwtf:%d] %s %s:%d %s\n", (int)level, component ? component : "log",
            file ? file : "-", line, message ? message : "");
}

static bool parse_u16(const char* value, uint16_t* output)
{
    char* end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (!value || *value == '\0' || !end || *end != '\0' || parsed == 0
        || parsed > UINT16_MAX) {
        return false;
    }
    *output = (uint16_t)parsed;
    return true;
}

static bool parse_u32(const char* value, uint32_t* output)
{
    char* end = NULL;
    unsigned long parsed = strtoul(value, &end, 10);
    if (!value || *value == '\0' || !end || *end != '\0' || parsed > UINT32_MAX) {
        return false;
    }
    *output = (uint32_t)parsed;
    return true;
}

static bool parse_size(const char* value, size_t* output)
{
    char* end = NULL;
    unsigned long long parsed = strtoull(value, &end, 10);
    if (!value || *value == '\0' || !end || *end != '\0') {
        return false;
    }
    *output = (size_t)parsed;
    return true;
}

int main(int argc, char** argv)
{
    uint16_t port = BROWSER_INTEROP_DEFAULT_PORT;
    const char* cert_path = "certs/localhost.crt";
    const char* key_path = "certs/localhost.key";
    uint32_t timeout_ms = BROWSER_INTEROP_DEFAULT_TIMEOUT_MS;

    interop_state_t state = {
        .expected_uni_streams = BROWSER_INTEROP_DEFAULT_STREAMS,
        .expected_uni_bytes = BROWSER_INTEROP_DEFAULT_BYTES,
    };
    atomic_init(&state.sessions_connected, 0);
    atomic_init(&state.datagram_echoed, 0);
    atomic_init(&state.bidi_echoed, 0);
    atomic_init(&state.done_echoed, 0);
    atomic_init(&state.uni_streams_completed, 0);
    atomic_init(&state.failures, 0);

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &port)) {
                fprintf(stderr, "browser interop: invalid --port\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_path = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_path = argv[++i];
        } else if (strcmp(argv[i], "--expected-streams") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &state.expected_uni_streams)) {
                fprintf(stderr, "browser interop: invalid --expected-streams\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--expected-bytes") == 0 && i + 1 < argc) {
            if (!parse_size(argv[++i], &state.expected_uni_bytes)) {
                fprintf(stderr, "browser interop: invalid --expected-bytes\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--timeout-ms") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &timeout_ms)) {
                fprintf(stderr, "browser interop: invalid --timeout-ms\n");
                return 2;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            state.verbose = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--port port] [--cert file] [--key file] "
                   "[--expected-streams n] [--expected-bytes n] [--timeout-ms n] "
                   "[--verbose]\n",
                   argv[0]);
            return 0;
        } else {
            fprintf(stderr, "browser interop: unknown argument: %s\n", argv[i]);
            return 2;
        }
    }

    wtf_context_config_t context_config = {
        .log_level = state.verbose ? WTF_LOG_LEVEL_TRACE : WTF_LOG_LEVEL_ERROR,
        .log_callback = log_callback,
        .log_user_context = &state,
    };
    wtf_context_t* context = NULL;
    wtf_result_t result = wtf_context_create(&context_config, &context);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "browser interop: context create failed: %s\n",
                wtf_result_to_string(result));
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
        .port = port,
        .cert_config = &cert_config,
        .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
        .max_sessions_per_connection = 8,
        .max_streams_per_session = 32,
        .max_data_per_session = 32 * 1024 * 1024,
        .stream_recv_window = 2 * 1024 * 1024,
        .conn_flow_control_window = 32 * 1024 * 1024,
        .connection_validator = connection_validator,
        .session_callback = session_callback,
        .user_context = &state,
    };

    wtf_server_t* server = NULL;
    result = wtf_server_create(context, &server_config, &server);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "browser interop: server create failed: %s\n",
                wtf_result_to_string(result));
        wtf_context_destroy(context);
        return 1;
    }

    result = wtf_server_start(server);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "browser interop: server start failed: %s\n",
                wtf_result_to_string(result));
        wtf_server_destroy(server);
        wtf_context_destroy(context);
        return 1;
    }

    fprintf(stdout, "LIBWTF_BROWSER_INTEROP_READY %u\n", port);
    fflush(stdout);

    unsigned elapsed_ms = 0;
    int exit_code = 1;
    while (elapsed_ms < timeout_ms) {
        if (atomic_load(&state.failures) > 0) {
            break;
        }

        if (atomic_load(&state.sessions_connected) > 0
            && atomic_load(&state.datagram_echoed) > 0
            && atomic_load(&state.bidi_echoed) > 0
            && atomic_load(&state.done_echoed) > 0
            && atomic_load(&state.uni_streams_completed)
                >= (int)state.expected_uni_streams) {
            fprintf(stdout, "LIBWTF_BROWSER_INTEROP_DONE\n");
            fflush(stdout);
            exit_code = 0;
            break;
        }

        sleep_ms(50);
        elapsed_ms += 50;
    }

    if (exit_code != 0) {
        fprintf(stderr,
                "browser interop: timed out/failing "
                "sessions=%d datagram=%d bidi=%d done=%d uni=%d/%u failures=%d\n",
                atomic_load(&state.sessions_connected), atomic_load(&state.datagram_echoed),
                atomic_load(&state.bidi_echoed), atomic_load(&state.done_echoed),
                atomic_load(&state.uni_streams_completed), state.expected_uni_streams,
                atomic_load(&state.failures));
    }

    wtf_stream_t* pending_done = atomic_exchange(&state.pending_done, NULL);
    if (pending_done) {
        wtf_stream_unref(pending_done);
    }
    wtf_server_stop(server);
    wtf_server_destroy(server);
    wtf_context_destroy(context);
    return exit_code;
}
