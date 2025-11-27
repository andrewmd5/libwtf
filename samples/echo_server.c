#include <inttypes.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "wtf.h"

#ifdef _WIN32
    #include <windows.h>
    #define sleep_ms(ms) Sleep(ms)
    #define strdup _strdup
    #ifndef _WIN32
        #include <sys/time.h>
    #endif
#else
    #include <sys/time.h>
    #include <time.h>
    #include <unistd.h>
    #define sleep_ms(ms)                                                                           \
        do {                                                                                       \
            struct timespec ts = {0};                                                              \
            ts.tv_sec = (ms) / 1000;                                                               \
            ts.tv_nsec = ((ms) % 1000) * 1000000;                                                  \
            nanosleep(&ts, NULL);                                                                  \
        } while (0)
#endif

static volatile bool g_running = true;
static wtf_server_t* g_server = NULL;
static wtf_context_t* g_context = NULL;
void stream_callback(const wtf_stream_event_t* event);
void session_callback(const wtf_session_event_t* event);

typedef struct {
    uint64_t sessions_created;
    uint64_t sessions_destroyed;
    uint64_t streams_created;
    uint64_t streams_destroyed;
    uint64_t datagrams_received;
    uint64_t datagrams_sent;
    uint64_t bytes_received;
    uint64_t bytes_sent;
    uint64_t server_streams_created;
} server_stats_t;

static server_stats_t g_stats = {0};

typedef struct session_context {
    wtf_session_t* session;
    uint32_t session_id;
    time_t created_time;
    uint32_t stream_count;
    uint64_t bytes_sent;
    uint64_t bytes_received;
} session_context_t;

typedef struct stream_context {
    wtf_stream_t* stream;
    uint32_t stream_id;
    wtf_session_t* session;
    time_t created_time;
    bool is_server_initiated;
    bool needs_welcome;
    char stream_type[32];
} stream_context_t;

typedef enum {
    CMD_UNKNOWN,
    CMD_REQUEST_STREAM,
    CMD_PING,
    CMD_ECHO,
    CMD_STATS,
    CMD_CREATE_SERVER_STREAM,
    CMD_BULK_DATA,
    CMD_CLOSE_SESSION
} command_type_t;

typedef struct {
    command_type_t type;
    char* param1;
    char* param2;
    char* data;
    size_t data_length;
} command_t;

void signal_handler(int sig)
{
    (void)sig;
    g_running = false;
    printf("\n[SIGNAL] Shutting down server...\n");
}

uint64_t get_timestamp_ms()
{
#ifdef _WIN32
    static LARGE_INTEGER frequency = {0};
    static bool initialized = false;

    if (!initialized) {
        QueryPerformanceFrequency(&frequency);
        initialized = true;
    }

    LARGE_INTEGER counter;
    QueryPerformanceCounter(&counter);

    return (uint64_t)((counter.QuadPart * 1000) / frequency.QuadPart);
#else
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0) {
        return (uint64_t)(ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
    } else {
        struct timeval tv;
        gettimeofday(&tv, NULL);
        return (uint64_t)(tv.tv_sec * 1000 + tv.tv_usec / 1000);
    }
#endif
}

void print_stats()
{
    printf("\n[STATS] Server Statistics:\n");
    printf("  Sessions: %" PRIu64 " created, %" PRIu64 " active\n", g_stats.sessions_created,
           g_stats.sessions_created - g_stats.sessions_destroyed);
    printf("  Streams: %" PRIu64 " created, %" PRIu64 " active\n", g_stats.streams_created,
           g_stats.streams_created - g_stats.streams_destroyed);
    printf("  Server Streams: %" PRIu64 " created\n", g_stats.server_streams_created);
    printf("  Datagrams: %" PRIu64 " received, %" PRIu64 " sent\n", g_stats.datagrams_received,
           g_stats.datagrams_sent);
    printf("  Bytes: %" PRIu64 " received, %" PRIu64 " sent\n", g_stats.bytes_received,
           g_stats.bytes_sent);
    printf("\n");
}

command_t parse_command(const char* message, size_t length)
{
    command_t cmd = {0};
    cmd.type = CMD_UNKNOWN;

    char* msg_copy = malloc(length + 1);
    if (!msg_copy)
        return cmd;

    memcpy(msg_copy, message, length);
    msg_copy[length] = '\0';

    if (strncmp(msg_copy, "REQUEST_STREAM:", 15) == 0) {
        cmd.type = CMD_REQUEST_STREAM;
        cmd.param1 = strdup(msg_copy + 15);
    } else if (strncmp(msg_copy, "PING_", 5) == 0) {
        cmd.type = CMD_PING;
        cmd.param1 = strdup(msg_copy + 5);
    } else if (strncmp(msg_copy, "STATS", 5) == 0) {
        cmd.type = CMD_STATS;
    } else if (strncmp(msg_copy, "CREATE_SERVER_STREAM:", 21) == 0) {
        cmd.type = CMD_CREATE_SERVER_STREAM;
        cmd.param1 = strdup(msg_copy + 21);
    } else if (strncmp(msg_copy, "BULK:", 5) == 0) {
        cmd.type = CMD_BULK_DATA;
        cmd.param1 = strdup(msg_copy + 5);
    } else if (strncmp(msg_copy, "CLOSE_SESSION", 13) == 0) {
        cmd.type = CMD_CLOSE_SESSION;
    } else {
        cmd.type = CMD_ECHO;
        cmd.data = malloc(length);
        if (cmd.data) {
            memcpy(cmd.data, message, length);
            cmd.data_length = length;
        }
    }

    free(msg_copy);
    return cmd;
}

void free_command(command_t* cmd)
{
    if (cmd->param1)
        free(cmd->param1);
    if (cmd->param2)
        free(cmd->param2);
    if (cmd->data)
        free(cmd->data);
    memset(cmd, 0, sizeof(command_t));
}

wtf_result_t handle_request_stream(wtf_session_t* session, const char* stream_type)
{
    printf("[CMD] Creating server-initiated stream: %s\n", stream_type);

    wtf_stream_type_t type = WTF_STREAM_BIDIRECTIONAL;
    if (strcmp(stream_type, "unidirectional") == 0) {
        type = WTF_STREAM_UNIDIRECTIONAL;
    }

    wtf_stream_t* stream = NULL;
    wtf_result_t result = wtf_session_create_stream(session, type, &stream);

    if (result == WTF_SUCCESS) {
        g_stats.server_streams_created++;

        // Create stream context and mark it as needing welcome message
        stream_context_t* stream_ctx = malloc(sizeof(stream_context_t));
        if (stream_ctx) {
            stream_ctx->stream = stream;
            stream_ctx->stream_id = (uint32_t)(g_stats.streams_created + 1);
            stream_ctx->session = session;
            stream_ctx->created_time = time(NULL);
            stream_ctx->is_server_initiated = true;
            stream_ctx->needs_welcome = true;
            strncpy(stream_ctx->stream_type, stream_type, sizeof(stream_ctx->stream_type) - 1);
            stream_ctx->stream_type[sizeof(stream_ctx->stream_type) - 1] = '\0';

            wtf_stream_set_context(stream, stream_ctx);
        }

        wtf_stream_set_callback(stream, stream_callback);
        printf("[CMD] Server stream created, waiting for open event\n");
    } else {
        printf("[CMD] Failed to create server stream: %s\n", wtf_result_to_string(result));
    }

    return result;
}

wtf_result_t handle_ping(wtf_session_t* session, const char* ping_data)
{
    uint64_t timestamp = get_timestamp_ms();
    
    int msg_len = snprintf(NULL, 0, "PONG_%s_server_time=%" PRIu64, ping_data, timestamp);
    if (msg_len <= 0) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    char* pong_response = malloc(msg_len + 1);
    if (!pong_response) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    
    int actual_len = snprintf(pong_response, msg_len + 1, "PONG_%s_server_time=%" PRIu64,
                             ping_data, timestamp);
    
    if (actual_len != msg_len) {
        free(pong_response);
        return WTF_ERROR_INVALID_PARAMETER;
    }
    
    wtf_buffer_t buffer = {.data = (uint8_t*)pong_response, .length = (size_t)msg_len};
    wtf_result_t result = wtf_session_send_datagram(session, &buffer, 1);
    
    if (result == WTF_SUCCESS) {
        g_stats.datagrams_sent++;
        g_stats.bytes_sent += buffer.length;
        printf("[CMD] PONG sent in response to PING_%s\n", ping_data);
    } else {
         free(pong_response);
    }
    return result;
}

wtf_result_t handle_stats_request(wtf_session_t* session)
{
    int msg_len = snprintf(
        NULL, 0,
        "STATS:sessions=%" PRIu64 "/%" PRIu64 ",streams=%" PRIu64 "/%" PRIu64
        ",server_streams=%" PRIu64
        ","
        "datagrams_rx=%" PRIu64 ",datagrams_tx=%" PRIu64 ",bytes_rx=%" PRIu64 ",bytes_tx=%" PRIu64,
        g_stats.sessions_created - g_stats.sessions_destroyed, g_stats.sessions_created,
        g_stats.streams_created - g_stats.streams_destroyed, g_stats.streams_created,
        g_stats.server_streams_created, g_stats.datagrams_received, g_stats.datagrams_sent,
        g_stats.bytes_received, g_stats.bytes_sent);
    
    if (msg_len <= 0) {
        return WTF_ERROR_INVALID_PARAMETER;
    }

    char* stats_response = malloc(msg_len + 1);
    if (!stats_response) {
        return WTF_ERROR_OUT_OF_MEMORY;
    }
    
    int actual_len = snprintf(
        stats_response, msg_len + 1,
        "STATS:sessions=%" PRIu64 "/%" PRIu64 ",streams=%" PRIu64 "/%" PRIu64
        ",server_streams=%" PRIu64
        ","
        "datagrams_rx=%" PRIu64 ",datagrams_tx=%" PRIu64 ",bytes_rx=%" PRIu64 ",bytes_tx=%" PRIu64,
        g_stats.sessions_created - g_stats.sessions_destroyed, g_stats.sessions_created,
        g_stats.streams_created - g_stats.streams_destroyed, g_stats.streams_created,
        g_stats.server_streams_created, g_stats.datagrams_received, g_stats.datagrams_sent,
        g_stats.bytes_received, g_stats.bytes_sent);
    
    if (actual_len != msg_len) {
        free(stats_response);
        return WTF_ERROR_INVALID_PARAMETER;
    }
    
    wtf_buffer_t buffer = {.data = (uint8_t*)stats_response, .length = (size_t)msg_len};
    wtf_result_t result = wtf_session_send_datagram(session, &buffer, 1);
    
    if (result == WTF_SUCCESS) {
        g_stats.datagrams_sent++;
        g_stats.bytes_sent += buffer.length;
        printf("[CMD] Stats sent to client\n");
    } else {
        free(stats_response);
    }
    
    return result;
}

wtf_result_t handle_bulk_data(wtf_session_t* session, const char* bulk_info)
{
    char bulk_response[256];
    int msg_len = snprintf(bulk_response, sizeof(bulk_response),
                           "BULK_RECEIVED:info=%s,timestamp=%" PRIu64, bulk_info,
                           get_timestamp_ms());

    if (msg_len > 0 && msg_len < (int)sizeof(bulk_response)) {
        wtf_buffer_t buffer = {.data = (uint8_t*)bulk_response, .length = (size_t)msg_len};

        wtf_result_t result = wtf_session_send_datagram(session, &buffer, 1);
        if (result == WTF_SUCCESS) {
            g_stats.datagrams_sent++;
            g_stats.bytes_sent += buffer.length;
            printf("[CMD] Bulk data acknowledgment sent\n");
        }
        return result;
    }

    return WTF_ERROR_INVALID_PARAMETER;
}

wtf_result_t handle_close_session(wtf_session_t* session)
{
    printf("[CMD] Client requested session closure\n");
    return wtf_session_close(session, 0, "Client requested closure");
}

wtf_connection_decision_t connection_validator(const wtf_connection_request_t* request,
                                               void* user_data)
{
    (void)user_data;

    printf("[CONN] Connection request from %s%s\n",
           request->authority ? request->authority : "unknown",
           request->path ? request->path : "/");

    for (size_t i = 0; i < request->header_count; i++) {
        printf("[CONN] Header: %s = %s\n", request->headers[i].name, request->headers[i].value);
    }

    return WTF_CONNECTION_ACCEPT;
}

void stream_callback(const wtf_stream_event_t* event)
{
    stream_context_t* stream_ctx = (stream_context_t*)event->user_context;

    switch (event->type) {
        case WTF_STREAM_EVENT_SEND_COMPLETE: {
            for (uint32_t i = 0; i < event->send_complete.buffer_count; i++) {
                if (event->send_complete.buffers[i].data) {
                    free(event->send_complete.buffers[i].data);
                }
            }
            break;
        }

        case WTF_STREAM_EVENT_DATA_RECEIVED: {
            if (event->data_received.fin) {
                break;
            }
            printf("[STREAM] Data received on stream %u\n", stream_ctx ? stream_ctx->stream_id : 0);

            const uint32_t buffer_count = event->data_received.buffer_count;
            const wtf_buffer_t* data = event->data_received.buffers;

            size_t total_length = 0;
            for (uint32_t i = 0; i < buffer_count; i++) {
                total_length += data[i].length;
            }

            char* text = malloc(total_length + 1);
            if (!text)
                break;

            size_t offset = 0;
            for (uint32_t i = 0; i < buffer_count; i++) {
                memcpy(text + offset, data[i].data, data[i].length);
                offset += data[i].length;
            }
            text[total_length] = '\0';

            g_stats.bytes_received += total_length;
            printf("[STREAM] Received: %.*s\n", (int)total_length, text);

            command_t cmd = parse_command(text, total_length);

            switch (cmd.type) {
                case CMD_REQUEST_STREAM:
                    if (stream_ctx && cmd.param1) {
                        handle_request_stream(stream_ctx->session, cmd.param1);
                    }
                    break;
                case CMD_PING:
                    if (stream_ctx && cmd.param1) {
                        handle_ping(stream_ctx->session, cmd.param1);
                    }
                    break;
                case CMD_STATS:
                    if (stream_ctx) {
                        handle_stats_request(stream_ctx->session);
                    }
                    break;
                case CMD_BULK_DATA:
                    if (stream_ctx && cmd.param1) {
                        handle_bulk_data(stream_ctx->session, cmd.param1);
                    }
                    break;
                case CMD_ECHO:
                default: {
                    char* echo_data = malloc(total_length);
                    wtf_buffer_t* response_buffers = malloc(sizeof(wtf_buffer_t));

                    if (echo_data && response_buffers) {
                        memcpy(echo_data, text, total_length);

                        response_buffers[0].length = (uint32_t)total_length;
                        response_buffers[0].data = (uint8_t*)echo_data;

                        wtf_result_t result = wtf_stream_send(event->stream, response_buffers, 1,
                                                              false);
                        if (result == WTF_SUCCESS) {
                            g_stats.bytes_sent += total_length;
                            printf("[STREAM] Echoed %zu bytes back\n", total_length);
                        } else {
                            printf("[STREAM] Failed to echo data: %s\n",
                                   wtf_result_to_string(result));
                            free(echo_data);
                            free(response_buffers);
                        }
                    }
                }
            }

            free_command(&cmd);
            free(text);
            break;
        }

        case WTF_STREAM_EVENT_PEER_CLOSED:
            printf("[STREAM] Stream %u closed by peer\n", stream_ctx ? stream_ctx->stream_id : 0);
            break;

        case WTF_STREAM_EVENT_CLOSED:
            printf("[STREAM] Stream %u fully closed\n", stream_ctx ? stream_ctx->stream_id : 0);
            g_stats.streams_destroyed++;
            if (stream_ctx) {
                free(stream_ctx);
            }
            break;

        case WTF_STREAM_EVENT_ABORTED:
            printf("[STREAM] Stream %u aborted with error %u\n",
                   stream_ctx ? stream_ctx->stream_id : 0, event->aborted.error_code);
            g_stats.streams_destroyed++;
            if (stream_ctx) {
                free(stream_ctx);
            }
            break;

        default:
            break;
    }
}

void session_callback(const wtf_session_event_t* event)
{
    session_context_t* session_ctx = (session_context_t*)event->user_context;

    switch (event->type) {
        case WTF_SESSION_EVENT_CONNECTED: {
            printf("[SESSION] New session connected\n");

            session_ctx = malloc(sizeof(session_context_t));
            if (session_ctx) {
                session_ctx->session = event->session;
                session_ctx->session_id = (uint32_t)++g_stats.sessions_created;
                session_ctx->created_time = time(NULL);
                session_ctx->stream_count = 0;
                session_ctx->bytes_sent = 0;
                session_ctx->bytes_received = 0;
                wtf_session_set_context(event->session, session_ctx);
            }

            printf("[SESSION] Session %u established\n", session_ctx ? session_ctx->session_id : 0);
            break;
        }

        case WTF_SESSION_EVENT_STREAM_OPENED: {
            printf("[SESSION] New stream opened on session %u\n",
                   session_ctx ? session_ctx->session_id : 0);

            g_stats.streams_created++;
            if (session_ctx) {
                session_ctx->stream_count++;
            }

            // Get or create stream context
            stream_context_t* stream_ctx = (stream_context_t*)wtf_stream_get_context(
                event->stream_opened.stream);
            if (!stream_ctx) {
                stream_ctx = malloc(sizeof(stream_context_t));
                if (stream_ctx) {
                    stream_ctx->stream = event->stream_opened.stream;
                    stream_ctx->stream_id = (uint32_t)g_stats.streams_created;
                    stream_ctx->session = event->session;
                    stream_ctx->created_time = time(NULL);
                    stream_ctx->is_server_initiated = false;
                    stream_ctx->needs_welcome = false;
                    stream_ctx->stream_type[0] = '\0';

                    wtf_stream_set_context(event->stream_opened.stream, stream_ctx);
                }
            }

            wtf_stream_set_callback(event->stream_opened.stream, stream_callback);

            printf("[SESSION] Stream %u configured (server-initiated: %s)\n",
                   stream_ctx ? stream_ctx->stream_id : 0,
                   stream_ctx && stream_ctx->is_server_initiated ? "yes" : "no");
            break;
        }

        case WTF_SESSION_EVENT_DISCONNECTED: {
            printf("[SESSION] Session %u disconnected (error: %u, reason: %s)\n",
                   session_ctx ? session_ctx->session_id : 0, event->disconnected.error_code,
                   event->disconnected.reason ? event->disconnected.reason : "none");

            g_stats.sessions_destroyed++;
            if (session_ctx) {
                free(session_ctx);
            }
            break;
        }

        case WTF_SESSION_EVENT_DATAGRAM_RECEIVED: {
            printf("[DATAGRAM] Received on session %u (%u bytes)\n",
                   session_ctx ? session_ctx->session_id : 0,
                   (unsigned int)event->datagram_received.length);

            g_stats.datagrams_received++;
            g_stats.bytes_received += event->datagram_received.length;

            char* text = malloc(event->datagram_received.length + 1);
            if (text) {
                memcpy(text, event->datagram_received.data, event->datagram_received.length);
                text[event->datagram_received.length] = '\0';

                printf("[DATAGRAM] Content: %s\n", text);

                command_t cmd = parse_command((const char*)event->datagram_received.data,
                                              event->datagram_received.length);

                switch (cmd.type) {
                    case CMD_REQUEST_STREAM:
                        if (cmd.param1) {
                            handle_request_stream(event->session, cmd.param1);
                        }
                        break;

                    case CMD_PING:
                        if (cmd.param1) {
                            handle_ping(event->session, cmd.param1);
                        }
                        break;

                    case CMD_STATS:
                        handle_stats_request(event->session);
                        break;

                    case CMD_CREATE_SERVER_STREAM:
                        if (cmd.param1) {
                            handle_request_stream(event->session, cmd.param1);
                        }
                        break;

                    case CMD_BULK_DATA:
                        if (cmd.param1) {
                            handle_bulk_data(event->session, cmd.param1);
                        }
                        break;

                    case CMD_CLOSE_SESSION:
                        handle_close_session(event->session);
                        break;

                    case CMD_ECHO:
                    default: {
                        char* reversed = malloc(event->datagram_received.length + 1);
                        if (reversed) {
                            size_t len = event->datagram_received.length;
                            memcpy(reversed, event->datagram_received.data, len);

                            for (size_t i = 0; i < len / 2; i++) {
                                char temp = reversed[i];
                                reversed[i] = reversed[len - i - 1];
                                reversed[len - i - 1] = temp;
                            }

                            wtf_buffer_t buffer = {.data = (uint8_t*)reversed, .length = len};

                            wtf_result_t result = wtf_session_send_datagram(event->session, &buffer,
                                                                            1);
                            if (result == WTF_SUCCESS) {
                                g_stats.datagrams_sent++;
                                g_stats.bytes_sent += len;
                                printf("[DATAGRAM] Echoed (reversed): %.*s\n", (int)len, reversed);
                            } else {
                                printf("[DATAGRAM] Failed to echo: %s\n",
                                       wtf_result_to_string(result));
                                free(reversed);
                            }
                        }
                        break;
                    }
                }

                free_command(&cmd);
                free(text);
            }
            break;
        }

        case WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE: {
            if (WTF_DATAGRAM_SEND_STATE_IS_FINAL(event->datagram_send_state_changed.state)) {
                for (uint32_t i = 0; i < event->datagram_send_state_changed.buffer_count; i++) {
                    if (event->datagram_send_state_changed.buffers[i].data) {
                        free(event->datagram_send_state_changed.buffers[i].data);
                    }
                }
            }
            break;
        }
        case WTF_SESSION_EVENT_DRAINING:
            printf("[SESSION] Session %u is draining\n", session_ctx ? session_ctx->session_id : 0);
            break;

        default:
            break;
    }
}

void log_callback(wtf_log_level_t level, const char* component, const char* file, int line,
                  const char* message, void* user_context)
{
    const char* level_str = "";

    switch (level) {
        case WTF_LOG_LEVEL_TRACE:
            level_str = "TRACE";
            break;
        case WTF_LOG_LEVEL_DEBUG:
            level_str = "DEBUG";
            break;
        case WTF_LOG_LEVEL_INFO:
            level_str = "INFO";
            break;
        case WTF_LOG_LEVEL_WARN:
            level_str = "WARN";
            break;
        case WTF_LOG_LEVEL_ERROR:
            level_str = "ERROR";
            break;
        case WTF_LOG_LEVEL_CRITICAL:
            level_str = "CRITICAL";
            break;
        default:
            return;
    }

    printf("[%s] %s: %s\n", level_str, component, message);
}

int main(int argc, char* argv[])
{
    printf("===============================================\n");
    printf("WebTransport Echo Server\n");
    printf("Version: %s\n", wtf_get_version()->version);
    printf("===============================================\n\n");

    uint16_t port = 4433;
    const char* cert_file = "server.crt";
    const char* key_file = "server.key";
    const char* cert_thumbprint = NULL;
    const char* cert_store = "My";
    wtf_certificate_type_t cert_type = WTF_CERT_TYPE_FILE;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--cert") == 0 && i + 1 < argc) {
            cert_file = argv[++i];
        } else if (strcmp(argv[i], "--key") == 0 && i + 1 < argc) {
            key_file = argv[++i];
        } else if (strcmp(argv[i], "--thumbprint") == 0 && i + 1 < argc) {
            cert_thumbprint = argv[++i];
            cert_type = WTF_CERT_TYPE_HASH;
        } else if (strcmp(argv[i], "--store") == 0 && i + 1 < argc) {
            cert_store = argv[++i];
            if (cert_type == WTF_CERT_TYPE_HASH) {
                cert_type = WTF_CERT_TYPE_HASH_STORE;
            }
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --port <port>           Listen port (default: 4433)\n");
            printf("  --cert <file>           Certificate file (default: server.crt)\n");
            printf("  --key <file>            Private key file (default: server.key)\n");
            printf("  --thumbprint <hash>     Certificate thumbprint (Windows/Schannel)\n");
            printf("  --store <name>          Certificate store name (default: My)\n");
            printf("  --verbose               Enable verbose logging\n");
            printf("  --help                  Show this help\n");
            printf("\nSupported Commands:\n");
            printf("  REQUEST_STREAM:<type>     - Request server to create stream\n");
            printf("  PING_<data>               - Ping with custom data\n");
            printf("  STATS                     - Get server statistics\n");
            printf("  CREATE_SERVER_STREAM:<type> - Create server-initiated stream\n");
            printf("  BULK:<info>               - Send bulk data\n");
            printf("  CLOSE_SESSION             - Close the session\n");
            printf("  <any other data>          - Echo back (streams) or reverse (datagrams)\n");
            return 0;
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    printf("[CONFIG] Server Configuration:\n");
    printf("  Port: %u\n", port);
    if (cert_type == WTF_CERT_TYPE_FILE) {
        printf("  Certificate: %s\n", cert_file);
        printf("  Private key: %s\n", key_file);
    } else if (cert_type == WTF_CERT_TYPE_HASH) {
        printf("  Certificate thumbprint: %s\n", cert_thumbprint);
    } else if (cert_type == WTF_CERT_TYPE_HASH_STORE) {
        printf("  Certificate thumbprint: %s\n", cert_thumbprint);
        printf("  Certificate store: %s\n", cert_store);
    }
    printf("  Verbose logging: %s\n", verbose ? "enabled" : "disabled");
    printf("\n");

    wtf_context_config_t context_config = {0};
    context_config.log_level = verbose ? WTF_LOG_LEVEL_TRACE : WTF_LOG_LEVEL_INFO;
    context_config.log_callback = log_callback;
    context_config.worker_thread_count = 4;
    context_config.enable_load_balancing = true;

    wtf_result_t status = wtf_context_create(&context_config, &g_context);
    if (status != WTF_SUCCESS) {
        printf("[ERROR] Failed to create context: %s\n", wtf_result_to_string(status));
        return 1;
    }

    wtf_certificate_config_t cert_config = {0};
    cert_config.cert_type = cert_type;

    switch (cert_type) {
        case WTF_CERT_TYPE_FILE:
            cert_config.cert_data.file.cert_path = cert_file;
            cert_config.cert_data.file.key_path = key_file;
            break;
        case WTF_CERT_TYPE_HASH:
            cert_config.cert_data.hash.thumbprint = cert_thumbprint;
            break;
        case WTF_CERT_TYPE_HASH_STORE:
            cert_config.cert_data.hash_store.thumbprint = cert_thumbprint;
            cert_config.cert_data.hash_store.store_name = cert_store;
            break;
        default:
            printf("[ERROR] Unsupported certificate type\n");
            wtf_context_destroy(g_context);
            return 1;
    }

    wtf_server_config_t config = {0};
    config.port = port;
    config.cert_config = &cert_config;
    config.session_callback = session_callback;
    config.connection_validator = connection_validator;
    config.max_sessions_per_connection = 32;
    config.max_streams_per_session = 256;
    config.idle_timeout_ms = 60000;
    config.handshake_timeout_ms = 10000;
    config.enable_0rtt = true;
    config.enable_migration = true;

    status = wtf_server_create(g_context, &config, &g_server);
    if (status != WTF_SUCCESS) {
        printf("[ERROR] Failed to create server: %s\n", wtf_result_to_string(status));
        wtf_context_destroy(g_context);
        return 1;
    }

    status = wtf_server_start(g_server);
    if (status != WTF_SUCCESS) {
        printf("[ERROR] Failed to start server: %s\n", wtf_result_to_string(status));
        wtf_server_destroy(g_server);
        wtf_context_destroy(g_context);
        return 1;
    }

    printf("[SERVER] WebTransport server listening on port %u\n", port);
    printf("[SERVER] Ready to accept connections...\n");
    printf("[SERVER] Press Ctrl+C to stop\n\n");

    print_stats();

    time_t last_stats_print = time(NULL);
    while (g_running) {
        sleep_ms(1000);

        time_t now = time(NULL);
        if (now - last_stats_print >= 30
            && (g_stats.sessions_created > 0 || g_stats.datagrams_received > 0)) {
            print_stats();
            last_stats_print = now;
        }
    }

    printf("\n[SHUTDOWN] Stopping server...\n");
    print_stats();

    wtf_server_stop(g_server);
    wtf_server_destroy(g_server);
    wtf_context_destroy(g_context);

    printf("[SHUTDOWN] Server stopped cleanly\n");
    return 0;
}
