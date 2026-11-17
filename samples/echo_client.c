#include "wtf.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
    #include <windows.h>
#else
    #include <unistd.h>
#endif

static wtf_client_t* g_client = NULL;
static volatile int g_running = 1;

static wtf_webtransport_draft_t parse_draft(const char* value)
{
    if (!value || strcmp(value, "auto") == 0) {
        return WTF_WEBTRANSPORT_DRAFT_AUTO;
    }
    if (strcmp(value, "2") == 0 || strcmp(value, "02") == 0) {
        return WTF_WEBTRANSPORT_DRAFT_02;
    }
    if (strcmp(value, "7") == 0 || strcmp(value, "07") == 0) {
        return WTF_WEBTRANSPORT_DRAFT_07;
    }
    if (strcmp(value, "15") == 0) {
        return WTF_WEBTRANSPORT_DRAFT_15;
    }
    return WTF_WEBTRANSPORT_DRAFT_AUTO;
}

static void sleep_seconds(unsigned seconds)
{
#ifdef _WIN32
    Sleep(seconds * 1000);
#else
    sleep(seconds);
#endif
}

static void log_callback(wtf_log_level_t level, const char* component, const char* file,
                         int line, const char* message, void* user_context)
{
    const char* label = user_context ? user_context : "client";
    fprintf(stderr, "[%s:%d] %s %s:%d %s\n", label, (int)level,
            component ? component : "log", file ? file : "-", line, message ? message : "");
}

static void stream_callback(const wtf_stream_event_t* event)
{
    switch (event->type) {
        case WTF_STREAM_EVENT_DATA_RECEIVED:
            for (uint32_t i = 0; i < event->data_received.buffer_count; i++) {
                printf("[stream] %.*s\n", (int)event->data_received.buffers[i].length,
                       (const char*)event->data_received.buffers[i].data);
            }
            break;
        case WTF_STREAM_EVENT_CLOSED:
        case WTF_STREAM_EVENT_ABORTED:
            break;
        default:
            break;
    }
}

static void send_stream_message(wtf_session_t* session, const char* message)
{
    wtf_stream_t* stream = NULL;
    if (wtf_session_create_stream(session, WTF_STREAM_BIDIRECTIONAL, stream_callback, NULL,
                                 &stream) != WTF_SUCCESS) {
        return;
    }

    wtf_stream_send_copy(stream, message, strlen(message), false);

    wtf_stream_unref(stream);
}

static void send_datagram(wtf_session_t* session, const char* message)
{
    wtf_session_send_datagram_copy(session, message, strlen(message));
}

static void session_callback(const wtf_session_event_t* event)
{
    switch (event->type) {
        case WTF_SESSION_EVENT_CONNECTED:
            printf("[session] connected\n");
            send_datagram(event->session, "hello over datagram");
            send_stream_message(event->session, "hello over stream");
            break;
        case WTF_SESSION_EVENT_DATAGRAM_RECEIVED:
            printf("[datagram] %.*s\n", (int)event->datagram_received.length,
                   (const char*)event->datagram_received.data);
            break;
        case WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE:
            break;
        case WTF_SESSION_EVENT_DISCONNECTED:
            printf("[session] disconnected: %s\n",
                   event->disconnected.reason ? event->disconnected.reason : "");
            g_running = 0;
            break;
        default:
            break;
    }
}

int main(int argc, char** argv)
{
    const char* url = NULL;
    const char* host = "localhost";
    uint16_t port = 4433;
    const char* path = "/";
    const char* origin = NULL;
    const char* ca_cert_file = NULL;
    const char* pinned_cert_file = NULL;
    wtf_webtransport_draft_t draft = WTF_WEBTRANSPORT_DRAFT_AUTO;
    bool insecure = true;
    bool verbose = false;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            url = argv[++i];
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            port = (uint16_t)atoi(argv[++i]);
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            path = argv[++i];
        } else if (strcmp(argv[i], "--origin") == 0 && i + 1 < argc) {
            origin = argv[++i];
        } else if (strcmp(argv[i], "--draft") == 0 && i + 1 < argc) {
            draft = parse_draft(argv[++i]);
        } else if (strcmp(argv[i], "--ca-cert") == 0 && i + 1 < argc) {
            ca_cert_file = argv[++i];
        } else if (strcmp(argv[i], "--pinned-cert") == 0 && i + 1 < argc) {
            pinned_cert_file = argv[++i];
        } else if (strcmp(argv[i], "--secure") == 0) {
            insecure = false;
        } else if (strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [--url https://host:port/path] [--host host] [--port port] "
                   "[--path path] [--origin origin] [--draft auto|02|07|15] "
                   "[--ca-cert file] [--pinned-cert file] [--secure] [--verbose]\n",
                   argv[0]);
            return 0;
        }
    }

    if (ca_cert_file && pinned_cert_file) {
        fprintf(stderr, "--ca-cert and --pinned-cert are mutually exclusive\n");
        return 1;
    }

    char url_buffer[512];
    if (!url) {
        bool needs_ipv6_brackets = strchr(host, ':') != NULL && host[0] != '[';
        const char* path_prefix = path[0] == '/' ? "" : "/";
        int len = snprintf(url_buffer, sizeof(url_buffer), needs_ipv6_brackets
                               ? "https://[%s]:%u%s%s"
                               : "https://%s:%u%s%s",
                           host, port, path_prefix, path);
        if (len < 0 || (size_t)len >= sizeof(url_buffer)) {
            fprintf(stderr, "URL is too long\n");
            return 1;
        }
        url = url_buffer;
    }

    wtf_context_config_t context_config = {
        .log_level = verbose ? WTF_LOG_LEVEL_TRACE : WTF_LOG_LEVEL_INFO,
        .log_callback = log_callback,
        .log_user_context = "client",
    };
    wtf_context_t* context = NULL;
    wtf_result_t result = wtf_context_create(&context_config, &context);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "context create failed: %s\n", wtf_result_to_string(result));
        return 1;
    }

    wtf_client_config_t client_config = {
        .url = url,
        .origin = origin,
        .draft = draft,
        .skip_certificate_validation = insecure && !ca_cert_file && !pinned_cert_file,
        .ca_cert_file = ca_cert_file,
        .pinned_server_certificate_file = pinned_cert_file,
        .session_callback = session_callback,
    };

    result = wtf_client_create(context, &client_config, &g_client);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "client create failed: %s\n", wtf_result_to_string(result));
        wtf_context_destroy(context);
        return 1;
    }

    wtf_session_t* session = NULL;
    result = wtf_client_open(g_client, &session);
    if (result != WTF_SUCCESS) {
        fprintf(stderr, "connect failed: %s\n", wtf_result_to_string(result));
        wtf_client_destroy(g_client);
        wtf_context_destroy(context);
        return 1;
    }

    while (g_running) {
        sleep_seconds(1);
        break;
    }

    wtf_session_unref(session);
    wtf_client_disconnect(g_client, 0, "done");
    wtf_client_destroy(g_client);
    wtf_context_destroy(context);
    return 0;
}
