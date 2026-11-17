#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "wtf.h"

static const char payload[] = "network-backend-roundtrip";
static atomic_bool stream_echo, datagram_echo;
static atomic_bool failed;
static size_t received_bytes;
static bool server_mode;
static volatile sig_atomic_t running = 1;

static void network_roundtrip_log(wtf_log_level_t level, const char* component,
    const char* file, int line, const char* message, void* context)
{
    (void)level;
    (void)file;
    (void)line;
    (void)context;
    fprintf(stderr, "%s: %s\n", component, message);
}

static void network_roundtrip_stop(int sig)
{
    (void)sig;
    running = 0;
}

static void network_roundtrip_stream_event(const wtf_stream_event_t* event)
{
    if (event->type == WTF_STREAM_EVENT_DATA_RECEIVED) {
        for (uint32_t i = 0; i < event->data_received.buffer_count; ++i) {
            const wtf_buffer_t* buffer = &event->data_received.buffers[i];
            if (server_mode) {
                wtf_stream_send_copy(event->stream, buffer->data, buffer->length, false);
            } else {
                if (buffer->length > sizeof(payload) - 1 - received_bytes
                    || memcmp(buffer->data, payload + received_bytes, buffer->length)) {
                    fprintf(stderr, "stream echo mismatch\n");
                    return;
                }
                received_bytes += buffer->length;
                if (received_bytes == sizeof(payload) - 1) {
                    atomic_store(&stream_echo, true);
                }
            }
        }
    } else if (event->type == WTF_STREAM_EVENT_PEER_CLOSED && server_mode) {
        wtf_stream_close(event->stream);
    }
}

static void network_roundtrip_session_event(const wtf_session_event_t* event)
{
    if (event->type == WTF_SESSION_EVENT_DISCONNECTED && !server_mode
        && (!atomic_load(&stream_echo) || !atomic_load(&datagram_echo))) {
        const char* reason = event->disconnected.reason;
        if (!reason) {
            reason = "";
        }
        fprintf(stderr, "connection closed before echo: %u %s\n",
            event->disconnected.error_code, reason);
        atomic_store(&failed, true);
    } else if (event->type == WTF_SESSION_EVENT_STREAM_OPENED) {
        wtf_stream_set_callback(event->stream_opened.stream, network_roundtrip_stream_event);
    } else if (event->type == WTF_SESSION_EVENT_CONNECTED && !server_mode) {
        struct sockaddr_storage address = {0};
        size_t address_size = sizeof(address);
        if (wtf_session_get_peer_address(event->session, &address, &address_size) != WTF_SUCCESS
            || (address.ss_family != AF_INET && address.ss_family != AF_INET6)) {
            fprintf(stderr, "peer address unavailable\n");
            atomic_store(&failed, true);
        }
        wtf_stream_t* stream = NULL;
        wtf_result_t result = wtf_session_create_stream(
            event->session, WTF_STREAM_BIDIRECTIONAL, network_roundtrip_stream_event, NULL, &stream);
        if (result == WTF_SUCCESS) {
            result = wtf_stream_send_copy(stream, payload, sizeof(payload) - 1, true);
            wtf_stream_unref(stream);
        }
        if (result != WTF_SUCCESS) {
            fprintf(stderr, "stream send failed: %s\n", wtf_result_to_string(result));
            atomic_store(&failed, true);
        }
        result = wtf_session_send_datagram_copy(event->session, payload, sizeof(payload) - 1);
        if (result != WTF_SUCCESS) {
            fprintf(stderr, "datagram send failed: %s\n", wtf_result_to_string(result));
            atomic_store(&failed, true);
        }
    } else if (event->type == WTF_SESSION_EVENT_DATAGRAM_RECEIVED) {
        if (server_mode) {
            wtf_session_send_datagram_copy(
                event->session, event->datagram_received.data, event->datagram_received.length);
        } else if (event->datagram_received.length == sizeof(payload) - 1
            && !memcmp(event->datagram_received.data, payload, sizeof(payload) - 1)) {
            atomic_store(&datagram_echo, true);
        }
    }
}

int main(int argc, char** argv)
{
    if (argc < 3) {
        return 2;
    }
    server_mode = !strcmp(argv[1], "server");
    uint16_t port = (uint16_t)strtoul(argv[2], NULL, 10);
    if (server_mode && argc != 5) {
        return 2;
    }
    signal(SIGTERM, network_roundtrip_stop);
    wtf_context_config_t context_config = {
        .log_level = WTF_LOG_LEVEL_WARN,
        .log_callback = network_roundtrip_log,
    };
    wtf_context_t* context = NULL;
    if (wtf_context_create(&context_config, &context) != WTF_SUCCESS) {
        return 1;
    }
    wtf_server_t* server = NULL;
    wtf_client_t* client = NULL;
    wtf_session_t* session = NULL;
    wtf_result_t result;
    if (server_mode) {
        wtf_certificate_config_t certificate = {.cert_type = WTF_CERT_TYPE_FILE};
        certificate.cert_data.file.cert_path = argv[3];
        certificate.cert_data.file.key_path = argv[4];
        wtf_server_config_t config = {.host = "127.0.0.1",
            .port = port,
            .cert_config = &certificate,
            .draft = WTF_WEBTRANSPORT_DRAFT_07,
            .session_callback = network_roundtrip_session_event};
        result = wtf_server_create(context, &config, &server);
        if (result == WTF_SUCCESS) {
            result = wtf_server_start(server);
        }
    } else {
        char url[80];
        snprintf(url, sizeof(url), "https://127.0.0.1:%u/", port);
        wtf_client_config_t config = {.url = url,
            .draft = WTF_WEBTRANSPORT_DRAFT_07,
            .skip_certificate_validation = true,
            .session_callback = network_roundtrip_session_event};
        result = wtf_client_create(context, &config, &client);
        if (result == WTF_SUCCESS) {
            result = wtf_client_open(client, &session);
        }
    }
    if (result != WTF_SUCCESS) {
        wtf_context_destroy(context);
        return 1;
    }
    if (server_mode) {
        puts("READY");
        fflush(stdout);
    }
    for (unsigned i = 0; running && i < 1000; ++i) {
        if (atomic_load(&failed)) {
            break;
        }
        if (!server_mode && atomic_load(&stream_echo) && atomic_load(&datagram_echo)) {
            break;
        }
        struct timespec delay = {.tv_nsec = 10000000};
        nanosleep(&delay, NULL);
    }
    bool success = !atomic_load(&failed)
        && (server_mode || (atomic_load(&stream_echo) && atomic_load(&datagram_echo)));
    if (session) {
        wtf_session_unref(session);
    }
    wtf_context_destroy(context);
    if (success) {
        puts("PASS stream and datagram roundtrip");
        return 0;
    }
    fprintf(stderr, "roundtrip timed out: stream=%d datagram=%d\n", atomic_load(&stream_echo),
        atomic_load(&datagram_echo));
    return 1;
}
