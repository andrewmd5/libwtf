#include "wtf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
/*
static volatile bool g_connected = false;
static volatile bool g_stream_open = false;
static wt_stream_t* g_stream = NULL;

void client_callback(const wt_event_t* event, void* user_data) {
    (void)user_data;
    
    switch (event->type) {
        case WT_EVENT_SESSION_CONNECTED:
            printf("Connected to server! Subprotocol: %s\n", 
                   event->session_connected.subprotocol ? event->session_connected.subprotocol : "none");
            g_connected = true;
            
            // Create a bidirectional stream
            printf("Creating bidirectional stream...\n");
            wt_session_create_bidirectional_stream(event->session_connected.session);
            break;
            
        case WT_EVENT_STREAM_OPENED:
            printf("Stream opened successfully\n");
            g_stream = event->stream_opened.stream;
            g_stream_open = true;
            
            // Send initial message
            const char* message = "Hello from WebTransport client!";
            printf("Sending: %s\n", message);
            wt_stream_write(g_stream, (const uint8_t*)message, strlen(message), false);
            break;
            
        case WT_EVENT_STREAM_DATA:
            printf("Received echo: %.*s\n", 
                   (int)event->stream_data.length,
                   (char*)event->stream_data.data);
            
            if (event->stream_data.fin) {
                printf("Stream closed by server\n");
                g_stream_open = false;
            }
            break;
            
        case WT_EVENT_STREAM_CLOSED:
            printf("Stream closed\n");
            g_stream_open = false;
            break;
            
        case WT_EVENT_SESSION_DISCONNECTED:
            printf("Disconnected from server: error_code=%u, reason=%s\n",
                   event->session_disconnected.error_code,
                   event->session_disconnected.reason ? event->session_disconnected.reason : "unknown");
            g_connected = false;
            g_stream_open = false;
            break;
            
        case WT_EVENT_DATAGRAM_RECEIVED:
            printf("Datagram received: %.*s\n",
                   (int)event->datagram_received.length,
                   (char*)event->datagram_received.data);
            break;
            
        case WT_EVENT_STREAM_ERROR:
            printf("Stream error: %s\n", 
                   event->stream_error.message ? event->stream_error.message : "unknown");
            break;
            
        case WT_EVENT_SESSION_ERROR:
            printf("Session error: %s\n",
                   event->session_error.message ? event->session_error.message : "unknown");
            g_connected = false;
            break;
            
        default:
            break;
    }
}

int main(int argc, char* argv[]) {
    printf("WebTransport Echo Client\n");
    printf("========================\n");
    
    // Parse command line arguments
    const char* url = "wt://localhost:4433/echo";
    const char* origin = "https://localhost";
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--url") == 0 && i + 1 < argc) {
            url = argv[++i];
        } else if (strcmp(argv[i], "--origin") == 0 && i + 1 < argc) {
            origin = argv[++i];
        } else if (strcmp(argv[i], "--help") == 0) {
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  --url <url>        Server URL (default: wt://localhost:4433/echo)\n");
            printf("  --origin <origin>  Client origin (default: https://localhost)\n");
            printf("  --help             Show this help\n");
            return 0;
        }
    }
    
    // Initialize WebTransport library
    wt_result_t result = wt_init();
    if (result != WT_SUCCESS) {
        printf("Failed to initialize WebTransport: %s\n", wt_error_string(result));
        return 1;
    }
    
    // Enable debug logging
    wt_set_log_level(WT_LOG_LEVEL_INFO);
    
    // Create client
    wt_client_t* client = wt_client_create(client_callback, NULL);
    if (!client) {
        printf("Failed to create client\n");
        wt_cleanup();
        return 1;
    }
    
    // Configure connection
    wt_client_config_t config = {
        .url = url,
        .subprotocol = "echo",
        .origin = origin,
        .connection_timeout_ms = 10000,
        .idle_timeout_ms = 30000,
        .verify_server_cert = false, // For demo with self-signed certs
        .enable_datagrams = true
    };
    
    printf("Connecting to: %s\n", url);
    printf("Origin: %s\n", origin);
    printf("Subprotocol: %s\n", config.subprotocol);
    
    // Connect to server
    result = wt_client_connect(client, &config);
    if (result != WT_SUCCESS) {
        printf("Failed to initiate connection: %s\n", wt_error_string(result));
        wt_client_destroy(client);
        wt_cleanup();
        return 1;
    }
    
    // Wait for connection
    printf("Waiting for connection...\n");
    int timeout = 100; // 10 seconds
    while (!g_connected && timeout-- > 0) {
        usleep(100000); // 100ms
    }
    
    if (!g_connected) {
        printf("Connection timeout\n");
        wt_client_destroy(client);
        wt_cleanup();
        return 1;
    }
    
    // Wait for stream to open
    timeout = 50; // 5 seconds
    while (!g_stream_open && timeout-- > 0) {
        usleep(100000); // 100ms
    }
    
    if (!g_stream_open) {
        printf("Stream creation timeout\n");
        wt_client_destroy(client);
        wt_cleanup();
        return 1;
    }
    
    // Interactive mode
    printf("\nEntering interactive mode. Type messages to send (empty line to quit):\n");
    char input[1024];
    
    while (g_connected && g_stream_open) {
        printf("> ");
        fflush(stdout);
        
        if (!fgets(input, sizeof(input), stdin)) {
            break;
        }
        
        // Remove newline
        input[strcspn(input, "\n")] = 0;
        
        if (strlen(input) == 0) {
            break;
        }
        
        // Send message
        result = wt_stream_write(g_stream, (const uint8_t*)input, strlen(input), false);
        if (result != WT_SUCCESS) {
            printf("Failed to send message: %s\n", wt_error_string(result));
            break;
        }
        
        // Give some time for echo response
        usleep(100000); // 100ms
    }
    
    // Test datagrams if still connected
    if (g_connected) {
        printf("\nTesting datagrams...\n");
        wt_session_t* session = wt_client_get_session(client);
        if (session) {
            const char* dgram_msg = "Datagram test message";
            result = wt_session_send_datagram(session, (const uint8_t*)dgram_msg, strlen(dgram_msg), NULL);
            if (result == WT_SUCCESS) {
                printf("Datagram sent: %s\n", dgram_msg);
                usleep(500000); // Wait 500ms for response
            } else {
                printf("Failed to send datagram: %s\n", wt_error_string(result));
            }
        }
    }
    
    // Cleanup
    printf("\nDisconnecting...\n");
    if (g_stream_open && g_stream) {
        wt_stream_close(g_stream);
    }
    
    wt_client_disconnect(client, 0, "Client shutdown");
    
    // Wait a bit for graceful shutdown
    usleep(500000); // 500ms
    
    wt_client_destroy(client);
    wt_cleanup();
    
    printf("Client stopped.\n");
    return 0;
}
*/
int main(int argc, char const *argv[])
{
    /* code */
    return 0;
}
