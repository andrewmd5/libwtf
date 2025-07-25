# libwtf - WebTransport Fast

<p align="center">
  <a href="https://github.com/andrewmd5/libwtf"><img alt="GitHub" src="https://img.shields.io/github/stars/andrewmd5/libwtf?style=flat-square" /></a>
  <a href="https://github.com/andrewmd5/libwtf/releases"><img alt="Release" src="https://img.shields.io/github/v/release/andrewmd5/libwtf?style=flat-square" /></a>
</p>

---

A high-performance WebTransport implementation built on [MsQuic](https://github.com/microsoft/msquic).

## Overview

libwtf implements [WebTransport over HTTP/3 (draft-07)](https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3-07) with forward compatibility for [draft-13](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/). The library handles real-world browser quirks where Chrome sends draft-02 format without proper negotiation.

WebTransport provides low-latency, bidirectional communication over QUIC with support for both reliable streams and unreliable datagrams. All communication occurs over a single QUIC connection with built-in congestion control and multiplexing.

## Features

The library centers around session management with isolated WebTransport sessions. Applications handle connection validation, session lifecycle events, and stream management through callback-based APIs.

Stream support includes both bidirectional and unidirectional channels with flow control and priority handling. Datagram support enables low-latency messaging for real-time applications.

The implementation provides comprehensive error handling with detailed diagnostics and performance statistics for monitoring connection health and throughput.

**Status:** Early development - not recommended for production use.

## Installation

```bash
# Build from source
git clone https://github.com/andrewmd5/libwtf.git
cd libwtf
mkdir build 
cd build && cmake ..
make
```

## Quick Start

```c
#include "wtf.h"

void session_callback(const wtf_session_event_t *event) {
    switch (event->type) {
    case WTF_SESSION_EVENT_CONNECTED:
        printf("Session established\n");
        break;
    case WTF_SESSION_EVENT_DATAGRAM_RECEIVED:
        // Echo datagram back
        wtf_session_send_datagram(event->session, &event->datagram_received.data);
        break;
    }
}

int main() {
    // Initialize context
    wtf_context_config_t ctx_config = {.log_level = WTF_LOG_INFO};
    wtf_context_t *context;
    wtf_context_create(&ctx_config, &context);
    
    // Configure server
    wtf_server_config_t config = {
        .port = 4433,
        .cert_file = "server.crt",
        .key_file = "server.key", 
        .session_callback = session_callback
    };
    
    // Start server
    wtf_server_t *server;
    wtf_server_create(context, &config, &server);
    wtf_server_start(server);
    
    // Server runs...
    
    wtf_server_destroy(server);
    wtf_context_destroy(context);
}
```

## Stream Handling

```c
void stream_callback(const wtf_stream_event_t *event) {
    switch (event->type) {
    case WTF_STREAM_EVENT_DATA_RECEIVED:
        // Echo data back
        wtf_stream_send(event->stream, event->data_received.buffers,
                       event->data_received.buffer_count, false);
        break;
    case WTF_STREAM_EVENT_PEER_CLOSED:
        printf("Stream closed by peer\n");
        break;
    }
}

// In session callback:
case WTF_SESSION_EVENT_STREAM_OPENED:
    wtf_stream_set_callback(event->stream_opened.stream, stream_callback);
    break;
```

## Server-Initiated Streams

```c
// Create outbound stream
wtf_stream_t *stream;
wtf_result_t result = wtf_session_create_stream(session, WTF_STREAM_BIDIRECTIONAL, &stream);

if (result == WTF_SUCCESS) {
    // Send initial data
    const char *message = "Hello from server";
    wtf_buffer_t buffer = {.data = (uint8_t*)message, .length = strlen(message)};
    wtf_stream_send(stream, &buffer, 1, false);
}
```

## Connection Validation

```c
wtf_connection_decision_t connection_validator(const wtf_connection_request_t *request, void *user_data) {
    printf("Connection from: %s%s\n", 
           request->authority ? request->authority : "unknown",
           request->path ? request->path : "/");
    
    // Validate origin, check authentication, etc.
    if (request->origin && strcmp(request->origin, "https://example.com") == 0) {
        return WTF_CONNECTION_ACCEPT;
    }
    
    return WTF_CONNECTION_REJECT;
}
```

## Error Handling

The library provides comprehensive error handling with detailed diagnostics:

```c
wtf_result_t result = wtf_server_start(server);
if (result != WTF_SUCCESS) {
    printf("Server start failed: %s\n", wtf_result_to_string(result));
    return -1;
}

// Get detailed error information
wtf_error_details_t details;
if (wtf_get_error_details(error_code, &details) == WTF_SUCCESS) {
    printf("Error: %s (code: %u)\n", details.description, details.error_code);
}
```

## Example Server

Included with libwtf is a complete echo server that demonstrates session management, stream handling, datagram processing, and command parsing. The server supports interactive commands for testing WebTransport features.

```bash
./example_server --port 4433 --cert server.crt --key server.key --verbose
```

## Build Requirements

- C11 compatible compiler
- [MsQuic](https://github.com/microsoft/msquic)
- [OpenSSL](https://github.com/openssl/openssl)

## Technical Considerations

WebTransport runs over QUIC with HTTP/3 framing. The implementation handles QPACK header compression, flow control, and connection migration. Session multiplexing allows multiple WebTransport sessions over a single QUIC connection.

Browser compatibility varies significantly. Chrome supports WebTransport but with draft-02 semantics, while Firefox implementation is still evolving. The library includes compatibility shims for real-world deployment.

Future client implementation will provide matching functionality for WebTransport clients, enabling full-duplex communication patterns.

---

Feedback and contributions welcome!