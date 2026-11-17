#ifndef WTF_NETWORK_INTERNAL_H
#define WTF_NETWORK_INTERNAL_H

#if !defined(__APPLE__) || !defined(WTF_QUIC_BACKEND_NETWORK)
    #error "Network backend internals require WTF_QUIC_BACKEND_NETWORK on Apple platforms"
#endif

#include <Network/Network.h>
#include <Security/Security.h>
#include <TargetConditionals.h>
#include <dispatch/dispatch.h>
#include <msquic.h>
#include <stdatomic.h>

#include "log.h"
#include "network.h"
#include "network_private.h"
#include "wtf.h"

#define NETWORK_SEND_LIMIT (8u * 1024u * 1024u)
#define NETWORK_PENDING_SEND_LIMIT 1024u
#define NETWORK_MIN_SEND_CHARGE 1024u
#define NETWORK_RECEIVE_SIZE (64u * 1024u)

typedef enum {
    NETWORK_REGISTRATION,
    NETWORK_CONFIGURATION,
    NETWORK_LISTENER,
    NETWORK_CONNECTION,
    NETWORK_STREAM
} network_handle_kind;

typedef enum {
    NETWORK_HANDLE_OPEN,
    NETWORK_HANDLE_CLOSING,
    NETWORK_HANDLE_CLOSED
} network_handle_state;

struct QUIC_HANDLE {
    atomic_uint references;
    network_handle_kind kind;
    network_handle_state state;
    HQUIC parent;
    dispatch_queue_t queue;
    void* callback;
    void* context;
};

typedef struct network_configuration network_configuration;
typedef struct network_connection network_connection;
typedef struct network_stream network_stream;
typedef struct network_send_operation network_send_operation;

/* A handle is stable before Network assigns the QUIC stream ID. */
#define NAME network_stream_map
#define KEY_TY uintptr_t
#define VAL_TY network_stream*
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

typedef struct {
    struct QUIC_HANDLE handle;
    dispatch_group_t drain;
    dispatch_queue_t session_queue;
} network_registration;

struct network_configuration {
    struct QUIC_HANDLE handle;
    QUIC_SETTINGS settings;
    QUIC_CREDENTIAL_FLAGS credential_flags;
    char* alpn;
    sec_identity_t identity;
    SecCertificateRef anchor;
    uint8_t certificate_pin[32];
#if TARGET_OS_OSX
    SecKeychainRef keychain;
    char* keychain_directory;
#endif
};

typedef enum {
    NETWORK_LISTENER_CREATED,
    NETWORK_LISTENER_STARTING,
    NETWORK_LISTENER_READY,
    NETWORK_LISTENER_STOPPING,
    NETWORK_LISTENER_STOPPED
} network_listener_state;

typedef struct {
    struct QUIC_HANDLE handle;
    network_listener_state state;
    network_configuration* configuration;
    nw_listener_t listener;
    dispatch_semaphore_t startup;
    QUIC_STATUS startup_status;
} network_listener;

typedef enum {
    NETWORK_CONNECTION_CREATED,
    NETWORK_CONNECTION_STARTING,
    NETWORK_CONNECTION_READY,
    NETWORK_CONNECTION_LOCAL_CLOSE,
    NETWORK_CONNECTION_REMOTE_CLOSE,
    NETWORK_CONNECTION_DRAINING,
    NETWORK_CONNECTION_COMPLETE
} network_connection_state;

typedef enum {
    NETWORK_DATAGRAM_NONE,
    NETWORK_DATAGRAM_STARTING,
    NETWORK_DATAGRAM_READY,
    NETWORK_DATAGRAM_CLOSED
} network_datagram_state;

typedef struct {
    network_send_operation* first;
    size_t count;
    size_t charged_bytes;
} network_send_queue;

struct network_connection {
    struct QUIC_HANDLE handle;
    network_connection_state state;
    network_configuration* configuration;
    nw_connection_group_t group;
    nw_protocol_metadata_t metadata;
    dispatch_source_t handshake_timer;
    nw_connection_t datagram;
    network_datagram_state datagram_state;
    uint16_t datagram_size;
    network_stream_map streams;
    uint64_t local_max_streams_bidi;
    uint64_t local_max_streams_uni;
    network_send_queue sends;
    QUIC_ADDR address;
    uint64_t close_code;
    char* close_reason;
};

typedef enum {
    NETWORK_STREAM_CREATED,
    NETWORK_STREAM_STARTING,
    NETWORK_STREAM_READY,
    NETWORK_STREAM_CANCELLING,
    NETWORK_STREAM_CANCELLED,
    NETWORK_STREAM_COMPLETE
} network_stream_state;

typedef enum {
    NETWORK_STREAM_LOCAL_BIDI,
    NETWORK_STREAM_LOCAL_UNI,
    NETWORK_STREAM_PEER_PENDING,
    NETWORK_STREAM_PEER_BIDI,
    NETWORK_STREAM_PEER_UNI
} network_stream_origin;

typedef enum {
    NETWORK_SEND_OPEN,
    NETWORK_SEND_FIN_PENDING,
    NETWORK_SEND_FINISHED,
    NETWORK_SEND_ABORT_PENDING,
    NETWORK_SEND_ABORTED
} network_send_state;

typedef enum {
    NETWORK_RECEIVE_IDLE,
    NETWORK_RECEIVE_PENDING,
    NETWORK_RECEIVE_PAUSING,
    NETWORK_RECEIVE_PAUSED,
    NETWORK_RECEIVE_FINISHED,
    NETWORK_RECEIVE_ABORTED
} network_receive_state;

typedef enum {
    NETWORK_DELIVERY_NONE,
    NETWORK_DELIVERY_DATA,
    NETWORK_DELIVERY_FIN,
    NETWORK_DELIVERY_ERROR
} network_delivery_kind;

struct network_stream {
    struct QUIC_HANDLE handle;
    network_stream_state state;
    network_stream_origin origin;
    network_send_state send_state;
    network_receive_state receive_state;
    nw_connection_t connection;
    nw_protocol_metadata_t metadata;
    nw_content_context_t send_context;
    uint16_t priority;
    uint64_t reliable_offset;
    atomic_uint_fast64_t id;
    uint64_t received_bytes;
    network_send_queue sends;
    dispatch_data_t deferred_data;
    network_delivery_kind deferred_kind;
};

typedef enum {
    NETWORK_SEND_ON_PROCESS,
    NETWORK_SEND_ON_RELEASE
} network_send_completion_mode;

typedef enum {
    NETWORK_SEND_PENDING,
    NETWORK_SEND_COMPLETED
} network_send_completion;

struct network_send_operation {
    network_send_operation* next;
    network_send_operation** previous;
    HQUIC owner;
    void* context;
    size_t charge;
    network_send_completion completion;
    network_send_completion_mode mode;
    QUIC_STATUS status;
    unsigned pending_callbacks;
};

HQUIC network_handle_create(network_handle_kind kind, size_t size, HQUIC parent);
HQUIC network_handle_retain(HQUIC handle);
void network_handle_release(HQUIC handle);
void network_handle_close(HQUIC handle);
void network_run(HQUIC handle, dispatch_block_t work);
wtf_context_t* network_logging_context(HQUIC handle);
nw_protocol_definition_t network_quic_definition(void);
QUIC_STATUS network_error_status(nw_error_t error);
QUIC_STATUS network_emit_connection(network_connection* connection, QUIC_CONNECTION_EVENT* event);
QUIC_STATUS network_emit_stream(network_stream* stream, QUIC_STREAM_EVENT* event);

network_send_operation* network_send_reserve(HQUIC owner, void* context, size_t length);
void network_send_complete(network_send_operation* operation, nw_error_t error);
void network_send_cancel_all(HQUIC owner);
QUIC_STATUS network_send_validate(
    const QUIC_BUFFER* buffers, uint32_t count, size_t limit, size_t* length);
dispatch_data_t network_send_data(
    network_send_operation* operation, const QUIC_BUFFER* buffers, uint32_t count, size_t length);
void network_send_abandon(network_send_operation* operation);

QUIC_STATUS network_configuration_open(HQUIC registration,
    const QUIC_BUFFER* alpns,
    uint32_t count,
    const QUIC_SETTINGS* settings,
    uint32_t settings_size,
    void* context,
    HQUIC* out);
QUIC_STATUS network_configuration_load(
    HQUIC configuration, const QUIC_CREDENTIAL_CONFIG* credentials);
void network_configuration_dispose(network_configuration* configuration);
nw_parameters_t network_parameters_create(network_connection* connection,
    network_configuration* configuration,
    const char* host,
    uint16_t port);
dispatch_queue_t network_session_queue_create(void);
void network_session_configure(nw_protocol_options_t options,
    network_configuration* configuration,
    const char* host,
    uint16_t port);

QUIC_STATUS network_listener_open(
    HQUIC registration, QUIC_LISTENER_CALLBACK_HANDLER callback, void* context, HQUIC* out);
QUIC_STATUS network_listener_start(
    HQUIC handle, const QUIC_BUFFER* alpns, uint32_t count, const QUIC_ADDR* address);
void network_listener_stop(HQUIC handle);
void network_listener_close(network_listener* listener);
void network_listener_dispose(network_listener* listener);

QUIC_STATUS network_connection_open(
    HQUIC registration, QUIC_CONNECTION_CALLBACK_HANDLER callback, void* context, HQUIC* out);
QUIC_STATUS network_connection_start(
    HQUIC handle, HQUIC configuration, QUIC_ADDRESS_FAMILY family, const char* host, uint16_t port);
QUIC_STATUS network_connection_configure(HQUIC handle, HQUIC configuration);
void network_connection_shutdown(
    HQUIC handle, QUIC_CONNECTION_SHUTDOWN_FLAGS flags, QUIC_UINT62 code);
void network_connection_close(network_connection* connection);
void network_connection_dispose(network_connection* connection);
void network_connection_finish(network_connection* connection);
void network_connection_start_group(network_connection* connection);
void network_connection_read_address(network_connection* connection);
QUIC_STATUS network_datagram_send(
    HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count, QUIC_SEND_FLAGS flags, void* context);

QUIC_STATUS network_stream_open(HQUIC connection,
    QUIC_STREAM_OPEN_FLAGS flags,
    QUIC_STREAM_CALLBACK_HANDLER callback,
    void* context,
    HQUIC* out);
QUIC_STATUS network_stream_start(HQUIC handle, QUIC_STREAM_START_FLAGS flags);
QUIC_STATUS network_stream_send(
    HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count, QUIC_SEND_FLAGS flags, void* context);
QUIC_STATUS network_stream_shutdown(
    HQUIC handle, QUIC_STREAM_SHUTDOWN_FLAGS flags, QUIC_UINT62 code);
QUIC_STATUS network_stream_receive_enabled(HQUIC handle, BOOLEAN enabled);
QUIC_STATUS network_stream_set_parameter(
    network_stream* stream, uint32_t parameter, uint32_t size, const void* buffer);
void network_stream_accept(network_connection* connection, nw_connection_t incoming);
void network_stream_close(network_stream* stream);
void network_stream_detach(network_stream* stream);
void network_stream_dispose(network_stream* stream);
void network_stream_cancel(network_stream* stream);
void network_stream_finish(network_stream* stream);

#endif
