#ifndef WTF_TYPES_H
#define WTF_TYPES_H
#include <lsqpack.h>
#include <lsxpack_header.h>
#include <msquic.h>
#include <stdatomic.h>
#include <tinycthread.h>

#include "wtf.h"
#ifdef __cplusplus
extern "C" {
#endif

#if defined(__GNUC__) || defined(__clang__)
    #define WTF_MAYBE_UNUSED __attribute__((unused))
#else
    #define WTF_MAYBE_UNUSED
#endif

#define WTF_ALPN "h3"
#define WTF_DEFAULT_IDLE_TIMEOUT_MS 30000
#define WTF_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000
#define WTF_DEFAULT_MAX_SESSIONS 16
#define WTF_DEFAULT_MAX_STREAMS_PER_SESSION 1000
#define WTF_DEFAULT_MAX_DATA_PER_SESSION (16 * 1024 * 1024)
#define WTF_DEFAULT_STREAM_RECV_WINDOW (1024 * 1024)
#define WTF_DEFAULT_CONN_FLOW_CONTROL_WINDOW (16 * 1024 * 1024)
#define WTF_MAX_PENDING_CONNECT_REQUESTS 64
#define WTF_MAX_SEND_BUFFERS 64
#define WTF_INLINE_SEND_BUFFERS 4
#define WTF_INLINE_SEND_STORAGE 128
#define WTF_INLINE_CAPSULE_STORAGE 32
#define WTF_MAX_DATAGRAM_SIZE 65536
#define WTF_MAX_STREAM_BUFFER_SIZE (1024 * 1024)
#define WTF_MAX_CONNECT_RESPONSE_HEADERS 32
#define WTF_MAX_CONNECT_RESPONSE_HEADER_BYTES 8192
#define WTF_CLOSE_ERROR_CODE_LENGTH 4
#define WTF_MAX_CLOSE_REASON_LENGTH 1024

typedef enum {
    WTF_FRAME_DATA = 0x00,
    WTF_FRAME_HEADERS = 0x01,
    WTF_FRAME_CANCEL_PUSH = 0x03,
    WTF_FRAME_SETTINGS = 0x04,
    WTF_FRAME_PUSH_PROMISE = 0x05,
    WTF_FRAME_GOAWAY = 0x07,
    WTF_FRAME_MAX_PUSH_ID = 0x0D,
    WTF_FRAME_BIDIR_WEBTRANSPORT_STREAM = 0x41
} wtf_h3_frame_type_t;

typedef enum {
    WTF_STREAM_TYPE_CONTROL = 0x00,
    WTF_STREAM_TYPE_PUSH = 0x01,
    WTF_STREAM_TYPE_QPACK_ENCODER = 0x02,
    WTF_STREAM_TYPE_QPACK_DECODER = 0x03,
    WTF_STREAM_TYPE_UNI_WEBTRANSPORT_STREAM = 0x54
} wtf_h3_stream_type_t;

typedef enum {
    WTF_SETTING_QPACK_MAX_TABLE_CAPACITY = 0x01,
    WTF_SETTING_MAX_FIELD_SECTION_SIZE = 0x06,
    WTF_SETTING_QPACK_BLOCKED_STREAMS = 0x07,
    WTF_SETTING_ENABLE_CONNECT_PROTOCOL = 0x08,
    WTF_SETTING_H3_DATAGRAM = 0x33,
    WTF_SETTING_H3_DRAFT04_DATAGRAM = 0xffd277,
    WTF_SETTING_WT_INITIAL_MAX_DATA = 0x2b61,
    WTF_SETTING_WT_INITIAL_MAX_STREAMS_UNI = 0x2b64,
    WTF_SETTING_WT_INITIAL_MAX_STREAMS_BIDI = 0x2b65,
    WTF_SETTING_ENABLE_WEBTRANSPORT_DRAFT02 = 0x2b603742,
    WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS_DRAFT07 = 0xc671706a,
    WTF_SETTING_WT_ENABLED_DRAFT15 = 0x2c7cf000,
    WTF_SETTING_WT_MAX_SESSIONS = 0x14e9cd29
} wtf_h3_setting_t;

#define WTF_QPACK_DYNAMIC_TABLE_SIZE 4096
#define WTF_QPACK_MAX_BLOCKED_STREAMS 100

#define WTF_WEBTRANSPORT_PROTOCOL_DRAFT15 "webtransport-h3"
#define WTF_WEBTRANSPORT_PROTOCOL_DRAFT02 "webtransport"
#define WTF_WEBTRANSPORT_DRAFT02_REQUEST_HEADER "sec-webtransport-http3-draft02"
#define WTF_WEBTRANSPORT_DRAFT02_REQUEST_VALUE "1"
#define WTF_WEBTRANSPORT_DRAFT02_RESPONSE_HEADER "sec-webtransport-http3-draft"
#define WTF_WEBTRANSPORT_DRAFT02_RESPONSE_VALUE "draft02"
#define WTF_CONNECT_METHOD "CONNECT"
#define WTF_HTTPS_SCHEME "https"

#define WTF_STREAM_IS_UNIDIRECTIONAL(id) ((id) & 0x02)
#define WTF_STREAM_IS_CLIENT_INITIATED(id) (((id) & 0x01) == 0)

#ifndef ARRAYSIZE
    #define ARRAYSIZE(A) (sizeof(A) / sizeof((A)[0]))
#endif

#ifndef CXPLAT_ANALYSIS_ASSERT
    #define CXPLAT_ANALYSIS_ASSERT(X)
#endif

#ifndef min
    #define min(a, b) ((a) > (b) ? (b) : (a))
#endif

#ifndef max
    #define max(a, b) ((a) < (b) ? (b) : (a))
#endif

typedef struct wtf_connection wtf_connection;
typedef struct wtf_context wtf_context;
typedef struct wtf_server wtf_server;
typedef struct wtf_client wtf_client;
typedef struct wtf_session wtf_session;
typedef struct wtf_stream wtf_stream;
typedef struct wtf_http3_stream wtf_http3_stream;
typedef struct wtf_qpack_context wtf_qpack_context;
typedef struct wtf_settings wtf_settings;
typedef struct wtf_connect_request wtf_connect_request;
typedef struct wtf_connect_response wtf_connect_response;
typedef struct wtf_connection_request_handle wtf_connection_request_handle;
typedef struct wtf_header_decode_context wtf_header_decode_context;
typedef struct wtf_send_context wtf_send_context;
typedef struct wtf_capsule wtf_capsule;

#if defined(__cplusplus)
    #define WTF_STATIC_ASSERT static_assert
#else
    #define WTF_STATIC_ASSERT _Static_assert
#endif

WTF_STATIC_ASSERT(sizeof(wtf_buffer_t) == sizeof(QUIC_BUFFER),
                  "wtf_buffer_t must stay layout-compatible with QUIC_BUFFER");
WTF_STATIC_ASSERT(offsetof(wtf_buffer_t, length) == offsetof(QUIC_BUFFER, Length),
                  "wtf_buffer_t.length must match QUIC_BUFFER.Length");
WTF_STATIC_ASSERT(offsetof(wtf_buffer_t, data) == offsetof(QUIC_BUFFER, Buffer),
                  "wtf_buffer_t.data must match QUIC_BUFFER.Buffer");

#define NAME session_map
#define KEY_TY uint64_t
#define VAL_TY wtf_session*
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

#define NAME stream_map
#define KEY_TY uint64_t
#define VAL_TY wtf_stream*
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

#define NAME http3_stream_map
#define KEY_TY uint64_t
#define VAL_TY wtf_http3_stream*
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

#define NAME connection_map
#define KEY_TY uint64_t
#define VAL_TY wtf_connection*
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

typedef enum {
    WTF_CONNECTION_STATE_HANDSHAKING,
    WTF_CONNECTION_STATE_READY,
    WTF_CONNECTION_STATE_CLOSING,
    WTF_CONNECTION_STATE_CLOSED
} wtf_connection_state_t;

typedef enum {
    WTF_INTERNAL_STREAM_STATE_IDLE,
    WTF_INTERNAL_STREAM_STATE_OPEN,
    WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL,
    WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE,
    WTF_INTERNAL_STREAM_STATE_CLOSED,
    WTF_INTERNAL_STREAM_STATE_RESET
} wtf_internal_stream_state_t;

typedef enum {
    WTF_HTTP3_STREAM_FLAG_NONE = 0,
    WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT = 1u << 0,
    WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT_SENT = 1u << 1
} wtf_http3_stream_flags_t;

typedef enum {
    WTF_CLIENT_FLAG_NONE = 0,
    WTF_CLIENT_FLAG_TRANSPORT_STARTED = 1u << 0,
    WTF_CLIENT_FLAG_TRANSPORT_READY = 1u << 1
} wtf_client_flags_t;

typedef enum {
    WTF_ENDPOINT_SERVER,
    WTF_ENDPOINT_CLIENT
} wtf_endpoint_role_t;

#define WTF_WEBTRANSPORT_DRAFT_NONE WTF_WEBTRANSPORT_DRAFT_AUTO

typedef struct wtf_capsule {
    uint64_t type;
    uint64_t length;
    uint8_t* data;
} wtf_capsule;

typedef struct wtf_qpack_context {
    struct lsqpack_enc encoder;
    struct lsqpack_dec decoder;
    uint32_t max_table_capacity;
    uint32_t max_blocked_streams;
    uint32_t peer_max_table_capacity;
    uint64_t peer_blocked_streams;
    bool initialized;
    uint8_t tsu_buf[4096];
    size_t tsu_buf_sz;
    mtx_t mutex;
} wtf_qpack_context;

typedef struct wtf_header_decode_context {
    wtf_connect_request* request;
    wtf_connect_response* response;
    wtf_connection* connection;
    bool decode_response;
    bool headers_complete;
    bool seen_regular_header;
    bool malformed_header_block;
    bool seen_method;
    bool seen_protocol;
    bool seen_scheme;
    bool seen_authority;
    bool seen_path;
    bool seen_status;
    char decode_buffer[4096];
    struct lsxpack_header current_header;
    size_t header_count;
} wtf_header_decode_context;

typedef struct wtf_settings {
    uint32_t max_field_section_size;
    uint32_t qpack_max_table_capacity;
    uint32_t qpack_blocked_streams;
    uint32_t webtransport_max_sessions;
    uint64_t wt_initial_max_data;
    uint64_t wt_initial_max_streams_bidi;
    uint64_t wt_initial_max_streams_uni;
    bool wt_initial_max_data_received;
    bool wt_initial_max_streams_bidi_received;
    bool wt_initial_max_streams_uni_received;
    bool h3_datagram_enabled;
    bool h3_datagram_rfc_enabled;
    bool h3_datagram_draft04_enabled;
    bool enable_connect_protocol;
    bool enable_webtransport;
    bool enable_webtransport_draft02;
    bool enable_webtransport_draft07;
    bool enable_webtransport_draft15;
    bool settings_sent;
    bool settings_received;
} wtf_settings;

typedef struct wtf_connect_request {
    char* method;
    char* protocol;
    char* scheme;
    char* authority;
    char* path;
    char* origin;
    wtf_http_header_t* headers;
    size_t header_count;
    size_t header_capacity;
    bool valid;
} wtf_connect_request;

typedef struct wtf_connect_response {
    uint16_t status_code;
    char* draft_header;
    wtf_http_header_t* headers;
    size_t header_count;
    size_t header_capacity;
    bool valid;
} wtf_connect_response;

typedef struct wtf_connection_request_handle {
    atomic_uint ref_count;
    bool completed;
    wtf_http3_stream* stream;
    wtf_connection_response_t response;
    mtx_t mutex;
} wtf_connection_request_handle;

typedef struct wtf_stream {
    atomic_uint ref_count;
    bool destroyed;
    HQUIC quic_stream;
    uint64_t stream_id;
    wtf_session* session;
    wtf_stream_type_t type;
    wtf_internal_stream_state_t state;

    wtf_stream_callback_t callback;
    void* user_context;
    uint16_t priority;
    bool receive_enabled;
    bool peer_closed_notified;

    mtx_t mutex;
} wtf_stream;

typedef struct wtf_http3_stream {
    atomic_uint ref_count;
    bool destroyed;
    uint64_t id;
    HQUIC quic_stream;
    wtf_connection* connection;
    uint64_t type;
    wtf_internal_stream_state_t state;

    uint8_t* buffered_data;
    size_t buffered_data_length;
    size_t buffered_data_capacity;
    bool frame_header_complete;

    uint8_t* header_buffer;
    size_t header_buffer_size;
    size_t header_buffer_used;

    wtf_session* webtransport_session;
    bool is_webtransport;
    bool callback_transferred;
    wtf_http3_stream_flags_t flags;

    uint8_t* pending_connect_header_block;
    size_t pending_connect_header_length;
    bool has_pending_connect_header_block;
    struct wtf_http3_stream* next_client_pending_connect;

    uint64_t capsule_type;
    uint64_t capsule_length;
    uint64_t capsule_bytes_read;
    bool capsule_header_complete;
    uint8_t capsule_header[2 * sizeof(uint64_t)];
    size_t capsule_header_length;
    uint8_t* capsule_buffer;
    uint8_t capsule_inline[WTF_INLINE_CAPSULE_STORAGE];
} wtf_http3_stream;

typedef struct wtf_session {
    atomic_uint ref_count;
    bool destroyed;
    wtf_connection* connection;
    wtf_http3_stream* connect_stream;
    wtf_session_state_t state;
    uint64_t id;
    struct wtf_session* next_closed;
    bool retired;

    wtf_session_callback_t callback;
    void* user_context;

    stream_map streams;
    uint32_t max_streams;
    uint32_t pending_stream_count;
    uint64_t local_max_streams_bidi;
    uint64_t local_max_streams_uni;
    uint64_t remote_max_streams_bidi;
    uint64_t remote_max_streams_uni;
    uint64_t incoming_streams_bidi;
    uint64_t incoming_streams_uni;
    uint64_t outgoing_streams_bidi;
    uint64_t outgoing_streams_uni;
    uint64_t local_max_data;
    uint64_t remote_max_data;
    uint64_t received_data;
    uint64_t sent_data;
    mtx_t streams_mutex;

    uint32_t close_error_code;
    char* close_reason;
} wtf_session;

typedef struct wtf_connection {
    atomic_uint ref_count;
    bool destroyed;
    uint64_t id;
    HQUIC quic_connection;
    wtf_context* context;
    wtf_endpoint_role_t role;
    wtf_server* server;
    wtf_client* client;
    wtf_connection_state_t state;
    atomic_bool datagram_send_enabled;
    atomic_uint max_datagram_size;

    wtf_settings local_settings;
    wtf_settings peer_settings;
    wtf_webtransport_draft_t requested_webtransport_draft;
    wtf_webtransport_draft_t selected_webtransport_draft;
    bool webtransport_flow_control_enabled;
    bool reliable_reset_negotiation_complete;
    bool reliable_reset_negotiated;
    uint32_t pending_connect_count;

    wtf_http3_stream* control_stream;
    wtf_http3_stream* qpack_encoder_stream;
    wtf_http3_stream* qpack_decoder_stream;
    wtf_http3_stream* peer_control_stream;
    wtf_http3_stream* peer_encoder_stream;
    wtf_http3_stream* peer_decoder_stream;
    http3_stream_map streams;
    mtx_t streams_mutex;

    wtf_qpack_context qpack;

    session_map sessions;
    wtf_session* closed_sessions;
    uint32_t max_sessions;
    mtx_t sessions_mutex;

    QUIC_ADDR peer_address;

    uint32_t max_streams_per_session;
    uint64_t max_data_per_session;
    wtf_connection_validator_t connection_validator;
    wtf_session_callback_t session_callback;
    void* user_context;
} wtf_connection;

typedef struct wtf_server {
    wtf_context_t* context;
    wtf_server_config_t config;
    wtf_server_state_t state;

    HQUIC listener;
    HQUIC configuration;
    QUIC_CREDENTIAL_CONFIG* cred_config;

    connection_map connections;
    mtx_t connections_mutex;
    cnd_t connections_drained;
    bool destroying;

    mtx_t mutex;
} wtf_server;

typedef struct wtf_client {
    wtf_context_t* context;
    wtf_client_config_t config;
    wtf_client_state_t state;
    char* host;
    char* authority;
    char* path;
    uint16_t port;
    bool pinned_server_certificate_present;
    uint8_t pinned_server_certificate_sha256[32];

    HQUIC configuration;
    HQUIC quic_connection;
    QUIC_CREDENTIAL_CONFIG* cred_config;
    wtf_connection* connection;
    wtf_http3_stream* pending_connect_head;
    wtf_http3_stream* pending_connect_tail;
    uint32_t pending_connect_count;
    uint32_t opened_session_count;

    wtf_client_flags_t flags;

    mtx_t mutex;
    cnd_t connected;
} wtf_client;

typedef struct wtf_context {
    wtf_context_config_t config;

    const QUIC_API_TABLE* quic_api;
    HQUIC registration;

    wtf_server* server;
    wtf_client* client;

    wtf_log_callback_t log_callback;
    void* log_user_context;
    wtf_log_level_t log_level;

    mtx_t mutex;
} wtf_context;

//! Unpacked send context
typedef struct {
    wtf_buffer_t* buffers;
    uint32_t count;
    wtf_session* session;
    uint64_t flow_control_length;
    bool internal_send;
    bool owns_buffer_data;
    bool buffers_inline;
    bool owns_session_ref;
    uint32_t app_buffer_offset;
    void* operation_context;
    wtf_buffer_t inline_buffers[WTF_INLINE_SEND_BUFFERS];
    uint8_t inline_data[WTF_INLINE_SEND_STORAGE];
} wtf_internal_send_context;

#ifdef __cplusplus
}
#endif
#endif  // WTF_TYPES_H
