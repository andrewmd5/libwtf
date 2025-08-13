#ifndef WTF_TYPES_H
#define WTF_TYPES_H
#include <lsqpack.h>
#include <lsxpack_header.h>
#include <msquic.h>
#include <tinycthread.h>

#include "wtf.h"
#ifdef __cplusplus
extern "C" {
#endif

#define WTF_UNUSED(x) (void)(x)

#define WTF_ALPN "h3"
#define WTF_DEFAULT_IDLE_TIMEOUT_MS 30000
#define WTF_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000
#define WTF_DEFAULT_MAX_SESSIONS 16
#define WTF_MAX_DATAGRAM_SIZE 65536
#define WTF_MAX_STREAM_BUFFER_SIZE (1024 * 1024)
#define WTF_MAX_BUFFERED_STREAMS 16
#define WTF_MAX_BUFFERED_DATAGRAMS 1000
#define WTF_MAX_STACK_BUFFERS 64

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
    WTF_SETTING_ENABLE_WEBTRANSPORT = 0x2b603742,
    WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS = 0x2b603743
} wtf_h3_setting_t;

#define WTF_QPACK_DYNAMIC_TABLE_SIZE 4096
#define WTF_QPACK_MAX_BLOCKED_STREAMS 100

#define WTF_WEBTRANSPORT_PROTOCOL "webtransport"
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

#ifndef UNREFERENCED_PARAMETER
    #define UNREFERENCED_PARAMETER(P) (void)(P)
#endif

typedef struct wtf_connection wtf_connection;
typedef struct wtf_server wtf_server;
typedef struct wtf_session wtf_session;
typedef struct wtf_stream wtf_stream;
typedef struct wtf_http3_stream wtf_http3_stream;
typedef struct wtf_qpack_context wtf_qpack_context;
typedef struct wtf_settings wtf_settings;
typedef struct wtf_connect_request wtf_connect_request;
typedef struct wtf_header_decode_context wtf_header_decode_context;
typedef struct wtf_datagram wtf_datagram;
typedef struct wtf_send_context wtf_send_context;
typedef struct wtf_capsule wtf_capsule;

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

typedef struct wtf_datagram {
    uint8_t* data;
    size_t length;
    uint64_t session_id;
    void* send_context;
    struct wtf_datagram* next;
} wtf_datagram;

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
    wtf_connection* connection;
    bool headers_complete;
    char decode_buffer[4096];
    struct lsxpack_header current_header;
    size_t header_count;
} wtf_header_decode_context;

typedef struct wtf_settings {
    uint32_t max_field_section_size;
    uint32_t qpack_max_table_capacity;
    uint32_t qpack_blocked_streams;
    uint32_t webtransport_max_sessions;
    bool h3_datagram_enabled;
    bool enable_connect_protocol;
    bool enable_webtransport;
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
    bool valid;
} wtf_connect_request;

typedef struct wtf_stream {
    HQUIC quic_stream;
    uint64_t stream_id;
    wtf_session* session;
    wtf_stream_type_t type;
    wtf_internal_stream_state_t state;

    wtf_stream_callback_t callback;
    void* user_context;
    uint16_t priority;
    bool receive_enabled;

    mtx_t mutex;
} wtf_stream;

typedef struct wtf_http3_stream {
    uint64_t id;
    HQUIC quic_stream;
    wtf_connection* connection;
    uint64_t type;
    wtf_internal_stream_state_t state;

    uint32_t buffered_frames_length;
    uint8_t buffered_frames[1024];
    bool frame_header_complete;

    uint8_t* header_buffer;
    size_t header_buffer_size;
    size_t header_buffer_used;

    wtf_session* webtransport_session;
    bool is_webtransport;

    uint64_t capsule_type;
    uint64_t capsule_length;
    uint64_t capsule_bytes_read;
    bool capsule_header_complete;
    uint8_t* capsule_buffer;
} wtf_http3_stream;

typedef struct wtf_session {
    wtf_connection* connection;
    wtf_http3_stream* connect_stream;
    wtf_session_state_t state;
    uint64_t id;

    wtf_session_callback_t callback;
    void* user_context;

    stream_map streams;
    uint32_t max_streams;
    mtx_t streams_mutex;

    uint32_t close_error_code;
    char* close_reason;
} wtf_session;

typedef struct wtf_connection {
    uint64_t id;
    HQUIC quic_connection;
    wtf_server* server;
    wtf_connection_state_t state;
    uint32_t max_datagram_size;

    wtf_settings local_settings;
    wtf_settings peer_settings;

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
    uint32_t max_sessions;
    mtx_t sessions_mutex;

    http3_stream_map buffered_streams;
    uint32_t buffered_stream_count;
    wtf_datagram* buffered_datagrams;
    uint32_t buffered_datagram_count;
    mtx_t buffered_mutex;

    QUIC_ADDR peer_address;
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

    mtx_t mutex;
} wtf_server;

typedef struct wtf_context {
    wtf_context_config_t config;

    const QUIC_API_TABLE* quic_api;
    HQUIC registration;

    wtf_server* server;

    wtf_log_callback_t log_callback;
    void* log_user_context;
    wtf_log_level_t log_level;

    mtx_t mutex;
} wtf_context;

//! Unpacked send context
typedef struct {
    wtf_buffer_t* buffers;
    uint32_t count;
    void* user_context;
    QUIC_BUFFER* quic_buffers;
    wtf_session* session;
    bool internal_send;
} wtf_internal_send_context;

#ifdef __cplusplus
}
#endif
#endif  // WTF_TYPES_H
