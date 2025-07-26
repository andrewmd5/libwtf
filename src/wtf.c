#include <stdint.h>
#ifdef __APPLE__
#include <netinet/in.h>
#include <sys/types.h>
#endif

#include "tinycthread.h"
#include "wtf.h"
#include <lsqpack.h>
#include <lsxpack_header.h>
#include <msquic.h>

#include <assert.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
#include <winsock2.h>
#include <io.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <ctype.h>
#endif

#include "wtf_version.h"   

#define WTF_UNUSED(x) (void)(x)

#define WTF_ALPN "h3"
#define WTF_DEFAULT_IDLE_TIMEOUT_MS 30000
#define WTF_DEFAULT_HANDSHAKE_TIMEOUT_MS 10000
#define WTF_DEFAULT_MAX_SESSIONS 16
#define WTF_MAX_DATAGRAM_SIZE 65536
#define WTF_MAX_STREAM_BUFFER_SIZE (1024 * 1024)
#define WTF_MAX_BUFFERED_STREAMS 100
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
  WTF_FRAME_WEBTRANSPORT_STREAM = 0x41
} wtf_h3_frame_type_t;

typedef enum {
  WTF_STREAM_TYPE_CONTROL = 0x00,
  WTF_STREAM_TYPE_PUSH = 0x01,
  WTF_STREAM_TYPE_QPACK_ENCODER = 0x02,
  WTF_STREAM_TYPE_QPACK_DECODER = 0x03,
  WTF_STREAM_TYPE_WEBTRANSPORT_STREAM = 0x54
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

#ifdef _WIN32
#define CxPlatByteSwapUint16 _byteswap_ushort
#define CxPlatByteSwapUint32 _byteswap_ulong
#define CxPlatByteSwapUint64 _byteswap_uint64
#else
#define CxPlatByteSwapUint16(value) __builtin_bswap16((unsigned short)(value))
#define CxPlatByteSwapUint32(value) __builtin_bswap32((value))
#define CxPlatByteSwapUint64(value) __builtin_bswap64((value))
#endif

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

#ifndef CXPLAT_DBG_ASSERT
#define CXPLAT_DBG_ASSERT(X)
#endif

#include <quic_var_int.h>

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
#define VAL_TY wtf_session *
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

#define NAME stream_map
#define KEY_TY uint64_t
#define VAL_TY wtf_stream *
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

#define NAME http3_stream_map
#define KEY_TY uint64_t
#define VAL_TY wtf_http3_stream *
#define HASH_FN vt_hash_integer
#define CMPR_FN vt_cmpr_integer
#include "verstable.h"

static inline uint64_t wtf_hash_pointer(wtf_connection *ptr) {
  return vt_hash_integer((uintptr_t)ptr);
}

static inline bool wtf_cmpr_pointer(wtf_connection *ptr1,
                                    wtf_connection *ptr2) {
  return ptr1 == ptr2;
}

#define NAME connection_set
#define KEY_TY wtf_connection *
#define HASH_FN wtf_hash_pointer
#define CMPR_FN wtf_cmpr_pointer
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
  uint8_t *data;
  size_t length;
  uint64_t session_id;
  void *send_context;
  struct wtf_datagram *next;
} wtf_datagram;

typedef struct wtf_capsule {
  uint64_t type;
  uint64_t length;
  uint8_t *data;
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
  wtf_connect_request *request;
  wtf_connection *connection;
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
  char *method;
  char *protocol;
  char *scheme;
  char *authority;
  char *path;
  char *origin;
  bool valid;
} wtf_connect_request;

typedef struct wtf_stream {
  HQUIC quic_stream;
  uint64_t stream_id;
  wtf_session *session;
  wtf_stream_type_t type;
  wtf_internal_stream_state_t state;

  wtf_stream_callback_t callback;
  void *user_context;
  uint16_t priority;
  bool receive_enabled;

  uint64_t bytes_sent;
  uint64_t bytes_received;

  mtx_t mutex;
} wtf_stream;

typedef struct wtf_http3_stream {
  uint64_t id;
  HQUIC quic_stream;
  wtf_connection *connection;
  uint64_t type;
  wtf_internal_stream_state_t state;

  uint32_t buffered_headers_length;
  uint8_t buffered_headers[1024];
  bool frame_header_complete;

  uint8_t *header_buffer;
  size_t header_buffer_size;
  size_t header_buffer_used;

  wtf_session *webtransport_session;
  bool is_webtransport;

  uint64_t capsule_type;
  uint64_t capsule_length;
  uint64_t capsule_bytes_read;
  bool capsule_header_complete;
  uint8_t *capsule_buffer;
} wtf_http3_stream;

typedef struct wtf_session {
  wtf_connection *connection;
  wtf_http3_stream *connect_stream;
  wtf_session_state_t state;
  uint64_t id;

  wtf_session_callback_t callback;
  void *user_context;

  stream_map streams;
  uint32_t max_streams;
  mtx_t streams_mutex;

  uint32_t close_error_code;
  char *close_reason;
} wtf_session;

typedef struct wtf_connection {
  HQUIC quic_connection;
  wtf_server *server;
  wtf_connection_state_t state;
  uint32_t max_datagram_size;

  wtf_settings local_settings;
  wtf_settings peer_settings;

  wtf_http3_stream *control_stream;
  wtf_http3_stream *qpack_encoder_stream;
  wtf_http3_stream *qpack_decoder_stream;
  wtf_http3_stream *peer_control_stream;
  wtf_http3_stream *peer_encoder_stream;
  wtf_http3_stream *peer_decoder_stream;
  http3_stream_map streams;
  mtx_t streams_mutex;

  wtf_qpack_context qpack;

  session_map sessions;
  uint32_t max_sessions;
  mtx_t sessions_mutex;

  http3_stream_map buffered_streams;
  uint32_t buffered_stream_count;
  wtf_datagram *buffered_datagrams;
  uint32_t buffered_datagram_count;
  mtx_t buffered_mutex;

  QUIC_ADDR peer_address;
} wtf_connection;

typedef struct wtf_server {
    wtf_context_t *context;
    wtf_server_config_t config;
    wtf_server_state_t state;

    HQUIC listener;
    HQUIC configuration;
    QUIC_CREDENTIAL_CONFIG *cred_config;

    connection_set connections;
    mtx_t connections_mutex;

    wtf_server_statistics_t stats;
    mtx_t mutex;
} wtf_server;

typedef struct wtf_context {
  wtf_context_config_t config;

  const QUIC_API_TABLE *quic_api;
  HQUIC registration;

  wtf_server *server;

  wtf_log_callback_t log_callback;
  void *log_user_context;
  wtf_log_level_t log_level;

  mtx_t mutex;
} wtf_context;

static bool wtf_process_settings_frame(wtf_http3_stream *stream,
                                       const uint8_t *data, size_t data_len);
static bool wtf_process_headers_frame(wtf_http3_stream *stream,
                                      wtf_connect_request *request);
static bool wtf_process_h3_datagram(wtf_connection *conn, const uint8_t *data,
                                    size_t data_len);
static bool wtf_create_control_stream(wtf_connection *conn);
static bool wtf_create_qpack_streams(wtf_connection *conn);
static wtf_result_t wtf_parse_connect_headers(wtf_http3_stream *stream,
                                              const uint8_t *data,
                                              size_t data_len,
                                              wtf_connect_request *request);
static bool wtf_send_connect_response(wtf_http3_stream *stream,
                                      uint16_t status_code);


static QUIC_STREAM_CALLBACK wtf_stream_callback;
static QUIC_STREAM_CALLBACK wtf_upgraded_stream_callback;
static QUIC_CONNECTION_CALLBACK wtf_connection_callback;
static QUIC_LISTENER_CALLBACK wtf_listener_callback;

static bool wtf_qpack_initialize_encoder(wtf_connection *conn);
static void wtf_qpack_send_encoder_data(wtf_connection *conn);

static void wtf_qpack_process_encoder_data(wtf_connection *conn,
                                           const uint8_t *data, size_t length);
static void wtf_qpack_process_decoder_data(wtf_connection *conn,
                                           const uint8_t *data, size_t length);
static struct lsxpack_header *
wtf_header_prepare_decode(void *context, struct lsxpack_header *header,
                          size_t space);
static int wtf_header_process_header(void *context,
                                     struct lsxpack_header *header);
static void wtf_header_unblocked(void *context);

static wtf_stream *wtf_stream_create(wtf_session *session, uint64_t stream_id,
                                     wtf_stream_type_t type);
static void wtf_stream_destroy(wtf_stream *stream);
static wtf_result_t wtf_stream_send_internal(wtf_stream *stream,
                                             const wtf_buffer_t *buffers,
                                             size_t buffer_count, bool fin);
static bool wtf_stream_process_received_data(wtf_stream *stream,
                                             const uint8_t *data, size_t length,
                                             bool fin);
static void wtf_stream_handle_reset(wtf_stream *stream, QUIC_UINT62 error_code);
static uint32_t wtf_map_webtransport_error_to_h3(uint32_t wt_error);
static uint32_t wtf_map_h3_error_to_webtransport(uint64_t h3_error);

static wtf_session *wtf_session_create(wtf_connection *conn,
                                       wtf_http3_stream *connect_stream);
static void wtf_session_destroy(wtf_session *session);
static wtf_result_t
wtf_session_send_datagram_internal(wtf_session *session,
                                   const wtf_buffer_t *data);
static bool wtf_session_process_datagram(wtf_session *session,
                                         const uint8_t *data, size_t length);
static wtf_result_t wtf_session_send_capsule(wtf_session *session,
                                             uint64_t type, const uint8_t *data,
                                             size_t length);
static bool wtf_session_process_capsule(wtf_session *session,
                                        const wtf_capsule *capsule);

static wtf_http3_stream *wtf_http3_stream_create(wtf_connection *conn,
                                                 HQUIC quic_stream,
                                                 uint64_t stream_id);
static void wtf_http3_stream_destroy(wtf_http3_stream *stream);
static bool wtf_process_stream_receive(wtf_http3_stream *stream,
                                       const QUIC_BUFFER *buffer);
static bool wtf_parse_capsule(wtf_http3_stream *stream, const uint8_t *data,
                              size_t length, wtf_capsule *capsule);

static wtf_connection *wtf_connection_create(wtf_server *server,
                                             HQUIC quic_connection);
static void wtf_connection_destroy(wtf_connection *conn);
static bool wtf_connection_associate_stream_with_session(
    wtf_connection *conn, wtf_http3_stream *h3_stream, wtf_session *session);
static wtf_session *wtf_connection_find_session(wtf_connection *conn,
                                                uint64_t session_id);

static void wtf_settings_init(wtf_settings *settings);
static bool wtf_write_settings_frame(wtf_connection *conn, uint8_t *buffer,
                                     size_t buffer_size,
                                     size_t *frame_length);
static bool wtf_parse_settings_frame(wtf_connection *conn, const uint8_t *data,
                                     size_t data_len);
static bool wtf_send_settings_on_control_stream(wtf_connection *conn);

static void wtf_qpack_init(wtf_qpack_context *qpack,
                           uint32_t max_table_capacity,
                           uint32_t max_blocked_streams);
static void wtf_qpack_cleanup(wtf_qpack_context *qpack);

static wtf_result_t wtf_quic_status_to_result(QUIC_STATUS status);

#ifdef WTF_ENABLE_LOGGING

static void wtf_log_internal(wtf_context *ctx, wtf_log_level_t level,
                             const char *component, const char *file, int line,
                             const char *format, ...);

#define WTF_LOG(ctx, level, component, ...)                                    \
  do {                                                                         \
    if ((ctx) && (ctx)->log_callback && (level) >= (ctx)->log_level) {         \
      wtf_log_internal(ctx, level, component, __FILE__, __LINE__,              \
                       __VA_ARGS__);                                           \
    }                                                                          \
  } while (0)

#define WTF_LOG_TRACE(ctx, component, ...)                                     \
  WTF_LOG(ctx, WTF_LOG_TRACE, component, __VA_ARGS__)
#define WTF_LOG_DEBUG(ctx, component, ...)                                     \
  WTF_LOG(ctx, WTF_LOG_DEBUG, component, __VA_ARGS__)
#define WTF_LOG_INFO(ctx, component, ...)                                      \
  WTF_LOG(ctx, WTF_LOG_INFO, component, __VA_ARGS__)
#define WTF_LOG_WARN(ctx, component, ...)                                      \
  WTF_LOG(ctx, WTF_LOG_WARN, component, __VA_ARGS__)
#define WTF_LOG_ERROR(ctx, component, ...)                                     \
  WTF_LOG(ctx, WTF_LOG_ERROR, component, __VA_ARGS__)
#define WTF_LOG_CRITICAL(ctx, component, ...)                                  \
  WTF_LOG(ctx, WTF_LOG_CRITICAL, component, __VA_ARGS__)

#else

#define WTF_LOG(ctx, level, component, ...)                                    \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(level);                                                             \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_TRACE(ctx, component, ...)                                     \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_DEBUG(ctx, component, ...)                                     \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_INFO(ctx, component, ...)                                      \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_WARN(ctx, component, ...)                                      \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_ERROR(ctx, component, ...)                                     \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)
#define WTF_LOG_CRITICAL(ctx, component, ...)                                  \
  do {                                                                         \
    (void)(ctx);                                                               \
    (void)(component);                                                         \
  } while (0)

#endif

#ifdef WTF_ENABLE_LOGGING
static void wtf_log_internal(wtf_context *ctx, wtf_log_level_t level,
                             const char *component, const char *file, int line,
                             const char *format, ...) {
  if (!ctx || !ctx->log_callback) {
    return;
  }

  va_list args;
  va_start(args, format);

  char message[1024];
  vsnprintf(message, sizeof(message), format, args);

  ctx->log_callback(level, component, file, line, message);

  va_end(args);
}
#endif

static bool wtf_path_valid(const char* path) {
    if (path == NULL) {
        return false;
    }
    
#ifdef _WIN32
    return _access(path, 0) == 0;
#else
    return access(path, F_OK) == 0;
#endif
}

static bool wtf_parse_thumbprint(const char *hex_thumbprint, uint8_t sha_hash[20]) {
    if (!hex_thumbprint || !sha_hash) {
        return false;
    }
    
    size_t hex_len = strlen(hex_thumbprint);
    
    // Remove common separators and validate length
    size_t clean_len = 0;
    char clean_hex[41]; // 40 chars + null terminator
    
    for (size_t i = 0; i < hex_len && clean_len < 40; i++) {
        char c = hex_thumbprint[i];
        if (c == ':' || c == '-' || c == ' ') {
            continue; // Skip separators
        }
        if (!isxdigit(c)) {
            return false; // Invalid hex character
        }
        clean_hex[clean_len++] = tolower(c);
    }
    
    if (clean_len != 40) {
        return false; // SHA1 hash must be exactly 40 hex characters
    }
    
    clean_hex[40] = '\0';
    
    // Convert hex string to binary
    for (int i = 0; i < 20; i++) {
        char byte_str[3] = {clean_hex[i * 2], clean_hex[i * 2 + 1], '\0'};
        char *endptr;
        unsigned long byte_val = strtoul(byte_str, &endptr, 16);
        
        if (*endptr != '\0' || byte_val > 255) {
            return false;
        }
        
        sha_hash[i] = (uint8_t)byte_val;
    }
    
    return true;
}


static wtf_result_t wtf_quic_status_to_result(QUIC_STATUS status) {
  if (status == QUIC_STATUS_CONNECTION_REFUSED ||
      status == QUIC_STATUS_ABORTED) {
    return WTF_ERROR_CONNECTION_ABORTED;
  }
  if (status == QUIC_STATUS_TLS_ERROR) {
    return WTF_ERROR_TLS_HANDSHAKE_FAILED;
  }
  
  switch (status) {
  case QUIC_STATUS_SUCCESS:
    return WTF_SUCCESS;
  case QUIC_STATUS_INVALID_PARAMETER:
    return WTF_ERROR_INVALID_PARAMETER;
  case QUIC_STATUS_OUT_OF_MEMORY:
    return WTF_ERROR_OUT_OF_MEMORY;
  case QUIC_STATUS_CONNECTION_TIMEOUT:
    return WTF_ERROR_CONNECTION_ABORTED;
  case QUIC_STATUS_PROTOCOL_ERROR:
    return WTF_ERROR_PROTOCOL_VIOLATION;
  default:
    return WTF_ERROR_INTERNAL;
  }
}

static uint32_t wtf_map_webtransport_error_to_h3(uint32_t wt_error) {

  uint64_t base = WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE;
  uint64_t mapped = base + wt_error + (wt_error / 0x1e);

  if (mapped > WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX) {
    mapped = WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX;
  }

  return (uint32_t)mapped;
}

static uint32_t wtf_map_h3_error_to_webtransport(uint64_t h3_error) {
  if (h3_error < WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE ||
      h3_error > WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX) {
    return 0;
  }

  if ((h3_error - 0x21) % 0x1f == 0) {
    return 0;
  }

  uint64_t shifted = h3_error - WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE;
  return (uint32_t)(shifted - (shifted / 0x1f));
}

static char *wtf_strdup(const char *s) {
  if (s == NULL) {
    #ifdef EINVAL
      errno = EINVAL;
    #endif
    return NULL;
  }
  
  #if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
    return strdup(s);
  #elif defined(_WIN32)
    return _strdup(s);
  #endif
  
  size_t siz = strlen(s) + 1;
  char *y = malloc(siz);
  if (y != NULL) {
    memcpy(y, s, siz);
  } else {
    #ifdef ENOMEM
      errno = ENOMEM;
    #endif
  }
  return y;
}

static size_t wtf_strncpy(char *dest, const char *src, size_t dest_size) {
    if (!dest || dest_size == 0) {
        #ifdef EINVAL
            errno = EINVAL;
        #endif
        return 0;
    }
    
    if (!src) {
        dest[0] = '\0';
        return 0;
    }
    
#ifdef _WIN32
    errno_t err = strcpy_s(dest, dest_size, src);
    if (err != 0) {
        dest[0] = '\0';
        return 0;
    }
    return strlen(dest);
#else
    size_t result = strlcpy(dest, src, dest_size);
    if (result >= dest_size) {
        return dest_size - 1;
    }
    return result;
#endif
}

static char *wtf_strndup(const char *s, size_t n) {
  if (s == NULL) {
    #ifdef EINVAL
      errno = EINVAL;
    #endif
    return NULL;
  }
  
  #if defined(_POSIX_C_SOURCE) && _POSIX_C_SOURCE >= 200809L
    return strndup(s, n);
  #endif
  
  size_t len = 0;
  while (len < n && s[len] != '\0') {
    len++;
  }
  
  char *y = malloc(len + 1);
  if (y != NULL) {
    memcpy(y, s, len);
    y[len] = '\0';
  } else {
    #ifdef ENOMEM
      errno = ENOMEM;
    #endif
  }
  return y;
}


static wtf_datagram *wtf_datagram_create(const uint8_t *data, size_t length,
                                         uint64_t session_id,
                                         void *send_context) {
  wtf_datagram *dgram = malloc(sizeof(wtf_datagram));
  if (!dgram) {
    return NULL;
  }

  dgram->data = malloc(length);
  if (!dgram->data) {
    free(dgram);
    return NULL;
  }

  memcpy(dgram->data, data, length);
  dgram->length = length;
  dgram->session_id = session_id;
  dgram->send_context = send_context;
  dgram->next = NULL;

  return dgram;
}

static void wtf_datagram_destroy(wtf_datagram *dgram) {
  if (dgram) {
    if (dgram->data) {
      free(dgram->data);
    }
    free(dgram);
  }
}

static bool wtf_varint_decode(size_t data_len, const uint8_t *data,
                              size_t *offset, uint64_t *value) {
  if (!data || !offset || !value || *offset >= data_len) {
    return false;
  }

  uint16_t temp_offset = (uint16_t)*offset;
  QUIC_VAR_INT temp_value;

  if (!QuicVarIntDecode((uint16_t)data_len, data, &temp_offset, &temp_value)) {
    return false;
  }

  *offset = temp_offset;
  *value = temp_value;
  return true;
}

static size_t wtf_varint_size(uint64_t value) { return QuicVarIntSize(value); }

static bool wtf_varint_encode(uint64_t value, uint8_t *buffer,
                              size_t buffer_size, size_t *bytes_written) {
  if (!buffer || !bytes_written) {
    return false;
  }

  size_t required = wtf_varint_size(value);
  if (buffer_size < required) {
    return false;
  }

  uint8_t *end = QuicVarIntEncode(value, buffer);
  *bytes_written = end - buffer;

  return true;
}

static bool wtf_validate_stream_id(uint64_t stream_id,
                                   bool is_client_initiated) {
  bool client_initiated = WTF_STREAM_IS_CLIENT_INITIATED(stream_id);
  return client_initiated == is_client_initiated;
}

static const struct lsqpack_dec_hset_if wtf_qpack_decoder_interface = {
    .dhi_unblocked = wtf_header_unblocked,
    .dhi_prepare_decode = wtf_header_prepare_decode,
    .dhi_process_header = wtf_header_process_header,
};

static void wtf_header_unblocked(void *context) { (void)context; }

static void wtf_qpack_init(wtf_qpack_context *qpack,
                           uint32_t max_table_capacity,
                           uint32_t max_blocked_streams) {
  if (!qpack)
    return;

  memset(qpack, 0, sizeof(*qpack));
  qpack->max_table_capacity = max_table_capacity;
  qpack->max_blocked_streams = max_blocked_streams;
  qpack->peer_max_table_capacity = 0;
  qpack->peer_blocked_streams = 0;
  qpack->initialized = false;
  qpack->tsu_buf_sz = sizeof(qpack->tsu_buf);

  if (mtx_init(&qpack->mutex, mtx_plain) != thrd_success) {
    return;
  }

  lsqpack_enc_preinit(&qpack->encoder, NULL);
  lsqpack_dec_init(&qpack->decoder, NULL, 0, 0, &wtf_qpack_decoder_interface,
                   0);
}

static bool wtf_qpack_initialize_encoder(wtf_connection *conn) {
  if (!conn)
    return false;

  wtf_qpack_context *qpack = &conn->qpack;

  mtx_lock(&qpack->mutex);

  if (qpack->initialized) {
    mtx_unlock(&qpack->mutex);
    return true;
  }

  uint32_t table_capacity =
      min(qpack->max_table_capacity, qpack->peer_max_table_capacity);
  uint32_t blocked_streams =
      (uint32_t)min(qpack->max_blocked_streams, qpack->peer_blocked_streams);

  if (table_capacity == 0) {
    table_capacity = WTF_QPACK_DYNAMIC_TABLE_SIZE;
  }
  if (blocked_streams == 0) {
    blocked_streams = WTF_QPACK_MAX_BLOCKED_STREAMS;
  }

  WTF_LOG_DEBUG(
      conn->server->context, "qpack",
      "Initializing QPACK encoder with table_capacity=%u, blocked_streams=%u",
      table_capacity, blocked_streams);

  qpack->tsu_buf_sz = sizeof(qpack->tsu_buf);
  int result = lsqpack_enc_init(
      &qpack->encoder, NULL, table_capacity, table_capacity, blocked_streams,
      LSQPACK_ENC_OPT_STAGE_2, qpack->tsu_buf, &qpack->tsu_buf_sz);

  if (result != 0) {
    WTF_LOG_ERROR(conn->server->context, "qpack",
                  "Failed to initialize QPACK encoder: %d", result);
    mtx_unlock(&qpack->mutex);
    return false;
  }

  lsqpack_dec_cleanup(&qpack->decoder);
  lsqpack_dec_init(&qpack->decoder, NULL, table_capacity, blocked_streams,
                   &wtf_qpack_decoder_interface, (enum lsqpack_dec_opts)0);

  qpack->initialized = true;

  mtx_unlock(&qpack->mutex);
  return true;
}

static void wtf_qpack_send_encoder_data(wtf_connection *conn) {
  if (!conn || !conn->qpack_encoder_stream)
    return;

  wtf_qpack_context *qpack = &conn->qpack;

  mtx_lock(&qpack->mutex);

  if (!qpack->initialized || qpack->tsu_buf_sz == 0) {
    mtx_unlock(&qpack->mutex);
    return;
  }

  size_t total_size = sizeof(QUIC_BUFFER) + qpack->tsu_buf_sz;
  void *send_buffer_raw = malloc(total_size);
  if (!send_buffer_raw) {
    WTF_LOG_ERROR(conn->server->context, "qpack",
                  "Failed to allocate encoder send buffer");
    mtx_unlock(&qpack->mutex);
    return;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
  uint8_t *data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

  memcpy(data, qpack->tsu_buf, qpack->tsu_buf_sz);
  send_buffer->Buffer = data;
  send_buffer->Length = (uint32_t)qpack->tsu_buf_sz;

  qpack->tsu_buf_sz = 0;

  mtx_unlock(&qpack->mutex);

  QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
      conn->qpack_encoder_stream->quic_stream, send_buffer, 1,
      QUIC_SEND_FLAG_NONE, send_buffer_raw);
  size_t bytes_to_send = send_buffer->Length;

  if (QUIC_SUCCEEDED(status)) {
    WTF_LOG_TRACE(conn->server->context, "qpack",
                  "Sent %zu bytes of encoder data", bytes_to_send);
  } else {
    WTF_LOG_ERROR(conn->server->context, "qpack",
                  "Failed to send encoder data: 0x%x", status);
    free(send_buffer_raw);
  }
}

static void wtf_qpack_process_encoder_data(wtf_connection *conn,
                                           const uint8_t *data, size_t length) {
  if (!conn || !data || length == 0)
    return;

  mtx_lock(&conn->qpack.mutex);

  if (!conn->qpack.initialized) {
    mtx_unlock(&conn->qpack.mutex);
    return;
  }

  WTF_LOG_DEBUG(conn->server->context, "qpack",
                "Processing %zu bytes of encoder data", length);

  int result = lsqpack_dec_enc_in(&conn->qpack.decoder, data, length);

  mtx_unlock(&conn->qpack.mutex);

  if (result != 0) {
    WTF_LOG_ERROR(conn->server->context, "qpack",
                  "Failed to process encoder data: %d", result);
  }
}

static void wtf_qpack_process_decoder_data(wtf_connection *conn,
                                           const uint8_t *data, size_t length) {
  if (!conn || !data || length == 0)
    return;

  mtx_lock(&conn->qpack.mutex);

  if (!conn->qpack.initialized) {
    mtx_unlock(&conn->qpack.mutex);
    return;
  }

  WTF_LOG_DEBUG(conn->server->context, "qpack",
                "Processing %zu bytes of decoder data", length);

  int result = lsqpack_enc_decoder_in(&conn->qpack.encoder, data, length);

  mtx_unlock(&conn->qpack.mutex);

  if (result != 0) {
    WTF_LOG_ERROR(conn->server->context, "qpack",
                  "Failed to process decoder data: %d", result);
  }
}

static struct lsxpack_header *
wtf_header_prepare_decode(void *context, struct lsxpack_header *header,
                          size_t space) {
  wtf_header_decode_context *ctx = (wtf_header_decode_context *)context;

  if (!ctx)
    return NULL;

  if (space > sizeof(ctx->decode_buffer)) {
    if (ctx->connection && ctx->connection->server &&
        ctx->connection->server->context) {
      WTF_LOG_ERROR(ctx->connection->server->context, "qpack",
                    "Header too large: %zu bytes", space);
    }
    return NULL;
  }

  if (header) {
    header->buf = ctx->decode_buffer;
    header->val_len = (lsxpack_strlen_t)space;
  } else {
    header = &ctx->current_header;
    lsxpack_header_prepare_decode(header, ctx->decode_buffer, 0, space);
  }

  return header;
}

static int wtf_header_process_header(void *context,
                                     struct lsxpack_header *header) {
  wtf_header_decode_context *ctx = (wtf_header_decode_context *)context;

  if (!ctx || !header || !header->buf) {
    return -1;
  }

  wtf_connect_request *request = ctx->request;
  if (!request) {
    return -1;
  }

  const char *name = (header->name_len > 0)
                         ? (const char *)(header->buf + header->name_offset)
                         : NULL;
  const char *value = (header->val_len > 0)
                          ? (const char *)(header->buf + header->val_offset)
                          : "";
  size_t name_len = header->name_len;
  size_t value_len = header->val_len;

  if (!name || name_len == 0) {
    if (ctx->connection && ctx->connection->server &&
        ctx->connection->server->context) {
      WTF_LOG_ERROR(ctx->connection->server->context, "qpack",
                    "Header missing name");
    }
    return -1;
  }

  if (name_len > 256 || value_len > 4096) {
    if (ctx->connection && ctx->connection->server &&
        ctx->connection->server->context) {
      WTF_LOG_ERROR(ctx->connection->server->context, "qpack",
                    "Header too large: name=%zu, value=%zu", name_len,
                    value_len);
    }
    return -1;
  }

  if (ctx->connection && ctx->connection->server &&
      ctx->connection->server->context) {
    WTF_LOG_TRACE(ctx->connection->server->context, "qpack",
                  "Processing header: %.*s = %.*s", (int)name_len, name,
                  (int)value_len, value);
  }

  if (name[0] == ':') {

    if (name_len == 7 && strncmp(name, ":method", 7) == 0) {
      if (request->method)
        free(request->method);
      request->method = wtf_strndup(value, value_len);
    } else if (name_len == 7 && strncmp(name, ":scheme", 7) == 0) {
      if (request->scheme)
        free(request->scheme);
      request->scheme = wtf_strndup(value, value_len);
    } else if (name_len == 10 && strncmp(name, ":authority", 10) == 0) {
      if (request->authority)
        free(request->authority);
      request->authority = wtf_strndup(value, value_len);
    } else if (name_len == 5 && strncmp(name, ":path", 5) == 0) {
      if (request->path)
        free(request->path);
      request->path = wtf_strndup(value, value_len);
    } else if (name_len == 9 && strncmp(name, ":protocol", 9) == 0) {
      if (request->protocol)
        free(request->protocol);
      request->protocol = wtf_strndup(value, value_len);
    } else {
      if (ctx->connection && ctx->connection->server &&
          ctx->connection->server->context) {
        WTF_LOG_DEBUG(ctx->connection->server->context, "qpack",
                      "Ignoring unknown pseudo-header: %.*s", (int)name_len,
                      name);
      }
    }
  } else {

    if (name_len == 6 && strncmp(name, "origin", 6) == 0) {
      if (request->origin)
        free(request->origin);
      request->origin = wtf_strndup(value, value_len);
    } else {
      if (ctx->connection && ctx->connection->server &&
          ctx->connection->server->context) {
        WTF_LOG_DEBUG(ctx->connection->server->context, "qpack",
                      "Ignoring regular header: %.*s", (int)name_len, name);
      }
    }
  }

  ctx->header_count++;
  return 0;
}

static void wtf_qpack_cleanup(wtf_qpack_context *qpack) {
  if (!qpack)
    return;

  mtx_lock(&qpack->mutex);

  if (qpack->initialized) {
    lsqpack_enc_cleanup(&qpack->encoder);
    lsqpack_dec_cleanup(&qpack->decoder);
    qpack->initialized = false;
  }

  mtx_unlock(&qpack->mutex);
  mtx_destroy(&qpack->mutex);
}

static void wtf_settings_init(wtf_settings *settings) {
  if (!settings)
    return;

  memset(settings, 0, sizeof(*settings));
  settings->max_field_section_size = 65536;
  settings->qpack_max_table_capacity = WTF_QPACK_DYNAMIC_TABLE_SIZE;
  settings->qpack_blocked_streams = WTF_QPACK_MAX_BLOCKED_STREAMS;
  settings->webtransport_max_sessions = WTF_DEFAULT_MAX_SESSIONS;
  settings->h3_datagram_enabled = true;
  settings->enable_connect_protocol = true;
  settings->enable_webtransport = true;
  settings->settings_sent = false;
  settings->settings_received = false;
}

static bool wtf_write_settings_frame(wtf_connection *conn, uint8_t *buffer,
                                     size_t buffer_size,
                                     size_t *frame_length) {
  if (!conn || !buffer || !frame_length)
    return false;

  size_t offset = 0;
  size_t bytes_written;

  if (!wtf_varint_encode(WTF_FRAME_SETTINGS, buffer + offset,
                         buffer_size - offset, &bytes_written)) {
    return false;
  }
  offset += bytes_written;

  size_t settings_size = 0;
  settings_size +=
      wtf_varint_size(WTF_SETTING_QPACK_MAX_TABLE_CAPACITY) +
      wtf_varint_size(conn->local_settings.qpack_max_table_capacity);
  settings_size += wtf_varint_size(WTF_SETTING_QPACK_BLOCKED_STREAMS) +
                   wtf_varint_size(conn->local_settings.qpack_blocked_streams);
  settings_size +=
      wtf_varint_size(WTF_SETTING_ENABLE_CONNECT_PROTOCOL) + wtf_varint_size(1);
  settings_size +=
      wtf_varint_size(WTF_SETTING_ENABLE_WEBTRANSPORT) + wtf_varint_size(1);
  settings_size +=
      wtf_varint_size(WTF_SETTING_H3_DATAGRAM) + wtf_varint_size(1);
  settings_size +=
      wtf_varint_size(WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS) +
      wtf_varint_size(conn->local_settings.webtransport_max_sessions);
  settings_size += wtf_varint_size(WTF_SETTING_MAX_FIELD_SECTION_SIZE) +
                   wtf_varint_size(conn->local_settings.max_field_section_size);

  if (!wtf_varint_encode(settings_size, buffer + offset, buffer_size - offset,
                         &bytes_written)) {
    return false;
  }
  offset += bytes_written;

  struct {
    uint64_t id;
    uint64_t value;
  } settings_list[] = {{WTF_SETTING_QPACK_MAX_TABLE_CAPACITY,
                        conn->local_settings.qpack_max_table_capacity},
                       {WTF_SETTING_QPACK_BLOCKED_STREAMS,
                        conn->local_settings.qpack_blocked_streams},
                       {WTF_SETTING_ENABLE_CONNECT_PROTOCOL, 1},
                       {WTF_SETTING_ENABLE_WEBTRANSPORT, 1},
                       {WTF_SETTING_H3_DATAGRAM, 1},
                       {WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS,
                        conn->local_settings.webtransport_max_sessions},
                       {WTF_SETTING_MAX_FIELD_SECTION_SIZE,
                        conn->local_settings.max_field_section_size}};

  for (size_t i = 0; i < ARRAYSIZE(settings_list); i++) {
    if (!wtf_varint_encode(settings_list[i].id, buffer + offset,
                           buffer_size - offset, &bytes_written)) {
      return false;
    }
    offset += bytes_written;

    if (!wtf_varint_encode(settings_list[i].value, buffer + offset,
                           buffer_size - offset, &bytes_written)) {
      return false;
    }
    offset += bytes_written;
  }

  *frame_length = offset;
  return true;
}

static bool wtf_send_settings_on_control_stream(wtf_connection *conn) {
  if (!conn || !conn->control_stream || !conn->control_stream->quic_stream) {
    return false;
  }

  size_t buffer_size = 512;

  void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + buffer_size);
  if (!send_buffer_raw) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "Failed to allocate settings buffer");
    return false;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
  uint8_t *data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
  size_t settings_length;

  if (!wtf_write_settings_frame(conn, data, buffer_size, &settings_length)) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "Failed to write settings frame");
    free(send_buffer_raw);
    return false;
  }


  send_buffer->Buffer = data;
  send_buffer->Length = (uint32_t) settings_length;

  QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
      conn->control_stream->quic_stream, send_buffer, 1, QUIC_SEND_FLAG_NONE,
      send_buffer_raw);

  if (QUIC_SUCCEEDED(status)) {
    conn->local_settings.settings_sent = true;
    WTF_LOG_INFO(conn->server->context, "settings",
                 "Server settings sent after receiving client settings "
                 "(version negotiation)");
    return true;
  } else {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "Failed to send settings frame: 0x%x", status);
    free(send_buffer_raw);
    return false;
  }
}

static bool wtf_parse_settings_frame(wtf_connection *conn, const uint8_t *data,
                                     size_t data_len) {
  if (!conn || !data)
    return false;

  size_t offset = 0;

  WTF_LOG_DEBUG(conn->server->context, "http3",
                "Parsing settings frame: %zu bytes", data_len);

  while (offset < data_len) {
    uint64_t setting_id, setting_value;

    if (!wtf_varint_decode(data_len, data, &offset, &setting_id)) {
      WTF_LOG_ERROR(conn->server->context, "http3",
                    "Failed to decode setting ID at offset %zu", offset);
      return false;
    }

    if (!wtf_varint_decode(data_len, data, &offset, &setting_value)) {
      WTF_LOG_ERROR(conn->server->context, "http3",
                    "Failed to decode setting value for ID %llu at offset %zu",
                    (unsigned long long)setting_id, offset);
      return false;
    }

    WTF_LOG_DEBUG(conn->server->context, "http3",
                  "Setting ID: %llu (0x%llx), Value: %llu",
                  (unsigned long long)setting_id,
                  (unsigned long long)setting_id,
                  (unsigned long long)setting_value);

    switch (setting_id) {
    case WTF_SETTING_ENABLE_CONNECT_PROTOCOL:
      conn->peer_settings.enable_connect_protocol = (setting_value != 0);
      WTF_LOG_DEBUG(conn->server->context, "http3",
                    "CONNECT protocol enabled: %s",
                    conn->peer_settings.enable_connect_protocol ? "yes" : "no");
      break;

    case WTF_SETTING_ENABLE_WEBTRANSPORT:
      conn->peer_settings.enable_webtransport = (setting_value != 0);
      WTF_LOG_TRACE(conn->server->context, "http3", "WebTransport enabled: %s",
                    conn->peer_settings.enable_webtransport ? "yes" : "no");
      break;

    case WTF_SETTING_H3_DATAGRAM:
      conn->peer_settings.h3_datagram_enabled = (setting_value != 0);
      WTF_LOG_TRACE(conn->server->context, "http3", "H3 datagrams enabled: %s",
                    conn->peer_settings.h3_datagram_enabled ? "yes" : "no");
      break;

    case WTF_SETTING_QPACK_MAX_TABLE_CAPACITY:
      conn->peer_settings.qpack_max_table_capacity = (uint32_t)setting_value;
      conn->qpack.peer_max_table_capacity = (uint32_t)setting_value;
      WTF_LOG_TRACE(conn->server->context, "http3",
                    "Peer QPACK max table capacity: %u",
                    (uint32_t)setting_value);
      break;

    case WTF_SETTING_MAX_FIELD_SECTION_SIZE:
      conn->peer_settings.max_field_section_size = (uint32_t)setting_value;
      WTF_LOG_TRACE(conn->server->context, "http3",
                    "Max field section size: %u", (uint32_t)setting_value);
      break;

    case WTF_SETTING_QPACK_BLOCKED_STREAMS:
      conn->peer_settings.qpack_blocked_streams = (uint32_t)setting_value;
      conn->qpack.peer_blocked_streams = setting_value;
      WTF_LOG_TRACE(conn->server->context, "http3",
                    "Peer QPACK blocked streams: %u", (uint32_t)setting_value);
      break;

    case WTF_SETTING_WEBTRANSPORT_MAX_SESSIONS:
      conn->peer_settings.webtransport_max_sessions = (uint32_t)setting_value;
      WTF_LOG_TRACE(conn->server->context, "http3",
                    "Peer WebTransport max sessions: %u",
                    (uint32_t)setting_value);
      break;

    default:
      WTF_LOG_DEBUG(conn->server->context, "http3",
                    "Ignoring unknown setting %llu (0x%llx) = %llu",
                    (unsigned long long)setting_id,
                    (unsigned long long)setting_id,
                    (unsigned long long)setting_value);
      break;
    }
  }

  conn->peer_settings.settings_received = true;

  if (!conn->local_settings.settings_sent) {
    WTF_LOG_INFO(conn->server->context, "settings",
                 "Received client settings - now sending server settings "
                 "(version negotiation)");
    if (!wtf_send_settings_on_control_stream(conn)) {
      WTF_LOG_ERROR(
          conn->server->context, "settings",
          "Failed to send server settings after receiving client settings");
      return false;
    }
  }

  if (!conn->peer_settings.enable_connect_protocol) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "CONNECT protocol not enabled by peer");
    return false;
  }

  if (!conn->peer_settings.h3_datagram_enabled) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "H3 datagrams not enabled by peer");
    return false;
  }

  if (!conn->peer_settings.enable_webtransport) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "WebTransport not enabled by peer");
    return false;
  }

  if (!wtf_qpack_initialize_encoder(conn)) {
    WTF_LOG_ERROR(conn->server->context, "settings",
                  "Failed to initialize QPACK encoder");
    return false;
  }

  wtf_qpack_send_encoder_data(conn);

  if (conn->local_settings.settings_sent &&
      conn->peer_settings.settings_received) {
    conn->state = WTF_CONNECTION_STATE_READY;
    WTF_LOG_INFO(conn->server->context, "http3",
                 "Version negotiation completed - WebTransport ready with "
                 "dynamic QPACK");
  }

  return true;
}

static bool wtf_process_headers_frame(wtf_http3_stream *stream,
                                      wtf_connect_request *request) {
  if (!stream || !request) {
    return false;
  }

  wtf_connection *conn = stream->connection;

  WTF_LOG_INFO(conn->server->context, "connect",
               "Processing complete CONNECT request on stream %llu",
               (unsigned long long)stream->id);

  bool success = false;

  if (!conn->local_settings.settings_sent ||
      !conn->peer_settings.settings_received) {
    WTF_LOG_ERROR(conn->server->context, "connect",
                  "HEADERS received before settings exchange complete");
    wtf_send_connect_response(stream, 400);
    goto cleanup;
  }

  if (!request->valid) {
    WTF_LOG_ERROR(conn->server->context, "connect", "Invalid CONNECT request");
    wtf_send_connect_response(stream, 400);
    goto cleanup;
  }

  if (request->method && strcmp(request->method, "CONNECT") == 0 &&
      request->protocol && strcmp(request->protocol, "webtransport") == 0 &&
      request->scheme && strcmp(request->scheme, "https") == 0) {

    WTF_LOG_INFO(conn->server->context, "connect",
                 "Valid WebTransport CONNECT request received");

    bool accept_connection = true;
    if (conn->server->config.connection_validator) {
      wtf_connection_request_t conn_request = {
          .origin = request->origin,
          .path = request->path,
          .authority = request->authority,
          .headers = NULL,
          .header_count = 0,
          .peer_address = &conn->peer_address,
          .address_length = sizeof(conn->peer_address)};

      wtf_connection_decision_t decision =
          conn->server->config.connection_validator(
              &conn_request, conn->server->config.user_context);

      accept_connection = (decision == WTF_CONNECTION_ACCEPT);
    }

    if (accept_connection) {

      wtf_session *session = wtf_session_create(conn, stream);
      if (session) {
        session->id = stream->id;
        session->callback = conn->server->config.session_callback;
        session->user_context = conn->server->config.user_context;

        mtx_lock(&conn->sessions_mutex);
        session_map_itr itr =
            session_map_insert(&conn->sessions, session->id, session);
        if (session_map_is_end(itr)) {
          mtx_unlock(&conn->sessions_mutex);
          WTF_LOG_ERROR(conn->server->context, "connect",
                        "Failed to add session to map");
          wtf_session_destroy(session);
          wtf_send_connect_response(stream, 500);
          goto cleanup;
        }
        mtx_unlock(&conn->sessions_mutex);

        stream->webtransport_session = session;

        if (wtf_send_connect_response(stream, 200)) {
          WTF_LOG_INFO(conn->server->context, "connect",
                       "WebTransport session established");

          conn->server->stats.total_sessions_accepted++;
          success = true;
        } else {
          WTF_LOG_ERROR(conn->server->context, "connect",
                        "Failed to send CONNECT response");
          wtf_send_connect_response(stream, 500);
        }
      } else {
        WTF_LOG_ERROR(conn->server->context, "connect",
                      "Failed to allocate session");
        wtf_send_connect_response(stream, 500);
      }
    } else {
      WTF_LOG_INFO(conn->server->context, "connect",
                   "Connection rejected by validator");
      wtf_send_connect_response(stream, 403);
      conn->server->stats.total_sessions_rejected++;
    }
  } else {
    WTF_LOG_ERROR(conn->server->context, "connect", "Invalid CONNECT request");
    wtf_send_connect_response(stream, 400);
  }

cleanup:

  if (request->method)
    free(request->method);
  if (request->protocol)
    free(request->protocol);
  if (request->scheme)
    free(request->scheme);
  if (request->authority)
    free(request->authority);
  if (request->path)
    free(request->path);
  if (request->origin)
    free(request->origin);

  return success;
}

static bool wtf_process_settings_frame(wtf_http3_stream *stream,
                                       const uint8_t *data, size_t data_len) {
  if (!stream || !data)
    return false;

  if (stream->type != WTF_STREAM_TYPE_CONTROL) {
    WTF_LOG_ERROR(stream->connection->server->context, "http3",
                  "SETTINGS frame received on non-control stream %llu",
                  (unsigned long long)stream->id);
    return false;
  }

  return wtf_parse_settings_frame(stream->connection, data, data_len);
}

static bool wtf_process_goaway_frame(wtf_http3_stream *stream,
                                     const uint8_t *data, size_t data_len) {
  if (!stream || !data)
    return false;

  size_t offset = 0;
  uint64_t stream_id;

  if (!wtf_varint_decode(data_len, data, &offset, &stream_id)) {
    WTF_LOG_ERROR(stream->connection->server->context, "http3",
                  "Failed to decode GOAWAY stream ID");
    return false;
  }

  WTF_LOG_INFO(stream->connection->server->context, "http3",
               "Received GOAWAY for stream ID %llu",
               (unsigned long long)stream_id);

  stream->connection->state = WTF_CONNECTION_STATE_CLOSING;

  wtf_connection *conn = stream->connection;
  mtx_lock(&conn->sessions_mutex);

  for (session_map_itr itr = session_map_first(&conn->sessions);
       !session_map_is_end(itr); itr = session_map_next(itr)) {
    wtf_session *session = itr.data->val;

    if (session->state == WTF_SESSION_CONNECTED) {
      WTF_LOG_INFO(conn->server->context, "session",
                   "Draining session %llu due to GOAWAY",
                   (unsigned long long)session->id);

      wtf_session_send_capsule(session, WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION,
                               NULL, 0);

      session->state = WTF_SESSION_DRAINING;

      if (session->callback) {
        wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                     .session = (wtf_session_t *)session,
                                     .user_context = session->user_context};
        session->callback(&event);
      }
    }
  }

  mtx_unlock(&conn->sessions_mutex);

  return true;
}

static wtf_stream *wtf_stream_create(wtf_session *session, uint64_t stream_id,
                                     wtf_stream_type_t type) {
  if (!session)
    return NULL;

  wtf_stream *stream = malloc(sizeof(wtf_stream));
  if (!stream) {
    return NULL;
  }

  memset(stream, 0, sizeof(*stream));
  stream->stream_id = stream_id;
  stream->session = session;
  stream->type = type;
  stream->state = WTF_INTERNAL_STREAM_STATE_IDLE;
  stream->priority = 0;
  stream->receive_enabled = true;

  if (mtx_init(&stream->mutex, mtx_plain) != thrd_success) {
    free(stream);
    return NULL;
  }

  return stream;
}

static void wtf_stream_destroy(wtf_stream *stream) {
  if (!stream)
    return;

  mtx_destroy(&stream->mutex);
  free(stream);
}

static wtf_result_t wtf_stream_send_internal(wtf_stream *stream,
                                             const wtf_buffer_t *buffers,
                                             size_t buffer_count, bool fin) {
  if (!stream || !buffers || buffer_count == 0) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  mtx_lock(&stream->mutex);

  if (stream->state == WTF_INTERNAL_STREAM_STATE_CLOSED ||
      stream->state == WTF_INTERNAL_STREAM_STATE_RESET) {
    mtx_unlock(&stream->mutex);
    return WTF_ERROR_INVALID_STATE;
  }

  uint32_t total_length = 0;
  for (size_t i = 0; i < buffer_count; i++) {
    total_length += (uint32_t)buffers[i].length;
  }

  if (total_length > WTF_MAX_STREAM_BUFFER_SIZE) {
    mtx_unlock(&stream->mutex);
    return WTF_ERROR_BUFFER_TOO_SMALL;
  }

  mtx_unlock(&stream->mutex);

  wtf_connection *conn = stream->session->connection;
  if (!conn) {
    WTF_LOG_ERROR(stream->session->connection->server->context, "stream",
                  "No connection found for WebTransport stream %llu",
                  (unsigned long long)stream->stream_id);
    return WTF_ERROR_INVALID_STATE;
  }

  HQUIC quic_stream = stream->quic_stream;
  if (!quic_stream) {
    WTF_LOG_ERROR(conn->server->context, "stream",
                  "No QUIC stream found for WebTransport stream %llu",
                  (unsigned long long)stream->stream_id);
    return WTF_ERROR_INVALID_STATE;
  }

  void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + total_length);
  if (!send_buffer_raw) {
    return WTF_ERROR_OUT_OF_MEMORY;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
  uint8_t *data_buffer = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

  uint32_t data_offset = 0;
  for (size_t i = 0; i < buffer_count; i++) {
    if (buffers[i].data && buffers[i].length > 0) {
      memcpy(data_buffer + data_offset, buffers[i].data, buffers[i].length);
      data_offset += (uint32_t)buffers[i].length;
    }
  }

  send_buffer->Buffer = data_buffer;
  send_buffer->Length = total_length;

  QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
      quic_stream, send_buffer, 1,
      fin ? QUIC_SEND_FLAG_FIN : QUIC_SEND_FLAG_NONE, send_buffer_raw);

  if (QUIC_SUCCEEDED(status)) {
    mtx_lock(&stream->mutex);
    stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
    stream->bytes_sent += total_length;

    if (fin) {
      stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;
    }
    mtx_unlock(&stream->mutex);

    return WTF_SUCCESS;
  } else {
    free(send_buffer_raw);
    return wtf_quic_status_to_result(status);
  }
}

static bool wtf_stream_process_received_data(wtf_stream *stream,
                                             const uint8_t *data, size_t length,
                                             bool fin) {
  if (!stream || !data || length == 0)
    return false;

  mtx_lock(&stream->mutex);

  if (!stream->receive_enabled ||
      stream->state == WTF_INTERNAL_STREAM_STATE_CLOSED ||
      stream->state == WTF_INTERNAL_STREAM_STATE_RESET) {
    mtx_unlock(&stream->mutex);
    return false;
  }

  stream->bytes_received += length;

  if (fin) {
    if (stream->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
      stream->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
    } else {
      stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
    }
  }

  mtx_unlock(&stream->mutex);

  if (stream->callback) {
    wtf_buffer_t receive_buffers[] = {{data, length}};

    wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_DATA_RECEIVED,
                                .stream = (wtf_stream_t *)stream,
                                .user_context = stream->user_context,
                                .data_received = {.buffers = receive_buffers,
                                                  .buffer_count = 1,
                                                  .fin = fin}};

    stream->callback(&event);
  }

  return true;
}

static void wtf_stream_handle_reset(wtf_stream *stream, QUIC_UINT62 error_code) {
  if (!stream)
    return;

  mtx_lock(&stream->mutex);
  stream->state = WTF_INTERNAL_STREAM_STATE_RESET;
  mtx_unlock(&stream->mutex);

  if (stream->callback) {
    wtf_stream_event_t event = {
        .type = WTF_STREAM_EVENT_ABORTED,
        .stream = (wtf_stream_t *)stream,
        .user_context = stream->user_context,
        .aborted = {.error_code =
                        wtf_map_h3_error_to_webtransport(error_code)}};

    stream->callback(&event);
  }
}

static bool wtf_process_h3_datagram(wtf_connection *conn, const uint8_t *data,
                                    size_t data_len) {
  if (!conn || !data || data_len == 0)
    return false;

  size_t offset = 0;
  uint64_t quarter_stream_id;

  if (!wtf_varint_decode(data_len, data, &offset, &quarter_stream_id)) {
    WTF_LOG_ERROR(conn->server->context, "datagram",
                  "Failed to decode Quarter Stream ID");
    return false;
  }

  uint64_t stream_id = quarter_stream_id * 4;

  if (!wtf_validate_stream_id(stream_id, true)) {
    WTF_LOG_ERROR(conn->server->context, "datagram",
                  "Invalid stream ID %llu from Quarter Stream ID %llu",
                  (unsigned long long)stream_id,
                  (unsigned long long)quarter_stream_id);
    return false;
  }

  wtf_session *session = wtf_connection_find_session(conn, stream_id);
  if (!session) {

    mtx_lock(&conn->buffered_mutex);

    if (conn->buffered_datagram_count >= WTF_MAX_BUFFERED_DATAGRAMS) {
      mtx_unlock(&conn->buffered_mutex);
      WTF_LOG_WARN(conn->server->context, "datagram",
                   "Dropping datagram - buffer full");
      return false;
    }

    wtf_datagram *dgram =
        wtf_datagram_create(data + offset, data_len - offset, stream_id, NULL);
    if (dgram) {
      if (conn->buffered_datagrams) {

        wtf_datagram *tail = conn->buffered_datagrams;
        while (tail->next)
          tail = tail->next;
        tail->next = dgram;
      } else {
        conn->buffered_datagrams = dgram;
      }
      conn->buffered_datagram_count++;
    }

    mtx_unlock(&conn->buffered_mutex);

    WTF_LOG_TRACE(conn->server->context, "datagram",
                  "Buffered datagram for session %llu",
                  (unsigned long long)stream_id);
    return true;
  }

  const uint8_t *payload = data + offset;
  size_t payload_len = data_len - offset;

  return wtf_session_process_datagram(session, payload, payload_len);
}

static wtf_result_t
wtf_session_send_datagram_internal(wtf_session *session,
                                   const wtf_buffer_t *data) {
  if (!session || !data || data->length == 0) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  if (session->state != WTF_SESSION_CONNECTED) {
    return WTF_ERROR_INVALID_STATE;
  }

  wtf_connection *conn = session->connection;

  if (!conn->peer_settings.h3_datagram_enabled) {
    return WTF_ERROR_PROTOCOL_VIOLATION;
  }

  uint64_t quarter_stream_id = session->id / 4;

  size_t header_size = wtf_varint_size(quarter_stream_id);
  size_t total_size = header_size + data->length;

  if (total_size > conn->max_datagram_size) {
    return WTF_ERROR_BUFFER_TOO_SMALL;
  }

  void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + total_size);
  if (!send_buffer_raw) {
    return WTF_ERROR_OUT_OF_MEMORY;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
  uint8_t *datagram_data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

  size_t bytes_written;
  if (!wtf_varint_encode(quarter_stream_id, datagram_data, header_size,
                         &bytes_written)) {
    free(send_buffer_raw);
    return WTF_ERROR_INTERNAL;
  }

  memcpy(datagram_data + bytes_written, data->data, data->length);

  send_buffer->Buffer = datagram_data;
  send_buffer->Length = (uint32_t)total_size;

  QUIC_STATUS status = conn->server->context->quic_api->DatagramSend(
      conn->quic_connection, send_buffer, 1, QUIC_SEND_FLAG_NONE,
      send_buffer_raw);

  if (QUIC_SUCCEEDED(status)) {
    return WTF_SUCCESS;
  } else {
    free(send_buffer_raw);
    return wtf_quic_status_to_result(status);
  }
}

static bool wtf_session_process_datagram(wtf_session *session,
                                         const uint8_t *data, size_t length) {
  if (!session || !data || length == 0)
    return false;

  if (session->callback) {
    wtf_buffer_t buffer = {data, length};
    wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DATAGRAM_RECEIVED,
                                 .session = (wtf_session_t *)session,
                                 .user_context = session->user_context,
                                 .datagram_received = {buffer}};

    session->callback(&event);
  }

  return true;
}

static wtf_session *wtf_session_create(wtf_connection *conn,
                                       wtf_http3_stream *connect_stream) {
  if (!conn || !connect_stream)
    return NULL;

  wtf_session *session = malloc(sizeof(wtf_session));
  if (!session) {
    return NULL;
  }

  memset(session, 0, sizeof(*session));
  session->connection = conn;
  session->connect_stream = connect_stream;
  session->state = WTF_SESSION_HANDSHAKING;
  session->id = connect_stream->id;
  session->max_streams = conn->server->config.max_streams_per_session;
  if (session->max_streams == 0) {
    session->max_streams = 1000;
  }

  stream_map_init(&session->streams);

  if (mtx_init(&session->streams_mutex, mtx_plain) != thrd_success) {
    stream_map_cleanup(&session->streams);
    free(session);
    return NULL;
  }

  return session;
}

static void wtf_session_destroy(wtf_session *session) {
  if (!session)
    return;

  mtx_lock(&session->streams_mutex);
  for (stream_map_itr itr = stream_map_first(&session->streams);
       !stream_map_is_end(itr); itr = stream_map_next(itr)) {
    wtf_stream_destroy(itr.data->val);
  }
  stream_map_cleanup(&session->streams);
  mtx_unlock(&session->streams_mutex);

  if (session->close_reason) {
    free(session->close_reason);
  }

  mtx_destroy(&session->streams_mutex);

  free(session);
}

static wtf_result_t wtf_session_send_capsule(wtf_session *session,
                                             uint64_t type, const uint8_t *data,
                                             size_t length) {
  if (!session || !session->connect_stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  size_t type_size = wtf_varint_size(type);
  size_t length_size = wtf_varint_size(length);
  size_t total_size = type_size + length_size + length;

  void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + total_size);
  if (!send_buffer_raw) {
    return WTF_ERROR_OUT_OF_MEMORY;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
  uint8_t *capsule_data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

  size_t offset = 0;
  size_t bytes_written;

  if (!wtf_varint_encode(type, capsule_data + offset, total_size - offset,
                         &bytes_written)) {
    free(send_buffer_raw);
    return WTF_ERROR_INTERNAL;
  }
  offset += bytes_written;

  if (!wtf_varint_encode(length, capsule_data + offset, total_size - offset,
                         &bytes_written)) {
    free(send_buffer_raw);
    return WTF_ERROR_INTERNAL;
  }
  offset += bytes_written;

  if (data && length > 0) {
    memcpy(capsule_data + offset, data, length);
  }

  send_buffer->Buffer = capsule_data;
  send_buffer->Length = (uint32_t)total_size;

  QUIC_STATUS status =
      session->connection->server->context->quic_api->StreamSend(
          session->connect_stream->quic_stream, send_buffer, 1,
          QUIC_SEND_FLAG_NONE, send_buffer_raw);

  if (QUIC_FAILED(status)) {
    free(send_buffer_raw);
    return wtf_quic_status_to_result(status);
  }

  return WTF_SUCCESS;
}

static bool wtf_session_process_capsule(wtf_session *session,
                                        const wtf_capsule *capsule) {
  if (!session || !capsule)
    return false;

  WTF_LOG_TRACE(session->connection->server->context, "capsule",
                "Processing capsule type %llu, length %llu for session %llu",
                (unsigned long long)capsule->type,
                (unsigned long long)capsule->length,
                (unsigned long long)session->id);

  switch (capsule->type) {
  case WTF_CAPSULE_DATAGRAM: {

    return true;
  }

  case WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION: {

    WTF_LOG_INFO(session->connection->server->context, "session",
                 "Session %llu received DRAIN capsule",
                 (unsigned long long)session->id);

    if (session->state == WTF_SESSION_CONNECTED) {
      session->state = WTF_SESSION_DRAINING;

      if (session->callback) {
        wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                     .session = (wtf_session_t *)session,
                                     .user_context = session->user_context};
        session->callback(&event);
      }
    } else {
      WTF_LOG_TRACE(session->connection->server->context, "session",
                    "Ignoring DRAIN capsule - session %llu is in state %d",
                    (unsigned long long)session->id, session->state);
    }

    return true;
  }

  case WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION: {

    if (capsule->length < 4) {
      WTF_LOG_ERROR(session->connection->server->context, "capsule",
                    "CLOSE capsule too short: %llu bytes",
                    (unsigned long long)capsule->length);
      return false;
    }

    uint32_t error_code = 0;
    if (capsule->data && capsule->length >= 4) {
      error_code = (uint32_t)(((uint32_t)capsule->data[0] << 24) |
                              ((uint32_t)capsule->data[1] << 16) |
                              ((uint32_t)capsule->data[2] << 8) |
                              (uint32_t)capsule->data[3]);
    }

    char *reason = NULL;
    size_t reason_len = (size_t)capsule->length - 4;
    if (reason_len > 0 && capsule->data) {

      if (reason_len > 1024) {
        reason_len = 1024;
      }
      reason = wtf_strndup((const char *)(capsule->data + 4), reason_len);
    }

    WTF_LOG_INFO(session->connection->server->context, "session",
                 "Session %llu received CLOSE capsule: error=%u, reason='%s'",
                 (unsigned long long)session->id, error_code,
                 reason ? reason : "");

    session->close_error_code = error_code;
    if (session->close_reason) {
      free(session->close_reason);
    }
    session->close_reason = reason;
    session->state = WTF_SESSION_CLOSED;

    if (session->callback) {
      wtf_session_event_t event = {
          .type = WTF_SESSION_EVENT_DISCONNECTED,
          .session = (wtf_session_t *)session,
          .user_context = session->user_context,
          .disconnected = {.error_code = error_code, .reason = reason}};
      session->callback(&event);
    }

    return true;
  }

  default:

    WTF_LOG_DEBUG(session->connection->server->context, "capsule",
                  "Ignoring unknown capsule type %llu",
                  (unsigned long long)capsule->type);
    return true;
  }
}

static bool wtf_parse_capsule(wtf_http3_stream *stream, const uint8_t *data,
                              size_t length, wtf_capsule *capsule) {
  if (!stream || !data || !capsule || length == 0)
    return false;

  size_t offset = 0;

  if (!stream->capsule_header_complete) {

    if (!wtf_varint_decode(length, data, &offset, &stream->capsule_type)) {
      return false;
    }

    if (!wtf_varint_decode(length, data, &offset, &stream->capsule_length)) {
      return false;
    }

    stream->capsule_header_complete = true;
    stream->capsule_bytes_read = 0;

    if (stream->capsule_length > 0) {
      if (stream->capsule_length > WTF_MAX_DATAGRAM_SIZE) {
        WTF_LOG_ERROR(stream->connection->server->context, "capsule",
                      "Capsule too large: %llu bytes",
                      (unsigned long long)stream->capsule_length);
        return false;
      }

      if (stream->capsule_buffer) {
        free(stream->capsule_buffer);
      }

      stream->capsule_buffer = malloc((size_t)stream->capsule_length);
      if (!stream->capsule_buffer) {
        return false;
      }
    }
  }

  size_t available_data = length - offset;
  size_t bytes_needed =
      (size_t)stream->capsule_length - stream->capsule_bytes_read;
  size_t bytes_to_copy = min(available_data, bytes_needed);

  if (bytes_to_copy > 0 && stream->capsule_buffer) {
    memcpy(stream->capsule_buffer + stream->capsule_bytes_read, data + offset,
           bytes_to_copy);
    stream->capsule_bytes_read += bytes_to_copy;
  }

  if (stream->capsule_bytes_read >= (size_t)stream->capsule_length) {
    capsule->type = stream->capsule_type;
    capsule->length = stream->capsule_length;
    capsule->data = stream->capsule_buffer;

    stream->capsule_header_complete = false;
    stream->capsule_buffer = NULL;

    return true;
  }

  return false;
}

static bool wtf_stream_belongs_to_session(uint64_t stream_id,
                                          uint64_t session_id,
                                          const uint8_t *stream_data,
                                          size_t data_len) {

  if (WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)) {

    if (data_len < 2)
      return false;

    size_t offset = 0;
    uint64_t stream_type;
    if (!wtf_varint_decode(data_len, stream_data, &offset, &stream_type)) {
      return false;
    }

    if (stream_type != WTF_STREAM_TYPE_WEBTRANSPORT_STREAM) {
      return false;
    }

    uint64_t parsed_session_id;
    if (!wtf_varint_decode(data_len, stream_data, &offset,
                           &parsed_session_id)) {
      return false;
    }

    return parsed_session_id == session_id;
  } else {

    if (data_len < 2)
      return false;

    size_t offset = 0;
    uint64_t frame_type;
    if (!wtf_varint_decode(data_len, stream_data, &offset, &frame_type)) {
      return false;
    }

    if (frame_type != WTF_FRAME_WEBTRANSPORT_STREAM) {
      return false;
    }

    uint64_t parsed_session_id;
    if (!wtf_varint_decode(data_len, stream_data, &offset,
                           &parsed_session_id)) {
      return false;
    }

    return parsed_session_id == session_id;
  }
}

static bool wtf_connection_associate_stream_with_session(
    wtf_connection *conn, wtf_http3_stream *h3_stream, wtf_session *session) {
  if (!conn || !h3_stream || !session)
    return false;

  uint64_t stream_id = h3_stream->id;
  uint64_t session_id = session->id;

  mtx_lock(&session->streams_mutex);
  if (stream_map_size(&session->streams) >= session->max_streams) {
    mtx_unlock(&session->streams_mutex);
    WTF_LOG_WARN(
        conn->server->context, "stream",
        "Session %llu has reached stream limit %u - rejecting stream %llu",
        (unsigned long long)session_id, session->max_streams,
        (unsigned long long)stream_id);

    if (h3_stream->quic_stream) {
      conn->server->context->quic_api->StreamShutdown(
          h3_stream->quic_stream,
          QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
              QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
          WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED);
    }

    return false;
  }

  stream_map_itr existing_itr = stream_map_get(&session->streams, stream_id);
  if (!stream_map_is_end(existing_itr)) {
    mtx_unlock(&session->streams_mutex);
    WTF_LOG_TRACE(conn->server->context, "stream",
                  "Stream %llu already associated with session %llu",
                  (unsigned long long)stream_id,
                  (unsigned long long)session_id);
    return true;
  }
  mtx_unlock(&session->streams_mutex);

  wtf_stream_type_t stream_type = WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)
                                      ? WTF_STREAM_UNIDIRECTIONAL
                                      : WTF_STREAM_BIDIRECTIONAL;

  wtf_stream *wt_stream = wtf_stream_create(session, stream_id, stream_type);
  if (!wt_stream) {
    WTF_LOG_ERROR(conn->server->context, "stream",
                  "Failed to create WebTransport stream for stream %llu",
                  (unsigned long long)stream_id);
    return false;
  }

  if (session->callback) {

    wt_stream->callback = NULL;
    wt_stream->user_context = session->user_context;
  }

  mtx_lock(&session->streams_mutex);
  stream_map_itr itr =
      stream_map_insert(&session->streams, stream_id, wt_stream);
  if (stream_map_is_end(itr)) {
    mtx_unlock(&session->streams_mutex);
    WTF_LOG_ERROR(conn->server->context, "stream",
                  "Failed to add stream to map");
    wtf_stream_destroy(wt_stream);
    return false;
  }
  mtx_unlock(&session->streams_mutex);

  if (h3_stream->quic_stream) {

    wt_stream->quic_stream = h3_stream->quic_stream;

    bool is_connect_stream = (h3_stream->id == session->connect_stream->id);

    if (!is_connect_stream) {

      conn->server->context->quic_api->SetCallbackHandler(
          h3_stream->quic_stream, wtf_upgraded_stream_callback, wt_stream);

      WTF_LOG_DEBUG(conn->server->context, "stream",
                    "Transferred QUIC handle and switched callback for "
                    "WebTransport stream %llu",
                    (unsigned long long)stream_id);
    } else {

      WTF_LOG_DEBUG(conn->server->context, "stream",
                    "Transferred QUIC handle from CONNECT stream %llu "
                    "(preserving wtf_stream_callback)",
                    (unsigned long long)stream_id);
    }
  }

  WTF_LOG_INFO(
      conn->server->context, "stream",
      "Created and associated WebTransport stream %llu (%s) with session %llu",
      (unsigned long long)stream_id,
      stream_type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional"
                                              : "unidirectional",
      (unsigned long long)session_id);

  if (session->callback) {
    wtf_session_event_t event = {
        .type = WTF_SESSION_EVENT_STREAM_OPENED,
        .session = (wtf_session_t *)session,
        .user_context = session->user_context,
        .stream_opened = {.stream = (wtf_stream_t *)wt_stream,
                          .stream_type = stream_type}};
    session->callback(&event);
  }

  return true;
}

static wtf_session *wtf_connection_find_session(wtf_connection *conn,
                                                uint64_t session_id) {
  if (!conn)
    return NULL;

  mtx_lock(&conn->sessions_mutex);

  session_map_itr itr = session_map_get(&conn->sessions, session_id);
  wtf_session *session = NULL;
  if (!session_map_is_end(itr)) {
    session = itr.data->val;
  }

  mtx_unlock(&conn->sessions_mutex);
  return session;
}

static void wtf_connection_process_buffered_data(wtf_connection *conn,
                                                 wtf_session *session) {
  if (!conn || !session)
    return;

  mtx_lock(&conn->buffered_mutex);

  wtf_datagram **dgram_ptr = &conn->buffered_datagrams;
  while (*dgram_ptr) {
    wtf_datagram *dgram = *dgram_ptr;

    if (dgram->session_id == session->id) {

      *dgram_ptr = dgram->next;
      conn->buffered_datagram_count--;

      mtx_unlock(&conn->buffered_mutex);
      wtf_session_process_datagram(session, dgram->data, dgram->length);
      wtf_datagram_destroy(dgram);
      mtx_lock(&conn->buffered_mutex);

      dgram_ptr = &conn->buffered_datagrams;
    } else {
      dgram_ptr = &(*dgram_ptr)->next;
    }
  }

  uint64_t streams_to_process[WTF_MAX_BUFFERED_STREAMS];
  size_t stream_count_to_process = 0;

  for (http3_stream_map_itr itr =
           http3_stream_map_first(&conn->buffered_streams);
       !http3_stream_map_is_end(itr) &&
       stream_count_to_process < WTF_MAX_BUFFERED_STREAMS;
       itr = http3_stream_map_next(itr)) {
    wtf_http3_stream *stream = itr.data->val;
    bool stream_belongs = false;

    if (stream->buffered_headers_length > 0) {
      stream_belongs = wtf_stream_belongs_to_session(
          stream->id, session->id, stream->buffered_headers,
          stream->buffered_headers_length);
    }

    if (stream_belongs) {
      streams_to_process[stream_count_to_process++] = stream->id;
    }
  }

  for (size_t i = 0; i < stream_count_to_process; i++) {
    uint64_t stream_id = streams_to_process[i];
    http3_stream_map_itr buffered_itr =
        http3_stream_map_get(&conn->buffered_streams, stream_id);

    if (!http3_stream_map_is_end(buffered_itr)) {
      wtf_http3_stream *stream = buffered_itr.data->val;

      http3_stream_map_erase(&conn->buffered_streams, stream_id);
      conn->buffered_stream_count--;

      mtx_unlock(&conn->buffered_mutex);

      mtx_lock(&conn->streams_mutex);
      http3_stream_map_itr itr =
          http3_stream_map_insert(&conn->streams, stream->id, stream);
      if (!http3_stream_map_is_end(itr)) {
        stream->webtransport_session = session;
        stream->is_webtransport = true;
      }
      mtx_unlock(&conn->streams_mutex);

      size_t offset = 0;
      uint64_t frame_or_type;
      uint64_t parsed_session_id;

      if (wtf_varint_decode(stream->buffered_headers_length,
                            stream->buffered_headers, &offset,
                            &frame_or_type) &&
          wtf_varint_decode(stream->buffered_headers_length,
                            stream->buffered_headers, &offset,
                            &parsed_session_id)) {

        wtf_connection_associate_stream_with_session(conn, stream, session);
      }

      mtx_lock(&conn->buffered_mutex);
    }
  }

  mtx_unlock(&conn->buffered_mutex);

  WTF_LOG_DEBUG(conn->server->context, "session",
                "Processed buffered data for session %llu",
                (unsigned long long)session->id);
}

static bool wtf_send_connect_response(wtf_http3_stream *stream,
                                      uint16_t status_code) {
  if (!stream || !stream->connection) {
    return false;
  }

  wtf_connection *conn = stream->connection;

  uint32_t max_response_size = 1024;

  void *response_buffer_raw = malloc(sizeof(QUIC_BUFFER) + max_response_size);
  if (!response_buffer_raw) {
    WTF_LOG_ERROR(conn->server->context, "connect",
                  "Failed to allocate response buffer");
    return false;
  }

  QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)response_buffer_raw;
  uint8_t *response_data = (uint8_t *)response_buffer_raw + sizeof(QUIC_BUFFER);

  size_t offset = 0;
  size_t bytes_written;

  if (!wtf_varint_encode(WTF_FRAME_HEADERS, response_data + offset,
                         max_response_size - offset, &bytes_written)) {
    free(response_buffer_raw);
    return false;
  }
  offset += bytes_written;

  uint8_t status_data[64];
  uint32_t status_len = 0;

  if (conn->qpack.initialized) {
    mtx_lock(&conn->qpack.mutex);

    struct lsxpack_header status_header;
    memset(&status_header, 0, sizeof(status_header));

    char status_value[4];
    snprintf(status_value, sizeof(status_value), "%u", status_code);

    status_header.buf = (char *)(status_data + 2);
    status_header.name_offset = 0;
    status_header.name_len = 7;
    status_header.val_offset = 7;
    status_header.val_len = (lsxpack_strlen_t) strlen(status_value);

    memcpy(status_header.buf, ":status", 7);
    memcpy(status_header.buf + 7, status_value, status_header.val_len);

    if (lsqpack_enc_start_header(&conn->qpack.encoder, stream->id, 0) == 0) {
      size_t prefix_len = 2;
      size_t header_len = sizeof(status_data) - 2;

      uint8_t enc_stream_buf[256];
      size_t enc_stream_size = sizeof(enc_stream_buf);

      if (lsqpack_enc_encode(&conn->qpack.encoder, enc_stream_buf,
                             &enc_stream_size, status_data + 2, &header_len,
                             &status_header,
                             (enum lsqpack_enc_flags)0) == LQES_OK) {

        enum lsqpack_enc_header_flags hflags;
        size_t pref_sz = lsqpack_enc_end_header(&conn->qpack.encoder, status_data,
                                             prefix_len, &hflags);
        if (pref_sz >= 0) {
          status_len = (uint32_t)(pref_sz + header_len);

          if (enc_stream_size > 0 && enc_stream_size < sizeof(enc_stream_buf)) {
            if (conn->qpack.tsu_buf_sz + enc_stream_size <=
                sizeof(conn->qpack.tsu_buf)) {
              memcpy(conn->qpack.tsu_buf + conn->qpack.tsu_buf_sz,
                     enc_stream_buf, enc_stream_size);
              conn->qpack.tsu_buf_sz += enc_stream_size;
            }
          }
        }
      }
    }

    mtx_unlock(&conn->qpack.mutex);
  }

  if (status_len == 0) {
    WTF_LOG_ERROR(conn->server->context, "connect",
                  "Failed to encode status code %u", status_code);
    return false;
  }

  if (!wtf_varint_encode(status_len, response_data + offset,
                         max_response_size - offset, &bytes_written)) {
    free(response_buffer_raw);
    return false;
  }
  offset += bytes_written;

  if (offset + status_len > max_response_size) {
    free(response_buffer_raw);
    return false;
  }
  memcpy(response_data + offset, status_data, status_len);
  offset += status_len;

  send_buffer->Buffer = response_data;
  send_buffer->Length = (uint32_t)offset;

  QUIC_STATUS quic_status = conn->server->context->quic_api->StreamSend(
      stream->quic_stream, send_buffer, 1, QUIC_SEND_FLAG_NONE,
      response_buffer_raw);

  if (QUIC_FAILED(quic_status)) {
    WTF_LOG_ERROR(conn->server->context, "connect", "StreamSend failed: 0x%x",
                  quic_status);
    free(response_buffer_raw);
    return false;
  }

  if (status_code == 200) {

    wtf_session *session = stream->webtransport_session;
    if (session) {
      session->state = WTF_SESSION_CONNECTED;
      session->id = stream->id;

      WTF_LOG_INFO(
          conn->server->context, "webtransport",
          "WebTransport session %llu established on CONNECT stream %llu",
          (unsigned long long)session->id, (unsigned long long)stream->id);

      wtf_qpack_send_encoder_data(conn);

      wtf_connection_process_buffered_data(conn, session);

      if (session->callback) {
        wtf_session_event_t event = {.type = WTF_SESSION_EVENT_CONNECTED,
                                     .session = (wtf_session_t *)session,
                                     .user_context = session->user_context};
        session->callback(&event);
      }
    }
  } else {

    wtf_qpack_send_encoder_data(conn);
  }

  return true;
}

static wtf_result_t wtf_parse_connect_headers(wtf_http3_stream *stream,
                                              const uint8_t *data,
                                              size_t data_len,
                                              wtf_connect_request *request) {
  if (!stream || !data || !request || !stream->connection) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_connection *conn = stream->connection;

  WTF_LOG_DEBUG(conn->server->context, "qpack",
                "Parsing CONNECT headers: %zu bytes", data_len);

  memset(request, 0, sizeof(*request));
  request->valid = false;

  wtf_header_decode_context decode_ctx = {0};
  decode_ctx.request = request;
  decode_ctx.connection = conn;
  decode_ctx.headers_complete = false;
  decode_ctx.header_count = 0;

  mtx_lock(&conn->qpack.mutex);

  if (!conn->qpack.initialized) {
    mtx_unlock(&conn->qpack.mutex);
    WTF_LOG_ERROR(conn->server->context, "qpack", "QPACK not initialized");
    return WTF_ERROR_INVALID_STATE;
  }

  struct lsqpack_dec *decoder = &conn->qpack.decoder;

  const uint8_t *header_data = data;
  uint64_t stream_id = stream->id;

  enum lsqpack_read_header_status decode_result =
      lsqpack_dec_header_in(decoder, &decode_ctx, stream_id, data_len,
                            &header_data, data_len, NULL, NULL);

  mtx_unlock(&conn->qpack.mutex);

  wtf_result_t result = WTF_SUCCESS;

  switch (decode_result) {
  case LQRHS_DONE:
    WTF_LOG_DEBUG(
        conn->server->context, "qpack",
        "Headers decoded successfully, %zu headers processed (static encoding)",
        decode_ctx.header_count);

    if (!request->method || strcmp(request->method, "CONNECT") != 0) {
      WTF_LOG_ERROR(conn->server->context, "qpack",
                    "Invalid or missing :method header");
      result = WTF_ERROR_PROTOCOL_VIOLATION;
    } else if (!request->protocol) {
      WTF_LOG_ERROR(conn->server->context, "qpack", "Missing :protocol header");
      result = WTF_ERROR_PROTOCOL_VIOLATION;
    } else if (!request->scheme) {
      WTF_LOG_ERROR(conn->server->context, "qpack", "Missing :scheme header");
      result = WTF_ERROR_PROTOCOL_VIOLATION;
    } else if (!request->authority) {
      WTF_LOG_ERROR(conn->server->context, "qpack",
                    "Missing :authority header");
      result = WTF_ERROR_PROTOCOL_VIOLATION;
    } else {
      request->valid = true;

      WTF_LOG_DEBUG(conn->server->context, "qpack",
                    "Static QPACK encoding used - no decoder output required");
    }
    break;

  case LQRHS_BLOCKED:
    WTF_LOG_DEBUG(conn->server->context, "qpack",
                  "Header block blocked - waiting for encoder stream data");

    result = WTF_ERROR_PROTOCOL_VIOLATION;
    break;

  case LQRHS_NEED:
    WTF_LOG_ERROR(conn->server->context, "qpack", "Incomplete header block");
    result = WTF_ERROR_PROTOCOL_VIOLATION;
    break;

  case LQRHS_ERROR:
  default:
    WTF_LOG_ERROR(conn->server->context, "qpack", "Header decoding error");
    result = WTF_ERROR_PROTOCOL_VIOLATION;
    break;
  }

  if (result != WTF_SUCCESS) {
    if (request->method) {
      free(request->method);
      request->method = NULL;
    }
    if (request->protocol) {
      free(request->protocol);
      request->protocol = NULL;
    }
    if (request->scheme) {
      free(request->scheme);
      request->scheme = NULL;
    }
    if (request->authority) {
      free(request->authority);
      request->authority = NULL;
    }
    if (request->path) {
      free(request->path);
      request->path = NULL;
    }
    if (request->origin) {
      free(request->origin);
      request->origin = NULL;
    }
    request->valid = false;
  }

  return result;
}

static bool wtf_combine_stream_data(wtf_http3_stream *stream,
                                    const uint8_t **data, uint32_t *length,
                                    uint8_t **combined_data,
                                    bool *allocated_buffer) {
  if (stream->buffered_headers_length == 0) {
    *allocated_buffer = false;
    return true;
  }

  uint32_t combined_length = stream->buffered_headers_length + *length;
  *combined_data = malloc(combined_length);
  if (!*combined_data) {
    return false;
  }

  memcpy(*combined_data, stream->buffered_headers,
         stream->buffered_headers_length);
  memcpy(*combined_data + stream->buffered_headers_length, *data, *length);

  stream->buffered_headers_length = 0;
  *data = *combined_data;
  *length = combined_length;
  *allocated_buffer = true;
  return true;
}

static bool wtf_parse_unidirectional_stream_type(wtf_http3_stream *stream,
                                                 const uint8_t *data,
                                                 uint32_t length,
                                                 uint32_t *offset) {
  if (stream->type != 0)
    return true;

  QUIC_VAR_INT stream_type;
  uint16_t type_offset = (uint16_t)*offset;

  if (!QuicVarIntDecode((uint16_t)length, data, &type_offset, &stream_type)) {
    if (stream->buffered_headers_length + length <=
        sizeof(stream->buffered_headers)) {
      memcpy(stream->buffered_headers + stream->buffered_headers_length, data,
             length);
      stream->buffered_headers_length += length;
    }
    return false;
  }

  stream->type = stream_type;
  *offset = type_offset;

  switch (stream_type) {
  case WTF_STREAM_TYPE_CONTROL:
    stream->connection->peer_control_stream = stream;
    break;
  case WTF_STREAM_TYPE_QPACK_ENCODER:
    stream->connection->peer_encoder_stream = stream;
    break;
  case WTF_STREAM_TYPE_QPACK_DECODER:
    stream->connection->peer_decoder_stream = stream;
    break;
  case WTF_STREAM_TYPE_WEBTRANSPORT_STREAM:
    stream->is_webtransport = true;
    break;
  }
  return true;
}

static bool wtf_process_qpack_stream_data(wtf_http3_stream *stream,
                                          const uint8_t *data, uint32_t length,
                                          uint32_t offset) {
  if (stream->type == WTF_STREAM_TYPE_QPACK_ENCODER && offset < length) {
    wtf_qpack_process_encoder_data(stream->connection, data + offset,
                                   length - offset);
    return true;
  }
  if (stream->type == WTF_STREAM_TYPE_QPACK_DECODER && offset < length) {
    wtf_qpack_process_decoder_data(stream->connection, data + offset,
                                   length - offset);
    return true;
  }
  return false;
}

static bool wtf_process_webtransport_stream_data(wtf_http3_stream *stream,
                                                 const uint8_t *data,
                                                 uint32_t length,
                                                 uint32_t *offset) {
  if (!((WTF_STREAM_IS_UNIDIRECTIONAL(stream->id) &&
         stream->type == WTF_STREAM_TYPE_WEBTRANSPORT_STREAM) ||
        (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id) && stream->is_webtransport &&
         stream->webtransport_session))) {
    return false;
  }

  if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
    if (*offset < length && stream->webtransport_session) {
      wtf_session *session = stream->webtransport_session;
      mtx_lock(&session->streams_mutex);
      stream_map_itr wt_itr = stream_map_get(&session->streams, stream->id);
      wtf_stream *wt_stream =
          !stream_map_is_end(wt_itr) ? wt_itr.data->val : NULL;
      mtx_unlock(&session->streams_mutex);

      if (wt_stream) {
        wtf_stream_process_received_data(wt_stream, data + *offset,
                                         length - *offset, false);
      }
    }
    return true;
  }

  if (!stream->webtransport_session) {
    QUIC_VAR_INT session_id;
    uint16_t session_offset = (uint16_t)*offset;

    if (!QuicVarIntDecode((uint16_t)length, data, &session_offset,
                          &session_id)) {
      if (stream->buffered_headers_length + length <=
          sizeof(stream->buffered_headers)) {
        memcpy(stream->buffered_headers + stream->buffered_headers_length, data,
               length);
        stream->buffered_headers_length += length;
      }
      return true;
    }

    *offset = session_offset;
    wtf_session *session =
        wtf_connection_find_session(stream->connection, session_id);
    if (!session) {
      *offset = 0;
      return false;
    }

    stream->webtransport_session = session;
    if (!wtf_connection_associate_stream_with_session(stream->connection,
                                                      stream, session)) {
      return false;
    }

    if (*offset < length) {
      mtx_lock(&session->streams_mutex);
      stream_map_itr wt_itr = stream_map_get(&session->streams, stream->id);
      wtf_stream *wt_stream =
          !stream_map_is_end(wt_itr) ? wt_itr.data->val : NULL;
      mtx_unlock(&session->streams_mutex);

      if (wt_stream) {
        wtf_stream_process_received_data(wt_stream, data + *offset,
                                         length - *offset, false);
      }
    }
  }
  return true;
}

static bool wtf_process_webtransport_capsules(wtf_http3_stream *stream,
                                              const uint8_t *data,
                                              uint32_t length,
                                              uint32_t *processed_bytes) {
  if (!stream->webtransport_session ||
      WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
    return false;
  }

  if (stream->webtransport_session->state == WTF_SESSION_CLOSED) {
    stream->connection->server->context->quic_api->StreamShutdown(
        stream->quic_stream,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
        WTF_H3_MESSAGE_ERROR);
    return false;
  }

  wtf_capsule capsule;
  if (wtf_parse_capsule(stream, data + *processed_bytes,
                        length - *processed_bytes, &capsule)) {
    wtf_session_process_capsule(stream->webtransport_session, &capsule);

    if (capsule.data) {
      free(capsule.data);
    }

    size_t capsule_total_size = wtf_varint_size(capsule.type) +
                                wtf_varint_size(capsule.length) +
                                (size_t)capsule.length;
    *processed_bytes += (uint32_t)capsule_total_size;
    return true;
  } else {

    uint32_t remaining = length - *processed_bytes;
    if (remaining > 0 && remaining <= sizeof(stream->buffered_headers)) {
      memcpy(stream->buffered_headers, data + *processed_bytes, remaining);
      stream->buffered_headers_length = remaining;
    }
    return false;
  }
}

static bool
wtf_process_http3_frames(wtf_http3_stream *stream, const uint8_t *data,
                         uint32_t length, uint32_t offset,
                         wtf_connect_request *pending_connect_request,
                         bool *has_connect_headers) {
  uint32_t processed_bytes = offset;

  while (processed_bytes < length) {

    if (wtf_process_webtransport_capsules(stream, data, length,
                                          &processed_bytes)) {
      continue;
    }

    QUIC_VAR_INT frame_type, frame_length;
    uint32_t frame_start = processed_bytes;
    uint16_t decode_offset = (uint16_t)processed_bytes;

    if (!QuicVarIntDecode((uint16_t)length, data, &decode_offset,
                          &frame_type) ||
        !QuicVarIntDecode((uint16_t)length, data, &decode_offset,
                          &frame_length)) {

      uint32_t remaining = length - frame_start;
      if (remaining > 0 && remaining <= sizeof(stream->buffered_headers)) {
        memcpy(stream->buffered_headers, data + frame_start, remaining);
        stream->buffered_headers_length = remaining;
      }
      break;
    }

    uint32_t frame_header_end = (uint32_t)decode_offset;

    if (frame_header_end + (uint32_t)frame_length > length) {
      uint32_t remaining = length - frame_start;
      if (remaining > 0 && remaining <= sizeof(stream->buffered_headers)) {
        memcpy(stream->buffered_headers, data + frame_start, remaining);
        stream->buffered_headers_length = remaining;
      }
      break;
    }

    bool frame_valid = true;
    switch (frame_type) {
    case WTF_FRAME_SETTINGS:
      if (stream->type == WTF_STREAM_TYPE_CONTROL) {
        frame_valid = wtf_process_settings_frame(
            stream, data + frame_header_end, (uint32_t)frame_length);
      }
      break;

    case WTF_FRAME_HEADERS:
      if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        frame_valid =
            (wtf_parse_connect_headers(stream, data + frame_header_end,
                                       (uint32_t)frame_length,
                                       pending_connect_request) == WTF_SUCCESS);
        if (frame_valid) {
          *has_connect_headers = true;
        }
      }
      break;

    case WTF_FRAME_DATA:

      break;

    case WTF_FRAME_WEBTRANSPORT_STREAM:
      if (!WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
        stream->is_webtransport = true;

        uint64_t session_id = 0;
        bool found_session = false;

        if (frame_length > 0) {
          size_t session_offset = 0;
          if (wtf_varint_decode((size_t)frame_length, data + frame_header_end,
                                &session_offset, &session_id)) {
            found_session = true;
          }
        } else {

          mtx_lock(&stream->connection->sessions_mutex);
          session_map_itr first_session_itr =
              session_map_first(&stream->connection->sessions);
          if (!session_map_is_end(first_session_itr)) {
            session_id = first_session_itr.data->val->id;
            found_session = true;
          }
          mtx_unlock(&stream->connection->sessions_mutex);
        }

        if (found_session) {
          wtf_session *session =
              wtf_connection_find_session(stream->connection, session_id);
          if (session) {
            stream->webtransport_session = session;
            wtf_connection_associate_stream_with_session(stream->connection,
                                                         stream, session);
          }
        }
      }
      break;

    case WTF_FRAME_GOAWAY:
      if (stream->type == WTF_STREAM_TYPE_CONTROL) {
        frame_valid = wtf_process_goaway_frame(stream, data + frame_header_end,
                                               (uint32_t)frame_length);
      }
      break;

    default:

      break;
    }

    if (!frame_valid) {
      return false;
    }

    processed_bytes = frame_header_end + (uint32_t)frame_length;
  }

  return true;
}

static bool wtf_process_stream_receive(wtf_http3_stream *stream,
                                       const QUIC_BUFFER *buffer) {
  const uint8_t *data = buffer->Buffer;
  uint32_t length = buffer->Length;
  uint32_t offset = 0;

  if (!data || length == 0) {
    return true;
  }

  uint8_t *combined_data = NULL;
  bool allocated_buffer = false;
  if (!wtf_combine_stream_data(stream, &data, &length, &combined_data,
                               &allocated_buffer)) {
    return false;
  }

  if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
    if (!wtf_parse_unidirectional_stream_type(stream, data, length, &offset)) {
      if (allocated_buffer)
        free(combined_data);
      return true;
    }

    if (wtf_process_qpack_stream_data(stream, data, length, offset)) {
      if (allocated_buffer)
        free(combined_data);
      return true;
    }
  }

  if (wtf_process_webtransport_stream_data(stream, data, length, &offset)) {
    if (allocated_buffer)
      free(combined_data);
    return true;
  }

  bool should_process_frames = false;
  if (WTF_STREAM_IS_UNIDIRECTIONAL(stream->id)) {
    should_process_frames = (stream->type == WTF_STREAM_TYPE_CONTROL);
  } else {
    should_process_frames = !stream->is_webtransport;
  }

  if (!should_process_frames) {
    if (allocated_buffer)
      free(combined_data);
    return true;
  }

  wtf_connect_request pending_connect_request = {0};
  bool has_connect_headers = false;

  bool frames_valid =
      wtf_process_http3_frames(stream, data, length, offset,
                               &pending_connect_request, &has_connect_headers);

  if (allocated_buffer) {
    free(combined_data);
  }

  if (!frames_valid) {

    if (pending_connect_request.method)
      free(pending_connect_request.method);
    if (pending_connect_request.protocol)
      free(pending_connect_request.protocol);
    if (pending_connect_request.scheme)
      free(pending_connect_request.scheme);
    if (pending_connect_request.authority)
      free(pending_connect_request.authority);
    if (pending_connect_request.path)
      free(pending_connect_request.path);
    if (pending_connect_request.origin)
      free(pending_connect_request.origin);
    return false;
  }

  if (has_connect_headers) {
    return wtf_process_headers_frame(stream, &pending_connect_request);
  }

  return true;
}

static wtf_http3_stream *wtf_http3_stream_create(wtf_connection *conn,
                                                 HQUIC quic_stream,
                                                 uint64_t stream_id) {
  wtf_http3_stream *stream = malloc(sizeof(wtf_http3_stream));
  if (!stream) {
    return NULL;
  }

  memset(stream, 0, sizeof(*stream));
  stream->id = stream_id;
  stream->quic_stream = quic_stream;
  stream->connection = conn;
  stream->state = WTF_INTERNAL_STREAM_STATE_IDLE;

  if (stream_id != UINT64_MAX) {
    mtx_lock(&conn->streams_mutex);
    http3_stream_map_itr itr =
        http3_stream_map_insert(&conn->streams, stream_id, stream);
    if (http3_stream_map_is_end(itr)) {
      mtx_unlock(&conn->streams_mutex);
      free(stream);
      return NULL;
    }
    mtx_unlock(&conn->streams_mutex);
  }

  return stream;
}

static void wtf_http3_stream_destroy(wtf_http3_stream *stream) {
  if (!stream)
    return;

  if (stream->header_buffer) {
    free(stream->header_buffer);
  }
  if (stream->capsule_buffer) {
    free(stream->capsule_buffer);
  }
  free(stream);
}

static wtf_connection *wtf_connection_create(wtf_server *server,
                                             HQUIC quic_connection) {
  wtf_connection *conn = malloc(sizeof(wtf_connection));
  if (!conn) {
    return NULL;
  }

  memset(conn, 0, sizeof(*conn));
  conn->quic_connection = quic_connection;
  conn->server = server;
  conn->state = WTF_CONNECTION_STATE_HANDSHAKING;
  conn->max_sessions = server->config.max_sessions_per_connection > 0
                           ? server->config.max_sessions_per_connection
                           : WTF_DEFAULT_MAX_SESSIONS;
  conn->max_datagram_size = WTF_MAX_DATAGRAM_SIZE;

  wtf_settings_init(&conn->local_settings);
  wtf_settings_init(&conn->peer_settings);

  session_map_init(&conn->sessions);
  http3_stream_map_init(&conn->streams);
  http3_stream_map_init(&conn->buffered_streams);

  if (mtx_init(&conn->streams_mutex, mtx_plain) != thrd_success) {
    session_map_cleanup(&conn->sessions);
    http3_stream_map_cleanup(&conn->streams);
    http3_stream_map_cleanup(&conn->buffered_streams);
    free(conn);
    return NULL;
  }

  if (mtx_init(&conn->sessions_mutex, mtx_plain) != thrd_success) {
    mtx_destroy(&conn->streams_mutex);
    session_map_cleanup(&conn->sessions);
    http3_stream_map_cleanup(&conn->streams);
    http3_stream_map_cleanup(&conn->buffered_streams);
    free(conn);
    return NULL;
  }

  if (mtx_init(&conn->buffered_mutex, mtx_plain) != thrd_success) {
    mtx_destroy(&conn->sessions_mutex);
    mtx_destroy(&conn->streams_mutex);
    session_map_cleanup(&conn->sessions);
    http3_stream_map_cleanup(&conn->streams);
    http3_stream_map_cleanup(&conn->buffered_streams);
    free(conn);
    return NULL;
  }

  wtf_qpack_init(&conn->qpack, WTF_QPACK_DYNAMIC_TABLE_SIZE,
                 WTF_QPACK_MAX_BLOCKED_STREAMS);

  uint32_t addr_size = sizeof(conn->peer_address);
  server->context->quic_api->GetParam(quic_connection,
                                      QUIC_PARAM_CONN_REMOTE_ADDRESS,
                                      &addr_size, &conn->peer_address);
  return conn;
}

static void wtf_connection_destroy(wtf_connection *conn) {
  if (!conn)
    return;

  mtx_lock(&conn->sessions_mutex);
  for (session_map_itr itr = session_map_first(&conn->sessions);
       !session_map_is_end(itr); itr = session_map_next(itr)) {
    wtf_session_destroy(itr.data->val);
  }
  session_map_cleanup(&conn->sessions);
  mtx_unlock(&conn->sessions_mutex);

  mtx_lock(&conn->streams_mutex);
  for (http3_stream_map_itr itr = http3_stream_map_first(&conn->streams);
       !http3_stream_map_is_end(itr); itr = http3_stream_map_next(itr)) {
    wtf_http3_stream_destroy(itr.data->val);
  }
  http3_stream_map_cleanup(&conn->streams);
  mtx_unlock(&conn->streams_mutex);

  mtx_lock(&conn->buffered_mutex);
  for (http3_stream_map_itr itr =
           http3_stream_map_first(&conn->buffered_streams);
       !http3_stream_map_is_end(itr); itr = http3_stream_map_next(itr)) {
    wtf_http3_stream_destroy(itr.data->val);
  }
  http3_stream_map_cleanup(&conn->buffered_streams);

  wtf_datagram *buffered_dgram = conn->buffered_datagrams;
  while (buffered_dgram) {
    wtf_datagram *next = buffered_dgram->next;
    wtf_datagram_destroy(buffered_dgram);
    buffered_dgram = next;
  }
  mtx_unlock(&conn->buffered_mutex);

  wtf_qpack_cleanup(&conn->qpack);
  mtx_destroy(&conn->buffered_mutex);
  mtx_destroy(&conn->sessions_mutex);
  mtx_destroy(&conn->streams_mutex);
  free(conn);
}

static bool wtf_create_control_stream(wtf_connection *conn) {
  WTF_LOG_INFO(conn->server->context, "http3", "Creating control stream...");

  wtf_http3_stream *stream = wtf_http3_stream_create(conn, NULL, UINT64_MAX);
  if (!stream) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "Failed to create control stream context");
    return false;
  }

  stream->type = WTF_STREAM_TYPE_CONTROL;
  conn->control_stream = stream;

  HQUIC control_stream;
  QUIC_STATUS status = conn->server->context->quic_api->StreamOpen(
      conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
      wtf_stream_callback, stream, &control_stream);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "Failed to create control stream: 0x%x", status);
    free(stream);
    return false;
  }

  stream->quic_stream = control_stream;

  status = conn->server->context->quic_api->StreamStart(
      control_stream, QUIC_STREAM_START_FLAG_NONE);
  if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "StreamStart failed for control stream: 0x%x", status);
    conn->server->context->quic_api->StreamClose(control_stream);
    return false;
  }

  WTF_LOG_INFO(conn->server->context, "http3",
               "Control stream creation initiated");
  return true;
}

static bool wtf_create_qpack_streams(wtf_connection *conn) {
  WTF_LOG_INFO(conn->server->context, "http3", "Creating QPACK streams...");

  wtf_http3_stream *enc_stream =
      wtf_http3_stream_create(conn, NULL, UINT64_MAX);
  if (!enc_stream) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "Failed to create encoder stream context");
    return false;
  }

  enc_stream->type = WTF_STREAM_TYPE_QPACK_ENCODER;
  conn->qpack_encoder_stream = enc_stream;

  HQUIC encoder_stream = NULL;
  QUIC_STATUS status = conn->server->context->quic_api->StreamOpen(
      conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
      wtf_stream_callback, enc_stream, &encoder_stream);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "StreamOpen failed for encoder stream: 0x%x", status);
    free(enc_stream);
    return false;
  }

  enc_stream->quic_stream = encoder_stream;

  status = conn->server->context->quic_api->StreamStart(
      encoder_stream, QUIC_STREAM_START_FLAG_NONE);
  if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "StreamStart failed for encoder stream: 0x%x", status);
    conn->server->context->quic_api->StreamClose(encoder_stream);
    return false;
  }

  WTF_LOG_DEBUG(conn->server->context, "http3",
                "QPACK encoder stream creation initiated");

  wtf_http3_stream *dec_stream =
      wtf_http3_stream_create(conn, NULL, UINT64_MAX);
  if (!dec_stream) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "Failed to create decoder stream context");
    return false;
  }

  dec_stream->type = WTF_STREAM_TYPE_QPACK_DECODER;
  conn->qpack_decoder_stream = dec_stream;

  HQUIC decoder_stream = NULL;
  status = conn->server->context->quic_api->StreamOpen(
      conn->quic_connection, QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL,
      wtf_stream_callback, dec_stream, &decoder_stream);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "StreamOpen failed for decoder stream: 0x%x", status);
    free(dec_stream);
    return false;
  }

  dec_stream->quic_stream = decoder_stream;

  status = conn->server->context->quic_api->StreamStart(
      decoder_stream, QUIC_STREAM_START_FLAG_NONE);
  if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
    WTF_LOG_ERROR(conn->server->context, "conn",
                  "StreamStart failed for decoder stream: 0x%x", status);
    conn->server->context->quic_api->StreamClose(decoder_stream);
    return false;
  }

  WTF_LOG_DEBUG(conn->server->context, "http3",
                "QPACK decoder stream creation initiated");
  WTF_LOG_INFO(conn->server->context, "http3",
               "QPACK streams creation initiated successfully");
  return true;
}

static QUIC_STATUS QUIC_API wtf_upgraded_stream_callback(
    HQUIC Stream, void *Context, QUIC_STREAM_EVENT *Event) {
  wtf_stream *wt_stream = (wtf_stream *)Context;

  if (!wt_stream || !wt_stream->session || !wt_stream->session->connection ||
      !wt_stream->session->connection->server ||
      !wt_stream->session->connection->server->context) {
    return QUIC_STATUS_INTERNAL_ERROR;
  }

  wtf_connection *conn = wt_stream->session->connection;

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_START_COMPLETE: {
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream start complete, status=0x%x",
                  Event->START_COMPLETE.Status);

    if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
      WTF_LOG_ERROR(conn->server->context, "webtransport",
                    "WebTransport stream start failed: 0x%x",
                    Event->START_COMPLETE.Status);
      return QUIC_STATUS_SUCCESS;
    }

    uint64_t stream_id = Event->START_COMPLETE.ID;
    mtx_lock(&wt_stream->mutex);
    wt_stream->stream_id = stream_id;
    wt_stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
    mtx_unlock(&wt_stream->mutex);

    mtx_lock(&wt_stream->session->streams_mutex);

    if (stream_map_get(&wt_stream->session->streams, UINT64_MAX).data != NULL) {
      stream_map_erase(&wt_stream->session->streams, UINT64_MAX);
    }
    stream_map_itr itr =
        stream_map_insert(&wt_stream->session->streams, stream_id, wt_stream);
    if (stream_map_is_end(itr)) {
      WTF_LOG_ERROR(conn->server->context, "webtransport",
                    "Failed to add WebTransport stream to session map");
    }
    mtx_unlock(&wt_stream->session->streams_mutex);

    uint8_t header[32];
    size_t header_offset = 0;
    size_t bytes_written;

    if (wt_stream->type == WTF_STREAM_UNIDIRECTIONAL) {

      if (!wtf_varint_encode(WTF_STREAM_TYPE_WEBTRANSPORT_STREAM,
                             header + header_offset,
                             sizeof(header) - header_offset, &bytes_written)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "Failed to encode WebTransport stream type");
        return QUIC_STATUS_SUCCESS;
      }
      header_offset += bytes_written;

      if (!wtf_varint_encode(wt_stream->session->id, header + header_offset,
                             sizeof(header) - header_offset, &bytes_written)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "Failed to encode session ID");
        return QUIC_STATUS_SUCCESS;
      }
      header_offset += bytes_written;
    } else {

      if (!wtf_varint_encode(WTF_FRAME_WEBTRANSPORT_STREAM,
                             header + header_offset,
                             sizeof(header) - header_offset, &bytes_written)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "Failed to encode WebTransport frame type");
        return QUIC_STATUS_SUCCESS;
      }
      header_offset += bytes_written;

      if (!wtf_varint_encode(wt_stream->session->id, header + header_offset,
                             sizeof(header) - header_offset, &bytes_written)) {
        WTF_LOG_ERROR(conn->server->context, "webtransport",
                      "Failed to encode session ID");
        return QUIC_STATUS_SUCCESS;
      }
      header_offset += bytes_written;
    }

    if (header_offset > 0) {
      void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + header_offset);
      if (send_buffer_raw) {
        QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
        uint8_t *data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);

        memcpy(data, header, header_offset);
        send_buffer->Buffer = data;
        send_buffer->Length = (uint32_t)header_offset;

        QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
            Stream, send_buffer, 1, QUIC_SEND_FLAG_NONE, send_buffer_raw);

        if (QUIC_FAILED(status)) {
          WTF_LOG_ERROR(conn->server->context, "webtransport",
                        "Failed to send WebTransport stream header: 0x%x",
                        status);
          free(send_buffer_raw);

          conn->server->context->quic_api->StreamShutdown(
              Stream,
              QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                  QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
              WTF_H3_INTERNAL_ERROR);
          return QUIC_STATUS_SUCCESS;
        } else {
          WTF_LOG_INFO(conn->server->context, "webtransport",
                       "WebTransport stream %llu header sent",
                       (unsigned long long)stream_id);
        }
      }
    }

    WTF_LOG_INFO(
        conn->server->context, "webtransport",
        "WebTransport stream %llu (%s) ready", (unsigned long long)stream_id,
        wt_stream->type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional"
                                                    : "unidirectional");
    if (wt_stream->session->callback) {
      wtf_session_event_t event = {
          .type = WTF_SESSION_EVENT_STREAM_OPENED,
          .session = wt_stream->session,
          .user_context = wt_stream->user_context,
          .stream_opened = {.stream = (wtf_stream_t *)wt_stream,
                            .stream_type = wt_stream->type}};
      wt_stream->session->callback(&event);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_RECEIVE: {
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream data received on stream %llu",
                  (unsigned long long)wt_stream->stream_id);

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      const QUIC_BUFFER *buffer = &Event->RECEIVE.Buffers[i];
      if (!wtf_stream_process_received_data(wt_stream, buffer->Buffer,
                                            buffer->Length, false)) {
        WTF_LOG_ERROR(
            conn->server->context, "webtransport",
            "Failed to process WebTransport stream data on stream %llu",
            (unsigned long long)wt_stream->stream_id);

        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
      }
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_SEND_COMPLETE: {
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream send complete on stream %llu",
                  (unsigned long long)wt_stream->stream_id);

    if (Event->SEND_COMPLETE.ClientContext) {
      free(Event->SEND_COMPLETE.ClientContext);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream peer send shutdown on stream %llu",
                  (unsigned long long)wt_stream->stream_id);

    mtx_lock(&wt_stream->mutex);
    if (wt_stream->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
      wt_stream->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
    } else {
      wt_stream->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
    }
    mtx_unlock(&wt_stream->mutex);

    if (wt_stream->callback) {
      wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_PEER_CLOSED,
                                  .stream = (wtf_stream_t *)wt_stream,
                                  .user_context = wt_stream->user_context};
      wt_stream->callback(&event);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {
    QUIC_UINT62 error_code = Event->PEER_SEND_ABORTED.ErrorCode;
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream peer send aborted on stream %llu: 0x%x",
                  (unsigned long long)wt_stream->stream_id, error_code);

    wtf_stream_handle_reset(wt_stream, error_code);

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream send shutdown complete on stream %llu",
                  (unsigned long long)wt_stream->stream_id);
    return QUIC_STATUS_SUCCESS;

  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE:
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "WebTransport stream shutdown complete on stream %llu",
                  (unsigned long long)wt_stream->stream_id);

    if (wt_stream->callback) {
      wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_CLOSED,
                                  .stream = (wtf_stream_t *)wt_stream,
                                  .user_context = wt_stream->user_context};
      wt_stream->callback(&event);
    }

    mtx_lock(&wt_stream->session->streams_mutex);
    stream_map_erase(&wt_stream->session->streams, wt_stream->stream_id);
    mtx_unlock(&wt_stream->session->streams_mutex);

    wtf_stream_destroy(wt_stream);

    return QUIC_STATUS_SUCCESS;

  default:
    WTF_LOG_DEBUG(conn->server->context, "webtransport",
                  "Unhandled WebTransport stream event: %d", Event->Type);
    return QUIC_STATUS_SUCCESS;
  }
}

static QUIC_STATUS QUIC_API wtf_stream_callback(HQUIC Stream, void *Context,
                                                QUIC_STREAM_EVENT *Event) {
  wtf_http3_stream *stream = (wtf_http3_stream *)Context;
  wtf_connection *conn = NULL;

  if (!stream || !stream->connection || !stream->connection->server ||
      !stream->connection->server->context) {
    return QUIC_STATUS_INTERNAL_ERROR;
  }

  conn = stream->connection;

  switch (Event->Type) {
  case QUIC_STREAM_EVENT_START_COMPLETE: {

    WTF_LOG_DEBUG(conn->server->context, "stream",
                  "Stream start complete, status=0x%x",
                  Event->START_COMPLETE.Status);

    if (QUIC_FAILED(Event->START_COMPLETE.Status)) {
      WTF_LOG_ERROR(conn->server->context, "stream",
                    "Stream start failed: 0x%x", Event->START_COMPLETE.Status);
      return QUIC_STATUS_SUCCESS;
    }

    stream->id = Event->START_COMPLETE.ID;
    stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;

    mtx_lock(&conn->streams_mutex);
    http3_stream_map_itr itr =
        http3_stream_map_insert(&conn->streams, stream->id, stream);
    if (http3_stream_map_is_end(itr)) {
      WTF_LOG_ERROR(conn->server->context, "stream",
                    "Failed to add stream to map after START_COMPLETE");
    }
    mtx_unlock(&conn->streams_mutex);

    WTF_LOG_INFO(
        conn->server->context, "stream", "Stream ID ready: %llu, type: %llu",
        (unsigned long long)stream->id, (unsigned long long)stream->type);

    if (stream->type == WTF_STREAM_TYPE_CONTROL ||
        stream->type == WTF_STREAM_TYPE_QPACK_ENCODER ||
        stream->type == WTF_STREAM_TYPE_QPACK_DECODER) {

      uint32_t total_size = 512;

      void *send_buffer_raw = malloc(sizeof(QUIC_BUFFER) + total_size);
      if (!send_buffer_raw) {
        WTF_LOG_ERROR(conn->server->context, "stream",
                      "Failed to allocate send buffer");
        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_FRAME_ERROR);
        return QUIC_STATUS_SUCCESS;
      }

      QUIC_BUFFER *send_buffer = (QUIC_BUFFER *)send_buffer_raw;
      uint8_t *data = (uint8_t *)send_buffer_raw + sizeof(QUIC_BUFFER);
      size_t offset = 0;
      size_t bytes_written;

      if (!wtf_varint_encode(stream->type, data + offset, total_size - offset,
                             &bytes_written)) {
        WTF_LOG_ERROR(conn->server->context, "stream",
                      "Failed to encode stream type");
        free(send_buffer_raw);
        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_FRAME_ERROR);
        return QUIC_STATUS_SUCCESS;
      }
      offset += bytes_written;

      if (stream->type == WTF_STREAM_TYPE_CONTROL) {
        WTF_LOG_INFO(conn->server->context, "http3",
                     "Control stream ready - waiting for client settings "
                     "before sending ours");
      }

      send_buffer->Buffer = data;
      send_buffer->Length = (uint32_t)offset;

      QUIC_STATUS status = conn->server->context->quic_api->StreamSend(
          Stream, send_buffer, 1, QUIC_SEND_FLAG_NONE, send_buffer_raw);

      if (QUIC_SUCCEEDED(status)) {
        WTF_LOG_INFO(conn->server->context, "http3",
                     "Stream type %llu sent on stream %llu",
                     (unsigned long long)stream->type,
                     (unsigned long long)stream->id);
      } else {
        WTF_LOG_ERROR(conn->server->context, "stream",
                      "Failed to send stream type and data: 0x%x", status);
        free(send_buffer_raw);
        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
      }
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_RECEIVE: {

    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->server->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);
    if (QUIC_FAILED(status)) {
      WTF_LOG_ERROR(conn->server->context, "stream",
                    "Failed to get stream ID for receive: 0x%x", status);
      conn->server->context->quic_api->StreamShutdown(
          Stream,
          QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
              QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }

    if (stream->id == UINT64_MAX) {

      stream->id = stream_id;

      mtx_lock(&conn->streams_mutex);
      http3_stream_map_itr itr =
          http3_stream_map_insert(&conn->streams, stream_id, stream);
      if (http3_stream_map_is_end(itr)) {
        mtx_unlock(&conn->streams_mutex);
        WTF_LOG_ERROR(conn->server->context, "stream",
                      "Failed to add peer stream to map with stream ID %llu",
                      (unsigned long long)stream_id);
        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            WTF_H3_INTERNAL_ERROR);
        return QUIC_STATUS_SUCCESS;
      }
      mtx_unlock(&conn->streams_mutex);

      WTF_LOG_DEBUG(conn->server->context, "stream",
                    "Updated peer stream with ID %llu",
                    (unsigned long long)stream_id);
    }

    for (uint32_t i = 0; i < Event->RECEIVE.BufferCount; i++) {
      if (!wtf_process_stream_receive(stream, &Event->RECEIVE.Buffers[i])) {
        WTF_LOG_ERROR(conn->server->context, "stream",
                      "Failed to process stream data on stream %llu",
                      (unsigned long long)stream_id);

        uint64_t error_code = WTF_H3_GENERAL_PROTOCOL_ERROR;
        if (WTF_STREAM_IS_UNIDIRECTIONAL(stream_id)) {
          switch (stream->type) {
          case WTF_STREAM_TYPE_CONTROL:
            error_code = WTF_H3_CLOSED_CRITICAL_STREAM;
            break;
          case WTF_STREAM_TYPE_QPACK_ENCODER:
            error_code = WTF_QPACK_ENCODER_STREAM_ERROR;
            break;
          case WTF_STREAM_TYPE_QPACK_DECODER:
            error_code = WTF_QPACK_DECODER_STREAM_ERROR;
            break;
          default:
            error_code = WTF_H3_FRAME_ERROR;
            break;
          }
        } else {
          error_code = WTF_H3_MESSAGE_ERROR;
        }

        conn->server->context->quic_api->StreamShutdown(
            Stream,
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
                QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
            error_code);

        if (stream->type == WTF_STREAM_TYPE_CONTROL) {
          WTF_LOG_ERROR(conn->server->context, "stream",
                        "Critical control stream error - closing connection");
          conn->server->context->quic_api->ConnectionShutdown(
              conn->quic_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
              WTF_H3_CLOSED_CRITICAL_STREAM);
        }

        return QUIC_STATUS_SUCCESS;
      }
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_SEND_COMPLETE: {

    if (Event->SEND_COMPLETE.ClientContext) {
      free(Event->SEND_COMPLETE.ClientContext);
    }
    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN: {

    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->server->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);

    if (QUIC_SUCCEEDED(status)) {
      mtx_lock(&conn->streams_mutex);
      http3_stream_map_itr itr =
          http3_stream_map_get(&conn->streams, stream_id);
      if (!http3_stream_map_is_end(itr)) {
        wtf_http3_stream *current = itr.data->val;
        if (current->state == WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL) {
          current->state = WTF_INTERNAL_STREAM_STATE_CLOSED;
        } else {
          current->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE;
        }
      }
      mtx_unlock(&conn->streams_mutex);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_PEER_SEND_ABORTED: {

    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->server->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);

    if (QUIC_SUCCEEDED(status)) {
      mtx_lock(&conn->streams_mutex);
      http3_stream_map_itr itr =
          http3_stream_map_get(&conn->streams, stream_id);
      if (!http3_stream_map_is_end(itr)) {
        wtf_http3_stream *current = itr.data->val;
        current->state = WTF_INTERNAL_STREAM_STATE_RESET;
      }
      mtx_unlock(&conn->streams_mutex);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_STREAM_EVENT_SEND_SHUTDOWN_COMPLETE:
    return QUIC_STATUS_SUCCESS;

  case QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE: {

    uint64_t stream_id;
    uint32_t stream_id_size = sizeof(stream_id);
    QUIC_STATUS status = conn->server->context->quic_api->GetParam(
        Stream, QUIC_PARAM_STREAM_ID, &stream_id_size, &stream_id);

    if (QUIC_SUCCEEDED(status)) {
      mtx_lock(&conn->streams_mutex);
      http3_stream_map_itr itr =
          http3_stream_map_get(&conn->streams, stream_id);
      if (!http3_stream_map_is_end(itr)) {
        wtf_http3_stream *to_remove = itr.data->val;

        if (to_remove->id != UINT64_MAX) {
          http3_stream_map_erase(&conn->streams, stream_id);
        }
        wtf_http3_stream_destroy(to_remove);
      }
      mtx_unlock(&conn->streams_mutex);
    }

    return QUIC_STATUS_SUCCESS;
  }

  default:
    return QUIC_STATUS_SUCCESS;
  }
}

static QUIC_STATUS QUIC_API wtf_connection_callback(
    HQUIC Connection, void *Context, QUIC_CONNECTION_EVENT *Event) {
  wtf_connection *conn = (wtf_connection *)Context;

  if (!conn || !conn->server || !conn->server->context) {
    return QUIC_STATUS_INTERNAL_ERROR;
  }

  switch (Event->Type) {
  case QUIC_CONNECTION_EVENT_CONNECTED: {
    WTF_LOG_INFO(conn->server->context, "conn",
                 "Connection established - starting HTTP/3 handshake");

    if (Event->CONNECTED.NegotiatedAlpnLength > 0 &&
        Event->CONNECTED.NegotiatedAlpn) {
      char alpn_str[256];
      size_t copy_len =
          min(Event->CONNECTED.NegotiatedAlpnLength, sizeof(alpn_str) - 1);
      memcpy(alpn_str, Event->CONNECTED.NegotiatedAlpn, copy_len);
      alpn_str[copy_len] = '\0';
      WTF_LOG_TRACE(conn->server->context, "conn", "Negotiated ALPN: %s",
                    alpn_str);
    }

    if (Event->CONNECTED.SessionResumed) {
      WTF_LOG_TRACE(conn->server->context, "conn", "Session resumed");
    }

    if (!wtf_create_control_stream(conn)) {
      WTF_LOG_ERROR(conn->server->context, "conn",
                    "Failed to create control stream");
      conn->server->context->quic_api->ConnectionShutdown(
          Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }

    if (!wtf_create_qpack_streams(conn)) {
      WTF_LOG_ERROR(conn->server->context, "conn",
                    "Failed to create QPACK streams");
      conn->server->context->quic_api->ConnectionShutdown(
          Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }

    conn->server->stats.total_connections_attempted++;

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_PEER_STREAM_STARTED: {
    WTF_LOG_DEBUG(conn->server->context, "conn", "Peer started new stream");

    wtf_http3_stream *stream = wtf_http3_stream_create(
        conn, Event->PEER_STREAM_STARTED.Stream, UINT64_MAX);
    if (!stream) {
      WTF_LOG_ERROR(conn->server->context, "conn",
                    "Failed to create peer stream context");
      conn->server->context->quic_api->StreamShutdown(
          Event->PEER_STREAM_STARTED.Stream,
          QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
              QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }

    conn->server->context->quic_api->SetCallbackHandler(
        Event->PEER_STREAM_STARTED.Stream, wtf_stream_callback, stream);
    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED: {

    const uint8_t *data = Event->DATAGRAM_RECEIVED.Buffer->Buffer;
    uint32_t length = Event->DATAGRAM_RECEIVED.Buffer->Length;

    wtf_process_h3_datagram(conn, data, length);
    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_DATAGRAM_SEND_STATE_CHANGED: {

    if (Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext &&
        Event->DATAGRAM_SEND_STATE_CHANGED.State == QUIC_DATAGRAM_SEND_SENT) {
      free(Event->DATAGRAM_SEND_STATE_CHANGED.ClientContext);
    }
    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_PEER_CERTIFICATE_RECEIVED: {

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_TRANSPORT:
  case QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER: {
    uint64_t error_code = Event->SHUTDOWN_INITIATED_BY_PEER.ErrorCode;
    WTF_LOG_INFO(conn->server->context, "conn",
                 "Connection shutdown initiated: error=0x%llx",
                 (unsigned long long)error_code);

    conn->state = WTF_CONNECTION_STATE_CLOSING;

    mtx_lock(&conn->sessions_mutex);
    for (session_map_itr itr = session_map_first(&conn->sessions);
         !session_map_is_end(itr); itr = session_map_next(itr)) {
      wtf_session *session = itr.data->val;
      if (session->callback && session->state == WTF_SESSION_CONNECTED) {
        session->state = WTF_SESSION_CLOSED;
        wtf_session_event_t event = {
            .type = WTF_SESSION_EVENT_DISCONNECTED,
            .session = (wtf_session_t *)session,
            .user_context = session->user_context,
            .disconnected = {.error_code = (uint32_t)error_code,
                             .reason = "Connection shutdown"}};
        session->callback(&event);
      }
    }
    mtx_unlock(&conn->sessions_mutex);

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE: {
    WTF_LOG_INFO(conn->server->context, "conn", "Connection shutdown complete");

    conn->state = WTF_CONNECTION_STATE_CLOSED;

    mtx_lock(&conn->server->connections_mutex);
    connection_set_erase(&conn->server->connections, conn);
    mtx_unlock(&conn->server->connections_mutex);

    wtf_connection_destroy(conn);
    return QUIC_STATUS_SUCCESS;
  }
  case QUIC_CONNECTION_EVENT_IDEAL_PROCESSOR_CHANGED: {
    WTF_LOG_INFO(conn->server->context, "conn", "Ideal processor changed to %d",
                 Event->IDEAL_PROCESSOR_CHANGED.IdealProcessor);
    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_DATAGRAM_STATE_CHANGED: {

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_CONNECTION_EVENT_RESUMPTION_TICKET_RECEIVED: {
    WTF_LOG_DEBUG(conn->server->context, "conn", "Resumption ticket received");

    return QUIC_STATUS_SUCCESS;
  }

  default:
    WTF_LOG_DEBUG(conn->server->context, "conn",
                  "Unhandled connection event: %d", Event->Type);
    return QUIC_STATUS_SUCCESS;
  }
}

static QUIC_STATUS QUIC_API wtf_listener_callback(HQUIC Listener, void *Context,
                                                  QUIC_LISTENER_EVENT *Event) {
  WTF_UNUSED(Listener);
  wtf_server *server = (wtf_server *)Context;

  if (!server || !server->context) {
    return QUIC_STATUS_INTERNAL_ERROR;
  }

  switch (Event->Type) {
  case QUIC_LISTENER_EVENT_NEW_CONNECTION: {
    WTF_LOG_INFO(server->context, "server", "New connection received");

    mtx_lock(&server->connections_mutex);
    bool accept_connection = (connection_set_size(&server->connections) < 1000);
    mtx_unlock(&server->connections_mutex);

    if (!accept_connection) {
      WTF_LOG_WARN(server->context, "server",
                   "Connection limit reached - rejecting connection");
      server->context->quic_api->ConnectionShutdown(
          Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_EXCESSIVE_LOAD);
      return QUIC_STATUS_SUCCESS;
    }

    wtf_connection *conn =
        wtf_connection_create(server, Event->NEW_CONNECTION.Connection);
    if (!conn) {
      WTF_LOG_ERROR(server->context, "server",
                    "Failed to create connection context");
      server->context->quic_api->ConnectionShutdown(
          Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }

    mtx_lock(&server->connections_mutex);
    connection_set_itr itr = connection_set_insert(&server->connections, conn);
    if (connection_set_is_end(itr)) {
      mtx_unlock(&server->connections_mutex);
      WTF_LOG_ERROR(server->context, "listener",
                    "Failed to add connection to set");
      wtf_connection_destroy(conn);
      server->context->quic_api->ConnectionShutdown(
          Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_INTERNAL_ERROR);
      return QUIC_STATUS_SUCCESS;
    }
    mtx_unlock(&server->connections_mutex);

    server->context->quic_api->SetCallbackHandler(
        Event->NEW_CONNECTION.Connection, wtf_connection_callback, conn);

    QUIC_STATUS status = server->context->quic_api->ConnectionSetConfiguration(
        Event->NEW_CONNECTION.Connection, server->configuration);

    if (QUIC_FAILED(status)) {
      WTF_LOG_ERROR(server->context, "server",
                    "Failed to set connection configuration: 0x%x", status);
      server->context->quic_api->ConnectionShutdown(
          Event->NEW_CONNECTION.Connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE,
          WTF_H3_INTERNAL_ERROR);
    }

    return QUIC_STATUS_SUCCESS;
  }

  case QUIC_LISTENER_EVENT_STOP_COMPLETE: {
    WTF_LOG_INFO(server->context, "server", "Listener stopped");
    return QUIC_STATUS_SUCCESS;
  }

  default:
    return QUIC_STATUS_SUCCESS;
  }
}

wtf_version_info_t *wtf_get_version() {
  static wtf_version_info_t version_info = {.major = WTF_VERSION_MAJOR,
                                            .minor = WTF_VERSION_MINOR,
                                            .patch = WTF_VERSION_PATCH,
                                            .version = WTF_VERSION};
  return &version_info;
}

wtf_result_t wtf_context_create(const wtf_context_config_t *config,
                                wtf_context_t **context) {
  if (!config || !context) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_context_t *ctx = malloc(sizeof(wtf_context_t));
  if (!ctx) {
    return WTF_ERROR_OUT_OF_MEMORY;
  }

  memset(ctx, 0, sizeof(*ctx));
  ctx->config = *config;
  ctx->log_level = config->log_level;
  ctx->log_callback = config->log_callback;
  ctx->log_user_context = config->log_user_context;

  if (mtx_init(&ctx->mutex, mtx_plain) != thrd_success) {
    free(ctx);
    return WTF_ERROR_INTERNAL;
  }

  QUIC_STATUS status = MsQuicOpen2(&ctx->quic_api);
  if (QUIC_FAILED(status)) {
    WTF_LOG_CRITICAL(ctx, "context", "MsQuicOpen2 failed: 0x%x", status);
    mtx_destroy(&ctx->mutex);
    free(ctx);
    return wtf_quic_status_to_result(status);
  }

  QUIC_EXECUTION_PROFILE execution_profile = QUIC_EXECUTION_PROFILE_LOW_LATENCY;
  if (config->execution_profile == WTF_EXECUTION_PROFILE_MAX_THROUGHPUT) {
    execution_profile = QUIC_EXECUTION_PROFILE_TYPE_MAX_THROUGHPUT;
  } else if (config->execution_profile == WTF_EXECUTION_PROFILE_REAL_TIME) {
    execution_profile = QUIC_EXECUTION_PROFILE_TYPE_REAL_TIME;
  } else if (config->execution_profile == WTF_EXECUTION_PROFILE_SCAVENGER) {
    execution_profile = QUIC_EXECUTION_PROFILE_TYPE_SCAVENGER;
  }

  const QUIC_REGISTRATION_CONFIG reg_config = {
      .AppName = "libwtf", .ExecutionProfile = execution_profile};

  status = ctx->quic_api->RegistrationOpen(&reg_config, &ctx->registration);
  if (QUIC_FAILED(status)) {
    WTF_LOG_CRITICAL(ctx, "context", "RegistrationOpen failed: 0x%x", status);
    MsQuicClose(ctx->quic_api);
    mtx_destroy(&ctx->mutex);
    free(ctx);
    return wtf_quic_status_to_result(status);
  }

  WTF_LOG_INFO(ctx, "context", "WebTransport context created successfully");

  *context = ctx;
  return WTF_SUCCESS;
}

void wtf_context_destroy(wtf_context_t *context) {
  if (!context) {
    return;
  }

  wtf_context *ctx = context;

  WTF_LOG_INFO(ctx, "context", "Destroying WebTransport context");

  mtx_lock(&ctx->mutex);

  if (ctx->server) {
    wtf_server_destroy((wtf_server_t *)ctx->server);
    ctx->server = NULL;
  }

  if (ctx->registration) {
    ctx->quic_api->RegistrationClose(ctx->registration);
    ctx->registration = NULL;
  }

  if (ctx->quic_api) {
    MsQuicClose(ctx->quic_api);
    ctx->quic_api = NULL;
  }

  mtx_unlock(&ctx->mutex);
  mtx_destroy(&ctx->mutex);

  free(context);
}

static void wtf_cleanup_server_cred_config(wtf_server *srv) {
    if (!srv || !srv->cred_config) return;
    
    QUIC_CREDENTIAL_CONFIG *cred_config = srv->cred_config;
    
    switch (cred_config->Type) {
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE:
            if (cred_config->CertificateFile) {
                free((void*)cred_config->CertificateFile->CertificateFile);
                free((void*)cred_config->CertificateFile->PrivateKeyFile);
                free(cred_config->CertificateFile);
            }
            break;
            
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED:
            if (cred_config->CertificateFileProtected) {
                free((void*)cred_config->CertificateFileProtected->CertificateFile);
                free((void*)cred_config->CertificateFileProtected->PrivateKeyFile);
                if (cred_config->CertificateFileProtected->PrivateKeyPassword) {
                    size_t pwd_len = strlen(cred_config->CertificateFileProtected->PrivateKeyPassword);
                    memset((void*)cred_config->CertificateFileProtected->PrivateKeyPassword, 0, pwd_len);
                    free((void*)cred_config->CertificateFileProtected->PrivateKeyPassword);
                }
                free(cred_config->CertificateFileProtected);
            }
            break;
            
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH:
            if (cred_config->CertificateHash) {
                free(cred_config->CertificateHash);
            }
            break;
            
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE:
            if (cred_config->CertificateHashStore) {
                free(cred_config->CertificateHashStore);
            }
            break;
            
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12:
            if (cred_config->CertificatePkcs12) {
                if (cred_config->CertificatePkcs12->Asn1Blob) {
                    memset((void*)cred_config->CertificatePkcs12->Asn1Blob, 0, 
                           cred_config->CertificatePkcs12->Asn1BlobLength);
                    free((void*)cred_config->CertificatePkcs12->Asn1Blob);
                }
                if (cred_config->CertificatePkcs12->PrivateKeyPassword) {
                    size_t pwd_len = strlen(cred_config->CertificatePkcs12->PrivateKeyPassword);
                    memset((void*)cred_config->CertificatePkcs12->PrivateKeyPassword, 0, pwd_len);
                    free((void*)cred_config->CertificatePkcs12->PrivateKeyPassword);
                }
                free(cred_config->CertificatePkcs12);
            }
            break;
            
        case QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT:
            // Certificate context is managed externally, nothing to free
            break;
            
        case QUIC_CREDENTIAL_TYPE_NONE:
        default:
            break;
    }
    
    // Clean up principal and CA cert file if allocated
    if (cred_config->Principal) {
        free((void*)cred_config->Principal);
    }
    if (cred_config->CaCertificateFile) {
        free((void*)cred_config->CaCertificateFile);
    }
    
    // Free the credential config itself
    free(srv->cred_config);
    srv->cred_config = NULL;
}

wtf_result_t wtf_server_create(wtf_context_t *context,
                               const wtf_server_config_t *config,
                               wtf_server_t **server) {
  wtf_result_t result = WTF_SUCCESS;
  wtf_context *ctx = NULL;
  wtf_server_t *srv = NULL;
  QUIC_STATUS status;

  if (!context || !config || !server) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  ctx = context;

  mtx_lock(&ctx->mutex);

  if (ctx->server) {
    result = WTF_ERROR_INVALID_STATE;
    goto cleanup_unlock_context;
  }

  srv = malloc(sizeof(wtf_server_t));
  if (!srv) {
    result = WTF_ERROR_OUT_OF_MEMORY;
    goto cleanup_unlock_context;
  }

  memset(srv, 0, sizeof(*srv));
  srv->context = ctx;
  srv->config = *config;
  srv->state = WTF_SERVER_STOPPED;

  connection_set_init(&srv->connections);

  if (mtx_init(&srv->mutex, mtx_plain) != thrd_success) {
    result = WTF_ERROR_INTERNAL;
    goto cleanup_connection_set;
  }

  if (mtx_init(&srv->connections_mutex, mtx_plain) != thrd_success) {
    result = WTF_ERROR_INTERNAL;
    goto cleanup_server_mutex;
  }

  QUIC_SETTINGS settings = {0};
  settings.IdleTimeoutMs = config->idle_timeout_ms > 0
                               ? config->idle_timeout_ms
                               : WTF_DEFAULT_IDLE_TIMEOUT_MS;
  settings.IsSet.IdleTimeoutMs = TRUE;
  settings.HandshakeIdleTimeoutMs = config->handshake_timeout_ms > 0
                                        ? config->handshake_timeout_ms
                                        : WTF_DEFAULT_HANDSHAKE_TIMEOUT_MS;
  settings.IsSet.HandshakeIdleTimeoutMs = TRUE;
  settings.ServerResumptionLevel = config->enable_0rtt
                                       ? QUIC_SERVER_RESUME_AND_ZERORTT
                                       : QUIC_SERVER_RESUME_ONLY;
  settings.IsSet.ServerResumptionLevel = TRUE;
  settings.DatagramReceiveEnabled = TRUE;
  settings.IsSet.DatagramReceiveEnabled = TRUE;
  settings.PeerBidiStreamCount = 1000;
  settings.IsSet.PeerBidiStreamCount = TRUE;
  settings.PeerUnidiStreamCount = 20;
  settings.IsSet.PeerUnidiStreamCount = TRUE;
  settings.SendBufferingEnabled = FALSE;
  settings.IsSet.SendBufferingEnabled = FALSE;

  settings.StreamRecvWindowDefault = 64 * 1024;
  settings.IsSet.StreamRecvWindowDefault = TRUE;
  settings.ConnFlowControlWindow = 1024 * 1024;
  settings.IsSet.ConnFlowControlWindow = TRUE;

  if (config->cert_config == NULL) {
    WTF_LOG_ERROR(ctx, "server", "Certificate configuration is required");
    result = WTF_ERROR_INVALID_PARAMETER;
    goto cleanup_connections_mutex;
  }

  srv->cred_config = malloc(sizeof(QUIC_CREDENTIAL_CONFIG));
  if (!srv->cred_config) {
    result = WTF_ERROR_OUT_OF_MEMORY;
    goto cleanup_connections_mutex;
  }

  memset(srv->cred_config, 0, sizeof(QUIC_CREDENTIAL_CONFIG));
  srv->cred_config->Flags = QUIC_CREDENTIAL_FLAG_NONE;

  switch (config->cert_config->cert_type) {
    case WTF_CERT_TYPE_NONE:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_NONE;
        srv->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_CLIENT;
        break;
        
    case WTF_CERT_TYPE_FILE:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE;
        srv->cred_config->CertificateFile = malloc(sizeof(QUIC_CERTIFICATE_FILE));
        if (!srv->cred_config->CertificateFile) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        if (!config->cert_config->cert_data.file.cert_path || 
            !config->cert_config->cert_data.file.key_path ||
            !wtf_path_valid(config->cert_config->cert_data.file.cert_path) ||
            !wtf_path_valid(config->cert_config->cert_data.file.key_path)) {
            WTF_LOG_ERROR(ctx, "server", "Invalid certificate or key file path");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }
        
        srv->cred_config->CertificateFile->CertificateFile = wtf_strdup(config->cert_config->cert_data.file.cert_path);
        srv->cred_config->CertificateFile->PrivateKeyFile = wtf_strdup(config->cert_config->cert_data.file.key_path);
        
        if (!srv->cred_config->CertificateFile->CertificateFile || !srv->cred_config->CertificateFile->PrivateKeyFile) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        break;
        
    case WTF_CERT_TYPE_FILE_PROTECTED:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_FILE_PROTECTED;
        srv->cred_config->CertificateFileProtected = malloc(sizeof(QUIC_CERTIFICATE_FILE_PROTECTED));
        if (!srv->cred_config->CertificateFileProtected) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        if (!config->cert_config->cert_data.protected_file.cert_path ||
            !config->cert_config->cert_data.protected_file.key_path ||
            !config->cert_config->cert_data.protected_file.password ||
            !wtf_path_valid(config->cert_config->cert_data.protected_file.cert_path) ||
            !wtf_path_valid(config->cert_config->cert_data.protected_file.key_path)) {
            WTF_LOG_ERROR(ctx, "server", "Invalid certificate or key file path, or missing password for protected certificate");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }
        
        srv->cred_config->CertificateFileProtected->CertificateFile = wtf_strdup(config->cert_config->cert_data.protected_file.cert_path);
        srv->cred_config->CertificateFileProtected->PrivateKeyFile = wtf_strdup(config->cert_config->cert_data.protected_file.key_path);
        srv->cred_config->CertificateFileProtected->PrivateKeyPassword = wtf_strdup(config->cert_config->cert_data.protected_file.password);
        
        if (!srv->cred_config->CertificateFileProtected->CertificateFile || 
            !srv->cred_config->CertificateFileProtected->PrivateKeyFile ||
            !srv->cred_config->CertificateFileProtected->PrivateKeyPassword) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        break;
        
    case WTF_CERT_TYPE_HASH:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH;
        srv->cred_config->CertificateHash = malloc(sizeof(QUIC_CERTIFICATE_HASH));
        if (!srv->cred_config->CertificateHash) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        if (!wtf_parse_thumbprint(config->cert_config->cert_data.hash.thumbprint,
                                 srv->cred_config->CertificateHash->ShaHash)) {
            WTF_LOG_ERROR(ctx, "server", "Invalid certificate thumbprint format");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }
        break;
        
    case WTF_CERT_TYPE_HASH_STORE:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_HASH_STORE;
        srv->cred_config->CertificateHashStore = malloc(sizeof(QUIC_CERTIFICATE_HASH_STORE));
        if (!srv->cred_config->CertificateHashStore) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        if (!config->cert_config->cert_data.hash_store.store_name) {
            WTF_LOG_ERROR(ctx, "server", "Certificate store name is required");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }

        srv->cred_config->CertificateHashStore->Flags = 0; // Default flags
        
        if (!wtf_parse_thumbprint(config->cert_config->cert_data.hash_store.thumbprint,
                                 srv->cred_config->CertificateHashStore->ShaHash)) {
            WTF_LOG_ERROR(ctx, "server", "Invalid certificate thumbprint format");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }
        
        wtf_strncpy(srv->cred_config->CertificateHashStore->StoreName,
                   config->cert_config->cert_data.hash_store.store_name,
                   sizeof(srv->cred_config->CertificateHashStore->StoreName));
        break;
        
    case WTF_CERT_TYPE_CONTEXT:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_CONTEXT;
        srv->cred_config->CertificateContext = (QUIC_CERTIFICATE*)config->cert_config->cert_data.context;
        break;
        
    case WTF_CERT_TYPE_PKCS12:
        srv->cred_config->Type = QUIC_CREDENTIAL_TYPE_CERTIFICATE_PKCS12;
        srv->cred_config->CertificatePkcs12 = malloc(sizeof(QUIC_CERTIFICATE_PKCS12));
        if (!srv->cred_config->CertificatePkcs12) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        if (!config->cert_config->cert_data.pkcs12.data || 
            config->cert_config->cert_data.pkcs12.data_size == 0) {
            WTF_LOG_ERROR(ctx, "server", "Invalid PKCS#12 certificate data");
            result = WTF_ERROR_INVALID_PARAMETER;
            goto cleanup_cred_config;
        }
        
        srv->cred_config->CertificatePkcs12->Asn1Blob = malloc(config->cert_config->cert_data.pkcs12.data_size);
        if (!srv->cred_config->CertificatePkcs12->Asn1Blob) {
            result = WTF_ERROR_OUT_OF_MEMORY;
            goto cleanup_cred_config;
        }
        
        memcpy((void*)srv->cred_config->CertificatePkcs12->Asn1Blob,
               config->cert_config->cert_data.pkcs12.data,
               config->cert_config->cert_data.pkcs12.data_size);
        srv->cred_config->CertificatePkcs12->Asn1BlobLength = (uint32_t)config->cert_config->cert_data.pkcs12.data_size;
        srv->cred_config->CertificatePkcs12->PrivateKeyPassword = config->cert_config->cert_data.pkcs12.password ? wtf_strdup(config->cert_config->cert_data.pkcs12.password) : NULL;
        break;
        
    default:
        WTF_LOG_ERROR(ctx, "server", "Invalid certificate type: %d", config->cert_config->cert_type);
        result = WTF_ERROR_INVALID_PARAMETER;
        goto cleanup_cred_config;
  }

  if (config->cert_config->principal) {
    srv->cred_config->Principal = wtf_strdup(config->cert_config->principal);
  }

  if (config->cert_config->ca_cert_file) {
    srv->cred_config->CaCertificateFile = wtf_strdup(config->cert_config->ca_cert_file);
    srv->cred_config->Flags |= QUIC_CREDENTIAL_FLAG_SET_CA_CERTIFICATE_FILE;
  }

  const char *alpn = WTF_ALPN;
  QUIC_BUFFER alpn_buffer = {(uint32_t)strlen(alpn), (uint8_t *)alpn};

  status = ctx->quic_api->ConfigurationOpen(ctx->registration, &alpn_buffer, 1,
                                            &settings, sizeof(settings), NULL,
                                            &srv->configuration);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(ctx, "server", "ConfigurationOpen failed: 0x%x", status);
    result = wtf_quic_status_to_result(status);
    goto cleanup_cred_config;
  }

  status = ctx->quic_api->ConfigurationLoadCredential(srv->configuration,
                                                      srv->cred_config);
  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(ctx, "server", "ConfigurationLoadCredential failed: 0x%x",
                  status);
    result = wtf_quic_status_to_result(status);
    goto cleanup_configuration;
  }

  ctx->server = srv;
  mtx_unlock(&ctx->mutex);

  WTF_LOG_INFO(ctx, "server", "WebTransport server created successfully");

  *server = srv;
  return WTF_SUCCESS;

cleanup_configuration:
  ctx->quic_api->ConfigurationClose(srv->configuration);

cleanup_cred_config:
  wtf_cleanup_server_cred_config(srv);

cleanup_connections_mutex:
  mtx_destroy(&srv->connections_mutex);

cleanup_server_mutex:
  mtx_destroy(&srv->mutex);

cleanup_connection_set:
  connection_set_cleanup(&srv->connections);
  free(srv);

cleanup_unlock_context:
  mtx_unlock(&ctx->mutex);
  return result;
}

wtf_result_t wtf_server_start(wtf_server_t *server) {
  if (!server) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_server *srv = server;

  mtx_lock(&srv->mutex);

  if (srv->state != WTF_SERVER_STOPPED) {
    mtx_unlock(&srv->mutex);
    return WTF_ERROR_INVALID_STATE;
  }

  srv->state = WTF_SERVER_STARTING;

  WTF_LOG_INFO(srv->context, "server",
               "Starting WebTransport server on port %u", srv->config.port);

  QUIC_STATUS status = srv->context->quic_api->ListenerOpen(
      srv->context->registration, wtf_listener_callback, srv, &srv->listener);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(srv->context, "server", "ListenerOpen failed: 0x%x", status);
    srv->state = WTF_SERVER_STOPPED;
    mtx_unlock(&srv->mutex);
    return wtf_quic_status_to_result(status);
  }

  QUIC_ADDR address = {0};
  QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_UNSPEC);
  QuicAddrSetPort(&address, srv->config.port);

  if (srv->config.host) {

    if (inet_pton(AF_INET, srv->config.host,
                  &((struct sockaddr_in *)&address)->sin_addr) == 1) {
      QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_INET);
    } else if (inet_pton(AF_INET6, srv->config.host,
                         &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
      QuicAddrSetFamily(&address, QUIC_ADDRESS_FAMILY_INET6);
    }
  }

  const char *alpn = WTF_ALPN;
  QUIC_BUFFER alpn_buffer = {(uint32_t)strlen(alpn), (uint8_t *)alpn};

  status = srv->context->quic_api->ListenerStart(srv->listener, &alpn_buffer, 1,
                                                 &address);
  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(srv->context, "server", "ListenerStart failed: 0x%x", status);
    srv->context->quic_api->ListenerClose(srv->listener);
    srv->listener = NULL;
    srv->state = WTF_SERVER_STOPPED;
    mtx_unlock(&srv->mutex);
    return wtf_quic_status_to_result(status);
  }

  srv->state = WTF_SERVER_LISTENING;
  mtx_unlock(&srv->mutex);

  WTF_LOG_INFO(srv->context, "server",
               "WebTransport server started successfully on port %u",
               srv->config.port);

  return WTF_SUCCESS;
}

wtf_result_t wtf_server_stop(wtf_server_t *server) {
  if (!server) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_server *srv = server;

  if (!srv->context) {
    return WTF_ERROR_INVALID_STATE;
  }

  mtx_lock(&srv->mutex);

  if (srv->state != WTF_SERVER_LISTENING) {
    mtx_unlock(&srv->mutex);
    return WTF_ERROR_INVALID_STATE;
  }

  srv->state = WTF_SERVER_STOPPING;

  WTF_LOG_INFO(srv->context, "server", "Stopping WebTransport server");

  if (srv->listener) {
    srv->context->quic_api->ListenerStop(srv->listener);
    srv->context->quic_api->ListenerClose(srv->listener);
    srv->listener = NULL;
  }

  srv->state = WTF_SERVER_STOPPED;
  mtx_unlock(&srv->mutex);

  WTF_LOG_INFO(srv->context, "server", "WebTransport server stopped");

  return WTF_SUCCESS;
}

wtf_server_state_t wtf_server_get_state(wtf_server_t *server) {
  if (!server) {
    return WTF_SERVER_STOPPED;
  }

  wtf_server *srv = server;

  mtx_lock(&srv->mutex);
  wtf_server_state_t state = srv->state;
  mtx_unlock(&srv->mutex);

  return state;
}

wtf_result_t wtf_server_get_statistics(wtf_server_t *server,
                                       wtf_server_statistics_t *stats) {
  if (!server || !stats) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_server *srv = server;

  mtx_lock(&srv->connections_mutex);
  *stats = srv->stats;
  stats->active_sessions = (uint32_t)connection_set_size(&srv->connections);
  mtx_unlock(&srv->connections_mutex);

  return WTF_SUCCESS;
}

void wtf_server_destroy(wtf_server_t *server) {
  if (!server) {
    return;
  }

  wtf_server *srv = server;

  WTF_LOG_INFO(srv->context, "server", "Destroying WebTransport server");

  if (srv->state == WTF_SERVER_LISTENING) {
    wtf_server_stop(server);
  }

  mtx_lock(&srv->context->mutex);

  mtx_lock(&srv->connections_mutex);
  for (connection_set_itr itr = connection_set_first(&srv->connections);
       !connection_set_is_end(itr); itr = connection_set_next(itr)) {
    wtf_connection *conn = itr.data->key;
    if (conn->quic_connection) {
      srv->context->quic_api->ConnectionShutdown(
          conn->quic_connection, QUIC_CONNECTION_SHUTDOWN_FLAG_NONE, 0);
    }
  }
  connection_set_cleanup(&srv->connections);
  mtx_unlock(&srv->connections_mutex);

  if (srv->configuration) {
    srv->context->quic_api->ConfigurationClose(srv->configuration);
  }

  // Clean up credential config stored on server
  wtf_cleanup_server_cred_config(srv);

  mtx_destroy(&srv->connections_mutex);
  mtx_destroy(&srv->mutex);

  srv->context->server = NULL;

  mtx_unlock(&srv->context->mutex);

  free(server);
}

wtf_result_t wtf_context_set_log_level(wtf_context_t *context,
                                       wtf_log_level_t level) {
  if (!context) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_context *ctx = context;

  mtx_lock(&ctx->mutex);
  ctx->log_level = level;
  mtx_unlock(&ctx->mutex);

  return WTF_SUCCESS;
}

wtf_result_t wtf_session_close(wtf_session_t *session, uint32_t error_code,
                               const char *reason) {
  if (!session) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_session *sess = (wtf_session *)session;

  if (sess->state == WTF_SESSION_CLOSED) {
    return WTF_ERROR_INVALID_STATE;
  }

  WTF_LOG_INFO(sess->connection->server->context, "session",
               "Closing session %llu with error %u: %s",
               (unsigned long long)sess->id, error_code, reason ? reason : "");

  sess->state = WTF_SESSION_CLOSED;
  sess->close_error_code = error_code;

  if (sess->close_reason) {
    free(sess->close_reason);
  }
  sess->close_reason = reason ? wtf_strndup(reason, 1024) : NULL;

  uint8_t close_data[1028];
  uint32_t close_len = 4;

  close_data[0] = (uint8_t)(error_code >> 24);
  close_data[1] = (uint8_t)(error_code >> 16);
  close_data[2] = (uint8_t)(error_code >> 8);
  close_data[3] = (uint8_t)(error_code);

  if (reason) {
    size_t reason_len = strlen(reason);
    if (reason_len > 1024) {
      WTF_LOG_WARN(sess->connection->server->context, "session",
                   "Close reason truncated from %zu to 1024 bytes", reason_len);
      reason_len = 1024;
    }
    memcpy(close_data + 4, reason, reason_len);
    close_len += (uint32_t)reason_len;
  }

  wtf_result_t result = wtf_session_send_capsule(
      sess, WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION, close_data, close_len);

  if (result == WTF_SUCCESS && sess->connect_stream &&
      sess->connect_stream->quic_stream) {
    WTF_LOG_DEBUG(
        sess->connection->server->context, "session",
        "Sending FIN on CONNECT stream after CLOSE_WEBTRANSPORT_SESSION");

    QUIC_BUFFER empty_buffer = {0};
    empty_buffer.Buffer = NULL;
    empty_buffer.Length = 0;

    QUIC_STATUS status =
        sess->connection->server->context->quic_api->StreamSend(
            sess->connect_stream->quic_stream, &empty_buffer, 1,
            QUIC_SEND_FLAG_FIN, NULL);

    if (QUIC_FAILED(status)) {
      WTF_LOG_WARN(sess->connection->server->context, "session",
                   "Failed to send FIN after CLOSE capsule: 0x%x", status);
    }
  }

  mtx_lock(&sess->streams_mutex);
  for (stream_map_itr itr = stream_map_first(&sess->streams);
       !stream_map_is_end(itr); itr = stream_map_next(itr)) {
    wtf_stream *stream = itr.data->val;

    if (stream->callback) {
      wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_CLOSED,
                                  .stream = (wtf_stream_t *)stream,
                                  .user_context = stream->user_context};
      stream->callback(&event);
    }

    if (stream->quic_stream && sess->connection && sess->connection->server &&
        sess->connection->server->context) {
      sess->connection->server->context->quic_api->StreamShutdown(
          stream->quic_stream,
          QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
              QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
          WTF_WEBTRANSPORT_SESSION_GONE);
    }
  }
  mtx_unlock(&sess->streams_mutex);

  if (sess->callback) {
    wtf_session_event_t event = {
        .type = WTF_SESSION_EVENT_DISCONNECTED,
        .session = session,
        .user_context = sess->user_context,
        .disconnected = {.error_code = error_code, .reason = reason}};
    sess->callback(&event);
  }

  return result;
}

wtf_result_t wtf_session_drain(wtf_session_t *session) {
  if (!session) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_session *sess = (wtf_session *)session;

  if (sess->state != WTF_SESSION_CONNECTED) {
    return WTF_ERROR_INVALID_STATE;
  }

  WTF_LOG_INFO(sess->connection->server->context, "session",
               "Draining session %llu", (unsigned long long)sess->id);

  sess->state = WTF_SESSION_DRAINING;

  if (sess->callback) {
    wtf_session_event_t event = {.type = WTF_SESSION_EVENT_DRAINING,
                                 .session = session,
                                 .user_context = sess->user_context};
    sess->callback(&event);
  }

  return wtf_session_send_capsule(sess, WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION,
                                  NULL, 0);
}

wtf_result_t wtf_session_send_datagram(wtf_session_t *session,
                                       const wtf_buffer_t *data) {
  if (!session || !data) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  return wtf_session_send_datagram_internal((wtf_session *)session, data);
}

wtf_session_state_t wtf_session_get_state(wtf_session_t *session) {
  if (!session)
    return WTF_SESSION_CLOSED;
  return ((wtf_session *)session)->state;
}

wtf_result_t wtf_session_get_peer_address(wtf_session_t *session,
                                          void *address_buffer,
                                          size_t *buffer_size) {
  if (!session || !buffer_size) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_session *sess = (wtf_session *)session;

  if (*buffer_size < sizeof(sess->connection->peer_address)) {
    *buffer_size = sizeof(sess->connection->peer_address);
    return WTF_ERROR_BUFFER_TOO_SMALL;
  }

  if (address_buffer) {
    memcpy(address_buffer, &sess->connection->peer_address,
           sizeof(sess->connection->peer_address));
  }
  *buffer_size = sizeof(sess->connection->peer_address);

  return WTF_SUCCESS;
}

void wtf_session_set_context(wtf_session_t *session, void *user_context) {
  if (!session) {
    return;
  }
  ((wtf_session *)session)->user_context = user_context;
}

wtf_result_t wtf_stream_send(wtf_stream_t *stream, const wtf_buffer_t *buffers,
                             size_t buffer_count, bool fin) {
  if (!stream || !buffers || buffer_count == 0) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  return wtf_stream_send_internal((wtf_stream *)stream, buffers, buffer_count,
                                  fin);
}

wtf_result_t wtf_stream_close(wtf_stream_t *stream) {
  if (!stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_stream *strm = (wtf_stream *)stream;

  mtx_lock(&strm->mutex);

  if (strm->state == WTF_INTERNAL_STREAM_STATE_CLOSED ||
      strm->state == WTF_INTERNAL_STREAM_STATE_RESET) {
    mtx_unlock(&strm->mutex);
    return WTF_ERROR_INVALID_STATE;
  }

  strm->state = WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL;

  mtx_unlock(&strm->mutex);

  wtf_buffer_t empty_buffer = {NULL, 0};
  return wtf_stream_send_internal(strm, &empty_buffer, 1, true);
}

wtf_result_t wtf_stream_abort(wtf_stream_t *stream, uint32_t error_code) {
  if (!stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_stream *strm = (wtf_stream *)stream;

  WTF_LOG_DEBUG(strm->session->connection->server->context, "stream",
                "Aborting stream %llu with error %u",
                (unsigned long long)strm->stream_id, error_code);

  mtx_lock(&strm->mutex);
  strm->state = WTF_INTERNAL_STREAM_STATE_RESET;
  mtx_unlock(&strm->mutex);

  if (strm->quic_stream) {
    wtf_connection *conn = strm->session->connection;
    conn->server->context->quic_api->StreamShutdown(
        strm->quic_stream,
        QUIC_STREAM_SHUTDOWN_FLAG_ABORT_SEND |
            QUIC_STREAM_SHUTDOWN_FLAG_ABORT_RECEIVE,
        wtf_map_webtransport_error_to_h3(error_code));
  }

  if (strm->callback) {
    wtf_stream_event_t event = {.type = WTF_STREAM_EVENT_ABORTED,
                                .stream = stream,
                                .user_context = strm->user_context,
                                .aborted = {.error_code = error_code}};
    strm->callback(&event);
  }

  return WTF_SUCCESS;
}

wtf_result_t wtf_stream_get_id(wtf_stream_t *stream, uint64_t *stream_id) {
  if (!stream || !stream_id) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  *stream_id = ((wtf_stream *)stream)->stream_id;
  return WTF_SUCCESS;
}

wtf_stream_type_t wtf_stream_get_type(wtf_stream_t *stream) {
  if (!stream)
    return WTF_STREAM_BIDIRECTIONAL;
  return ((wtf_stream *)stream)->type;
}

wtf_stream_state_t wtf_stream_get_state(wtf_stream_t *stream) {
  if (!stream)
    return WTF_STREAM_CLOSED;

  wtf_stream *strm = (wtf_stream *)stream;

  mtx_lock(&strm->mutex);
  wtf_internal_stream_state_t internal_state = strm->state;
  mtx_unlock(&strm->mutex);

  switch (internal_state) {
  case WTF_INTERNAL_STREAM_STATE_IDLE:
  case WTF_INTERNAL_STREAM_STATE_OPEN:
  case WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_REMOTE:
    return WTF_STREAM_OPEN;
  case WTF_INTERNAL_STREAM_STATE_HALF_CLOSED_LOCAL:
    return WTF_STREAM_CLOSING;
  case WTF_INTERNAL_STREAM_STATE_CLOSED:
  case WTF_INTERNAL_STREAM_STATE_RESET:
  default:
    return WTF_STREAM_CLOSED;
  }
}

wtf_result_t wtf_session_create_stream(wtf_session_t *session,
                                       wtf_stream_type_t type,
                                       wtf_stream_t **stream) {
  if (!session || !stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_session *sess = (wtf_session *)session;

  if (sess->state != WTF_SESSION_CONNECTED) {
    return WTF_ERROR_INVALID_STATE;
  }

  mtx_lock(&sess->streams_mutex);
  if (stream_map_size(&sess->streams) >= sess->max_streams) {
    mtx_unlock(&sess->streams_mutex);
    WTF_LOG_WARN(sess->connection->server->context, "stream",
                 "Session %llu has reached stream limit %u",
                 (unsigned long long)sess->id, sess->max_streams);
    return WTF_ERROR_FLOW_CONTROL;
  }
  mtx_unlock(&sess->streams_mutex);

  WTF_LOG_DEBUG(sess->connection->server->context, "stream",
                "Creating %s WebTransport stream on session %llu",
                type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional"
                                                 : "unidirectional",
                (unsigned long long)sess->id);

  wtf_stream *wt_stream = wtf_stream_create(sess, UINT64_MAX, type);
  if (!wt_stream) {
    return WTF_ERROR_OUT_OF_MEMORY;
  }

  wtf_connection *conn = sess->connection;


  uint32_t stream_open_flags = QUIC_STREAM_OPEN_FLAG_NONE;
  if (type == WTF_STREAM_UNIDIRECTIONAL) {
    stream_open_flags = QUIC_STREAM_OPEN_FLAG_UNIDIRECTIONAL;
  }

  HQUIC quic_stream;
  QUIC_STATUS status = conn->server->context->quic_api->StreamOpen(
      conn->quic_connection, stream_open_flags, wtf_upgraded_stream_callback,
      wt_stream, &quic_stream);

  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(
        conn->server->context, "stream",
        "StreamOpen failed for WebTransport %s stream on session %llu: 0x%x",
        type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional" : "unidirectional",
        (unsigned long long)sess->id, status);
    wtf_stream_destroy(wt_stream);
    return wtf_quic_status_to_result(status);
  }

  wt_stream->quic_stream = quic_stream;

  status = conn->server->context->quic_api->StreamStart(
      quic_stream, QUIC_STREAM_START_FLAG_NONE);
  if (QUIC_FAILED(status) && status != QUIC_STATUS_PENDING) {
    WTF_LOG_ERROR(conn->server->context, "stream",
                  "StreamStart failed for WebTransport stream: 0x%x", status);
    conn->server->context->quic_api->StreamClose(quic_stream);
    wtf_stream_destroy(wt_stream);
    return wtf_quic_status_to_result(status);
  }

  WTF_LOG_INFO(conn->server->context, "stream",
               "WebTransport %s stream created and started on session %llu",
               type == WTF_STREAM_BIDIRECTIONAL ? "bidirectional"
                                                : "unidirectional",
               (unsigned long long)sess->id);

  *stream = (wtf_stream_t *)wt_stream;
  return WTF_SUCCESS;
}

void wtf_stream_set_callback(wtf_stream_t *stream,
                             wtf_stream_callback_t callback) {
  if (!stream) {
    return;
  }
  ((wtf_stream *)stream)->callback = callback;
}

void wtf_stream_set_context(wtf_stream_t *stream, void *user_context) {
  if (!stream) {
    return;
  }
  ((wtf_stream *)stream)->user_context = user_context;
}

wtf_result_t wtf_stream_set_priority(wtf_stream_t *stream, uint16_t priority) {
  if (!stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  stream->priority = priority;

  QUIC_STATUS status =
      stream->session->connection->server->context->quic_api->SetParam(
          stream->quic_stream, QUIC_PARAM_STREAM_PRIORITY, sizeof(priority),
          &priority);
  if (QUIC_FAILED(status)) {
    WTF_LOG_ERROR(stream->session->connection->server->context, "stream",
                  "SetParam failed for WebTransport stream: 0x%x", status);
    return wtf_quic_status_to_result(status);
  }

  return WTF_SUCCESS;
}

wtf_result_t wtf_stream_get_statistics(wtf_stream_t *stream,
                                       uint64_t *bytes_sent,
                                       uint64_t *bytes_received) {
  if (!stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_stream *strm = (wtf_stream *)stream;

  mtx_lock(&strm->mutex);
  if (bytes_sent)
    *bytes_sent = strm->bytes_sent;
  if (bytes_received)
    *bytes_received = strm->bytes_received;
  mtx_unlock(&strm->mutex);

  return WTF_SUCCESS;
}

wtf_result_t wtf_stream_set_receive_enabled(wtf_stream_t *stream,
                                            bool enabled) {
  if (!stream) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_stream *strm = (wtf_stream *)stream;

  mtx_lock(&strm->mutex);
  strm->receive_enabled = enabled;
  mtx_unlock(&strm->mutex);

  return WTF_SUCCESS;
}

wtf_result_t wtf_connection_get_session_limit(wtf_http3_connection_t *conn,
                                              uint32_t *max_sessions,
                                              uint32_t *current_sessions) {
  if (!conn) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_connection *connection = (wtf_connection *)conn;

  if (max_sessions)
    *max_sessions = connection->max_sessions;

  if (current_sessions) {
    mtx_lock(&connection->sessions_mutex);
    *current_sessions = (uint32_t)session_map_size(&connection->sessions);
    mtx_unlock(&connection->sessions_mutex);
  }

  return WTF_SUCCESS;
}

bool wtf_connection_can_accept_session(wtf_http3_connection_t *conn) {
  if (!conn)
    return false;

  wtf_connection *connection = (wtf_connection *)conn;

  mtx_lock(&connection->sessions_mutex);
  bool can_accept =
      session_map_size(&connection->sessions) < connection->max_sessions;
  mtx_unlock(&connection->sessions_mutex);

  return can_accept;
}

wtf_result_t wtf_connection_get_sessions(wtf_http3_connection_t *conn,
                                         wtf_session_t **sessions,
                                         size_t *session_count,
                                         size_t max_sessions) {
  if (!conn || !session_count) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  wtf_connection *connection = (wtf_connection *)conn;

  mtx_lock(&connection->sessions_mutex);

  size_t count = 0;
  for (session_map_itr itr = session_map_first(&connection->sessions);
       !session_map_is_end(itr) && count < max_sessions;
       itr = session_map_next(itr)) {
    if (sessions) {
      sessions[count] = (wtf_session_t *)itr.data->val;
    }
    count++;
  }

  *session_count = count;

  mtx_unlock(&connection->sessions_mutex);

  return WTF_SUCCESS;
}

wtf_session_t *wtf_connection_find_session_by_id(wtf_http3_connection_t *conn,
                                                 uint64_t session_id) {
  if (!conn)
    return NULL;

  return (wtf_session_t *)wtf_connection_find_session((wtf_connection *)conn,
                                                      session_id);
}

wtf_stream_t *wtf_session_find_stream_by_id(wtf_session_t *session,
                                            uint64_t stream_id) {
  if (!session)
    return NULL;

  wtf_session *sess = (wtf_session *)session;

  mtx_lock(&sess->streams_mutex);

  stream_map_itr itr = stream_map_get(&sess->streams, stream_id);
  wtf_stream *stream = NULL;
  if (!stream_map_is_end(itr)) {
    stream = itr.data->val;
  }

  mtx_unlock(&sess->streams_mutex);
  return (wtf_stream_t *)stream;
}

const char *wtf_result_to_string(wtf_result_t result) {
  switch (result) {
  case WTF_SUCCESS:
    return "Success";
  case WTF_ERROR_INVALID_PARAMETER:
    return "Invalid parameter";
  case WTF_ERROR_OUT_OF_MEMORY:
    return "Out of memory";
  case WTF_ERROR_INTERNAL:
    return "Internal error";
  case WTF_ERROR_CONNECTION_ABORTED:
    return "Connection aborted";
  case WTF_ERROR_STREAM_ABORTED:
    return "Stream aborted";
  case WTF_ERROR_INVALID_STATE:
    return "Invalid state";
  case WTF_ERROR_BUFFER_TOO_SMALL:
    return "Buffer too small";
  case WTF_ERROR_NOT_FOUND:
    return "Not found";
  case WTF_ERROR_REJECTED:
    return "Rejected";
  case WTF_ERROR_TIMEOUT:
    return "Timeout";
  case WTF_ERROR_TLS_HANDSHAKE_FAILED:
    return "TLS handshake failed";
  case WTF_ERROR_PROTOCOL_VIOLATION:
    return "Protocol violation";
  case WTF_ERROR_FLOW_CONTROL:
    return "Flow control error";
  default:
    return "Unknown error";
  }
}

const char *wtf_webtransport_error_to_string(uint32_t error_code) {
  switch (error_code) {
  case 0x00:
    return "No error";
  case 0x01:
    return "General protocol error";
  case 0x02:
    return "Internal error";
  case 0x03:
    return "Connection error";
  case 0x04:
    return "Flow control error";
  case 0x05:
    return "Stream limit error";
  case 0x06:
    return "Stream state error";
  case 0x07:
    return "Final size error";
  case 0x08:
    return "Frame encoding error";
  case 0x09:
    return "Transport parameter error";
  case 0x0A:
    return "Connection ID limit error";
  case 0x0B:
    return "Protocol violation";
  case 0x0C:
    return "Invalid token";
  case 0x0D:
    return "Application error";
  case 0x0E:
    return "Crypto buffer exceeded";
  case 0x0F:
    return "Key update error";
  case 0x10:
    return "Aead limit reached";
  case 0x11:
    return "No viable path";
  default:
    return "Unknown error";
  }
}

wtf_result_t wtf_get_error_details(uint32_t error_code,
                                   wtf_error_details_t *details) {
  if (!details) {
    return WTF_ERROR_INVALID_PARAMETER;
  }

  details->error_code = error_code;
  details->description = wtf_webtransport_error_to_string(error_code);
  details->is_application_error = (error_code >= 0x100);
  details->is_transport_error = (error_code < 0x100);
  details->is_protocol_error = (error_code >= 0x100 && error_code <= 0x1FF);

  return WTF_SUCCESS;
}

bool wtf_is_valid_application_error(uint32_t error_code) {
  return (error_code >= 0x100 && error_code <= 0x3FFFFFFF);
}

const char *wtf_http3_error_to_string(uint64_t http3_error) {
  switch (http3_error) {
  case WTF_H3_NO_ERROR:
    return "HTTP3_NO_ERROR";
  case WTF_H3_GENERAL_PROTOCOL_ERROR:
    return "HTTP3_GENERAL_PROTOCOL_ERROR";
  case WTF_H3_INTERNAL_ERROR:
    return "HTTP3_INTERNAL_ERROR";
  case WTF_H3_STREAM_CREATION_ERROR:
    return "HTTP3_STREAM_CREATION_ERROR";
  case WTF_H3_CLOSED_CRITICAL_STREAM:
    return "HTTP3_CLOSED_CRITICAL_STREAM";
  case WTF_H3_FRAME_UNEXPECTED:
    return "HTTP3_FRAME_UNEXPECTED";
  case WTF_H3_FRAME_ERROR:
    return "HTTP3_FRAME_ERROR";
  case WTF_H3_EXCESSIVE_LOAD:
    return "HTTP3_EXCESSIVE_LOAD";
  case WTF_H3_ID_ERROR:
    return "HTTP3_ID_ERROR";
  case WTF_H3_SETTINGS_ERROR:
    return "HTTP3_SETTINGS_ERROR";
  case WTF_H3_MISSING_SETTINGS:
    return "HTTP3_MISSING_SETTINGS";
  case WTF_H3_REQUEST_REJECTED:
    return "HTTP3_REQUEST_REJECTED";
  case WTF_H3_REQUEST_CANCELLED:
    return "HTTP3_REQUEST_CANCELLED";
  case WTF_H3_REQUEST_INCOMPLETE:
    return "HTTP3_REQUEST_INCOMPLETE";
  case WTF_H3_MESSAGE_ERROR:
    return "HTTP3_MESSAGE_ERROR";
  case WTF_H3_CONNECT_ERROR:
    return "HTTP3_CONNECT_ERROR";
  case WTF_H3_VERSION_FALLBACK:
    return "HTTP3_VERSION_FALLBACK";
  case WTF_QPACK_DECOMPRESSION_FAILED:
    return "QPACK_DECOMPRESSION_FAILED";
  case WTF_QPACK_ENCODER_STREAM_ERROR:
    return "QPACK_ENCODER_STREAM_ERROR";
  case WTF_QPACK_DECODER_STREAM_ERROR:
    return "QPACK_DECODER_STREAM_ERROR";
  case WTF_H3_DATAGRAM_ERROR:
    return "H3_DATAGRAM_ERROR";
  default:
    return "Unknown HTTP/3 error";
  }
}