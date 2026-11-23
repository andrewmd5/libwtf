#ifndef WTF_H
#define WTF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// #region Export macros

#ifdef _WIN32
    #ifdef WTF_EXPORTS
        #define WTF_API __declspec(dllexport)
    #else
        #define WTF_API __declspec(dllimport)
    #endif
#else
    #ifdef WTF_EXPORTS
        #define WTF_API __attribute__((visibility("default")))
    #else
        #define WTF_API
    #endif
#endif

// #endregion

// #region Forward declarations

//! Forward declarations
typedef struct wtf_context wtf_context_t;
typedef struct wtf_server wtf_server_t;
typedef struct wtf_client wtf_client_t;
typedef struct wtf_session wtf_session_t;
typedef struct wtf_stream wtf_stream_t;
typedef struct wtf_connection_request_handle wtf_connection_request_handle_t;

// #endregion

// #region Enums

//! Execution profiles for performance optimization
typedef enum {
    WTF_EXECUTION_PROFILE_LOW_LATENCY = 0,     //! Optimized for minimal latency
    WTF_EXECUTION_PROFILE_MAX_THROUGHPUT = 1,  //! Optimized for maximum data throughput
    WTF_EXECUTION_PROFILE_REAL_TIME = 2,       //! Real-time processing priority
    WTF_EXECUTION_PROFILE_SCAVENGER = 3        //! Background processing priority
} wtf_execution_profile_t;

//! Result codes for all WebTransport operations
typedef enum {
    WTF_SUCCESS = 0,
    WTF_ERROR_INVALID_PARAMETER,
    WTF_ERROR_OUT_OF_MEMORY,
    WTF_ERROR_INTERNAL,
    WTF_ERROR_CONNECTION_ABORTED,
    WTF_ERROR_STREAM_ABORTED,
    WTF_ERROR_INVALID_STATE,
    WTF_ERROR_BUFFER_TOO_SMALL,
    WTF_ERROR_NOT_FOUND,
    WTF_ERROR_REJECTED,
    WTF_ERROR_TIMEOUT,
    WTF_ERROR_TLS_HANDSHAKE_FAILED,
    WTF_ERROR_PROTOCOL_VIOLATION,
    WTF_ERROR_FLOW_CONTROL,
    WTF_ERROR_NOT_SUPPORTED
} wtf_result_t;

//! Logging levels for debugging and monitoring
typedef enum {
    WTF_LOG_LEVEL_TRACE = 0,     //! Most detailed messages, may contain sensitive data
    WTF_LOG_LEVEL_DEBUG = 1,     //! Interactive investigation during development
    WTF_LOG_LEVEL_INFO = 2,      //! General application flow information
    WTF_LOG_LEVEL_WARN = 3,      //! Abnormal or unexpected events
    WTF_LOG_LEVEL_ERROR = 4,     //! Current flow stopped due to failure
    WTF_LOG_LEVEL_CRITICAL = 5,  //! Unrecoverable application or system crash
    WTF_LOG_LEVEL_NONE = 6       //! Disable all logging
} wtf_log_level_t;

//! Server operational states
typedef enum {
    WTF_SERVER_STOPPED,    //! Server is not running
    WTF_SERVER_STARTING,   //! Server is initializing
    WTF_SERVER_LISTENING,  //! Server is accepting connections
    WTF_SERVER_STOPPING    //! Server is shutting down
} wtf_server_state_t;

//! Client operational states
typedef enum {
    WTF_CLIENT_DISCONNECTED,  //! Client is not connected
    WTF_CLIENT_CONNECTING,    //! QUIC/HTTP/3/WebTransport handshake is in progress
    WTF_CLIENT_CONNECTED,     //! WebTransport session is active and ready
    WTF_CLIENT_CLOSING,       //! Client is closing
    WTF_CLIENT_CLOSED         //! Client has closed
} wtf_client_state_t;

//! Session lifecycle states
typedef enum {
    WTF_SESSION_HANDSHAKING,  //! Initial connection handshake
    WTF_SESSION_CONNECTED,    //! Session is active and ready
    WTF_SESSION_DRAINING,     //! Session is draining before close
    WTF_SESSION_CLOSED        //! Session has been closed
} wtf_session_state_t;

//! Stream operational states
typedef enum {
    WTF_STREAM_OPEN,     //! Stream is active
    WTF_STREAM_CLOSING,  //! Stream is closing gracefully
    WTF_STREAM_CLOSED    //! Stream is fully closed
} wtf_stream_state_t;

//! Stream direction types
typedef enum {
    WTF_STREAM_BIDIRECTIONAL = 0,  //! Data can flow in both directions
    WTF_STREAM_UNIDIRECTIONAL = 1  //! Data flows in one direction only
} wtf_stream_type_t;

//! Connection validation decisions
typedef enum {
    WTF_CONNECTION_ACCEPT,  //! Accept the incoming connection
    WTF_CONNECTION_REJECT,  //! Reject the incoming connection
    WTF_CONNECTION_DEFER    //! Defer the decision; complete request->handle asynchronously
} wtf_connection_decision_t;

//! WebTransport-over-HTTP/3 draft selection.
//! AUTO advertises all supported drafts and selects the newest draft the peer supports.
typedef enum {
    WTF_WEBTRANSPORT_DRAFT_AUTO = 0,
    WTF_WEBTRANSPORT_DRAFT_02 = 2,
    WTF_WEBTRANSPORT_DRAFT_07 = 7,
    WTF_WEBTRANSPORT_DRAFT_15 = 15
} wtf_webtransport_draft_t;

//! WebTransport congestion-control preference.
//! This is a hint; the transport may fall back to its default algorithm.
typedef enum {
    WTF_CONGESTION_CONTROL_DEFAULT = 0,
    WTF_CONGESTION_CONTROL_THROUGHPUT = 1,
    WTF_CONGESTION_CONTROL_LOW_LATENCY = 2
} wtf_congestion_control_t;

//! Stream send-buffering preference.
//! ENABLED allows send completion after the transport copies the payload.
//! DISABLED delays completion until the transport releases the queued data,
//! allowing the application to bound outstanding sends. DEFAULT uses the
//! transport default. Completion always permits buffer reuse; it does not
//! confirm delivery to the peer application.
typedef enum {
    WTF_SEND_BUFFERING_DEFAULT = 0,
    WTF_SEND_BUFFERING_ENABLED = 1,
    WTF_SEND_BUFFERING_DISABLED = 2
} wtf_send_buffering_t;

//! HTTP/3 error codes as defined in RFC 9114
typedef enum {
    WTF_H3_NO_ERROR = 0x0100,
    WTF_H3_GENERAL_PROTOCOL_ERROR = 0x0101,
    WTF_H3_INTERNAL_ERROR = 0x0102,
    WTF_H3_STREAM_CREATION_ERROR = 0x0103,
    WTF_H3_CLOSED_CRITICAL_STREAM = 0x0104,
    WTF_H3_FRAME_UNEXPECTED = 0x0105,
    WTF_H3_FRAME_ERROR = 0x0106,
    WTF_H3_EXCESSIVE_LOAD = 0x0107,
    WTF_H3_ID_ERROR = 0x0108,
    WTF_H3_SETTINGS_ERROR = 0x0109,
    WTF_H3_MISSING_SETTINGS = 0x010a,
    WTF_H3_REQUEST_REJECTED = 0x010b,
    WTF_H3_REQUEST_CANCELLED = 0x010c,
    WTF_H3_REQUEST_INCOMPLETE = 0x010d,
    WTF_H3_MESSAGE_ERROR = 0x010e,
    WTF_H3_CONNECT_ERROR = 0x010f,
    WTF_H3_VERSION_FALLBACK = 0x0110
} wtf_h3_error_t;

//! Datagram send states for tracking datagram lifecycle
typedef enum {
    WTF_DATAGRAM_SEND_UNKNOWN = 0,  //! Not yet sent.
    //! Indicates the datagram has now been sent out on the network. This is not a final state; keep
    //! payload bytes alive until WTF_DATAGRAM_SEND_STATE_IS_FINAL(state) is true.
    WTF_DATAGRAM_SEND_SENT = 1,
    //! The sent datagram is suspected to be lost. If desired, the app could retransmit the data
    //! now.
    WTF_DATAGRAM_SEND_LOST_SUSPECTED = 2,
    //! The datagram is confirmed lost and no longer tracked. The app should not retransmit.
    WTF_DATAGRAM_SEND_LOST_DISCARDED = 3,
    //! The sent datagram has been acknowledged.
    WTF_DATAGRAM_SEND_ACKNOWLEDGED = 4,
    //! The sent datagram has been acknowledged after previously being suspected as lost.
    WTF_DATAGRAM_SEND_ACKNOWLEDGED_SPURIOUS = 5,
    //! The queued datagram was canceled; either because the connection was shutdown or the peer did
    //! not negotiate the feature.
    WTF_DATAGRAM_SEND_CANCELED = 6,
    //! Network.framework processed the send; acknowledgment/loss is unavailable.
    //! Final state: the payload may be released, without inferring peer receipt.
    WTF_DATAGRAM_SEND_UNTRACKED = 7
} wtf_datagram_send_state_t;

#define WTF_DATAGRAM_SEND_STATE_IS_FINAL(State) ((State) >= WTF_DATAGRAM_SEND_LOST_DISCARDED)

//! QPACK error codes as defined in RFC 9204
typedef enum {
    WTF_QPACK_DECOMPRESSION_FAILED = 0x0200,
    WTF_QPACK_ENCODER_STREAM_ERROR = 0x0201,
    WTF_QPACK_DECODER_STREAM_ERROR = 0x0202
} wtf_qpack_error_t;

//! H3 Datagram error codes as defined in RFC 9297
typedef enum {
    WTF_H3_DATAGRAM_ERROR = 0x33
} wtf_h3_datagram_error_t;

//! WebTransport specific error codes
#define WTF_WEBTRANSPORT_FLOW_CONTROL_ERROR 0x045d4487
#define WTF_WEBTRANSPORT_ALPN_ERROR 0x0817b3dd
#define WTF_WEBTRANSPORT_REQUIREMENTS_NOT_MET 0x212c0d48
#define WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED 0x3994bd84
#define WTF_WEBTRANSPORT_SESSION_GONE 0x170d7b68
#define WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE 0x52e4a40fa8db
#define WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX 0x52e5ac983162

//! Capsule types for the Capsule Protocol
typedef enum {
    WTF_CAPSULE_DATAGRAM = 0x00,
    WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION = 0x2843,
    WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION = 0x78ae,
    WTF_CAPSULE_WT_MAX_DATA = 0x190B4D3D,
    WTF_CAPSULE_WT_MAX_STREAMS_BIDI = 0x190B4D3F,
    WTF_CAPSULE_WT_MAX_STREAMS_UNI = 0x190B4D40,
    WTF_CAPSULE_WT_DATA_BLOCKED = 0x190B4D41,
    WTF_CAPSULE_WT_STREAMS_BLOCKED_BIDI = 0x190B4D43,
    WTF_CAPSULE_WT_STREAMS_BLOCKED_UNI = 0x190B4D44
} wtf_capsule_type_t;

//! Session event types for callback notifications
typedef enum {
    WTF_SESSION_EVENT_CONNECTED,                   //! Session established successfully
    WTF_SESSION_EVENT_DISCONNECTED,                //! Session has been disconnected
    WTF_SESSION_EVENT_DRAINING,                    //! Session is being drained
    WTF_SESSION_EVENT_STREAM_OPENED,               //! New stream created on session
    WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE,  //! This event indicates a state change for a
                                                   //! previous unreliable datagram send
    WTF_SESSION_EVENT_DATAGRAM_RECEIVED,           //! Datagram received on session
} wtf_session_event_type_t;

//! Stream event types for callback notifications
typedef enum {
    WTF_STREAM_EVENT_DATA_RECEIVED,  //! Data received on stream
    WTF_STREAM_EVENT_SEND_COMPLETE,  //! Payload may be reused; does not confirm peer receipt
    WTF_STREAM_EVENT_PEER_CLOSED,    //! Peer closed their end of stream
    WTF_STREAM_EVENT_CLOSED,         //! Stream fully closed
    WTF_STREAM_EVENT_ABORTED         //! Stream was aborted with error
} wtf_stream_event_type_t;

// #endregion

// #region Data Structures

//! Data buffer for network operations
typedef struct {
    uint32_t length;      //! Size of data in bytes
    const uint8_t* data;  //! Pointer to read-only buffer data
} wtf_buffer_t;

//! HTTP header for connection validation
typedef struct {
    const char* name;   //! Header name
    const char* value;  //! Header value
} wtf_http_header_t;

//! Mutable CONNECT response metadata for connection validation callbacks.
//! Initialize and free only through libwtf; add custom headers with
//! wtf_connection_response_add_header().
typedef struct {
    wtf_http_header_t* headers;  //! Response headers owned by libwtf; valid only during callback
    size_t header_count;         //! Number of response headers
    size_t header_capacity;      //! Internal header capacity
} wtf_connection_response_t;

//! Connection request information for validation
typedef struct {
    const char* origin;                //! Origin of the request; valid only during callback
    const char* path;                  //! Request path; valid only during callback
    const char* authority;             //! Authority header value; valid only during callback
    const wtf_http_header_t* headers;  //! Array of HTTP headers; valid only during callback
    size_t header_count;               //! Number of headers
    void* peer_address;                //! Peer network address; valid only during callback
    size_t address_length;             //! Size of address structure
    wtf_connection_request_handle_t* handle;  //! Complete this handle if returning DEFER
} wtf_connection_request_t;

//! Session event data structure
typedef struct {
    wtf_session_event_type_t type;  //! Type of session event
    wtf_session_t* session;         //! Borrowed; call wtf_session_ref() to keep after callback
    void* user_context;             //! User-provided context data

    union {
        struct {
            uint16_t status_code;              //! CONNECT response status, or 0 when unavailable
            const wtf_http_header_t* headers;  //! CONNECT response headers; valid only during callback
            size_t header_count;               //! Number of CONNECT response headers
        } connected;

        struct {
            uint32_t error_code;               //! Error code for disconnection
            const char* reason;                //! Human-readable reason
            uint16_t status_code;              //! CONNECT response status, or 0 when unavailable
            const wtf_http_header_t* headers;  //! CONNECT response headers; valid only during callback
            size_t header_count;               //! Number of CONNECT response headers
        } disconnected;

        struct {
            wtf_stream_t* stream;           //! Borrowed; call wtf_stream_ref() to keep after callback
            wtf_stream_type_t stream_type;  //! Type of the new stream
        } stream_opened;

        struct {
            const wtf_buffer_t* buffers;      //! Sent datagram buffers; valid only during callback
            uint32_t buffer_count;            //! Number of buffers sent
            wtf_datagram_send_state_t state;  //! New state of the datagram send
            void* operation_context;          //! Context passed to wtf_session_send_datagram
        } datagram_send_state_changed;

        struct {
            uint32_t length;     //! Size of data in bytes
            const uint8_t* data;  //! Valid only until the session callback returns
        } datagram_received;
    };
} wtf_session_event_t;

//! Stream event data structure
typedef struct {
    wtf_stream_event_type_t type;  //! Type of stream event
    wtf_stream_t* stream;          //! Borrowed; call wtf_stream_ref() to keep after callback
    void* user_context;            //! User-provided context data

    union {
        struct {
            const wtf_buffer_t* buffers;  //! Received buffers; valid only during callback
            uint32_t buffer_count;        //! Number of buffers
        } data_received;

        struct {
            const wtf_buffer_t* buffers;  //! Sent data buffers; valid only during callback
            uint32_t buffer_count;        //! Number of buffers sent
            bool cancelled;               //! True if send was cancelled
            void* operation_context;      //! Context passed to wtf_stream_send
        } send_complete;

        struct {
            uint32_t error_code;  //! Error code for abort
        } aborted;
    };
} wtf_stream_event_t;

//! Detailed error information
typedef struct {
    uint32_t error_code;        //! Numeric error code
    const char* description;    //! Human-readable description
    bool is_application_error;  //! True if application-level error
    bool is_transport_error;    //! True if transport-level error
    bool is_protocol_error;     //! True if protocol violation
} wtf_error_details_t;

// #endregion

// #region Callback Types

//! Connection validation callback
//! @param request incoming connection request details
//! @param response mutable CONNECT response metadata for extra response headers
//! @param user_context user-provided context data
//! @return decision to accept or reject the connection
typedef wtf_connection_decision_t (*wtf_connection_validator_t)(
    const wtf_connection_request_t* request, wtf_connection_response_t* response,
    void* user_context);

//! Session event notification callback
//! Callbacks run on MsQuic worker threads and may run concurrently for different objects.
//! @param event session event details
typedef void (*wtf_session_callback_t)(const wtf_session_event_t* event);

//! Stream event notification callback
//! Callbacks run on MsQuic worker threads and may run concurrently for different objects.
//! @param event stream event details
typedef void (*wtf_stream_callback_t)(const wtf_stream_event_t* event);

//! Logging callback
//! @param level log message severity level
//! @param component component that generated the log
//! @param file source file name
//! @param line source file line number
//! @param message formatted log message
//! @param user_context user provided context (see wtf_context_config_t::log_user_context)
typedef void (*wtf_log_callback_t)(wtf_log_level_t level, const char* component, const char* file,
                                   int line, const char* message, void* user_context);

// #endregion

// #region Configuration Structures

typedef enum {
    WTF_CERT_TYPE_NONE,            //! No certificate (client only)
    WTF_CERT_TYPE_FILE,            //! Certificate pair loaded from disk (PEM/CER)
    WTF_CERT_TYPE_FILE_PROTECTED,  //! Protected certificate with password
    WTF_CERT_TYPE_HASH,            //! Certificate specified by hash (Windows/Schannel)
    WTF_CERT_TYPE_HASH_STORE,      //! Certificate from specific store by hash
    WTF_CERT_TYPE_CONTEXT,         //! Windows CAPI certificate context
    WTF_CERT_TYPE_PKCS12,          //! PKCS#12/PFX certificate with optional password
} wtf_certificate_type_t;

typedef struct {
    wtf_certificate_type_t cert_type;  //! Type of certificate configuration

    // Union for different certificate data types
    union {
        // File-based certificates
        struct {
            const char* cert_path;  //! Path to certificate file
            const char* key_path;   //! Path to private key file
        } file;

        // Protected file-based certificates
        struct {
            const char* cert_path;  //! Path to certificate file
            const char* key_path;   //! Path to private key file
            const char* password;   //! Password for private key
        } protected_file;

        // Hash-based certificates (Windows/Schannel)
        struct {
            const char* thumbprint;  //! Hex string of certificate thumbprint
        } hash;

        // Store-based certificates (Windows/Schannel)
        struct {
            const char* thumbprint;  //! Hex string of certificate thumbprint
            const char* store_name;  //! Name of certificate store
        } hash_store;

        // PKCS#12/PFX certificates
        struct {
            const void* data;      //! PKCS#12 binary data
            size_t data_size;      //! Size of PKCS#12 data
            const char* password;  //! Optional password for PKCS#12
        } pkcs12;

        // Windows certificate context (opaque pointer)
        void* context;  //! Borrowed platform certificate context; must outlive the server
    } cert_data;

    const char* principal;     //! Principal name for certificate selection
    const char* ca_cert_file;  //! Optional CA certificate file path
} wtf_certificate_config_t;

//! Server configuration parameters
typedef struct {
    const char* host;                       //! Host address to bind to
    uint16_t port;                          //! Port number to listen on

    wtf_certificate_config_t* cert_config;  //! TLS certificate configuration; copied at create time
    wtf_webtransport_draft_t draft;         //! Draft to advertise, or AUTO to advertise all

    // Session limits
    uint32_t max_sessions_per_connection;  //! Maximum sessions per connection
    uint32_t max_streams_per_session;      //! Maximum streams per session
    uint64_t max_data_per_session;         //! Maximum data per session
    uint32_t stream_recv_window;           //! QUIC stream receive window; 0 uses library default
    uint32_t conn_flow_control_window;     //! QUIC connection receive window; 0 uses library default

    // Timeouts
    uint32_t idle_timeout_ms;       //! Idle timeout in milliseconds
    uint32_t handshake_timeout_ms;  //! Handshake timeout in milliseconds

    // Features
    bool enable_0rtt;       //! Enable 0-RTT connections
    bool enable_migration;  //! MsQuic migration toggle; Network.framework manages migration automatically
    wtf_send_buffering_t send_buffering;  //! Stream send-buffering mode; 0 uses transport default

    // Callbacks
    wtf_connection_validator_t connection_validator;  //! Connection validation callback
    wtf_session_callback_t session_callback;          //! Session event callback
    void* user_context;                               //! User context for callbacks
} wtf_server_config_t;

//! Client configuration parameters
typedef struct {
    const char* url;     //! HTTPS URL with explicit port; copied at create time
    const char* origin;  //! Optional Origin header; required for draft-02 compatibility

    const wtf_http_header_t* headers;  //! Extra request headers; copied at create time
    size_t header_count;               //! Number of extra request headers

    wtf_webtransport_draft_t draft;  //! Draft to use, or AUTO to select newest peer-supported draft

    bool allow_pooling;                         //! Allow multiple sessions on the same QUIC connection
    wtf_congestion_control_t congestion_control; //! Congestion-control preference hint
    bool require_unreliable;                    //! Require HTTP/3 datagram support; always true for libwtf H3

    bool skip_certificate_validation;  //! Disable server certificate validation for local testing
    //! Optional CA file for MsQuic/OpenSSL TLS backends; copied at create time.
    //! For Schannel/native store backends, trust private CAs through the OS certificate store.
    const char* ca_cert_file;
    //! Optional PEM/DER leaf certificate file to pin exactly. The file is parsed with native
    //! certificate APIs, native PKI validation is bypassed, and the received leaf certificate
    //! must match the canonical DER certificate from the file.
    const char* pinned_server_certificate_file;

    uint32_t max_sessions_per_connection; //! Pool capacity when allow_pooling is true
    uint32_t max_streams_per_session;   //! Maximum streams for the opened session
    uint64_t max_data_per_session;      //! Maximum data per session
    uint32_t stream_recv_window;        //! QUIC stream receive window; 0 uses library default
    uint32_t conn_flow_control_window;  //! QUIC connection receive window; 0 uses library default

    uint32_t idle_timeout_ms;       //! Idle timeout in milliseconds
    uint32_t handshake_timeout_ms;  //! Handshake/session setup timeout in milliseconds

    bool enable_0rtt;       //! Allow 0-RTT transport use when cached tickets are available
    bool enable_migration;  //! MsQuic migration toggle; Network.framework manages migration automatically
    wtf_send_buffering_t send_buffering;  //! Stream send-buffering mode; 0 uses transport default

    wtf_session_callback_t session_callback;  //! Session event callback
    void* user_context;                       //! User context for callbacks
} wtf_client_config_t;

//! Library context configuration
typedef struct {
    wtf_log_level_t log_level;                  //! Global logging level
    wtf_log_callback_t log_callback;            //! Custom logging callback
    void* log_user_context;                     //! Context for log callback
    uint32_t worker_thread_count;               //! Number of worker threads
    bool enable_load_balancing;                 //! Enable load balancing
    bool disable_encryption;                    //! Disable encryption for testing
    wtf_execution_profile_t execution_profile;  //! Performance profile
} wtf_context_config_t;

//! Library version information
typedef struct {
    uint32_t major;       //! Major version number
    uint32_t minor;       //! Minor version number
    uint32_t patch;       //! Patch version number
    const char* version;  //! Build information string
} wtf_version_info_t;

// #endregion

// #region Core API Functions

//! Get library version information
//! @return pointer to version structure
WTF_API const wtf_version_info_t* wtf_get_version();

//! Create a new WebTransport context
//! @param config context configuration parameters
//! @param context pointer to receive the created context
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_context_create(const wtf_context_config_t* config,
                                        wtf_context_t** context);

//! Destroy a WebTransport context and cleanup all resources
//! @param context context to destroy
WTF_API void wtf_context_destroy(wtf_context_t* context);

//! Set global log level for the context
//! @param context target context
//! @param level new logging level
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_context_set_log_level(wtf_context_t* context, wtf_log_level_t level);

//! Create a new WebTransport server
//! @param context parent context for the server
//! @param config server configuration parameters
//! @param server pointer to receive the created server
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_server_create(wtf_context_t* context, const wtf_server_config_t* config,
                                       wtf_server_t** server);

//! Start the server listening for connections
//! @param server server instance to start
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_server_start(wtf_server_t* server);

//! Stop the server gracefully
//! @param server server instance to stop
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_server_stop(wtf_server_t* server);

//! Get current server state
//! @param server target server instance
//! @return current operational state
WTF_API wtf_server_state_t wtf_server_get_state(wtf_server_t* server);

//! Add a non-pseudo HTTP response header while handling a connection validation callback.
//! The name and value are copied. Header names beginning with ':' are rejected.
//! @param response response object passed to wtf_connection_validator_t
//! @param name HTTP header name
//! @param value HTTP header value
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_connection_response_add_header(wtf_connection_response_t* response,
                                                        const char* name, const char* value);

//! Retain a deferred connection request handle beyond the callback/completion owner.
//! @param handle request handle from wtf_connection_request_t
WTF_API void wtf_connection_request_ref(wtf_connection_request_handle_t* handle);

//! Release a retained deferred connection request handle.
//! @param handle request handle from wtf_connection_request_t
WTF_API void wtf_connection_request_unref(wtf_connection_request_handle_t* handle);

//! Add a response header to a deferred connection request.
//! The name and value are copied. Header names beginning with ':' are rejected.
//! @param handle deferred request handle
//! @param name HTTP header name
//! @param value HTTP header value
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_connection_request_add_response_header(
    wtf_connection_request_handle_t* handle, const char* name, const char* value);

//! Complete an asynchronously deferred connection request.
//! Passing WTF_CONNECTION_ACCEPT sends a 2xx CONNECT response and establishes the session.
//! Passing WTF_CONNECTION_REJECT sends a rejection response. WTF_CONNECTION_DEFER is invalid here.
//! This consumes the callback's deferred handle reference; do not use the handle afterwards unless
//! you retained it with wtf_connection_request_ref().
//! @param handle deferred request handle
//! @param decision accept or reject decision
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_connection_request_complete(wtf_connection_request_handle_t* handle,
                                                     wtf_connection_decision_t decision);

//! Destroy the server and free resources
//! @param server server instance to destroy
WTF_API void wtf_server_destroy(wtf_server_t* server);

//! Create a new WebTransport client.
//! @param context parent context for the client
//! @param config client configuration parameters
//! @param client pointer to receive the created client
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_client_create(wtf_context_t* context, const wtf_client_config_t* config,
                                       wtf_client_t** client);

//! Open an asynchronous WebTransport session and return a retained handshaking session.
//! Completion or failure is reported through the session callback.
//! @param client client instance to open
//! @param session pointer to receive a retained session; release with wtf_session_unref()
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_client_open(wtf_client_t* client, wtf_session_t** session);

//! Compatibility alias for wtf_client_open().
WTF_API wtf_result_t wtf_client_connect(wtf_client_t* client, wtf_session_t** session);

//! Close the client connection.
//! @param client client instance to close
//! @param error_code application error code
//! @param reason optional human-readable reason
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_client_disconnect(wtf_client_t* client, uint32_t error_code,
                                           const char* reason);

//! Get current client state.
//! @param client target client instance
//! @return current client state
WTF_API wtf_client_state_t wtf_client_get_state(wtf_client_t* client);

//! Destroy the client and free resources.
//! @param client client instance to destroy
WTF_API void wtf_client_destroy(wtf_client_t* client);

// #endregion

// #region Session Management API

//! Close a session with optional error code and reason
//! @param session session to close
//! @param error_code application error code
//! @param reason human-readable reason for closure
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_session_close(wtf_session_t* session, uint32_t error_code,
                                       const char* reason);

//! Drain a session - sends DRAIN_WEBTRANSPORT_SESSION capsule
//! @param session session to drain
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_session_drain(wtf_session_t* session);

//! Send a datagram on a session
//! @param session target session
//! @param buffers array of buffers containing datagram data
//! @param buffer_count number of buffers in array
//! @param operation_context caller-owned token returned on send state changes
//! @return WTF_SUCCESS on success, error code on failure
//!
//! @note Memory ownership:
//! - The buffers array and all buffer data are always owned by the caller.
//! - On SUCCESS: The library copies the buffer descriptors, but does not copy payload bytes.
//!   The payload bytes must remain valid until the datagram send reaches a final state
//!   (use WTF_DATAGRAM_SEND_STATE_IS_FINAL macro).
//! - On immediate FAILURE: The caller retains ownership and no send-state callback is delivered.
//! - Event buffer descriptors are borrowed and valid only for the callback duration.
WTF_API wtf_result_t wtf_session_send_datagram(wtf_session_t* session, const wtf_buffer_t* buffers,
                                               uint32_t buffer_count, void* operation_context);

//! Send a datagram using a library-owned payload copy.
//! @param session target session
//! @param data datagram payload bytes; may be NULL only when length is 0
//! @param length datagram payload length in bytes
//! @return WTF_SUCCESS on success, error code on failure
//!
//! @note Memory ownership:
//! - The payload is copied before this function returns.
//! - Send-state callbacks still occur, with operation_context set to NULL.
//! - Event buffers remain borrowed and valid only for the callback duration.
WTF_API wtf_result_t wtf_session_send_datagram_copy(wtf_session_t* session, const void* data,
                                                    size_t length);

//! Retain a session handle beyond the current callback or lookup result.
//! @param session target session
WTF_API void wtf_session_ref(wtf_session_t* session);

//! Release a session handle retained by the application.
//! @param session target session
WTF_API void wtf_session_unref(wtf_session_t* session);

//! Set the session callback and context.
//! Intended for setup-time use before concurrent callbacks are active.
//! @param session target session
//! @param callback event callback function
//! @param user_context user-provided context data
WTF_API void wtf_session_set_callback(wtf_session_t* session, wtf_session_callback_t callback,
                                      void* user_context);

//! Get the maximum datagram payload size currently accepted for a session.
//! The value is derived from the negotiated QUIC datagram send limit minus libwtf's per-session
//! datagram prefix. It can differ between sessions on the same connection when the encoded session
//! id length differs.
//! @param session target session
//! @return maximum datagram payload size in bytes, or 0 when datagrams are unavailable or not yet
//! sendable
WTF_API uint32_t wtf_session_get_max_datagram_size(wtf_session_t* session);

//! Open a new stream on a session
//! @param session parent session for the stream
//! @param type stream type (bidirectional or unidirectional)
//! @param callback optional stream event callback; NULL disables stream notifications
//! @param user_context caller-owned context passed to the stream callback
//! @param stream pointer to receive the created stream; release with wtf_stream_unref()
//! @return WTF_SUCCESS on success, error code on failure
//!
//! The callback and context are installed before the stream starts. Callbacks may run before
//! this function returns; use event->stream inside the callback. Keep user_context valid until
//! callbacks have finished. On failure, no further callbacks occur after this function returns.
WTF_API wtf_result_t wtf_session_create_stream(wtf_session_t* session, wtf_stream_type_t type,
                                               wtf_stream_callback_t callback, void* user_context,
                                               wtf_stream_t** stream);

//! Get session state
//! @param session target session
//! @return current session state
WTF_API wtf_session_state_t wtf_session_get_state(wtf_session_t* session);

//! Get session peer address
//! @param session target session
//! @param address_buffer buffer to receive address data
//! @param buffer_size pointer to buffer size, updated with actual size
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_session_get_peer_address(wtf_session_t* session, void* address_buffer,
                                                  size_t* buffer_size);

//! Read a statistic by its case-sensitive key. The value is written only on success.
//! The following read-only keys describe the underlying QUIC connection and are shared by
//! pooled sessions. Each call samples one key.
//! | Key | Meaning |
//! | --- | --- |
//! | quic.smoothed_rtt_us | Smoothed round-trip time in microseconds |
//! | quic.min_rtt_us | Minimum observed round-trip time in microseconds |
//! | quic.rtt_variance_us | Round-trip time variation in microseconds |
//! | quic.congestion_window_bytes | Send congestion window in bytes |
//! | quic.path_mtu_bytes | Current path MTU in bytes |
//! | quic.congestion_events | Send congestion events |
//! | quic.packets_sent | QUIC packets sent |
//! | quic.packets_lost | QUIC packets declared lost and not later acknowledged |
//! | quic.bytes_sent | UDP payload bytes sent |
//! | quic.bytes_received | UDP payload bytes received |
//! Custom keys starting with app. belong to the individual session and can be read for as long
//! as the caller holds a session reference, including after disconnect.
//! @return WTF_ERROR_NOT_FOUND for an unknown or unset key, WTF_ERROR_INVALID_STATE if the
//! connection is gone, or WTF_ERROR_NOT_SUPPORTED if the backend cannot supply a known metric.
WTF_API wtf_result_t wtf_session_get_stat(wtf_session_t* session, const char* key, uint64_t* value);

//! Insert or replace a custom statistic. The case-sensitive key must start with app. and
//! include a suffix. The session owns a copy of the key.
WTF_API wtf_result_t wtf_session_set_stat(wtf_session_t* session, const char* key, uint64_t value);

//! Remove a custom app. statistic. Returns WTF_ERROR_NOT_FOUND if the key is unset.
WTF_API wtf_result_t wtf_session_remove_stat(wtf_session_t* session, const char* key);

//! Set session user context
//! Intended for setup-time use before concurrent callbacks are active.
//! @param session target session
//! @param user_context user-provided context data
WTF_API void wtf_session_set_context(wtf_session_t* session, void* user_context);

//! Get session user context
//! @param session target session
//! @return user-provided context data  
WTF_API void* wtf_session_get_context(wtf_session_t* session);

// #endregion

// #region Stream Management API

//! Send data on a stream
//! @param stream target stream
//! @param buffers array of data buffers to send
//! @param buffer_count number of buffers in array
//! @param fin true if this is the final data
//! @param operation_context caller-owned token returned on send completion
//! @return WTF_SUCCESS on success, error code on failure
//!
//! @note Memory ownership:
//! - The buffers array and all buffer data are always owned by the caller.
//! - On SUCCESS: The library copies the buffer descriptors, but does not copy payload bytes.
//!   The payload bytes must remain valid until WTF_STREAM_EVENT_SEND_COMPLETE.
//! - On immediate FAILURE: The caller retains ownership and no send-complete callback is delivered.
//! - Event buffer descriptors are borrowed and valid only for the callback duration.
WTF_API wtf_result_t wtf_stream_send(wtf_stream_t* stream, const wtf_buffer_t* buffers,
                                     uint32_t buffer_count, bool fin, void* operation_context);

//! Send data on a stream using a library-owned payload copy.
//! @param stream target stream
//! @param data payload bytes; may be NULL only when length is 0 and fin is true
//! @param length payload length in bytes
//! @param fin true if this send also closes the local send side
//! @return WTF_SUCCESS on success, error code on failure
//!
//! @note Memory ownership:
//! - The payload is copied before this function returns.
//! - Send-complete callbacks still occur for non-empty sends, with operation_context set to NULL.
//! - Passing length 0 with fin true is equivalent to wtf_stream_close().
WTF_API wtf_result_t wtf_stream_send_copy(wtf_stream_t* stream, const void* data, size_t length,
                                          bool fin);

//! Close a stream gracefully (send FIN)
//! @param stream stream to close
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_stream_close(wtf_stream_t* stream);

//! Abort a stream with error code
//! @param stream stream to abort
//! @param error_code application error code
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_stream_abort(wtf_stream_t* stream, uint32_t error_code);

//! Retain a stream handle beyond the current callback or lookup result.
//! @param stream target stream
WTF_API void wtf_stream_ref(wtf_stream_t* stream);

//! Release a stream handle retained by the application.
//! @param stream target stream
WTF_API void wtf_stream_unref(wtf_stream_t* stream);

//! Get the stream ID
//! @param stream target stream
//! @param stream_id pointer to receive the stream ID
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_stream_get_id(wtf_stream_t* stream, uint64_t* stream_id);

//! Set the stream callback.
//! Intended for setup-time use before concurrent callbacks are active.
//! @param stream target stream
//! @param callback event callback function
WTF_API void wtf_stream_set_callback(wtf_stream_t* stream, wtf_stream_callback_t callback);

//! Set stream user context
//! Intended for setup-time use before concurrent callbacks are active.
//! @param stream target stream
//! @param user_context user-provided context data
WTF_API void wtf_stream_set_context(wtf_stream_t* stream, void* user_context);

//! Get stream user context
//! @param stream target stream
//! @return user-provided context data
WTF_API void* wtf_stream_get_context(wtf_stream_t* stream); 

//! Get stream type
//! @param stream target stream
//! @return stream type (bidirectional or unidirectional)
WTF_API wtf_stream_type_t wtf_stream_get_type(wtf_stream_t* stream);

//! Get stream state
//! @param stream target stream
//! @return current stream state
WTF_API wtf_stream_state_t wtf_stream_get_state(wtf_stream_t* stream);

//! Set stream priority - higher values indicate higher priority
//! @param stream target stream
//! @param priority priority value (higher = more priority)
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_stream_set_priority(wtf_stream_t* stream, uint16_t priority);

//! Enable or disable stream receive operations
//! @param stream target stream
//! @param enabled true to enable, false to disable
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_stream_set_receive_enabled(wtf_stream_t* stream, bool enabled);

// #endregion

// #region Advanced Connection Features


//! Find stream by ID within session
//! @param session target session
//! @param stream_id ID of stream to find
//! @return retained stream pointer or NULL if not found; release with wtf_stream_unref()
WTF_API wtf_stream_t* wtf_session_find_stream_by_id(wtf_session_t* session, uint64_t stream_id);

// #endregion

// #region Error and Utility Functions

//! Get error string for result code
//! @param result error code to convert
//! @return human-readable error description
WTF_API const char* wtf_result_to_string(wtf_result_t result);

//! Convert WebTransport error to string
//! @param error_code WebTransport error code
//! @return human-readable error description
WTF_API const char* wtf_webtransport_error_to_string(uint32_t error_code);

//! Get detailed error information
//! @param error_code error code to analyze
//! @param details pointer to error details structure to fill
//! @return WTF_SUCCESS on success, error code on failure
WTF_API wtf_result_t wtf_get_error_details(uint32_t error_code, wtf_error_details_t* details);

//! Check if error code is valid application error
//! @param error_code error code to validate
//! @return true if error code is in valid application range
WTF_API bool wtf_is_valid_application_error(uint32_t error_code);

//! Convert HTTP/3 error to string
//! @param http3_error HTTP/3 error code
//! @return human-readable error description
WTF_API const char* wtf_http3_error_to_string(uint64_t http3_error);

// #endregion

#ifdef __cplusplus
}
#endif

#endif  // WTF_H
