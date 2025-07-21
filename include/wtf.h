#ifndef WTF_H
#define WTF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// #region Forward declarations

//! Forward declarations
typedef struct wtf_context wtf_context_t;
typedef struct wtf_server wtf_server_t;
typedef struct wtf_session wtf_session_t;
typedef struct wtf_stream wtf_stream_t;
typedef struct wtf_http3_connection wtf_http3_connection_t;

// #endregion

// #region Enums

//! Execution profiles for performance optimization
typedef enum {
    WTF_EXECUTION_PROFILE_LOW_LATENCY = 0,    //! Optimized for minimal latency
    WTF_EXECUTION_PROFILE_MAX_THROUGHPUT = 1, //! Optimized for maximum data throughput
    WTF_EXECUTION_PROFILE_REAL_TIME = 2,      //! Real-time processing priority
    WTF_EXECUTION_PROFILE_SCAVENGER = 3       //! Background processing priority
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
    WTF_ERROR_FLOW_CONTROL
} wtf_result_t;

//! Logging levels for debugging and monitoring
typedef enum {
    WTF_LOG_TRACE = 0,    //! Most detailed messages, may contain sensitive data
    WTF_LOG_DEBUG = 1,    //! Interactive investigation during development
    WTF_LOG_INFO = 2,     //! General application flow information
    WTF_LOG_WARN = 3,     //! Abnormal or unexpected events
    WTF_LOG_ERROR = 4,    //! Current flow stopped due to failure
    WTF_LOG_CRITICAL = 5, //! Unrecoverable application or system crash
    WTF_LOG_NONE = 6      //! Disable all logging
} wtf_log_level_t;

//! Server operational states
typedef enum {
    WTF_SERVER_STOPPED,   //! Server is not running
    WTF_SERVER_STARTING,  //! Server is initializing
    WTF_SERVER_LISTENING, //! Server is accepting connections
    WTF_SERVER_STOPPING   //! Server is shutting down
} wtf_server_state_t;

//! Session lifecycle states
typedef enum {
    WTF_SESSION_HANDSHAKING, //! Initial connection handshake
    WTF_SESSION_CONNECTED,   //! Session is active and ready
    WTF_SESSION_DRAINING,    //! Session is draining before close
    WTF_SESSION_CLOSED       //! Session has been closed
} wtf_session_state_t;

//! Stream operational states
typedef enum {
    WTF_STREAM_OPEN,    //! Stream is active
    WTF_STREAM_CLOSING, //! Stream is closing gracefully
    WTF_STREAM_CLOSED   //! Stream is fully closed
} wtf_stream_state_t;

//! Stream direction types
typedef enum {
    WTF_STREAM_BIDIRECTIONAL = 0, //! Data can flow in both directions
    WTF_STREAM_UNIDIRECTIONAL = 1 //! Data flows in one direction only
} wtf_stream_type_t;

//! Connection validation decisions
typedef enum {
    WTF_CONNECTION_ACCEPT, //! Accept the incoming connection
    WTF_CONNECTION_REJECT  //! Reject the incoming connection
} wtf_connection_decision_t;

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

//! QPACK error codes as defined in RFC 9204
typedef enum {
    WTF_QPACK_DECOMPRESSION_FAILED = 0x0200,
    WTF_QPACK_ENCODER_STREAM_ERROR = 0x0201,
    WTF_QPACK_DECODER_STREAM_ERROR = 0x0202
} wtf_qpack_error_t;

//! H3 Datagram error codes as defined in RFC 9297
typedef enum { WTF_H3_DATAGRAM_ERROR = 0x33 } wtf_h3_datagram_error_t;

//! WebTransport specific error codes
typedef enum {
    WTF_WEBTRANSPORT_BUFFERED_STREAM_REJECTED = 0x3994bd84,
    WTF_WEBTRANSPORT_SESSION_GONE = 0x170d7b68,
    WTF_WEBTRANSPORT_APPLICATION_ERROR_BASE = 0x52e4a40fa8db,
    WTF_WEBTRANSPORT_APPLICATION_ERROR_MAX = 0x52e5ac983162
} wtf_webtransport_error_t;

//! Capsule types for the Capsule Protocol
typedef enum {
    WTF_CAPSULE_DATAGRAM = 0x00,
    WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION = 0x2843,
    WTF_CAPSULE_DRAIN_WEBTRANSPORT_SESSION = 0x78ae
} wtf_capsule_type_t;

//! Session event types for callback notifications
typedef enum {
    WTF_SESSION_EVENT_CONNECTED,        //! Session established successfully
    WTF_SESSION_EVENT_DISCONNECTED,     //! Session has been disconnected
    WTF_SESSION_EVENT_DRAINING,         //! Session is being drained
    WTF_SESSION_EVENT_STREAM_OPENED,    //! New stream created on session
    WTF_SESSION_EVENT_DATAGRAM_RECEIVED //! Datagram received on session
} wtf_session_event_type_t;

//! Stream event types for callback notifications
typedef enum {
    WTF_STREAM_EVENT_DATA_RECEIVED, //! Data received on stream
    WTF_STREAM_EVENT_SEND_COMPLETE, //! Send operation completed
    WTF_STREAM_EVENT_PEER_CLOSED,   //! Peer closed their end of stream
    WTF_STREAM_EVENT_CLOSED,        //! Stream fully closed
    WTF_STREAM_EVENT_ABORTED        //! Stream was aborted with error
} wtf_stream_event_type_t;

// #endregion

// #region Data Structures

//! Data buffer for network operations
typedef struct {
    const uint8_t *data; //! Pointer to buffer data
    size_t length;       //! Size of data in bytes
} wtf_buffer_t;

//! HTTP header for connection validation
typedef struct {
    const char *name;  //! Header name
    const char *value; //! Header value
} wtf_http_header_t;

//! Connection request information for validation
typedef struct {
    const char *origin;               //! Origin of the request
    const char *path;                 //! Request path
    const char *authority;            //! Authority header value
    const wtf_http_header_t *headers; //! Array of HTTP headers
    size_t header_count;              //! Number of headers
    void *peer_address;               //! Peer network address
    size_t address_length;            //! Size of address structure
} wtf_connection_request_t;

//! Session event data structure
typedef struct {
    wtf_session_event_type_t type; //! Type of session event
    wtf_session_t *session;        //! Session that generated the event
    void *user_context;            //! User-provided context data
    union {
        struct {
            // Session is ready for streams/datagrams
        } connected;
        struct {
            uint32_t error_code; //! Error code for disconnection
            const char *reason;  //! Human-readable reason
        } disconnected;
        struct {
            // Session is draining
        } draining;
        struct {
            wtf_stream_t *stream;          //! Newly opened stream
            wtf_stream_type_t stream_type; //! Type of the new stream
        } stream_opened;
        struct {
            wtf_buffer_t data; //! Received datagram data
        } datagram_received;
    };
} wtf_session_event_t;

//! Stream event data structure
typedef struct {
    wtf_stream_event_type_t type; //! Type of stream event
    wtf_stream_t *stream;         //! Stream that generated the event
    void *user_context;           //! User-provided context data
    union {
        struct {
            wtf_buffer_t *buffers; //! Array of received data buffers
            size_t buffer_count;   //! Number of buffers
            bool fin;              //! True if this is the final data
        } data_received;
        struct {
            void *send_context; //! Context from send operation
            bool cancelled;     //! True if send was cancelled
        } send_complete;
        struct {
            // Stream closed gracefully by peer
        } peer_closed;
        struct {
            // Stream fully closed
        } closed;
        struct {
            uint32_t error_code; //! Error code for abort
        } aborted;
    };
} wtf_stream_event_t;

//! Detailed error information
typedef struct {
    uint32_t error_code;       //! Numeric error code
    const char *description;   //! Human-readable description
    bool is_application_error; //! True if application-level error
    bool is_transport_error;   //! True if transport-level error
    bool is_protocol_error;    //! True if protocol violation
} wtf_error_details_t;

// #endregion

// #region Callback Types

//! Connection validation callback
//! @param request incoming connection request details
//! @param user_context user-provided context data
//! @return decision to accept or reject the connection
typedef wtf_connection_decision_t (*wtf_connection_validator_t)(const wtf_connection_request_t *request,
                                                                void *user_context);

//! Session event notification callback
//! @param event session event details
typedef void (*wtf_session_callback_t)(const wtf_session_event_t *event);

//! Stream event notification callback
//! @param event stream event details
typedef void (*wtf_stream_callback_t)(const wtf_stream_event_t *event);

//! Logging callback
//! @param level log message severity level
//! @param component component that generated the log
//! @param file source file name
//! @param line source file line number
//! @param message formatted log message
typedef void (*wtf_log_callback_t)(wtf_log_level_t level, const char *component, const char *file, int line,
                                   const char *message);

// #endregion

// #region Configuration Structures

//! Server configuration parameters
typedef struct {
    const char *host;      //! Host address to bind to
    uint16_t port;         //! Port number to listen on
    const char *cert_file; //! Path to certificate file
    const char *key_file;  //! Path to private key file
    const char *cert_hash; //! Certificate hash for validation

    // Session limits
    uint32_t max_sessions_per_connection; //! Maximum sessions per connection
    uint32_t max_streams_per_session;     //! Maximum streams per session
    uint64_t max_data_per_session;        //! Maximum data per session

    // Timeouts
    uint32_t idle_timeout_ms;      //! Idle timeout in milliseconds
    uint32_t handshake_timeout_ms; //! Handshake timeout in milliseconds

    // Features
    bool enable_0rtt;      //! Enable 0-RTT connections
    bool enable_migration; //! Enable connection migration

    // Callbacks
    wtf_connection_validator_t connection_validator; //! Connection validation callback
    wtf_session_callback_t session_callback;         //! Session event callback
    void *user_context;                              //! User context for callbacks
} wtf_server_config_t;

//! Library context configuration
typedef struct {
    wtf_log_level_t log_level;                 //! Global logging level
    wtf_log_callback_t log_callback;           //! Custom logging callback
    void *log_user_context;                    //! Context for log callback
    uint32_t worker_thread_count;              //! Number of worker threads
    bool enable_load_balancing;                //! Enable load balancing
    bool disable_encryption;                   //! Disable encryption for testing
    wtf_execution_profile_t execution_profile; //! Performance profile
} wtf_context_config_t;

//! Server performance statistics
typedef struct {
    uint32_t active_sessions;             //! Currently active sessions
    uint64_t total_sessions_accepted;     //! Total sessions accepted
    uint64_t total_sessions_rejected;     //! Total sessions rejected
    uint64_t total_connections_attempted; //! Total connection attempts
    uint64_t total_bytes_sent;            //! Total bytes transmitted
    uint64_t total_bytes_received;        //! Total bytes received
} wtf_server_statistics_t;

//! Library version information
typedef struct {
    uint32_t major;             //! Major version number
    uint32_t minor;             //! Minor version number
    uint32_t patch;             //! Patch version number
    const char *version;     //! Build information string
} wtf_version_info_t;

// #endregion

// #region Core API Functions

//! Get library version information
//! @return pointer to version structure
wtf_version_info_t *wtf_get_version();

//! Create a new WebTransport context
//! @param config context configuration parameters
//! @param context pointer to receive the created context
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_context_create(const wtf_context_config_t *config, wtf_context_t **context);

//! Destroy a WebTransport context and cleanup all resources
//! @param context context to destroy
void wtf_context_destroy(wtf_context_t *context);

//! Set global log level for the context
//! @param context target context
//! @param level new logging level
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_context_set_log_level(wtf_context_t *context, wtf_log_level_t level);

//! Create a new WebTransport server
//! @param context parent context for the server
//! @param config server configuration parameters
//! @param server pointer to receive the created server
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_server_create(wtf_context_t *context, const wtf_server_config_t *config, wtf_server_t **server);

//! Start the server listening for connections
//! @param server server instance to start
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_server_start(wtf_server_t *server);

//! Stop the server gracefully
//! @param server server instance to stop
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_server_stop(wtf_server_t *server);

//! Get current server state
//! @param server target server instance
//! @return current operational state
wtf_server_state_t wtf_server_get_state(wtf_server_t *server);

//! Get server statistics
//! @param server target server instance
//! @param stats pointer to statistics structure to fill
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_server_get_statistics(wtf_server_t *server, wtf_server_statistics_t *stats);

//! Destroy the server and free resources
//! @param server server instance to destroy
void wtf_server_destroy(wtf_server_t *server);

// #endregion

// #region Session Management API

//! Close a session with optional error code and reason
//! @param session session to close
//! @param error_code application error code
//! @param reason human-readable reason for closure
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_session_close(wtf_session_t *session, uint32_t error_code, const char *reason);

//! Drain a session - sends DRAIN_WEBTRANSPORT_SESSION capsule
//! @param session session to drain
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_session_drain(wtf_session_t *session);

//! Send a datagram on a session
//! @param session target session
//! @param data buffer containing datagram data
//! @return WTF_SUCCESS on success, error code on failure
//! @note The data buffer must remain valid until send completion
wtf_result_t wtf_session_send_datagram(wtf_session_t *session, const wtf_buffer_t *data);

//! Open a new stream on a session
//! @param session parent session for the stream
//! @param type stream type (bidirectional or unidirectional)
//! @param stream pointer to receive the created stream
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_session_create_stream(wtf_session_t *session, wtf_stream_type_t type, wtf_stream_t **stream);

//! Get session state
//! @param session target session
//! @return current session state
wtf_session_state_t wtf_session_get_state(wtf_session_t *session);

//! Get session peer address
//! @param session target session
//! @param address_buffer buffer to receive address data
//! @param buffer_size pointer to buffer size, updated with actual size
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_session_get_peer_address(wtf_session_t *session, void *address_buffer, size_t *buffer_size);

//! Set session user context
//! @param session target session
//! @param user_context user-provided context data
void wtf_session_set_context(wtf_session_t *session, void *user_context);

// #endregion

// #region Stream Management API

//! Send data on a stream
//! @param stream target stream
//! @param buffers array of data buffers to send
//! @param buffer_count number of buffers in array
//! @param fin true if this is the final data
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_send(wtf_stream_t *stream, const wtf_buffer_t *buffers, size_t buffer_count, bool fin);

//! Close a stream gracefully (send FIN)
//! @param stream stream to close
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_close(wtf_stream_t *stream);

//! Abort a stream with error code
//! @param stream stream to abort
//! @param error_code application error code
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_abort(wtf_stream_t *stream, uint32_t error_code);

//! Get the stream ID
//! @param stream target stream
//! @param stream_id pointer to receive the stream ID
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_get_id(wtf_stream_t *stream, uint64_t *stream_id);

//! Set the stream callback
//! @param stream target stream
//! @param callback event callback function
void wtf_stream_set_callback(wtf_stream_t *stream, wtf_stream_callback_t callback);

//! Set stream user context
//! @param stream target stream
//! @param user_context user-provided context data
void wtf_stream_set_context(wtf_stream_t *stream, void *user_context);

//! Get stream type
//! @param stream target stream
//! @return stream type (bidirectional or unidirectional)
wtf_stream_type_t wtf_stream_get_type(wtf_stream_t *stream);

//! Get stream state
//! @param stream target stream
//! @return current stream state
wtf_stream_state_t wtf_stream_get_state(wtf_stream_t *stream);

//! Set stream priority - higher values indicate higher priority
//! @param stream target stream
//! @param priority priority value (higher = more priority)
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_set_priority(wtf_stream_t *stream, uint16_t priority);

//! Get stream statistics
//! @param stream target stream
//! @param bytes_sent pointer to receive bytes sent count
//! @param bytes_received pointer to receive bytes received count
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_get_statistics(wtf_stream_t *stream, uint64_t *bytes_sent, uint64_t *bytes_received);

//! Enable or disable stream receive operations
//! @param stream target stream
//! @param enabled true to enable, false to disable
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_stream_set_receive_enabled(wtf_stream_t *stream, bool enabled);

// #endregion

// #region Advanced Connection Features

//! Get connection session limits
//! @param conn target connection
//! @param max_sessions pointer to receive maximum sessions limit
//! @param current_sessions pointer to receive current session count
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_connection_get_session_limit(wtf_http3_connection_t *conn, uint32_t *max_sessions,
                                              uint32_t *current_sessions);

//! Check if connection can accept new sessions
//! @param conn target connection
//! @return true if connection can accept new sessions
bool wtf_connection_can_accept_session(wtf_http3_connection_t *conn);

//! Get all active sessions on a connection
//! @param conn target connection
//! @param sessions array to receive session pointers
//! @param session_count pointer to receive actual session count
//! @param max_sessions maximum sessions that can fit in array
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_connection_get_sessions(wtf_http3_connection_t *conn, wtf_session_t **sessions, size_t *session_count,
                                         size_t max_sessions);

//! Find session by ID in connection
//! @param conn target connection
//! @param session_id ID of session to find
//! @return session pointer or NULL if not found
wtf_session_t *wtf_connection_find_session_by_id(wtf_http3_connection_t *conn, uint64_t session_id);

//! Find stream by ID within session
//! @param session target session
//! @param stream_id ID of stream to find
//! @return stream pointer or NULL if not found
wtf_stream_t *wtf_session_find_stream_by_id(wtf_session_t *session, uint64_t stream_id);

// #endregion

// #region Error and Utility Functions

//! Get error string for result code
//! @param result error code to convert
//! @return human-readable error description
const char *wtf_result_to_string(wtf_result_t result);

//! Convert WebTransport error to string
//! @param error_code WebTransport error code
//! @return human-readable error description
const char *wtf_webtransport_error_to_string(uint32_t error_code);

//! Get detailed error information
//! @param error_code error code to analyze
//! @param details pointer to error details structure to fill
//! @return WTF_SUCCESS on success, error code on failure
wtf_result_t wtf_get_error_details(uint32_t error_code, wtf_error_details_t *details);

//! Check if error code is valid application error
//! @param error_code error code to validate
//! @return true if error code is in valid application range
bool wtf_is_valid_application_error(uint32_t error_code);

//! Convert HTTP/3 error to string
//! @param http3_error HTTP/3 error code
//! @return human-readable error description
const char *wtf_http3_error_to_string(uint64_t http3_error);

// #endregion

#ifdef __cplusplus
}
#endif

#endif // WTF_H