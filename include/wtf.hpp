#ifndef LIBWTF_INCLUDE_WTF_HPP_
#define LIBWTF_INCLUDE_WTF_HPP_

//! @file wtf.hpp
//! C++23 ownership and callback wrappers for the public libwtf C API.

#include <atomic>
#include <chrono>
#include <concepts>
#include <cstddef>
#include <cstdint>
#include <exception>
#include <expected>
#include <functional>
#include <limits>
#include <memory>
#include <mutex>
#include <optional>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>
#include <version>

#include "wtf.h"

#if !defined(__cpp_lib_expected) || !defined(__cpp_lib_move_only_function)
#error "wtf.hpp requires C++23 std::expected and std::move_only_function"
#endif

namespace wtf {

//! Borrowed, read-only payload bytes.
using Bytes = std::span<const std::byte>;
//! Owned payload storage; moving it into a send transfers its allocation.
using ByteBuffer = std::vector<std::byte>;

//! A libwtf operation failure. Descriptions use library-owned static storage.
struct Error {
    wtf_result_t code;  //!< Original C API result code.
    //! Return the description associated with code.
    [[nodiscard]] std::string_view message() const noexcept {
        return wtf_result_to_string(code);
    }
    bool operator==(const Error&) const = default;
};

//! Value or transport error. An empty Result<> represents successful
//! completion.
template <typename T = void>
using Result = std::expected<T, Error>;

//! Direction of an application stream.
enum class StreamType {
    kBidirectional = WTF_STREAM_BIDIRECTIONAL,
    kUnidirectional = WTF_STREAM_UNIDIRECTIONAL,
};

//! WebTransport draft advertised during connection setup.
enum class Draft {
    kAuto = WTF_WEBTRANSPORT_DRAFT_AUTO,
    k02 = WTF_WEBTRANSPORT_DRAFT_02,
    k07 = WTF_WEBTRANSPORT_DRAFT_07,
    k15 = WTF_WEBTRANSPORT_DRAFT_15,
};

//! Send completion timing. Completion permits buffer reuse, not peer delivery.
enum class SendBuffering {
    kDefault = WTF_SEND_BUFFERING_DEFAULT,
    kEnabled = WTF_SEND_BUFFERING_ENABLED,
    kDisabled = WTF_SEND_BUFFERING_DISABLED,
};

//! Transport congestion-control preference. Network.framework accepts kDefault
//! and rejects explicit presets with WTF_ERROR_NOT_SUPPORTED.
enum class CongestionControl {
    kDefault = WTF_CONGESTION_CONTROL_DEFAULT,
    kThroughput = WTF_CONGESTION_CONTROL_THROUGHPUT,
    kLowLatency = WTF_CONGESTION_CONTROL_LOW_LATENCY,
};

//! WebTransport session lifecycle.
enum class SessionState {
    kHandshaking = WTF_SESSION_HANDSHAKING,
    kConnected = WTF_SESSION_CONNECTED,
    kDraining = WTF_SESSION_DRAINING,
    kClosed = WTF_SESSION_CLOSED,
};

//! Application stream lifecycle.
enum class StreamState {
    kOpen = WTF_STREAM_OPEN,
    kClosing = WTF_STREAM_CLOSING,
    kClosed = WTF_STREAM_CLOSED,
};

//! Borrowed receive buffers, preserving their original scatter/gather layout.
//! The descriptors, bytes, and ranges returned by this class expire when the
//! receive callback returns. Copy bytes explicitly to keep them.
class BufferSequence {
  public:
    //! Borrow a descriptor array and its payloads.
    explicit BufferSequence(std::span<const wtf_buffer_t> buffers) noexcept
        : buffers_(buffers) {
    }
    //! Iterate over the payload spans without joining or copying them.
    [[nodiscard]] auto chunks() const noexcept {
        return buffers_ | std::views::transform([](const wtf_buffer_t& buffer) {
            return Bytes(
                reinterpret_cast<const std::byte*>(buffer.data),
                buffer.length
            );
        });
    }
    //! Return the borrowed C buffer descriptors.
    [[nodiscard]] std::span<const wtf_buffer_t> native_buffers() const noexcept {
        return buffers_;
    }
    //! Return the total payload length across all descriptors.
    [[nodiscard]] std::size_t size_bytes() const noexcept {
        std::size_t size = 0;
        for (const auto& buffer : buffers_) {
            size += buffer.length;
        }
        return size;
    }

  private:
    std::span<const wtf_buffer_t> buffers_;
};

//! An owned HTTP header used when creating a client.
struct Header {
    std::string name;   //!< Field name, excluding pseudo-headers.
    std::string value;  //!< Field value.
};

//! CONNECT response metadata, borrowed for the duration of its callback.
struct ConnectResponse {
    //! Absent if no HTTP status is available.
    std::optional<std::uint16_t> status_code = std::nullopt;
    //! Header storage is valid only during the callback.
    std::span<const wtf_http_header_t> headers;
};

//! Session disconnection details, borrowed for the duration of on_disconnected.
struct DisconnectInfo {
    std::uint32_t error_code;  //!< Application or protocol error code.
    //! Absent if no reason was supplied.
    std::optional<std::string_view> reason = std::nullopt;
    //! CONNECT failure response, when available.
    std::optional<ConnectResponse> response = std::nullopt;
};

//! Stream send completion. The caller may now reuse borrowed payload storage.
//! Completion does not confirm delivery to the peer application.
struct SendCompletion {
    bool cancelled;  //!< True when the transport cancelled the send.
    void* context;   //!< Token supplied in SendOptions.
};

//! A datagram send state change. Only a final state permits payload reuse.
//! Network.framework reports WTF_DATAGRAM_SEND_UNTRACKED as its final state;
//! acknowledgment and loss information are unavailable.
struct DatagramCompletion {
    wtf_datagram_send_state_t state;  //!< Send state reported by the backend.
    void* context;                    //!< Token supplied in DatagramOptions.
    //! Return whether tracking is finished and the payload can be released.
    [[nodiscard]] bool final() const noexcept {
        return WTF_DATAGRAM_SEND_STATE_IS_FINAL(state);
    }
};

//! Options for an owned or borrowed stream send.
struct SendOptions {
    bool fin = false;         //!< Finish the local send side after this payload.
    void* context = nullptr;  //!< Returned unchanged in send completion events.
    //! Called once after an accepted send releases its payload, including
    //! cancellation. May run before Send() returns. Immediate failure does not
    //! invoke it.
    std::move_only_function<void(SendCompletion) noexcept> on_complete = {};
};

//! Options for an owned or borrowed datagram send.
struct DatagramOptions {
    void* context = nullptr;  //!< Returned unchanged in send state events.
    //! Called once at a final send state. Immediate failure does not invoke it.
    std::move_only_function<void(DatagramCompletion) noexcept> on_complete = {};
};

//! Transport settings shared by client and server creation.
//! Absent limits, windows, and timeouts select libwtf defaults.
//! Explicit limits and timeouts must be positive.
struct TransportOptions {
    //! AUTO selects the newest mutually supported draft.
    Draft draft = Draft::kAuto;
    //! Session/pool capacity.
    std::optional<std::uint32_t> max_sessions_per_connection = std::nullopt;
    //! Active stream limit.
    std::optional<std::uint32_t> max_streams_per_session = std::nullopt;
    //! Session receive credit.
    std::optional<std::uint64_t> max_data_per_session = std::nullopt;
    //! QUIC per-stream receive window.
    std::optional<std::uint32_t> stream_recv_window = std::nullopt;
    //! QUIC connection receive window.
    std::optional<std::uint32_t> conn_flow_control_window = std::nullopt;
    //! Connection idle timeout.
    std::optional<std::chrono::milliseconds> idle_timeout = std::nullopt;
    //! Handshake/session setup deadline.
    std::optional<std::chrono::milliseconds> handshake_timeout = std::nullopt;
    //! Permit early transport data when a cached resumption ticket is available.
    bool enable_0rtt = false;
    //! Toggle MsQuic migration. Network.framework manages migration automatically.
    bool enable_migration = false;
    //! Send completion timing preference.
    SendBuffering send_buffering = SendBuffering::kDefault;
};

//! Owned certificate configuration. File names, passwords, hashes, and PKCS#12
//! bytes are stored by value. NativeIdentity alone borrows a platform object.
struct Certificate {
    //! Certificate and unencrypted private-key files.
    struct PemFiles {
        std::string certificate;  //!< PEM/CER certificate path.
        std::string key;          //!< PEM private-key path.
    };
    //! Certificate and password-protected private-key files.
    struct ProtectedPemFiles {
        std::string certificate;
        std::string key;
        std::string password;
    };
    //! Owned PKCS#12/PFX bytes and their import password.
    struct Pkcs12Data {
        ByteBuffer data;
        std::optional<std::string> password = std::nullopt;
    };
    //! Windows/Schannel certificate thumbprint.
    struct HashValue {
        std::string thumbprint;
    };
    //! Windows/Schannel certificate thumbprint and certificate-store name.
    struct StoreHash {
        std::string thumbprint;
        std::string store;
    };
    //! Borrowed platform identity. It must outlive the server.
    struct NativeIdentity {
        void* context;
    };

    //! Certificate representation; monostate means no identity was supplied.
    std::variant<
        std::monostate,
        PemFiles,
        ProtectedPemFiles,
        Pkcs12Data,
        HashValue,
        StoreHash,
        NativeIdentity
    > identity = {};

    //! Certificate principal, when specified.
    std::optional<std::string> principal = std::nullopt;
    //! CA file where the TLS backend supports it.
    std::optional<std::string> ca_cert_file = std::nullopt;

    //! Return a C configuration borrowing this object's storage.
    //! The result is valid only while this Certificate exists and is unmodified.
    [[nodiscard]] wtf_certificate_config_t native_config() const noexcept {
        wtf_certificate_config_t config{
            .cert_type = WTF_CERT_TYPE_NONE,
            .cert_data = {},
            .principal = nullptr,
            .ca_cert_file = nullptr,
        };
        if (principal) {
            config.principal = principal->c_str();
        }
        if (ca_cert_file) {
            config.ca_cert_file = ca_cert_file->c_str();
        }
        std::visit(
            [&config]<typename T>(const T& value) {
                if constexpr (std::same_as<T, PemFiles>) {
                    config.cert_type = WTF_CERT_TYPE_FILE;
                    config.cert_data.file = {
                        .cert_path = value.certificate.c_str(),
                        .key_path = value.key.c_str(),
                    };
                } else if constexpr (std::same_as<T, ProtectedPemFiles>) {
                    config.cert_type = WTF_CERT_TYPE_FILE_PROTECTED;
                    config.cert_data.protected_file = {
                        .cert_path = value.certificate.c_str(),
                        .key_path = value.key.c_str(),
                        .password = value.password.c_str(),
                    };
                } else if constexpr (std::same_as<T, Pkcs12Data>) {
                    config.cert_type = WTF_CERT_TYPE_PKCS12;
                    config.cert_data.pkcs12 = {
                        .data = value.data.data(),
                        .data_size = value.data.size(),
                        .password = nullptr,
                    };
                    if (value.password) {
                        config.cert_data.pkcs12.password = value.password->c_str();
                    }
                } else if constexpr (std::same_as<T, HashValue>) {
                    config.cert_type = WTF_CERT_TYPE_HASH;
                    config.cert_data.hash = {
                        .thumbprint = value.thumbprint.c_str(),
                    };
                } else if constexpr (std::same_as<T, StoreHash>) {
                    config.cert_type = WTF_CERT_TYPE_HASH_STORE;
                    config.cert_data.hash_store = {
                        .thumbprint = value.thumbprint.c_str(),
                        .store_name = value.store.c_str(),
                    };
                } else if constexpr (std::same_as<T, NativeIdentity>) {
                    config.cert_type = WTF_CERT_TYPE_CONTEXT;
                    config.cert_data.context = value.context;
                }
            },
            identity
        );
        return config;
    }
};

//! Client configuration. Create() copies configuration into the C library;
//! this object need not outlive the client.
struct ClientOptions {
    //! HTTPS URL with an explicit port.
    std::string url;
    //! Origin header; required for draft-02 peers.
    std::optional<std::string> origin = std::nullopt;
    //! Additional non-pseudo CONNECT request headers.
    std::vector<Header> headers = {};
    //! Limits, timeouts, and transport features.
    TransportOptions transport = {};
    //! Permit multiple sessions on one connection.
    bool allow_pooling = false;
    //! Backend congestion-control preference.
    CongestionControl congestion_control = CongestionControl::kDefault;
    //! Require HTTP/3 datagrams, as libwtf currently does.
    bool require_unreliable = true;
    //! Disable validation for local testing.
    bool skip_certificate_validation = false;
    //! CA file for backends supporting custom CAs.
    std::optional<std::string> ca_cert_file = std::nullopt;
    //! PEM/DER leaf certificate to pin exactly.
    std::optional<std::string> pinned_server_certificate_file = std::nullopt;
};

//! Server configuration. Create() copies it into the C library.
struct ServerOptions {
    //! Bind address; absent uses the C library default.
    std::optional<std::string> host = std::nullopt;
    //! UDP listening port.
    std::uint16_t port = 4433;
    //! Server TLS identity.
    Certificate certificate = {};
    //! Limits, timeouts, and transport features.
    TransportOptions transport = {};
};

//! A log message whose string views expire when on_log returns.
struct LogMessage {
    wtf_log_level_t level;
    std::optional<std::string_view> component = std::nullopt;
    std::optional<std::string_view> file = std::nullopt;
    std::optional<int> line = std::nullopt;
    std::optional<std::string_view> message = std::nullopt;
};

//! Context-wide transport and logging configuration.
struct ContextOptions {
    //! Minimum emitted log severity.
    wtf_log_level_t log_level = WTF_LOG_LEVEL_INFO;
    //! May run during Create(), teardown, and concurrently on transport threads.
    std::move_only_function<void(const LogMessage&) noexcept> on_log = {};
    //! Positive worker count; absent lets the transport choose.
    std::optional<std::uint32_t> worker_thread_count = std::nullopt;
    //! Request backend load balancing.
    bool enable_load_balancing = false;
    //! Disable transport encryption for testing.
    bool disable_encryption = false;
    //! Transport worker scheduling preference.
    wtf_execution_profile_t execution_profile = WTF_EXECUTION_PROFILE_LOW_LATENCY;
};

class Context;
class Session;
class Stream;
class SessionView;
class StreamView;
class DeferredRequest;
class ConnectionRequest;
struct StreamHandlers;
struct SessionHandlers;

namespace internal {

inline Result<> ResultFromStatus(wtf_result_t code) noexcept {
    if (code != WTF_SUCCESS) {
        return std::unexpected(Error{
            .code = code,
        });
    }
    return {};
}

struct ContextState {
    wtf_context_t* handle = nullptr;
    std::move_only_function<void(const LogMessage&) noexcept> on_log;
    ~ContextState() {
        if (handle) {
            wtf_context_destroy(handle);
        }
    }
};

struct EndpointState;
struct StreamCallbackState;

template <typename T, void (*Ref)(T*), void (*Unref)(T*)>
class RetainedHandle {
  public:
    RetainedHandle() = default;
    RetainedHandle(T* handle, std::shared_ptr<EndpointState> endpoint) noexcept
        : handle_(handle), endpoint_(std::move(endpoint)) {
    }
    RetainedHandle(const RetainedHandle& other) noexcept
        : handle_(other.handle_), endpoint_(other.endpoint_) {
        Ref(handle_);
    }
    RetainedHandle(RetainedHandle&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)),
          endpoint_(std::move(other.endpoint_)) {
    }
    RetainedHandle& operator=(RetainedHandle other) noexcept {
        swap(other);
        return *this;
    }
    ~RetainedHandle() {
        Unref(handle_);
    }
    void swap(RetainedHandle& other) noexcept {
        std::swap(handle_, other.handle_);
        endpoint_.swap(other.endpoint_);
    }
    [[nodiscard]] T* get() const noexcept {
        return handle_;
    }
    [[nodiscard]] EndpointState* endpoint() const noexcept {
        return endpoint_.get();
    }

  private:
    T* handle_ = nullptr;
    std::shared_ptr<EndpointState> endpoint_;
};

inline thread_local EndpointState* active_endpoint = nullptr;

class CallbackScope {
  public:
    explicit CallbackScope(EndpointState* endpoint) noexcept
        : previous_(std::exchange(active_endpoint, endpoint)) {
    }
    ~CallbackScope() {
        active_endpoint = previous_;
    }
    CallbackScope(const CallbackScope&) = delete;
    CallbackScope& operator=(const CallbackScope&) = delete;

  private:
    EndpointState* previous_;
};

void StreamCallback(const wtf_stream_event_t* event) noexcept;
void SessionCallback(const wtf_session_event_t* event) noexcept;

}  // namespace internal

//! Borrowed stream access, valid only for its callback or while an owning
//! Stream remains alive. Retain() obtains an independent application reference.
//! Methods preserve the C API's threading requirements.
class StreamView {
  public:
    StreamView() = default;
    //! Return whether this view contains a handle; a closed handle is still
    //! nonempty.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }
    //! Borrow the C handle. Do not replace the wrapper's callback or user
    //! context.
    [[nodiscard]] wtf_stream_t* native_handle() const noexcept {
        return handle_;
    }
    //! Retain the C stream and the parent context; empty views produce empty
    //! owners.
    [[nodiscard]] Stream Retain() const;
    //! Return the current application-stream state, or nullopt for an empty view.
    [[nodiscard]] std::optional<StreamState> state() const noexcept {
        if (handle_ == nullptr) {
            return std::nullopt;
        }
        return static_cast<StreamState>(wtf_stream_get_state(handle_));
    }
    //! Return the stream direction while open, or nullopt for an empty/closed view.
    [[nodiscard]] std::optional<StreamType> type() const noexcept {
        if (handle_ == nullptr || wtf_stream_get_state(handle_) == WTF_STREAM_CLOSED) {
            return std::nullopt;
        }
        return static_cast<StreamType>(wtf_stream_get_type(handle_));
    }
    //! Return the ID when assigned, nullopt while starting, or the C API's query error.
    [[nodiscard]] Result<std::optional<std::uint64_t>> id() const noexcept {
        std::uint64_t id = 0;
        auto result = internal::ResultFromStatus(wtf_stream_get_id(handle_, &id));
        if (!result) {
            return std::unexpected(result.error());
        }
        if (id == std::numeric_limits<std::uint64_t>::max()) {
            return std::optional<std::uint64_t>{};
        }
        return std::optional<std::uint64_t>{id};
    }
    //! Finish the local send side with FIN. Pending sends complete
    //! asynchronously.
    [[nodiscard]] Result<> Close() const noexcept {
        return internal::ResultFromStatus(wtf_stream_close(handle_));
    }
    //! Abort both stream directions with an application error code.
    //! Pending payload storage remains borrowed until completion or endpoint teardown.
    [[nodiscard]] Result<> Abort(std::uint32_t code) const noexcept {
        return internal::ResultFromStatus(wtf_stream_abort(handle_, code));
    }
    //! Set the transport's relative stream priority; higher values have higher
    //! priority.
    [[nodiscard]] Result<> SetPriority(std::uint16_t priority) const noexcept {
        return internal::ResultFromStatus(wtf_stream_set_priority(handle_, priority));
    }
    //! Pause or resume transport receive delivery.
    [[nodiscard]] Result<> SetReceiveEnabled(bool enabled) const noexcept {
        return internal::ResultFromStatus(wtf_stream_set_receive_enabled(handle_, enabled));
    }
    //! Send an owned payload, retaining its allocation until completion or
    //! cancellation. Passing std::move(buffer) avoids a wrapper payload copy; the
    //! backend may copy.
    //! @param data payload ownership is consumed, including on immediate failure
    //! @param options FIN, caller token, and optional completion callback
    //! @return success when accepted; readiness/delivery is not implied
    [[nodiscard]] Result<> Send(ByteBuffer data, SendOptions options = {}) const;
    //! Copy a payload before returning; the caller may immediately reuse its
    //! storage.
    //! @param data payload bytes; an empty span is valid only with fin=true
    //! @param fin finish the local send side after this data
    [[nodiscard]] Result<> SendCopy(Bytes data, bool fin = false) const noexcept {
        return internal::ResultFromStatus(
            wtf_stream_send_copy(handle_, data.data(), data.size(), fin)
        );
    }
    //! Copy the text bytes, excluding any terminator, with the same lifetime as
    //! SendCopy(Bytes).
    [[nodiscard]] Result<> SendCopy(std::string_view text, bool fin = false) const noexcept {
        return SendCopy(std::as_bytes(std::span(text.data(), text.size())), fin);
    }
    //! Send borrowed bytes without a wrapper payload copy.
    //! Keep bytes unchanged until completion, or until endpoint Reset() returns.
    //! Immediate failure leaves ownership with the caller and emits no
    //! completion.
    [[nodiscard]] Result<> SendBorrowed(Bytes data, SendOptions options = {}) const;
    //! Send borrowed scatter/gather payloads. Descriptor storage may be reused on
    //! return; payload bytes have the same lifetime as SendBorrowed(Bytes).
    [[nodiscard]] Result<> SendBorrowed(
        std::span<const wtf_buffer_t> buffers,
        SendOptions options = {}
    ) const;

  private:
    friend struct internal::EndpointState;
    StreamView(wtf_stream_t* handle, internal::EndpointState* endpoint) noexcept
        : handle_(handle), endpoint_(endpoint) {
    }
    wtf_stream_t* handle_ = nullptr;
    internal::EndpointState* endpoint_ = nullptr;
};

//! Borrowed session access, valid only for its callback or while a Session
//! owner lives. A successful stream/datagram submission is asynchronous.
//! Receive spans and response-header views must be copied before their callback
//! returns if needed later.
class SessionView {
  public:
    SessionView() = default;
    //! Return whether this view contains a handle, including closed sessions.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }
    //! Borrow the C handle without transferring ownership or callback
    //! registration.
    [[nodiscard]] wtf_session_t* native_handle() const noexcept {
        return handle_;
    }
    //! Retain the C session and parent context beyond the current callback.
    [[nodiscard]] Session Retain() const;
    //! Return the current session lifecycle state.
    [[nodiscard]] std::optional<SessionState> state() const noexcept {
        if (handle_ == nullptr) {
            return std::nullopt;
        }
        return static_cast<SessionState>(wtf_session_get_state(handle_));
    }
    //! Close this WebTransport session with an application code and optional
    //! reason. The reason is copied as needed; callers need not keep its storage
    //! alive.
    [[nodiscard]] Result<> Close(std::uint32_t code = 0, std::string_view reason = {}) const {
        const std::string terminated(reason);
        return internal::ResultFromStatus(
            wtf_session_close(handle_, code, terminated.c_str())
        );
    }
    //! Send DRAIN_WEBTRANSPORT_SESSION and prevent new streams on the draining
    //! session.
    [[nodiscard]] Result<> Drain() const noexcept {
        return internal::ResultFromStatus(wtf_session_drain(handle_));
    }
    //! Return the application datagram limit, or nullopt before datagrams are
    //! available.
    [[nodiscard]] std::optional<std::uint32_t> max_datagram_size() const noexcept {
        const auto size = wtf_session_get_max_datagram_size(handle_);
        if (size == 0) {
            return std::nullopt;
        }
        return size;
    }
    //! Copy the peer's platform socket-address bytes into owned storage.
    [[nodiscard]] Result<ByteBuffer> PeerAddress() const;
    //! Read a documented QUIC statistic or a custom app. statistic.
    [[nodiscard]] Result<std::uint64_t> GetStat(std::string_view key) const {
        if (key.find('\0') != std::string_view::npos) {
            return std::unexpected(Error{.code = WTF_ERROR_INVALID_PARAMETER});
        }
        const std::string terminated(key);
        std::uint64_t value = 0;
        auto result = internal::ResultFromStatus(
            wtf_session_get_stat(handle_, terminated.c_str(), &value)
        );
        if (!result) {
            return std::unexpected(result.error());
        }
        return value;
    }
    //! Insert or replace a session-local app. statistic.
    [[nodiscard]] Result<> SetStat(std::string_view key, std::uint64_t value) const {
        if (key.find('\0') != std::string_view::npos) {
            return std::unexpected(Error{.code = WTF_ERROR_INVALID_PARAMETER});
        }
        const std::string terminated(key);
        return internal::ResultFromStatus(wtf_session_set_stat(handle_, terminated.c_str(), value));
    }
    //! Remove a session-local app. statistic.
    [[nodiscard]] Result<> RemoveStat(std::string_view key) const {
        if (key.find('\0') != std::string_view::npos) {
            return std::unexpected(Error{.code = WTF_ERROR_INVALID_PARAMETER});
        }
        const std::string terminated(key);
        return internal::ResultFromStatus(wtf_session_remove_stat(handle_, terminated.c_str()));
    }
    //! Start a stream with handlers installed before transport activity begins.
    //! Handlers can run before this function returns; their StreamView is already
    //! usable.
    //! @param type bidirectional or unidirectional
    //! @param handlers retained until stream shutdown or endpoint destruction
    //! @return an owned reference, or the C stream-creation error
    [[nodiscard]] Result<Stream> OpenStream(StreamType type, StreamHandlers handlers) const;
    //! Start a bidirectional stream with no application event handlers.
    [[nodiscard]] Result<Stream> OpenBidirectionalStream() const;
    //! Start a bidirectional stream with handlers installed before startup.
    [[nodiscard]] Result<Stream> OpenBidirectionalStream(StreamHandlers handlers) const;
    //! Start a unidirectional stream with no application event handlers.
    [[nodiscard]] Result<Stream> OpenUnidirectionalStream() const;
    //! Start a unidirectional stream with handlers installed before startup.
    [[nodiscard]] Result<Stream> OpenUnidirectionalStream(StreamHandlers handlers) const;
    //! Return a retained reference, or nullopt if the stream is absent or the
    //! endpoint closed.
    [[nodiscard]] std::optional<Stream> FindStreamById(std::uint64_t id) const;
    //! Send owned datagram bytes, retaining them through intermediate send
    //! states. Ownership is consumed on both success and immediate failure.
    [[nodiscard]] Result<> SendDatagram(ByteBuffer data, DatagramOptions options = {}) const;
    //! Copy datagram bytes before returning so their storage may be reused
    //! immediately.
    [[nodiscard]] Result<> SendDatagramCopy(Bytes data) const noexcept {
        return internal::ResultFromStatus(
            wtf_session_send_datagram_copy(handle_, data.data(), data.size())
        );
    }
    //! Copy text bytes as a datagram, excluding any terminator.
    [[nodiscard]] Result<> SendDatagramCopy(std::string_view text) const noexcept {
        return SendDatagramCopy(std::as_bytes(std::span(text.data(), text.size())));
    }
    //! Send borrowed bytes. Keep them unchanged until a final datagram send
    //! state, or until endpoint Reset() returns. Immediate failure emits no
    //! state-change callback.
    [[nodiscard]] Result<> SendDatagramBorrowed(
        Bytes data,
        DatagramOptions options = {}
    ) const;
    //! Send borrowed scatter/gather bytes. Descriptors may be reused on return;
    //! payload bytes have the same lifetime as SendDatagramBorrowed(Bytes).
    [[nodiscard]] Result<> SendDatagramBorrowed(
        std::span<const wtf_buffer_t> buffers,
        DatagramOptions options = {}
    ) const;

  private:
    friend struct internal::EndpointState;
    SessionView(wtf_session_t* handle, internal::EndpointState* endpoint) noexcept
        : handle_(handle), endpoint_(endpoint) {
    }
    wtf_session_t* handle_ = nullptr;
    internal::EndpointState* endpoint_ = nullptr;
};

//! Stream event handlers. Installed once before stream startup; replacement
//! while callbacks are active is unsupported. Callbacks must not throw.
struct StreamHandlers {
    //! Received descriptors and bytes are borrowed until this handler returns.
    std::move_only_function<void(StreamView, BufferSequence) noexcept> on_data = {};
    //! Receives C transport completion events, including sends made with SendCopy().
    std::move_only_function<void(StreamView, SendCompletion) noexcept> on_send_complete = {};
    //! The peer finished its send side; local sending may still continue.
    std::move_only_function<void(StreamView) noexcept> on_peer_closed = {};
    //! Final stream notification. The callback's view is borrowed.
    std::move_only_function<void(StreamView) noexcept> on_closed = {};
    //! Peer/application reset error. Send cancellation and on_closed may follow.
    std::move_only_function<void(StreamView, std::uint32_t) noexcept> on_aborted = {};
};

//! Handlers shared by an endpoint's sessions. Different connections may invoke
//! them concurrently. Do not destroy the Client or Server from one of its
//! handlers.
struct SessionHandlers {
    //! CONNECT succeeded and application traffic may begin.
    std::move_only_function<void(SessionView, ConnectResponse) noexcept> on_connected = {};
    //! Session ended or CONNECT failed; details are borrowed until return.
    std::move_only_function<void(SessionView, DisconnectInfo) noexcept> on_disconnected = {};
    //! Session entered draining state.
    std::move_only_function<void(SessionView) noexcept> on_draining = {};
    //! Configure an incoming stream before its receive delivery resumes.
    //! Return its handlers; use Retain() to keep its handle beyond this callback.
    std::move_only_function<StreamHandlers(SessionView, StreamView) noexcept> on_stream = {};
    //! Datagram payload bytes are borrowed until this handler returns.
    std::move_only_function<void(SessionView, Bytes) noexcept> on_datagram = {};
    //! All intermediate and final send states; tokens match
    //! DatagramOptions::context.
    std::move_only_function<void(SessionView, DatagramCompletion) noexcept>
        on_datagram_send_state = {};
};

//! Retained application reference to a C stream and its parent context.
//! Copying retains; moving empties the source; destruction releases the
//! reference. Releasing a reference does not send FIN or abort. Call Close() or
//! Abort() explicitly. view() provides the same operations without retaining.
class Stream {
  public:
    Stream() = default;
    //! Return whether this owner contains a C handle, including a closed handle.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_.get() != nullptr;
    }
    //! Borrow the C handle without transferring its reference or callback state.
    [[nodiscard]] wtf_stream_t* native_handle() const noexcept {
        return handle_.get();
    }
    //! Borrow a view for use while this owner remains alive.
    [[nodiscard]] StreamView view() const noexcept;
    //! @copydoc StreamView::state
    [[nodiscard]] std::optional<StreamState> state() const noexcept {
        return view().state();
    }
    //! @copydoc StreamView::type
    [[nodiscard]] std::optional<StreamType> type() const noexcept {
        return view().type();
    }
    //! @copydoc StreamView::id
    [[nodiscard]] Result<std::optional<std::uint64_t>> id() const noexcept {
        return view().id();
    }
    //! @copydoc StreamView::Close
    [[nodiscard]] Result<> Close() const noexcept {
        return view().Close();
    }
    //! @copydoc StreamView::Abort
    [[nodiscard]] Result<> Abort(std::uint32_t code) const noexcept {
        return view().Abort(code);
    }
    //! @copydoc StreamView::SetPriority
    [[nodiscard]] Result<> SetPriority(std::uint16_t value) const noexcept {
        return view().SetPriority(value);
    }
    //! @copydoc StreamView::SetReceiveEnabled
    [[nodiscard]] Result<> SetReceiveEnabled(bool value) const noexcept {
        return view().SetReceiveEnabled(value);
    }
    //! @copydoc StreamView::Send
    [[nodiscard]] Result<> Send(ByteBuffer data, SendOptions options = {}) const {
        return view().Send(std::move(data), std::move(options));
    }
    //! @copydoc StreamView::SendCopy
    [[nodiscard]] Result<> SendCopy(Bytes data, bool fin = false) const noexcept {
        return view().SendCopy(data, fin);
    }
    //! @copydoc StreamView::SendCopy
    [[nodiscard]] Result<> SendCopy(std::string_view text, bool fin = false) const noexcept {
        return view().SendCopy(text, fin);
    }
    //! @copydoc StreamView::SendBorrowed
    [[nodiscard]] Result<> SendBorrowed(Bytes data, SendOptions options = {}) const {
        return view().SendBorrowed(data, std::move(options));
    }
    //! @copydoc StreamView::SendBorrowed
    [[nodiscard]] Result<> SendBorrowed(
        std::span<const wtf_buffer_t> buffers,
        SendOptions options = {}
    ) const {
        return view().SendBorrowed(buffers, std::move(options));
    }

  private:
    friend struct internal::EndpointState;
    Stream(
        wtf_stream_t* handle,
        std::shared_ptr<internal::EndpointState> endpoint
    ) noexcept
        : handle_(handle, std::move(endpoint)) {
    }
    internal::RetainedHandle<wtf_stream_t, wtf_stream_ref, wtf_stream_unref> handle_;
};

//! Retained application reference to a C session and its parent context.
//! Copying retains; moving empties the source; destruction releases the
//! reference. Close() ends the session explicitly. Keeping this reference alive
//! does not keep its Client or Server running after that endpoint is destroyed.
class Session {
  public:
    Session() = default;
    //! Return whether this owner contains a C handle, including a closed handle.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_.get() != nullptr;
    }
    //! Borrow the C handle without transferring its reference or callback state.
    [[nodiscard]] wtf_session_t* native_handle() const noexcept {
        return handle_.get();
    }
    //! Borrow a view for use while this owner remains alive.
    [[nodiscard]] SessionView view() const noexcept;
    //! @copydoc SessionView::state
    [[nodiscard]] std::optional<SessionState> state() const noexcept {
        return view().state();
    }
    //! @copydoc SessionView::Close
    [[nodiscard]] Result<> Close(std::uint32_t code = 0, std::string_view reason = {}) const {
        return view().Close(code, reason);
    }
    //! @copydoc SessionView::Drain
    [[nodiscard]] Result<> Drain() const noexcept {
        return view().Drain();
    }
    //! @copydoc SessionView::max_datagram_size
    [[nodiscard]] std::optional<std::uint32_t> max_datagram_size() const noexcept {
        return view().max_datagram_size();
    }
    //! @copydoc SessionView::PeerAddress
    [[nodiscard]] Result<ByteBuffer> PeerAddress() const {
        return view().PeerAddress();
    }
    //! @copydoc SessionView::GetStat
    [[nodiscard]] Result<std::uint64_t> GetStat(std::string_view key) const {
        return view().GetStat(key);
    }
    //! @copydoc SessionView::SetStat
    [[nodiscard]] Result<> SetStat(std::string_view key, std::uint64_t value) const {
        return view().SetStat(key, value);
    }
    //! @copydoc SessionView::RemoveStat
    [[nodiscard]] Result<> RemoveStat(std::string_view key) const {
        return view().RemoveStat(key);
    }
    //! @copydoc SessionView::OpenStream
    [[nodiscard]] Result<Stream> OpenStream(
        StreamType type,
        StreamHandlers handlers = {}
    ) const {
        return view().OpenStream(type, std::move(handlers));
    }
    //! @copydoc SessionView::OpenBidirectionalStream
    [[nodiscard]] Result<Stream> OpenBidirectionalStream(
        StreamHandlers handlers = {}
    ) const {
        return view().OpenBidirectionalStream(std::move(handlers));
    }
    //! @copydoc SessionView::OpenUnidirectionalStream
    [[nodiscard]] Result<Stream> OpenUnidirectionalStream(
        StreamHandlers handlers = {}
    ) const {
        return view().OpenUnidirectionalStream(std::move(handlers));
    }
    //! @copydoc SessionView::FindStreamById
    [[nodiscard]] std::optional<Stream> FindStreamById(std::uint64_t id) const {
        return view().FindStreamById(id);
    }
    //! @copydoc SessionView::SendDatagram
    [[nodiscard]] Result<> SendDatagram(ByteBuffer data, DatagramOptions options = {}) const {
        return view().SendDatagram(std::move(data), std::move(options));
    }
    //! @copydoc SessionView::SendDatagramCopy
    [[nodiscard]] Result<> SendDatagramCopy(Bytes data) const noexcept {
        return view().SendDatagramCopy(data);
    }
    //! @copydoc SessionView::SendDatagramCopy
    [[nodiscard]] Result<> SendDatagramCopy(std::string_view text) const noexcept {
        return view().SendDatagramCopy(text);
    }
    //! @copydoc SessionView::SendDatagramBorrowed
    [[nodiscard]] Result<> SendDatagramBorrowed(
        Bytes data,
        DatagramOptions options = {}
    ) const {
        return view().SendDatagramBorrowed(data, std::move(options));
    }
    //! @copydoc SessionView::SendDatagramBorrowed
    [[nodiscard]] Result<> SendDatagramBorrowed(
        std::span<const wtf_buffer_t> buffers,
        DatagramOptions options = {}
    ) const {
        return view().SendDatagramBorrowed(buffers, std::move(options));
    }

  private:
    friend struct internal::EndpointState;
    Session(
        wtf_session_t* handle,
        std::shared_ptr<internal::EndpointState> endpoint
    ) noexcept
        : handle_(handle, std::move(endpoint)) {
    }
    internal::RetainedHandle<wtf_session_t, wtf_session_ref, wtf_session_unref> handle_;
};

namespace internal {

struct SendOperation {
    ByteBuffer payload;
    SendOptions options;
};

struct DatagramOperation {
    ByteBuffer payload;
    DatagramOptions options;
};

struct StreamCallbackState : std::enable_shared_from_this<StreamCallbackState> {
    EndpointState* endpoint;
    StreamHandlers handlers;
    std::mutex mutex;
    std::unordered_map<void*, std::unique_ptr<SendOperation>> sends;

    StreamCallbackState(EndpointState* owner, StreamHandlers callbacks)
        : endpoint(owner), handlers(std::move(callbacks)) {
    }

    std::unique_ptr<SendOperation> TakeSend(void* token) noexcept {
        std::lock_guard lock(mutex);
        auto node = sends.extract(token);
        if (node.empty()) {
            return {};
        }
        return std::move(node.mapped());
    }

    void CancelSends() noexcept {
        decltype(sends) cancelled;
        {
            std::lock_guard lock(mutex);
            cancelled.swap(sends);
        }
        for (auto& [token, operation] : cancelled) {
            if (operation->options.on_complete) {
                operation->options.on_complete({
                    .cancelled = true,
                    .context = operation->options.context,
                });
            }
        }
    }
};

struct EndpointState : std::enable_shared_from_this<EndpointState> {
    static std::shared_ptr<EndpointState> Create(
        const Context& context,
        SessionHandlers handlers
    );
    StreamView BorrowStream(wtf_stream_t* handle) noexcept {
        return StreamView(handle, this);
    }
    SessionView BorrowSession(wtf_session_t* handle) noexcept {
        return SessionView(handle, this);
    }
    Stream AdoptStream(wtf_stream_t* handle) {
        return Stream(handle, shared_from_this());
    }
    Session AdoptSession(wtf_session_t* handle) {
        return Session(handle, shared_from_this());
    }
    Stream RetainStream(wtf_stream_t* handle) {
        wtf_stream_ref(handle);
        return AdoptStream(handle);
    }
    Session RetainSession(wtf_session_t* handle) {
        wtf_session_ref(handle);
        return AdoptSession(handle);
    }
    DeferredRequest DeferRequest(wtf_connection_request_handle_t* handle);
    wtf_connection_decision_t Validate(
        const wtf_connection_request_t* request,
        wtf_connection_response_t* response
    ) noexcept;
    enum class Lifetime {
        kOpen,
        kClosing,
        kClosed,
    };
    std::shared_ptr<ContextState> context;
    SessionHandlers handlers;
    std::move_only_function<void(ConnectionRequest&) noexcept> on_request;
    std::atomic<Lifetime> lifetime{Lifetime::kOpen};
    std::mutex mutex;
    std::unordered_map<void*, std::shared_ptr<StreamCallbackState>> streams;
    std::unordered_map<void*, std::unique_ptr<DatagramOperation>> datagrams;

    [[nodiscard]] bool open() const noexcept {
        return lifetime.load(std::memory_order_acquire) == Lifetime::kOpen;
    }
    std::shared_ptr<StreamCallbackState> AddStream(StreamHandlers callbacks) {
        auto stream = std::make_shared<StreamCallbackState>(this, std::move(callbacks));
        std::lock_guard lock(mutex);
        streams.emplace(stream.get(), stream);
        return stream;
    }
    std::shared_ptr<StreamCallbackState> FindStream(void* token) noexcept {
        std::lock_guard lock(mutex);
        auto found = streams.find(token);
        if (found == streams.end()) {
            return {};
        }
        return found->second;
    }
    void RemoveStream(void* token) noexcept {
        std::shared_ptr<StreamCallbackState> retired;
        {
            std::lock_guard lock(mutex);
            auto node = streams.extract(token);
            if (!node.empty()) {
                retired = std::move(node.mapped());
            }
        }
        if (retired) {
            retired->CancelSends();
        }
    }
    void BeginClose() noexcept {
        if (active_endpoint == this) {
            std::terminate();
        }
        lifetime.store(Lifetime::kClosing, std::memory_order_release);
    }
    void FinishClose() noexcept {
        lifetime.store(Lifetime::kClosed, std::memory_order_release);
        decltype(streams) retired_streams;
        decltype(datagrams) cancelled_datagrams;
        {
            std::lock_guard lock(mutex);
            retired_streams.swap(streams);
            cancelled_datagrams.swap(datagrams);
        }
        for (auto& [token, stream] : retired_streams) {
            stream->CancelSends();
        }
        for (auto& [token, operation] : cancelled_datagrams) {
            if (operation->options.on_complete) {
                operation->options.on_complete({
                    .state = WTF_DATAGRAM_SEND_CANCELED,
                    .context = operation->options.context,
                });
            }
        }
        handlers = {};
        on_request = {};
    }
};

inline bool ValidTransportOptions(const TransportOptions& options) noexcept {
    constexpr auto max = std::numeric_limits<std::uint32_t>::max();
    if (options.idle_timeout &&
        (options.idle_timeout->count() <= 0 || options.idle_timeout->count() > max)) {
        return false;
    }
    if (options.handshake_timeout &&
        (options.handshake_timeout->count() <= 0 || options.handshake_timeout->count() > max)) {
        return false;
    }
    if (options.max_sessions_per_connection &&
        *options.max_sessions_per_connection == 0) {
        return false;
    }
    if (options.max_streams_per_session && *options.max_streams_per_session == 0) {
        return false;
    }
    if (options.max_data_per_session && *options.max_data_per_session == 0) {
        return false;
    }
    if (options.stream_recv_window && *options.stream_recv_window == 0) {
        return false;
    }
    if (options.conn_flow_control_window && *options.conn_flow_control_window == 0) {
        return false;
    }
    return true;
}

template <typename Config>
void ApplyTransportOptions(const TransportOptions& options, Config& config) noexcept {
    config.draft = static_cast<wtf_webtransport_draft_t>(std::to_underlying(options.draft));
    if (options.max_sessions_per_connection) {
        config.max_sessions_per_connection = *options.max_sessions_per_connection;
    }
    if (options.max_streams_per_session) {
        config.max_streams_per_session = *options.max_streams_per_session;
    }
    if (options.max_data_per_session) {
        config.max_data_per_session = *options.max_data_per_session;
    }
    if (options.stream_recv_window) {
        config.stream_recv_window = *options.stream_recv_window;
    }
    if (options.conn_flow_control_window) {
        config.conn_flow_control_window = *options.conn_flow_control_window;
    }
    if (options.idle_timeout) {
        config.idle_timeout_ms = static_cast<std::uint32_t>(options.idle_timeout->count());
    }
    if (options.handshake_timeout) {
        config.handshake_timeout_ms =
            static_cast<std::uint32_t>(options.handshake_timeout->count());
    }
    config.enable_0rtt = options.enable_0rtt;
    config.enable_migration = options.enable_migration;
    config.send_buffering = static_cast<wtf_send_buffering_t>(
        std::to_underlying(options.send_buffering)
    );
}

inline void StreamCallback(const wtf_stream_event_t* event) noexcept {
    auto state = static_cast<StreamCallbackState*>(event->user_context)->shared_from_this();
    CallbackScope scope(state->endpoint);
    StreamView stream = state->endpoint->BorrowStream(event->stream);
    switch (event->type) {
        case WTF_STREAM_EVENT_DATA_RECEIVED: {
            if (state->handlers.on_data) {
                const BufferSequence data(std::span(event->data_received.buffers,
                                                    event->data_received.buffer_count));
                state->handlers.on_data(stream, data);
            }
            break;
        }
        case WTF_STREAM_EVENT_SEND_COMPLETE: {
            auto operation = state->TakeSend(event->send_complete.operation_context);
            void* context = event->send_complete.operation_context;
            if (operation) {
                context = operation->options.context;
            }
            const SendCompletion completion{
                .cancelled = event->send_complete.cancelled,
                .context = context,
            };
            if (operation && operation->options.on_complete) {
                operation->options.on_complete(completion);
            }
            if (state->handlers.on_send_complete) {
                state->handlers.on_send_complete(stream, completion);
            }
            break;
        }
        case WTF_STREAM_EVENT_PEER_CLOSED: {
            if (state->handlers.on_peer_closed) {
                state->handlers.on_peer_closed(stream);
            }
            break;
        }
        case WTF_STREAM_EVENT_ABORTED: {
            if (state->handlers.on_aborted) {
                state->handlers.on_aborted(stream, event->aborted.error_code);
            }
            break;
        }
        case WTF_STREAM_EVENT_CLOSED: {
            if (state->handlers.on_closed) {
                state->handlers.on_closed(stream);
            }
            state->endpoint->RemoveStream(state.get());
            break;
        }
    }
}

inline void SessionCallback(const wtf_session_event_t* event) noexcept {
    auto* endpoint = static_cast<EndpointState*>(event->user_context);
    CallbackScope scope(endpoint);
    SessionView session = endpoint->BorrowSession(event->session);
    switch (event->type) {
        case WTF_SESSION_EVENT_CONNECTED: {
            if (endpoint->handlers.on_connected) {
                ConnectResponse response{
                    .headers = {
                        event->connected.headers,
                        event->connected.header_count,
                    },
                };
                if (event->connected.status_code != 0) {
                    response.status_code = event->connected.status_code;
                }
                endpoint->handlers.on_connected(session, response);
            }
            break;
        }
        case WTF_SESSION_EVENT_DISCONNECTED: {
            if (endpoint->handlers.on_disconnected) {
                DisconnectInfo info{
                    .error_code = event->disconnected.error_code,
                };
                if (event->disconnected.reason != nullptr) {
                    info.reason = std::string_view(event->disconnected.reason);
                }
                if (event->disconnected.status_code != 0 ||
                    event->disconnected.headers != nullptr) {
                    info.response = ConnectResponse{
                        .headers = {
                            event->disconnected.headers,
                            event->disconnected.header_count,
                        },
                    };
                    if (event->disconnected.status_code != 0) {
                        info.response->status_code = event->disconnected.status_code;
                    }
                }
                endpoint->handlers.on_disconnected(session, info);
            }
            break;
        }
        case WTF_SESSION_EVENT_DRAINING: {
            if (endpoint->handlers.on_draining) {
                endpoint->handlers.on_draining(session);
            }
            break;
        }
        case WTF_SESSION_EVENT_STREAM_OPENED: {
            wtf_stream_t* handle = event->stream_opened.stream;
            if (endpoint->FindStream(wtf_stream_get_context(handle))) {
                break;
            }
            auto state = endpoint->AddStream({});
            wtf_stream_set_context(handle, state.get());
            wtf_stream_set_callback(handle, StreamCallback);
            if (endpoint->handlers.on_stream) {
                state->handlers = endpoint->handlers.on_stream(
                    session,
                    endpoint->BorrowStream(handle)
                );
            }
            break;
        }
        case WTF_SESSION_EVENT_DATAGRAM_RECEIVED: {
            if (endpoint->handlers.on_datagram) {
                const Bytes payload(
                    reinterpret_cast<const std::byte*>(event->datagram_received.data),
                    event->datagram_received.length
                );
                endpoint->handlers.on_datagram(session, payload);
            }
            break;
        }
        case WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE: {
            std::unique_ptr<DatagramOperation> completed;
            void* context = event->datagram_send_state_changed.operation_context;
            const auto state = event->datagram_send_state_changed.state;
            {
                std::lock_guard lock(endpoint->mutex);
                auto found = endpoint->datagrams.find(context);
                if (found != endpoint->datagrams.end()) {
                    context = found->second->options.context;
                    if (WTF_DATAGRAM_SEND_STATE_IS_FINAL(state)) {
                        completed = std::move(found->second);
                        endpoint->datagrams.erase(found);
                    }
                }
            }
            const DatagramCompletion completion{
                .state = state,
                .context = context,
            };
            if (completed && completed->options.on_complete) {
                completed->options.on_complete(completion);
            }
            if (endpoint->handlers.on_datagram_send_state) {
                endpoint->handlers.on_datagram_send_state(session, completion);
            }
            break;
        }
    }
}

}  // namespace internal

inline StreamView Stream::view() const noexcept {
    if (handle_.endpoint() == nullptr) {
        return {};
    }
    return handle_.endpoint()->BorrowStream(handle_.get());
}

inline SessionView Session::view() const noexcept {
    if (handle_.endpoint() == nullptr) {
        return {};
    }
    return handle_.endpoint()->BorrowSession(handle_.get());
}

inline Stream StreamView::Retain() const {
    if (!handle_ || !endpoint_) {
        return {};
    }
    return endpoint_->RetainStream(handle_);
}

inline Session SessionView::Retain() const {
    if (!handle_ || !endpoint_) {
        return {};
    }
    return endpoint_->RetainSession(handle_);
}

inline Result<ByteBuffer> SessionView::PeerAddress() const {
    std::size_t size = 0;
    auto result = wtf_session_get_peer_address(handle_, nullptr, &size);
    if (result != WTF_SUCCESS && result != WTF_ERROR_BUFFER_TOO_SMALL) {
        return std::unexpected(Error{
            .code = result,
        });
    }
    ByteBuffer address(size);
    result = wtf_session_get_peer_address(handle_, address.data(), &size);
    if (result != WTF_SUCCESS) {
        return std::unexpected(Error{
            .code = result,
        });
    }
    address.resize(size);
    return address;
}

inline Result<Stream> SessionView::OpenStream(
    StreamType type,
    StreamHandlers handlers
) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    auto state = endpoint_->AddStream(std::move(handlers));
    wtf_stream_t* stream = nullptr;
    const auto stream_type = static_cast<wtf_stream_type_t>(std::to_underlying(type));
    auto result = wtf_session_create_stream(handle_,
                                            stream_type,
                                            internal::StreamCallback,
                                            state.get(),
                                            &stream);
    if (result != WTF_SUCCESS) {
        endpoint_->RemoveStream(state.get());
        return std::unexpected(Error{
            .code = result,
        });
    }
    return endpoint_->AdoptStream(stream);
}

inline Result<Stream> SessionView::OpenBidirectionalStream() const {
    return OpenStream(StreamType::kBidirectional, {});
}
inline Result<Stream> SessionView::OpenBidirectionalStream(StreamHandlers handlers) const {
    return OpenStream(StreamType::kBidirectional, std::move(handlers));
}
inline Result<Stream> SessionView::OpenUnidirectionalStream() const {
    return OpenStream(StreamType::kUnidirectional, {});
}
inline Result<Stream> SessionView::OpenUnidirectionalStream(StreamHandlers handlers) const {
    return OpenStream(StreamType::kUnidirectional, std::move(handlers));
}
inline std::optional<Stream> SessionView::FindStreamById(std::uint64_t id) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::nullopt;
    }
    auto* stream = wtf_session_find_stream_by_id(handle_, id);
    if (!stream) {
        return std::nullopt;
    }
    return endpoint_->AdoptStream(stream);
}

namespace internal {

inline Result<> SubmitStreamSend(
    StreamView stream,
    const std::shared_ptr<StreamCallbackState>& state,
    std::span<const wtf_buffer_t> buffers,
    std::unique_ptr<SendOperation> operation
) {
    if (buffers.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    const bool fin = operation->options.fin;
    void* token = operation.get();
    {
        std::lock_guard lock(state->mutex);
        state->sends.emplace(token, std::move(operation));
    }
    auto result = wtf_stream_send(stream.native_handle(),
                                  buffers.data(),
                                  static_cast<std::uint32_t>(buffers.size()),
                                  fin,
                                  token);
    if (result != WTF_SUCCESS) {
        auto failed = state->TakeSend(token);
    }
    return ResultFromStatus(result);
}

inline Result<> SubmitDatagram(
    SessionView session,
    EndpointState& endpoint,
    std::span<const wtf_buffer_t> buffers,
    std::unique_ptr<DatagramOperation> operation
) {
    if (buffers.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    void* token = operation.get();
    {
        std::lock_guard lock(endpoint.mutex);
        endpoint.datagrams.emplace(token, std::move(operation));
    }
    auto result = wtf_session_send_datagram(session.native_handle(),
                                            buffers.data(),
                                            static_cast<std::uint32_t>(buffers.size()),
                                            token);
    if (result != WTF_SUCCESS) {
        std::unique_ptr<DatagramOperation> failed;
        {
            std::lock_guard lock(endpoint.mutex);
            auto node = endpoint.datagrams.extract(token);
            if (!node.empty()) {
                failed = std::move(node.mapped());
            }
        }
    }
    return ResultFromStatus(result);
}

}  // namespace internal

inline Result<> StreamView::Send(ByteBuffer data, SendOptions options) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    auto state = endpoint_->FindStream(wtf_stream_get_context(handle_));
    if (!state) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    auto operation = std::make_unique<internal::SendOperation>(internal::SendOperation{
        .payload = std::move(data),
        .options = std::move(options),
    });
    wtf_buffer_t buffer{
        .length = static_cast<std::uint32_t>(operation->payload.size()),
        .data = reinterpret_cast<const std::uint8_t*>(operation->payload.data()),
    };
    return internal::SubmitStreamSend(*this, state, {&buffer, 1}, std::move(operation));
}

inline Result<> StreamView::SendBorrowed(Bytes data, SendOptions options) const {
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    wtf_buffer_t buffer{
        .length = static_cast<std::uint32_t>(data.size()),
        .data = reinterpret_cast<const std::uint8_t*>(data.data()),
    };
    return SendBorrowed({&buffer, 1}, std::move(options));
}

inline Result<> StreamView::SendBorrowed(
    std::span<const wtf_buffer_t> buffers,
    SendOptions options
) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    auto state = endpoint_->FindStream(wtf_stream_get_context(handle_));
    if (!state) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    if (buffers.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    if (!options.on_complete) {
        auto result = wtf_stream_send(handle_,
                                      buffers.data(),
                                      static_cast<std::uint32_t>(buffers.size()),
                                      options.fin,
                                      options.context);
        return internal::ResultFromStatus(result);
    }
    auto operation = std::make_unique<internal::SendOperation>(internal::SendOperation{
        .payload = {},
        .options = std::move(options),
    });
    return internal::SubmitStreamSend(*this, state, buffers, std::move(operation));
}

inline Result<> SessionView::SendDatagram(ByteBuffer data, DatagramOptions options) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    auto operation = std::make_unique<internal::DatagramOperation>(internal::DatagramOperation{
        .payload = std::move(data),
        .options = std::move(options),
    });
    wtf_buffer_t buffer{
        .length = static_cast<std::uint32_t>(operation->payload.size()),
        .data = reinterpret_cast<const std::uint8_t*>(operation->payload.data()),
    };
    return internal::SubmitDatagram(*this, *endpoint_, {&buffer, 1}, std::move(operation));
}

inline Result<> SessionView::SendDatagramBorrowed(Bytes data, DatagramOptions options) const {
    if (data.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    wtf_buffer_t buffer{
        .length = static_cast<std::uint32_t>(data.size()),
        .data = reinterpret_cast<const std::uint8_t*>(data.data()),
    };
    return SendDatagramBorrowed({&buffer, 1}, std::move(options));
}

inline Result<> SessionView::SendDatagramBorrowed(
    std::span<const wtf_buffer_t> buffers,
    DatagramOptions options
) const {
    if (!handle_ || !endpoint_ || !endpoint_->open()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_STATE,
        });
    }
    if (buffers.size() > std::numeric_limits<std::uint32_t>::max()) {
        return std::unexpected(Error{
            .code = WTF_ERROR_INVALID_PARAMETER,
        });
    }
    if (!options.on_complete) {
        auto result = wtf_session_send_datagram(handle_,
                                                buffers.data(),
                                                static_cast<std::uint32_t>(buffers.size()),
                                                options.context);
        return internal::ResultFromStatus(result);
    }
    auto operation = std::make_unique<internal::DatagramOperation>(internal::DatagramOperation{
        .payload = {},
        .options = std::move(options),
    });
    return internal::SubmitDatagram(*this, *endpoint_, buffers, std::move(operation));
}

//! Move-only owner of an asynchronous connection decision.
//! Accept() and Reject() consume the pending decision. Destruction rejects an
//! unanswered request. The retained C handle and context survive endpoint
//! shutdown, but completing a request after shutdown may return
//! WTF_ERROR_INVALID_STATE.
class DeferredRequest {
  public:
    DeferredRequest() = default;
    DeferredRequest(const DeferredRequest&) = delete;
    DeferredRequest& operator=(const DeferredRequest&) = delete;
    DeferredRequest(DeferredRequest&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)),
          endpoint_(std::move(other.endpoint_)) {
    }
    DeferredRequest& operator=(DeferredRequest&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = std::exchange(other.handle_, nullptr);
            endpoint_ = std::move(other.endpoint_);
        }
        return *this;
    }
    ~DeferredRequest() {
        Reset();
    }
    //! Return whether a decision is still pending.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }
    //! Borrow the retained C request handle without consuming the decision.
    [[nodiscard]] wtf_connection_request_handle_t* native_handle() const noexcept {
        return handle_;
    }
    //! Copy an additional CONNECT response header before completing the request.
    //! Pseudo-header names are rejected by libwtf.
    [[nodiscard]] Result<> AddHeader(std::string_view name, std::string_view value) const {
        const std::string terminated_name(name);
        const std::string terminated_value(value);
        auto result = wtf_connection_request_add_response_header(handle_,
                                                                 terminated_name.c_str(),
                                                                 terminated_value.c_str());
        return internal::ResultFromStatus(result);
    }
    //! Accept the request and consume this decision, including if completion
    //! fails.
    [[nodiscard]] Result<> Accept() noexcept {
        return Complete(WTF_CONNECTION_ACCEPT);
    }
    //! Reject the request and consume this decision, including if completion
    //! fails.
    [[nodiscard]] Result<> Reject() noexcept {
        return Complete(WTF_CONNECTION_REJECT);
    }

  private:
    friend struct internal::EndpointState;
    DeferredRequest(
        wtf_connection_request_handle_t* handle,
        std::shared_ptr<internal::EndpointState> endpoint
    ) noexcept
        : handle_(handle), endpoint_(std::move(endpoint)) {
        wtf_connection_request_ref(handle_);
    }
    Result<> Complete(wtf_connection_decision_t decision) noexcept {
        auto* handle = std::exchange(handle_, nullptr);
        if (!handle) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_STATE,
            });
        }
        auto result = wtf_connection_request_complete(handle, decision);
        wtf_connection_request_unref(handle);
        endpoint_.reset();
        return internal::ResultFromStatus(result);
    }
    void Reset() noexcept {
        if (handle_) {
            static_cast<void>(Reject());
        }
    }
    wtf_connection_request_handle_t* handle_ = nullptr;
    std::shared_ptr<internal::EndpointState> endpoint_;
};

inline DeferredRequest internal::EndpointState::DeferRequest(
    wtf_connection_request_handle_t* handle
) {
    return DeferredRequest(handle, shared_from_this());
}

//! Incoming CONNECT request borrowed only for the validation callback.
//! Requests are accepted by default when a validation callback is installed.
//! Reject() changes the decision; Defer() transfers it to an asynchronous
//! owner.
class ConnectionRequest {
  public:
    //! Return the Origin header, preserving absence separately from an empty
    //! value.
    [[nodiscard]] std::optional<std::string_view> origin() const noexcept {
        if (request_->origin == nullptr) {
            return std::nullopt;
        }
        return std::string_view(request_->origin);
    }
    //! Return the requested path. The view expires when validation returns.
    [[nodiscard]] std::optional<std::string_view> path() const noexcept {
        if (request_->path == nullptr) {
            return std::nullopt;
        }
        return std::string_view(request_->path);
    }
    //! Return the requested authority. The view expires when validation returns.
    [[nodiscard]] std::optional<std::string_view> authority() const noexcept {
        if (request_->authority == nullptr) {
            return std::nullopt;
        }
        return std::string_view(request_->authority);
    }
    //! Borrow request headers for the duration of validation.
    [[nodiscard]] std::span<const wtf_http_header_t> headers() const noexcept {
        return {request_->headers, request_->header_count};
    }
    //! Borrow the peer's platform socket-address bytes during validation.
    [[nodiscard]] Bytes peer_address() const noexcept {
        return {
            static_cast<const std::byte*>(request_->peer_address),
            request_->address_length,
        };
    }
    //! Copy a response header. After Defer(), add headers through
    //! DeferredRequest.
    [[nodiscard]] Result<> AddHeader(std::string_view name, std::string_view value) const {
        if (decision_ == WTF_CONNECTION_DEFER) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_STATE,
            });
        }
        const std::string terminated_name(name);
        const std::string terminated_value(value);
        auto result = wtf_connection_response_add_header(response_,
                                                         terminated_name.c_str(),
                                                         terminated_value.c_str());
        return internal::ResultFromStatus(result);
    }
    //! Accept when validation returns. Has no effect after Defer().
    void Accept() noexcept {
        if (decision_ != WTF_CONNECTION_DEFER) {
            decision_ = WTF_CONNECTION_ACCEPT;
        }
    }
    //! Reject when validation returns. Has no effect after Defer().
    void Reject() noexcept {
        if (decision_ != WTF_CONNECTION_DEFER) {
            decision_ = WTF_CONNECTION_REJECT;
        }
    }
    //! Transfer the decision to an owner that may be moved to another thread.
    //! Request strings and headers remain callback-only; copy them separately.
    //! @return a pending decision, or WTF_ERROR_INVALID_STATE if already deferred
    [[nodiscard]] Result<DeferredRequest> Defer() {
        if (decision_ == WTF_CONNECTION_DEFER) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_STATE,
            });
        }
        decision_ = WTF_CONNECTION_DEFER;
        return endpoint_->DeferRequest(request_->handle);
    }

  private:
    friend struct internal::EndpointState;
    ConnectionRequest(
        const wtf_connection_request_t* request,
        wtf_connection_response_t* response,
        internal::EndpointState* endpoint
    ) noexcept
        : request_(request), response_(response), endpoint_(endpoint) {
    }
    const wtf_connection_request_t* request_;
    wtf_connection_response_t* response_;
    internal::EndpointState* endpoint_;
    wtf_connection_decision_t decision_ = WTF_CONNECTION_ACCEPT;
};

inline wtf_connection_decision_t internal::EndpointState::Validate(
    const wtf_connection_request_t* request,
    wtf_connection_response_t* response
) noexcept {
    CallbackScope scope(this);
    ConnectionRequest view(request, response, this);
    on_request(view);
    return view.decision_;
}

//! Move-only owner of library configuration and logging state.
//! Clients, servers, retained sessions, and retained streams keep the native
//! context alive after this owner moves or is destroyed. They do not retain
//! arbitrary application objects referenced by callbacks.
class Context {
  public:
    Context() = default;
    Context(const Context&) = delete;
    Context& operator=(const Context&) = delete;
    Context(Context&&) noexcept = default;
    Context& operator=(Context&&) noexcept = default;

    //! Create a context and install logging before native initialization.
    //! @param options configuration and an optional concurrent logging handler
    //! @return an owner, or the C API's initialization error
    [[nodiscard]] static Result<Context> Create(ContextOptions options = {}) {
        auto state = std::make_shared<internal::ContextState>();
        state->on_log = std::move(options.on_log);
        if (options.worker_thread_count && *options.worker_thread_count == 0) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_PARAMETER,
            });
        }
        wtf_log_callback_t callback = nullptr;
        if (state->on_log) {
            callback = [](
                wtf_log_level_t level,
                const char* component,
                const char* file,
                int line,
                const char* message,
                void* context
            ) noexcept {
                auto* state = static_cast<internal::ContextState*>(context);
                LogMessage entry{
                    .level = level,
                };
                if (component != nullptr) {
                    entry.component = std::string_view(component);
                }
                if (file != nullptr) {
                    entry.file = std::string_view(file);
                }
                if (line > 0) {
                    entry.line = line;
                }
                if (message != nullptr) {
                    entry.message = std::string_view(message);
                }
                state->on_log(entry);
            };
        }
        wtf_context_config_t config{
            .log_level = options.log_level,
            .log_callback = callback,
            .log_user_context = state.get(),
            .worker_thread_count = 0,
            .enable_load_balancing = options.enable_load_balancing,
            .disable_encryption = options.disable_encryption,
            .execution_profile = options.execution_profile,
        };
        if (options.worker_thread_count) {
            config.worker_thread_count = *options.worker_thread_count;
        }
        auto result = wtf_context_create(&config, &state->handle);
        if (result != WTF_SUCCESS) {
            return std::unexpected(Error{
                .code = result,
            });
        }
        Context context;
        context.state_ = std::move(state);
        return context;
    }
    //! Return whether this owner contains a native context.
    [[nodiscard]] explicit operator bool() const noexcept {
        return state_ != nullptr;
    }
    //! Borrow the native context; the caller must not destroy it.
    [[nodiscard]] wtf_context_t* native_handle() const noexcept {
        if (!state_) {
            return nullptr;
        }
        return state_->handle;
    }
    //! Change this context's minimum emitted log severity.
    [[nodiscard]] Result<> SetLogLevel(wtf_log_level_t level) const noexcept {
        return internal::ResultFromStatus(wtf_context_set_log_level(native_handle(), level));
    }

  private:
    friend struct internal::EndpointState;
    std::shared_ptr<internal::ContextState> state_;
};

inline std::shared_ptr<internal::EndpointState> internal::EndpointState::Create(
    const Context& context,
    SessionHandlers handlers
) {
    auto endpoint = std::make_shared<EndpointState>();
    endpoint->context = context.state_;
    endpoint->handlers = std::move(handlers);
    return endpoint;
}

//! Move-only owner of a client endpoint. Destruction closes its connections
//! before releasing handlers and pending owned sends.
//! Destroy or Reset() outside this endpoint's callbacks and synchronize other
//! threads using it first. Violating the callback precondition terminates.
class Client {
  public:
    Client() = default;
    Client(const Client&) = delete;
    Client& operator=(const Client&) = delete;
    Client(Client&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)),
          endpoint_(std::move(other.endpoint_)) {
    }
    Client& operator=(Client&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = std::exchange(other.handle_, nullptr);
            endpoint_ = std::move(other.endpoint_);
        }
        return *this;
    }
    ~Client() {
        Reset();
    }

    //! Configure a client without starting a session.
    //! @param context retained while this client or its application handles live
    //! @param options copied into the C library during this call
    //! @param handlers installed before Open(); shared by the client's sessions
    //! @return a client owner, or a configuration/transport error
    [[nodiscard]] static Result<Client> Create(
        const Context& context,
        const ClientOptions& options,
        SessionHandlers handlers = {}
    ) {
        if (!context || !internal::ValidTransportOptions(options.transport)) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_PARAMETER,
            });
        }
        auto endpoint = internal::EndpointState::Create(context, std::move(handlers));
        std::vector<wtf_http_header_t> headers;
        headers.reserve(options.headers.size());
        for (const auto& header : options.headers) {
            headers.push_back({
                .name = header.name.c_str(),
                .value = header.value.c_str(),
            });
        }
        wtf_client_config_t config{
            .url = options.url.c_str(),
            .origin = nullptr,
            .headers = headers.data(),
            .header_count = headers.size(),
            .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
            .allow_pooling = options.allow_pooling,
            .congestion_control = static_cast<wtf_congestion_control_t>(
                std::to_underlying(options.congestion_control)
            ),
            .require_unreliable = options.require_unreliable,
            .skip_certificate_validation = options.skip_certificate_validation,
            .ca_cert_file = nullptr,
            .pinned_server_certificate_file = nullptr,
            .max_sessions_per_connection = 0,
            .max_streams_per_session = 0,
            .max_data_per_session = 0,
            .stream_recv_window = 0,
            .conn_flow_control_window = 0,
            .idle_timeout_ms = 0,
            .handshake_timeout_ms = 0,
            .enable_0rtt = false,
            .enable_migration = false,
            .send_buffering = WTF_SEND_BUFFERING_DEFAULT,
            .session_callback = internal::SessionCallback,
            .user_context = endpoint.get(),
        };
        if (options.origin) {
            config.origin = options.origin->c_str();
        }
        if (options.ca_cert_file) {
            config.ca_cert_file = options.ca_cert_file->c_str();
        }
        if (options.pinned_server_certificate_file) {
            config.pinned_server_certificate_file =
                options.pinned_server_certificate_file->c_str();
        }
        internal::ApplyTransportOptions(options.transport, config);
        wtf_client_t* handle = nullptr;
        auto result = wtf_client_create(context.native_handle(), &config, &handle);
        if (result != WTF_SUCCESS) {
            return std::unexpected(Error{
                .code = result,
            });
        }
        Client client;
        client.handle_ = handle;
        client.endpoint_ = std::move(endpoint);
        return client;
    }
    //! Return whether this owner contains a client, regardless of connection
    //! state.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }
    //! Borrow the native client; do not destroy it or replace wrapper callbacks.
    [[nodiscard]] wtf_client_t* native_handle() const noexcept {
        return handle_;
    }
    //! Return the current C client lifecycle state.
    [[nodiscard]] std::optional<wtf_client_state_t> state() const noexcept {
        if (handle_ == nullptr) {
            return std::nullopt;
        }
        return wtf_client_get_state(handle_);
    }
    //! Begin an asynchronous session and return its retained handle.
    //! Success means setup started; on_connected reports CONNECT completion.
    //! Callbacks may run before Open() returns.
    [[nodiscard]] Result<Session> Open() const {
        if (!handle_ || !endpoint_->open()) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_STATE,
            });
        }
        wtf_session_t* session = nullptr;
        auto result = wtf_client_open(handle_, &session);
        if (result != WTF_SUCCESS) {
            return std::unexpected(Error{
                .code = result,
            });
        }
        return endpoint_->AdoptSession(session);
    }
    //! Close the client's connection with an application code and copied reason.
    [[nodiscard]] Result<> Disconnect(std::uint32_t code = 0, std::string_view reason = {}) const {
        const std::string terminated(reason);
        return internal::ResultFromStatus(
            wtf_client_disconnect(handle_, code, terminated.c_str())
        );
    }
    //! Destroy the native client and release handlers; the owner becomes empty.
    //! Invoke outside callbacks, with other application users synchronized.
    void Reset() noexcept {
        if (handle_) {
            endpoint_->BeginClose();
            wtf_client_destroy(std::exchange(handle_, nullptr));
            endpoint_->FinishClose();
            endpoint_.reset();
        }
    }

  private:
    wtf_client_t* handle_ = nullptr;
    std::shared_ptr<internal::EndpointState> endpoint_;
};

//! Move-only owner of a listening endpoint and its connections.
//! Destruction performs Reset(). Invoke it outside this endpoint's callbacks
//! after synchronizing other application users. A callback violation
//! terminates.
class Server {
  public:
    Server() = default;
    Server(const Server&) = delete;
    Server& operator=(const Server&) = delete;
    Server(Server&& other) noexcept
        : handle_(std::exchange(other.handle_, nullptr)),
          endpoint_(std::move(other.endpoint_)) {
    }
    Server& operator=(Server&& other) noexcept {
        if (this != &other) {
            Reset();
            handle_ = std::exchange(other.handle_, nullptr);
            endpoint_ = std::move(other.endpoint_);
        }
        return *this;
    }
    ~Server() {
        Reset();
    }

    //! Configure a server without starting its listener.
    //! @param context retained while this server or its application handles live
    //! @param options copied during creation, except borrowed platform identities
    //! @param handlers installed before Start(); shared across accepted sessions
    //! @param on_request optional validator; call Reject() or Defer() on its
    //! request
    //! @return a server owner, or a configuration/transport error
    //! Without on_request, libwtf's default Origin validation remains in force.
    [[nodiscard]] static Result<Server> Create(
        const Context& context,
        const ServerOptions& options,
        SessionHandlers handlers = {},
        std::move_only_function<void(ConnectionRequest&) noexcept> on_request = {}
    ) {
        if (!context || !internal::ValidTransportOptions(options.transport)) {
            return std::unexpected(Error{
                .code = WTF_ERROR_INVALID_PARAMETER,
            });
        }
        auto endpoint = internal::EndpointState::Create(context, std::move(handlers));
        endpoint->on_request = std::move(on_request);
        wtf_connection_validator_t validator = nullptr;
        if (endpoint->on_request) {
            validator = [](
                const wtf_connection_request_t* request,
                wtf_connection_response_t* response,
                void* context
            ) noexcept {
                auto* endpoint = static_cast<internal::EndpointState*>(context);
                return endpoint->Validate(request, response);
            };
        }
        auto certificate = options.certificate.native_config();
        wtf_server_config_t config{
            .host = nullptr,
            .port = options.port,
            .cert_config = &certificate,
            .draft = WTF_WEBTRANSPORT_DRAFT_AUTO,
            .max_sessions_per_connection = 0,
            .max_streams_per_session = 0,
            .max_data_per_session = 0,
            .stream_recv_window = 0,
            .conn_flow_control_window = 0,
            .idle_timeout_ms = 0,
            .handshake_timeout_ms = 0,
            .enable_0rtt = false,
            .enable_migration = false,
            .send_buffering = WTF_SEND_BUFFERING_DEFAULT,
            .connection_validator = validator,
            .session_callback = internal::SessionCallback,
            .user_context = endpoint.get(),
        };
        if (options.host) {
            config.host = options.host->c_str();
        }
        internal::ApplyTransportOptions(options.transport, config);
        wtf_server_t* handle = nullptr;
        auto result = wtf_server_create(context.native_handle(), &config, &handle);
        if (result != WTF_SUCCESS) {
            return std::unexpected(Error{
                .code = result,
            });
        }
        Server server;
        server.handle_ = handle;
        server.endpoint_ = std::move(endpoint);
        return server;
    }
    //! Return whether this owner contains a server, including stopped servers.
    [[nodiscard]] explicit operator bool() const noexcept {
        return handle_ != nullptr;
    }
    //! Borrow the native server; do not destroy it or replace wrapper callbacks.
    [[nodiscard]] wtf_server_t* native_handle() const noexcept {
        return handle_;
    }
    //! Return the current C server lifecycle state.
    [[nodiscard]] std::optional<wtf_server_state_t> state() const noexcept {
        if (handle_ == nullptr) {
            return std::nullopt;
        }
        return wtf_server_get_state(handle_);
    }
    //! Start listening using the configuration passed to Create().
    [[nodiscard]] Result<> Start() const noexcept {
        return internal::ResultFromStatus(wtf_server_start(handle_));
    }
    //! Stop accepting connections according to the C server's graceful-stop
    //! behavior.
    [[nodiscard]] Result<> Stop() const noexcept {
        return internal::ResultFromStatus(wtf_server_stop(handle_));
    }
    //! Stop and destroy the native server; the owner becomes empty.
    //! Invoke outside callbacks, with other application users synchronized.
    void Reset() noexcept {
        if (handle_) {
            endpoint_->BeginClose();
            wtf_server_destroy(std::exchange(handle_, nullptr));
            endpoint_->FinishClose();
            endpoint_.reset();
        }
    }

  private:
    wtf_server_t* handle_ = nullptr;
    std::shared_ptr<internal::EndpointState> endpoint_;
};

//! Return library-owned version information with static lifetime.
[[nodiscard]] inline const wtf_version_info_t& Version() noexcept {
    return *wtf_get_version();
}

//! Decode an application/transport error code. Description storage is
//! library-owned.
[[nodiscard]] inline Result<wtf_error_details_t> ErrorDetails(std::uint32_t code) noexcept {
    wtf_error_details_t details{};
    auto result = wtf_get_error_details(code, &details);
    if (result != WTF_SUCCESS) {
        return std::unexpected(Error{
            .code = result,
        });
    }
    return details;
}

}  // namespace wtf

#endif  // LIBWTF_INCLUDE_WTF_HPP_
