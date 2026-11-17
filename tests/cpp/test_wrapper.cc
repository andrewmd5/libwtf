#include "wtf.hpp"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>

wtf::Result<wtf::Client> CreateCppHeaderClient(
    const wtf::Context& context,
    wtf::SessionHandlers handlers
);

struct wtf_context {
    wtf_context_config_t config;
};
struct wtf_stream;
struct wtf_session {
    unsigned refs = 1;
    wtf_session_state_t state = WTF_SESSION_HANDSHAKING;
    wtf_session_callback_t callback = nullptr;
    void* context = nullptr;
    std::vector<wtf_stream*> streams;
};
struct wtf_stream {
    unsigned refs = 1;
    wtf_stream_state_t state = WTF_STREAM_OPEN;
    wtf_stream_type_t type = WTF_STREAM_BIDIRECTIONAL;
    wtf_stream_callback_t callback = nullptr;
    void* context = nullptr;
    std::uint64_t id = 0;
};
struct wtf_client {
    wtf_client_config_t config;
    std::vector<wtf_session*> sessions;
};
struct wtf_server {
    wtf_server_config_t config;
};
struct wtf_connection_request_handle {
    unsigned refs = 1;
    bool completed = false;
};

namespace {

struct StreamSend {
    wtf_stream_t* stream;
    std::vector<wtf_buffer_t> buffers;
    void* context;
};
struct DatagramSend {
    wtf_session_t* session;
    std::vector<wtf_buffer_t> buffers;
    void* context;
};
struct Mock {
    unsigned contexts = 0;
    unsigned clients = 0;
    unsigned servers = 0;
    unsigned sessions = 0;
    unsigned streams = 0;
    unsigned requests = 0;
    unsigned accepted = 0;
    unsigned rejected = 0;
    wtf_result_t create_result = WTF_SUCCESS;
    wtf_result_t send_result = WTF_SUCCESS;
    bool inline_receive = false;
    bool inline_complete = false;
    bool suppress_close_callbacks = false;
    std::vector<StreamSend> sends;
    std::vector<DatagramSend> datagrams;
    std::string url;
    std::optional<std::string> origin;
    std::string header_name;
    std::string header_value;
    wtf_client_config_t client_config{};
    wtf_server_config_t server_config{};
    wtf_certificate_type_t certificate_type = WTF_CERT_TYPE_NONE;
} mock;

void Receive(wtf_stream_t* stream) {
    std::uint8_t first[] = {'a', 'b'};
    std::uint8_t second[] = {'c'};
    wtf_buffer_t buffers[] = {
        {
            .length = 2,
            .data = first,
        },
        {
            .length = 1,
            .data = second,
        },
    };
    wtf_stream_event_t event{};
    event.type = WTF_STREAM_EVENT_DATA_RECEIVED;
    event.stream = stream;
    event.user_context = stream->context;
    event.data_received = {buffers, 2};
    stream->callback(&event);
}

void CloseStream(wtf_stream_t* stream) {
    stream->state = WTF_STREAM_CLOSED;
    if (stream->callback && !mock.suppress_close_callbacks) {
        wtf_stream_event_t event{};
        event.type = WTF_STREAM_EVENT_CLOSED;
        event.stream = stream;
        event.user_context = stream->context;
        stream->callback(&event);
    }
}

void CompleteSend(bool cancelled = false) {
    auto send = std::move(mock.sends.front());
    mock.sends.erase(mock.sends.begin());
    wtf_stream_event_t event{};
    event.type = WTF_STREAM_EVENT_SEND_COMPLETE;
    event.stream = send.stream;
    event.user_context = send.stream->context;
    event.send_complete = {
        .buffers = send.buffers.data(),
        .buffer_count = static_cast<std::uint32_t>(send.buffers.size()),
        .cancelled = cancelled,
        .operation_context = send.context,
    };
    send.stream->callback(&event);
}

void CompleteDatagram(wtf_datagram_send_state_t state) {
    const auto& send = mock.datagrams.front();
    wtf_session_event_t event{};
    event.type = WTF_SESSION_EVENT_DATAGRAM_SEND_STATE_CHANGE;
    event.session = send.session;
    event.user_context = send.session->context;
    event.datagram_send_state_changed = {
        .buffers = send.buffers.data(),
        .buffer_count = static_cast<std::uint32_t>(send.buffers.size()),
        .state = state,
        .operation_context = send.context,
    };
    send.session->callback(&event);
    if (WTF_DATAGRAM_SEND_STATE_IS_FINAL(state)) {
        mock.datagrams.erase(mock.datagrams.begin());
    }
}

class CppWrapper : public ::testing::Test {
  protected:
    void SetUp() override {
        mock = Mock{};
    }
    void TearDown() override {
        EXPECT_EQ(0u, mock.contexts);
        EXPECT_EQ(0u, mock.clients);
        EXPECT_EQ(0u, mock.servers);
        EXPECT_EQ(0u, mock.sessions);
        EXPECT_EQ(0u, mock.streams);
        EXPECT_EQ(0u, mock.requests);
        EXPECT_TRUE(mock.sends.empty());
        EXPECT_TRUE(mock.datagrams.empty());
    }

    wtf::Context Context() {
        auto context = wtf::Context::Create();
        EXPECT_TRUE(context);
        return std::move(*context);
    }
    wtf::Client Client(
        const wtf::Context& context,
        wtf::SessionHandlers handlers = {}
    ) {
        auto client = CreateCppHeaderClient(context, std::move(handlers));
        EXPECT_TRUE(client);
        return std::move(*client);
    }
};

TEST_F(CppWrapper, MoveOnlyOwnersKeepTheContextAliveForChildren) {
    static_assert(!std::is_copy_constructible_v<wtf::Context>);
    static_assert(!std::is_copy_constructible_v<wtf::Client>);
    static_assert(!std::is_copy_constructible_v<wtf::Server>);
    static_assert(std::is_nothrow_move_constructible_v<wtf::Client>);
    static_assert(std::is_nothrow_move_assignable_v<wtf::Server>);
    static_assert(std::is_copy_constructible_v<wtf::Session>);
    static_assert(std::is_nothrow_move_constructible_v<wtf::Stream>);

    auto context = Context();
    auto client = Client(context);
    auto moved = std::move(client);
    EXPECT_FALSE(client);
    context = {};
    EXPECT_EQ(1u, mock.contexts);
    moved.Reset();
    EXPECT_EQ(0u, mock.contexts);
}

TEST_F(CppWrapper, RetainedHandlesRemainValidAfterEndpointShutdown) {
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    ASSERT_TRUE(session);
    auto stream = session->OpenBidirectionalStream();
    ASSERT_TRUE(stream);
    auto copy = *stream;
    auto session_copy = *session;
    auto moved = std::move(copy);
    EXPECT_FALSE(copy);
    EXPECT_EQ(3u, stream->native_handle()->refs);
    client.Reset();
    context = {};
    EXPECT_EQ(wtf::StreamState::kClosed, moved.state());
    EXPECT_FALSE(moved.type());
    EXPECT_EQ(wtf::SessionState::kClosed, session_copy.state());
    EXPECT_EQ(1u, mock.contexts);
}

TEST_F(CppWrapper, HandlersExistBeforeCreationReturnsAndSurviveMoves) {
    mock.inline_receive = true;
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    ASSERT_TRUE(session);
    std::string received;

    auto stream = session->OpenBidirectionalStream({
        .on_data = [value = std::make_unique<int>(7), &received](
            wtf::StreamView stream,
            wtf::BufferSequence buffers
        ) noexcept {
            EXPECT_EQ(7, *value);
            EXPECT_TRUE(stream);
            EXPECT_EQ(3u, buffers.size_bytes());
            for (auto chunk : buffers.chunks()) {
                received.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
            }
        },
    });
    ASSERT_TRUE(stream);
    EXPECT_EQ("abc", received);
    auto moved = std::move(*stream);
    Receive(moved.native_handle());
    EXPECT_EQ("abcabc", received);
}

TEST_F(CppWrapper, IncomingStreamsInstallTheirOwnHandlers) {
    auto context = Context();
    unsigned receives = 0;
    wtf::Stream retained;
    auto client = Client(context, {
        .on_stream = [&receives, &retained](wtf::SessionView, wtf::StreamView stream) noexcept {
            retained = stream.Retain();
            return wtf::StreamHandlers{
                .on_data = [&receives](wtf::StreamView, wtf::BufferSequence) noexcept {
                    ++receives;
                },
            };
        },
    });
    auto session = client.Open();
    ASSERT_TRUE(session);
    auto* incoming = new wtf_stream;
    ++mock.streams;
    incoming->context = session->native_handle()->context;
    session->native_handle()->streams.push_back(incoming);
    wtf_session_event_t event{
        .type = WTF_SESSION_EVENT_STREAM_OPENED,
        .session = session->native_handle(),
        .user_context = session->native_handle()->context,
        .stream_opened = {
            .stream = incoming,
            .stream_type = WTF_STREAM_BIDIRECTIONAL,
        },
    };
    session->native_handle()->callback(&event);
    Receive(incoming);
    EXPECT_EQ(1u, receives);
    EXPECT_EQ(incoming, retained.native_handle());
}

TEST_F(CppWrapper, OwnedSendMovesPayloadAndRetainsItUntilCompletion) {
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenBidirectionalStream();
    unsigned completions = 0;
    wtf::ByteBuffer payload(1024, std::byte{0x5a});
    auto* address = payload.data();
    auto lifetime = std::make_shared<int>(1);
    std::weak_ptr weak = lifetime;

    ASSERT_TRUE(stream->Send(std::move(payload), {
        .fin = true,
        .on_complete = [keep = std::move(lifetime), &completions](
            wtf::SendCompletion completion
        ) noexcept {
            EXPECT_FALSE(completion.cancelled);
            ++completions;
        },
    }));
    ASSERT_EQ(1u, mock.sends.size());
    EXPECT_EQ(address, reinterpret_cast<const std::byte*>(mock.sends[0].buffers[0].data));
    EXPECT_EQ(0x5a, mock.sends[0].buffers[0].data[1023]);
    EXPECT_FALSE(weak.expired());
    CompleteSend();
    EXPECT_EQ(1u, completions);
    EXPECT_TRUE(weak.expired());
}

TEST_F(CppWrapper, InlineSendCompletionDoesNotUseDestroyedOperationState) {
    mock.inline_complete = true;
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenUnidirectionalStream();
    unsigned completions = 0;
    EXPECT_TRUE(stream->Send(wtf::ByteBuffer(16, std::byte{0x2a}), {
        .on_complete = [&completions](wtf::SendCompletion) noexcept {
            ++completions;
        },
    }));
    EXPECT_EQ(1u, completions);
    EXPECT_TRUE(mock.sends.empty());
}

TEST_F(CppWrapper, ImmediateSendFailureReleasesOwnershipWithoutCompletion) {
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenBidirectionalStream();
    mock.send_result = WTF_ERROR_FLOW_CONTROL;
    auto lifetime = std::make_shared<int>(1);
    std::weak_ptr weak = lifetime;
    auto result = stream->Send(wtf::ByteBuffer(16), {
        .on_complete = [keep = std::move(lifetime)](wtf::SendCompletion) noexcept {
            ADD_FAILURE() << "Immediate failure must not report completion";
        },
    });
    ASSERT_FALSE(result);
    EXPECT_EQ(WTF_ERROR_FLOW_CONTROL, result.error().code);
    EXPECT_TRUE(weak.expired());
}

TEST_F(CppWrapper, BorrowedScatterGatherPreservesPointersAndUserToken) {
    auto context = Context();
    void* token = &context;
    unsigned completions = 0;
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenBidirectionalStream({
        .on_send_complete = [&](wtf::StreamView, wtf::SendCompletion completion) noexcept {
            EXPECT_EQ(token, completion.context);
            ++completions;
        },
    });
    std::uint8_t first[] = {1, 2};
    std::uint8_t second[] = {3};
    wtf_buffer_t buffers[] = {
        {
            .length = 2,
            .data = first,
        },
        {
            .length = 1,
            .data = second,
        },
    };
    ASSERT_TRUE(stream->SendBorrowed(buffers, {
        .context = token,
    }));
    ASSERT_EQ(2u, mock.sends[0].buffers.size());
    EXPECT_EQ(first, mock.sends[0].buffers[0].data);
    EXPECT_EQ(second, mock.sends[0].buffers[1].data);
    CompleteSend();
    EXPECT_EQ(1u, completions);
}

TEST_F(CppWrapper, DatagramOwnershipSurvivesIntermediateStates) {
    auto context = Context();
    unsigned states = 0;
    unsigned completions = 0;
    void* token = &context;
    auto client = Client(context, {
        .on_datagram_send_state = [&](wtf::SessionView, wtf::DatagramCompletion event) noexcept {
            EXPECT_EQ(token, event.context);
            ++states;
        },
    });
    auto session = client.Open();
    auto lifetime = std::make_shared<int>(1);
    std::weak_ptr weak = lifetime;
    ASSERT_TRUE(session->SendDatagram(wtf::ByteBuffer(32, std::byte{0x33}), {
        .context = token,
        .on_complete = [keep = std::move(lifetime), &completions](
            wtf::DatagramCompletion event
        ) noexcept {
            EXPECT_TRUE(event.final());
            ++completions;
        },
    }));
    CompleteDatagram(WTF_DATAGRAM_SEND_SENT);
    EXPECT_FALSE(weak.expired());
    EXPECT_EQ(0u, completions);
    EXPECT_EQ(0x33, mock.datagrams[0].buffers[0].data[31]);
    CompleteDatagram(WTF_DATAGRAM_SEND_ACKNOWLEDGED);
    EXPECT_TRUE(weak.expired());
    EXPECT_EQ(2u, states);
    EXPECT_EQ(1u, completions);
}

TEST_F(CppWrapper, ShutdownCancelsOwnedSendsWhenNativeCallbacksAreSuppressed) {
    auto context = Context();
    unsigned cancelled = 0;
    unsigned datagrams_cancelled = 0;
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenBidirectionalStream();
    EXPECT_TRUE(stream->Send(wtf::ByteBuffer(32, std::byte{0x11}), {
        .on_complete = [&cancelled](wtf::SendCompletion event) noexcept {
            EXPECT_TRUE(event.cancelled);
            ++cancelled;
        },
    }));
    EXPECT_TRUE(session->SendDatagram(wtf::ByteBuffer(32), {
        .on_complete = [&datagrams_cancelled](wtf::DatagramCompletion event) noexcept {
            EXPECT_EQ(WTF_DATAGRAM_SEND_CANCELED, event.state);
            ++datagrams_cancelled;
        },
    }));
    mock.suppress_close_callbacks = true;
    client.Reset();
    EXPECT_EQ(1u, cancelled);
    EXPECT_EQ(1u, datagrams_cancelled);
}

TEST_F(CppWrapper, ReentrantStreamCloseKeepsTheExecutingHandlerAlive) {
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    unsigned received = 0;
    auto stream = session->OpenBidirectionalStream({
        .on_data = [value = std::make_unique<int>(9), &received](
            wtf::StreamView stream,
            wtf::BufferSequence
        ) noexcept {
            CloseStream(stream.native_handle());
            EXPECT_EQ(9, *value);
            ++received;
        },
    });
    Receive(stream->native_handle());
    EXPECT_EQ(1u, received);
}

TEST_F(CppWrapper, ConfigurationUsesOwnedStringsAndRejectsInvalidDurations) {
    auto context = Context();
    wtf::ClientOptions options{
        .url = "https://localhost:4433/game",
        .origin = "https://game.example",
        .headers = {
            {
                .name = "x-game",
                .value = "doom",
            },
        },
        .transport = {
            .draft = wtf::Draft::k07,
            .max_sessions_per_connection = 3,
            .max_streams_per_session = 64,
            .max_data_per_session = 1024,
            .stream_recv_window = 4096,
            .conn_flow_control_window = 65536,
            .idle_timeout = std::chrono::milliseconds(1200),
            .handshake_timeout = std::chrono::milliseconds(500),
            .enable_0rtt = true,
            .enable_migration = true,
            .send_buffering = wtf::SendBuffering::kDisabled,
        },
        .allow_pooling = true,
        .congestion_control = wtf::CongestionControl::kThroughput,
        .skip_certificate_validation = true,
    };
    auto client = wtf::Client::Create(context, options);
    ASSERT_TRUE(client);
    EXPECT_EQ(options.url, mock.url);
    EXPECT_EQ("x-game", mock.header_name);
    EXPECT_EQ("doom", mock.header_value);
    EXPECT_EQ(WTF_WEBTRANSPORT_DRAFT_07, mock.client_config.draft);
    EXPECT_EQ(64u, mock.client_config.max_streams_per_session);
    EXPECT_EQ(1200u, mock.client_config.idle_timeout_ms);
    EXPECT_EQ(500u, mock.client_config.handshake_timeout_ms);
    EXPECT_EQ(WTF_SEND_BUFFERING_DISABLED, mock.client_config.send_buffering);
    EXPECT_TRUE(mock.client_config.enable_0rtt);
    EXPECT_TRUE(mock.client_config.enable_migration);
    EXPECT_EQ(WTF_CONGESTION_CONTROL_THROUGHPUT, mock.client_config.congestion_control);
    options.transport.idle_timeout = std::chrono::milliseconds(-1);
    EXPECT_FALSE(wtf::Client::Create(context, options));
}

TEST_F(CppWrapper, FailedFactoriesReleaseCallbackCaptures) {
    auto context = Context();
    auto lifetime = std::make_shared<int>(1);
    std::weak_ptr weak = lifetime;
    mock.create_result = WTF_ERROR_OUT_OF_MEMORY;
    auto client = wtf::Client::Create(
        context,
        {
            .url = "https://localhost:4433/",
        },
        {
            .on_connected = [keep = std::move(lifetime)](
                wtf::SessionView,
                wtf::ConnectResponse
            ) noexcept {
            },
        }
    );
    ASSERT_FALSE(client);
    EXPECT_EQ(WTF_ERROR_OUT_OF_MEMORY, client.error().code);
    EXPECT_TRUE(weak.expired());
}

TEST_F(CppWrapper, DeferredRequestsCompleteOnceAndRejectWhenDropped) {
    auto context = Context();
    std::optional<wtf::DeferredRequest> pending;
    auto server = wtf::Server::Create(
        context,
        {},
        {},
        [&](wtf::ConnectionRequest& request) noexcept {
            EXPECT_EQ("/game", request.path());
            EXPECT_TRUE(request.AddHeader("x-test", "ok"));
            auto deferred = request.Defer();
            ASSERT_TRUE(deferred);
            pending.emplace(std::move(*deferred));
        }
    );
    ASSERT_TRUE(server);
    for (unsigned attempt = 0; attempt < 2; ++attempt) {
        auto* handle = new wtf_connection_request_handle;
        ++mock.requests;
        wtf_connection_request_t request{};
        request.path = "/game";
        request.handle = handle;
        wtf_connection_response_t response{};
        auto* native = server->native_handle();
        EXPECT_EQ(WTF_CONNECTION_DEFER,
                  native->config.connection_validator(&request,
                                                      &response,
                                                      native->config.user_context));
        ASSERT_TRUE(pending);
        if (attempt == 0) {
            EXPECT_TRUE(pending->Accept());
            EXPECT_FALSE(pending->Reject());
        }
        pending.reset();
    }
    EXPECT_EQ(1u, mock.accepted);
    EXPECT_EQ(1u, mock.rejected);
}

TEST_F(CppWrapper, CertificateVariantsUseTheCorrespondingCRepresentation) {
    auto context = Context();
    wtf::ServerOptions options{
        .certificate = {
            .identity = wtf::Certificate::PemFiles{
                .certificate = "cert.pem",
                .key = "key.pem",
            },
        },
    };
    auto server = wtf::Server::Create(context, options);
    ASSERT_TRUE(server);
    EXPECT_EQ(WTF_CERT_TYPE_FILE, mock.certificate_type);
    server->Reset();
    options.certificate = {
        .identity = wtf::Certificate::Pkcs12Data{
            .data = wtf::ByteBuffer(8),
            .password = "password",
        },
    };
    server = wtf::Server::Create(context, options);
    ASSERT_TRUE(server);
    EXPECT_EQ(WTF_CERT_TYPE_PKCS12, mock.certificate_type);
}

TEST_F(CppWrapper, OptionalConfigurationPreservesAbsentAndEmptyStrings) {
    auto context = Context();
    wtf::ClientOptions options{
        .url = "https://localhost:4433/",
    };
    auto absent = wtf::Client::Create(context, options);
    ASSERT_TRUE(absent);
    EXPECT_FALSE(mock.origin.has_value());
    absent->Reset();
    options.origin = std::string{};
    auto empty = wtf::Client::Create(context, options);
    ASSERT_TRUE(empty);
    ASSERT_TRUE(mock.origin.has_value());
    EXPECT_TRUE(mock.origin->empty());
    wtf::Certificate certificate{
        .identity = wtf::Certificate::Pkcs12Data{
            .data = wtf::ByteBuffer(8),
        },
    };
    EXPECT_EQ(nullptr, certificate.native_config().principal);
    EXPECT_EQ(nullptr, certificate.native_config().cert_data.pkcs12.password);
    certificate.principal = std::string{};
    ASSERT_NE(nullptr, certificate.native_config().principal);
    EXPECT_STREQ("", certificate.native_config().principal);
}

TEST_F(CppWrapper, NullableCallbackMetadataDoesNotInventEmptyValues) {
    auto context = Context();
    unsigned calls = 0;
    auto client = Client(context, {
        .on_disconnected = [&calls](wtf::SessionView, wtf::DisconnectInfo info) noexcept {
            if (calls == 0) {
                EXPECT_FALSE(info.reason.has_value());
                EXPECT_FALSE(info.response.has_value());
            } else {
                ASSERT_TRUE(info.reason.has_value());
                EXPECT_TRUE(info.reason->empty());
                ASSERT_TRUE(info.response.has_value());
                EXPECT_EQ(403, info.response->status_code);
            }
            ++calls;
        },
    });
    auto session = client.Open();
    ASSERT_TRUE(session);
    auto* handle = session->native_handle();
    wtf_session_event_t event{
        .type = WTF_SESSION_EVENT_DISCONNECTED,
        .session = handle,
        .user_context = handle->context,
        .disconnected = {},
    };
    handle->callback(&event);
    event.disconnected.reason = "";
    event.disconnected.status_code = 403;
    handle->callback(&event);
    EXPECT_EQ(2u, calls);
}

TEST_F(CppWrapper, NullableLogFieldsRemainOptional) {
    unsigned calls = 0;
    auto context = wtf::Context::Create({
        .on_log = [&calls](const wtf::LogMessage& entry) noexcept {
            if (calls == 0) {
                EXPECT_FALSE(entry.component);
                EXPECT_FALSE(entry.file);
                EXPECT_FALSE(entry.line);
                EXPECT_FALSE(entry.message);
            } else {
                ASSERT_TRUE(entry.component);
                EXPECT_TRUE(entry.component->empty());
                ASSERT_TRUE(entry.file);
                EXPECT_TRUE(entry.file->empty());
                ASSERT_TRUE(entry.message);
                EXPECT_TRUE(entry.message->empty());
                EXPECT_EQ(10, entry.line);
            }
            ++calls;
        },
    });
    ASSERT_TRUE(context);
    auto* native = context->native_handle();
    native->config.log_callback(WTF_LOG_LEVEL_INFO,
                                nullptr,
                                nullptr,
                                0,
                                nullptr,
                                native->config.log_user_context);
    native->config.log_callback(WTF_LOG_LEVEL_INFO,
                                "",
                                "",
                                10,
                                "",
                                native->config.log_user_context);
    EXPECT_EQ(2u, calls);
}

TEST_F(CppWrapper, EmptyHandlesAndPendingIdsHaveNoInventedState) {
    wtf::Stream empty_stream;
    wtf::Session empty_session;
    EXPECT_FALSE(empty_stream.state());
    EXPECT_FALSE(empty_stream.type());
    EXPECT_FALSE(empty_stream.id());
    EXPECT_FALSE(empty_session.state());
    EXPECT_FALSE(empty_session.max_datagram_size());
    auto context = Context();
    auto client = Client(context);
    auto session = client.Open();
    auto stream = session->OpenBidirectionalStream();
    stream->native_handle()->id = std::numeric_limits<std::uint64_t>::max();
    auto pending_id = stream->id();
    ASSERT_TRUE(pending_id);
    EXPECT_FALSE(pending_id->has_value());
    EXPECT_FALSE(session->FindStreamById(999));
}

TEST_F(CppWrapper, ExplicitZeroLimitsAreRejectedInsteadOfSelectingDefaults) {
    auto context = Context();
    auto client = wtf::Client::Create(context, {
        .url = "https://localhost:4433/",
        .transport = {
            .max_streams_per_session = 0,
        },
    });
    ASSERT_FALSE(client);
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, client.error().code);
}

TEST_F(CppWrapper, ResetReleasesHandlersWhileClosedHandlesRemainRetained) {
    auto context = Context();
    auto lifetime = std::make_shared<int>(1);
    std::weak_ptr weak = lifetime;
    auto client = Client(context, {
        .on_connected = [keep = std::move(lifetime)](
            wtf::SessionView,
            wtf::ConnectResponse
        ) noexcept {
        },
    });
    auto session = client.Open();
    ASSERT_TRUE(session);
    EXPECT_FALSE(weak.expired());
    client.Reset();
    EXPECT_TRUE(weak.expired());
    EXPECT_TRUE(session);
}

}  // namespace

extern "C" {
wtf_result_t wtf_context_create(
    const wtf_context_config_t* config,
    wtf_context_t** out
) {
    if (mock.create_result != WTF_SUCCESS) {
        return mock.create_result;
    }
    *out = new wtf_context{
        .config = *config,
    };
    ++mock.contexts;
    return WTF_SUCCESS;
}
void wtf_context_destroy(wtf_context_t* context) {
    if (context) {
        --mock.contexts;
        delete context;
    }
}
wtf_result_t wtf_context_set_log_level(wtf_context_t*, wtf_log_level_t) {
    return WTF_SUCCESS;
}
const char* wtf_result_to_string(wtf_result_t) {
    return "mock error";
}

wtf_result_t wtf_client_create(
    wtf_context_t*,
    const wtf_client_config_t* config,
    wtf_client_t** out
) {
    if (mock.create_result != WTF_SUCCESS) {
        return mock.create_result;
    }
    *out = new wtf_client{
        .config = *config,
        .sessions = {},
    };
    mock.client_config = *config;
    mock.url = config->url;
    if (config->origin != nullptr) {
        mock.origin = std::string(config->origin);
    } else {
        mock.origin = std::nullopt;
    }
    if (config->header_count) {
        mock.header_name = config->headers[0].name;
        mock.header_value = config->headers[0].value;
    }
    ++mock.clients;
    return WTF_SUCCESS;
}
wtf_result_t wtf_client_open(wtf_client_t* client, wtf_session_t** out) {
    auto* session = new wtf_session;
    ++mock.sessions;
    session->callback = client->config.session_callback;
    session->context = client->config.user_context;
    session->state = WTF_SESSION_CONNECTED;
    client->sessions.push_back(session);
    wtf_session_ref(session);
    *out = session;
    wtf_session_event_t event{};
    event.type = WTF_SESSION_EVENT_CONNECTED;
    event.session = session;
    event.user_context = session->context;
    session->callback(&event);
    return WTF_SUCCESS;
}
void wtf_client_destroy(wtf_client_t* client) {
    if (!client) {
        return;
    }
    // Pending bytes must survive until the underlying endpoint is destroyed.
    if (!mock.sends.empty() && mock.sends.front().buffers[0].length) {
        EXPECT_NE(nullptr, mock.sends.front().buffers[0].data);
        const volatile auto first_byte = mock.sends.front().buffers[0].data[0];
        static_cast<void>(first_byte);
    }
    if (mock.suppress_close_callbacks) {
        mock.sends.clear();
        mock.datagrams.clear();
    } else {
        while (!mock.sends.empty()) {
            CompleteSend(true);
        }
        while (!mock.datagrams.empty()) {
            CompleteDatagram(WTF_DATAGRAM_SEND_CANCELED);
        }
    }
    for (auto* session : client->sessions) {
        session->state = WTF_SESSION_CLOSED;
        for (auto* stream : session->streams) {
            if (stream->state != WTF_STREAM_CLOSED) {
                CloseStream(stream);
            }
            wtf_stream_unref(stream);
        }
        wtf_session_unref(session);
    }
    delete client;
    --mock.clients;
}
wtf_result_t wtf_client_disconnect(wtf_client_t*, std::uint32_t, const char*) {
    return WTF_SUCCESS;
}
wtf_client_state_t wtf_client_get_state(wtf_client_t* client) {
    return client ? WTF_CLIENT_CONNECTED : WTF_CLIENT_CLOSED;
}
wtf_result_t wtf_server_create(
    wtf_context_t*,
    const wtf_server_config_t* config,
    wtf_server_t** out
) {
    *out = new wtf_server{
        .config = *config,
    };
    mock.server_config = *config;
    mock.certificate_type = config->cert_config->cert_type;
    ++mock.servers;
    return WTF_SUCCESS;
}
void wtf_server_destroy(wtf_server_t* server) {
    if (server) {
        delete server;
        --mock.servers;
    }
}
wtf_result_t wtf_server_start(wtf_server_t*) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_server_stop(wtf_server_t*) {
    return WTF_SUCCESS;
}
wtf_server_state_t wtf_server_get_state(wtf_server_t*) {
    return WTF_SERVER_LISTENING;
}
void wtf_session_ref(wtf_session_t* session) {
    if (session) {
        ++session->refs;
    }
}
void wtf_session_unref(wtf_session_t* session) {
    if (session && --session->refs == 0) {
        delete session;
        --mock.sessions;
    }
}
wtf_session_state_t wtf_session_get_state(wtf_session_t* session) {
    return session ? session->state : WTF_SESSION_CLOSED;
}
wtf_result_t wtf_session_close(wtf_session_t*, std::uint32_t, const char*) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_session_drain(wtf_session_t*) {
    return WTF_SUCCESS;
}
std::uint32_t wtf_session_get_max_datagram_size(wtf_session_t* session) {
    if (session == nullptr) {
        return 0;
    }
    return 1200;
}
wtf_result_t wtf_session_get_peer_address(
    wtf_session_t*,
    void* buffer,
    std::size_t* size
) {
    if (*size < 4) {
        *size = 4;
        return WTF_ERROR_BUFFER_TOO_SMALL;
    }
    std::memset(buffer, 0, 4);
    *size = 4;
    return WTF_SUCCESS;
}
wtf_result_t wtf_session_create_stream(
    wtf_session_t* session,
    wtf_stream_type_t type,
    wtf_stream_callback_t callback,
    void* context,
    wtf_stream_t** out
) {
    auto* stream = new wtf_stream;
    ++mock.streams;
    stream->type = type;
    stream->callback = callback;
    stream->context = context;
    session->streams.push_back(stream);
    wtf_stream_ref(stream);
    if (mock.inline_receive) {
        Receive(stream);
    }
    *out = stream;
    return WTF_SUCCESS;
}
wtf_stream_t* wtf_session_find_stream_by_id(
    wtf_session_t* session,
    std::uint64_t id
) {
    if (id >= session->streams.size()) {
        return nullptr;
    }
    auto* stream = session->streams[id];
    wtf_stream_ref(stream);
    return stream;
}
wtf_result_t wtf_session_send_datagram(
    wtf_session_t* session,
    const wtf_buffer_t* buffers,
    std::uint32_t count,
    void* context
) {
    if (mock.send_result != WTF_SUCCESS) {
        return mock.send_result;
    }
    mock.datagrams.push_back({
        .session = session,
        .buffers = {buffers, buffers + count},
        .context = context,
    });
    return WTF_SUCCESS;
}
wtf_result_t wtf_session_send_datagram_copy(
    wtf_session_t*,
    const void*,
    std::size_t
) {
    return WTF_SUCCESS;
}
void wtf_stream_ref(wtf_stream_t* stream) {
    if (stream) {
        ++stream->refs;
    }
}
void wtf_stream_unref(wtf_stream_t* stream) {
    if (stream && --stream->refs == 0) {
        delete stream;
        --mock.streams;
    }
}
wtf_stream_state_t wtf_stream_get_state(wtf_stream_t* stream) {
    return stream ? stream->state : WTF_STREAM_CLOSED;
}
wtf_stream_type_t wtf_stream_get_type(wtf_stream_t* stream) {
    return stream ? stream->type : WTF_STREAM_BIDIRECTIONAL;
}
void* wtf_stream_get_context(wtf_stream_t* stream) {
    return stream->context;
}
void wtf_stream_set_context(wtf_stream_t* stream, void* context) {
    stream->context = context;
}
void wtf_stream_set_callback(
    wtf_stream_t* stream,
    wtf_stream_callback_t callback
) {
    stream->callback = callback;
}
wtf_result_t wtf_stream_get_id(wtf_stream_t* stream, std::uint64_t* id) {
    if (stream == nullptr) {
        return WTF_ERROR_INVALID_PARAMETER;
    }
    *id = stream->id;
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_close(wtf_stream_t*) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_abort(wtf_stream_t*, std::uint32_t) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_set_priority(wtf_stream_t*, std::uint16_t) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_set_receive_enabled(wtf_stream_t*, bool) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_send(
    wtf_stream_t* stream,
    const wtf_buffer_t* buffers,
    std::uint32_t count,
    bool,
    void* context
) {
    if (mock.send_result != WTF_SUCCESS) {
        return mock.send_result;
    }
    mock.sends.push_back({
        .stream = stream,
        .buffers = {buffers, buffers + count},
        .context = context,
    });
    if (mock.inline_complete) {
        CompleteSend();
    }
    return WTF_SUCCESS;
}
wtf_result_t wtf_stream_send_copy(
    wtf_stream_t*,
    const void*,
    std::size_t,
    bool
) {
    return WTF_SUCCESS;
}
void wtf_connection_request_ref(wtf_connection_request_handle_t* handle) {
    if (handle) {
        ++handle->refs;
    }
}
void wtf_connection_request_unref(wtf_connection_request_handle_t* handle) {
    if (handle && --handle->refs == 0) {
        delete handle;
        --mock.requests;
    }
}
wtf_result_t wtf_connection_request_complete(
    wtf_connection_request_handle_t* handle,
    wtf_connection_decision_t decision
) {
    if (handle->completed) {
        return WTF_ERROR_INVALID_STATE;
    }
    handle->completed = true;
    if (decision == WTF_CONNECTION_ACCEPT) {
        ++mock.accepted;
    } else {
        ++mock.rejected;
    }
    wtf_connection_request_unref(handle);
    return WTF_SUCCESS;
}
wtf_result_t wtf_connection_request_add_response_header(
    wtf_connection_request_handle_t*,
    const char*,
    const char*
) {
    return WTF_SUCCESS;
}
wtf_result_t wtf_connection_response_add_header(
    wtf_connection_response_t*,
    const char*,
    const char*
) {
    return WTF_SUCCESS;
}
}  // extern "C"
