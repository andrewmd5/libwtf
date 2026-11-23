#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <vector>

extern "C" {
#include "conn.h"
#include "http3.h"
#include "qpack.h"
#include "session.h"
#include "stream.h"
#include "utils.h"

void wtf_test_echo_session(wtf_session_t*);
void wtf_test_echo_stream(wtf_session_t*, wtf_stream_t*);
wtf_result_t wtf_test_echo_send(wtf_stream_t*, const void*, size_t);
size_t wtf_test_echo_queued(void);
void wtf_test_echo_disconnected(const wtf_session_event_t*);
}

namespace {

struct PendingSend {
    HQUIC handle;
    void* context;
};

std::vector<PendingSend> pending_sends;
unsigned closed_handles;
unsigned disconnects;
bool fail_send;
wtf_session* retained_session;

QUIC_STATUS QUIC_API GetParam(HQUIC, uint32_t, uint32_t*, void*)
{
    // Terminal cleanup must work even if querying a stream ID fails.
    return QUIC_STATUS_INVALID_STATE;
}

void QUIC_API StreamClose(HQUIC) { ++closed_handles; }

QUIC_STATUS QUIC_API StreamShutdown(HQUIC, QUIC_STREAM_SHUTDOWN_FLAGS, QUIC_UINT62)
{
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API StreamOpen(HQUIC, QUIC_STREAM_OPEN_FLAGS, QUIC_STREAM_CALLBACK_HANDLER,
                                void* context, HQUIC* stream)
{
    *stream = reinterpret_cast<HQUIC>(context);
    return QUIC_STATUS_SUCCESS;
}

QUIC_STATUS QUIC_API StreamSend(HQUIC handle, const QUIC_BUFFER*, uint32_t,
                                QUIC_SEND_FLAGS, void* context)
{
    if (fail_send) return QUIC_STATUS_OUT_OF_MEMORY;
    if (context) pending_sends.push_back({handle, context});
    return QUIC_STATUS_SUCCESS;
}

void Disconnected(const wtf_session_event_t* event)
{
    if (event->type == WTF_SESSION_EVENT_DISCONNECTED) ++disconnects;
}

void RetainOnDisconnect(const wtf_session_event_t* event)
{
    Disconnected(event);
    retained_session = event->session;
    wtf_session_ref(retained_session);
}

class LifetimeRegression : public ::testing::Test {
protected:
    QUIC_API_TABLE api = {};
    wtf_context context = {};
    wtf_server server = {};
    wtf_connection* conn = nullptr;
    std::vector<wtf_http3_stream*> connects;
    std::vector<wtf_stream*> children;
    uintptr_t next_handle = 1;

    void SetUp() override
    {
        api.GetParam = GetParam;
        api.StreamClose = StreamClose;
        api.StreamShutdown = StreamShutdown;
        api.StreamOpen = StreamOpen;
        api.StreamSend = StreamSend;
        context.quic_api = &api;
        server.context = &context;
        conn = wtf_connection_create(&server, nullptr);
        ASSERT_NE(nullptr, conn);
        closed_handles = disconnects = 0;
        fail_send = false;
        retained_session = nullptr;
        pending_sends.clear();
    }

    HQUIC Handle() { return reinterpret_cast<HQUIC>(next_handle++); }

    wtf_session* Session()
    {
        auto* h3 = wtf_http3_stream_create(conn, Handle(), UINT64_MAX);
        h3->id = next_handle * 4;
        connects.push_back(h3);
        auto* session = wtf_session_create(conn, h3);
        session->state = WTF_SESSION_CONNECTED;
        session->callback = Disconnected;
        h3->webtransport_session = session;
        wtf_session_add_ref(session); // CONNECT's owner, separate from the live map.
        session_map_insert(&conn->sessions, session->id, session);
        return session;
    }

    wtf_stream* EchoStream(wtf_session* session)
    {
        auto* stream = wtf_stream_create(session, next_handle * 4, WTF_STREAM_BIDIRECTIONAL);
        stream->quic_stream = Handle();
        stream->state = WTF_INTERNAL_STREAM_STATE_OPEN;
        stream->user_context = session->user_context;
        children.push_back(stream);
        wtf_test_echo_stream(session, stream);
        return stream;
    }

    void CompleteSends(bool cancelled = false)
    {
        auto sends = std::move(pending_sends);
        pending_sends.clear();
        for (auto send : sends) {
            wtf_stream* owner = nullptr;
            for (auto* stream : children) {
                if (stream->quic_stream == send.handle) owner = stream;
            }
            if (owner) {
                QUIC_STREAM_EVENT event = {};
                event.Type = QUIC_STREAM_EVENT_SEND_COMPLETE;
                event.SEND_COMPLETE.ClientContext = send.context;
                event.SEND_COMPLETE.Canceled = cancelled;
                EXPECT_EQ(QUIC_STATUS_SUCCESS,
                          wtf_upgraded_stream_callback(send.handle, owner, &event));
            } else {
                wtf_internal_send_context_destroy(
                    static_cast<wtf_internal_send_context*>(send.context));
            }
        }
    }

    void Finish(wtf_http3_stream* stream)
    {
        QUIC_STREAM_EVENT event = {};
        event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
        EXPECT_EQ(QUIC_STATUS_SUCCESS,
                  wtf_http3_stream_callback(stream->quic_stream, stream, &event));
    }

    void TearDown() override
    {
        CompleteSends(true);
        for (auto* stream : children) {
            QUIC_STREAM_EVENT event = {};
            event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
            wtf_upgraded_stream_callback(stream->quic_stream, stream, &event);
        }
        for (auto* stream : connects) Finish(stream);
        if (retained_session) wtf_session_unref(retained_session);
        EXPECT_EQ(0u, wtf_test_echo_queued());
        EXPECT_EQ(0u, session_map_size(&conn->sessions));
        EXPECT_EQ(0u, http3_stream_map_size(&conn->streams));
        EXPECT_EQ(1u, atomic_load(&conn->ref_count));
        wtf_connection_destroy(conn);
    }
};

TEST_F(LifetimeRegression, StreamCreationInstallsCallbackBeforeStarting)
{
    auto* session = Session();
    wtf_stream_t* stream = nullptr;
    struct CallbackState {
        wtf_stream_t** output;
        wtf_stream_t* received_stream;
    } state = {&stream, nullptr};

    api.StreamSend = [](HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count,
                        QUIC_SEND_FLAGS flags, void* context) {
        QUIC_STATUS status = StreamSend(handle, buffers, count, flags, context);
        auto* stream = reinterpret_cast<wtf_stream*>(handle);
        QUIC_STREAM_EVENT started = {};
        started.Type = QUIC_STREAM_EVENT_START_COMPLETE;
        started.START_COMPLETE.Status = QUIC_STATUS_SUCCESS;
        started.START_COMPLETE.ID = 1;
        wtf_upgraded_stream_callback(handle, stream, &started);

        uint8_t payload = 0x5a;
        QUIC_BUFFER buffer = {1, &payload};
        QUIC_STREAM_EVENT receive = {};
        receive.Type = QUIC_STREAM_EVENT_RECEIVE;
        receive.RECEIVE.Buffers = &buffer;
        receive.RECEIVE.BufferCount = 1;
        receive.RECEIVE.TotalBufferLength = 1;
        wtf_upgraded_stream_callback(handle, stream, &receive);
        return status;
    };

    ASSERT_EQ(WTF_SUCCESS, wtf_session_create_stream(session, WTF_STREAM_BIDIRECTIONAL,
        [](const wtf_stream_event_t* event) {
            if (event->type != WTF_STREAM_EVENT_DATA_RECEIVED) {
                return;
            }
            auto* state = static_cast<CallbackState*>(event->user_context);
            ASSERT_NE(nullptr, state);
            EXPECT_EQ(nullptr, *state->output);
            state->received_stream = event->stream;
            ASSERT_EQ(1u, event->data_received.buffer_count);
            ASSERT_EQ(1u, event->data_received.buffers[0].length);
            EXPECT_EQ(0x5a, event->data_received.buffers[0].data[0]);
        }, &state, &stream));
    ASSERT_NE(nullptr, stream);
    EXPECT_EQ(stream, state.received_stream);
    EXPECT_EQ(&state, wtf_stream_get_context(stream));

    auto* created = static_cast<wtf_stream*>(stream);
    children.push_back(created);
    CompleteSends();
    QUIC_STREAM_EVENT shutdown = {};
    shutdown.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
    wtf_upgraded_stream_callback(created->quic_stream, created, &shutdown);
    children.pop_back();
    wtf_stream_unref(stream);
}

TEST_F(LifetimeRegression, CustomStatsOwnTheirKeysAndStayWithTheirSession)
{
    auto* first = Session();
    auto* second = Session();
    char key[] = "app.frames";
    ASSERT_EQ(WTF_SUCCESS, wtf_session_set_stat(first, key, 4));
    key[4] = 'x';

    uint64_t value = 99;
    ASSERT_EQ(WTF_SUCCESS, wtf_session_get_stat(first, "app.frames", &value));
    EXPECT_EQ(4u, value);
    EXPECT_EQ(WTF_ERROR_NOT_FOUND, wtf_session_get_stat(second, "app.frames", &value));
    EXPECT_EQ(4u, value);
    EXPECT_EQ(WTF_ERROR_NOT_FOUND, wtf_session_get_stat(first, "quic.unknown", &value));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_session_set_stat(first, "quic.packets_sent", 1));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_remove_stat(first, "app."));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_get_stat(first, "app.frames", nullptr));

    ASSERT_EQ(WTF_SUCCESS, wtf_session_set_stat(first, "app.frames", 0));
    wtf_session_shutdown(first, 0, "closed");
    ASSERT_EQ(WTF_SUCCESS, wtf_session_get_stat(first, "app.frames", &value));
    EXPECT_EQ(0u, value);
    EXPECT_EQ(WTF_SUCCESS, wtf_session_remove_stat(first, "app.frames"));
    EXPECT_EQ(WTF_ERROR_NOT_FOUND, wtf_session_remove_stat(first, "app.frames"));
}

template <typename Bits, typename Value>
void ExpectCustomStatRoundTrip(wtf_session_t* session, const char* key, Value original)
{
    static_assert(sizeof(Bits) == sizeof(Value));
    SCOPED_TRACE(key);

    Bits bits;
    std::memcpy(&bits, &original, sizeof(bits));
    ASSERT_EQ(WTF_SUCCESS, wtf_session_set_stat(session, key, bits));

    uint64_t stored = 0;
    ASSERT_EQ(WTF_SUCCESS, wtf_session_get_stat(session, key, &stored));
    EXPECT_EQ(static_cast<uint64_t>(bits), stored);

    Bits restored_bits = static_cast<Bits>(stored);
    Value restored;
    std::memcpy(&restored, &restored_bits, sizeof(restored));
    EXPECT_EQ(original, restored);
}

TEST_F(LifetimeRegression, CustomStatsPreserveNumericBitPatterns)
{
    auto* session = Session();
    ExpectCustomStatRoundTrip<uint32_t>(session, "app.float", -16.67f);
    ExpectCustomStatRoundTrip<uint64_t>(session, "app.double", 1234.56789012345);
    ExpectCustomStatRoundTrip<uint64_t>(session, "app.negative_zero", -0.0);
    ExpectCustomStatRoundTrip<uint16_t>(session, "app.short", int16_t{-42});
    ExpectCustomStatRoundTrip<uint64_t>(session, "app.counter", UINT64_MAX);
}

TEST_F(LifetimeRegression, TransportCloseWaitsForStatisticsQuery)
{
    auto* session = Session();
    conn->server = nullptr;
    conn->quic_connection = reinterpret_cast<HQUIC>(conn);
    api.ConnectionClose = [](HQUIC) { ++closed_handles; };
    api.GetParam = [](HQUIC handle, uint32_t param, uint32_t*, void* buffer) -> QUIC_STATUS {
        if (param != QUIC_PARAM_CONN_STATISTICS_V2) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        QUIC_CONNECTION_EVENT closed = {};
        closed.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_COMPLETE;
        auto* connection = reinterpret_cast<wtf_connection*>(handle);
        wtf_connection_callback(handle, connection, &closed);
        EXPECT_EQ(0u, closed_handles);
        auto* stats = static_cast<QUIC_STATISTICS_V2*>(buffer);
        stats->SendSuspectedLostPackets = 10;
        stats->SendSpuriousLostPackets = 4;
        return QUIC_STATUS_SUCCESS;
    };

    uint64_t value = 0;
    ASSERT_EQ(WTF_SUCCESS, wtf_session_get_stat(session, "quic.packets_lost", &value));
    EXPECT_EQ(6u, value);
    EXPECT_EQ(1u, closed_handles);
    EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_session_get_stat(session, "quic.packets_lost", &value));
}

TEST_F(LifetimeRegression, StreamCreationAllowsNullCallback)
{
    auto* session = Session();
    wtf_stream_t* stream = nullptr;
    ASSERT_EQ(WTF_SUCCESS, wtf_session_create_stream(session, WTF_STREAM_UNIDIRECTIONAL,
        nullptr, session, &stream));
    ASSERT_NE(nullptr, stream);
    auto* created = static_cast<wtf_stream*>(stream);
    EXPECT_EQ(nullptr, created->callback);
    EXPECT_EQ(session, wtf_stream_get_context(stream));
    children.push_back(created);
    wtf_stream_unref(stream);
}

TEST_F(LifetimeRegression, FailedStreamCreationReturnsCreditAndParentReference)
{
    auto* session = Session();
    unsigned references = atomic_load(&session->ref_count);
    api.StreamOpen = [](HQUIC, QUIC_STREAM_OPEN_FLAGS, QUIC_STREAM_CALLBACK_HANDLER,
                        void*, HQUIC*) {
        return QUIC_STATUS_OUT_OF_MEMORY;
    };
    wtf_stream_t* stream = reinterpret_cast<wtf_stream_t*>(1);
    EXPECT_EQ(WTF_ERROR_OUT_OF_MEMORY, wtf_session_create_stream(session,
        WTF_STREAM_BIDIRECTIONAL,
        [](const wtf_stream_event_t*) {
            ADD_FAILURE() << "StreamOpen failure must not invoke the stream callback";
        }, session, &stream));
    EXPECT_EQ(nullptr, stream);
    EXPECT_EQ(references, atomic_load(&session->ref_count));
    EXPECT_EQ(0u, session->pending_stream_count);
    EXPECT_TRUE(pending_sends.empty());
}

TEST_F(LifetimeRegression, RepeatedResetBeforeReceiveReleasesConnectionOwner)
{
    for (unsigned i = 0; i < 10000; ++i) {
        auto* stream = wtf_http3_stream_create(conn, Handle(), UINT64_MAX);
        QUIC_STREAM_EVENT reset = {};
        reset.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
        wtf_http3_stream_callback(stream->quic_stream, stream, &reset);
        Finish(stream);
        ASSERT_EQ(1u, atomic_load(&conn->ref_count));
    }
    EXPECT_EQ(10000u, closed_handles);
}

TEST_F(LifetimeRegression, ShutdownRemovesRegisteredStreamWithoutQueryingId)
{
    auto* stream = wtf_http3_stream_create(conn, Handle(), UINT64_MAX);
    stream->id = 4;
    http3_stream_map_insert(&conn->streams, 4, stream);
    wtf_http3_stream_add_ref(stream);
    conn->peer_control_stream = stream;
    Finish(stream);
    EXPECT_EQ(nullptr, conn->peer_control_stream);
    EXPECT_EQ(1u, closed_handles);
}

TEST_F(LifetimeRegression, FinBeforeReceiveReleasesPlaceholder)
{
    auto* stream = wtf_http3_stream_create(conn, Handle(), UINT64_MAX);
    QUIC_STREAM_EVENT event = {};
    event.Type = QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN;
    wtf_http3_stream_callback(stream->quic_stream, stream, &event);
    Finish(stream);
    EXPECT_EQ(1u, closed_handles);
}

TEST_F(LifetimeRegression, DeferredOwnerCanOutlivePlaceholderShutdown)
{
    auto* stream = wtf_http3_stream_create(conn, Handle(), UINT64_MAX);
    wtf_http3_stream_add_ref(stream);
    Finish(stream);
    EXPECT_EQ(2u, atomic_load(&conn->ref_count));
    EXPECT_TRUE(stream->destroyed);
    wtf_http3_stream_release(stream);
}

TEST_F(LifetimeRegression, RepeatedCloseCapsulesDoNotRetainSessions)
{
    uint8_t data[] = {0, 0, 0, 1};
    wtf_capsule close = {};
    close.type = WTF_CAPSULE_CLOSE_WEBTRANSPORT_SESSION;
    close.length = sizeof(data);
    close.data = data;
    for (unsigned i = 0; i < 10000; ++i) {
        auto* session = Session();
        auto* stream = connects.back();
        connects.pop_back();
        ASSERT_TRUE(wtf_session_process_capsule(session, &close));
        ASSERT_EQ(0u, session_map_size(&conn->sessions));
        Finish(stream);
        ASSERT_EQ(1u, atomic_load(&conn->ref_count));
    }
    EXPECT_EQ(10000u, disconnects);
}

TEST_F(LifetimeRegression, ConnectFinWithoutCloseCapsuleRetiresSessionOnce)
{
    Session();
    auto* stream = connects.back();
    QUIC_STREAM_EVENT event = {};
    event.Type = QUIC_STREAM_EVENT_PEER_SEND_SHUTDOWN;
    wtf_http3_stream_callback(stream->quic_stream, stream, &event);
    EXPECT_EQ(0u, session_map_size(&conn->sessions));
    EXPECT_EQ(1u, disconnects);
}

TEST_F(LifetimeRegression, ExplicitAppReferenceSurvivesTerminalCallback)
{
    auto* session = Session();
    session->callback = RetainOnDisconnect;
    wtf_session_shutdown(session, 0, "test");
    Finish(connects.back());
    connects.clear();
    ASSERT_NE(nullptr, retained_session);
    EXPECT_EQ(WTF_SESSION_CLOSED, retained_session->state);
    EXPECT_EQ(2u, atomic_load(&conn->ref_count));
}

TEST_F(LifetimeRegression, LocalCloseRetiresSessionAndNotifiesOnce)
{
    auto* session = Session();
    EXPECT_EQ(WTF_SUCCESS, wtf_session_close(session, 1, "local close"));
    EXPECT_EQ(0u, session_map_size(&conn->sessions));
    EXPECT_EQ(1u, disconnects);
    EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_session_close(session, 1, "again"));
}

TEST_F(LifetimeRegression, FlowControlFailureRetiresSessionOnce)
{
    auto* session = Session();
    wtf_session_fail_flow_control(session);
    wtf_session_fail_flow_control(session);
    EXPECT_EQ(0u, session_map_size(&conn->sessions));
    EXPECT_EQ(1u, disconnects);
}

TEST_F(LifetimeRegression, ParentShutdownRetiresAllSessionsBeforeStreamCallbacks)
{
    Session();
    Session();
    QUIC_CONNECTION_EVENT event = {};
    event.Type = QUIC_CONNECTION_EVENT_SHUTDOWN_INITIATED_BY_PEER;
    event.SHUTDOWN_INITIATED_BY_PEER.ErrorCode = 1;
    wtf_connection_callback(nullptr, conn, &event);
    EXPECT_EQ(0u, session_map_size(&conn->sessions));
    EXPECT_EQ(2u, disconnects);
    for (auto* stream : connects) Finish(stream);
    connects.clear();
    EXPECT_EQ(2u, disconnects);
    EXPECT_EQ(1u, atomic_load(&conn->ref_count));
}

TEST_F(LifetimeRegression, EchoStreamBudgetStaysChargedUntilCompletion)
{
    auto* session = Session();
    wtf_test_echo_session(session);
    session->callback = wtf_test_echo_disconnected;
    auto* stream = EchoStream(session);
    std::vector<uint8_t> payload(1024 * 1024);
    EXPECT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, payload.data(), payload.size()));
    EXPECT_EQ(payload.size(), wtf_test_echo_queued());
    EXPECT_EQ(WTF_ERROR_FLOW_CONTROL, wtf_test_echo_send(stream, payload.data(), 1));
    CompleteSends();
    EXPECT_EQ(0u, wtf_test_echo_queued());
    EXPECT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, payload.data(), payload.size()));
    // A session can disconnect before its remaining sends complete.
    wtf_session_shutdown(session, 0, "test");
    CompleteSends(true);
}

TEST_F(LifetimeRegression, EchoSessionAndProcessBudgetsBoundManyStreams)
{
    std::vector<uint8_t> payload(1024 * 1024);
    for (unsigned n = 0; n < 4; ++n) {
        auto* session = Session();
        wtf_test_echo_session(session);
        session->callback = wtf_test_echo_disconnected;
        for (unsigned i = 0; i < 8; ++i) {
            EXPECT_EQ(WTF_SUCCESS,
                      wtf_test_echo_send(EchoStream(session), payload.data(), payload.size()));
        }
        EXPECT_EQ(WTF_ERROR_FLOW_CONTROL,
                  wtf_test_echo_send(EchoStream(session), payload.data(), 1));
    }
    auto* extra = Session();
    wtf_test_echo_session(extra);
    extra->callback = wtf_test_echo_disconnected;
    auto* stream = EchoStream(extra);
    EXPECT_EQ(32u * 1024u * 1024u, wtf_test_echo_queued());
    EXPECT_EQ(WTF_ERROR_FLOW_CONTROL, wtf_test_echo_send(stream, payload.data(), 1));
    CompleteSends();
    EXPECT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, payload.data(), 1));
}

TEST_F(LifetimeRegression, FailedEchoSendReturnsItsBudget)
{
    auto* session = Session();
    wtf_test_echo_session(session);
    session->callback = wtf_test_echo_disconnected;
    auto* stream = EchoStream(session);
    uint8_t data = 0;
    fail_send = true;
    EXPECT_EQ(WTF_ERROR_OUT_OF_MEMORY, wtf_test_echo_send(stream, &data, 1));
    EXPECT_EQ(0u, wtf_test_echo_queued());
    fail_send = false;
    EXPECT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, &data, 1));
}

TEST_F(LifetimeRegression, ResetKeepsEchoContextUntilCancelledSendsComplete)
{
    auto* session = Session();
    wtf_test_echo_session(session);
    session->callback = wtf_test_echo_disconnected;
    auto* stream = EchoStream(session);
    uint8_t data = 0;
    ASSERT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, &data, 1));
    QUIC_STREAM_EVENT reset = {};
    reset.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
    wtf_upgraded_stream_callback(stream->quic_stream, stream, &reset);
    EXPECT_NE(nullptr, wtf_stream_get_context(stream));
    EXPECT_EQ(1024u, wtf_test_echo_queued());
    CompleteSends(true);
    EXPECT_EQ(0u, wtf_test_echo_queued());
}

TEST_F(LifetimeRegression, TinyEchoSendsCannotBypassAllocationBudget)
{
    auto* session = Session();
    wtf_test_echo_session(session);
    session->callback = wtf_test_echo_disconnected;
    auto* stream = EchoStream(session);
    uint8_t data = 0;
    for (unsigned i = 0; i < 1024; ++i) {
        ASSERT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, &data, 1));
    }
    EXPECT_EQ(1024u * 1024u, wtf_test_echo_queued());
    EXPECT_EQ(WTF_ERROR_FLOW_CONTROL, wtf_test_echo_send(stream, &data, 1));
    CompleteSends();
    EXPECT_EQ(WTF_SUCCESS, wtf_test_echo_send(stream, &data, 1));
}

TEST_F(LifetimeRegression, QpackEncoderStreamCanArriveBeforeSettings)
{
    const uint8_t capacity_and_insert[] = {0x3f, 0x61, 0x41, 'x', 0x01, 'y'};
    ASSERT_TRUE(wtf_qpack_process_encoder(&context, &conn->qpack,
        capacity_and_insert, sizeof(capacity_and_insert)));

    conn->qpack.peer_max_table_capacity = 0;
    conn->qpack.peer_blocked_streams = 0;
    ASSERT_TRUE(wtf_qpack_init_encoder(&context, &conn->qpack));

    const uint8_t duplicate[] = {0x00};
    EXPECT_TRUE(wtf_qpack_process_encoder(&context, &conn->qpack, duplicate, sizeof(duplicate)));
}

TEST_F(LifetimeRegression, ControlStreamTypeIsNotParsedAgainAfterAReceiveBoundary)
{
    api.GetParam = [](HQUIC, uint32_t parameter, uint32_t* size, void* value) {
        if (parameter != QUIC_PARAM_STREAM_ID || *size < sizeof(uint64_t)) {
            return QUIC_STATUS_NOT_SUPPORTED;
        }
        *static_cast<uint64_t*>(value) = 3;
        *size = sizeof(uint64_t);
        return QUIC_STATUS_SUCCESS;
    };
    auto* stream = wtf_http3_stream_create(conn, Handle(), 3);
    wtf_http3_stream_add_ref(stream);
    connects.push_back(stream);
    uint8_t control_type = WTF_STREAM_TYPE_CONTROL;
    QUIC_BUFFER buffer = {1, &control_type};
    QUIC_STREAM_EVENT receive = {};
    receive.Type = QUIC_STREAM_EVENT_RECEIVE;
    receive.RECEIVE.Buffers = &buffer;
    receive.RECEIVE.BufferCount = 1;
    receive.RECEIVE.TotalBufferLength = 1;
    wtf_http3_stream_callback(stream->quic_stream, stream, &receive);
    ASSERT_EQ(WTF_STREAM_TYPE_CONTROL, stream->type);

    uint8_t extension_frame[] = {0x21, 0x00};
    buffer = {sizeof(extension_frame), extension_frame};
    receive.RECEIVE.TotalBufferLength = sizeof(extension_frame);
    wtf_http3_stream_callback(stream->quic_stream, stream, &receive);
    EXPECT_EQ(WTF_STREAM_TYPE_CONTROL, stream->type);
    EXPECT_EQ(stream, conn->peer_control_stream);
}

TEST_F(LifetimeRegression, QuicStreamAvailabilityDoesNotGrantWebTransportCredit)
{
    auto* session = Session();
    conn->webtransport_flow_control_enabled = true;
    session->remote_max_streams_bidi = 3;
    session->remote_max_streams_uni = 2;
    QUIC_CONNECTION_EVENT available = {};
    available.Type = QUIC_CONNECTION_EVENT_STREAMS_AVAILABLE;
    available.STREAMS_AVAILABLE.BidirectionalCount = 64;
    available.STREAMS_AVAILABLE.UnidirectionalCount = 64;
    wtf_connection_callback(nullptr, conn, &available);
    ASSERT_EQ(3u, session->remote_max_streams_bidi);
    ASSERT_EQ(2u, session->remote_max_streams_uni);

    uint8_t limit = 4;
    wtf_capsule update = {WTF_CAPSULE_WT_MAX_STREAMS_BIDI, 1, &limit};
    EXPECT_TRUE(wtf_session_process_capsule(session, &update));
    EXPECT_EQ(4u, session->remote_max_streams_bidi);
}

TEST_F(LifetimeRegression, ClientSessionUsesPeerCreditReceivedDuringHandshake)
{
    auto* session = Session();
    auto* stream = connects.back();
    session->state = WTF_SESSION_HANDSHAKING;
    conn->peer_settings.wt_initial_max_streams_bidi = 3;
    conn->peer_settings.wt_initial_max_streams_uni = 2;
    conn->peer_settings.wt_initial_max_data = 4096;
    ASSERT_TRUE(wtf_qpack_init_encoder(&context, &conn->qpack));
    wtf_client client = {};
    conn->role = WTF_ENDPOINT_CLIENT;
    conn->client = &client;
    stream->flags = static_cast<wtf_http3_stream_flags_t>(WTF_HTTP3_STREAM_FLAG_CLIENT_CONNECT);
    api.GetParam = [](HQUIC, uint32_t, uint32_t* size, void* value) {
        *static_cast<uint64_t*>(value) = 8;
        *size = sizeof(uint64_t);
        return QUIC_STATUS_SUCCESS;
    };
    uint8_t response[] = {0x01, 0x03, 0x00, 0x00, 0xd9};
    QUIC_BUFFER buffer = {sizeof(response), response};
    QUIC_STREAM_EVENT receive = {};
    receive.Type = QUIC_STREAM_EVENT_RECEIVE;
    receive.RECEIVE.Buffers = &buffer;
    receive.RECEIVE.BufferCount = 1;
    receive.RECEIVE.TotalBufferLength = sizeof(response);
    wtf_http3_stream_callback(stream->quic_stream, stream, &receive);
    EXPECT_EQ(WTF_SESSION_CONNECTED, session->state);
    EXPECT_EQ(3u, session->remote_max_streams_bidi);
    EXPECT_EQ(2u, session->remote_max_streams_uni);
    EXPECT_EQ(4096u, session->remote_max_data);
    conn->client = nullptr;
    conn->role = WTF_ENDPOINT_SERVER;
}

} // namespace
