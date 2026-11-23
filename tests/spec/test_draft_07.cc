#include "http3_spec_test.h"

namespace {

// draft-ietf-webtrans-http3-07, §§3.1–3.4, 4.4, 4.6, 5, 8.1.
class Draft07Spec : public Http3SpecTest {};
class Draft07ClientSpec : public Http3ClientSpecTest {};

TEST_F(Draft07ClientSpec, ServerLimitAppliesToQueuedAndNewSessions)
{
    auto* first = OpenSession();
    auto* surplus = OpenSession();
    ASSERT_NE(nullptr, first);
    ASSERT_NE(nullptr, surplus);
    EXPECT_TRUE(streams.empty());

    ReceiveSettings({{0xc671706a, 1}, {0x08, 1}, {0x33, 1}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    EXPECT_EQ(2u, streams.size()); // One control stream and one CONNECT.
    EXPECT_EQ(WTF_SESSION_HANDSHAKING, first->state);
    EXPECT_EQ(WTF_SESSION_CLOSED, surplus->state);
    EXPECT_EQ(std::vector<uint32_t>({WTF_ERROR_REJECTED}), session_errors);
    EXPECT_EQ(nullptr, OpenSession(WTF_ERROR_REJECTED));
    EXPECT_EQ(2u, streams.size());

    QUIC_STREAM_EVENT rejected = {};
    rejected.Type = QUIC_STREAM_EVENT_PEER_SEND_ABORTED;
    rejected.PEER_SEND_ABORTED.ErrorCode = 0x10b;
    auto* connect = streams.back().http3;
    EXPECT_EQ(QUIC_STATUS_SUCCESS, wtf_http3_stream_callback(connect->quic_stream, connect, &rejected));
    EXPECT_EQ(WTF_SESSION_CLOSED, first->state);
    EXPECT_EQ(std::vector<uint32_t>({WTF_ERROR_REJECTED, WTF_ERROR_REJECTED}), session_errors);
    EXPECT_NE(nullptr, OpenSession());
    EXPECT_EQ(3u, streams.size());
}

TEST_F(Draft07Spec, ClientSettingsAdvertiseCapacityAndRfcDatagrams)
{
    ReceiveSettings({{0xc671706a, 3}, {0x33, 1}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    EXPECT_EQ(WTF_WEBTRANSPORT_DRAFT_07, connection->selected_webtransport_draft);
    EXPECT_EQ(3u, connection->peer_settings.webtransport_max_sessions);

    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport"));
    ExpectResponse(request, 200);
    ASSERT_NE(nullptr, request.http3->webtransport_session);
    EXPECT_EQ(WTF_SESSION_CONNECTED, request.http3->webtransport_session->state);
}

TEST_F(Draft07Spec, LegacyDatagramSettingDoesNotEnableDraft07)
{
    ReceiveSettings({{0xc671706a, 3}, {0xffd277, 1}});
    EXPECT_FALSE(connection->peer_settings.settings_received);
    EXPECT_FALSE(connection_errors.empty());
}

TEST_F(Draft07Spec, ServerResetsExcessConnectAndReusesReleasedSlot)
{
    connection->max_sessions = 1;
    connection->local_settings.webtransport_max_sessions = 1;
    ReceiveSettings({{0xc671706a, 5}, {0x33, 1}});
    auto& first = OpenStream(0);
    auto& excess = OpenStream(4);
    Receive(first, Connect("webtransport"));
    ASSERT_NE(nullptr, first.http3->webtransport_session);
    Receive(excess, Connect("webtransport"));
    EXPECT_TRUE(excess.sent.empty());
    EXPECT_EQ(std::vector<uint64_t>({0x10b}), excess.resets); // H3_REQUEST_REJECTED.
    EXPECT_TRUE(connection_errors.empty());

    Receive(first, Frame(0x00, Frame(0x2843, {0, 0, 0, 0})), true);
    auto& replacement = OpenStream(8);
    Receive(replacement, Connect("webtransport"));
    ExpectResponse(replacement, 200);
}

TEST_F(Draft07Spec, DeferredAcceptanceChecksSessionLimitAgain)
{
    connection->max_sessions = 1;
    connection->local_settings.webtransport_max_sessions = 1;
    ReceiveSettings({{0xc671706a, 5}, {0x33, 1}});
    std::vector<wtf_connection_request_handle_t*> handles;
    connection->user_context = &handles;
    connection->connection_validator = [](const wtf_connection_request_t* request,
                                           wtf_connection_response_t*, void* context) {
        static_cast<decltype(handles)*>(context)->push_back(request->handle);
        return WTF_CONNECTION_DEFER;
    };
    auto& first = OpenStream(0);
    auto& second = OpenStream(4);
    Receive(first, Connect("webtransport"));
    Receive(second, Connect("webtransport"));
    EXPECT_EQ(2u, handles.size());
    for (size_t i = 0; i < handles.size(); i++) {
        EXPECT_EQ(i == 0 ? WTF_SUCCESS : WTF_ERROR_REJECTED,
                  wtf_connection_request_complete(handles[i], WTF_CONNECTION_ACCEPT));
    }
    ExpectResponse(first, 200);
    EXPECT_EQ(std::vector<uint64_t>({0x10b}), second.resets);
    EXPECT_TRUE(connection_errors.empty());
}

TEST_F(Draft07Spec, QuarterStreamIdRoutesDatagramToItsConnectStream)
{
    ReceiveSettings({{0xc671706a, 2}, {0x33, 1}});
    auto& first = OpenStream(0);
    auto& second = OpenStream(4);
    Receive(first, Connect("webtransport"));
    Receive(second, Connect("webtransport"));
    ASSERT_NE(nullptr, first.http3->webtransport_session);
    ASSERT_NE(nullptr, second.http3->webtransport_session);

    Bytes payloads[2];
    auto on_session_event = [](const wtf_session_event_t* event) {
        if (event->type == WTF_SESSION_EVENT_DATAGRAM_RECEIVED) {
            const auto& datagram = event->datagram_received;
            auto* received = static_cast<Bytes*>(event->user_context);
            received->assign(datagram.data, datagram.data + datagram.length);
        }
    };
    first.http3->webtransport_session->callback = on_session_event;
    first.http3->webtransport_session->user_context = &payloads[0];
    second.http3->webtransport_session->callback = on_session_event;
    second.http3->webtransport_session->user_context = &payloads[1];

    ReceiveDatagram({1, 0xab, 0xcd});
    EXPECT_TRUE(payloads[0].empty());
    EXPECT_EQ(Bytes({0xab, 0xcd}), payloads[1]);
}

TEST_F(Draft07Spec, DrainingSessionStillReceivesCloseMetadata)
{
    ReceiveSettings({{0xc671706a, 1}, {0x33, 1}});
    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport"));
    auto* session = request.http3->webtransport_session;
    ASSERT_NE(nullptr, session);

    Receive(request, Frame(0x00, Frame(0x78ae, {})));
    ASSERT_EQ(WTF_SESSION_DRAINING, session->state);
    Receive(request, Frame(0x00, Frame(0x2843, {0x01, 0x02, 0x03, 0x04, 'b', 'y', 'e'})), true);
    EXPECT_EQ(WTF_SESSION_CLOSED, session->state);
    EXPECT_EQ(0x01020304u, session->close_error_code);
    EXPECT_STREQ("bye", session->close_reason);
}

} // namespace
