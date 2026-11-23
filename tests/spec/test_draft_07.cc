#include "http3_spec_test.h"

namespace {

// draft-ietf-webtrans-http3-07, §§3.1–3.4, 4.4, 4.6, 5, 8.1.
class Draft07Spec : public Http3SpecTest {};

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

    uint8_t wire[] = {1, 0xab, 0xcd};
    QUIC_BUFFER buffer = {sizeof(wire), wire};
    QUIC_CONNECTION_EVENT event = {};
    event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
    event.DATAGRAM_RECEIVED.Buffer = &buffer;
    EXPECT_EQ(QUIC_STATUS_SUCCESS, wtf_connection_callback(connection->quic_connection,
                                                               connection, &event));
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
