#include "http3_spec_test.h"

extern "C" {
#include "stream.h"
}

namespace {

// draft-ietf-webtrans-http3-02, §§3.1, 3.3, 6, 8.2.
class Draft02Spec : public Http3SpecTest {};

TEST_F(Draft02Spec, ConnectWaitsForSettingsAndReturnsSelectedDraft)
{
    connection->requested_webtransport_draft = WTF_WEBTRANSPORT_DRAFT_02;
    connection->connection_validator = [](const wtf_connection_request_t* request,
                                             wtf_connection_response_t*, void*) {
        EXPECT_STREQ("https://localhost", request->origin);
        return WTF_CONNECTION_ACCEPT;
    };
    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport", {{"origin", "https://localhost"},
                                              {"sec-webtransport-http3-draft02", "1"}}));
    EXPECT_TRUE(request.sent.empty());
    ASSERT_EQ(nullptr, request.http3->webtransport_session);

    ReceiveSettings({{0x2b603742, 1}, {0xffd277, 1}});
    ASSERT_EQ(WTF_WEBTRANSPORT_DRAFT_02, connection->selected_webtransport_draft);
    ASSERT_NE(nullptr, request.http3->webtransport_session);
    EXPECT_EQ(WTF_SESSION_CONNECTED, request.http3->webtransport_session->state);
    ExpectResponse(request, 200, "draft02");
}

TEST_F(Draft02Spec, ConnectRequiresOrigin)
{
    ReceiveSettings({{0x2b603742, 1}, {0xffd277, 1}});
    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport", {{"sec-webtransport-http3-draft02", "1"}}));
    EXPECT_EQ(nullptr, request.http3->webtransport_session);
    ExpectResponse(request, 400);
}

TEST_F(Draft02Spec, EnableSettingIsBoolean)
{
    ReceiveSettings({{0x2b603742, 2}, {0xffd277, 1}});
    EXPECT_FALSE(connection->peer_settings.settings_received);
    EXPECT_EQ(std::vector<uint64_t>({0x109}), connection_errors); // H3_SETTINGS_ERROR.
}

TEST_F(Draft02Spec, RegisteredDatagramsUseTheUnchangedPayload)
{
    connection->connection_validator = [](const wtf_connection_request_t*,
                                           wtf_connection_response_t*, void*) {
        return WTF_CONNECTION_ACCEPT;
    };
    Bytes payloads;
    connection->session_callback = [](const wtf_session_event_t* event) {
        if (event->type == WTF_SESSION_EVENT_DATAGRAM_RECEIVED) {
            const auto& datagram = event->datagram_received;
            auto& payloads = *static_cast<Bytes*>(event->user_context);
            payloads.insert(payloads.end(), datagram.data, datagram.data + datagram.length);
        }
    };
    connection->user_context = &payloads;

    auto& early = OpenStream(0);
    auto request = Connect("webtransport", {{"origin", "https://localhost"},
                                            {"sec-webtransport-http3-draft02", "1"}});
    Bytes format;
    AppendVarint(format, 0xff7c00);
    auto registration = Frame(0x00, Frame(0xff37a2, format));
    auto headers_and_registration = request;
    headers_and_registration.insert(headers_and_registration.end(), registration.begin(),
                                    registration.end());
    Receive(early, std::move(headers_and_registration));
    ReceiveSettings({{0x2b603742, 1}, {0xffd277, 1}});
    ExpectResponse(early, 200, "draft02");
    ReceiveDatagram({0, 0xab});
    EXPECT_EQ(Bytes({0xab}), payloads);

    auto& late = OpenStream(4);
    Receive(late, request);
    ExpectResponse(late, 200, "draft02");
    ASSERT_NE(nullptr, late.http3->webtransport_session);
    EXPECT_EQ(WTF_ERROR_INVALID_STATE,
              wtf_session_send_datagram_copy(late.http3->webtransport_session, "x", 1));
    ReceiveDatagram({1, 0xcd});
    EXPECT_EQ(Bytes({0xab}), payloads);
    Receive(late, registration);
    ReceiveDatagram({1, 0xef});
    Receive(late, Frame(0x00, Frame(0xff37a5, {0x12})));
    EXPECT_EQ(Bytes({0xab, 0xef, 0x12}), payloads);
}

TEST_F(Draft02Spec, StreamResetErrorUsesEightBits)
{
    connection->connection_validator = [](const wtf_connection_request_t*,
                                           wtf_connection_response_t*, void*) {
        return WTF_CONNECTION_ACCEPT;
    };
    ReceiveSettings({{0x2b603742, 1}, {0xffd277, 1}});
    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport", {{"origin", "https://localhost"},
                                              {"sec-webtransport-http3-draft02", "1"}}));
    ASSERT_NE(nullptr, request.http3->webtransport_session);
    auto* stream = wtf_stream_create(request.http3->webtransport_session, 4, WTF_STREAM_BIDIRECTIONAL);
    ASSERT_NE(nullptr, stream);
    Stream transport;
    stream->quic_stream = reinterpret_cast<HQUIC>(&transport);
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_abort(stream, 256));
    EXPECT_TRUE(transport.resets.empty());
    EXPECT_EQ(WTF_SUCCESS, wtf_stream_abort(stream, 255));
    EXPECT_EQ(std::vector<uint64_t>({0x52e4a40fa9e2}), transport.resets);
    wtf_stream_destroy(stream);
}

} // namespace
