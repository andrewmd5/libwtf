#include "http3_spec_test.h"

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

} // namespace
