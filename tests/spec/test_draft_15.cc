#include "http3_spec_test.h"

namespace {

// draft-ietf-webtrans-http3-15, §§3.1–3.2, 5.1, 5.5, 5.6.2, 7.1, 9.2.
class Draft15Spec : public Http3SpecTest {
protected:
    void SetUp() override
    {
        Http3SpecTest::SetUp();
        ASSERT_NE(nullptr, connection);
        connection->requested_webtransport_draft = WTF_WEBTRANSPORT_DRAFT_15;
    }
};

TEST_F(Draft15Spec, NonzeroSettingAndModernConnectEstablishSession)
{
    ReceiveSettings({{0x2c7cf000, 2}, {0x33, 1}, {0x2b61, 63}, {0x2b64, 1}, {0x2b65, 3}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    EXPECT_EQ(WTF_WEBTRANSPORT_DRAFT_15, connection->selected_webtransport_draft);
    EXPECT_TRUE(connection->webtransport_flow_control_enabled);

    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport-h3"));
    ExpectResponse(request, 200);
    auto* session = request.http3->webtransport_session;
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(WTF_SESSION_CONNECTED, session->state);
    EXPECT_EQ(63u, session->remote_max_data);
    EXPECT_EQ(1u, session->remote_max_streams_uni);
    EXPECT_EQ(3u, session->remote_max_streams_bidi);

    // WT_MAX_STREAMS in an HTTP DATA frame grants credit to the indicated direction.
    Receive(request, Frame(0x00, Frame(0x190b4d40, {4})));
    EXPECT_EQ(4u, session->remote_max_streams_uni);
    EXPECT_EQ(3u, session->remote_max_streams_bidi);
}

TEST_F(Draft15Spec, OneNonzeroSettingEnablesFlowControlAndOmittedCreditDefaultsToZero)
{
    ReceiveSettings({{0x2c7cf000, 1}, {0x33, 1}, {0x2b65, 3}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    ASSERT_TRUE(connection->webtransport_flow_control_enabled);

    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport-h3"));
    auto* session = request.http3->webtransport_session;
    ASSERT_NE(nullptr, session);
    EXPECT_EQ(0u, session->remote_max_data);
    EXPECT_EQ(0u, session->remote_max_streams_uni);
    EXPECT_EQ(3u, session->remote_max_streams_bidi);
}

TEST_F(Draft15Spec, ZeroPeerCreditDisablesFlowControlAndIgnoresCapsules)
{
    ReceiveSettings({{0x2c7cf000, 1}, {0x33, 1}, {0x2b61, 0}, {0x2b64, 0}, {0x2b65, 0}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    EXPECT_FALSE(connection->webtransport_flow_control_enabled);

    auto& request = OpenStream(0);
    Receive(request, Connect("webtransport-h3"));
    auto* session = request.http3->webtransport_session;
    ASSERT_NE(nullptr, session);
    Receive(request, Frame(0x00, Frame(0x190b4d3f, {4})));
    EXPECT_EQ(0u, session->remote_max_streams_bidi);
    EXPECT_EQ(WTF_SESSION_CONNECTED, session->state);
}

TEST_F(Draft15Spec, PeerCreditAloneDoesNotEnableFlowControl)
{
    connection->local_settings.wt_initial_max_streams_uni = 0;
    connection->local_settings.wt_initial_max_streams_bidi = 0;
    connection->local_settings.wt_initial_max_data = 0;
    ReceiveSettings({{0x2c7cf000, 1}, {0x33, 1}, {0x2b65, 3}});
    ASSERT_TRUE(connection->peer_settings.settings_received);
    EXPECT_FALSE(connection->webtransport_flow_control_enabled);
}

} // namespace
