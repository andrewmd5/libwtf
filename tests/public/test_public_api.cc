#include <gtest/gtest.h>

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>

extern "C" {
#include "wtf.h"
}

namespace {

constexpr const char* kServerCertPath = WTF_TEST_CERT_DIR "/localhost.crt";
constexpr const char* kServerKeyPath = WTF_TEST_CERT_DIR "/localhost.key";

class ContextFixture : public ::testing::Test {
  protected:
    void SetUp() override
    {
        wtf_context_config_t config = {};
        config.log_level = WTF_LOG_LEVEL_NONE;
        ASSERT_EQ(WTF_SUCCESS, wtf_context_create(&config, &context_));
        ASSERT_NE(nullptr, context_);
    }

    void TearDown() override
    {
        wtf_context_destroy(context_);
        context_ = nullptr;
    }

    wtf_context_t* context_ = nullptr;
};

void free_response_headers(wtf_connection_response_t* response)
{
    if (!response) {
        return;
    }
    for (size_t i = 0; i < response->header_count; i++) {
        free((void*)response->headers[i].name);
        free((void*)response->headers[i].value);
    }
    free(response->headers);
    *response = {};
}

}  // namespace

TEST(PublicApiSurface, UtilityExportsHaveStableContracts)
{
    const wtf_version_info_t* version = wtf_get_version();
    ASSERT_NE(nullptr, version);
    EXPECT_NE(nullptr, version->version);

    EXPECT_STREQ("Success", wtf_result_to_string(WTF_SUCCESS));
    EXPECT_NE(nullptr, wtf_result_to_string(WTF_ERROR_INVALID_PARAMETER));
    EXPECT_NE(nullptr, wtf_webtransport_error_to_string(WTF_WEBTRANSPORT_SESSION_GONE));
    EXPECT_STREQ("HTTP3_NO_ERROR", wtf_http3_error_to_string(WTF_H3_NO_ERROR));
    EXPECT_NE(nullptr, wtf_http3_error_to_string(WTF_H3_INTERNAL_ERROR));

    wtf_error_details_t details = {};
    EXPECT_EQ(WTF_SUCCESS, wtf_get_error_details(WTF_WEBTRANSPORT_SESSION_GONE, &details));
    EXPECT_EQ(WTF_WEBTRANSPORT_SESSION_GONE, details.error_code);
    EXPECT_NE(nullptr, details.description);
    EXPECT_TRUE(wtf_is_valid_application_error(0));
    EXPECT_TRUE(wtf_is_valid_application_error(UINT32_MAX));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_get_error_details(0, nullptr));
}

TEST(PublicApiSurface, StructsEnumsAndMacrosRemainUsableFromCpp)
{
    wtf_client_config_t client = {};
    client.url = "https://example.com:443/wt";
    client.draft = WTF_WEBTRANSPORT_DRAFT_AUTO;
    client.allow_pooling = true;
    client.congestion_control = WTF_CONGESTION_CONTROL_LOW_LATENCY;
    client.require_unreliable = true;

    EXPECT_STREQ("https://example.com:443/wt", client.url);
    EXPECT_EQ(WTF_WEBTRANSPORT_DRAFT_AUTO, client.draft);
    EXPECT_TRUE(client.allow_pooling);
    EXPECT_EQ(WTF_CONGESTION_CONTROL_LOW_LATENCY, client.congestion_control);
    EXPECT_TRUE(client.require_unreliable);

    EXPECT_TRUE(WTF_DATAGRAM_SEND_STATE_IS_FINAL(WTF_DATAGRAM_SEND_LOST_DISCARDED));
    EXPECT_TRUE(WTF_DATAGRAM_SEND_STATE_IS_FINAL(WTF_DATAGRAM_SEND_ACKNOWLEDGED));
    EXPECT_FALSE(WTF_DATAGRAM_SEND_STATE_IS_FINAL(WTF_DATAGRAM_SEND_SENT));
}

TEST(PublicApiSurface, ContextContracts)
{
    wtf_context_t* context = nullptr;
    wtf_context_config_t config = {};
    config.log_level = WTF_LOG_LEVEL_NONE;

    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_context_create(nullptr, &context));
    EXPECT_EQ(nullptr, context);
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_context_create(&config, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_context_set_log_level(nullptr, WTF_LOG_LEVEL_DEBUG));
    wtf_context_destroy(nullptr);

    ASSERT_EQ(WTF_SUCCESS, wtf_context_create(&config, &context));
    ASSERT_NE(nullptr, context);
    EXPECT_EQ(WTF_SUCCESS, wtf_context_set_log_level(context, WTF_LOG_LEVEL_ERROR));
    wtf_context_destroy(context);
}

TEST_F(ContextFixture, ClientCreateValidationAndLifecycle)
{
    wtf_client_t* client = nullptr;
    wtf_client_config_t config = {};
    config.url = "https://127.0.0.1:4433/demo";
    config.draft = WTF_WEBTRANSPORT_DRAFT_AUTO;
    config.skip_certificate_validation = true;

    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(nullptr, &config, &client));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, nullptr, &client));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, &config, nullptr));
    EXPECT_EQ(WTF_CLIENT_CLOSED, wtf_client_get_state(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_open(nullptr, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_connect(nullptr, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_disconnect(nullptr, 0, nullptr));
    wtf_client_destroy(nullptr);

    wtf_client_config_t bad_url = config;
    bad_url.url = "http://127.0.0.1:4433/demo";
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, &bad_url, &client));

    bad_url.url = "https://127.0.0.1/demo";
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, &bad_url, &client));

    bad_url.url = "https://127.0.0.1:4433/demo#frag";
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, &bad_url, &client));

    wtf_http_header_t bad_header = {};
    bad_header.name = ":authority";
    bad_header.value = "nope";
    wtf_client_config_t bad_headers = config;
    bad_headers.headers = &bad_header;
    bad_headers.header_count = 1;
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_create(context_, &bad_headers, &client));

    wtf_client_config_t bad_cert_options = config;
    bad_cert_options.ca_cert_file = kServerCertPath;
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_client_create(context_, &bad_cert_options, &client));

    ASSERT_EQ(WTF_SUCCESS, wtf_client_create(context_, &config, &client));
    ASSERT_NE(nullptr, client);
    EXPECT_EQ(WTF_CLIENT_DISCONNECTED, wtf_client_get_state(client));

    wtf_session_t* session = nullptr;
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_open(client, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_client_connect(client, nullptr));
    EXPECT_EQ(nullptr, session);

    wtf_client_t* second_client = nullptr;
    EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_client_create(context_, &config, &second_client));
    EXPECT_EQ(nullptr, second_client);

    EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_client_disconnect(client, 0, "not open"));
    wtf_client_destroy(client);
}

TEST_F(ContextFixture, ServerCreateValidationAndLifecycle)
{
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_start(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_stop(nullptr));
    EXPECT_EQ(WTF_SERVER_STOPPED, wtf_server_get_state(nullptr));
    wtf_server_destroy(nullptr);

    wtf_server_t* server = nullptr;
    wtf_server_config_t config = {};
    config.host = "127.0.0.1";
    config.port = 0;
    config.draft = WTF_WEBTRANSPORT_DRAFT_AUTO;

    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_create(nullptr, &config, &server));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_create(context_, nullptr, &server));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_create(context_, &config, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_server_create(context_, &config, &server));

    wtf_certificate_config_t cert = {};
    cert.cert_type = WTF_CERT_TYPE_FILE;
    cert.cert_data.file.cert_path = kServerCertPath;
    cert.cert_data.file.key_path = kServerKeyPath;
    config.cert_config = &cert;

    ASSERT_EQ(WTF_SUCCESS, wtf_server_create(context_, &config, &server));
    ASSERT_NE(nullptr, server);
    EXPECT_EQ(WTF_SERVER_STOPPED, wtf_server_get_state(server));

    wtf_server_t* second_server = nullptr;
    EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_server_create(context_, &config, &second_server));
    EXPECT_EQ(nullptr, second_server);

    wtf_result_t start_result = wtf_server_start(server);
    EXPECT_EQ(WTF_SUCCESS, start_result);
    if (start_result == WTF_SUCCESS) {
        EXPECT_EQ(WTF_SERVER_LISTENING, wtf_server_get_state(server));
        EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_server_start(server));
        EXPECT_EQ(WTF_SUCCESS, wtf_server_stop(server));
        EXPECT_EQ(WTF_SERVER_STOPPED, wtf_server_get_state(server));
        EXPECT_EQ(WTF_ERROR_INVALID_STATE, wtf_server_stop(server));
    }

    wtf_server_destroy(server);
}

TEST(PublicApiSurface, ConnectionResponseAndDeferredRequestContracts)
{
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_response_add_header(nullptr, "x-test", "ok"));

    wtf_connection_response_t response = {};
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_response_add_header(&response, ":status", "200"));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_response_add_header(&response, "", "value"));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_response_add_header(&response, "x-test", nullptr));
    ASSERT_EQ(WTF_SUCCESS, wtf_connection_response_add_header(&response, "x-test", "ok"));
    ASSERT_EQ(1u, response.header_count);
    EXPECT_STREQ("x-test", response.headers[0].name);
    EXPECT_STREQ("ok", response.headers[0].value);
    free_response_headers(&response);

    wtf_connection_request_ref(nullptr);
    wtf_connection_request_unref(nullptr);
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_request_add_response_header(nullptr, "x-test", "ok"));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_connection_request_complete(nullptr, WTF_CONNECTION_ACCEPT));
}

TEST(PublicApiSurface, SessionNullContracts)
{
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_close(nullptr, 0, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_drain(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_send_datagram(nullptr, nullptr, 0, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_session_send_datagram_copy(nullptr, "data", 4));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_session_create_stream(nullptr,
                                                                     WTF_STREAM_BIDIRECTIONAL,
                                                                     nullptr, nullptr, nullptr));
    EXPECT_EQ(WTF_SESSION_CLOSED, wtf_session_get_state(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER,
              wtf_session_get_peer_address(nullptr, nullptr, nullptr));
    EXPECT_EQ(0u, wtf_session_get_max_datagram_size(nullptr));
    EXPECT_EQ(nullptr, wtf_session_find_stream_by_id(nullptr, 1));
    EXPECT_EQ(nullptr, wtf_session_get_context(nullptr));

    wtf_session_ref(nullptr);
    wtf_session_unref(nullptr);
    wtf_session_set_callback(nullptr, nullptr, nullptr);
    wtf_session_set_context(nullptr, nullptr);
}

TEST(PublicApiSurface, StreamNullContracts)
{
    uint8_t payload[] = {1, 2, 3};
    wtf_buffer_t buffer = {};
    buffer.length = sizeof(payload);
    buffer.data = payload;
    uint64_t stream_id = 0;

    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_send(nullptr, &buffer, 1, false, nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_send_copy(nullptr, payload,
                                                               sizeof(payload), false));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_close(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_abort(nullptr, 0));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_get_id(nullptr, &stream_id));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_get_id(nullptr, nullptr));
    EXPECT_EQ(WTF_STREAM_BIDIRECTIONAL, wtf_stream_get_type(nullptr));
    EXPECT_EQ(WTF_STREAM_CLOSED, wtf_stream_get_state(nullptr));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_set_priority(nullptr, 1));
    EXPECT_EQ(WTF_ERROR_INVALID_PARAMETER, wtf_stream_set_receive_enabled(nullptr, true));
    EXPECT_EQ(nullptr, wtf_stream_get_context(nullptr));

    wtf_stream_ref(nullptr);
    wtf_stream_unref(nullptr);
    wtf_stream_set_callback(nullptr, nullptr);
    wtf_stream_set_context(nullptr, nullptr);
}

#ifdef WTF_QUIC_BACKEND_NETWORK
TEST_F(ContextFixture, NetworkSupportsDelayedCompletionAndRejectsUnsupportedCongestionMode)
{
    wtf_client_config_t config = {};
    config.url = "https://127.0.0.1:4433/";
    config.draft = WTF_WEBTRANSPORT_DRAFT_15;
    wtf_client_t* client = nullptr;
    wtf_result_t draft15_result = wtf_client_create(context_, &config, &client);
    if (draft15_result == WTF_SUCCESS) {
        wtf_client_destroy(client);
        client = nullptr;
    } else {
        EXPECT_EQ(WTF_ERROR_NOT_SUPPORTED, draft15_result);
    }

    config.draft = WTF_WEBTRANSPORT_DRAFT_07;
    config.send_buffering = WTF_SEND_BUFFERING_DISABLED;
    ASSERT_EQ(WTF_SUCCESS, wtf_client_create(context_, &config, &client));
    wtf_client_destroy(client);
    client = nullptr;
    config.send_buffering = WTF_SEND_BUFFERING_DEFAULT;
    config.congestion_control = WTF_CONGESTION_CONTROL_THROUGHPUT;
    EXPECT_EQ(WTF_ERROR_NOT_SUPPORTED, wtf_client_create(context_, &config, &client));
    EXPECT_EQ(nullptr, client);
    config.congestion_control = WTF_CONGESTION_CONTROL_DEFAULT;
    config.enable_migration = true;
    ASSERT_EQ(WTF_SUCCESS, wtf_client_create(context_, &config, &client));
    wtf_client_destroy(client);
    EXPECT_TRUE(WTF_DATAGRAM_SEND_STATE_IS_FINAL(WTF_DATAGRAM_SEND_UNTRACKED));
}
#endif
