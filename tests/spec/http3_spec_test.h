#pragma once

#include <gtest/gtest.h>

#include <cstdint>
#include <initializer_list>
#include <list>
#include <string_view>
#include <utility>
#include <vector>

extern "C" {
#include "client.h"
#include "conn.h"
#include "http3.h"
#include "qpack.h"
#include "session.h"
#include "settings.h"
#include "utils.h"
#include "varint.h"
}

class Http3SpecTest : public ::testing::Test {
protected:
    using Bytes = std::vector<uint8_t>;
    using Settings = std::initializer_list<std::pair<uint64_t, uint64_t>>;
    using Fields = std::initializer_list<std::pair<std::string_view, std::string_view>>;

    struct Stream {
        Bytes sent;
        wtf_http3_stream* http3 = nullptr;
        std::vector<uint64_t> resets;
    };

    QUIC_API_TABLE api = {};
    wtf_context context = {};
    wtf_server server = {};
    wtf_connection* connection = nullptr;
    std::vector<uint64_t> connection_errors;
    std::list<Stream> streams;

    void SetUp() override
    {
        api.StreamClose = [](HQUIC) {};
        api.StreamShutdown = [](HQUIC handle, QUIC_STREAM_SHUTDOWN_FLAGS, QUIC_UINT62 code) {
            reinterpret_cast<Stream*>(handle)->resets.push_back(code);
            return QUIC_STATUS_SUCCESS;
        };
        api.StreamSend = Send;
        api.ConnectionClose = [](HQUIC) {};
        api.ConnectionShutdown = Shutdown;
        api.GetParam = [](HQUIC, uint32_t, uint32_t*, void*) {
            return QUIC_STATUS_INVALID_STATE;
        };
        context.quic_api = &api;
        server.context = &context;
        connection = wtf_connection_create(&server, reinterpret_cast<HQUIC>(this));
        ASSERT_NE(nullptr, connection);
        connection->local_settings.settings_sent = true;
        connection->reliable_reset_negotiated = true;
    }

    void TearDown() override
    {
        if (!connection) return;
        for (auto& stream : streams) {
            if (!stream.http3) continue;
            QUIC_STREAM_EVENT event = {};
            event.Type = QUIC_STREAM_EVENT_SHUTDOWN_COMPLETE;
            event.SHUTDOWN_COMPLETE.ConnectionShutdown = true;
            wtf_http3_stream_callback(stream.http3->quic_stream, stream.http3, &event);
        }
        wtf_connection_destroy(connection);
    }

    Stream& OpenStream(uint64_t id)
    {
        auto& stream = streams.emplace_back();
        stream.http3 = wtf_http3_stream_create(connection, reinterpret_cast<HQUIC>(&stream), id);
        if (stream.http3) {
            wtf_http3_stream_add_ref(stream.http3); // Transport callback reference.
        }
        return stream;
    }

    void Receive(Stream& stream, Bytes bytes, bool fin = false)
    {
        ASSERT_NE(nullptr, stream.http3);
        QUIC_BUFFER buffer = {static_cast<uint32_t>(bytes.size()), bytes.data()};
        QUIC_STREAM_EVENT event = {};
        event.Type = QUIC_STREAM_EVENT_RECEIVE;
        event.RECEIVE.Buffers = &buffer;
        event.RECEIVE.BufferCount = 1;
        event.RECEIVE.TotalBufferLength = bytes.size();
        event.RECEIVE.Flags = fin ? QUIC_RECEIVE_FLAG_FIN : QUIC_RECEIVE_FLAG_NONE;
        EXPECT_EQ(QUIC_STATUS_SUCCESS,
                  wtf_http3_stream_callback(stream.http3->quic_stream, stream.http3, &event));
    }

    void ReceiveSettings(Settings settings)
    {
        Bytes payload;
        for (auto [id, value] : settings) {
            AppendVarint(payload, id);
            AppendVarint(payload, value);
        }
        auto bytes = Frame(0x04, payload);
        bytes.insert(bytes.begin(), 0x00); // Control stream type.
        const uint64_t peer_control_id = connection->role == WTF_ENDPOINT_SERVER ? 2 : 3;
        Receive(OpenStream(peer_control_id), std::move(bytes));
    }

    void ReceiveDatagram(Bytes bytes)
    {
        QUIC_BUFFER buffer = {static_cast<uint32_t>(bytes.size()), bytes.data()};
        QUIC_CONNECTION_EVENT event = {};
        event.Type = QUIC_CONNECTION_EVENT_DATAGRAM_RECEIVED;
        event.DATAGRAM_RECEIVED.Buffer = &buffer;
        EXPECT_EQ(QUIC_STATUS_SUCCESS,
                  wtf_connection_callback(connection->quic_connection, connection, &event));
    }

    static Bytes Connect(std::string_view protocol, Fields fields = {})
    {
        Bytes block = {0, 0, 0xcf, 0xd7, 0xc1}; // QPACK prefix, CONNECT, https, /.
        AppendField(block, ":authority", "localhost");
        AppendField(block, ":protocol", protocol);
        for (auto [name, value] : fields) {
            AppendField(block, name, value);
        }
        return Frame(0x01, block);
    }

    void ExpectResponse(Stream& stream, uint16_t status, const char* draft = nullptr)
    {
        size_t offset = 0;
        uint64_t type = 0;
        uint64_t length = 0;
        const auto& bytes = stream.sent;
        ASSERT_TRUE(wtf_varint_decode(bytes.size(), bytes.data(), &offset, &type));
        ASSERT_EQ(0x01u, type);
        ASSERT_TRUE(wtf_varint_decode(bytes.size(), bytes.data(), &offset, &length));
        ASSERT_EQ(bytes.size() - offset, length);
        wtf_connect_response response = {};
        EXPECT_EQ(WTF_SUCCESS, wtf_qpack_parse_response_headers(&context, stream.http3,
                      bytes.data() + offset, static_cast<size_t>(length), &response));
        EXPECT_TRUE(response.valid);
        EXPECT_EQ(status, response.status_code);
        if (draft) EXPECT_STREQ(draft, response.draft_header);
        wtf_connect_response_cleanup(&response);
    }

    static Bytes Frame(uint64_t type, const Bytes& payload)
    {
        Bytes frame;
        AppendVarint(frame, type);
        AppendVarint(frame, payload.size());
        frame.insert(frame.end(), payload.begin(), payload.end());
        return frame;
    }

    static void AppendVarint(Bytes& bytes, uint64_t value)
    {
        uint8_t encoded[8];
        auto* end = wtf_varint_encode(value, encoded);
        bytes.insert(bytes.end(), encoded, end);
    }

private:
    // Literal QPACK field line with a literal name, without Huffman coding or dynamic entries.
    static void AppendField(Bytes& block, std::string_view name, std::string_view value)
    {
        ASSERT_LT(name.size(), 7 + 128);
        ASSERT_LT(value.size(), 127u);
        if (name.size() < 7) {
            block.push_back(static_cast<uint8_t>(0x20 | name.size()));
        } else {
            block.push_back(0x27);
            block.push_back(static_cast<uint8_t>(name.size() - 7));
        }
        block.insert(block.end(), name.begin(), name.end());
        block.push_back(static_cast<uint8_t>(value.size()));
        block.insert(block.end(), value.begin(), value.end());
    }

    static QUIC_STATUS QUIC_API Send(HQUIC handle, const QUIC_BUFFER* buffers, uint32_t count,
                                     QUIC_SEND_FLAGS, void* send_context)
    {
        auto& sent = reinterpret_cast<Stream*>(handle)->sent;
        for (uint32_t i = 0; i < count; i++) {
            sent.insert(sent.end(), buffers[i].Buffer, buffers[i].Buffer + buffers[i].Length);
        }
        wtf_internal_send_context_destroy(static_cast<wtf_internal_send_context*>(send_context));
        return QUIC_STATUS_SUCCESS;
    }

    static void QUIC_API Shutdown(HQUIC handle, QUIC_CONNECTION_SHUTDOWN_FLAGS, QUIC_UINT62 code)
    {
        reinterpret_cast<Http3SpecTest*>(handle)->connection_errors.push_back(code);
    }
};

class Http3ClientSpecTest : public Http3SpecTest {
protected:
    wtf_client client = {};
    std::vector<wtf_session_t*> client_sessions;
    std::vector<uint32_t> session_errors;

    void SetUp() override
    {
        Http3SpecTest::SetUp();
        ASSERT_NE(nullptr, connection);
        ASSERT_EQ(thrd_success, mtx_init(&client.mutex, mtx_plain));
        if (cnd_init(&client.connected) != thrd_success) {
            mtx_destroy(&client.mutex);
            FAIL() << "Could not initialize the client condition variable";
        }

        connection->role = WTF_ENDPOINT_CLIENT;
        connection->client = &client;
        connection->session_callback = [](const wtf_session_event_t* event) {
            if (event->type == WTF_SESSION_EVENT_DISCONNECTED) {
                auto* test = static_cast<Http3ClientSpecTest*>(event->user_context);
                test->session_errors.push_back(event->disconnected.error_code);
            }
        };
        connection->user_context = this;
        client.connection = connection;
        client.state = WTF_CLIENT_CONNECTING;
        client.config.allow_pooling = true;
        api.StreamOpen = OpenClientStream;
        api.StreamStart = [](HQUIC, QUIC_STREAM_START_FLAGS) { return QUIC_STATUS_SUCCESS; };
    }

    void TearDown() override
    {
        if (client.connection) {
            wtf_client_fail_pending_sessions(&client, WTF_ERROR_CONNECTION_ABORTED, "test cleanup");
        }
        Http3SpecTest::TearDown();
        for (auto* session : client_sessions) wtf_session_unref(session);
        if (client.connection) {
            cnd_destroy(&client.connected);
            mtx_destroy(&client.mutex);
        }
    }

    wtf_session_t* OpenSession(wtf_result_t expected = WTF_SUCCESS)
    {
        wtf_session_t* session = nullptr;
        EXPECT_EQ(expected, wtf_http3_client_open_session(&client, &session));
        if (session) client_sessions.push_back(session);
        return session;
    }

private:
    static QUIC_STATUS QUIC_API OpenClientStream(HQUIC handle, QUIC_STREAM_OPEN_FLAGS,
                                                 QUIC_STREAM_CALLBACK_HANDLER, void* context,
                                                 HQUIC* result)
    {
        auto* test = static_cast<Http3ClientSpecTest*>(reinterpret_cast<Http3SpecTest*>(handle));
        auto& stream = test->streams.emplace_back();
        stream.http3 = static_cast<wtf_http3_stream*>(context);
        *result = reinterpret_cast<HQUIC>(&stream);
        return QUIC_STATUS_SUCCESS;
    }
};
