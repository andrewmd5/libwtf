#include "wtf.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <semaphore>
#include <string>
#include <utility>


TEST(CppIntegration, EchoStreamsAndDatagramsWithOwnedSends) {
    using namespace std::chrono_literals;

    auto server_context = wtf::Context::Create({
        .log_level = WTF_LOG_LEVEL_NONE,
    });
    auto client_context = wtf::Context::Create({
        .log_level = WTF_LOG_LEVEL_NONE,
    });
    ASSERT_TRUE(server_context);
    ASSERT_TRUE(client_context);

    wtf::ServerOptions server_options{
        .host = "127.0.0.1",
        .port = 44445,
        .certificate = {
            .identity = wtf::Certificate::PemFiles{
                .certificate = WTF_TEST_CERT_DIR "/localhost.crt",
                .key = WTF_TEST_CERT_DIR "/localhost.key",
            },
        },
        .transport = {
            .draft = wtf::Draft::k07,
            .enable_migration = true,
            .send_buffering = wtf::SendBuffering::kDisabled,
        },
    };
    wtf::SessionHandlers server_handlers{
        .on_stream = [](wtf::SessionView, wtf::StreamView) noexcept {
            return wtf::StreamHandlers{
                .on_data = [](wtf::StreamView stream, wtf::BufferSequence data) noexcept {
                    for (auto chunk : data.chunks()) {
                        if (!stream.SendCopy(chunk)) {
                            static_cast<void>(stream.Abort(1));
                            return;
                        }
                    }
                },
                .on_peer_closed = [](wtf::StreamView stream) noexcept {
                    static_cast<void>(stream.Close());
                },
            };
        },
        .on_datagram = [](wtf::SessionView session, wtf::Bytes data) noexcept {
            static_cast<void>(session.SendDatagramCopy(data));
        },
    };
    auto server = wtf::Server::Create(
        *server_context,
        server_options,
        std::move(server_handlers)
    );
    ASSERT_TRUE(server);
    ASSERT_TRUE(server->Start());

    std::binary_semaphore stream_echo(0);
    std::binary_semaphore datagram_echo(0);
    std::binary_semaphore sent(0);
    std::binary_semaphore datagram_sent(0);
    std::string received;

    wtf::ClientOptions client_options{
        .url = "https://127.0.0.1:44445/",
        .transport = {
            .draft = wtf::Draft::k07,
            .enable_migration = true,
            .send_buffering = wtf::SendBuffering::kDisabled,
        },
        .skip_certificate_validation = true,
    };
    wtf::SessionHandlers client_handlers{
        .on_connected = [&](wtf::SessionView session, wtf::ConnectResponse) noexcept {
            auto stream = session.OpenBidirectionalStream({
                .on_data = [&](wtf::StreamView, wtf::BufferSequence data) noexcept {
                    for (auto chunk : data.chunks()) {
                        received.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                    }
                },
                .on_peer_closed = [&](wtf::StreamView) noexcept {
                    stream_echo.release();
                },
            });
            if (!stream) {
                return;
            }

            wtf::ByteBuffer payload(256 * 1024, std::byte{0x5a});
            static_cast<void>(stream->Send(std::move(payload), {
                .fin = true,
                .on_complete = [&](wtf::SendCompletion completion) noexcept {
                    if (!completion.cancelled) {
                        sent.release();
                    }
                },
            }));
            static_cast<void>(session.SendDatagram(
                wtf::ByteBuffer(32, std::byte{0x2a}),
                {
                    .on_complete = [&](wtf::DatagramCompletion completion) noexcept {
                        EXPECT_TRUE(completion.final());
#ifdef WTF_QUIC_BACKEND_NETWORK
                        EXPECT_EQ(WTF_DATAGRAM_SEND_UNTRACKED, completion.state);
#endif
                        datagram_sent.release();
                    },
                }
            ));
        },
        .on_datagram = [&](wtf::SessionView, wtf::Bytes data) noexcept {
            if (data.size() == 32 && data.front() == std::byte{0x2a}) {
                datagram_echo.release();
            }
        },
    };
    auto client = wtf::Client::Create(
        *client_context,
        client_options,
        std::move(client_handlers)
    );
    ASSERT_TRUE(client);
    auto session = client->Open();
    ASSERT_TRUE(session);
    ASSERT_TRUE(stream_echo.try_acquire_for(5s));
    ASSERT_TRUE(datagram_echo.try_acquire_for(5s));
    ASSERT_TRUE(sent.try_acquire_for(5s));
    ASSERT_TRUE(datagram_sent.try_acquire_for(5s));
    EXPECT_EQ(std::string(256 * 1024, '\x5a'), received);
}
