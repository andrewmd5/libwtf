#include <iostream>
#include <utility>

#include "wtf.hpp"

int main(int argc, char** argv) {
    if (argc != 3) {
        std::cerr << "Usage: wtf_echo_cpp certificate.pem private-key.pem\n";
        return 2;
    }

    auto context = wtf::Context::Create({
        .log_level = WTF_LOG_LEVEL_WARN,
    });
    if (!context) {
        std::cerr << context.error().message() << '\n';
        return 1;
    }

    wtf::ServerOptions options{
        .port = 4433,
        .certificate = {
            .identity = wtf::Certificate::PemFiles{
                .certificate = argv[1],
                .key = argv[2],
            },
        },
    };

    wtf::SessionHandlers handlers{
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
        *context,
        options,
        std::move(handlers),
        [](wtf::ConnectionRequest& request) noexcept {
            if (request.path() != "/") {
                request.Reject();
            }
        }
    );
    if (!server) {
        std::cerr << server.error().message() << '\n';
        return 1;
    }
    if (auto result = server->Start(); !result) {
        std::cerr << result.error().message() << '\n';
        return 1;
    }

    std::cout << "Listening on port 4433. Press Enter to stop.\n";
    std::cin.get();
}
