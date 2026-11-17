#include "wtf.hpp"

#include <utility>

wtf::Result<wtf::Client> CreateCppHeaderClient(
    const wtf::Context& context,
    wtf::SessionHandlers handlers
) {
    return wtf::Client::Create(
        context,
        {
            .url = "https://localhost:4433/",
        },
        std::move(handlers)
    );
}
