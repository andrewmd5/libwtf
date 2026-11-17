# libwtf

C WebTransport over HTTP/3, built on [MsQuic](https://github.com/microsoft/msquic),
with an optional native macOS Network.framework backend.

Supports server and native client use, streams, datagrams, pooled sessions, and draft-15,
draft-07, and draft-02 negotiation.

## Build

```sh
git clone --recurse-submodules https://github.com/andrewmd5/libwtf.git
cd libwtf
make
```

## Test

```sh
make test
make report
```

## Run

```sh
./build/output/wtf_echo_server --port 4433 --cert certs/localhost.crt --key certs/localhost.key
./build/output/wtf_echo_client --host localhost --port 4433 --draft auto
```

The echo server disables transport send buffering and bounds outstanding responses
to 1 MiB per stream, 8 MiB per session, and 32 MiB across the server. Each send
charges at least 1 KiB to bound metadata for small payloads. Charges remain until
send completion; streams that exceed a limit are aborted. Applications that queue
responses should apply similar limits and backpressure.

## API

See [include/wtf.h](include/wtf.h).

## C++

Include [wtf.hpp](include/wtf.hpp) and link libwtf. With CMake, link
`WebTransport::cpp` instead of `WebTransport::wtf` to request C++23.
The standard library must provide `std::expected` and `std::move_only_function`.
Clang 21 with libstdc++ 15 works; libc++ currently lacks the latter.

`Context`, `Client`, and `Server` are move-only RAII owners. `Session` and `Stream`
retain their C handles; copying retains and destruction releases. Call `Close()`
or `Abort()` to change transport state. Callback views are borrowed; use
`Retain()` to keep one. Children keep the context alive after its owner moves or
leaves scope. Destroy clients and servers outside callbacks, after synchronizing
other application threads that use them.

`Send(std::vector<std::byte>)` takes ownership until completion. `SendCopy()`
copies before returning. `SendBorrowed()` leaves the payload with the caller
until completion. Datagram buffers stay alive until a final send state.
Callbacks are `noexcept`, run on transport threads, and can run concurrently for
different connections. Receive data and response headers are callback-only views.

Enable `WTF_BUILD_CPP` along with `WTF_BUILD_TESTS` or `WTF_BUILD_SAMPLES` to build
the wrapper tests or [C++ echo server](samples/echo_cpp.cc).

## License

MIT
