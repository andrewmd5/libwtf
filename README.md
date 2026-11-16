# libwtf

C WebTransport over HTTP/3, built on [MsQuic](https://github.com/microsoft/msquic).

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

## License

MIT
