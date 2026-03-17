# zquic

A QUIC protocol library for Zig. Sans-I/O — you own the socket; the library owns the state machine.

## Features

- QUIC v1 (RFC 9000) and v2 (RFC 9369)
- TLS 1.3 with AES-128-GCM and ChaCha20-Poly1305 (RFC 9001)
- Session resumption and 0-RTT
- HTTP/3 (RFC 9114) and QPACK (RFC 9204)
- CUBIC congestion control (RFC 9438)
- Zero external dependencies

## Build

```sh
zig build test    # run tests
zig build         # build server binary
```

Requires Zig 0.16.0-dev or later.

## Interop Results

<!-- INTEROP_START -->
Tested against ngtcp2 client — 22/22 passing, goodput 9394 kbps on 10 Mbps link:

| Result | Test cases |
| :---: | --- |
| ✅ Pass (22/22) | handshake, transfer, longrtt, chacha20, multiplexing, retry, resumption, zerortt, http3, blackhole, keyupdate, ecn, amplificationlimit, handshakeloss, transferloss, handshakecorruption, transfercorruption, v2, ipv6, rebind-port, rebind-addr, connectionmigration |
<!-- INTEROP_END -->

## Limitations

- Server-side only (no TLS client)

## License

MIT
