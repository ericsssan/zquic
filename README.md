# zquic

A QUIC protocol library for Zig. Sans-I/O — you own the socket; the library owns the state machine.

## Features

- QUIC v1 (RFC 9000) and v2 (RFC 9369)
- TLS 1.3 server handshake with AES-128-GCM and ChaCha20-Poly1305 (RFC 9001)
- Session resumption and 0-RTT
- Loss recovery, RTT estimation, PTO (RFC 9002)
- CUBIC and BBR v3 congestion control (RFC 9438)
- Stream multiplexing and flow control
- Path migration and NAT rebinding
- Pacing with wire-time accounting
- Packet coalescing (RFC 9000 §12.2)
- PMTUD, retry tokens, key rotation, ECN
- Ed25519 and P-256 certificates
- Zero external dependencies

## Build

```sh
zig build test                  # run tests (default: BBR)
zig build test -Dcongestion=cubic  # run tests with CUBIC
zig build                       # build server binary
zig build -Dcongestion=cubic    # build with CUBIC
```

Requires Zig 0.17.0-dev.657+2faf8debf or later.

## Interop Results

<!-- INTEROP_START -->
Tested against 11 QUIC clients via [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) on a 10 Mbps / 30 ms RTT link:

| Client | Tests | Goodput |
| --- | --- | --- |
| ngtcp2 | 22/22 | 9432 kbps |
| quic-go | 20/20 | 9507 kbps |
| quiche | 18/18 | — |
| neqo | 19/22 | — |
| kwik | 19/21 | 7849 kbps |
| picoquic | 16/22 | — |
| mvfst | 12/16 | 9496 kbps |
| aioquic | 13/21 | 9190 kbps |
| lsquic | — | 9454 kbps |
| msquic | — | 7937 kbps |
| quinn | — | 9462 kbps |

Test cases: handshake, transfer, longrtt, chacha20, multiplexing, retry, resumption, zerortt, http3, blackhole, keyupdate, ecn, amplificationlimit, handshakeloss, transferloss, handshakecorruption, transfercorruption, v2, ipv6, rebind-port, rebind-addr, connectionmigration
<!-- INTEROP_END -->

## Limitations

- Server-side only (no TLS client)

## License

MIT
