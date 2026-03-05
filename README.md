# zquic

A QUIC protocol library for Zig. Sans-I/O — you own the socket; the library owns the state machine.

[![CI](https://github.com/ericsssan/zquic/actions/workflows/ci.yml/badge.svg)](https://github.com/ericsssan/zquic/actions/workflows/ci.yml)
[![Interop](https://github.com/ericsssan/zquic/actions/workflows/interop.yml/badge.svg)](https://github.com/ericsssan/zquic/actions/workflows/interop.yml)

## Features

- QUIC v1 (RFC 9000) and v2 (RFC 9369)
- TLS 1.3 server handshake with AES-128-GCM, key rotation, SSLKEYLOG (RFC 9001)
- Loss recovery, RTT estimation, PTO (RFC 9002)
- CUBIC congestion control (RFC 9438)
- Stream multiplexing, flow control, path migration, PMTUD, retry tokens
- Ed25519 and P-256 certificates
- Zero external dependencies

## Requirements

Zig `0.14.0` or later (tested on `0.16.0-dev`).

## Build

```sh
zig build test --summary all   # run tests
zig build                      # build server binary
```

## Usage

`Connection(N)` is parameterized by max concurrent streams:

```zig
const quic = @import("zquic");

var conn = try quic.Connection(64).accept(config, io);

// Feed received datagrams
try conn.receive(udp_payload, src_addr, now_ns, io);

// Drain outgoing datagrams
var out: [1500]u8 = undefined;
while (true) {
    const n = conn.send(&out);
    if (n == 0) break;
    socket.sendTo(out[0..n], peer_addr);
}

// Drive timers
if (conn.nextTimeout()) |deadline| { /* sleep, then: */ conn.tick(now_ns); }

// Poll events
while (conn.pollEvent()) |ev| { /* stream data, connected, closed, etc. */ }
```

For multiple connections, use the pool allocator:

```zig
const Conn = quic.Connection(64);
var pool: quic.pool.Pool(Conn, 1024) = .{};

var conn = pool.acquire() orelse return error.PoolExhausted;
defer pool.release(conn);
```

## Architecture

```
src/quic/
  connection.zig         # connection state machine
  stream.zig             # stream multiplexing
  crypto.zig             # key derivation, AES-128-GCM, header protection
  packet.zig             # packet encoding/decoding
  frame.zig              # frame types
  tls.zig                # TLS 1.3 handshake
  loss_recovery.zig      # RTT, PTO, loss detection
  flow_control.zig       # flow control
  congestion/cubic.zig   # CUBIC
  transport_params.zig   # transport parameters
  connection_id.zig      # CID generation
  varint.zig             # variable-length integers (RFC 9000 §16)
  pool.zig               # O(1) fixed-capacity pool

tools/
  server.zig             # quic-interop-runner HTTP/0.9 server
  Dockerfile             # Alpine image for interop runner
```

## Interop Results

> **Note:** [`ghcr.io/ericsssan/zquic-interop:latest`](https://github.com/ericsssan/zquic/pkgs/container/zquic-interop) is built solely for use with [quic-interop-runner](https://github.com/quic-interop/quic-interop-runner). It is not a general-purpose or production image.

<!-- INTEROP_START -->
| Test | (pending first run) |
| --- | :---: |
<!-- INTEROP_END -->

## Limitations

- Server-side only (no TLS client)
- No HTTP/3
- No 0-RTT / session resumption

## License

MIT
