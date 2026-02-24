# zquic

A QUIC protocol library written in Zig. Pure sans-I/O design — no sockets, no threads, no allocator in the hot path. The library is a state machine you drive; you own the I/O.

> **Status: Phase 1 complete.** Core QUIC transport (RFC 9000) and QUIC-TLS (RFC 9001) are implemented and tested. See [Roadmap](#roadmap) for what's next.

## Features

- **RFC 9000** — packet encoding/decoding, frame types, stream multiplexing, flow control, connection state machine
- **RFC 9001** — TLS 1.3 handshake (sans-I/O), AES-128-GCM payload encryption, header protection, initial key derivation verified against RFC 9001 Appendix A test vectors
- **RFC 9438** — CUBIC congestion control
- **Zero dependencies** — all crypto via `std.crypto`, no external libraries
- **No allocator in hot path** — O(1) pool allocator, fixed-capacity buffers
- **Comptime-safe** — `ConnectionHot` layout enforced at compile time

## Requirements

- Zig `0.16.0-dev` (master branch)

## Build

```sh
zig build          # build library
zig build test     # run all tests (110 tests)
```

## Usage

zquic is a sans-I/O library. You feed raw UDP datagrams in and drain bytes to send out:

```zig
const quic = @import("zquic");

var conn = quic.Connection.init(allocator, .server);

// Feed a received UDP datagram
try conn.receive(udp_payload, src_addr, now_ns);

// Drain bytes to transmit
var out: [1500]u8 = undefined;
const n = conn.send(&out);
if (n > 0) socket.sendTo(out[0..n], peer_addr);

// Drive timers
if (conn.nextTimeout()) |deadline| {
    // sleep until deadline, then:
    conn.tick(now_ns);
}
```

## Architecture

```
src/
  root.zig                  # public API re-exports
  quic/
    varint.zig              # RFC 9000 §16 — variable-length integers
    packet.zig              # RFC 9000 §17 — long/short header encode/decode
    frame.zig               # RFC 9000 §19 — STREAM, ACK, CRYPTO, etc.
    crypto.zig              # RFC 9001 §5  — key derivation, AES-128-GCM, header protection
    tls.zig                 # RFC 9001     — TLS 1.3 handshake state machine
    connection.zig          # RFC 9000 §8  — connection state machine
    connection_id.zig       #              — 8-byte CID generation
    stream.zig              # RFC 9000 §2  — stream multiplexing, ring buffers
    flow_control.zig        # RFC 9000 §4  — per-connection flow control
    pool.zig                #              — O(1) fixed-capacity pool allocator
    congestion/
      cubic.zig             # RFC 9438     — CUBIC congestion control
```

The hot/cold connection split keeps the 64-byte hot path cache-friendly:

```zig
pub const ConnectionHot = struct {
    rx_pn_space: [3]u64,   // largest received PN per epoch
    tx_pn_space: [3]u64,   // next TX PN per epoch
    state:       ConnState,
    epoch:       u8,
    // ...
    comptime { std.debug.assert(@sizeOf(@This()) == 64); }
};
```

## Roadmap

- **Phase 2** — I/O integration: POSIX UDP backend (kqueue/epoll), echo server example
- **Phase 3** — HTTP/3 (RFC 9114) + QPACK (RFC 9204)
- **Phase 4** — Connection migration, preferred address, stateless reset
- **Phase 5** — Multi-core: thread-per-core with SO_REUSEPORT, CID-based routing

## License

MIT — see [LICENSE](LICENSE).
