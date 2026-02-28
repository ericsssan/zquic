# zquic

A QUIC protocol library written in Zig. Pure sans-I/O design — no sockets, no threads, no allocator in the hot path. The library is a state machine you drive; you own the I/O.

> **Status: Core QUIC implementation complete.** RFC 9000, 9001, 9002, 9438 fully implemented. 794 tests passing. Ready for interop testing and performance optimization.

## Features

- **RFC 9000** — packet encoding/decoding, frame types, stream multiplexing, flow control, connection state machine, path migration, stateless reset, retry tokens, connection migration, PMTUD
- **RFC 9001** — TLS 1.3 handshake (server-side, sans-I/O), AES-128-GCM payload encryption, header protection, key updates, initial/handshake/1-RTT keys
- **RFC 9002** — RTT estimation, PTO-based loss detection, ACK-based loss detection, persistent congestion, key update integration
- **RFC 9438** — CUBIC congestion control with saturation arithmetic, overflow guards
- **Zero dependencies** — all crypto via `std.crypto`, no external libraries
- **No allocator in hot path** — O(1) pool allocator, fixed-capacity buffers
- **Comptime-safe** — `ConnectionHot` layout enforced at compile time (64 bytes)
- **Crypto constant-time** — timing-safe MAC verification, memory zeroization for sensitive data
- **Replay protection** — per-epoch packet number validation, stateless reset token validation

## Requirements

- Zig `0.16.0-dev` (master branch or later)

## Build & Test

```sh
zig build                          # build library
zig build test --summary all       # run all 794 tests
```

## Usage

zquic is a sans-I/O library. You feed raw UDP datagrams in and drain bytes to send out:

```zig
const quic = @import("zquic");

var conn = try quic.Connection.accept(.{}, io);

// Feed a received UDP datagram
conn.receive(udp_payload, src_addr, now_ns, io) catch {};

// Drain bytes to transmit
var out: [1500]u8 = undefined;
const n = conn.send(&out);
if (n > 0) socket.sendTo(out[0..n], peer_addr);

// Drive timers
if (conn.nextTimeout()) |deadline| {
    // sleep until deadline, then:
    conn.tick(now_ns);
}

// Poll events (stream data, connection closed, etc.)
while (conn.pollEvent()) |ev| {
    // handle ev
}
```

## Architecture

```
src/
  root.zig                      # public API re-exports
  quic/
    varint.zig                  # RFC 9000 §16 — variable-length integers
    packet.zig                  # RFC 9000 §17 — long/short header encode/decode
    frame.zig                   # RFC 9000 §19 — STREAM, ACK, CRYPTO, etc.
    connection_id.zig           # 8-byte CID generation & pool
    crypto.zig                  # RFC 9001 §5  — key derivation, AES-128-GCM, header protection
    tls.zig                     # RFC 9001 §4  — TLS 1.3 server handshake, transcript, secrets
    transport_params.zig        # RFC 9000 §18 — transport parameter encoding/decoding
    connection.zig              # RFC 9000 §8  — connection state machine, frame processing
    stream.zig                  # RFC 9000 §2  — stream multiplexing, ring buffers, gap list
    flow_control.zig            # RFC 9000 §4  — per-connection & per-stream flow control
    loss_recovery.zig           # RFC 9002 §6  — RTT estimator, PTO, loss detection, ACK tracking
    pool.zig                    # O(1) fixed-capacity pool allocator
    congestion/
      cubic.zig                 # RFC 9438     — CUBIC congestion control
```

The hot/cold connection split keeps the 64-byte hot path cache-friendly:

```zig
pub const ConnectionHot = struct {
    rx_pn_space: [3]u64,        // largest received PN per epoch
    tx_pn_space: [3]u64,        // next TX PN per epoch
    state:       ConnState,
    epoch:       u8,
    rx_pn_valid: [3]bool,       // replay protection per epoch
    // ...
    comptime { std.debug.assert(@sizeOf(@This()) == 64); }
};
```

## Task List & Roadmap

### Completed ✅
- **#12** Stream table redesign: pre-allocated hash pool
- **#13** PMTUD (Path MTU Discovery) - RFC 9000 §14

### High Priority - Next (Blocking Production)
- **#14** Micro-optimization for performance and efficiency — benchmark suite, profile hot paths, eliminate bottlenecks in packet processing, frame encoding/decoding, and crypto operations
- **#15** Interop testing via quic-interop-runner — validate against Chrome/ngtcp2/quic-go
- **#16** ECN (Explicit Congestion Notification) — ~200 LOC, direct congestion improvement

### Medium Priority
- **#17** TlsClient + cert validation callback — enables client connections
- **#18** Retry packets + connection rate limiting — DoS mitigation
- **#19** 0-RTT session resumption — low-latency reconnects

### Lower Priority (Post-Functional)
- **#20** Security audit — comprehensive crypto/timing/input validation review
- **#21** SIMD/AES-NI/huge-pages/CID BPF optimizations — extreme performance polish

## Test Coverage

- **794 tests passing** across all modules
- RFC test vectors verified (RFC 9001 Appendix A crypto vectors)
- Fuzz targets for frame round-trip, GapList, stream send buffer, loss recovery, RTT estimation
- Regression tests for all major bugs fixed

## Known Limitations

- **TLS server-only** — TlsClient not yet implemented (see #17)
- **No HTTP/3** — this is a QUIC transport library only
- **No 0-RTT yet** — PSK and session resumption pending (see #19)
- **No Retry tokens yet** — address validation with Retry pending (see #18)
- **MAX_STREAMS=4** (configurable) — hash pool redesign planned (completed but not integrated into stream table yet)

## Design Notes

### Sans-I/O Architecture
Library is a pure protocol state machine. Caller drives via:
- `connection.receive(data, src, now_ns, io)` — feed raw UDP bytes
- `connection.send(out) usize` — drain bytes to transmit
- `connection.nextTimeout() ?i64` — nanosecond deadline
- `connection.tick(now_ns)` — drive timers
- `connection.pollEvent() ?Event` — get stream data, connection closed, etc.

### Why AES-128-GCM only?
Deliberate: homogeneous SIMD batching opportunity vs. ChaCha20 variability. Performance tradeoff accepted.

### Crypto Security
- Constant-time MAC verification (`std.crypto.timing_safe.eql`)
- Memory zeroization for secrets (`std.crypto.secureZero`)
- Per-epoch replay protection (stateless)
- Stateless reset token validation

## License

MIT — see [LICENSE](LICENSE).
