# zquic

A QUIC protocol library written in Zig. Pure sans-I/O design — no sockets, no threads, no allocator in the hot path. The library is a state machine you drive; you own the I/O.

> **Status: Core QUIC implementation complete.** RFC 9000, 9001, 9002, 9369, 9438 fully implemented. **973 tests passing**. Interop server built and wired into quic-interop-runner CI. In progress: resolving remaining interop test failures.

## Features

- **RFC 9000** — packet encoding/decoding, frame types, stream multiplexing, flow control, connection state machine, path migration, stateless reset, retry tokens, connection migration, PMTUD
- **RFC 9001** — TLS 1.3 handshake (server-side, sans-I/O), AES-128-GCM payload encryption, header protection, key rotation with deterministic secret derivation, initial/handshake/1-RTT keys; Ed25519 and P-256 ECDSA certificates; SSLKEYLOG support for Wireshark decryption
- **RFC 9002** — RTT estimation, PTO-based loss detection, ACK-based loss detection, persistent congestion, ECN CE reaction
- **RFC 9369** — QUIC v2 (`0x6b3343cf`): v2 initial salt, `quicv2 *` key-derivation labels, long-header type-bit rotation, v2 Retry integrity tag
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
zig build                          # build library + interop server
zig build test --summary all       # run all 973 tests
zig build verify-key-rotation      # verify key rotation mechanism
```

## Usage

zquic is a sans-I/O library. You feed raw UDP datagrams in and drain bytes to send out.

**Single Connection (Testing/Examples):**

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

**Multiple Connections (Production):**

For production deployments with many simultaneous connections, use the pool allocator to avoid stack pressure (Connection is ~37KB):

```zig
const quic = @import("zquic");

// Pre-allocate 10,000 connection slots on heap
var conn_pool = try quic.Pool(quic.Connection, 10_000).init(allocator);
defer conn_pool.deinit();

// Accept new connection
var conn = try conn_pool.acquire();
defer conn_pool.release(conn);

// Same API as single-connection example above
conn.receive(udp_payload, src_addr, now_ns, io) catch {};
// ... etc
```

The pool allocator is O(1) acquire/release with no allocations in the hot path.

## Architecture

```
src/
  root.zig                      # public API re-exports
  quic/
    varint.zig                  # RFC 9000 §16 — variable-length integers
    packet.zig                  # RFC 9000 §17, RFC 9369 §3 — long/short header encode/decode (v1+v2)
    frame.zig                   # RFC 9000 §19 — STREAM, ACK, CRYPTO, etc.
    connection_id.zig           # 8-byte CID generation & pool
    crypto.zig                  # RFC 9001 §5, RFC 9369 §3 — key derivation (v1+v2), AES-128-GCM, header protection
    tls.zig                     # RFC 9001 §4  — TLS 1.3 server handshake, transcript, secrets
    transport_params.zig        # RFC 9000 §18 — transport parameter encoding/decoding
    connection.zig              # RFC 9000 §8  — connection state machine, frame processing
    stream.zig                  # RFC 9000 §2  — stream multiplexing, ring buffers, gap list
    flow_control.zig            # RFC 9000 §4  — per-connection & per-stream flow control
    loss_recovery.zig           # RFC 9002 §6  — RTT estimator, PTO, loss detection, ACK tracking
    pool.zig                    # O(1) fixed-capacity pool allocator
    fuzz.zig                    # fuzz targets for frame, varint, transport params, packet, stream, loss recovery
    congestion/
      cubic.zig                 # RFC 9438     — CUBIC congestion control

tools/
  server.zig                    # quic-interop-runner compatible UDP server (HTTP/0.9, event-driven)
  pem.zig                       # PEM → DER decoder, PKCS#8 key extraction (Ed25519 + P-256)
  Dockerfile                    # multi-stage build → minimal Alpine image for interop runner
```

The hot/cold connection split keeps the 64-byte hot path cache-friendly:

```zig
pub const ConnectionHot = struct {
    rx_pn: [3]u64,              // largest received PN per epoch
    tx_pn: [3]u64,              // next TX PN per epoch
    state:       ConnState,
    epoch:       u8,
    rx_pn_valid: [3]bool,       // replay protection per epoch
    _pad: [11]u8,
    comptime { std.debug.assert(@sizeOf(ConnectionHot) == 64); }
};
```

## Roadmap

### Completed ✅
- Stream table redesign: pre-allocated O(1) hash pool, 64 streams
- PMTUD (Path MTU Discovery) — RFC 9000 §14
- Retry tokens + address validation — RFC 9000 §8.1
- ECN (Explicit Congestion Notification) — RFC 9000 §12.1, RFC 9002 §B.1
- QUIC v2 — RFC 9369 (v2 salt, labels, header type rotation, Retry integrity tag)
- Key rotation (RFC 9001 §6) — deterministic secret derivation, secure zeroization, SSLKEYLOG support
- SSLKEYLOG writing — Wireshark decryption for all key generations, incremental updates
- Interop server — quic-interop-runner compatible Docker image; CI wired up (TESTCASE: handshake, transfer, retry, keyupdate, v2)

### Next
- 0-RTT session resumption — low-latency reconnects

### Later
- Full interop test coverage — all quic-interop-runner test cases passing
- Security audit — comprehensive cryptographic/input validation review
- SIMD batch packet decryption — AES-NI pipelining for multi-packet throughput
- Huge page support — TLB pressure reduction for 5M+ RPS workloads

## Test Coverage

- **973 tests passing** across all modules
- RFC test vectors verified (RFC 9001 Appendix A crypto vectors, RFC 9369 v2 vectors)
- Fuzz targets for frame round-trip, GapList, stream send buffer, loss recovery, RTT estimation
- Regression tests for all major bugs fixed (out-of-order packets, ACK gap encoding, key rotation, etc.)
- Key rotation verification tool: `zig build verify-key-rotation` proves deterministic secret derivation

## Known Limitations

- **TLS server-only** — by design; interop is validated via quic-interop-runner against third-party clients
- **No HTTP/3** — this is a QUIC transport library only
- **No 0-RTT yet** — PSK and session resumption pending
- **MAX_STREAMS=64** — compile-time constant, pre-allocated hash pool

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

### Version Support

**QUIC v1 (0x00000001)** is always supported and returned in Version Negotiation packets.
**QUIC v2 (0x6b3343cf)** is also fully implemented with RFC 9369 compliance.

When a client requests an unknown version, the server responds with a VN packet listing both v1 and v2. This ensures interoperability with clients that may not support v2 yet.

### TLS Certificates

This is a **server-side QUIC implementation only**. TLS certificates are generated as self-signed (Ed25519 or P-256 ECDSA) for testing and interop validation.

**Important:** This library does NOT validate peer certificates (no client implementation). For production deployments that require certificate validation, integrate with your application's certificate management system.

## License

MIT — see [LICENSE](LICENSE).
