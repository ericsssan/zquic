# zquic — Design Document

> A native Zig QUIC implementation. Zero dependencies. Single binary.

---

## 1. Why QUIC over UDP

### The TCP problem

Linux kernel TCP processing costs ~2,000–3,000 cycles per packet:
- sk_buff allocation (heap alloc, ~500–800 cycles)
- TCP stack traversal
- Kernel → userspace copy

This caps throughput at ~1–1.5M PPS per core regardless of NIC speed.
With 4 cores + SO_REUSEPORT: ~6M PPS ceiling.

### UDP enables a higher-efficiency path

Raw kernel UDP throughput is similar to TCP: **~1–1.5M PPS per core** in
practice. The difference is what UDP *permits*:

- **io_uring SQPOLL**: kernel polls the submission queue — zero syscalls in the
  hot path. TCP's in-kernel reliability stack cannot be moved to userspace.
- **UDP GSO**: batch multiple QUIC packets per `sendmsg()`. Cloudflare measured
  a 98% syscall reduction (904K → 18K calls) applying GSO to QUIC sends.
- **No kernel connection state**: QUIC state lives entirely in userspace; no
  kernel-maintained TCP socket tables to update per packet.

With io_uring + SQPOLL + GSO, effective UDP PPS approaches kernel-bypass levels:

| Path                               | PPS per core |
|------------------------------------|--------------|
| Kernel TCP (ceiling, no bypass)    | ~1–1.5M      |
| Kernel UDP (baseline)              | ~1–1.5M      |
| UDP + io_uring SQPOLL + GSO        | ~3–5M (est.) |
| Netmap (lightweight kernel bypass) | ~5.8M        |
| DPDK                               | ~15M+        |

With 4 cores + io_uring: **~12–20M effective PPS ceiling**, vs kernel TCP's
hard ~6M ceiling — roughly a **2–3× advantage**.

### QUIC advantages

- **0-RTT**: Repeat clients send data in the first packet. No handshake cost.
- **Multiplexing**: Multiple streams per connection, no head-of-line blocking.
- **Built-in TLS 1.3**: Mandatory. Packet crypto via AES-128-GCM + AES-NI.
- **Connection migration**: Clients can switch networks without reconnecting.
- **No TCP baggage**: No Nagle algorithm, no TIME_WAIT, no SYN flooding.

---

## 2. Performance Model

All numbers below are **theoretical maximums derived from first principles**,
not measured benchmarks.

### Wire cost model

```
Minimum QUIC round-trip:

  Request:
    QUIC short header (1-RTT):   ~28 bytes
    QUIC STREAM frame overhead:  ~10 bytes
    UDP + IP + Ethernet:          46 bytes
    ──────────────────────────────────────
                                  ~84 bytes

  Response:
    QUIC short header:           ~28 bytes
    QUIC STREAM frame overhead:  ~10 bytes
    UDP + IP + Ethernet:          46 bytes
    ──────────────────────────────────────
                                  ~84 bytes

  Round-trip total:              ~168 bytes
```

### NIC ceiling

```
NIC ceiling (RPS) = NIC bandwidth (bytes/sec) / round-trip bytes

  1 Gbps  = 125,000,000 / 168   =  ~744K RPS
  10 Gbps = 1,250,000,000 / 168 =  ~7.4M RPS
  25 Gbps = 3,125,000,000 / 168 = ~18.6M RPS
  100 Gbps = 12,500,000,000 / 168 = ~74M RPS
```

### CPU ceiling

```
Hot path cycles per request (estimated):
  UDP receive (io_uring, amortized):    ~50 cycles
  QUIC packet decode:                  ~100 cycles
  TLS decrypt (AES-NI):                 ~80 cycles
  QUIC frame parse:                     ~50 cycles
  QUIC frame encode:                    ~50 cycles
  TLS encrypt (AES-NI):                 ~80 cycles
  UDP send (io_uring, amortized):       ~50 cycles
  ──────────────────────────────────────────────────
  Total:                               ~460 cycles

CPU ceiling = (clock_hz × cores) / cycles_per_request
  4-core  @ 3 GHz: (3B × 4)  / 460 = ~26M RPS
  16-core @ 3 GHz: (3B × 16) / 460 = ~104M RPS
```

### Ceiling summary

```
NIC     NIC ceiling  CPU (4c)  CPU (16c)  Binding (≥ min cores)
──────────────────────────────────────────────────────────────────
1G      ~744K        ~26M      ~104M      NIC
10G     ~7.4M        ~26M      ~104M      NIC
25G     ~18.6M       ~26M      ~104M      NIC
100G    ~74M         ~26M      ~104M      NIC (with 16+ cores)
```

At 100G with 4 cores: CPU (~23.5M) is binding, NIC not reached.
At 100G with 16 cores: NIC (~65M) is binding — that is the design target.

---

## 3. Architecture

### Layer separation

zquic is the QUIC transport layer only. Application framing layers live in
separate repositories that depend on zquic.

```
zquic (this repo)
└── src/quic/       QUIC transport (RFC 9000 / RFC 9001)
                    - Packet encoding/decoding
                    - Connection state machine
                    - Stream multiplexing
                    - Flow control
                    - Congestion control (CUBIC)
                    - TLS 1.3 handshake
                    - 0-RTT session resumption
                    - Connection migration
                    - Stateless reset
                    - Retry / address validation
```

zquic is usable directly for any protocol over QUIC: game networking,
DNS-over-QUIC, gRPC-over-QUIC, custom binary protocols, etc.

### Threading model: thread-per-core

```
Core 0: owns socket 0 (SO_REUSEPORT), io_uring ring 0, connection subset 0
Core 1: owns socket 1 (SO_REUSEPORT), io_uring ring 1, connection subset 1
Core 2: owns socket 2 (SO_REUSEPORT), io_uring ring 2, connection subset 2
Core 3: owns socket 3 (SO_REUSEPORT), io_uring ring 3, connection subset 3
```

No cross-core sharing in hot path. Cross-core communication via SPSC lock-free
ring buffers only when necessary.

### I/O model: pluggable backends

The I/O layer is a comptime interface. The hot path never calls I/O directly.

```
┌──────────────────────────────────────────────┐
│              QUIC hot path                   │
│   (packet encode/decode, crypto, streams)    │
└──────────────────┬───────────────────────────┘
                   │ IoBackend interface
        ┌──────────┴──────────────────┐
        │                             │
   io_uring (Linux 5.1+)        epoll (Linux)
   SQPOLL + fixed buffers        recvmmsg/sendmmsg
   zero syscalls in hot path     standard approach
        │
   kqueue (macOS/FreeBSD)
   development + testing
```

Default backend per platform:
- Linux (production): io_uring SQPOLL + fixed buffer registration
- Linux (fallback): epoll + recvmmsg/sendmmsg
- macOS/FreeBSD (development): kqueue

### Memory model: no allocation in hot path

```
Startup:
  - Pre-allocate connection pool (N slots, cache-line aligned)
  - Pre-allocate packet buffer pool (ring buffer per core)
  - Pre-allocate TLS session cache

Hot path:
  - All memory from pre-allocated pools
  - Pool allocator: O(1) acquire/release
  - No malloc, no free, no GC
```

### Crypto decisions

#### Cipher suite: AES-128-GCM only

zquic targets new hardware and drops support for legacy clients.
ChaCha20-Poly1305 is not implemented.

Consequences:
- No cipher negotiation branch in the hot path
- SIMD batch decryption is always homogeneous — no per-packet sorting
- `conn.cipher` field removed from hot struct entirely
- Clients without AES hardware (old Android, IoT, embedded) cannot connect

```
AES-128-GCM:  10 rounds, ~3–5 GB/s per core (AES-NI)
AES-256-GCM:  14 rounds, ~2–3 GB/s per core (AES-NI)  — ~30% slower
```

AES-128 is chosen. Security: 2^128 operations to break — no known practical
attack. AES-256's extra cost buys nothing for non-quantum threat models.
Post-quantum vulnerability in QUIC lies in key exchange (ECDH), not the
symmetric cipher.

#### Crypto implementation: std.crypto only

All cryptographic operations use `std.crypto` (Zig standard library):
- TLS 1.3 handshake: X25519 key exchange, HKDF-SHA256, Ed25519 certificates
- Packet crypto: AES-128-GCM encryption/decryption, AES-128-ECB header protection
- Key derivation: HKDF-SHA256 per RFC 9001

Zero external dependencies. The binary is fully self-contained.

### Performance techniques

#### 1. Cache locality [hardware-level]

A cache miss costs ~200 cycles — erasing every other optimization. Connection
state is split into hot struct (seq numbers, crypto ctx, stream state) and
cold struct (peer address, TLS cert, stats):

```zig
const ConnectionHot = struct {
    rx_seq:      u64,   // touched every packet
    tx_seq:      u64,   // touched every packet
    crypto_ctx:  AesCtx,// touched every packet
    stream_state:u32,   // touched every packet
    _pad:        [16]u8,// fill to 64-byte cache line
};  // exactly 64 bytes — one cache line

const ConnectionCold = struct {
    peer_addr:   SocketAddr, // touched on handshake only
    tls_cert:    []u8,       // touched on handshake only
    stats:       ConnStats,  // touched on close only
};
```

#### 2. SIMD — Single Instruction, Multiple Data [hardware-level]

```
Scalar AES-GCM:   1 block (16 bytes) per instruction
AES-NI pipelined: 8 blocks (128 bytes) per instruction cycle (throughput)
```

Applied in zquic:
- AES-NI for packet encryption — mandatory for QUIC, hardware-accelerated
- `@Vector` for batch connection ID lookup across incoming packets

```zig
// Process 8 connection IDs simultaneously
const incoming_ids = @Vector(8, u64){ p0.id, p1.id, p2.id, p3.id,
                                      p4.id, p5.id, p6.id, p7.id };
const matches = incoming_ids == @splat(target_id);
```

#### 3. RSS — Receive Side Scaling [hardware-level: NIC]

NIC ASIC hashes 5-tuple directly into per-core RX queues — before the kernel
is involved. Packets from the same QUIC connection always arrive on the same
core. Connection state stays in that core's L1/L2 permanently.

```
SO_REUSEPORT:  NIC → kernel → software hash → dispatch to core 0/1/2/3
RSS:           NIC ASIC → DMA directly into per-core RX queue
```

Used together: RSS pins connections at the NIC, SO_REUSEPORT gives each core
its own socket.

#### 4. NIC Checksum Offload [hardware-level: NIC]

UDP and IP checksums computed by NIC ASIC during TX and RX. Zero CPU cycles.
Enabled via `SO_NO_CHECK` (TX) and kernel RX checksum offload.

#### 5. GRO — Generic Receive Offload [hardware-level: NIC]

Coalesces multiple incoming UDP packets into a single buffer before kernel
delivery. Fewer io_uring completions, fewer CPU wake-ups. Linux 5.10+.

```
Without GRO:  65M packets → 65M kernel events
With GRO:     65M packets → ~4M coalesced events  (16× fewer)
```

#### 6. Explicit Prefetch [hw-guided]

Connection state lookup by CID is random access — the prefetcher cannot
predict it. Issue prefetch immediately after parsing CID:

```zig
const conn_id = parseConnectionId(raw_header);
@prefetch(&conn_table[conn_id].hot, .{ .rw = .read, .locality = 3 });
// ~200 cycles of other work: finish header parse, validate packet number
// By here, conn_table[conn_id].hot is in L1. Zero stall.
const conn = &conn_table[conn_id].hot;
processPacket(packet, conn);
```

#### 7. ILP — Instruction-Level Parallelism [hardware-level: CPU]

AES-NI has ~4 cycle latency but ~1 cycle throughput when pipelined.
Interleave decryption across packets to saturate the AES pipeline:

```zig
// Interleaved — CPU pipelines all three simultaneously
const d0 = aesDecryptStart(packet[0]);
const d1 = aesDecryptStart(packet[1]);  // issues while d0 in-flight
const d2 = aesDecryptStart(packet[2]);  // issues while d0, d1 in-flight
const r0 = aesDecryptFinish(d0);
const r1 = aesDecryptFinish(d1);
const r2 = aesDecryptFinish(d2);
// All three complete in ~4 cycles total, not 4×3=12 cycles
```

#### 8. io_uring SQPOLL — zero syscalls [software-level]

Kernel polls the submission queue in a dedicated kernel thread. Zero syscalls
in the hot path. Fixed buffer registration eliminates kernel→userspace copies.
GSO batches 32–64 packets per sendmsg.

#### 9. Thread-per-core + SO_REUSEPORT — zero contention [software-level]

Each core owns its socket, ring, connection subset, and memory pool. No locks
on the hot path. Cross-core communication via SPSC lock-free ring buffers only.

#### 10. Zero allocation in hot path — zero jitter [software-level]

Pre-allocate everything at startup. Pool allocator only in hot path: O(1),
deterministic, no syscall. Zig enforces this — the allocator is passed as a
parameter. A wrong allocator type is a compile error.

#### 11. Comptime dispatch — zero indirection [software-level]

Protocol dispatch resolved at compile time. No vtables, no function pointers,
no runtime branching on type.

```zig
const dispatch = comptime buildDispatch(.{
    .initial   = handleInitial,
    .handshake = handleHandshake,
    .one_rtt   = handleOneRtt,
});
```

#### Summary

```
Technique                   Layer            Eliminates
─────────────────────────────────────────────────────────────────────────────
1.  Cache locality           hardware (CPU)   cache miss stalls (~200c each)
2.  SIMD + AES-NI            hardware (CPU)   scalar throughput bottleneck
3.  RSS                      hardware (NIC)   kernel distribution overhead
4.  NIC checksum offload     hardware (NIC)   ~40 cycles/packet
5.  GRO                      hardware (NIC)   16× fewer kernel receive events
6.  Explicit prefetch        hw-guided        random access stalls
7.  ILP (pipeline AES)       hardware (CPU)   crypto latency
─────────────────────────────────────────────────────────────────────────────
8.  io_uring SQPOLL          software         syscall overhead (~1K cycles)
9.  Thread-per-core          software         lock contention, false sharing
10. Zero allocation          software         malloc jitter, P99/P999 spikes
11. Comptime dispatch        software         vtable, branch mispredict
─────────────────────────────────────────────────────────────────────────────
```

---

## 4. Dependency Management (Zig)

Zig projects add zquic via `build.zig.zon`:

```zig
.dependencies = .{
    .zquic = .{
        .url = "https://github.com/ericsssan/zquic/archive/refs/tags/v0.1.0.tar.gz",
        .hash = "...",
    },
},
```

Then in `build.zig`:
```zig
exe.root_module.addImport("quic", b.dependency("zquic", .{}).module("quic"));
```

No system dependencies. Zig fetches, verifies the hash, builds from source.

---

## 5. Scalability

### What scales well

**Vertical scaling (more cores)**: Thread-per-core + SO_REUSEPORT is linear
by construction. Each core is fully independent — no locks in the hot path.
Scaling from 4 to 16 to 64 cores requires no architectural changes.

**Request rate**: Pool allocator + explicit backpressure. When the pool is
exhausted, new connections are rejected cleanly. No OOM, no latency collapse,
no unbounded queue growth.

**NIC speed (1G → 100G)**: Architecture scales by tuning batch sizes and core
count. No structural changes needed.

### Active connection scaling

```
1K connections   × 1KB state = 1MB   → fits in L3 cache
10K connections  × 1KB state = 10MB  → fits in L3 cache (just)
100K connections × 1KB state = 100MB → spills to RAM → +200 cycles/packet
```

Beyond 100K active connections, hot struct lookups miss L3 cache. Performance
degrades gracefully. The threshold only applies to *simultaneously* active
connections — 1M total with 5K active is fine.

Pool exhaustion policy: reject new connections at pool limit. Explicit
backpressure is preferable to silent degradation.

### Scalability summary

```
Dimension                           Status      Notes
────────────────────────────────────────────────────────────────────────
Vertical (more cores)               designed    linear, no shared state
Request rate                        designed    pool + explicit backpressure
NIC speed (1G → 100G)               designed    batch size + core tuning
Active connections < L3/64bytes     designed    hot structs cache-resident
Active connections > L3/64bytes     gap         tiering not implemented
Pool exhaustion policy              designed    reject new connections at limit
Observability (stats interface)     partial     struct defined, not implemented
```

---

## 6. Development Workflow

```
Write code (Mac)
    ↓
Build + functional test (Docker on Mac — io_uring works in Linux VM)
    ↓
Benchmark (Linux server)
```

Zig version: 0.16.0-dev.2637+6a9510c0e (master via zigup)

---

## 7. Open Source

License: MIT

Repo structure:
```
zquic/
├── src/
│   ├── root.zig
│   └── quic/
│       ├── varint.zig
│       ├── packet.zig
│       ├── frame.zig
│       ├── crypto.zig
│       ├── tls.zig
│       ├── connection.zig
│       ├── connection_id.zig
│       ├── stream.zig
│       ├── flow_control.zig
│       ├── pool.zig
│       └── congestion/
│           └── cubic.zig
├── build.zig
├── build.zig.zon
├── DESIGN.md          ← this file
└── README.md
```

---

## 8. Implementation Roadmap

### Phase 1: Core QUIC transport ✅
- QUIC packet parsing (Initial, Handshake, 1-RTT)
- Connection establishment + state machine
- TLS 1.3 handshake (RFC 9001)
- Stream multiplexing + flow control (RFC 9000 §2, §4)
- Basic congestion control (CUBIC, RFC 9438)
- Pool allocator (no malloc in hot path)
- **Milestone**: 110/110 tests passing, all core RFC 9000/9001 modules complete ✅

### Phase 2: RFC compliance — remaining transport features
- **Connection migration** (RFC 9000 §9) — client switches IP/port mid-connection;
  server validates new path and migrates without dropping streams
- **Stateless reset** (RFC 9000 §10.3) — terminate a connection without keeping
  state; token derived from CID so any server instance can issue it
- **Retry packets** (RFC 9000 §8.1) — address validation before committing state;
  server sends Retry, client echoes token in subsequent Initial
- **Version negotiation** (RFC 9000 §6) — respond to unknown QUIC versions with
  a Version Negotiation packet listing supported versions
- **0-RTT session resumption** (RFC 9001 §4.6) — send application data in the
  first packet for repeat clients; requires session ticket storage and replay
  protection (RFC 8446 §8)
- **Loss detection improvements** (RFC 9002) — Probe Timeout (PTO), persistent
  congestion detection, ACK-based loss threshold (kPacketThreshold)
- **PATH_CHALLENGE / PATH_RESPONSE frames** (RFC 9000 §19.17–19.18) — liveness
  and path validation used by migration and preferred address
- **NEW_CONNECTION_ID / RETIRE_CONNECTION_ID** (RFC 9000 §19.15–19.16) — CID
  rotation for privacy and migration support
- **Preferred address** (RFC 9000 §9.6) — server advertises a preferred address
  in transport parameters; client migrates to it after handshake
- **HANDSHAKE_DONE frame** (RFC 9000 §19.20) — server signals handshake
  confirmation to the client, unlocking 1-RTT key discard
- **Transport parameters** (RFC 9000 §18) — full encoding/decoding of all
  mandatory and optional transport parameters in TLS extensions
- **Milestone**: passes quic-interop-runner; connection migration verified
  against a reference client

### Phase 3: Performance — I/O and multi-core
- **io_uring backend** (Linux 5.1+) — SQPOLL + fixed buffer registration;
  zero syscalls in hot path; replaces blocking recvmsg/sendmsg
- **UDP GSO/GRO** — batch 16–64 QUIC packets per sendmsg (GSO TX);
  coalesce incoming packets before delivery (GRO RX, Linux 5.10+)
- **Thread-per-core + SO_REUSEPORT** — one io_uring ring + socket per core;
  no cross-core locking in hot path
- **CID-encoded thread affinity** (Novel §1) — SO_REUSEPORT_CBPF routes
  packets to the correct core socket using CID bits 0–1; no XDP needed
- **kqueue backend** (macOS/FreeBSD) — development + CI platform support
- **Milestone**: loopback benchmark on Linux; confirm linear core scaling

### Phase 4: Performance — CPU and memory
- **SIMD batch packet header processing** — @Vector(8, u64) CID lookup
- **ILP-pipelined AES-NI** — interleaved AES-GCM across packets to saturate
  the AES pipeline (~4 cycle throughput vs 4×N sequential latency)
- **Huge pages for packet buffer pool** (Novel §2) — mmap(MAP_HUGETLB)
  reduces TLB pressure at 5M+ RPS
- **Speculative CID ring lookup** (Novel §5) — recent-16 CID ring checked
  with one SIMD compare before main hash table
- **Zero-copy in-place TLS decryption** (Novel §6) — AES-GCM decrypts into
  io_uring fixed buffer; app handler receives pointer, no copy
- **Comptime congestion control** (Novel §4) — CC algorithm as comptime type
  parameter; inlined into hot path, zero dispatch overhead
- **NUMA-aware allocation** — pin threads and memory to same NUMA node
- **Milestone**: architecture review — confirm design scales to 100G without
  structural changes

### Phase 5: Measured benchmarks (requires hardware)
- Loopback benchmark on target hardware
- Publish: RPS, P50/P99/P999 latency, CPU% per core, cycles/packet
- **Milestone**: published benchmark results with full methodology

---

## 9. Novel Techniques

These have no known open-source QUIC implementation. All labeled [HYPOTHESIS]
until measured.

---

### 1. CID-encoded thread affinity via SO_REUSEPORT BPF [HYPOTHESIS]

Encode thread index in Connection ID bytes 0–1. Attach a `SO_REUSEPORT_CBPF`
program that reads those bytes and routes to the correct per-core socket.

```
Packet arrives at kernel
  → BPF program reads CID bytes 0–1 (thread index)
  → kernel routes to socket[thread_index]
  → correct core receives packet, connection state already in its L1/L2
```

Works on any Linux 4.5+ kernel. Connection state never touches the wrong
core's cache.

---

### 2. Huge pages for packet buffer pool [HYPOTHESIS]

At 5M+ RPS, TLB pressure becomes a real constraint. Each packet buffer lookup
is a virtual→physical translation. With 4KB pages:

```
5M RPS × 2 packets/request = 10M TLB lookups/sec
TLB miss → page table walk → ~10–50 cycles
TLB has ~1,000–2,000 entries → miss rate climbs at 10M lookups/sec
```

Pre-allocating packet buffers from 2MB huge pages reduces page table entries
needed by 512×. The entire pool for a core fits in a handful of TLB entries.

Available via `mmap(MAP_HUGETLB)`. No special kernel config required.

---

### 3. Adaptive connection state tiering [HYPOTHESIS]

Connection state is not uniformly hot. A server with 100K connections serves
them with highly skewed access frequency (power law).

Three-tier layout based on last-active time:

```
Hot tier:   last-active < 100ms → ConnectionHot in L2-resident pool
Warm tier:  last-active 100ms–10s → CompactConn in L3-resident pool
Cold tier:  last-active > 10s → ColdConn on heap

Packet arrives for cold connection:
  → promote to warm tier (memcpy compact state)
  → if sustained traffic → promote to hot tier
```

A server with 100K connections but only 1K active keeps only 1K hot structs
(64KB) in cache rather than 100K (6.5MB+).

---

### 4. Comptime congestion control selection [HYPOTHESIS]

CC algorithm as a comptime type parameter — inlined directly into the packet
processing loop. Zero runtime dispatch overhead:

```zig
fn processAck(comptime CC: type, conn: *Conn, ack: AckFrame) void {
    CC.onAck(conn, ack);  // inlined — no vtable, no branch
}

const server = Server(Cubic);  // or Server(Bbr2), Server(Copa)
```

Different binaries for different workloads — each optimally compiled.

---

### 5. Speculative connection lookup [HYPOTHESIS]

Maintain a recent-16 CID ring per core. Check with SIMD before the main hash
table lookup:

```zig
const recent = @Vector(16, u64){ ring[0], ring[1], ... ring[15] };
const hit = recent == @splat(incoming_cid);
if (@reduce(.Or, hit)) {
    return recent_conns[@ctz(hit)];  // state likely still in L1
}
// Cold path: full hash table lookup
```

For keep-alive workloads, hit rate approaches 100% — hash table rarely needed.

---

### 6. Zero-copy in-place TLS decryption [HYPOTHESIS]

AES-GCM supports in-place decryption. With io_uring fixed buffers:

```
Kernel DMA → pre-registered buffer (zero copy from NIC)
AES-GCM decrypts in-place (ciphertext → plaintext, same memory)
Application handler receives pointer into that buffer (zero copy to app)
```

Packet payload never copied. Buffer returned to pool after handler returns.
Requires explicit API contract: handler must not hold the pointer after return.

---

**Investigation priority**: #2 (huge pages, low risk), #1 (CID BPF, moderate),
#5 (CID ring, low risk), #3 (state tiering, high complexity),
#4 (comptime CC, Zig-specific), #6 (zero-copy TLS, highest complexity).
