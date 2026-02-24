# zquic — Design Document

> A native Zig QUIC implementation. Zero dependencies. Single binary.

---

## 1. Motivation

Modern tools (to be filled in with specific example) are too slow and too
resource-heavy for high-throughput infrastructure. The goal is to challenge the
status quo — not by being marginally faster, but by being fundamentally
different in architecture.

Precedents show this is possible:
- nginx replaced Apache by rethinking the concurrency model
- Redis replaced SQL caches by eliminating layers
- ScyllaDB replaced Cassandra by rewriting in C++ with thread-per-core
- TigerBeetle replaced PostgreSQL for accounting by going deterministic and
  eliminating dynamic allocation

The pattern: pick one specific thing existing tools handle poorly, go deep on
it, make it undeniably better.

Our target: **the highest possible QUIC RPS per CPU cycle, on commodity
hardware, as a single static binary.**


---

## 2. Why QUIC over UDP

### The TCP PPS problem

Linux kernel TCP processing costs ~2,000–3,000 cycles per packet:
- sk_buff allocation (heap alloc, ~500–800 cycles)
- TCP stack traversal
- Kernel → userspace copy

This caps throughput at ~1–1.5M PPS per core regardless of NIC speed.
(Consistent with ~3 GHz: 3B / 2,000 = 1.5M PPS, 3B / 3,000 = 1M PPS.)

With 4 cores + SO_REUSEPORT: ~6M PPS ceiling.

### UDP enables a higher-efficiency path

Raw kernel UDP throughput is similar to TCP: **~1–1.5M PPS per core** in
practice (Cloudflare measured 1.4M PPS per core at 100% CPU; LWN.net cites
1–2M for kernel forwarding). The difference is what UDP *permits*:

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
hard ~6M ceiling — roughly a **2–3× advantage** from the optimization headroom
UDP enables, not from raw kernel UDP speed.

### QUIC + io_uring eliminates the kernel bottleneck

QUIC runs over UDP and reimplements reliability, ordering, flow control, and
congestion control in userspace, where we control the implementation and can
optimize for our specific workload.

Kernel UDP alone costs similar cycles to kernel TCP (~2,000 cycles/packet
inferred from Cloudflare's 1.4M PPS at 100% CPU). The gain comes from
combining QUIC with **io_uring SQPOLL**, which eliminates kernel UDP overhead
entirely. With kernel cost removed, only the QUIC userspace work remains:

- Packet number encryption: ~20–50 cycles
- Header protection: ~20–50 cycles
- AES-GCM (AES-NI hardware): ~50–100 cycles
- ACK processing: ~50 cycles
- Stream multiplexing: ~30 cycles
- Total: ~170–280 cycles

vs kernel TCP: ~2,000–3,000 cycles (cannot be bypassed).
QUIC + io_uring is 7–18× cheaper per packet than kernel TCP
(170–280 cycles vs 2,000–3,000 cycles). TCP has no equivalent escape hatch —
its reliability stack lives in the kernel and cannot be moved.

### Where QUIC is not faster than TCP

QUIC moves reliability into userspace, which adds CPU cycles per byte compared
to kernel TCP. On stable, low-latency links with large transfers (2GB+ files,
streaming), kernel TCP's zero-copy sendfile + offload can outperform QUIC on
raw throughput.

QUIC's advantages appear where TCP's kernel stack is the constraint:
- High packet loss (QUIC's per-stream loss recovery vs TCP's head-of-line blocking)
- Many short-lived connections (0-RTT eliminates handshake cost)
- High connection count (no kernel connection state per socket)
- High packet rate workloads (io_uring bypasses kernel overhead)

zquic targets the high-RPS, small-request use case (APIs, KV lookups, microservices)
— where these QUIC characteristics are advantages, not the large-file transfer case.

### QUIC advantages over TCP

- **0-RTT**: Repeat clients send data in the first packet. No handshake cost.
- **Multiplexing**: Multiple streams per connection, no head-of-line blocking.
- **Built-in TLS 1.3**: Mandatory. Packet crypto via AES-128-GCM + AES-NI — ~3–5 GB/s per core.
- **Connection migration**: Clients can switch networks without reconnecting.
- **No TCP baggage**: No Nagle algorithm, no TIME_WAIT, no SYN flooding.

---

## 3. Hardware Reality Check

### $20/month VPS constraints

Research conducted on actual 2025-2026 VPS pricing and benchmarks:

| Provider        | vCPU | RAM  | NIC (actual)        | Price   |
|-----------------|------|------|---------------------|---------|
| DigitalOcean    | 2    | 4 GB | 2 Gbps (hard cap)   | $18/mo  |
| Linode          | 2    | 4 GB | 4 Gbps (port speed) | $24/mo  |

### Theoretical RPS ceilings

All numbers below are **theoretical maximums derived from first principles**,
not measured benchmarks. Calculations are shown so they can be independently
verified or challenged.

#### Wire cost model

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

#### NIC ceiling formula

```
NIC ceiling (RPS) = NIC bandwidth (bytes/sec) / round-trip bytes

  1 Gbps  = 125,000,000 / 168  =   ~744K RPS
  10 Gbps = 1,250,000,000 / 168 =  ~7.4M RPS
  25 Gbps = 3,125,000,000 / 168 =  ~18.6M RPS
  100 Gbps= 12,500,000,000 / 168 = ~74M  RPS
```

#### CPU ceiling formula

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

#### PPS ceiling formula

```
io_uring SQPOLL + GSO (16 packets/call): ~8–10M effective PPS per core
  4-core:  ~32–40M PPS
  16-core: ~128–160M PPS
```

#### Full ceiling table by NIC speed

```
NIC     NIC ceiling  CPU (4c)  CPU (16c)  Min cores   Binding (≥ min cores)
──────────────────────────────────────────────────────────────────────────
1G      ~744K        ~26M      ~104M      1            NIC
10G     ~7.4M        ~26M      ~104M      3            NIC
25G     ~18.6M       ~26M      ~104M      6            NIC
100G    ~74M         ~26M      ~104M      16           NIC (with 16+ cores)
```

At 100G with 4 cores: CPU (~23.5M) is binding, NIC not reached.
At 100G with 16 cores: NIC (~65M) is binding — that is the design target.

#### 100G hardware requirements

To reach the NIC ceiling at 100G, the following is needed:

```
Crypto load at 100G:
  12.5 GB/s to encrypt/decrypt
  AES-NI throughput per core: ~3–5 GB/s
  Cores needed for crypto: ~3–5 cores

Processing load at 100G for ~65M RPS:
  74M × 460 cycles = 34.04B cycles/sec
  At 3 GHz: ~11 cores needed

Total: ~16 cores to approach 100G NIC ceiling
```

Hardware with 100G NICs:

| Hardware             | NIC    | Cores | Approx cost  |
|----------------------|--------|-------|--------------|
| AWS c5n.18xlarge     | 100G   | 72    | ~$3.50/hr    |
| AWS c5n.metal        | 100G   | 96    | ~$4.80/hr    |
| Equinix c3.medium    | 2×25G  | 24    | ~$1.50/hr    |

These are future benchmark targets.

**Design target: architecture scales to 100G NIC + 16 cores without changes.**

### Why not DPDK?

DPDK requires bare metal hardware with dedicated NICs (Intel X710, Mellanox
ConnectX). Not available on shared VPS. AF_XDP is available but requires
implementing a full TCP stack in userspace — months of work for uncertain gain.
io_uring + UDP + GSO is the right tradeoff for VPS-class hardware, and the
same design scales to bare metal without changes.

---

## 4. The Real Problems (NIC Is Not The Only One)

Saturating a 10G NIC — 99.7% utilization — is achievable. You cannot exceed a hardware ceiling.

**Hitting the NIC ceiling is not the end goal.**

The NIC ceiling being the constraint only means the transport layer bottleneck
has been addressed. It says nothing about everything above it. The unsolved
problems are:

### 1. CPU efficiency

Two servers, both saturating a 10G NIC at 6M RPS:

```
Server A (poorly optimized): 6M RPS,  95% CPU  →  5% left for app logic
Server B (zquic):           6M RPS,  40% CPU  → 60% left for app logic
```

Same throughput. Server B handles 12× more application logic at the same RPS,
or runs at the same load on half the hardware. At Netflix / Uber / AWS scale,
this is millions of dollars in server cost annually.

### 2. Tail latency (P99, P999)

Throughput benchmarks report averages. Production systems are judged by tail
latency. Two servers at 6M RPS average:

```
Server A:  P50=50μs  P99=2ms    P999=50ms
Server B:  P50=50μs  P99=80μs   P999=200μs
```

Same throughput. Server B's P999 is 250× better. For real-time APIs,
financial systems, and interactive applications, P999 is often the SLA metric.

Causes of tail latency in existing implementations:
- `malloc` in hot path → non-deterministic allocation time
- Kernel scheduler interruptions
- False sharing between cores → cache line bouncing
- Dynamic dispatch (vtable, function pointers) → branch misprediction

zquic eliminates each: pool allocator, CPU pinning, explicit cache-line
layout, comptime dispatch.

### 3. Behaviour under overload

What happens when you send 7M RPS to a server with a 6M RPS ceiling?

```
Bad design:  queue builds → latency spikes to seconds → OOM → crash
Good design: graceful backpressure → stable latency → controlled shedding
```

This is entirely an implementation concern, not a NIC concern.

### 4. Concurrent connection scaling

Most benchmarks test 100–1,000 connections at maximum throughput. Production
servers handle 10,000–100,000 concurrent connections. Connection state that
fits in L3 cache (8–32 MB) at 1K connections spills to RAM at 100K connections.

```
1K connections  × 1KB state = 1MB   → fits in L3 cache
10K connections × 1KB state = 10MB  → fits in L3 cache (just)
100K connections× 1KB state = 100MB → spills to RAM → +200 cycles/packet

zquic: connection state structs designed to be cache-line efficient,
hot fields packed together, cold fields separated.
```

### Summary: what zquic targets

```
NIC saturation:   same ceiling as existing libraries
CPU efficiency:   comptime dispatch, zero-alloc hot path, thread-per-core
Tail latency:     pool allocator, CPU pinning, cache-line layout
Deployment:       single static binary, zero runtime dependencies
```

---

## 5. Architecture

### Layer separation

zquic is the QUIC transport layer only. Application framing layers (if needed) live in separate repositories that depend on zquic.

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

The I/O layer is an interface. The hot path never calls I/O directly — it
writes to and reads from an abstract I/O backend. This allows extreme
optimization on Linux without breaking portability on other platforms.

```
┌──────────────────────────────────────────────┐
│              QUIC hot path                   │
│   (packet encode/decode, crypto, streams)    │
└──────────────────┬───────────────────────────┘
                   │ IoBackend interface
        ┌──────────┴──────────────────┐
        │                             │
   io_uring (Linux 5.1+)        epoll (Linux)
   SQPOLL + fixed buffers        AsyncUDPSocket
   zero syscalls in hot path     standard approach
        │                             │
   kqueue (macOS/FreeBSD)        (future)
   development + testing         AF_XDP / DPDK
```

Default backend per platform:
- Linux (production): io_uring SQPOLL + fixed buffer registration
- Linux (fallback / restricted kernels): epoll + recvmmsg/sendmmsg
- macOS/FreeBSD (development): kqueue

io_uring SQPOLL specifics:
```
Kernel polls SQ ring → zero syscalls in hot path
Fixed buffer registration → kernel DMA-writes into our pre-registered pool
GSO → batch 16–64 QUIC packets per sendmsg at 100G scale
GRO → batch receive, fewer kernel events
```

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

AES-128-GCM vs AES-256-GCM:

```
AES-128-GCM:  10 rounds, ~3–5 GB/s per core (AES-NI)
AES-256-GCM:  14 rounds, ~2–3 GB/s per core (AES-NI)  — ~30% slower
```

AES-128 is chosen. Security: 2^128 operations to break — no known practical
attack exists or is foreseeable on classical hardware. AES-256's extra cost
buys nothing for non-quantum threat models. Post-quantum vulnerability in
QUIC lies in key exchange (ECDH), not the symmetric cipher.

Regulatory/compliance deployments requiring AES-256 are out of scope.

#### Crypto layer split

TLS 1.3 handshake and packet encryption are separated:

```
TLS 1.3 handshake (once per connection)
  → external TLS library (BoringSSL / OpenSSL / wolfSSL via callbacks)
  → certificate validation, ECDH key exchange, session tickets, 0-RTT
  → not performance-critical — happens once, not per packet

Packet crypto (every packet — the hot path)
  → std.crypto (Zig standard library)
  → AES-128-GCM: encryption, decryption, authentication tag
  → Header protection: AES-128-ECB (packet number encryption)
  → Key derivation: HKDF-SHA256
  → We own the buffer lifecycle → enables in-place decryption, ILP pipelining
```

The interface between them is defined by RFC 9001: the TLS library exports
traffic secrets via HKDF, zquic derives packet protection keys and handles
all per-packet crypto internally.

Using `std.crypto` for packet crypto keeps the binary dependency-free while
keeping the complex handshake logic in a battle-tested library.

### Performance techniques — priority order

Six techniques push throughput toward the theoretical maximum. Ordered by
impact — the first two are hardware-level and dwarf the rest if neglected.

---

#### 1. Cache locality [hardware-level]

A cache miss costs ~200 cycles — erasing every other optimization below.
Data must be in L1/L2 cache before the CPU reaches the instruction that needs
it. This governs every struct layout decision in zquic.

```
L1 cache hit:   ~4 cycles
L2 cache hit:   ~12 cycles
L3 cache hit:   ~40 cycles
RAM access:     ~200 cycles  ← one miss costs more than an entire request
```

Applied in zquic:
- Connection state split into hot struct (seq numbers, crypto ctx, stream state)
  and cold struct (peer address, TLS cert, stats) — accessed on different paths
- Hot struct fits in one or two cache lines (64 bytes each)
- Packet buffer pool laid out sequentially — prefetcher can predict next access
- Thread-per-core means each core's working set stays in its own L1/L2

```zig
const ConnectionHot = struct {
    rx_seq:      u64,   // touched every packet
    tx_seq:      u64,   // touched every packet
    crypto_ctx:  AesCtx,// touched every packet
    stream_state:u32,   // touched every packet
    _pad:        [16]u8,// fill to 64-byte cache line
};  // exactly 64 bytes — one cache line

const ConnectionCold = struct {
    peer_addr:   std.net.Address, // touched on handshake only
    tls_cert:    []u8,            // touched on handshake only
    stats:       ConnStats,       // touched on close only
};
```

---

#### 2. SIMD — Single Instruction, Multiple Data [hardware-level]

One CPU instruction operates on N values simultaneously. Multiplies throughput
without adding cores or clock cycles.

```
Scalar AES-GCM:   1 block (16 bytes) per instruction
AES-NI pipelined: 8 blocks (128 bytes) per instruction cycle (throughput)

Scalar header scan:   1 packet header per loop iteration
@Vector(8, u64):      8 packet headers per iteration
```

Applied in zquic:
- AES-NI for TLS encryption — mandatory for QUIC, hardware-accelerated
- `@Vector` for batch packet header processing (connection ID lookup,
  packet number decode, header protection removal across multiple packets)
- SIMD batch connection ID lookup across incoming packets

```zig
// Process 8 connection IDs simultaneously to find matching connections
const incoming_ids = @Vector(8, u64){ p0.id, p1.id, p2.id, p3.id,
                                      p4.id, p5.id, p6.id, p7.id };
const matches = incoming_ids == @splat(target_id);
```

---

#### 3. io_uring SQPOLL — zero syscalls [software-level]

Kernel polls the submission queue in a kernel thread. Userspace writes to the
ring and the kernel picks it up — no `read()`, no `write()`, no `sendmsg()`
syscall in the hot path.

```
Traditional:   recv() syscall → kernel → copy → userspace   (~1,000 cycles)
io_uring SQPOLL: write descriptor to ring → kernel thread sees it (~50 cycles)
```

Combined with fixed buffer registration: packet data never copied. The kernel
DMA-writes directly into our pre-registered buffer pool.

GSO (Generic Segmentation Offload) batches 32–64 QUIC packets per `sendmsg`
at 100G scale, amortizing the per-call overhead across many packets.

---

#### 4. Thread-per-core + SO_REUSEPORT — zero contention [software-level]

Each core owns its socket, io_uring ring, connection subset, and packet pool.
No mutexes. No atomics on the hot path. No cache line bouncing between cores.

```
Core 0: socket 0, ring 0, connections [0..N],   pool 0
Core 1: socket 1, ring 1, connections [N..2N],  pool 1
Core 2: socket 2, ring 2, connections [2N..3N], pool 2
Core 3: socket 3, ring 3, connections [3N..4N], pool 3
```

Cross-core communication (rare, e.g. connection migration) uses SPSC
(single-producer single-consumer) lock-free ring buffers — no mutex, one
atomic load + one atomic store per message.

---

#### 5. Zero allocation in hot path — zero jitter [software-level]

General-purpose `malloc` is non-deterministic: it takes locks, searches free
lists, occasionally calls `mmap`. Under high RPS this creates latency spikes
that show up as P99/P999 outliers.

Pre-allocate everything at startup. Use a pool allocator in the hot path:

```
Startup:  allocate N connection slots, M packet buffers, K TLS sessions
Hot path: pool.acquire() → O(1), deterministic, no syscall
          pool.release() → O(1), deterministic, no syscall
```

Zig enforces this explicitly — the allocator is passed as a parameter.
The hot path receives a `PoolAllocator`, not a `GeneralPurposeAllocator`.
A wrong allocator is a compile error, not a runtime surprise.

---

#### 6. Comptime dispatch — zero indirection [software-level]

All protocol dispatch, routing, and handler lookup resolved at compile time.
No vtables, no function pointers, no runtime branching on type.

```zig
// Packet type dispatch — resolved at compile time
const dispatch = comptime buildDispatch(.{
    .initial   = handleInitial,
    .handshake = handleHandshake,
    .one_rtt   = handleOneRtt,
});

// Frame type dispatch — resolved at compile time
const frame_dispatch = comptime buildDispatch(.{
    .stream  = handleStream,
    .ack     = handleAck,
    .crypto  = handleCrypto,
});
```

No indirect jumps. No branch misprediction on dispatch. The CPU's branch
predictor sees a direct call it has already cached.

---

---

#### 3. RSS — Receive Side Scaling [hardware-level: NIC]

SO_REUSEPORT (our baseline) has the **kernel** hash packets to cores.
RSS moves that decision to the **NIC ASIC** — before the kernel is involved.

```
SO_REUSEPORT:
  NIC → kernel → software hash → dispatch to core 0/1/2/3

RSS:
  NIC ASIC hashes 5-tuple (src IP, dst IP, src port, dst port, proto)
  → DMA directly into per-core RX queue
  Kernel never makes the distribution decision
```

Packets from the same QUIC connection always arrive on the same CPU core.
Connection state stays in that core's L1/L2 cache permanently — never
evicted by another core touching it. RSS is the hardware implementation of
thread-per-core affinity.

Used together: RSS pins connections at the NIC, SO_REUSEPORT gives each
core its own socket. Both reinforce the same guarantee from different layers.

---

#### 4. NIC Checksum Offload [hardware-level: NIC]

UDP and IP checksums computed by NIC ASIC during transmission and reception.
Zero CPU cycles involved.

```
Software checksum:   ~30–50 cycles per packet
NIC checksum offload: 0 cycles (happens in NIC pipeline, overlapped with DMA)

At 65M RPS (100G target):
  65,000,000 × 40 cycles = 2.6B cycles/sec saved
  ≈ one full CPU core freed purely from checksum elimination
```

Enabled via socket option `SO_NO_CHECK` (TX) and kernel RX checksum offload.
All modern NICs support this and enable it by default.

---

#### 5. GRO — Generic Receive Offload [hardware-level: NIC]

Reverse of GSO. NIC (or kernel NIC driver) coalesces multiple incoming UDP
packets into a single large buffer before handing to the kernel. Fewer
kernel events, fewer io_uring completions, fewer CPU wake-ups.

```
Without GRO:  65M incoming packets → 65M kernel events → 65M ring entries
With GRO:     65M incoming packets → ~4M coalesced events → 4M ring entries
              16× fewer events to process
```

UDP GRO available since Linux 5.10. Enabled via `UDP_GRO` socket option.
Works in concert with GSO on the send path — GSO batches sends, GRO batches
receives.

---

#### 6. Explicit Prefetch — hiding random access latency [hw-guided]

The hardware prefetcher handles sequential access automatically. Connection
state lookup by connection ID is random access — the prefetcher cannot predict
it. We fix this with explicit prefetch instructions issued ahead of need:

```zig
// Packet arrives. We parse the connection ID from the header first.
// Issue prefetch NOW — 200 cycles before we'll actually use the state.
const conn_id = parseConnectionId(raw_header);
@prefetch(&conn_table[conn_id].hot, .{ .rw = .read, .locality = 3 });

// ~200 cycles of other work: finish header parse, remove header protection,
// validate packet number — all while hardware fetches connection state.

// By here, conn_table[conn_id].hot is in L1. Zero stall.
const conn = &conn_table[conn_id].hot;
processPacket(packet, conn);
```

Converts a ~200 cycle RAM stall into zero visible latency by overlapping the
memory fetch with other useful work.

---

#### 7. ILP — Instruction-Level Parallelism [hardware-level: CPU]

Out-of-order CPUs execute independent instructions simultaneously. AES-NI
has ~4 cycle latency but ~1 cycle throughput when pipelined. Processing
packets in interleaved batches saturates the AES pipeline:

```zig
// Bad: sequential — each decrypt blocks on the previous
const r0 = aesDecrypt(packet[0]);  // 4 cycle latency
const r1 = aesDecrypt(packet[1]);  // waits for r0 to finish
const r2 = aesDecrypt(packet[2]);  // waits for r1 to finish

// Good: interleaved — CPU pipelines all three simultaneously
const d0 = aesDecryptStart(packet[0]);
const d1 = aesDecryptStart(packet[1]);  // CPU issues while d0 in-flight
const d2 = aesDecryptStart(packet[2]);  // CPU issues while d0, d1 in-flight
// All three complete in ~4 cycles total, not 4×3=12 cycles
const r0 = aesDecryptFinish(d0);
const r1 = aesDecryptFinish(d1);
const r2 = aesDecryptFinish(d2);
```

At batch size 8: effectively free crypto — latency hidden inside the pipeline.

---

#### 8. io_uring SQPOLL — zero syscalls [software-level]

Kernel polls the submission queue in a dedicated kernel thread. Zero syscalls
in the hot path. Fixed buffer registration eliminates kernel→userspace copies.
GSO batches 32–64 packets per sendmsg at 100G scale.

---

#### 9. Thread-per-core + SO_REUSEPORT — zero contention [software-level]

Each core owns its socket, ring, connection subset, and memory pool. No locks
on the hot path. Cross-core communication via SPSC lock-free ring buffers only.

---

#### 10. Zero allocation in hot path — zero jitter [software-level]

Pre-allocate everything at startup. Pool allocator only in hot path: O(1),
deterministic, no syscall. Zig enforces this — allocator passed as parameter,
wrong allocator type is a compile error.

---

#### 11. Comptime dispatch — zero indirection [software-level]

Protocol dispatch, routing, handler lookup all resolved at compile time.
No vtables, no function pointers, no runtime branching on type.

---

#### Summary

```
Technique                   Layer            Eliminates
─────────────────────────────────────────────────────────────────────────────
1.  Cache locality           hardware (CPU)   cache miss stalls (~200c each)
2.  SIMD + AES-NI            hardware (CPU)   scalar throughput bottleneck
3.  RSS                      hardware (NIC)   kernel distribution overhead
4.  NIC checksum offload     hardware (NIC)   ~40 cycles/packet, frees a core
5.  GRO                      hardware (NIC)   16× fewer kernel receive events
6.  Explicit prefetch        hw-guided        random access stalls
7.  ILP (pipeline AES)       hardware (CPU)   crypto latency
────────────────────────────────────────────────────────────────────────────
8.  io_uring SQPOLL          software         syscall overhead (~1K cycles)
9.  Thread-per-core          software         lock contention, false sharing
10. Zero allocation          software         malloc jitter, P99/P999 spikes
11. Comptime dispatch        software         vtable, branch mispredict
─────────────────────────────────────────────────────────────────────────────

Techniques 1–7 move work off the general-purpose CPU entirely or exploit
dedicated silicon. Techniques 8–11 minimize overhead of work the CPU must do.
Both layers are required. Neglecting either wastes the other.
```

---

## 6. Dependency Management (Zig)

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

## 7. Benchmark Targets

### Claim tiers

All performance claims are labeled by evidence tier:

```
[THEORETICAL] — derived from wire size + CPU cycle model, no hardware needed
               reproducible by anyone with a calculator

[MODELED]     — derived from instruction counts on real code
               requires profiling to validate

[MEASURED]    — run on specific hardware with specific tooling
               the gold standard, deferred until hardware available
```

### Theoretical performance envelope [THEORETICAL]

```
Hardware              NIC     Cores   Theoretical RPS ceiling
──────────────────────────────────────────────────────────────
Any server            10G     4       ~7.4M RPS  (NIC binding)
Any server            25G     8       ~18.6M RPS (NIC binding)
Any server            100G    16      ~74M  RPS  (NIC binding)

NIC is binding at sufficient core count.
At 4 cores + 100G: CPU (~23.5M) is binding, not NIC.
Crypto requires ~1 dedicated core per 5 Gbps throughput (AES-NI).
```

### Theoretical performance envelope [THEORETICAL]

Expected RPS ceiling on loopback benchmark (4-core, 3GHz):

| Constraint       | Ceiling      | Notes                               |
|------------------|--------------|-------------------------------------|
| CPU (4 cores)    | ~26M RPS     | 460 cycles/request, see model above |
| 10G NIC          | ~7.4M RPS    | NIC binding at sufficient cores     |
| 100G NIC         | ~74M RPS     | NIC binding at 16+ cores            |

### Benchmark methodology (when hardware is available)

- **Tool**: wrk2 (constant-rate load generator, measures latency correctly)
- **Endpoint**: in-memory key-value GET — realistic, not hello world
- **Metrics**: RPS, P50, P99, P999 latency, CPU % per core
- **Connections**: 100, 1K, 10K (test scaling)
- **No pipelining** for primary numbers — honest real-world comparison
- **Loopback** (client + server same machine) for reproducibility
- Pipelining results published separately, clearly labeled
- CPU measurement: `perf stat` during benchmark run

### Why loopback, not two machines

Shared VPS NICs introduce noise — benchmark results vary by 40% depending
on co-tenancy. Loopback removes the NIC variable entirely and measures what
matters: server processing efficiency. This is standard practice (TechEmpower,
wrk2 docs, Bun benchmarks all use loopback or dedicated switches).

---

## 8. Scalability Analysis

### What scales well

**Vertical scaling (more cores, same machine)**
Thread-per-core + SO_REUSEPORT is linear by construction. Each core is fully
independent — no locks, no shared queues in the hot path. Adding cores adds
proportional capacity. Scaling from 4 to 16 to 64 cores requires no
architectural changes.

**Request rate**
Pool allocator + explicit backpressure means overload is handled predictably.
When the pool is exhausted, new connections are rejected cleanly. No OOM,
no latency collapse, no unbounded queue growth.

**NIC speed (1G → 100G)**
The ceiling table in section 3 shows the architecture scales from 1G to 100G
by tuning batch sizes and core count. No structural changes needed.

---

### Known gaps

#### Connection count beyond the pre-allocated pool

The 100K figure is a cache performance cliff, not a hard limit. Beyond it,
hot struct lookups miss L3 cache and go to RAM (~200 cycles vs ~40 cycles).
The server keeps running — performance degrades gracefully, not catastrophically.

The distinction between total and active connections matters:

```
Total connections:  all connections the server is tracking
Active connections: connections receiving traffic right now

1M total, 5K active → only 5K hot structs need to be cache-resident (320KB)
                    → 995K cold connections sit in RAM untouched
                    → no cache pressure
```

At NIC-ceiling RPS, active connection count is bounded by per-connection
request rate. At 6.5M RPS with 1000 req/sec per connection: ~6.5K active
connections — well within L2 cache on any modern CPU. The 100K threshold
only applies when 100K connections are simultaneously active, which requires
a very specific workload (many low-frequency connections).

Pool exhaustion policy: reject new connections at pool limit.
Explicit backpressure is preferable to silent degradation. Spilling to heap
breaks the zero-alloc guarantee and introduces unpredictable latency.

The adaptive state tiering hypothesis (section 15, novel technique #3)
addresses the >100K active connection case but is not yet designed in detail.

#### Horizontal scaling (multiple machines)
The current design is entirely single-machine. Stateless horizontal scaling
(independent connections per machine, load balancer in front) works without
changes. Stateful scenarios have gaps:

**Session ticket sharing**: QUIC 0-RTT resumption requires the server to
recognise a session ticket from a previous connection. If a client connects
to server B with a ticket issued by server A, server B cannot resume it
unless tickets are shared across machines. No design for this yet.

**CID-aware load balancing**: Layer-4 load balancers that route by IP+port
will misroute packets when a QUIC client migrates networks (the connection
CID stays the same but the source IP changes). CID-based routing at the
CID-aware load balancing at the load balancer level is needed for
multi-machine deployments. Not designed.

#### Zero-downtime restart
Restarting zquic drops all in-flight QUIC connections. For any production
deployment with real traffic, restartless deploys are a hard requirement.
Not designed in zquic yet.

#### Observability and load balancer signalling

The load balancer needs a signal to know when a machine is overloaded with
active connections. Three approaches, each with different tradeoffs:

**Pull: health endpoint**
zquic exposes a stats struct. The embedding application serves it:
```
GET /.well-known/health
→ { "active_conns": 8420, "pool_utilisation": 84%, "p99_us": 120 }
```
Simple, works with any load balancer. Lag between polls means overload can
spike and recover between checks.

**Push: connection refusal**
When pool utilisation crosses a threshold (e.g. 80%), zquic stops accepting
new connections — sends QUIC `CONNECTION_REFUSED`. The load balancer observes
failures and stops routing to that instance. Reactive but requires no polling.

**Passive: load balancer observes latency**
Smart load balancers (Envoy, HAProxy) measure backend response latency
passively. When P99 spikes, traffic is reduced. No changes needed in zquic.

zquic's responsibility is exposing the raw signals as a stats interface:
```zig
pub const Stats = struct {
    active_conns:     u32,  // currently tracked connections
    pool_utilisation: u8,   // 0–100%
    rx_pps:           u64,  // packets/sec received
    tx_pps:           u64,  // packets/sec sent
    // per-core versions available via Stats.perCore(core_id)
};
```

What to do with those signals — health endpoint, connection refusal
threshold, Prometheus scrape — is the embedding application's concern,
not the transport's. The transport exposes data. The operator decides policy.

#### Cross-core connection migration
When a mobile client switches networks, the new 5-tuple may hash to a
different core. The SPSC ring buffer handles the handoff, but if migration
frequency is high (mobile-heavy workloads), cross-core coordination becomes
measurable overhead.

---

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
Horizontal (multi-machine)          out of scope transport layer concern only
Zero-downtime restart               out of scope server layer concern
Session ticket sharing              out of scope deployment concern
CID-aware load balancing            out of scope load balancer concern
```

Transport-layer gaps (zquic owns these):
- Active connection tiering above cache threshold
- Pool exhaustion policy (reject is the right answer)
- Stats interface implementation

Everything else is the embedding application's or operator's concern.

---

## 9. Development Workflow

```
Write code (Mac)
    ↓
Build + functional test (Docker on Mac — io_uring works in Linux VM)
    ↓
Benchmark (Linux server)
```

Zig version: 0.16.0-dev.2637+6a9510c0e (master via zigup)

---

## 10. Open Source

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

## 11. Implementation Roadmap

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
  state; uses a token derived from the CID so any server instance can issue it
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
- **Milestone**: passes RFC 9000 compliance test suite (quic-interop-runner);
  connection migration verified against a reference client

### Phase 3: Performance — I/O and multi-core
- **io_uring backend** (Linux 5.1+) — SQPOLL + fixed buffer registration;
  zero syscalls in hot path; replaces blocking recvmsg/sendmsg
- **UDP GSO/GRO** — batch 16–64 QUIC packets per sendmsg (GSO TX);
  coalesce incoming packets before delivery (GRO RX, Linux 5.10+)
- **Thread-per-core + SO_REUSEPORT** — one io_uring ring + socket per core;
  no cross-core locking in hot path
- **CID-encoded thread affinity** (Novel technique §1) — SO_REUSEPORT_CBPF
  routes packets to the correct core socket using CID bits 0–1; no XDP needed
- **kqueue backend** (macOS/FreeBSD) — development + CI platform support
- **Milestone**: loopback benchmark on Linux; compare recvmsg vs io_uring
  baseline; confirm linear core scaling

### Phase 4: Performance — CPU and memory
- **SIMD batch packet header processing** — @Vector(8, u64) CID lookup;
  8 connection IDs compared per instruction
- **ILP-pipelined AES-NI** — interleaved AES-GCM across packets to saturate
  the AES pipeline (~4 cycle throughput vs 4×N sequential latency)
- **Huge pages for packet buffer pool** (Novel technique §2) — mmap(MAP_HUGETLB)
  reduces TLB pressure at 5M+ RPS
- **Speculative CID ring lookup** (Novel technique §5) — recent-16 CID ring
  checked with one SIMD compare before main hash table
- **Zero-copy in-place TLS decryption** (Novel technique §6) — AES-GCM
  decrypts into io_uring fixed buffer; app handler receives pointer, no copy
- **Comptime congestion control** (Novel technique §4) — CC algorithm as
  comptime type parameter; inlined into hot path, zero dispatch overhead
- **NUMA-aware allocation** — pin threads and memory to same NUMA node
- **Milestone**: architecture review — confirm design scales to 100G without
  structural changes (theoretical analysis + cycle model)

### Phase 5: Measured benchmarks (requires hardware)
- Loopback benchmark on target hardware
- Publish: RPS, P50/P99/P999 latency, CPU% per core, cycles/packet vs theoretical model
- Publish: RPS, P50/P99/P999 latency, CPU% per core, cycles/packet
- **Milestone**: published benchmark results with full methodology

---

## 12. Novel Techniques (Unexplored in Open QUIC Implementations)

The techniques below have no known open-source QUIC implementation.
This section records ideas with no known open-source implementation — research
territory. All labeled [HYPOTHESIS] until measured.

---

### 1. CID-encoded thread affinity via SO_REUSEPORT BPF [HYPOTHESIS]

Thread affinity can be encoded in the Connection ID and enforced without XDP using
`SO_REUSEPORT_CBPF`: a small BPF program attached directly to the socket
that extracts bits from the Connection ID and routes to the correct per-core
socket.

```
Packet arrives at kernel
  → BPF program reads CID bytes 0–1 (encode thread index)
  → kernel routes to socket[thread_index]
  → correct core receives packet, connection state already in its L1/L2
```

No Katran. No XDP infrastructure. Works on any Linux 4.5+ kernel.
Connection state never touches the wrong core's cache.

---

### 2. Huge pages for packet buffer pool [HYPOTHESIS]

At 5M+ RPS, TLB pressure becomes a real constraint. Each packet buffer
lookup is a virtual→physical translation. With 4KB pages:

```
5M RPS × 2 packets/request = 10M TLB lookups/sec
TLB miss → page table walk → ~10–50 cycles
TLB has ~1,000–2,000 entries → at 10M lookups/sec with diverse addresses,
miss rate climbs
```

Pre-allocating packet buffers from 2MB huge pages reduces the page table
entries needed by 512×. The entire packet buffer pool for a core may fit
in a handful of TLB entries.

Available via `mmap(MAP_HUGETLB)` or `memfd_create` with huge page backing.
No special kernel config required on modern Linux.

---

### 3. Adaptive connection state tiering [HYPOTHESIS]

Connection state is not uniformly hot. A server with 100K connections
serves them with highly skewed access frequency (power law). Most state
sits idle.

Three-tier layout:

```
Hot tier:   last-active < 100ms → ConnectionHot in pre-allocated L2-resident pool
Warm tier:  last-active 100ms–10s → CompactConn in L3-resident pool
Cold tier:  last-active > 10s → ColdConn swapped to normal heap

Packet arrives for cold connection:
  → promote to warm tier (memcpy compact state)
  → if sustained traffic → promote to hot tier
```

Hot tier stays small enough to fit entirely in L2 cache across all cores.
A server with 100K connections but only 1K active at any instant keeps only
1K hot structs (64KB) in cache rather than 100K (6.5MB+).

---

### 4. Comptime congestion control selection [HYPOTHESIS]

Existing libraries select congestion control at runtime (function pointers,
vtable, switch statement). In Zig, the CC algorithm can be a comptime
parameter — the binary is compiled with one CC algorithm inlined directly
into the packet processing loop.

```zig
fn processAck(comptime CC: type, conn: *Conn, ack: AckFrame) void {
    // CC.onAck is inlined — no vtable, no branch, no function pointer
    CC.onAck(conn, ack);
}

// Build with Copa for video workloads:
const server = Server(Copa);

// Build with BBR2 for bulk transfer:
const server = Server(Bbr2);
```

Different binaries for different workloads — each optimally compiled. The
CC logic becomes dead-code-eliminated and inlined into the hot path.

Zero runtime CC dispatch overhead. Not possible in C without macros.

---

### 5. Speculative connection lookup [HYPOTHESIS]

Current approach: receive packet → parse header → extract CID → look up
connection → process packet.

The CID lookup (hash table) is the first random memory access — guaranteed
cache miss for a new packet from any of 100K connections.

Alternative: issue the prefetch for CID lookup before finishing header parse,
overlapping the ~200 cycle memory fetch with the remaining header work. This
is already in the design (technique 6). Extension: maintain a small
"recent connections" ring of the last 16 CIDs per core. Check this ring
first with SIMD comparison before hitting the main hash table.

```zig
// Check recent-16 ring with one SIMD compare
const recent = @Vector(16, u64){ ring[0], ring[1], ... ring[15] };
const hit = recent == @splat(incoming_cid);
if (@reduce(.Or, hit)) {
    // Hot path: connection seen recently, state likely still in L1
    return recent_conns[@ctz(hit)];
}
// Cold path: full hash table lookup
```

For workloads with connection reuse (keep-alive, persistent streams), the
recent ring hit rate approaches 100% — eliminating the hash table lookup
entirely from the common case.

---

### 6. Zero-copy in-place TLS decryption [HYPOTHESIS]

Standard TLS flow: kernel copies packet to library buffer → library decrypts
into a separate plaintext buffer → application reads plaintext buffer.
Two copies minimum.

With io_uring fixed buffers + AES-GCM's in-place decryption property:

```
Kernel DMA → pre-registered buffer (zero copy from NIC)
AES-GCM decrypts in-place in that buffer (ciphertext → plaintext, same memory)
Application handler receives pointer into that buffer (zero copy to app)
```

The packet payload is never copied. The buffer is returned to the pool
after the handler returns. This requires careful lifetime management
(handler must not hold the pointer after returning) — enforced by Zig's
comptime lifetime tracking or explicit API contract.

---

### Status

These are research hypotheses. None are implemented. Priority order for
investigation: #2 (huge pages, low risk, measurable gain), #1 (CID BPF
routing, moderate complexity), #5 (recent connection ring, low risk),
#3 (state tiering, high complexity), #4 (comptime CC, Zig-specific),
#6 (zero-copy TLS, highest complexity).
