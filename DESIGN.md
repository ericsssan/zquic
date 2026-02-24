# zquic — Design Document

> A native Zig QUIC/HTTP3 implementation. Zero dependencies. Single binary.
> Research-driven. Built for ultra-low-latency.

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

Our target: **the highest possible HTTP/3 RPS per CPU cycle, on commodity
hardware, as a single static binary.**


---

## 2. Why HTTP/3 Only

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

### HTTP/3 + io_uring eliminates the kernel bottleneck

HTTP/3 runs over QUIC which runs over UDP. QUIC reimplements reliability,
ordering, flow control, and congestion control — but in userspace, where we
control the implementation and can optimize for our specific workload.

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

### Additional HTTP/3 advantages

- **0-RTT**: Repeat clients send data in the first packet. No handshake cost.
- **Multiplexing**: Multiple streams per connection, no head-of-line blocking.
- **Built-in TLS 1.3**: Mandatory. Packet crypto via AES-128-GCM + AES-NI — ~3–5 GB/s per core.
- **Connection migration**: Clients can switch networks without reconnecting.
- **No TCP baggage**: No Nagle algorithm, no TIME_WAIT, no SYN flooding.

### Compatibility

HTTP/3 is supported by Chrome, Firefox, Safari, curl, AWS ALB, Cloudflare,
nginx, Caddy, HAProxy. For internal infrastructure (microservices), HTTP/3-only
is viable today. For public-facing services, TCP fallback would be needed — but
that is a later concern.

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
Minimum QUIC/HTTP3 round-trip:

  Request:
    QUIC short header (1-RTT):   ~28 bytes
    HTTP/3 HEADERS (QPACK):      ~20 bytes
    UDP + IP + Ethernet:          46 bytes
    ──────────────────────────────────────
                                  ~94 bytes

  Response:
    QUIC short header:           ~28 bytes
    HTTP/3 HEADERS + DATA:       ~24 bytes
    UDP + IP + Ethernet:          46 bytes
    ──────────────────────────────────────
                                  ~98 bytes

  Round-trip total:              ~192 bytes
```

#### NIC ceiling formula

```
NIC ceiling (RPS) = NIC bandwidth (bytes/sec) / round-trip bytes

  1 Gbps  = 125,000,000 / 192  =   ~651K RPS
  10 Gbps = 1,250,000,000 / 192 =  ~6.5M RPS
  25 Gbps = 3,125,000,000 / 192 =  ~16M  RPS
  100 Gbps= 12,500,000,000 / 192 = ~65M  RPS
```

#### CPU ceiling formula

```
Hot path cycles per request (estimated):
  UDP receive (io_uring, amortized):    ~50 cycles
  QUIC packet decode:                  ~100 cycles
  TLS decrypt (AES-NI):                 ~80 cycles
  HTTP/3 frame parse:                   ~50 cycles
  Route lookup (comptime hash):         ~20 cycles
  Handler (in-memory KV):               ~30 cycles
  HTTP/3 frame encode:                  ~50 cycles
  TLS encrypt (AES-NI):                 ~80 cycles
  UDP send (io_uring, amortized):       ~50 cycles
  ──────────────────────────────────────────────────
  Total:                               ~510 cycles

CPU ceiling = (clock_hz × cores) / cycles_per_request
  4-core  @ 3 GHz: (3B × 4)  / 510 = ~23.5M RPS
  16-core @ 3 GHz: (3B × 16) / 510 = ~94M   RPS
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
1G      ~651K        ~23.5M    ~94M       1            NIC
10G     ~6.5M        ~23.5M    ~94M       3            NIC
25G     ~16M         ~23.5M    ~94M       6            NIC
100G    ~65M         ~23.5M    ~94M       16           NIC (with 16+ cores)
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
  65M × 510 cycles = 33.15B cycles/sec
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

ngtcp2 achieves 9.97 Gbit/s on a 10G NIC — 99.7% utilization. It is already
at the NIC ceiling. You cannot exceed a hardware ceiling.

**This does not mean the problem is solved.**

The NIC ceiling being the constraint only means the transport layer bottleneck
has been addressed. It says nothing about everything above it. The unsolved
problems are:

### 1. CPU efficiency

Two servers, both saturating a 10G NIC at 6M RPS:

```
Server A (ngtcp2 + nginx):  6M RPS,  95% CPU  →  5% left for app logic
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

### 5. The application layer is the actual product

Nobody deploys a raw QUIC transport server. They deploy an application on top
of it. The NIC ceiling is table stakes. The unsolved problems live above it:

```
NIC + transport    → solved (ngtcp2, quiche are good here)
───────────────────────────────────────────────────────────
Router             → comptime routing, zero dispatch overhead
Middleware         → zero-cost abstractions
Serialization      → zero-copy, schema-driven (not JSON)
Data access        → co-located KV, no network round-trip
Backpressure       → explicit, predictable
Memory             → no GC, no surprise allocations
Deployment         → single binary, zero runtime dependencies
```

### Summary: what zquic targets

```
NIC saturation:   same ceiling as existing libraries
CPU efficiency:   comptime dispatch, zero-alloc hot path, thread-per-core
Tail latency:     pool allocator, CPU pinning, cache-line layout
App layer:        integrated router, handler ABI, middleware
Deployment:       single static binary, zero runtime dependencies
```

---

## 5. QUIC Library Research

Notable implementations:

| Library   | Lang  | HTTP/3       | TLS backend       | I/O model         | CC algorithms              | Notes                        |
|-----------|-------|--------------|-------------------|-------------------|----------------------------|------------------------------|
| ngtcp2    | C     | + nghttp3    | pluggable (6+)    | caller-owned      | CUBIC, Reno                | curl's primary               |
| lsquic    | C+ASM | built-in     | BoringSSL         | caller-owned      | CUBIC, BBR                 | LiteSpeed; GQUIC + IETF QUIC |
| mvfst     | C++   | + Proxygen   | Fizz (OpenSSL)    | folly EventBase   | CUBIC, BBR, BBR2, Copa, RL | Meta; >75% of Meta traffic   |
| quicly    | C     | via H2O      | Picotls           | caller-owned      | not documented             | H2O server; latency-focused  |
| msquic    | C     | no           | OpenSSL           | caller-owned      | CUBIC, BBR                 | Windows/.NET primary         |
| quiche    | Rust  | built-in     | BoringSSL         | sans-io           | CUBIC, BBR                 | Cloudflare edge              |
| picoquic  | C     | minimal      | Picotls           | caller-owned      | CUBIC, BBR                 | Research-focused             |
| quinn     | Rust  | + h3 crate   | rustls            | sans-io           | CUBIC                      | Pure Rust                    |
| s2n-quic  | Rust  | no           | s2n-tls           | caller-owned      | CUBIC, BBR                 | AWS; formally verified parts |

### mvfst (Meta)

mvfst ("move fast") is Meta's production QUIC implementation, open-sourced May 2019. It is the
most production-battle-tested library in this list by scale.

**Production scale:**
- >75% of Meta's internet traffic (Facebook, Instagram) runs over QUIC/HTTP3 via mvfst
- Serves billions of users
- Integrated with Katran (Meta's XDP/eBPF load balancer): Connection ID encodes
  `workerId/processId/hostId`, allowing Katran to route packets directly to the correct
  server thread without application-layer lookup

**Architecture:**
- Thread-per-core: one `folly::EventBase` per worker thread, all packet processing inline
  (no queuing), chosen specifically to minimize tail latency
- I/O: `folly::AsyncUDPSocket` (epoll-backed) — no io_uring
- GSO: yes (write batching). GRO: yes (receive coalescing)
- No RSS, no NUMA, no SIMD in the library (crypto delegated to OpenSSL via Fizz)
- Memory: `folly::IOBuf` scatter/gather; jemalloc as heap allocator
- HTTP/3 is NOT in mvfst — it lives in Proxygen (separate library)
- Zero-downtime restart support built in

**TLS: Fizz**
Meta's own TLS 1.3 C++ library. Ships with mvfst. The only supported backend — mvfst is
not crypto-agnostic. Fizz wraps OpenSSL and libsodium for primitives; adds zero-copy
scatter/gather I/O APIs, PSK resumption, 0-RTT, and exported keying material for QUIC.

**Congestion control: Copa**
Copa (delay-based, MIT) is the standout algorithm not found elsewhere. Deployed globally
for Facebook live video upload on Android.

A/B results vs CUBIC (production, Facebook live video):
```
Metric          CUBIC     Copa      Delta
P50 RTT         499ms     479ms     -4%
P90 RTT         5.4s      3.9s      -27%
P50 goodput     —         —         +16.3%
P95 transport   —         —         -45%
```

Copa has known problems with ISP traffic policing (~10% of sessions where it cannot
distinguish congestion from rate limiting).

BBR2 is also implemented (not available in ngtcp2 or quiche).

**Goodput efficiency (TUM 2022 comparison paper):**
```
mvfst:    95.02%  (highest among tested)
ngtcp2:   92.54%
quiche:   91.52%
lsquic:   90.34%
```

**Research:**
- mvfst-rl: separate repo, reinforcement learning congestion controller (IMPALA-based,
  NeurIPS 2019 ML for Systems). Not production-deployed.
- External 2025 paper: 1.88x throughput improvement after architectural optimizations
  (studying QUIC throughput bottlenecks).

Decision: **build natively in Zig rather than FFI wrapping**.

Reasons:
- No existing production-ready Zig QUIC implementation exists
- C FFI inherits that library's allocator, memory layout, and design decisions
- Native Zig enables comptime optimizations unavailable to C libraries
- Native Zig enables explicit cache-line discipline
- Native Zig enables zero-allocation hot path from day one
- Single static binary with no C library dependency
- Research and open-source value

---

## 6. Architecture

### Layer separation

```
zquic repo
├── src/quic/       QUIC transport (RFC 9000)
│                   - Packet encoding/decoding
│                   - Connection state machine
│                   - Stream multiplexing
│                   - Flow control
│                   - Congestion control (CUBIC default)
│                   - TLS 1.3 integration
│                   - 0-RTT support
│
├── src/http3/      HTTP/3 framing (RFC 9114)
│                   - QPACK header compression (RFC 9204)
│                   - Request/response framing
│                   - Server push
│
├── src/server/     Opinionated HTTP/3 server
│                   - Routing (comptime trie)
│                   - Handler interface
│                   - Middleware chain
│                   - Connection pool
│
└── src/c_api.zig   C API wrapper (for C/C++ consumers)
    include/zquic.h Public C header
```

Each layer is independently usable:
- `quic` alone: for custom protocols (game networking, DNS-over-QUIC, etc.)
- `quic` + `http3`: for HTTP/3 clients/servers with custom server logic
- `server`: batteries-included HTTP/3 server

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
- SIMD string matching in HTTP/3 header parsing (method, path)

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

// HTTP/3 router — perfect hash computed at build time
const router = comptime Router.init(.{
    .{ "GET",  "/v1/get", kvGet  },
    .{ "POST", "/v1/set", kvSet  },
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

## 7. Language Compatibility — Do You Have to Write Zig?

No. There are three integration levels, each with different performance
characteristics and adoption effort.

### Level 1: C API (any language via FFI)

zquic exposes a stable C API via `include/zquic.h`. Any language with C FFI
gets the transport performance for free.

```c
// zquic.h
ZQuicServer* zquic_server_new(const ZQuicConfig* config);
void zquic_server_set_handler(ZQuicServer*, HandlerFn);
int  zquic_server_listen(ZQuicServer*, const char* addr, uint16_t port);
void zquic_server_free(ZQuicServer*);
```

| Language | Integration method  | Transport perf | Handler perf |
|----------|---------------------|---------------|--------------|
| C        | #include + -lzquic  | ✅ full       | ✅ full      |
| C++      | extern "C"          | ✅ full       | ✅ full      |
| Rust     | bindgen             | ✅ full       | ✅ full      |
| Go       | cgo                 | ✅ full       | ✅ near-full |
| Python   | ctypes / cffi       | ✅ full       | ❌ Python-speed |
| Node.js  | napi                | ✅ full       | ❌ JS-speed  |

The transport layer runs at full speed regardless of language. The handler
(your application code) runs at the speed of the chosen language. For
Python/JS users, the bottleneck moves from the network to the language runtime.
That is still a significant improvement — transport is no longer the wall.

Build produces: `libzquic.a` (static) and `libzquic.so` (dynamic).

### Level 2: Handler ABI (compiled plugin)

A stable binary interface lets handlers be compiled to `.so` and loaded at
runtime. Any language that can compile to a shared library can implement it:

```c
// The ABI contract — stable across versions
typedef struct {
    const char*    method;
    size_t         method_len;
    const char*    path;
    size_t         path_len;
    const uint8_t* body;
    size_t         body_len;
} ZQuicRequest;

typedef struct {
    uint16_t       status;
    const uint8_t* body;
    size_t         body_len;
} ZQuicResponse;

// Implement this function in any language, compile to .so
typedef void (*HandlerFn)(const ZQuicRequest*, ZQuicResponse*, void* ctx);
```

| Language | Compilation target | Performance |
|----------|--------------------|-------------|
| Zig      | `.so` native       | ✅ full speed |
| C / C++  | `.so` native       | ✅ full speed |
| Rust     | `.so` cdylib        | ✅ full speed |
| Go       | `.so` cgo          | ✅ near-full |
| Swift    | `.so` native       | ✅ near-full |
| Java     | `.so` GraalVM native image | ✅ good |
| Python   | `.so` Cython / mypyc | moderate |

Hot reload: swap `.so` without restarting the server. Different routes can
dispatch to handlers compiled from different languages.

### Level 3: WebAssembly (maximum flexibility)

Compile handlers to `.wasm`. zquic embeds a WASM runtime (wasmtime) and
executes handlers in a sandbox:

```
Handler written in Rust/C/Go/Python/JS/Swift/Kotlin
         ↓ compile
    handler.wasm
         ↓ load
    zquic (wasmtime runtime)
         ↓
    ~80–90% of native speed (WASM JIT)
```

Benefits:
- Any language that compiles to WASM (virtually all modern languages)
- Sandboxed — handler crash cannot kill the server
- Hot reload — swap `.wasm` at runtime
- This is the model used by Cloudflare Workers, Fastly Compute, AWS Lambda@Edge

Cost:
- ~10–20% performance overhead vs native
- wasmtime adds binary size (~5MB)

### The Migration Story

This is the adoption story that matters for real-world impact:

```
Step 1 — Drop in zquic, keep existing handler code
  "Replace nginx + your framework with zquic.
   Write your handler in any language you already use.
   Get 10× better transport for free."

Step 2 — Rewrite hot handlers in Zig/C/Rust
  "Profile. Find the 20% of handlers handling 80% of traffic.
   Rewrite those in Zig. Get the last 10% of performance."

Step 3 — Full Zig (optional, for maximum performance)
  "If you need every last cycle, write everything in Zig.
   But Step 1 and Step 2 are enough for most production workloads."
```

You do not need to rewrite your application in Zig to benefit from zquic.
You need Zig (or C/Rust) only if you want zero-overhead handlers in addition
to zero-overhead transport.

---

## 8. Dependency Management (Zig)

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
// Use just the QUIC transport
exe.root_module.addImport("quic", b.dependency("zquic", .{}).module("quic"));

// Or the full server
exe.root_module.addImport("zquic", b.dependency("zquic", .{}).module("server"));
```

No system dependencies. Zig fetches, verifies the hash, builds from source.

---

## 9. Benchmark Targets

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
Any server            10G     4       ~6.5M RPS  (NIC binding)
Any server            25G     8       ~16M  RPS  (NIC binding)
Any server            100G    16      ~65M  RPS  (NIC binding)

NIC is binding at sufficient core count.
At 4 cores + 100G: CPU (~23.5M) is binding, not NIC.
Crypto requires ~1 dedicated core per 5 Gbps throughput (AES-NI).
```

### Comparison against existing frameworks [THEORETICAL]

Expected RPS on loopback benchmark on target hardware (same machine, no NIC variable),
in-memory KV GET endpoint:

| System           | Expected RPS | Notes                        |
|------------------|--------------|------------------------------|
| Node.js (http)   | ~50K         | JS event loop, V8 overhead   |
| Bun              | ~80K         | JSC, faster than Node        |
| Go (net/http)    | ~200K        | GC pauses, runtime overhead  |
| Go (fasthttp)    | ~400K        | optimized, reduced allocs    |
| **zquic (Zig)**  | **~1M–6M**   | theoretical, see model above |

10× improvement over Go fasthttp is the minimum credible claim.
100× improvement over Node.js is the theoretical maximum.

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

## 10. Scalability Analysis

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
load balancer (similar to how Katran works for mvfst) is needed for
multi-machine deployments. Not designed.

#### Zero-downtime restart
Restarting zquic drops all in-flight QUIC connections. For any production
deployment with real traffic, restartless deploys are a hard requirement.
mvfst built this explicitly. Not designed in zquic yet.

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

## 11. Development Workflow

```
Write code (Mac)
    ↓
Build + functional test (Docker on Mac — io_uring works in Linux VM)
    ↓
Benchmark (Linux server)
```

Zig version: 0.16.0-dev.2637+6a9510c0e (master via zigup)

---

## 12. Open Source

License: MIT (maximally permissive, C consumers can use without copyleft concern)

Repo structure:
```
zquic/
├── src/
│   ├── quic/
│   ├── http3/
│   ├── server/
│   └── c_api.zig
├── include/
│   └── zquic.h
├── examples/
│   ├── zig/
│   └── c/
├── bench/
├── build.zig
├── build.zig.zon
├── DESIGN.md          ← this file
└── README.md
```

---

## 13. Implementation Roadmap

### Phase 1: QUIC transport
- UDP socket + io_uring with SQPOLL
- QUIC packet parsing (Initial, Handshake, 1-RTT)
- Connection establishment + state machine
- TLS 1.3 handshake
- Stream multiplexing + flow control
- Basic congestion control (CUBIC)
- Thread-per-core + SO_REUSEPORT
- Pool allocator (no malloc in hot path)
- **Milestone**: QUIC echo server running, connection establishment verified

### Phase 2: HTTP/3 framing
- QPACK header compression (RFC 9204)
- Request/response framing (RFC 9114)
- Keep-alive, stream reuse
- **Milestone**: HTTP/3 hello world responding to curl --http3

### Phase 3: Server layer
- Comptime router (perfect hash, zero runtime dispatch)
- Handler ABI (stable C-compatible interface)
- Middleware chain
- In-memory KV store (benchmark endpoint)
- **Milestone**: [THEORETICAL] benchmark model validated against loopback test

### Phase 4: Language integrations
- zquic.h public C header
- c_api.zig wrapper → libzquic.a + libzquic.so
- Handler ABI stabilized
- C, Rust, Go example handlers
- **Milestone**: Go handler running on zquic transport

### Phase 5: 100G design validation
- GSO batch size tuning (32–64 packets/call for 100G)
- NUMA-aware allocation (pin threads + memory to same node)
- Multi-core crypto pipeline (distribute AES-NI across cores)
- Connection state cache layout profiled and optimized
- SIMD batch packet header processing (@Vector)
- **Milestone**: architecture review — confirm design scales to 100G without
  structural changes (theoretical analysis, not measured)

### Phase 6: Measured benchmarks (requires hardware)
- Loopback benchmark on target hardware
- Compare vs Node.js, Bun, Go, fasthttp
- Publish: RPS, P50/P99/P999 latency, CPU% per core
- **Milestone**: published benchmark results with methodology

---

## 14. Competitive Analysis: ngtcp2 Source Deep Dive

ngtcp2 is the best-in-class C QUIC implementation (9.97 Gbit/s on 10G NIC,
used by curl). Understanding what it does and what it avoids informs every
architectural decision in zquic. This section records findings from direct
source analysis of the ngtcp2 codebase.

### What ngtcp2 does well

#### Pluggable allocator
ngtcp2 does not hardcode malloc. All allocation goes through an
`ngtcp2_mem` struct containing function pointers for malloc/calloc/free/realloc.
Callers can supply a custom allocator. This is the right design — and confirms
that pool allocation is viable in a C QUIC implementation.

#### Custom pool infrastructure
ngtcp2 has three allocator implementations:
- **OPL** (`ngtcp2_opl`): object pool list — a LIFO intrusive linked list for
  fixed-size object reuse. O(1) acquire/release.
- **balloc** (`ngtcp2_balloc`): bump-pointer block allocator — allocates from
  a pre-committed slab, cheap for variable-length objects (packet payloads,
  headers).
- **objalloc** (`ngtcp2_objalloc`): combines OPL + balloc — tries OPL first
  (recycled object), falls back to balloc (fresh slab allocation).

Objects pooled: `frame_chain`, `rtb_entry` (retransmit buffer), `strm`
(stream state), `acktr_entry` (ACK tracking).

**In steady state: zero `malloc` calls per packet.** Pool reuse only.
This is better than expected for a C library.

#### GSO support
ngtcp2 supports UDP Generic Segmentation Offload via `UDP_SEGMENT` cmsg and
a configurable `gso_burst` parameter. This is the correct approach — batch
multiple QUIC packets per `sendmsg()` syscall, reducing kernel overhead.
ngtcp2's aggregate write API (`ngtcp2_conn_write_aggregate_pkt2_versioned`)
is explicitly designed for GSO-batched sends.

---

### What ngtcp2 avoids (confirmed gaps)

These are not opinions — they are confirmed by searching the entire ngtcp2
source tree.

#### No io_uring
**Zero references** to `io_uring`, `liburing`, `IORING_OP_*`, or any
io_uring API in the entire codebase. All I/O uses standard POSIX `sendmsg()`
/ `recvmsg()` syscalls. This means every packet send/receive costs a full
kernel context switch (~1,000 cycles). There is no mechanism to eliminate
this overhead without replacing the I/O layer.

#### No RSS
**Zero references** to `SO_ATTACH_REUSEPORT_CBPF`, `SO_ATTACH_REUSEPORT_EBPF`,
or any RSS configuration. The ngtcp2 example server uses a single thread.
Multi-core scaling is left entirely to the application.

#### No NUMA awareness
**Zero references** to `numa_alloc_onnode`, `mbind`, `set_mempolicy`, or
NUMA topology. At 100K+ connections, connection state objects will be
allocated on whichever NUMA node happens to have free memory — possibly
requiring cross-socket memory access on multi-socket machines.

#### No congestion control beyond CUBIC/RENO
ngtcp2 implements CUBIC and Reno. No BBR. BBR achieves higher throughput
at the same RTT by modeling bottleneck bandwidth rather than relying on
loss as a congestion signal. Absence of BBR is a real-world limitation for
long-distance or high-BDP paths.

---

### The critical structural gap: conn struct layout

`ngtcp2_conn` is the central connection object. Source analysis shows:

```
ngtcp2_conn struct size: ~6.5–7.5 KB
```

Fields that are touched on every packet (hot fields):
- Packet number decryption key
- RX/TX sequence numbers
- ACK tracking state
- Stream state root

Fields that are rarely touched (cold fields):
- Peer address and port
- TLS certificate chain
- Connection statistics
- Path validation state
- Retry token

**These hot and cold fields are not separated.** They are interleaved
throughout the 6.5–7.5 KB struct in the order they were added during
development. A typical packet processing call touches ~200–400 bytes of
hot fields scattered across the struct, pulling in multiple full cache lines
even when only the hot fields are needed.

```
Hot fields needed per packet: ~200–400 bytes
Cache lines loaded (ngtcp2):  ~4–7 lines  (fields scattered across 6.5KB)
Cache lines loaded (zquic):   ~2 lines    (hot fields packed into 128 bytes)

At 6M RPS, 2 fewer cache line loads per packet:
  2 × 200 cycles × 6,000,000 = 2.4B cycles/sec saved
  ≈ one full CPU core freed purely from struct layout
```

---

### The crypto abstraction gap

ngtcp2 handles TLS crypto via three callbacks: `encrypt`, `decrypt`, `hp_mask`
(header protection). These are function pointers registered at connection
setup time.

Hot path crypto dereferences (per packet):
- **Receive**: 3 pointer dereferences (hp_mask → decrypt → verify)
- **Send**: 4 pointer dereferences (hp_mask → encrypt → tag → write)
- **Total**: 7 indirect function calls per packet round-trip

Each indirect call is a branch misprediction risk + icache pressure. At 6M RPS:
```
7 indirect calls × 6M RPS = 42M indirect branch predictions per second
```

Additionally, ngtcp2 performs header protection with scalar XOR and nonce
construction with scalar `memcpy`. **There is no SIMD anywhere in ngtcp2.**
AES-NI is only invoked through whatever TLS library the application linked
(OpenSSL, BoringSSL, etc.) — ngtcp2 itself makes no use of SIMD intrinsics.

---

### The call depth gap

ngtcp2 packet receive entry point:

```
ngtcp2_conn_read_pkt_versioned()
  └── conn_recv_cpkt()
        └── conn_recv_pkt()
              └── switch(frame.type) [20+ cases]
                    └── conn_recv_stream()  / conn_recv_ack() / ...
                          └── ... (1–3 more levels)
```

Minimum call depth to reach frame handling: **7–9 frames deep**.

Each function call is:
- Stack frame setup/teardown (~5–10 cycles)
- Potential icache miss if function not recently called
- Compiler cannot inline across translation unit boundaries

In Zig with comptime dispatch, the equivalent path collapses to a direct
call with inlining — no intermediate stack frames.

---

### Design implications

Each finding maps to a specific design decision:

```
ngtcp2 gap                    zquic approach
──────────────────────────────────────────────────────────────────────
No io_uring                   io_uring SQPOLL from Phase 1
                              Eliminates syscall cost per packet

No RSS                        SO_REUSEPORT (Phase 1) + RSS config docs
                              NIC pins connections to cores at hardware level

No NUMA                       Thread-per-core with numa_alloc_onnode
                              Memory allocated on same NUMA node as thread

No SIMD in crypto path        @Vector batch header processing
                              ILP-pipelined AES-NI batches (Phase 5)
                              Direct intrinsics, not TLS library callback

7 indirect crypto calls       Comptime dispatch — zero indirection
                              All crypto resolved to direct calls at build time

6.5KB monolithic conn struct  Hot/cold split: ConnectionHot (64 bytes, 1 cache line)
                              ConnectionCold (accessed only on handshake/close)

7–9 call depth to frame       Comptime inlined dispatch — flat call depth
                              No intermediate stack frames in hot path

No pre-allocation at startup  Pre-allocate at startup, pool acquire in hot path
(lazy allocation)             Eliminates first-packet allocation jitter

No BBR                        CUBIC (Phase 1) + BBR (Phase 5)
                              Better throughput on high-BDP paths

GSO: ✅ present               GSO retained and enhanced
                              GSO + io_uring = maximum batching efficiency
```

### Summary: what we keep, what we change

```
ngtcp2 design          Keep in zquic?   Why
─────────────────────────────────────────────────────────────────────
Pluggable allocator    ✅ keep          Right idea; zquic makes it stricter
Pool objects (OPL)     ✅ keep          Proven approach; extend to all hot objects
GSO support            ✅ keep          Combine with io_uring for maximum effect
Standard POSIX I/O     ❌ replace       io_uring SQPOLL eliminates syscall cost
Monolithic conn struct ❌ replace       Hot/cold split saves ~2 cache lines/packet
Function pointer crypto❌ replace       Comptime dispatch, direct SIMD calls
Scalar header ops      ❌ replace       @Vector batch processing
7–9 call depth         ❌ replace       Comptime inlined dispatch
Single-threaded model  ❌ replace       Thread-per-core + SO_REUSEPORT
No RSS config          ❌ add           Document + support RSS setup
No NUMA                ❌ add           NUMA-aware allocation from Phase 5
No BBR                 ❌ add           Add in Phase 5
```

---

## 15. Novel Techniques (Unexplored in Open QUIC Implementations)

Sections 6 and 13 cover known techniques applied better than existing libraries.
This section records ideas with no known open-source implementation — research
territory. All labeled [HYPOTHESIS] until measured.

---

### 1. CID-encoded thread affinity via SO_REUSEPORT BPF [HYPOTHESIS]

mvfst solves thread affinity by encoding workerId in the Connection ID and
routing at the Katran (XDP) load balancer layer — requiring a separate
infrastructure component. The same result is achievable without XDP using
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
