# Oracle Test Harness

A fast, Docker-free oracle for zquic. Pairs the real zquic client/server against
independent reference implementations (ngtcp2, quiche, quic-go) over localhost
UDP — the same wire bytes the quic-interop-runner tests, minus all the scaffolding
(Docker image builds, per-test containers, ns-3/tc-netem, pcap+tshark, sequential
cleanup) that makes a full interop run take 20-40 minutes.

Target: the core oracle matrix runs in **seconds**, on every commit.

## Current status (what actually ships)

Shipped today (`oracle/run.sh`) — **76/76, verified green across four impls**
(quicgo, ngtcp2 (h3), quiche, quiche-h3), gating `main` in CI
(`run.sh --require quicgo,ngtcp2,quiche,quiche-h3`):

- **4 reference impls:** quic-go (HTTP/0.9, always/CI), ngtcp2 (HTTP/3), quiche
  (HTTP/0.9), quiche-h3 (HTTP/3 — the GREASE-frame guard, #4). ngtcp2/quiche build
  from sibling checkouts; CI builds all four.
- **Data-path, both directions:** handshake, transfer, multiplexing — hash-verified
  and cert-verified both ways (ref client checks zquic's cert; zquic client with
  VERIFY_PEER=1 checks the ref server's CertificateVerify, #2).
- **Behavioral, wire-proven:** retry (`s2c RETRY`), versionnegotiation
  (`s2c VERSION_NEGOTIATION`), 0-RTT (`c2s 0RTT`), key update (Key Phase bit flip via
  `kpcheck` + `SSLKEYLOGFILE`, #40), ECN (`s2c ECT0` from the IP TOS byte, Linux-only
  #41), amplification limit (3× via per-datagram byte accounting, RFC 9000 §8.1),
  connection migration (`[CM] path_migrated` to a preferred_address), NAT rebind
  (`[CM] nat_rebind`, RFC 9000 §9.3.1 — the proxy swaps its server-facing source
  port mid-transfer; the server detects it and sends a PATH_CHALLENGE), idle timeout
  (`[IDLE]`),
  stateless reset — server *and* client direction (#42).
- **Also green:** resumption (PSK, both directions), multiconnect, chacha20, QUIC v2.
- **Impairment (seeded, deterministic):** handshakeloss (30%), transferloss (6%),
  longrtt (200ms), handshakecorruption (5% bit-flip), transfercorruption (2%).
- **HTTP/3 path:** ngtcp2 + quiche-h3 exercise zquic's H3/QPACK.
- **Crypto:** RFC 9001 A.1/A.2/A.5 vectors as unit tests.
- **Self-test:** 13 meta-checks assert each assertion still rejects its negative (#9).
- **Not yet:** packet-reordering and NAT address-rebind (`rebind-addr`) impairment;
  server-direction 0-RTT wire-proof; ECN wire-proof on macOS; CA-chain / hostname
  validation.

## Why

The 60 `integration_test.zig` scenarios + `netsim` are all zquic↔zquic — fast, but
*self-consistency* tests. They cannot catch a spec bug that zquic's own encoder and
decoder agree on (wrong frame encoding, a transport param both sides mishandle, an
HP/AEAD detail). The Docker interop runner is the only oracle today, and it is too
slow for the inner dev loop. This harness restores the oracle property — independent
impl on the wire — at interactive speed.

## Architecture

```
oracle/
  build-refs.sh     # build + cache reference binaries + fixtures
  run.sh            # orchestrator: launch endpoints, assert, report
  refs/quicgo/      # quic-go oracle endpoint (hq-interop / HTTP-0.9)
  refs/proxy/       # capturing + impairment UDP relay (Go)
  certs/ www/       # cert+key, served files (generated; gitignored)
  .cache/           # built reference binaries (gitignored)
```

## Validation model (this is the point)

- **Data-path cases** (handshake/transfer/multiplexing): the independent impl is
  the judge. It rejects non-conformant wire bytes/crypto/transport-params, so a
  hash-matched transfer through quic-go is a real oracle — not self-validation.
- **Behavioral cases** (retry, ...): a hash match does NOT prove the mechanism
  fired. The capturing proxy classifies every packet (QUIC long-header types are
  unmasked by header protection, so Retry/VN/0-RTT are visible without keys) and
  the case passes only if the required class appears ON THE WIRE. Verified by a
  falsification test: transfer-mode server transfers fine but produces no Retry →
  the wire-check fails where hash-only would false-pass.
- **Crypto path**: RFC 9001 Appendix A vectors as unit tests (exact bytes from the
  spec). A.1 AES keys + A.2 AES HP + A.5 ChaCha20 packet protection.

- **Endpoints over loopback UDP.** zquic server on :p, reference client → :p (or
  via the proxy). Assert: client exits 0 AND downloaded bytes hash-match the served
  file, within a timeout. Independent ports → cases run in parallel.
- **No Docker, no root, no netns.** Network impairment is a userspace UDP relay
  (`netproxy.zig`), seeded for determinism, replacing tc-netem for the *loss/longrtt
  cases. Clean-network cases need no proxy.
- **Reference binaries built once, cached.** Rebuilt only when missing.

## Reference impls (all three)

| impl    | build              | client CLI / iface          | roles         |
| ------- | ------------------ | --------------------------- | ------------- |
| ngtcp2  | cmake + quictls    | `h09client host port url`   | client+server |
|         | (source ../ngtcp2) | `h09server addr port key crt`| (h09 + h3)   |
| quiche  | cargo (apps)       | `quiche-client`/`-server`   | client+server |
| quic-go | go build (interop) | env-interface endpoint      | client+server |

ngtcp2's example CLIs take direct args → simplest to drive; built first to prove the
harness. quiche/quic-go added after.

## Test matrix (both directions where the ref supports the role)

Clean network (Phase 1): handshake, transfer, multiplexing, retry, resumption,
zerortt, keyupdate, v2, http3, chacha20.
Impaired (Phase 2, via netproxy): handshakeloss, transferloss, longrtt.

Each case runs: zquic-server ↔ ref-client, and ref-server ↔ zquic-client.

## Phases

- **Phase 0 — foundation.** `build-refs.sh` builds ngtcp2 (+quictls). Generate
  certs/www. Prove ONE case end-to-end: zquic server ↔ ngtcp2 h09client, handshake
  + transfer, hash-verified. Validates the whole approach.
- **Phase 1 — clean matrix.** `run.sh` orchestrator over the clean-network cases ×
  both directions × ngtcp2. `zig build oracle` wrapper.
- **Phase 2 — behavioral + impairment. DONE.** Wire-proven: retry,
  versionnegotiation, 0-RTT (`c2s 0RTT`), keyupdate (Key Phase bit via `kpcheck`
  + `SSLKEYLOGFILE`), ecn (`s2c ECT0` from IP TOS, Linux), migration, NAT rebind
  (`[CM] nat_rebind` via proxy `-rebind-after`), stateless reset (both directions),
  amplification limit, idle timeout. Proxy injects seeded -loss/-corrupt/-delayms
  and a count-triggered -rebind-after. Remaining: packet-reordering and
  address-rebind (`rebind-addr`) impairment, server-direction 0-RTT.
- **Phase 3 — multi-impl + CI. DONE.** All four impls (quicgo, ngtcp2 (h3), quiche,
  quiche-h3) build in `build-refs.sh` and gate `main` via the `oracle` CI job
  (`run.sh --require quicgo,ngtcp2,quiche,quiche-h3`). The full Docker matrix stays
  for the pre-release 11-client cross-impl sweep only.

## Complementary (cheap, parallel win)

Add RFC 9001 Appendix A Initial-packet vectors (A.1-A.3 AES, A.5 ChaCha20) as plain
unit tests — a deterministic crypto oracle for the Initial protection/AEAD/HP path,
zero external deps. (A.4 Retry is already verified in packet.zig.)

## Non-goals

Not replacing quic-interop-runner — that stays for the comprehensive cross-impl /
cross-client release sweep. This harness is the fast inner-loop oracle.
