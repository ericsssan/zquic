# zquic oracle harness

A fast, Docker-free **oracle** for zquic: it runs the real zquic client/server
against an **independent** reference implementation over localhost UDP, and
validates against the **QUIC RFCs** — the same wire bytes the
[quic-interop-runner](https://github.com/quic-interop/quic-interop-runner) tests,
minus the scaffolding (Docker, ns-3/tc-netem, pcap+tshark) that makes a full run
take 20-40 minutes. The whole matrix runs in **~3 seconds**.

## Why this exists

`src/quic/integration_test.zig` (60 scenarios) and `netsim` are excellent but
**self-consistency** tests: every one is zquic↔zquic, so they cannot catch a spec
bug that zquic's own encoder and decoder agree on. This harness restores the
*oracle* property — an independent judge — at interactive speed, so it can run on
every commit. It complements, not replaces, the Docker runner (use that for the
full 11-client cross-impl sweep before a release).

## Quick start

```sh
zig build                 # build the zquic server + client
oracle/build-refs.sh      # build reference binaries + generate certs/www (once)
oracle/run.sh             # run the full matrix
oracle/run.sh -i quicgo transfer handshakeloss   # specific impl / cases
zig build test            # RFC 9001 crypto vectors live here (crypto.zig)
```

## What each check actually validates

| Check kind   | Cases                              | The judge is…                              |
| ------------ | ---------------------------------- | ------------------------------------------ |
| data-path    | handshake, transfer, multiplexing  | the **independent impl** — it rejects non-conformant wire bytes / crypto / transport params. Bytes are hash-verified end-to-end. |
| TLS auth     | (same, zquic-server direction)     | the ref client **verifies zquic's certificate** against the local CA (`cert-verified`). |
| behavioral   | retry                              | **the wire** — the case passes only if the mechanism's packet actually appears (long-header types are unmasked by header protection, so the proxy classifies them without keys). |
| loss recovery| handshakeloss, transferloss        | the data still arrives **through deterministic packet loss** (the proxy drops a seeded fraction); exercises PTO + retransmission. |
| crypto       | RFC 9001 A.1/A.2/A.5 (unit tests)  | the **RFC's exact bytes** — zero self-definition. |

Each assertion is falsification-checked (e.g. a transfer-mode server produces no
Retry → the retry wire-check fails; 95% loss → the transfer fails). "It passed"
means the specific thing was verified, not just "the file moved."

## Adding a test case

In `oracle/run.sh`, add to the relevant maps:

- `CASE_PATHS[name]` — the path(s) served from `oracle/www/`.
- Data-path case → add the name to `DATA_CASES` (runs both directions, hash-only).
- Proxied case → add to `PROXIED_CASES` and set one or both of:
  - `WIRE_REQUIRE[name]="s2c RETRY"` — a class+direction the proxy capture must contain.
  - `IMPAIR[name]="-loss 30 -seed 7"` — deterministic proxy impairment.
  - `TC[name]="transfer"` — the TESTCASE zquic endpoints get (default = case name).

The proxy classifies `INITIAL / 0RTT / HANDSHAKE / RETRY / VERSION_NEGOTIATION /
SHORT` per packet (coalescing-aware). Cleartext-detectable mechanisms (retry, VN,
0-RTT presence) need no keys; key-update / ECN need keylog-based decryption (TODO).

## Adding a reference implementation

Implement two adapters in `run.sh` (`ref_client` / `ref_server`) for the new
`impl`, and build it in `build-refs.sh`. `ref_client` MUST `exec` its binary (so
the timeout can kill the real process) and accept `-ca` for cert verification.
Then `oracle/run.sh -i <impl>`.

## Reference implementations

- **quic-go** — HTTP/0.9 (`hq-interop`), pure `go build`, runs everywhere incl. CI.
  The cert-verifying direction uses this.
- **ngtcp2** — **HTTP/3** (`osslclient`/`osslserver`), so it exercises zquic's
  H3/QPACK path (quic-go does not). Optional + local: built from a sibling
  `../ngtcp2` checkout against brew OpenSSL 3 + libev + libnghttp3; `build-refs.sh`
  skips it gracefully where those are absent (e.g. CI). Runs the protocol-agnostic
  cases; skips `retry` (needs the server's hq-interop retry mode).
- **quiche** — HTTP/0.9, so a second independent impl validates zquic's `hq-interop`
  path alongside quic-go. Optional + local: cargo-built from a sibling `../quiche`
  checkout (`git clone --recursive`). Driven with `--wire-version 00000001` because
  quiche's default `babababa` is a deliberate GREASE version (which zquic correctly
  VN's). Note: quiche over **HTTP/3** currently stalls against zquic — issue #4.

`oracle/run.sh` with no `-i` runs every impl that's built (quic-go always; ngtcp2 /
quiche when their sibling checkouts + deps are present).

## Known gaps (deliberate, tracked)

- **Cert verification is one-directional.** The ref client verifies zquic's
  server cert; the reverse can't, because zquic's own client doesn't validate
  certs — see issue #2.
- **Endpoints construct `Connection` by value on the stack** (band-aided with a
  large `stack_size`) — see issue #3.
- **Not yet covered:** 0-RTT, key update, ECN, migration, resumption, version
  negotiation, HTTP/3, and impairment beyond loss (delay/reorder).

See `PLAN.md` for the phased design.
