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
| server prop  | versionnegotiation                 | **the wire** — a client offering an unknown version (ngtcp2 `--version`, or quiche's default GREASE `babababa`) must get a `VERSION_NEGOTIATION` packet back. Wire-only (the handshake intentionally doesn't complete). |
| loss recovery| handshakeloss, transferloss        | the data still arrives **through seeded packet loss** (the proxy drops a fixed fraction; the seed fixes the drop *sequence*, not which logical packets — see #8); exercises PTO + retransmission. Use `-n N` to repeat-stress. |
| crypto       | RFC 9001 A.1/A.2/A.5 (unit tests)  | the **RFC's exact bytes** — zero self-definition. |
| self-test    | (meta) wire_has, assert_match      | **the harness itself** — each assertion is run against a known negative (a corrupted/missing file, a transfer capture with no Retry/VN) and must reject it, so a refactor can't silently turn a check into a no-op (#9). Runs on every full run and via `--self-test`. |

Each assertion is falsification-checked (e.g. a transfer-mode server produces no
Retry → the retry wire-check fails; 95% loss → the transfer fails). "It passed"
means the specific thing was verified, not just "the file moved." Those
falsification checks are no longer manual — they run as a standing **self-test**
(`oracle/run.sh --self-test`, also appended to every full run): the meta-tests
assert that `assert_match` rejects a corrupted/missing file and that the wire-check
finds no Retry/VN in a normal transfer, so the suite can't degrade into a
confidently-green no-op (#9).

## Adding a test case

In `oracle/run.sh`, add to the relevant maps:

- `CASE_PATHS[name]` — the path(s) served from `oracle/www/`.
- Data-path case → add the name to `DATA_CASES` (runs both directions, hash-only).
- Proxied case → add to `PROXIED_CASES` and set one or both of:
  - `WIRE_REQUIRE[name]="s2c RETRY"` — a class+direction the proxy capture must contain.
  - `IMPAIR[name]="-loss 30 -seed 7"` — seeded proxy impairment (reproducible
    drop sequence; outcomes still vary slightly with timing — #8).
  - `TC[name]="transfer"` — the TESTCASE zquic endpoints get (default = case name).

The proxy classifies `INITIAL / 0RTT / HANDSHAKE / RETRY / VERSION_NEGOTIATION /
SHORT` per packet (coalescing-aware). Cleartext-detectable mechanisms (retry, VN,
0-RTT presence) need no keys. The Key Phase bit is wire-proven by `kpcheck`, which
strips header protection using the endpoint's `SSLKEYLOGFILE` (#40); ECN is read
straight from the IP TOS byte via `IP_RECVTOS` (Linux only, #41) — neither needs
payload decryption.

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
  VN's).
- **quiche-h3** — the same quiche binary over HTTP/3. quiche is the only client that
  prepends GREASE frames before the request HEADERS (RFC 9114 §9), so this guards
  zquic's h3 frame handling. (It found issue #4 — zquic dropped requests that didn't
  start with HEADERS — now fixed.) Scoped to data-path cases (loss/RTT are covered
  by ngtcp2-h3).

`oracle/run.sh` with no `-i` runs every impl that's built (quic-go always; ngtcp2 /
quiche when their sibling checkouts + deps are present).

## Known gaps (deliberate, tracked)

- **Cert verification is bidirectional** (issue #2 fixed). The ref client verifies
  zquic's server cert, and the zquic client (VERIFY_PEER=1) verifies the ref
  server's CertificateVerify (ECDSA-P256 / Ed25519). CA-chain / hostname
  validation is not yet implemented.
- **Endpoints construct `Connection` by value on the stack** (band-aided with a
  large `stack_size`) — see issue #3.
- **ECN wire-proof is Linux-only.** The transfer still runs on macOS, but the
  `s2c ECT0` wire assertion is skipped there — `IP_RECVTOS` is not reliably
  populated on Darwin loopback (#41).
- **0-RTT is client-direction only.** The wire-check proves the zquic *client*
  sends early data (`c2s 0RTT`); zquic-*server* 0-RTT acceptance is not yet
  wire-proven.
- **Not yet covered:** packet reordering and NAT rebinding (`rebind-addr` /
  `rebind-port`) impairment — the proxy does loss / corruption / delay / ECN but
  not reorder or source-port rebind — and keyupdate in the client direction against
  quiche (#22). (0-RTT, key update, ECN, migration, resumption, version negotiation,
  and HTTP/3 are now all covered — see `PLAN.md`.)

See `PLAN.md` for the phased design.
