#!/usr/bin/env bash
#
# zquic oracle harness — fast, Docker-free interop against reference impls.
#
# SCOPE: three reference impls — quic-go (HTTP/0.9, in CI), quiche (HTTP/0.9),
# ngtcp2 (HTTP/3); the latter two optional/local. Cases: handshake/transfer/
# multiplexing both directions; retry (wire-checked); handshakeloss/transferloss/
# longrtt (seeded impairment). See README.md / PLAN.md for details.
#
# Two kinds of checks:
#   data-path: assert downloaded bytes hash-match the served files. The
#     independent impl is the judge of wire codec / crypto / transport params.
#     When the ref CLIENT talks to the zquic server it ALSO verifies zquic's
#     certificate against the local CA (real TLS-auth oracle). The reverse
#     direction also verifies: the zquic client (VERIFY_PEER=1) checks the ref
#     server's CertificateVerify signature (#2) — both directions cert-verified.
#   behavioral: route through the capturing proxy and assert the mechanism
#     actually appeared ON THE WIRE (e.g. a Retry packet), not just that the file
#     transferred.
#
# Usage: oracle/run.sh [-i impl] [-r impl,...] [-n N] [case...]
#   -r/--require impl[,impl]  fail (exit 3) if a named impl isn't built, instead
#                             of silently running a smaller green matrix (#7).
#                             Also honored via the ORACLE_REQUIRE env var.
#   -n/--repeat N             run the selection N times, require all green — a
#                             stability check for the SEEDED (not outcome-
#                             deterministic) loss cases (#8). Also ORACLE_REPEAT.
#   --self-test               run only the meta-tests: prove the harness's own
#                             assertions still reject their negatives (#9). Also
#                             runs automatically at the end of every full run.
#
if (( BASH_VERSINFO[0] < 4 )); then
  echo "oracle/run.sh requires bash 4+ (found ${BASH_VERSION})." >&2
  echo "On macOS: brew install bash  (then use /opt/homebrew/bin/bash oracle/run.sh)" >&2
  exit 1
fi
set -u

ORACLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$ORACLE")"
ZQUIC_SERVER="$ROOT/zig-out/bin/server"
ZQUIC_CLIENT="$ROOT/zig-out/bin/client"
CERTS="$ORACLE/certs"; WWW="$ORACLE/www"; BIN="$ORACLE/.cache/bin"; TMP="$ORACLE/.cache/run"
PROXY="$BIN/proxy"
KPCHECK="$BIN/kpcheck"
PORT_BASE=59200  # RFC 6335 dynamic/private range; avoids IANA-registered 4500 (ipsec-msft)
CLIENT_TIMEOUT=25   # seconds; loopback handshake+1MB is <1s, so this only catches hangs

declare -A CASE_PATHS=(
  [handshake]="/1.bin"
  [transfer]="/big.bin"
  [multiplexing]="/1.bin /2.bin /3.bin /4.bin"
  [retry]="/big.bin"
  [handshakeloss]="/1.bin"
  [transferloss]="/big.bin"
  [longrtt]="/1.bin"   # high-RTT correctness, not bulk throughput — keep it small + fast
  [handshakecorruption]="/1.bin"
  [transfercorruption]="/big.bin"
  [ecn]="/big.bin"         # meaningful: server TESTCASE=ecn enables ECN socket options
  [keyupdate]="/big.bin"   # meaningful (client dir): zquic client calls initiateKeyUpdate()
)
# Behavioral cases: required wire token (class the proxy capture must contain).
declare -A WIRE_REQUIRE=( [retry]="s2c RETRY" [ecn]="s2c ECT0" )
# Proxy impairment / extra flags. SEEDED for loss cases (not outcome-deterministic:
# the seed fixes the drop sequence, but which logical packet is the Nth datagram
# shifts with timing — #8). Rates carry headroom; use `-n N` for repeat-stability.
declare -A IMPAIR=(
  [handshakeloss]="-loss 30 -seed 7"
  [transferloss]="-loss 6 -seed 7"
  [longrtt]="-delayms 100"   # 200ms RTT: exercises RTT estimation / timers / pacing
  [handshakecorruption]="-corrupt 5 -seed 42"   # 5% bit-flip; AEAD drops → retransmit
  [transfercorruption]="-corrupt 2 -seed 42"    # 2% on big.bin (5% cascades on 1MB)
  [ecn]="-ecn"               # proxy reads IP_RECVTOS CMSG; logs s2c ECT0 count (#41)
)
# Per-case timeout overrides (seconds). Loss cases need extra headroom: 30% loss
# with exponential PTO backoff can cascade to ~12s worst-case on a quiet machine
# and ~20s under 5% CI CPU contention, leaving almost no margin at 25s (#36).
declare -A CASE_TIMEOUT=(
  [handshakeloss]=45
  [transferloss]=45
)
# zquic TESTCASE to pass to the endpoints (default = case name). Impaired cases
# just serve/fetch like transfer; the impairment is injected by the proxy.
declare -A TC=( [handshakeloss]="transfer" [transferloss]="transfer" [longrtt]="transfer" \
                [handshakecorruption]="transfer" [transfercorruption]="transfer" )
# Per-impl protocol override: ngtcp2's example binaries are HTTP/3 only, so pair
# them with zquic's http3 path — this exercises zquic's H3/QPACK, which the
# quic-go (hq-interop / HTTP-0.9) cases never touch.
declare -A IMPL_TC=( [ngtcp2]="http3" [quiche-h3]="http3" )
# Cases an impl can't run: retry needs the server's hq-interop retry mode, which
# can't coexist with a forced http3 protocol.
# quiche-h3 exists to guard the H3 GREASE-frame handling (RFC 9114 §9) — quiche is
# the only client that prepends GREASE. Its data-path cases do that; loss/RTT are
# already covered by ngtcp2-h3, and quiche-h3 is slow under 30% loss, so skip them.
declare -A IMPL_SKIP=( [ngtcp2]="retry ecn keyupdate" [quiche]="keyupdate" [quiche-h3]="retry handshakeloss transferloss longrtt ecn keyupdate" )
# Cases to skip only in the dp_zquic_client direction (ref server + zquic client).
# quiche-server drops streams after a Key Phase bit flip (#22); quiche is fully skipped
# for keyupdate (client doesn't initiate key updates, same as ngtcp2), so this is redundant
# but kept for clarity.
declare -A SKIP_CLIENT=( [quiche]="keyupdate" )
DATA_CASES=(handshake transfer multiplexing keyupdate)
# ecn moved to PROXIED_CASES: server-direction only via proxy with -ecn (#41 wire-proof).
PROXIED_CASES=(retry handshakeloss transferloss longrtt handshakecorruption transfercorruption ecn)

# zquic TESTCASE for (impl, case): impl protocol override > case override > name.
ztc() { echo "${IMPL_TC[$1]:-${TC[$2]:-$2}}"; }
skipped()     { case " ${IMPL_SKIP[$1]:-}   " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
skip_client() { case " ${SKIP_CLIENT[$1]:-} " in *" $2 "*) return 0 ;; *) return 1 ;; esac; }
ALL_IMPLS=(quicgo ngtcp2 quiche quiche-h3)
IMPLS=(); IMPL_SET=0
PASS=0; FAIL=0; FAILED=()

ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED+=("$*"); }
# dump_xfer LOGFILE: server-side recovery-state progression around a failed
# transfer (invest/recovery). Shows transfer onset + the steady stall state so a
# hard recovery stall (off frozen, unacked>0, acked frozen) can be told apart
# from slow-but-progressing recovery (off/acked creeping). Fields per [XFER]:
# off=bytes written, acked=client-acked, smax=flow-ctl limit, unacked=off-acked,
# cwnd/bif=congestion vs in-flight, queued, pto_ms=ms-to-PTO, ptoc=PTO backoff,
# retx=pending stream retx, ping=idle PINGs sent.
dump_xfer() {
  local f="$1"; local n; n=$(grep -c '\[XFER\]' "$f" 2>/dev/null || echo 0)
  echo "  [CONN recovery state over time — ptoarm=false while owing data ⇒ PTO unarmed bug]"
  grep '\[CONN\]' "$f" 2>/dev/null | tail -16 | sed 's/^/    /'
  echo "  [TX feed state — off frozen < filesize ⇒ send-side stall]"
  grep '\[TX\]' "$f" 2>/dev/null | tail -8 | sed 's/^/    /'
  echo "  [XFER $n samples; onset 4 + stall tail 24]"
  grep '\[XFER\]' "$f" 2>/dev/null | head -4 | sed 's/^/    /'
  [ "$n" -gt 28 ] && echo "    ..."
  grep '\[XFER\]' "$f" 2>/dev/null | tail -24 | sed 's/^/    /'
  echo "  [SLEEP requested-vs-actual — wanted<<slept ⇒ receiveTimeout ignores deadline]"
  grep '\[SLEEP\]' "$f" 2>/dev/null | tail -10 | sed 's/^/    /'
  echo "  [LOOP heartbeat — gaps mean the loop blocked in receiveTimeout]"
  grep '\[LOOP\]' "$f" 2>/dev/null | tail -8 | sed 's/^/    /'
  echo "  [TICKPTO — d_minus_now>0 always ⇒ tick never reaches the deadline]"
  grep '\[TICKPTO\]' "$f" 2>/dev/null | tail -10 | sed 's/^/    /'
  echo "  [PTOB branch fires]"
  grep '\[PTOB\]' "$f" 2>/dev/null | head -3 | sed 's/^/    /'
  grep '\[PTOB\]' "$f" 2>/dev/null | tail -6 | sed 's/^/    /'
  echo "  [IDLE] $(grep -c '\[IDLE\]' "$f" 2>/dev/null) server idle-timeouts"
}

# PIDs of every process this oracle run has backgrounded. cleanup() kills by
# exact PID rather than pkill -f (which matches any process carrying the binary
# path in its argv, including a concurrent oracle run or a CI wrapper script).
_HARNESS_PIDS=()

cleanup() {
  local pid
  for pid in "${_HARNESS_PIDS[@]+"${_HARNESS_PIDS[@]}"}"; do
    kill "$pid" 2>/dev/null
  done
  wait "${_HARNESS_PIDS[@]+"${_HARNESS_PIDS[@]}"}" 2>/dev/null
  return 0
}
trap cleanup EXIT

# to SECS cmd... — run cmd with a hard timeout; returns 124 on timeout.
# cmd must be a binary or a function that exec's a binary (so the polled pid IS
# the process to kill). Output/redirection is inherited from the caller.
to() {
  local secs=$1; shift
  "$@" & local pid=$! i=0
  while kill -0 "$pid" 2>/dev/null; do
    if [ "$i" -ge "$((secs * 10))" ]; then kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; return 124; fi
    sleep 0.1; i=$((i + 1))
  done
  wait "$pid"; return $?
}

# Portable SHA-256 (Linux sha256sum / macOS shasum).
h256() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else shasum -a256 "$1" | awk '{print $1}'; fi
}

# Is UDP `port` bound? Uses lsof on macOS (works without root) and ss on Linux
# (reads kernel netlink directly; lsof on Linux may silently return empty for
# UDP sockets without elevated permissions — #39). Ports are fresh + pre-cleaned,
# so a port-level check is sufficient. (-P/-n: numeric; 4500 prints as the
# service name "ipsec-msft" otherwise.)
port_bound() {
  local port=$2
  case "$(uname -s)" in
    Darwin) lsof -nP -iUDP:"$port" 2>/dev/null | grep -q ":$port" ;;
    *)      ss -lun 2>/dev/null | grep -qE "[:.]$port([^0-9]|$)" ;;
  esac
}

# Wait until pid has bound UDP port, or it dies. Requires lsof/ss (checked at
# startup). Returns 1 if the port is not bound within 5 seconds — a live-but-
# unbound process is not ready (#33).
wait_listen() {
  local pid=$1 port=$2 i
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 1
    port_bound "$pid" "$port" && return 0
    sleep 0.1
  done
  return 1
}
stop() { kill "$@" 2>/dev/null; wait "$@" 2>/dev/null; }

# wire_has TOKEN CAPFILE — true if the proxy capture contains a class+direction
# token (e.g. "s2c RETRY"). The single chokepoint for every behavioral wire-check,
# so the self-test (#9) can prove it still discriminates present from absent.
wire_has() { grep -q "$1" "$2" 2>/dev/null; }

# dump_capture CAPFILE — print a sorted class summary after a wire_has failure
# so a developer can see what the proxy DID capture without reading the file (#34).
dump_capture() {
  local f=$1 lines=0
  [ -f "$f" ] && lines=$(wc -l <"$f" 2>/dev/null)
  echo "  capture ($f, ${lines} lines):"
  if [ "${lines:-0}" -eq 0 ]; then
    echo "    (empty — proxy may not have received any packets)"
  else
    sort "$f" 2>/dev/null | uniq -c | sort -rn | head -10 | sed 's/^/    /'
  fi
}

assert_match() { # <dir> <path...>
  local dir=$1; shift; local p base want got
  for p in "$@"; do
    base="$(basename "$p")"
    [ -f "$dir/$base" ] || { echo "missing $base (looked in $dir)"; return 1; }
    want=$(h256 "$WWW/$base"); got=$(h256 "$dir/$base")
    [ "$want" = "$got" ] || { echo "hash mismatch $base: want $want got $got"; return 1; }
  done
}

# ref_client: MUST be invoked only via `to` (it exec's, replacing the subshell so
# the timeout can kill the real process). Always verifies the zquic cert (-ca).
ref_client() { # <impl> <port> <outdir> <path...>
  local impl=$1 port=$2 out=$3; shift 3
  local urls=() p; for p in "$@"; do urls+=("https://127.0.0.1:$port$p"); done
  case "$impl" in
    quicgo) exec "$BIN/quicgo" client -ca "$CERTS/cert.pem" "$out" "${urls[@]}" ;;
    ngtcp2) exec "$BIN/ngtcp2-client" -q --download="$out" --exit-on-all-streams-close 127.0.0.1 "$port" "${urls[@]}" ;;
    quiche) exec "$BIN/quiche-client" --no-verify --wire-version 00000001 --http-version HTTP/0.9 --dump-responses "$out" "${urls[@]}" ;;
    quiche-h3) exec "$BIN/quiche-client" --no-verify --wire-version 00000001 --http-version HTTP/3 --dump-responses "$out" "${urls[@]}" ;;
    *) echo "unknown impl $impl" >&2; exit 2 ;;
  esac
}
# Are the binaries for an impl present?
impl_ok() {
  case "$1" in
    quicgo) [ -x "$BIN/quicgo" ] ;;
    ngtcp2) [ -x "$BIN/ngtcp2-client" ] && [ -x "$BIN/ngtcp2-server" ] ;;
    quiche | quiche-h3) [ -x "$BIN/quiche-client" ] && [ -x "$BIN/quiche-server" ] ;;
    *) return 1 ;;
  esac
}
ref_server() { # <impl> <port> <logfile> — starts server, sets _LAST_SERVER_PID
  local impl=$1 port=$2 logf=$3
  case "$impl" in
    quicgo)    "$BIN/quicgo" server "127.0.0.1:$port" "$CERTS/cert.pem" "$CERTS/priv.key" "$WWW" >"$logf" 2>&1 & _LAST_SERVER_PID=$! ;;
    ngtcp2)    "$BIN/ngtcp2-server" -q --htdocs="$WWW" '*' "$port" "$CERTS/priv.key" "$CERTS/cert.pem" >"$logf" 2>&1 & _LAST_SERVER_PID=$! ;;
    quiche)    "$BIN/quiche-server" --listen "127.0.0.1:$port" --cert "$CERTS/cert.pem" --key "$CERTS/priv.key" --root "$WWW" --http-version HTTP/0.9 >"$logf" 2>&1 & _LAST_SERVER_PID=$! ;;
    quiche-h3) "$BIN/quiche-server" --listen "127.0.0.1:$port" --cert "$CERTS/cert.pem" --key "$CERTS/priv.key" --root "$WWW" --http-version HTTP/3 >"$logf" 2>&1 & _LAST_SERVER_PID=$! ;;
    *) return 2 ;;
  esac
  _HARNESS_PIDS+=("$_LAST_SERVER_PID")
}

dp_zquic_server() { # zquic server <-> ref client
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local cv=""; [ "$impl" = quicgo ] && cv=" | cert-verified" # only quic-go verifies the zquic cert
  local out="$d/zsrv"; rm -rf "$out"; mkdir -p "$out"
  TESTCASE="$(ztc "$impl" "$case")" CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$port" || { bad "$case [zquic-server <-> $impl-client] (no bind)"; stop "$sp"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$out" $paths >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "$case [zquic-server <-> $impl-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$case [zquic-server <-> $impl-client] (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m kphs_chk=1
  [ "$case" = keyupdate ] && ! grep -q "\[KPHS\]" "$d/zsrv.log" && kphs_chk=0
  if m="$(assert_match "$out" $paths)"; then
    if [ "$kphs_chk" -eq 0 ]; then bad "$case [zquic-server <-> $impl-client] (no key phase rotation in server log)"; else ok "$case [zquic-server <-> $impl-client$cv]"; fi
  else bad "$case [zquic-server <-> $impl-client] ($m)"; fi
}
dp_zquic_client() { # ref server <-> zquic client (no cert verify — zquic client limitation)
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local out="$d/zcli"; rm -rf "$out"; mkdir -p "$out"
  ref_server "$impl" "$port" "$d/rsrv.log" || { bad "$case [$impl-server <-> zquic-client] (no bind)"; return; }
  local sp=$_LAST_SERVER_PID
  wait_listen "$sp" "$port" || { bad "$case [$impl-server <-> zquic-client] (no bind)"; stop "$sp"; return; }
  local reqs="" p; for p in $paths; do reqs="$reqs https://127.0.0.1:$port$p"; done
  # VERIFY_PEER=1: the zquic client validates the ref server's CertificateVerify
  # against its (P-256) cert — now both directions are cert-verified (#2).
  to "$CLIENT_TIMEOUT" env VERIFY_PEER=1 TESTCASE="$(ztc "$impl" "$case")" REQUESTS="${reqs# }" DOWNLOADS="$out" "$ZQUIC_CLIENT" >"$d/zcli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "$case [$impl-server <-> zquic-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$case [$impl-server <-> zquic-client] (client rc=$rc)"; return; }
  local m kphs_chk=1
  [ "$case" = keyupdate ] && ! grep -q "\[KPHS\]" "$d/zcli.log" && kphs_chk=0
  if m="$(assert_match "$out" $paths)"; then
    if [ "$kphs_chk" -eq 0 ]; then bad "$case [$impl-server <-> zquic-client] (no key phase rotation in client log)"; else ok "$case [$impl-server <-> zquic-client | cert-verified]"; fi
  else
    bad "$case [$impl-server <-> zquic-client] ($m)"
    if [ "$case" = keyupdate ]; then
      echo "=== keyupdate debug ===" ; echo "--- zcli.log ---"; cat "$d/zcli.log" 2>/dev/null; echo "--- rsrv.log (last 10) ---"; tail -10 "$d/rsrv.log" 2>/dev/null
    fi
  fi
}
# proxied: zquic server <-> [proxy: capture (+optional impairment)] <-> ref client.
# Always asserts hash. If WIRE_REQUIRE[case] is set, also asserts the mechanism
# appears on the wire. If IMPAIR[case] is set, the proxy injects loss/delay.
proxied() {
  local impl=$1 case=$2 sport=$3 pport=$4 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local want="${WIRE_REQUIRE[$case]:-}" impair="${IMPAIR[$case]:-}" tc="$(ztc "$impl" "$case")"
  local ct="${CASE_TIMEOUT[$case]:-$CLIENT_TIMEOUT}"
  local tag="$case [zquic-server <-> $impl-client${impair:+ | impair:$impair}${want:+ | wire: $want}]"
  local out="$d/wire"; rm -rf "$out"; mkdir -p "$out"; local capf="$d/capture.txt"
  TRANSFER_DEBUG="${ORACLE_XFER_DEBUG:-}" TESTCASE="$tc" CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$sport" || { bad "$tag (no server bind)"; stop "$sp"; return; }
  # GOMAXPROCS=1: the capturing proxy is purely I/O-bound packet forwarding, but
  # Go defaults GOMAXPROCS to the runner's core count and spreads it across all of
  # them, competing with the single-threaded, latency-sensitive zquic server. On a
  # loaded CI runner that starves the server's receive path (it drops client ACKs →
  # send_acked stalls → seeded-loss recovery stalls / truncations). Pinning the
  # proxy to one OS thread keeps cores free for the server. Applied at every proxy
  # launch below.
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" $impair >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "$tag (no proxy bind)"; stop "$sp" "$px"; return; }
  to "$ct" ref_client "$impl" "$pport" "$out" $paths >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  [ $rc -eq 124 ] && { bad "$tag (TIMEOUT)"; echo "[HSDONE loss=$(grep -c 'HSDONE.*loss' "$d/zsrv.log" 2>/dev/null) retx=$(grep -c 'HSDONE.*queue' "$d/zsrv.log" 2>/dev/null)]"; echo "[AUTH]"; grep 'AUTH\]' "$d/zsrv.log" 2>/dev/null | head -3; echo "[PTO]"; grep 'PTO\]' "$d/zsrv.log" 2>/dev/null | tail -5; echo "[STREAM]"; grep 'STREAM\]' "$d/zsrv.log" 2>/dev/null | head -5; echo "[STREAM last]"; grep 'STREAM\]' "$d/zsrv.log" 2>/dev/null | tail -5; echo "[ACKR]"; grep 'ACKR\]' "$d/zsrv.log" 2>/dev/null | tail -5; echo "[zsrv tail]"; tail -3 "$d/zsrv.log" 2>/dev/null; echo "[cli]"; cat "$d/cli.log" 2>/dev/null; echo "[proxy drop]"; grep -i 'drop\|loss\|discard' "$d/proxy.log" 2>/dev/null | tail -5; echo "[cap $(wc -l <"$d/capture.txt" 2>/dev/null)]"; sort "$d/capture.txt" 2>/dev/null | uniq -c | sort -rn | head -10; echo "[cap tail]"; tail -20 "$d/capture.txt" 2>/dev/null; dump_xfer "$d/zsrv.log"; return; }
  [ $rc -eq 0 ] || {
    bad "$tag (client rc=$rc: $(tail -1 "$d/cli.log"))"
    # rc=254 = ref client (quiche/ngtcp2) idle-timed-out mid-transfer — the
    # dominant seeded-loss failure. Dump the server's recovery state so we can
    # see why the tail never lands (invest/recovery).
    echo "  [s2c bytes proxy saw]"; awk '/s2c DGRAM/{n+=$3} END{print n+0}' "$capf" 2>/dev/null
    dump_xfer "$d/zsrv.log"
    return
  }
  local m; if ! m="$(assert_match "$out" $paths)"; then
    bad "$tag (transfer: $m)"
    # Hash-mismatch diagnostics (#seeded-loss investigation): a mismatch under
    # pure loss means wrong bytes were delivered (loss should retransmit identical
    # bytes), so locate the first differing offset and dump the server's view.
    local bp; for bp in $paths; do local bb; bb="$(basename "$bp")"
      if [ -f "$out/$bb" ]; then
        local esz gsz; esz=$(wc -c <"$WWW/$bb"); gsz=$(wc -c <"$out/$bb")
        echo "  [diag] $bb expected=$esz got=$gsz first-diff-offset=$(cmp "$WWW/$bb" "$out/$bb" 2>&1 | sed 's/.*char //;s/,.*//' | head -1)"
      else echo "  [diag] $bb MISSING in $out"; fi
    done
    echo "  [zsrv tail]"; tail -4 "$d/zsrv.log" 2>/dev/null
    echo "  [zsrv errors]"; grep -iE "error|panic|overflow|reset|violat" "$d/zsrv.log" 2>/dev/null | head -5
    dump_xfer "$d/zsrv.log"
    echo "  [s2c bytes proxy saw]"; awk '/s2c DGRAM/{n+=$3} END{print n+0}' "$capf" 2>/dev/null
    echo "  [cli tail]"; tail -3 "$d/cli.log" 2>/dev/null
    return
  fi
  # ECN wire-proof requires Linux: IP_RECVTOS CMSG is not reliably populated on macOS loopback (#41).
  if [ -n "$want" ] && echo "$want" | grep -q "ECT\|^CE" && [ "$(uname -s)" != "Linux" ]; then
    ok "$tag (ECN wire-proof skipped on $(uname -s))"
    return
  fi
  if [ -n "$want" ] && ! wire_has "$want" "$capf"; then
    bad "$tag — transfer ok but '$want' NOT seen on wire"
    dump_capture "$capf"
    return
  fi
  ok "$tag${want:+ ✓}"
}

# kp_case: Key Phase bit wire-proof (#40).
# Runs keyupdate through the capturing proxy (which dumps SHORT packet bytes via
# -shorts), then kpcheck removes header protection using the server's SSLKEYLOGFILE
# and asserts the Key Phase bit actually flipped on wire — not just in server logs.
# Only runs against quicgo (the only impl that initiates key updates in the oracle).
kp_case() { # <impl> <sport> <pport>
  local impl=$1 sport=$2 pport=$3
  local d="$TMP/$impl/keyupdate_kp" paths="${CASE_PATHS[keyupdate]}"
  local tag="keyupdate [zquic-server <-> $impl-client | kp-wire-proof]"
  local keylogf="$d/keys.log" shortsf="$d/shorts.txt" capf="$d/capture.txt"
  rm -rf "$d"; mkdir -p "$d/wire"
  TESTCASE=keyupdate CERTS="$CERTS" WWW="$WWW" PORT="$sport" SSLKEYLOGFILE="$keylogf" \
    "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$sport" || { bad "$tag (no server bind)"; stop "$sp"; return; }
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" \
    -capture "$capf" -shorts "$shortsf" >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "$tag (no proxy bind)"; stop "$sp" "$px"; return; }
  local reqs=(); for p in $paths; do reqs+=("https://127.0.0.1:$pport$p"); done
  to "$CLIENT_TIMEOUT" "$BIN/quicgo" client -ca "$CERTS/cert.pem" "$d/wire" "${reqs[@]}" \
    >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  [ $rc -eq 124 ] && { bad "$tag (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$tag (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m; if ! m="$(assert_match "$d/wire" $paths)"; then bad "$tag (transfer: $m)"; return; fi
  if [ ! -x "$KPCHECK" ]; then
    ok "$tag (kpcheck not built — log-only fallback; run oracle/build-refs.sh)"
    return
  fi
  if "$KPCHECK" -keylog "$keylogf" -shorts "$shortsf" >"$d/kpcheck.log" 2>&1; then
    ok "$tag ✓"
  else
    bad "$tag — KP bit did not flip on wire: $(cat "$d/kpcheck.log")"
  fi
}

# versionnegotiation (server property, not per-impl): a client offering an unknown
# version MUST get a Version Negotiation packet (RFC 9000 §6.1). ngtcp2's --version
# forces a greased version. Wire-only: the handshake intentionally does not complete
# (client is pinned to the bad version), so we assert just the VN packet.
vn_case() { # <trigger_impl> <sport> <pport>
  local trig=$1 sport=$2 pport=$3 d="$TMP/server/versionnegotiation"; mkdir -p "$d"; local capf="$d/capture.txt"
  TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$sport" || { bad "versionnegotiation (no server bind)"; stop "$sp"; return; }
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "versionnegotiation (no proxy bind)"; stop "$sp" "$px"; return; }
  # Each client offers an unknown version: ngtcp2 via --version, quiche via its
  # default GREASE wire-version (babababa). Wire-only — the handshake won't complete.
  local vn_rc
  case "$trig" in
    ngtcp2) to 8 "$BIN/ngtcp2-client" -q --download="$d" --exit-on-all-streams-close --version=0x1a2a3a4a \
              127.0.0.1 "$pport" "https://127.0.0.1:$pport/1.bin" >"$d/cli.log" 2>&1; vn_rc=$? ;;
    quiche) to 8 "$BIN/quiche-client" --no-verify --wire-version babababa --http-version HTTP/0.9 \
              --dump-responses "$d" "https://127.0.0.1:$pport/1.bin" >"$d/cli.log" 2>&1; vn_rc=$? ;;
  esac
  stop "$sp" "$px"
  if [ "$vn_rc" -eq 0 ]; then
    bad "versionnegotiation ($trig exited 0 — handshake completed with unknown version; server should have rejected it)"
    return
  fi
  if wire_has "s2c VERSION_NEGOTIATION" "$capf"; then
    ok "versionnegotiation [zquic server emits VN; $trig offers unknown version | wire ✓]"
  else
    bad "versionnegotiation — zquic did not send a VERSION_NEGOTIATION packet"
    dump_capture "$capf"
  fi
}

# chacha20: assert transfer completes when server is pinned to TLS_CHACHA20_POLY1305_SHA256.
# Server-only (server sets preferred_cipher; both quicgo and quiche offer chacha20).
chacha20_case() { # <impl> <port>
  local impl=$1 port=$2 d="$TMP/server/chacha20"; rm -rf "$d/out"; mkdir -p "$d/out"
  TESTCASE=chacha20 CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$port" || { bad "chacha20 [zquic-server <-> $impl-client] (no bind)"; stop "$sp"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$d/out" /1.bin >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "chacha20 [zquic-server <-> $impl-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "chacha20 [zquic-server <-> $impl-client] (client rc=$rc)"; return; }
  local m; if m="$(assert_match "$d/out" "/1.bin")"; then
    ok "chacha20 [zquic-server <-> $impl-client | TLS_CHACHA20_POLY1305_SHA256]"
  else
    bad "chacha20 [zquic-server <-> $impl-client] ($m)"
  fi
}

# v2_case: assert transfer completes with QUIC v2 (0x6b3343cf) server and ref client.
# Uses quicgo -v2 (quic-go supports Version2 via Config.Versions).
v2_case() { # <impl> <port>
  local impl=$1 port=$2 d="$TMP/server/v2"; rm -rf "$d/out"; mkdir -p "$d/out"
  TESTCASE=v2 CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$port" || { bad "v2 [zquic-server <-> $impl-client] (no bind)"; stop "$sp"; return; }
  case "$impl" in
    quicgo) to "$CLIENT_TIMEOUT" "$BIN/quicgo" client -v2 "$d/out" \
              "https://127.0.0.1:$port/1.bin" >"$d/cli.log" 2>&1 ;;
    *) bad "v2: no v2-capable ref impl available"; stop "$sp"; return ;;
  esac
  local rc=$?; stop "$sp"
  [ $rc -eq 124 ] && { bad "v2 [zquic-server <-> $impl-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "v2 [zquic-server <-> $impl-client] (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m; if m="$(assert_match "$d/out" "/1.bin")"; then
    ok "v2 [zquic-server <-> $impl-client | QUIC v2 (0x6b3343cf)]"
  else
    bad "v2 [zquic-server <-> $impl-client] ($m)"
  fi
}

# amplimit_case: assert server doesn't violate the 3× amplification limit (RFC 9000 §8.1).
# Uses DGRAM records in the proxy capture (added for this check) to count actual
# datagram bytes, avoiding the double-count from coalesced packets.
amplimit_case() { # <impl> <sport> <pport>
  local impl=$1 sport=$2 pport=$3 d="$TMP/server/amplificationlimit"
  rm -rf "$d/out"; mkdir -p "$d/out"; local capf="$d/capture.txt"
  TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$sport" || { bad "amplificationlimit (no server bind)"; stop "$sp"; return; }
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "amplificationlimit (no proxy bind)"; stop "$sp" "$px"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$pport" "$d/out" /1.bin >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  [ $rc -eq 124 ] && { bad "amplificationlimit (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "amplificationlimit (client rc=$rc)"; return; }
  local m; if ! m="$(assert_match "$d/out" "/1.bin")"; then bad "amplificationlimit [$impl] (data: $m)"; return; fi
  # Count DGRAM bytes per direction before the first c2s HANDSHAKE (= address
  # validation event per RFC 9001 §4.1.2). Assert s2c ≤ 3× c2s.
  local msg; msg=$(awk '
    BEGIN { c2s=0; s2c=0; done=0 }
    done  { next }
    /^c2s HANDSHAKE/ { done=1; next }
    /^c2s DGRAM/ { c2s += $3 }
    /^s2c DGRAM/ { s2c += $3 }
    END {
      if (c2s == 0) { print "skip: no c2s bytes in capture"; exit 0 }
      if (s2c > c2s * 3) { print "FAIL s2c=" s2c " > 3x c2s=" c2s " (limit=" c2s*3 ")"; exit 1 }
      print "OK s2c=" s2c " <= 3x c2s=" c2s " (limit=" c2s*3 ")"
    }
  ' "$capf"); local awk_rc=$?
  if [ $awk_rc -ne 0 ]; then bad "amplificationlimit [$impl] — $msg"; else ok "amplificationlimit [$impl] — $msg (RFC 9000 §8.1 ✓)"; fi
}

# zerortt_case: assert 0-RTT packets appear on the wire (c2s 0RTT in proxy capture).
# zquic client (TESTCASE=zerortt) makes two sequential connections through the proxy:
# connection 1 warms up a session ticket, connection 2 sends early data (0-RTT).
zerortt_case() { # <impl> <sport> <pport>
  local impl=$1 sport=$2 pport=$3 d="$TMP/$impl/zerortt"
  rm -rf "$d/out"; mkdir -p "$d/out"; local capf="$d/capture.txt"
  ref_server "$impl" "$sport" "$d/rsrv.log" || { bad "zerortt [zquic-client <-> $impl-server] (no server cmd)"; return; }
  local sp=$_LAST_SERVER_PID
  wait_listen "$sp" "$sport" || { bad "zerortt [zquic-client <-> $impl-server] (no bind)"; stop "$sp"; return; }
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "zerortt [zquic-client <-> $impl-server] (no proxy bind)"; stop "$sp" "$px"; return; }
  # Both connections go through the proxy. The capture captures both sequentially.
  to "$CLIENT_TIMEOUT" env TESTCASE=zerortt REQUESTS="https://127.0.0.1:$pport/1.bin" \
    DOWNLOADS="$d/out" "$ZQUIC_CLIENT" >"$d/zcli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  [ $rc -eq 124 ] && { bad "zerortt [zquic-client <-> $impl-server] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "zerortt [zquic-client <-> $impl-server] (client rc=$rc)"; return; }
  local m; if ! m="$(assert_match "$d/out" "/1.bin")"; then bad "zerortt [zquic-client <-> $impl-server] (data: $m)"; return; fi
  if wire_has "c2s 0RTT" "$capf"; then
    ok "zerortt [zquic-client <-> $impl-server | wire: c2s 0RTT ✓]"
  else
    bad "zerortt [zquic-client <-> $impl-server] — transfer ok but 0RTT NOT seen on wire"
    dump_capture "$capf"
  fi
}

# resumption_case: verify TLS 1.3 session ticket resumption (PSK, no early data).
# Server direction: zquic server issues a ticket; quicgo -resumption makes two
# sequential connections and asserts DidResume on conn2. Only runs when impl=quicgo
# (the -resumption flag is specific to the quicgo oracle binary; no quiche equiv).
# Client direction: zquic client (TESTCASE=resumption) + ref server — runs for any
# impl, giving a second independent check of zquic's PSK handling (#23).
resumption_case() { # <impl> <srv_port> <cli_port>
  local impl=$1 sport=$2 cport=$3
  local paths="/1.bin /big.bin"

  # Server direction: only quicgo has the -resumption flag; skip for other impls.
  if [ "$impl" = quicgo ]; then
    local d="$TMP/server/resumption"; rm -rf "$d/out"; mkdir -p "$d/out"
    TESTCASE=resumption CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
    _HARNESS_PIDS+=("$sp")
    wait_listen "$sp" "$sport" || { bad "resumption [zquic-server <-> $impl-client] (no bind)"; stop "$sp"; return; }
    to "$CLIENT_TIMEOUT" "$BIN/quicgo" client -ca "$CERTS/cert.pem" -resumption "$d/out" \
      "https://127.0.0.1:$sport/1.bin" "https://127.0.0.1:$sport/big.bin" >"$d/cli.log" 2>&1; local rc=$?
    stop "$sp"
    [ $rc -eq 124 ] && { bad "resumption [zquic-server <-> $impl-client] (TIMEOUT)"; return; }
    [ $rc -eq 0 ] || { bad "resumption [zquic-server <-> $impl-client] (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
    local m; if m="$(assert_match "$d/out" $paths)"; then
      ok "resumption [zquic-server <-> $impl-client | PSK session ticket]"
    else
      bad "resumption [zquic-server <-> $impl-client] ($m)"
    fi
  fi

  # Client direction: zquic client (TESTCASE=resumption) + ref server
  local d2="$TMP/$impl/resumption_cli"; rm -rf "$d2/out"; mkdir -p "$d2/out"
  ref_server "$impl" "$cport" "$d2/rsrv.log" || { bad "resumption [$impl-server <-> zquic-client] (no server cmd)"; return; }
  local sp2=$_LAST_SERVER_PID
  wait_listen "$sp2" "$cport" || { bad "resumption [$impl-server <-> zquic-client] (no bind)"; stop "$sp2"; return; }
  local reqs="https://127.0.0.1:$cport/1.bin https://127.0.0.1:$cport/big.bin"
  to "$CLIENT_TIMEOUT" env VERIFY_PEER=1 TESTCASE=resumption REQUESTS="$reqs" DOWNLOADS="$d2/out" \
    "$ZQUIC_CLIENT" >"$d2/zcli.log" 2>&1; local rc=$?
  stop "$sp2"
  [ $rc -eq 124 ] && { bad "resumption [$impl-server <-> zquic-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "resumption [$impl-server <-> zquic-client] (client rc=$rc)"; return; }
  local m; if m="$(assert_match "$d2/out" $paths)"; then
    ok "resumption [$impl-server <-> zquic-client | cert-verified]"
  else
    bad "resumption [$impl-server <-> zquic-client] ($m)"
  fi
}

# connectionmigration_case: server advertises a preferred_address (RFC 9000 §9.6);
# ref client migrates to it mid-transfer and the bulk download still completes.
# Server direction only — zquic client does not yet follow preferred_address.
# Two ports: handshake_port (initial connection) + migrate_port (preferred_address).
# ngtcp2 speaks HTTP/3 only, so we pair it with TESTCASE=http3 + CM_PORT (the server
# enables the CM socket whenever CM_PORT is set, regardless of testcase name).
connectionmigration_case() { # <impl> <handshake_port> <migrate_port>
  local impl=$1 hport=$2 mport=$3 d="$TMP/server/connectionmigration"
  local tc="connectionmigration"; [ "$impl" = ngtcp2 ] && tc="http3"
  rm -rf "$d/out"; mkdir -p "$d/out"
  CM_ADDR4=127.0.0.1 CM_PORT="$mport" TESTCASE="$tc" \
    CERTS="$CERTS" WWW="$WWW" PORT="$hport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$hport" || { bad "connectionmigration (no server bind on $hport)"; stop "$sp"; return; }
  wait_listen "$sp" "$mport" || { bad "connectionmigration (no CM socket bind on $mport)"; stop "$sp"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$hport" "$d/out" /big.bin >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "connectionmigration (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "connectionmigration (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m; if ! m="$(assert_match "$d/out" "/big.bin")"; then
    bad "connectionmigration ($m)"; return
  fi
  # Wire proof: server must log [CM] path_migrated, proving the client sent a
  # PATH_CHALLENGE to the preferred_address port and the server adopted it.
  # Without this, a client that ignores preferred_address still transfers big.bin
  # on the original path, yielding a false PASS.
  if ! grep -q '\[CM\] path_migrated' "$d/zsrv.log" 2>/dev/null; then
    bad "connectionmigration (no path_migrated in server log — client did not migrate to 127.0.0.1:$mport)"
    return
  fi
  ok "connectionmigration [zquic-server → $impl preferred_addr 127.0.0.1:$mport]"
}

# statelessreset_case: server with a known RESET_KEY must emit [SRST] when it
# receives a SHORT packet for an unknown DCID (RFC 9000 §10.3).
# Wire proof: server log contains "[SRST] stateless reset sent".
# Flow:
#   1. Start server with RESET_KEY=K (deterministic tokens via HMAC-SHA256).
#   2. Client connects and completes a transfer (server assigns a connection ID).
#   3. Capture the server's log SCID entry (not needed — we inject a random
#      SHORT packet; server must respond to ANY unknown SHORT when key is set).
#   4. Stop server, restart fresh (state lost) with same RESET_KEY.
#   5. Send a crafted SHORT packet (random DCID) via netcat/socat.
#   6. Server generates HMAC(key, dcid) → sends stateless reset → logs [SRST].
statelessreset_case() { # <impl> <port>
  local impl=$1 port=$2
  local d="$TMP/server/statelessreset"
  local key="deadbeefcafebabedeadbeefcafebabe0102030405060708090a0b0c0d0e0f10"
  rm -rf "$d/out"; mkdir -p "$d/out"

  # Phase 1: establish a connection so we know the server works.
  RESET_KEY="$key" TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$port" \
    "$ZQUIC_SERVER" >"$d/zsrv1.log" 2>&1 & local sp1=$!
  _HARNESS_PIDS+=("$sp1")
  wait_listen "$sp1" "$port" || { bad "statelessreset (no server bind phase 1)"; stop "$sp1"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$d/out" /1.bin >"$d/cli.log" 2>&1
  local rc=$?
  stop "$sp1"
  [ $rc -eq 0 ] || { bad "statelessreset (phase 1 transfer failed rc=$rc)"; return; }

  # Phase 2: restart server (state lost) with same RESET_KEY. Send a crafted
  # SHORT packet with a random unknown DCID. Server must send [SRST].
  RESET_KEY="$key" TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$port" \
    "$ZQUIC_SERVER" >"$d/zsrv2.log" 2>&1 & local sp2=$!
  _HARNESS_PIDS+=("$sp2")
  wait_listen "$sp2" "$port" || { bad "statelessreset (no server bind phase 2)"; stop "$sp2"; return; }
  # Craft a 32-byte SHORT packet: first byte has fixed bit=1, long-header bit=0.
  # Remaining bytes are random. The last 16 bytes do NOT match a valid token
  # (random dcid), so AEAD will fail and the server will generate [SRST].
  printf '\x41\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e' | \
    nc -u -w 1 127.0.0.1 "$port" >/dev/null 2>&1 || true
  sleep 1
  stop "$sp2"
  if grep -q '\[SRST\] stateless reset sent' "$d/zsrv2.log" 2>/dev/null; then
    ok "statelessreset [zquic-server sends [SRST] for unknown SHORT CID]"
  else
    bad "statelessreset (no [SRST] in server log — stateless reset not sent)"
  fi
}

# statelessreset_client_case: zquic CLIENT must detect a stateless reset from
# a quicgo server that restarted with the same RESET_KEY (#42).
# Flow:
#   1. Start quicgo server with RESET_KEY=K (deterministic tokens via HMAC-SHA256).
#   2. Route client through proxy with -delayms 20 (40ms RTT cap) so the 2GB sparse
#      file download outlasts the sleep 1 even on the fastest CI loopback.
#   3. Allow time for handshake to complete (quicgo sends NEW_CONNECTION_ID + tokens).
#   4. Kill quicgo and immediately restart with same RESET_KEY at same port.
#   5. Proxy continues forwarding; new server doesn't know the conn → stateless reset.
#   6. Reset token = HMAC(K, client_dcid)[:16] matches zquic's peer_cid_table entry.
#   7. Client logs [SRST] stateless reset received.
statelessreset_client_case() { # <sport> <pport>
  local sport=$1 pport=$2
  local d="$TMP/client/statelessreset_cli"
  local key="deadbeefcafebabedeadbeefcafebabe0102030405060708090a0b0c0d0e0f10"
  rm -rf "$d/out"; mkdir -p "$d/out"

  # Create a temporary www dir with a 2GB sparse file. truncate -s is instant.
  local tw="$d/tmpwww"; mkdir -p "$tw"
  truncate -s 2g "$tw/big.bin" 2>/dev/null || \
    dd if=/dev/zero of="$tw/big.bin" bs=1M count=2048 2>/dev/null

  # Phase 1: quicgo server → proxy (20ms delay) → zquic client.
  # SERVE_RATE_KBPS=512 limits server output to 512 KB/s: 2 GB / 0.5 MB/s = 4096 s,
  # so the client is mid-download at the sleep 1 below regardless of QUIC window growth.
  # (Without rate limiting, the QUIC receive window doubles every RTT and can transfer
  # 2 GB in ~520ms even through a 20ms-delay proxy, making the test flaky.)
  RESET_KEY="$key" SERVE_RATE_KBPS=512 "$BIN/quicgo" server "127.0.0.1:$sport" "$CERTS/cert.pem" "$CERTS/priv.key" "$tw" \
    >"$d/qgsrv1.log" 2>&1 & local sp1=$!
  _HARNESS_PIDS+=("$sp1")
  wait_listen "$sp1" "$sport" || { bad "statelessreset-client (phase 1: no quicgo bind)"; stop "$sp1"; return; }

  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -delayms 20 -tolerant-back \
    >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  wait_listen "$px" "$pport" || { bad "statelessreset-client (no proxy bind)"; stop "$sp1" "$px"; return; }

  to "$CLIENT_TIMEOUT" env VERIFY_PEER=1 TESTCASE=transfer \
    REQUESTS="https://127.0.0.1:$pport/big.bin" DOWNLOADS="$d/out" \
    "$ZQUIC_CLIENT" >"$d/zcli.log" 2>&1 & local cp=$!
  _HARNESS_PIDS+=("$cp")

  # Allow handshake to complete so quicgo sends NEW_CONNECTION_ID with reset tokens.
  sleep 1
  # Kill the original quicgo (state loss simulated). Use SIGKILL so quicgo exits
  # immediately without sending a CONNECTION_CLOSE — a graceful close would cause the
  # zquic client to exit cleanly instead of waiting for a stateless reset.
  kill -9 "$sp1" 2>/dev/null; wait "$sp1" 2>/dev/null || true

  # Phase 2: restart quicgo with same RESET_KEY at same port. The proxy continues
  # forwarding client packets; the new server doesn't know the connection and sends
  # a stateless reset back through the proxy to the client.
  RESET_KEY="$key" "$BIN/quicgo" server "127.0.0.1:$sport" "$CERTS/cert.pem" "$CERTS/priv.key" "$tw" \
    >"$d/qgsrv2.log" 2>&1 & local sp2=$!
  _HARNESS_PIDS+=("$sp2")
  wait_listen "$sp2" "$sport" || { stop "$cp" "$px"; bad "statelessreset-client (phase 2: no quicgo bind)"; stop "$sp2"; return; }

  # Wait for the client to receive the stateless reset and exit (or time out).
  wait "$cp" 2>/dev/null || true
  stop "$sp2" "$px"

  if grep -q '\[SRST\] stateless reset received' "$d/zcli.log" 2>/dev/null; then
    ok "statelessreset-client [quicgo-server restart → zquic-client detects [SRST]]"
  else
    bad "statelessreset-client (no [SRST] in client log — stateless reset not detected)"
    echo "=== statelessreset-client debug ==="
    echo "--- zcli.log ---"; cat "$d/zcli.log" 2>/dev/null
    echo "--- proxy.log ---"; cat "$d/proxy.log" 2>/dev/null
    echo "--- qgsrv1.log (last 5) ---"; tail -5 "$d/qgsrv1.log" 2>/dev/null
    echo "--- qgsrv2.log (last 5) ---"; tail -5 "$d/qgsrv2.log" 2>/dev/null
  fi
}

# idle_timeout_case: server with IDLE_TIMEOUT=3 must emit [IDLE] after 4s of
# silence. Wire proof: server log contains "[IDLE] connection timed out".
# A second transfer after the idle wait succeeds — proving the server is alive
# and freed the slot, and can accept new connections after idle cleanup.
idle_timeout_case() { # <impl> <port>
  local impl=$1 port=$2 d="$TMP/server/idletimeout"
  rm -rf "$d/out" "$d/out2"; mkdir -p "$d/out" "$d/out2"
  IDLE_TIMEOUT=3 TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$port" \
    "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$port" || { bad "idletimeout (no server bind)"; stop "$sp"; return; }
  # First transfer — exits WITHOUT sending CONNECTION_CLOSE (-no-close flag) so the
  # server sees the client vanish and must fire its idle timer.
  # quicgo is the only impl with -no-close; other impls may send CONNECTION_CLOSE.
  local first_rc
  if [ "$impl" = quicgo ]; then
    to "$CLIENT_TIMEOUT" "$BIN/quicgo" client -ca "$CERTS/cert.pem" -no-close \
      "$d/out" "https://127.0.0.1:$port/1.bin" >"$d/cli.log" 2>&1; first_rc=$?
  else
    to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$d/out" /1.bin >"$d/cli.log" 2>&1; first_rc=$?
  fi
  [ $first_rc -eq 0 ] || { bad "idletimeout (first transfer failed rc=$first_rc)"; stop "$sp"; return; }
  # Wait for idle timeout (3s) + margin.
  sleep 4
  # Second transfer — new QUIC connection; proves server is alive after cleanup.
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$d/out2" /2.bin >"$d/cli2.log" 2>&1
  local rc=$?
  stop "$sp"
  [ $rc -eq 0 ] || { bad "idletimeout (second transfer failed rc=$rc — server died or slot not freed)"; return; }
  # Wire proof: server must have logged the idle timeout event.
  if ! grep -q '\[IDLE\] connection timed out' "$d/zsrv.log" 2>/dev/null; then
    bad "idletimeout (no [IDLE] in server log — idle timeout did not fire or was not logged)"
    return
  fi
  ok "idletimeout [zquic-server 3s idle → [IDLE] + accepts fresh conn]"
}

# multiconnect_case: verify zquic handles multiple independent connections.
# Server direction: N sequential ref-client calls, each its own connection, to one
# zquic server — exercises per-connection state teardown and re-init.
# Client direction: zquic client (TESTCASE=multiconnect) opens one connection per
# file URL — exercises the client's per-request connection path.
multiconnect_case() { # <impl> <srv_port> <cli_port>
  local impl=$1 sport=$2 cport=$3
  local paths="/1.bin /big.bin"

  # Server direction: sequential connections from ref client.
  local d="$TMP/server/multiconnect"; rm -rf "$d/out"; mkdir -p "$d/out"
  TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  wait_listen "$sp" "$sport" || { bad "multiconnect [zquic-server <-> $impl-client×2] (no bind)"; stop "$sp"; return; }
  local mok=1 p
  for p in $paths; do
    to "$CLIENT_TIMEOUT" ref_client "$impl" "$sport" "$d/out" "$p" >"$d/cli${p//\//_}.log" 2>&1 || { mok=0; break; }
  done
  stop "$sp"
  if [ "$mok" -ne 1 ]; then bad "multiconnect [zquic-server <-> $impl-client×2] (connection failed)"; return; fi
  local m; if m="$(assert_match "$d/out" $paths)"; then
    ok "multiconnect [zquic-server <-> $impl-client×2 | N sequential connections]"
  else
    bad "multiconnect [zquic-server <-> $impl-client×2] ($m)"
  fi

  # Client direction: zquic client opens one connection per file.
  local d2="$TMP/$impl/multiconnect_cli"; rm -rf "$d2/out"; mkdir -p "$d2/out"
  ref_server "$impl" "$cport" "$d2/rsrv.log" || { bad "multiconnect [$impl-server <-> zquic-client×2] (no server cmd)"; return; }
  local sp2=$_LAST_SERVER_PID
  wait_listen "$sp2" "$cport" || { bad "multiconnect [$impl-server <-> zquic-client×2] (no bind)"; stop "$sp2"; return; }
  local reqs="" pp; for pp in $paths; do reqs="$reqs https://127.0.0.1:$cport$pp"; done
  to "$CLIENT_TIMEOUT" env VERIFY_PEER=1 TESTCASE=multiconnect REQUESTS="${reqs# }" DOWNLOADS="$d2/out" \
    "$ZQUIC_CLIENT" >"$d2/zcli.log" 2>&1; local rc=$?
  stop "$sp2"
  [ $rc -eq 124 ] && { bad "multiconnect [$impl-server <-> zquic-client×2] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "multiconnect [$impl-server <-> zquic-client×2] (client rc=$rc)"; return; }
  local m; if m="$(assert_match "$d2/out" $paths)"; then
    ok "multiconnect [$impl-server <-> zquic-client×2 | cert-verified]"
  else
    bad "multiconnect [$impl-server <-> zquic-client×2] ($m)"
  fi
}

# self_test (#9): prove the harness's OWN assertions still reject the negative case
# — otherwise a refactor could turn assert_match / the wire-checks into no-ops that
# pass everything green. Each check below FAILS the run if an assertion stops
# discriminating. Runs on every full run and via `--self-test`.
self_test() {
  echo ""; echo "═══ self-test: the harness's own assertions ═══"
  local d="$TMP/selftest"; rm -rf "$d"; mkdir -p "$d/match" "$d/out"

  # (a) wire_has — must find a present token and miss an absent one.
  printf 'c2s INITIAL 1200\ns2c HANDSHAKE 1000\nc2s SHORT 80\n' >"$d/syn.cap"
  if wire_has "s2c HANDSHAKE" "$d/syn.cap"; then ok "meta: wire_has finds a present token"; else bad "meta: wire_has missed a present token (no-op!)"; fi
  if wire_has "s2c RETRY" "$d/syn.cap"; then bad "meta: wire_has matched an ABSENT token (no-op!)"; else ok "meta: wire_has rejects an absent token"; fi

  # (b) assert_match — accept a correct copy, reject a corrupted + a missing file.
  cp "$WWW/1.bin" "$d/match/1.bin"
  if assert_match "$d/match" "/1.bin" >/dev/null 2>&1; then ok "meta: assert_match accepts a correct file"; else bad "meta: assert_match rejected a correct file"; fi
  head -c 65536 /dev/zero >"$d/match/1.bin"
  if assert_match "$d/match" "/1.bin" >/dev/null 2>&1; then bad "meta: assert_match accepted a CORRUPTED file (no-op!)"; else ok "meta: assert_match rejects a corrupted file"; fi
  rm -f "$d/match/1.bin"
  if assert_match "$d/match" "/1.bin" >/dev/null 2>&1; then bad "meta: assert_match accepted a MISSING file (no-op!)"; else ok "meta: assert_match rejects a missing file"; fi

  # (c) Falsification on a REAL capture: a normal v1 transfer must classify packets
  #     yet contain NEITHER behavioral token, so the retry/VN wire-checks correctly
  #     FAIL here — the exact false-pass the README claims is guarded against.
  local sti=quicgo; impl_ok quicgo || sti="${IMPLS[0]}"
  local sport=$port pport=$((port + 1)); port=$((port + 2)); local capf="$d/transfer.cap"
  TESTCASE=transfer CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  _HARNESS_PIDS+=("$sp")
  if ! wait_listen "$sp" "$sport"; then bad "meta: self-test server bind"; stop "$sp"; return; fi
  GOMAXPROCS=1 "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" >"$d/proxy.log" 2>&1 & local px=$!
  _HARNESS_PIDS+=("$px")
  if ! wait_listen "$px" "$pport"; then bad "meta: self-test proxy bind"; stop "$sp" "$px"; return; fi
  to "$CLIENT_TIMEOUT" ref_client "$sti" "$pport" "$d/out" /1.bin >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  if [ $rc -ne 0 ]; then bad "meta: self-test transfer failed (rc=$rc) — capture unverifiable"; return; fi
  if wire_has " INITIAL " "$capf" && wire_has " HANDSHAKE " "$capf"; then ok "meta: classifier emits INITIAL+HANDSHAKE on a normal transfer"; else bad "meta: classifier emitted no handshake classes (capture broken)"; fi
  if wire_has "c2s DGRAM" "$capf" && wire_has "s2c DGRAM" "$capf"; then ok "meta: proxy emits per-datagram DGRAM byte-count records"; else bad "meta: proxy emits no DGRAM records (amplificationlimit check broken — rebuild proxy)"; fi
  if wire_has "s2c RETRY" "$capf"; then bad "meta: RETRY seen in a non-retry transfer (false-pass risk)"; else ok "meta: retry wire-check fails on a transfer capture (falsification)"; fi
  if wire_has "s2c VERSION_NEGOTIATION" "$capf"; then bad "meta: VN seen in a v1 handshake (false-pass risk)"; else ok "meta: VN wire-check fails on a v1 capture (falsification)"; fi
  if wire_has "c2s 0RTT" "$capf"; then bad "meta: 0RTT seen in a plain transfer (false-pass risk)"; else ok "meta: zerortt wire-check fails on a plain transfer (falsification)"; fi
  if grep -q "\[KPHS\]" "$d/zsrv.log"; then bad "meta: [KPHS] seen in a plain transfer (keyupdate wire-check false-pass risk)"; else ok "meta: keyupdate log-check fails on plain transfer (falsification)"; fi

  # (d) kpcheck falsification (#40): uniform KP bits (no key update) must be rejected.
  # Two identical all-zero SHORT packets → same HP mask → same KP bit → no flip detected.
  if [ -x "$KPCHECK" ]; then
    local zeros64; zeros64=$(printf '%064d' 0 | tr '0' '0') # 64 zero hex chars (32-byte secret)
    local zeros100; zeros100=$(printf '%0100d' 0 | tr '0' '0') # 100 zero hex chars (50-byte packet)
    local fake_kl="$d/fake.keys" fake_sh="$d/fake.shorts"
    printf 'CLIENT_TRAFFIC_SECRET_0 %s %s\nSERVER_TRAFFIC_SECRET_0 %s %s\n' \
      "$zeros64" "$zeros64" "$zeros64" "$zeros64" >"$fake_kl"
    printf 'c2s-dcid-len 8\ns2c-dcid-len 8\ns2c %s\ns2c %s\n' \
      "$zeros100" "$zeros100" >"$fake_sh"
    if "$KPCHECK" -keylog "$fake_kl" -shorts "$fake_sh" >/dev/null 2>&1; then
      bad "meta: kpcheck PASSED on uniform KP bits (false-pass risk — #40)"
    else
      ok "meta: kpcheck fails when KP bit never flips (falsification ✓)"
    fi
  fi
}

CASES=(); REQUIRE=(); REPEAT=1; SELFTEST=0
while [ $# -gt 0 ]; do
  case "$1" in
    -i | --impl) IMPLS=("$2"); IMPL_SET=1; shift 2 ;;
    --impl=*) IMPLS=("${1#*=}"); IMPL_SET=1; shift ;;
    -r | --require) IFS=', ' read -r -a REQUIRE <<<"$2"; shift 2 ;;
    --require=*) IFS=', ' read -r -a REQUIRE <<<"${1#*=}"; shift ;;
    -n | --repeat) REPEAT="$2"; shift 2 ;;
    --repeat=*) REPEAT="${1#*=}"; shift ;;
    --self-test) SELFTEST=1; shift ;;
    --) shift; CASES+=("$@"); break ;;
    -*) echo "unknown flag: $1" >&2; exit 2 ;;
    *) CASES+=("$1"); shift ;;
  esac
done
# Env fallback for required impls (lets CI forbid a silently-smaller matrix).
if [ ${#REQUIRE[@]} -eq 0 ] && [ -n "${ORACLE_REQUIRE:-}" ]; then
  IFS=', ' read -r -a REQUIRE <<<"$ORACLE_REQUIRE"
fi
# Repeat count: flag wins, else ORACLE_REPEAT env, else 1. Sanitize to an int.
[ "$REPEAT" -eq 1 ] 2>/dev/null && [ -n "${ORACLE_REPEAT:-}" ] && REPEAT="$ORACLE_REPEAT"
case "$REPEAT" in *[!0-9]* | '') REPEAT=1 ;; esac

# Stability mode (#8): loss impairment is SEEDED, not outcome-deterministic — the
# seed fixes the drop *sequence*, but which logical packet is the Nth datagram
# shifts with timing (coalescing, PTO). So re-run the selection N times in fresh
# processes and require EVERY iteration green; latent flakiness fails hard here
# instead of surfacing as an intermittent red. Children carry ORACLE_IN_REPEAT.
if [ "$REPEAT" -gt 1 ] && [ -z "${ORACLE_IN_REPEAT:-}" ]; then
  FWD=()
  [ $IMPL_SET -eq 1 ] && FWD+=(-i "${IMPLS[0]}")
  [ ${#REQUIRE[@]} -gt 0 ] && FWD+=(-r "$(IFS=,; printf '%s' "${REQUIRE[*]}")")
  [ ${#CASES[@]} -gt 0 ] && FWD+=(-- "${CASES[@]}")
  green=0
  echo "stability mode: $REPEAT iterations (all must pass)"
  for k in $(seq 1 "$REPEAT"); do
    echo ""; echo "━━━ iteration $k/$REPEAT ━━━"
    if ORACLE_IN_REPEAT=1 bash "$0" "${FWD[@]}"; then green=$((green + 1)); fi
  done
  echo ""; echo "═════════════════════════════════"
  echo "STABILITY: $green/$REPEAT iterations fully green"
  [ "$green" -eq "$REPEAT" ] && exit 0 || exit 1
fi

[ -x "$ZQUIC_SERVER" ] || { echo "build zquic: zig build"; exit 1; }
[ -x "$PROXY" ] || { echo "missing proxy — run oracle/build-refs.sh"; exit 1; }
# Require the platform-appropriate socket inspection tool (#39).
case "$(uname -s)" in
  Darwin) command -v lsof >/dev/null 2>&1 || \
            { echo "oracle: lsof required on macOS for port-bind checks" >&2; exit 1; } ;;
  *)      command -v ss >/dev/null 2>&1 || \
            { echo "oracle: ss (iproute2) required on Linux for port-bind checks" >&2; exit 1; } ;;
esac
if [ $IMPL_SET -eq 1 ]; then
  for i in "${IMPLS[@]}"; do impl_ok "$i" || { echo "missing ref $i — run oracle/build-refs.sh"; exit 1; }; done
else
  for i in "${ALL_IMPLS[@]}"; do impl_ok "$i" && IMPLS+=("$i"); done
  [ ${#IMPLS[@]} -gt 0 ] || { echo "no reference impls built — run oracle/build-refs.sh"; exit 1; }
  # Surface reduced coverage: a built-but-absent impl is easy to miss otherwise (#7).
  absent=(); for i in "${ALL_IMPLS[@]}"; do impl_ok "$i" || absent+=("$i"); done
  [ ${#absent[@]} -gt 0 ] && echo "note: not built, skipped: ${absent[*]} (run oracle/build-refs.sh to include)"
fi
# Hard-require named impls (anti silent-coverage-reduction, #7): refuse to report a
# smaller green matrix when an impl that MUST be present is missing.
if [ ${#REQUIRE[@]} -gt 0 ]; then
  miss=(); for r in "${REQUIRE[@]}"; do impl_ok "$r" || miss+=("$r"); done
  if [ ${#miss[@]} -gt 0 ]; then
    echo "ERROR: required reference impl(s) not built: ${miss[*]}" >&2
    echo "  must be present (oracle/build-refs.sh) — refusing a smaller green matrix." >&2
    exit 3
  fi
fi

# --self-test (#9): run only the meta-tests (assertions reject their negatives) + exit.
if [ "$SELFTEST" -eq 1 ]; then
  cleanup; port=$PORT_BASE
  self_test
  echo ""; echo "─────────────────────────────────"
  echo "TOTAL: $PASS passed, $FAIL failed"
  [ $FAIL -gt 0 ] && { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
  exit 0
fi

sel_data=("${DATA_CASES[@]}"); sel_prox=("${PROXIED_CASES[@]}")
if [ ${#CASES[@]} -gt 0 ]; then
  sel_data=(); sel_prox=()
  for c in "${CASES[@]}"; do
    # Standalone cases run outside the per-impl loop (server properties / behavioral).
    case "$c" in versionnegotiation|chacha20|v2|amplificationlimit|zerortt|resumption|multiconnect|connectionmigration|idletimeout|statelessreset|statelessresetclient) continue ;; esac
    if [ -n "${WIRE_REQUIRE[$c]:-}${IMPAIR[$c]:-}" ]; then sel_prox+=("$c"); else sel_data+=("$c"); fi
  done
fi

cleanup  # pre-clean any stragglers from a prior run
echo "zquic oracle — impls: ${IMPLS[*]}"
echo "logs:  $TMP"
port=$PORT_BASE
for impl in "${IMPLS[@]}"; do
  echo ""; echo "═══ oracle: $impl ═══"
  for case in "${sel_data[@]}"; do
    skipped "$impl" "$case" && continue
    mkdir -p "$TMP/$impl/$case"
    dp_zquic_server "$impl" "$case" "$port"; port=$((port + 1))
    skip_client "$impl" "$case" || { dp_zquic_client "$impl" "$case" "$port"; port=$((port + 1)); }
  done
  for case in "${sel_prox[@]}"; do
    skipped "$impl" "$case" && continue
    mkdir -p "$TMP/$impl/$case"
    proxied "$impl" "$case" "$port" "$((port + 1))"; port=$((port + 2))
  done
  # Key Phase bit wire-proof (#40): runs only with quicgo (initiates key updates).
  if [ "$impl" = quicgo ] && { [ ${#CASES[@]} -eq 0 ] || printf '%s\n' "${CASES[@]}" | grep -qx "keyupdate"; }; then
    kp_case quicgo "$port" "$((port + 1))"; port=$((port + 2))
  fi
done

# Server-property and standalone behavioral cases. Run on a full run or when named
# explicitly. Each function picks the best available impl for its needs.
_want_svr() { [ ${#CASES[@]} -eq 0 ] || printf '%s\n' "${CASES[@]}" | grep -qx "$1"; }
_any_svr=0
for _sc in versionnegotiation chacha20 v2 amplificationlimit zerortt resumption multiconnect connectionmigration idletimeout statelessreset statelessresetclient; do
  _want_svr "$_sc" && _any_svr=1 && break
done

if [ "$_any_svr" -eq 1 ]; then
  echo ""; echo "═══ oracle: server properties & standalone ═══"

  # versionnegotiation: server must emit VN when client offers an unknown version.
  if _want_svr versionnegotiation; then
    trig=""; impl_ok ngtcp2 && trig=ngtcp2 || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { vn_case "$trig" "$port" "$((port + 1))"; port=$((port + 2)); }
  fi

  # chacha20: transfer must complete when server prefers TLS_CHACHA20_POLY1305_SHA256.
  if _want_svr chacha20; then
    trig=""; impl_ok quicgo && trig=quicgo || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { chacha20_case "$trig" "$port"; port=$((port + 1)); }
  fi

  # v2: transfer must complete with QUIC v2 server and a v2-capable ref client (quicgo -v2).
  if _want_svr v2; then
    impl_ok quicgo && { v2_case quicgo "$port"; port=$((port + 1)); }
  fi

  # amplificationlimit: server must not send > 3× client bytes before address validation.
  if _want_svr amplificationlimit; then
    trig=""; impl_ok quicgo && trig=quicgo || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { amplimit_case "$trig" "$port" "$((port + 1))"; port=$((port + 2)); }
  fi

  # resumption: session ticket issued on conn1; conn2 resumes with PSK (no early data).
  # Server direction uses quicgo -resumption (only impl with that flag). Client
  # direction runs against each available impl for independent PSK coverage (#23).
  if _want_svr resumption; then
    [ -x "$ZQUIC_CLIENT" ] || bad "resumption: $ZQUIC_CLIENT missing — run: zig build"
    for trig in quicgo quiche; do
      impl_ok "$trig" || continue
      resumption_case "$trig" "$port" "$((port + 1))"; port=$((port + 2))
    done
  fi

  # zerortt: 0-RTT packets must appear on the wire (c2s 0RTT in proxy capture).
  # Requires quicgo-server: only quicgo issues early_data-capable session tickets
  # to the zquic client. quiche-server does not, so using it as a fallback would
  # always produce FAIL — skipped entirely when quicgo is not built.
  if _want_svr zerortt; then
    [ -x "$ZQUIC_CLIENT" ] || bad "zerortt: $ZQUIC_CLIENT missing — run: zig build"
    if impl_ok quicgo; then
      zerortt_case quicgo "$port" "$((port + 1))"; port=$((port + 2))
    fi
  fi

  # multiconnect: server handles N sequential connections (data-path); client opens
  # one connection per file (TESTCASE=multiconnect). No proxy needed — data-path only.
  if _want_svr multiconnect; then
    [ -x "$ZQUIC_CLIENT" ] || bad "multiconnect: $ZQUIC_CLIENT missing — run: zig build"
    trig=""; impl_ok quicgo && trig=quicgo || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { multiconnect_case "$trig" "$port" "$((port + 1))"; port=$((port + 2)); }
  fi

  # connectionmigration: server advertises preferred_address; ref client migrates to it
  # mid-transfer and the download must still complete. Two ports: handshake + migrate.
  # Uses ngtcp2 (HTTP/3 mode) — it follows preferred_address by default.
  # quic-go does not implement preferred_address migration ("We don't support
  # connection migration yet" in connection.go) so it cannot trigger this test.
  if _want_svr connectionmigration; then
    trig=""; impl_ok ngtcp2 && trig=ngtcp2
    [ -n "$trig" ] && { connectionmigration_case "$trig" "$port" "$((port + 1))"; port=$((port + 2)); }
  fi

  # idletimeout: server with a 3s idle timeout must emit [IDLE] after silence
  # and still accept a fresh connection afterward (RFC 9000 §10.1 / §10.2).
  # Uses the server-side [IDLE] log as wire proof; no proxy needed.
  if _want_svr idletimeout; then
    trig=""; impl_ok quicgo && trig=quicgo || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { idle_timeout_case "$trig" "$port"; port=$((port + 1)); }
  fi

  # statelessreset: server with RESET_KEY must send [SRST] for unknown SHORT
  # packet after state loss (RFC 9000 §10.3). Uses nc to inject a raw UDP packet.
  if _want_svr statelessreset; then
    trig=""; impl_ok quicgo && trig=quicgo || { impl_ok quiche && trig=quiche; }
    [ -n "$trig" ] && { statelessreset_case "$trig" "$port"; port=$((port + 1)); }
  fi

  # statelessreset-client: zquic client must detect a stateless reset from a
  # quicgo server that restarted with the same RESET_KEY (RFC 9000 §10.3, #42).
  # Requires zquic client binary and quicgo (which supports StatelessResetKey).
  if _want_svr statelessresetclient; then
    [ -x "$ZQUIC_CLIENT" ] || bad "statelessreset-client: $ZQUIC_CLIENT missing — run: zig build"
    impl_ok quicgo && { statelessreset_client_case "$port" "$((port + 1))"; port=$((port + 2)); }
  fi
fi

# Meta-tests on every full run: guarantee the harness's assertions still
# discriminate pass from fail (#9) — they can't silently become no-ops.
[ ${#CASES[@]} -eq 0 ] && self_test

echo ""; echo "─────────────────────────────────"
echo "TOTAL: $PASS passed, $FAIL failed"
[ $FAIL -gt 0 ] && { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
exit 0
