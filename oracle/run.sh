#!/usr/bin/env bash
#
# zquic oracle harness — fast, Docker-free interop against reference impls.
#
# SCOPE (what actually ships today): 1 reference impl (quic-go); data-path cases
# handshake/transfer/multiplexing in BOTH directions; behavioral case `retry`
# in the zquic-server direction only. ngtcp2/quiche, impairment, and the other
# interop cases are not yet implemented — see PLAN.md.
#
# Two kinds of checks:
#   data-path: assert downloaded bytes hash-match the served files. The
#     independent impl is the judge of wire codec / crypto / transport params.
#     When the ref CLIENT talks to the zquic server it ALSO verifies zquic's
#     certificate against the local CA (real TLS-auth oracle). NOTE: the reverse
#     direction does NOT verify — zquic's own client does not validate certs, so
#     ref-server <-> zquic-client covers wire/crypto but NOT the ref's cert.
#   behavioral: route through the capturing proxy and assert the mechanism
#     actually appeared ON THE WIRE (e.g. a Retry packet), not just that the file
#     transferred.
#
# Usage: oracle/run.sh [-i impl] [case...]
#
set -u

ORACLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$ORACLE")"
ZQUIC_SERVER="$ROOT/zig-out/bin/server"
ZQUIC_CLIENT="$ROOT/zig-out/bin/client"
CERTS="$ORACLE/certs"; WWW="$ORACLE/www"; BIN="$ORACLE/.cache/bin"; TMP="$ORACLE/.cache/run"
PROXY="$BIN/proxy"
PORT_BASE=4500
CLIENT_TIMEOUT=25   # seconds; loopback handshake+1MB is <1s, so this only catches hangs

declare -A CASE_PATHS=(
  [handshake]="/1.bin"
  [transfer]="/big.bin"
  [multiplexing]="/1.bin /2.bin /3.bin /4.bin"
  [retry]="/big.bin"
  [handshakeloss]="/1.bin"
  [transferloss]="/big.bin"
)
# Behavioral cases: required wire token (class the proxy capture must contain).
declare -A WIRE_REQUIRE=( [retry]="s2c RETRY" )
# Proxy impairment flags (deterministic via fixed seed) — tests loss recovery.
declare -A IMPAIR=( [handshakeloss]="-loss 30 -seed 7" [transferloss]="-loss 6 -seed 7" )
# zquic TESTCASE to pass to the endpoints (default = case name). Loss cases just
# serve/fetch like transfer; the impairment is injected by the proxy.
declare -A TC=( [handshakeloss]="transfer" [transferloss]="transfer" )
DATA_CASES=(handshake transfer multiplexing)
PROXIED_CASES=(retry handshakeloss transferloss)
IMPLS=(quicgo)
PASS=0; FAIL=0; FAILED=()

ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED+=("$*"); }

# Kill only this harness's own binaries (full paths) — safe pre-clean + on exit.
cleanup() {
  for b in "$ZQUIC_SERVER" "$ZQUIC_CLIENT" "$PROXY" "$BIN"/quicgo "$BIN"/ngtcp2 "$BIN"/quiche; do
    [ -e "$b" ] && pkill -f "$b" 2>/dev/null
  done
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

# Is UDP `port` bound? Portable across macOS (lsof) and Linux (ss). Ports are
# fresh + pre-cleaned, so a port-level check is sufficient. (-P/-n: numeric;
# 4500 prints as the service name "ipsec-msft" otherwise.)
port_bound() {
  local port=$2
  if command -v lsof >/dev/null 2>&1; then
    lsof -nP -iUDP:"$port" 2>/dev/null | grep -q ":$port"
  elif command -v ss >/dev/null 2>&1; then
    ss -lun 2>/dev/null | grep -qE "[:.]$port([^0-9]|$)"
  else
    return 1
  fi
}

# Wait until pid has bound UDP port, or it dies. Polls precisely for ~2s; if the
# socket tool can't confirm but the process is alive, proceeds anyway (QUIC
# retransmits a lost Initial, so a slightly-early client still connects).
wait_listen() {
  local pid=$1 port=$2 i
  for i in $(seq 1 20); do
    kill -0 "$pid" 2>/dev/null || return 1
    port_bound "$pid" "$port" && return 0
    sleep 0.1
  done
  kill -0 "$pid" 2>/dev/null
}
stop() { kill "$@" 2>/dev/null; wait "$@" 2>/dev/null; }

assert_match() { # <dir> <path...>
  local dir=$1; shift; local p base
  for p in "$@"; do
    base="$(basename "$p")"
    [ -f "$dir/$base" ] || { echo "missing $base"; return 1; }
    [ "$(h256 "$WWW/$base")" = "$(h256 "$dir/$base")" ] || { echo "hash mismatch $base"; return 1; }
  done
}

# ref_client: MUST be invoked only via `to` (it exec's, replacing the subshell so
# the timeout can kill the real process). Always verifies the zquic cert (-ca).
ref_client() { # <impl> <port> <outdir> <path...>
  local impl=$1 port=$2 out=$3; shift 3
  local urls=() p; for p in "$@"; do urls+=("https://127.0.0.1:$port$p"); done
  case "$impl" in
    quicgo) exec "$BIN/quicgo" client -ca "$CERTS/cert.pem" "$out" "${urls[@]}" ;;
    *) echo "unknown impl $impl" >&2; exit 2 ;;
  esac
}
ref_server() { # <impl> <port> <logfile> -> pid (binary backgrounded; pid is the binary)
  local impl=$1 port=$2 logf=$3
  case "$impl" in
    quicgo) "$BIN/quicgo" server "127.0.0.1:$port" "$CERTS/cert.pem" "$CERTS/priv.key" "$WWW" >"$logf" 2>&1 & echo $! ;;
    *) return 2 ;;
  esac
}

dp_zquic_server() { # zquic server <-> ref client (ref verifies zquic cert)
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local out="$d/zsrv"; rm -rf "$out"; mkdir -p "$out"
  TESTCASE="$case" CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  wait_listen "$sp" "$port" || { bad "$case [zquic-server <-> $impl-client] (no bind)"; stop "$sp"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$port" "$out" $paths >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "$case [zquic-server <-> $impl-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$case [zquic-server <-> $impl-client] (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m; if m="$(assert_match "$out" $paths)"; then ok "$case [zquic-server <-> $impl-client | cert-verified]"; else bad "$case [zquic-server <-> $impl-client] ($m)"; fi
}
dp_zquic_client() { # ref server <-> zquic client (no cert verify — zquic client limitation)
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local out="$d/zcli"; rm -rf "$out"; mkdir -p "$out"
  local sp; sp="$(ref_server "$impl" "$port" "$d/rsrv.log")"
  wait_listen "$sp" "$port" || { bad "$case [$impl-server <-> zquic-client] (no bind)"; stop "$sp"; return; }
  local reqs="" p; for p in $paths; do reqs="$reqs https://127.0.0.1:$port$p"; done
  to "$CLIENT_TIMEOUT" env TESTCASE="$case" REQUESTS="${reqs# }" DOWNLOADS="$out" "$ZQUIC_CLIENT" >"$d/zcli.log" 2>&1; local rc=$?
  stop "$sp"
  [ $rc -eq 124 ] && { bad "$case [$impl-server <-> zquic-client] (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$case [$impl-server <-> zquic-client] (client rc=$rc)"; return; }
  local m; if m="$(assert_match "$out" $paths)"; then ok "$case [$impl-server <-> zquic-client]"; else bad "$case [$impl-server <-> zquic-client] ($m)"; fi
}
# proxied: zquic server <-> [proxy: capture (+optional impairment)] <-> ref client.
# Always asserts hash. If WIRE_REQUIRE[case] is set, also asserts the mechanism
# appears on the wire. If IMPAIR[case] is set, the proxy injects loss/delay.
proxied() {
  local impl=$1 case=$2 sport=$3 pport=$4 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local want="${WIRE_REQUIRE[$case]:-}" impair="${IMPAIR[$case]:-}" tc="${TC[$case]:-$case}"
  local tag="$case [zquic-server <-> $impl-client${impair:+ | impair:$impair}${want:+ | wire: $want}]"
  local out="$d/wire"; rm -rf "$out"; mkdir -p "$out"; local capf="$d/capture.txt"
  TESTCASE="$tc" CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  wait_listen "$sp" "$sport" || { bad "$tag (no server bind)"; stop "$sp"; return; }
  "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" $impair >"$d/proxy.log" 2>&1 & local px=$!
  wait_listen "$px" "$pport" || { bad "$tag (no proxy bind)"; stop "$sp" "$px"; return; }
  to "$CLIENT_TIMEOUT" ref_client "$impl" "$pport" "$out" $paths >"$d/cli.log" 2>&1; local rc=$?
  stop "$sp" "$px"
  [ $rc -eq 124 ] && { bad "$tag (TIMEOUT)"; return; }
  [ $rc -eq 0 ] || { bad "$tag (client rc=$rc: $(tail -1 "$d/cli.log"))"; return; }
  local m; if ! m="$(assert_match "$out" $paths)"; then bad "$tag (transfer: $m)"; return; fi
  if [ -n "$want" ] && ! grep -q "$want" "$capf" 2>/dev/null; then
    bad "$tag — transfer ok but mechanism NOT seen on wire"; return
  fi
  ok "$tag${want:+ ✓}"
}

CASES=()
while getopts "i:" opt; do case $opt in i) IMPLS=("$OPTARG") ;; esac; done
shift $((OPTIND - 1)); [ $# -gt 0 ] && CASES=("$@")

[ -x "$ZQUIC_SERVER" ] || { echo "build zquic: zig build"; exit 1; }
[ -x "$PROXY" ] || { echo "missing proxy — run oracle/build-refs.sh"; exit 1; }
for i in "${IMPLS[@]}"; do [ -x "$BIN/$i" ] || { echo "missing ref $i — run oracle/build-refs.sh"; exit 1; }; done

sel_data=("${DATA_CASES[@]}"); sel_prox=("${PROXIED_CASES[@]}")
if [ ${#CASES[@]} -gt 0 ]; then
  sel_data=(); sel_prox=()
  for c in "${CASES[@]}"; do
    if [ -n "${WIRE_REQUIRE[$c]:-}${IMPAIR[$c]:-}" ]; then sel_prox+=("$c"); else sel_data+=("$c"); fi
  done
fi

cleanup  # pre-clean any stragglers from a prior run
echo "zquic oracle — impls: ${IMPLS[*]}"
port=$PORT_BASE
for impl in "${IMPLS[@]}"; do
  echo ""; echo "═══ oracle: $impl ═══"
  for case in "${sel_data[@]}"; do
    mkdir -p "$TMP/$impl/$case"
    dp_zquic_server "$impl" "$case" "$port"; port=$((port + 1))
    dp_zquic_client "$impl" "$case" "$port"; port=$((port + 1))
  done
  for case in "${sel_prox[@]}"; do
    mkdir -p "$TMP/$impl/$case"
    proxied "$impl" "$case" "$port" "$((port + 1))"; port=$((port + 2))
  done
done

echo ""; echo "─────────────────────────────────"
echo "TOTAL: $PASS passed, $FAIL failed"
[ $FAIL -gt 0 ] && { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
exit 0
