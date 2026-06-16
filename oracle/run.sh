#!/usr/bin/env bash
#
# zquic oracle harness — fast, Docker-free interop against reference impls.
#
# Two kinds of checks:
#   data-path cases  (handshake/transfer/multiplexing): run BOTH directions
#     (zquic-server <-> ref-client and ref-server <-> zquic-client) and assert
#     downloaded bytes hash-match the served files. The independent impl is the
#     judge — it rejects non-conformant wire bytes/crypto/params.
#   behavioral cases (retry, ...): route through the capturing proxy and assert
#     the protocol mechanism actually appeared ON THE WIRE (e.g. a Retry packet),
#     not merely that the file transferred. QUIC long-header packet types are
#     unmasked by header protection, so they're classifiable without keys.
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

declare -A CASE_PATHS=(
  [handshake]="/1.bin"
  [transfer]="/big.bin"
  [multiplexing]="/1.bin /2.bin /3.bin /4.bin"
  [retry]="/big.bin"
)
# Behavioral cases: server TESTCASE -> required wire token (class the proxy must see).
declare -A WIRE_REQUIRE=(
  [retry]="s2c RETRY"
)
DATA_CASES=(handshake transfer multiplexing)
BEHAVIORAL_CASES=(retry)

IMPLS=(quicgo)
PASS=0; FAIL=0; FAILED=()

ok()  { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED+=("$*"); }

wait_listen() {
  local pid=$1 port=$2 i
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 1
    lsof -nP -iUDP:"$port" -a -p "$pid" 2>/dev/null | grep -q ":$port" && return 0
    sleep 0.1
  done
  return 1
}

assert_match() { # <dir> <path...>
  local dir=$1; shift; local p base
  for p in "$@"; do
    base="$(basename "$p")"
    [ -f "$dir/$base" ] || { echo "missing $base"; return 1; }
    [ "$(shasum -a256 "$WWW/$base" | awk '{print $1}')" = \
      "$(shasum -a256 "$dir/$base" | awk '{print $1}')" ] || { echo "hash mismatch $base"; return 1; }
  done
}

ref_client() { # <impl> <port> <outdir> <path...>
  local impl=$1 port=$2 out=$3; shift 3
  local urls=() p; for p in "$@"; do urls+=("https://127.0.0.1:$port$p"); done
  case "$impl" in quicgo) "$BIN/quicgo" client "$out" "${urls[@]}" ;; *) return 2 ;; esac
}
ref_server() { # <impl> <port> <logfile> -> pid
  local impl=$1 port=$2 logf=$3
  case "$impl" in
    quicgo) "$BIN/quicgo" server "127.0.0.1:$port" "$CERTS/cert.pem" "$CERTS/priv.key" "$WWW" >"$logf" 2>&1 & echo $! ;;
    *) return 2 ;;
  esac
}

# data-path, dir A: zquic server <-> ref client
dp_zquic_server() {
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local out="$d/zsrv"; rm -rf "$out"; mkdir -p "$out"
  TESTCASE="$case" CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  wait_listen "$sp" "$port" || { bad "$case [zquic-server <-> $impl-client] (no bind)"; kill "$sp" 2>/dev/null; return; }
  local msg rc; msg="$(ref_client "$impl" "$port" "$out" $paths 2>&1)"; rc=$?
  kill "$sp" 2>/dev/null
  [ $rc -eq 0 ] || { bad "$case [zquic-server <-> $impl-client] (client rc=$rc: ${msg:0:50})"; return; }
  if msg="$(assert_match "$out" $paths)"; then ok "$case [zquic-server <-> $impl-client]"; else bad "$case [zquic-server <-> $impl-client] ($msg)"; fi
}
# data-path, dir B: ref server <-> zquic client
dp_zquic_client() {
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}" d="$TMP/$impl/$case"
  local out="$d/zcli"; rm -rf "$out"; mkdir -p "$out"
  local sp; sp="$(ref_server "$impl" "$port" "$d/rsrv.log")"
  wait_listen "$sp" "$port" || { bad "$case [$impl-server <-> zquic-client] (no bind)"; kill "$sp" 2>/dev/null; return; }
  local reqs="" p; for p in $paths; do reqs="$reqs https://127.0.0.1:$port$p"; done
  TESTCASE="$case" REQUESTS="${reqs# }" DOWNLOADS="$out" "$ZQUIC_CLIENT" >"$d/zcli.log" 2>&1; local rc=$?
  kill "$sp" 2>/dev/null
  [ $rc -eq 0 ] || { bad "$case [$impl-server <-> zquic-client] (client rc=$rc)"; return; }
  local m; if m="$(assert_match "$out" $paths)"; then ok "$case [$impl-server <-> zquic-client]"; else bad "$case [$impl-server <-> zquic-client] ($m)"; fi
}

# behavioral: zquic server <-> [proxy capture] <-> ref client; assert wire token + hash
behavioral() {
  local impl=$1 case=$2 sport=$3 pport=$4 paths="${CASE_PATHS[$2]}" want="${WIRE_REQUIRE[$2]}" d="$TMP/$impl/$case"
  local out="$d/wire"; rm -rf "$out"; mkdir -p "$out"; local capf="$d/capture.txt"
  TESTCASE="$case" CERTS="$CERTS" WWW="$WWW" PORT="$sport" "$ZQUIC_SERVER" >"$d/zsrv.log" 2>&1 & local sp=$!
  wait_listen "$sp" "$sport" || { bad "$case [wire: $want] (no server bind)"; kill "$sp" 2>/dev/null; return; }
  "$PROXY" -listen "127.0.0.1:$pport" -target "127.0.0.1:$sport" -capture "$capf" >"$d/proxy.log" 2>&1 & local px=$!
  wait_listen "$px" "$pport" || { bad "$case [wire: $want] (no proxy bind)"; kill "$sp" "$px" 2>/dev/null; return; }
  local msg rc; msg="$(ref_client "$impl" "$pport" "$out" $paths 2>&1)"; rc=$?
  kill "$sp" "$px" 2>/dev/null
  [ $rc -eq 0 ] || { bad "$case [wire: $want] (client rc=$rc: ${msg:0:40})"; return; }
  if ! msg="$(assert_match "$out" $paths)"; then bad "$case [wire: $want] (transfer: $msg)"; return; fi
  if grep -q "$want" "$capf" 2>/dev/null; then
    ok "$case [zquic-server <-> $impl-client | wire: $want ✓]"
  else
    bad "$case [wire: $want] — transfer ok but mechanism NOT seen on wire"
  fi
}

IMPLS_SEL=(); CASES=()
while getopts "i:" opt; do case $opt in i) IMPLS=("$OPTARG") ;; esac; done
shift $((OPTIND-1)); [ $# -gt 0 ] && CASES=("$@")

[ -x "$ZQUIC_SERVER" ] || { echo "build zquic: zig build"; exit 1; }
[ -x "$PROXY" ] || { echo "missing proxy — run oracle/build-refs.sh"; exit 1; }
for i in "${IMPLS[@]}"; do [ -x "$BIN/$i" ] || { echo "missing ref $i — run oracle/build-refs.sh"; exit 1; }; done

# Select cases
sel_data=("${DATA_CASES[@]}"); sel_beh=("${BEHAVIORAL_CASES[@]}")
if [ ${#CASES[@]} -gt 0 ]; then
  sel_data=(); sel_beh=()
  for c in "${CASES[@]}"; do
    [ -n "${WIRE_REQUIRE[$c]:-}" ] && sel_beh+=("$c") || sel_data+=("$c")
  done
fi

echo "zquic oracle — impls: ${IMPLS[*]}"
port=$PORT_BASE
for impl in "${IMPLS[@]}"; do
  echo ""; echo "═══ oracle: $impl ═══"
  for case in "${sel_data[@]}"; do
    mkdir -p "$TMP/$impl/$case"
    dp_zquic_server "$impl" "$case" "$port"; port=$((port+1))
    dp_zquic_client "$impl" "$case" "$port"; port=$((port+1))
  done
  for case in "${sel_beh[@]}"; do
    mkdir -p "$TMP/$impl/$case"
    behavioral "$impl" "$case" "$port" "$((port+1))"; port=$((port+2))
  done
done

echo ""; echo "─────────────────────────────────"
echo "TOTAL: $PASS passed, $FAIL failed"
[ $FAIL -gt 0 ] && { printf '  - %s\n' "${FAILED[@]}"; exit 1; }
exit 0
