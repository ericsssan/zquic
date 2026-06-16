#!/usr/bin/env bash
#
# zquic oracle harness — fast, Docker-free interop against reference impls.
#
# Runs each test case in BOTH directions (zquic-server <-> ref-client and
# ref-server <-> zquic-client) over localhost UDP, and asserts the downloaded
# bytes hash-match the served files. See PLAN.md.
#
# Usage:
#   oracle/run.sh [-i impl] [case...]      # default: all impls, all clean cases
#   oracle/run.sh -i quicgo transfer multiplexing
#
set -u

ORACLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$ORACLE")"
ZQUIC_SERVER="$ROOT/zig-out/bin/server"
ZQUIC_CLIENT="$ROOT/zig-out/bin/client"
CERTS="$ORACLE/certs"
WWW="$ORACLE/www"
BIN="$ORACLE/.cache/bin"
TMP="$ORACLE/.cache/run"
PORT_BASE=4500

# Test cases → space-separated request paths served from $WWW.
declare -A CASE_PATHS=(
  [handshake]="/1.bin"
  [transfer]="/big.bin"
  [multiplexing]="/1.bin /2.bin /3.bin /4.bin"
)
CLEAN_CASES=(handshake transfer multiplexing)

IMPLS=(quicgo)
PASS=0; FAIL=0; FAILED_CASES=()

log()  { printf '%s\n' "$*"; }
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$*"; PASS=$((PASS+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$*"; FAIL=$((FAIL+1)); FAILED_CASES+=("$*"); }

# Wait until $1 (pid) has bound UDP $2, or the pid dies. Returns 1 on failure.
wait_listen() {
  local pid=$1 port=$2 i
  for i in $(seq 1 50); do
    kill -0 "$pid" 2>/dev/null || return 1
    lsof -nP -iUDP:"$port" -a -p "$pid" 2>/dev/null | grep -q ":$port" && return 0
    sleep 0.1
  done
  return 1
}

# assert_match <download_dir> <path...>  — each downloaded basename hash-matches $WWW.
assert_match() {
  local dir=$1; shift
  local p base
  for p in "$@"; do
    base="$(basename "$p")"
    [ -f "$dir/$base" ] || { echo "missing $base"; return 1; }
    [ "$(shasum -a256 "$WWW/$base" | awk '{print $1}')" = \
      "$(shasum -a256 "$dir/$base" | awk '{print $1}')" ] || { echo "hash mismatch $base"; return 1; }
  done
  return 0
}

# ---- reference endpoint adapters --------------------------------------------
# ref_client <impl> <port> <outdir> <path...>
ref_client() {
  local impl=$1 port=$2 out=$3; shift 3
  local urls=() p
  for p in "$@"; do urls+=("https://127.0.0.1:$port$p"); done
  case "$impl" in
    quicgo) "$BIN/quicgo" client "$out" "${urls[@]}" ;;
    *) echo "unknown impl $impl"; return 2 ;;
  esac
}
# ref_server <impl> <port> <logfile> -> echoes pid
ref_server() {
  local impl=$1 port=$2 logf=$3
  case "$impl" in
    quicgo) "$BIN/quicgo" server "127.0.0.1:$port" "$CERTS/cert.pem" "$CERTS/priv.key" "$WWW" >"$logf" 2>&1 & echo $! ;;
    *) return 2 ;;
  esac
}

# ---- one case, one direction ------------------------------------------------
# dir A: zquic server  <-> ref client
run_zquic_server() {
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}"
  local out="$TMP/$impl/$case/zsrv"; rm -rf "$out"; mkdir -p "$out"
  TESTCASE="$case" CERTS="$CERTS" WWW="$WWW" PORT="$port" "$ZQUIC_SERVER" >"$TMP/$impl/$case/zsrv.log" 2>&1 &
  local sp=$!
  if ! wait_listen "$sp" "$port"; then bad "$case [zquic-server <-> $impl-client] (server didn't bind)"; kill "$sp" 2>/dev/null; return; fi
  local msg; msg="$(ref_client "$impl" "$port" "$out" $paths 2>&1)"; local rc=$?
  kill "$sp" 2>/dev/null
  if [ $rc -ne 0 ]; then bad "$case [zquic-server <-> $impl-client] (client rc=$rc: ${msg:0:60})"; return; fi
  if msg="$(assert_match "$out" $paths)"; then ok "$case [zquic-server <-> $impl-client]"; else bad "$case [zquic-server <-> $impl-client] ($msg)"; fi
}
# dir B: ref server <-> zquic client
run_zquic_client() {
  local impl=$1 case=$2 port=$3 paths="${CASE_PATHS[$2]}"
  local out="$TMP/$impl/$case/zcli"; rm -rf "$out"; mkdir -p "$out"
  local sp; sp="$(ref_server "$impl" "$port" "$TMP/$impl/$case/rsrv.log")"
  if ! wait_listen "$sp" "$port"; then bad "$case [$impl-server <-> zquic-client] (server didn't bind)"; kill "$sp" 2>/dev/null; return; fi
  local reqs="" p; for p in $paths; do reqs="$reqs https://127.0.0.1:$port$p"; done
  TESTCASE="$case" REQUESTS="${reqs# }" DOWNLOADS="$out" "$ZQUIC_CLIENT" >"$TMP/$impl/$case/zcli.log" 2>&1
  local rc=$?
  kill "$sp" 2>/dev/null
  if [ $rc -ne 0 ]; then bad "$case [$impl-server <-> zquic-client] (client rc=$rc)"; return; fi
  local m; if m="$(assert_match "$out" $paths)"; then ok "$case [$impl-server <-> zquic-client]"; else bad "$case [$impl-server <-> zquic-client] ($m)"; fi
}

# ---- main -------------------------------------------------------------------
CASES=("${CLEAN_CASES[@]}")
while getopts "i:" opt; do case $opt in i) IMPLS=("$OPTARG") ;; esac; done
shift $((OPTIND-1))
[ $# -gt 0 ] && CASES=("$@")

[ -x "$ZQUIC_SERVER" ] || { echo "build zquic first: zig build"; exit 1; }
for impl in "${IMPLS[@]}"; do [ -x "$BIN/$impl" ] || { echo "missing ref $impl — run oracle/build-refs.sh"; exit 1; }; done

log "zquic oracle — impls: ${IMPLS[*]} | cases: ${CASES[*]}"
port=$PORT_BASE
for impl in "${IMPLS[@]}"; do
  log ""; log "═══ oracle: $impl ═══"
  for case in "${CASES[@]}"; do
    mkdir -p "$TMP/$impl/$case"
    run_zquic_server "$impl" "$case" "$port"; port=$((port+1))
    run_zquic_client "$impl" "$case" "$port"; port=$((port+1))
  done
done

log ""
log "─────────────────────────────────"
log "TOTAL: $PASS passed, $FAIL failed"
if [ $FAIL -gt 0 ]; then printf '  - %s\n' "${FAILED_CASES[@]}"; exit 1; fi
