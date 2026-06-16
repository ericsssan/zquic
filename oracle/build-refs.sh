#!/usr/bin/env bash
#
# Build + cache reference implementations and test fixtures for the oracle
# harness. Idempotent: skips anything already present. See PLAN.md.
#
set -eu

ORACLE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="$ORACLE/.cache/bin"
CERTS="$ORACLE/certs"
WWW="$ORACLE/www"
mkdir -p "$BIN" "$CERTS" "$WWW" "$ORACLE/downloads"

# ---- test fixtures ----------------------------------------------------------
if [ ! -f "$CERTS/cert.pem" ] || [ ! -f "$CERTS/priv.key" ]; then
  echo "==> generating P-256 cert + PKCS#8 key"
  openssl ecparam -name prime256v1 -genkey -noout -out "$CERTS/ec.key" 2>/dev/null
  openssl pkcs8 -topk8 -nocrypt -in "$CERTS/ec.key" -out "$CERTS/priv.key" 2>/dev/null
  openssl req -new -x509 -key "$CERTS/priv.key" -out "$CERTS/cert.pem" -days 825 \
    -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:server,IP:127.0.0.1" 2>/dev/null
  rm -f "$CERTS/ec.key"
fi
if [ ! -f "$WWW/big.bin" ]; then
  echo "==> generating www test files"
  for f in 1.bin 2.bin 3.bin 4.bin; do head -c 65536 /dev/urandom > "$WWW/$f"; done
  head -c 1048576 /dev/urandom > "$WWW/big.bin"
fi

# ---- capturing proxy (pure go stdlib) ---------------------------------------
if [ ! -x "$BIN/proxy" ]; then
  echo "==> building capturing proxy"
  ( cd "$ORACLE/refs/proxy" && go build -o "$BIN/proxy" . )
else
  echo "==> proxy present (skip)"
fi

# ---- quic-go (pure go build) ------------------------------------------------
if [ ! -x "$BIN/quicgo" ]; then
  echo "==> building quic-go oracle"
  ( cd "$ORACLE/refs/quicgo" && go build -o "$BIN/quicgo" . )
else
  echo "==> quic-go oracle present (skip)"
fi

# ---- ngtcp2 (cmake + quictls) -- TODO (Phase 3) -----------------------------
# ngtcp2 source at ../../ngtcp2; build h09client/h09server against brew quictls.
#
# ---- quiche (cargo) ---------------------------------------------------------- TODO (Phase 3)

echo "==> refs ready in $BIN:"
ls -1 "$BIN"
