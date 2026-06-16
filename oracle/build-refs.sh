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

# ---- ngtcp2 (optional: HTTP/3 oracle; local source + cmake + OpenSSL 3.5+) ----
# Builds osslclient/osslserver from a sibling ../ngtcp2 checkout against brew's
# OpenSSL 3 (has the QUIC API), libev, and libnghttp3. Skips gracefully if the
# source or deps are absent (e.g. CI), where the quic-go oracle still runs.
NGTCP2_SRC="$(cd "$ORACLE/.." && pwd)/../ngtcp2"
if [ -x "$BIN/ngtcp2-client" ] && [ -x "$BIN/ngtcp2-server" ]; then
  echo "==> ngtcp2 oracle present (skip)"
elif [ -d "$NGTCP2_SRC" ] && command -v cmake >/dev/null 2>&1 && command -v brew >/dev/null 2>&1; then
  SSL="$(brew --prefix openssl@3 2>/dev/null)"; EV="$(brew --prefix libev 2>/dev/null)"; H3="$(brew --prefix libnghttp3 2>/dev/null)"
  if [ -e "$SSL/lib/libssl.dylib" ] && [ -e "$EV/lib/libev.dylib" ] && [ -e "$H3/lib/libnghttp3.dylib" ]; then
    echo "==> building ngtcp2 (HTTP/3 oracle) — this is slow the first time"
    if ( cd "$NGTCP2_SRC" \
         && git submodule update --init >/dev/null 2>&1 \
         && PKG_CONFIG_PATH="$EV/lib/pkgconfig:$H3/lib/pkgconfig:$SSL/lib/pkgconfig" \
            cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_OPENSSL=ON \
              -DOPENSSL_ROOT_DIR="$SSL" -DCMAKE_PREFIX_PATH="$EV;$H3" -DENABLE_EXAMPLES=ON >/dev/null 2>&1 \
         && cmake --build build -j4 --target osslclient osslserver >/dev/null 2>&1 ); then
      ln -sf "$NGTCP2_SRC/build/examples/osslclient" "$BIN/ngtcp2-client"
      ln -sf "$NGTCP2_SRC/build/examples/osslserver" "$BIN/ngtcp2-server"
      echo "==> ngtcp2 built"
    else
      echo "==> ngtcp2 build failed — skipping (quic-go oracle still runs)"
    fi
  else
    echo "==> ngtcp2 deps missing — skip. Install: brew install openssl@3 libev libnghttp3"
  fi
else
  echo "==> ngtcp2 source (../ngtcp2) or cmake/brew not found — skip (HTTP/3 oracle)"
fi

# ---- quiche (cargo) ---------------------------------------------------------- TODO

echo "==> refs ready in $BIN:"
ls -1 "$BIN"
