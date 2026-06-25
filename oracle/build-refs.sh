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
# loss.bin: 768 KiB, deliberately BELOW quiche's default initial_max_stream_data
# (1,000,000). The seeded-loss / corruption transfer cases serve this instead of
# big.bin so they do not depend on a MAX_STREAM_DATA window extension. big.bin
# (1 MB) exceeds quiche's stream FC limit, so EVERY transfer of it needs the peer
# to extend the window; under heavy loss the peer's consumption (and thus its
# extension) lags past the idle timeout — a client flow-control behavior, not a
# server defect, and the dominant residual flakiness of transferloss/
# transfercorruption. The no-loss transfer case keeps big.bin (FC-extension
# coverage retained), since without impairment the extension always lands in time.
if [ ! -f "$WWW/loss.bin" ]; then
  head -c 786432 /dev/urandom > "$WWW/loss.bin"
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

# ---- kpcheck (pure go stdlib — no external deps) ----------------------------
if [ ! -x "$BIN/kpcheck" ]; then
  echo "==> building kpcheck (KP bit wire-proof tool, #40)"
  ( cd "$ORACLE/refs/kpcheck" && go build -o "$BIN/kpcheck" . )
else
  echo "==> kpcheck present (skip)"
fi

# ---- ngtcp2 (optional: HTTP/3 oracle; local source + cmake) --------------------
# Two build paths — same source, different TLS backends:
#   macOS: OpenSSL 3 QUIC API via brew (osslclient / osslserver)
#   Linux: GnuTLS QUIC API via apt  (gtlsclient  / gtlsserver)
# In both cases the result is symlinked to $BIN/ngtcp2-{client,server} (#29).
# Deps are installed by the caller (workflow / developer); this script just builds.
NGTCP2_SRC="$(cd "$ORACLE/.." && pwd)/../ngtcp2"
if [ -x "$BIN/ngtcp2-client" ] && [ -x "$BIN/ngtcp2-server" ]; then
  echo "==> ngtcp2 oracle present (skip)"
elif [ -d "$NGTCP2_SRC" ] && command -v cmake >/dev/null 2>&1 && command -v brew >/dev/null 2>&1; then
  # macOS: OpenSSL 3 has the QUIC transport API (brew install openssl@3 libev libnghttp3)
  SSL="$(brew --prefix openssl@3 2>/dev/null)"; EV="$(brew --prefix libev 2>/dev/null)"; H3="$(brew --prefix libnghttp3 2>/dev/null)"
  if [ -e "$SSL/lib/libssl.dylib" ] && [ -e "$EV/lib/libev.dylib" ] && [ -e "$H3/lib/libnghttp3.dylib" ]; then
    echo "==> building ngtcp2 (HTTP/3 oracle, macOS/OpenSSL) — this is slow the first time"
    if ( cd "$NGTCP2_SRC" \
         && git submodule update --init >/dev/null 2>&1 \
         && PKG_CONFIG_PATH="$EV/lib/pkgconfig:$H3/lib/pkgconfig:$SSL/lib/pkgconfig" \
            cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DENABLE_OPENSSL=ON \
              -DOPENSSL_ROOT_DIR="$SSL" -DCMAKE_PREFIX_PATH="$EV;$H3" -DENABLE_EXAMPLES=ON >/dev/null 2>&1 \
         && cmake --build build -j4 --target osslclient osslserver >/dev/null 2>&1 ); then
      ln -sf "$NGTCP2_SRC/build/examples/osslclient" "$BIN/ngtcp2-client"
      ln -sf "$NGTCP2_SRC/build/examples/osslserver" "$BIN/ngtcp2-server"
      echo "==> ngtcp2 built (macOS/OpenSSL)"
    else
      echo "==> ngtcp2 build failed — skipping (quic-go oracle still runs)"
    fi
  else
    echo "==> ngtcp2 deps missing — skip. Install: brew install openssl@3 libev libnghttp3"
  fi
elif [ -d "$NGTCP2_SRC" ] && command -v cmake >/dev/null 2>&1 && [ "$(uname -s)" = "Linux" ]; then
  # Linux: GnuTLS 3.7+ has QUIC transport support (apt-get install libgnutls28-dev libev-dev libnghttp3-dev)
  echo "==> building ngtcp2 (HTTP/3 oracle, Linux/GnuTLS) — this is slow the first time"
  _cmake_log=$(mktemp)
  if ( cd "$NGTCP2_SRC" \
       && git submodule update --init --depth 1 >/dev/null 2>&1 \
       && cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
            -DENABLE_GNUTLS=ON -DENABLE_OPENSSL=OFF -DENABLE_EXAMPLES=ON >"$_cmake_log" 2>&1 \
       && cmake --build build -j"$(nproc)" --target gtlsclient gtlsserver >>"$_cmake_log" 2>&1 ); then
    ln -sf "$NGTCP2_SRC/build/examples/gtlsclient" "$BIN/ngtcp2-client"
    ln -sf "$NGTCP2_SRC/build/examples/gtlsserver" "$BIN/ngtcp2-server"
    echo "==> ngtcp2 built (Linux/GnuTLS)"
  else
    echo "==> ngtcp2 build failed — cmake output:"
    cat "$_cmake_log"
    echo "    ensure deps: sudo apt-get install libgnutls28-dev libev-dev libnghttp3-dev"
  fi
  rm -f "$_cmake_log"
else
  echo "==> ngtcp2 source (../ngtcp2) or cmake not found — skip (HTTP/3 oracle)"
  echo "    macOS: brew install openssl@3 libev libnghttp3"
  echo "    Linux: git clone ../ngtcp2 + apt-get install libgnutls28-dev libev-dev libnghttp3-dev"
fi

# ---- quiche (optional: HTTP/0.9 oracle; sibling ../quiche + cargo + BoringSSL) -
QUICHE_SRC="$(cd "$ORACLE/.." && pwd)/../quiche"
if [ -x "$BIN/quiche-client" ] && [ -x "$BIN/quiche-server" ]; then
  echo "==> quiche oracle present (skip)"
elif [ -d "$QUICHE_SRC" ] && command -v cargo >/dev/null 2>&1 && command -v cmake >/dev/null 2>&1; then
  echo "==> building quiche (HTTP/0.9 oracle) — first time also builds BoringSSL"
  if ( cd "$QUICHE_SRC/apps" && cargo build --release >/dev/null 2>&1 ); then
    ln -sf "$QUICHE_SRC/target/release/quiche-client" "$BIN/quiche-client"
    ln -sf "$QUICHE_SRC/target/release/quiche-server" "$BIN/quiche-server"
    echo "==> quiche built"
  else
    echo "==> quiche build failed — skipping (other oracles still run)"
  fi
else
  echo "==> quiche source (../quiche) or cargo/cmake not found — skip."
  echo "    enable: git clone --recursive https://github.com/cloudflare/quiche ../quiche"
fi

echo "==> refs ready in $BIN:"
ls -1 "$BIN"
