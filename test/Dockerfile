# Dockerfile for running zig build test inside Docker.
# Works around macOS Xcode SDK arm64e linker issue.
#
# Usage:
#   docker build -f Dockerfile.test -t zquic-test .
#   docker run --rm zquic-test

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends wget xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV ZIG_VERSION=0.17.0-dev.657+2faf8debf

RUN set -e; \
    ARCH=$(uname -m); \
    if [ "$ARCH" = "x86_64" ]; then \
      ZIG_ARCH="x86_64"; \
      TARGET="x86_64-linux-musl"; \
    elif [ "$ARCH" = "aarch64" ]; then \
      ZIG_ARCH="aarch64"; \
      TARGET="aarch64-linux-musl"; \
    else \
      echo "Unsupported architecture: $ARCH"; \
      exit 1; \
    fi; \
    ZIG_TARBALL="zig-${ZIG_ARCH}-linux-${ZIG_VERSION}.tar.xz"; \
    wget -q "https://ziglang.org/builds/${ZIG_TARBALL}"; \
    tar xf "${ZIG_TARBALL}"; \
    rm "${ZIG_TARBALL}"; \
    ln -s "zig-${ZIG_ARCH}-linux-${ZIG_VERSION}" /zig; \
    echo "export TARGET=${TARGET}" > /build_env.sh

ENV PATH="/zig:${PATH}"

WORKDIR /build
COPY . .

RUN . /build_env.sh && zig build test -Dtarget="${TARGET}" -Dcongestion=bbr
