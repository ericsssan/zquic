# Multi-stage build for quic-interop-runner.
#
# Stage 1: Build the server binary (static musl target).
# Stage 2: Minimal Alpine runtime image.
# Supports multiple architectures (amd64, arm64).

FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends wget xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV ZIG_VERSION=0.16.0-dev.2676+4e2cec265

# Auto-detect architecture and download appropriate Zig binary
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
    echo "export TARGET=${TARGET}" > /build_env.sh; \
    echo "export PATH=/zig:\$PATH" >> /build_env.sh

ENV PATH="/zig:${PATH}"

WORKDIR /build
COPY . .

RUN set -e; \
    . /build_env.sh; \
    zig build -Doptimize=ReleaseSafe -Dtarget="${TARGET}"

# Stage 2: Minimal runtime image.
FROM alpine:3.19

RUN apk add --no-cache iptables ip6tables iproute2

COPY --from=builder /build/zig-out/bin/server /server
COPY tools/run_server.sh /run_server.sh
RUN chmod +x /run_server.sh

RUN mkdir -p /logs

EXPOSE 443/udp

ENV PORT=443
ENV TESTCASE=transfer
ENV CERTS=/certs
ENV WWW=/www

ENTRYPOINT ["/run_server.sh"]
