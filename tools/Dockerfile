# Multi-stage build for quic-interop-runner.
#
# Stage 1: Build the server binary (static musl target).
# Stage 2: Minimal Alpine runtime image.

FROM --platform=linux/amd64 debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends wget xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

ENV ZIG_VERSION=0.16.0-dev.2637+6a9510c0e
ENV ZIG_TARBALL=zig-linux-x86_64-${ZIG_VERSION}.tar.xz

RUN wget -q https://ziglang.org/builds/${ZIG_TARBALL} \
    && tar xf ${ZIG_TARBALL} \
    && rm ${ZIG_TARBALL}

ENV PATH="/zig-linux-x86_64-${ZIG_VERSION}:${PATH}"

WORKDIR /build
COPY . .

RUN zig build -Doptimize=ReleaseSafe -Dtarget=x86_64-linux-musl

# Stage 2: Minimal runtime image.
FROM --platform=linux/amd64 alpine:3.19

COPY --from=builder /build/zig-out/bin/server /server

EXPOSE 443/udp

ENV PORT=443
ENV TESTCASE=transfer
ENV CERTS=/certs
ENV WWW=/www

ENTRYPOINT ["/server"]
