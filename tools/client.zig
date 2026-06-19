//! zquic interop client — quic-interop-runner compatible UDP client.
//!
//! Supported TESTCASE values: handshake, transfer, multiconnect, keyupdate, v2, ecn, resumption, zerortt, chacha20, retry, versionnegotiation.
//! All other values cause exit(127) as required by the interop runner.
//! HTTP/0.9: sends "GET /path\r\n" on client-initiated bidi streams.
//! Downloads are saved to ${DOWNLOADS} directory.

const std = @import("std");
const quic = @import("zquic");
const http3 = @import("http3");
const qpack = @import("qpack");

const net = std.Io.net;
const page_allocator = std.heap.page_allocator;
const MAX_DATAGRAM = 1452;
const SEND_CHUNK: usize = 1380;

const Conn = quic.Connection(128);

const supported_cases = [_][]const u8{
    "handshake",
    "transfer",
    "multiplexing",
    "multiconnect",
    "keyupdate",
    "v2",
    "ecn",
    "resumption",
    "zerortt",
    "chacha20",
    "retry",
    "versionnegotiation",
    "http3",
};

const ALPN = "hq-interop";

/// Per-stream download state.
const Download = struct {
    active: bool = false,
    stream_id: u62 = 0,
    /// Destination path for the downloaded file.
    path: [512]u8 = undefined,
    path_len: usize = 0,
    /// Bytes received so far.
    received: u64 = 0,
    /// File handle for writing.
    file: ?std.Io.File = null,
    // H3 streaming parser state (persisted across receiveH3StreamData calls).
    h3_hdr: [16]u8 = undefined, // accumulate frame type+length varint bytes
    h3_hdr_len: usize = 0, // bytes accumulated so far (0 = waiting for next frame)
    h3_in_data: bool = false, // true when consuming a DATA frame body
    h3_remaining: usize = 0, // bytes left in current frame body (0 = reading header)
};

const MAX_DOWNLOADS = 2048;

/// noinline prevents LLVM from merging this into _start's combined frame in
/// ReleaseSafe builds.  Connection(128) is ~12 MB; if main (and runConnection)
/// are inlined into _start, the _start prologue does `sub rsp, 12MB` *before*
/// expandStackSize() raises RLIMIT_STACK, causing an immediate SIGSEGV.
pub noinline fn main(init: std.process.Init) !void {
    const io = init.io;

    // Determine testcase
    const testcase = init.environ_map.get("TESTCASE") orelse {
        std.debug.print("TESTCASE not set, exiting\n", .{});
        std.process.exit(127);
    };
    var is_supported = false;
    for (supported_cases) |s| {
        if (std.mem.eql(u8, testcase, s)) {
            is_supported = true;
            break;
        }
    }
    if (!is_supported) std.process.exit(127);

    // Parse REQUESTS: space-separated list of URLs like "https://server:port/path"
    const requests_str = init.environ_map.get("REQUESTS") orelse {
        std.debug.print("REQUESTS not set, exiting\n", .{});
        std.process.exit(1);
    };
    const downloads_dir = init.environ_map.get("DOWNLOADS") orelse "/downloads";

    // Parse first URL to extract host and port
    var host_buf: [256]u8 = undefined;
    var host_len: usize = 0;
    var port: u16 = 443;
    parseFirstUrl(requests_str, &host_buf, &host_len, &port);

    // Parse all request paths
    const req_paths_ptr = try page_allocator.create([MAX_DOWNLOADS][256]u8);
    defer page_allocator.destroy(req_paths_ptr);
    const req_path_lens_ptr = try page_allocator.create([MAX_DOWNLOADS]usize);
    defer page_allocator.destroy(req_path_lens_ptr);
    var req_count: usize = 0;
    parseRequestPaths(requests_str, req_paths_ptr, req_path_lens_ptr, &req_count);
    const req_paths: *[MAX_DOWNLOADS][256]u8 = req_paths_ptr;
    const req_path_lens: *[MAX_DOWNLOADS]usize = req_path_lens_ptr;

    std.debug.print("zquic interop client: testcase={s} host={s} port={d} requests={d}\n", .{
        testcase, host_buf[0..host_len], port, req_count,
    });

    // Resolve server address
    const server_addr = resolveHost(host_buf[0..host_len], port, io) orelse {
        std.debug.print("Failed to resolve host: {s}\n", .{host_buf[0..host_len]});
        std.process.exit(1);
    };

    // Bind UDP socket matching server address family.
    const bind_addr: net.IpAddress = switch (server_addr) {
        .ip4 => .{ .ip4 = net.Ip4Address.unspecified(0) },
        .ip6 => .{ .ip6 = net.Ip6Address.unspecified(0) },
    };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    const effective_server_addr = &server_addr;
    defer sock.close(io);

    // Set ECN marking: stamp all outgoing packets with ECT(0) (RFC 9000 §13.4.2).
    {
        const ect0 = [_]u8{ 0x02, 0, 0, 0 };
        const os = @import("builtin").os.tag;
        const ip_tos: u32 = if (os == .linux) 1 else 3;
        const ipv6_tclass: u32 = if (os == .linux) 67 else 36;
        switch (server_addr) {
            .ip4 => std.posix.setsockopt(sock.handle, std.posix.IPPROTO.IP, ip_tos, &ect0) catch {},
            .ip6 => std.posix.setsockopt(sock.handle, std.posix.IPPROTO.IPV6, ipv6_tclass, &ect0) catch {},
        }
    }

    const is_h3 = std.mem.eql(u8, testcase, "http3");
    const config: quic.Config = .{
        .is_server = false,
        .alpn = if (is_h3) "h3" else ALPN,
        .initial_quic_version = quic.packet.QUIC_VERSION_1,
        .initial_max_streams_bidi = 1024,
        .initial_max_streams_uni = 1024,
        .advertise_v2 = std.mem.eql(u8, testcase, "v2"),
        // Opt-in cert validation (ECDSA-P256 / Ed25519 leaf): set VERIFY_PEER to
        // verify the server's CertificateVerify (#2). Off by default for interop
        // against servers using unsupported signature schemes (e.g. RSA).
        .verify_peer = init.environ_map.get("VERIFY_PEER") != null,
    };

    if (std.mem.eql(u8, testcase, "multiconnect")) {
        // Each request gets its own connection.
        for (0..req_count) |i| {
            const paths = req_paths[i .. i + 1];
            const lens = req_path_lens[i .. i + 1];
            _ = try runConnection(config, &sock, effective_server_addr, io, testcase, paths, lens, 1, downloads_dir);
        }
    } else if (std.mem.eql(u8, testcase, "resumption")) {
        // Connection 1: download first half, collect session ticket.
        const half = if (req_count > 1) req_count / 2 else req_count;
        const ticket = try runConnection(config, &sock, effective_server_addr, io, testcase, req_paths, req_path_lens, half, downloads_dir);
        // Connection 2: resume with PSK, download second half.
        if (req_count > half) {
            var config2 = config;
            config2.session_ticket = ticket;
            _ = try runConnection(config2, &sock, effective_server_addr, io, testcase, req_paths[half..], req_path_lens[half..], req_count - half, downloads_dir);
        }
    } else if (std.mem.eql(u8, testcase, "zerortt")) {
        // Connection 1: download one file to warm up the ticket.
        const ticket = try runConnection(config, &sock, effective_server_addr, io, testcase, req_paths[0..1], req_path_lens[0..1], 1, downloads_dir);
        // Connection 2: reconnect with PSK + 0-RTT, send all requests.
        var config2 = config;
        config2.session_ticket = ticket;
        _ = try runConnection(config2, &sock, effective_server_addr, io, testcase, req_paths, req_path_lens, req_count, downloads_dir);
    } else {
        _ = try runConnection(config, &sock, effective_server_addr, io, testcase, req_paths, req_path_lens, req_count, downloads_dir);
    }

    std.debug.print("Client done\n", .{});
}

/// Run one QUIC connection, send `req_count` HTTP/0.9 requests, and return
/// the session ticket emitted by the server (for resumption/0-RTT follow-up).
fn runConnection(
    config: quic.Config,
    sock: *const net.Socket,
    dest: *const net.IpAddress,
    io: std.Io,
    testcase: []const u8,
    req_paths: anytype,
    req_path_lens: anytype,
    req_count: usize,
    downloads_dir: []const u8,
) !?quic.tls.SessionTicket {
    const conn_ptr = try page_allocator.create(Conn);
    defer page_allocator.destroy(conn_ptr);
    try conn_ptr.connectInto(config, io); // init in place — no stack temp (#3)
    const conn = conn_ptr;

    const init_now: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    conn.current_time_ns = init_now;

    var send_buf: [MAX_DATAGRAM]u8 = undefined;
    drainSend(conn, sock, io, dest, &send_buf);

    // For zerortt: send all requests immediately as 0-RTT if keys are available.
    const is_zerortt = std.mem.eql(u8, testcase, "zerortt");
    const downloads_ptr = try page_allocator.create([MAX_DOWNLOADS]Download);
    defer page_allocator.destroy(downloads_ptr);
    const downloads: *[MAX_DOWNLOADS]Download = downloads_ptr;
    for (downloads) |*d| d.* = .{};
    var requests_sent = false;
    var next_req: usize = 0; // index of next request to send

    if (is_zerortt and config.session_ticket != null and conn.zero_rtt_keys != null) {
        // 0-RTT path: send requests before handshake completes.
        requests_sent = true;
        sendRequests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req);
        drainSend(conn, sock, io, dest, &send_buf);
    }

    var all_done = false;

    const timeout_5s: std.Io.Timeout = .{ .duration = .{ .raw = .{ .nanoseconds = 5_000_000_000 }, .clock = .awake } };
    var idle_ticks: usize = 0;

    while (!all_done and idle_ticks < 100) {
        const conn_timeout = conn.nextTimeout();
        const now_pre: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
        const timeout = if (conn_timeout) |ct| blk: {
            const delta = ct - now_pre;
            if (delta <= 0) break :blk std.Io.Timeout{ .duration = .{ .raw = .{ .nanoseconds = 0 }, .clock = .awake } };
            break :blk std.Io.Timeout{ .duration = .{ .raw = .{ .nanoseconds = delta }, .clock = .awake } };
        } else timeout_5s;

        var recv_buf: [MAX_DATAGRAM]u8 = undefined;
        if (sock.receiveTimeout(io, &recv_buf, timeout)) |msg| {
            const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
            const src_addr = ipAddressToSocketAddr(msg.from);
            conn.receive(recv_buf[0..msg.data.len], src_addr, now_ns, 0, io) catch |err| {
                std.debug.print("recv error: {}\n", .{err});
            };
            drainSend(conn, sock, io, dest, &send_buf);
            idle_ticks = 0;
        } else |_| {
            // RFC 9000 §21.2.1: ICMP errors and other transient socket errors MUST be
            // ignored — the QUIC PTO / loss-recovery mechanism handles retransmission.
            idle_ticks += 1;
        }

        if (conn_timeout) |ct| {
            const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
            if (now_ns >= ct) {
                conn.tick(now_ns);
                drainSend(conn, sock, io, dest, &send_buf);
            }
        }

        while (conn.pollEvent()) |event| {
            switch (event) {
                .connected => {
                    writeKeyLog(conn, io);
                    const use_h3 = std.mem.eql(u8, testcase, "http3");
                    if (use_h3) sendH3ControlStreams(conn);
                    // Always mark requests as sent and try to send any remaining.
                    // For 0-RTT connections, sendRequests may have been called early
                    // but couldn't open streams (peer_max_streams_bidi=0 before handshake).
                    // The connected event delivers real transport params so streams work now.
                    requests_sent = true;
                    if (next_req < req_count) {
                        if (use_h3)
                            sendH3Requests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req)
                        else
                            sendRequests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req);
                        drainSend(conn, sock, io, dest, &send_buf);
                    }
                    if (std.mem.eql(u8, testcase, "keyupdate")) {
                        conn.initiateKeyUpdate() catch {};
                    }
                },
                .stream_data => |sd| {
                    const use_h3_rx = std.mem.eql(u8, testcase, "http3");
                    if (use_h3_rx)
                        receiveH3StreamData(conn, downloads, sd.stream_id, io)
                    else
                        receiveStreamData(conn, downloads, sd.stream_id, io);
                    conn.flushControlFrames() catch {};
                    if (next_req < req_count) {
                        if (use_h3_rx)
                            sendH3Requests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req)
                        else
                            sendRequests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req);
                    }
                    drainSend(conn, sock, io, dest, &send_buf);
                },
                .connection_closed => {
                    for (downloads) |*d| {
                        if (d.active) receiveStreamData(conn, downloads, d.stream_id, io);
                    }
                    all_done = true;
                },
                else => {},
            }
        }

        // After processing events, try to open more streams if the peer's
        // MAX_STREAMS_BIDI limit increased (e.g., after a batch of streams
        // completed and the server sent a MAX_STREAMS frame).
        if (requests_sent and next_req < req_count and conn.hot.state == .established) {
            const prev = next_req;
            const use_h3_b = std.mem.eql(u8, testcase, "http3");
            if (use_h3_b)
                sendH3Requests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req)
            else
                sendRequests(conn, downloads, req_paths, req_path_lens, req_count, downloads_dir, &next_req);
            if (next_req > prev) drainSend(conn, sock, io, dest, &send_buf);
        }

        if (requests_sent and req_count > 0) {
            var completed: usize = 0;
            for (downloads) |*d| {
                if (!d.active) continue;
                if (conn.streamFinished(d.stream_id)) {
                    completed += 1;
                }
            }
            if (completed >= req_count) {
                // For resumption/zerortt: keep running until we have a session ticket
                // (the server's NewSessionTicket arrives as a post-handshake message).
                const need_ticket = std.mem.eql(u8, testcase, "resumption") or std.mem.eql(u8, testcase, "zerortt");
                if (!need_ticket or conn.getSessionTicket() != null) {
                    all_done = true;
                }
            }
        }

        // Note: "handshake" test also requires file downloads (do not exit early).

        if (conn.hot.state == .closed or conn.hot.state == .draining) {
            all_done = true;
        }
    }

    const ticket = conn.getSessionTicket();

    for (downloads) |*d| {
        if (d.file) |f| f.close(io);
    }

    conn.close(0, true, "") catch {};
    drainSend(conn, sock, io, dest, &send_buf);
    conn.deinit();

    return ticket;
}

/// Send as many requests as the peer's stream limit allows.
/// Returns the number of requests successfully sent so far (cumulative).
fn sendRequests(
    conn: *Conn,
    downloads: *[MAX_DOWNLOADS]Download,
    req_paths: anytype,
    req_path_lens: anytype,
    req_count: usize,
    downloads_dir: []const u8,
    next_req: *usize,
) void {
    while (next_req.* < req_count) {
        const i = next_req.*;
        const stream_id: u62 = @intCast(i * 4); // client-initiated bidi

        // Check if we'd exceed the peer's stream limit
        if (stream_id / 4 >= conn.peer_max_streams_bidi) break;

        const path = req_paths[i][0..req_path_lens[i]];

        // Build HTTP/0.9 request: "GET /path\r\n"
        var req_buf: [512]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "GET {s}\r\n", .{path}) catch {
            next_req.* += 1;
            continue;
        };
        // Send with FIN: for HTTP/0.9 the GET request is the entire client message.
        // Sending FIN immediately lets the connection reclaim the stream slot once
        // the server's response + FIN are ACKed, enabling more than 128 streams per
        // connection for multiplexing tests with hundreds of files.
        conn.streamSend(stream_id, req, true) catch break; // send queue full

        // Set up download
        downloads[i] = .{
            .active = true,
            .stream_id = stream_id,
            .received = 0,
        };

        // Build output path: downloads_dir + basename(path)
        const basename = std.fs.path.basename(path);
        const out_path = std.fmt.bufPrint(&downloads[i].path, "{s}/{s}", .{ downloads_dir, basename }) catch {
            next_req.* += 1;
            continue;
        };
        downloads[i].path_len = out_path.len;
        next_req.* += 1;
    }
}

fn receiveStreamData(conn: *Conn, downloads: *[MAX_DOWNLOADS]Download, stream_id: u62, io: std.Io) void {
    for (downloads) |*d| {
        if (!d.active or d.stream_id != stream_id) continue;

        // Open file on first data
        if (d.file == null and d.path_len > 0) {
            d.file = std.Io.Dir.createFileAbsolute(io, d.path[0..d.path_len], .{}) catch {
                d.active = false;
                return;
            };
        }

        // Read all available data from stream and write to file
        var buf: [4096]u8 = undefined;
        while (true) {
            const n = conn.streamRecv(stream_id, &buf);
            if (n == 0) break;
            if (d.file) |file| {
                file.writePositionalAll(io, buf[0..n], d.received) catch {};
            }
            d.received += n;
        }
        return;
    }
}

fn drainSend(conn: *Conn, sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, buf: *[MAX_DATAGRAM]u8) void {
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    while (true) {
        const n = conn.send(buf, now_ns);
        if (n == 0) break;
        var messages = [_]net.OutgoingMessage{.{
            .address = dest,
            .data_ptr = buf,
            .data_len = n,
        }};
        sock.sendMany(io, &messages, .{}) catch {};
    }
}

fn parseFirstUrl(requests: []const u8, host: *[256]u8, host_len: *usize, port: *u16) void {
    // Format: "https://host:port/path" or "https://host/path"
    var url = requests;
    // Get first URL (space-separated)
    if (std.mem.indexOf(u8, url, " ")) |idx| url = url[0..idx];

    // Strip "https://"
    if (std.mem.startsWith(u8, url, "https://")) url = url[8..];

    // Find end of host:port
    const path_start = std.mem.indexOf(u8, url, "/") orelse url.len;
    const host_port = url[0..path_start];

    // Check for port
    if (std.mem.lastIndexOf(u8, host_port, ":")) |colon| {
        const h = host_port[0..colon];
        const p = host_port[colon + 1 ..];
        @memcpy(host[0..h.len], h);
        host_len.* = h.len;
        port.* = std.fmt.parseInt(u16, p, 10) catch 443;
    } else {
        @memcpy(host[0..host_port.len], host_port);
        host_len.* = host_port.len;
        port.* = 443;
    }
}

fn parseRequestPaths(requests: []const u8, paths: *[MAX_DOWNLOADS][256]u8, lens: *[MAX_DOWNLOADS]usize, count: *usize) void {
    var remaining = requests;
    count.* = 0;
    while (remaining.len > 0 and count.* < MAX_DOWNLOADS) {
        // Skip whitespace
        while (remaining.len > 0 and remaining[0] == ' ') remaining = remaining[1..];
        if (remaining.len == 0) break;

        // Find end of URL
        const end = std.mem.indexOf(u8, remaining, " ") orelse remaining.len;
        const url = remaining[0..end];
        remaining = if (end < remaining.len) remaining[end + 1 ..] else &.{};

        // Extract path from URL
        var u = url;
        if (std.mem.startsWith(u8, u, "https://")) u = u[8..];
        const path_start = std.mem.indexOf(u8, u, "/") orelse continue;
        const path = u[path_start..];

        @memcpy(paths[count.*][0..path.len], path);
        lens[count.*] = path.len;
        count.* += 1;
    }
}

fn resolveHost(host: []const u8, port: u16, io: std.Io) ?net.IpAddress {
    // Try parsing as an IP literal first (fast path, no I/O).
    if (net.IpAddress.resolve(io, host, port)) |addr| return addr else |_| {}

    // Fall back to /etc/hosts — required in Docker interop containers where
    // the server address is a hostname alias (e.g. "server4") rather than an
    // IP literal.  Avoids linking libc (getaddrinfo) which crashes at startup
    // in containers that enforce an 8MB stack limit.
    return resolveFromEtcHosts(host, port, io);
}

/// Parse /etc/hosts and return the first IPv4/IPv6 address for `host`.
fn resolveFromEtcHosts(host: []const u8, port: u16, io: std.Io) ?net.IpAddress {
    const file = std.Io.Dir.openFileAbsolute(io, "/etc/hosts", .{}) catch return null;
    defer file.close(io);

    var buf: [4096]u8 = undefined;
    var offset: u64 = 0;
    var leftover: usize = 0;

    while (true) {
        const n = file.readPositionalAll(io, buf[leftover..], offset) catch break;
        if (n == 0) break;
        const total = leftover + n;
        offset += n;

        var data = buf[0..total];
        while (std.mem.indexOf(u8, data, "\n")) |nl| {
            const line = data[0..nl];
            data = data[nl + 1 ..];

            // Strip comments and skip blank lines.
            const trimmed = std.mem.trim(u8, line, " \t\r");
            if (trimmed.len == 0 or trimmed[0] == '#') continue;

            // First token = IP address, remaining tokens = hostnames.
            var tokens = std.mem.tokenizeAny(u8, trimmed, " \t");
            const ip_str = tokens.next() orelse continue;
            while (tokens.next()) |name| {
                if (!std.mem.eql(u8, name, host)) continue;
                // Match found — parse the IP.
                if (net.IpAddress.resolve(io, ip_str, port)) |addr| return addr else |_| {}
            }
        }
        // Keep unprocessed bytes (partial last line) for next read.
        leftover = data.len;
        if (leftover > 0) std.mem.copyForwards(u8, buf[0..leftover], data);
        if (n < buf.len - leftover) break; // EOF
    }
    return null;
}

fn ipAddressToSocketAddr(addr: net.IpAddress) quic.SocketAddr {
    return switch (addr) {
        .ip4 => |a| .{ .v4 = .{ .addr = a.bytes, .port = a.port } },
        .ip6 => |a| .{ .v6 = .{ .addr = a.bytes, .port = a.port } },
    };
}

/// Write NSS key log (SSLKEYLOGFILE) to /logs/keys.log so the interop runner
/// can decrypt packet captures with Wireshark/tshark.
fn writeKeyLog(conn: *const Conn, io: std.Io) void {
    const tls_c = &conn.tls_state.client;
    const random_hex = std.fmt.bytesToHex(tls_c.client_random, .lower);
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls_c.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls_c.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    const secrets_0 = conn.deriveSecretsForGeneration(0);
    line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_0 {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(secrets_0.client, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_0 {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(secrets_0.server, .lower) }) catch return;
    pos += line.len;

    // Append to keylog (resumption test has 2 connections that both write keys).
    const file = std.Io.Dir.createFileAbsolute(io, "/logs/keys.log", .{ .truncate = false }) catch return;
    defer file.close(io);
    const offset = file.length(io) catch 0;
    file.writePositionalAll(io, buf[0..pos], offset) catch return;
    file.sync(io) catch {};
}

// ---------------------------------------------------------------------------
// HTTP/3 support
// ---------------------------------------------------------------------------

/// Open client-initiated unidirectional control streams (RFC 9114 §6.2).
/// Stream IDs: client-initiated uni = 4*n + 2 → 2, 6, 10
fn sendH3ControlStreams(conn: *Conn) void {
    const stream_ids = [_]u62{ 2, 6, 10 };
    const stream_types = [_]u64{
        http3.StreamType.control,
        http3.StreamType.qpack_encoder,
        http3.StreamType.qpack_decoder,
    };
    for (stream_ids, stream_types) |sid, stype| {
        var buf: [64]u8 = undefined;
        var pos: usize = 0;
        pos += http3.varint.encode(buf[pos..], stype) catch return;
        if (stype == http3.StreamType.control) {
            pos += http3.frame.writeHeader(buf[pos..], http3.FrameType.settings, 0) catch return;
        }
        conn.streamSend(sid, buf[0..pos], false) catch {};
    }
}

/// Send H3 HEADERS frames for GET requests.
fn sendH3Requests(
    conn: *Conn,
    downloads: *[MAX_DOWNLOADS]Download,
    req_paths: anytype,
    req_path_lens: anytype,
    req_count: usize,
    downloads_dir: []const u8,
    next_req: *usize,
) void {
    while (next_req.* < req_count) {
        const i = next_req.*;
        const stream_id: u62 = @intCast(i * 4);
        if (stream_id / 4 >= conn.peer_max_streams_bidi) break;

        const path = req_paths[i][0..req_path_lens[i]];

        // QPACK-encode H3 HEADERS: :method GET, :scheme https, :authority, :path
        var qbuf: [512]u8 = undefined;
        const fields = [_]qpack.Field{
            .{ .name = ":method", .value = "GET" },
            .{ .name = ":scheme", .value = "https" },
            .{ .name = ":authority", .value = "server" },
            .{ .name = ":path", .value = path },
        };
        const qlen = qpack.encoder.encode(&fields, &qbuf, null) catch {
            next_req.* += 1;
            continue;
        };

        // Wrap in H3 HEADERS frame
        var fbuf: [600]u8 = undefined;
        var fpos: usize = 0;
        fpos += http3.frame.writeHeader(fbuf[fpos..], http3.FrameType.headers, qlen) catch {
            next_req.* += 1;
            continue;
        };
        @memcpy(fbuf[fpos..][0..qlen], qbuf[0..qlen]);
        fpos += qlen;

        conn.streamSend(stream_id, fbuf[0..fpos], true) catch break;

        downloads[i] = .{ .active = true, .stream_id = stream_id, .received = 0 };
        const basename = std.fs.path.basename(path);
        const out_path = std.fmt.bufPrint(&downloads[i].path, "{s}/{s}", .{ downloads_dir, basename }) catch {
            next_req.* += 1;
            continue;
        };
        downloads[i].path_len = out_path.len;
        next_req.* += 1;
    }
}

/// Receive H3-framed data: skip HEADERS frames, extract DATA frame payloads.
///
/// Uses a streaming state machine persisted in d.h3_* fields so that frames
/// spanning multiple streamRecv chunks are handled correctly.  The old approach
/// of draining into a local accum buffer lost bytes at partial-frame boundaries:
/// once streamRecv consumes bytes from the ring buffer they are gone, so any
/// partial DATA frame body that didn't fit in one shot was silently discarded.
fn receiveH3StreamData(conn: *Conn, downloads: *[MAX_DOWNLOADS]Download, stream_id: u62, io: std.Io) void {
    // Ignore unidirectional streams (server control/QPACK).
    if (stream_id & 0x3 != 0) {
        var sink: [4096]u8 = undefined;
        while (conn.streamRecv(stream_id, &sink) > 0) {}
        return;
    }

    for (downloads) |*d| {
        if (!d.active or d.stream_id != stream_id) continue;

        if (d.file == null and d.path_len > 0) {
            d.file = std.Io.Dir.createFileAbsolute(io, d.path[0..d.path_len], .{}) catch {
                d.active = false;
                return;
            };
        }

        var chunk: [4096]u8 = undefined;
        while (true) {
            const n = conn.streamRecv(stream_id, &chunk);
            if (n == 0) break;
            var off: usize = 0;
            while (off < n) {
                if (d.h3_remaining > 0) {
                    // Inside a frame body: consume bytes directly.
                    const take = @min(d.h3_remaining, n - off);
                    if (d.h3_in_data) {
                        if (d.file) |file| {
                            file.writePositionalAll(io, chunk[off..][0..take], d.received) catch {};
                        }
                        d.received += take;
                    }
                    d.h3_remaining -= take;
                    off += take;
                } else {
                    // Accumulate frame header bytes one at a time until we can
                    // decode both the type varint and length varint.
                    d.h3_hdr[d.h3_hdr_len] = chunk[off];
                    d.h3_hdr_len += 1;
                    off += 1;

                    const hdr_buf = d.h3_hdr[0..d.h3_hdr_len];
                    const t = http3.varint.decode(hdr_buf) catch continue; // type varint incomplete
                    const l = http3.varint.decode(hdr_buf[t.consumed..]) catch continue; // length varint incomplete

                    // Full frame header decoded — transition to body state.
                    d.h3_in_data = (t.value == http3.FrameType.data);
                    d.h3_remaining = @intCast(l.value);
                    d.h3_hdr_len = 0; // reset for next frame header
                }
            }
        }
        return;
    }
}
