//! zquic interop client — quic-interop-runner compatible UDP client.
//!
//! Supported TESTCASE values: handshake, transfer, multiconnect, keyupdate, v2, ecn, resumption, zerortt.
//! All other values cause exit(127) as required by the interop runner.
//! HTTP/0.9: sends "GET /path\r\n" on client-initiated bidi streams.
//! Downloads are saved to ${DOWNLOADS} directory.

const std = @import("std");
const quic = @import("zquic");

const net = std.Io.net;
const page_allocator = std.heap.page_allocator;
const MAX_DATAGRAM = 1452;
const SEND_CHUNK: usize = 1380;

const Conn = quic.Connection(64);

const supported_cases = [_][]const u8{
    "handshake",
    "transfer",
    "multiconnect",
    "keyupdate",
    "v2",
    "ecn",
    "resumption",
    "zerortt",
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
};

const MAX_DOWNLOADS = 64;

pub fn main(init: std.process.Init) !void {
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
    var req_paths: [MAX_DOWNLOADS][256]u8 = undefined;
    var req_path_lens: [MAX_DOWNLOADS]usize = undefined;
    var req_count: usize = 0;
    parseRequestPaths(requests_str, &req_paths, &req_path_lens, &req_count);

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

    const config: quic.Config = .{
        .is_server = false,
        .alpn = ALPN,
        .initial_quic_version = if (std.mem.eql(u8, testcase, "v2")) quic.packet.QUIC_VERSION_2 else quic.packet.QUIC_VERSION_1,
        .initial_max_streams_bidi = 64,
        .initial_max_streams_uni = 100,
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
        const ticket = try runConnection(config, &sock, effective_server_addr, io, testcase, &req_paths, &req_path_lens, half, downloads_dir);
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
        _ = try runConnection(config2, &sock, effective_server_addr, io, testcase, &req_paths, &req_path_lens, req_count, downloads_dir);
    } else {
        _ = try runConnection(config, &sock, effective_server_addr, io, testcase, &req_paths, &req_path_lens, req_count, downloads_dir);
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
    conn_ptr.* = try Conn.connect(config, io);
    const conn = conn_ptr;

    const init_now: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    conn.current_time_ns = init_now;

    var send_buf: [MAX_DATAGRAM]u8 = undefined;
    drainSend(conn, sock, io, dest, &send_buf);

    // For zerortt: send all requests immediately as 0-RTT if keys are available.
    const is_zerortt = std.mem.eql(u8, testcase, "zerortt");
    var downloads: [MAX_DOWNLOADS]Download = [_]Download{.{}} ** MAX_DOWNLOADS;
    var requests_sent = false;

    if (is_zerortt and config.session_ticket != null and conn.zero_rtt_keys != null) {
        // 0-RTT path: send requests before handshake completes.
        requests_sent = true;
        sendRequests(conn, &downloads, req_paths, req_path_lens, req_count, downloads_dir);
        drainSend(conn, sock, io, dest, &send_buf);
    }

    var all_done = false;

    const timeout_5s: std.Io.Timeout = .{ .duration = .{ .raw = .{ .nanoseconds = 5_000_000_000 }, .clock = .awake } };
    var idle_ticks: usize = 0;

    while (!all_done and idle_ticks < 100) {
        const conn_timeout = conn.nextTimeout();
        const timeout = if (conn_timeout) |ct| blk: {
            const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
            const delta = ct - now_ns;
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
        } else |err| {
            if (err != error.Timeout) break;
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
                    std.debug.print("Connected\n", .{});
                    if (!requests_sent) {
                        requests_sent = true;
                        sendRequests(conn, &downloads, req_paths, req_path_lens, req_count, downloads_dir);
                        drainSend(conn, sock, io, dest, &send_buf);
                    }
                    if (std.mem.eql(u8, testcase, "keyupdate")) {
                        conn.initiateKeyUpdate() catch {};
                    }
                },
                .stream_data => |sd| {
                    receiveStreamData(conn, &downloads, sd.stream_id, io);
                },
                .connection_closed => {
                    std.debug.print("Connection closed\n", .{});
                    for (&downloads) |*d| {
                        if (d.active) receiveStreamData(conn, &downloads, d.stream_id, io);
                    }
                    all_done = true;
                },
                else => {},
            }
        }

        if (requests_sent and req_count > 0) {
            var completed: usize = 0;
            for (&downloads) |*d| {
                if (!d.active) continue;
                if (conn.streamFinished(d.stream_id)) completed += 1;
            }
            if (completed >= req_count) all_done = true;
        }

        if (std.mem.eql(u8, testcase, "handshake") and conn.hot.state == .established) {
            all_done = true;
        }

        if (conn.hot.state == .closed or conn.hot.state == .draining) {
            all_done = true;
        }
    }

    const ticket = conn.getSessionTicket();

    for (&downloads) |*d| {
        if (d.file) |f| f.close(io);
    }

    conn.close(0, true, "") catch {};
    drainSend(conn, sock, io, dest, &send_buf);
    conn.deinit();

    return ticket;
}

fn sendRequests(
    conn: *Conn,
    downloads: *[MAX_DOWNLOADS]Download,
    req_paths: anytype,
    req_path_lens: anytype,
    req_count: usize,
    downloads_dir: []const u8,
) void {
    for (0..req_count) |i| {
        const stream_id: u62 = @intCast(i * 4); // client-initiated bidi
        const path = req_paths[i][0..req_path_lens[i]];

        // Build HTTP/0.9 request: "GET /path\r\n"
        var req_buf: [512]u8 = undefined;
        const req = std.fmt.bufPrint(&req_buf, "GET {s}\r\n", .{path}) catch continue;
        conn.streamSend(stream_id, req, false) catch continue;

        // Set up download
        downloads[i] = .{
            .active = true,
            .stream_id = stream_id,
            .received = 0,
        };

        // Build output path: downloads_dir + basename(path)
        const basename = std.fs.path.basename(path);
        const out_path = std.fmt.bufPrint(&downloads[i].path, "{s}/{s}", .{ downloads_dir, basename }) catch continue;
        downloads[i].path_len = out_path.len;
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
    return net.IpAddress.resolve(io, host, port) catch return null;
}

fn ipAddressToSocketAddr(addr: net.IpAddress) quic.SocketAddr {
    return switch (addr) {
        .ip4 => |a| .{ .v4 = .{ .addr = a.bytes, .port = a.port } },
        .ip6 => |a| .{ .v6 = .{ .addr = a.bytes, .port = a.port } },
    };
}
