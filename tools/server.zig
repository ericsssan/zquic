//! zquic interop server — quic-interop-runner compatible UDP server.
//!
//! Supported TESTCASE values: handshake, transfer, multiconnect, retry, keyupdate, v2.
//! All other values cause exit(127) as required by the interop runner.
//! HTTP/0.9: accepts "GET /path\r\n" and serves files from ${WWW} directory.
//! File serving is event-driven: data is pushed in chunks each event loop tick
//! so that the 4096-byte stream send buffer never overflows.

const std = @import("std");
const quic = @import("zquic");
const pem = @import("pem.zig");

const net = std.Io.net;
const DEFAULT_PORT: u16 = 443;
const MAX_DATAGRAM = 1452;
// Chunk size ≤ STREAM_BUF_SIZE so streamSend never returns buffer-full.
const SEND_CHUNK: usize = 2048;
// Maximum concurrent file transfers per connection.
const MAX_TRANSFERS = 8;

const ALPN = "hq-interop";

const supported_cases = [_][]const u8{
    "handshake", "transfer", "multiconnect", "retry", "keyupdate", "v2",
};

/// State for one in-progress file transfer.
const FileTransfer = struct {
    active: bool = false,
    stream_id: u62 = 0,
    /// Absolute path of the file being served, NUL-terminated.
    path: [512]u8 = undefined,
    path_len: usize = 0,
    /// Next byte offset to read from.
    offset: u64 = 0,
};

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Determine the testcase; exit 127 if unsupported.
    const testcase = init.environ_map.get("TESTCASE") orelse "transfer";
    var is_supported = false;
    for (supported_cases) |s| {
        if (std.mem.eql(u8, testcase, s)) {
            is_supported = true;
            break;
        }
    }
    if (!is_supported) std.process.exit(127);

    // Read configuration from environment.
    const certs_dir = init.environ_map.get("CERTS") orelse "/certs";
    const www_dir = init.environ_map.get("WWW") orelse "/www";
    const port: u16 = blk: {
        const p = init.environ_map.get("PORT") orelse break :blk DEFAULT_PORT;
        break :blk std.fmt.parseInt(u16, p, 10) catch DEFAULT_PORT;
    };

    // Load certificate and private key from $CERTS.
    var cert_path_buf: [512]u8 = undefined;
    var key_path_buf: [512]u8 = undefined;
    const cert_path = try std.fmt.bufPrint(&cert_path_buf, "{s}/cert.pem", .{certs_dir});
    const key_path = try std.fmt.bufPrint(&key_path_buf, "{s}/priv.key", .{certs_dir});

    var cert_pem_buf: [8192]u8 = undefined;
    var key_pem_buf: [4096]u8 = undefined;
    const cert_pem_len = try readFileFull(io, cert_path, &cert_pem_buf);
    const key_pem_len = try readFileFull(io, key_path, &key_pem_buf);

    var cert_der_buf: [4096]u8 = undefined;
    var key_der_buf: [512]u8 = undefined;
    const cert_der_len = try pem.pemToDer(cert_pem_buf[0..cert_pem_len], &cert_der_buf);
    const key_der_len = try pem.pemToDer(key_pem_buf[0..key_pem_len], &key_der_buf);
    const key_material = try pem.parsePrivateKey(key_der_buf[0..key_der_len]);

    const config: quic.Config = .{
        .alpn = ALPN,
        .validate_addr = std.mem.eql(u8, testcase, "retry"),
        .cert_der = cert_der_buf[0..cert_der_len],
        .cert_seed = key_material.seed,
        .cert_key_algorithm = switch (key_material.algorithm) {
            .ed25519 => .ed25519,
            .p256 => .p256,
        },
    };

    // Bind UDP socket.
    const bind_addr = net.IpAddress{ .ip4 = net.Ip4Address.unspecified(port) };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);

    std.debug.print("zquic interop server: testcase={s} port={d}\n", .{ testcase, port });

    var recv_buf: [MAX_DATAGRAM]u8 = undefined;
    var send_buf: [MAX_DATAGRAM]u8 = undefined;

    // Accept and handle connections one at a time.
    while (true) {
        var conn = try quic.Connection.accept(config, io);
        var peer_addr: ?net.IpAddress = null;

        // Per-connection file transfer state.
        var transfers = [_]FileTransfer{.{}} ** MAX_TRANSFERS;

        conn_loop: while (true) {
            const timeout = computeTimeout(conn.nextTimeout());
            const msg = sock.receiveTimeout(io, &recv_buf, timeout) catch |err| {
                if (err == error.Timeout) {
                    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
                    conn.tick(now_ns);
                    if (peer_addr) |pa| {
                        flushTransfers(&conn, &transfers, www_dir, io);
                        drainSend(&conn, &sock, io, &pa, &send_buf);
                    }
                    continue :conn_loop;
                }
                std.debug.print("recv error: {}\n", .{err});
                break :conn_loop;
            };

            peer_addr = msg.from;
            const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
            conn.receive(msg.data, ipToSocketAddr(msg.from), now_ns, io) catch |err| {
                std.debug.print("receive error: {}\n", .{err});
            };

            while (conn.pollEvent()) |ev| {
                switch (ev) {
                    .connected => std.debug.print("handshake complete\n", .{}),
                    .retry_sent => {
                        drainSend(&conn, &sock, io, &msg.from, &send_buf);
                        break :conn_loop;
                    },
                    .stream_data => |s| startTransfer(&conn, s.stream_id, &transfers, www_dir),
                    .connection_closed => break :conn_loop,
                    else => {},
                }
            }

            // Advance any pending file transfers now that the send window may have grown.
            flushTransfers(&conn, &transfers, www_dir, io);
            drainSend(&conn, &sock, io, &msg.from, &send_buf);
        }
    }
}

/// Parse the HTTP/0.9 request from the stream receive buffer and register a FileTransfer.
/// Does not send any data — flushTransfers() does the actual I/O.
fn startTransfer(conn: *quic.Connection, stream_id: u62, transfers: *[MAX_TRANSFERS]FileTransfer, www: []const u8) void {
    const st = conn.streams.get(stream_id) orelse return;
    var req_buf: [256]u8 = undefined;
    const n = st.read(&req_buf);
    const req = req_buf[0..n];

    if (!std.mem.startsWith(u8, req, "GET ")) {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    }
    const eol = std.mem.indexOf(u8, req, "\r\n") orelse {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };
    const path = req[4..eol]; // e.g. "/index.html"

    // Reject path traversal: any component containing ".." is forbidden.
    if (std.mem.indexOf(u8, path, "..") != null) {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    }

    // Find or allocate a transfer slot.
    var slot: ?*FileTransfer = null;
    for (transfers) |*t| {
        if (!t.active) {
            slot = t;
            break;
        }
    }
    const t = slot orelse {
        // No free slot; close the stream empty.
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };

    var full_path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ www, path }) catch {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };

    t.active = true;
    t.stream_id = stream_id;
    t.offset = 0;
    @memcpy(t.path[0..full_path.len], full_path);
    t.path_len = full_path.len;
}

/// Try to advance all active file transfers, sending up to SEND_CHUNK bytes each.
/// Called every event loop iteration so data flows as the congestion window grows.
fn flushTransfers(conn: *quic.Connection, transfers: *[MAX_TRANSFERS]FileTransfer, www: []const u8, io: std.Io) void {
    _ = www;
    for (transfers) |*t| {
        if (!t.active) continue;
        advanceTransfer(conn, t, io);
    }
}

fn advanceTransfer(conn: *quic.Connection, t: *FileTransfer, io: std.Io) void {
    const path = t.path[0..t.path_len];
    const file = std.Io.Dir.openFileAbsolute(io, path, .{}) catch {
        conn.streamSend(t.stream_id, &.{}, true) catch {};
        t.active = false;
        return;
    };
    defer file.close(io);

    var data_buf: [SEND_CHUNK]u8 = undefined;
    const r = file.readPositionalAll(io, &data_buf, t.offset) catch {
        conn.streamSend(t.stream_id, &.{}, true) catch {};
        t.active = false;
        return;
    };

    if (r == 0) {
        // EOF — send FIN.
        conn.streamSend(t.stream_id, &.{}, true) catch {};
        t.active = false;
        return;
    }

    conn.streamSend(t.stream_id, data_buf[0..r], false) catch {
        // Buffer full — leave offset unchanged and retry next tick.
        return;
    };
    t.offset += r;
}

/// Read an entire file into `out`. Returns number of bytes read.
fn readFileFull(io: std.Io, path: []const u8, out: []u8) !usize {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return file.readPositionalAll(io, out, 0);
}

fn drainSend(conn: *quic.Connection, sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, buf: *[MAX_DATAGRAM]u8) void {
    while (true) {
        const n = conn.send(buf);
        if (n == 0) break;
        sock.send(io, dest, buf[0..n]) catch {};
    }
}

fn computeTimeout(deadline: ?i64) std.Io.Timeout {
    const d = deadline orelse return .none;
    return .{ .deadline = .{ .raw = .{ .nanoseconds = d }, .clock = .awake } };
}

fn ipToSocketAddr(addr: net.IpAddress) quic.SocketAddr {
    return switch (addr) {
        .ip4 => |a| .{ .v4 = .{ .addr = a.bytes, .port = a.port } },
        .ip6 => |a| .{ .v6 = .{ .addr = a.bytes, .port = a.port } },
    };
}
