//! zquic interop server — quic-interop-runner compatible UDP server.
//!
//! Supported TESTCASE values: handshake, transfer, multiconnect, retry, keyupdate.
//! All other values cause exit(127) as required by the interop runner.
//! HTTP/0.9: accepts "GET /path\r\n" and serves files from ${WWW} directory.

const std = @import("std");
const quic = @import("zquic");
const pem = @import("pem.zig");

const net = std.Io.net;
const DEFAULT_PORT: u16 = 443;
const MAX_DATAGRAM = 1452;

const ALPN = "hq-interop";

const supported_cases = [_][]const u8{
    "handshake", "transfer", "multiconnect", "retry", "keyupdate",
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

    var cert_der_buf: [2048]u8 = undefined;
    var key_der_buf: [256]u8 = undefined;
    const cert_der_len = try pem.pemToDer(cert_pem_buf[0..cert_pem_len], &cert_der_buf);
    const key_der_len = try pem.pemToDer(key_pem_buf[0..key_pem_len], &key_der_buf);
    const seed = try pem.pkcs8Ed25519Seed(key_der_buf[0..key_der_len]);

    const config: quic.Config = .{
        .alpn = ALPN,
        .validate_addr = std.mem.eql(u8, testcase, "retry"),
        .cert_der = cert_der_buf[0..cert_der_len],
        .cert_seed = seed,
    };

    // Bind UDP socket.
    const bind_addr = net.IpAddress{ .ip4 = net.Ip4Address.unspecified(port) };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);

    std.debug.print("zquic interop server: testcase={s} port={d}\n", .{ testcase, port });

    var recv_buf: [MAX_DATAGRAM]u8 = undefined;
    var send_buf: [MAX_DATAGRAM]u8 = undefined;

    // Accept and handle connections.
    while (true) {
        var conn = try quic.Connection.accept(config, io);
        var peer_addr: ?net.IpAddress = null;

        conn_loop: while (true) {
            const timeout = computeTimeout(conn.nextTimeout());
            const msg = sock.receiveTimeout(io, &recv_buf, timeout) catch |err| {
                if (err == error.Timeout) {
                    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
                    conn.tick(now_ns);
                    if (peer_addr) |pa| drainSend(&conn, &sock, io, &pa, &send_buf);
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
            drainSend(&conn, &sock, io, &msg.from, &send_buf);

            while (conn.pollEvent()) |ev| {
                switch (ev) {
                    .connected => std.debug.print("handshake complete\n", .{}),
                    .retry_sent => {
                        drainSend(&conn, &sock, io, &msg.from, &send_buf);
                        break :conn_loop;
                    },
                    .stream_data => |s| serveHttp09(&conn, s.stream_id, www_dir, io),
                    .connection_closed => break :conn_loop,
                    else => {},
                }
            }
        }
    }
}

/// Read an entire file into `out`. Returns number of bytes read.
fn readFileFull(io: std.Io, path: []const u8, out: []u8) !usize {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return file.readPositionalAll(io, out, 0);
}

/// Serve a single HTTP/0.9 request from the given stream.
/// Parses "GET /path\r\n" and sends the file contents followed by a FIN.
fn serveHttp09(conn: *quic.Connection, stream_id: u62, www: []const u8, io: std.Io) void {
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

    var full_path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ www, path }) catch {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };

    const file = std.Io.Dir.openFileAbsolute(io, full_path, .{}) catch {
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };
    defer file.close(io);

    var data_buf: [65536]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const r = file.readPositionalAll(io, &data_buf, offset) catch break;
        if (r == 0) break;
        conn.streamSend(stream_id, data_buf[0..r], false) catch break;
        offset += r;
    }
    conn.streamSend(stream_id, &.{}, true) catch {};
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
