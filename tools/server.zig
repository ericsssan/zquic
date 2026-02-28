//! zquic interop server — throwaway UDP shim for end-to-end testing.
//!
//! Drives Connection.accept() from a real UDP socket so the TLS handshake
//! and stream transfer can be verified against third-party QUIC clients.
//! Single-connection, blocking I/O loop; not intended for production use.

const std = @import("std");
const quic = @import("zquic");

const net = std.Io.net;
const DEFAULT_PORT: u16 = 4433;
const MAX_DATAGRAM = 1452;

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    var args_iter = std.process.Args.Iterator.init(init.minimal.args);
    _ = args_iter.next(); // skip argv[0]
    const port: u16 = if (args_iter.next()) |arg|
        std.fmt.parseInt(u16, arg, 10) catch DEFAULT_PORT
    else
        DEFAULT_PORT;

    const bind_addr = net.IpAddress{ .ip4 = net.Ip4Address.unspecified(port) };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);

    std.debug.print("zquic server listening on :{d}\n", .{port});

    var recv_buf: [MAX_DATAGRAM]u8 = undefined;
    var send_buf: [MAX_DATAGRAM]u8 = undefined;

    while (true) {
        var conn = try quic.Connection.accept(.{}, io);
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
                    .stream_data => |s| echoStream(&conn, s.stream_id),
                    .connection_closed => break :conn_loop,
                    else => {},
                }
            }
        }
    }
}

fn drainSend(conn: *quic.Connection, sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, buf: *[MAX_DATAGRAM]u8) void {
    while (true) {
        const n = conn.send(buf);
        if (n == 0) break;
        sock.send(io, dest, buf[0..n]) catch {};
    }
}

fn echoStream(conn: *quic.Connection, stream_id: u62) void {
    const st = conn.streams.get(stream_id) orelse return;
    var tmp: [4096]u8 = undefined;
    _ = st.read(&tmp);
    // stub: just close the stream with a FIN
    conn.streamSend(stream_id, &.{}, true) catch {};
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
