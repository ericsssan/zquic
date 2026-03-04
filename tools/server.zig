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
// Chunk size must fit inside a single QUIC packet (MAX_DATAGRAM=1452 minus
// short header ~13 + AEAD 16 + STREAM frame header ~17 = ~46 bytes overhead).
const SEND_CHUNK: usize = 1200;
// Maximum concurrent file transfers per connection.
const MAX_TRANSFERS = 64;

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
    // Check this FIRST before attempting to load certs, so that compliance
    // checks with unsupported testcases exit cleanly with 127.
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

    var cert_pem_buf: [65536]u8 = undefined;
    var key_pem_buf: [8192]u8 = undefined;
    const cert_pem_len = readFileFull(io, cert_path, &cert_pem_buf) catch |err| {
        std.debug.print("Failed to read certificate from {s}: {}\n", .{ cert_path, err });
        std.process.exit(127);
    };
    const key_pem_len = readFileFull(io, key_path, &key_pem_buf) catch |err| {
        std.debug.print("Failed to read key from {s}: {}\n", .{ key_path, err });
        std.process.exit(127);
    };

    var cert_der_buf: [65536]u8 = undefined;
    var key_der_buf: [4096]u8 = undefined;
    const cert_der_len = try pem.pemToDer(cert_pem_buf[0..cert_pem_len], &cert_der_buf);
    const key_der_len = try pem.pemToDerBlock(key_pem_buf[0..key_pem_len], "PRIVATE KEY", &key_der_buf);
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
        .initial_quic_version = if (std.mem.eql(u8, testcase, "v2")) quic.packet.QUIC_VERSION_2 else quic.packet.QUIC_VERSION_1,
        .initial_max_streams_bidi = if (std.mem.eql(u8, testcase, "transfer")) 512 else 100,
        .initial_max_streams_uni = if (std.mem.eql(u8, testcase, "transfer")) 100 else 100,
    };

    // Bind UDP socket.
    const bind_addr = net.IpAddress{ .ip6 = net.Ip6Address.unspecified(port) };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);

    std.debug.print("zquic interop server: testcase={s} port={d}\n", .{ testcase, port });

    var recv_buf: [MAX_DATAGRAM]u8 = undefined;
    var send_buf: [MAX_DATAGRAM]u8 = undefined;

    // Accept and handle connections one at a time.
    while (true) {
        var conn = try quic.Connection.accept(config, io);
        var peer_addr: ?net.IpAddress = null;
        var last_logged_generation: u32 = 0;

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
            if (msg.data.len >= 1) {
                const is_long = (msg.data[0] & 0x80) != 0;
                if (is_long and msg.data.len >= 6) {
                    const ver = std.mem.readInt(u32, msg.data[1..5], .big);
                    const dcid_len = msg.data[5];
                    const pkt_type_str = switch ((msg.data[0] >> 4) & 0x03) {
                        0 => "Initial",
                        1 => "0-RTT",
                        2 => "Handshake",
                        3 => "Retry",
                        else => "?",
                    };
                    std.debug.print("recv LONG pkt: len={d} type={s} first=0x{x:0>2} ver=0x{x:0>8} dcid_len={d}\n",
                        .{ msg.data.len, pkt_type_str, msg.data[0], ver, dcid_len });
                    if (dcid_len > 0 and msg.data.len >= 6 + dcid_len) {
                        std.debug.print("  dcid=", .{});
                        for (msg.data[6..][0..dcid_len]) |b| std.debug.print("{x:0>2}", .{b});
                        std.debug.print("\n", .{});
                    }
                    const scid_off: usize = 6 + dcid_len;
                    if (msg.data.len > scid_off) {
                        const scid_len = msg.data[scid_off];
                        std.debug.print("  scid_len={d}", .{scid_len});
                        if (scid_len > 0 and msg.data.len >= scid_off + 1 + scid_len) {
                            std.debug.print(" scid=", .{});
                            for (msg.data[scid_off + 1 ..][0..scid_len]) |b| std.debug.print("{x:0>2}", .{b});
                        }
                        std.debug.print("\n", .{});
                    }
                } else if (!is_long) {
                    // Short header: byte 0 layout: 0 1 spin reserved reserved key_phase pn_len[1:0]
                    const key_phase = (msg.data[0] >> 2) & 1;
                    // DCID = our SCID = local_cid (8 bytes after first byte)
                    std.debug.print("recv 1-RTT pkt: len={d} first=0x{x:0>2} key_phase={d}", .{ msg.data.len, msg.data[0], key_phase });
                    if (msg.data.len >= 9) { // 1 + 8
                        std.debug.print(" dcid=", .{});
                        for (msg.data[1..9]) |b| std.debug.print("{x:0>2}", .{b});
                    }
                    std.debug.print("\n", .{});
                }
            }
            conn.receive(msg.data, ipToSocketAddr(msg.from), now_ns, io) catch |err| {
                std.debug.print("receive error: {}\n", .{err});
            };
            std.debug.print("  -> state={s} key_phase={d} gen={d}/{d} peer_scid=", .{ @tagName(conn.hot.state), @intFromBool(conn.current_key_phase), conn.current_key_generation, last_logged_generation });
            for (conn.peer_scid[0..conn.peer_scid_len]) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print(" local_cid=", .{});
            for (conn.local_cid.bytes) |b| std.debug.print("{x:0>2}", .{b});
            std.debug.print("\n", .{});

            // If key rotation occurred, update keylog immediately (don't wait for connection_closed)
            if (conn.current_key_generation > last_logged_generation) {
                std.debug.print("[keylog] updating keylog (gen was {d}, now {d})\n", .{ last_logged_generation, conn.current_key_generation });
                updateKeyLog(&conn, io, last_logged_generation);
                last_logged_generation = conn.current_key_generation;
            }

            while (conn.pollEvent()) |ev| {
                std.debug.print("  -> event: {s}\n", .{@tagName(ev)});
                switch (ev) {
                    .connected => {
                        std.debug.print("handshake complete\n", .{});
                        writeKeyLog(&conn, io);
                        last_logged_generation = 0; // Mark that gen 0 has been written
                    },
                    .retry_sent => {
                        drainSend(&conn, &sock, io, &msg.from, &send_buf);
                        break :conn_loop;
                    },
                    .stream_data => |s| startTransfer(&conn, s.stream_id, &transfers, www_dir),
                    .connection_closed => {
                        // Note: appendRotatedSecretsToKeyLog is not called here because
                        // keylog updates now happen incrementally in the main loop above
                        break :conn_loop;
                    },
                    else => {},
                }
            }

            // Advance any pending file transfers now that the send window may have grown.
            flushTransfers(&conn, &transfers, www_dir, io);

            // DO NOT actively close the connection after transfers complete.
            // The client is responsible for closing the connection when it's done downloading.
            // For "multiplexing" test with 2000 files but only 8 transfer slots, closing after
            // the first batch would prematurely terminate the connection. Instead, rely on the
            // idle timeout (configured by the client) to clean up abandoned connections.

            std.debug.print("  sq depth={d}\n", .{conn.sq_tail - conn.sq_head});
            var sent_bytes: usize = 0;
            var pkt_count: usize = 0;
            while (true) {
                const n = conn.send(&send_buf);
                if (n == 0) break;
                pkt_count += 1;
                if (n >= 1 and (send_buf[0] & 0x80) != 0 and n >= 6) {
                    // Long header: print type, ver, dcid, scid
                    const ver = std.mem.readInt(u32, send_buf[1..5], .big);
                    const dcid_len = send_buf[5];
                    const pkt_type_str = switch ((send_buf[0] >> 4) & 0x03) {
                        0 => "Initial",
                        1 => "0-RTT",
                        2 => "Handshake",
                        3 => "Retry",
                        else => "?",
                    };
                    std.debug.print("  send[{d}] LONG {s}: len={d} first=0x{x:0>2} ver=0x{x:0>8}", .{ pkt_count, pkt_type_str, n, send_buf[0], ver });
                    if (n >= 6 + dcid_len + 1) {
                        if (dcid_len > 0) {
                            std.debug.print(" dcid=", .{});
                            for (send_buf[6..][0..dcid_len]) |b| std.debug.print("{x:0>2}", .{b});
                        } else {
                            std.debug.print(" dcid=(empty)", .{});
                        }
                        const scid_len = send_buf[6 + dcid_len];
                        std.debug.print(" scid_len={d}", .{scid_len});
                        const scid_off: usize = 6 + dcid_len + 1;
                        if (scid_len > 0 and n >= scid_off + scid_len) {
                            std.debug.print(" scid=", .{});
                            for (send_buf[scid_off..][0..scid_len]) |b| std.debug.print("{x:0>2}", .{b});
                        }
                    }
                    std.debug.print("\n", .{});
                } else if (n >= 1 and (send_buf[0] & 0x80) == 0) {
                    // Short header 1-RTT
                    const key_phase = (send_buf[0] >> 2) & 1;
                    std.debug.print("  send[{d}] 1-RTT: len={d} first=0x{x:0>2} key_phase={d}", .{ pkt_count, n, send_buf[0], key_phase });
                    if (n >= 9) {
                        std.debug.print(" dcid=", .{});
                        for (send_buf[1..9]) |b| std.debug.print("{x:0>2}", .{b});
                    }
                    std.debug.print("\n", .{});
                } else {
                    std.debug.print("  send[{d}]: len={d} first=0x{x:0>2}\n", .{ pkt_count, n, send_buf[0] });
                }
                sock.send(io, &msg.from, send_buf[0..n]) catch |e| {
                    std.debug.print("  send error: {}\n", .{e});
                };
                sent_bytes += n;
            }
            if (sent_bytes > 0) std.debug.print("  -> sent {d} bytes in {d} pkts\n", .{ sent_bytes, pkt_count });
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

    // Loop until the send queue is full or EOF is reached so we fill the
    // congestion window on every event rather than sending one chunk at a time.
    while (true) {
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
            // Send queue or flow-control window full — retry next tick.
            return;
        };
        t.offset += r;
    }
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

/// Update SSLKEYLOG file with newly rotated keys. Rewrites the entire file
/// with all generations up to current. Called immediately after key rotation
/// to ensure Wireshark can decrypt packets before connection closes.
fn updateKeyLog(conn: *const quic.Connection, io: std.Io, _: u32) void {
    const tls = &conn.tls_state;
    const random_hex = std.fmt.bytesToHex(tls.client_random, .lower);
    var buf: [16384]u8 = undefined;
    var pos: usize = 0;

    // Write handshake secrets (same as initial)
    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    // Write all generations (0 through current)
    var gen: u32 = 0;
    while (gen <= conn.current_key_generation) : (gen += 1) {
        const secrets = conn.deriveSecretsForGeneration(gen);
        line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_{d} {s} {s}\n",
            .{ gen, random_hex, std.fmt.bytesToHex(secrets.client, .lower) }) catch return;
        pos += line.len;

        line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_{d} {s} {s}\n",
            .{ gen, random_hex, std.fmt.bytesToHex(secrets.server, .lower) }) catch return;
        pos += line.len;

        if (pos >= buf.len - 256) break;
    }

    // Overwrite the keylog file with all generations
    const file = std.Io.Dir.createFileAbsolute(io, "/logs/keys.log", .{}) catch return;
    defer file.close(io);
    file.writePositionalAll(io, buf[0..pos], 0) catch {};
    std.debug.print("keylog updated (generations 0..{d}, {d} bytes)\n", .{ conn.current_key_generation, pos });
}

/// Write an SSLKEYLOG file so network analyzers (Wireshark/tshark) can decrypt
/// 1-RTT QUIC packets including those with key updates.  Written to /logs/keys.log
/// (the path the interop runner expects for server logs).
/// Writes initial secrets at handshake, then appends rotated secrets dynamically.
fn writeKeyLog(conn: *const quic.Connection, io: std.Io) void {
    const tls = &conn.tls_state;
    const random_hex = std.fmt.bytesToHex(tls.client_random, .lower);
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    // Write handshake secrets
    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    // Write initial application secrets (generation 0)
    const secrets_0 = conn.deriveSecretsForGeneration(0);
    line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_0 {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(secrets_0.client, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_0 {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(secrets_0.server, .lower) }) catch return;
    pos += line.len;

    const file = std.Io.Dir.createFileAbsolute(io, "/logs/keys.log", .{}) catch return;
    defer file.close(io);
    file.writePositionalAll(io, buf[0..pos], 0) catch {};
    std.debug.print("keylog written ({d} bytes)\n", .{pos});
}

/// Update SSLKEYLOG file with any new rotated keys. Called after key updates to
/// ensure Wireshark can decrypt packets with new keys. Rewrites the entire file
/// with all generations up to the current key generation.
fn appendRotatedSecretsToKeyLog(conn: *const quic.Connection, io: std.Io) void {
    std.debug.print("appendRotatedSecretsToKeyLog called (gen={d})\n", .{conn.current_key_generation});
    const tls = &conn.tls_state;
    const random_hex = std.fmt.bytesToHex(tls.client_random, .lower);
    var buf: [16384]u8 = undefined;
    var pos: usize = 0;

    // Skip if no key rotations occurred
    if (conn.current_key_generation == 0) {
        std.debug.print("  -> skipping (no rotations)\n", .{});
        return;
    }

    // Write handshake secrets
    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n",
        .{ random_hex, std.fmt.bytesToHex(tls.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    // Write all generations (0 through current)
    var gen: u32 = 0;
    while (gen <= conn.current_key_generation) : (gen += 1) {
        const secrets = conn.deriveSecretsForGeneration(gen);
        line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_{d} {s} {s}\n",
            .{ gen, random_hex, std.fmt.bytesToHex(secrets.client, .lower) }) catch return;
        pos += line.len;

        line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_{d} {s} {s}\n",
            .{ gen, random_hex, std.fmt.bytesToHex(secrets.server, .lower) }) catch return;
        pos += line.len;

        if (pos >= buf.len - 256) break; // Avoid buffer overflow
    }

    // Overwrite the keylog file with all generations
    const file = std.Io.Dir.createFileAbsolute(io, "/logs/keys.log", .{}) catch return;
    defer file.close(io);
    file.writePositionalAll(io, buf[0..pos], 0) catch {};
    std.debug.print("keylog updated ({d} bytes with generations 0..{d})\n", .{ pos, conn.current_key_generation });
}

fn ipToSocketAddr(addr: net.IpAddress) quic.SocketAddr {
    return switch (addr) {
        .ip4 => |a| .{ .v4 = .{ .addr = a.bytes, .port = a.port } },
        .ip6 => |a| .{ .v6 = .{ .addr = a.bytes, .port = a.port } },
    };
}
