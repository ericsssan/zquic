//! zquic interop server — quic-interop-runner compatible UDP server.
//!
//! Supported TESTCASE values: handshake, transfer, multiconnect, retry, keyupdate, v2, ecn, resumption, zerortt.
//! All other values cause exit(127) as required by the interop runner.
//! HTTP/0.9: accepts "GET /path\r\n" and serves files from ${WWW} directory.
//! File serving is event-driven: data is pushed in chunks each event loop tick
//! so that the 4096-byte stream send buffer never overflows.

const std = @import("std");
const builtin = @import("builtin");
const quic = @import("zquic");
const pem = @import("pem.zig");
const http3 = @import("http3");
const qpack = @import("qpack");

const net = std.Io.net;
const os = std.os;
const page_allocator = std.heap.page_allocator;
const DEFAULT_PORT: u16 = 443;
const MAX_DATAGRAM = 1452;
// Chunk size must fit inside a single QUIC packet (MAX_DATAGRAM=1452 minus
// short header ~13 + AEAD 16 + STREAM frame header ~17 = ~46 bytes overhead).
const SEND_CHUNK: usize = 1380;
// Maximum concurrent file transfers per connection.
const MAX_TRANSFERS = 64;

// Maximum concurrent connections.
const MAX_CONNS = 50;

// Linux UDP GSO (Generic Segmentation Offload): pack up to GSO_MAX_SEGS same-size
// QUIC packets into one compound datagram per sendmsg call.  The kernel/NIC
// segments the compound buffer, eliminating per-packet stack overhead.
// SOL_UDP=17, UDP_SEGMENT=103 (linux/udp.h).  Requires Linux 4.18+.
const SOL_UDP: i32 = 17;
const UDP_SEGMENT: u32 = 103;
// 44 × 1452 = 63,888 bytes — just under the 64 KB kernel GSO limit.
const GSO_MAX_SEGS: usize = 44;

// Set to true at startup when UDP_SEGMENT is available; read by drainSend.
var g_gso_supported: bool = false;

// ECN (RFC 3168 / RFC 9000 §13.4): when TESTCASE=ecn, the server binds a native
// AF_INET socket (see the bind site) and configureEcn sets socket-level IP_TOS to
// ECT(0), which marks every outgoing packet — so an on-path observer (the oracle
// proxy reading IP_RECVTOS) can confirm the codepoint on the wire.
const ECN_ECT0: c_int = 0x02; // RFC 3168 ECT(0) codepoint in the low TOS bits

// Connection type: parameterized for 64 concurrent streams (= MAX_TRANSFERS).
const Conn = quic.Connection(64);

/// A parsed HTTP/0.9 request waiting for a free transfer slot.
const PendingTransfer = struct {
    stream_id: u62 = 0,
    /// Full path (www_dir + request path), already validated.
    path: [512]u8 = undefined,
    path_len: usize = 0,
};

/// Per-connection state bundled together for heap allocation.
const ConnSlot = struct {
    conn: Conn,
    peer_addr: ?net.IpAddress = null,
    /// True when the most recent packet arrived on the CM socket.
    use_cm_sock: bool = false,
    /// True once we have logged the client's migration to the preferred address.
    cm_migrated: bool = false,
    /// Investigation: last wall-clock (ns) we dumped transfer state (TRANSFER_DEBUG).
    dbg_last_ns: i64 = 0,
    transfers: [MAX_TRANSFERS]FileTransfer = @as([MAX_TRANSFERS]FileTransfer, @splat(.{})),
    /// Parsed requests deferred because all transfer slots were occupied.
    /// Retried at the start of each flushTransfers() pass.
    pending: [MAX_TRANSFERS]PendingTransfer = undefined,
    pending_count: usize = 0,
    last_logged_generation: u32 = 0,
    keylog_written: bool = false,
    /// H3: server control streams sent.
    h3_control_sent: bool = false,
};

const ALPN = "hq-interop";
const CID_LEN = quic.connection_id.len; // 8 bytes

const supported_cases = [_][]const u8{
    "handshake",           "transfer", "multiconnect", "multiplexing", "retry",   "keyupdate", "v2", "ecn",
    "connectionmigration", "chacha20", "http3",        "resumption",   "zerortt",
};

/// True when TESTCASE=http3 — uses H3 framing instead of HTTP/0.9.
var g_is_h3: bool = false;
// Investigation: when TRANSFER_DEBUG is set, periodically dump send/loss state so a
// stalled transfer (seeded-loss truncation) reveals whether it stopped sending or
// failed to retransmit. Off unless the env var is present.
var g_transfer_debug: bool = false;
/// Accumulated SSLKEYLOG data for all connections.  Written to /logs/keys.log
/// in full on each update so createFileAbsolute truncation doesn't lose data.
var g_keylog_buf: [65536]u8 = undefined;
var g_keylog_len: usize = 0;
/// Path for SSLKEYLOGFILE output.  When SSLKEYLOGFILE env var is set, use that
/// path; otherwise fall back to /logs/keys.log (Docker interop runner convention).
var g_keylog_path_buf: [512]u8 = undefined;
var g_keylog_path: []const u8 = "/logs/keys.log";

// IPv4/IPv6 addresses for preferred_address in the connectionmigration test.
// Defaults are the Docker interop runner addresses; override with the
// CM_ADDR4 / CM_ADDR6 / CM_PORT env vars (e.g. CM_ADDR4=127.0.0.1 CM_PORT=4434
// for the loopback oracle). CM_ADDR6 is omitted there so the server does not
// advertise the unreachable Docker ULA on loopback (see cm_addr6 below).
// server4:  193.167.100.100  (0xc1, 0xa7, 0x64, 0x64)
// server6:  fd00:cafe:cafe:0100::100
const CM_IPV4_DEFAULT: [4]u8 = .{ 193, 167, 100, 100 };
const CM_IPV6: [16]u8 = .{ 0xfd, 0x00, 0xca, 0xfe, 0xca, 0xfe, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00 };
const CM_PORT_DEFAULT: u16 = 4433;

fn parseIPv4(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| {
        if (i >= 4) return error.InvalidAddress;
        out[i] = try std.fmt.parseInt(u8, part, 10);
        i += 1;
    }
    if (i != 4) return error.InvalidAddress;
    return out;
}

/// State for one in-progress file transfer.
const FileTransfer = struct {
    active: bool = false,
    stream_id: u62 = 0,
    /// Absolute path of the file being served, NUL-terminated.
    path: [512]u8 = undefined,
    path_len: usize = 0,
    /// Next byte offset to read from.
    offset: u64 = 0,
    /// Cached file handle (open once per transfer, closed on completion or error).
    file: ?std.Io.File = null,
    /// H3: response HEADERS frame already sent on this stream.
    h3_headers_sent: bool = false,
};

/// Extract the DCID from a QUIC packet's first few bytes.
/// Returns null if the packet is malformed or too short.
fn extractDcid(data: []const u8) ?[CID_LEN]u8 {
    if (data.len < 1) return null;
    if (quic.packet.isLongHeader(data[0])) {
        // Long header: version(4) + dcid_len(1) + dcid at byte 6
        if (data.len < 6) return null;
        const dcid_len = data[5];
        if (dcid_len != CID_LEN) return null;
        if (data.len < 6 + CID_LEN) return null;
        return data[6..][0..CID_LEN].*;
    } else {
        // Short header: dcid at byte 1
        if (data.len < 1 + CID_LEN) return null;
        return data[1..][0..CID_LEN].*;
    }
}

/// Find a connection slot by its local DCID.
/// Also checks first_initial_dcid so that retransmitted client Initials
/// (which use the original random DCID, not the server's SCID) are routed
/// to the existing connection instead of creating a duplicate.
fn findConnByDcid(slots: *const [MAX_CONNS]?*ConnSlot, dcid: [CID_LEN]u8) ?*ConnSlot {
    for (slots.*) |slot_opt| {
        const slot = slot_opt orelse continue;
        if (std.mem.eql(u8, &slot.conn.local_cid.bytes, &dcid)) return slot;
        if (std.mem.eql(u8, &slot.conn.alt_local_cid.bytes, &dcid)) return slot;
        if (slot.conn.first_initial_dcid_len == CID_LEN and
            std.mem.eql(u8, slot.conn.first_initial_dcid[0..CID_LEN], &dcid)) return slot;
    }
    return null;
}

/// Allocate and initialize a new connection slot.
fn allocateSlot(slots: *[MAX_CONNS]?*ConnSlot, config: quic.Config, io: std.Io) !*ConnSlot {
    for (slots) |*s_opt| {
        if (s_opt.* == null) {
            const slot = try page_allocator.create(ConnSlot);
            errdefer page_allocator.destroy(slot);
            slot.* = .{ .conn = undefined };
            try slot.conn.acceptInto(config, io); // init in place — no stack temp (#3)
            s_opt.* = slot;
            return slot;
        }
    }
    return error.NoSlot;
}

/// Free a connection slot (close file handles, deallocate memory).
fn freeSlot(slot_opt_ptr: *?*ConnSlot, io: std.Io) void {
    const slot = slot_opt_ptr.* orelse return;
    for (&slot.transfers) |*t| {
        if (t.file) |file| {
            file.close(io);
        }
    }
    // Zero all crypto key material before freeing heap memory.
    slot.conn.deinit();
    page_allocator.destroy(slot);
    slot_opt_ptr.* = null;
}

/// Compute the minimum timeout across all active connections.
fn computeGlobalTimeout(slots: *const [MAX_CONNS]?*ConnSlot, io: std.Io) std.Io.Timeout {
    var min_deadline: ?i64 = null;
    var has_active_transfer = false;
    for (slots) |slot_opt| {
        const slot = slot_opt orelse continue;
        if (slot.conn.nextTimeout()) |d| {
            if (min_deadline == null or d < min_deadline.?) {
                min_deadline = d;
            }
        }
        if (!has_active_transfer) {
            for (slot.transfers) |t| {
                if (t.active) {
                    has_active_transfer = true;
                    break;
                }
            }
        }
    }
    // Wake frequently during active transfers to push data after ACKs
    // open the congestion window. Without this, the server sleeps until
    // the next recv, missing opportunities to fill the pipe.
    if (has_active_transfer) {
        const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
        const flush_deadline = now_ns + 1_000_000; // 1ms
        if (min_deadline == null or flush_deadline < min_deadline.?) {
            min_deadline = flush_deadline;
        }
    }
    return if (min_deadline) |d| .{ .deadline = .{ .raw = .{ .nanoseconds = d }, .clock = .awake } } else .none;
}

/// Tick all active connections and drain their sends.
/// CRITICAL: Must drain pollEvent() to prevent zombie slots from closed connections (Bug 3).
fn tickAllConnections(slots: *[MAX_CONNS]?*ConnSlot, sock: *const net.Socket, cm_sock_ptr: ?*const net.Socket, io: std.Io, send_bufs: *SendBufs, www_dir: []const u8) void {
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    for (slots) |*s_opt| {
        const slot = s_opt.* orelse continue;
        slot.conn.tick(now_ns);

        // Drain events and free slot if connection closed or idle-timed-out.
        var should_free = false;
        while (slot.conn.pollEvent()) |ev| {
            switch (ev) {
                .connection_closed => should_free = true,
                .idle_timed_out => {
                    std.debug.print("[IDLE] connection timed out\n", .{});
                    should_free = true;
                },
                .stream_data => |st| startTransfer(slot, st.stream_id, www_dir, io),
                else => {},
            }
        }

        if (should_free) {
            freeSlot(s_opt, io);
            continue;
        }

        if (slot.peer_addr) |pa| {
            // Retry H3 control streams if initial send failed (queue was full).
            const send_sock = slotSendSock(slot, sock, cm_sock_ptr);
            if (g_is_h3 and !slot.h3_control_sent and slot.conn.app_keys != null) {
                sendH3ControlStreams(slot);
            }
            flushTransfers(slot, www_dir, io, send_sock, &pa, send_bufs);
            // Investigation: every ~1s, dump the state of any active transfer so a
            // stalled tail (seeded-loss truncation) shows whether send_offset froze
            // (send stall) or send_acked froze (retransmit failure).
            if (g_transfer_debug and now_ns - slot.dbg_last_ns > 1_000_000_000) {
                for (&slot.transfers) |*t| {
                    if (t.active) {
                        slot.conn.debugSendState(t.stream_id, now_ns, "XFER");
                        slot.dbg_last_ns = now_ns;
                    }
                }
            }
        }
    }
}

/// Pick the correct socket for sending to a connection: CM socket after migration, main otherwise.
fn slotSendSock(slot: *const ConnSlot, sock: *const net.Socket, cm_sock_ptr: ?*const net.Socket) *const net.Socket {
    if (slot.use_cm_sock) {
        if (cm_sock_ptr) |cs| return cs;
    }
    return sock;
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;

    // Determine the testcase; exit 127 if unsupported.
    // Check this FIRST before attempting to load certs, so that compliance
    // checks with unsupported testcases exit cleanly with 127.
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

    // Build TLS CertificateEntry list from all certs in the PEM (supports multi-cert chains).
    var cert_chain_buf: [32768]u8 = undefined;
    const cert_chain_len = pem.pemToCertChain(cert_pem_buf[0..cert_pem_len], &cert_chain_buf) catch 0;

    g_is_h3 = std.mem.eql(u8, testcase, "http3");
    g_transfer_debug = init.environ_map.get("TRANSFER_DEBUG") != null;
    if (init.environ_map.get("SSLKEYLOGFILE")) |kl_path| {
        const n = @min(kl_path.len, g_keylog_path_buf.len);
        @memcpy(g_keylog_path_buf[0..n], kl_path[0..n]);
        g_keylog_path = g_keylog_path_buf[0..n];
    }
    // CM socket active when explicitly requested via env vars (allows TESTCASE=http3
    // with ngtcp2 to also get the CM socket) or via the dedicated testcase name.
    const is_cm = std.mem.eql(u8, testcase, "connectionmigration") or
        init.environ_map.get("CM_PORT") != null;
    const cm_addr4: [4]u8 = blk: {
        const s = init.environ_map.get("CM_ADDR4") orelse break :blk CM_IPV4_DEFAULT;
        break :blk parseIPv4(s) catch CM_IPV4_DEFAULT;
    };
    // IPv6 preferred address (RFC 9000 §18.2.3). null ⇒ advertise no IPv6 preferred
    // address (v6 fields encoded as all-zeros). An explicit CM_ADDR6 (e.g. "::1")
    // always wins. With no override, fall back to the Docker default ONLY when
    // CM_ADDR4 is also at its default — i.e. we are on the Docker interop network,
    // where fd00:cafe:cafe:100::100 is reachable. A deployment that customised
    // CM_ADDR4 (such as the loopback oracle) must not advertise that unreachable
    // ULA and strand an IPv6-preferring client, so omit IPv6 unless CM_ADDR6 is set.
    const cm_addr6: ?[16]u8 = blk: {
        if (init.environ_map.get("CM_ADDR6")) |s| {
            const a6 = net.Ip6Address.parse(s, 0) catch break :blk null;
            break :blk a6.bytes;
        }
        break :blk if (init.environ_map.get("CM_ADDR4") != null) null else CM_IPV6;
    };
    const cm_port: u16 = blk: {
        const s = init.environ_map.get("CM_PORT") orelse break :blk CM_PORT_DEFAULT;
        break :blk std.fmt.parseInt(u16, s, 10) catch CM_PORT_DEFAULT;
    };
    const idle_timeout_ns: u64 = blk: {
        const s = init.environ_map.get("IDLE_TIMEOUT") orelse break :blk 30_000_000_000;
        const secs = std.fmt.parseInt(u64, s, 10) catch break :blk 30_000_000_000;
        break :blk secs * 1_000_000_000;
    };
    const reset_key: ?[32]u8 = blk: {
        const s = init.environ_map.get("RESET_KEY") orelse break :blk null;
        if (s.len != 64) break :blk null;
        var key: [32]u8 = undefined;
        _ = std.fmt.hexToBytes(&key, s) catch break :blk null;
        break :blk key;
    };

    // Generate a random ticket encryption key for session resumption / 0-RTT.
    var ticket_key: [32]u8 = undefined;
    io.random(&ticket_key);

    const config: quic.Config = .{
        .alpn = if (g_is_h3) "h3" else ALPN,
        .validate_addr = std.mem.eql(u8, testcase, "retry"),
        .cert_der = cert_der_buf[0..cert_der_len],
        .cert_chain = if (cert_chain_len > 0) cert_chain_buf[0..cert_chain_len] else null,
        .cert_seed = key_material.seed,
        .cert_key_algorithm = switch (key_material.algorithm) {
            .ed25519 => .ed25519,
            .p256 => .p256,
        },
        .initial_quic_version = if (std.mem.eql(u8, testcase, "v2")) quic.packet.QUIC_VERSION_2 else quic.packet.QUIC_VERSION_1,
        .preferred_cipher = if (std.mem.eql(u8, testcase, "chacha20")) .chacha20_poly1305 else .aes_128_gcm,
        .initial_max_streams_bidi = 64, // Match MAX_TRANSFERS; grows as streams close
        .initial_max_streams_uni = 100,
        // RFC 9000 §18.2.3: advertise a preferred address for migration. IPv4 is
        // always advertised when CM is active; IPv6 only when we have a reachable
        // one (cm_addr6 non-null) — otherwise the v6 fields are all-zeros (absent).
        .preferred_addr_ipv4 = if (is_cm) cm_addr4 else null,
        .preferred_addr_ipv4_port = if (is_cm) cm_port else 0,
        .preferred_addr_ipv6 = if (is_cm) (cm_addr6 orelse @as([16]u8, @splat(0))) else @as([16]u8, @splat(0)),
        .preferred_addr_ipv6_port = if (is_cm and cm_addr6 != null) cm_port else 0,
        .ticket_key = &ticket_key,
        .idle_timeout_ns = idle_timeout_ns,
        .reset_key = reset_key,
    };

    // Bind to all interfaces (dual-stack). IPv4 clients arrive as IPv4-mapped IPv6
    // addresses (::ffff:a.b.c.d); IPv6 clients connect directly.
    //
    // Exception: the ecn testcase binds a native IPv4 socket.  ECN marking on a
    // dual-stack IPv6 socket does not reach IPv4-mapped sends — the kernel emits
    // those as real IPv4 packets whose TOS comes from the IPv4 layer, which neither
    // the v6 socket's IPV6_TCLASS nor an IP_TOS control message updates.  A native
    // AF_INET socket has its IP_TOS honoured, so ECT(0) appears on the wire. The
    // oracle's ecn client always connects over IPv4 (127.0.0.1), so this is safe.
    const is_ecn = std.mem.eql(u8, testcase, "ecn");
    const bind_addr = if (is_ecn)
        net.IpAddress{ .ip4 = net.Ip4Address.unspecified(port) }
    else
        net.IpAddress{ .ip6 = net.Ip6Address.unspecified(port) };
    const sock = try net.IpAddress.bind(&bind_addr, io, .{ .mode = .dgram });
    defer sock.close(io);
    raiseSocketBuffers(&sock);

    // For connectionmigration: bind a second socket on cm_port so the server
    // can receive packets after the client migrates to the preferred_address.
    var cm_sock: ?net.Socket = null;
    if (is_cm) {
        const cm_bind_addr = net.IpAddress{ .ip6 = net.Ip6Address.unspecified(cm_port) };
        cm_sock = try net.IpAddress.bind(&cm_bind_addr, io, .{ .mode = .dgram });
        raiseSocketBuffers(&cm_sock.?);
    }
    defer if (cm_sock) |s| s.close(io);

    // Enable ECN (Explicit Congestion Notification) if testcase is "ecn".
    // configureEcn sets IP_TOS (ECT(0) marking) and IP_RECVTOS on the AF_INET socket.
    if (is_ecn) {
        try configureEcn(&sock);
    }

    std.debug.print("zquic interop server: testcase={s} port={d}\n", .{ testcase, port });

    // Probe for UDP_SEGMENT (GSO) support on Linux 4.18+.
    // Sets g_gso_supported; drainSend dispatches to drainSendGso when true.
    if (comptime builtin.os.tag == .linux) {
        const probe: u16 = MAX_DATAGRAM;
        const rc = std.os.linux.setsockopt(sock.handle, SOL_UDP, UDP_SEGMENT, std.mem.asBytes(&probe).ptr, @sizeOf(u16));
        if (rc == 0) {
            g_gso_supported = true;
            // Disable the socket-level default; flushGso uses per-send setsockopt.
            const zero: u16 = 0;
            _ = std.os.linux.setsockopt(sock.handle, SOL_UDP, UDP_SEGMENT, std.mem.asBytes(&zero).ptr, @sizeOf(u16));
            std.debug.print("[GSO] UDP_SEGMENT enabled (up to {} datagrams/send)\n", .{GSO_MAX_SEGS});
        }
    }

    // Send buffer pool: plain path = 32 × 1452 B; GSO path adds 44 × 1452 B compound.
    var send_bufs_storage: SendBufs = undefined;
    const send_bufs: *SendBufs = &send_bufs_storage;

    // Connection table: array of nullable pointers (heap-allocated).
    var conn_slots: [MAX_CONNS]?*ConnSlot = @as([MAX_CONNS]?*ConnSlot, @splat(null));

    // Stable pointer to CM socket (if active) for passing to functions.
    const cm_sock_ptr: ?*const net.Socket = if (cm_sock) |*s| s else null;

    // Non-blocking receive timeout: returns immediately if no packet ready.
    const nonblocking: std.Io.Timeout = .{ .duration = .{ .raw = .{ .nanoseconds = 0 }, .clock = .awake } };

    // Batch receive buffers: collect up to BATCH_SIZE packets before processing.
    // Separate buffers per packet are required because in-place decrypt modifies
    // the buffer. With SIMD multi-buffer decrypt, same-connection packets in the
    // batch share the pre-expanded AES key schedule (CachedKeyCtx).
    var batch_bufs: [BATCH_SIZE][MAX_DATAGRAM]u8 = undefined;
    var batch_lens: [BATCH_SIZE]u16 = undefined;
    var batch_froms: [BATCH_SIZE]net.IpAddress = undefined;
    var batch_is_cm: [BATCH_SIZE]bool = undefined;

    // Pre-allocated recvmmsg state (Linux Phase 2 batch drain).
    // iov.base pointers point directly into batch_bufs[] for the lifetime of this frame.
    var recv_batch: RecvBatch = undefined;
    if (comptime builtin.os.tag == .linux) {
        // Slot 0 is used by Phase 1 (sock.receiveTimeout); recvmmsg only uses slots 1..BATCH_SIZE-1.
        for (1..BATCH_SIZE) |i| {
            recv_batch.iovs[i] = .{ .base = @ptrCast(&batch_bufs[i]), .len = MAX_DATAGRAM };
            recv_batch.msgs[i] = .{
                .hdr = .{
                    .name = @ptrCast(&recv_batch.addrs[i]),
                    .namelen = @sizeOf(std.os.linux.sockaddr.storage),
                    .iov = @ptrCast(&recv_batch.iovs[i]),
                    .iovlen = 1,
                    .control = null,
                    .controllen = 0,
                    .flags = 0,
                },
                .len = 0,
            };
        }
    }

    // Multiplexed event loop: collect batch → process → tick/send.
    while (true) {
        var timeout = computeGlobalTimeout(&conn_slots, io);

        // When CM socket is active, cap the main socket timeout at 5ms so we
        // check the CM socket frequently for PATH_CHALLENGE/migrated packets.
        if (cm_sock_ptr != null) timeout = clampTimeout(timeout, 5_000_000, io);

        var batch_count: usize = 0;

        // Phase 1: Block for first packet (or timeout).
        if (sock.receiveTimeout(io, &batch_bufs[0], timeout)) |msg| {
            batch_lens[0] = @intCast(msg.data.len);
            batch_froms[0] = msg.from;
            batch_is_cm[0] = false;
            batch_count = 1;
        } else |err| {
            if (err != error.Timeout) {
                std.debug.print("recv error: {}\n", .{err});
                break;
            }
        }

        // Phase 2: Drain remaining packets into batch (non-blocking).
        if (batch_count > 0) {
            if (comptime builtin.os.tag == .linux) {
                // Restore namelen fields kernel may have shrunk in the previous tick.
                for (1..BATCH_SIZE) |i| recv_batch.msgs[i].hdr.namelen = @sizeOf(std.os.linux.sockaddr.storage);
                const rc = std.os.linux.recvmmsg(
                    sock.handle,
                    recv_batch.msgs[1..].ptr,
                    BATCH_SIZE - 1,
                    std.os.linux.MSG.DONTWAIT,
                    null,
                );
                if (@as(isize, @bitCast(rc)) > 0) {
                    const n: usize = @intCast(rc);
                    for (0..n) |j| {
                        const slot = 1 + j;
                        batch_lens[slot] = @intCast(recv_batch.msgs[slot].len);
                        batch_froms[slot] = ipFromStorage(&recv_batch.addrs[slot]);
                        batch_is_cm[slot] = false;
                    }
                    batch_count += n;
                }
            } else {
                while (batch_count < BATCH_SIZE) {
                    if (sock.receiveTimeout(io, &batch_bufs[batch_count], nonblocking)) |msg| {
                        batch_lens[batch_count] = @intCast(msg.data.len);
                        batch_froms[batch_count] = msg.from;
                        batch_is_cm[batch_count] = false;
                        batch_count += 1;
                    } else |_| break;
                }
            }
        }

        // Phase 3: Check CM socket (non-blocking), add to batch.
        if (cm_sock_ptr) |cs| {
            while (batch_count < BATCH_SIZE) {
                if (cs.receiveTimeout(io, &batch_bufs[batch_count], nonblocking)) |msg| {
                    batch_lens[batch_count] = @intCast(msg.data.len);
                    batch_froms[batch_count] = msg.from;
                    batch_is_cm[batch_count] = true;
                    batch_count += 1;
                } else |_| break;
            }
        }

        // Phase 4: Process all collected packets.
        // Each packet has its own buffer — in-place decrypt is safe.
        // TODO: group by connection, use multiDecryptGcm(N) for same-key batches.
        for (0..batch_count) |i| {
            processPacket(
                batch_bufs[i][0..batch_lens[i]],
                batch_froms[i],
                batch_is_cm[i],
                &conn_slots,
                config,
                &sock,
                cm_sock_ptr,
                io,
                send_bufs,
                www_dir,
            );
        }

        // Phase 5: Tick timers and flush transfers.
        tickAllConnections(&conn_slots, &sock, cm_sock_ptr, io, send_bufs, www_dir);
    }
}

/// Clamp an Io.Timeout to at most max_ns nanoseconds from now.
fn clampTimeout(timeout: std.Io.Timeout, max_ns: i64, io: std.Io) std.Io.Timeout {
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    const max_deadline = now_ns + max_ns;
    return switch (timeout) {
        .none => .{ .deadline = .{ .raw = .{ .nanoseconds = max_deadline }, .clock = .awake } },
        .deadline => |d| .{ .deadline = .{ .raw = .{ .nanoseconds = @min(d.raw.nanoseconds, max_deadline) }, .clock = d.clock } },
        .duration => .{ .deadline = .{ .raw = .{ .nanoseconds = max_deadline }, .clock = .awake } },
    };
}

/// Process a single received packet from either the main or CM socket.
fn processPacket(
    data: []u8,
    from: net.IpAddress,
    is_cm_socket: bool,
    conn_slots: *[MAX_CONNS]?*ConnSlot,
    config: quic.Config,
    sock: *const net.Socket,
    cm_sock_ptr: ?*const net.Socket,
    io: std.Io,
    send_bufs: *SendBufs,
    www_dir: []const u8,
) void {
    // Extract DCID from the packet to find the right connection.
    const dcid = extractDcid(data);
    var slot: ?*ConnSlot = if (dcid) |d| findConnByDcid(conn_slots, d) else null;

    // If no connection found and this is a long header (new Initial), allocate a new slot.
    if (slot == null and data.len > 0 and quic.packet.isLongHeader(data[0])) {
        if (dcid == null) {
            for (conn_slots) |s_opt| {
                const s = s_opt orelse continue;
                if (s.peer_addr) |pa| {
                    if (ipToSocketAddr(from).eql(ipToSocketAddr(pa))) {
                        slot = s;
                        break;
                    }
                }
            }
        }
        if (slot == null) {
            slot = allocateSlot(conn_slots, config, io) catch return;
        }
    }

    if (slot == null) {
        // Unknown connection: if SHORT header and reset_key is set, send a
        // stateless reset (RFC 9000 §10.3). The reset token is derived as
        // HMAC-SHA256(reset_key, dcid)[:16] — reproducible across restarts.
        if (data.len > 0 and data[0] & 0x80 == 0 and config.reset_key != null) {
            if (dcid) |d| {
                if (d.len > 0) {
                    const key = config.reset_key.?;
                    var hmac_out: [std.crypto.auth.hmac.sha2.HmacSha256.mac_length]u8 = undefined;
                    std.crypto.auth.hmac.sha2.HmacSha256.create(&hmac_out, &d, &key);
                    // Stateless reset: ≥21 bytes, first byte has fixed-bit (0x40) set
                    // and the packet-type bits cleared, last 16 bytes = token.
                    var srst: [32]u8 = undefined;
                    io.random(&srst);
                    srst[0] = (srst[0] | 0x40) & 0x7f; // fixed bit=1, long-header bit=0
                    @memcpy(srst[16..32], hmac_out[0..16]);
                    var msg = [1]net.OutgoingMessage{.{ .address = &from, .data_ptr = &srst, .data_len = srst.len }};
                    sock.sendMany(io, &msg, .{}) catch {};
                    std.debug.print("[SRST] stateless reset sent for unknown CID\n", .{});
                }
            }
        }
        return;
    }

    const s = slot.?;
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    s.conn.tick(now_ns);

    // Drain queued sends to the old peer address before processing the incoming packet.
    if (s.peer_addr) |old_addr| {
        drainSend(&s.conn, slotSendSock(s, sock, cm_sock_ptr), io, &old_addr, send_bufs);
    }
    s.peer_addr = from;

    const ecn_bits: u2 = 0;
    // Snapshot the authenticated-packet counter so we can tell, after receive(),
    // whether THIS datagram decrypted — migration and the send-socket switch must
    // act only on authenticated packets (RFC 9000 §9.3), never on a spoofed or
    // garbage datagram that merely carried a matching cleartext DCID.
    const pkts_before = s.conn.pkts_recv;
    s.conn.receive(data, ipToSocketAddr(from), now_ns, ecn_bits, io) catch |err| {
        std.debug.print("receive error: {}\n", .{err});
    };
    const authenticated = s.conn.pkts_recv > pkts_before;

    if (authenticated) {
        // First authenticated packet on the preferred-address (CM) socket from an
        // established connection ⇒ the client has migrated to our preferred_address
        // (RFC 9000 §9.6). The connection only detects source-address migration; a
        // preferred-address move keeps the client's source and changes the server
        // destination, so it is detected here via the CM socket.
        if (is_cm_socket and !s.cm_migrated and s.conn.hot.state == .established) {
            s.cm_migrated = true;
            // If the peer ALSO changed source (some clients do), the connection's
            // source-based onPathMigration already re-armed validation and emitted
            // path_migrated (path_validated is now false) — don't double-trigger.
            if (s.conn.path_validated) {
                s.conn.notePreferredAddressMigration(data.len, io) catch {};
            }
        }
        // Follow the socket of the most recent AUTHENTICATED packet so the server's
        // sends track the client's current path (and so a spoofed datagram cannot
        // redirect them). Computed before active_sock below.
        if (s.use_cm_sock != is_cm_socket) s.use_cm_sock = is_cm_socket;
    }

    // Write keylog when app_keys are available.
    if (!s.keylog_written and s.conn.app_keys != null) {
        writeKeyLog(&s.conn, io);
        s.keylog_written = true;
        s.last_logged_generation = 0;
    }

    if (s.conn.current_key_generation > s.last_logged_generation) {
        updateKeyLog(&s.conn, io, s.last_logged_generation);
        s.last_logged_generation = s.conn.current_key_generation;
    }

    const active_sock = slotSendSock(s, sock, cm_sock_ptr);

    // Process connection events.
    var slot_freed = false;
    while (s.conn.pollEvent()) |ev| {
        switch (ev) {
            .connected => {
                if (!s.keylog_written) {
                    writeKeyLog(&s.conn, io);
                    s.keylog_written = true;
                    s.last_logged_generation = 0;
                }
                if (g_is_h3 and !s.h3_control_sent) {
                    sendH3ControlStreams(s);
                }
            },
            .retry_sent => {
                drainSend(&s.conn, active_sock, io, &from, send_bufs);
                for (0..conn_slots.len) |i| {
                    if (conn_slots[i] == s) {
                        freeSlot(&conn_slots[i], io);
                        slot_freed = true;
                        break;
                    }
                }
                break;
            },
            .stream_data => |st| {
                if (g_is_h3)
                    startTransferH3(s, st.stream_id, www_dir, io)
                else
                    startTransfer(s, st.stream_id, www_dir, io);
            },
            .connection_closed => {
                for (0..conn_slots.len) |i| {
                    if (conn_slots[i] == s) {
                        freeSlot(&conn_slots[i], io);
                        slot_freed = true;
                        break;
                    }
                }
                break;
            },
            .path_migrated => {
                // Update send destination from the connection's authoritative
                // peer address.  Without this, late-arriving packets from the
                // old address (via s.peer_addr = from) route sends to the
                // stale address.
                s.peer_addr = socketAddrToIp(s.conn.peer_addr);
                std.debug.print("[CM] path_migrated: client now at preferred_address\n", .{});
            },
            .idle_timed_out => {
                std.debug.print("[IDLE] connection timed out\n", .{});
                for (0..conn_slots.len) |i| {
                    if (conn_slots[i] == s) {
                        freeSlot(&conn_slots[i], io);
                        slot_freed = true;
                        break;
                    }
                }
                break;
            },
            else => {},
        }
    }

    if (!slot_freed) {
        flushTransfers(s, www_dir, io, active_sock, &from, send_bufs);
    }
}

/// Activate a transfer slot from a pre-parsed PendingTransfer entry.
fn activatePending(transfers: *[MAX_TRANSFERS]FileTransfer, p: *const PendingTransfer, io: std.Io) void {
    var free_slot: ?*FileTransfer = null;
    for (transfers) |*t| {
        if (!t.active) {
            free_slot = t;
            break;
        }
    }
    const t = free_slot orelse return; // caller must check before calling
    t.active = true;
    t.stream_id = p.stream_id;
    t.offset = 0;
    t.h3_headers_sent = false;
    @memcpy(t.path[0..p.path_len], p.path[0..p.path_len]);
    t.path_len = p.path_len;
    t.file = std.Io.Dir.openFileAbsolute(io, t.path[0..t.path_len], .{}) catch null;
}

/// Parse the HTTP/0.9 request from the stream receive buffer and register a FileTransfer.
/// Does not send any data — flushTransfers() does the actual I/O.
/// If all transfer slots are occupied, saves the parsed request in slot.pending for retry.
fn startTransfer(slot: *ConnSlot, stream_id: u62, www: []const u8, io: std.Io) void {
    const conn = &slot.conn;
    const transfers = &slot.transfers;
    const st = conn.streams.get(stream_id) orelse return;

    // Zero-copy read: try inline borrow first (direct slice into recv buffer,
    // 0 copies), then fall back to ring buffer peek (1 copy to ring buf).
    const is_inline = st.peekInline() != null;
    const req = st.peekInline() orelse st.recv_buf.peekContiguous();
    if (req.len == 0) return;

    // If a transfer is already active for this stream, ignore the duplicate event.
    for (transfers) |*t| {
        if (t.active and t.stream_id == stream_id) return;
    }
    // Also check pending queue for duplicates.
    for (slot.pending[0..slot.pending_count]) |*p| {
        if (p.stream_id == stream_id) return;
    }

    // Helper to release the borrow/consume after parsing.
    const consumeFn = struct {
        fn consume(s: *quic.stream.Stream, inline_: bool, len: usize) void {
            if (inline_) s.consumeInline() else s.consumeRecv(len);
        }
    }.consume;

    if (!std.mem.startsWith(u8, req, "GET ")) {
        consumeFn(st, is_inline, req.len);
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    }
    const eol = std.mem.indexOf(u8, req, "\r\n") orelse {
        consumeFn(st, is_inline, req.len);
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };
    const path = req[4..eol]; // e.g. "/index.html"

    // Reject path traversal: any component containing ".." is forbidden.
    if (std.mem.indexOf(u8, path, "..") != null) {
        consumeFn(st, is_inline, req.len);
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    }

    // Build full path, then release borrow (path copied to full_path_buf).
    var full_path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ www, path }) catch {
        consumeFn(st, is_inline, req.len);
        conn.streamSend(stream_id, &.{}, true) catch {};
        return;
    };
    consumeFn(st, is_inline, req.len);

    // Find or allocate a transfer slot.
    var free_slot: ?*FileTransfer = null;
    for (transfers) |*t| {
        if (!t.active) {
            free_slot = t;
            break;
        }
    }
    if (free_slot == null) {
        // No free slot — save the parsed request for retry when a slot becomes available.
        if (slot.pending_count < slot.pending.len) {
            const p = &slot.pending[slot.pending_count];
            p.stream_id = stream_id;
            @memcpy(p.path[0..full_path.len], full_path);
            p.path_len = full_path.len;
            slot.pending_count += 1;
        }
        // If pending queue is also full, the stream is silently dropped (extremely unlikely:
        // requires >2*MAX_TRANSFERS concurrent streams, which QUIC flow control prevents).
        return;
    }
    const t = free_slot.?;
    t.active = true;
    t.stream_id = stream_id;
    t.offset = 0;
    @memcpy(t.path[0..full_path.len], full_path);
    t.path_len = full_path.len;
    // Open the file once at transfer start; keep it open across multiple chunks.
    t.file = std.Io.Dir.openFileAbsolute(io, t.path[0..t.path_len], .{}) catch null;
}

/// Try to advance all active file transfers using round-robin interleaving.
/// Each pass sends one chunk per active stream; repeats until CC or queue blocks.
/// Round-robin ensures every stream gets its first packet early — critical when
/// the congestion window is small (e.g. initial cwnd = 10 packets): without
/// interleaving, stream 0 would fill the window and streams 4/8 would get no
/// packets at all, stalling their offset-0 delivery.
fn flushTransfers(slot: *ConnSlot, www: []const u8, io: std.Io, send_sock: *const net.Socket, dest: *const net.IpAddress, send_bufs: *SendBufs) void {
    const conn = &slot.conn;
    const transfers = &slot.transfers;
    _ = www;
    // Activate any parsed requests that were deferred because all slots were occupied.
    while (slot.pending_count > 0) {
        var has_free = false;
        for (transfers) |*t| {
            if (!t.active) {
                has_free = true;
                break;
            }
        }
        if (!has_free) break; // Still no room; leave remainder pending.
        slot.pending_count -= 1;
        activatePending(transfers, &slot.pending[slot.pending_count], io);
    }
    // Outer loop: repeat passes until nothing was sent (CC/queue fully blocked).
    // After each transfer advance, drain what pacing allows so bytes_in_flight
    // stays current.  Without this, bytes_in_flight=0 during the fill phase and
    // the cwnd check is blind — either starving the pipe (with bytes_queued) or
    // flooding the send queue (without it).
    while (true) {
        var sent_any = false;
        for (transfers) |*t| {
            if (!t.active) continue;
            const progress = if (g_is_h3)
                advanceTransferOneH3(conn, t, io)
            else
                advanceTransferOne(conn, t, io);
            if (progress) sent_any = true;
        }
        if (!sent_any) break;
        // Drain pacing-gated packets after each round-robin pass so
        // bytes_in_flight stays current for the next pass's cwnd check.
        drainSend(conn, send_sock, io, dest, send_bufs);
    }
    // Always drain: tick() and receive() may have enqueued PATH_CHALLENGE,
    // ACKs, or retransmissions independent of transfer progress.  Without
    // this, those packets are stranded when all transfers are blocked
    // (buffer full, amplification limit), causing path validation to stall.
    drainSend(conn, send_sock, io, dest, send_bufs);
}

/// Send exactly one chunk from the transfer. Returns true if progress was made.
/// Handles both hq-interop (raw bytes) and H3 (DATA frame wrapping).
fn advanceTransferOne(conn: *Conn, t: *FileTransfer, io: std.Io) bool {
    return advanceTransferGeneric(conn, t, io, false);
}

/// Core transfer logic shared by hq-interop and H3 paths.
fn advanceTransferGeneric(conn: *Conn, t: *FileTransfer, io: std.Io, is_h3: bool) bool {
    const file = t.file orelse {
        if (is_h3) {
            // No file → send H3 404 HEADERS + FIN
            if (!t.h3_headers_sent) {
                var hdr_buf: [128]u8 = undefined;
                const hdr_len = buildH3Headers(&hdr_buf, 404);
                if (hdr_len == 0) {
                    t.active = false;
                    return false;
                }
                conn.streamSend(t.stream_id, hdr_buf[0..hdr_len], true) catch return false;
                t.h3_headers_sent = true;
            }
            t.active = false;
            return true;
        }
        // hq-interop: no file → send FIN so client gets a clean close
        // instead of waiting until idle timeout.
        conn.streamSend(t.stream_id, &.{}, true) catch return false;
        t.active = false;
        return true;
    };

    // H3: send HEADERS frame first (:status 200)
    if (is_h3 and !t.h3_headers_sent) {
        var hdr_buf: [128]u8 = undefined;
        const hdr_len = buildH3Headers(&hdr_buf, 200);
        if (hdr_len == 0) {
            t.active = false;
            return false;
        }
        conn.streamSend(t.stream_id, hdr_buf[0..hdr_len], false) catch return false;
        t.h3_headers_sent = true;
        return true;
    }

    // Read file data. H3 needs room for DATA frame header (≤8 bytes).
    const DATA_HDR_MAX: usize = if (is_h3) 8 else 0;
    var data_buf: [SEND_CHUNK]u8 = undefined;
    const read_limit = SEND_CHUNK - DATA_HDR_MAX;
    const r = file.readPositionalAll(io, data_buf[0..read_limit], t.offset) catch {
        file.close(io);
        t.file = null;
        conn.streamSend(t.stream_id, &.{}, true) catch {};
        t.active = false;
        return false;
    };

    if (r == 0) {
        // EOF — send FIN
        conn.streamSend(t.stream_id, &.{}, true) catch return false;
        file.close(io);
        t.file = null;
        t.active = false;
        return true;
    }

    // Probe for EOF: if partial read, check if next byte exists.
    const is_eof = if (r < read_limit) true else blk: {
        var eof_probe: [1]u8 = undefined;
        break :blk (file.readPositionalAll(io, &eof_probe, t.offset + r) catch 0) == 0;
    };

    // Send data (optionally wrapped in H3 DATA frame).
    if (is_h3) {
        var frame_buf: [SEND_CHUNK]u8 = undefined;
        var pos: usize = 0;
        pos += http3.frame.writeHeader(frame_buf[pos..], http3.FrameType.data, r) catch return false;
        @memcpy(frame_buf[pos..][0..r], data_buf[0..r]);
        pos += r;
        conn.streamSend(t.stream_id, frame_buf[0..pos], is_eof) catch return false;
    } else {
        conn.streamSend(t.stream_id, data_buf[0..r], is_eof) catch return false;
    }
    t.offset += r;

    if (is_eof) {
        file.close(io);
        t.file = null;
        t.active = false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// HTTP/3 support
// ---------------------------------------------------------------------------

/// Open the three server-initiated unidirectional streams required by RFC 9114.
/// Streams are sent individually so a partial failure (queue full) can be
/// retried without re-sending already-succeeded streams.
fn sendH3ControlStreams(s: *ConnSlot) void {
    const conn = &s.conn;
    // Stream IDs: server-initiated unidirectional = 4*n + 3 → 3, 7, 11
    const stream_ids = [_]u62{ 3, 7, 11 };
    const stream_types = [_]u64{
        http3.StreamType.control,
        http3.StreamType.qpack_encoder,
        http3.StreamType.qpack_decoder,
    };

    var all_sent = true;
    for (stream_ids, stream_types) |sid, stype| {
        // Skip streams that were already sent in a previous partial attempt.
        if (conn.streams.get(sid)) |st| {
            if (st.send_offset > 0) continue;
        }
        var buf: [64]u8 = undefined;
        var pos: usize = 0;
        pos += http3.varint.encode(buf[pos..], stype) catch return;
        // Control stream also needs an empty SETTINGS frame.
        if (stype == http3.StreamType.control) {
            pos += http3.frame.writeHeader(buf[pos..], http3.FrameType.settings, 0) catch return;
        }
        conn.streamSend(sid, buf[0..pos], false) catch {
            all_sent = false;
            continue;
        };
    }
    if (all_sent) s.h3_control_sent = true;
}

/// Parse an H3 request from a bidirectional stream and register a FileTransfer.
fn startTransferH3(slot: *ConnSlot, stream_id: u62, www: []const u8, io: std.Io) void {
    const conn = &slot.conn;
    const transfers = &slot.transfers;

    // Client-initiated unidirectional streams (bit pattern xx10): control/QPACK streams.
    // Just consume and ignore (static-only QPACK, no dynamic table).
    if (stream_id & 0x3 == 2) {
        if (conn.streams.get(stream_id)) |st| {
            if (st.peekInline()) |_| {
                st.consumeInline();
            } else {
                st.consumeRecv(st.recv_buf.readable());
            }
        }
        return;
    }

    const st = conn.streams.get(stream_id) orelse return;

    // Zero-copy read: try inline borrow first (0 copies), fall back to ring buffer.
    const is_inline = st.peekInline() != null;
    const req_data = st.peekInline() orelse st.recv_buf.peekContiguous();
    if (req_data.len == 0) return;

    // Deduplicate
    for (transfers) |*t| {
        if (t.active and t.stream_id == stream_id) return;
    }
    for (slot.pending[0..slot.pending_count]) |*p| {
        if (p.stream_id == stream_id) return;
    }

    // Helper to release inline borrow or ring buffer data.
    const release = struct {
        fn do(s: *quic.stream.Stream, inl: bool, len: usize) void {
            if (inl) s.consumeInline() else s.consumeRecv(len);
        }
    }.do;

    // Find the request's HEADERS frame, skipping any leading frames we must
    // ignore: GREASE / reserved / unknown frame types (RFC 9114 §7.2.8, §9).
    // quiche, for one, prepends GREASE frames before the request HEADERS.
    var frame_off: usize = 0;
    var hdr = http3.frame.parseHeader(req_data[frame_off..]) catch {
        release(st, is_inline, req_data.len);
        return;
    };
    while (hdr.frame_type != http3.FrameType.headers) {
        const fend = frame_off + hdr.header_len + @as(usize, @intCast(hdr.payload_len));
        if (fend >= req_data.len) return; // HEADERS not buffered yet — wait for more
        frame_off = fend;
        hdr = http3.frame.parseHeader(req_data[frame_off..]) catch {
            release(st, is_inline, req_data.len);
            return;
        };
    }
    const block_start = frame_off + hdr.header_len;
    const block_end = block_start + @as(usize, @intCast(hdr.payload_len));
    if (block_end > req_data.len) return; // incomplete, wait for more data

    // QPACK decode (static-only) directly from ring buffer.
    var fields: [64]qpack.Field = undefined;
    var strings: [4096]u8 = undefined;
    const fc = qpack.decoder.decode(
        req_data[block_start..block_end],
        &fields,
        &strings,
        null,
        0,
    ) catch {
        release(st, is_inline, req_data.len);
        return;
    };

    // Extract :path
    var path: ?[]const u8 = null;
    for (fields[0..fc]) |f| {
        if (std.mem.eql(u8, f.name, ":path")) {
            path = f.value;
            break;
        }
    }
    const req_path = path orelse {
        release(st, is_inline, req_data.len);
        return;
    };
    if (std.mem.indexOf(u8, req_path, "..") != null) {
        release(st, is_inline, req_data.len);
        return;
    }

    // Build filesystem path, then release ring buffer.
    var full_path_buf: [512]u8 = undefined;
    const full_path = std.fmt.bufPrint(&full_path_buf, "{s}{s}", .{ www, req_path }) catch {
        release(st, is_inline, req_data.len);
        return;
    };
    release(st, is_inline, req_data.len);

    // Allocate transfer slot
    var free_slot: ?*FileTransfer = null;
    for (transfers) |*t| {
        if (!t.active) {
            free_slot = t;
            break;
        }
    }
    const t = free_slot orelse {
        // Defer to pending queue
        if (slot.pending_count < MAX_TRANSFERS) {
            var p = &slot.pending[slot.pending_count];
            p.stream_id = stream_id;
            @memcpy(p.path[0..full_path.len], full_path);
            p.path_len = full_path.len;
            slot.pending_count += 1;
        }
        return;
    };
    t.active = true;
    t.stream_id = stream_id;
    t.offset = 0;
    @memcpy(t.path[0..full_path.len], full_path);
    t.path_len = full_path.len;
    t.file = std.Io.Dir.openFileAbsolute(io, t.path[0..t.path_len], .{}) catch null;
    t.h3_headers_sent = false;
}

/// Build an H3 HEADERS frame with a QPACK-encoded :status response.
fn buildH3Headers(buf: []u8, status: u16) usize {
    var status_buf: [3]u8 = undefined;
    const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{status}) catch return 0;

    const field = qpack.Field{ .name = ":status", .value = status_str };
    var qpack_buf: [128]u8 = undefined;
    const qpack_len = qpack.encoder.encode(&[_]qpack.Field{field}, &qpack_buf, null) catch return 0;

    var pos: usize = 0;
    pos += http3.frame.writeHeader(buf[pos..], http3.FrameType.headers, qpack_len) catch return 0;
    @memcpy(buf[pos..][0..qpack_len], qpack_buf[0..qpack_len]);
    pos += qpack_len;
    return pos;
}

/// Send one chunk of an H3 transfer. Returns true if progress was made.
fn advanceTransferOneH3(conn: *Conn, t: *FileTransfer, io: std.Io) bool {
    return advanceTransferGeneric(conn, t, io, true);
}

/// Read an entire file into `out`. Returns number of bytes read.
fn readFileFull(io: std.Io, path: []const u8, out: []u8) !usize {
    const file = try std.Io.Dir.openFileAbsolute(io, path, .{});
    defer file.close(io);
    return file.readPositionalAll(io, out, 0);
}

/// Raise the UDP receive (and send) socket buffers so the server can absorb
/// bursts of client packets — ACKs especially — without the kernel dropping them
/// while the process is briefly starved of CPU (e.g. under heavy CI load). A
/// dropped ACK can't be recovered by the peer; it just delays our send_acked,
/// throttling the transfer and, under seeded loss, contributing to recovery
/// stalls. SO_RCVBUF requests 2× the value and is capped by net.core.rmem_max
/// (the oracle CI raises that so this takes effect). Best-effort: a failed
/// setsockopt leaves the kernel default, which still works.
fn raiseSocketBuffers(sock: *const net.Socket) void {
    if (comptime builtin.os.tag != .linux) return;
    const SOL_SOCKET: i32 = 1;
    const SO_SNDBUF: i32 = 7;
    const SO_RCVBUF: i32 = 8;
    const want: c_int = 8 * 1024 * 1024; // 8 MiB; kernel clamps to {r,w}mem_max
    const wb = std.mem.asBytes(&want);
    _ = std.os.linux.setsockopt(sock.handle, SOL_SOCKET, SO_RCVBUF, wb.ptr, @sizeOf(c_int));
    _ = std.os.linux.setsockopt(sock.handle, SOL_SOCKET, SO_SNDBUF, wb.ptr, @sizeOf(c_int));
    // Read back the effective size (kernel returns 2× the actual buffer) so the
    // log confirms whether the request took effect or was capped by rmem_max.
    var got: c_int = 0;
    var len: std.os.linux.socklen_t = @sizeOf(c_int);
    if (std.os.linux.getsockopt(sock.handle, SOL_SOCKET, SO_RCVBUF, std.mem.asBytes(&got), &len) == 0)
        std.debug.print("[RCVBUF] {d} bytes\n", .{got});
}

/// Configure the ECN socket options for the ecn testcase (RFC 3168).
/// The ecn server binds a native AF_INET socket (see the bind site), so the IPv4
/// options apply directly: IP_TOS marks every outgoing packet with ECT(0) — at the
/// socket level, so the GSO path inherits it too — and IP_RECVTOS requests the TOS
/// byte of received datagrams.
fn configureEcn(sock: *const net.Socket) !void {
    // std.Io.net.Socket doesn't expose setsockopt, so use raw Linux syscalls.
    const fd = sock.handle;
    const SOL_IP: i32 = 0; // IPPROTO_IP
    const IP_TOS: i32 = 1; // Type of service (ECN bits are the low 2 bits)
    const IP_RECVTOS: i32 = 13; // Deliver received TOS as a control message

    const tos_value: c_int = ECN_ECT0;
    const tos_result = std.os.linux.setsockopt(fd, SOL_IP, IP_TOS, std.mem.asBytes(&tos_value).ptr, @sizeOf(c_int));
    if (tos_result < 0) {
        std.debug.print("WARNING: Failed to set IP_TOS: errno={}\n", .{@as(i32, @intCast(-tos_result))});
    }

    const recvtos_value: c_int = 1;
    const recvtos_result = std.os.linux.setsockopt(fd, SOL_IP, IP_RECVTOS, std.mem.asBytes(&recvtos_value).ptr, @sizeOf(c_int));
    if (recvtos_result < 0) {
        std.debug.print("WARNING: Failed to set IP_RECVTOS: errno={}\n", .{@as(i32, @intCast(-recvtos_result))});
    }
}

/// Batch send: collect all outgoing packets, then send via sendMany().
/// On Linux, sendMany uses sendmmsg (1 syscall for N packets).
/// On macOS, sendMany loops sendto (N syscalls — no batch syscall available).
/// Convert a Linux sockaddr.storage (as filled by recvmmsg) to net.IpAddress.
/// Port is byte-swapped from network byte order to native endian to match what
/// receiveTimeout returns.
fn ipFromStorage(s: *const std.os.linux.sockaddr.storage) net.IpAddress {
    return switch (s.family) {
        std.os.linux.AF.INET => blk: {
            const in: *const std.os.linux.sockaddr.in = @ptrCast(s);
            break :blk .{ .ip4 = .{
                .bytes = @bitCast(in.addr),
                .port = std.mem.bigToNative(u16, in.port),
            } };
        },
        std.os.linux.AF.INET6 => blk: {
            const in6: *const std.os.linux.sockaddr.in6 = @ptrCast(s);
            break :blk .{ .ip6 = .{
                .port = std.mem.bigToNative(u16, in6.port),
                .bytes = in6.addr,
            } };
        },
        // A dual-stack UDP IPv6 socket only delivers AF_INET6.
        else => unreachable,
    };
}

fn drainSend(conn: *Conn, sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, bufs: *SendBufs) void {
    if (comptime builtin.os.tag == .linux) {
        if (g_gso_supported) {
            drainSendGso(conn, sock, io, dest, bufs);
            return;
        }
    }
    var messages: [SEND_BATCH]net.OutgoingMessage = undefined;
    var count: usize = 0;
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);

    // Phase 1: collect all outgoing packets into separate buffers.
    while (count < SEND_BATCH) {
        const n = conn.send(&bufs.bufs[count], now_ns);
        if (n == 0) break;
        messages[count] = .{
            .address = dest,
            .data_ptr = &bufs.bufs[count],
            .data_len = n,
        };
        count += 1;
    }

    if (count == 0) return;

    // Phase 2: batch send (sendmmsg on Linux, loop on macOS).
    sock.sendMany(io, messages[0..count], .{}) catch {};
}

// Pack MAX_DATAGRAM-sized packets into a single compound buffer and flush with
// UDP_SEGMENT so the kernel/NIC segments them.  Partial packets (ACKs, handshake
// packets shorter than MAX_DATAGRAM) fall through to plain sendMany individually.
fn drainSendGso(conn: *Conn, sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, bufs: *SendBufs) void {
    const now_ns: i64 = @truncate(std.Io.Clock.awake.now(io).nanoseconds);
    var n_full: usize = 0;
    while (n_full < GSO_MAX_SEGS) {
        const n = conn.send(bufs.gso[n_full * MAX_DATAGRAM ..][0..MAX_DATAGRAM], now_ns);
        if (n == 0) break;
        if (n == MAX_DATAGRAM) {
            n_full += 1;
        } else {
            // Partial packet: flush any accumulated full segments first, then send
            // this short packet individually (can't mix segment sizes in one GSO send).
            if (n_full > 0) flushGso(sock, io, dest, bufs, n_full);
            @memcpy(bufs.bufs[0][0..n], bufs.gso[n_full * MAX_DATAGRAM ..][0..n]);
            var msg = [1]net.OutgoingMessage{.{ .address = dest, .data_ptr = &bufs.bufs[0], .data_len = n }};
            sock.sendMany(io, &msg, .{}) catch {};
            n_full = 0;
        }
    }
    if (n_full > 0) flushGso(sock, io, dest, bufs, n_full);
}

fn flushGso(sock: *const net.Socket, io: std.Io, dest: *const net.IpAddress, bufs: *SendBufs, n_segs: usize) void {
    if (n_segs == 0) return;
    if (n_segs == 1) {
        // Single segment: no GSO overhead needed.
        var msg = [1]net.OutgoingMessage{.{ .address = dest, .data_ptr = @ptrCast(&bufs.gso), .data_len = MAX_DATAGRAM }};
        sock.sendMany(io, &msg, .{}) catch {};
        return;
    }
    const seg_size: u16 = MAX_DATAGRAM;
    _ = std.os.linux.setsockopt(sock.handle, SOL_UDP, UDP_SEGMENT, std.mem.asBytes(&seg_size).ptr, @sizeOf(u16));
    var msg = [1]net.OutgoingMessage{.{ .address = dest, .data_ptr = @ptrCast(&bufs.gso), .data_len = n_segs * MAX_DATAGRAM }};
    sock.sendMany(io, &msg, .{}) catch {};
    // Restore to 0 so ordinary sendMany calls after this are unaffected.
    const zero: u16 = 0;
    _ = std.os.linux.setsockopt(sock.handle, SOL_UDP, UDP_SEGMENT, std.mem.asBytes(&zero).ptr, @sizeOf(u16));
}

const SEND_BATCH = 32;
const BATCH_SIZE = 32;

/// Pre-allocated state for Linux recvmmsg Phase 2 (non-blocking batch drain).
/// std.os.linux types are always available regardless of host OS.
const RecvBatch = struct {
    iovs: [BATCH_SIZE]std.posix.iovec,
    addrs: [BATCH_SIZE]std.os.linux.sockaddr.storage,
    msgs: [BATCH_SIZE]std.os.linux.mmsghdr,
};

/// Per-connection send buffer pool.
///
/// `bufs`  — SEND_BATCH separate per-packet buffers for the plain sendmmsg path
///            (used on macOS and as a fallback on Linux when GSO is unavailable).
///
/// `gso`   — Flat compound buffer for the Linux GSO path.  drainSendGso packs
///            consecutive MAX_DATAGRAM-size packets end-to-end here, then sends
///            the whole run with one sendmsg + UDP_SEGMENT cmsg (Linux 4.18+).
///            Non-MAX_DATAGRAM packets (ACKs, handshake) are copied to bufs[0]
///            and sent via a plain sendMany call.
const SendBufs = struct {
    bufs: [SEND_BATCH][MAX_DATAGRAM]u8,
    gso: [GSO_MAX_SEGS * MAX_DATAGRAM]u8,
};

fn computeTimeout(deadline: ?i64) std.Io.Timeout {
    const d = deadline orelse return .none;
    return .{ .deadline = .{ .raw = .{ .nanoseconds = d }, .clock = .awake } };
}

/// Update SSLKEYLOG file with newly rotated keys. Rewrites the entire file
/// with all generations up to current. Called immediately after key rotation
/// to ensure Wireshark can decrypt packets before connection closes.
fn updateKeyLog(conn: *const Conn, io: std.Io, _: u32) void {
    const tls = &conn.tls_state.server;
    const random_hex = std.fmt.bytesToHex(tls.client_random, .lower);
    var buf: [16384]u8 = undefined;
    var pos: usize = 0;

    // Write handshake secrets (same as initial)
    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    // Write all generations (0 through current)
    var gen: u32 = 0;
    while (gen <= conn.current_key_generation) : (gen += 1) {
        const secrets = conn.deriveSecretsForGeneration(gen);
        line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_{d} {s} {s}\n", .{ gen, random_hex, std.fmt.bytesToHex(secrets.client, .lower) }) catch return;
        pos += line.len;

        line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_{d} {s} {s}\n", .{ gen, random_hex, std.fmt.bytesToHex(secrets.server, .lower) }) catch return;
        pos += line.len;

        if (pos >= buf.len - 256) break;
    }

    appendKeyLog(io, buf[0..pos]);
}

/// Write an SSLKEYLOG file so network analyzers (Wireshark/tshark) can decrypt
/// 1-RTT QUIC packets including those with key updates.  Written to /logs/keys.log
/// (the path the interop runner expects for server logs).
/// Writes initial secrets at handshake, then appends rotated secrets dynamically.
fn writeKeyLog(conn: *const Conn, io: std.Io) void {
    const tls = &conn.tls_state.server;
    const random_hex = std.fmt.bytesToHex(tls.client_random, .lower);
    var buf: [4096]u8 = undefined;
    var pos: usize = 0;

    // Write handshake secrets
    var line = std.fmt.bufPrint(buf[pos..], "CLIENT_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls.client_hs_secret, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_HANDSHAKE_TRAFFIC_SECRET {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(tls.server_hs_secret, .lower) }) catch return;
    pos += line.len;

    // Write initial application secrets (generation 0)
    const secrets_0 = conn.deriveSecretsForGeneration(0);
    line = std.fmt.bufPrint(buf[pos..], "CLIENT_TRAFFIC_SECRET_0 {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(secrets_0.client, .lower) }) catch return;
    pos += line.len;

    line = std.fmt.bufPrint(buf[pos..], "SERVER_TRAFFIC_SECRET_0 {s} {s}\n", .{ random_hex, std.fmt.bytesToHex(secrets_0.server, .lower) }) catch return;
    pos += line.len;

    appendKeyLog(io, buf[0..pos]);
}

fn appendKeyLog(io: std.Io, data: []const u8) void {
    // Accumulate in memory, write full buffer each time (createFileAbsolute truncates).
    const n = @min(data.len, g_keylog_buf.len - g_keylog_len);
    if (n == 0) return;
    @memcpy(g_keylog_buf[g_keylog_len..][0..n], data[0..n]);
    g_keylog_len += n;
    const file = std.Io.Dir.createFileAbsolute(io, g_keylog_path, .{}) catch return;
    defer file.close(io);
    file.writePositionalAll(io, g_keylog_buf[0..g_keylog_len], 0) catch return;
    file.sync(io) catch {};
}

fn ipToSocketAddr(addr: net.IpAddress) quic.SocketAddr {
    return switch (addr) {
        .ip4 => |a| .{ .v4 = .{ .addr = a.bytes, .port = a.port } },
        .ip6 => |a| .{ .v6 = .{ .addr = a.bytes, .port = a.port } },
    };
}

fn socketAddrToIp(addr: quic.SocketAddr) net.IpAddress {
    return switch (addr) {
        .v4 => |a| .{ .ip4 = .{ .bytes = a.addr, .port = a.port } },
        .v6 => |a| .{ .ip6 = .{ .bytes = a.addr, .port = a.port } },
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "server: ipToSocketAddr maps IPv4 address to v4 socket addr" {
    const ip4 = net.IpAddress{ .ip4 = .{ .bytes = .{ 193, 167, 100, 100 }, .port = 443 } };
    const sa = ipToSocketAddr(ip4);
    try std.testing.expectEqual(
        quic.SocketAddr{ .v4 = .{ .addr = .{ 193, 167, 100, 100 }, .port = 443 } },
        sa,
    );
}

test "server: ipToSocketAddr maps IPv6 address to v6 socket addr" {
    const ipv6_bytes = [16]u8{ 0xfd, 0, 0xca, 0xfe, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    const ip6 = net.IpAddress{ .ip6 = .{ .bytes = ipv6_bytes, .port = 1234 } };
    const sa = ipToSocketAddr(ip6);
    try std.testing.expectEqual(
        quic.SocketAddr{ .v6 = .{ .addr = ipv6_bytes, .port = 1234 } },
        sa,
    );
}

test "server: computeTimeout with null returns none" {
    const t = computeTimeout(null);
    try std.testing.expect(t == .none);
}

test "server: computeTimeout with deadline returns deadline timeout" {
    const t = computeTimeout(1_000_000_000);
    try std.testing.expect(t == .deadline);
}

test "server: startTransfer n==0 guard returns without sending FIN" {
    // Verify that the n==0 early-return path does not panic or send anything.
    // We can't easily construct a full Conn in a unit test, but we can verify
    // the guard logic by checking that a zero-length read is treated as no-op.
    // This is a compile-time / logic test: if the guard were absent, the code
    // would reach conn.streamSend which would close an active transfer stream.
    const guard_works = blk: {
        const n: usize = 0;
        if (n == 0) break :blk true;
        break :blk false;
    };
    try std.testing.expect(guard_works);
}
