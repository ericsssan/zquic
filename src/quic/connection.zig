//! QUIC connection state machine (RFC 9000).
//!
//! Sans-I/O design: the caller owns the UDP socket and event loop.
//! The connection is driven by:
//!
//!   connection.receive(data, src) — feed a received UDP datagram
//!   connection.send(out)          — drain the next UDP datagram to transmit
//!   connection.nextTimeout()      — nanosecond deadline for tick()
//!   connection.tick(now_ns)       — drive timer-based events
//!
//! No sockets, no threads, no allocator in the hot path.

const std = @import("std");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const varint = @import("varint.zig");
const cid_mod = @import("connection_id.zig");
const stream_mod = @import("stream.zig");
const flow_control = @import("flow_control.zig");
const cubic_mod = @import("congestion/cubic.zig");
const pool_mod = @import("pool.zig");

const ConnectionId = cid_mod.ConnectionId;

// ---------------------------------------------------------------------------
// Address (sans std.net — caller provides raw sockaddr bytes)
// ---------------------------------------------------------------------------

pub const SocketAddr = union(enum(u1)) {
    v4: struct { addr: [4]u8, port: u16 },
    v6: struct { addr: [16]u8, port: u16 },

    pub fn eql(a: SocketAddr, b: SocketAddr) bool {
        return switch (a) {
            .v4 => |av4| switch (b) {
                .v4 => |bv4| av4.port == bv4.port and std.mem.eql(u8, &av4.addr, &bv4.addr),
                .v6 => false,
            },
            .v6 => |av6| switch (b) {
                .v6 => |bv6| av6.port == bv6.port and std.mem.eql(u8, &av6.addr, &bv6.addr),
                .v4 => false,
            },
        };
    }
};

// ---------------------------------------------------------------------------
// Hot path struct — exactly 64 bytes, cache-line aligned
// ---------------------------------------------------------------------------

pub const ConnState = enum(u8) {
    idle = 0,
    handshake = 1,
    established = 2,
    draining = 3,
    closed = 4,
};

pub const ConnectionHot = struct {
    /// Largest received packet number per epoch [Initial, Handshake, 1-RTT].
    rx_pn: [3]u64,
    /// Next TX packet number per epoch.
    tx_pn: [3]u64,
    state: ConnState,
    /// Current crypto epoch (0=Initial, 1=Handshake, 2=1-RTT).
    epoch: u8,
    _pad: [14]u8,

    comptime {
        std.debug.assert(@sizeOf(ConnectionHot) == 64);
    }
};

// ---------------------------------------------------------------------------
// Send queue
// ---------------------------------------------------------------------------

const MAX_PACKET_SIZE = 1350;
const SEND_QUEUE_DEPTH = 8;

const SendSlot = struct {
    buf: [MAX_PACKET_SIZE]u8,
    len: usize,
};

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

pub const Config = struct {
    /// True when this endpoint is acting as a server (passive open).
    is_server: bool = true,
    /// Initial receive window for the connection.
    initial_max_data: u64 = flow_control.DEFAULT_MAX_DATA,
    /// Initial receive window per stream.
    initial_max_stream_data: u64 = flow_control.DEFAULT_MAX_STREAM_DATA,
    /// Maximum idle timeout in nanoseconds (0 = disabled).
    idle_timeout_ns: u64 = 30_000_000_000, // 30s
};

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

pub const Connection = struct {
    hot: ConnectionHot align(64),

    // Identity
    local_cid: ConnectionId,
    peer_cid: ConnectionId,
    peer_addr: SocketAddr,

    // Crypto
    initial_keys: crypto.InitialKeys,
    tls_state: tls.TlsServer,

    // Per-epoch packet keys (null until negotiated)
    hs_keys: ?tls.HandshakeKeys,
    app_keys: ?tls.AppKeys,

    // Stream layer
    streams: stream_mod.StreamTable,

    // Flow control
    conn_flow: flow_control.FlowController,

    // Congestion control
    congestion: cubic_mod.Cubic,

    // Send queue (ring buffer of ready-to-send packets)
    sq: [SEND_QUEUE_DEPTH]SendSlot,
    sq_head: usize,
    sq_tail: usize,

    // Timers
    idle_deadline_ns: ?i64,
    pto_deadline_ns: ?i64,

    // Stats
    bytes_sent: u64,
    bytes_recv: u64,
    pkts_sent: u64,
    pkts_recv: u64,

    // Config
    config: Config,

    /// Create a server-side connection.  Call `receive()` with the first
    /// datagram to start the handshake.
    pub fn accept(config: Config, io: std.Io) !Connection {
        const tls_server = try tls.TlsServer.init(io);
        const local_cid = ConnectionId.generate(0, io);

        return Connection{
            .hot = .{
                .rx_pn = [_]u64{0} ** 3,
                .tx_pn = [_]u64{0} ** 3,
                .state = .idle,
                .epoch = 0,
                ._pad = [_]u8{0} ** 14,
            },
            .local_cid = local_cid,
            .peer_cid = ConnectionId.zero,
            .peer_addr = .{ .v4 = .{ .addr = [_]u8{0} ** 4, .port = 0 } },
            .initial_keys = undefined,
            .tls_state = tls_server,
            .hs_keys = null,
            .app_keys = null,
            .streams = .{},
            .conn_flow = flow_control.FlowController.init(
                config.initial_max_data,
                config.initial_max_data,
            ),
            .congestion = cubic_mod.Cubic.init(),
            .sq = undefined,
            .sq_head = 0,
            .sq_tail = 0,
            .idle_deadline_ns = null,
            .pto_deadline_ns = null,
            .bytes_sent = 0,
            .bytes_recv = 0,
            .pkts_sent = 0,
            .pkts_recv = 0,
            .config = config,
        };
    }

    // -----------------------------------------------------------------------
    // Public API
    // -----------------------------------------------------------------------

    /// Feed a received UDP datagram into the connection.
    /// `data`    — raw UDP payload (may contain coalesced QUIC packets).
    /// `src`     — sender address (used for migration detection).
    /// `now_ns`  — current monotonic time in nanoseconds.
    /// `io`      — I/O handle (needed for TLS key generation).
    pub fn receive(self: *Connection, data: []const u8, src: SocketAddr, now_ns: i64, io: std.Io) !void {
        _ = src;
        _ = now_ns;

        // Process all coalesced packets in the datagram
        var remaining = data;
        while (remaining.len > 0) {
            const consumed = try self.processOnePacket(remaining, io);
            if (consumed == 0) break;
            remaining = remaining[consumed..];
        }
    }

    /// Write the next UDP payload to `out`. Returns bytes written (0 = nothing pending).
    pub fn send(self: *Connection, out: []u8) usize {
        if (self.sq_head == self.sq_tail) return 0;
        const slot = &self.sq[self.sq_head % SEND_QUEUE_DEPTH];
        const n = @min(slot.len, out.len);
        @memcpy(out[0..n], slot.buf[0..n]);
        self.sq_head += 1;
        self.bytes_sent += n;
        self.pkts_sent += 1;
        return n;
    }

    /// Returns the nanosecond deadline when `tick()` must be called,
    /// or null if no timer is active.
    pub fn nextTimeout(self: *const Connection) ?i64 {
        var min: ?i64 = null;
        if (self.idle_deadline_ns) |d| min = d;
        if (self.pto_deadline_ns) |d| {
            if (min == null or d < min.?) min = d;
        }
        return min;
    }

    /// Drive timer events. Call when `nextTimeout()` deadline has passed.
    pub fn tick(self: *Connection, now_ns: i64) void {
        if (self.idle_deadline_ns) |d| {
            if (now_ns >= d) {
                self.hot.state = .draining;
                self.idle_deadline_ns = null;
            }
        }
        if (self.pto_deadline_ns) |d| {
            if (now_ns >= d) {
                // PTO: send a PING to probe
                self.queuePing() catch {};
                self.pto_deadline_ns = null;
            }
        }
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.hot.state == .closed or self.hot.state == .draining;
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.hot.state == .established;
    }

    // -----------------------------------------------------------------------
    // Internal packet processing
    // -----------------------------------------------------------------------

    fn processOnePacket(self: *Connection, data: []const u8, io: std.Io) !usize {
        if (data.len == 0) return 0;

        if (packet.isLongHeader(data[0])) {
            return self.processLongHeaderPacket(data, io);
        } else {
            return self.processShortHeaderPacket(data);
        }
    }

    fn processLongHeaderPacket(self: *Connection, data: []const u8, io: std.Io) !usize {
        const result = try packet.parseLongHeader(data);
        const hdr = result.header;

        switch (hdr.packet_type) {
            .initial => {
                // On first Initial, record peer CID and derive initial keys
                if (self.hot.state == .idle) {
                    self.peer_cid = hdr.src_cid;
                    self.initial_keys = crypto.deriveInitialKeys(&hdr.dest_cid.bytes);
                    self.hot.state = .handshake;
                }

                // Decrypt the Initial packet
                const keys = self.initial_keys.client;
                const pn = packet.decodePacketNumber(
                    self.hot.rx_pn[0],
                    hdr.packet_number,
                    @as(u8, hdr.pn_len) * 8,
                );

                // Build AAD = header bytes (before payload)
                const payload_start = result.consumed - hdr.payload.len;
                const aad = data[0..payload_start];

                if (hdr.payload.len < 16) return error.PacketTooShort;
                const pt_len = hdr.payload.len - 16;
                var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
                if (pt_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
                try crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]);

                if (pn > self.hot.rx_pn[0]) self.hot.rx_pn[0] = pn;
                self.bytes_recv += result.consumed;
                self.pkts_recv += 1;

                // Process frames in plaintext
                try self.processFrames(plaintext[0..pt_len], 0, io);

                return result.consumed;
            },
            .handshake => {
                // Handshake packet: use handshake keys
                if (self.hs_keys == null) return result.consumed;
                const keys = self.hs_keys.?.client;
                const pn = packet.decodePacketNumber(
                    self.hot.rx_pn[1],
                    hdr.packet_number,
                    @as(u8, hdr.pn_len) * 8,
                );
                const payload_start = result.consumed - hdr.payload.len;
                const aad = data[0..payload_start];
                if (hdr.payload.len < 16) return error.PacketTooShort;
                const pt_len = hdr.payload.len - 16;
                var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
                if (pt_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
                try crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]);
                if (pn > self.hot.rx_pn[1]) self.hot.rx_pn[1] = pn;
                try self.processFrames(plaintext[0..pt_len], 1, io);
                return result.consumed;
            },
            else => return result.consumed, // ignore retry, 0-rtt
        }
    }

    fn processShortHeaderPacket(self: *Connection, data: []const u8) !usize {
        if (self.app_keys == null) return 0;
        const result = try packet.parseShortHeader(data, cid_mod.len);
        const hdr = result.header;
        const keys = self.app_keys.?.client;
        const pn = packet.decodePacketNumber(
            self.hot.rx_pn[2],
            hdr.packet_number,
            @as(u8, hdr.pn_len) * 8,
        );
        const payload_start = result.consumed - hdr.payload.len;
        const aad = data[0..payload_start];
        if (hdr.payload.len < 16) return data.len;
        const pt_len = hdr.payload.len - 16;
        var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
        if (pt_len > MAX_PACKET_SIZE) return data.len;
        crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]) catch return data.len;
        if (pn > self.hot.rx_pn[2]) self.hot.rx_pn[2] = pn;
        self.bytes_recv += data.len;
        self.pkts_recv += 1;
        self.processFrames(plaintext[0..pt_len], 2, null) catch {};
        return data.len;
    }

    fn processFrames(self: *Connection, plaintext: []const u8, epoch: u8, io: ?std.Io) !void {
        var pos: usize = 0;
        while (pos < plaintext.len) {
            const fr = frame.parseFrame(plaintext[pos..]) catch break;
            pos += fr.consumed;

            switch (fr.frame) {
                .padding => {},
                .ping => try self.queueAck(epoch),
                .ack => |a| self.processAck(a),
                .crypto => |c| {
                    if (io) |real_io| {
                        try self.processCryptoFrame(c, epoch, real_io);
                    }
                },
                .stream => |s| try self.processStreamFrame(s),
                .max_data => |v| self.conn_flow.updateSendMax(v),
                .max_stream_data => |f| {
                    if (self.streams.get(f.stream_id)) |st| {
                        st.send_max = @intCast(f.max_data);
                    }
                },
                .handshake_done => self.hot.state = .established,
                .connection_close => self.hot.state = .draining,
                else => {},
            }
        }
    }

    fn processCryptoFrame(self: *Connection, f: frame.CryptoFrame, epoch: u8, io: std.Io) !void {
        var out_buf: [8192]u8 = undefined;
        const out_len = try self.tls_state.processCrypto(f.data, &out_buf, io);
        _ = epoch;

        // Update HS keys if TLS just derived them
        if (self.hs_keys == null and
            self.tls_state.state != .wait_client_hello)
        {
            self.hs_keys = self.tls_state.handshake_keys;
        }

        if (out_len > 0) {
            // Queue the TLS output as CRYPTO frames in the appropriate epoch packets.
            // Initial epoch: wrap in Initial packet.
            // Handshake epoch: wrap in Handshake packet.
            // For Phase 1: queue Initial packet with ServerHello,
            //              then Handshake packet with EE+Cert+CV+Finished.
            // Simplified: queue everything as one Initial packet and one Handshake packet.
            try self.queueTlsOutput(out_buf[0..out_len]);
        }

        if (self.tls_state.isComplete()) {
            self.app_keys = self.tls_state.app_keys;
            self.hot.state = .established;
            try self.queueHandshakeDone();
        }
    }

    fn processStreamFrame(self: *Connection, f: frame.StreamFrame) !void {
        const st = self.streams.getOrCreate(f.stream_id) orelse return error.TooManyStreams;
        self.conn_flow.onReceived(@intCast(f.data.len));
        try st.receiveData(f.offset, f.data, f.fin);

        // Echo: if we received data, send it back on the same stream
        if (self.hot.state == .established and f.data.len > 0) {
            try self.queueStreamData(f.stream_id, f.data, f.fin);
        }
    }

    fn processAck(self: *Connection, _: frame.AckFrame) void {
        // Simplified: just record that we got an ACK
        _ = self;
    }

    // -----------------------------------------------------------------------
    // Send queue helpers
    // -----------------------------------------------------------------------

    fn enqueueSend(self: *Connection, data: []const u8) !void {
        const next = (self.sq_tail + 1) % SEND_QUEUE_DEPTH;
        if (next == self.sq_head % SEND_QUEUE_DEPTH) return error.SendQueueFull;
        const slot = &self.sq[self.sq_tail % SEND_QUEUE_DEPTH];
        const n = @min(data.len, MAX_PACKET_SIZE);
        @memcpy(slot.buf[0..n], data[0..n]);
        slot.len = n;
        self.sq_tail += 1;
    }

    fn queueAck(self: *Connection, epoch: u8) !void {
        var pkt: [MAX_PACKET_SIZE]u8 = undefined;
        var fpos: usize = 0;
        const ack_frame_data: frame.Frame = .{ .ack = .{
            .largest_acked = self.hot.rx_pn[epoch],
            .ack_delay = 0,
            .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ++ [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        } };
        fpos += frame.encodeFrame(pkt[fpos..], ack_frame_data);
        try self.enqueueSend(pkt[0..fpos]);
    }

    fn queuePing(self: *Connection) !void {
        var pkt: [4]u8 = undefined;
        const n = frame.encodeFrame(&pkt, .ping);
        try self.enqueueSend(pkt[0..n]);
    }

    fn queueHandshakeDone(self: *Connection) !void {
        var pkt: [MAX_PACKET_SIZE]u8 = undefined;
        var pos: usize = 0;
        pos += frame.encodeFrame(pkt[pos..], .handshake_done);
        // Encrypt with 1-RTT keys and send
        if (self.app_keys) |ak| {
            const pn = self.hot.tx_pn[2];
            self.hot.tx_pn[2] += 1;
            var out: [MAX_PACKET_SIZE]u8 = undefined;
            const hdr_len = packet.encodeShortHeader(&out, self.peer_cid, @intCast(pn), false);
            const ct_len = pos + 16;
            if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
            crypto.encryptPayload(ak.server, pn, out[0..hdr_len], pkt[0..pos], out[hdr_len..][0..ct_len]);
            try self.enqueueSend(out[0 .. hdr_len + ct_len]);
        }
    }

    fn queueTlsOutput(self: *Connection, tls_data: []const u8) !void {
        // Queue TLS output as Initial + Handshake packets.
        // Phase 1 simplified: everything goes in one packet.
        var pkt: [MAX_PACKET_SIZE]u8 = undefined;
        var fpos: usize = 0;

        const crypto_frame: frame.Frame = .{ .crypto = .{ .offset = 0, .data = tls_data } };
        fpos += frame.encodeFrame(pkt[fpos..], crypto_frame);

        // Encrypt with server initial keys and emit as Initial packet
        const ik = self.initial_keys.server;
        const pn = self.hot.tx_pn[0];
        self.hot.tx_pn[0] += 1;

        var out: [MAX_PACKET_SIZE]u8 = undefined;
        const hdr_len = packet.encodeLongHeader(
            &out,
            .initial,
            packet.QUIC_VERSION_1,
            self.peer_cid,
            self.local_cid,
            &.{},
            @intCast(pn),
            fpos,
        );

        const ct_out_len = fpos + 16;
        if (hdr_len + ct_out_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ik, pn, out[0..hdr_len], pkt[0..fpos], out[hdr_len..][0..ct_out_len]);
        try self.enqueueSend(out[0 .. hdr_len + ct_out_len]);
    }

    fn queueStreamData(self: *Connection, id: u62, data: []const u8, fin: bool) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        const st = self.streams.getOrCreate(id) orelse return;
        const offset = st.send_offset;
        st.onSent(data.len);

        var pkt: [MAX_PACKET_SIZE]u8 = undefined;
        var fpos: usize = 0;

        const sf: frame.Frame = .{ .stream = .{
            .stream_id = id,
            .offset = @intCast(offset),
            .fin = fin,
            .data = data,
        } };
        fpos += frame.encodeFrame(pkt[fpos..], sf);

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        var out: [MAX_PACKET_SIZE]u8 = undefined;
        const hdr_len = packet.encodeShortHeader(&out, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, out[0..hdr_len], pkt[0..fpos], out[hdr_len..][0..ct_len]);
        try self.enqueueSend(out[0 .. hdr_len + ct_len]);
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "connection: hot struct is 64 bytes" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 64), @sizeOf(ConnectionHot));
}

test "connection: accept initializes correctly" {
    const io = std.testing.io;
    const config = Config{};
    var conn = try Connection.accept(config, io);
    const testing = std.testing;
    try testing.expectEqual(ConnState.idle, conn.hot.state);
    try testing.expectEqual(@as(u8, 0), conn.hot.epoch);
    try testing.expect(!conn.isEstablished());
    try testing.expect(!conn.isClosed());
}

test "connection: send returns 0 when queue empty" {
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    var out: [MAX_PACKET_SIZE]u8 = undefined;
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

test "connection: enqueue and drain send queue" {
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    const data = [_]u8{0xde, 0xad, 0xbe, 0xef};
    try conn.enqueueSend(&data);

    var out: [8]u8 = undefined;
    const n = conn.send(&out);
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualSlices(u8, &data, out[0..n]);
}

test "connection: tick transitions to draining on idle timeout" {
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.idle_deadline_ns = 1000;
    conn.tick(2000);
    const testing = std.testing;
    try testing.expectEqual(ConnState.draining, conn.hot.state);
}
