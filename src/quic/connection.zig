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
const loss_recovery_mod = @import("loss_recovery.zig");

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
// Event queue
// ---------------------------------------------------------------------------

pub const EVENT_QUEUE_DEPTH = 16;

pub const Event = union(enum) {
    stream_data: struct { stream_id: u62 },
    stream_reset: struct { stream_id: u62, error_code: u62 },
    connection_closed: struct { error_code: u62, is_app: bool },
    connected,
    stop_sending: struct { stream_id: u62, error_code: u62 },
};

const EventQueue = struct {
    items: [EVENT_QUEUE_DEPTH]Event = undefined,
    head: usize = 0,
    tail: usize = 0,

    pub fn push(self: *EventQueue, ev: Event) void {
        if (self.tail - self.head >= EVENT_QUEUE_DEPTH) return; // drop if full
        self.items[self.tail & (EVENT_QUEUE_DEPTH - 1)] = ev;
        self.tail += 1;
    }

    pub fn pop(self: *EventQueue) ?Event {
        if (self.head == self.tail) return null;
        const ev = self.items[self.head & (EVENT_QUEUE_DEPTH - 1)];
        self.head += 1;
        return ev;
    }

    pub fn isEmpty(self: *const EventQueue) bool {
        return self.head == self.tail;
    }
};

// ---------------------------------------------------------------------------
// Hot path struct — exactly 64 bytes, cache-line aligned
// ---------------------------------------------------------------------------

pub const ConnState = enum(u8) {
    idle = 0,
    handshake = 1,
    established = 2,
    closing = 3,
    draining = 4,
    closed = 5,
};

pub const ConnectionHot = struct {
    /// Largest received packet number per epoch [Initial, Handshake, 1-RTT].
    rx_pn: [3]u64,
    /// Next TX packet number per epoch.
    tx_pn: [3]u64,
    state: ConnState,
    /// Current crypto epoch (0=Initial, 1=Handshake, 2=1-RTT).
    epoch: u8,
    /// Whether we have seen at least one valid packet in each epoch.
    /// Used for simplified PN replay protection: once true, packets with
    /// pn <= rx_pn[epoch] are silently dropped (RFC 9000 §17 simplified).
    rx_pn_valid: [3]bool,
    _pad: [11]u8,

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
// Peer CID table
// ---------------------------------------------------------------------------

const MAX_PEER_CIDS = 4;

const PeerCidEntry = struct {
    cid: ConnectionId,
    seq: u62,
    reset_token: [16]u8,
    valid: bool,
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

    // Loss recovery (RTT estimation, sent-packet tracking, PTO)
    loss: loss_recovery_mod.LossRecovery,
    /// Monotonic time updated by receive() and tick().
    current_time_ns: i64,
    /// Cached max_ack_delay from peer transport params (ns). Default 25 ms.
    cached_max_ack_delay_ns: u64,
    /// Cached ack_delay_exponent from peer transport params. Default 3 (RFC 9000 §18.2).
    cached_ack_delay_exp: u6,

    // Send queue (ring buffer of ready-to-send packets)
    sq: [SEND_QUEUE_DEPTH]SendSlot,
    sq_head: usize,
    sq_tail: usize,

    // Timers
    idle_deadline_ns: ?i64,
    pto_deadline_ns: ?i64,
    /// Deadline for transitioning out of closing/draining state.
    drain_deadline_ns: ?i64,

    // Stats
    bytes_sent: u64,
    bytes_recv: u64,
    pkts_sent: u64,
    pkts_recv: u64,

    // Config
    config: Config,

    // Event queue
    events: EventQueue,

    // Connection close
    closing_frame_buf: [128]u8,
    closing_frame_len: usize,

    // Scratch buffer shared by all queue* helpers for frame serialisation.
    // enc_scratch holds the encrypted packet output (header + ciphertext).
    // Safe to share because those helpers are never called re-entrantly.
    pkt_scratch: [MAX_PACKET_SIZE]u8,
    enc_scratch: [MAX_PACKET_SIZE]u8,

    // Peer stream limits (updated by MAX_STREAMS frames and transport params)
    peer_max_streams_bidi: u62,
    peer_max_streams_uni: u62,

    // Peer connection ID table (NEW_CONNECTION_ID)
    peer_cid_table: [MAX_PEER_CIDS]PeerCidEntry,
    peer_cid_retire_prior: u62,

    // Amplification limit tracking (RFC 9000 §8.1.2).
    /// True once the client address has been validated (handshake complete).
    path_validated: bool,
    /// Bytes received from the unvalidated peer (stops counting post-validation).
    bytes_unvalidated_recv: u64,
    /// Bytes sent to the unvalidated peer (stops counting post-validation).
    bytes_unvalidated_sent: u64,

    /// Outstanding PATH_CHALLENGE data we sent; null if none pending (RFC 9000 §9.2).
    pending_path_challenge: ?[8]u8,

    // Pending retransmit flags
    pending_handshake_done: bool,
    pending_max_data: bool,
    /// Count of streams with a pending_reset set; avoids O(MAX_STREAMS) scan in tick().
    pending_reset_count: u8,
    /// Timestamp of the last Version Negotiation response (nanoseconds).
    /// Used to rate-limit VN responses to 1 per second.
    last_vn_ns: i64,

    // Per-epoch TLS send offset (for FrameInfo tracking)
    crypto_send_offset: [3]u64,
    /// Cached idle timeout cast to i64 — computed once in accept() so receive() avoids
    /// the @intCast/@min per packet. Zero when idle timeout is disabled.
    idle_timeout_i64: i64,

    /// Create a server-side connection.  Call `receive()` with the first
    /// datagram to start the handshake.
    pub fn accept(config: Config, io: std.Io) !Connection {
        const tls_server = try tls.TlsServer.init(io);
        const local_cid = ConnectionId.generate(0, io);
        const idle_timeout_i64: i64 = if (config.idle_timeout_ns > 0)
            @intCast(@min(config.idle_timeout_ns, @as(u64, std.math.maxInt(i64))))
        else
            0;

        return Connection{
            .hot = .{
                .rx_pn = [_]u64{0} ** 3,
                .tx_pn = [_]u64{0} ** 3,
                .state = .idle,
                .epoch = 0,
                .rx_pn_valid = .{ false, false, false },
                ._pad = [_]u8{0} ** 11,
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
            .loss = loss_recovery_mod.LossRecovery.init(),
            .current_time_ns = 0,
            .cached_max_ack_delay_ns = 25_000_000,
            .cached_ack_delay_exp = 3,
            .idle_timeout_i64 = idle_timeout_i64,
            .sq = undefined,
            .sq_head = 0,
            .sq_tail = 0,
            .idle_deadline_ns = null,
            .pto_deadline_ns = null,
            .drain_deadline_ns = null,
            .bytes_sent = 0,
            .bytes_recv = 0,
            .pkts_sent = 0,
            .pkts_recv = 0,
            .config = config,
            .events = .{},
            .closing_frame_buf = undefined,
            .closing_frame_len = 0,
            .pkt_scratch = undefined,
            .enc_scratch = undefined,
            .peer_max_streams_bidi = 0,
            .peer_max_streams_uni = 0,
            .peer_cid_table = [_]PeerCidEntry{.{
                .cid = .{},
                .seq = 0,
                .reset_token = [_]u8{0} ** 16,
                .valid = false,
            }} ** MAX_PEER_CIDS,
            .peer_cid_retire_prior = 0,
            .path_validated = false,
            .bytes_unvalidated_recv = 0,
            .bytes_unvalidated_sent = 0,
            .pending_path_challenge = null,
            .pending_handshake_done = false,
            .pending_max_data = false,
            .pending_reset_count = 0,
            .last_vn_ns = -1_000_000_000, // sentinel: "1s before the epoch" so first VN is always allowed
            .crypto_send_offset = .{ 0, 0, 0 },
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
        self.current_time_ns = now_ns;

        // Closing: retransmit CONNECTION_CLOSE, do not process the datagram.
        if (self.hot.state == .closing) {
            self.queueConnectionClose() catch {};
            return;
        }

        // Draining / closed: silently discard.
        if (self.hot.state == .draining or self.hot.state == .closed) return;

        // Refresh idle timer.
        if (self.idle_timeout_i64 > 0) {
            self.idle_deadline_ns = now_ns +| self.idle_timeout_i64;
        }

        // Amplification limit: track bytes received before path validation.
        if (!self.path_validated) {
            self.bytes_unvalidated_recv +|= data.len;
        }

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
        // RFC 9000 §10.2: draining state — must not send anything.
        if (self.hot.state == .draining) return 0;
        if (self.sq_head == self.sq_tail) return 0;
        const slot = &self.sq[self.sq_head & (SEND_QUEUE_DEPTH - 1)];
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
        const idle  = self.idle_deadline_ns  orelse std.math.maxInt(i64);
        const pto   = self.pto_deadline_ns   orelse std.math.maxInt(i64);
        const drain = self.drain_deadline_ns orelse std.math.maxInt(i64);
        const m = @min(@min(idle, pto), drain);
        return if (m == std.math.maxInt(i64)) null else m;
    }

    /// Drive timer events. Call when `nextTimeout()` deadline has passed.
    pub fn tick(self: *Connection, now_ns: i64) void {
        self.current_time_ns = now_ns;

        // Drain timer: closing/draining → closed.
        if (self.drain_deadline_ns) |d| {
            if (now_ns >= d) {
                self.hot.state = .closed;
                self.drain_deadline_ns = null;
            }
        }

        // Idle timeout → closed (RFC 9000 §10.1).
        if (self.idle_deadline_ns) |d| {
            if (now_ns >= d) {
                self.hot.state = .closed;
                self.idle_deadline_ns = null;
            }
        }

        // PTO: suppress in closing/draining/closed states.
        if (self.hot.state != .closing and
            self.hot.state != .draining and
            self.hot.state != .closed)
        {
            if (self.pto_deadline_ns) |d| {
                if (now_ns >= d) {
                    // PTO: send a PING probe, then double the backoff
                    self.loss.onPtoFired();
                    self.queuePing() catch {};
                    self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
                }
            }
        }

        // Flush pending retransmits.
        if (self.pending_handshake_done) {
            self.pending_handshake_done = false;
            self.queueHandshakeDone() catch {};
        }
        if (self.pending_max_data) {
            self.pending_max_data = false;
            self.queueMaxData() catch {};
        }

        // Flush pending stream resets (fast-path: skip scan when nothing is pending).
        if (self.pending_reset_count > 0) self.flushPendingResets() catch {};

        // Flush pending MAX_STREAM_DATA frames (only meaningful when established).
        if (self.hot.state == .established) self.flushPendingMaxStreamData();
    }

    pub fn isClosed(self: *const Connection) bool {
        return self.hot.state == .closed or
            self.hot.state == .draining or
            self.hot.state == .closing;
    }

    pub fn isDraining(self: *const Connection) bool {
        return self.hot.state == .draining;
    }

    pub fn isEstablished(self: *const Connection) bool {
        return self.hot.state == .established;
    }

    /// Drain the next application event, or null if none pending.
    pub fn pollEvent(self: *Connection) ?Event {
        return self.events.pop();
    }

    /// Buffer stream data for sending and queue a packet.
    pub fn streamSend(self: *Connection, stream_id: u62, data: []const u8, fin: bool) !void {
        const st = self.streams.getOrCreate(stream_id) orelse return error.TooManyStreams;
        if (!st.canSend(@intCast(data.len))) return error.StreamNotWritable;
        const n = st.bufferSendData(data);
        if (n < data.len) return error.BufferFull;
        if (fin) st.send_fin = true;
        if (self.hot.state == .established) {
            try self.queueStreamData(stream_id, data, fin);
        }
    }

    /// Initiate a connection close.  Transitions to closing, queues a CONNECTION_CLOSE,
    /// and arms the drain timer.
    pub fn close(self: *Connection, error_code: u62, is_app: bool, reason: []const u8) !void {
        if (self.hot.state == .closing or
            self.hot.state == .draining or
            self.hot.state == .closed) return;
        self.hot.state = .closing;

        // Serialize CONNECTION_CLOSE into the persistent frame buffer.
        const cc_frame: frame.Frame = .{ .connection_close = .{
            .error_code = error_code,
            .frame_type = 0,
            .reason = reason,
            .is_app = is_app,
        } };
        self.closing_frame_len = frame.encodeFrame(&self.closing_frame_buf, cc_frame);

        // Drain deadline: now + 3 × PTO.
        const pto = self.loss.rtt.ptoBase(self.cached_max_ack_delay_ns);
        const pto3 = @min(pto *| 3, @as(u64, std.math.maxInt(i64)));
        self.drain_deadline_ns = self.current_time_ns +| @as(i64, @intCast(pto3));

        // Queue the CONNECTION_CLOSE frame.
        self.queueConnectionClose() catch {};

        // Notify the application.
        self.events.push(.{ .connection_closed = .{ .error_code = error_code, .is_app = is_app } });
    }

    /// Reset a stream and queue a RESET_STREAM frame.
    pub fn resetStream(self: *Connection, stream_id: u62, error_code: u62) !void {
        const st = self.streams.get(stream_id) orelse return error.StreamNotFound;
        st.initiateReset(error_code);
        self.pending_reset_count += 1;
        try self.flushPendingResets();
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
        // RFC 9000 §6: Version negotiation.
        // Check the version field before full parsing — VN packets (version 0) have
        // a different wire format that parseLongHeader cannot handle.
        if (data.len >= 5) {
            const ver = std.mem.readInt(u32, data[1..5], .big);
            if (ver != packet.QUIC_VERSION_1) {
                if (ver != 0) {
                    // Rate-limit VN responses to 1 per second to prevent amplification.
                    if (self.current_time_ns - self.last_vn_ns >= 1_000_000_000) {
                        self.last_vn_ns = self.current_time_ns;
                        self.sendVersionNeg(data) catch {};
                    }
                }
                // Version 0 = received a VN packet from the peer; ignore it.
                return data.len;
            }
        }

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

                // Replay protection: drop packets whose PN we've already surpassed.
                if (self.hot.rx_pn_valid[0] and pn <= self.hot.rx_pn[0]) return result.consumed;

                // Build AAD = header bytes (before payload)
                const payload_start = result.consumed - hdr.payload.len;
                const aad = data[0..payload_start];

                if (hdr.payload.len < 16) return error.PacketTooShort;
                const pt_len = hdr.payload.len - 16;
                var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
                if (pt_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
                try crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]);

                if (pn > self.hot.rx_pn[0]) self.hot.rx_pn[0] = pn;
                self.hot.rx_pn_valid[0] = true;
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
                // Replay protection
                if (self.hot.rx_pn_valid[1] and pn <= self.hot.rx_pn[1]) return result.consumed;
                const payload_start = result.consumed - hdr.payload.len;
                const aad = data[0..payload_start];
                if (hdr.payload.len < 16) return error.PacketTooShort;
                const pt_len = hdr.payload.len - 16;
                var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
                if (pt_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
                try crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]);
                if (pn > self.hot.rx_pn[1]) self.hot.rx_pn[1] = pn;
                self.hot.rx_pn_valid[1] = true;
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
        // Replay protection: silently drop packets with PN <= highest seen in this epoch.
        if (self.hot.rx_pn_valid[2] and pn <= self.hot.rx_pn[2]) return data.len;
        const payload_start = result.consumed - hdr.payload.len;
        const aad = data[0..payload_start];
        if (hdr.payload.len < 16) return data.len;
        const pt_len = hdr.payload.len - 16;
        var plaintext: [MAX_PACKET_SIZE]u8 = undefined;
        if (pt_len > MAX_PACKET_SIZE) return data.len;
        crypto.decryptPayload(keys, pn, aad, hdr.payload, plaintext[0..pt_len]) catch return data.len;
        if (pn > self.hot.rx_pn[2]) self.hot.rx_pn[2] = pn;
        self.hot.rx_pn_valid[2] = true;
        self.bytes_recv += data.len;
        self.pkts_recv += 1;
        self.processFrames(plaintext[0..pt_len], 2, null) catch {};
        return data.len;
    }

    /// Returns true when `f` is permitted inside a packet in the given epoch.
    /// RFC 9000 §12.4 Table 3:
    ///   epoch 0 (Initial) and epoch 1 (Handshake) allow only:
    ///     PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE (transport, 0x1c).
    ///   epoch 2 (1-RTT) allows all frame types.
    fn isFrameAllowedInEpoch(f: frame.Frame, epoch: u8) bool {
        return switch (f) {
            .padding, .ping, .ack, .crypto, .connection_close => true,
            else => epoch == 2,
        };
    }

    fn processFrames(self: *Connection, plaintext: []const u8, epoch: u8, io: ?std.Io) !void {
        var pos: usize = 0;
        while (pos < plaintext.len) {
            const fr = frame.parseFrame(plaintext[pos..]) catch break;
            pos += fr.consumed;

            // RFC 9000 §12.4: reject frames not permitted in this epoch.
            if (!isFrameAllowedInEpoch(fr.frame, epoch)) return error.ProtocolViolation;

            switch (fr.frame) {
                .padding => {},
                .ping => try self.queueAck(epoch),
                .ack => |a| try self.processAck(a, epoch),
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
                .handshake_done => {
                    // RFC 9000 §19.20: HANDSHAKE_DONE is only sent by the server.
                    // A server-role endpoint must never receive it.
                    if (self.config.is_server) return error.ProtocolViolation;
                    self.hot.state = .established;
                    self.events.push(.connected);
                },
                .connection_close => |cc| {
                    if (self.hot.state != .closing and
                        self.hot.state != .draining and
                        self.hot.state != .closed)
                    {
                        self.hot.state = .draining;
                        const pto = self.loss.rtt.ptoBase(self.cached_max_ack_delay_ns);
                        const pto3 = @min(pto *| 3, @as(u64, std.math.maxInt(i64)));
                        self.drain_deadline_ns = self.current_time_ns +| @as(i64, @intCast(pto3));
                        self.events.push(.{ .connection_closed = .{
                            .error_code = cc.error_code,
                            .is_app = cc.is_app,
                        } });
                    }
                },
                .reset_stream => |rs| {
                    if (self.streams.get(rs.stream_id)) |st| {
                        st.onResetReceived(rs.error_code, rs.final_size) catch {};
                    }
                    self.events.push(.{ .stream_reset = .{
                        .stream_id = rs.stream_id,
                        .error_code = rs.error_code,
                    } });
                },
                .stop_sending => |ss| {
                    if (self.streams.get(ss.stream_id)) |st| {
                        st.onStopSendingReceived(ss.error_code);
                        self.pending_reset_count += 1;
                    }
                    self.events.push(.{ .stop_sending = .{
                        .stream_id = ss.stream_id,
                        .error_code = ss.error_code,
                    } });
                    self.flushPendingResets() catch {};
                },
                .path_challenge => |pc| try self.queuePathResponse(pc.data),
                .path_response => |pr| {
                    // Validate that the response echoes our outstanding challenge (RFC 9000 §9.2).
                    if (self.pending_path_challenge) |challenge| {
                        if (std.mem.eql(u8, &pr.data, &challenge)) {
                            self.pending_path_challenge = null; // challenge satisfied
                        } else {
                            return error.ProtocolViolation; // data mismatch
                        }
                    }
                    // No pending challenge: silently ignore.
                },
                .max_streams_bidi => |v| {
                    if (v > self.peer_max_streams_bidi) self.peer_max_streams_bidi = v;
                },
                .max_streams_uni => |v| {
                    if (v > self.peer_max_streams_uni) self.peer_max_streams_uni = v;
                },
                .new_connection_id => |ncid| self.processNewConnectionId(ncid),
                .retire_connection_id => {}, // silently consumed — single-CID server
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
            self.path_validated = true; // handshake completion validates the peer address
            self.events.push(.connected);

            // Apply negotiated transport parameters.
            const params = self.tls_state.peerTransportParams();
            self.conn_flow.updateSendMax(params.initial_max_data);
            self.cached_max_ack_delay_ns = params.max_ack_delay_ms * 1_000_000;
            self.cached_ack_delay_exp = @intCast(@min(params.ack_delay_exponent, 20));

            // Initialize peer stream limits from transport parameters.
            const bidi_limit = @min(params.initial_max_streams_bidi, @as(u64, std.math.maxInt(u62)));
            const uni_limit = @min(params.initial_max_streams_uni, @as(u64, std.math.maxInt(u62)));
            self.peer_max_streams_bidi = @intCast(bidi_limit);
            self.peer_max_streams_uni = @intCast(uni_limit);

            try self.queueHandshakeDone();
        }
    }

    fn processStreamFrame(self: *Connection, f: frame.StreamFrame) !void {
        // RFC 9000 §12.4: STREAM frames are only valid in 1-RTT (established) state.
        if (self.hot.state != .established) return error.ProtocolViolation;
        // Server must only receive client-initiated streams (bit 0 = 0).
        if (f.stream_id & 1 != 0) return error.StreamStateError;
        const st = self.streams.getOrCreate(f.stream_id) orelse return error.TooManyStreams;
        self.conn_flow.onReceived(@intCast(f.data.len));
        try st.receiveData(f.offset, f.data, f.fin);
        // Notify the application; the echo behaviour from Phase 1 is removed.
        self.events.push(.{ .stream_data = .{ .stream_id = f.stream_id } });
    }

    fn processAck(self: *Connection, ack: frame.AckFrame, epoch: u8) !void {
        const max_ack_delay_ns = self.cached_max_ack_delay_ns; // cached: used twice
        // Convert AckFrame ranges into loss_recovery.AckedRange slices.
        // ranges[0] has gap=0 (first ACK range); subsequent entries carry the gap
        // to the *next* range (stored in the following slot by the frame parser).
        var ranges_buf: [32]loss_recovery_mod.AckedRange = undefined;
        var range_count: usize = 0;
        var high: u64 = @as(u64, ack.largest_acked);
        for (0..ack.range_count) |i| {
            const ack_range_val = @as(u64, ack.ranges[i].ack_range);
            if (ack_range_val > high) return error.InvalidFrame; // malformed: would underflow
            const low = high - ack_range_val;
            ranges_buf[range_count] = .{ .low = low, .high = high };
            range_count += 1;
            if (i + 1 < ack.range_count) {
                const gap_val = @as(u64, ack.ranges[i + 1].gap);
                if (low == 0 or gap_val >= low) return error.InvalidFrame; // malformed: would underflow
                high = low - 1 - gap_val;
            }
        }

        // ack_delay field is in units of 2^ack_delay_exponent µs; convert to ns.
        const ack_delay_ns: u64 = @as(u64, ack.ack_delay) *
            (@as(u64, 1) << self.cached_ack_delay_exp) * 1000;
        const result = self.loss.onAckReceived(
            @as(u64, ack.largest_acked),
            ack_delay_ns,
            ranges_buf[0..range_count],
            epoch,
            self.current_time_ns,
            max_ack_delay_ns,
        );

        // Feed acknowledgement data to CUBIC
        if (result.newly_acked > 0) {
            self.congestion.onAckReceived(
                result.bytes_acked,
                self.loss.rtt.smoothed_rtt,
                self.current_time_ns,
            );
            self.loss.resetPtoCount();
        }

        // One congestion event per loss detection (RFC 9438 §5.6)
        if (result.newly_lost > 0) {
            self.congestion.onPacketLost(self.current_time_ns);
        }

        // Persistent congestion: collapse cwnd when loss span > 3×PTO (RFC 9002 §6.1.2)
        if (result.persistent_congestion) {
            self.congestion.onPersistentCongestion();
        }

        // Process acked / lost frames for retransmission.
        self.processAckedFrames(result);
        self.processLostFrames(result);

        // Refresh PTO timer after any ACK
        self.pto_deadline_ns = self.loss.ptoDeadline(max_ack_delay_ns);
    }

    // -----------------------------------------------------------------------
    // Retransmission helpers (Step 4)
    // -----------------------------------------------------------------------

    fn processAckedFrames(self: *Connection, result: loss_recovery_mod.AckResult) void {
        for (result.acked_frames[0..result.acked_frame_count]) |fi| {
            for (fi.frames[0..fi.count]) |frame_info| {
                switch (frame_info) {
                    .stream => |s| {
                        if (self.streams.get(s.stream_id)) |st| {
                            st.onAcked(s.offset, s.len);
                            if (s.fin) {
                                st.fin_acked = true;
                                if (st.state == .closed) {
                                    self.streams.close(s.stream_id);
                                }
                            }
                        }
                    },
                    else => {},
                }
            }
        }
    }

    fn processLostFrames(self: *Connection, result: loss_recovery_mod.AckResult) void {
        // Declared once outside the loop; reused for each retransmitted stream frame.
        var stream_retx_buf: [MAX_PACKET_SIZE]u8 = undefined;
        for (result.lost_frames[0..result.lost_frame_count]) |fi| {
            for (fi.frames[0..fi.count]) |frame_info| {
                switch (frame_info) {
                    .stream => |s| {
                        if (self.streams.get(s.stream_id)) |st| {
                            const n = st.getSendData(s.offset, &stream_retx_buf);
                            if (n > 0 or s.fin) {
                                self.encryptAndEnqueueStreamFrame(
                                    s.stream_id,
                                    s.offset,
                                    stream_retx_buf[0..n],
                                    s.fin,
                                ) catch {};
                            }
                        }
                    },
                    .handshake_done => {
                        self.pending_handshake_done = true;
                    },
                    .max_data => {
                        self.pending_max_data = true;
                    },
                    .ping => {
                        self.queuePing() catch {};
                    },
                    .reset_stream => |rs| {
                        self.queueResetStream(rs.stream_id, rs.error_code, rs.final_size) catch {};
                    },
                    .connection_close => {
                        self.queueConnectionClose() catch {};
                    },
                    .crypto_frame, .max_stream_data, .none => {},
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Send queue helpers
    // -----------------------------------------------------------------------

    fn enqueueSend(self: *Connection, data: []const u8) !void {
        // Use monotonic head/tail subtraction (not modular comparison) to correctly
        // detect full queue regardless of wrap-around.
        if (self.sq_tail - self.sq_head >= SEND_QUEUE_DEPTH) return error.SendQueueFull;

        // Amplification limit: must not send more than 3× received before path
        // validation.  Only enforced once we have received at least one datagram
        // (bytes_unvalidated_recv > 0) so that direct enqueueSend calls in tests are
        // unaffected before any receive has happened (RFC 9000 §8.1.2).
        if (!self.path_validated and self.bytes_unvalidated_recv > 0) {
            const new_sent = self.bytes_unvalidated_sent +| data.len;
            if (new_sent > self.bytes_unvalidated_recv *| 3) {
                return error.AmplificationLimitExceeded;
            }
            self.bytes_unvalidated_sent = new_sent;
        }
        const slot = &self.sq[self.sq_tail & (SEND_QUEUE_DEPTH - 1)];
        const n = @min(data.len, MAX_PACKET_SIZE);
        @memcpy(slot.buf[0..n], data[0..n]);
        slot.len = n;
        self.sq_tail += 1;
    }

    fn queueAck(self: *Connection, epoch: u8) !void {
        var fpos: usize = 0;
        const ack_frame_data: frame.Frame = .{ .ack = .{
            .largest_acked = @intCast(self.hot.rx_pn[epoch]),
            .ack_delay = 0,
            .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        } };
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], ack_frame_data);
        try self.enqueueSend(self.pkt_scratch[0..fpos]);
    }

    fn queuePing(self: *Connection) !void {
        if (self.app_keys) |ak| {
            // Post-handshake: send an encrypted PING in a 1-RTT packet.
            const n = frame.encodeFrame(&self.pkt_scratch, .ping);
            const pn = self.hot.tx_pn[2];
            self.hot.tx_pn[2] += 1;
            const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
            const ct_len = n + 16;
            if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
            crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..n], self.enc_scratch[hdr_len..][0..ct_len]);
            const out_len = hdr_len + ct_len;
            try self.enqueueSend(self.enc_scratch[0..out_len]);
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .ping;
            fi.count = 1;
            self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
            self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
        } else {
            // Pre-handshake: send a raw (unencrypted) PING for testing purposes.
            const n = frame.encodeFrame(&self.pkt_scratch, .ping);
            try self.enqueueSend(self.pkt_scratch[0..n]);
        }
    }

    fn queueHandshakeDone(self: *Connection) !void {
        var pos: usize = 0;
        pos += frame.encodeFrame(self.pkt_scratch[pos..], .handshake_done);
        // Encrypt with 1-RTT keys and send
        if (self.app_keys) |ak| {
            const pn = self.hot.tx_pn[2];
            self.hot.tx_pn[2] += 1;
            const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
            const ct_len = pos + 16;
            if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
            crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..pos], self.enc_scratch[hdr_len..][0..ct_len]);
            const out_len = hdr_len + ct_len;
            try self.enqueueSend(self.enc_scratch[0..out_len]);
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .handshake_done;
            fi.count = 1;
            self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
            self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
        }
    }

    fn queueTlsOutput(self: *Connection, tls_data: []const u8) !void {
        // Queue TLS output as Initial + Handshake packets.
        // Phase 1 simplified: everything goes in one packet.
        var fpos: usize = 0;

        const tls_offset = self.crypto_send_offset[0];
        const crypto_frame: frame.Frame = .{ .crypto = .{ .offset = @intCast(tls_offset), .data = tls_data } };
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], crypto_frame);

        // Encrypt with server initial keys and emit as Initial packet
        const ik = self.initial_keys.server;
        const pn = self.hot.tx_pn[0];
        self.hot.tx_pn[0] += 1;

        const hdr_len = packet.encodeLongHeader(
            &self.enc_scratch,
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
        crypto.encryptPayload(ik, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_out_len]);
        const out_len = hdr_len + ct_out_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);

        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.frames[0] = .{ .crypto_frame = .{
            .offset = @intCast(tls_offset),
            .len = @intCast(@min(tls_data.len, 0xffff)),
        } };
        fi.count = 1;
        self.crypto_send_offset[0] += tls_data.len;
        self.loss.onPacketSent(pn, 0, out_len, true, self.current_time_ns, fi);
        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
    }

    /// Encode and enqueue a Version Negotiation packet in response to an
    /// unknown-version long-header packet.  `raw` is the received datagram.
    fn sendVersionNeg(self: *Connection, raw: []const u8) !void {
        // Manually read DCID and SCID lengths to extract the client's SCID,
        // which becomes the DCID of our VN response.
        if (raw.len < 7) return;
        var pos: usize = 5; // skip first_byte (1) + version (4)
        const dcid_len: usize = raw[pos];
        pos += 1 + dcid_len;
        if (pos >= raw.len) return;
        const scid_len: usize = raw[pos];
        pos += 1;
        if (pos + scid_len > raw.len) return;

        var src_cid: cid_mod.ConnectionId = .{};
        const copy_len = @min(scid_len, cid_mod.len);
        @memcpy(src_cid.bytes[0..copy_len], raw[pos..][0..copy_len]);

        var vn_buf: [32]u8 = undefined;
        const n = packet.encodeVersionNegotiation(&vn_buf, src_cid, self.local_cid);
        try self.enqueueSend(vn_buf[0..n]);
    }

    /// Low-level: encrypt and enqueue a STREAM frame at an explicit offset.
    /// Does NOT advance stream.send_offset (caller is responsible for that).
    fn encryptAndEnqueueStreamFrame(
        self: *Connection,
        id: u62,
        offset: u62,
        data: []const u8,
        fin: bool,
    ) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        var fpos: usize = 0;
        const sf: frame.Frame = .{ .stream = .{
            .stream_id = id,
            .offset = offset,
            .fin = fin,
            .data = data,
        } };
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], sf);

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);

        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.frames[0] = .{ .stream = .{
            .stream_id = id,
            .offset = offset,
            .len = @intCast(@min(data.len, 0xffff)),
            .fin = fin,
        } };
        fi.count = 1;
        self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
    }

    fn queueStreamData(self: *Connection, id: u62, data: []const u8, fin: bool) !void {
        if (self.app_keys == null) return;

        const st = self.streams.getOrCreate(id) orelse return;
        const offset: u62 = @intCast(st.send_offset);
        st.onSent(data.len);

        try self.encryptAndEnqueueStreamFrame(id, offset, data, fin);
    }

    /// Encrypt and enqueue the pre-serialized CONNECTION_CLOSE frame.
    fn queueConnectionClose(self: *Connection) !void {
        if (self.app_keys == null) return;
        if (self.closing_frame_len == 0) return;
        const ak = self.app_keys.?;

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = self.closing_frame_len + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(
            ak.server,
            pn,
            self.enc_scratch[0..hdr_len],
            self.closing_frame_buf[0..self.closing_frame_len],
            self.enc_scratch[hdr_len..][0..ct_len],
        );
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);
        // Not tracked for retransmission — closing state re-sends on every receive().
    }

    /// Queue a RESET_STREAM frame for `stream_id`.
    fn queueResetStream(self: *Connection, stream_id: u62, error_code: u62, final_size: u62) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        var fpos: usize = 0;
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .reset_stream = .{
            .stream_id = stream_id,
            .error_code = error_code,
            .final_size = final_size,
        } });

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);

        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.frames[0] = .{ .reset_stream = .{
            .stream_id = stream_id,
            .error_code = error_code,
            .final_size = final_size,
        } };
        fi.count = 1;
        self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
    }

    /// Queue a MAX_DATA frame advertising the current connection receive window.
    fn queueMaxData(self: *Connection) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        const new_max: u62 = @intCast(@min(self.conn_flow.recv_max, std.math.maxInt(u62)));
        var fpos: usize = 0;
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .max_data = new_max });

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);

        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.frames[0] = .{ .max_data = new_max };
        fi.count = 1;
        self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
    }

    /// Scan all streams for pending_reset and queue a RESET_STREAM frame for each.
    fn flushPendingResets(self: *Connection) !void {
        for (0..stream_mod.MAX_STREAMS) |i| {
            if (!self.streams.used[i]) continue;
            const st = &self.streams.streams[i];
            if (st.pending_reset) |pr| {
                st.pending_reset = null;
                if (self.pending_reset_count > 0) self.pending_reset_count -= 1;
                try self.queueResetStream(st.id, pr.error_code, pr.final_size);
            }
        }
    }

    /// Echo a PATH_RESPONSE with the same 8-byte data from a PATH_CHALLENGE.
    /// PATH_RESPONSE is not tracked for retransmission (RFC 9000 §8.2.2).
    fn queuePathResponse(self: *Connection, data: [8]u8) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        var fpos: usize = 0;
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .path_response = .{ .data = data } });

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);
        // Not tracked via loss recovery — PATH_RESPONSE is not retransmittable.
    }

    /// Queue a PATH_CHALLENGE with `data` and record it so the peer's
    /// PATH_RESPONSE can be validated (RFC 9000 §9.2).
    pub fn sendPathChallenge(self: *Connection, data: [8]u8) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        var fpos: usize = 0;
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .path_challenge = .{ .data = data } });

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        try self.enqueueSend(self.enc_scratch[0..hdr_len + ct_len]);
        // Store challenge so incoming PATH_RESPONSE can be validated.
        self.pending_path_challenge = data;
    }

    /// Process a NEW_CONNECTION_ID frame: store the CID and retire entries below retire_prior_to.
    fn processNewConnectionId(self: *Connection, ncid: frame.NewConnectionIdFrame) void {
        // Update the retire-prior-to pointer (monotonically increasing).
        if (ncid.retire_prior_to > self.peer_cid_retire_prior) {
            self.peer_cid_retire_prior = ncid.retire_prior_to;
            // Invalidate any stored CIDs that are now below the threshold.
            for (&self.peer_cid_table) |*entry| {
                if (entry.valid and entry.seq < ncid.retire_prior_to) {
                    entry.valid = false;
                }
            }
        }

        // Don't store CIDs that are already retired.
        if (ncid.sequence_number < self.peer_cid_retire_prior) return;

        // Store in the first free slot.
        for (&self.peer_cid_table) |*entry| {
            if (!entry.valid) {
                var new_cid: ConnectionId = .{};
                const copy_len = @min(@as(usize, ncid.cid_len), cid_mod.len);
                @memcpy(new_cid.bytes[0..copy_len], ncid.cid[0..copy_len]);
                entry.cid = new_cid;
                entry.seq = ncid.sequence_number;
                entry.reset_token = ncid.stateless_reset_token;
                entry.valid = true;
                break;
            }
        }
    }

    /// Queue a MAX_STREAM_DATA frame advertising `new_max` bytes for `stream_id`.
    fn queueMaxStreamData(self: *Connection, stream_id: u62, new_max: u62) !void {
        if (self.app_keys == null) return;
        const ak = self.app_keys.?;

        var fpos: usize = 0;
        fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .max_stream_data = .{
            .stream_id = stream_id,
            .max_data = new_max,
        } });

        const pn = self.hot.tx_pn[2];
        self.hot.tx_pn[2] += 1;

        const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_cid, @intCast(pn), false);
        const ct_len = fpos + 16;
        if (hdr_len + ct_len > MAX_PACKET_SIZE) return error.PacketTooLarge;
        crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
        const out_len = hdr_len + ct_len;
        try self.enqueueSend(self.enc_scratch[0..out_len]);

        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.frames[0] = .{ .max_stream_data = .{ .stream_id = stream_id, .max_data = new_max } };
        fi.count = 1;
        self.loss.onPacketSent(pn, 2, out_len, true, self.current_time_ns, fi);
        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
    }

    /// Scan all streams and send MAX_STREAM_DATA frames for any whose recv window grew.
    fn flushPendingMaxStreamData(self: *Connection) void {
        for (0..stream_mod.MAX_STREAMS) |i| {
            if (!self.streams.used[i]) continue;
            const st = &self.streams.streams[i];
            if (st.shouldSendMaxStreamData()) {
                const new_max: u62 = @intCast(@min(st.recv_max, std.math.maxInt(u62)));
                st.last_sent_max_stream_data = st.recv_max;
                self.queueMaxStreamData(st.id, new_max) catch {};
            }
        }
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

test "connection: tick transitions to closed on idle timeout" {
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.idle_deadline_ns = 1000;
    conn.tick(2000);
    const testing = std.testing;
    try testing.expectEqual(ConnState.closed, conn.hot.state);
}

test "connection: unknown version triggers VN response" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Build a minimal long-header packet with an unknown version (0x00000002).
    // Format: first_byte | version(4) | dcid_len | dcid(8) | scid_len | scid(8)
    var pkt: [32]u8 = undefined;
    pkt[0] = 0xc0; // long header, Initial type bits
    std.mem.writeInt(u32, pkt[1..5], 0x00000002, .big); // unknown version
    pkt[5] = 8; // DCID length
    @memset(pkt[6..14], 0xaa); // DCID
    pkt[14] = 8; // SCID length
    @memset(pkt[15..23], 0xbb); // SCID (becomes DCID in the VN response)

    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&pkt, src, 0, io) catch {};

    // A Version Negotiation packet should be queued.
    var out: [64]u8 = undefined;
    const n = conn.send(&out);
    try testing.expect(n > 0);

    // VN packet has version 0x00000000.
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, out[1..5], .big));

    // Long header bit must be set.
    try testing.expect(out[0] & 0x80 != 0);
}

test "connection: nextTimeout returns minimum of active deadlines" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    try testing.expectEqual(@as(?i64, null), conn.nextTimeout());

    conn.idle_deadline_ns = 5000;
    try testing.expectEqual(@as(?i64, 5000), conn.nextTimeout());

    conn.pto_deadline_ns = 3000;
    try testing.expectEqual(@as(?i64, 3000), conn.nextTimeout()); // min wins

    conn.idle_deadline_ns = null;
    try testing.expectEqual(@as(?i64, 3000), conn.nextTimeout());
}

test "loss: connection initializes with zeroed loss recovery" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{}, io);
    try testing.expectEqual(@as(u64, 0), conn.loss.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), conn.loss.pto_count);
    try testing.expectEqual(@as(?i64, null), conn.loss.last_ack_eliciting_ns);
    try testing.expectEqual(@as(?i64, null), conn.pto_deadline_ns);
    try testing.expectEqual(@as(u64, 25_000_000), conn.cached_max_ack_delay_ns);
}

test "loss: onPacketSent wires bytes_in_flight and pto_deadline" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.current_time_ns = 1_000_000;
    conn.loss.onPacketSent(1, 0, 1200, true, conn.current_time_ns, .{});
    try testing.expectEqual(@as(u64, 1200), conn.loss.bytes_in_flight);
    try testing.expect(conn.loss.ptoDeadline(conn.cached_max_ack_delay_ns) != null);
}

test "loss: pto_deadline_ns null when no ack-eliciting packets in flight" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{}, io);
    try testing.expectEqual(@as(?i64, null), conn.pto_deadline_ns);
}

test "loss: onPtoFired increments pto_count; resetPtoCount zeroes it" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.loss.onPtoFired();
    try testing.expectEqual(@as(u32, 1), conn.loss.pto_count);
    conn.loss.onPtoFired();
    try testing.expectEqual(@as(u32, 2), conn.loss.pto_count);
    conn.loss.resetPtoCount();
    try testing.expectEqual(@as(u32, 0), conn.loss.pto_count);
}

test "loss: onAckReceived decrements bytes_in_flight" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.current_time_ns = 0;
    conn.loss.onPacketSent(1, 0, 1200, true, 0, .{});
    try testing.expectEqual(@as(u64, 1200), conn.loss.bytes_in_flight);

    const ranges = [_]loss_recovery_mod.AckedRange{.{ .low = 1, .high = 1 }};
    _ = conn.loss.onAckReceived(1, 0, &ranges, 0, 1_000_000, conn.cached_max_ack_delay_ns);
    try testing.expectEqual(@as(u64, 0), conn.loss.bytes_in_flight);
}

test "connection: send queue full returns SendQueueFull error" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Fill all 8 queue slots
    const data = [_]u8{0x01};
    var i: usize = 0;
    while (i < SEND_QUEUE_DEPTH) : (i += 1) {
        try conn.enqueueSend(&data);
    }
    // One more must fail
    try testing.expectError(error.SendQueueFull, conn.enqueueSend(&data));

    // Drain one slot: now there is room again
    var out: [8]u8 = undefined;
    _ = conn.send(&out);
    try conn.enqueueSend(&data); // must succeed now
}

test "connection: processAck uses packet epoch not connection epoch" {
    // Verify that processAck is called with the epoch from processFrames,
    // not self.hot.epoch. We do this by tracking bytes_in_flight:
    // send a packet in epoch 0 and ACK it via an ACK frame in epoch 0.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.current_time_ns = 0;

    // Record a sent packet in epoch 0
    conn.loss.onPacketSent(1, 0, 1200, true, 0, .{});
    try testing.expectEqual(@as(u64, 1200), conn.loss.bytes_in_flight);

    // Build an ACK frame acknowledging pn=1
    const ack = frame.AckFrame{
        .largest_acked = 1,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 1 }} ++ [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    };
    // Call processAck with epoch=0 (the epoch the ACK was received in)
    try conn.processAck(ack, 0);

    // bytes_in_flight must be reduced (ACK was processed with correct epoch)
    try testing.expectEqual(@as(u64, 0), conn.loss.bytes_in_flight);
}

test "connection: version 0 packet is silently ignored" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Build a minimal long-header packet with version 0 (VN packet from peer).
    var pkt: [32]u8 = undefined;
    pkt[0] = 0x80;
    std.mem.writeInt(u32, pkt[1..5], 0x00000000, .big); // version 0
    pkt[5] = 8;
    @memset(pkt[6..14], 0xcc); // DCID
    pkt[14] = 8;
    @memset(pkt[15..23], 0xdd); // SCID

    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&pkt, src, 0, io) catch {};

    // No packet should be queued (VN response is NOT sent for version-0 packets).
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

// ---------------------------------------------------------------------------
// New tests — event queue (Step 3)
// ---------------------------------------------------------------------------

test "event_queue: push and pop FIFO" {
    const testing = std.testing;
    var q = EventQueue{};
    try testing.expect(q.isEmpty());

    q.push(.{ .stream_data = .{ .stream_id = 1 } });
    q.push(.{ .stream_data = .{ .stream_id = 2 } });
    q.push(.connected);

    const ev1 = q.pop().?;
    try testing.expectEqual(@as(u62, 1), ev1.stream_data.stream_id);
    const ev2 = q.pop().?;
    try testing.expectEqual(@as(u62, 2), ev2.stream_data.stream_id);
    const ev3 = q.pop().?;
    switch (ev3) {
        .connected => {},
        else => try testing.expect(false),
    }
    try testing.expectEqual(@as(?Event, null), q.pop());
}

test "event: pollEvent returns null when empty" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    try testing.expectEqual(@as(?Event, null), conn.pollEvent());
}

test "event_queue: full queue drops new events" {
    const testing = std.testing;
    var q = EventQueue{};
    // Fill to capacity
    var i: usize = 0;
    while (i < EVENT_QUEUE_DEPTH) : (i += 1) {
        q.push(.connected);
    }
    // This push must be silently dropped (no panic)
    q.push(.{ .stream_data = .{ .stream_id = 99 } });
    // Pop all — should only get EVENT_QUEUE_DEPTH items, all .connected
    var count: usize = 0;
    while (q.pop()) |ev| {
        switch (ev) {
            .connected => {},
            else => try testing.expect(false),
        }
        count += 1;
    }
    try testing.expectEqual(EVENT_QUEUE_DEPTH, count);
}

// ---------------------------------------------------------------------------
// New tests — retransmission (Step 4)
// ---------------------------------------------------------------------------

test "retransmit: acked stream frame advances send_acked" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Set up a stream with buffered send data
    const st = conn.streams.getOrCreate(0).?;
    _ = st.bufferSendData("hello world"); // 11 bytes at offset 0
    st.send_offset = 11;

    // Simulate an AckResult acknowledging 11 bytes of stream data at offset 0
    var ack_result = loss_recovery_mod.AckResult{};
    var fi = loss_recovery_mod.SentFrameInfo{};
    fi.frames[0] = .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .len = 11,
        .fin = false,
    } };
    fi.count = 1;
    ack_result.acked_frames[0] = fi;
    ack_result.acked_frame_count = 1;

    conn.processAckedFrames(ack_result);

    try testing.expectEqual(@as(u64, 11), st.send_acked);
}

test "retransmit: acked FIN on closed stream triggers stream reclamation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    const st = conn.streams.getOrCreate(4).?;
    st.state = .closed;
    _ = st.bufferSendData("bye");
    st.send_offset = 3;

    var ack_result = loss_recovery_mod.AckResult{};
    var fi = loss_recovery_mod.SentFrameInfo{};
    fi.frames[0] = .{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .len = 3,
        .fin = true,
    } };
    fi.count = 1;
    ack_result.acked_frames[0] = fi;
    ack_result.acked_frame_count = 1;

    conn.processAckedFrames(ack_result);

    // Stream should have been reclaimed
    try testing.expectEqual(@as(?*stream_mod.Stream, null), conn.streams.get(4));
}

test "retransmit: lost HANDSHAKE_DONE sets pending_handshake_done flag" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var lost_result = loss_recovery_mod.AckResult{};
    var fi = loss_recovery_mod.SentFrameInfo{};
    fi.frames[0] = .handshake_done;
    fi.count = 1;
    lost_result.lost_frames[0] = fi;
    lost_result.lost_frame_count = 1;

    conn.processLostFrames(lost_result);

    try testing.expect(conn.pending_handshake_done);
}

test "retransmit: lost MAX_DATA sets pending_max_data flag" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var lost_result = loss_recovery_mod.AckResult{};
    var fi = loss_recovery_mod.SentFrameInfo{};
    fi.frames[0] = .{ .max_data = 65536 };
    fi.count = 1;
    lost_result.lost_frames[0] = fi;
    lost_result.lost_frame_count = 1;

    conn.processLostFrames(lost_result);

    try testing.expect(conn.pending_max_data);
}

// ---------------------------------------------------------------------------
// New tests — connection close (Step 5)
// ---------------------------------------------------------------------------

test "close: close() transitions to closing state" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 0;
    try conn.close(0, false, &[_]u8{});
    try testing.expectEqual(ConnState.closing, conn.hot.state);
}

test "close: close() is idempotent when already closing" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 0;
    try conn.close(0, false, &[_]u8{});
    try conn.close(1, true, &[_]u8{}); // must not change state or panic
    try testing.expectEqual(ConnState.closing, conn.hot.state);
}

test "close: drain_deadline arms after close()" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    try conn.close(0, false, &[_]u8{});
    try testing.expect(conn.drain_deadline_ns != null);
    try testing.expect(conn.drain_deadline_ns.? > 1_000_000_000);
}

test "close: drain timer in tick transitions to closed" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .closing;
    conn.drain_deadline_ns = 5000;
    conn.tick(6000);
    try testing.expectEqual(ConnState.closed, conn.hot.state);
    try testing.expectEqual(@as(?i64, null), conn.drain_deadline_ns);
}

test "close: draining state suppresses send()" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .draining;
    // Queue something
    try conn.enqueueSend(&[_]u8{0x01});
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

test "close: nextTimeout includes drain_deadline" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.drain_deadline_ns = 2000;
    conn.idle_deadline_ns = 5000;
    // drain is smaller → nextTimeout returns drain
    try testing.expectEqual(@as(?i64, 2000), conn.nextTimeout());
}

test "close: close() pushes connection_closed event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 0;
    try conn.close(42, true, &[_]u8{});
    const ev = conn.pollEvent().?;
    switch (ev) {
        .connection_closed => |cc| {
            try testing.expectEqual(@as(u62, 42), cc.error_code);
            try testing.expect(cc.is_app);
        },
        else => try testing.expect(false),
    }
}

test "close: closing state discards incoming packets (returns early)" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .closing;
    conn.current_time_ns = 0;

    // Feed a dummy packet — should not panic and connection stays closing.
    const dummy = [_]u8{0x00} ** 10;
    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&dummy, src, 0, io) catch {};
    try testing.expectEqual(ConnState.closing, conn.hot.state);
}

test "close: receive refreshes idle_deadline on active connection" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established;
    conn.idle_deadline_ns = 500;

    // Feed a (malformed but non-empty) packet at time 1000.
    const dummy = [_]u8{0x00} ** 5;
    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&dummy, src, 1_000_000_000, io) catch {};

    // idle_deadline should be refreshed beyond 500.
    try testing.expect(conn.idle_deadline_ns.? > 500);
}

// ---------------------------------------------------------------------------
// New tests — RESET_STREAM / STOP_SENDING (Step 6)
// ---------------------------------------------------------------------------

test "stream_reset: processFrames handles RESET_STREAM and pushes event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Create a stream first
    _ = conn.streams.getOrCreate(0).?;

    // Build a raw RESET_STREAM frame
    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .reset_stream = .{
        .stream_id = 0,
        .error_code = 7,
        .final_size = 0,
    } });

    // processFrames directly
    conn.processFrames(buf[0..n], 2, null) catch {};

    const ev = conn.pollEvent().?;
    switch (ev) {
        .stream_reset => |r| {
            try testing.expectEqual(@as(u62, 0), r.stream_id);
            try testing.expectEqual(@as(u62, 7), r.error_code);
        },
        else => try testing.expect(false),
    }
}

test "security: processStreamFrame rejects server-initiated stream ID" {
    // A server-side connection must reject STREAM frames with server-initiated IDs (bit 0 = 1).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established; // SEC-004: state guard passes; stream-ID guard fires

    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 1, // bit 0 = 1 → server-initiated, invalid for received frames
        .offset = 0,
        .fin = false,
        .data = "hi",
    } });
    try testing.expectError(error.StreamStateError, conn.processFrames(buf[0..n], 2, null));
}

test "security: processAck malformed ack_range returns InvalidFrame" {
    // An ACK with ack_range > largest_acked must return error.InvalidFrame (SEC-002).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    const ack = frame.AckFrame{
        .largest_acked = 2,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 10 }} // 10 > largest_acked=2
                ++ [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    };
    try testing.expectError(error.InvalidFrame, conn.processAck(ack, 0));
}

test "security: processAck malformed gap returns InvalidFrame" {
    // Gap value that would underflow the running low pointer must return InvalidFrame.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Two ranges: first [10..10], gap=100 (too large), second [0..0].
    // After first range: low=10, high=10.  gap=100 >= low=10 → underflow guard.
    var ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32;
    ranges[0] = .{ .gap = 0, .ack_range = 0 }; // first range: [10..10]
    ranges[1] = .{ .gap = 100, .ack_range = 0 }; // gap 100 >= low 10 → underflow
    const ack = frame.AckFrame{
        .largest_acked = 10,
        .ack_delay = 0,
        .ranges = ranges,
        .range_count = 2,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    };
    try testing.expectError(error.InvalidFrame, conn.processAck(ack, 0));
}

test "security: VN rate limit suppresses second response within 1s" {
    // First unknown-version packet at t=0 → VN sent.
    // Second at t=500ms (< 1s) → no VN.
    // Third at t=1001ms (≥ 1s) → VN sent again.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var pkt: [32]u8 = undefined;
    pkt[0] = 0xc0;
    std.mem.writeInt(u32, pkt[1..5], 0x00000002, .big);
    pkt[5] = 8; @memset(pkt[6..14], 0xaa);
    pkt[14] = 8; @memset(pkt[15..23], 0xbb);
    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };

    // t=0: first packet → VN response queued
    conn.receive(&pkt, src, 0, io) catch {};
    var out: [64]u8 = undefined;
    try testing.expect(conn.send(&out) > 0); // VN sent

    // t=500ms: second packet → rate-limited, no VN
    conn.receive(&pkt, src, 500_000_000, io) catch {};
    try testing.expectEqual(@as(usize, 0), conn.send(&out)); // suppressed

    // t=1001ms: third packet → 1s elapsed, VN allowed again
    conn.receive(&pkt, src, 1_001_000_000, io) catch {};
    try testing.expect(conn.send(&out) > 0); // VN sent again
}

test "event_queue: wraparound maintains FIFO order" {
    // Push/pop 20 events total (> EVENT_QUEUE_DEPTH=16) in batches so head and
    // tail wrap around the ring buffer. Verify FIFO order is preserved.
    const testing = std.testing;
    var q = EventQueue{};

    // Fill and drain twice to force head/tail past the buffer boundary.
    var round: usize = 0;
    while (round < 2) : (round += 1) {
        var i: usize = 0;
        while (i < EVENT_QUEUE_DEPTH) : (i += 1) {
            q.push(.{ .stream_data = .{ .stream_id = @intCast(round * EVENT_QUEUE_DEPTH + i) } });
        }
        i = 0;
        while (i < EVENT_QUEUE_DEPTH) : (i += 1) {
            const ev = q.pop().?;
            const expected: u62 = @intCast(round * EVENT_QUEUE_DEPTH + i);
            try testing.expectEqual(expected, ev.stream_data.stream_id);
        }
    }
    try testing.expect(q.isEmpty());
}

test "connection: cached_ack_delay_exp default is 3" {
    // RFC 9000 §18.2 default for ack_delay_exponent is 3.
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{}, io);
    try testing.expectEqual(@as(u6, 3), conn.cached_ack_delay_exp);
}

test "connection: idle_timeout_i64 matches config at accept()" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{ .idle_timeout_ns = 10_000_000_000 }, io);
    try testing.expectEqual(@as(i64, 10_000_000_000), conn.idle_timeout_i64);
}

test "connection: idle_timeout_i64 is zero when idle_timeout_ns is zero" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{ .idle_timeout_ns = 0 }, io);
    try testing.expectEqual(@as(i64, 0), conn.idle_timeout_i64);
}

test "security: rx_pn_valid initializes to false for all epochs" {
    // All three epochs must start with rx_pn_valid = false (no packet seen yet).
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection.accept(.{}, io);
    try testing.expect(!conn.hot.rx_pn_valid[0]);
    try testing.expect(!conn.hot.rx_pn_valid[1]);
    try testing.expect(!conn.hot.rx_pn_valid[2]);
}

test "security: ConnectionHot size unchanged after adding rx_pn_valid" {
    // Adding [3]bool + shrinking _pad by 3 must keep the struct at exactly 64 bytes.
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(ConnectionHot));
}

test "connection: nextTimeout returns null when all deadlines are null" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.idle_deadline_ns = null;
    conn.pto_deadline_ns = null;
    conn.drain_deadline_ns = null;
    try testing.expectEqual(@as(?i64, null), conn.nextTimeout());
}

test "connection: nextTimeout sentinel does not leak as a valid deadline" {
    // Even if two timers are null, the returned value must be the one real deadline.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.idle_deadline_ns = null;
    conn.pto_deadline_ns = 42;
    conn.drain_deadline_ns = null;
    try testing.expectEqual(@as(?i64, 42), conn.nextTimeout());
}

test "stream_reset: processFrames handles STOP_SENDING and pushes event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    const st = conn.streams.getOrCreate(0).?;
    st.send_offset = 100;

    // Build a raw STOP_SENDING frame
    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stop_sending = .{
        .stream_id = 0,
        .error_code = 3,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    // pending_reset is consumed by flushPendingResets() (set then cleared).
    // The observable result is the stop_sending event.
    const ev = conn.pollEvent().?;
    switch (ev) {
        .stop_sending => |s| {
            try testing.expectEqual(@as(u62, 0), s.stream_id);
            try testing.expectEqual(@as(u62, 3), s.error_code);
        },
        else => try testing.expect(false),
    }
}

test "loss: multi-packet loss triggers single congestion event" {
    // Verify the fix for RFC 9438 §5.6: when N packets are lost in one ACK event,
    // cwnd drops by exactly BETA_CUBIC once (not BETA_CUBIC^N).
    // Setup: send 10 packets, ACK only pn=10. K_PACKET_THRESHOLD=3 means
    // pn=1..7 are declared lost (7 losses in a single processAck call).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.current_time_ns = 1_000_000_000;

    // Force CUBIC into congestion avoidance with a known large window.
    conn.congestion.ssthresh = 0; // cwnd always > ssthresh=0 → CUBIC always used
    conn.congestion.cwnd = 100 * 1200; // 120000 bytes (100 × MSS)
    const initial_cwnd = conn.congestion.cwnd;

    // Register 10 packets in epoch 0, all sent at t=0.
    var pn: u64 = 1;
    while (pn <= 10) : (pn += 1) {
        conn.loss.onPacketSent(pn, 0, 1200, true, 0, .{});
    }

    // ACK only pn=10; pn=1..7 satisfy K_PACKET_THRESHOLD and are declared lost.
    const ack = frame.AckFrame{
        .largest_acked = 10,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    };
    try conn.processAck(ack, 0);

    // After the fix: cwnd reduced exactly once → floor(120000 × 0.7) = 84000.
    // If the bug (loop) were present: cwnd ≈ floor(120000 × 0.7^7) ≈ 9897.
    const expected: u64 = @intFromFloat(@as(f64, @floatFromInt(initial_cwnd)) * 0.7);
    try testing.expectEqual(expected, conn.congestion.cwnd);
}

// ---------------------------------------------------------------------------
// New tests — connected event (Step 2)
// ---------------------------------------------------------------------------

test "connection: HANDSHAKE_DONE frame pushes connected event (client)" {
    // HANDSHAKE_DONE is valid only for clients (is_server=false). RFC 9000 §19.20.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{ .is_server = false }, io);

    // Build a raw HANDSHAKE_DONE frame and feed it through processFrames
    var buf: [4]u8 = undefined;
    const n = frame.encodeFrame(&buf, .handshake_done);
    try conn.processFrames(buf[0..n], 2, null);

    const ev = conn.pollEvent().?;
    switch (ev) {
        .connected => {},
        else => try testing.expect(false),
    }
    try testing.expectEqual(ConnState.established, conn.hot.state);
}

// ---------------------------------------------------------------------------
// New tests — PATH_CHALLENGE / PATH_RESPONSE (Step 3)
// ---------------------------------------------------------------------------

test "connection: PATH_CHALLENGE without app_keys is silently consumed (no panic)" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_challenge = .{ .data = .{ 1, 2, 3, 4, 5, 6, 7, 8 } } });
    // Must not panic or error; app_keys is null so queuePathResponse returns early
    conn.processFrames(buf[0..n], 2, null) catch {};

    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

test "connection: PATH_RESPONSE is silently consumed" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = .{ 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4 } } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    // No event, no packet queued
    try testing.expectEqual(@as(?Event, null), conn.pollEvent());
    var out: [64]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

// ---------------------------------------------------------------------------
// New tests — MAX_STREAMS (Step 4)
// ---------------------------------------------------------------------------

test "connection: MAX_STREAMS_BIDI updates peer_max_streams_bidi" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .max_streams_bidi = 100 });
    conn.processFrames(buf[0..n], 2, null) catch {};
    try testing.expectEqual(@as(u62, 100), conn.peer_max_streams_bidi);
}

test "connection: MAX_STREAMS_BIDI value never decreases" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.peer_max_streams_bidi = 50;

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .max_streams_bidi = 30 });
    conn.processFrames(buf[0..n], 2, null) catch {};
    try testing.expectEqual(@as(u62, 50), conn.peer_max_streams_bidi);
}

// ---------------------------------------------------------------------------
// New tests — NEW_CONNECTION_ID (Step 5)
// ---------------------------------------------------------------------------

test "connection: NEW_CONNECTION_ID stores CID entry" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var cid_bytes: [20]u8 = undefined;
    @memset(&cid_bytes, 0xab);
    var tok: [16]u8 = undefined;
    @memset(&tok, 0xcd);

    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 0,
        .cid = cid_bytes,
        .cid_len = 8,
        .stateless_reset_token = tok,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    var found = false;
    for (conn.peer_cid_table) |entry| {
        if (entry.valid and entry.seq == 1) { found = true; break; }
    }
    try testing.expect(found);
}

test "connection: NEW_CONNECTION_ID retire_prior_to invalidates old CIDs" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    var cid0: [20]u8 = undefined; @memset(&cid0, 0xaa);
    var cid1: [20]u8 = undefined; @memset(&cid1, 0xcc);
    var tok0: [16]u8 = undefined; @memset(&tok0, 0xbb);
    var tok1: [16]u8 = undefined; @memset(&tok1, 0xdd);

    var buf: [64]u8 = undefined;
    var n = frame.encodeFrame(&buf, .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .cid = cid0, .cid_len = 8,
        .stateless_reset_token = tok0,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    // seq=1 with retire_prior_to=1 → seq=0 must be invalidated
    n = frame.encodeFrame(&buf, .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .cid = cid1, .cid_len = 8,
        .stateless_reset_token = tok1,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    var found_old = false;
    for (conn.peer_cid_table) |entry| {
        if (entry.valid and entry.seq == 0) { found_old = true; break; }
    }
    try testing.expect(!found_old);
}

// ---------------------------------------------------------------------------
// New tests — MAX_STREAM_DATA generation via tick() (Step 6)
// ---------------------------------------------------------------------------

test "connection: tick clears shouldSendMaxStreamData after stream read" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Create a stream and simulate the application reading data (grows recv_max)
    const st = conn.streams.getOrCreate(0).?;
    try st.receiveData(0, "hello world", false);
    var read_buf: [16]u8 = undefined;
    _ = st.read(&read_buf);
    // recv_max has grown beyond last_sent_max_stream_data
    try testing.expect(st.shouldSendMaxStreamData());

    // tick() calls flushPendingMaxStreamData only when established (PERF-001).
    conn.hot.state = .established;
    conn.tick(1_000_000);
    try testing.expect(!st.shouldSendMaxStreamData());
}

// ---------------------------------------------------------------------------
// New tests — persistent congestion in connection (Step 7)
// ---------------------------------------------------------------------------

test "connection: persistent congestion collapses cwnd to 2*MSS" {
    // ptoBase with default RTT ≈ 1_024_000_000 ns; 3×PTO ≈ 3_072_000_000 ns.
    // Send pn=1..5, with pn=5 sent at t=3_200_000_000 (> 3×PTO span from pn=1 at t=0).
    // ACK pn=8 → pn=1..5 declared lost → persistent_congestion = true → cwnd = 2*MSS.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    conn.congestion.cwnd = 100 * 1200;
    conn.congestion.ssthresh = 0; // always in CUBIC phase

    conn.current_time_ns = 0;
    conn.loss.onPacketSent(1, 0, 1200, true, 0, .{});
    conn.loss.onPacketSent(2, 0, 1200, true, 0, .{});
    conn.loss.onPacketSent(3, 0, 1200, true, 0, .{});
    conn.loss.onPacketSent(4, 0, 1200, true, 0, .{});
    conn.loss.onPacketSent(5, 0, 1200, true, 3_200_000_000, .{});
    conn.loss.onPacketSent(8, 0, 1200, true, 3_200_000_000, .{});

    const ack = frame.AckFrame{
        .largest_acked = 8,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    };
    conn.current_time_ns = 3_200_000_000;
    try conn.processAck(ack, 0);

    // Persistent congestion → cwnd = 2 * MSS = 2400
    try testing.expectEqual(@as(u64, 2 * 1200), conn.congestion.cwnd);
}

// ---------------------------------------------------------------------------
// Security & performance regression tests (Round 5 hardening)
// ---------------------------------------------------------------------------

// SEC-001: HANDSHAKE_DONE direction enforcement
test "security: server rejects HANDSHAKE_DONE (direction violation)" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{ .is_server = true }, io); // default
    var buf: [4]u8 = undefined;
    const n = frame.encodeFrame(&buf, .handshake_done);
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 2, null));
    // State must not have changed
    try testing.expectEqual(ConnState.idle, conn.hot.state);
}

// SEC-004: STREAM frames rejected before established state
test "security: STREAM frame before established returns ProtocolViolation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    // Connection is .idle — STREAM must be rejected
    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 2, null));
}

// SEC-005: Amplification limit
test "security: amplification limit blocks excessive sends" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    // Simulate receiving a small datagram (100 bytes received → 300 bytes budget).
    // We increment manually since we're bypassing real receive().
    conn.bytes_unvalidated_recv = 100;

    // First 300 bytes should be allowed (3 × 100).
    const pkt = [_]u8{0x01} ** 100;
    try conn.enqueueSend(&pkt);
    try conn.enqueueSend(&pkt);
    try conn.enqueueSend(&pkt);

    // 301st byte triggers the limit.
    try testing.expectError(error.AmplificationLimitExceeded, conn.enqueueSend(&[_]u8{0x01}));
}

test "security: amplification limit lifted after path_validated" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    conn.bytes_unvalidated_recv = 1; // very small budget
    conn.path_validated = true;      // validated → no limit

    // Even though budget is tiny, sends are allowed once validated.
    try conn.enqueueSend(&[_]u8{0x01} ** 100);
    try testing.expect(true); // no error
}

// SEC-006: Frame-type per epoch enforcement
test "security: STREAM frame in Initial epoch returns ProtocolViolation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.hot.state = .established; // bypass SEC-004 state check

    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0, .offset = 0, .fin = false, .data = "hi",
    } });
    // Feed as epoch 0 (Initial) — STREAM is not allowed there.
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 0, null));
}

test "security: HANDSHAKE_DONE in epoch 0 returns ProtocolViolation" {
    // Even for a client, HANDSHAKE_DONE in the Initial epoch is forbidden.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{ .is_server = false }, io);
    var buf: [4]u8 = undefined;
    const n = frame.encodeFrame(&buf, .handshake_done);
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 0, null));
}

test "security: ACK frame in epoch 0 is allowed" {
    // ACK is unrestricted (Initial, Handshake, 1-RTT).
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    const ack_frame_data: frame.Frame = .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    } };
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, ack_frame_data);
    // Must not return ProtocolViolation for epoch 0.
    conn.processFrames(buf[0..n], 0, null) catch |err| {
        try std.testing.expect(err != error.ProtocolViolation);
    };
}

// SEC-007: stream.canSend overflow-safe
test "security: stream.canSend prevents u64 wrap-around" {
    const testing = std.testing;
    var s = stream_mod.Stream.init(0);
    s.send_max = std.math.maxInt(u64);
    s.send_offset = std.math.maxInt(u64) - 1;
    // Requesting 2 bytes would wrap: (maxInt - 1) + 2 overflows.
    try testing.expect(!s.canSend(2));
    // Requesting exactly 1 byte does not overflow.
    try testing.expect(s.canSend(1));
}

// SEC-008: NEW_CONNECTION_ID CID length > 20 rejected
test "security: NEW_CONNECTION_ID with cid_len > 20 returns InvalidFrame" {
    const testing = std.testing;
    // Manually build a NEW_CONNECTION_ID frame with cid_len = 21.
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    // Frame type 0x18
    buf[pos] = 0x18; pos += 1;
    // sequence_number = 1 (varint)
    buf[pos] = 0x01; pos += 1;
    // retire_prior_to = 0 (varint)
    buf[pos] = 0x00; pos += 1;
    // cid_len = 21 (too large)
    buf[pos] = 21; pos += 1;
    // cid data (21 bytes) + reset_token (16 bytes) — pad with zeros
    @memset(buf[pos..][0..37], 0xab);
    pos += 37;
    try testing.expectError(error.InvalidFrame, frame.parseFrame(buf[0..pos]));
}

// SEC-009: PATH_RESPONSE validation against pending challenge
test "security: PATH_RESPONSE matching pending challenge clears it" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    const challenge_data = [8]u8{ 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4 };
    conn.pending_path_challenge = challenge_data;

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = challenge_data } });
    try conn.processFrames(buf[0..n], 2, null);

    // pending_path_challenge must be cleared
    try testing.expectEqual(@as(?[8]u8, null), conn.pending_path_challenge);
}

test "security: PATH_RESPONSE with wrong data returns ProtocolViolation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);
    conn.pending_path_challenge = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const wrong_data = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = wrong_data } });
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 2, null));
}

// SEC-010: RESET_STREAM final_size consistency
test "security: RESET_STREAM with inconsistent final_size while FIN pending returns FinalSizeError" {
    // Out-of-order FIN: FIN arrives at offset 20 before gap data (0..20).
    // fin_recv_offset is set to 25 but recv_offset stays 0 (pending).
    // A RESET with final_size != 25 must be rejected (RFC 9000 §3.3).
    const testing = std.testing;
    var s = stream_mod.Stream.init(0);
    s.recv_max = 1024;
    // FIN at offset 20 with 5 bytes; out-of-order so recv_offset stays 0.
    try s.receiveData(20, "world", true); // fin_recv_offset = 25
    try testing.expect(s.fin_recv_offset != null);
    // RESET with final_size = 10 ≠ 25 → FinalSizeError
    try testing.expectError(error.FinalSizeError, s.onResetReceived(0, 10));
}

test "security: RESET_STREAM with matching final_size while FIN pending is accepted" {
    const testing = std.testing;
    var s = stream_mod.Stream.init(0);
    s.recv_max = 1024;
    // FIN at offset 20 with 5 bytes; fin_recv_offset = 25, recv_offset = 0.
    try s.receiveData(20, "world", true);
    try testing.expect(s.fin_recv_offset != null);
    // RESET with final_size = 25 == fin_recv_offset → accepted
    try s.onResetReceived(0, 25);
    try testing.expectEqual(stream_mod.StreamState.reset, s.state);
}

// PERF-001: flushPendingMaxStreamData skipped when not established
test "perf: flushPendingMaxStreamData not called when not established" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection.accept(.{}, io);

    const st = conn.streams.getOrCreate(0).?;
    try st.receiveData(0, "hello world", false);
    var buf: [16]u8 = undefined;
    _ = st.read(&buf);
    try testing.expect(st.shouldSendMaxStreamData());

    // tick() in idle state must NOT clear the flag (no flush).
    conn.tick(1_000_000);
    try testing.expect(st.shouldSendMaxStreamData()); // flag still set
}

// SEC-008 (frame.zig): CID length bounds test via frame encoding round-trip
test "security: NEW_CONNECTION_ID parse rejects cid_len = 21" {
    // Verify the bounds check via the frame parser used in protocol flow.
    // We manually encode the offending byte sequence rather than using encodeFrame
    // (which only handles valid frames).
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    // 0x18 | seq=1 | rpt=0 | cid_len=21 | 21 bytes cid | 16 bytes token
    buf[0] = 0x18; buf[1] = 0x01; buf[2] = 0x00; buf[3] = 21;
    @memset(buf[4..][0..37], 0); // 21-byte cid + 16-byte token
    try testing.expectError(error.InvalidFrame, frame.parseFrame(buf[0..41]));
}
