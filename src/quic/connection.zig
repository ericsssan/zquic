//! QUIC connection state machine (RFC 9000).
//!
//! Sans-I/O design: the caller owns the UDP socket and event loop.
//! The connection is driven by:
//!
//!   connection.receive(data, src) — feed a received UDP datagram
//!   connection.send(out, now_ns)   — drain the next UDP datagram to transmit
//!   connection.nextTimeout()      — nanosecond deadline for tick()
//!   connection.tick(now_ns)       — drive timer-based events
//!
//! No sockets, no threads, no allocator in the hot path.

const std = @import("std");
const crypto = @import("crypto.zig");
const crypto_simd = @import("crypto_simd.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const tls = @import("tls.zig");
const transport_params = @import("transport_params.zig");
const varint = @import("varint.zig");
const cid_mod = @import("connection_id.zig");
const stream_mod = @import("stream.zig");
const flow_control = @import("flow_control.zig");
const cc_mod = @import("congestion/cc.zig");
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

    /// Returns true if only the port differs (same address family + IP).
    /// RFC 9000 §9.3.1: port-only changes indicate NAT rebinding, not path migration.
    pub fn isPortOnlyChange(a: SocketAddr, b: SocketAddr) bool {
        return switch (a) {
            .v4 => |av4| switch (b) {
                .v4 => |bv4| std.mem.eql(u8, &av4.addr, &bv4.addr) and av4.port != bv4.port,
                .v6 => false,
            },
            .v6 => |av6| switch (b) {
                .v6 => |bv6| std.mem.eql(u8, &av6.addr, &bv6.addr) and av6.port != bv6.port,
                .v4 => false,
            },
        };
    }
};

// ---------------------------------------------------------------------------
// Event queue
// ---------------------------------------------------------------------------

pub const EVENT_QUEUE_DEPTH = 256;

pub const Event = union(enum) {
    stream_data: struct { stream_id: u62 },
    stream_reset: struct { stream_id: u62, error_code: u62 },
    connection_closed: struct { error_code: u62, is_app: bool },
    connected,
    stop_sending: struct { stream_id: u62, error_code: u62 },
    /// Peer changed source address; app can query `peer_addr` for the new path.
    path_migrated,
    /// A Retry packet was sent; caller should drain send buf, then discard this connection object.
    retry_sent,
};

pub const EventQueue = struct {
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

pub const MAX_PACKET_SIZE = 1500; // Maximum received packet size (standard MTU)
pub const MAX_SEND_PACKET_SIZE = 1452; // Maximum packet size for sending (UDP datagram limit)
pub const SEND_QUEUE_DEPTH = 256;

/// Maximum number of out-of-order CRYPTO fragments buffered per epoch.
const CRYPTO_STAGE_DEPTH = 16;
/// Maximum bytes in a single staged CRYPTO fragment (conservatively > max QUIC payload).
pub const CRYPTO_STAGE_FRAG = 1400;
/// Maximum number of pending stream retransmits when send queue is full.
/// Must be large enough to handle worst-case burst losses when pacing
/// keeps the send queue non-empty during loss detection.  The epoch 2
/// sent buffer holds up to 128 packets, each with up to 1 stream frame
/// in practice, so 128 covers the realistic worst case.
const MAX_PENDING_RETX = 128;

/// A single buffered out-of-order CRYPTO fragment.
const CryptoStagedFrag = struct {
    offset: u64 = 0,
    len: u16 = 0,
    data: [CRYPTO_STAGE_FRAG]u8 = undefined,
};

const SendSlot = struct {
    buf: [MAX_SEND_PACKET_SIZE]u8,
    len: usize,
};

/// Per-slot metadata for deferred wire-time accounting.
/// Stored in parallel with SendSlot; consumed by send() to call
/// loss.onPacketSent at wire time rather than queue time.
const SendMeta = struct {
    pn: u64 = 0,
    epoch: u8 = 0,
    size: u16 = 0,
    ack_eliciting: bool = false,
    /// Queue-time timestamp for delivery rate computation.  Wire-time
    /// (now_ns in send()) is used for loss detection timing, but delivery
    /// rate must use queue-time to avoid pacing delays inflating
    /// send_elapsed and depressing BBR's bandwidth estimate.
    queued_ns: i64 = 0,
    frame_info: loss_recovery_mod.SentFrameInfo = .{},
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
    /// Enable address validation with Retry tokens (RFC 9000 §8.1).
    validate_addr: bool = false,
    /// 32-byte secret for token derivation via HKDF-Expand.
    token_secret: [32]u8 = [_]u8{0} ** 32,
    /// Token validity window in nanoseconds (default 5 minutes).
    token_validity_ns: i64 = 5 * 60 * std.time.ns_per_s,
    /// ALPN protocol to require. Static/caller-owned slice; "" = no ALPN check.
    alpn: []const u8 = "",
    /// Pre-loaded DER certificate (null = use ephemeral self-signed).
    cert_der: ?[]const u8 = null,
    /// 32-byte private key material for cert_der: Ed25519 seed or P-256 scalar.
    cert_seed: ?[32]u8 = null,
    /// Key algorithm for cert_der (ignored when cert_der is null).
    cert_key_algorithm: tls.KeyAlgorithm = .ed25519,
    /// Pre-formatted TLS CertificateEntry list for the full cert chain.
    /// When non-null, buildCertificateMessage sends this instead of just cert_der.
    /// Format: [3-byte len][DER][2-byte ext(0)] repeated for each cert.
    cert_chain: ?[]const u8 = null,
    /// Initial QUIC version (0x00000001 = v1, 0x6b3343cf = v2).
    /// Overridden by client's version in first Initial packet.
    initial_quic_version: u32 = packet.QUIC_VERSION_1,
    /// Maximum number of client-initiated bidirectional streams to advertise.
    initial_max_streams_bidi: u64 = 100,
    /// Maximum number of client-initiated unidirectional streams to advertise.
    initial_max_streams_uni: u64 = 100,
    /// IPv4 address for preferred_address transport parameter (RFC 9000 §18.2.3).
    /// When non-null, the server advertises this as its preferred migration target.
    /// The alt_local_cid and alt_local_reset_token are used automatically.
    preferred_addr_ipv4: ?[4]u8 = null,
    preferred_addr_ipv4_port: u16 = 0,
    /// IPv6 address for preferred_address transport parameter (RFC 9000 §18.2.3).
    preferred_addr_ipv6: [16]u8 = [_]u8{0} ** 16,
    preferred_addr_ipv6_port: u16 = 0,
    /// Preferred AEAD cipher suite. The server negotiates this when the client offers it.
    preferred_cipher: crypto.CipherSuite = .aes_128_gcm,
    /// 32-byte key for session ticket encryption (enables resumption/0-RTT).
    /// When null, session tickets are not issued.
    ticket_key: ?*const [32]u8 = null,
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

pub fn Connection(comptime max_streams: usize) type {
    return struct {
        const Self = @This();

        hot: ConnectionHot align(64),

        // Identity
        local_cid: ConnectionId,
        peer_cid: ConnectionId,
        /// Client's SCID as received in the first Initial packet (0–20 bytes).
        /// RFC 9000 §7.2: server DCID in long-header packets must equal client SCID.
        peer_scid: [20]u8 = [_]u8{0} ** 20,
        peer_scid_len: u8 = 0,
        peer_addr: SocketAddr,

        // Crypto
        initial_keys: crypto.InitialKeys,
        tls_state: tls.TlsServer,
        /// Initial QUIC version from client's first Initial packet.
        /// Used for encoding Initial response packets (always matches client's version).
        initial_version: u32,
        /// QUIC version negotiated for this connection (v1 or v2).
        /// Used for Handshake and 1-RTT packets (may differ from initial_version).
        quic_version: u32,

        // Per-epoch packet keys (null until negotiated)
        hs_keys: ?tls.HandshakeKeys,
        app_keys: ?tls.AppKeys,

        // Stream layer
        streams: stream_mod.StreamTable(max_streams),

        // Flow control
        conn_flow: flow_control.FlowController,

        // Congestion control
        congestion: cc_mod.CongestionControl,

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
        sq_meta: [SEND_QUEUE_DEPTH]SendMeta,
        sq_head: usize,
        sq_tail: usize,
        /// Bytes in the send queue (ack-eliciting only) that have not yet
        /// been handed to the socket.  Complements loss.bytes_in_flight which
        /// counts wire-sent bytes only.
        bytes_queued: u64,

        // Timers
        idle_deadline_ns: ?i64,
        pto_deadline_ns: ?i64,
        /// Deadline for transitioning out of closing/draining state.
        drain_deadline_ns: ?i64,
        /// RFC 9002 §6.1.2 time-threshold loss detection alarm.
        /// Fires when unacked packets behind largest_acked have aged past the time threshold.
        time_loss_alarm_ns: ?i64,

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
        // Sized to MAX_SEND_PACKET_SIZE to allow large data chunks + frame headers.
        pkt_scratch: [MAX_SEND_PACKET_SIZE]u8,
        enc_scratch: [MAX_SEND_PACKET_SIZE]u8,

        // Receive-path: in-place decrypt on caller's mutable buffer (zero copy).
        // rx_hp_buf and rx_plaintext eliminated — saves 3000 bytes per connection.

        /// Stream ID with an active inline borrow (at most one at a time).
        inline_borrow_stream: ?u62 = null,
        /// Consecutive idle PTO PINGs sent (no real data to probe).
        /// Capped at 2 to prevent infinite PING flood after transfers complete.
        /// Reset to 0 when real stream data is sent.
        idle_ping_count: u8 = 0,

        // Peer stream limits (updated by MAX_STREAMS frames and transport params)
        peer_max_streams_bidi: u62,
        peer_max_streams_uni: u62,

        // Local stream limits: how many client-initiated streams we allow the peer to open.
        // Initialized from TransportParams defaults; must match what we advertise in TLS.
        local_max_streams_bidi: u62,
        local_max_streams_uni: u62,

        // Pending MAX_STREAMS frames to send when slots become available (RFC 9000 §4.6)
        pending_max_streams_bidi: ?u62 = null,
        pending_max_streams_uni: ?u62 = null,

        // Per-stream flow control limits advertised by the peer (RFC 9000 §7.3, §18.2).
        // initial_max_stream_data_bidi_local: the peer's send limit on bidi streams they initiate
        // (= how many bytes we allow them to send on client-initiated bidi streams).
        // Used to initialize stream.send_max when a new stream is created.
        peer_max_stream_data_bidi_local: u64,

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

        // ECN (Explicit Congestion Notification) tracking (RFC 9001 Appendix A).
        /// Count of ECT(0) packets received in each epoch [Initial, Handshake, 1-RTT].
        ecn_ect0_recv: [3]u64,
        /// Count of CE (Congestion Experienced) packets received in each epoch.
        ecn_ce_recv: [3]u64,

        /// Outstanding PATH_CHALLENGE data we sent; null if none pending (RFC 9000 §9.2).
        pending_path_challenge: ?[8]u8,

        // Key update state (RFC 9001 §6) ------------------------------------------

        /// True once we have sent a key update and are waiting for the peer to ACK
        /// with the new key_phase bit.
        key_update_pending: bool,
        /// Current key_phase bit used in Short Header TX/RX (RFC 9001 §6).
        current_key_phase: bool,
        /// Pre-computed next-generation app keys (ready to use on peer-initiated update).
        next_app_keys: ?tls.AppKeys,

        // Cached AES contexts — pre-expanded key schedule for multi-buffer SIMD.
        // Avoids ~200ns key expansion per packet on the 1-RTT hot path.
        cached_app_keys: ?crypto_simd.CachedKeyCtx,
        cached_next_keys: ?crypto_simd.CachedKeyCtx,

        /// Next-generation client traffic secret (source for key derivation).
        next_client_secret: [32]u8,
        /// Next-generation server traffic secret.
        next_server_secret: [32]u8,
        /// Current key generation number (0 = initial, 1 = first rotation, etc).
        /// Used for SSLKEYLOG tracking of rotated secrets.
        current_key_generation: u32,

        // Path migration state (RFC 9000 §9) ----------------------------------------

        /// True when the peer transport parameters include disable_active_migration.
        peer_disable_migration: bool,

        // Path MTU Discovery (RFC 9000 §14) -----------------------------------------

        /// Current discovered path MTU (bytes). Starts at QUIC minimum (1200).
        /// Increased when probes are successfully ACKed, decreased on loss.
        path_mtu: u16 = 1200,
        /// In-flight PMTUD probe state (null if no probe active).
        pmtud_probing: ?struct {
            target_size: u16, // size we're probing
            packet_number: u64, // packet number of the probe
            epoch: u2, // encryption epoch (0=Initial, 1=Handshake, 2=1-RTT)
            sent_ns: i64, // when we sent the probe
        } = null,
        /// Deadline for the next PMTUD probe (nanoseconds). Initially 0 (inactive).
        pmtud_next_probe_ns: i64 = 0,

        // ECN state (RFC 9000 §12.1, RFC 9002 §B.1) ------------------------------------

        /// Monotonically increasing ECN CE count seen per epoch [Initial, Handshake, 1-RTT].
        /// When a peer ACK reports a higher CE count, we treat it as a congestion event.
        ecn_ce_seen: [3]u62,
        /// Per-epoch sliding-window bitmap of received packet numbers (RFC 9000 §13.2).
        /// Bit i of rx_pn_bitmap[e] is set when packet (rx_pn[e] − i) was received.
        /// Bit 0 is always set when rx_pn_valid[e] is true (= largest received packet).
        /// Window covers the most recent 64 packet numbers; older PNs are treated as
        /// duplicates (safe: RFC 9000 §13.2.3 only requires tracking a recent window).
        rx_pn_bitmap: [3]u64,

        // Retry token state (RFC 9000 §8.1) ------------------------------------------

        /// Connection ID we chose for Retry packet (null if no Retry sent).
        retry_scid: ?ConnectionId = null,
        /// Original DCID from validated Retry token (null if no token validation).
        /// Variable length 0–20 bytes (quic-go sends 20-byte initial DCIDs).
        original_dcid: ?[20]u8 = null,
        original_dcid_len: u8 = 0,
        /// DCID from the client's very first Initial packet (set on first receive, idle→handshake).
        /// Used for original_destination_connection_id (RFC 9000 §7.3):
        /// the server MUST always include this parameter, even without Retry.
        first_initial_dcid: [20]u8 = [_]u8{0} ** 20,
        first_initial_dcid_len: u8 = 0,

        /// Alternative local CID advertised to peer via NEW_CONNECTION_ID (sequence=1).
        /// Helps tshark track 1-RTT packets when the primary CID appears in client
        /// long-header DCID before the server's Initial SCID in the trace.
        alt_local_cid: ConnectionId,
        /// Stateless reset token for alt_local_cid (RFC 9000 §10.3.1).
        alt_local_reset_token: [16]u8,

        // Pending retransmit flags
        pending_handshake_done: bool,
        pending_max_data: bool,
        /// Count of streams with a pending_reset set; avoids O(MAX_STREAMS) scan in tick().
        pending_reset_count: u8,
        /// Per-version DoS protection: track last 4 unknown versions + response times.
        /// Prevents attackers from spamming different versions (RFC 9000 §5.1 rate-limiting).
        unknown_versions: [4]u32,
        unknown_version_times: [4]i64,
        unknown_version_idx: u8,

        // Per-epoch TLS send offset (for FrameInfo tracking)
        crypto_send_offset: [3]u64,
        /// Rotating retransmit position for CRYPTO PTO retransmissions.
        /// Each PTO cycle continues from where the last left off, ensuring
        /// all CRYPTO data is eventually delivered under amplification limits.
        crypto_retx_pos: [2]usize,
        /// Buffer storing outgoing CRYPTO data (epochs 0 and 1) for PTO retransmission.
        /// Populated by sendCryptoChunk; retransmitted by the PTO handler in tick().
        /// Sized to match the TLS output buffer so overflow is structurally impossible.
        crypto_send_saved: [2][32768]u8,
        crypto_send_saved_len: [2]u16,
        /// Handshake CRYPTO data (EncryptedExtensions through Finished) buffered during
        /// amplification limit, awaiting budget to send. Allows retry when more client
        /// packets arrive and grow the budget (RFC 9000 §8.1.2).
        tls_pending_hs: [32768]u8,
        /// Number of bytes in tls_pending_hs awaiting transmission.
        tls_pending_hs_len: usize,
        /// Read offset in tls_pending_hs (bytes already sent from this buffer).
        tls_pending_hs_offset: usize,
        /// Stream frames that failed to retransmit (send queue full). Drained in tick().
        stream_pending_retx: [MAX_PENDING_RETX]struct {
            stream_id: u62,
            offset: u62,
            len: u16,
            fin: bool,
        },
        stream_pending_retx_count: u8,
        /// CRYPTO frames that failed to retransmit (send queue full). Drained in tick().
        crypto_pending_retx: [MAX_PENDING_RETX]struct {
            epoch: u8,
            offset: u62,
            len: u16,
        },
        crypto_pending_retx_count: u8,
        /// Per-epoch expected CRYPTO receive offset (RFC 9000 §19.6).
        /// Out-of-order/duplicate CRYPTO frames are rejected or trimmed against this.
        crypto_recv_offset: [3]u64,
        /// Out-of-order CRYPTO fragment staging (RFC 9000 §19.6).
        /// Stores fragments that arrived before their predecessors; drained in-order.
        crypto_staged: [3][CRYPTO_STAGE_DEPTH]CryptoStagedFrag,
        crypto_staged_count: [3]u8,
        /// Total bytes currently staged per epoch (DoS defense: prevents unbounded memory pinning).
        /// Limit: 16KB per epoch. Frames exceeding this are silently dropped.
        crypto_staged_bytes: [3]u32 = [_]u32{ 0, 0, 0 },
        /// Highest peer-provided sequence in NEW_CONNECTION_ID (monotonic bound for validation).
        peer_cid_highest_seq: u62 = 0,

        /// Deferred ACK flags: set when an ack-eliciting frame is received in an epoch.
        /// Flushed to encrypted ACK packets at the end of receive().
        pending_ack: [3]bool,
        /// Cached idle timeout cast to i64 — computed once in accept() so receive() avoids
        /// the @intCast/@min per packet. Zero when idle timeout is disabled.
        idle_timeout_i64: i64,

        // Session resumption / 0-RTT state
        /// Set after handshake completes when ticket_key is configured; triggers NST send.
        pending_new_session_ticket: bool = false,
        /// 0-RTT decryption keys derived from client_early_traffic_secret.
        zero_rtt_keys: ?crypto.PacketKeys = null,
        /// True when we are accepting 0-RTT data (STREAM frames allowed before established).
        accepting_early_data: bool = false,

        /// Create a server-side connection.  Call `receive()` with the first
        /// datagram to start the handshake.
        pub fn accept(config: Config, io: std.Io) !Self {
            var tls_server = if (config.cert_der) |der|
                try tls.TlsServer.initFromCert(der, config.cert_seed.?, config.cert_key_algorithm, io)
            else
                try tls.TlsServer.init(io);
            if (config.cert_chain) |chain| tls_server.setCertChain(chain);
            // NOTE: Do NOT set tls_server.quic_version here. Let it default to V1.
            // The connection layer will set it to the client's Initial version (line 962).
            // TLS will only switch versions if version_information indicates support (RFC 9368).
            tls_server.server_configured_version = config.initial_quic_version;
            tls_server.preferred_cipher = config.preferred_cipher;
            tls_server.ticket_key = config.ticket_key;
            if (config.alpn.len > 0) {
                const n = @min(config.alpn.len, 32);
                @memcpy(tls_server.required_alpn[0..n], config.alpn[0..n]);
                tls_server.required_alpn_len = @intCast(n);
            }
            const local_cid = ConnectionId.generate(0, io);
            const alt_local_cid = ConnectionId.generate(0, io);
            var alt_local_reset_token: [16]u8 = undefined;
            io.random(&alt_local_reset_token);
            const idle_timeout_i64: i64 = if (config.idle_timeout_ns > 0)
                @intCast(@min(config.idle_timeout_ns, @as(u64, std.math.maxInt(i64))))
            else
                0;

            return Self{
                .hot = .{
                    .rx_pn = [_]u64{0} ** 3,
                    .tx_pn = [_]u64{0} ** 3,
                    .state = .idle,
                    .epoch = 0,
                    .rx_pn_valid = .{ false, false, false },
                    ._pad = [_]u8{0} ** 11,
                },
                .local_cid = local_cid,
                .alt_local_cid = alt_local_cid,
                .alt_local_reset_token = alt_local_reset_token,
                .peer_cid = ConnectionId.zero,
                .peer_addr = .{ .v4 = .{ .addr = [_]u8{0} ** 4, .port = 0 } },
                .initial_keys = .{
                    .client = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
                    .server = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
                },
                .tls_state = tls_server,
                .initial_version = packet.QUIC_VERSION_1,
                .quic_version = packet.QUIC_VERSION_1,
                .hs_keys = null,
                .app_keys = null,
                .streams = .{},
                .conn_flow = flow_control.FlowController.init(
                    config.initial_max_data,
                    config.initial_max_data,
                ),
                .congestion = cc_mod.CongestionControl.init(),
                .loss = loss_recovery_mod.LossRecovery.init(),
                .current_time_ns = 0,
                .cached_max_ack_delay_ns = 25_000_000,
                .cached_ack_delay_exp = 3,
                .idle_timeout_i64 = idle_timeout_i64,
                .sq = undefined,
                .sq_meta = [_]SendMeta{.{}} ** SEND_QUEUE_DEPTH,
                .sq_head = 0,
                .sq_tail = 0,
                .bytes_queued = 0,
                .idle_deadline_ns = null,
                .pto_deadline_ns = null,
                .drain_deadline_ns = null,
                .time_loss_alarm_ns = null,
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
                // rx_hp_buf and rx_plaintext removed (in-place decrypt)
                .inline_borrow_stream = null,
                .idle_ping_count = 0,
                .peer_max_streams_bidi = 0,
                .peer_max_streams_uni = 0,
                .local_max_streams_bidi = @min(config.initial_max_streams_bidi, @as(u64, std.math.maxInt(u62))),
                .local_max_streams_uni = @min(config.initial_max_streams_uni, @as(u64, std.math.maxInt(u62))),
                .peer_max_stream_data_bidi_local = flow_control.DEFAULT_MAX_STREAM_DATA,
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
                .ecn_ect0_recv = .{ 0, 0, 0 },
                .ecn_ce_recv = .{ 0, 0, 0 },
                .pending_path_challenge = null,
                .key_update_pending = false,
                .current_key_phase = false,
                .next_app_keys = null,
                .cached_app_keys = null,
                .cached_next_keys = null,
                .next_client_secret = [_]u8{0} ** 32,
                .next_server_secret = [_]u8{0} ** 32,
                .current_key_generation = 0,
                .peer_disable_migration = false,
                .pending_handshake_done = false,
                .pending_max_data = false,
                .pending_reset_count = 0,
                .unknown_versions = [_]u32{0} ** 4,
                .unknown_version_times = [_]i64{std.math.minInt(i64)} ** 4,
                .unknown_version_idx = 0,
                .crypto_send_offset = .{ 0, 0, 0 },
                .crypto_retx_pos = .{ 0, 0 },
                .crypto_send_saved = @import("std").mem.zeroes([2][32768]u8),
                .crypto_send_saved_len = .{ 0, 0 },
                .tls_pending_hs = std.mem.zeroes([32768]u8),
                .tls_pending_hs_len = 0,
                .tls_pending_hs_offset = 0,
                .stream_pending_retx = undefined,
                .stream_pending_retx_count = 0,
                .crypto_pending_retx = undefined,
                .crypto_pending_retx_count = 0,
                .crypto_recv_offset = .{ 0, 0, 0 },
                .crypto_staged = @import("std").mem.zeroes([3][CRYPTO_STAGE_DEPTH]CryptoStagedFrag),
                .crypto_staged_count = .{ 0, 0, 0 },
                .pending_ack = .{ false, false, false },
                .ecn_ce_seen = .{ 0, 0, 0 },
                .rx_pn_bitmap = [_]u64{0} ** 3,
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
        pub fn receive(self: *Self, data: []u8, src: SocketAddr, now_ns: i64, ecn_bits: u2, io: std.Io) !void {
            self.current_time_ns = now_ns;

            // Flush any unconsumed inline borrows before the recv buffer is overwritten.
            // Sans-IO guarantee: receive() is the only entry that overwrites the buffer,
            // so inline slices are valid from processStreamFrame until here.
            self.flushAllInlineBorrows();

            // Track ECN bits if present (RFC 9001 Appendix A)
            // ecn_bits: 0=not-ECT, 1=ECT(1), 2=ECT(0), 3=CE
            if (ecn_bits != 0) {
                const epoch: usize = self.hot.epoch;
                if (ecn_bits == 2) {
                    // ECT(0) - increment ECT(0) counter for this epoch
                    if (epoch < self.ecn_ect0_recv.len) {
                        self.ecn_ect0_recv[epoch] +|= 1;
                    }
                } else if (ecn_bits == 3) {
                    // CE - increment CE counter for this epoch
                    if (epoch < self.ecn_ce_recv.len) {
                        self.ecn_ce_recv[epoch] +|= 1;
                    }
                }
            }

            // Path migration detection (RFC 9000 §9): only in established state,
            // and only when the peer has not disabled active migration.
            if (self.hot.state == .established and !self.peer_addr.eql(src)) {
                if (!self.peer_disable_migration) {
                    if (SocketAddr.isPortOnlyChange(self.peer_addr, src)) {
                        // RFC 9000 §9.3.1: port-only change is likely NAT rebinding.
                        // Skip congestion reset and path validation to preserve throughput.
                        self.onNatRebind(src, io) catch {};
                    } else {
                        self.onPathMigration(src, io) catch {};
                    }
                }
            }

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
                // Try to flush any Handshake CRYPTO data buffered during previous amplification limits
                self.flushPendingHsCrypto();
                // RFC 9002 §6.2.2.1: restart PTO when anti-amplification budget grows.
                // The PTO was suppressed (set to null) when the server was fully limited;
                // now that we have more budget, re-arm it so retransmits can proceed.
                if (self.pto_deadline_ns == null and self.loss.bytes_in_flight > 0) {
                    self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
                }
            }

            // Process all coalesced packets in the datagram
            var remaining = data;
            while (remaining.len > 0) {
                const consumed = try self.processOnePacket(remaining, src, io);
                if (consumed == 0) break;
                remaining = remaining[consumed..];
            }

            // Flush deferred ACKs — at most one encrypted ACK per packet-number space
            // per datagram (RFC 9000 §13.2.1).
            //
            // Exception: suppress the Initial-epoch (epoch 0) ACK if TLS has not yet
            // produced any output (hs_keys == null).  When the client sends a
            // fragmented ClientHello across two Initial packets, responding to the
            // first with a standalone ACK-only packet delays ServerHello and causes
            // tshark to see the client's first 1-RTT packet before the ServerHello
            // in the left-node trace, breaking decryption.  Holding the ACK means
            // it will be included (along with ServerHello) on the next datagram.
            if (self.pending_ack[0]) {
                if (self.hs_keys != null) {
                    self.pending_ack[0] = false;
                    self.sendEncryptedAck(0) catch {};
                }
            }
            if (self.pending_ack[1]) {
                self.pending_ack[1] = false;
                self.sendEncryptedAck(1) catch {};
            }
            if (self.pending_ack[2]) {
                self.pending_ack[2] = false;
                self.sendEncryptedAck(2) catch {};
            }
        }

        /// Store per-packet metadata for deferred wire-time accounting.
        /// Called immediately after enqueueSend() succeeds (sq_tail already
        /// advanced), so the metadata is written to the slot that was just filled.
        fn storeSendMeta(self: *Self, pn: u64, epoch: u8, size: usize, ack_eliciting: bool, fi: loss_recovery_mod.SentFrameInfo) void {
            const idx = (self.sq_tail - 1) & (SEND_QUEUE_DEPTH - 1);
            const sz: u16 = @intCast(@min(size, 0xffff));
            self.sq_meta[idx] = .{
                .pn = pn,
                .epoch = epoch,
                .size = sz,
                .ack_eliciting = ack_eliciting,
                .queued_ns = self.current_time_ns,
                .frame_info = fi,
            };
            if (ack_eliciting) {
                self.bytes_queued += sz;
            }
        }

        /// Write the next UDP payload to `out`. Returns bytes written (0 = nothing pending).
        /// `now_ns` is the wall-clock time used for wire-time accounting (loss recovery,
        /// pacing, and PTO arming).
        ///
        /// RFC 9000 §12.2: coalesces consecutive long-header packets (Initial +
        /// Handshake) into a single UDP datagram so they share one loss event
        /// instead of being independently dropped.
        pub fn send(self: *Self, out: []u8, now_ns: i64) usize {
            // RFC 9000 §10.2: draining state — must not send anything.
            if (self.hot.state == .draining) return 0;
            if (self.sq_head == self.sq_tail) {
                // Nothing to send — if cwnd has room, we are app-limited.
                if (self.loss.bytes_in_flight + self.bytes_queued < self.congestion.cwnd) {
                    self.loss.delivery.app_limited = true;
                }
                return 0;
            }
            const mask = SEND_QUEUE_DEPTH - 1;
            var meta = self.sq_meta[self.sq_head & mask];
            // Pacing gate: refill tokens and check if we can send.
            const pacing_tokens = self.congestion.pacing.refill(self.congestion.cwnd, now_ns);
            if (meta.ack_eliciting and pacing_tokens < meta.size and
                self.congestion.pacing.rate > 0 and self.congestion.shouldPace())
            {
                // Pacing blocks this ack-eliciting packet.  Scan ahead for a
                // non-ack-eliciting packet (e.g., ACK-only) that can skip the
                // gate — the server must always respond to client packets even
                // when retransmissions are pacing-gated, otherwise the client
                // sees a dead connection and idle-closes.
                var found = false;
                var scan = self.sq_head + 1;
                while (scan < self.sq_tail) {
                    const scan_meta = self.sq_meta[scan & mask];
                    if (!scan_meta.ack_eliciting) {
                        // Swap this non-ack-eliciting packet to the front.
                        const scan_slot_idx = scan & mask;
                        const head_slot_idx = self.sq_head & mask;
                        const tmp_meta = self.sq_meta[head_slot_idx];
                        self.sq_meta[head_slot_idx] = self.sq_meta[scan_slot_idx];
                        self.sq_meta[scan_slot_idx] = tmp_meta;
                        const tmp_buf = self.sq[head_slot_idx];
                        self.sq[head_slot_idx] = self.sq[scan_slot_idx];
                        self.sq[scan_slot_idx] = tmp_buf;
                        meta = self.sq_meta[self.sq_head & mask];
                        found = true;
                        break;
                    }
                    scan += 1;
                }
                if (!found) return 0;
            }
            const slot = &self.sq[self.sq_head & mask];
            var total = @min(slot.len, out.len);
            @memcpy(out[0..total], slot.buf[0..total]);
            // Wire-time accounting for the first packet.
            self.loss.onPacketSent(meta.pn, meta.epoch, meta.size, meta.ack_eliciting, now_ns, meta.queued_ns, meta.frame_info);
            if (meta.ack_eliciting) {
                self.bytes_queued -|= meta.size;
                self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
            }
            self.sq_head += 1;

            // Coalesce: append consecutive long-header packets (epoch 0/1) into
            // the same UDP datagram (RFC 9000 §12.2).  This halves handshake loss
            // probability under lossy networks.  Do NOT coalesce 1-RTT packets —
            // that breaks connection migration (Handshake ACK + 1-RTT data in one
            // datagram confuses path validation).
            if (meta.epoch < 2) {
                while (self.sq_head < self.sq_tail) {
                    const next_meta = self.sq_meta[self.sq_head & mask];
                    if (next_meta.epoch >= 2) break;
                    const next_slot = &self.sq[self.sq_head & mask];
                    if (total + next_slot.len > out.len) break;
                    @memcpy(out[total..][0..next_slot.len], next_slot.buf[0..next_slot.len]);
                    self.loss.onPacketSent(next_meta.pn, next_meta.epoch, next_meta.size, next_meta.ack_eliciting, now_ns, next_meta.queued_ns, next_meta.frame_info);
                    if (next_meta.ack_eliciting) {
                        self.bytes_queued -|= next_meta.size;
                        self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
                    }
                    total += next_slot.len;
                    self.sq_head += 1;
                }
            }

            if (self.congestion.pacing.rate > 0) {
                self.congestion.pacing.consume(total);
            }
            self.bytes_sent += total;
            self.pkts_sent += 1;
            return total;
        }

        /// Returns the nanosecond deadline when `tick()` must be called,
        /// or null if no timer is active.  Includes the pacing deadline when
        /// the send queue is non-empty so the event loop wakes to drain it.
        pub fn nextTimeout(self: *const Self) ?i64 {
            const idle = self.idle_deadline_ns orelse std.math.maxInt(i64);
            const pto = self.pto_deadline_ns orelse std.math.maxInt(i64);
            const drain = self.drain_deadline_ns orelse std.math.maxInt(i64);
            const tl = self.time_loss_alarm_ns orelse std.math.maxInt(i64);
            const pacing: i64 = if (self.sq_head != self.sq_tail)
                self.congestion.pacing.nextSendTime() orelse std.math.maxInt(i64)
            else
                std.math.maxInt(i64);
            const m = @min(@min(@min(@min(idle, pto), drain), tl), pacing);
            return if (m == std.math.maxInt(i64)) null else m;
        }

        /// Drive timer events. Call when `nextTimeout()` deadline has passed.
        pub fn tick(self: *Self, now_ns: i64) void {
            self.current_time_ns = now_ns;

            // Drain timer: closing/draining → closed.
            if (self.drain_deadline_ns) |d| {
                if (now_ns >= d) {
                    self.hot.state = .closed;
                    self.drain_deadline_ns = null;
                    self.events.push(.{ .connection_closed = .{ .error_code = 0, .is_app = false } });
                }
            }

            // Idle timeout → closed (RFC 9000 §10.1).
            if (self.idle_deadline_ns) |d| {
                if (now_ns >= d) {
                    self.hot.state = .closed;
                    self.idle_deadline_ns = null;
                    self.events.push(.{ .connection_closed = .{ .error_code = 0, .is_app = false } });
                }
            }

            // Flush any Handshake CRYPTO that was buffered when amplification limit
            // blocked the initial send.  This must run on every tick — not just in
            // receive() — because under high loss the client's packets may never
            // arrive to trigger receive(), leaving the pending HS data unsent.
            self.flushPendingHsCrypto();

            // Drain any deferred CRYPTO and stream retransmits before generating new traffic
            self.drainPendingCryptoRetx();
            self.drainPendingStreamRetx();

            // Re-arm PTO if drain sent packets but PTO was null (e.g., processAck set
            // pto_deadline_ns to null when bytes_in_flight dropped to 0, then loss
            // detection queued CRYPTO retransmits that drainPendingCryptoRetx just sent).
            if (self.pto_deadline_ns == null and self.loss.bytes_in_flight > 0) {
                self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
            }

            // PTO: suppress in closing/draining/closed states.
            if (self.hot.state != .closing and
                self.hot.state != .draining and
                self.hot.state != .closed)
            {
                if (self.pto_deadline_ns) |d| {
                    if (now_ns >= d) {
                        self.loss.onPtoFired();
                        if (self.app_keys != null) {
                            // Post-handshake PTO: retransmit PATH_CHALLENGE if pending (RFC 9000 §9.2),
                            // drain pending stream retransmits, probe with unacked stream data,
                            // or send a 1-RTT PING probe (RFC 9002 §6.2).
                            // Note: crypto_pending_retx is cleared on handshake completion, so
                            // no CRYPTO drain is needed here.
                            if (self.pending_path_challenge) |challenge| {
                                self.sendPathChallenge(challenge) catch {};
                            } else if (self.stream_pending_retx_count > 0) {
                                self.drainPendingStreamRetx();
                            } else if (self.probeUnackedStreamData()) {
                                // Sent unacked stream data as PTO probe (RFC 9002 §6.2:
                                // "a sender SHOULD include new data in probe datagrams").
                            } else {
                                // Only PING probe if there's meaningful data in flight
                                // (not just our own previous PINGs). Without this guard,
                                // PTO sends infinite PINGs after all transfers complete:
                                // each PING creates in-flight state → PTO fires → PING → loop.
                                // Limit to 6 consecutive idle PINGs, then let idle timeout close.
                                if (self.idle_ping_count < 6) {
                                    self.queuePing() catch {};
                                    self.idle_ping_count += 1;
                                }
                            }
                        } else {
                            // During handshake: flush pending buffered HS data first (covers the case
                            // where amplification limit blocked the initial Handshake send), then
                            // retransmit previously-sent CRYPTO data as probe packets (RFC 9002 §6.2.4).
                            // Prioritize Handshake over Initial: once we have HS keys, the client
                            // must have processed our Initial, so retransmitting Initial wastes budget.
                            const sent_before = self.bytes_unvalidated_sent;
                            self.flushPendingHsCrypto();
                            // Retransmit CRYPTO data as PTO probes (RFC 9002 §6.2.4).
                            // Once we have Handshake keys, the client has already processed
                            // our ServerHello — skip Initial retransmit to preserve scarce
                            // amplification budget for the Handshake CRYPTO (cert chain)
                            // that the client actually needs. Under 30% corruption with
                            // the 3× amplification limit, each wasted 149-byte Initial
                            // starves the 753-byte Handshake, causing permanent deadlock.
                            // Skip Initial retransmit if the client has already proven it
                            // has our ServerHello (by sending a Handshake-epoch packet).
                            // Each wasted 149-byte Initial starves the Handshake CRYPTO
                            // retransmit under the 3× amplification limit.
                            const client_has_sh = self.hot.rx_pn_valid[1];
                            if (!client_has_sh) {
                                self.retransmitCryptoSaved(0);
                            }
                            self.retransmitCryptoSaved(1);
                            const no_progress = self.bytes_unvalidated_sent == sent_before;
                            if (no_progress and !self.path_validated and self.bytes_unvalidated_recv > 0) {
                                // Amplification-limited: can't send anything. Schedule PTO
                                // from current time to prevent the deadline-in-the-past flooding
                                // bug (last_ack_eliciting_ns doesn't advance when no ack-eliciting
                                // packets are sent, causing ptoDeadline() to return a past time).
                                const pto_base = self.loss.rtt.ptoBase(self.cached_max_ack_delay_ns);
                                const shift: u6 = @intCast(@min(self.loss.pto_count, 5));
                                const backoff: u64 = pto_base *| (@as(u64, 1) << shift);
                                const max_i64: u64 = @as(u64, std.math.maxInt(i64));
                                self.pto_deadline_ns = self.current_time_ns +| @as(i64, @intCast(@min(backoff, max_i64)));
                            } else {
                                self.pto_deadline_ns = self.loss.ptoDeadline(self.cached_max_ack_delay_ns);
                            }
                        }
                    }
                }
            }

            // Time-threshold loss alarm (RFC 9002 §6.1.2): fire when unacked packets
            // behind largest_acked have aged past 9/8×RTT, without waiting for PTO.
            if (self.hot.state != .closing and
                self.hot.state != .draining and
                self.hot.state != .closed)
            {
                if (self.time_loss_alarm_ns) |tl| {
                    if (now_ns >= tl) {
                        self.time_loss_alarm_ns = null;
                        const tns = self.loss.timeThresholdNs();
                        var tl_result = loss_recovery_mod.AckResult{};
                        for (0..3) |epoch_idx| {
                            const la = self.loss.largest_acked[epoch_idx];
                            if (la == 0) continue;
                            self.loss.sent.detectLoss(
                                la,
                                tns,
                                now_ns,
                                @intCast(epoch_idx),
                                &tl_result,
                                &self.loss.bytes_in_flight,
                            );
                        }
                        if (tl_result.newly_lost > 0) {
                            self.congestion.onPacketLost(tl_result.bytes_lost, now_ns);
                            self.processLostFrames(tl_result);
                        }
                        // Reschedule if there are still candidates.
                        self.time_loss_alarm_ns = self.loss.timeLossAlarmNs(self.cached_max_ack_delay_ns);
                    }
                }
            }

            // PMTUD: periodically probe for larger MTU (RFC 9000 §14).
            // Start probing after handshake completes; probe every 10 seconds.
            if (self.hot.state == .established and self.app_keys != null) {
                if (self.pmtud_probing == null and now_ns >= self.pmtud_next_probe_ns) {
                    const next_size = self.getNextPmtudSize();
                    if (next_size > self.path_mtu) {
                        if (self.queuePmtudProbe(next_size)) {
                            self.pmtud_next_probe_ns = now_ns + 10_000_000_000;
                        } else |err| {
                            if (err == error.PacketTooLarge) {
                                self.path_mtu = (1200 + next_size) / 2;
                            }
                            self.pmtud_next_probe_ns = now_ns + 1_000_000_000;
                        }
                    }
                }
                if (self.pmtud_probing) |probe| {
                    const pto_ns = self.loss.rtt.ptoBase(self.cached_max_ack_delay_ns);
                    if (now_ns - probe.sent_ns > 3 *| pto_ns) {
                        self.path_mtu = (1200 + probe.target_size) / 2;
                        self.pmtud_probing = null;
                        self.pmtud_next_probe_ns = now_ns + 1_000_000_000;
                    }
                }
            }

            // Send NewSessionTicket if pending (post-handshake, 1-RTT CRYPTO).
            if (self.pending_new_session_ticket and self.app_keys != null) {
                if (self.sendNewSessionTicket()) {
                    self.pending_new_session_ticket = false;
                } else |_| {}
            }

            // Flush pending retransmits.
            if (self.pending_handshake_done) {
                self.pending_handshake_done = false;
                self.queueHandshakeDone() catch {};
            }

            // Flush pending stream resets (fast-path: skip scan when nothing is pending).
            if (self.pending_reset_count > 0) self.flushPendingResets() catch {};

            // Batch MAX_DATA + MAX_STREAM_DATA into a single 1-RTT packet (coalescing).
            if (self.hot.state == .established) self.flushControlFrames() catch {};
        }

        pub fn isClosed(self: *const Self) bool {
            return self.hot.state == .closed or
                self.hot.state == .draining or
                self.hot.state == .closing;
        }

        pub fn isDraining(self: *const Self) bool {
            return self.hot.state == .draining;
        }

        pub fn isEstablished(self: *const Self) bool {
            return self.hot.state == .established;
        }

        /// Drain the next application event, or null if none pending.
        pub fn pollEvent(self: *Self) ?Event {
            return self.events.pop();
        }

        /// Buffer stream data for sending and queue a packet.
        pub fn streamSend(self: *Self, stream_id: u62, data: []const u8, fin: bool) !void {
            const st = self.streams.getOrCreate(stream_id) orelse return error.TooManyStreams;
            if (!st.canSend(@intCast(data.len))) {
                // RFC 9000 §19.13 SHOULD: signal peer to increase the flow control window.
                if (self.hot.state == .established) {
                    self.queueStreamDataBlocked(stream_id, @intCast(st.send_max)) catch {};
                }
                return error.StreamNotWritable;
            }
            // Check buffer capacity before any mutation so the operation is all-or-nothing.
            if (st.sendBufferFree() < data.len) return error.BufferFull;
            if (self.hot.state != .established) return error.StreamNotWritable;
            // Congestion window gate for new sends only (RFC 9002 §7).
            // Retransmissions (processLostFrames) bypass this check so loss recovery
            // is never blocked by a temporarily-reduced cwnd after a loss event.
            // Estimate packet size as data.len + 64 bytes of header/AEAD overhead.
            if (self.loss.bytes_in_flight + self.bytes_queued + data.len + 64 > self.congestion.cwnd) {
                return error.CongestionWindowFull;
            }
            // Clear app-limited flag: we are actively sending.
            self.loss.delivery.app_limited = false;
            try self.queueStreamData(stream_id, data, fin);
        }

        /// Initiate a connection close.  Transitions to closing, queues a CONNECTION_CLOSE,
        /// and arms the drain timer.
        pub fn close(self: *Self, error_code: u62, is_app: bool, reason: []const u8) !void {
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

        /// Zero all cryptographic key material held by this connection.
        /// Must be called when the connection is no longer needed.
        /// Uses volatile writes (secureZero) to prevent compiler elision.
        pub fn deinit(self: *Self) void {
            self.tls_state.deinit();
            std.crypto.secureZero(u8, @as(*volatile [@sizeOf(crypto.InitialKeys)]u8, @ptrCast(&self.initial_keys)));
            std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.next_client_secret)));
            std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.next_server_secret)));
            if (self.hs_keys) |*ks| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(tls.HandshakeKeys)]u8, @ptrCast(ks)));
                self.hs_keys = null;
            }
            if (self.app_keys) |*ks| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(tls.AppKeys)]u8, @ptrCast(ks)));
                self.app_keys = null;
            }
            if (self.next_app_keys) |*ks| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(tls.AppKeys)]u8, @ptrCast(ks)));
                self.next_app_keys = null;
            }
            if (self.zero_rtt_keys) |*ks| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(crypto.PacketKeys)]u8, @ptrCast(ks)));
                self.zero_rtt_keys = null;
            }
            self.accepting_early_data = false;
        }

        /// Reset a stream and queue a RESET_STREAM frame.
        pub fn resetStream(self: *Self, stream_id: u62, error_code: u62) !void {
            const st = self.streams.get(stream_id) orelse return error.StreamNotFound;
            st.initiateReset(error_code);
            self.pending_reset_count += 1;
            try self.flushPendingResets();
        }

        // -----------------------------------------------------------------------
        // Internal packet processing
        // -----------------------------------------------------------------------

        pub fn processOnePacket(self: *Self, data: []u8, src: SocketAddr, io: std.Io) !usize {
            if (data.len == 0) return 0;

            if (packet.isLongHeader(data[0])) {
                return self.processLongHeaderPacket(data, src, io);
            } else {
                return self.processShortHeaderPacket(data);
            }
        }

        pub fn processLongHeaderPacket(self: *Self, data: []u8, src: SocketAddr, io: std.Io) !usize {
            // RFC 9000 §6 + RFC 9368: Version negotiation with compatible version support.
            // Check the version field before full parsing — VN packets (version 0) have
            // a different wire format that parseLongHeader cannot handle.
            if (data.len >= 5) {
                const ver = std.mem.readInt(u32, data[1..5], .big);

                // RFC 9368: Compatible version negotiation.
                // v1 and v2 can negotiate together. Client chooses version by sending with that version.
                // Server must respond with matching version (initial keys are version-specific).
                if (self.hot.state == .idle) {
                    // Check if version is supported (v1 or v2).
                    if (ver != packet.QUIC_VERSION_1 and ver != packet.QUIC_VERSION_2 and ver != 0) {
                        // Unsupported version; send Version Negotiation.
                        if (!self.shouldThrottleVersionNeg(ver)) {
                            self.sendVersionNeg(data) catch {};
                        }
                        return data.len;
                    }
                    // RFC 9368: Compatible version negotiation.
                    // For idle connections, respond with our configured version,
                    // not the client's version. The client's version was used to decrypt this Initial
                    // (initial keys are version-specific), but our response uses our configured version.
                    // Version negotiation for idle connections happens in the Initial packet
                    // block below (line ~987), where we set quic_version = ver (client's version).
                    // The quic_version tracks the version being used for the handshake and will
                    // be updated by the TLS layer if compatible version negotiation negotiates a
                    // different version via version_information transport parameter.
                } else {
                    // RFC 9369: During handshake, allow version changes for compatible version negotiation.
                    // Only reject version mismatches after the handshake is complete (connection established).
                    if (self.hot.state == .established and ver != self.quic_version and ver != 0) {
                        return data.len; // Silently drop mismatched version during 1-RTT
                    }
                    // During handshake, reject packets with unsupported versions (not v1 or v2).
                    // This prevents garbage packets with random version bytes from corrupting handshake.
                    if (ver != packet.QUIC_VERSION_1 and ver != packet.QUIC_VERSION_2 and ver != 0) {
                        return data.len; // Silently drop unsupported version during handshake
                    }
                }
            }

            // Reject packets larger than MAX_PACKET_SIZE (RFC 9000 compliance).
            if (data.len > MAX_PACKET_SIZE) return error.PacketTooLarge;

            // Read raw header fields (not HP-protected: version, DCID, SCID are in the clear).
            if (data.len < 7) return error.PacketTooShort;
            const ver = std.mem.readInt(u32, data[1..5], .big);
            const raw_dcid_len = data[5];
            if (raw_dcid_len > 20) return data.len; // invalid CID length; silently drop
            if (data.len < 6 + raw_dcid_len) return error.PacketTooShort;
            const raw_dcid = data[6..][0..raw_dcid_len];

            // Packet type bits 5–4 are NOT header-protected (RFC 9001 §5.4.1).
            const raw_pkt_type = packet.longHeaderType(data[0], ver);

            // RFC 9000 §9: Discard Initial packets in established state.
            // In established state, all Initial packets (even with matching DCID) must be
            // silently dropped. This handles late/retransmitted Initial packets and new
            // connection attempts that happen to use the same server local_cid.
            if (raw_pkt_type == .initial and self.hot.state == .established) {
                return data.len;
            }

            // For handshake state Initial packets, validate DCID against the client's original
            // DCID stored from the first Initial.  RFC 9000 §7.2: a client MUST NOT change its
            // Destination CID before receiving the server's first Initial packet, so all Initial
            // retransmissions (including those carrying fragmented ClientHello bytes) must carry
            // the same variable-length DCID.  The old check compared against local_cid (fixed
            // 8 bytes) and silently dropped every packet whose dcid_len > 8.
            if (raw_pkt_type == .initial and self.hot.state == .handshake and
                self.first_initial_dcid_len > 0)
            {
                if (!std.mem.eql(u8, raw_dcid, self.first_initial_dcid[0..self.first_initial_dcid_len])) {
                    return data.len; // Different DCID: belongs to a different connection.
                }
            }

            // On the first Initial, derive initial keys from the client's DCID before HP removal.
            // Keys are required to select the HP key and remove header protection.
            // Always use the client's version for key derivation to decrypt incoming packets.
            //
            // IMPORTANT: We derive keys here (needed for HP removal and decryption) but
            // defer the state transition to .handshake until AFTER decryption succeeds.
            // This prevents corrupted Initial packets from creating zombie connections
            // that block all subsequent valid Initials from the same client address.
            var transitioning_from_idle = false;
            if (raw_pkt_type == .initial and self.hot.state == .idle) {
                transitioning_from_idle = true;
                self.initial_version = ver;
                self.initial_keys = crypto.deriveInitialKeys(raw_dcid, ver);

                // RFC 9369: Native V2 mode support.
                // If configured for V2 and client sent V1, respond with V2.
                // Otherwise echo client's version (RFC 9368 compatible mode).
                self.quic_version = if (self.config.initial_quic_version == packet.QUIC_VERSION_2 and ver == packet.QUIC_VERSION_1)
                    packet.QUIC_VERSION_2
                else
                    ver;
                // NOTE: Do NOT set tls_state.quic_version here. deliverCryptoChunk pushes
                // conn.quic_version into TLS before processCrypto, allowing TLS to upgrade it
                // via version_information. conn.quic_version then adopts TLS's result.
            } else if (raw_pkt_type == .initial and self.hot.state != .idle and ver != self.initial_version) {
                // RFC 9369: Compatible version negotiation with Retry.
                // Client may retry with a different version (e.g., after Retry response).
                // Re-derive initial keys with the new version to allow decryption.
                self.initial_version = ver;
                self.initial_keys = crypto.deriveInitialKeys(raw_dcid, ver);
            }

            // Select the header-protection key for this packet type.
            const hp_keys: crypto.PacketKeys = switch (raw_pkt_type) {
                .initial => self.initial_keys.client,
                .handshake => if (self.hs_keys) |hk| hk.client else return data.len,
                .zero_rtt => if (self.zero_rtt_keys) |zk| zk else return data.len,
                else => return data.len, // Retry: can't process
            };

            // Compute offset of the packet-number field; validate buffer has space for HP sample.
            const pn_off = packet.longHeaderPnOffset(data, ver) catch return data.len;
            if (pn_off + 4 + 16 > data.len) return error.PacketTooShort;

            // Remove header protection in-place on the caller's mutable buffer (zero copy).
            _ = crypto.removeHeaderProtection(hp_keys, &data[0], data[pn_off..][0..4], data[pn_off + 4 ..][0..16]);

            // Parse with header protection removed.
            const result = try packet.parseLongHeader(data);

            const hdr = result.header;

            switch (hdr.packet_type) {
                .initial => {
                    // peer_cid, quic_version and initial_keys were set in the pre-HP block above.

                    // Address validation via Retry (RFC 9000 §8.1).
                    // Only on the first Initial (original_dcid == null); retransmitted
                    // Initials after a valid token skip re-validation.
                    if (self.config.validate_addr and self.original_dcid == null) {
                        if (hdr.token.len == 0) {
                            // No token: send Retry and stop processing this datagram.
                            try self.sendRetry(raw_dcid, src, self.current_time_ns, io);
                            return result.consumed;
                        }
                        if (self.validateToken(hdr.token, src, self.current_time_ns)) |tok| {
                            self.original_dcid = tok.raw;
                            self.original_dcid_len = tok.len;
                            // RFC 9000 §7.3: server MUST include retry_source_connection_id in
                            // transport params when a Retry was used.  The post-Retry Initial's
                            // DCID is exactly the SCID we put in the Retry packet.
                            var rs: ConnectionId = .{};
                            const copy_len = @min(raw_dcid_len, cid_mod.len);
                            if (copy_len > 0) @memcpy(rs.bytes[0..copy_len], raw_dcid[0..copy_len]);
                            self.retry_scid = rs;
                        } else {
                            // RFC 9000 §8.1.3: "A server MUST drop any Initial packet that
                            // does not contain a valid token." Silent drop — do not error.
                            return result.consumed;
                        }
                    }

                    // Decrypt the Initial packet.
                    const keys = self.initial_keys.client;
                    const pn = packet.decodePacketNumber(
                        self.hot.rx_pn[0],
                        hdr.packet_number,
                        @as(u8, hdr.pn_len) * 8,
                    );

                    // Replay / duplicate protection (RFC 9000 §13.2).
                    if (self.isPnDuplicate(0, pn)) {
                        return result.consumed;
                    }

                    // AAD = HP-removed header bytes (before payload, per RFC 9001 §5.3).
                    const payload_start = result.consumed - hdr.payload.len;
                    const aad: []const u8 = data[0..payload_start];

                    if (hdr.payload.len < 16) return error.PacketTooShort;
                    if (hdr.payload.len - 16 > MAX_PACKET_SIZE) return error.PacketTooLarge;

                    // In-place decrypt: plaintext overwrites ciphertext in caller's buffer.
                    const pt_len = crypto.decryptPayloadInPlace(keys, pn, aad, data[payload_start..][0..hdr.payload.len]) catch |err| {
                        return err;
                    };
                    // Defense-in-depth: zero plaintext after frame processing (key material in Initial).
                    defer std.crypto.secureZero(u8, data[payload_start..][0..pt_len]);

                    // Decryption succeeded — now commit the idle→handshake transition.
                    // This is deferred from the pre-HP block to prevent corrupted Initials
                    // from creating zombie connections with wrong first_initial_dcid.
                    if (transitioning_from_idle) {
                        self.hot.state = .handshake;
                        // Record the client's address now so the first post-handshake 1-RTT
                        // packet does not trigger a false path migration (RFC 9000 §9).
                        self.peer_addr = src;
                        // Store the DCID for original_destination_connection_id (RFC 9000 §7.3).
                        @memcpy(self.first_initial_dcid[0..raw_dcid_len], raw_dcid);
                        self.first_initial_dcid_len = @intCast(raw_dcid_len);
                        // Set peer_cid and peer_scid from the SCID field (not HP-protected).
                        if (data.len >= 6 + raw_dcid_len + 1) {
                            const raw_scid_len = data[6 + raw_dcid_len];
                            if (raw_scid_len <= 20 and data.len >= 6 + raw_dcid_len + 1 + raw_scid_len) {
                                if (raw_scid_len > 0) @memcpy(self.peer_scid[0..raw_scid_len], data[6 + raw_dcid_len + 1 ..][0..raw_scid_len]);
                                self.peer_scid_len = @intCast(raw_scid_len);
                                const copy_len = @min(raw_scid_len, cid_mod.len);
                                var pc: ConnectionId = .{};
                                if (copy_len > 0) @memcpy(pc.bytes[0..copy_len], data[6 + raw_dcid_len + 1 ..][0..copy_len]);
                                self.peer_cid = pc;
                            }
                        }
                    }

                    self.markPnReceived(0, pn);
                    self.bytes_recv += result.consumed;
                    self.pkts_recv += 1;

                    // Process frames from in-place decrypted plaintext (zero copy).
                    try self.processFrames(data[payload_start..][0..pt_len], 0, io);

                    return result.consumed;
                },
                .handshake => {
                    // Handshake packet: use handshake keys.
                    if (self.hs_keys == null) return result.consumed;
                    const keys = self.hs_keys.?.client;
                    const pn = packet.decodePacketNumber(
                        self.hot.rx_pn[1],
                        hdr.packet_number,
                        @as(u8, hdr.pn_len) * 8,
                    );
                    // Replay / duplicate protection (RFC 9000 §13.2).
                    if (self.isPnDuplicate(1, pn)) return result.consumed;
                    // AAD = HP-removed header bytes.
                    const payload_start = result.consumed - hdr.payload.len;
                    const aad: []const u8 = data[0..payload_start];
                    if (hdr.payload.len < 16) return error.PacketTooShort;
                    if (hdr.payload.len - 16 > MAX_PACKET_SIZE) return error.PacketTooLarge;

                    const pt_len = crypto.decryptPayloadInPlace(keys, pn, aad, data[payload_start..][0..hdr.payload.len]) catch |err| {
                        return err;
                    };
                    defer std.crypto.secureZero(u8, data[payload_start..][0..pt_len]);
                    self.markPnReceived(1, pn);
                    try self.processFrames(data[payload_start..][0..pt_len], 1, io);
                    return result.consumed;
                },
                .zero_rtt => {
                    // 0-RTT packet: use 0-RTT keys, epoch 2 PN space (RFC 9001 §4.1.4).
                    const zk = self.zero_rtt_keys orelse return result.consumed;
                    const pn = packet.decodePacketNumber(
                        self.hot.rx_pn[2],
                        hdr.packet_number,
                        @as(u8, hdr.pn_len) * 8,
                    );
                    if (self.isPnDuplicate(2, pn)) return result.consumed;
                    const payload_start = result.consumed - hdr.payload.len;
                    const aad: []const u8 = data[0..payload_start];
                    if (hdr.payload.len < 16) return error.PacketTooShort;
                    if (hdr.payload.len - 16 > MAX_PACKET_SIZE) return error.PacketTooLarge;

                    const pt_len = crypto.decryptPayloadInPlace(zk, pn, aad, data[payload_start..][0..hdr.payload.len]) catch {
                        return result.consumed; // silent drop on decrypt failure
                    };
                    self.markPnReceived(2, pn);
                    self.bytes_recv += result.consumed;
                    self.pkts_recv += 1;
                    try self.processFramesZeroRtt(data[payload_start..][0..pt_len], io);
                    return result.consumed;
                },
                else => return result.consumed, // ignore retry
            }
        }

        /// Returns the bytes we send as our SCID in long-header packets.
        /// RFC 9000 §7.2: server MUST use its own chosen connection ID, not echo the client's DCID.
        pub fn ourScidBytes(self: *const Self) []const u8 {
            return &self.local_cid.bytes;
        }

        // -----------------------------------------------------------------------
        // Packet-number tracking helpers (RFC 9000 §13.2)
        // -----------------------------------------------------------------------

        /// Returns true when `pn` in `epoch` has already been processed.
        /// Uses the 64-slot sliding-window bitmap; any PN more than 63 below the
        /// largest-received is conservatively treated as a duplicate (RFC 9000 §13.2.3).
        pub fn isPnDuplicate(self: *const Self, epoch: u8, pn: u64) bool {
            if (!self.hot.rx_pn_valid[epoch]) return false;
            const largest = self.hot.rx_pn[epoch];
            if (pn > largest) return false; // new packet, larger than anything seen
            const delta = largest - pn;
            if (delta >= 64) return true; // outside window → treat as duplicate
            return (self.rx_pn_bitmap[epoch] >> @as(u6, @intCast(delta))) & 1 == 1;
        }

        /// Record that `pn` in `epoch` was successfully decrypted and processed.
        /// Updates rx_pn[epoch] / rx_pn_valid[epoch] and the bitmap.
        pub fn markPnReceived(self: *Self, epoch: u8, pn: u64) void {
            if (!self.hot.rx_pn_valid[epoch]) {
                // First packet in this epoch.
                self.hot.rx_pn[epoch] = pn;
                self.hot.rx_pn_valid[epoch] = true;
                self.rx_pn_bitmap[epoch] = 1; // bit 0 = the largest (only) received PN
                return;
            }
            const largest = self.hot.rx_pn[epoch];
            if (pn > largest) {
                // New largest: left-shift the bitmap to make room, set bit 0.
                const shift = pn - largest;
                self.rx_pn_bitmap[epoch] = if (shift >= 64)
                    1
                else
                    (self.rx_pn_bitmap[epoch] << @as(u6, @intCast(shift))) | 1;
                self.hot.rx_pn[epoch] = pn;
            } else {
                // Out-of-order fill: mark the specific bit without changing largest.
                const delta = largest - pn;
                if (delta < 64) {
                    self.rx_pn_bitmap[epoch] |= @as(u64, 1) << @as(u6, @intCast(delta));
                }
                // delta >= 64: too old to track; isPnDuplicate already gates this path.
            }
        }

        /// Build ACK ranges from a received-packet sliding-window bitmap.
        ///
        /// `bitmap` — rx_pn_bitmap[epoch], bit 0 = largest received, bit i = largest−i.
        /// `out`    — output slice of at most 32 AckRange entries.
        ///
        /// Returns the number of entries filled.  The first entry carries the
        /// "First ACK Range" (RFC 9000 §19.3); subsequent entries carry the
        /// (gap, ack_range) pairs for additional blocks.
        ///
        /// Optimized with @ctz() (count trailing zeros) to skip runs of bits in O(#gaps)
        /// instead of O(64) bit-by-bit iterations. Typical ACK frame has 2-4 ranges,
        /// so this optimization reduces instruction count by ~30-50 cycles per ACK.
        pub fn buildAckRangesFromBitmap(bitmap: u64, out: *[32]frame.AckRange) usize {
            if (bitmap == 0) {
                // No packets received; output zero-length first ACK range.
                out[0] = .{ .gap = 0, .ack_range = 0 };
                return 1;
            }

            // FIRST RUN: Count leading 1s using @ctz(~bitmap).
            // @ctz(~bitmap) returns the position of the first 0 bit = length of the run.
            // Note: @ctz(u64) returns u7 (values 0-64), so cast to smaller type once validated.
            const first_run_raw: u7 = @ctz(~bitmap);
            const first_run: u62 = @as(u62, @intCast(first_run_raw));
            out[0] = .{ .gap = 0, .ack_range = if (first_run > 0) first_run - 1 else 0 };

            // If all bits are 1s (first_run == 64), we're done.
            if (first_run >= 64) return 1;

            var count: usize = 1;
            var remaining = bitmap >> @as(u6, @intCast(first_run)); // Skip the first run; bit position is now implicit.
            var bit: u62 = first_run;

            // SUBSEQUENT RUNS: alternately count 0s (gaps) and 1s (ack blocks).
            while (bit < 64 and count < 32 and remaining > 0) {
                // Count leading 0s: @ctz(remaining) = position of first 1.
                const gap_raw: u7 = @ctz(remaining);
                const gap: u62 = @as(u62, @intCast(gap_raw));

                // If the gap spans to the end of the 64-bit window, we're done.
                if (gap + bit >= 64) break;

                remaining >>= @as(u6, @intCast(gap));
                bit += gap;

                // Now remaining starts with a 1. Count the run of 1s.
                const run_raw: u7 = @ctz(~remaining);
                const run: u62 = @as(u62, @intCast(run_raw));
                if (run == 0) break; // Shouldn't happen, but safeguard.

                // RFC 9000 §19.3.1: Gap field encodes as (unacked_packets - 1).
                // @ctz counts leading 0s = number of unacked packets, so subtract 1.
                const gap_value: u62 = if (gap > 0) gap - 1 else 0;
                out[count] = .{ .gap = gap_value, .ack_range = run - 1 };
                count += 1;

                remaining >>= @as(u6, @intCast(run));
                bit += run;
            }

            return count;
        }

        pub fn processShortHeaderPacket(self: *Self, data: []u8) !usize {
            if (self.app_keys == null) return 0;

            // Reject packets larger than MAX_PACKET_SIZE (RFC 9000 compliance).
            if (data.len > MAX_PACKET_SIZE) return 0;

            // DCID in short headers = server's SCID = local_cid (always cid_mod.len bytes).
            const our_scid_len: usize = cid_mod.len;

            // Remove header protection in-place on the caller's buffer (zero copy).
            const pn_off = packet.shortHeaderPnOffset(our_scid_len);
            if (pn_off + 4 + 16 > data.len) {
                return 0;
            }
            _ = crypto.removeHeaderProtection(self.app_keys.?.client, &data[0], data[pn_off..][0..4], data[pn_off + 4 ..][0..16]);

            const result = try packet.parseShortHeader(data, our_scid_len);
            const hdr = result.header;
            const pn = packet.decodePacketNumber(
                self.hot.rx_pn[2],
                hdr.packet_number,
                @as(u8, hdr.pn_len) * 8,
            );
            // Replay / duplicate protection (RFC 9000 §13.2).
            if (self.isPnDuplicate(2, pn)) return result.consumed;
            const payload_start = result.consumed - hdr.payload.len;
            const payload_len = hdr.payload.len;
            // AAD = HP-removed header bytes (per RFC 9001 §5.3).
            const aad: []const u8 = data[0..payload_start];
            if (payload_len < 16) return result.consumed;
            const pt_len = payload_len - 16;
            if (pt_len > MAX_PACKET_SIZE) return result.consumed;

            // Save potential stateless reset token BEFORE in-place decrypt
            // (decrypt overwrites the buffer even on auth failure).
            var saved_tail: [16]u8 = undefined;
            if (data.len >= 21) @memcpy(&saved_tail, data[data.len - 16 ..][0..16]);

            // Mutable payload region for in-place decrypt.
            const payload = data[payload_start..][0..payload_len];

            // Key phase handling (RFC 9001 §6): different phase bit indicates key update.
            if (hdr.key_phase != self.current_key_phase) {
                // Peer initiated key update. Try next-generation keys first.
                var decrypted_with_next = false;
                if (self.next_app_keys) |nk| {
                    const ctx = self.cached_next_keys orelse crypto_simd.CachedKeyCtx.init(nk.client);
                    const nonce = crypto.buildNonce(nk.client.iv, pn);
                    if (crypto_simd.decryptCached(ctx, nonce, aad, payload)) |_| {
                        decrypted_with_next = true;
                    } else |_| {}
                }
                if (decrypted_with_next) {
                    self.rotateKeys();
                    self.key_update_pending = false;
                } else {
                    // Fallback: current keys (handles reordering during key transition).
                    const ctx = self.cached_app_keys orelse crypto_simd.CachedKeyCtx.init(self.app_keys.?.client);
                    const nonce = crypto.buildNonce(self.app_keys.?.client.iv, pn);
                    _ = crypto_simd.decryptCached(ctx, nonce, aad, payload) catch {
                        if (data.len >= 21 and self.checkStatelessResetToken(&saved_tail)) {
                            self.hot.state = .closed;
                            self.events.push(.{ .connection_closed = .{ .error_code = 0, .is_app = false } });
                        }
                        return data.len;
                    };
                }
            } else {
                // Same phase — HOT PATH. Cached key schedule, no branch on cipher suite.
                const ctx = self.cached_app_keys orelse crypto_simd.CachedKeyCtx.init(self.app_keys.?.client);
                const nonce = crypto.buildNonce(self.app_keys.?.client.iv, pn);
                _ = crypto_simd.decryptCached(ctx, nonce, aad, payload) catch {
                    if (data.len >= 21 and self.checkStatelessResetToken(&saved_tail)) {
                        self.hot.state = .closed;
                        self.events.push(.{ .connection_closed = .{ .error_code = 0, .is_app = false } });
                    }
                    return data.len;
                };
                self.key_update_pending = false;
            }

            // Record packet reception AFTER successful decryption AND key rotation
            self.markPnReceived(2, pn);
            self.bytes_recv += data.len;
            self.pkts_recv += 1;
            // Process frames from in-place decrypted plaintext (zero copy).
            self.processFrames(data[payload_start..][0..pt_len], 2, null) catch |err| {
                const code: u62 = switch (err) {
                    error.FlowControlViolation => 0x03,
                    error.StreamLimitError => 0x04,
                    error.StreamStateError => 0x05,
                    error.FrameEncodingError => 0x07,
                    else => 0x0a,
                };
                self.close(code, false, "") catch {};
            };
            return data.len;
        }

        /// RFC 9000 §10.3: check if the last 16 bytes of a received packet match any
        /// known peer stateless reset token.  Called after decryption failure to detect
        /// an incoming stateless reset.  Returns true if the connection should close.
        pub fn checkStatelessReset(self: *Self, raw_packet: []const u8) bool {
            // RFC 9000 §10.3: a stateless reset is at least 21 bytes
            // (1 fixed-bit header + 4 bytes min body + 16-byte token).
            if (raw_packet.len < 21) return false;
            return self.checkStatelessResetToken(raw_packet[raw_packet.len - 16 ..][0..16]);
        }

        /// Check a pre-saved 16-byte token against known peer stateless reset tokens.
        /// Used by in-place decrypt path where the original packet tail may be
        /// overwritten by AEAD — caller saves the token before decryption.
        fn checkStatelessResetToken(self: *Self, token: *const [16]u8) bool {
            for (&self.peer_cid_table) |*entry| {
                if (!entry.valid) continue;
                if (std.crypto.timing_safe.eql([16]u8, entry.reset_token, token.*)) return true;
            }
            return false;
        }

        /// Returns true when `f` is permitted inside a packet in the given epoch.
        /// RFC 9000 §12.4 Table 3:
        ///   epoch 0 (Initial) and epoch 1 (Handshake) allow only:
        ///     PADDING, PING, ACK, CRYPTO, CONNECTION_CLOSE (transport, 0x1c).
        ///   epoch 2 (1-RTT) allows all frame types.
        ///   0-RTT (is_zero_rtt=true): PADDING, PING, STREAM, CONNECTION_CLOSE (0x1c),
        ///     RESET_STREAM, STOP_SENDING, MAX_DATA, MAX_STREAM_DATA, MAX_STREAMS,
        ///     DATA_BLOCKED, STREAM_DATA_BLOCKED, STREAMS_BLOCKED, NEW_CONNECTION_ID.
        ///     Prohibited: ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN (RFC 9000 Table 3).
        ///
        /// RFC 9000 Table 3 column notation: I=Initial H=Handshake 0=0-RTT 1=1-RTT
        ///   CONNECTION_CLOSE (0x1c): IH01 — all epochs
        ///   CONNECTION_CLOSE (0x1d) / APPLICATION_CLOSE: __01 — 1-RTT only
        pub fn isFrameAllowedInEpoch(f: frame.Frame, epoch: u8, is_zero_rtt: bool) bool {
            if (is_zero_rtt) {
                // RFC 9000 Table 3: 0-RTT prohibits ACK, CRYPTO, HANDSHAKE_DONE, NEW_TOKEN.
                return switch (f) {
                    .ack, .crypto, .handshake_done, .new_token => false,
                    .connection_close => |cc| !cc.is_app, // only transport close (0x1c)
                    .padding,
                    .ping,
                    .stream,
                    .reset_stream,
                    .stop_sending,
                    .max_data,
                    .max_stream_data,
                    .max_streams_bidi,
                    .max_streams_uni,
                    .data_blocked,
                    .stream_data_blocked,
                    .streams_blocked_bidi,
                    .streams_blocked_uni,
                    .new_connection_id,
                    .retire_connection_id,
                    .path_challenge,
                    .path_response,
                    => true,
                };
            }
            return switch (f) {
                .padding, .ping, .ack, .crypto => true,
                // RFC 9000 Table 3: transport close (0x1c) is IH01; app close (0x1d) is __01.
                .connection_close => |cc| !cc.is_app or epoch == 2,
                else => epoch == 2,
            };
        }

        pub fn processFrames(self: *Self, plaintext: []const u8, epoch: u8, io: ?std.Io) !void {
            return self.processFramesInner(plaintext, epoch, io, false);
        }

        fn processFramesZeroRtt(self: *Self, plaintext: []const u8, io: ?std.Io) !void {
            return self.processFramesInner(plaintext, 2, io, true);
        }

        fn processFramesInner(self: *Self, plaintext: []const u8, epoch: u8, io: ?std.Io, is_zero_rtt: bool) !void {
            var pos: usize = 0;
            while (pos < plaintext.len) {
                // RFC 9000 §12.4: a malformed frame MUST trigger FRAME_ENCODING_ERROR.
                const fr = frame.parseFrame(plaintext[pos..]) catch {
                    return error.FrameEncodingError;
                };
                pos += fr.consumed;

                // RFC 9000 §12.4: reject frames not permitted in this epoch.
                if (!isFrameAllowedInEpoch(fr.frame, epoch, is_zero_rtt)) return error.ProtocolViolation;

                // RFC 9000 §19.19: all frames except PADDING and ACK are ack-eliciting.
                const is_ack_eliciting = switch (fr.frame) {
                    .padding, .ack => false,
                    else => true,
                };
                if (is_ack_eliciting) {
                    self.pending_ack[epoch] = true;
                }

                switch (fr.frame) {
                    .padding => {},
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
                            // RFC 9000 §4.2: flow control limits are monotonically increasing.
                            const new_max: u64 = f.max_data;
                            if (new_max > st.send_max) st.send_max = new_max;
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
                            // RFC 9000 §4.5: bytes promised by the sender (up to final_size)
                            // must be charged against the connection-level flow control window
                            // even if they were never received.  STREAM frames already charged
                            // processStreamFrame via highest_recv_offset; only charge the delta
                            // from the highest offset we've seen to the stream's final_size.
                            const prev_hwm = st.highest_recv_offset;
                            st.onResetReceived(rs.error_code, rs.final_size) catch {};
                            const final: u64 = rs.final_size;
                            if (final > prev_hwm) {
                                self.conn_flow.onReceived(final - prev_hwm);
                            }
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
                                self.path_validated = true;
                            }
                            // Mismatch: silently ignore (RFC 9000 §8.2.3).
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
                    // RFC 9000 §4.1: when the peer signals it is blocked on flow
                    // control, respond with updated credits on the next tick().
                    .data_blocked => self.pending_max_data = true,
                    .stream_data_blocked => |sdb| {
                        if (self.streams.get(sdb.stream_id)) |st| {
                            // Reset watermark so flushPendingMaxStreamData() sends
                            // a fresh MAX_STREAM_DATA frame on the next tick().
                            st.last_sent_max_stream_data = 0;
                        }
                    },
                    else => {},
                }
            }
        }

        pub fn processCryptoFrame(self: *Self, f: frame.CryptoFrame, epoch: u8, io: std.Io) !void {
            // RFC 9000 §19.6: validate CRYPTO frame offset to prevent TLS corruption.
            const expected = self.crypto_recv_offset[epoch];
            const end = @as(u64, f.offset) + @as(u64, f.data.len);

            // Pure duplicate: already processed all bytes in this frame → skip.
            if (end <= expected) return;

            // Out-of-order: stage for later delivery when its predecessor arrives.
            if (@as(u64, f.offset) > expected) {
                try self.stageCryptoFrag(epoch, @as(u64, f.offset), f.data);
                return;
            }

            // Partial overlap: trim leading bytes already delivered.
            const trim = expected - @as(u64, f.offset);
            const effective_data = f.data[trim..];

            // In-order delivery: feed to TLS, then drain any buffered staging.
            try self.deliverCryptoChunk(epoch, effective_data, io);
            try self.drainStagedCrypto(epoch, io);
        }

        /// Buffer a CRYPTO fragment that arrived out of order.
        /// DoS defense: silently drop fragments if staging exceeds 16KB per epoch.
        pub fn stageCryptoFrag(self: *Self, epoch: u8, offset: u64, data: []const u8) !void {
            const count = self.crypto_staged_count[epoch];
            if (count >= CRYPTO_STAGE_DEPTH) return; // staging full; peer will retransmit

            const copy_len: u16 = @intCast(@min(data.len, CRYPTO_STAGE_FRAG));

            // DoS defense: enforce 16KB byte limit per epoch to prevent memory pinning.
            // If adding this fragment would exceed 16KB, silently drop (peer will retransmit).
            const CRYPTO_STAGED_BYTES_LIMIT = 16_384;
            if (self.crypto_staged_bytes[epoch] +| copy_len > CRYPTO_STAGED_BYTES_LIMIT) {
                return; // Limit exceeded; drop and let peer retransmit
            }

            self.crypto_staged[epoch][count] = .{
                .offset = offset,
                .len = copy_len,
            };
            @memcpy(self.crypto_staged[epoch][count].data[0..copy_len], data[0..copy_len]);
            self.crypto_staged_count[epoch] = count + 1;

            self.crypto_staged_bytes[epoch] +|= copy_len;
        }

        /// Drain staged fragments that are now deliverable (in-order).
        fn drainStagedCrypto(self: *Self, epoch: u8, io: std.Io) !void {
            while (true) {
                const expected = self.crypto_recv_offset[epoch];
                const count = self.crypto_staged_count[epoch];
                // Find a staged fragment that overlaps or starts at expected.
                var found: usize = count;
                for (0..count) |i| {
                    const frag = &self.crypto_staged[epoch][i];
                    const frag_end = frag.offset + frag.len;
                    if (frag_end > expected and frag.offset <= expected) {
                        found = i;
                        break;
                    }
                }
                if (found == count) break;

                const frag = self.crypto_staged[epoch][found];
                // Remove from staging array.
                if (found < count - 1) {
                    std.mem.copyForwards(
                        CryptoStagedFrag,
                        self.crypto_staged[epoch][found .. count - 1],
                        self.crypto_staged[epoch][found + 1 .. count],
                    );
                }
                self.crypto_staged_count[epoch] = count - 1;

                // Decrement byte counter for drained fragment
                self.crypto_staged_bytes[epoch] -|= frag.len;

                // Trim leading overlap and deliver.
                const t: u64 = if (frag.offset < expected) expected - frag.offset else 0;
                const d = frag.data[@intCast(t)..frag.len];
                if (d.len > 0) try self.deliverCryptoChunk(epoch, d, io);
            }
        }

        /// Feed one contiguous in-order chunk to the TLS state machine and handle its output.
        fn deliverCryptoChunk(self: *Self, epoch: u8, data: []const u8, io: std.Io) !void {
            self.crypto_recv_offset[epoch] += data.len;

            // Before processing ClientHello, configure transport parameters for EncryptedExtensions.
            if (self.tls_state.state == .wait_client_hello) {
                var our_params = transport_params.TransportParams{
                    .initial_max_streams_bidi = self.local_max_streams_bidi,
                    .initial_max_streams_uni = self.local_max_streams_uni,
                };
                // initial_source_connection_id MUST equal the SCID we sent in our Initial packet
                // (RFC 9000 §7.3). Our wire SCID is ourScidBytes() = local_cid.bytes.
                const scid_bytes = self.ourScidBytes();
                var isci: [20]u8 = [_]u8{0} ** 20;
                @memcpy(isci[0..scid_bytes.len], scid_bytes);
                our_params.initial_source_connection_id = isci;
                our_params.initial_source_connection_id_len = @intCast(scid_bytes.len);
                if (self.original_dcid) |dcid| {
                    our_params.original_destination_connection_id = dcid;
                    our_params.original_destination_connection_id_len = self.original_dcid_len;
                    if (self.retry_scid) |scid| {
                        our_params.retry_source_connection_id = scid;
                    }
                } else if (self.first_initial_dcid_len > 0) {
                    our_params.original_destination_connection_id = self.first_initial_dcid;
                    our_params.original_destination_connection_id_len = self.first_initial_dcid_len;
                }

                // RFC 9369: version_information - advertise supported versions
                // Server always supports V1, optionally V2 if configured
                if (self.config.initial_quic_version == packet.QUIC_VERSION_2) {
                    // Server supports both V1 and V2: advertise in version_information
                    // List chosen version (V2) first, then alternatives
                    var vi: [20]u8 = undefined;
                    std.mem.writeInt(u32, vi[0..4], packet.QUIC_VERSION_2, .big);
                    std.mem.writeInt(u32, vi[4..8], packet.QUIC_VERSION_1, .big);
                    our_params.version_information = vi;
                    our_params.version_information_len = 8; // 2 versions * 4 bytes each
                } else {
                    // Server only supports V1 (default)
                    // RFC 9369 requires version_information for servers supporting V2.
                    // V1-only servers can omit it.
                    our_params.version_information = null;
                }

                // RFC 9000 §18.2.3: advertise preferred_address if configured.
                // Advertise both IPv4 and IPv6 preferred addresses so that the client
                // can migrate to whichever address family it is not currently using.
                if (self.config.preferred_addr_ipv4) |ipv4| {
                    var pa_cid: [20]u8 = [_]u8{0} ** 20;
                    const pa_cid_len = self.alt_local_cid.bytes.len;
                    @memcpy(pa_cid[0..pa_cid_len], &self.alt_local_cid.bytes);
                    our_params.preferred_address = transport_params.PreferredAddress{
                        .ipv4_addr = ipv4,
                        .ipv4_port = self.config.preferred_addr_ipv4_port,
                        .ipv6_addr = self.config.preferred_addr_ipv6,
                        .ipv6_port = self.config.preferred_addr_ipv6_port,
                        .cid = pa_cid,
                        .cid_len = @intCast(pa_cid_len),
                        .reset_token = self.alt_local_reset_token,
                    };
                }

                self.tls_state.our_transport_params = our_params;
            }

            // Push client's Initial version into TLS as baseline BEFORE processing ClientHello.
            // TLS may upgrade it to server_configured_version via version_information (RFC 9369).
            // Guard ensures this only fires on ClientHello call, not again on ClientFinished.
            if (self.tls_state.state == .wait_client_hello) {
                self.tls_state.quic_version = self.quic_version;
                self.tls_state.current_time_ns = self.current_time_ns;
            }

            var out_buf: [32768]u8 = undefined;
            const out_len = try self.tls_state.processCrypto(data, &out_buf, io);

            if (self.hs_keys == null and self.tls_state.state != .wait_client_hello) {
                // Adopt whatever version TLS negotiated (V1 unchanged, or V2 if version_info matched).
                self.quic_version = self.tls_state.quic_version;
                self.hs_keys = self.tls_state.handshake_keys;

                // If TLS accepted 0-RTT, derive 0-RTT decryption keys from client_early_traffic_secret.
                if (self.tls_state.accept_early_data) {
                    self.zero_rtt_keys = crypto.derivePacketKeysWithSuite(
                        self.tls_state.client_early_traffic_secret,
                        self.quic_version,
                        self.tls_state.negotiated_cipher,
                    );
                    self.accepting_early_data = true;
                }
            }

            if (out_len > 0) {
                try self.queueTlsOutput(out_buf[0..out_len]);
            }

            if (self.tls_state.isComplete()) {
                self.app_keys = self.tls_state.app_keys;
                // Cache key schedule for the hot path (both AES and ChaCha20).
                self.cached_app_keys = crypto_simd.CachedKeyCtx.init(self.tls_state.app_keys.client);
                self.hot.state = .established;
                // Defense-in-depth: zero initial keys after transition to 1-RTT (no longer needed)
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(crypto.InitialKeys)]u8, @ptrCast(&self.initial_keys)));
                // Discard any queued CRYPTO retransmits — they used handshake-epoch keys that
                // the peer will discard once 1-RTT keys are established (RFC 9001 §4.9).
                // Keeping them would cause stale CRYPTO sends on every tick and block the PTO
                // handler from sending PING probes or stream retransmits post-handshake.
                self.crypto_pending_retx_count = 0;
                self.path_validated = true;
                self.events.push(.connected);

                self.next_client_secret = crypto.deriveNextAppSecret(self.tls_state.client_app_secret, self.quic_version);
                self.next_server_secret = crypto.deriveNextAppSecret(self.tls_state.server_app_secret, self.quic_version);
                self.next_app_keys = tls.AppKeys{
                    .client = crypto.derivePacketKeysWithSuite(self.next_client_secret, self.quic_version, self.tls_state.negotiated_cipher),
                    .server = crypto.derivePacketKeysWithSuite(self.next_server_secret, self.quic_version, self.tls_state.negotiated_cipher),
                };
                // RFC 9001 §6.1: header protection key does not change with key updates.
                // Override the derived hp fields with the gen-0 hp from the active keys.
                if (self.app_keys) |cur| {
                    self.next_app_keys.?.client.hp = cur.client.hp;
                    self.next_app_keys.?.server.hp = cur.server.hp;
                }
                // Cache next-gen key schedule for fast key-update decrypt.
                self.cached_next_keys = crypto_simd.CachedKeyCtx.init(self.next_app_keys.?.client);

                const params = self.tls_state.peerTransportParams();
                self.conn_flow.updateSendMax(params.initial_max_data);
                self.cached_max_ack_delay_ns = params.max_ack_delay_ms * 1_000_000;
                self.cached_ack_delay_exp = @intCast(@min(params.ack_delay_exponent, 20));
                self.peer_max_stream_data_bidi_local = params.initial_max_stream_data_bidi_local;

                const bidi_limit = @min(params.initial_max_streams_bidi, @as(u64, std.math.maxInt(u62)));
                const uni_limit = @min(params.initial_max_streams_uni, @as(u64, std.math.maxInt(u62)));
                self.peer_max_streams_bidi = @intCast(bidi_limit);
                self.peer_max_streams_uni = @intCast(uni_limit);

                self.peer_disable_migration = params.disable_active_migration;

                // 0-RTT acceptance phase is over once handshake completes.
                self.accepting_early_data = false;

                // Schedule NewSessionTicket if ticket_key is configured.
                if (self.config.ticket_key != null) {
                    self.pending_new_session_ticket = true;
                }

                try self.queueHandshakeDone();
            }
        }

        pub fn processStreamFrame(self: *Self, f: frame.StreamFrame) !void {
            // RFC 9000 §12.4: STREAM frames are only valid in 1-RTT (established) state.
            // Exception: allow STREAM in handshake state when accepting 0-RTT data.
            if (self.hot.state != .established and !self.accepting_early_data) return error.ProtocolViolation;
            // Server must only receive client-initiated streams (bit 0 = 0).
            if (f.stream_id & 1 != 0) return error.StreamStateError;
            // RFC 9000 §4.6: reject streams that exceed the advertised stream limit.
            const stream_num = f.stream_id >> 2;
            if ((f.stream_id >> 1) & 1 == 0) {
                // Client-initiated bidirectional (type bits = 0b00)
                if (stream_num >= self.local_max_streams_bidi) return error.StreamLimitError;
            } else {
                // Client-initiated unidirectional (type bits = 0b10)
                if (stream_num >= self.local_max_streams_uni) return error.StreamLimitError;
            }
            // RFC 9000 §4.1: connection-level flow control tracks the sum of per-stream
            // high-water marks, not raw bytes per frame. Only charge for bytes that advance
            // the stream's highest received offset (retransmissions cost nothing).
            const new_end = std.math.add(u64, f.offset, f.data.len) catch return error.OffsetOverflow;
            const existing_st = self.streams.get(f.stream_id);
            const old_hwm: u64 = if (existing_st) |est| est.highest_recv_offset else 0;
            const fc_delta: u64 = if (new_end > old_hwm) new_end - old_hwm else 0;
            if (!self.conn_flow.canReceive(fc_delta)) return error.FlowControlViolation;
            const is_new = existing_st == null;
            const st = self.streams.getOrCreate(f.stream_id) orelse return error.TooManyStreams;
            // Apply the peer's per-stream send limit on first access (RFC 9000 §7.3).
            // Stream.init() defaults send_max to STREAM_BUF_SIZE; override with the negotiated value
            // so the server is not artificially throttled below the peer's advertised window.
            // Only applies to bidirectional streams (bit 1 == 0) since we don't send on remote-initiated uni.
            if (is_new and (f.stream_id >> 1) & 1 == 0) {
                st.send_max = self.peer_max_stream_data_bidi_local;
            }
            // Inline borrow: if data is in-order (offset == recv_offset) and there's
            // no existing inline borrow, skip the ring buffer entirely.  The app gets
            // a direct slice into the recv buffer — zero copies.
            // Falls back to ring buffer for out-of-order or when inline is already active.
            const is_in_order = f.offset == st.recv_offset and st.inline_recv == null;
            if (is_in_order and f.data.len > 0 and !f.fin) {
                // Fast path: borrow the slice, skip receiveData entirely.
                // The data lives in the caller's recv buffer until next receive().
                self.conn_flow.onReceived(fc_delta);
                if (new_end > old_hwm) st.highest_recv_offset = new_end;
                st.recv_offset += f.data.len;
                st.inline_recv = f.data;
                self.inline_borrow_stream = f.stream_id;
                // Update gap list to reflect the received range.
                st.gap_list.fill(f.offset, f.data.len);
            } else {
                // Slow path: out-of-order, FIN, or inline already active → ring buffer.
                try st.receiveData(f.offset, f.data, f.fin);
                self.conn_flow.onReceived(fc_delta);
                if (new_end > old_hwm) st.highest_recv_offset = new_end;
            }
            // Grow connection receive window when 75% consumed (RFC 9000 §4.2).
            if (self.conn_flow.shouldSendMaxData()) {
                self.conn_flow.recv_max = self.conn_flow.nextMaxData();
                self.pending_max_data = true;
            }
            self.events.push(.{ .stream_data = .{ .stream_id = f.stream_id } });
        }

        pub fn processAck(self: *Self, ack: frame.AckFrame, epoch: u8) !void {
            // RFC 9000 §19.3.1: acknowledging a packet that has not yet been sent is
            // a connection error of type PROTOCOL_VIOLATION.
            if (@as(u64, ack.largest_acked) >= self.hot.tx_pn[epoch]) return error.ProtocolViolation;
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
                    // RFC 9000 §19.3.1: Gap field = (unacked_count - 1), so:
                    // next_high = prev_low - 1 - (gap_val + 1) = prev_low - 2 - gap_val
                    if (low < gap_val + 2) return error.InvalidFrame; // malformed: would underflow
                    high = low - 2 - gap_val;
                }
            }

            // ack_delay field is in units of 2^ack_delay_exponent µs; convert to ns.
            // Cap before multiplying: ack_delay is a peer-supplied u62 and
            // ack_delay_exp reaches 20, so the raw product can overflow u64.
            // Any delay that saturates u64 is effectively infinite — safe to clamp.
            const ack_delay_shift: u64 = @as(u64, 1) << self.cached_ack_delay_exp;
            const ack_delay_max_units: u64 = std.math.maxInt(u64) / (ack_delay_shift * 1000);
            const ack_delay_ns: u64 = @min(@as(u64, ack.ack_delay), ack_delay_max_units) *
                ack_delay_shift * 1000;
            const result = self.loss.onAckReceived(
                @as(u64, ack.largest_acked),
                ack_delay_ns,
                ranges_buf[0..range_count],
                epoch,
                self.current_time_ns,
                max_ack_delay_ns,
            );

            // PMTUD: detect if a probe was successfully ACKed.
            // Loss detection relies on 3×PTO timeout in tick(), which is safer than inferring from largest_acked.
            if (self.pmtud_probing) |probe| {
                for (ranges_buf[0..range_count]) |range| {
                    if (probe.packet_number >= range.low and probe.packet_number <= range.high) {
                        // Probe was ACKed! Increase path_mtu for next probe.
                        self.path_mtu = probe.target_size;
                        self.pmtud_probing = null;
                        self.pmtud_next_probe_ns = self.current_time_ns + 10_000_000_000; // probe next size in 10s
                        break;
                    }
                }
            }

            // Feed acknowledgement data to congestion controller
            if (result.newly_acked > 0) {
                self.congestion.onAckReceived(
                    result.delivery_rate_sample,
                    self.current_time_ns,
                );
                self.loss.resetPtoCount();
            }

            // One congestion event per loss detection (RFC 9438 §5.6)
            if (result.newly_lost > 0) {
                self.congestion.onPacketLost(result.bytes_lost, self.current_time_ns);
            }

            // Persistent congestion: collapse cwnd when loss span > 3×PTO (RFC 9002 §6.1.2)
            if (result.persistent_congestion) {
                self.congestion.onPersistentCongestion();
            }

            // ECN: react to CE mark increases (RFC 9002 §B.1).
            // A rising CE count means the network is signalling congestion without drops.
            if (ack.has_ecn) {
                const ce: u62 = @intCast(@min(ack.ecn_ce, std.math.maxInt(u62)));
                if (ce > self.ecn_ce_seen[epoch]) {
                    const ce_delta = ce - self.ecn_ce_seen[epoch];
                    self.ecn_ce_seen[epoch] = ce;
                    if (result.largest_acked_sent_ns) |_| {
                        self.congestion.onEcnCe(ce_delta, self.current_time_ns);
                    }
                }
            }

            // Process lost frames before acked frames: retransmit while streams are
            // still alive, then close streams whose FIN was acknowledged. Without this
            // ordering, processAckedFrames would free a stream slot (on FIN ACK) before
            // processLostFrames could retransmit an earlier lost data packet for that stream.
            self.processLostFrames(result);
            self.processAckedFrames(result);

            // Refresh PTO timer and time-loss alarm after any ACK.
            self.pto_deadline_ns = self.loss.ptoDeadline(max_ack_delay_ns);
            // With wire-time accounting, retransmissions queued by processLostFrames
            // are in bytes_queued (not bytes_in_flight).  ptoDeadline returns null
            // when bytes_in_flight == 0.  Force-arm PTO when queued data exists so
            // the server doesn't go silent while pacing drains retransmissions.
            if (self.pto_deadline_ns == null and self.bytes_queued > 0) {
                const pto_base = self.loss.rtt.ptoBase(max_ack_delay_ns);
                const max_i64: u64 = @as(u64, std.math.maxInt(i64));
                self.pto_deadline_ns = self.current_time_ns +| @as(i64, @intCast(@min(pto_base, max_i64)));
            }
            // RFC 9002 §6.2.2.1: server MUST keep PTO armed during handshake even
            // when bytes_in_flight == 0.  The peer may have ACKed our Handshake CRYPTO
            // at the QUIC level but not yet processed it at the TLS level (e.g. gaps in
            // the CRYPTO stream).  Without PTO the server stops retransmitting and the
            // handshake deadlocks.
            if (self.pto_deadline_ns == null and self.app_keys == null and
                self.hot.state != .idle and self.hot.state != .closed)
            {
                const pto = self.loss.rtt.ptoBase(max_ack_delay_ns);
                const shift: u6 = @intCast(@min(self.loss.pto_count, 5));
                const backoff: u64 = pto *| (@as(u64, 1) << shift);
                const max_i64: u64 = @as(u64, std.math.maxInt(i64));
                self.pto_deadline_ns = self.current_time_ns +| @as(i64, @intCast(@min(backoff, max_i64)));
            }
            self.time_loss_alarm_ns = self.loss.timeLossAlarmNs(max_ack_delay_ns);
        }

        // -----------------------------------------------------------------------
        // Retransmission helpers (Step 4)
        // -----------------------------------------------------------------------

        pub fn processAckedFrames(self: *Self, result: loss_recovery_mod.AckResult) void {
            for (result.acked_frames[0..result.acked_frame_count]) |fi| {
                for (fi.frames[0..fi.count]) |frame_info| {
                    switch (frame_info) {
                        .stream => |s| {
                            if (self.streams.get(s.stream_id)) |st| {
                                st.onAcked(s.offset, s.len);
                                if (s.fin) st.fin_acked = true;
                                // Close the stream slot only when BOTH the FIN and all data
                                // bytes have been acknowledged. Closing on FIN ACK alone is
                                // premature when a data packet was lost: the FIN can be ACK'd
                                // before loss detection fires for the earlier data packet.
                                // If we free the slot then, streams.get() returns null in
                                // processLostFrames and the lost data is never retransmitted.
                                if (st.fin_acked and st.state == .closed and st.send_acked >= st.send_offset) {
                                    self.streams.close(s.stream_id);
                                    // Increment local stream limit as slots become available (RFC 9000 §4.6)
                                    const is_bidi = (s.stream_id & 2) == 0;
                                    if (is_bidi) {
                                        self.local_max_streams_bidi +|= 1;
                                        self.pending_max_streams_bidi = self.local_max_streams_bidi;
                                    } else {
                                        self.local_max_streams_uni +|= 1;
                                        self.pending_max_streams_uni = self.local_max_streams_uni;
                                    }
                                }
                            }
                        },
                        else => {},
                    }
                }
            }
        }

        pub fn processLostFrames(self: *Self, result: loss_recovery_mod.AckResult) void {
            // Sized to MAX_SEND_PACKET_SIZE so getSendData never returns more bytes than
            // encryptAndEnqueueStreamFrame can encode into pkt_scratch without overflow.
            var stream_retx_buf: [MAX_SEND_PACKET_SIZE]u8 = undefined;
            for (result.lost_frames[0..result.lost_frame_count], result.lost_epochs[0..result.lost_frame_count]) |fi, epoch| {
                for (fi.frames[0..fi.count]) |frame_info| {
                    switch (frame_info) {
                        .stream => |s| {
                            if (self.streams.get(s.stream_id)) |st| {
                                // Cap read to the original frame length to avoid encoding
                                // more than was originally sent (getSendData may return
                                // adjacent buffered data beyond the lost frame boundary).
                                const n = @min(st.getSendData(s.offset, &stream_retx_buf), s.len);
                                if (n > 0 or s.fin) {
                                    self.encryptAndEnqueueStreamFrame(
                                        s.stream_id,
                                        s.offset,
                                        stream_retx_buf[0..n],
                                        s.fin,
                                    ) catch {
                                        // Send queue full — defer for retry in drainPendingStreamRetx()
                                        if (self.stream_pending_retx_count < MAX_PENDING_RETX) {
                                            self.stream_pending_retx[self.stream_pending_retx_count] = .{
                                                .stream_id = s.stream_id,
                                                .offset = s.offset,
                                                .len = @intCast(n),
                                                .fin = s.fin,
                                            };
                                            self.stream_pending_retx_count += 1;
                                        }
                                    };
                                }
                            }
                        },
                        .handshake_done => {
                            self.pending_handshake_done = true;
                        },
                        .max_data => {
                            self.pending_max_data = true;
                        },
                        .max_streams_bidi => |max_bidi| {
                            self.pending_max_streams_bidi = max_bidi;
                        },
                        .max_streams_uni => |max_uni| {
                            self.pending_max_streams_uni = max_uni;
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
                        .crypto_frame => |cf| {
                            // Queue lost CRYPTO frame for immediate retransmission.
                            if (self.crypto_pending_retx_count < MAX_PENDING_RETX) {
                                self.crypto_pending_retx[self.crypto_pending_retx_count] = .{
                                    .epoch = epoch,
                                    .offset = cf.offset,
                                    .len = cf.len,
                                };
                                self.crypto_pending_retx_count += 1;
                            }
                        },
                        .max_stream_data, .none => {},
                    }
                }
            }
        }

        fn drainPendingStreamRetx(self: *Self) void {
            if (self.stream_pending_retx_count == 0) return;
            var stream_retx_buf: [MAX_SEND_PACKET_SIZE]u8 = undefined;
            var remaining: u8 = 0;
            for (self.stream_pending_retx[0..self.stream_pending_retx_count]) |p| {
                // Try to get the stream; if not found, stream is closed so discard
                const st = self.streams.get(p.stream_id) orelse {
                    continue;
                };
                const n = @min(st.getSendData(p.offset, &stream_retx_buf), p.len);
                // Check if data is already acked (offset < send_acked); if so, safe to discard
                if (p.offset < st.send_acked) {
                    // Already acked — discard this retransmit
                    continue;
                }
                // Only attempt send if we have data or a FIN bit
                if (n > 0 or p.fin) {
                    self.encryptAndEnqueueStreamFrame(p.stream_id, p.offset, stream_retx_buf[0..n], p.fin) catch {
                        // Send queue full — keep in queue and retry later
                        self.stream_pending_retx[remaining] = p;
                        remaining += 1;
                        continue;
                    };
                } else {
                    // No data available and not already acked — keep retrying
                    self.stream_pending_retx[remaining] = p;
                    remaining += 1;
                }
            }
            self.stream_pending_retx_count = remaining;
        }

        /// PTO probe: scan sent table for the oldest unacked 1-RTT packet with stream data
        /// and retransmit it. Returns true if a probe was sent. RFC 9002 §6.2 recommends
        /// including ack-eliciting data in PTO probes rather than just PING.
        fn probeUnackedStreamData(self: *Self) bool {
            var stream_retx_buf: [MAX_SEND_PACKET_SIZE]u8 = undefined;
            const table = &self.loss.sent;
            const to_find = table.valid_per_epoch[2]; // 1-RTT epoch
            if (to_find == 0) return false;
            var found: u16 = 0;
            // Find the oldest valid 1-RTT packet with stream frame info.
            var best_pn: u64 = std.math.maxInt(u64);
            var best_idx: ?usize = null;
            for (table.slots, 0..) |slot, idx| {
                if (found >= to_find) break;
                if (!slot.valid or slot.epoch != 2) continue;
                found += 1;
                if (slot.in_flight and slot.pn < best_pn) {
                    // Check if this packet carried stream data.
                    const fi = table.frame_info[idx];
                    for (fi.frames[0..fi.count]) |frame_info| {
                        switch (frame_info) {
                            .stream => {
                                best_pn = slot.pn;
                                best_idx = idx;
                                break;
                            },
                            else => {},
                        }
                    }
                }
            }
            const idx = best_idx orelse return false;
            const fi = table.frame_info[idx];
            for (fi.frames[0..fi.count]) |frame_info| {
                switch (frame_info) {
                    .stream => |s| {
                        const st = self.streams.get(s.stream_id) orelse continue;
                        if (s.offset < st.send_acked) continue;
                        const n = @min(st.getSendData(s.offset, &stream_retx_buf), s.len);
                        if (n > 0 or s.fin) {
                            self.encryptAndEnqueueStreamFrame(s.stream_id, s.offset, stream_retx_buf[0..n], s.fin) catch return false;
                            return true;
                        }
                    },
                    else => {},
                }
            }
            return false;
        }

        pub fn drainPendingCryptoRetx(self: *Self) void {
            if (self.crypto_pending_retx_count == 0) return;
            const max_chunk = MAX_SEND_PACKET_SIZE - 100;
            var remaining: u8 = 0;
            for (self.crypto_pending_retx[0..self.crypto_pending_retx_count]) |p| {
                const epoch = p.epoch;
                // Only retransmit Initial (0) and Handshake (1) CRYPTO.
                // Epoch 2 CRYPTO (e.g. NewSessionTicket) is not saved for retransmission.
                if (epoch >= 2) continue;
                const data_len = self.crypto_send_saved_len[epoch];
                const offset = p.offset;
                const len = p.len;

                // Skip if data is no longer available (already acked/sent completely)
                if (offset >= data_len) continue;

                // Get the chunk from the saved buffer
                const available = data_len - offset;
                const chunk_len = @min(len, @min(available, max_chunk));
                const chunk = self.crypto_send_saved[epoch][offset..][0..chunk_len];

                // Build and send CRYPTO frame for this lost chunk
                const crypto_frame_val: frame.Frame = .{ .crypto = .{ .offset = @intCast(offset), .data = chunk } };
                var fpos: usize = 0;
                fpos += frame.encodeFrame(self.pkt_scratch[fpos..], crypto_frame_val);

                // Send using the appropriate epoch's keys
                const result = if (epoch == 0)
                    self.sendCryptoChunkEpoch0(chunk, offset, fpos)
                else
                    self.sendCryptoChunkEpoch1(chunk, offset, fpos);

                result catch {
                    // Send queue full — keep in queue and retry later
                    self.crypto_pending_retx[remaining] = p;
                    remaining += 1;
                    continue;
                };

                // Successfully sent chunk_len bytes. If more remains, queue the next chunk.
                if (chunk_len < len) {
                    if (remaining < MAX_PENDING_RETX) {
                        self.crypto_pending_retx[remaining] = .{
                            .epoch = epoch,
                            .offset = offset + chunk_len,
                            .len = len - chunk_len,
                        };
                        remaining += 1;
                    }
                }
            }
            self.crypto_pending_retx_count = remaining;
        }

        fn sendCryptoChunkEpoch0(self: *Self, chunk: []const u8, offset: u62, fpos: usize) !void {
            const packet_version = self.quic_version;
            const ik = if (packet_version == packet.QUIC_VERSION_2)
                crypto.deriveInitialKeys(self.first_initial_dcid[0..self.first_initial_dcid_len], packet.QUIC_VERSION_2).server
            else
                self.initial_keys.server;
            const pn = self.hot.tx_pn[0];
            self.hot.tx_pn[0] += 1;
            const ct_len = fpos + 16;
            const hdr_len = packet.encodeLongHeader(
                &self.enc_scratch,
                .initial,
                packet_version,
                self.peer_scid[0..self.peer_scid_len],
                self.ourScidBytes(),
                &.{},
                @intCast(pn),
                ct_len,
            );
            if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) {
                self.hot.tx_pn[0] -= 1;
                return error.PacketTooLarge;
            }
            crypto.encryptPayload(ik, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
            crypto.applyHeaderProtection(ik, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
            try self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]);
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .crypto_frame = .{ .offset = @intCast(offset), .len = @intCast(chunk.len) } };
            fi.count = 1;
            self.storeSendMeta(pn, 0, hdr_len + ct_len, true, fi);
        }

        fn sendCryptoChunkEpoch1(self: *Self, chunk: []const u8, offset: u62, fpos: usize) !void {
            const hk = self.hs_keys orelse return error.NoHandshakeKeys;
            const pn = self.hot.tx_pn[1];
            self.hot.tx_pn[1] += 1;
            const ct_len = fpos + 16;
            const hdr_len = packet.encodeLongHeader(
                &self.enc_scratch,
                .handshake,
                self.quic_version,
                self.peer_scid[0..self.peer_scid_len],
                self.ourScidBytes(),
                &.{},
                @intCast(pn),
                ct_len,
            );
            if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) {
                self.hot.tx_pn[1] -= 1;
                return error.PacketTooLarge;
            }
            crypto.encryptPayload(hk.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
            crypto.applyHeaderProtection(hk.server, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
            try self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]);
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .crypto_frame = .{ .offset = @intCast(offset), .len = @intCast(chunk.len) } };
            fi.count = 1;
            self.storeSendMeta(pn, 1, hdr_len + ct_len, true, fi);
        }

        // -----------------------------------------------------------------------
        // Send queue helpers
        // -----------------------------------------------------------------------

        pub fn enqueueSend(self: *Self, data: []const u8) !void {
            // Use monotonic head/tail subtraction (not modular comparison) to correctly
            // detect full queue regardless of wrap-around.
            if (self.sq_tail - self.sq_head >= SEND_QUEUE_DEPTH) return error.SendQueueFull;

            // RFC 9000 §10.1.2: restart idle timer when sending a packet.
            if (self.idle_timeout_i64 > 0) {
                self.idle_deadline_ns = self.current_time_ns +| self.idle_timeout_i64;
            }

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
            const n = @min(data.len, MAX_SEND_PACKET_SIZE);
            @memcpy(slot.buf[0..n], data[0..n]);
            slot.len = n;
            self.sq_tail += 1;
        }

        /// Send an encrypted ACK frame for the given epoch.
        /// epoch 0 = Initial (long header, initial_keys.server)
        /// epoch 1 = Handshake (long header, hs_keys.?.server)
        /// epoch 2 = 1-RTT (short header, app_keys.?.server)
        /// ACK frames are not ack-eliciting (RFC 9002 §2), so ack_eliciting=false.
        pub fn sendEncryptedAck(self: *Self, epoch: u8) !void {
            // RFC 9000 §13.2: only send ACKs if we've actually received packets in this epoch.
            if (!self.hot.rx_pn_valid[epoch]) {
                return;
            }

            var fpos: usize = 0;
            // Build ACK ranges from the received-packet bitmap so that the peer can
            // precisely identify which packets we have (and have not) received.  This
            // is required by RFC 9000 §13.2: an endpoint MUST send ACK frames that
            // cover all ack-eliciting packets it has received.
            var ack_ranges: [32]frame.AckRange = undefined;
            const ack_range_count = buildAckRangesFromBitmap(self.rx_pn_bitmap[epoch], &ack_ranges);

            // Include ACK-ECN frame with actual ECN counts received from peer (RFC 9000 §13.2.1).
            // ecn_ect0_recv and ecn_ce_recv are populated by receive() based on ecn_bits parameter.
            const ack_frame_data: frame.Frame = .{
                .ack = .{
                    .largest_acked = @intCast(self.hot.rx_pn[epoch]),
                    .ack_delay = 0,
                    .ranges = ack_ranges,
                    .range_count = ack_range_count,
                    .ect0 = @intCast(@min(self.ecn_ect0_recv[epoch], std.math.maxInt(u62))),
                    .ect1 = 0, // We don't track ECT(1), only ECT(0)
                    .ecn_ce = @intCast(@min(self.ecn_ce_recv[epoch], std.math.maxInt(u62))),
                    .has_ecn = true,
                },
            };
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], ack_frame_data);

            switch (epoch) {
                0 => {
                    // Initial packet: Long Header, epoch 0 keys
                    // RFC 9369: If configured for V2, respond with V2 Initial and V2 keys.
                    // Re-derive V2 keys if needed; otherwise use V1 keys derived earlier.
                    const packet_version = self.quic_version; // V2 if configured, V1 otherwise
                    const ik = if (packet_version == packet.QUIC_VERSION_2)
                        crypto.deriveInitialKeys(self.first_initial_dcid[0..self.first_initial_dcid_len], packet.QUIC_VERSION_2).server
                    else
                        self.initial_keys.server;
                    const pn = self.hot.tx_pn[0];
                    self.hot.tx_pn[0] += 1;
                    const ct_len = fpos + 16;
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .initial,
                        packet_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len, // payload_len = ciphertext + AEAD tag (RFC 9000 §17.2)
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) return error.PacketTooLarge;
                    crypto.encryptPayload(ik, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(ik, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    try self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]);
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.count = 0; // ACK is not ack-eliciting; no frame info tracked
                    self.storeSendMeta(pn, 0, hdr_len + ct_len, false, fi);
                },
                1 => {
                    // Handshake packet: Long Header, handshake keys
                    if (self.hs_keys == null) return;
                    const hk = self.hs_keys.?.server;
                    const pn = self.hot.tx_pn[1];
                    self.hot.tx_pn[1] += 1;
                    const ct_len = fpos + 16;
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .handshake,
                        self.quic_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len, // payload_len = ciphertext + AEAD tag (RFC 9000 §17.2)
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) return error.PacketTooLarge;
                    crypto.encryptPayload(hk, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(hk, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    try self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]);
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.count = 0;
                    self.storeSendMeta(pn, 1, hdr_len + ct_len, false, fi);
                },
                2 => {
                    // 1-RTT packet: Short Header, app keys
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.count = 0;
                    _ = self.sendShortHeaderPacket(fpos, fi, false) catch return;
                },
                else => return,
            }
        }

        // -----------------------------------------------------------------------
        // 1-RTT packet send helper
        // -----------------------------------------------------------------------

        /// Encrypt the frame payload in pkt_scratch[0..plaintext_len], wrap in a
        /// 1-RTT Short Header packet, and enqueue for sending.
        /// Optionally tracks the packet for loss recovery and updates PTO.
        ///
        /// `plaintext_len`:  bytes of frame data already serialized in pkt_scratch.
        /// `fi`:             frame info for loss tracking; null = don't track (e.g. PATH_RESPONSE).
        /// `ack_eliciting`:  whether this packet is ack-eliciting (for loss recovery).
        ///
        /// Returns the packet number used, or error on failure.
        /// On PacketTooLarge, reverts tx_pn so no PN is wasted.
        pub fn sendShortHeaderPacket(self: *Self, plaintext_len: usize, fi: ?loss_recovery_mod.SentFrameInfo, ack_eliciting: bool) !u64 {
            const ak = self.app_keys orelse return error.NoAppKeys;

            const pn = self.hot.tx_pn[2];
            self.hot.tx_pn[2] += 1;

            const hdr_len = packet.encodeShortHeader(&self.enc_scratch, self.peer_scid[0..self.peer_scid_len], @intCast(pn), self.current_key_phase);
            const ct_len = plaintext_len + 16;
            if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) {
                self.hot.tx_pn[2] -= 1;
                return error.PacketTooLarge;
            }
            crypto.encryptPayload(ak.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..plaintext_len], self.enc_scratch[hdr_len..][0..ct_len]);
            crypto.applyHeaderProtection(ak.server, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
            const out_len = hdr_len + ct_len;
            self.enqueueSend(self.enc_scratch[0..out_len]) catch |err| {
                self.hot.tx_pn[2] -= 1;
                return err;
            };

            if (fi) |frame_info| {
                self.storeSendMeta(pn, 2, out_len, ack_eliciting, frame_info);
            }
            return pn;
        }

        pub fn queuePing(self: *Self) !void {
            const n = frame.encodeFrame(&self.pkt_scratch, .ping);
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .ping;
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(n, fi, true);
        }

        /// Queue a PMTUD probe: a PING frame padded to target_size.
        /// Only works in 1-RTT (post-handshake); pre-handshake probes are not supported.
        /// Determine the next MTU size to probe. Probes: 1200 → 1500 → 2048 → 4096 → MAX_PACKET_SIZE.
        pub fn getNextPmtudSize(self: *const Self) u16 {
            return switch (self.path_mtu) {
                0...1199 => 1200,
                1200...1499 => 1500,
                1500...2047 => 2048,
                2048...4095 => 4096,
                else => @min(@as(u16, 65535), self.path_mtu *| 2), // exponential growth beyond 4096
            };
        }

        pub fn queuePmtudProbe(self: *Self, target_size: u16) !void {
            if (self.app_keys == null) return error.InvalidState;
            if (target_size < 1200 or target_size > 65535) return error.InvalidSize;
            if (target_size > MAX_SEND_PACKET_SIZE) return error.PacketTooLarge;

            var pos: usize = 0;
            pos += frame.encodeFrame(self.pkt_scratch[pos..], .ping);

            // Pad to exact target_size: header(1+scid_len+4) + plaintext + AEAD(16) = target_size
            const short_hdr_len: usize = 1 + self.peer_scid_len + 4;
            const max_plaintext = if (target_size > short_hdr_len + 16)
                target_size - short_hdr_len - 16
            else
                @as(usize, 1);
            if (max_plaintext > pos) {
                pos += frame.encodeFrame(self.pkt_scratch[pos..], .{ .padding = max_plaintext - pos });
            }

            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .ping;
            fi.count = 1;
            const pn = try self.sendShortHeaderPacket(pos, fi, true);

            self.pmtud_probing = .{
                .target_size = target_size,
                .packet_number = pn,
                .epoch = 2,
                .sent_ns = self.current_time_ns,
            };
        }

        /// Build and send a NewSessionTicket in a 1-RTT CRYPTO frame (post-handshake).
        fn sendNewSessionTicket(self: *Self) !void {
            var nst_buf: [512]u8 = undefined;
            self.tls_state.current_time_ns = self.current_time_ns;
            const nst_len = self.tls_state.buildNewSessionTicket(&nst_buf);
            if (nst_len == 0) return;

            const tls_offset = self.crypto_send_offset[2];
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .crypto = .{
                .offset = @intCast(tls_offset),
                .data = nst_buf[0..nst_len],
            } });

            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .crypto_frame = .{ .offset = @intCast(tls_offset), .len = @intCast(@min(nst_len, 0xffff)) } };
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(fpos, fi, true);
            self.crypto_send_offset[2] += nst_len;
        }

        fn queueHandshakeDone(self: *Self) !void {
            var pos: usize = 0;
            pos += frame.encodeFrame(self.pkt_scratch[pos..], .handshake_done);
            var ncid_frame = frame.NewConnectionIdFrame{
                .sequence_number = 1,
                .retire_prior_to = 0,
                .cid = undefined,
                .cid_len = @intCast(self.alt_local_cid.bytes.len),
                .stateless_reset_token = self.alt_local_reset_token,
            };
            @memcpy(ncid_frame.cid[0..self.alt_local_cid.bytes.len], &self.alt_local_cid.bytes);
            pos += frame.encodeFrame(self.pkt_scratch[pos..], .{ .new_connection_id = ncid_frame });

            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .handshake_done;
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(pos, fi, true);
        }

        pub fn queueTlsOutput(self: *Self, tls_data: []const u8) !void {
            if (tls_data.len == 0) return;

            // RFC 9001 §4.1.3: ServerHello MUST be sent in an Initial CRYPTO frame;
            // EncryptedExtensions through Finished MUST be in Handshake CRYPTO frames.
            //
            // Split point: end of the first TLS handshake message (ServerHello).
            // TLS handshake message format: type(1) || length(3) || body(length).
            const sh_end: usize = blk: {
                if (tls_data.len >= 4 and tls_data[0] == 0x02) { // SERVER_HELLO
                    const body_len: usize =
                        (@as(usize, tls_data[1]) << 16) |
                        (@as(usize, tls_data[2]) << 8) |
                        @as(usize, tls_data[3]);
                    break :blk @min(4 + body_len, tls_data.len);
                }
                // Unexpected format — treat all data as Initial (graceful fallback).
                break :blk tls_data.len;
            };

            // Initial epoch: ServerHello.
            if (sh_end > 0) {
                _ = self.sendCryptoChunk(tls_data[0..sh_end], 0) catch {
                    // If sending fails (e.g., amplification limit or packet too large),
                    // treat it as 0 bytes sent and let normal retry mechanisms handle it.
                    // ServerHello will be retried by PTO mechanism or next client packet
                    return;
                };
            }

            // Handshake epoch: EncryptedExtensions + Certificate + CertificateVerify + Finished.
            var sent: usize = sh_end;
            while (sent < tls_data.len) {
                const prev_sent = sent;
                const n = self.sendCryptoChunk(tls_data[sent..], 1) catch {
                    // If sending fails (e.g., amplification limit or packet too large),
                    // buffer remainder for retry when budget grows
                    const remaining = tls_data[sent..];
                    const copy_len = @min(remaining.len, self.tls_pending_hs.len);
                    @memcpy(self.tls_pending_hs[0..copy_len], remaining[0..copy_len]);
                    self.tls_pending_hs_len = copy_len;
                    self.tls_pending_hs_offset = 0;
                    return;
                };
                sent += n;
                if (sent == prev_sent) {
                    // Amplification limit hit — buffer remainder for retry when budget grows
                    const remaining = tls_data[sent..];
                    const copy_len = @min(remaining.len, self.tls_pending_hs.len);
                    @memcpy(self.tls_pending_hs[0..copy_len], remaining[0..copy_len]);
                    self.tls_pending_hs_len = copy_len;
                    self.tls_pending_hs_offset = 0;
                    break;
                }
            }
        }

        /// Encrypt and enqueue up to one packet worth of CRYPTO data in `epoch`
        /// (0 = Initial, 1 = Handshake).  Returns the number of data bytes consumed.
        fn sendCryptoChunk(self: *Self, data: []const u8, epoch: u8) !usize {
            // Per-packet data limit: MAX_SEND_PACKET_SIZE minus overhead.
            // Header worst case: 1 (first) + 4 (version) + 1 (DCID len) + 20 (DCID max) +
            //                    1 (SCID len) + 20 (SCID max) + 3 (token len varint) +
            //                    2 (length varint) + 4 (pn) = ~56-67B
            // CRYPTO frame: 1 (type) + varint(offset, 1-8B) + varint(length, 1-2B) = 3-11B
            // AEAD tag: 16B
            // Worst case total: 67 + 11 + 16 = 94B
            // Safe margin: 100B to account for all variabilities
            const OVERHEAD = 100;

            // When amplification-limited, cap packet size to remaining budget so we
            // can still send partial chunks instead of failing entirely.  This is
            // critical for flushPendingHsCrypto: the 9-cert chain in amplificationlimit
            // generates ~8KB of Handshake CRYPTO, and the remaining budget after the
            // initial flight may only be ~500 bytes — too small for a full 1352-byte chunk.
            var effective_max: usize = MAX_SEND_PACKET_SIZE;
            if (!self.path_validated and self.bytes_unvalidated_recv > 0) {
                const budget = self.bytes_unvalidated_recv *| 3;
                if (budget > self.bytes_unvalidated_sent) {
                    effective_max = @min(effective_max, @as(usize, @intCast(budget - self.bytes_unvalidated_sent)));
                } else {
                    return 0; // fully amplification-limited
                }
            }
            if (effective_max <= OVERHEAD) return 0;
            const max_chunk = effective_max - OVERHEAD;
            const chunk_len = @min(data.len, max_chunk);
            const chunk = data[0..chunk_len];

            const tls_offset = self.crypto_send_offset[epoch];
            const crypto_frame_val: frame.Frame = .{ .crypto = .{
                .offset = @intCast(tls_offset),
                .data = chunk,
            } };
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], crypto_frame_val);

            switch (epoch) {
                0 => {
                    const packet_version = self.quic_version; // V2 if configured, V1 otherwise
                    const ik = if (packet_version == packet.QUIC_VERSION_2)
                        crypto.deriveInitialKeys(self.first_initial_dcid[0..self.first_initial_dcid_len], packet.QUIC_VERSION_2).server
                    else
                        self.initial_keys.server;
                    const pn = self.hot.tx_pn[0];
                    self.hot.tx_pn[0] += 1;
                    const ct_len = fpos + 16;
                    // RFC 9369: If configured for V2, respond with V2 Initial and V2 keys.
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .initial,
                        packet_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len,
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) return error.PacketTooLarge;
                    crypto.encryptPayload(ik, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(ik, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]) catch |err| {
                        // If amplification limit exceeded, revert packet number and return 0 to retry later
                        if (err == error.AmplificationLimitExceeded) {
                            self.hot.tx_pn[0] -= 1;
                            return 0;
                        }
                        return err;
                    };
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.frames[0] = .{ .crypto_frame = .{
                        .offset = @intCast(tls_offset),
                        .len = @intCast(@min(chunk_len, 0xffff)),
                    } };
                    fi.count = 1;
                    self.crypto_send_offset[0] += chunk_len;
                    self.storeSendMeta(pn, 0, hdr_len + ct_len, true, fi);
                },
                1 => {
                    const hk = self.hs_keys.?.server;
                    const pn = self.hot.tx_pn[1];
                    self.hot.tx_pn[1] += 1;
                    const ct_len = fpos + 16;
                    // RFC 9369: Send Handshake packet with negotiated version.
                    // Keys are derived from client's version for compatibility.
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .handshake,
                        self.quic_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len,
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) return error.PacketTooLarge;
                    crypto.encryptPayload(hk, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(hk, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]) catch |err| {
                        // If amplification limit exceeded, revert packet number and return 0 to retry later
                        if (err == error.AmplificationLimitExceeded) {
                            self.hot.tx_pn[1] -= 1;
                            return 0;
                        }
                        return err;
                    };
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.frames[0] = .{ .crypto_frame = .{
                        .offset = @intCast(tls_offset),
                        .len = @intCast(@min(chunk_len, 0xffff)),
                    } };
                    fi.count = 1;
                    self.crypto_send_offset[1] += chunk_len;
                    self.storeSendMeta(pn, 1, hdr_len + ct_len, true, fi);
                },
                else => unreachable,
            }
            // Save chunk for potential PTO retransmission (epochs 0 and 1 only).
            // The buffer is sized to match the TLS out_buf (8192 bytes); overflow is impossible
            // as long as processCrypto writes into an [8192]u8 output buffer (see processCryptoFrame).
            if (epoch < 2) {
                const old: usize = self.crypto_send_saved_len[epoch];
                const end: usize = old + chunk_len;
                std.debug.assert(end <= self.crypto_send_saved[epoch].len);
                @memcpy(self.crypto_send_saved[epoch][old..end], chunk);
                self.crypto_send_saved_len[epoch] = @intCast(end);
            }
            return chunk_len;
        }

        /// Retransmit saved CRYPTO data for the given epoch as probe packets.
        /// Chunks large CRYPTO data (e.g., handshake with certificate chain) across multiple packets.
        /// Called by the PTO handler when the handshake stalls (app_keys == null).
        pub fn retransmitCryptoSaved(self: *Self, comptime epoch: u8) void {
            comptime std.debug.assert(epoch < 2);
            const data_len = self.crypto_send_saved_len[epoch];
            if (data_len == 0) return;
            const data = self.crypto_send_saved[epoch][0..data_len];

            const OVERHEAD = 100;
            // Budget-aware chunk sizing: cap to remaining amplification budget
            // so partial CRYPTO can be sent even when budget is tight.
            // Without this, a 754-byte cert chain retransmit silently fails when
            // only ~100 bytes of budget remain, causing handshake deadlock.
            var effective_max: usize = MAX_SEND_PACKET_SIZE;
            if (!self.path_validated and self.bytes_unvalidated_recv > 0) {
                const budget = self.bytes_unvalidated_recv *| 3;
                if (budget > self.bytes_unvalidated_sent) {
                    effective_max = @min(effective_max, @as(usize, @intCast(budget - self.bytes_unvalidated_sent)));
                } else {
                    return; // fully amplification-limited
                }
            }
            if (effective_max <= OVERHEAD) return;
            const max_chunk = effective_max - OVERHEAD;

            // Start from the rotating retransmit offset so each PTO cycle sends
            // the NEXT portion of CRYPTO data instead of re-sending from offset 0.
            // This is critical under amplification limits: budget is scarce, so
            // each cycle must advance through the data to eventually deliver it all.
            var sent: usize = self.crypto_retx_pos[epoch];
            if (sent >= data.len) sent = 0; // wrap around
            const start_pos = sent;
            var wrapped = false;
            while (true) {
                if (wrapped and sent >= start_pos) break; // full cycle done
                const chunk_end = @min(sent + max_chunk, data.len);
                const chunk = data[sent..chunk_end];

                // Build CRYPTO frame for this chunk at the correct stream offset
                const crypto_frame_val: frame.Frame = .{ .crypto = .{ .offset = @intCast(sent), .data = chunk } };
                var fpos: usize = 0;
                fpos += frame.encodeFrame(self.pkt_scratch[fpos..], crypto_frame_val);

                if (epoch == 0) {
                    const packet_version = self.quic_version; // V2 if configured, V1 otherwise
                    const ik = if (packet_version == packet.QUIC_VERSION_2)
                        crypto.deriveInitialKeys(self.first_initial_dcid[0..self.first_initial_dcid_len], packet.QUIC_VERSION_2).server
                    else
                        self.initial_keys.server;
                    const pn = self.hot.tx_pn[0];
                    self.hot.tx_pn[0] += 1;
                    const ct_len = fpos + 16;
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .initial,
                        packet_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len,
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) {
                        self.hot.tx_pn[0] -= 1; // Revert pn if packet too large
                        break;
                    }
                    crypto.encryptPayload(ik, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(ik, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]) catch break;
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.frames[0] = .{ .crypto_frame = .{ .offset = @intCast(sent), .len = @intCast(chunk.len) } };
                    fi.count = 1;
                    self.storeSendMeta(pn, 0, hdr_len + ct_len, true, fi);
                } else {
                    const hk = self.hs_keys orelse break;
                    const pn = self.hot.tx_pn[1];
                    self.hot.tx_pn[1] += 1;
                    const ct_len = fpos + 16;
                    const hdr_len = packet.encodeLongHeader(
                        &self.enc_scratch,
                        .handshake,
                        self.quic_version,
                        self.peer_scid[0..self.peer_scid_len],
                        self.ourScidBytes(),
                        &.{},
                        @intCast(pn),
                        ct_len,
                    );
                    if (hdr_len + ct_len > MAX_SEND_PACKET_SIZE) {
                        self.hot.tx_pn[1] -= 1; // Revert pn if packet too large
                        break;
                    }
                    crypto.encryptPayload(hk.server, pn, self.enc_scratch[0..hdr_len], self.pkt_scratch[0..fpos], self.enc_scratch[hdr_len..][0..ct_len]);
                    crypto.applyHeaderProtection(hk.server, &self.enc_scratch[0], self.enc_scratch[hdr_len - 4 ..][0..4], self.enc_scratch[hdr_len..][0..16]);
                    self.enqueueSend(self.enc_scratch[0 .. hdr_len + ct_len]) catch break;
                    var fi = loss_recovery_mod.SentFrameInfo{};
                    fi.frames[0] = .{ .crypto_frame = .{ .offset = @intCast(sent), .len = @intCast(chunk.len) } };
                    fi.count = 1;
                    self.storeSendMeta(pn, 1, hdr_len + ct_len, true, fi);
                }

                sent += chunk.len;
                if (sent >= data.len) {
                    sent = 0;
                    wrapped = true;
                }
            }
            self.crypto_retx_pos[epoch] = sent; // save for next PTO
        }

        /// Flush pending Handshake CRYPTO data buffered during amplification limit.
        /// Called by receive() after each client packet to allow retry when the budget grows.
        /// Returns without action if tls_pending_hs_len == 0.
        /// Flush the single active inline borrow (if any). Called at the start
        /// of receive() before the recv buffer is overwritten.  O(1) — no scan.
        fn flushAllInlineBorrows(self: *Self) void {
            if (self.inline_borrow_stream) |sid| {
                if (self.streams.get(sid)) |st| {
                    st.flushInline();
                }
                self.inline_borrow_stream = null;
            }
        }

        fn flushPendingHsCrypto(self: *Self) void {
            if (self.tls_pending_hs_len == 0) return;
            const pending = self.tls_pending_hs[self.tls_pending_hs_offset..self.tls_pending_hs_len];
            var sent: usize = 0;
            while (sent < pending.len) {
                const n = self.sendCryptoChunk(pending[sent..], 1) catch break;
                if (n == 0) break; // still blocked by amplification limit
                sent += n;
            }
            self.tls_pending_hs_offset += sent;
            if (self.tls_pending_hs_offset >= self.tls_pending_hs_len) {
                self.tls_pending_hs_len = 0;
                self.tls_pending_hs_offset = 0;
            }
        }

        /// Check whether we should throttle sending a VN packet for this version.
        /// Returns true if we've recently sent VN for this version (60s cooldown).
        /// Updates the per-version tracking on first-time or expired entries.
        /// Public for testing purposes.
        pub fn shouldThrottleVersionNeg(self: *Self, version: u32) bool {
            const COOLDOWN_NS = 60 * 1_000_000_000; // 60 seconds

            // Check if this version is in our recent list within cooldown window.
            for (&self.unknown_versions, &self.unknown_version_times) |*stored_ver, *stored_time| {
                if (stored_ver.* == version) {
                    // Found this version in our list.
                    if (self.current_time_ns - stored_time.* < COOLDOWN_NS) {
                        return true; // throttle: recently sent VN for this version
                    }
                    // Cooldown expired; update the timestamp and proceed to send VN.
                    stored_time.* = self.current_time_ns;
                    return false;
                }
            }

            // Version not in our list; record it (round-robin: FIFO slot).
            const idx = self.unknown_version_idx & 3;
            self.unknown_versions[idx] = version;
            self.unknown_version_times[idx] = self.current_time_ns;
            self.unknown_version_idx += 1;
            return false; // permit: first time seeing this version
        }

        /// Encode and enqueue a Version Negotiation packet in response to an
        /// unknown-version long-header packet.  `raw` is the received datagram.
        fn sendVersionNeg(self: *Self, raw: []const u8) !void {
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

            const client_scid = raw[pos..][0..scid_len];

            // RFC 9000 §6: advertise all versions the server supports for compatibility.
            // RFC 9000 §6.1: DCID of VN response MUST be a verbatim copy of the client's SCID.
            var vn_buf: [64]u8 = undefined;
            const vn_n = packet.encodeVersionNegotiation(
                &vn_buf,
                client_scid,
                &self.local_cid.bytes,
            );
            try self.enqueueSend(vn_buf[0..vn_n]);
        }

        /// Build and enqueue a Retry packet (RFC 9000 §8.1).
        /// Generates a fresh address-validation token, picks a new SCID, and pushes
        /// `retry_sent` so the caller knows to drain and discard this connection.
        fn sendRetry(self: *Self, odcid: []const u8, src: SocketAddr, now_ns: i64, io: std.Io) !void {
            const token = self.generateToken(src, odcid, now_ns, io);
            self.retry_scid = ConnectionId.generate(0, io);
            var buf: [256]u8 = undefined;
            const n = packet.encodeRetry(&buf, self.peer_scid[0..self.peer_scid_len], self.retry_scid.?, &token, odcid, self.quic_version);
            try self.enqueueSend(buf[0..n]);
            self.events.push(.retry_sent);
        }

        /// Low-level: encrypt and enqueue a STREAM frame at an explicit offset.
        /// Does NOT advance stream.send_offset (caller is responsible for that).
        fn encryptAndEnqueueStreamFrame(self: *Self, id: u62, offset: u62, data: []const u8, fin: bool) !void {
            self.idle_ping_count = 0; // real data → reset idle PING counter
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .stream = .{
                .stream_id = id,
                .offset = offset,
                .fin = fin,
                .data = data,
            } });
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .stream = .{
                .stream_id = id,
                .offset = offset,
                .len = @intCast(@min(data.len, 0xffff)),
                .fin = fin,
            } };
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(fpos, fi, true);
        }

        fn queueStreamData(self: *Self, id: u62, data: []const u8, fin: bool) !void {
            if (self.app_keys == null) return;

            const st = self.streams.getOrCreate(id) orelse return;
            const offset: u62 = @intCast(st.send_offset);
            // Enqueue the packet first; if the send queue is full this returns an error
            // and no state is changed (send_buf and send_offset remain unmodified).
            try self.encryptAndEnqueueStreamFrame(id, offset, data, fin);
            // Only after the packet is successfully queued: buffer for retransmission
            // and advance the send offset.
            _ = st.bufferSendData(data);
            st.onSent(data.len);
            // Transition stream state after successful FIN enqueue — only on first call,
            // not during retransmission (processLostFrames calls encryptAndEnqueueStreamFrame
            // directly and must not re-trigger the state transition).
            if (fin and !st.send_fin) {
                st.send_fin = true;
                st.sendFin();
            }
        }

        /// Encrypt and enqueue the pre-serialized CONNECTION_CLOSE frame.
        fn queueConnectionClose(self: *Self) !void {
            if (self.closing_frame_len == 0) return;
            @memcpy(self.pkt_scratch[0..self.closing_frame_len], self.closing_frame_buf[0..self.closing_frame_len]);
            // Not tracked for retransmission — closing state re-sends on every receive().
            _ = self.sendShortHeaderPacket(self.closing_frame_len, null, false) catch return;
        }

        /// Queue a RESET_STREAM frame for `stream_id`.
        fn queueResetStream(self: *Self, stream_id: u62, error_code: u62, final_size: u62) !void {
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .reset_stream = .{
                .stream_id = stream_id,
                .error_code = error_code,
                .final_size = final_size,
            } });
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .reset_stream = .{
                .stream_id = stream_id,
                .error_code = error_code,
                .final_size = final_size,
            } };
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(fpos, fi, true);
        }

        /// Scan all streams for pending_reset and queue a RESET_STREAM frame for each.
        fn flushPendingResets(self: *Self) !void {
            for (0..max_streams) |i| {
                if (!self.streams.occupied(i)) continue;
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
        fn queuePathResponse(self: *Self, data: [8]u8) !void {
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .path_response = .{ .data = data } });
            _ = self.sendShortHeaderPacket(fpos, null, false) catch return;
        }

        /// Queue a PATH_CHALLENGE with `data` and record it so the peer's
        /// PATH_RESPONSE can be validated (RFC 9000 §9.2).
        pub fn sendPathChallenge(self: *Self, data: [8]u8) !void {
            self.pending_path_challenge = data;
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .path_challenge = .{ .data = data } });
            _ = self.sendShortHeaderPacket(fpos, null, false) catch return;
        }

        /// Process a NEW_CONNECTION_ID frame: store the CID and retire entries below retire_prior_to.
        /// Security: Validate sequence number is monotonic and not excessively large (DoS defense).
        pub fn processNewConnectionId(self: *Self, ncid: frame.NewConnectionIdFrame) void {
            // RFC 9000 §19.15: reject CIDs that are already retired.
            if (ncid.sequence_number < self.peer_cid_retire_prior) return;

            // Security: Sequence number must not exceed current_max + 1000 (DoS defense).
            // This prevents attacker from causing unbounded sequence space exploration.
            // Note: we do NOT reject seq < peer_cid_highest_seq because frames may arrive
            // out-of-order; RFC 9000 only requires rejection when seq < retire_prior_to.
            const max_allowed_seq = self.peer_cid_highest_seq +| 1000;
            if (ncid.sequence_number > max_allowed_seq) return;

            // Update the highest-seen sequence number
            if (ncid.sequence_number > self.peer_cid_highest_seq) {
                self.peer_cid_highest_seq = ncid.sequence_number;
            }

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
        fn queueMaxStreamData(self: *Self, stream_id: u62, new_max: u62) !void {
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .max_stream_data = .{
                .stream_id = stream_id,
                .max_data = new_max,
            } });
            var fi = loss_recovery_mod.SentFrameInfo{};
            fi.frames[0] = .{ .max_stream_data = .{ .stream_id = stream_id, .max_data = new_max } };
            fi.count = 1;
            _ = try self.sendShortHeaderPacket(fpos, fi, true);
        }

        /// Queue a STREAM_DATA_BLOCKED frame (RFC 9000 §19.13) for the given stream.
        /// Sent when the sender is blocked by flow control at `max` bytes.
        fn queueStreamDataBlocked(self: *Self, stream_id: u62, max: u62) !void {
            var fpos: usize = 0;
            fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .stream_data_blocked = .{
                .stream_id = stream_id,
                .max = max,
            } });
            // Informational; not tracked for loss recovery.
            _ = try self.sendShortHeaderPacket(fpos, null, false);
        }

        /// Scan all streams and send MAX_STREAM_DATA frames for any whose recv window grew.
        fn flushPendingMaxStreamData(self: *Self) void {
            for (0..max_streams) |i| {
                if (!self.streams.occupied(i)) continue;
                const st = &self.streams.streams[i];
                if (st.shouldSendMaxStreamData()) {
                    const new_max: u62 = @intCast(@min(st.recv_max, std.math.maxInt(u62)));
                    st.last_sent_max_stream_data = st.recv_max;
                    self.queueMaxStreamData(st.id, new_max) catch {};
                }
            }
        }

        /// Batch MAX_DATA and MAX_STREAM_DATA frames into a single 1-RTT packet.
        /// Called from tick() to replace the individual queueMaxData +
        /// flushPendingMaxStreamData calls when the connection is established.
        ///
        /// MAX_DATA: tracked in SentFrameInfo (loss recovery sets pending_max_data on loss).
        /// MAX_STREAM_DATA: not tracked (shouldSendMaxStreamData re-triggers on next tick).
        pub fn flushControlFrames(self: *Self) !void {
            if (self.app_keys == null) return;

            // Leave room for Short Header (~13 bytes) + AEAD tag (16 bytes).
            // Use MAX_SEND_PACKET_SIZE (not MAX_PACKET_SIZE) since pkt_scratch is
            // sized to MAX_SEND_PACKET_SIZE; using the larger incoming value would
            // allow fpos to exceed the scratch buffer bounds.
            const frame_budget = MAX_SEND_PACKET_SIZE - 30;
            var fpos: usize = 0;
            var fi = loss_recovery_mod.SentFrameInfo{};
            var has_ack_eliciting = false;

            // 1. Pending MAX_DATA frame
            if (self.pending_max_data) {
                self.pending_max_data = false;
                const new_max: u62 = @intCast(@min(self.conn_flow.recv_max, std.math.maxInt(u62)));
                fpos += frame.encodeFrame(self.pkt_scratch[fpos..], .{ .max_data = new_max });
                if (fi.count < loss_recovery_mod.MAX_FRAMES_PER_PACKET) {
                    fi.frames[fi.count] = .{ .max_data = new_max };
                    fi.count += 1;
                }
                has_ack_eliciting = true;
            }

            // 1b. Pending MAX_STREAMS_BIDI frame
            if (self.pending_max_streams_bidi) |max_bidi| {
                const f_frame: frame.Frame = .{ .max_streams_bidi = max_bidi };
                const encoded_len = frame.encodeFrame(self.pkt_scratch[fpos..], f_frame);
                if (fpos + encoded_len <= frame_budget) {
                    fpos += encoded_len;
                    self.pending_max_streams_bidi = null;
                    if (fi.count < loss_recovery_mod.MAX_FRAMES_PER_PACKET) {
                        fi.frames[fi.count] = .{ .max_streams_bidi = max_bidi };
                        fi.count += 1;
                    }
                    has_ack_eliciting = true;
                }
            }

            // 1c. Pending MAX_STREAMS_UNI frame
            if (self.pending_max_streams_uni) |max_uni| {
                const f_frame: frame.Frame = .{ .max_streams_uni = max_uni };
                const encoded_len = frame.encodeFrame(self.pkt_scratch[fpos..], f_frame);
                if (fpos + encoded_len <= frame_budget) {
                    fpos += encoded_len;
                    self.pending_max_streams_uni = null;
                    if (fi.count < loss_recovery_mod.MAX_FRAMES_PER_PACKET) {
                        fi.frames[fi.count] = .{ .max_streams_uni = max_uni };
                        fi.count += 1;
                    }
                    has_ack_eliciting = true;
                }
            }

            // 2. Pending MAX_STREAM_DATA frames (not tracked for retransmission;
            //    shouldSendMaxStreamData re-arms on next tick if needed).
            for (0..max_streams) |i| {
                if (!self.streams.occupied(i)) continue;
                const st = &self.streams.streams[i];
                if (!st.shouldSendMaxStreamData()) continue;
                const new_max: u62 = @intCast(@min(st.recv_max, std.math.maxInt(u62)));
                const f_frame: frame.Frame = .{ .max_stream_data = .{
                    .stream_id = st.id,
                    .max_data = new_max,
                } };
                const encoded_len = frame.encodeFrame(self.pkt_scratch[fpos..], f_frame);
                if (fpos + encoded_len > frame_budget) break; // packet full
                fpos += encoded_len;
                st.last_sent_max_stream_data = st.recv_max;
                has_ack_eliciting = true;
            }

            if (fpos == 0) return; // nothing to send
            _ = try self.sendShortHeaderPacket(fpos, fi, has_ack_eliciting);
        }

        // -----------------------------------------------------------------------
        // Key update (RFC 9001 §6)
        // -----------------------------------------------------------------------

        /// Rotate application keys: promote next → current, flip key_phase bit,
        /// derive the new next generation.  Called on peer-initiated key updates
        /// (inside processShortHeaderPacket) and as part of initiateKeyUpdate.
        pub fn rotateKeys(self: *Self) void {
            // Zero the outgoing application keys before replacing them (RFC 9001 §6,
            // defence-in-depth: previous-epoch key material must not linger in memory).
            if (self.app_keys) |*old| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(tls.AppKeys)]u8, @ptrCast(old)));
            }
            self.app_keys = self.next_app_keys;
            // Zero old cached key schedule (defense-in-depth: AES round keys are key material).
            if (self.cached_app_keys) |*old_cached| {
                std.crypto.secureZero(u8, @as(*volatile [@sizeOf(crypto_simd.CachedKeyCtx)]u8, @ptrCast(old_cached)));
            }
            self.cached_app_keys = self.cached_next_keys;
            self.current_key_phase = !self.current_key_phase;
            self.current_key_generation += 1;
            self.key_update_pending = false;

            // Derive next-next generation from the (now-current) secrets.
            const new_client = crypto.deriveNextAppSecret(self.next_client_secret, self.quic_version);
            const new_server = crypto.deriveNextAppSecret(self.next_server_secret, self.quic_version);

            // Zero the outgoing secrets before overwriting (defence-in-depth).
            std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.next_client_secret)));
            std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.next_server_secret)));

            self.next_client_secret = new_client;
            self.next_server_secret = new_server;
            self.next_app_keys = tls.AppKeys{
                .client = crypto.derivePacketKeysWithSuite(self.next_client_secret, self.quic_version, self.tls_state.negotiated_cipher),
                .server = crypto.derivePacketKeysWithSuite(self.next_server_secret, self.quic_version, self.tls_state.negotiated_cipher),
            };
            // RFC 9001 §6.1: header protection key does not change with key updates.
            if (self.app_keys) |cur| {
                self.next_app_keys.?.client.hp = cur.client.hp;
                self.next_app_keys.?.server.hp = cur.server.hp;
            }
            // Cache rotated key schedule.
            self.cached_next_keys = crypto_simd.CachedKeyCtx.init(self.next_app_keys.?.client);
        }

        /// Initiate a locally-triggered key update (RFC 9001 §6).
        /// Returns error.NotEstablished if the handshake is not complete,
        /// or error.KeyUpdatePending if a previous update has not been acknowledged.
        pub fn initiateKeyUpdate(self: *Self) !void {
            if (self.app_keys == null) return error.NotEstablished;
            if (self.key_update_pending) return error.KeyUpdatePending;
            self.rotateKeys(); // flips phase, derives new next, clears pending
            self.key_update_pending = true; // signal TX side to use new key_phase
        }

        /// Derive client and server secrets for a given generation (0=initial, 1+=rotations).
        /// Used for SSLKEYLOG to track all key generations.
        pub fn deriveSecretsForGeneration(self: *const Self, generation: u32) struct { client: [32]u8, server: [32]u8 } {
            var client = self.tls_state.client_app_secret;
            var server = self.tls_state.server_app_secret;
            for (0..generation) |_| {
                client = crypto.deriveNextAppSecret(client, self.quic_version);
                server = crypto.deriveNextAppSecret(server, self.quic_version);
            }
            return .{ .client = client, .server = server };
        }

        // -----------------------------------------------------------------------
        // Path migration (RFC 9000 §9)
        // -----------------------------------------------------------------------

        /// Handle a source address change: reset congestion, request path validation.
        fn onPathMigration(self: *Self, new_addr: SocketAddr, io: std.Io) !void {
            // RFC 9000 §9.4: reset congestion controller on path change.
            self.congestion = cc_mod.CongestionControl.init();
            // RFC 9000 §9.4: reset amplification limit for the new path (separate from old path tracking).
            // Each path must independently satisfy the 3x amplification limit until validated.
            self.bytes_unvalidated_recv = 0;
            self.bytes_unvalidated_sent = 0;
            // Immediately adopt new address (RFC 9000 §9.3.1).
            self.peer_addr = new_addr;
            // RFC 9000 §9.3: reset path validation on migration — must re-validate new path.
            self.path_validated = false;
            // Send PATH_CHALLENGE to validate the new path.
            var challenge: [8]u8 = undefined;
            io.random(&challenge);
            try self.sendPathChallenge(challenge);
            self.events.push(.path_migrated);
        }

        /// Handle a port-only source address change (NAT rebinding).
        /// RFC 9000 §9.3.1: an endpoint MAY skip path validation if only the
        /// source port changed.  Preserves congestion state for throughput.
        fn onNatRebind(self: *Self, new_addr: SocketAddr, io: std.Io) !void {
            // Adopt new address without resetting congestion or path validation.
            self.peer_addr = new_addr;
            // Still send PATH_CHALLENGE to confirm reachability on the new port.
            var challenge: [8]u8 = undefined;
            io.random(&challenge);
            try self.sendPathChallenge(challenge);
            self.events.push(.path_migrated);
        }

        /// Helper: normalize address to IPv6 for token hashing.
        fn normalizeAddressToIPv6(src: SocketAddr) [16]u8 {
            var ipv6: [16]u8 = [_]u8{0} ** 16;
            switch (src) {
                .v4 => |v4| {
                    ipv6[10] = 0xff;
                    ipv6[11] = 0xff;
                    @memcpy(ipv6[12..16], &v4.addr);
                },
                .v6 => |v6| {
                    @memcpy(ipv6[0..16], &v6.addr);
                },
            }
            return ipv6;
        }

        /// Generate a stateless Retry token (62 bytes).
        /// Format: [12]u8 nonce || [34]u8 AES-128-GCM(plaintext) || [16]u8 tag
        /// Plaintext: [16]u8 IPv6-normalized address || [2]u8 port || [8]u8 timestamp || [8]u8 ODCID
        // Token size: nonce(12) + ciphertext(47) + tag(16) = 75 bytes.
        // Plaintext layout: odcid_len(1) + odcid(20, zero-padded) + addr(16) + port(2) + ts(8) = 47 bytes.
        pub const TOKEN_SIZE: usize = 75;

        pub fn generateToken(self: *const Self, src: SocketAddr, odcid: []const u8, now_ns: i64, io: std.Io) [TOKEN_SIZE]u8 {
            // Normalize address to IPv6 for consistent handling
            const addr_ipv6 = normalizeAddressToIPv6(src);

            // Build plaintext (47 bytes): odcid_len(1) + odcid(20) + addr(16) + port(2) + ts(8)
            var plaintext: [47]u8 = [_]u8{0} ** 47;
            var pos: usize = 0;

            // Original DCID length (1 byte) + DCID bytes (padded to 20)
            plaintext[pos] = @intCast(@min(odcid.len, 20));
            pos += 1;
            const copy_len = @min(odcid.len, 20);
            @memcpy(plaintext[pos..][0..copy_len], odcid[0..copy_len]);
            pos += 20; // always advance by 20 (zero-padded)

            // Address (16 bytes)
            @memcpy(plaintext[pos..][0..16], &addr_ipv6);
            pos += 16;

            // Port (2 bytes, big-endian)
            const port: u16 = switch (src) {
                .v4 => |v4| v4.port,
                .v6 => |v6| v6.port,
            };
            std.mem.writeInt(u16, plaintext[pos..][0..2], port, .big);
            pos += 2;

            // Timestamp (8 bytes, unsigned, saturating)
            const now_u64: u64 = @intCast(@max(now_ns, 0));
            std.mem.writeInt(u64, plaintext[pos..][0..8], now_u64, .little);
            pos += 8;

            std.debug.assert(pos == 47);

            // Generate random nonce
            var token: [TOKEN_SIZE]u8 = undefined;
            var nonce: [12]u8 = undefined;
            io.random(&nonce);

            // Derive token key from secret via HKDF-Expand
            var token_key: [16]u8 = undefined;
            const label = "zquic retry token key";
            std.crypto.kdf.hkdf.HkdfSha256.expand(&token_key, label, self.config.token_secret);

            // Encrypt plaintext with AES-128-GCM
            var ciphertext: [47]u8 = undefined;
            var tag: [16]u8 = undefined;
            std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&ciphertext, &tag, &plaintext, &.{}, nonce, token_key);

            // Assemble token: nonce || ciphertext || tag
            @memcpy(token[0..12], &nonce);
            @memcpy(token[12..59], &ciphertext);
            @memcpy(token[59..75], &tag);

            // Defense-in-depth: zero plaintext after encryption (no longer needed)
            std.crypto.secureZero(u8, @as(*volatile [47]u8, @ptrCast(&plaintext)));
            // Also zero the temporary token_key (though it's derived from config secret)
            std.crypto.secureZero(u8, @as(*volatile [16]u8, @ptrCast(&token_key)));

            return token;
        }

        /// Validate a token from an Initial packet.
        /// Returns the original DCID (raw bytes, length) on success, null on failure.
        pub const ValidatedToken = struct { raw: [20]u8, len: u8 };
        pub fn validateToken(self: *const Self, token: []const u8, src: SocketAddr, now_ns: i64) ?ValidatedToken {
            // Token must be exactly TOKEN_SIZE (75) bytes
            if (token.len != TOKEN_SIZE) return null;

            // Extract components: nonce(12) + ciphertext(47) + tag(16)
            const nonce = token[0..12];
            const ciphertext = token[12..59];
            const tag_in = token[59..75];

            // Derive token key
            var token_key: [16]u8 = undefined;
            const label = "zquic retry token key";
            std.crypto.kdf.hkdf.HkdfSha256.expand(&token_key, label, self.config.token_secret);

            // Decrypt with AES-128-GCM
            var plaintext: [47]u8 = undefined;
            // Defense-in-depth: zero plaintext after validation (no longer needed)
            defer std.crypto.secureZero(u8, @as(*volatile [47]u8, @ptrCast(&plaintext)));
            var tag_arr: [16]u8 = undefined;
            @memcpy(&tag_arr, tag_in);

            var nonce_arr: [12]u8 = undefined;
            @memcpy(&nonce_arr, nonce);

            std.crypto.aead.aes_gcm.Aes128Gcm.decrypt(
                &plaintext,
                ciphertext[0..47],
                tag_arr,
                &.{},
                nonce_arr,
                token_key,
            ) catch return null;

            // Extract fields from plaintext: odcid_len(1) + odcid(20) + addr(16) + port(2) + ts(8)
            var pos: usize = 0;

            // Original DCID length + bytes
            const odcid_len: u8 = if (plaintext[pos] <= 20) plaintext[pos] else return null;
            pos += 1;
            var odcid_raw: [20]u8 = [_]u8{0} ** 20;
            @memcpy(&odcid_raw, plaintext[pos..][0..20]);
            pos += 20;

            // Address (16 bytes, must match normalized version)
            const addr_ipv6_stored = plaintext[pos..][0..16];
            const addr_ipv6_current = normalizeAddressToIPv6(src);
            if (!std.mem.eql(u8, addr_ipv6_stored, &addr_ipv6_current)) return null;
            pos += 16;

            // Port (2 bytes, must match)
            const port_stored = std.mem.readInt(u16, plaintext[pos..][0..2], .big);
            const port_current: u16 = switch (src) {
                .v4 => |v4| v4.port,
                .v6 => |v6| v6.port,
            };
            if (port_stored != port_current) return null;
            pos += 2;

            // Timestamp validation
            const issued_at_u64 = std.mem.readInt(u64, plaintext[pos..][0..8], .little);
            pos += 8;

            std.debug.assert(pos == 47);

            const now_u64: u64 = @intCast(@max(now_ns, 0));

            // Reject tokens from the future (clock skew)
            if (issued_at_u64 > now_u64) return null;

            // Reject expired tokens
            const elapsed_u64 = now_u64 - issued_at_u64;
            const validity_u64: u64 = @intCast(@max(self.config.token_validity_ns, 0));
            if (elapsed_u64 > validity_u64) return null;

            return .{ .raw = odcid_raw, .len = odcid_len };
        }
    };
}
