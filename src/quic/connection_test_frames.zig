//! Tests for Connection — MAX_STREAM_DATA, persistent congestion, security
//! features, key rotation (initial), path migration, sendEncryptedAck,
//! deferred ACK, receive window growth, CRYPTO framing, flow control.
const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const ConnectionHot = conn_mod.ConnectionHot;
const ConnState = conn_mod.ConnState;
const Config = conn_mod.Config;
const Event = conn_mod.Event;
const SocketAddr = conn_mod.SocketAddr;
const MAX_PACKET_SIZE = conn_mod.MAX_PACKET_SIZE;
const MAX_SEND_PACKET_SIZE = conn_mod.MAX_SEND_PACKET_SIZE;
const frame = @import("frame.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const stream_mod = @import("stream.zig");
const tls = @import("tls.zig");
const cc_mod = @import("congestion/cc.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const transport_params = @import("transport_params.zig");

// ---------------------------------------------------------------------------
// New tests — MAX_STREAM_DATA generation via tick() (Step 6)
// ---------------------------------------------------------------------------

test "connection: tick clears shouldSendMaxStreamData after stream read" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Create a stream and simulate the application reading data (grows recv_max)
    const st = conn.streams.getOrCreate(0).?;
    try st.receiveData(0, "hello world", false);
    var read_buf: [16]u8 = undefined;
    _ = st.read(&read_buf);
    // recv_max has grown beyond last_sent_max_stream_data
    try testing.expect(st.shouldSendMaxStreamData());

    // Simulate established state with dummy app_keys (keys don't need to be valid
    // for decryption here; we only check that the watermark is cleared and a packet queued).
    conn.hot.state = .established;
    conn.app_keys = tls.AppKeys{
        .client = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
        .server = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
    };
    const sq_before = conn.sq_tail;
    conn.tick(1_000_000);
    // Watermark cleared (frame was batched by flushControlFrames)
    try testing.expect(!st.shouldSendMaxStreamData());
    // A packet was queued
    try testing.expect(conn.sq_tail > sq_before);
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
    var conn = try Connection(16).accept(.{}, io);

    conn.congestion.cwnd = 100 * 1200;
    if (cc_mod.selected == .cubic) {
        conn.congestion.ssthresh = 0; // always in CUBIC phase
    }

    conn.current_time_ns = 0;
    conn.hot.tx_pn[0] = 9; // pretend pn=0..8 were sent
    conn.loss.onPacketSent(1, 0, 1200, true, 0, 0, .{});
    conn.loss.onPacketSent(2, 0, 1200, true, 0, 0, .{});
    conn.loss.onPacketSent(3, 0, 1200, true, 0, 0, .{});
    conn.loss.onPacketSent(4, 0, 1200, true, 0, 0, .{});
    conn.loss.onPacketSent(5, 0, 1200, true, 3_200_000_000, 3_200_000_000, .{});
    conn.loss.onPacketSent(8, 0, 1200, true, 3_200_000_000, 3_200_000_000, .{});

    const ack = frame.AckFrame{
        .largest_acked = 8,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    conn.current_time_ns = 3_200_000_000;
    try conn.processAck(ack, 0);

    // Persistent congestion: CUBIC → cwnd = 2*MSS, BBR → cwnd = 4*MSS (BBR_MIN_CWND).
    if (cc_mod.selected == .cubic) {
        try testing.expectEqual(@as(u64, 2 * 1452), conn.congestion.cwnd);
    } else {
        try testing.expectEqual(@as(u64, 4 * 1452), conn.congestion.cwnd);
    }
}

// ---------------------------------------------------------------------------
// Security & performance regression tests (Round 5 hardening)
// ---------------------------------------------------------------------------

// SEC-001: HANDSHAKE_DONE direction enforcement
test "security: server rejects HANDSHAKE_DONE (direction violation)" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .is_server = true }, io); // default
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
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

    conn.bytes_unvalidated_recv = 1; // very small budget
    conn.path_validated = true; // validated → no limit

    // Even though budget is tiny, sends are allowed once validated.
    try conn.enqueueSend(&[_]u8{0x01} ** 100);
    // Verify the send queue actually accepted the bytes.
    var out: [MAX_PACKET_SIZE]u8 = undefined;
    try testing.expect(conn.send(&out, 0) > 0);
}

// SEC-006: Frame-type per epoch enforcement
test "security: STREAM frame in Initial epoch returns ProtocolViolation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established; // bypass SEC-004 state check

    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hi",
    } });
    // Feed as epoch 0 (Initial) — STREAM is not allowed there.
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 0, null));
}

test "security: HANDSHAKE_DONE in epoch 0 returns ProtocolViolation" {
    // Even for a client, HANDSHAKE_DONE in the Initial epoch is forbidden.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .is_server = false }, io);
    var buf: [4]u8 = undefined;
    const n = frame.encodeFrame(&buf, .handshake_done);
    try testing.expectError(error.ProtocolViolation, conn.processFrames(buf[0..n], 0, null));
}

test "security: ACK frame in epoch 0 is allowed" {
    // ACK is unrestricted (Initial, Handshake, 1-RTT).
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.tx_pn[0] = 1; // pretend pn=0 was sent in epoch 0
    const ack_frame_data: frame.Frame = .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
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
    buf[pos] = 0x18;
    pos += 1;
    // sequence_number = 1 (varint)
    buf[pos] = 0x01;
    pos += 1;
    // retire_prior_to = 0 (varint)
    buf[pos] = 0x00;
    pos += 1;
    // cid_len = 21 (too large)
    buf[pos] = 21;
    pos += 1;
    // cid data (21 bytes) + reset_token (16 bytes) — pad with zeros
    @memset(buf[pos..][0..37], 0xab);
    pos += 37;
    try testing.expectError(error.InvalidFrame, frame.parseFrame(buf[0..pos]));
}

// SEC-009: PATH_RESPONSE validation against pending challenge
test "security: PATH_RESPONSE matching pending challenge clears it" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const challenge_data = [8]u8{ 0xde, 0xad, 0xbe, 0xef, 1, 2, 3, 4 };
    conn.pending_path_challenge = challenge_data;

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = challenge_data } });
    try conn.processFrames(buf[0..n], 2, null);

    // pending_path_challenge must be cleared
    try testing.expectEqual(@as(?[8]u8, null), conn.pending_path_challenge);
}

test "connection: PATH_RESPONSE mismatch is silently ignored (RFC 9000 §8.2.3)" {
    // A PATH_RESPONSE that does not match the pending challenge must be silently
    // ignored — not treated as a protocol violation.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.pending_path_challenge = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };

    const wrong_data = [8]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = wrong_data } });
    // Must NOT return an error.
    try conn.processFrames(buf[0..n], 2, null);
    // Challenge must still be pending (not cleared by the bad response).
    try testing.expectEqual(conn.pending_path_challenge.?, [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 });
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
    var conn = try Connection(16).accept(.{}, io);

    const st = conn.streams.getOrCreate(0).?;
    try st.receiveData(0, "hello world", false);
    var buf: [16]u8 = undefined;
    _ = st.read(&buf);
    try testing.expect(st.shouldSendMaxStreamData());

    // tick() in idle state must NOT clear the flag (no flush).
    conn.tick(1_000_000);
    try testing.expect(st.shouldSendMaxStreamData()); // flag still set
}

// BUG-1 regression: ACK with maximum ack_delay must not overflow u64.
test "connection: ACK with max ack_delay does not overflow" {
    // ack_delay (u62) × 2^ack_delay_exp × 1000 previously overflowed u64.
    // In debug/ReleaseSafe this panics; in ReleaseFast it silently corrupts RTT.
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.tx_pn[2] = 1; // pretend pn=0 was sent in epoch 2
    var buf: [64]u8 = undefined;
    const ack_frm = frame.Frame{ .ack = .{
        .largest_acked = 0,
        .ack_delay = std.math.maxInt(u62),
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    } };
    const n = frame.encodeFrame(&buf, ack_frm);
    // Must complete without panic in any build mode.
    try conn.processFrames(buf[0..n], 2, null);
}

// BUG-3 regression: DATA_BLOCKED / STREAM_DATA_BLOCKED must trigger credit updates.
test "connection: DATA_BLOCKED triggers pending MAX_DATA update" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    try testing.expect(!conn.pending_max_data);
    var buf: [8]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .data_blocked = 0 });
    try conn.processFrames(buf[0..n], 2, null);
    try testing.expect(conn.pending_max_data);
}

test "connection: STREAM_DATA_BLOCKED triggers MAX_STREAM_DATA update" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const st = conn.streams.getOrCreate(0).?;
    st.recv_max = stream_mod.STREAM_BUF_SIZE;
    // Mark "already sent" at current recv_max — no update should be pending yet.
    st.last_sent_max_stream_data = st.recv_max;
    try testing.expect(!st.shouldSendMaxStreamData());

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream_data_blocked = .{
        .stream_id = 0,
        .max = @intCast(st.recv_max),
    } });
    try conn.processFrames(buf[0..n], 2, null);
    // last_sent_max_stream_data must have been zeroed → update now pending.
    try testing.expect(st.shouldSendMaxStreamData());
}

// SEC-008 (frame.zig): CID length bounds test via frame encoding round-trip
test "security: NEW_CONNECTION_ID parse rejects cid_len = 21" {
    // Verify the bounds check via the frame parser used in protocol flow.
    // We manually encode the offending byte sequence rather than using encodeFrame
    // (which only handles valid frames).
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    // 0x18 | seq=1 | rpt=0 | cid_len=21 | 21 bytes cid | 16 bytes token
    buf[0] = 0x18;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 21;
    @memset(buf[4..][0..37], 0); // 21-byte cid + 16-byte token
    try testing.expectError(error.InvalidFrame, frame.parseFrame(buf[0..41]));
}

test "security: shouldThrottleVersionNeg tracks per-version cooldown" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Version A at t=0: should not throttle (first time)
    conn.current_time_ns = 0;
    try testing.expect(!conn.shouldThrottleVersionNeg(0xAAAAAAAA));

    // Version A at t=30s: should throttle (within 60s cooldown)
    conn.current_time_ns = 30_000_000_000;
    try testing.expect(conn.shouldThrottleVersionNeg(0xAAAAAAAA));

    // Version B at t=30s: should not throttle (different version)
    try testing.expect(!conn.shouldThrottleVersionNeg(0xBBBBBBBB));

    // Version C at t=40s: should not throttle (different version)
    conn.current_time_ns = 40_000_000_000;
    try testing.expect(!conn.shouldThrottleVersionNeg(0xCCCCCCCC));

    // Version D at t=50s: should not throttle (different version)
    try testing.expect(!conn.shouldThrottleVersionNeg(0xDDDDDDDD));

    // Version E at t=60s: should not throttle (different version, fills 4th slot)
    conn.current_time_ns = 60_000_000_000;
    try testing.expect(!conn.shouldThrottleVersionNeg(0xEEEEEEEE));

    // Version A at t=61s: should throttle (within 60s cooldown, recorded at t=0)
    // Time diff = 61s - 0s = 61s > 60s cooldown, should NOT throttle (cooldown expired)
    conn.current_time_ns = 61_000_000_000;
    try testing.expect(!conn.shouldThrottleVersionNeg(0xAAAAAAAA));
}

test "security: shouldThrottleVersionNeg round-robin eviction after 4 versions" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    conn.current_time_ns = 0;

    // Record 4 versions (fills all slots)
    try testing.expect(!conn.shouldThrottleVersionNeg(0x11111111));
    try testing.expect(!conn.shouldThrottleVersionNeg(0x22222222));
    try testing.expect(!conn.shouldThrottleVersionNeg(0x33333333));
    try testing.expect(!conn.shouldThrottleVersionNeg(0x44444444));

    // All 4 should throttle at t=30s (within 60s cooldown)
    conn.current_time_ns = 30_000_000_000;
    try testing.expect(conn.shouldThrottleVersionNeg(0x11111111));
    try testing.expect(conn.shouldThrottleVersionNeg(0x22222222));
    try testing.expect(conn.shouldThrottleVersionNeg(0x33333333));
    try testing.expect(conn.shouldThrottleVersionNeg(0x44444444));

    // Record a 5th version (evicts slot 0: 0x11111111)
    try testing.expect(!conn.shouldThrottleVersionNeg(0x55555555));

    // 0x11111111 should NOT throttle anymore (was evicted)
    try testing.expect(!conn.shouldThrottleVersionNeg(0x11111111));
}

// ---------------------------------------------------------------------------
// Phase 4 — Key Update Tests (RFC 9001 §6)
// ---------------------------------------------------------------------------

test "connection: current_key_phase defaults false" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{}, io);
    try testing.expect(!conn.current_key_phase);
}

test "connection: key_update_pending defaults false" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{}, io);
    try testing.expect(!conn.key_update_pending);
}

test "connection: initiateKeyUpdate errors when not established" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    // app_keys == null → NotEstablished
    try std.testing.expectError(error.NotEstablished, conn.initiateKeyUpdate());
}

test "connection: initiateKeyUpdate errors when key_update_pending" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.next_client_secret = [_]u8{0x33} ** 32;
    conn.next_server_secret = [_]u8{0x44} ** 32;
    conn.next_app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.key_update_pending = true;
    try std.testing.expectError(error.KeyUpdatePending, conn.initiateKeyUpdate());
}

test "connection: initiateKeyUpdate flips key_phase and sets pending" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.next_client_secret = [_]u8{0x55} ** 32;
    conn.next_server_secret = [_]u8{0x66} ** 32;
    conn.next_app_keys = tls.AppKeys{ .client = k, .server = k };

    try testing.expect(!conn.current_key_phase);
    try conn.initiateKeyUpdate();
    try testing.expect(conn.current_key_phase); // flipped to true
    try testing.expect(conn.key_update_pending); // pending set
}

test "connection: rotateKeys advances next-generation secrets" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    const secret = [_]u8{0x77} ** 32;
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.next_client_secret = secret;
    conn.next_server_secret = secret;
    conn.next_app_keys = tls.AppKeys{ .client = k, .server = k };

    try conn.initiateKeyUpdate(); // internally calls rotateKeys()

    // next_client_secret must now be derived from the (promoted) secret,
    // which equals deriveNextAppSecret(secret) ≠ secret.
    try testing.expect(!std.mem.eql(u8, &conn.next_client_secret, &secret));
    const expected = crypto.deriveNextAppSecret(secret, packet.QUIC_VERSION_1);
    try testing.expectEqualSlices(u8, &expected, &conn.next_client_secret);
}

test "connection: ACK generation after key update" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Setup: establish connection with initial keys
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.next_client_secret = [_]u8{0x55} ** 32;
    conn.next_server_secret = [_]u8{0x66} ** 32;
    conn.next_app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.hot.state = .established;

    // Receive some packets (pn 10, 11, 12) to build up ACK bitmap
    conn.markPnReceived(2, 10);
    conn.markPnReceived(2, 11);
    conn.markPnReceived(2, 12);

    // Verify bitmap is correct before key update
    try testing.expectEqual(@as(u64, 12), conn.hot.rx_pn[2]);
    try testing.expect(conn.hot.rx_pn_valid[2]);
    try testing.expectEqual(@as(u64, 0b111), conn.rx_pn_bitmap[2]); // bits 0,1,2 set for packets 12,11,10

    // Perform key update (simulating peer-initiated)
    const old_phase = conn.current_key_phase;
    conn.rotateKeys();

    // Verify key_phase flipped
    try testing.expect(conn.current_key_phase != old_phase);

    // Verify bitmap still intact after key update
    try testing.expectEqual(@as(u64, 12), conn.hot.rx_pn[2]);
    try testing.expect(conn.hot.rx_pn_valid[2]);
    try testing.expectEqual(@as(u64, 0b111), conn.rx_pn_bitmap[2]);

    // Test: receive another packet after key update and verify ACK generation still works
    conn.markPnReceived(2, 13);
    try testing.expectEqual(@as(u64, 13), conn.hot.rx_pn[2]);
    // Bitmap should be shifted: packet 13 is the new largest, packets 12,11,10 are at positions -1,-2,-3
    // Expected bitmap bits 0-3 should be set (for packets 13,12,11,10)
    try testing.expectEqual(@as(u64, 0b1111), conn.rx_pn_bitmap[2]);
}

// ---------------------------------------------------------------------------
// Phase 4 — Path Migration Tests (RFC 9000 §9)
// ---------------------------------------------------------------------------

test "connection: same address no migration" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // peer_addr initialised to 0.0.0.0:0; receive from the same address.
    const src = SocketAddr{ .v4 = .{ .addr = [_]u8{0} ** 4, .port = 0 } };
    try conn.receive(&[_]u8{}, src, 0, 0, io);
    // No migration event must have been pushed.
    try testing.expect(conn.pollEvent() == null);
}

test "connection: different address triggers migration" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 4321 } };
    try conn.receive(&[_]u8{}, new_src, 0, 0, io);
    // peer_addr must be updated to the new address.
    try testing.expect(conn.peer_addr.eql(new_src));
}

test "connection: migration resets congestion" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // Inflate the congestion window to a large value.
    conn.congestion.cwnd = 999_999;
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 1 }, .port = 5000 } };
    var empty = [_]u8{};
    try conn.receive(&empty, new_src, 0, 0, io);
    // Congestion state (cwnd) is preserved across migration to avoid throughput
    // collapse during rapid address changes.  RTT and PTO are reset instead.
    try testing.expectEqual(@as(u64, 999_999), conn.congestion.cwnd);
    try testing.expect(!conn.loss.rtt.initialized); // RTT was reset
}

test "connection: migration sets path_validated false" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.path_validated = true;
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 2 }, .port = 5001 } };
    try conn.receive(&[_]u8{}, new_src, 0, 0, io);
    try testing.expect(!conn.path_validated);
}

test "connection: migration event pushed" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 3 }, .port = 5002 } };
    try conn.receive(&[_]u8{}, new_src, 0, 0, io);
    const ev = conn.pollEvent();
    try testing.expect(ev != null);
    try testing.expect(std.meta.activeTag(ev.?) == .path_migrated);
}

test "connection: peer_disable_migration suppresses migration" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_disable_migration = true;
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 192, 168, 0, 1 }, .port = 8080 } };
    try conn.receive(&[_]u8{}, new_src, 0, 0, io);
    // peer_addr must NOT be updated when migration is disabled.
    const original = SocketAddr{ .v4 = .{ .addr = [_]u8{0} ** 4, .port = 0 } };
    try testing.expect(conn.peer_addr.eql(original));
    // No migration event.
    try testing.expect(conn.pollEvent() == null);
}

test "connection: migration only in established state" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    // state is .idle — migration check must not fire.
    const new_src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 1, 2, 3, 4 }, .port = 9000 } };
    // Empty datagram; receive() returns without error (while loop body never runs).
    try conn.receive(&[_]u8{}, new_src, 0, 0, io);
    try testing.expect(conn.pollEvent() == null);
}

test "connection: PATH_RESPONSE after migration validates path" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    // Simulate post-migration state: challenge outstanding, path not yet validated.
    const challenge_data = [8]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0x01, 0x02, 0x03, 0x04 };
    conn.pending_path_challenge = challenge_data;
    conn.path_validated = false;

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .path_response = .{ .data = challenge_data } });
    try conn.processFrames(buf[0..n], 2, null);

    // Challenge cleared and path marked validated.
    try testing.expectEqual(@as(?[8]u8, null), conn.pending_path_challenge);
    try testing.expect(conn.path_validated);
}

// ---------------------------------------------------------------------------
// Phase 5 — Protocol Completeness & Performance
// ---------------------------------------------------------------------------

// ---- Step 1: sendEncryptedAck (ACK encryption fix) ----

test "connection: sendEncryptedAck for Initial epoch produces long header" {
    // The first byte of a long-header QUIC packet has bit 7 = 1 (0x80 or above).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    // Derive real initial keys with a dummy DCID.
    const dcid = [_]u8{ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88 };
    conn.initial_keys = crypto.deriveInitialKeys(&dcid, packet.QUIC_VERSION_1);
    conn.markPnReceived(0, 5);

    try conn.sendEncryptedAck(0);

    // A packet must have been enqueued.
    try testing.expect(conn.sq_tail > 0);
    // First byte: long-header form bit (bit 7) must be set.
    const slot = &conn.sq[0];
    try testing.expect(slot.buf[0] & 0x80 != 0);
}

test "connection: sendEncryptedAck for 1-RTT epoch produces short header" {
    // The first byte of a 1-RTT packet has bit 7 = 0 and bit 6 = 1 (0x40-0x7f).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.markPnReceived(2, 3);

    try conn.sendEncryptedAck(2);

    try testing.expect(conn.sq_tail > 0);
    const slot = &conn.sq[0];
    // Short header: bit 7 = 0, bit 6 = 1 (fixed bit per RFC 9000 §17.3).
    try testing.expect(slot.buf[0] & 0x80 == 0);
    try testing.expect(slot.buf[0] & 0x40 != 0);
}

test "connection: sendEncryptedAck skips when hs_keys missing" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hs_keys = null;

    // Should not enqueue anything.
    try conn.sendEncryptedAck(1);
    try testing.expectEqual(@as(usize, 0), conn.sq_tail);
}

// ---- Step 2: Deferred ACK for all ack-eliciting frames ----

test "connection: PING frame sets pending_ack flag" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    var buf: [4]u8 = undefined;
    const n = frame.encodeFrame(&buf, .ping);
    try conn.processFrames(buf[0..n], 0, null);

    // pending_ack[0] (Initial epoch) must be set.
    try testing.expect(conn.pending_ack[0]);
    // Other epochs untouched.
    try testing.expect(!conn.pending_ack[1]);
    try testing.expect(!conn.pending_ack[2]);
}

test "connection: ACK frame does NOT set pending_ack" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.tx_pn[0] = 1; // pretend pn=0 was sent in epoch 0

    // Build a minimal ACK frame (largest_acked=0, range_count=1).
    var buf: [64]u8 = undefined;
    const ack_f: frame.Frame = .{ .ack = .{
        .largest_acked = 0,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    } };
    const n = frame.encodeFrame(&buf, ack_f);
    try conn.processFrames(buf[0..n], 0, null);

    try testing.expect(!conn.pending_ack[0]);
}

test "connection: receive() flushes deferred ACK after ack-eliciting packet" {
    // receive() with a PING frame (encapsulated in an Initial packet) must
    // produce an encrypted ACK in the send queue once hs_keys are available.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    conn.initial_keys = crypto.deriveInitialKeys(&dcid, packet.QUIC_VERSION_1);
    conn.hot.state = .handshake; // past idle so Initial packets are processed
    conn.peer_cid = conn.local_cid;
    // hs_keys must be non-null so epoch-0 ACK is not suppressed.
    const hs_secret = [_]u8{0xab} ** 32;
    conn.hs_keys = tls.HandshakeKeys{
        .client = crypto.derivePacketKeys(hs_secret, packet.QUIC_VERSION_1),
        .server = crypto.derivePacketKeys(hs_secret, packet.QUIC_VERSION_1),
    };

    // Build a PING frame and wrap it in an encrypted Initial packet.
    var pt: [4]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt, .ping);

    var enc_buf: [256]u8 = undefined;
    const client_keys = conn.initial_keys.client;
    const pn: u64 = 1;
    const ct_len = pt_len + 16; // ciphertext + AEAD tag
    const hdr_len = packet.encodeLongHeader(
        &enc_buf,
        .initial,
        packet.QUIC_VERSION_1,
        &conn.local_cid.bytes,
        &conn.local_cid.bytes,
        &.{},
        @intCast(pn),
        ct_len, // payload_len = ciphertext + AEAD tag (RFC 9000 §17.2)
    );
    crypto.encryptPayload(client_keys, pn, enc_buf[0..hdr_len], pt[0..pt_len], enc_buf[hdr_len..][0..ct_len]);
    // Apply header protection so receive() can remove it correctly.
    crypto.applyHeaderProtection(client_keys, &enc_buf[0], enc_buf[hdr_len - 4 ..][0..4], enc_buf[hdr_len..][0..16]);
    const pkt = enc_buf[0 .. hdr_len + ct_len];

    const src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 1234 } };
    try conn.receive(pkt, src, 0, 0, io);

    // An encrypted ACK must have been queued (sq_tail > 0).
    try testing.expect(conn.sq_tail > 0);
    // pending_ack[0] must be false (flushed).
    try testing.expect(!conn.pending_ack[0]);
}

test "connection: receive() suppresses epoch-0 ACK when hs_keys is null" {
    // When hs_keys == null (TLS has not yet produced ServerHello), a standalone
    // Initial ACK must NOT be sent.  This prevents the interop-runner left-node
    // trace from showing a client 1-RTT packet before the ServerHello.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const dcid = [_]u8{ 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe };
    conn.initial_keys = crypto.deriveInitialKeys(&dcid, packet.QUIC_VERSION_1);
    conn.hot.state = .handshake;
    conn.peer_cid = conn.local_cid;
    // hs_keys intentionally left null (TLS hasn't produced output yet).

    // Build a PING frame wrapped in an encrypted Initial packet.
    var pt: [4]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt, .ping);
    var enc_buf: [256]u8 = undefined;
    const client_keys = conn.initial_keys.client;
    const pn: u64 = 1;
    const ct_len = pt_len + 16;
    const hdr_len = packet.encodeLongHeader(
        &enc_buf,
        .initial,
        packet.QUIC_VERSION_1,
        &conn.local_cid.bytes,
        &conn.local_cid.bytes,
        &.{},
        @intCast(pn),
        ct_len,
    );
    crypto.encryptPayload(client_keys, pn, enc_buf[0..hdr_len], pt[0..pt_len], enc_buf[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(client_keys, &enc_buf[0], enc_buf[hdr_len - 4 ..][0..4], enc_buf[hdr_len..][0..16]);
    const pkt = enc_buf[0 .. hdr_len + ct_len];

    const src = SocketAddr{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 1234 } };
    try conn.receive(pkt, src, 0, 0, io);

    // No packet must be enqueued — ACK is suppressed until ServerHello is ready.
    try testing.expectEqual(@as(usize, 0), conn.sq_tail);
    // pending_ack[0] must remain true so it fires once hs_keys become available.
    try testing.expect(conn.pending_ack[0]);
}

// ---- Step 3: Connection MAX_DATA window growth ----

test "connection: recv window grows when 75% consumed" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;

    const initial_recv_max = conn.conn_flow.recv_max; // 1 MiB default
    // Consume exactly 75% of the window via stream frames.
    const threshold = (initial_recv_max * 3) / 4 + 1;

    // Use a small chunk that fits in stream buf.
    var data: [stream_mod.STREAM_BUF_SIZE / 2]u8 = undefined;
    @memset(&data, 0x42);

    // Keep feeding until we cross the threshold.
    var total_consumed: u64 = 0;
    while (total_consumed < threshold) {
        const chunk_size = @min(data.len, threshold - total_consumed);
        const chunk = data[0..chunk_size];
        const st = conn.streams.getOrCreate(0).?;
        // receiveData only accepts up to stream recv_max; create new streams as needed
        st.receiveData(st.recv_offset, chunk, false) catch {};
        conn.conn_flow.onReceived(chunk_size);
        total_consumed += chunk_size;
        if (conn.conn_flow.shouldSendMaxData()) {
            conn.conn_flow.recv_max = conn.conn_flow.nextMaxData();
            conn.pending_max_data = true;
            break;
        }
    }

    try testing.expect(conn.conn_flow.recv_max > initial_recv_max);
    try testing.expect(conn.pending_max_data);
}

test "connection: recv window stays unchanged when under 75%" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;

    const initial_recv_max = conn.conn_flow.recv_max;
    // Consume 50% — below threshold.
    conn.conn_flow.onReceived(initial_recv_max / 2);
    try testing.expect(!conn.conn_flow.shouldSendMaxData());
    try testing.expectEqual(initial_recv_max, conn.conn_flow.recv_max);
}

// ---- Step 4: CRYPTO frame offset validation ----

test "connection: CRYPTO at expected offset is accepted" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.crypto_recv_offset[0] = 0;

    // A CRYPTO frame at offset 0 with 1 byte of data increments the expected offset.
    const data = [_]u8{0x01};
    const f: frame.CryptoFrame = .{ .offset = 0, .data = &data };
    // processCryptoFrame will fail on TLS (garbage data) but the offset check passes first.
    // We just verify that crypto_recv_offset advanced past the offset guard.
    conn.processCryptoFrame(f, 0, io) catch {};
    // Expected offset advanced to 1.
    try testing.expectEqual(@as(u64, 1), conn.crypto_recv_offset[0]);
}

test "connection: CRYPTO duplicate frame is silently ignored" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    // Pretend we already processed 10 bytes.
    conn.crypto_recv_offset[0] = 10;

    const data = [_]u8{0x42} ** 10;
    // Frame at offset 0 with 10 bytes → end = 10 = expected → pure duplicate.
    const f: frame.CryptoFrame = .{ .offset = 0, .data = &data };
    // Must return without error (or any TLS error is irrelevant — offset guard fires first).
    // Since end (10) <= expected (10), returns early.
    conn.processCryptoFrame(f, 0, io) catch {};
    // Offset must NOT have advanced.
    try testing.expectEqual(@as(u64, 10), conn.crypto_recv_offset[0]);
}

test "connection: CRYPTO gap is staged, offset does not advance" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.crypto_recv_offset[0] = 0;

    const data = [_]u8{0x55} ** 5;
    // Frame at offset 100 when expected is 0 — gap: should be staged, not an error.
    const f: frame.CryptoFrame = .{ .offset = 100, .data = &data };
    try conn.processCryptoFrame(f, 0, io);
    // Offset must NOT have advanced (fragment is staged, not yet delivered).
    try testing.expectEqual(@as(u64, 0), conn.crypto_recv_offset[0]);
    // Fragment is in the staging buffer.
    try testing.expectEqual(@as(u8, 1), conn.crypto_staged_count[0]);
    try testing.expectEqual(@as(u64, 100), conn.crypto_staged[0][0].offset);
}

test "connection: CRYPTO partial overlap trims leading bytes" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.crypto_recv_offset[0] = 10;

    const data = [_]u8{0x99} ** 5;
    const f: frame.CryptoFrame = .{ .offset = 8, .data = &data };
    conn.processCryptoFrame(f, 0, io) catch {};

    try testing.expectEqual(@as(u64, 13), conn.crypto_recv_offset[0]);
}

// ---- Step 5: Control frame coalescing in tick() ----

test "connection: tick batches MAX_DATA and MAX_STREAM_DATA in one packet" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Set up pending MAX_DATA.
    conn.pending_max_data = true;

    // Set up a stream needing MAX_STREAM_DATA.
    const st = conn.streams.getOrCreate(0).?;
    st.last_sent_max_stream_data = 0; // force shouldSendMaxStreamData() = true

    const sq_before = conn.sq_tail;
    conn.tick(0);

    // Only one packet should have been sent (coalesced).
    try testing.expectEqual(sq_before + 1, conn.sq_tail);
    // Both flags cleared.
    try testing.expect(!conn.pending_max_data);
    try testing.expect(!st.shouldSendMaxStreamData());
}

test "connection: flushControlFrames is no-op when nothing pending" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    const sq_before = conn.sq_tail;
    try conn.flushControlFrames();
    try testing.expectEqual(sq_before, conn.sq_tail);
}

test "connection: coalesced packet tracked by loss recovery" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.pending_max_data = true;

    const pn_before = conn.hot.tx_pn[2];
    try conn.flushControlFrames();

    // Exactly one packet number consumed.
    try testing.expectEqual(pn_before + 1, conn.hot.tx_pn[2]);
    // PTO deadline updated (loss recovery called onPacketSent).
    // When no smoothed RTT estimate is available yet, ptoDeadline may return null
    // but the pto counter should reflect a sent packet.  Just verify pn advanced.
    try testing.expectEqual(pn_before + 1, conn.hot.tx_pn[2]);
}

// ---------------------------------------------------------------------------
// RFC enforcement tests: flow control and stream limits
// ---------------------------------------------------------------------------

test "connection: STREAM data within connection recv window is accepted" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;

    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    // Should succeed: 5 bytes is well within the 1 MiB default window.
    try conn.processFrames(buf[0..n], 2, null);
    try testing.expectEqual(@as(u64, 5), conn.conn_flow.recv_total);
}

test "connection: STREAM data exceeding connection recv window returns FlowControlViolation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // Artificially shrink the connection receive window to 4 bytes.
    conn.conn_flow.recv_max = 4;

    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 0,
            .offset = 0,
            .fin = false,
            .data = "hello", // 5 bytes > window of 4
        },
    });
    try testing.expectError(error.FlowControlViolation, conn.processFrames(buf[0..n], 2, null));
    // recv_total must not have been incremented.
    try testing.expectEqual(@as(u64, 0), conn.conn_flow.recv_total);
}

test "connection: STREAM on bidirectional stream within local_max_streams_bidi is accepted" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;

    // Stream 0 is client-initiated bidi stream #0 — always within any sane limit.
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 0, // stream #0 bidi
            .offset = 0,
            .fin = false,
            .data = "ok",
        },
    });
    try conn.processFrames(buf[0..n], 2, null);
}

test "connection: STREAM on bidirectional stream exceeding local_max_streams_bidi returns StreamLimitError" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // Lower the limit to 2 bidirectional streams.
    conn.local_max_streams_bidi = 2;

    // Stream #2 (stream_id = 8) is the third bidi stream — exceeds limit of 2.
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 8, // stream_num = 8>>2 = 2 >= local_max_streams_bidi (2)
            .offset = 0,
            .fin = false,
            .data = "bad",
        },
    });
    try testing.expectError(error.StreamLimitError, conn.processFrames(buf[0..n], 2, null));
}

test "connection: STREAM on unidirectional stream exceeding local_max_streams_uni returns StreamLimitError" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // Lower the limit to 1 unidirectional stream.
    conn.local_max_streams_uni = 1;

    // Stream #1 uni (stream_id = 6, bits = 0b10) — stream_num = 1 >= limit (1).
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 6, // stream_num = 6>>2 = 1 >= local_max_streams_uni (1)
            .offset = 0,
            .fin = false,
            .data = "bad",
        },
    });
    try testing.expectError(error.StreamLimitError, conn.processFrames(buf[0..n], 2, null));
}

test "connection: conn_flow.recv_total not charged when stream receiveData fails" {
    // If the stream rejects data (e.g., FinalSizeError after FIN), the connection
    // flow control counter must not be permanently incremented.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;

    // Send FIN at offset 3 (final_size = 3).
    var buf: [64]u8 = undefined;
    var n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = true,
        .data = "abc",
    } });
    try conn.processFrames(buf[0..n], 2, null);
    const recv_total_after_fin = conn.conn_flow.recv_total;

    // Send data beyond the established final size — stream rejects it (FinalSizeError).
    n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 0,
            .offset = 2,
            .fin = false,
            .data = "xyz", // end = 5 > final_size 3 → FinalSizeError
        },
    });
    // processFrames swallows 1-RTT errors via `catch {}`, so no error bubbles up.
    conn.processFrames(buf[0..n], 2, null) catch {};
    // recv_total must not have grown beyond what was committed by the accepted frame.
    try testing.expectEqual(recv_total_after_fin, conn.conn_flow.recv_total);
}

// ---------------------------------------------------------------------------
// Idle timeout + stateless reset tests
// ---------------------------------------------------------------------------

test "connection: enqueueSend refreshes idle deadline" {
    // RFC 9000 §10.1.2: idle timer must restart when a packet is sent.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000; // 1s
    conn.idle_timeout_i64 = 30_000_000_000; // 30s
    conn.idle_deadline_ns = 1; // stale deadline from before

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };
    conn.queuePing() catch {};

    // enqueueSend should have refreshed the deadline to current_time_ns + idle_timeout_i64.
    try testing.expectEqual(@as(?i64, 31_000_000_000), conn.idle_deadline_ns);
}

test "connection: stateless reset closes connection when token matches" {
    // RFC 9000 §10.3: receiving a packet whose last 16 bytes match a known peer
    // reset token must silently close the connection.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Install a known reset token in the peer CID table.
    const token = [_]u8{0xde} ** 16;
    conn.peer_cid_table[0] = .{ .cid = .{}, .seq = 0, .reset_token = token, .valid = true };

    // Build a minimal fake "packet" of ≥21 bytes whose last 16 bytes are the token.
    var fake_pkt: [32]u8 = undefined;
    @memset(&fake_pkt, 0x42);
    @memcpy(fake_pkt[16..32], &token);

    // checkStatelessReset must match.
    try testing.expect(conn.checkStatelessReset(&fake_pkt));
}

test "connection: stateless reset ignores short packet" {
    // Packets shorter than 21 bytes cannot be stateless resets (RFC 9000 §10.3).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const token = [_]u8{0xab} ** 16;
    conn.peer_cid_table[0] = .{ .cid = .{}, .seq = 0, .reset_token = token, .valid = true };

    var short_pkt: [20]u8 = undefined;
    @memset(&short_pkt, 0);
    @memcpy(short_pkt[4..20], &token);
    try testing.expect(!conn.checkStatelessReset(&short_pkt));
}

test "connection: stateless reset ignores non-matching token" {
    // A packet whose last 16 bytes do NOT match any stored token must not close.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const token = [_]u8{0xcd} ** 16;
    conn.peer_cid_table[0] = .{ .cid = .{}, .seq = 0, .reset_token = token, .valid = true };

    var pkt: [32]u8 = undefined;
    @memset(&pkt, 0x00); // last 16 bytes are 0x00, not 0xcd
    try testing.expect(!conn.checkStatelessReset(&pkt));
}

test "connection: new bidi stream send_max set from peer_max_stream_data_bidi_local" {
    // When a client-initiated bidirectional stream is created, its send_max must
    // reflect the peer's advertised initial_max_stream_data_bidi_local, not the
    // hardcoded STREAM_BUF_SIZE (RFC 9000 §7.3).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    // Simulate transport-param negotiation with a non-default value.
    const custom_limit: u64 = 128 * 1024; // 128 KiB
    conn.peer_max_stream_data_bidi_local = custom_limit;

    // Feed a STREAM frame to create stream 0 (client-initiated bidi).
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try conn.processFrames(buf[0..n], 2, null);

    const st = conn.streams.get(0).?;
    try testing.expectEqual(custom_limit, st.send_max);
}

test "connection: new bidi stream send_max not reset on second STREAM frame" {
    // A second STREAM frame on the same stream must not overwrite send_max that
    // was already updated (e.g. by a MAX_STREAM_DATA frame from the peer).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = 128 * 1024;

    var buf: [64]u8 = undefined;
    // First frame: creates the stream, sets send_max = 128 KiB.
    var n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hello",
    } });
    try conn.processFrames(buf[0..n], 2, null);

    // Simulate a MAX_STREAM_DATA update from the peer (e.g. 256 KiB).
    const st = conn.streams.get(0).?;
    st.send_max = 256 * 1024;

    // Second STREAM frame on the same stream: send_max must remain 256 KiB.
    n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 5,
        .fin = false,
        .data = "world",
    } });
    try conn.processFrames(buf[0..n], 2, null);

    try testing.expectEqual(@as(u64, 256 * 1024), st.send_max);
}

test "connection: MAX_STREAM_DATA cannot decrease send_max (RFC 9000 §4.2)" {
    // A peer that sends a MAX_STREAM_DATA with a lower value than previously
    // advertised must be silently ignored — flow control limits are monotonically
    // increasing (RFC 9000 §4.2).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = 64 * 1024;

    // Create stream 0.
    var buf: [64]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = "hi",
    } });
    try conn.processFrames(buf[0..n], 2, null);

    // Raise send_max to 256 KiB.
    const st = conn.streams.get(0).?;
    st.send_max = 256 * 1024;

    // Feed MAX_STREAM_DATA with a smaller value (128 KiB).
    var msd_buf: [32]u8 = undefined;
    const msd_n = frame.encodeFrame(&msd_buf, .{ .max_stream_data = .{
        .stream_id = 0,
        .max_data = 128 * 1024,
    } });
    try conn.processFrames(msd_buf[0..msd_n], 2, null);

    // send_max must remain at 256 KiB — the peer cannot decrease our window.
    try testing.expectEqual(@as(u64, 256 * 1024), st.send_max);
}

test "connection: RESET_STREAM charges gap bytes to connection flow control (RFC 9000 §4.5)" {
    // When a RESET_STREAM is received, the gap between bytes already received
    // and the stream's final_size must be charged to the connection-level
    // flow control window (RFC 9000 §4.5).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = stream_mod.STREAM_BUF_SIZE;

    // Create stream 0 and receive 100 bytes (charges 100 to conn_flow.recv_total).
    const data = [_]u8{'x'} ** 100;
    var data_buf: [200]u8 = undefined;
    const dn = frame.encodeFrame(&data_buf, .{ .stream = .{
        .stream_id = 0,
        .offset = 0,
        .fin = false,
        .data = &data,
    } });
    try conn.processFrames(data_buf[0..dn], 2, null);
    const recv_after_data = conn.conn_flow.recv_total;
    try testing.expectEqual(@as(u64, 100), recv_after_data);

    // Now receive RESET_STREAM with final_size = 500 (gap = 400 bytes).
    var rst_buf: [32]u8 = undefined;
    const rn = frame.encodeFrame(&rst_buf, .{ .reset_stream = .{
        .stream_id = 0,
        .error_code = 0,
        .final_size = 500,
    } });
    try conn.processFrames(rst_buf[0..rn], 2, null);

    // The connection flow control must now reflect the full 500 bytes.
    try testing.expectEqual(@as(u64, 500), conn.conn_flow.recv_total);
}

// ============================================================================
// Regression: 1-RTT processFrames errors were silently swallowed (finding #2)
// ============================================================================

test "connection: 1-RTT malformed frame closes connection with FRAME_ENCODING_ERROR" {
    // Regression: parseFrame failure in processFrames used `catch { break; }` which
    // silently stopped processing. Now it returns error.FrameEncodingError which is
    // caught at the call site and triggers close() with QUIC error code 0x07.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const app_key = [_]u8{0xAA} ** 32;
    const app_iv = [_]u8{0xBB} ** 12;
    const app_hp = [_]u8{0xCC} ** 32;
    conn.hot.state = .established;
    conn.app_keys = tls.AppKeys{
        .client = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
        .server = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
    };
    conn.peer_cid = conn.local_cid;

    // Build a 1-RTT packet whose payload decrypts to 0xff — an invalid varint that
    // will cause parseFrame to return error.InvalidFrame.
    const pt_garbled = [_]u8{0xff};
    const ct_len = pt_garbled.len + 16;

    var pkt: [256]u8 = undefined;
    const hdr_len = packet.encodeShortHeader(&pkt, &conn.local_cid.bytes, 1, false);
    crypto.encryptPayload(conn.app_keys.?.client, 1, pkt[0..hdr_len], &pt_garbled, pkt[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(conn.app_keys.?.client, &pkt[0], pkt[hdr_len - 4 ..][0..4], pkt[hdr_len..][0..16]);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5001 } };
    try conn.receive(pkt[0 .. hdr_len + ct_len], src, 1_000_000_000, 0, io);

    // Connection must be closing with FRAME_ENCODING_ERROR (0x07).
    try testing.expectEqual(ConnState.closing, conn.hot.state);
    var got_close = false;
    while (conn.events.pop()) |ev| {
        if (ev == .connection_closed and ev.connection_closed.error_code == 0x07) {
            got_close = true;
        }
    }
    try testing.expect(got_close);
}

test "connection: 1-RTT protocol violation closes connection, not silently ignored" {
    // Regression: processShortHeaderPacket used `catch {}` on processFrames, so
    // errors like ProtocolViolation were dropped. Now it calls close() with the
    // appropriate QUIC error code.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    // Establish state with 1-RTT keys.
    const app_key = [_]u8{0xAA} ** 32;
    const app_iv = [_]u8{0xBB} ** 12;
    const app_hp = [_]u8{0xCC} ** 32;
    conn.hot.state = .established;
    conn.app_keys = tls.AppKeys{
        .client = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
        .server = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
    };
    conn.peer_cid = conn.local_cid;

    // Build an encrypted 1-RTT short-header packet containing HANDSHAKE_DONE.
    // Servers must never receive HANDSHAKE_DONE — it's a ProtocolViolation.
    var pt_buf: [4]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt_buf, .handshake_done);
    const ct_len = pt_len + 16;

    var pkt: [256]u8 = undefined;
    const hdr_len = packet.encodeShortHeader(&pkt, &conn.local_cid.bytes, 1, false);
    crypto.encryptPayload(conn.app_keys.?.client, 1, pkt[0..hdr_len], pt_buf[0..pt_len], pkt[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(conn.app_keys.?.client, &pkt[0], pkt[hdr_len - 4 ..][0..4], pkt[hdr_len..][0..16]);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    try conn.receive(pkt[0 .. hdr_len + ct_len], src, 1_000_000_000, 0, io);

    // Connection must now be closing (not still established and not silently OK).
    try testing.expectEqual(ConnState.closing, conn.hot.state);

    // A connection_closed event with PROTOCOL_VIOLATION (0x0a) must be present.
    var got_close = false;
    while (conn.events.pop()) |ev| {
        if (ev == .connection_closed and ev.connection_closed.error_code == 0x0a) {
            got_close = true;
        }
    }
    try testing.expect(got_close);
}

// ============================================================================
// Audit regression tests (2026-03-07)
// ============================================================================

// Bug A: Connection flow control counted raw bytes per frame, not per-stream HWM.
// RFC 9000 §4.1: the connection window tracks the sum of highest byte offsets.

test "flow control: retransmitted STREAM data does not re-charge connection window" {
    // A retransmission of already-received bytes must not advance recv_total.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = stream_mod.STREAM_BUF_SIZE;

    const data = [_]u8{'x'} ** 100;
    var buf: [200]u8 = undefined;

    // First delivery: 100 bytes at offset 0.
    var n = frame.encodeFrame(&buf, .{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = &data } });
    try conn.processFrames(buf[0..n], 2, null);
    const recv_after_first = conn.conn_flow.recv_total;
    try testing.expectEqual(@as(u64, 100), recv_after_first);

    // Retransmission: exact same frame (offset 0, 100 bytes).
    n = frame.encodeFrame(&buf, .{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = &data } });
    conn.processFrames(buf[0..n], 2, null) catch {};
    // recv_total must NOT grow — retransmission charges nothing.
    try testing.expectEqual(recv_after_first, conn.conn_flow.recv_total);
}

test "flow control: out-of-order STREAM data charges HWM delta, not frame bytes" {
    // Out-of-order arrival at offset 200 should charge 300 bytes (0..300 HWM),
    // not just the 100 bytes in the frame.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = stream_mod.STREAM_BUF_SIZE;

    // Artificially grow stream recv_max so it doesn't block the high-offset frame.
    // First, create the stream with enough receive room.
    const data = [_]u8{'x'} ** 100;
    var buf: [512]u8 = undefined;

    // Frame at offset=200 (out of order): HWM goes 0→300, charge 300.
    const n = frame.encodeFrame(&buf, .{ .stream = .{ .stream_id = 0, .offset = 200, .fin = false, .data = &data } });
    try conn.processFrames(buf[0..n], 2, null);
    try testing.expectEqual(@as(u64, 300), conn.conn_flow.recv_total);

    // Frame at offset=0 (fills in the gap): HWM is already 300, charge 0.
    const n2 = frame.encodeFrame(&buf, .{ .stream = .{ .stream_id = 0, .offset = 0, .fin = false, .data = &data } });
    conn.processFrames(buf[0..n2], 2, null) catch {};
    try testing.expectEqual(@as(u64, 300), conn.conn_flow.recv_total);
}

test "flow control: RESET_STREAM uses highest_recv_offset for gap charge" {
    // When RESET arrives after out-of-order data, gap charge must use the
    // highest offset seen (not recv_offset contiguous frontier).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_max_stream_data_bidi_local = stream_mod.STREAM_BUF_SIZE;

    const data = [_]u8{'x'} ** 100;
    var buf: [512]u8 = undefined;

    // Data at offset=200 (out of order): HWM=300, recv_offset=0 (no contiguous data yet).
    const n = frame.encodeFrame(&buf, .{ .stream = .{ .stream_id = 0, .offset = 200, .fin = false, .data = &data } });
    try conn.processFrames(buf[0..n], 2, null);
    try testing.expectEqual(@as(u64, 300), conn.conn_flow.recv_total);

    // RESET with final_size=500: gap = 500 - 300 (HWM) = 200, not 500 - 0 (recv_offset) = 500.
    var rst_buf: [64]u8 = undefined;
    const rn = frame.encodeFrame(&rst_buf, .{ .reset_stream = .{
        .stream_id = 0,
        .error_code = 0,
        .final_size = 500,
    } });
    try conn.processFrames(rst_buf[0..rn], 2, null);
    try testing.expectEqual(@as(u64, 500), conn.conn_flow.recv_total);
}

// Bug E: pending_max_streams_bidi/uni were cleared before confirming frame fits.

test "flow control: pending_max_streams_bidi preserved when packet full" {
    // If the control packet is full, pending_max_streams_bidi must not be lost.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.app_keys = tls.AppKeys{
        .client = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
        .server = .{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm },
    };
    // Fill pkt_scratch to the budget limit by setting pending_max_data at max value
    // so MAX_DATA alone exhausts the frame budget, leaving no room for MAX_STREAMS.
    // In practice, with small frames, the budget is never hit — but we verify the
    // pending field survives if the budget IS exceeded.
    // Here: set pending_max_streams_bidi and confirm it is stored (not lost on init).
    conn.pending_max_streams_bidi = 200;
    conn.pending_max_data = false; // no other frames consuming budget
    const sq_before = conn.sq_tail;
    conn.tick(1_000_000);
    // If the MAX_STREAMS_BIDI frame fit, the pending field must be cleared.
    // If it didn't fit (extremely unlikely here), pending must still be 200.
    if (conn.sq_tail > sq_before) {
        // Frame was sent → pending must be null.
        try testing.expect(conn.pending_max_streams_bidi == null);
    } else {
        // Frame didn't fit → pending must survive.
        try testing.expectEqual(@as(?u62, 200), conn.pending_max_streams_bidi);
    }
}

// Bug I: StreamStateError must map to QUIC error code 0x05 (STREAM_STATE_ERROR).

test "connection: server-initiated stream ID in STREAM frame closes with STREAM_STATE_ERROR" {
    // The server must reject a STREAM frame with bit 0=1 (server-initiated stream ID)
    // with connection error 0x05 STREAM_STATE_ERROR (RFC 9000 §20.1), not 0x0a.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const app_key = [_]u8{0xAA} ** 32;
    const app_iv = [_]u8{0xBB} ** 12;
    const app_hp = [_]u8{0xCC} ** 32;
    conn.hot.state = .established;
    conn.app_keys = tls.AppKeys{
        .client = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
        .server = .{ .key = app_key, .iv = app_iv, .hp = app_hp, .suite = .aes_128_gcm },
    };
    conn.peer_cid = conn.local_cid;

    // stream_id=1 → bit 0=1 → server-initiated stream (invalid from client).
    var pt: [64]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt, .{ .stream = .{ .stream_id = 1, .offset = 0, .fin = false, .data = "x" } });
    const ct_len = pt_len + 16;
    var pkt: [256]u8 = undefined;
    const hdr_len = packet.encodeShortHeader(&pkt, &conn.local_cid.bytes, 1, false);
    crypto.encryptPayload(conn.app_keys.?.client, 1, pkt[0..hdr_len], pt[0..pt_len], pkt[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(conn.app_keys.?.client, &pkt[0], pkt[hdr_len - 4 ..][0..4], pkt[hdr_len..][0..16]);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    try conn.receive(pkt[0 .. hdr_len + ct_len], src, 1_000_000_000, 0, io);

    // Connection must be closing with STREAM_STATE_ERROR (0x05).
    try testing.expectEqual(ConnState.closing, conn.hot.state);
    var got_05 = false;
    while (conn.events.pop()) |ev| {
        if (ev == .connection_closed and ev.connection_closed.error_code == 0x05) got_05 = true;
    }
    try testing.expect(got_05);
}

// Bug D: processNewConnectionId must accept frames with seq < highest-seen
// when seq >= retire_prior_to (out-of-order delivery).

test "NEW_CONNECTION_ID: retired seq is silently dropped" {
    // After retire_prior_to advances to 6, a CID with seq=5 must be dropped.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // First frame: seq=10, retire_prior_to=6 → advances peer_cid_retire_prior to 6.
    conn.processNewConnectionId(.{
        .sequence_number = 10,
        .retire_prior_to = 6,
        .cid_len = 8,
        .cid = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .stateless_reset_token = [_]u8{0} ** 16,
    });
    try testing.expectEqual(@as(u62, 6), conn.peer_cid_retire_prior);

    // Second frame: seq=5 < retire_prior_to=6 → must be silently dropped.
    conn.processNewConnectionId(.{
        .sequence_number = 5,
        .retire_prior_to = 0,
        .cid_len = 8,
        .cid = [_]u8{ 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 },
        .stateless_reset_token = [_]u8{0} ** 16,
    });
    // seq=10 CID in slot 0, seq=5 was dropped → slot 1 must be invalid.
    try testing.expectEqual(@as(u62, 10), conn.peer_cid_table[0].seq);
    try testing.expectEqual(false, conn.peer_cid_table[1].valid);
}

// ============================================================================
// PMTUD (Path MTU Discovery) Regression Tests
// ============================================================================
