//! Tests for Connection — Path MTU Discovery (PMTUD), token generation
//! and validation, and Retry packet handling.
const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const Config = conn_mod.Config;
const Event = conn_mod.Event;
const SocketAddr = conn_mod.SocketAddr;
const frame = @import("frame.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const tls = @import("tls.zig");
const packet = @import("packet.zig");
const cid_mod = @import("connection_id.zig");
const ConnectionId = cid_mod.ConnectionId;
const crypto = @import("crypto.zig");
const transport_params = @import("transport_params.zig");

test "PMTUD: getNextPmtudSize probe sequence" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Test initial sequence: 1200 → 1500 → 2048 → 4096
    conn.path_mtu = 1200;
    try testing.expectEqual(@as(u16, 1500), conn.getNextPmtudSize());

    conn.path_mtu = 1500;
    try testing.expectEqual(@as(u16, 2048), conn.getNextPmtudSize());

    conn.path_mtu = 2048;
    try testing.expectEqual(@as(u16, 4096), conn.getNextPmtudSize());

    // Test exponential growth beyond 4096 (the critical fix)
    conn.path_mtu = 4096;
    try testing.expectEqual(@as(u16, 8192), conn.getNextPmtudSize());

    conn.path_mtu = 8192;
    try testing.expectEqual(@as(u16, 16384), conn.getNextPmtudSize());

    // Test saturation at 65535 (max u16)
    conn.path_mtu = 32768;
    try testing.expectEqual(@as(u16, 65535), conn.getNextPmtudSize());

    conn.path_mtu = 65535;
    try testing.expectEqual(@as(u16, 65535), conn.getNextPmtudSize());
}

test "PMTUD: queuePmtudProbe succeeds when conditions are met" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    // Setup 1-RTT keys (required for probing)
    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Attempt to queue a probe at valid size (within MAX_PACKET_SIZE=1200)
    try conn.queuePmtudProbe(1200);

    // Verify probe is tracked
    try testing.expect(conn.pmtud_probing != null);
    try testing.expectEqual(@as(u16, 1200), conn.pmtud_probing.?.target_size);
    try testing.expectEqual(@as(u64, 0), conn.pmtud_probing.?.packet_number); // first pn
    try testing.expectEqual(@as(u2, 2), conn.pmtud_probing.?.epoch); // 1-RTT
    try testing.expectEqual(@as(i64, 1_000_000_000), conn.pmtud_probing.?.sent_ns);
}

test "PMTUD: queuePmtudProbe rejects invalid sizes" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Reject too-small size (< 1200)
    try testing.expectError(error.InvalidSize, conn.queuePmtudProbe(1199));
    try testing.expectError(error.InvalidSize, conn.queuePmtudProbe(0));

    // Verify max valid size within MAX_SEND_PACKET_SIZE (1452) is allowed
    try conn.queuePmtudProbe(1452);

    // Sizes beyond MAX_SEND_PACKET_SIZE are rejected
    try testing.expectError(error.PacketTooLarge, conn.queuePmtudProbe(1453));
}

test "PMTUD: queuePmtudProbe rejects when no 1-RTT keys" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    // No app_keys set

    // Reject because we're not in 1-RTT
    try testing.expectError(error.InvalidState, conn.queuePmtudProbe(1500));
}

test "PMTUD: queuePmtudProbe initiates and stores probe info" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Manually initiate a probe at valid size
    try conn.queuePmtudProbe(1200);

    // Verify probe was started with correct target and timestamp
    try testing.expect(conn.pmtud_probing != null);
    try testing.expectEqual(@as(u16, 1200), conn.pmtud_probing.?.target_size);
    try testing.expectEqual(conn.current_time_ns, conn.pmtud_probing.?.sent_ns);
}

test "PMTUD: probe timeout detected at 3×PTO without ACK" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.cached_max_ack_delay_ns = 25_000_000; // 25ms

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Manually initiate probe at maximum valid size (1200)
    try conn.queuePmtudProbe(1200);

    // Calculate PTO (initial RTT is 1 second by default)
    const pto_ns = conn.loss.rtt.ptoBase(conn.cached_max_ack_delay_ns); // ~1s + margin

    // Fast forward past 3×PTO
    conn.tick(conn.current_time_ns + @as(i64, @intCast(pto_ns * 3)) + 1_000_000);

    // Verify probe was cleared. At RFC minimum (1200), binary search stays at 1200.
    try testing.expectEqual(@as(u16, 1200), conn.path_mtu);
    try testing.expect(conn.pmtud_probing == null);
}

test "PMTUD: ACK detection marks probe as successful" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Manually initiate probe at valid size
    try conn.queuePmtudProbe(1200);
    const probe_pn = conn.pmtud_probing.?.packet_number;

    // Simulate receiving an ACK that includes the probe packet number
    var ack_buf: [64]u8 = undefined;
    const ack_len = frame.encodeFrame(&ack_buf, .{
        .ack = .{
            .largest_acked = @intCast(probe_pn),
            .ack_delay = 0,
            .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        },
    });

    try conn.processFrames(ack_buf[0..ack_len], 2, null);

    // Verify probe was marked successful and path_mtu updated to probed size
    try testing.expectEqual(@as(u16, 1200), conn.path_mtu);
    try testing.expect(conn.pmtud_probing == null);
}

test "PMTUD: does not backoff on ACK with gap containing probe" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;
    conn.cached_max_ack_delay_ns = 25_000_000;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Initiate probe at valid size
    try conn.queuePmtudProbe(1200);
    const probe_pn = conn.pmtud_probing.?.packet_number;

    // Send another packet to have something larger to ACK
    conn.queuePing() catch {}; // pn = probe_pn + 1

    // ACK packet after probe but not the probe itself (probe is in the gap)
    var ack_buf: [64]u8 = undefined;
    const ack_len = frame.encodeFrame(&ack_buf, .{
        .ack = .{
            .largest_acked = @intCast(probe_pn + 1),
            .ack_delay = 0,
            .ranges = [_]frame.AckRange{.{ .gap = 1, .ack_range = 0 }} ** 32,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        },
    });

    const initial_mtu = conn.path_mtu;
    try conn.processFrames(ack_buf[0..ack_len], 2, null);

    // Verify probe is still in flight (not incorrectly marked as lost)
    // Path MTU should NOT have changed
    try testing.expectEqual(initial_mtu, conn.path_mtu);
    try testing.expect(conn.pmtud_probing != null);
}

test "PMTUD: does not backoff on ACK with unreachable packet" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Queue a small probe manually
    try conn.queuePmtudProbe(1200);
    const probe_pn = conn.pmtud_probing.?.packet_number;
    // Queue a second packet so we have a valid target to ACK (probe_pn + 1).
    conn.queuePing() catch {};

    // ACK a different packet (not the probe) — largest_acked is the ping, not the PMTUD probe.
    var ack_buf: [64]u8 = undefined;
    const ack_len = frame.encodeFrame(&ack_buf, .{
        .ack = .{
            .largest_acked = @intCast(probe_pn + 1), // ACK packet after probe, not the probe itself
            .ack_delay = 0,
            .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        },
    });

    const initial_mtu = conn.path_mtu;
    try conn.processFrames(ack_buf[0..ack_len], 2, null);

    // Probe should still be in flight (no false loss detection)
    try testing.expect(conn.pmtud_probing != null);
    try testing.expectEqual(initial_mtu, conn.path_mtu);
}

test "PMTUD: probe disabled during handshake" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.pmtud_next_probe_ns = 0;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    // No app_keys, not established
    try testing.expectEqual(.idle, conn.hot.state);
    try testing.expect(conn.app_keys == null);

    conn.tick(conn.current_time_ns);

    // No probe should be initiated
    try testing.expect(conn.pmtud_probing == null);
    try testing.expectEqual(@as(u16, 1200), conn.path_mtu);
}

test "PMTUD: state machine: probe can only be initiated when none in flight" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Initiate probe manually
    try conn.queuePmtudProbe(1200);
    try testing.expect(conn.pmtud_probing != null);
    const first_pn = conn.pmtud_probing.?.packet_number;

    // Manually reset deadline; should not initiate new probe while one is in flight
    conn.pmtud_next_probe_ns = 0;
    conn.tick(conn.current_time_ns + 1_000_000);

    // Still only same probe in flight
    try testing.expect(conn.pmtud_probing != null);
    try testing.expectEqual(first_pn, conn.pmtud_probing.?.packet_number);
}

test "PMTUD: respects 1-second retry interval after failure" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.cached_max_ack_delay_ns = 25_000_000;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Initiate and timeout probe manually
    try conn.queuePmtudProbe(1200);
    const pto_ns = conn.loss.rtt.ptoBase(conn.cached_max_ack_delay_ns);
    conn.tick(conn.current_time_ns + @as(i64, @intCast(pto_ns * 3)) + 1_000_000);

    // Should not initiate new probe before 1 second
    const timeout_time = conn.current_time_ns;
    conn.tick(timeout_time + 500_000_000); // 0.5s later
    try testing.expect(conn.pmtud_probing == null);
    // Deadline should be set to 1s out from timeout_time
    try testing.expect(conn.pmtud_next_probe_ns >= timeout_time + 1_000_000_000);
}

test "PMTUD: 3×PTO timeout check uses saturating multiply (no overflow panic)" {
    // Regression test for connection.zig:668 — plain `3 * pto_ns` overflows u64 when
    // smoothed_rtt is large; `3 *| pto_ns` saturates to maxInt(u64) instead.
    // With the plain multiply the comparison wraps to a small value, incorrectly clearing
    // the probe. With saturation the comparison is always false for any real elapsed time.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.cached_max_ack_delay_ns = 0;

    // Set RTT so ptoBase() returns a value where 3 * ptoBase overflows u64.
    // maxInt(u64) / 3 + 1 = 6148914691236517206
    conn.loss.rtt.smoothed_rtt = std.math.maxInt(u64) / 3 + 1;
    conn.loss.rtt.rtt_var = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    try conn.queuePmtudProbe(1200);
    try testing.expect(conn.pmtud_probing != null);

    // Advance time by 10 seconds — a modest elapsed time. With the buggy plain multiply
    // the wrapped result would make the condition true and clear the probe. With the
    // saturating multiply the timeout threshold is maxInt(u64) and the probe stays alive.
    conn.tick(conn.current_time_ns + 10_000_000_000);

    try testing.expect(conn.pmtud_probing != null);
}

test "PMTUD: probe packet is marked ack-eliciting" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    // Queue probe at realistic size (< MAX_PACKET_SIZE)
    try conn.queuePmtudProbe(1200);

    // Verify it was registered in loss recovery as ack-eliciting
    // (The onPacketSent call in queuePmtudProbe passes true for ack_eliciting)
    try testing.expect(conn.pmtud_probing != null);
    const pn = conn.pmtud_probing.?.packet_number;

    // Look up in loss recovery to verify it was tracked
    const sent_pkt = conn.loss.sent.get(pn, 2); // epoch 2 = 1-RTT
    try testing.expect(sent_pkt != null);
}

test "PMTUD: doesn't probe if already at maximum" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 65535;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    conn.tick(conn.current_time_ns);

    // No probe should be initiated (next_size == path_mtu)
    try testing.expect(conn.pmtud_probing == null);
}

test "PMTUD: backoff on PacketTooLarge error" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    conn.tick(conn.current_time_ns);

    try testing.expectEqual(@as(u16, 1350), conn.path_mtu);
    try testing.expect(conn.pmtud_probing == null);
}

test "PMTUD: converges when probe size exceeds MAX_PACKET_SIZE" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };
    conn.pmtud_next_probe_ns = 0;

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    for (0..5) |i| {
        conn.tick(conn.current_time_ns + @as(i64, @intCast(i)) * 1_500_000_000);
    }

    try testing.expect(conn.path_mtu < 1400);
}

test "PMTUD: short header padding calculation is correct" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.path_mtu = 1200;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    try conn.queuePmtudProbe(1200);
    try testing.expectEqual(@as(u16, 1200), conn.pmtud_probing.?.target_size);
}

test "PMTUD: rejects probe size above MAX_PACKET_SIZE" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.peer_cid = .{ .bytes = [_]u8{0} ** 8 };

    const k = crypto.PacketKeys{ .key = [_]u8{0} ** 32, .iv = [_]u8{0} ** 12, .hp = [_]u8{0} ** 32, .suite = .aes_128_gcm };
    conn.app_keys = tls.AppKeys{ .client = k, .server = k };

    try conn.queuePmtudProbe(1452);
    try testing.expectError(error.PacketTooLarge, conn.queuePmtudProbe(1453));
}

test "token: valid token can be generated and validated" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Set token secret
    const secret = [_]u8{0xaa} ** 32;
    conn.config.token_secret = secret;

    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    // Generate token (pass DCID as slice)
    const token = conn.generateToken(src, &odcid.bytes, now_ns, io);
    try testing.expectEqual(@as(usize, Connection(16).TOKEN_SIZE), token.len);

    // Validate token immediately (should succeed, returns ValidatedToken)
    const result = conn.validateToken(&token, src, now_ns);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u8, cid_mod.len), result.?.len);
    try testing.expectEqualSlices(u8, &odcid.bytes, result.?.raw[0..cid_mod.len]);
}

test "token: expired token is rejected" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0xbb} ** 32;
    conn.config.token_secret = secret;
    conn.config.token_validity_ns = 60 * std.time.ns_per_s; // 60 seconds

    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    const token = conn.generateToken(src, &odcid.bytes, now_ns, io);

    // Validate after token has expired (120 seconds later)
    const result = conn.validateToken(&token, src, now_ns + 120 * std.time.ns_per_s);
    try testing.expectEqual(@as(?Connection(16).ValidatedToken, null), result);
}

test "token: future-dated token is rejected (clock skew)" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0xcc} ** 32;
    conn.config.token_secret = secret;

    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    // Generate token "from the future"
    const future_ts = now_ns + 60 * std.time.ns_per_s;
    const token = conn.generateToken(src, &odcid.bytes, future_ts, io);

    // Try to validate with an earlier timestamp
    const result = conn.validateToken(&token, src, now_ns);
    try testing.expectEqual(@as(?Connection(16).ValidatedToken, null), result);
}

test "token: different source address causes validation failure" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0xdd} ** 32;
    conn.config.token_secret = secret;

    const src1: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const src2: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 101 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    // Generate token for src1
    const token = conn.generateToken(src1, &odcid.bytes, now_ns, io);

    // Try to validate with src2 (should fail)
    const result = conn.validateToken(&token, src2, now_ns);
    try testing.expectEqual(@as(?Connection(16).ValidatedToken, null), result);
}

test "token: tampered token (corrupted AEAD tag) is rejected" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0xee} ** 32;
    conn.config.token_secret = secret;

    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    // Generate token
    var token = conn.generateToken(src, &odcid.bytes, now_ns, io);

    // Corrupt the AEAD tag (last 16 bytes)
    token[74] ^= 0xff; // flip bits in last byte of tag

    // Validation should fail
    const result = conn.validateToken(&token, src, now_ns);
    try testing.expectEqual(@as(?Connection(16).ValidatedToken, null), result);
}

test "token: IPv6 source address validation" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0xff} ** 32;
    conn.config.token_secret = secret;

    const src: SocketAddr = .{ .v6 = .{ .addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 }, .port = 1234 } };
    const odcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    // Generate token with IPv6 source
    const token = conn.generateToken(src, &odcid.bytes, now_ns, io);
    try testing.expectEqual(@as(usize, Connection(16).TOKEN_SIZE), token.len);

    // Validate with same IPv6 source (should succeed)
    const result = conn.validateToken(&token, src, now_ns);
    try testing.expect(result != null);
    try testing.expectEqual(@as(u8, cid_mod.len), result.?.len);
    try testing.expectEqualSlices(u8, &odcid.bytes, result.?.raw[0..cid_mod.len]);
}

test "token: truncated token is rejected" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    const secret = [_]u8{0x99} ** 32;
    conn.config.token_secret = secret;

    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const now_ns: i64 = 1_000_000_000;

    // Create truncated token (too short)
    const truncated: [30]u8 = [_]u8{0} ** 30;

    // Validation should fail
    const result = conn.validateToken(&truncated, src, now_ns);
    try testing.expectEqual(@as(?Connection(16).ValidatedToken, null), result);
}

test "retry: transport params wiring with original_dcid and retry_scid" {
    const testing = std.testing;
    const io = std.testing.io;

    // Create a connection with address validation enabled
    var conn = try Connection(16).accept(.{ .validate_addr = true }, io);

    // Simulate receiving a Retry token (generate one to test the full flow)
    const src: SocketAddr = .{ .v4 = .{ .addr = [_]u8{ 192, 168, 1, 100 }, .port = 1234 } };
    const original_dcid = ConnectionId.generate(0, io);
    const now_ns: i64 = 1_000_000_000;

    const token = conn.generateToken(src, &original_dcid.bytes, now_ns, io);

    // Validate the token (simulating receiving an Initial with this token)
    const validated = conn.validateToken(&token, src, now_ns);
    try testing.expect(validated != null);
    try testing.expectEqualSlices(u8, &original_dcid.bytes, validated.?.raw[0..validated.?.len]);

    // Set the original_dcid in the connection (would normally happen during Initial processing)
    conn.original_dcid = validated.?.raw;
    conn.original_dcid_len = validated.?.len;

    // Set a retry_scid (would be generated when sending the Retry)
    conn.retry_scid = ConnectionId.generate(1, io);

    // Now verify that transport params can be built with these values
    var test_params = transport_params.TransportParams{};
    if (conn.original_dcid) |odcid| {
        test_params.original_destination_connection_id = odcid;
        test_params.original_destination_connection_id_len = conn.original_dcid_len;
        if (conn.retry_scid) |scid| {
            test_params.retry_source_connection_id = scid;
        }
    }

    // Verify the params were set correctly
    try testing.expect(test_params.original_destination_connection_id != null);
    try testing.expectEqualSlices(u8, &original_dcid.bytes, test_params.original_destination_connection_id.?[0..test_params.original_destination_connection_id_len]);
    try testing.expectEqual(conn.retry_scid, test_params.retry_source_connection_id);

    // Test encoding/decoding the params with the new fields
    var encoded_buf: [256]u8 = undefined;
    const encoded_len = transport_params.encode(test_params, &encoded_buf);
    try testing.expect(encoded_len > 0);

    // Decode and verify
    const decoded = try transport_params.decode(encoded_buf[0..encoded_len]);
    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expectEqualSlices(u8, &original_dcid.bytes, decoded.original_destination_connection_id.?[0..decoded.original_destination_connection_id_len]);
    try testing.expectEqual(test_params.retry_source_connection_id, decoded.retry_source_connection_id);
}

// ---------------------------------------------------------------------------
// Retry flow integration tests (RFC 9000 §8.1)
// ---------------------------------------------------------------------------

/// Build an encrypted Initial packet with an optional token.
/// Returns the encrypted packet bytes and the initial keys derived from `dcid_bytes`.
fn buildInitialPacket(
    buf: []u8,
    dcid_bytes: [8]u8,
    scid_bytes: [8]u8,
    token: []const u8,
    pn: u64,
) struct { keys: crypto.InitialKeys, pkt_len: usize } {
    const dcid = ConnectionId{ .bytes = dcid_bytes };
    const scid = ConnectionId{ .bytes = scid_bytes };
    const keys = crypto.deriveInitialKeys(&dcid_bytes, packet.QUIC_VERSION_1);

    // PING frame as a minimal payload
    var pt: [4]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt, .ping);
    const ct_len = pt_len + 16;

    const hdr_len = packet.encodeLongHeader(
        buf,
        .initial,
        packet.QUIC_VERSION_1,
        &dcid.bytes,
        &scid.bytes,
        token,
        @intCast(pn),
        ct_len,
    );
    crypto.encryptPayload(keys.client, pn, buf[0..hdr_len], pt[0..pt_len], buf[hdr_len..][0..ct_len]);
    // Apply header protection so processLongHeaderPacket can remove it.
    // PN is at buf[hdr_len-4..hdr_len], sample is at buf[hdr_len..hdr_len+16].
    crypto.applyHeaderProtection(keys.client, &buf[0], buf[hdr_len - 4 ..][0..4], buf[hdr_len..][0..16]);
    return .{ .keys = keys, .pkt_len = hdr_len + ct_len };
}

test "retry: validate_addr=false: tokenless Initial proceeds without Retry" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid, scid, &.{}, 1);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    try conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io);

    // No retry_sent event
    var got_retry = false;
    while (conn.events.pop()) |ev| {
        if (ev == .retry_sent) got_retry = true;
    }
    try testing.expect(!got_retry);
}

test "retry: validate_addr=true, no token: retry_sent event and Retry packet queued" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = true }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid, scid, &.{}, 1);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    try conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io);

    // retry_sent event must be present
    var got_retry = false;
    while (conn.events.pop()) |ev| {
        if (ev == .retry_sent) got_retry = true;
    }
    try testing.expect(got_retry);

    // A Retry packet must be in the send queue
    var out: [256]u8 = undefined;
    const n = conn.send(&out);
    try testing.expect(n > 0);
    // Retry first byte is 0xff (v1: type bits 0b11, unused=0xf)
    try testing.expectEqual(@as(u8, 0xff), out[0]);
}

test "retry: validate_addr=true, valid token: original_dcid stored, handshake proceeds" {
    const testing = std.testing;
    const io = std.testing.io;
    const secret = [_]u8{0xAB} ** 32;
    var conn = try Connection(16).accept(.{ .validate_addr = true, .token_secret = secret }, io);

    const dcid_bytes = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid_bytes = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 1 }, .port = 4321 } };
    const now_ns: i64 = 2_000_000_000;

    // Generate a valid token for this src + dcid
    const odcid = ConnectionId{ .bytes = dcid_bytes };
    const token = conn.generateToken(src, &odcid.bytes, now_ns, io);

    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid_bytes, scid_bytes, &token, 1);
    try conn.receive(buf[0..r.pkt_len], src, now_ns, 0, io);

    // original_dcid must be set (no retry sent)
    try testing.expect(conn.original_dcid != null);
    var got_retry = false;
    while (conn.events.pop()) |ev| {
        if (ev == .retry_sent) got_retry = true;
    }
    try testing.expect(!got_retry);
}

test "retry: validate_addr=true, expired token: silent drop (RFC 9000 §8.1.3)" {
    const testing = std.testing;
    const io = std.testing.io;
    const secret = [_]u8{0xCD} ** 32;
    var conn = try Connection(16).accept(.{
        .validate_addr = true,
        .token_secret = secret,
        .token_validity_ns = 60 * std.time.ns_per_s, // 1 minute
    }, io);

    const dcid_bytes = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
    const scid_bytes = [_]u8{ 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99 };
    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 2 }, .port = 1111 } };
    const issued_ns: i64 = 1_000_000_000;
    const now_ns: i64 = issued_ns + 120 * std.time.ns_per_s; // 2 minutes later → expired

    const odcid = ConnectionId{ .bytes = dcid_bytes };
    const token = conn.generateToken(src, &odcid.bytes, issued_ns, io);

    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid_bytes, scid_bytes, &token, 1);
    // RFC 9000 §8.1.3: MUST silently drop — no error, connection not established.
    try conn.receive(buf[0..r.pkt_len], src, now_ns, 0, io);
    // original_dcid must be null — token was rejected, handshake was not accepted.
    // app_keys must be null — TLS did not complete.
    try testing.expect(conn.original_dcid == null);
    try testing.expect(conn.app_keys == null);
}

test "retry: validate_addr=true, tampered token: silent drop (RFC 9000 §8.1.3)" {
    const testing = std.testing;
    const io = std.testing.io;
    const secret = [_]u8{0xEF} ** 32;
    var conn = try Connection(16).accept(.{ .validate_addr = true, .token_secret = secret }, io);

    const dcid_bytes = [_]u8{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF };
    const scid_bytes = [_]u8{ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 192, 168, 1, 1 }, .port = 8080 } };
    const now_ns: i64 = 3_000_000_000;

    const odcid = ConnectionId{ .bytes = dcid_bytes };
    var token = conn.generateToken(src, &odcid.bytes, now_ns, io);
    token[5] ^= 0xFF; // tamper with ciphertext byte

    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid_bytes, scid_bytes, &token, 1);
    // RFC 9000 §8.1.3: MUST silently drop — no error, connection not established.
    try conn.receive(buf[0..r.pkt_len], src, now_ns, 0, io);
    // original_dcid must be null — token was rejected, handshake was not accepted.
    // app_keys must be null — TLS did not complete.
    try testing.expect(conn.original_dcid == null);
    try testing.expect(conn.app_keys == null);
}

test "retry: validate_addr=true, wrong-address token: silent drop (RFC 9000 §8.1.3)" {
    const testing = std.testing;
    const io = std.testing.io;
    const secret = [_]u8{0x12} ** 32;
    var conn = try Connection(16).accept(.{ .validate_addr = true, .token_secret = secret }, io);

    const dcid_bytes = [_]u8{ 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80 };
    const scid_bytes = [_]u8{ 0x90, 0xA0, 0xB0, 0xC0, 0xD0, 0xE0, 0xF0, 0x00 };
    const src1: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 10 }, .port = 2222 } };
    const src2: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 20 }, .port = 2222 } };
    const now_ns: i64 = 4_000_000_000;

    const odcid = ConnectionId{ .bytes = dcid_bytes };
    const token = conn.generateToken(src1, &odcid.bytes, now_ns, io); // token bound to src1

    var buf: [256]u8 = undefined;
    const r = buildInitialPacket(&buf, dcid_bytes, scid_bytes, &token, 1);
    // RFC 9000 §8.1.3: MUST silently drop — no error, connection not established.
    _ = try conn.receive(buf[0..r.pkt_len], src2, now_ns, 0, io);
    // original_dcid must be null — token was rejected, handshake was not accepted.
    // app_keys must be null — TLS did not complete.
    try testing.expect(conn.original_dcid == null);
    try testing.expect(conn.app_keys == null);
}

// ---------------------------------------------------------------------------
// ECN integration tests (RFC 9000 §12.1, RFC 9002 §B.1)
// ---------------------------------------------------------------------------
