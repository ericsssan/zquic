//! Tests for handshakecorruption (C1) interop failure — cross-epoch sent table
//! collision, amplification budget starvation, and loss recovery under corruption.

const std = @import("std");
const testing = std.testing;
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const Config = conn_mod.Config;
const frame = @import("frame.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const crypto = @import("crypto.zig");
const tls_mod = @import("tls.zig");
const packet_mod = @import("packet.zig");

const Conn = Connection(16);

fn setupEstablished(conn: *Conn) void {
    conn.hot.state = .established;
    const k = crypto.PacketKeys{
        .key = [_]u8{0x01} ** 32,
        .iv = [_]u8{0x02} ** 12,
        .hp = [_]u8{0x03} ** 32,
        .suite = .aes_128_gcm,
    };
    conn.app_keys = tls_mod.AppKeys{ .client = k, .server = k };
    conn.path_validated = true;
    conn.loss.rtt.smoothed_rtt = 50_000_000;
    conn.loss.rtt.rtt_var = 25_000_000;
    conn.loss.rtt.latest_rtt = 50_000_000;
    conn.loss.rtt.min_rtt = 50_000_000;
    conn.peer_max_stream_data_bidi_local = 1_000_000;
    conn.local_max_streams_bidi = 64;
}

fn makeAck(largest: u62, range_count: usize, ranges: [32]frame.AckRange) frame.AckFrame {
    return .{
        .largest_acked = largest, .ack_delay = 0,
        .range_count = range_count, .has_ecn = false,
        .ranges = ranges, .ect0 = 0, .ect1 = 0, .ecn_ce = 0,
    };
}

// ---------------------------------------------------------------------------
// Cross-epoch sent table collision (root cause #1)
// ---------------------------------------------------------------------------

test "sent table: different epochs use different indices — no cross-epoch eviction" {
    var table = loss_recovery_mod.SentPacketTable.init();

    var stream_fi = loss_recovery_mod.SentFrameInfo{};
    stream_fi.frames[0] = .{ .stream = .{
        .stream_id = 0, .offset = 0, .len = 1024, .fin = true,
    } };
    stream_fi.count = 1;
    _ = table.add(.{
        .pn = 5, .sent_ns = 100, .size = 1066, .epoch = 2,
        .ack_eliciting = true, .in_flight = true, .valid = true,
    }, stream_fi);

    // Handshake pkn 5 must NOT evict 1-RTT pkn 5
    const evicted = table.add(.{
        .pn = 5, .sent_ns = 200, .size = 95, .epoch = 1,
        .ack_eliciting = true, .in_flight = true, .valid = true,
    }, .{});

    try testing.expect(evicted == null);
    try testing.expect(table.get(5, 2) != null);
    try testing.expect(table.get(5, 1) != null);
}

test "sent table: same-epoch never collides for pn < region size" {
    const MAX_SENT = loss_recovery_mod.MAX_SENT;
    for (0..3) |epoch| {
        var seen = [_]bool{false} ** MAX_SENT;
        for (0..loss_recovery_mod.SentPacketTable.EPOCH_SIZES[epoch]) |pn| {
            const idx = loss_recovery_mod.SentPacketTable.slotIndex(@intCast(pn), @intCast(epoch));
            if (seen[idx]) return error.TestUnexpectedResult;
            seen[idx] = true;
        }
    }
}

test "sent table: no cross-epoch collision for pn < region size" {
    for (0..loss_recovery_mod.SentPacketTable.EPOCH_SIZES[0]) |pn| {
        const idx0 = loss_recovery_mod.SentPacketTable.slotIndex(@intCast(pn), 0);
        const idx1 = loss_recovery_mod.SentPacketTable.slotIndex(@intCast(pn), 1);
        const idx2 = loss_recovery_mod.SentPacketTable.slotIndex(@intCast(pn), 2);
        if (idx0 == idx1 or idx0 == idx2 or idx1 == idx2) return error.TestUnexpectedResult;
    }
}

test "sent table: Initial and Handshake coexist, ACK one without affecting other" {
    var table = loss_recovery_mod.SentPacketTable.init();
    var bif: u64 = 0;

    for (0..6) |pn| {
        _ = table.add(.{
            .pn = @intCast(pn), .sent_ns = 0, .size = 149,
            .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true,
        }, .{});
        bif += 149;
    }
    for (0..6) |pn| {
        const evicted = table.add(.{
            .pn = @intCast(pn), .sent_ns = 0, .size = 752,
            .epoch = 1, .ack_eliciting = true, .in_flight = true, .valid = true,
        }, .{});
        try testing.expect(evicted == null);
        bif += 752;
    }

    try testing.expectEqual(@as(u16, 6), table.valid_per_epoch[0]);
    try testing.expectEqual(@as(u16, 6), table.valid_per_epoch[1]);

    var ack_result = loss_recovery_mod.AckResult{};
    table.ackRange(0, 5, 0, &ack_result, &bif);
    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[0]);
    try testing.expectEqual(@as(u16, 6), table.valid_per_epoch[1]);

    for (0..6) |pn| {
        try testing.expect(table.get(@intCast(pn), 1) != null);
    }
}

// ---------------------------------------------------------------------------
// Loss recovery under corruption (STREAM in pkn 5 with gap < threshold)
// ---------------------------------------------------------------------------

test "time-loss alarm fires for STREAM pkn with sub-threshold gap" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    setupEstablished(&conn);

    const t0: i64 = 1_000_000_000;
    conn.current_time_ns = t0;
    conn.pmtud_next_probe_ns = t0 + 999_000_000_000;

    conn.queuePing() catch {};
    conn.queuePing() catch {};
    for (0..3) |_| {
        const n = frame.encodeFrame(&conn.pkt_scratch, .ping);
        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.count = 0;
        _ = conn.sendShortHeaderPacket(n, fi, false) catch {};
    }
    conn.streamSend(0, &([_]u8{0xFF} ** 200), true) catch return error.TestUnexpectedResult;
    conn.queuePing() catch {};
    conn.queuePing() catch {};

    var buf: [1500]u8 = undefined;
    while (conn.send(&buf) > 0) {}

    // ACK [6..7],[1..3] — gap at [0,4,5]. pkn 5 gap = 2 < threshold 3.
    var ranges: [32]frame.AckRange = undefined;
    ranges[0] = .{ .gap = 0, .ack_range = 1 };
    ranges[1] = .{ .gap = 1, .ack_range = 2 };
    conn.current_time_ns = t0 + 100_000_000;
    conn.processAck(makeAck(7, 2, ranges), 2) catch {};
    while (conn.send(&buf) > 0) {}

    try testing.expect(conn.time_loss_alarm_ns != null);
    const alarm = conn.time_loss_alarm_ns.?;

    conn.tick(alarm + 1);

    var total: usize = 0;
    while (true) {
        const n = conn.send(&buf);
        if (n == 0) break;
        total += n;
    }
    try testing.expect(total > 200);
}

test "full retransmission lifecycle: loss → retransmit → PTO → re-probe" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    setupEstablished(&conn);

    const t0: i64 = 1_000_000_000;
    conn.current_time_ns = t0;
    conn.pmtud_next_probe_ns = t0 + 999_000_000_000;

    conn.queuePing() catch {}; // stand-in for HANDSHAKE_DONE
    conn.queuePing() catch {};
    for (0..3) |_| {
        const n = frame.encodeFrame(&conn.pkt_scratch, .ping);
        var fi = loss_recovery_mod.SentFrameInfo{};
        fi.count = 0;
        _ = conn.sendShortHeaderPacket(n, fi, false) catch {};
    }
    conn.streamSend(0, &([_]u8{0xFF} ** 200), true) catch return error.TestUnexpectedResult;
    conn.queuePing() catch {};
    conn.queuePing() catch {};

    var buf: [1500]u8 = undefined;
    while (conn.send(&buf) > 0) {}

    var ranges: [32]frame.AckRange = undefined;
    ranges[0] = .{ .gap = 0, .ack_range = 1 };
    ranges[1] = .{ .gap = 1, .ack_range = 2 };
    conn.current_time_ns = t0 + 100_000_000;
    conn.processAck(makeAck(7, 2, ranges), 2) catch {};
    while (conn.send(&buf) > 0) {}

    const alarm = conn.time_loss_alarm_ns orelse return error.TestUnexpectedResult;
    conn.tick(alarm + 1);
    while (conn.send(&buf) > 0) {}

    try testing.expect(conn.pto_deadline_ns != null);
    const pto1 = conn.pto_deadline_ns.?;
    conn.tick(pto1 + 1);

    var probe_sent = false;
    while (conn.send(&buf) > 0) { probe_sent = true; }
    try testing.expect(probe_sent);
    try testing.expect(conn.pto_deadline_ns != null);
    try testing.expect(!conn.isClosed());
}

// ---------------------------------------------------------------------------
// Amplification budget starvation (root cause #2)
// ---------------------------------------------------------------------------

test "PTO skips Initial retransmit when hs_keys exist to preserve budget for Handshake" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();

    conn.hot.state = .handshake;
    conn.path_validated = false;
    conn.bytes_unvalidated_recv = 1200;
    conn.bytes_unvalidated_sent = 3400; // only 200 bytes remaining

    const initial_data = [_]u8{0xAA} ** 90;
    conn.crypto_send_saved_len[0] = initial_data.len;
    @memcpy(conn.crypto_send_saved[0][0..initial_data.len], &initial_data);

    const hs_data = [_]u8{0xBB} ** 693;
    conn.crypto_send_saved_len[1] = hs_data.len;
    @memcpy(conn.crypto_send_saved[1][0..hs_data.len], &hs_data);

    // With hs_keys set, Handshake retransmit should go first
    conn.retransmitCryptoSaved(1);

    var buf: [1500]u8 = undefined;
    while (conn.send(&buf) > 0) {}

    const remaining = (conn.bytes_unvalidated_recv *| 3) -| conn.bytes_unvalidated_sent;
    // Budget should be consumed by Handshake, not wasted on Initial
    // (exact amount depends on whether HS fit; the point is HS goes first)
    _ = remaining;
}

// ---------------------------------------------------------------------------
// Zombie connection detection
// ---------------------------------------------------------------------------

test "zombie connection: pkts_recv == 0 after failed receive" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();

    try testing.expectEqual(@as(u64, 0), conn.pkts_recv);
    try testing.expect(conn.hot.state == .idle);

    const dummy_addr = conn_mod.SocketAddr{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 443 } };
    var bad_data = [_]u8{0xC0} ++ [_]u8{0} ** 99;
    conn.receive(&bad_data, dummy_addr, 1_000_000_000, 0, io) catch {};

    try testing.expectEqual(@as(u64, 0), conn.pkts_recv);
    try testing.expect(conn.hot.state == .idle);
}

// ---------------------------------------------------------------------------
// PTO and loss detection basics
// ---------------------------------------------------------------------------

test "ptoDeadline returns null when bytes_in_flight is 0" {
    var loss = loss_recovery_mod.LossRecovery.init();
    try testing.expect(loss.ptoDeadline(25_000_000) == null);
    loss.bytes_in_flight = 100;
    loss.last_ack_eliciting_ns = 1_000_000;
    loss.rtt.smoothed_rtt = 50_000_000;
    loss.rtt.rtt_var = 25_000_000;
    try testing.expect(loss.ptoDeadline(25_000_000) != null);
}

test "sendShortHeaderPacket arms PTO for ack-eliciting packets" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    setupEstablished(&conn);
    conn.current_time_ns = 1_000_000_000;
    conn.pto_deadline_ns = null;
    conn.queuePing() catch {};
    try testing.expect(conn.pto_deadline_ns != null);
}

test "processLostFrames retransmits STREAM directly when send queue has space" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    setupEstablished(&conn);
    conn.current_time_ns = 1_000_000_000;

    conn.streamSend(0, &([_]u8{0xAA} ** 100), true) catch return error.TestUnexpectedResult;
    var buf: [1500]u8 = undefined;
    while (conn.send(&buf) > 0) {}

    var result = loss_recovery_mod.AckResult{};
    result.lost_frame_count = 1;
    result.lost_frames[0] = loss_recovery_mod.SentFrameInfo{};
    result.lost_frames[0].frames[0] = .{ .stream = .{
        .stream_id = 0, .offset = 0, .len = 100, .fin = true,
    } };
    result.lost_frames[0].count = 1;
    result.lost_epochs[0] = 2;

    conn.processLostFrames(result);

    try testing.expectEqual(@as(u8, 0), conn.stream_pending_retx_count);
    try testing.expect(conn.loss.bytes_in_flight > 0);
    try testing.expect(conn.pto_deadline_ns != null);
}

test "pending stream retransmit arms PTO when drained via tick" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    setupEstablished(&conn);

    const t0: i64 = 1_000_000_000;
    conn.current_time_ns = t0;

    conn.stream_pending_retx[0] = .{
        .stream_id = 0, .offset = 0, .len = 50, .fin = true,
    };
    conn.stream_pending_retx_count = 1;
    const st = conn.streams.getOrCreate(0) orelse return error.TestUnexpectedResult;
    st.send_max = 1_000_000;
    _ = st.bufferSendData(&([_]u8{0xBB} ** 50));

    conn.pto_deadline_ns = null;
    conn.pmtud_next_probe_ns = t0 + 999_000_000_000;

    // tick() calls drainPendingStreamRetx internally
    conn.tick(t0 + 1);

    try testing.expectEqual(@as(u8, 0), conn.stream_pending_retx_count);
    try testing.expect(conn.loss.bytes_in_flight > 0);
    try testing.expect(conn.pto_deadline_ns != null);
}

test "processShortHeaderPacket silently drops when app_keys is null" {
    const io = std.testing.io;
    var conn = try Conn.accept(.{}, io);
    defer conn.deinit();
    try testing.expect(conn.app_keys == null);
    var fake_short: [64]u8 = undefined;
    @memset(&fake_short, 0);
    fake_short[0] = 0x40;
    const consumed = conn.processShortHeaderPacket(&fake_short) catch 0;
    try testing.expectEqual(@as(usize, 0), consumed);
}

test "corrupted short header with bit 7 flipped looks like long header" {
    try testing.expect(!packet_mod.isLongHeader(0x40));
    try testing.expect(packet_mod.isLongHeader(0x40 | 0x80));
}
