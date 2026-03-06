//! Tests for Connection — basic connection, event queue, retransmit, close,
//! initial packet handling, stream reset, path challenge, MAX_STREAMS,
//! NEW_CONNECTION_ID, and related functionality.
const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const ConnectionHot = conn_mod.ConnectionHot;
const ConnState = conn_mod.ConnState;
const Config = conn_mod.Config;
const Event = conn_mod.Event;
const EventQueue = conn_mod.EventQueue;
const MAX_PACKET_SIZE = conn_mod.MAX_PACKET_SIZE;
const SEND_QUEUE_DEPTH = conn_mod.SEND_QUEUE_DEPTH;
const EVENT_QUEUE_DEPTH = conn_mod.EVENT_QUEUE_DEPTH;
const SocketAddr = conn_mod.SocketAddr;
const frame = @import("frame.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const stream_mod = @import("stream.zig");
const tls = @import("tls.zig");

test "connection: hot struct is 64 bytes" {
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 64), @sizeOf(ConnectionHot));
}

test "connection: accept initializes correctly" {
    const io = std.testing.io;
    const config = Config{};
    var conn = try Connection(16).accept(config, io);
    const testing = std.testing;
    try testing.expectEqual(ConnState.idle, conn.hot.state);
    try testing.expectEqual(@as(u8, 0), conn.hot.epoch);
    try testing.expect(!conn.isEstablished());
    try testing.expect(!conn.isClosed());
}

test "connection: send returns 0 when queue empty" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    var out: [MAX_PACKET_SIZE]u8 = undefined;
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

test "connection: enqueue and drain send queue" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    const data = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    try conn.enqueueSend(&data);

    var out: [8]u8 = undefined;
    const n = conn.send(&out);
    const testing = std.testing;
    try testing.expectEqual(@as(usize, 4), n);
    try testing.expectEqualSlices(u8, &data, out[0..n]);
}

test "connection: tick transitions to closed on idle timeout" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.idle_deadline_ns = 1000;
    conn.tick(2000);
    const testing = std.testing;
    try testing.expectEqual(ConnState.closed, conn.hot.state);
}

test "connection: unknown version triggers VN response" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

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

test "connection: ver=0 packet does not trigger VN response" {
    // ver=0 identifies a Version Negotiation packet (RFC 9000 §17.2.1).
    // The outer guard `ver != 0` in the unsupported-version branch already
    // excludes ver=0, so no VN reply must be sent for such packets.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    var pkt: [32]u8 = undefined;
    pkt[0] = 0x80; // long header bit set
    std.mem.writeInt(u32, pkt[1..5], 0x00000000, .big); // ver=0 = VN marker
    pkt[5] = 8;
    @memset(pkt[6..14], 0xaa);
    pkt[14] = 8;
    @memset(pkt[15..23], 0xbb);

    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&pkt, src, 0, io) catch {};

    // No VN response must be queued for a ver=0 packet.
    var out: [64]u8 = undefined;
    const n = conn.send(&out);
    try testing.expectEqual(@as(usize, 0), n);
}

test "connection: nextTimeout returns minimum of active deadlines" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
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
    const conn = try Connection(16).accept(.{}, io);
    try testing.expectEqual(@as(u64, 0), conn.loss.bytes_in_flight);
    try testing.expectEqual(@as(u32, 0), conn.loss.pto_count);
    try testing.expectEqual(@as(?i64, null), conn.loss.last_ack_eliciting_ns);
    try testing.expectEqual(@as(?i64, null), conn.pto_deadline_ns);
    try testing.expectEqual(@as(u64, 25_000_000), conn.cached_max_ack_delay_ns);
}

test "loss: onPacketSent wires bytes_in_flight and pto_deadline" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.current_time_ns = 1_000_000;
    conn.loss.onPacketSent(1, 0, 1200, true, conn.current_time_ns, .{});
    try testing.expectEqual(@as(u64, 1200), conn.loss.bytes_in_flight);
    try testing.expect(conn.loss.ptoDeadline(conn.cached_max_ack_delay_ns) != null);
}

test "loss: pto_deadline_ns null when no ack-eliciting packets in flight" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{}, io);
    try testing.expectEqual(@as(?i64, null), conn.pto_deadline_ns);
}

test "loss: onPtoFired increments pto_count; resetPtoCount zeroes it" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);

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
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.current_time_ns = 0;
    conn.hot.tx_pn[0] = 2; // pretend pn=0 and pn=1 were sent in epoch 0

    conn.loss.onPacketSent(1, 0, 1200, true, 0, .{});
    try testing.expectEqual(@as(u64, 1200), conn.loss.bytes_in_flight);

    const ack = frame.AckFrame{
        .largest_acked = 1,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 1 }} ++ [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    try conn.processAck(ack, 0);

    try testing.expectEqual(@as(u64, 0), conn.loss.bytes_in_flight);
}

test "ack: buildAckRangesFromBitmap encodes gap values correctly without -1" {
    const testing = std.testing;

    // Bitmap: bit i = packet (largest - i). With largest=5:
    // Bits 0,1,2 = packets 5,4,3 received
    // Bit 3 = packet 2 NOT received (gap)
    // Bits 4,5 = packets 1,0 received
    // RFC 9000 §19.3.1: gap field encodes as (unacked_packets - 1)
    // So 1 missing packet → gap_value = 0, but the test name claims "without -1"
    // This test actually validates that gap_value = gap - 1 IS correct per RFC.

    var bitmap: [3]u64 = undefined;
    bitmap[0] = 0; // Initial epoch
    bitmap[1] = 0; // Handshake epoch
    // 1-RTT: bits 0,1,2,4,5 set → packets 5,4,3,1,0 received; packet 2 missing
    bitmap[2] = 0b0011_0111; // bits 0,1,2,4,5

    var ranges: [32]frame.AckRange = undefined;
    const count = Connection(16).buildAckRangesFromBitmap(bitmap[2], &ranges);

    // Should have 2 ranges: [5,4,3] (ack_range=2) and [1,0] (ack_range=1) with gap for packet 2
    try testing.expectEqual(@as(usize, 2), count);

    // First range: packets 5,4,3
    try testing.expectEqual(@as(u62, 2), ranges[0].ack_range); // 3 packets = ack_range of 2
    try testing.expectEqual(@as(u62, 0), ranges[0].gap);

    // Gap between first range (packet 3) and second range (packet 1): 1 missing packet (packet 2)
    // Per RFC 9000 §19.3.1: gap field = (missing_packets - 1) = 0
    // Second range: packets 1,0 with gap of 0 for 1 missing packet
    try testing.expectEqual(@as(u62, 0), ranges[1].gap); // 1 missing packet encoded as gap=0
    try testing.expectEqual(@as(u62, 1), ranges[1].ack_range); // 2 packets = ack_range of 1
}

test "ack: isPnDuplicate and markPnReceived handle out-of-order packets" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Test RFC 9000 §13.2: Out-of-order packet handling with duplicate detection
    // Scenario: receive packet 5, then 3, then 5 again (retransmit)
    const epoch: usize = 2; // 1-RTT epoch

    // Receive packet 5 (largest so far)
    try testing.expect(!conn.isPnDuplicate(epoch, 5));
    conn.markPnReceived(epoch, 5);

    // Receive packet 3 (out of order, should not be duplicate)
    try testing.expect(!conn.isPnDuplicate(epoch, 3));
    conn.markPnReceived(epoch, 3);

    // Receive packet 5 again (should now be duplicate)
    try testing.expect(conn.isPnDuplicate(epoch, 5));

    // Receive packet 4 (fills gap, should not be duplicate)
    try testing.expect(!conn.isPnDuplicate(epoch, 4));
    conn.markPnReceived(epoch, 4);

    // Receive packet 4 again (should now be duplicate)
    try testing.expect(conn.isPnDuplicate(epoch, 4));
}

test "connection: version 0 packet is silently ignored" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 0;
    try conn.close(0, false, &[_]u8{});
    try testing.expectEqual(ConnState.closing, conn.hot.state);
}

test "close: close() is idempotent when already closing" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 0;
    try conn.close(0, false, &[_]u8{});
    try conn.close(1, true, &[_]u8{}); // must not change state or panic
    try testing.expectEqual(ConnState.closing, conn.hot.state);
}

test "close: drain_deadline arms after close()" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.current_time_ns = 1_000_000_000;
    try conn.close(0, false, &[_]u8{});
    try testing.expect(conn.drain_deadline_ns != null);
    try testing.expect(conn.drain_deadline_ns.? > 1_000_000_000);
}

test "close: drain timer in tick transitions to closed" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .closing;
    conn.drain_deadline_ns = 5000;
    conn.tick(6000);
    try testing.expectEqual(ConnState.closed, conn.hot.state);
    try testing.expectEqual(@as(?i64, null), conn.drain_deadline_ns);
}

test "close: draining state suppresses send()" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .draining;
    // Queue something
    try conn.enqueueSend(&[_]u8{0x01});
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), conn.send(&out));
}

test "close: nextTimeout includes drain_deadline" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.drain_deadline_ns = 2000;
    conn.idle_deadline_ns = 5000;
    // drain is smaller → nextTimeout returns drain
    try testing.expectEqual(@as(?i64, 2000), conn.nextTimeout());
}

test "close: close() pushes connection_closed event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established;
    conn.idle_deadline_ns = 500;

    // Feed a (malformed but non-empty) packet at time 1000.
    const dummy = [_]u8{0x00} ** 5;
    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };
    conn.receive(&dummy, src, 1_000_000_000, io) catch {};

    // idle_deadline should be refreshed beyond 500.
    try testing.expect(conn.idle_deadline_ns.? > 500);
}

test "initial_packet: RFC9000§9 - drop Initial packets in established state" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Transition to established state (simulating a completed handshake).
    conn.hot.state = .established;
    conn.current_time_ns = 0;

    // Build a minimal Initial packet (fixed first byte 0xc0 for long header, type=initial).
    var pkt: [64]u8 = undefined;
    pkt[0] = 0xc0; // Long header, type=Initial (bits 5-4 = 00)
    pkt[1] = 0x00; // Version byte 0
    pkt[2] = 0x00; // Version byte 1
    pkt[3] = 0x00; // Version byte 2
    pkt[4] = 0x01; // Version byte 3 (v1)
    pkt[5] = 8; // DCID length
    // DCID = 8 bytes (arbitrary)
    pkt[6] = 0x00;
    pkt[7] = 0x01;
    pkt[8] = 0x02;
    pkt[9] = 0x03;
    pkt[10] = 0x04;
    pkt[11] = 0x05;
    pkt[12] = 0x06;
    pkt[13] = 0x07;

    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };

    // Attempt to receive Initial packet in established state.
    // Should silently drop (return early without error).
    conn.receive(&pkt, src, 0, io) catch {
        // Should not error; Initial in established should be silently dropped.
        testing.expect(false) catch unreachable;
        return;
    };

    // Connection should remain in established state.
    try testing.expectEqual(ConnState.established, conn.hot.state);
}

test "initial_packet: RFC9000§9 - drop Initial with mismatched DCID in handshake state" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Transition to handshake state.
    conn.hot.state = .handshake;
    // Set local_cid to a specific pattern (first byte = 0x01, rest = 0x00)
    conn.local_cid.bytes[0] = 0x01;
    @memset(conn.local_cid.bytes[1..], 0x00);
    conn.current_time_ns = 0;

    // Build Initial packet with DIFFERENT DCID than connection's local_cid.
    var pkt: [64]u8 = undefined;
    pkt[0] = 0xc0; // Long header, type=Initial
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x00;
    pkt[4] = 0x01; // Version v1
    pkt[5] = 8; // DCID length
    // DCID = 0x10 0x11 ... (different from local_cid)
    pkt[6] = 0x10;
    pkt[7] = 0x11;
    pkt[8] = 0x12;
    pkt[9] = 0x13;
    pkt[10] = 0x14;
    pkt[11] = 0x15;
    pkt[12] = 0x16;
    pkt[13] = 0x17;

    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };

    // Attempt to receive Initial packet with mismatched DCID in handshake state.
    conn.receive(&pkt, src, 0, io) catch {
        testing.expect(false) catch unreachable;
        return;
    };

    // Connection should remain in handshake state.
    try testing.expectEqual(ConnState.handshake, conn.hot.state);
}

// ---------------------------------------------------------------------------
// New tests — RESET_STREAM / STOP_SENDING (Step 6)
// ---------------------------------------------------------------------------

test "stream_reset: processFrames handles RESET_STREAM and pushes event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.state = .established; // SEC-004: state guard passes; stream-ID guard fires

    var buf: [32]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{
        .stream = .{
            .stream_id = 1, // bit 0 = 1 → server-initiated, invalid for received frames
            .offset = 0,
            .fin = false,
            .data = "hi",
        },
    });
    try testing.expectError(error.StreamStateError, conn.processFrames(buf[0..n], 2, null));
}

test "security: processAck malformed ack_range returns InvalidFrame" {
    // An ACK with ack_range > largest_acked must return error.InvalidFrame (SEC-002).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.tx_pn[0] = 3; // pretend pn=0..2 were sent

    const ack = frame.AckFrame{
        .largest_acked = 2,
        .ack_delay = 0,
        .ranges = [_]frame.AckRange{.{ .gap = 0, .ack_range = 10 }} // 10 > largest_acked=2
        ++ [_]frame.AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    try testing.expectError(error.InvalidFrame, conn.processAck(ack, 0));
}

test "security: processAck malformed gap returns InvalidFrame" {
    // Gap value that would underflow the running low pointer must return InvalidFrame.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.hot.tx_pn[0] = 11; // pretend pn=0..10 were sent

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
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    try testing.expectError(error.InvalidFrame, conn.processAck(ack, 0));
}

test "security: VN rate limit suppresses same version within 60s" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    var pkt: [32]u8 = undefined;
    pkt[0] = 0xc0;
    std.mem.writeInt(u32, pkt[1..5], 0x00000002, .big); // unknown version
    pkt[5] = 8;
    @memset(pkt[6..14], 0xaa);
    pkt[14] = 8;
    @memset(pkt[15..23], 0xbb);
    const src: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 9000 } };

    // First unknown version: send VN
    conn.receive(&pkt, src, 0, io) catch {};
    var out: [64]u8 = undefined;
    try testing.expect(conn.send(&out) > 0);

    // Same version within 60s: throttle (no VN)
    conn.receive(&pkt, src, 30_000_000_000, io) catch {}; // +30s
    try testing.expectEqual(@as(usize, 0), conn.send(&out));

    // Different unknown version within 60s of first: send VN (different version)
    std.mem.writeInt(u32, pkt[1..5], 0x00000003, .big); // different version
    conn.receive(&pkt, src, 35_000_000_000, io) catch {};
    try testing.expect(conn.send(&out) > 0);

    // First version after 60s: send VN again (cooldown expired)
    std.mem.writeInt(u32, pkt[1..5], 0x00000002, .big);
    conn.receive(&pkt, src, 61_000_000_000, io) catch {}; // +61s
    try testing.expect(conn.send(&out) > 0);
}

test "event_queue: wraparound maintains FIFO order" {
    const testing = std.testing;
    var q = EventQueue{};

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
    const conn = try Connection(16).accept(.{}, io);
    try testing.expectEqual(@as(u6, 3), conn.cached_ack_delay_exp);
}

test "connection: idle_timeout_i64 matches config at accept()" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{ .idle_timeout_ns = 10_000_000_000 }, io);
    try testing.expectEqual(@as(i64, 10_000_000_000), conn.idle_timeout_i64);
}

test "connection: idle_timeout_i64 is zero when idle_timeout_ns is zero" {
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{ .idle_timeout_ns = 0 }, io);
    try testing.expectEqual(@as(i64, 0), conn.idle_timeout_i64);
}

test "security: rx_pn_valid initializes to false for all epochs" {
    // All three epochs must start with rx_pn_valid = false (no packet seen yet).
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);
    conn.idle_deadline_ns = null;
    conn.pto_deadline_ns = null;
    conn.drain_deadline_ns = null;
    try testing.expectEqual(@as(?i64, null), conn.nextTimeout());
}

test "connection: nextTimeout sentinel does not leak as a valid deadline" {
    // Even if two timers are null, the returned value must be the one real deadline.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    conn.idle_deadline_ns = null;
    conn.pto_deadline_ns = 42;
    conn.drain_deadline_ns = null;
    try testing.expectEqual(@as(?i64, 42), conn.nextTimeout());
}

test "stream_reset: processFrames handles STOP_SENDING and pushes event" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);
    conn.current_time_ns = 1_000_000_000;

    // Force CUBIC into congestion avoidance with a known large window.
    conn.congestion.ssthresh = 0; // cwnd always > ssthresh=0 → CUBIC always used
    conn.congestion.cwnd = 100 * 1200; // 120000 bytes (100 × MSS)
    const initial_cwnd = conn.congestion.cwnd;

    // Register 10 packets in epoch 0, all sent at t=0.
    conn.hot.tx_pn[0] = 11; // pretend pn=0..10 were sent
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
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    try conn.processAck(ack, 0);

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
    var conn = try Connection(16).accept(.{ .is_server = false }, io);

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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

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
    var conn = try Connection(16).accept(.{}, io);

    var buf: [16]u8 = undefined;
    const n = frame.encodeFrame(&buf, .{ .max_streams_bidi = 100 });
    conn.processFrames(buf[0..n], 2, null) catch {};
    try testing.expectEqual(@as(u62, 100), conn.peer_max_streams_bidi);
}

test "connection: MAX_STREAMS_BIDI value never decreases" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
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
    var conn = try Connection(16).accept(.{}, io);

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
        if (entry.valid and entry.seq == 1) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "connection: NEW_CONNECTION_ID retire_prior_to invalidates old CIDs" {
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    var cid0: [20]u8 = undefined;
    @memset(&cid0, 0xaa);
    var cid1: [20]u8 = undefined;
    @memset(&cid1, 0xcc);
    var tok0: [16]u8 = undefined;
    @memset(&tok0, 0xbb);
    var tok1: [16]u8 = undefined;
    @memset(&tok1, 0xdd);

    var buf: [64]u8 = undefined;
    var n = frame.encodeFrame(&buf, .{ .new_connection_id = .{
        .sequence_number = 0,
        .retire_prior_to = 0,
        .cid = cid0,
        .cid_len = 8,
        .stateless_reset_token = tok0,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    // seq=1 with retire_prior_to=1 → seq=0 must be invalidated
    n = frame.encodeFrame(&buf, .{ .new_connection_id = .{
        .sequence_number = 1,
        .retire_prior_to = 1,
        .cid = cid1,
        .cid_len = 8,
        .stateless_reset_token = tok1,
    } });
    conn.processFrames(buf[0..n], 2, null) catch {};

    var found_old = false;
    for (conn.peer_cid_table) |entry| {
        if (entry.valid and entry.seq == 0) {
            found_old = true;
            break;
        }
    }
    try testing.expect(!found_old);
}

test "connection: Version Negotiation DCID echoes full client SCID (RFC 9000 §6.1)" {
    // Regression: sendVersionNeg capped the DCID at 8 bytes (cid_mod.len) regardless
    // of the actual client SCID length. RFC 9000 §6.1 requires the VN DCID to be a
    // verbatim copy of the client SCID.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Build a raw long-header packet with an unknown version and a 12-byte SCID.
    const unknown_version: u32 = 0xDEADBEEF;
    const client_dcid = [_]u8{0x11} ** 8;
    const client_scid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 }; // 12 bytes
    var raw: [64]u8 = undefined;
    var pos: usize = 0;
    raw[pos] = 0x80;
    pos += 1;
    std.mem.writeInt(u32, raw[pos..][0..4], unknown_version, .big);
    pos += 4;
    raw[pos] = client_dcid.len;
    pos += 1;
    @memcpy(raw[pos..][0..client_dcid.len], &client_dcid);
    pos += client_dcid.len;
    raw[pos] = client_scid.len;
    pos += 1;
    @memcpy(raw[pos..][0..client_scid.len], &client_scid);
    pos += client_scid.len;
    // Minimal payload so the packet isn't rejected for being too short.
    raw[pos] = 0x01;
    pos += 1; // PING frame byte

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    try conn.receive(raw[0..pos], src, 1_000_000_000, io);

    // Grab the VN packet from the send queue.
    var out: [256]u8 = undefined;
    const n = conn.send(&out);
    try testing.expect(n > 0);

    // First byte: long header (0x80 set).
    try testing.expect(out[0] & 0x80 != 0);
    // Bytes 1-4: version must be 0 (VN marker).
    const ver = std.mem.readInt(u32, out[1..5], .big);
    try testing.expectEqual(@as(u32, 0), ver);
    // Byte 5: DCID length must equal client's SCID length (12).
    try testing.expectEqual(@as(u8, client_scid.len), out[5]);
    // Bytes 6..18: DCID must be the client's SCID verbatim.
    try testing.expectEqualSlices(u8, &client_scid, out[6..][0..client_scid.len]);
}

test "connection: deinit zeroes all key material" {
    // Regression: Connection had no deinit(), so TlsServer.deinit() (which zeroes
    // handshake_secret, master_secret, ecdh_kp, etc.) was never called.
    // Also verifies that app_keys / hs_keys / next_app_keys are zeroed.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);

    // Populate key fields with non-zero values.
    const dummy_keys = tls.AppKeys{
        .client = .{ .key = [_]u8{0xAB} ** 16, .iv = [_]u8{0xCD} ** 12, .hp = [_]u8{0xEF} ** 16 },
        .server = .{ .key = [_]u8{0xAB} ** 16, .iv = [_]u8{0xCD} ** 12, .hp = [_]u8{0xEF} ** 16 },
    };
    conn.app_keys = dummy_keys;
    conn.next_app_keys = dummy_keys;
    conn.hs_keys = tls.HandshakeKeys{
        .client = dummy_keys.client,
        .server = dummy_keys.server,
    };

    conn.deinit();

    // All key fields must be null / zeroed after deinit.
    try testing.expectEqual(@as(?tls.AppKeys, null), conn.app_keys);
    try testing.expectEqual(@as(?tls.AppKeys, null), conn.next_app_keys);
    try testing.expectEqual(@as(?tls.HandshakeKeys, null), conn.hs_keys);
    // next_client_secret and next_server_secret must be zero.
    try testing.expectEqual([_]u8{0} ** 32, conn.next_client_secret);
    try testing.expectEqual([_]u8{0} ** 32, conn.next_server_secret);
}

// ---------------------------------------------------------------------------
// NEW_CONNECTION_ID coalesced in HANDSHAKE_DONE (tshark session tracking)
// ---------------------------------------------------------------------------

test "connection: alt_local_cid is distinct from primary local_cid" {
    // Verify that accept() generates two distinct CIDs so that the
    // NEW_CONNECTION_ID frame in HANDSHAKE_DONE advertises a CID different
    // from the primary one, allowing tshark to track the 1-RTT session.
    const testing = std.testing;
    const io = std.testing.io;
    const conn = try Connection(16).accept(.{}, io);

    // The alt CID must not be all-zero (it's randomly generated).
    try testing.expect(!std.mem.eql(u8, &conn.alt_local_cid.bytes, &[_]u8{0} ** 8));
    // The two CIDs must differ so tshark session tracking benefits from the extra CID.
    try testing.expect(!std.mem.eql(u8, &conn.local_cid.bytes, &conn.alt_local_cid.bytes));
}
