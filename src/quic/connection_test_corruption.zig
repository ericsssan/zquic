//! Tests for corrupted Initial packet handling and idle timeout cleanup.
//!
//! These tests verify that:
//! 1. A corrupted Initial packet that fails decryption does NOT leave the
//!    connection in an unrecoverable zombie state (Bug: state transitions
//!    to .handshake before decryption, storing corrupted first_initial_dcid).
//! 2. Idle timeout emits an idle_timed_out event so the slot can be freed.
//! 3. Drain timeout emits a connection_closed event so the slot can be freed.

const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const ConnState = conn_mod.ConnState;
const Config = conn_mod.Config;
const Event = conn_mod.Event;
const SocketAddr = conn_mod.SocketAddr;
const frame = @import("frame.zig");
const packet = @import("packet.zig");
const crypto = @import("crypto.zig");
const cid_mod = @import("connection_id.zig");
const ConnectionId = cid_mod.ConnectionId;

/// Build an encrypted Initial packet with a variable-length DCID.
/// This mirrors ngtcp2 behavior where DCID can be up to 20 bytes.
fn buildInitialPacketVarDcid(
    buf: []u8,
    dcid: []const u8,
    scid: []const u8,
    token: []const u8,
    pn: u64,
) struct { keys: crypto.InitialKeys, pkt_len: usize } {
    const keys = crypto.deriveInitialKeys(dcid, packet.QUIC_VERSION_1);

    var pt: [4]u8 = undefined;
    const pt_len = frame.encodeFrame(&pt, .ping);
    const ct_len = pt_len + 16;

    const hdr_len = packet.encodeLongHeader(
        buf,
        .initial,
        packet.QUIC_VERSION_1,
        dcid,
        scid,
        token,
        @intCast(pn),
        ct_len,
    );
    crypto.encryptPayload(keys.client, pn, buf[0..hdr_len], pt[0..pt_len], buf[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(keys.client, &buf[0], buf[hdr_len - 4 ..][0..4], buf[hdr_len..][0..16]);
    return .{ .keys = keys, .pkt_len = hdr_len + ct_len };
}

// ---------------------------------------------------------------------------
// Bug 1: Corrupted Initial creates zombie connection
// ---------------------------------------------------------------------------

test "corrupted Initial must not prevent subsequent valid Initial from same address" {
    // Scenario: A corrupted Initial arrives first (1 byte in DCID region flipped).
    // The connection transitions idle→handshake and stores the corrupted DCID.
    // When a valid retransmission arrives with the correct DCID, it should NOT
    // be silently dropped — the handshake should proceed.
    //
    // This is the root cause of the handshakecorruption interop test failure:
    // 1/50 connections fail because a corrupted Initial creates a zombie that
    // blocks all subsequent valid Initials from the same client address.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    // Use a 17-byte DCID like ngtcp2.
    const dcid = [_]u8{ 0x9d, 0xcb, 0xe8, 0x78, 0x79, 0x0a, 0x52, 0xe9, 0x81, 0x0e, 0xf3, 0x5e, 0xd4, 0xc0, 0x28, 0x2a, 0x05 };
    const scid = [_]u8{ 0x63, 0x7f, 0x4b, 0x08, 0xbf, 0x6f, 0x73, 0xb1, 0x65, 0xcf, 0xf4, 0x7e, 0xcb, 0x54, 0x57, 0x22, 0x0e };

    // Build a valid Initial packet, then corrupt 1 byte in the DCID region.
    var corrupted_buf: [1200]u8 = undefined;
    const r_good = buildInitialPacketVarDcid(&corrupted_buf, &dcid, &scid, &.{}, 0);

    // Corrupt byte 10 (inside the DCID, which starts at byte 6 for 17-byte DCIDs).
    // This simulates the interop corruption model (1 random byte flipped).
    corrupted_buf[10] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 193, 167, 0, 100 }, .port = 55472 } };

    // Send the corrupted Initial — decryption should fail.
    const corrupt_err = conn.receive(corrupted_buf[0..r_good.pkt_len], src, 1_000_000_000, 0, io);
    try testing.expect(corrupt_err == error.AuthenticationFailed or corrupt_err == error.DecryptionFailed);

    // BUG CHECK: After a corrupted Initial fails decryption, the connection
    // should be back in .idle state so it can process a valid Initial.
    // Currently it stays in .handshake with a corrupted first_initial_dcid,
    // causing all valid retransmissions to be silently dropped.
    try testing.expectEqual(ConnState.idle, conn.hot.state);

    // Now send the valid Initial (same DCID, uncorrupted).
    var valid_buf: [1200]u8 = undefined;
    const r_valid = buildInitialPacketVarDcid(&valid_buf, &dcid, &scid, &.{}, 0);

    // The valid Initial should be processed successfully (not silently dropped).
    // It will fail later in TLS processing (no valid ClientHello), but it must
    // at least get past decryption and transition to handshake.
    _ = conn.receive(valid_buf[0..r_valid.pkt_len], src, 2_000_000_000, 0, io) catch {};

    // The connection should now be in handshake state with the correct DCID.
    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expectEqual(@as(u8, 17), conn.first_initial_dcid_len);
    try testing.expectEqualSlices(u8, &dcid, conn.first_initial_dcid[0..17]);
}

test "corrupted Initial with corrupted DCID length byte must not block retransmissions" {
    // Scenario: The dcid_len byte (byte 5) is corrupted, changing the perceived
    // DCID length. This causes the server to store a wrong-length DCID, which
    // then never matches any valid retransmission's DCID.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    var corrupted_buf: [1200]u8 = undefined;
    const r = buildInitialPacketVarDcid(&corrupted_buf, &dcid, scid[0..8], &.{}, 0);

    // Corrupt the dcid_len byte (byte 5). Original is 17 (0x11), flip to something else.
    corrupted_buf[5] ^= 0x04; // now 0x15 = 21, which is > 20 so will be silently dropped

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 1 }, .port = 9999 } };

    // Send corrupted packet — should be dropped or error.
    _ = conn.receive(corrupted_buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // Connection must still be idle (corrupted packet should not create state).
    try testing.expectEqual(ConnState.idle, conn.hot.state);

    // Valid retransmission should work.
    var valid_buf: [1200]u8 = undefined;
    const r2 = buildInitialPacketVarDcid(&valid_buf, &dcid, scid[0..8], &.{}, 0);
    _ = conn.receive(valid_buf[0..r2.pkt_len], src, 2_000_000_000, 0, io) catch {};

    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expectEqual(@as(u8, 17), conn.first_initial_dcid_len);
}

test "corrupted Initial payload (not DCID) should allow valid retransmission" {
    // Scenario: Corruption in the payload/ciphertext area (not DCID bytes).
    // The DCID is correct, so initial keys are derived correctly.
    // Decryption fails due to corrupted ciphertext.
    // Since the DCID is correct, the next valid Initial should succeed
    // (keys match, DCID matches).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };

    var corrupted_buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&corrupted_buf, &dcid, &scid, &.{}, 0);

    // Corrupt a byte in the ciphertext (well past the header).
    corrupted_buf[r.pkt_len - 5] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };

    // Corrupted packet — decryption fails.
    const err = conn.receive(corrupted_buf[0..r.pkt_len], src, 1_000_000_000, 0, io);
    try testing.expect(err == error.AuthenticationFailed or err == error.DecryptionFailed);

    // After payload corruption (DCID correct), the connection should either:
    // (a) be back in .idle (ideal — full rollback), or
    // (b) be in .handshake with correct DCID and keys (acceptable — retransmission works).
    //
    // In case (b), a valid retransmission with the same DCID should decrypt
    // successfully because the stored first_initial_dcid matches.
    var valid_buf: [256]u8 = undefined;
    const r2 = buildInitialPacketVarDcid(&valid_buf, &dcid, &scid, &.{}, 0);
    // Should not error from decryption (may error later in TLS).
    _ = conn.receive(valid_buf[0..r2.pkt_len], src, 2_000_000_000, 0, io) catch {};

    // Connection should be in handshake with correct DCID.
    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expectEqualSlices(u8, &dcid, conn.first_initial_dcid[0..8]);
}

// ---------------------------------------------------------------------------
// Bug 2: Idle timeout does not emit idle_timed_out event
// ---------------------------------------------------------------------------

test "idle timeout must emit idle_timed_out event" {
    // When the idle timeout fires (RFC 9000 §10.1), the connection transitions
    // to .closed state. An idle_timed_out event MUST be emitted (distinct from
    // connection_closed which signals a peer-initiated or error close) so the
    // server can free the slot and log it.
    //
    // Without this event, zombie connections persist forever in the connection
    // table, preventing new connections from the same client address.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    // Simulate receiving a valid Initial to set idle_deadline_ns.
    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // Drain any events from the Initial processing.
    while (conn.pollEvent()) |_| {}

    // Verify idle_deadline_ns was set.
    try testing.expect(conn.idle_deadline_ns != null);

    // Advance time past the idle timeout (default 30s = 30_000_000_000 ns).
    conn.tick(32_000_000_000);

    // Connection should be closed.
    try testing.expectEqual(ConnState.closed, conn.hot.state);

    // An idle_timed_out event MUST have been emitted.
    var found_closed = false;
    while (conn.pollEvent()) |ev| {
        switch (ev) {
            .idle_timed_out => {
                found_closed = true;
            },
            else => {},
        }
    }
    try testing.expect(found_closed);
}

test "drain timeout must emit connection_closed event" {
    // When the drain timer fires (closing/draining → closed), a
    // connection_closed event must be emitted for slot cleanup.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    // Set up a drain deadline manually (simulating post-CONNECTION_CLOSE state).
    conn.hot.state = .draining;
    conn.drain_deadline_ns = 5_000_000_000; // 5s from epoch

    // Drain any pre-existing events.
    while (conn.pollEvent()) |_| {}

    // Advance time past drain deadline.
    conn.tick(6_000_000_000);

    // Connection should be closed.
    try testing.expectEqual(ConnState.closed, conn.hot.state);

    // A connection_closed event MUST have been emitted.
    var found_closed = false;
    while (conn.pollEvent()) |ev| {
        switch (ev) {
            .connection_closed => {
                found_closed = true;
            },
            else => {},
        }
    }
    try testing.expect(found_closed);
}

// ---------------------------------------------------------------------------
// Bug 3: Zombie in .closed state silently discards all packets
// ---------------------------------------------------------------------------

test "closed connection silently discards all incoming packets" {
    // Verify that once a connection is in .closed state, receive() is a no-op.
    // This confirms that even after idle timeout fires, the zombie keeps
    // silently dropping packets if the slot isn't freed.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    // Move to closed state.
    conn.hot.state = .closed;

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };

    // receive() should return successfully (silently discard), not process the packet.
    try conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io);

    // State should remain closed, no transition.
    try testing.expectEqual(ConnState.closed, conn.hot.state);
}

// ---------------------------------------------------------------------------
// Additional edge cases
// ---------------------------------------------------------------------------

test "multiple corrupted Initials followed by valid one should succeed" {
    // Simulates the interop scenario: several corrupted Initials arrive
    // before the first valid one. The connection should eventually process
    // the valid Initial correctly.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAB };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 1 }, .port = 12345 } };

    // Send 3 corrupted Initials with different corruption positions.
    const corrupt_positions = [_]usize{ 8, 12, 18 }; // all within DCID region (bytes 6-22)
    for (corrupt_positions) |pos| {
        var cbuf: [1200]u8 = undefined;
        const cr = buildInitialPacketVarDcid(&cbuf, &dcid, scid[0..8], &.{}, 0);
        cbuf[pos] ^= 0xAA;
        _ = conn.receive(cbuf[0..cr.pkt_len], src, 1_000_000_000, 0, io) catch {};
    }

    // Connection must still be in idle (all corrupted packets rolled back).
    try testing.expectEqual(ConnState.idle, conn.hot.state);

    // Valid Initial should now work.
    var valid_buf: [1200]u8 = undefined;
    const vr = buildInitialPacketVarDcid(&valid_buf, &dcid, scid[0..8], &.{}, 0);
    _ = conn.receive(valid_buf[0..vr.pkt_len], src, 2_000_000_000, 0, io) catch {};

    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expectEqual(@as(u8, 17), conn.first_initial_dcid_len);
    try testing.expectEqualSlices(u8, &dcid, conn.first_initial_dcid[0..17]);
}

test "corrupted Initial with version field corruption stays idle" {
    // If the version field is corrupted to an unsupported value, the server
    // sends Version Negotiation and stays in .idle state. This is correct
    // behavior — no zombie is created.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    // Corrupt byte 2 (inside the version field, bytes 1-4).
    buf[2] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // Should stay idle (version negotiation path doesn't change state).
    try testing.expectEqual(ConnState.idle, conn.hot.state);
}

test "valid Initial after corrupted one uses correct peer_addr and peer_cid" {
    // Verify that after a corrupted Initial is discarded, the subsequent
    // valid Initial correctly sets peer_addr and peer_cid/peer_scid.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00, 0xAB };
    const scid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    // Send corrupted Initial (DCID byte flipped).
    var cbuf: [1200]u8 = undefined;
    const cr = buildInitialPacketVarDcid(&cbuf, &dcid, scid[0..8], &.{}, 0);
    cbuf[10] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 192, 168, 1, 100 }, .port = 44085 } };
    _ = conn.receive(cbuf[0..cr.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // Send valid Initial from same address.
    var vbuf: [1200]u8 = undefined;
    const vr = buildInitialPacketVarDcid(&vbuf, &dcid, scid[0..8], &.{}, 0);
    _ = conn.receive(vbuf[0..vr.pkt_len], src, 2_000_000_000, 0, io) catch {};

    // peer_addr must be set correctly (from the valid Initial, not corrupted one).
    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expect(conn.peer_addr.eql(src));

    // peer_cid must match the SCID from the valid Initial.
    try testing.expectEqualSlices(u8, scid[0..8], conn.peer_cid.bytes[0..8]);
}

test "corrupted Initial does not consume idle_deadline or set bytes_recv" {
    // After a corrupted Initial fails decryption, the connection should not
    // have advanced internal counters (bytes_recv, pkts_recv) since the packet
    // was not successfully processed.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11 };
    const scid = [_]u8{ 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28 };

    var buf: [1200]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, scid[0..8], &.{}, 0);
    // Corrupt in DCID region.
    buf[15] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 10, 0, 0, 2 }, .port = 9999 } };
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // bytes_recv and pkts_recv must be 0 (corrupted packet was not counted).
    try testing.expectEqual(@as(u64, 0), conn.bytes_recv);
    try testing.expectEqual(@as(u64, 0), conn.pkts_recv);
}

test "corrupted Initial with flags byte corruption (short header) stays idle" {
    // If the first byte (flags) is corrupted so bit 7 is flipped, the packet
    // looks like a short header. Short-header processing should fail for an
    // idle connection (no app keys), but state must remain idle.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    // Corrupt byte 0 — flip bit 7 to turn long header into short header.
    buf[0] ^= 0x80;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // State must remain idle — short header on idle connection is dropped.
    try testing.expectEqual(ConnState.idle, conn.hot.state);
}

test "corrupted SCID does not prevent handshake when DCID is correct" {
    // If only the SCID region is corrupted but the DCID is intact, the
    // server should derive correct initial keys, decrypt successfully,
    // and transition to handshake. The SCID is used for peer_cid, which
    // may be wrong, but the handshake should at least start.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    // Corrupt a byte in the SCID region (byte 15 for 8+8 byte CIDs: dcid at 6..14, scid at 15..22).
    // SCID starts at byte 6 + dcid_len(8) + 1 = byte 15.
    buf[17] ^= 0xFF;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    // SCID corruption doesn't affect decryption (only DCID matters for key derivation).
    // The packet may still decrypt correctly since SCID is not part of AEAD.
    // However, SCID is inside the header which IS part of the AAD, so corruption
    // there will cause AEAD authentication failure.
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // If AEAD fails (SCID is part of AAD), state must roll back to idle.
    // If AEAD succeeds (unlikely with corrupted AAD), state transitions to handshake.
    // Either way, a subsequent valid Initial must succeed.
    var vbuf: [256]u8 = undefined;
    const vr = buildInitialPacketVarDcid(&vbuf, &dcid, &scid, &.{}, 0);
    _ = conn.receive(vbuf[0..vr.pkt_len], src, 2_000_000_000, 0, io) catch {};

    try testing.expectEqual(ConnState.handshake, conn.hot.state);
    try testing.expectEqualSlices(u8, &dcid, conn.first_initial_dcid[0..8]);
}

test "idle timeout after successful handshake start emits idle_timed_out" {
    // Ensure that idle timeout works correctly for a connection that
    // successfully started handshake (not just zombie connections).
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{ .validate_addr = false }, io);

    const dcid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const scid = [_]u8{ 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18 };
    var buf: [256]u8 = undefined;
    const r = buildInitialPacketVarDcid(&buf, &dcid, &scid, &.{}, 0);

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    _ = conn.receive(buf[0..r.pkt_len], src, 1_000_000_000, 0, io) catch {};

    // Should be in handshake state.
    try testing.expectEqual(ConnState.handshake, conn.hot.state);

    // Drain events.
    while (conn.pollEvent()) |_| {}

    // Advance past idle timeout (30s + margin).
    conn.tick(32_000_000_000);

    try testing.expectEqual(ConnState.closed, conn.hot.state);

    // Must emit idle_timed_out (distinct from connection_closed).
    var found = false;
    while (conn.pollEvent()) |ev| {
        switch (ev) {
            .idle_timed_out => found = true,
            else => {},
        }
    }
    try testing.expect(found);
}

test "connection: Version Negotiation trigger with oversized SCID is dropped, not crashed (RFC 9000 §17.2)" {
    // Regression (found by fuzzReceiveRaw): an idle server receiving a long-header
    // packet with an UNSUPPORTED version and a CID length field > 20 used to echo the
    // oversized CID into a 64-byte VN buffer, overflowing it (remote-DoS panic).
    // The malformed header must now be dropped without sending a VN or changing state.
    const testing = std.testing;
    const io = std.testing.io;
    var conn = try Connection(4).accept(.{}, io);
    defer conn.deinit();

    var pkt: [256]u8 = undefined;
    pkt[0] = 0xc0; // long header, fixed bit set
    std.mem.writeInt(u32, pkt[1..5], 0x1a2a3a4a, .big); // unsupported version (not v1/v2)
    pkt[5] = 0; // DCID length = 0
    pkt[6] = 107; // SCID length = 107 (> 20 — malformed), the overflow trigger
    @memset(pkt[7..][0..107], 0xAB);
    const total = 7 + 107;

    const src: SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 5000 } };
    // Must not crash (the bug was an index-out-of-bounds panic here).
    conn.receive(pkt[0..total], src, 1_000_000_000, 0, io) catch {};

    // Dropped: no state transition from a malformed packet.
    try testing.expectEqual(ConnState.idle, conn.hot.state);
}
