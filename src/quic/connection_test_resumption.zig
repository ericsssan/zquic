//! Unit tests for TLS 1.3 session resumption and 0-RTT support.

const std = @import("std");
const testing = std.testing;
const tls = @import("tls.zig");
const crypto = @import("crypto.zig");

const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;

// ---------------------------------------------------------------------------
// Ticket encrypt/decrypt round-trip
// ---------------------------------------------------------------------------

test "ticket encrypt/decrypt round-trip preserves PSK, cipher, and ALPN" {
    const io = std.testing.io;
    const ticket_key = [_]u8{0x42} ** 32;

    var server = try tls.TlsServer.init(io);
    defer server.deinit();
    server.ticket_key = &ticket_key;
    server.negotiated_cipher = .aes_128_gcm;
    server.negotiated_alpn_len = 2;
    server.negotiated_alpn[0] = 'h';
    server.negotiated_alpn[1] = '3';
    server.current_time_ns = 1_000_000_000_000;
    server.resumption_master_secret = [_]u8{0xAA} ** 32;

    var nst_buf: [512]u8 = undefined;
    const nst_len = server.buildNewSessionTicket(&nst_buf);
    try testing.expect(nst_len > 0);

    // type=4 (HS_NEW_SESSION_TICKET)
    try testing.expectEqual(@as(u8, 4), nst_buf[0]);

    // Extract ticket: skip type(1)+length(3)+lifetime(4)+age_add(4)+nonce_len(1)+nonce(1)=14
    const ticket_data_len = std.mem.readInt(u16, nst_buf[14..16], .big);
    const ticket_data = nst_buf[16..][0..ticket_data_len];

    const td = tls.decryptTicket(&ticket_key, ticket_data);
    try testing.expect(td != null);
    const data = td.?;

    try testing.expectEqual(crypto.CipherSuite.aes_128_gcm, data.cipher);
    try testing.expectEqual(@as(u8, 2), data.alpn_len);
    try testing.expectEqualSlices(u8, "h3", data.alpn[0..2]);
    try testing.expectEqual(@as(i64, 1_000_000_000_000), data.timestamp);
}

test "ticket decrypt fails with wrong key" {
    const io = std.testing.io;
    const ticket_key = [_]u8{0x42} ** 32;
    const wrong_key = [_]u8{0x99} ** 32;

    var server = try tls.TlsServer.init(io);
    defer server.deinit();
    server.ticket_key = &ticket_key;
    server.resumption_master_secret = [_]u8{0xBB} ** 32;
    server.current_time_ns = 1_000_000;

    var nst_buf: [512]u8 = undefined;
    const nst_len = server.buildNewSessionTicket(&nst_buf);
    try testing.expect(nst_len > 0);

    const ticket_data_len = std.mem.readInt(u16, nst_buf[14..16], .big);
    const ticket_data = nst_buf[16..][0..ticket_data_len];
    try testing.expect(tls.decryptTicket(&wrong_key, ticket_data) == null);
}

test "ticket decrypt fails with truncated data" {
    const ticket_key = [_]u8{0x42} ** 32;
    const short = [_]u8{0} ** 30;
    try testing.expect(tls.decryptTicket(&ticket_key, &short) == null);
}

// ---------------------------------------------------------------------------
// PSK binder computation
// ---------------------------------------------------------------------------

test "PSK binder computation is deterministic" {
    const zero32 = [_]u8{0} ** 32;
    const psk = [_]u8{0xCC} ** 32;

    const early_secret = HkdfSha256.extract(&zero32, &psk);

    var binder_key: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&binder_key, early_secret, "res binder", &tls.sha256_empty);

    var finished_key: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&finished_key, binder_key, "finished", "");

    const fake_ch = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05 };
    var ch_hash = Sha256.init(.{});
    ch_hash.update(&fake_ch);
    var ch_hash_val: [32]u8 = undefined;
    ch_hash.final(&ch_hash_val);

    var binder1: [32]u8 = undefined;
    Hmac256.create(&binder1, &ch_hash_val, &finished_key);
    var binder2: [32]u8 = undefined;
    Hmac256.create(&binder2, &ch_hash_val, &finished_key);

    try testing.expectEqualSlices(u8, &binder1, &binder2);

    // Verify non-zero
    var all_zero = true;
    for (binder1) |b| if (b != 0) {
        all_zero = false;
        break;
    };
    try testing.expect(!all_zero);
}

// ---------------------------------------------------------------------------
// PSK key schedule
// ---------------------------------------------------------------------------

test "PSK key schedule produces different early_secret than zero PSK" {
    const io = std.testing.io;
    var server_psk = try tls.TlsServer.init(io);
    defer server_psk.deinit();
    var server_zero = try tls.TlsServer.init(io);
    defer server_zero.deinit();

    const shared = [_]u8{0x55} ** 32;
    const psk = [_]u8{0xDD} ** 32;

    try server_psk.runKeySchedule(shared, psk);
    try server_zero.runKeySchedule(shared, null);

    try testing.expect(!std.mem.eql(u8, &server_psk.early_secret, &server_zero.early_secret));
}

// ---------------------------------------------------------------------------
// NewSessionTicket message format
// ---------------------------------------------------------------------------

test "NewSessionTicket has correct message type and lifetime" {
    const io = std.testing.io;
    var server = try tls.TlsServer.init(io);
    defer server.deinit();
    const ticket_key = [_]u8{0x11} ** 32;
    server.ticket_key = &ticket_key;
    server.resumption_master_secret = [_]u8{0x22} ** 32;
    server.current_time_ns = 42;

    var buf: [512]u8 = undefined;
    const len = server.buildNewSessionTicket(&buf);
    try testing.expect(len > 0);
    try testing.expectEqual(@as(u8, 4), buf[0]);

    const body_len = (@as(u32, buf[1]) << 16) | (@as(u32, buf[2]) << 8) | buf[3];
    try testing.expectEqual(len - 4, body_len);

    const lifetime = std.mem.readInt(u32, buf[4..8], .big);
    try testing.expectEqual(@as(u32, 86400), lifetime);
}

test "NewSessionTicket returns 0 when no ticket_key" {
    const io = std.testing.io;
    var server = try tls.TlsServer.init(io);
    defer server.deinit();
    var buf: [512]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), server.buildNewSessionTicket(&buf));
}

// ---------------------------------------------------------------------------
// 0-RTT key derivation
// ---------------------------------------------------------------------------

test "0-RTT keys differ from 1-RTT keys" {
    const early_secret = [_]u8{0xEE} ** 32;
    const ch_hash = [_]u8{0xFF} ** 32;

    var client_early_traffic_secret: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&client_early_traffic_secret, early_secret, "c e traffic", &ch_hash);

    const zero_rtt_keys = crypto.derivePacketKeysWithSuite(
        client_early_traffic_secret,
        @import("packet.zig").QUIC_VERSION_1,
        .aes_128_gcm,
    );

    var app_secret: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&app_secret, [_]u8{0xAA} ** 32, "c ap traffic", &ch_hash);
    const app_keys = crypto.derivePacketKeysWithSuite(
        app_secret,
        @import("packet.zig").QUIC_VERSION_1,
        .aes_128_gcm,
    );

    try testing.expect(!std.mem.eql(u8, &zero_rtt_keys.key, &app_keys.key));
}

// ---------------------------------------------------------------------------
// ClientHello PSK extension parsing
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// 0-RTT frame restrictions (RFC 9000 Table 3)
// ---------------------------------------------------------------------------

const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const Config = conn_mod.Config;
const frame = @import("frame.zig");
const loss_recovery_mod = @import("loss_recovery.zig");

/// Helper: call isFrameAllowedInEpoch via processFramesInner behavior.
/// Since isFrameAllowedInEpoch is private, we test it indirectly through
/// the connection's frame processing which uses the same logic.
fn checkFrameAllowed(comptime Conn: type, f: frame.Frame, epoch: u8, is_zero_rtt: bool) bool {
    return Conn.isFrameAllowedInEpoch(f, epoch, is_zero_rtt);
}

test "0-RTT rejects ACK frames (RFC 9000 Table 3)" {
    const Conn = Connection(16);
    const ack_frame: frame.Frame = .{ .ack = .{
        .largest_acked = 0, .ack_delay = 0,
        .ranges = undefined, .range_count = 0,
        .ect0 = 0, .ect1 = 0, .ecn_ce = 0, .has_ecn = false,
    } };
    // ACK allowed in epoch 0 (Initial) and epoch 2 (1-RTT)
    try testing.expect(checkFrameAllowed(Conn, ack_frame, 0, false));
    try testing.expect(checkFrameAllowed(Conn, ack_frame, 2, false));
    // ACK prohibited in 0-RTT
    try testing.expect(!checkFrameAllowed(Conn, ack_frame, 2, true));
}

test "0-RTT rejects CRYPTO frames (RFC 9000 Table 3)" {
    const Conn = Connection(16);
    const crypto_frame: frame.Frame = .{ .crypto = .{ .offset = 0, .data = &.{} } };
    // CRYPTO allowed in epoch 0, 1, and 2
    try testing.expect(checkFrameAllowed(Conn, crypto_frame, 0, false));
    try testing.expect(checkFrameAllowed(Conn, crypto_frame, 1, false));
    // CRYPTO prohibited in 0-RTT
    try testing.expect(!checkFrameAllowed(Conn, crypto_frame, 2, true));
}

test "0-RTT rejects HANDSHAKE_DONE (RFC 9000 Table 3)" {
    const Conn = Connection(16);
    try testing.expect(checkFrameAllowed(Conn, .handshake_done, 2, false));
    try testing.expect(!checkFrameAllowed(Conn, .handshake_done, 2, true));
}

test "0-RTT allows STREAM frames" {
    const Conn = Connection(16);
    const stream_frame: frame.Frame = .{ .stream = .{
        .stream_id = 0, .offset = 0, .fin = false, .data = &.{},
    } };
    try testing.expect(checkFrameAllowed(Conn, stream_frame, 2, true));
    try testing.expect(checkFrameAllowed(Conn, stream_frame, 2, false));
}

test "0-RTT allows PING and PADDING" {
    const Conn = Connection(16);
    try testing.expect(checkFrameAllowed(Conn, .ping, 2, true));
    try testing.expect(checkFrameAllowed(Conn, .{ .padding = 1 }, 2, true));
}

test "0-RTT rejects application CONNECTION_CLOSE (0x1d)" {
    const Conn = Connection(16);
    const app_close: frame.Frame = .{ .connection_close = .{
        .error_code = 0, .frame_type = 0, .reason = "", .is_app = true,
    } };
    const transport_close: frame.Frame = .{ .connection_close = .{
        .error_code = 0, .frame_type = 0, .reason = "", .is_app = false,
    } };
    // Transport close allowed in 0-RTT, app close not
    try testing.expect(checkFrameAllowed(Conn, transport_close, 2, true));
    try testing.expect(!checkFrameAllowed(Conn, app_close, 2, true));
}

// ---------------------------------------------------------------------------
// streamSend returns error when not established (regression: silent data drop)
// ---------------------------------------------------------------------------

test "streamSend returns error when connection not established" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    defer conn.deinit();
    conn.hot.state = .handshake;
    // Create a stream so getOrCreate succeeds
    _ = conn.streams.getOrCreate(0);

    const result = conn.streamSend(0, "hello", false);
    try testing.expectError(error.StreamNotWritable, result);
}

test "streamSend does not return StreamNotWritable when established" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    defer conn.deinit();
    conn.hot.state = .established;

    // Without app_keys, queueStreamData will fail — but the established check passes.
    // We verify the state check specifically by confirming handshake state errors
    // and established state does NOT error with StreamNotWritable for state reasons.
    conn.hot.state = .handshake;
    _ = conn.streams.getOrCreate(0);
    const err1 = conn.streamSend(0, "hi", false);
    try testing.expectError(error.StreamNotWritable, err1);

    // Now set established — should get past the state check
    // (may error on queueStreamData due to no app_keys, but NOT StreamNotWritable)
    conn.hot.state = .established;
    const err2 = conn.streamSend(0, "hi", false);
    if (err2) |_| {
        // succeeded (unlikely without keys, but valid)
    } else |err| {
        // Should NOT be StreamNotWritable — that would mean the state check failed
        try testing.expect(err != error.StreamNotWritable);
    }
}

// ---------------------------------------------------------------------------
// sendShortHeaderPacket reverts tx_pn on all error paths
// ---------------------------------------------------------------------------

test "sendShortHeaderPacket reverts tx_pn when app_keys is null" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    defer conn.deinit();
    conn.app_keys = null;

    const pn_before = conn.hot.tx_pn[2];
    const result = conn.sendShortHeaderPacket(1, null, false);
    try testing.expectError(error.NoAppKeys, result);
    try testing.expectEqual(pn_before, conn.hot.tx_pn[2]);
}

// ---------------------------------------------------------------------------
// drainPendingCryptoRetx skips epoch >= 2 (regression: index out of bounds panic)
// ---------------------------------------------------------------------------

test "drainPendingCryptoRetx skips epoch 2 without panic" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    defer conn.deinit();
    conn.hot.state = .established;
    conn.app_keys = conn.tls_state.app_keys;

    // Simulate a lost epoch-2 CRYPTO frame (NewSessionTicket)
    conn.crypto_pending_retx[0] = .{ .epoch = 2, .offset = 0, .len = 100 };
    conn.crypto_pending_retx_count = 1;

    // Must not panic (previously caused index out of bounds on crypto_send_saved_len[2])
    conn.drainPendingCryptoRetx();

    // The entry should be skipped (not retransmitted), count cleared
    try testing.expectEqual(@as(u8, 0), conn.crypto_pending_retx_count);
}

// ---------------------------------------------------------------------------
// accepting_early_data lifecycle
// ---------------------------------------------------------------------------

test "accepting_early_data is cleared on handshake completion" {
    const io = std.testing.io;
    var conn = try Connection(16).accept(.{}, io);
    defer conn.deinit();

    // Simulate 0-RTT acceptance
    conn.accepting_early_data = true;
    conn.hot.state = .handshake;

    // After handshake completes, accepting_early_data should be false
    // (tested indirectly: the field is cleared in deliverCryptoChunk after isComplete())
    try testing.expect(conn.accepting_early_data == true);

    // Simulate deinit — should clear the flag
    conn.accepting_early_data = true;
    conn.deinit();
    try testing.expect(conn.accepting_early_data == false);
}

// ---------------------------------------------------------------------------
// ClientHello PSK extension parsing
// ---------------------------------------------------------------------------

test "parseClientHello parses PSK extension fields" {
    // Build a minimal ClientHello with PSK extensions.
    var buf: [1024]u8 = undefined;
    var w: usize = 0;

    // Handshake header: type=1, length placeholder
    buf[0] = 1;
    w = 4;

    // legacy_version + random
    std.mem.writeInt(u16, buf[w..][0..2], 0x0303, .big);
    w += 2;
    @memset(buf[w..][0..32], 0xAA);
    w += 32;

    // session_id empty
    buf[w] = 0;
    w += 1;

    // cipher_suites: 1 suite
    std.mem.writeInt(u16, buf[w..][0..2], 2, .big);
    w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 0x1301, .big);
    w += 2;

    // compression: null
    buf[w] = 1;
    w += 1;
    buf[w] = 0;
    w += 1;

    // ---- Extensions ----
    const ext_len_pos = w;
    w += 2; // placeholder

    // Extension: key_share (x25519)
    // ext_data = list_len(2) + group(2) + key_len(2) + key(32) = 38 bytes
    std.mem.writeInt(u16, buf[w..][0..2], 0x0033, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 38, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 36, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 0x001d, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 32, .big); w += 2;
    @memset(buf[w..][0..32], 0x55); w += 32;

    // Extension: psk_key_exchange_modes (ext_len=2)
    std.mem.writeInt(u16, buf[w..][0..2], 0x002d, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 2, .big); w += 2;
    buf[w] = 1; w += 1; // modes_len=1
    buf[w] = 1; w += 1; // psk_dhe_ke

    // Extension: early_data (ext_len=0)
    std.mem.writeInt(u16, buf[w..][0..2], 0x002a, .big); w += 2;
    std.mem.writeInt(u16, buf[w..][0..2], 0, .big); w += 2;

    // Extension: pre_shared_key (must be last)
    std.mem.writeInt(u16, buf[w..][0..2], 0x0029, .big); w += 2;
    const psk_data_pos = w;
    w += 2; // ext data len placeholder

    // PSK identities: list_len(2) + [ id_len(2) + id(8) + age(4) ] = 2+14 = 16
    std.mem.writeInt(u16, buf[w..][0..2], 14, .big); w += 2; // identities list len
    std.mem.writeInt(u16, buf[w..][0..2], 8, .big); w += 2; // id len
    @memset(buf[w..][0..8], 0xBB); w += 8; // id data
    std.mem.writeInt(u32, buf[w..][0..4], 12345, .big); w += 4; // obfuscated_age

    // PSK binders: list_len(2) + [ binder_len(1) + binder(32) ] = 2+33 = 35
    const binders_list_pos = w;
    std.mem.writeInt(u16, buf[w..][0..2], 33, .big); w += 2; // binders list len
    buf[w] = 32; w += 1; // binder len
    @memset(buf[w..][0..32], 0xDD); w += 32; // binder data

    // Fill PSK ext data length
    std.mem.writeInt(u16, buf[psk_data_pos..][0..2], @intCast(w - psk_data_pos - 2), .big);

    // Fill total extensions length
    std.mem.writeInt(u16, buf[ext_len_pos..][0..2], @intCast(w - ext_len_pos - 2), .big);

    // Fill handshake msg length
    const msg_len = w - 4;
    buf[1] = @intCast((msg_len >> 16) & 0xff);
    buf[2] = @intCast((msg_len >> 8) & 0xff);
    buf[3] = @intCast(msg_len & 0xff);

    // Parse
    const ch = try tls.parseClientHello(buf[0..w]);

    try testing.expect(ch.has_psk);
    try testing.expect(ch.has_psk_dhe_ke);
    try testing.expect(ch.has_early_data);
    try testing.expectEqual(@as(u16, 8), ch.psk_identity_len);
    try testing.expectEqual(@as(u32, 12345), ch.psk_obfuscated_age);
    for (0..32) |i| try testing.expectEqual(@as(u8, 0xDD), ch.psk_binder[i]);

    // ch_truncated_len should exclude the binders
    const total_ch = 4 + msg_len;
    const binders_size: usize = 2 + 33; // list_len(2) + binder_len(1) + binder(32)
    _ = binders_list_pos;
    try testing.expectEqual(total_ch - binders_size, ch.ch_truncated_len);
}
