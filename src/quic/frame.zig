//! QUIC frame encoding and decoding (RFC 9000 §19).

const std = @import("std");
const varint = @import("varint.zig");

// ---------------------------------------------------------------------------
// Frame type codes
// ---------------------------------------------------------------------------

pub const FrameType = enum(u8) {
    padding = 0x00,
    ping = 0x01,
    ack = 0x02,
    ack_ecn = 0x03,
    reset_stream = 0x04,
    stop_sending = 0x05,
    crypto = 0x06,
    new_token = 0x07,
    stream = 0x08, // 0x08..0x0f depending on OFF/LEN/FIN bits
    max_data = 0x10,
    max_stream_data = 0x11,
    max_streams_bidi = 0x12,
    max_streams_uni = 0x13,
    data_blocked = 0x14,
    stream_data_blocked = 0x15,
    streams_blocked_bidi = 0x16,
    streams_blocked_uni = 0x17,
    new_connection_id = 0x18,
    retire_connection_id = 0x19,
    path_challenge = 0x1a,
    path_response = 0x1b,
    connection_close_quic = 0x1c,
    connection_close_app = 0x1d,
    handshake_done = 0x1e,
    _,
};

// ---------------------------------------------------------------------------
// Individual frame structures
// ---------------------------------------------------------------------------

pub const AckRange = struct {
    gap: u62,
    ack_range: u62,
};

pub const AckFrame = struct {
    largest_acked: u62,
    ack_delay: u62,
    ranges: [32]AckRange,
    range_count: usize,
    ect0: u62,
    ect1: u62,
    ecn_ce: u62,
    has_ecn: bool,
};

pub const CryptoFrame = struct {
    offset: u62,
    data: []const u8,
};

pub const StreamFrame = struct {
    stream_id: u62,
    offset: u62,
    fin: bool,
    data: []const u8,
};

pub const MaxStreamDataFrame = struct {
    stream_id: u62,
    max_data: u62,
};

pub const ResetStreamFrame = struct {
    stream_id: u62,
    error_code: u62,
    final_size: u62,
};

pub const StopSendingFrame = struct {
    stream_id: u62,
    error_code: u62,
};

pub const ConnectionCloseFrame = struct {
    error_code: u62,
    frame_type: u62,
    reason: []const u8,
    is_app: bool,
};

pub const NewConnectionIdFrame = struct {
    sequence_number: u62,
    retire_prior_to: u62,
    cid: [20]u8,
    cid_len: u8,
    stateless_reset_token: [16]u8,
};

pub const PathChallengeFrame = struct {
    data: [8]u8,
};

pub const PathResponseFrame = struct {
    data: [8]u8,
};

// ---------------------------------------------------------------------------
// Tagged union
// ---------------------------------------------------------------------------

pub const Frame = union(enum) {
    padding: usize, // number of PADDING bytes
    ping,
    ack: AckFrame,
    crypto: CryptoFrame,
    stream: StreamFrame,
    max_data: u62,
    max_stream_data: MaxStreamDataFrame,
    max_streams_bidi: u62,
    max_streams_uni: u62,
    reset_stream: ResetStreamFrame,
    stop_sending: StopSendingFrame,
    connection_close: ConnectionCloseFrame,
    handshake_done,
    new_connection_id: NewConnectionIdFrame,
    retire_connection_id: u62,
    path_challenge: PathChallengeFrame,
    path_response: PathResponseFrame,
    data_blocked: u62,
    stream_data_blocked: struct { stream_id: u62, max: u62 },
    streams_blocked_bidi: u62,
    streams_blocked_uni: u62,
    new_token: []const u8,
};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

/// Parse a QUIC frame from a buffer.
///
/// Returns ParseResult on success, or one of:
///   - BufferEmpty: no data in buffer
///   - InvalidFrame: malformed frame data (frame type/fields invalid)
///   - UnknownFrame: unrecognized frame type code
///
/// Note: Error messages do not include frame type context. To identify which
/// frame type failed, log the first byte(s) before calling parseFrame, or
/// enhance ParseResult to include frame_type_hint: u8 for debugging.
pub fn parseFrame(buf: []const u8) !ParseResult {
    if (buf.len == 0) return error.BufferEmpty;

    const type_vi = varint.decode(buf) orelse return error.InvalidFrame;
    var pos: usize = type_vi.len;
    const frame_type_raw: u8 = if (type_vi.value <= 0xff) @intCast(type_vi.value) else return error.UnknownFrame;

    switch (frame_type_raw) {
        // Fast-path: STREAM frames (most common in data transfer)
        0x08...0x0f => {
            const flags = frame_type_raw & 0x07;
            const has_offset = (flags & 0x04) != 0;
            const has_length = (flags & 0x02) != 0;
            const has_fin = (flags & 0x01) != 0;

            const sid = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += sid.len;

            var offset: u62 = 0;
            if (has_offset) {
                const off = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += off.len;
                offset = off.value;
            }

            var data: []const u8 = buf[pos..];
            if (has_length) {
                const dlen = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += dlen.len;
                const dl: usize = @intCast(dlen.value);
                if (pos + dl > buf.len) return error.BufferTooShort;
                data = buf[pos..][0..dl];
                pos += dl;
            } else {
                pos = buf.len;
            }

            return .{
                .frame = .{ .stream = .{
                    .stream_id = sid.value,
                    .offset = offset,
                    .fin = has_fin,
                    .data = data,
                } },
                .consumed = pos,
            };
        },
        // Fast-path: ACK frames (very frequent)
        0x02, 0x03 => {
            const has_ecn = frame_type_raw == 0x03; // hoisted: used twice below
            const la = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += la.len;
            const delay = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += delay.len;
            const count_vi = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += count_vi.len;
            const range_count: usize = @intCast(count_vi.value);
            if (range_count > 32) return error.InvalidFrame;

            var ack: AckFrame = .{
                .largest_acked = la.value,
                .ack_delay = delay.value,
                .ranges = undefined,
                .range_count = 0,
                .ect0 = 0,
                .ect1 = 0,
                .ecn_ce = 0,
                .has_ecn = has_ecn,
            };

            // First ACK range
            const first_range = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += first_range.len;
            ack.ranges[0] = .{ .gap = 0, .ack_range = first_range.value };
            ack.range_count = 1;

            // Additional ranges
            var i: usize = 0;
            while (i < range_count) : (i += 1) {
                const gap = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += gap.len;
                const r = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += r.len;
                if (ack.range_count < 32) {
                    ack.ranges[ack.range_count] = .{ .gap = gap.value, .ack_range = r.value };
                    ack.range_count += 1;
                }
            }

            if (has_ecn) {
                const ect0 = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += ect0.len;
                const ect1 = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += ect1.len;
                const ecn_ce = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
                pos += ecn_ce.len;
                ack.ect0 = ect0.value;
                ack.ect1 = ect1.value;
                ack.ecn_ce = ecn_ce.value;
            }

            return .{ .frame = .{ .ack = ack }, .consumed = pos };
        },
        // Common frames: PADDING, PING
        0x00 => {
            // Count consecutive PADDING bytes
            var count: usize = 0;
            while (pos + count < buf.len and buf[pos + count] == 0x00) : (count += 1) {}
            return .{ .frame = .{ .padding = count + 1 }, .consumed = pos + count };
        },
        0x01 => return .{ .frame = .ping, .consumed = pos },
        // Fast-path: CRYPTO frames (frequent in handshake)
        0x06 => {
            const offset = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += offset.len;
            const length = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += length.len;
            // Secondary validation: CRYPTO data length must not exceed 64KB (RFC 9000 §19.6 practical limit)
            if (length.value > 65536) return error.InvalidFrame;
            const data_len: usize = @intCast(length.value);
            if (pos + data_len > buf.len) return error.BufferTooShort;
            const data = buf[pos..][0..data_len];
            pos += data_len;
            return .{ .frame = .{ .crypto = .{ .offset = offset.value, .data = data } }, .consumed = pos };
        },
        0x10 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .max_data = v.value }, .consumed = pos };
        },
        0x11 => {
            const sid = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += sid.len;
            const md = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += md.len;
            return .{ .frame = .{ .max_stream_data = .{ .stream_id = sid.value, .max_data = md.value } }, .consumed = pos };
        },
        0x12 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .max_streams_bidi = v.value }, .consumed = pos };
        },
        0x13 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .max_streams_uni = v.value }, .consumed = pos };
        },
        0x14 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .data_blocked = v.value }, .consumed = pos };
        },
        0x15 => {
            const sid = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += sid.len;
            const max = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += max.len;
            return .{ .frame = .{ .stream_data_blocked = .{ .stream_id = sid.value, .max = max.value } }, .consumed = pos };
        },
        0x1c, 0x1d => {
            const ec = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += ec.len;
            const ft = if (frame_type_raw == 0x1c) varint.decode(buf[pos..]) orelse return error.InvalidFrame else blk: {
                break :blk varint.DecodeResult{ .value = 0, .len = 0 };
            };
            pos += ft.len;
            const rlen = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += rlen.len;
            const rl: usize = @intCast(rlen.value);
            if (rl > 256) return error.InvalidFrame; // cap reason string at 256 bytes
            if (pos + rl > buf.len) return error.BufferTooShort;
            const reason = buf[pos..][0..rl];
            pos += rl;
            return .{
                .frame = .{ .connection_close = .{
                    .error_code = ec.value,
                    .frame_type = ft.value,
                    .reason = reason,
                    .is_app = frame_type_raw == 0x1d,
                } },
                .consumed = pos,
            };
        },
        0x04 => {
            const sid = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += sid.len;
            const ec = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += ec.len;
            const fs = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += fs.len;
            return .{
                .frame = .{ .reset_stream = .{
                    .stream_id = sid.value,
                    .error_code = ec.value,
                    .final_size = fs.value,
                } },
                .consumed = pos,
            };
        },
        0x05 => {
            const sid = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += sid.len;
            const ec = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += ec.len;
            return .{
                .frame = .{ .stop_sending = .{
                    .stream_id = sid.value,
                    .error_code = ec.value,
                } },
                .consumed = pos,
            };
        },
        0x18 => {
            const seq = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += seq.len;
            const rpt = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += rpt.len;
            if (pos >= buf.len) return error.InvalidFrame;
            const cid_len = buf[pos];
            pos += 1;
            // RFC 9000 §10.3.2: CID length must be 0–20 bytes.
            if (cid_len > 20) return error.InvalidFrame;
            if (pos + cid_len + 16 > buf.len) return error.BufferTooShort;
            var f = NewConnectionIdFrame{
                .sequence_number = seq.value,
                .retire_prior_to = rpt.value,
                .cid = undefined,
                .cid_len = cid_len,
                .stateless_reset_token = undefined,
            };
            @memcpy(f.cid[0..cid_len], buf[pos..][0..cid_len]);
            pos += cid_len;
            @memcpy(&f.stateless_reset_token, buf[pos..][0..16]);
            pos += 16;
            return .{ .frame = .{ .new_connection_id = f }, .consumed = pos };
        },
        0x19 => {
            const seq = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += seq.len;
            return .{ .frame = .{ .retire_connection_id = seq.value }, .consumed = pos };
        },
        0x1a => {
            if (pos + 8 > buf.len) return error.BufferTooShort;
            var f = PathChallengeFrame{ .data = undefined };
            @memcpy(&f.data, buf[pos..][0..8]);
            pos += 8;
            return .{ .frame = .{ .path_challenge = f }, .consumed = pos };
        },
        0x1b => {
            if (pos + 8 > buf.len) return error.BufferTooShort;
            var f = PathResponseFrame{ .data = undefined };
            @memcpy(&f.data, buf[pos..][0..8]);
            pos += 8;
            return .{ .frame = .{ .path_response = f }, .consumed = pos };
        },
        0x1e => return .{ .frame = .handshake_done, .consumed = pos },
        0x16 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .streams_blocked_bidi = v.value }, .consumed = pos };
        },
        0x17 => {
            const v = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += v.len;
            return .{ .frame = .{ .streams_blocked_uni = v.value }, .consumed = pos };
        },
        0x07 => {
            const tlen = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += tlen.len;
            const tl: usize = @intCast(tlen.value);
            if (tl > 256) return error.InvalidFrame;
            if (pos + tl > buf.len) return error.BufferTooShort;
            const token = buf[pos..][0..tl];
            pos += tl;
            return .{ .frame = .{ .new_token = token }, .consumed = pos };
        },
        else => return error.UnknownFrame,
    }
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

pub fn encodeFrame(buf: []u8, frame: Frame) usize {
    var pos: usize = 0;

    switch (frame) {
        .padding => |n| {
            @memset(buf[pos..][0..n], 0x00);
            pos += n;
        },
        .ping => {
            buf[pos] = 0x01;
            pos += 1;
        },
        .crypto => |f| {
            buf[pos] = 0x06;
            pos += 1;
            pos += varint.encode(buf[pos..], f.offset);
            pos += varint.encode(buf[pos..], @intCast(f.data.len));
            @memcpy(buf[pos..][0..f.data.len], f.data);
            pos += f.data.len;
        },
        .stream => |f| {
            const has_offset = f.offset != 0;
            const flags: u8 = 0x02 | (if (has_offset) @as(u8, 0x04) else 0) | (if (f.fin) @as(u8, 0x01) else 0);
            buf[pos] = 0x08 | flags;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            if (has_offset) {
                pos += varint.encode(buf[pos..], f.offset);
            }
            pos += varint.encode(buf[pos..], @intCast(f.data.len));
            @memcpy(buf[pos..][0..f.data.len], f.data);
            pos += f.data.len;
        },
        .max_data => |v| {
            buf[pos] = 0x10;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .max_stream_data => |f| {
            buf[pos] = 0x11;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            pos += varint.encode(buf[pos..], f.max_data);
        },
        .handshake_done => {
            buf[pos] = 0x1e;
            pos += 1;
        },
        .connection_close => |f| {
            buf[pos] = if (f.is_app) @as(u8, 0x1d) else 0x1c;
            pos += 1;
            pos += varint.encode(buf[pos..], f.error_code);
            if (!f.is_app) {
                pos += varint.encode(buf[pos..], f.frame_type);
            }
            pos += varint.encode(buf[pos..], @intCast(f.reason.len));
            @memcpy(buf[pos..][0..f.reason.len], f.reason);
            pos += f.reason.len;
        },
        .ack => |f| {
            buf[pos] = if (f.has_ecn) @as(u8, 0x03) else 0x02;
            pos += 1;
            pos += varint.encode(buf[pos..], f.largest_acked);
            pos += varint.encode(buf[pos..], f.ack_delay);
            const extra_ranges = if (f.range_count > 0) f.range_count - 1 else 0;
            pos += varint.encode(buf[pos..], @intCast(extra_ranges));
            if (f.range_count > 0) {
                pos += varint.encode(buf[pos..], f.ranges[0].ack_range);
                for (1..f.range_count) |i| {
                    pos += varint.encode(buf[pos..], f.ranges[i].gap);
                    pos += varint.encode(buf[pos..], f.ranges[i].ack_range);
                }
            }
            if (f.has_ecn) {
                pos += varint.encode(buf[pos..], f.ect0);
                pos += varint.encode(buf[pos..], f.ect1);
                pos += varint.encode(buf[pos..], f.ecn_ce);
            }
        },
        .reset_stream => |f| {
            buf[pos] = 0x04;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            pos += varint.encode(buf[pos..], f.error_code);
            pos += varint.encode(buf[pos..], f.final_size);
        },
        .stop_sending => |f| {
            buf[pos] = 0x05;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            pos += varint.encode(buf[pos..], f.error_code);
        },
        .new_connection_id => |f| {
            buf[pos] = 0x18;
            pos += 1;
            pos += varint.encode(buf[pos..], f.sequence_number);
            pos += varint.encode(buf[pos..], f.retire_prior_to);
            buf[pos] = f.cid_len;
            pos += 1;
            @memcpy(buf[pos..][0..f.cid_len], f.cid[0..f.cid_len]);
            pos += f.cid_len;
            @memcpy(buf[pos..][0..16], &f.stateless_reset_token);
            pos += 16;
        },
        .retire_connection_id => |seq| {
            buf[pos] = 0x19;
            pos += 1;
            pos += varint.encode(buf[pos..], seq);
        },
        .path_challenge => |f| {
            buf[pos] = 0x1a;
            pos += 1;
            @memcpy(buf[pos..][0..8], &f.data);
            pos += 8;
        },
        .path_response => |f| {
            buf[pos] = 0x1b;
            pos += 1;
            @memcpy(buf[pos..][0..8], &f.data);
            pos += 8;
        },
        .max_streams_bidi => |v| {
            buf[pos] = 0x12;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .max_streams_uni => |v| {
            buf[pos] = 0x13;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .data_blocked => |v| {
            buf[pos] = 0x14;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .stream_data_blocked => |f| {
            buf[pos] = 0x15;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            pos += varint.encode(buf[pos..], f.max);
        },
        .streams_blocked_bidi => |v| {
            buf[pos] = 0x16;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .streams_blocked_uni => |v| {
            buf[pos] = 0x17;
            pos += 1;
            pos += varint.encode(buf[pos..], v);
        },
        .new_token => |tok| {
            buf[pos] = 0x07;
            pos += 1;
            pos += varint.encode(buf[pos..], @intCast(tok.len));
            @memcpy(buf[pos..][0..tok.len], tok);
            pos += tok.len;
        },
    }

    return pos;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "frame: CRYPTO encode/parse round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const data = [_]u8{ 0x01, 0x02, 0x03 };
    const f: Frame = .{ .crypto = .{ .offset = 0, .data = &data } };
    const written = encodeFrame(&buf, f);

    const result = try parseFrame(buf[0..written]);
    try testing.expectEqual(written, result.consumed);
    switch (result.frame) {
        .crypto => |c| {
            try testing.expectEqual(@as(u62, 0), c.offset);
            try testing.expectEqualSlices(u8, &data, c.data);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: STREAM encode/parse round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const payload = [_]u8{ 0xde, 0xad, 0xbe, 0xef };
    const f: Frame = .{ .stream = .{
        .stream_id = 4,
        .offset = 0,
        .fin = true,
        .data = &payload,
    } };
    const written = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..written]);
    switch (result.frame) {
        .stream => |s| {
            try testing.expectEqual(@as(u62, 4), s.stream_id);
            try testing.expect(s.fin);
            try testing.expectEqualSlices(u8, &payload, s.data);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: ACK encode/parse round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const ack: AckFrame = .{
        .largest_acked = 10,
        .ack_delay = 0,
        .ranges = [_]AckRange{.{ .gap = 0, .ack_range = 5 }} ++ [_]AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    const f: Frame = .{ .ack = ack };
    const written = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..written]);
    switch (result.frame) {
        .ack => |a| {
            try testing.expectEqual(@as(u62, 10), a.largest_acked);
            try testing.expectEqual(@as(usize, 1), a.range_count);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: HANDSHAKE_DONE encode/parse" {
    const testing = std.testing;
    var buf: [4]u8 = undefined;
    const written = encodeFrame(&buf, .handshake_done);
    try testing.expectEqual(@as(usize, 1), written);
    const result = try parseFrame(buf[0..written]);
    switch (result.frame) {
        .handshake_done => {},
        else => return error.WrongFrameType,
    }
}

test "frame: PING encode/parse" {
    const testing = std.testing;
    var buf: [4]u8 = undefined;
    const written = encodeFrame(&buf, .ping);
    try testing.expectEqual(@as(usize, 1), written);
    const result = try parseFrame(buf[0..1]);
    switch (result.frame) {
        .ping => {},
        else => return error.WrongFrameType,
    }
}

test "frame: RESET_STREAM encode/parse round-trip" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const f: Frame = .{ .reset_stream = .{ .stream_id = 3, .error_code = 7, .final_size = 1024 } };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .reset_stream => |r| {
            try testing.expectEqual(@as(u62, 3), r.stream_id);
            try testing.expectEqual(@as(u62, 7), r.error_code);
            try testing.expectEqual(@as(u62, 1024), r.final_size);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: STOP_SENDING encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .stop_sending = .{ .stream_id = 5, .error_code = 2 } };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .stop_sending => |s| {
            try testing.expectEqual(@as(u62, 5), s.stream_id);
            try testing.expectEqual(@as(u62, 2), s.error_code);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: NEW_CONNECTION_ID encode/parse round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const tok = [_]u8{0xbb} ** 16;
    var cid_bytes: [20]u8 = undefined;
    @memset(&cid_bytes, 0xaa);
    const f: Frame = .{ .new_connection_id = .{
        .sequence_number = 2,
        .retire_prior_to = 1,
        .cid = cid_bytes,
        .cid_len = 8,
        .stateless_reset_token = tok,
    } };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .new_connection_id => |nc| {
            try testing.expectEqual(@as(u62, 2), nc.sequence_number);
            try testing.expectEqual(@as(u62, 1), nc.retire_prior_to);
            try testing.expectEqual(@as(u8, 8), nc.cid_len);
            try testing.expectEqualSlices(u8, &tok, &nc.stateless_reset_token);
            try testing.expectEqualSlices(u8, cid_bytes[0..8], nc.cid[0..8]);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: RETIRE_CONNECTION_ID encode/parse round-trip" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const f: Frame = .{ .retire_connection_id = 42 };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .retire_connection_id => |seq| try testing.expectEqual(@as(u62, 42), seq),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: PATH_CHALLENGE encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const challenge_data = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    const f: Frame = .{ .path_challenge = .{ .data = challenge_data } };
    const n = encodeFrame(&buf, f);
    try testing.expectEqual(@as(usize, 9), n); // 1 type byte + 8 data bytes
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .path_challenge => |c| try testing.expectEqualSlices(u8, &challenge_data, &c.data),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: MAX_DATA encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .max_data = 1_000_000 };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .max_data => |v| try testing.expectEqual(@as(u62, 1_000_000), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: MAX_STREAM_DATA encode/parse round-trip" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const f: Frame = .{ .max_stream_data = .{ .stream_id = 4, .max_data = 65536 } };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .max_stream_data => |m| {
            try testing.expectEqual(@as(u62, 4), m.stream_id);
            try testing.expectEqual(@as(u62, 65536), m.max_data);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: ACK with multiple ranges encode/parse round-trip" {
    const testing = std.testing;
    var buf: [128]u8 = undefined;
    var ranges: [32]AckRange = [_]AckRange{.{ .gap = 0, .ack_range = 0 }} ** 32;
    ranges[0] = .{ .gap = 0, .ack_range = 4 }; // first range: pn 16..20
    ranges[1] = .{ .gap = 2, .ack_range = 3 }; // gap=2, second range: 4 pkts
    const ack = AckFrame{
        .largest_acked = 20,
        .ack_delay = 5,
        .ranges = ranges,
        .range_count = 2,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    };
    const n = encodeFrame(&buf, .{ .ack = ack });
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .ack => |a| {
            try testing.expectEqual(@as(u62, 20), a.largest_acked);
            try testing.expectEqual(@as(u62, 5), a.ack_delay);
            try testing.expectEqual(@as(usize, 2), a.range_count);
            try testing.expectEqual(@as(u62, 4), a.ranges[0].ack_range);
            try testing.expectEqual(@as(u62, 2), a.ranges[1].gap);
            try testing.expectEqual(@as(u62, 3), a.ranges[1].ack_range);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: MAX_STREAMS_BIDI encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .max_streams_bidi = 128 };
    const n = encodeFrame(&buf, f);
    try testing.expect(n > 0);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .max_streams_bidi => |v| try testing.expectEqual(@as(u62, 128), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: MAX_STREAMS_UNI encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .max_streams_uni = 64 };
    const n = encodeFrame(&buf, f);
    try testing.expect(n > 0);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .max_streams_uni => |v| try testing.expectEqual(@as(u62, 64), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: DATA_BLOCKED encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .data_blocked = 500_000 };
    const n = encodeFrame(&buf, f);
    try testing.expect(n > 0);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .data_blocked => |v| try testing.expectEqual(@as(u62, 500_000), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: STREAM_DATA_BLOCKED encode/parse round-trip" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    const f: Frame = .{ .stream_data_blocked = .{ .stream_id = 7, .max = 32768 } };
    const n = encodeFrame(&buf, f);
    try testing.expect(n > 0);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .stream_data_blocked => |s| {
            try testing.expectEqual(@as(u62, 7), s.stream_id);
            try testing.expectEqual(@as(u62, 32768), s.max);
        },
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: ACK range_count > 32 returns InvalidFrame" {
    // Build an ACK with range_count = 257 (well above the cap of 32).
    // Use a 2-byte varint for range_count to fit > 63.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x02;
    pos += 1; // ACK type
    pos += varint.encode(buf[pos..], 10); // largest_acked
    pos += varint.encode(buf[pos..], 0); // ack_delay
    pos += varint.encode(buf[pos..], 257); // range_count > 32
    pos += varint.encode(buf[pos..], 5); // first ACK range
    // Do NOT add 257 additional range pairs — the cap fires before the loop.
    try std.testing.expectError(error.InvalidFrame, parseFrame(buf[0..pos]));
}

test "frame: ACK range_count 33 returns InvalidFrame" {
    // 33 is one past the storage cap of 32 — must be rejected.
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x02;
    pos += 1; // ACK type
    pos += varint.encode(buf[pos..], 10); // largest_acked
    pos += varint.encode(buf[pos..], 0); // ack_delay
    pos += varint.encode(buf[pos..], 33); // range_count = 33 (one past cap)
    pos += varint.encode(buf[pos..], 5); // first ACK range
    try std.testing.expectError(error.InvalidFrame, parseFrame(buf[0..pos]));
}

test "frame: ACK range_count exactly 32 is accepted" {
    // 32 is the storage cap — must parse successfully (only > 32 is rejected).
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x02;
    pos += 1; // ACK type
    pos += varint.encode(buf[pos..], 63); // largest_acked (needs room for 32 ranges)
    pos += varint.encode(buf[pos..], 0); // ack_delay
    pos += varint.encode(buf[pos..], 32); // range_count = 32
    pos += varint.encode(buf[pos..], 0); // first ACK range (ack_range=0)
    // range_count=32 means 32 additional (gap, ack_range) pairs after the first ACK range.
    var i: usize = 0;
    while (i < 32) : (i += 1) {
        pos += varint.encode(buf[pos..], 0); // gap
        pos += varint.encode(buf[pos..], 0); // ack_range
    }
    const result = try parseFrame(buf[0..pos]);
    switch (result.frame) {
        .ack => |a| try std.testing.expect(a.range_count > 0),
        else => return error.WrongFrameType,
    }
}

test "frame: parseFrame empty buffer returns BufferEmpty" {
    try std.testing.expectError(error.BufferEmpty, parseFrame(&.{}));
}

test "frame: NEW_TOKEN encode/parse round-trip" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const token_data = [_]u8{ 0x01, 0x02, 0x03, 0x04 };
    const f: Frame = .{ .new_token = &token_data };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .new_token => |t| try testing.expectEqualSlices(u8, &token_data, t),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: NEW_TOKEN empty token round-trip" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const f: Frame = .{ .new_token = &.{} };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .new_token => |t| try testing.expectEqual(@as(usize, 0), t.len),
        else => return error.WrongFrameType,
    }
}

test "frame: NEW_TOKEN > 256 bytes returns InvalidFrame" {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x07;
    pos += 1; // NEW_TOKEN type
    pos += varint.encode(buf[pos..], 257); // length > cap of 256
    @memset(buf[pos..][0..257], 0xaa);
    pos += 257;
    try std.testing.expectError(error.InvalidFrame, parseFrame(buf[0..pos]));
}

test "frame: STREAMS_BLOCKED_BIDI encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .streams_blocked_bidi = 10 };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .streams_blocked_bidi => |v| try testing.expectEqual(@as(u62, 10), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: STREAMS_BLOCKED_UNI encode/parse round-trip" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const f: Frame = .{ .streams_blocked_uni = 5 };
    const n = encodeFrame(&buf, f);
    const result = try parseFrame(buf[0..n]);
    switch (result.frame) {
        .streams_blocked_uni => |v| try testing.expectEqual(@as(u62, 5), v),
        else => return error.WrongFrameType,
    }
    try testing.expectEqual(n, result.consumed);
}

test "frame: parseFrame unknown byte frame type (0x1f) returns UnknownFrame" {
    // 0x1f = 31, a valid 1-byte QUIC varint with no assigned frame type.
    // Top two bits are 00 (single-byte varint), value=31; falls to else → UnknownFrame.
    const buf = [_]u8{0x1f};
    try std.testing.expectError(error.UnknownFrame, parseFrame(&buf));
}

test "frame: parseFrame varint frame type > 0xFF returns UnknownFrame" {
    // 2-byte varint encoding of value 256 (0x41 0x00)
    const buf = [_]u8{ 0x41, 0x00 };
    try std.testing.expectError(error.UnknownFrame, parseFrame(&buf));
}

test "frame: PADDING consecutive zero bytes counts all" {
    const buf = [_]u8{ 0x00, 0x00, 0x00, 0x00, 0x00 }; // 5 PADDING bytes
    const result = try parseFrame(&buf);
    switch (result.frame) {
        .padding => |n| try std.testing.expectEqual(@as(usize, 5), n),
        else => return error.WrongFrameType,
    }
    try std.testing.expectEqual(@as(usize, 5), result.consumed);
}

test "frame: ACK_ECN (0x03) with ECN counts parses has_ecn=true" {
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x03;
    pos += 1; // ACK_ECN type
    pos += varint.encode(buf[pos..], 10); // largest_acked
    pos += varint.encode(buf[pos..], 0); // ack_delay
    pos += varint.encode(buf[pos..], 0); // range_count = 0
    pos += varint.encode(buf[pos..], 5); // first ACK range
    pos += varint.encode(buf[pos..], 7); // ECT0
    pos += varint.encode(buf[pos..], 3); // ECT1
    pos += varint.encode(buf[pos..], 1); // ECN_CE
    const result = try parseFrame(buf[0..pos]);
    switch (result.frame) {
        .ack => |a| {
            try std.testing.expect(a.has_ecn);
            try std.testing.expectEqual(@as(u64, 7), a.ect0);
            try std.testing.expectEqual(@as(u64, 3), a.ect1);
            try std.testing.expectEqual(@as(u64, 1), a.ecn_ce);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: STREAM without length field (0x08) consumes to buffer end" {
    // Type 0x08: no offset bit, no length bit, no FIN bit
    var buf: [12]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x08;
    pos += 1; // STREAM, no flags
    pos += varint.encode(buf[pos..], 42); // stream_id = 42
    const payload = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
    @memcpy(buf[pos..][0..payload.len], &payload);
    pos += payload.len;
    const result = try parseFrame(buf[0..pos]);
    switch (result.frame) {
        .stream => |s| {
            try std.testing.expectEqual(@as(u62, 42), s.stream_id);
            try std.testing.expectEqual(@as(u62, 0), s.offset);
            try std.testing.expect(!s.fin);
            try std.testing.expectEqualSlices(u8, &payload, s.data);
        },
        else => return error.WrongFrameType,
    }
    try std.testing.expectEqual(pos, result.consumed);
}

test "frame: CONNECTION_CLOSE reason exactly 256 bytes is accepted" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x1c;
    pos += 1; // CONNECTION_CLOSE (QUIC)
    pos += varint.encode(buf[pos..], 0); // error_code = 0
    pos += varint.encode(buf[pos..], 0); // frame_type = 0
    pos += varint.encode(buf[pos..], 256); // reason_len = 256 (at the cap)
    @memset(buf[pos..][0..256], 0x61); // 256 x 'a'
    pos += 256;
    const result = try parseFrame(buf[0..pos]);
    switch (result.frame) {
        .connection_close => |cc| try testing.expectEqual(@as(usize, 256), cc.reason.len),
        else => return error.WrongFrameType,
    }
}

test "frame: CONNECTION_CLOSE reason 257 bytes returns InvalidFrame" {
    var buf: [512]u8 = undefined;
    var pos: usize = 0;
    buf[pos] = 0x1c;
    pos += 1;
    pos += varint.encode(buf[pos..], 0); // error_code
    pos += varint.encode(buf[pos..], 0); // frame_type
    pos += varint.encode(buf[pos..], 257); // reason_len = 257 (one past the cap)
    @memset(buf[pos..][0..257], 0x62);
    pos += 257;
    try std.testing.expectError(error.InvalidFrame, parseFrame(buf[0..pos]));
}

test "frame: PATH_RESPONSE echoes PATH_CHALLENGE data" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    const data = [8]u8{ 0xde, 0xad, 0xbe, 0xef, 0x01, 0x02, 0x03, 0x04 };

    // Encode a challenge, then encode a response echoing the same data.
    const challenge: Frame = .{ .path_challenge = .{ .data = data } };
    const n_c = encodeFrame(&buf, challenge);
    const parsed_c = try parseFrame(buf[0..n_c]);

    const echo_data = parsed_c.frame.path_challenge.data;
    const response: Frame = .{ .path_response = .{ .data = echo_data } };
    var rbuf: [16]u8 = undefined;
    const n_r = encodeFrame(&rbuf, response);
    const parsed_r = try parseFrame(rbuf[0..n_r]);
    switch (parsed_r.frame) {
        .path_response => |r| try testing.expectEqualSlices(u8, &data, &r.data),
        else => return error.WrongFrameType,
    }
}

test "frame: ACK_ECN (0x03) encode/decode round-trip preserves ECN counts" {
    const testing = std.testing;
    const ack_frame = Frame{ .ack = AckFrame{
        .largest_acked = 42,
        .ack_delay = 10,
        .ranges = [_]AckRange{.{ .gap = 0, .ack_range = 42 }} ++ [_]AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 100,
        .ect1 = 200,
        .ecn_ce = 5,
        .has_ecn = true,
    } };

    var buf: [64]u8 = undefined;
    const n = encodeFrame(&buf, ack_frame);
    // Type byte must be 0x03 for ACK_ECN
    try testing.expectEqual(@as(u8, 0x03), buf[0]);

    const parsed = try parseFrame(buf[0..n]);
    switch (parsed.frame) {
        .ack => |a| {
            try testing.expect(a.has_ecn);
            try testing.expectEqual(@as(u62, 42), a.largest_acked);
            try testing.expectEqual(@as(u62, 100), a.ect0);
            try testing.expectEqual(@as(u62, 200), a.ect1);
            try testing.expectEqual(@as(u62, 5), a.ecn_ce);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: ACK (0x02) without ECN has_ecn=false" {
    const testing = std.testing;
    const ack_frame = Frame{ .ack = AckFrame{
        .largest_acked = 10,
        .ack_delay = 0,
        .ranges = [_]AckRange{.{ .gap = 0, .ack_range = 10 }} ++ [_]AckRange{.{ .gap = 0, .ack_range = 0 }} ** 31,
        .range_count = 1,
        .ect0 = 0,
        .ect1 = 0,
        .ecn_ce = 0,
        .has_ecn = false,
    } };

    var buf: [32]u8 = undefined;
    const n = encodeFrame(&buf, ack_frame);
    try testing.expectEqual(@as(u8, 0x02), buf[0]);

    const parsed = try parseFrame(buf[0..n]);
    switch (parsed.frame) {
        .ack => |a| try testing.expect(!a.has_ecn),
        else => return error.WrongFrameType,
    }
}

// ============================================================================
// Regression tests for frame parsing optimizations
// ============================================================================

test "frame: parse STREAM frame (high-frequency type)" {
    const testing = std.testing;
    // Regression: STREAM moved to first case in switch; verify it still parses correctly
    var buf: [256]u8 = undefined;
    const stream_frame = Frame{ .stream = .{
        .stream_id = 42,
        .offset = 100,
        .fin = false,
        .data = "hello",
    } };
    const n = encodeFrame(&buf, stream_frame);

    const parsed = try parseFrame(buf[0..n]);
    switch (parsed.frame) {
        .stream => |s| {
            try testing.expectEqual(@as(u62, 42), s.stream_id);
            try testing.expectEqual(@as(u62, 100), s.offset);
            try testing.expectEqual(false, s.fin);
            try testing.expectEqualSlices(u8, "hello", s.data);
        },
        else => return error.WrongFrameType,
    }
}

test "frame: parse PADDING frame (common frame type)" {
    const testing = std.testing;
    // Regression: PADDING moved to early position; verify it still parses correctly
    var buf: [10]u8 = undefined;
    @memset(&buf, 0x00); // PADDING is all zeros

    const parsed = try parseFrame(&buf);
    switch (parsed.frame) {
        .padding => |p| try testing.expectEqual(@as(usize, 10), p),
        else => return error.WrongFrameType,
    }
}

test "frame: parse PING frame (moved to early position)" {
    // Regression: PING moved earlier in switch; verify it still parses correctly
    const buf = [_]u8{0x01}; // PING frame type

    const parsed = try parseFrame(&buf);
    switch (parsed.frame) {
        .ping => {},
        else => return error.WrongFrameType,
    }
}

test "frame: parse all critical frame types in sequence" {
    const testing = std.testing;
    // Regression: verify reordered switch handles all frame types correctly
    const frame_types = [_]u8{
        0x00, // PADDING
        0x01, // PING
        0x02, // ACK
        0x06, // CRYPTO
        0x08, // STREAM (with offset, length, fin)
        0x1c, // CONNECTION_CLOSE
    };

    for (frame_types) |ft| {
        var buf: [256]u8 = undefined;
        // Build minimal valid frame for each type
        var pos: usize = 0;

        if (ft == 0x00) {
            // PADDING: just zeros
            buf[0] = 0x00;
            pos = 1;
        } else if (ft == 0x01) {
            // PING: just type
            buf[0] = 0x01;
            pos = 1;
        } else if (ft == 0x02) {
            // ACK: type + largest_acked + ack_delay + range_count + first_range
            buf[0] = 0x02;
            buf[1] = 0x00; // largest_acked = 0 (1 byte)
            buf[2] = 0x00; // ack_delay = 0 (1 byte)
            buf[3] = 0x00; // range_count = 0 (1 byte)
            buf[4] = 0x00; // first_range = 0 (1 byte)
            pos = 5;
        } else if (ft == 0x06) {
            // CRYPTO: type + offset + length + data
            buf[0] = 0x06;
            buf[1] = 0x00; // offset = 0
            buf[2] = 0x05; // length = 5
            buf[3..8].* = "hello".*;
            pos = 8;
        } else if (ft == 0x08) {
            // STREAM (0x08 = no offset, no length, no fin): type + stream_id + data
            buf[0] = 0x08;
            buf[1] = 0x00; // stream_id = 0
            buf[2..7].* = "hello".*;
            pos = 7;
        } else if (ft == 0x1c) {
            // CONNECTION_CLOSE: type + error_code + frame_type + reason_len + reason
            buf[0] = 0x1c;
            buf[1] = 0x00; // error_code = 0
            buf[2] = 0x00; // frame_type = 0
            buf[3] = 0x02; // reason_len = 2
            buf[4..6].* = "OK".*;
            pos = 6;
        }

        const parsed = try parseFrame(buf[0..pos]);
        try testing.expect(parsed.consumed > 0);
    }
}
