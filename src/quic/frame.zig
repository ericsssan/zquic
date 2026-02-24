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
    data_blocked: u62,
    stream_data_blocked: struct { stream_id: u62, max: u62 },
};

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub const ParseResult = struct {
    frame: Frame,
    consumed: usize,
};

pub fn parseFrame(buf: []const u8) !ParseResult {
    if (buf.len == 0) return error.BufferEmpty;

    const type_vi = varint.decode(buf) orelse return error.InvalidFrame;
    var pos: usize = type_vi.len;
    const frame_type_raw: u8 = if (type_vi.value <= 0xff) @intCast(type_vi.value) else return error.UnknownFrame;

    switch (frame_type_raw) {
        0x00 => {
            // Count consecutive PADDING bytes
            var count: usize = 0;
            while (pos + count < buf.len and buf[pos + count] == 0x00) : (count += 1) {}
            return .{ .frame = .{ .padding = count + 1 }, .consumed = pos + count };
        },
        0x01 => return .{ .frame = .ping, .consumed = pos },
        0x02, 0x03 => {
            const la = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += la.len;
            const delay = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += delay.len;
            const count_vi = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += count_vi.len;
            const range_count: usize = @intCast(count_vi.value);

            var ack: AckFrame = .{
                .largest_acked = la.value,
                .ack_delay = delay.value,
                .ranges = undefined,
                .range_count = 0,
                .ect0 = 0,
                .ect1 = 0,
                .ecn_ce = 0,
                .has_ecn = frame_type_raw == 0x03,
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

            if (frame_type_raw == 0x03) {
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
        0x06 => {
            const offset = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += offset.len;
            const length = varint.decode(buf[pos..]) orelse return error.InvalidFrame;
            pos += length.len;
            const data_len: usize = @intCast(length.value);
            if (pos + data_len > buf.len) return error.BufferTooShort;
            const data = buf[pos..][0..data_len];
            pos += data_len;
            return .{ .frame = .{ .crypto = .{ .offset = offset.value, .data = data } }, .consumed = pos };
        },
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
        0x1e => return .{ .frame = .handshake_done, .consumed = pos },
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
            const flags: u8 = 0x02 | (if (f.offset != 0) @as(u8, 0x04) else 0) | (if (f.fin) @as(u8, 0x01) else 0);
            buf[pos] = 0x08 | flags;
            pos += 1;
            pos += varint.encode(buf[pos..], f.stream_id);
            if (f.offset != 0) {
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
        else => {}, // encode-on-demand for other frame types
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
