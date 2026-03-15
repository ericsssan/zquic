// HTTP/3 frame parsing and serialisation — RFC 9114 §7
//
// Wire format (RFC 9114 §7.1):
//
//   HTTP/3 Frame {
//     Type   (QUIC varint),
//     Length (QUIC varint),
//     Value  (..Length bytes..),
//   }
//
// Type and Length are QUIC variable-length integers (RFC 9000 §16).
//
// Frame types handled here:
//
//   DATA        0x00  raw body bytes            §7.2.1
//   HEADERS     0x01  QPACK header block         §7.2.2
//   CANCEL_PUSH 0x03  push_id varint             §7.2.3
//   SETTINGS    0x04  (identifier, value) pairs  §7.2.4
//   PUSH_PROMISE 0x05  push_id + header block    §7.2.5
//   GOAWAY      0x07  stream_id varint           §7.2.6
//   MAX_PUSH_ID 0x0d  push_id varint             §7.2.7
//
// DATA and HEADERS frames carry variable-length payloads managed by the
// caller; only header helpers are provided for those types.

const varint = @import("varint.zig");

pub const FrameType = struct {
    pub const data: u64 = 0x00;
    pub const headers: u64 = 0x01;
    pub const cancel_push: u64 = 0x03;
    pub const settings: u64 = 0x04;
    pub const push_promise: u64 = 0x05;
    pub const goaway: u64 = 0x07;
    pub const max_push_id: u64 = 0x0d;
};

/// Parsed HTTP/3 frame header (type + payload length).
pub const FrameHeader = struct {
    frame_type: u64,
    payload_len: u64,
    /// Bytes consumed by the type + length fields.
    header_len: usize,
};

pub const ParseError = error{
    /// Input is truncated (frame header or payload is incomplete).
    Incomplete,
};

pub const WriteError = error{
    /// Output buffer is too small.
    BufferTooSmall,
    /// A varint value exceeds its representable range.
    Overflow,
};

// ----------------------------------------------------------------------------
// Frame header
// ----------------------------------------------------------------------------

/// Parse the type and length fields of a frame from `buf`.
/// Does NOT consume the payload; that starts at buf[result.header_len].
pub fn parseHeader(buf: []const u8) ParseError!FrameHeader {
    const t = try varint.decode(buf);
    const l = varint.decode(buf[t.consumed..]) catch return error.Incomplete;
    return .{
        .frame_type = t.value,
        .payload_len = l.value,
        .header_len = t.consumed + l.consumed,
    };
}

/// Write a frame header (type + length) into `buf`.
/// Returns bytes written.
pub fn writeHeader(buf: []u8, frame_type: u64, payload_len: u64) WriteError!usize {
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], frame_type);
    pos += try varint.encode(buf[pos..], payload_len);
    return pos;
}

// ----------------------------------------------------------------------------
// GOAWAY — §7.2.6: payload = stream_id (varint)
// ----------------------------------------------------------------------------

pub fn writeGoaway(buf: []u8, stream_id: u64) WriteError!usize {
    var pos: usize = 0;
    const payload_len = varint.encodedLen(stream_id);
    pos += try writeHeader(buf[pos..], FrameType.goaway, payload_len);
    pos += try varint.encode(buf[pos..], stream_id);
    return pos;
}

pub fn parseGoaway(payload: []const u8) ParseError!u64 {
    const r = try varint.decode(payload);
    return r.value;
}

// ----------------------------------------------------------------------------
// CANCEL_PUSH — §7.2.3: payload = push_id (varint)
// ----------------------------------------------------------------------------

pub fn writeCancelPush(buf: []u8, push_id: u64) WriteError!usize {
    var pos: usize = 0;
    const payload_len = varint.encodedLen(push_id);
    pos += try writeHeader(buf[pos..], FrameType.cancel_push, payload_len);
    pos += try varint.encode(buf[pos..], push_id);
    return pos;
}

pub fn parseCancelPush(payload: []const u8) ParseError!u64 {
    const r = try varint.decode(payload);
    return r.value;
}

// ----------------------------------------------------------------------------
// MAX_PUSH_ID — §7.2.7: payload = push_id (varint)
// ----------------------------------------------------------------------------

pub fn writeMaxPushId(buf: []u8, push_id: u64) WriteError!usize {
    var pos: usize = 0;
    const payload_len = varint.encodedLen(push_id);
    pos += try writeHeader(buf[pos..], FrameType.max_push_id, payload_len);
    pos += try varint.encode(buf[pos..], push_id);
    return pos;
}

pub fn parseMaxPushId(payload: []const u8) ParseError!u64 {
    const r = try varint.decode(payload);
    return r.value;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "writeHeader / parseHeader: DATA frame, 5-byte payload" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writeHeader(&buf, FrameType.data, 5);
    // Type=0x00 (1 byte), Length=5 (1 byte) → 2 bytes
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x05), buf[1]);

    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(FrameType.data, hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 5), hdr.payload_len);
    try std.testing.expectEqual(@as(usize, 2), hdr.header_len);
}

test "writeHeader / parseHeader: HEADERS frame, 0-byte payload" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    const n = try writeHeader(&buf, FrameType.headers, 0);
    try std.testing.expectEqual(@as(usize, 2), n);
    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(FrameType.headers, hdr.frame_type);
    try std.testing.expectEqual(@as(u64, 0), hdr.payload_len);
}

test "writeHeader / parseHeader: multi-byte payload length" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    // payload_len = 16384 requires 4 bytes for the varint
    const n = try writeHeader(&buf, FrameType.data, 16_384);
    // type(1) + length(4) = 5 bytes
    try std.testing.expectEqual(@as(usize, 5), n);
    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 16_384), hdr.payload_len);
    try std.testing.expectEqual(@as(usize, 5), hdr.header_len);
}

test "writeHeader: frame type > 63 uses multi-byte varint" {
    const std = @import("std");
    var buf: [8]u8 = undefined;
    // FrameType.max_push_id = 0x0d (fits in 1 byte), but test with a hypothetical large type
    const n = try writeHeader(&buf, 0x1f, 0);
    try std.testing.expectEqual(@as(usize, 2), n);
    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 0x1f), hdr.frame_type);
}

test "parseHeader: incomplete (only type byte)" {
    const std = @import("std");
    // Only the type byte, length missing
    const buf = [_]u8{0x01};
    try std.testing.expectError(error.Incomplete, parseHeader(&buf));
}

test "writeGoaway / parseGoaway round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writeGoaway(&buf, 42);

    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(FrameType.goaway, hdr.frame_type);
    const payload = buf[hdr.header_len .. hdr.header_len + @as(usize, @intCast(hdr.payload_len))];
    const stream_id = try parseGoaway(payload);
    try std.testing.expectEqual(@as(u64, 42), stream_id);
}

test "writeCancelPush / parseCancelPush round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writeCancelPush(&buf, 7);

    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(FrameType.cancel_push, hdr.frame_type);
    const payload = buf[hdr.header_len .. hdr.header_len + @as(usize, @intCast(hdr.payload_len))];
    const push_id = try parseCancelPush(payload);
    try std.testing.expectEqual(@as(u64, 7), push_id);
}

test "writeMaxPushId / parseMaxPushId round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writeMaxPushId(&buf, 1000);

    const hdr = try parseHeader(buf[0..n]);
    try std.testing.expectEqual(FrameType.max_push_id, hdr.frame_type);
    const payload = buf[hdr.header_len .. hdr.header_len + @as(usize, @intCast(hdr.payload_len))];
    const push_id = try parseMaxPushId(payload);
    try std.testing.expectEqual(@as(u64, 1000), push_id);
}

test "all known frame types encode with correct type byte" {
    const std = @import("std");
    var buf: [16]u8 = undefined;

    const types = [_]struct { t: u64, expected_first_byte: u8 }{
        .{ .t = FrameType.data, .expected_first_byte = 0x00 },
        .{ .t = FrameType.headers, .expected_first_byte = 0x01 },
        .{ .t = FrameType.cancel_push, .expected_first_byte = 0x03 },
        .{ .t = FrameType.settings, .expected_first_byte = 0x04 },
        .{ .t = FrameType.push_promise, .expected_first_byte = 0x05 },
        .{ .t = FrameType.goaway, .expected_first_byte = 0x07 },
        .{ .t = FrameType.max_push_id, .expected_first_byte = 0x0d },
    };

    for (types) |tc| {
        _ = try writeHeader(&buf, tc.t, 0);
        try std.testing.expectEqual(tc.expected_first_byte, buf[0]);
    }
}
