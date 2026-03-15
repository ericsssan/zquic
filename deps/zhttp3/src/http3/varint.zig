// QUIC variable-length integer encoding — RFC 9000 §16.1
//
// The two most-significant bits of the first byte indicate the total length:
//
//   MSBs  Length  Value range
//   00    1 byte  0 – 63
//   01    2 bytes 0 – 16 383
//   10    4 bytes 0 – 1 073 741 823
//   11    8 bytes 0 – 4 611 686 018 427 387 903
//
// Values are stored big-endian with the 2-bit prefix in the high bits of
// the first byte.  This is distinct from the HPACK/QPACK integer encoding
// used in src/qpack/int.zig.

/// Maximum representable value (2^62 - 1).
pub const MAX_VALUE: u64 = (1 << 62) - 1;

pub const DecodeResult = struct {
    value: u64,
    consumed: usize,
};

/// Decode one variable-length integer from `buf`.
/// Returns error.Incomplete if `buf` is too short.
pub fn decode(buf: []const u8) error{Incomplete}!DecodeResult {
    if (buf.len == 0) return error.Incomplete;
    const len: usize = switch (buf[0] >> 6) {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        else => unreachable,
    };
    if (buf.len < len) return error.Incomplete;
    var value: u64 = @as(u64, buf[0] & 0x3f);
    for (1..len) |i| value = (value << 8) | @as(u64, buf[i]);
    return .{ .value = value, .consumed = len };
}

/// Number of bytes needed to encode `value`.
pub fn encodedLen(value: u64) usize {
    if (value <= 63) return 1;
    if (value <= 16_383) return 2;
    if (value <= 1_073_741_823) return 4;
    return 8;
}

/// Encode `value` into `buf` (big-endian, with 2-bit length prefix).
/// Returns error.BufferTooSmall if `buf` is too short.
/// Returns error.Overflow if `value` exceeds MAX_VALUE.
pub fn encode(buf: []u8, value: u64) error{ BufferTooSmall, Overflow }!usize {
    if (value > MAX_VALUE) return error.Overflow;
    const len = encodedLen(value);
    if (buf.len < len) return error.BufferTooSmall;

    // Write big-endian bytes.
    var v = value;
    var i: usize = len;
    while (i > 0) {
        i -= 1;
        buf[i] = @intCast(v & 0xff);
        v >>= 8;
    }
    // OR the 2-bit length prefix into the first byte.
    buf[0] |= switch (len) {
        1 => @as(u8, 0x00),
        2 => @as(u8, 0x40),
        4 => @as(u8, 0x80),
        8 => @as(u8, 0xc0),
        else => unreachable,
    };
    return len;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "encode/decode: 1-byte boundary values (0, 63)" {
    const std = @import("std");
    var buf: [8]u8 = undefined;

    const n0 = try encode(&buf, 0);
    try std.testing.expectEqual(@as(usize, 1), n0);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    const r0 = try decode(buf[0..n0]);
    try std.testing.expectEqual(@as(u64, 0), r0.value);

    const n63 = try encode(&buf, 63);
    try std.testing.expectEqual(@as(usize, 1), n63);
    try std.testing.expectEqual(@as(u8, 0x3f), buf[0]);
    const r63 = try decode(buf[0..n63]);
    try std.testing.expectEqual(@as(u64, 63), r63.value);
}

test "encode/decode: 2-byte boundary values (64, 16383)" {
    const std = @import("std");
    var buf: [8]u8 = undefined;

    const n64 = try encode(&buf, 64);
    try std.testing.expectEqual(@as(usize, 2), n64);
    const r64 = try decode(buf[0..n64]);
    try std.testing.expectEqual(@as(u64, 64), r64.value);
    try std.testing.expectEqual(@as(usize, 2), r64.consumed);

    const n = try encode(&buf, 16_383);
    try std.testing.expectEqual(@as(usize, 2), n);
    const r = try decode(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 16_383), r.value);
}

test "encode/decode: 4-byte boundary values (16384, 1073741823)" {
    const std = @import("std");
    var buf: [8]u8 = undefined;

    for ([_]u64{ 16_384, 1_073_741_823 }) |v| {
        const n = try encode(&buf, v);
        try std.testing.expectEqual(@as(usize, 4), n);
        const r = try decode(buf[0..n]);
        try std.testing.expectEqual(v, r.value);
    }
}

test "encode/decode: 8-byte boundary values (1073741824, MAX_VALUE)" {
    const std = @import("std");
    var buf: [8]u8 = undefined;

    for ([_]u64{ 1_073_741_824, MAX_VALUE }) |v| {
        const n = try encode(&buf, v);
        try std.testing.expectEqual(@as(usize, 8), n);
        const r = try decode(buf[0..n]);
        try std.testing.expectEqual(v, r.value);
    }
}

test "encode: overflow above MAX_VALUE" {
    const std = @import("std");
    var buf: [8]u8 = undefined;
    try std.testing.expectError(error.Overflow, encode(&buf, MAX_VALUE + 1));
}

test "encode: buffer too small" {
    const std = @import("std");
    var buf: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encode(&buf, 64)); // needs 2 bytes
}

test "decode: incomplete" {
    const std = @import("std");
    // First byte says 2-byte value, but only 1 byte provided.
    const buf = [_]u8{0x40};
    try std.testing.expectError(error.Incomplete, decode(&buf));
}

test "decode: empty input" {
    const std = @import("std");
    try std.testing.expectError(error.Incomplete, decode(&[_]u8{}));
}

test "round-trip: full range sample" {
    const std = @import("std");
    const cases = [_]u64{ 0, 1, 62, 63, 64, 127, 16_383, 16_384, 65_535, 1_073_741_823, 1_073_741_824, MAX_VALUE };
    var buf: [8]u8 = undefined;
    for (cases) |v| {
        const n = try encode(&buf, v);
        const r = try decode(buf[0..n]);
        try std.testing.expectEqual(v, r.value);
        try std.testing.expectEqual(n, r.consumed);
    }
}
