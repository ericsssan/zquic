// QPACK integer encoding — RFC 7541 §5.1
// Used for header field indices, string lengths, and dynamic table sizes.

const std = @import("std");

pub const DecodeResult = struct {
    value: u64,
    consumed: usize,
};

/// Encodes `value` into `buf` with an `n`-bit prefix (1 ≤ n ≤ 8).
/// Sets the low n bits of buf[0] to the encoded value.
/// Does not touch the high (8-n) bits of buf[0] — caller sets those.
/// Returns the number of bytes written, or error.BufferTooSmall.
pub fn encode(buf: []u8, n: u4, value: u64) error{BufferTooSmall}!usize {
    std.debug.assert(n >= 1 and n <= 8);
    if (buf.len == 0) return error.BufferTooSmall;

    const max: u64 = (@as(u64, 1) << @as(u6, n)) - 1;
    if (value < max) {
        buf[0] = @intCast(value);
        return 1;
    }

    buf[0] = @intCast(max);
    var rem = value - max;
    var pos: usize = 1;
    while (rem >= 128) {
        if (pos >= buf.len) return error.BufferTooSmall;
        buf[pos] = @as(u8, @intCast(rem & 0x7f)) | 0x80;
        pos += 1;
        rem >>= 7;
    }
    if (pos >= buf.len) return error.BufferTooSmall;
    buf[pos] = @intCast(rem);
    return pos + 1;
}

/// Decodes an integer from `buf` using an `n`-bit prefix (1 ≤ n ≤ 8).
/// Reads the full multi-byte sequence starting at buf[0].
/// Returns the decoded value and the number of bytes consumed.
pub fn decode(buf: []const u8, n: u4) error{ Incomplete, Overflow }!DecodeResult {
    std.debug.assert(n >= 1 and n <= 8);
    if (buf.len == 0) return error.Incomplete;

    const max: u64 = (@as(u64, 1) << @as(u6, n)) - 1;
    const first: u64 = buf[0] & @as(u8, @intCast(max));

    if (first < max) {
        return .{ .value = first, .consumed = 1 };
    }

    var value: u64 = max;
    var pos: usize = 1;
    var shift: u7 = 0;

    while (pos < buf.len) : (pos += 1) {
        const b = buf[pos];
        const lo7: u64 = b & 0x7f;

        // Use u128 to detect u64 overflow before truncating.
        const contribution: u128 = @as(u128, lo7) << shift;
        if (contribution > std.math.maxInt(u64)) return error.Overflow;

        const res = @addWithOverflow(value, @as(u64, @intCast(contribution)));
        if (res[1] != 0) return error.Overflow;
        value = res[0];

        if ((b & 0x80) == 0) return .{ .value = value, .consumed = pos + 1 };

        shift += 7;
        if (shift > 63) return error.Overflow; // can't shift further in u64
    }

    return error.Incomplete;
}

// ----------------------------------------------------------------------------
// Tests — RFC 7541 §C.1 integer examples
// ----------------------------------------------------------------------------

test "encode: small value fits in prefix" {
    // §C.1.1: 10 encoded with 5-bit prefix → single byte 0x0a
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 5, 10);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 10), buf[0]);
}

test "encode: value at prefix max minus one" {
    // 30 with 5-bit prefix: max = 31, 30 < 31 → 1 byte
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 5, 30);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 30), buf[0]);
}

test "encode: multi-byte RFC example (1337, 5-bit prefix)" {
    // §C.1.2: 1337 with 5-bit prefix → [0x1f, 0x9a, 0x0a]
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 5, 1337);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x1f), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x9a), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x0a), buf[2]);
}

test "encode: 8-bit prefix (42)" {
    // §C.1.3: 42 with 8-bit prefix → [0x2a]
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 8, 42);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x2a), buf[0]);
}

test "encode: zero value" {
    var buf: [16]u8 = undefined;
    const n = try encode(&buf, 5, 0);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0), buf[0]);
}

test "encode: buffer too small" {
    var buf: [1]u8 = undefined;
    try std.testing.expectError(error.BufferTooSmall, encode(&buf, 5, 1337));
}

test "decode: small value" {
    const buf = [_]u8{10};
    const r = try decode(&buf, 5);
    try std.testing.expectEqual(@as(u64, 10), r.value);
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
}

test "decode: multi-byte RFC example (1337, 5-bit prefix)" {
    const buf = [_]u8{ 0x1f, 0x9a, 0x0a };
    const r = try decode(&buf, 5);
    try std.testing.expectEqual(@as(u64, 1337), r.value);
    try std.testing.expectEqual(@as(usize, 3), r.consumed);
}

test "decode: 8-bit prefix (42)" {
    const buf = [_]u8{0x2a};
    const r = try decode(&buf, 8);
    try std.testing.expectEqual(@as(u64, 42), r.value);
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
}

test "decode: incomplete input" {
    const buf = [_]u8{0x1f}; // prefix all-1s but no continuation
    try std.testing.expectError(error.Incomplete, decode(&buf, 5));
}

test "decode: empty input" {
    try std.testing.expectError(error.Incomplete, decode(&.{}, 5));
}

test "encode/decode round-trip" {
    var buf: [16]u8 = undefined;
    const values = [_]u64{ 0, 1, 30, 31, 127, 128, 255, 1337, 65535, 1 << 20 };
    for (values) |v| {
        const written = try encode(&buf, 5, v);
        const r = try decode(buf[0..written], 5);
        try std.testing.expectEqual(v, r.value);
        try std.testing.expectEqual(written, r.consumed);
    }
}
