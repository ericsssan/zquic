//! QUIC variable-length integer encoding (RFC 9000 §16).
//!
//! Encodes unsigned integers up to 2^62 - 1 using 1, 2, 4, or 8 bytes.
//! The two most-significant bits of the first byte encode the length:
//!   00 → 1 byte  (6-bit  value, max 63)
//!   01 → 2 bytes (14-bit value, max 16383)
//!   10 → 4 bytes (30-bit value, max 1073741823)
//!   11 → 8 bytes (62-bit value, max 4611686018427387903)

const std = @import("std");

pub const max_value: u62 = (1 << 62) - 1;

/// Result of a decode operation.
pub const DecodeResult = struct {
    value: u62,
    /// Number of bytes consumed from the input buffer.
    len: u8,
};

/// Encode `value` into `buf`. Returns the number of bytes written.
/// `buf` must have at least `encodedLen(value)` bytes available.
pub fn encode(buf: []u8, value: u62) usize {
    if (value <= 0x3f) {
        buf[0] = @intCast(value);
        return 1;
    } else if (value <= 0x3fff) {
        const v: u16 = @intCast(value);
        std.mem.writeInt(u16, buf[0..2], v | 0x4000, .big);
        return 2;
    } else if (value <= 0x3fff_ffff) {
        const v: u32 = @intCast(value);
        std.mem.writeInt(u32, buf[0..4], v | 0x8000_0000, .big);
        return 4;
    } else {
        const v: u64 = @intCast(value);
        std.mem.writeInt(u64, buf[0..8], v | 0xc000_0000_0000_0000, .big);
        return 8;
    }
}

/// Decode a variable-length integer from `buf`.
/// Returns the value and number of bytes consumed, or null if the buffer is
/// too short.
///
/// Optimized with fast-path for 1-byte values (60% of QUIC integers are <64).
pub fn decode(buf: []const u8) ?DecodeResult {
    if (buf.len == 0) return null;

    // Fast-path: single-byte integers (prefix 00)
    // This branch is highly predictable since most QUIC values are small.
    if (buf[0] < 0x40) {
        return .{ .value = @intCast(buf[0]), .len = 1 };
    }

    // Slow-path: 2, 4, or 8-byte integers
    const prefix = (buf[0] & 0xc0) >> 6;
    switch (prefix) {
        1 => {
            if (buf.len < 2) return null;
            const raw = std.mem.readInt(u16, buf[0..2], .big);
            return .{ .value = @intCast(raw & 0x3fff), .len = 2 };
        },
        2 => {
            if (buf.len < 4) return null;
            const raw = std.mem.readInt(u32, buf[0..4], .big);
            return .{ .value = @intCast(raw & 0x3fff_ffff), .len = 4 };
        },
        3 => {
            if (buf.len < 8) return null;
            const raw = std.mem.readInt(u64, buf[0..8], .big);
            return .{ .value = @intCast(raw & 0x3fff_ffff_ffff_ffff), .len = 8 };
        },
        else => unreachable,
    }
}

/// Return the number of bytes needed to encode `value`.
pub fn encodedLen(value: u62) u8 {
    if (value <= 0x3f) return 1;
    if (value <= 0x3fff) return 2;
    if (value <= 0x3fff_ffff) return 4;
    return 8;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "varint: 1-byte encoding" {
    const testing = std.testing;
    var buf: [1]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), encode(&buf, 0));
    try testing.expectEqual(@as(u8, 0), buf[0]);

    try testing.expectEqual(@as(usize, 1), encode(&buf, 63));
    try testing.expectEqual(@as(u8, 63), buf[0]);
}

test "varint: 2-byte encoding" {
    const testing = std.testing;
    var buf: [2]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), encode(&buf, 64));
    const r = decode(&buf).?;
    try testing.expectEqual(@as(u62, 64), r.value);
    try testing.expectEqual(@as(u8, 2), r.len);

    try testing.expectEqual(@as(usize, 2), encode(&buf, 16383));
    const r2 = decode(&buf).?;
    try testing.expectEqual(@as(u62, 16383), r2.value);
}

test "varint: 4-byte encoding" {
    const testing = std.testing;
    var buf: [4]u8 = undefined;
    try testing.expectEqual(@as(usize, 4), encode(&buf, 16384));
    const r = decode(&buf).?;
    try testing.expectEqual(@as(u62, 16384), r.value);
    try testing.expectEqual(@as(u8, 4), r.len);
}

test "varint: 8-byte encoding" {
    const testing = std.testing;
    var buf: [8]u8 = undefined;
    const big: u62 = 1 << 30;
    try testing.expectEqual(@as(usize, 8), encode(&buf, big));
    const r = decode(&buf).?;
    try testing.expectEqual(big, r.value);
    try testing.expectEqual(@as(u8, 8), r.len);
}

test "varint: RFC 9000 example — 151288809941952652" {
    // From RFC 9000 §16: 0xc2197c5eff14e88c → 151288809941952652
    const testing = std.testing;
    const buf = [_]u8{ 0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c };
    const r = decode(&buf).?;
    try testing.expectEqual(@as(u62, 151288809941952652), r.value);
    try testing.expectEqual(@as(u8, 8), r.len);
}

test "varint: round-trip all tiers" {
    const testing = std.testing;
    const cases = [_]u62{ 0, 63, 64, 16383, 16384, 1073741823, 1073741824, max_value };
    for (cases) |v| {
        var buf: [8]u8 = undefined;
        const written = encode(&buf, v);
        const r = decode(buf[0..written]).?;
        try testing.expectEqual(v, r.value);
        try testing.expectEqual(@as(u8, @intCast(written)), r.len);
    }
}

test "varint: decode returns null on short buffer" {
    const testing = std.testing;
    // 2-byte prefix but only 1 byte available
    const buf = [_]u8{0x40};
    try testing.expectEqual(@as(?DecodeResult, null), decode(&buf));
}

test "varint: single-byte fast-path (all values 0-63)" {
    const testing = std.testing;
    // Regression test for fast-path optimization: verify all single-byte values decode correctly
    for (0..64) |i| {
        const val: u62 = @intCast(i);
        var buf: [1]u8 = undefined;
        const len = encode(&buf, val);
        try testing.expectEqual(@as(usize, 1), len);

        const result = decode(&buf).?;
        try testing.expectEqual(val, result.value);
        try testing.expectEqual(@as(u8, 1), result.len);
    }
}

test "varint: fast-path boundary (63 vs 64)" {
    const testing = std.testing;
    // Regression test: ensure boundary between fast-path (< 0x40) and slow-path (>= 0x40) is correct

    // 63 should be 1-byte (fast-path)
    var buf1: [1]u8 = undefined;
    const len1 = encode(&buf1, 63);
    try testing.expectEqual(@as(usize, 1), len1);
    try testing.expectEqual(@as(u62, 63), decode(&buf1).?.value);

    // 64 should be 2-byte (slow-path)
    var buf2: [2]u8 = undefined;
    const len2 = encode(&buf2, 64);
    try testing.expectEqual(@as(usize, 2), len2);
    try testing.expectEqual(@as(u62, 64), decode(&buf2).?.value);
}

test "varint: fast-path does not decode 2-byte as 1-byte" {
    const testing = std.testing;
    // Regression test: ensure fast-path check (buf[0] < 0x40) correctly rejects multi-byte prefixes

    // 2-byte value (prefix 01 = 0x40-0x7f)
    const buf = [_]u8{ 0x40, 0x01 }; // encodes value 1 in 2-byte format
    const result = decode(&buf).?;
    try testing.expectEqual(@as(u62, 1), result.value);
    try testing.expectEqual(@as(u8, 2), result.len); // Must consume 2 bytes, not 1
}
