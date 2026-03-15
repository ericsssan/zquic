// QPACK/HPACK string literal encoding — RFC 7541 §5.2
//
// Wire format:
//   bit 7 of first byte:  H flag (1 = Huffman, 0 = literal)
//   bits [6:0] of first byte + optional continuation: string byte length (7-bit prefix)
//   remaining bytes: raw or Huffman-encoded string data

const std = @import("std");
const int = @import("int.zig");
const huffman = @import("huffman.zig");

pub const DecodeResult = struct {
    /// Decoded string bytes.
    /// For literal strings: slice into `src` (zero-copy).
    /// For Huffman strings: slice into caller-provided `scratch` buffer.
    value: []const u8,
    /// Total bytes consumed from `src`, including the length prefix.
    consumed: usize,
    /// True when value points into `scratch` (Huffman-decoded), false when it points into `src`.
    huffman_decoded: bool,
};

/// Encodes `str` as a string literal into `dst`.
/// Uses Huffman encoding if it produces a shorter result.
/// Returns the number of bytes written.
pub fn encode(str: []const u8, dst: []u8) error{BufferTooSmall}!usize {
    const huff_len = huffman.encodedLen(str);
    const use_huffman = huff_len < str.len;
    const data_len: u64 = if (use_huffman) huff_len else str.len;

    // Write length with 7-bit prefix; int.encode zeros the high bits of dst[0].
    const hdr_len = try int.encode(dst, 7, data_len);
    if (use_huffman) dst[0] |= 0x80; // set H bit

    const total = hdr_len + @as(usize, @intCast(data_len));
    if (dst.len < total) return error.BufferTooSmall;

    if (use_huffman) {
        _ = try huffman.encode(str, dst[hdr_len..total]);
    } else {
        @memcpy(dst[hdr_len..total], str);
    }

    return total;
}

/// Decodes a string literal from `src`.
/// `scratch` is used when Huffman decoding is required; must be large enough.
/// The returned `value` slice is only valid while `src` and `scratch` are live.
pub fn decode(
    src: []const u8,
    scratch: []u8,
) error{ Incomplete, Overflow, InvalidCode, BufferTooSmall, EosInValue }!DecodeResult {
    if (src.len == 0) return error.Incomplete;

    const is_huffman = (src[0] & 0x80) != 0;
    const hdr = try int.decode(src, 7);
    const str_len: usize = @intCast(hdr.value);
    const consumed = hdr.consumed + str_len;

    if (consumed > src.len) return error.Incomplete;

    const raw = src[hdr.consumed..consumed];

    if (is_huffman) {
        const n = try huffman.decode(raw, scratch);
        return .{ .value = scratch[0..n], .consumed = consumed, .huffman_decoded = true };
    } else {
        return .{ .value = raw, .consumed = consumed, .huffman_decoded = false };
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "encode: literal (no Huffman when literal is shorter)" {
    // Short single-character string: literal (1 byte) < huffman (1 byte after padding).
    // 'a' Huffman = 5 bits → 1 byte. Same size. Huffman is NOT shorter, so use literal.
    var buf: [32]u8 = undefined;
    const n = try encode("a", &buf);
    // H=0, length=1 → first byte = 0x01; then 'a' = 0x61
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]); // H=0, len=1
    try std.testing.expectEqual(@as(u8, 'a'), buf[1]);
}

test "encode: Huffman (www.example.com)" {
    // "www.example.com": literal = 15 bytes, Huffman = 12 bytes → use Huffman.
    var buf: [32]u8 = undefined;
    const n = try encode("www.example.com", &buf);
    // First byte: H=1 (0x80) | length prefix. Length = 12 fits in 7 bits → buf[0] = 0x80 | 12 = 0x8c.
    try std.testing.expectEqual(@as(usize, 13), n); // 1 byte header + 12 bytes data
    try std.testing.expectEqual(@as(u8, 0x8c), buf[0]);
    const expected_data = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    try std.testing.expectEqualSlices(u8, &expected_data, buf[1..13]);
}

test "decode: literal string" {
    // Encode then decode a literal string.
    const src = [_]u8{ 0x05, 'h', 'e', 'l', 'l', 'o' };
    var scratch: [32]u8 = undefined;
    const r = try decode(&src, &scratch);
    try std.testing.expectEqualStrings("hello", r.value);
    try std.testing.expectEqual(@as(usize, 6), r.consumed);
}

test "decode: Huffman string (www.example.com)" {
    // H=1, length=12, then Huffman bytes.
    var src_buf: [32]u8 = undefined;
    src_buf[0] = 0x8c; // H=1, len=12
    const huff = [_]u8{ 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff };
    @memcpy(src_buf[1..13], &huff);
    var scratch: [64]u8 = undefined;
    const r = try decode(src_buf[0..13], &scratch);
    try std.testing.expectEqualStrings("www.example.com", r.value);
    try std.testing.expectEqual(@as(usize, 13), r.consumed);
}

test "encode/decode round-trip: Huffman and literal paths" {
    var enc: [256]u8 = undefined;
    var scratch: [256]u8 = undefined;
    const cases = [_][]const u8{
        "GET",
        "https",
        "/",
        "www.example.com",
        "no-cache",
        "application/json",
        "text/html; charset=utf-8",
    };
    for (cases) |s| {
        const enc_n = try encode(s, &enc);
        const r = try decode(enc[0..enc_n], &scratch);
        try std.testing.expectEqualStrings(s, r.value);
        try std.testing.expectEqual(enc_n, r.consumed);
    }
}

test "decode: incomplete returns error" {
    const src = [_]u8{ 0x05, 'h', 'i' }; // claims 5 bytes but only 2 available
    var scratch: [32]u8 = undefined;
    try std.testing.expectError(error.Incomplete, decode(&src, &scratch));
}
