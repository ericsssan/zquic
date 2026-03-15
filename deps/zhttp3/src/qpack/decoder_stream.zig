// QPACK decoder stream — RFC 9204 §4.4
//
// Writes decoder stream instructions into a caller-supplied buffer.
// These are sent by the QPACK decoder to the QPACK encoder.
//
// Instruction formats:
//   §4.4.1  Section Acknowledgement  — 1  [7-bit stream_id]
//   §4.4.2  Stream Cancellation      — 01 [6-bit stream_id]
//   §4.4.3  Insert Count Increment   — 00 [6-bit increment]

const int = @import("int.zig");

pub const Error = error{
    /// Output buffer too small.
    BufferTooSmall,
    /// Integer overflow encoding the value.
    Overflow,
};

/// §4.4.1  Write a Section Acknowledgement instruction.
/// Sent after a header block that referenced the dynamic table is processed.
pub fn writeSectionAck(buf: []u8, stream_id: u64) Error!usize {
    const n = try int.encode(buf, 7, stream_id);
    buf[0] |= 0b1000_0000;
    return n;
}

/// §4.4.2  Write a Stream Cancellation instruction.
/// Sent when a stream is reset before its header block could be processed.
pub fn writeStreamCancellation(buf: []u8, stream_id: u64) Error!usize {
    const n = try int.encode(buf, 6, stream_id);
    buf[0] |= 0b0100_0000;
    return n;
}

/// §4.4.3  Write an Insert Count Increment instruction.
/// Sent to inform the encoder how many dynamic table insertions were received.
pub fn writeInsertCountIncrement(buf: []u8, increment: u64) Error!usize {
    // Top 2 bits = 00 (already zero from int.encode).
    return int.encode(buf, 6, increment);
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "writeSectionAck: stream_id fits in 7-bit prefix" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    const n = try writeSectionAck(&buf, 5);
    try std.testing.expectEqual(@as(usize, 1), n);
    // bit7=1, [6:0]=5 → 0b1000_0101 = 0x85
    try std.testing.expectEqual(@as(u8, 0x85), buf[0]);
}

test "writeSectionAck: stream_id requires multi-byte" {
    const std = @import("std");
    // stream_id=200: 200 >= 127 → first byte = 0xff (1 1111111), then 200-127=73
    var buf: [4]u8 = undefined;
    const n = try writeSectionAck(&buf, 200);
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0xff), buf[0]);
    try std.testing.expectEqual(@as(u8, 73), buf[1]);
}

test "writeStreamCancellation" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    const n = try writeStreamCancellation(&buf, 3);
    try std.testing.expectEqual(@as(usize, 1), n);
    // bits 7:6 = 01, [5:0]=3 → 0b0100_0011 = 0x43
    try std.testing.expectEqual(@as(u8, 0x43), buf[0]);
}

test "writeInsertCountIncrement" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    const n = try writeInsertCountIncrement(&buf, 10);
    try std.testing.expectEqual(@as(usize, 1), n);
    // bits 7:6 = 00, [5:0]=10 → 0b0000_1010 = 0x0a
    try std.testing.expectEqual(@as(u8, 0x0a), buf[0]);
}

test "writeInsertCountIncrement: zero increment" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    const n = try writeInsertCountIncrement(&buf, 0);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
}
