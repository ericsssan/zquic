// HTTP/3 server push — RFC 9114 §4.6 and §7.2.5
//
// Push sequence:
//
//   On the request stream (bidirectional, client→server):
//     Server sends PUSH_PROMISE frame before or alongside the response.
//     Payload: push_id (varint) | QPACK-encoded header block for the resource.
//
//   On a new push unidirectional stream (server→client):
//     Stream type 0x01 (push stream) — written first.
//     Push stream header: push_id (varint) — immediately after the type byte.
//     Then: HEADERS frame + optional DATA frames for the pushed response.
//
// This module handles PUSH_PROMISE frame encoding/decoding (§7.2.5) and the
// push stream opening (§4.6.1).  QPACK encoding of header blocks is the
// caller's responsibility.
//
// Client-side cancel (CANCEL_PUSH §7.2.3) and flow control (MAX_PUSH_ID §7.2.7)
// are handled by frame.zig — writeCancelPush, writeMaxPushId.

const varint = @import("varint.zig");
const frame = @import("frame.zig");

pub const Error = error{
    /// Input buffer is truncated.
    Incomplete,
    /// Output buffer is too small.
    BufferTooSmall,
    /// A varint value is out of range.
    Overflow,
    /// Stream type byte does not indicate a push stream (0x01).
    UnexpectedStreamType,
};

// ----------------------------------------------------------------------------
// PUSH_PROMISE frame — §7.2.5
//
//   PUSH_PROMISE Frame {
//     Type   (varint = 0x05)
//     Length (varint)
//     Push ID (varint)
//     Encoded Field Section (..)
//   }
// ----------------------------------------------------------------------------

pub const ParsedPushPromise = struct {
    push_id: u64,
    /// Slice of the original payload buffer — points at the QPACK-encoded
    /// header block.  Zero-copy; valid as long as the source buffer is live.
    header_block: []const u8,
};

/// Write a PUSH_PROMISE frame into buf.
///
/// encoded_headers is the QPACK-compressed header block for the promised
/// resource.  Returns bytes written.
pub fn writePushPromise(buf: []u8, push_id: u64, encoded_headers: []const u8) Error!usize {
    const push_id_len = varint.encodedLen(push_id);
    const payload_len = push_id_len + encoded_headers.len;
    var pos: usize = 0;
    pos += try frame.writeHeader(buf[pos..], frame.FrameType.push_promise, payload_len);
    pos += try varint.encode(buf[pos..], push_id);
    if (pos + encoded_headers.len > buf.len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + encoded_headers.len], encoded_headers);
    pos += encoded_headers.len;
    return pos;
}

/// Parse a PUSH_PROMISE payload (the bytes after the frame header).
///
/// Returns the push ID and a slice into payload pointing at the QPACK header
/// block.  Does not copy; the returned header_block slice refers into payload.
pub fn parsePushPromise(payload: []const u8) Error!ParsedPushPromise {
    const id = varint.decode(payload) catch return error.Incomplete;
    return .{
        .push_id = id.value,
        .header_block = payload[id.consumed..],
    };
}

// ----------------------------------------------------------------------------
// Push stream opening — §4.6.1
//
//   Push Stream Header {
//     Stream Type (varint = 0x01)
//     Push ID     (varint)
//   }
//
//   Followed by HEADERS frame then optional DATA frames.
// ----------------------------------------------------------------------------

pub const PUSH_STREAM_TYPE: u64 = 0x01;

/// Write the opening of a push unidirectional stream:
///   stream_type(0x01) | push_id (varint)
///
/// The HEADERS + DATA frames for the pushed response are written by the
/// caller after this prefix.  Returns bytes written.
pub fn writePushStreamOpening(buf: []u8, push_id: u64) Error!usize {
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], PUSH_STREAM_TYPE);
    pos += try varint.encode(buf[pos..], push_id);
    return pos;
}

pub const ParsedPushStreamOpening = struct {
    push_id: u64,
    /// Total bytes consumed from buf (stream type + push ID).
    consumed: usize,
};

/// Parse the opening of a push stream.
///
/// Reads the stream type varint (must be 0x01) followed by the push ID varint.
/// Returns error.UnexpectedStreamType if the stream type is not 0x01.
pub fn parsePushStreamOpening(buf: []const u8) Error!ParsedPushStreamOpening {
    const st = varint.decode(buf) catch return error.Incomplete;
    if (st.value != PUSH_STREAM_TYPE) return error.UnexpectedStreamType;
    const id = varint.decode(buf[st.consumed..]) catch return error.Incomplete;
    return .{
        .push_id = id.value,
        .consumed = st.consumed + id.consumed,
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "writePushPromise / parsePushPromise: basic round-trip" {
    const std = @import("std");
    var buf: [64]u8 = undefined;
    const headers = [_]u8{ 0xc0, 0x25 }; // dummy QPACK bytes
    const n = try writePushPromise(&buf, 3, &headers);

    const hdr = try frame.parseHeader(buf[0..n]);
    try std.testing.expectEqual(frame.FrameType.push_promise, hdr.frame_type);

    const payload_start = hdr.header_len;
    const payload_end = payload_start + @as(usize, @intCast(hdr.payload_len));
    const parsed = try parsePushPromise(buf[payload_start..payload_end]);
    try std.testing.expectEqual(@as(u64, 3), parsed.push_id);
    try std.testing.expectEqualSlices(u8, &headers, parsed.header_block);
}

test "writePushPromise / parsePushPromise: push_id requires multi-byte varint" {
    const std = @import("std");
    var buf: [128]u8 = undefined;
    const headers = [_]u8{0xd9}; // single dummy byte
    const big_id: u64 = 200; // requires 2-byte varint (>63)
    const n = try writePushPromise(&buf, big_id, &headers);

    const hdr = try frame.parseHeader(buf[0..n]);
    const payload_start = hdr.header_len;
    const payload_end = payload_start + @as(usize, @intCast(hdr.payload_len));
    const parsed = try parsePushPromise(buf[payload_start..payload_end]);
    try std.testing.expectEqual(big_id, parsed.push_id);
    try std.testing.expectEqualSlices(u8, &headers, parsed.header_block);
}

test "writePushPromise / parsePushPromise: empty header block" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writePushPromise(&buf, 0, &[_]u8{});

    const hdr = try frame.parseHeader(buf[0..n]);
    const payload_start = hdr.header_len;
    const payload_end = payload_start + @as(usize, @intCast(hdr.payload_len));
    const parsed = try parsePushPromise(buf[payload_start..payload_end]);
    try std.testing.expectEqual(@as(u64, 0), parsed.push_id);
    try std.testing.expectEqual(@as(usize, 0), parsed.header_block.len);
}

test "writePushStreamOpening / parsePushStreamOpening: round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const n = try writePushStreamOpening(&buf, 7);

    // First varint is the stream type.
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]);

    const parsed = try parsePushStreamOpening(buf[0..n]);
    try std.testing.expectEqual(@as(u64, 7), parsed.push_id);
    try std.testing.expectEqual(n, parsed.consumed);
}

test "parsePushStreamOpening: wrong stream type returns error" {
    const std = @import("std");
    var buf: [4]u8 = undefined;
    // Write stream type 0x00 (control) + push_id 5
    _ = try varint.encode(&buf, 0x00);
    _ = try varint.encode(buf[1..], 5);
    try std.testing.expectError(error.UnexpectedStreamType, parsePushStreamOpening(&buf));
}

test "writePushStreamOpening: large push_id round-trip" {
    const std = @import("std");
    var buf: [16]u8 = undefined;
    const large_id: u64 = 65535;
    const n = try writePushStreamOpening(&buf, large_id);
    const parsed = try parsePushStreamOpening(buf[0..n]);
    try std.testing.expectEqual(large_id, parsed.push_id);
}
