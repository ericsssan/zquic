// HTTP/3 unidirectional stream types — RFC 9114 §6.2
//
// When opening a unidirectional stream the sender writes a stream type
// varint as the first byte(s), then the stream's content.
//
// Stream types:
//   0x00  Control stream    — carries SETTINGS, GOAWAY, etc.
//   0x01  Push stream       — server push
//   0x02  QPACK encoder stream
//   0x03  QPACK decoder stream
//
// The control stream MUST be the first stream opened by each side, and
// the first frame on it MUST be a SETTINGS frame (RFC 9114 §6.2.1).

const varint = @import("varint.zig");
const frame = @import("frame.zig");
const settings = @import("settings.zig");

pub const StreamType = struct {
    pub const control: u64 = 0x00;
    pub const push: u64 = 0x01;
    pub const qpack_encoder: u64 = 0x02;
    pub const qpack_decoder: u64 = 0x03;
};

pub const Error = error{
    Incomplete,
    BufferTooSmall,
    Overflow,
    DuplicateSetting,
};

/// Write the stream type prefix for a new unidirectional stream.
/// Returns bytes written (1–8 bytes depending on type value).
pub fn writeStreamType(buf: []u8, stream_type: u64) Error!usize {
    return varint.encode(buf, stream_type);
}

pub const ParsedStreamType = struct {
    stream_type: u64,
    consumed: usize,
};

/// Parse the stream type from the start of a unidirectional stream.
pub fn parseStreamType(buf: []const u8) Error!ParsedStreamType {
    const r = try varint.decode(buf);
    return .{ .stream_type = r.value, .consumed = r.consumed };
}

/// Write a complete control stream opening:
///   stream type (0x00) + SETTINGS frame.
///
/// This is the correct opening sequence for the server's control stream
/// (RFC 9114 §6.2.1).  Returns bytes written.
pub fn writeControlStreamOpening(buf: []u8, s: settings.Settings) Error!usize {
    var pos: usize = 0;
    pos += try writeStreamType(buf[pos..], StreamType.control);
    pos += try settings.encodeFrame(s, buf[pos..]);
    return pos;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "writeStreamType / parseStreamType: control stream" {
    const std = @import("std");
    var buf: [8]u8 = undefined;
    const n = try writeStreamType(&buf, StreamType.control);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    const r = try parseStreamType(buf[0..n]);
    try std.testing.expectEqual(StreamType.control, r.stream_type);
    try std.testing.expectEqual(@as(usize, 1), r.consumed);
}

test "writeStreamType / parseStreamType: all known types" {
    const std = @import("std");
    var buf: [8]u8 = undefined;
    const types = [_]u64{
        StreamType.control,
        StreamType.push,
        StreamType.qpack_encoder,
        StreamType.qpack_decoder,
    };
    for (types) |t| {
        const n = try writeStreamType(&buf, t);
        const r = try parseStreamType(buf[0..n]);
        try std.testing.expectEqual(t, r.stream_type);
    }
}

test "writeControlStreamOpening: correct structure" {
    const std = @import("std");
    var buf: [64]u8 = undefined;
    const s = settings.Settings{ .qpack_max_table_capacity = 4096 };
    const n = try writeControlStreamOpening(&buf, s);

    // First byte: stream type 0x00
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);

    // Remaining bytes: a valid SETTINGS frame
    const hdr = try frame.parseHeader(buf[1..n]);
    try std.testing.expectEqual(frame.FrameType.settings, hdr.frame_type);

    const payload_start = 1 + hdr.header_len;
    const payload_end = payload_start + @as(usize, @intCast(hdr.payload_len));
    const decoded = try settings.decodePayload(buf[payload_start..payload_end]);
    try std.testing.expectEqual(@as(u64, 4096), decoded.qpack_max_table_capacity);
}

test "writeControlStreamOpening: empty settings" {
    const std = @import("std");
    var buf: [8]u8 = undefined;
    const n = try writeControlStreamOpening(&buf, settings.Settings{});
    // stream_type(1) + frame_type(1) + frame_length(1) = 3 bytes minimum
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, StreamType.control), buf[0]);
    try std.testing.expectEqual(@as(u8, frame.FrameType.settings), buf[1]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[2]); // payload length = 0
}
