// HTTP/3 SETTINGS frame — RFC 9114 §7.2.4
//
// The SETTINGS frame is sent on the control stream and carries connection-level
// configuration parameters.  Its payload is a sequence of (identifier, value)
// pairs, both encoded as QUIC variable-length integers.
//
// Rules (RFC 9114 §7.2.4):
//  - Unknown identifiers MUST be ignored.
//  - Duplicate identifiers are a connection error (H3_SETTINGS_ERROR).
//  - SETTINGS MUST NOT be sent on request or push streams.
//
// Known identifiers:
//   0x01  SETTINGS_QPACK_MAX_TABLE_CAPACITY  default 0
//   0x06  SETTINGS_MAX_FIELD_SECTION_SIZE    default unlimited
//   0x07  SETTINGS_QPACK_BLOCKED_STREAMS     default 0

const std = @import("std");
const varint = @import("varint.zig");
const frame = @import("frame.zig");

pub const SettingId = struct {
    pub const qpack_max_table_capacity: u64 = 0x01;
    pub const max_field_section_size: u64 = 0x06;
    pub const qpack_blocked_streams: u64 = 0x07;
};

/// Parsed SETTINGS parameters.
pub const Settings = struct {
    /// Max dynamic table capacity the peer may use when encoding headers for us.
    /// Default: 0 (dynamic table disabled).
    qpack_max_table_capacity: u64 = 0,
    /// Max total size of a field section (headers) we are willing to process.
    /// Default: unlimited (std.math.maxInt(u64)).
    max_field_section_size: u64 = std.math.maxInt(u64),
    /// Max number of streams that can be blocked waiting on dynamic table updates.
    /// Default: 0.
    qpack_blocked_streams: u64 = 0,
};

pub const Error = error{
    /// Input is truncated.
    Incomplete,
    /// Duplicate setting identifier in a single SETTINGS frame.
    DuplicateSetting,
    /// Buffer too small to write the encoded frame.
    BufferTooSmall,
    /// Varint value out of range.
    Overflow,
};

/// Encode the SETTINGS payload (without frame header) into `buf`.
/// Encodes only the settings that differ from their defaults.
/// Returns bytes written.
pub fn encodePayload(settings: Settings, buf: []u8) Error!usize {
    var pos: usize = 0;

    if (settings.qpack_max_table_capacity != 0) {
        pos += try varint.encode(buf[pos..], SettingId.qpack_max_table_capacity);
        pos += try varint.encode(buf[pos..], settings.qpack_max_table_capacity);
    }
    if (settings.max_field_section_size != std.math.maxInt(u64)) {
        pos += try varint.encode(buf[pos..], SettingId.max_field_section_size);
        pos += try varint.encode(buf[pos..], settings.max_field_section_size);
    }
    if (settings.qpack_blocked_streams != 0) {
        pos += try varint.encode(buf[pos..], SettingId.qpack_blocked_streams);
        pos += try varint.encode(buf[pos..], settings.qpack_blocked_streams);
    }

    return pos;
}

/// Decode a SETTINGS payload (without frame header) from `payload`.
/// Unknown identifiers are silently ignored.
/// Returns error.DuplicateSetting if any identifier appears more than once.
pub fn decodePayload(payload: []const u8) Error!Settings {
    var settings = Settings{};
    var seen_qpack_max: bool = false;
    var seen_max_field: bool = false;
    var seen_blocked: bool = false;
    var pos: usize = 0;

    while (pos < payload.len) {
        const id_r = varint.decode(payload[pos..]) catch return error.Incomplete;
        pos += id_r.consumed;

        const val_r = varint.decode(payload[pos..]) catch return error.Incomplete;
        pos += val_r.consumed;

        switch (id_r.value) {
            SettingId.qpack_max_table_capacity => {
                if (seen_qpack_max) return error.DuplicateSetting;
                seen_qpack_max = true;
                settings.qpack_max_table_capacity = val_r.value;
            },
            SettingId.max_field_section_size => {
                if (seen_max_field) return error.DuplicateSetting;
                seen_max_field = true;
                settings.max_field_section_size = val_r.value;
            },
            SettingId.qpack_blocked_streams => {
                if (seen_blocked) return error.DuplicateSetting;
                seen_blocked = true;
                settings.qpack_blocked_streams = val_r.value;
            },
            else => {}, // RFC 9114 §7.2.4: ignore unknown identifiers
        }
    }

    return settings;
}

/// Encode a full SETTINGS frame (header + payload) into `buf`.
/// Returns bytes written.
pub fn encodeFrame(settings: Settings, buf: []u8) Error!usize {
    // Encode payload into a temporary buffer to determine its length.
    var tmp: [64]u8 = undefined;
    const payload_len = try encodePayload(settings, &tmp);

    var pos: usize = 0;
    pos += try frame.writeHeader(buf[pos..], frame.FrameType.settings, payload_len);
    if (buf.len < pos + payload_len) return error.BufferTooSmall;
    @memcpy(buf[pos .. pos + payload_len], tmp[0..payload_len]);
    pos += payload_len;
    return pos;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "encodePayload: all defaults → empty payload" {
    const std2 = @import("std");
    var buf: [64]u8 = undefined;
    const n = try encodePayload(Settings{}, &buf);
    try std2.testing.expectEqual(@as(usize, 0), n);
}

test "encodePayload / decodePayload: qpack_max_table_capacity only" {
    const std2 = @import("std");
    var buf: [64]u8 = undefined;
    const s = Settings{ .qpack_max_table_capacity = 4096 };
    const n = try encodePayload(s, &buf);
    try std2.testing.expect(n > 0);

    const decoded = try decodePayload(buf[0..n]);
    try std2.testing.expectEqual(@as(u64, 4096), decoded.qpack_max_table_capacity);
    try std2.testing.expectEqual(std.math.maxInt(u64), decoded.max_field_section_size);
    try std2.testing.expectEqual(@as(u64, 0), decoded.qpack_blocked_streams);
}

test "encodePayload / decodePayload: all three settings" {
    const std2 = @import("std");
    var buf: [64]u8 = undefined;
    const s = Settings{
        .qpack_max_table_capacity = 4096,
        .max_field_section_size = 65536,
        .qpack_blocked_streams = 100,
    };
    const n = try encodePayload(s, &buf);
    const decoded = try decodePayload(buf[0..n]);
    try std2.testing.expectEqual(s.qpack_max_table_capacity, decoded.qpack_max_table_capacity);
    try std2.testing.expectEqual(s.max_field_section_size, decoded.max_field_section_size);
    try std2.testing.expectEqual(s.qpack_blocked_streams, decoded.qpack_blocked_streams);
}

test "decodePayload: unknown setting is ignored" {
    const std2 = @import("std");
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    // Write unknown id=0xff value=1 followed by known qpack_max=512
    pos += try varint.encode(buf[pos..], 0xff);
    pos += try varint.encode(buf[pos..], 1);
    pos += try varint.encode(buf[pos..], SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 512);

    const decoded = try decodePayload(buf[0..pos]);
    try std2.testing.expectEqual(@as(u64, 512), decoded.qpack_max_table_capacity);
}

test "decodePayload: duplicate setting returns error" {
    const std2 = @import("std");
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += try varint.encode(buf[pos..], SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 4096);
    pos += try varint.encode(buf[pos..], SettingId.qpack_max_table_capacity);
    pos += try varint.encode(buf[pos..], 8192);
    try std2.testing.expectError(error.DuplicateSetting, decodePayload(buf[0..pos]));
}

test "encodeFrame: produces valid frame header" {
    const std2 = @import("std");
    var buf: [64]u8 = undefined;
    const s = Settings{ .qpack_max_table_capacity = 4096 };
    const n = try encodeFrame(s, &buf);

    const hdr = try frame.parseHeader(buf[0..n]);
    try std2.testing.expectEqual(frame.FrameType.settings, hdr.frame_type);
    // Payload must be decodable
    const payload = buf[hdr.header_len .. hdr.header_len + @as(usize, @intCast(hdr.payload_len))];
    const decoded = try decodePayload(payload);
    try std2.testing.expectEqual(@as(u64, 4096), decoded.qpack_max_table_capacity);
}

test "encodeFrame: empty settings frame" {
    const std2 = @import("std");
    var buf: [4]u8 = undefined;
    const n = try encodeFrame(Settings{}, &buf);
    // type(1) + length(1) + payload(0) = 2 bytes
    try std2.testing.expectEqual(@as(usize, 2), n);
    try std2.testing.expectEqual(@as(u8, 0x04), buf[0]); // SETTINGS type
    try std2.testing.expectEqual(@as(u8, 0x00), buf[1]); // payload length = 0
}
