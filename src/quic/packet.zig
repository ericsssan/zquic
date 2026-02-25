//! QUIC packet header encoding and decoding (RFC 9000 §17).
//!
//! Supports Long Headers (Initial, 0-RTT, Handshake, Retry) and Short Headers
//! (1-RTT / "protected") packets.

const std = @import("std");
const varint = @import("varint.zig");
const cid = @import("connection_id.zig");
const ConnectionId = cid.ConnectionId;

pub const QUIC_VERSION_1: u32 = 0x0000_0001;

// ---------------------------------------------------------------------------
// Packet type classification
// ---------------------------------------------------------------------------

pub const PacketType = enum(u2) {
    initial = 0,
    zero_rtt = 1,
    handshake = 2,
    retry = 3,
};

/// Return true when the first byte indicates a Long Header packet.
pub fn isLongHeader(first_byte: u8) bool {
    return first_byte & 0x80 != 0;
}

/// Extract the PacketType from a Long Header first byte.
pub fn longHeaderType(first_byte: u8) PacketType {
    return @enumFromInt((first_byte >> 4) & 0x03);
}

// ---------------------------------------------------------------------------
// Long Header
// ---------------------------------------------------------------------------

pub const LongHeader = struct {
    packet_type: PacketType,
    version: u32,
    dest_cid: ConnectionId,
    src_cid: ConnectionId,
    /// Token (Initial packets only; empty slice for others).
    token: []const u8,
    /// Packet number length (bytes), 1..4.
    pn_len: u8,
    /// Raw (truncated) packet number read from the wire.
    packet_number: u32,
    /// Slice into the original buffer: everything after the packet-number field.
    /// For an *unprotected* header this is the encrypted payload + auth tag.
    payload: []const u8,
};

/// Parse a Long Header from `buf`.
/// Returns the header and the total number of bytes consumed (header + payload).
pub fn parseLongHeader(buf: []const u8) !struct { header: LongHeader, consumed: usize } {
    if (buf.len < 7) return error.PacketTooShort;
    if (!isLongHeader(buf[0])) return error.NotLongHeader;

    const first_byte = buf[0];
    var pos: usize = 1;

    // Version (4 bytes)
    if (pos + 4 > buf.len) return error.PacketTooShort;
    const version = std.mem.readInt(u32, buf[pos..][0..4], .big);
    pos += 4;

    // Destination CID
    if (pos >= buf.len) return error.PacketTooShort;
    const dcid_len = buf[pos];
    pos += 1;
    if (pos + dcid_len > buf.len) return error.PacketTooShort;
    // For QUIC v1, CID length must match our fixed 8-byte CID format.
    if (version == QUIC_VERSION_1 and dcid_len != cid.len) return error.UnsupportedCidLength;
    var dest_cid: ConnectionId = .{};
    if (dcid_len > 0) {
        const copy_len = @min(dcid_len, cid.len);
        @memcpy(dest_cid.bytes[0..copy_len], buf[pos..][0..copy_len]);
    }
    pos += dcid_len;

    // Source CID
    if (pos >= buf.len) return error.PacketTooShort;
    const scid_len = buf[pos];
    pos += 1;
    if (pos + scid_len > buf.len) return error.PacketTooShort;
    // For QUIC v1, CID length must match our fixed 8-byte CID format.
    if (version == QUIC_VERSION_1 and scid_len != cid.len) return error.UnsupportedCidLength;
    var src_cid: ConnectionId = .{};
    if (scid_len > 0) {
        const copy_len = @min(scid_len, cid.len);
        @memcpy(src_cid.bytes[0..copy_len], buf[pos..][0..copy_len]);
    }
    pos += scid_len;

    const pkt_type = longHeaderType(first_byte);

    // Token (Initial only)
    var token: []const u8 = &.{};
    if (pkt_type == .initial) {
        const tr = varint.decode(buf[pos..]) orelse return error.PacketTooShort;
        pos += tr.len;
        const tok_len: usize = @intCast(tr.value);
        if (pos + tok_len > buf.len) return error.PacketTooShort;
        token = buf[pos..][0..tok_len];
        pos += tok_len;
    }

    // Payload length (varint) then packet number
    const lr = varint.decode(buf[pos..]) orelse return error.PacketTooShort;
    pos += lr.len;
    const rem_len: usize = @intCast(lr.value);
    if (pos + rem_len > buf.len) return error.PacketTooShort;

    // Packet number length from bits 0..1 of first byte (after protection removed)
    const pn_len: u8 = (first_byte & 0x03) + 1;
    if (rem_len < pn_len) return error.PacketTooShort;

    var pn: u32 = 0;
    for (0..pn_len) |i| {
        pn = (pn << 8) | buf[pos + i];
    }
    pos += pn_len;

    const payload_end = pos + rem_len - pn_len;
    const payload = buf[pos..payload_end];
    pos = payload_end;

    return .{
        .header = .{
            .packet_type = pkt_type,
            .version = version,
            .dest_cid = dest_cid,
            .src_cid = src_cid,
            .token = token,
            .pn_len = pn_len,
            .packet_number = pn,
            .payload = payload,
        },
        .consumed = pos,
    };
}

/// Encode a Long Header into `buf`, without payload.
/// Returns the number of bytes written (header only, up to and including the PN).
pub fn encodeLongHeader(
    buf: []u8,
    pkt_type: PacketType,
    version: u32,
    dest: ConnectionId,
    src: ConnectionId,
    token: []const u8,
    pn: u32,
    payload_len: usize,
) usize {
    // We always use 4-byte packet numbers in Phase 1 (bits 0..1 = 0b11).
    const pn_len: u8 = 4;
    var pos: usize = 0;

    // First byte: 1 (long) | 1 (fixed) | type (2) | reserved (2) | pn_len-1 (2)
    buf[pos] = 0xc0 | (@as(u8, @intFromEnum(pkt_type)) << 4) | (pn_len - 1);
    pos += 1;

    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;

    // DCID
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &dest.bytes);
    pos += cid.len;

    // SCID
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &src.bytes);
    pos += cid.len;

    // Token (Initial only)
    if (pkt_type == .initial) {
        pos += varint.encode(buf[pos..], @intCast(token.len));
        @memcpy(buf[pos..][0..token.len], token);
        pos += token.len;
    }

    // Payload length = pn_len + ciphertext + tag
    const total_payload = pn_len + payload_len;
    pos += varint.encode(buf[pos..], @intCast(total_payload));

    // Packet number (4 bytes, big-endian)
    std.mem.writeInt(u32, buf[pos..][0..4], pn, .big);
    pos += 4;

    return pos;
}

// ---------------------------------------------------------------------------
// Short Header (1-RTT)
// ---------------------------------------------------------------------------

pub const ShortHeader = struct {
    spin_bit: bool,
    key_phase: bool,
    dest_cid: ConnectionId,
    pn_len: u8,
    packet_number: u32,
    payload: []const u8,
};

pub fn parseShortHeader(buf: []const u8, dcid_len: usize) !struct { header: ShortHeader, consumed: usize } {
    if (buf.len < 1 + dcid_len) return error.PacketTooShort;
    if (isLongHeader(buf[0])) return error.NotShortHeader;

    const first_byte = buf[0];
    var pos: usize = 1;

    var dest_cid: ConnectionId = .{};
    const copy_len = @min(dcid_len, cid.len);
    @memcpy(dest_cid.bytes[0..copy_len], buf[pos..][0..copy_len]);
    pos += dcid_len;

    const pn_len: u8 = (first_byte & 0x03) + 1;
    if (pos + pn_len > buf.len) return error.PacketTooShort;

    var pn: u32 = 0;
    for (0..pn_len) |i| {
        pn = (pn << 8) | buf[pos + i];
    }
    pos += pn_len;

    return .{
        .header = .{
            .spin_bit = (first_byte & 0x20) != 0,
            .key_phase = (first_byte & 0x04) != 0,
            .dest_cid = dest_cid,
            .pn_len = pn_len,
            .packet_number = pn,
            .payload = buf[pos..],
        },
        .consumed = buf.len,
    };
}

pub fn encodeShortHeader(
    buf: []u8,
    dest: ConnectionId,
    pn: u32,
    key_phase: bool,
) usize {
    const pn_len: u8 = 4;
    var pos: usize = 0;

    buf[pos] = 0x40 | (if (key_phase) @as(u8, 0x04) else 0) | (pn_len - 1);
    pos += 1;

    @memcpy(buf[pos..][0..cid.len], &dest.bytes);
    pos += cid.len;

    std.mem.writeInt(u32, buf[pos..][0..4], pn, .big);
    pos += 4;

    return pos;
}

/// Encode a Version Negotiation packet (RFC 9000 §17.2.1).
///
/// `dcid` is echoed from the client's SCID so the client can demultiplex.
/// `scid` is the server's own connection ID.
/// The packet advertises QUIC version 1 as the single supported version.
/// Returns the number of bytes written.
pub fn encodeVersionNegotiation(
    buf: []u8,
    dcid: ConnectionId,
    scid: ConnectionId,
) usize {
    var pos: usize = 0;

    // First byte: long header bit set (0x80), remaining bits arbitrary.
    buf[pos] = 0x80;
    pos += 1;

    // Version = 0x00000000  (identifies this as a VN packet).
    std.mem.writeInt(u32, buf[pos..][0..4], 0, .big);
    pos += 4;

    // Destination Connection ID (echoed client SCID).
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &dcid.bytes);
    pos += cid.len;

    // Source Connection ID (our CID).
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &scid.bytes);
    pos += cid.len;

    // Supported Versions: QUIC version 1.
    std.mem.writeInt(u32, buf[pos..][0..4], QUIC_VERSION_1, .big);
    pos += 4;

    return pos;
}

/// Decode a full packet number from a truncated value per RFC 9000 §A.3.
pub fn decodePacketNumber(largest_acked: u64, truncated: u32, pn_bits: u8) u64 {
    const expected: u64 = largest_acked + 1;
    const pn_win: u64 = @as(u64, 1) << @intCast(pn_bits);
    const pn_hwin: u64 = pn_win / 2;
    const pn_mask: u64 = pn_win - 1;

    const candidate = (expected & ~pn_mask) | @as(u64, truncated);

    if (candidate <= expected -| pn_hwin and candidate < (@as(u64, 1) << 62) - pn_win) {
        return candidate + pn_win;
    }
    if (candidate > expected + pn_hwin and candidate >= pn_win) {
        return candidate - pn_win;
    }
    return candidate;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "packet: long header encode/parse round-trip (Initial)" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const token = [_]u8{};
    const payload_len: usize = 100;

    const hdr_len = encodeLongHeader(&buf, .initial, QUIC_VERSION_1, dcid, scid, &token, 42, payload_len);
    // Fill in dummy payload
    @memset(buf[hdr_len..][0..payload_len], 0xab);

    const result = try parseLongHeader(buf[0 .. hdr_len + payload_len]);
    const h = result.header;

    try testing.expectEqual(PacketType.initial, h.packet_type);
    try testing.expectEqual(QUIC_VERSION_1, h.version);
    try testing.expect(ConnectionId.eql(dcid, h.dest_cid));
    try testing.expect(ConnectionId.eql(scid, h.src_cid));
    try testing.expectEqual(@as(u32, 42), h.packet_number);
    try testing.expectEqual(payload_len, h.payload.len);
}

test "packet: short header encode/parse round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11 } };

    const hdr_len = encodeShortHeader(&buf, dcid, 7, false);
    const payload = [_]u8{ 1, 2, 3, 4 };
    @memcpy(buf[hdr_len..][0..payload.len], &payload);

    const result = try parseShortHeader(buf[0 .. hdr_len + payload.len], cid.len);
    const h = result.header;

    try testing.expect(ConnectionId.eql(dcid, h.dest_cid));
    try testing.expectEqual(@as(u32, 7), h.packet_number);
    try testing.expect(!h.key_phase);
}

test "packet: decodePacketNumber" {
    const testing = std.testing;

    // RFC 9000 §A.3 example: largest=0xa82f30ea, truncated=0x9b32
    const largest: u64 = 0xa82f30ea;
    const truncated: u32 = 0x9b32;
    const decoded = decodePacketNumber(largest, truncated, 16);
    try testing.expectEqual(@as(u64, 0xa82f9b32), decoded);
}

test "packet: long header with wrong CID length returns UnsupportedCidLength" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    // Build a QUIC v1 Initial packet with a 4-byte DCID (not the expected 8 bytes)
    buf[0] = 0xc0; // long header, Initial
    std.mem.writeInt(u32, buf[1..5], QUIC_VERSION_1, .big);
    buf[5] = 4; // DCID length = 4 (wrong; must be 8 for our library)
    @memset(buf[6..10], 0xaa);
    buf[10] = 8; // SCID length
    @memset(buf[11..19], 0xbb);
    // pad rest
    @memset(buf[19..32], 0);
    try testing.expectError(error.UnsupportedCidLength, parseLongHeader(buf[0..32]));
}

test "packet: encodeVersionNegotiation structure" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const n = encodeVersionNegotiation(&buf, dcid, scid);

    // Exact wire size: 1 + 4 + 1 + 8 + 1 + 8 + 4 = 27 bytes.
    try testing.expectEqual(@as(usize, 27), n);

    // Long header bit must be set.
    try testing.expect(buf[0] & 0x80 != 0);

    // Version field must be 0x00000000.
    try testing.expectEqual(@as(u32, 0), std.mem.readInt(u32, buf[1..5], .big));

    // DCID length and bytes.
    try testing.expectEqual(@as(u8, cid.len), buf[5]);
    try testing.expectEqualSlices(u8, &dcid.bytes, buf[6..14]);

    // SCID length and bytes.
    try testing.expectEqual(@as(u8, cid.len), buf[14]);
    try testing.expectEqualSlices(u8, &scid.bytes, buf[15..23]);

    // Supported version: QUIC v1.
    try testing.expectEqual(QUIC_VERSION_1, std.mem.readInt(u32, buf[23..27], .big));
}
