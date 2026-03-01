//! QUIC packet header encoding and decoding (RFC 9000 §17).
//!
//! Supports Long Headers (Initial, 0-RTT, Handshake, Retry) and Short Headers
//! (1-RTT / "protected") packets.

const std = @import("std");
const varint = @import("varint.zig");
const cid = @import("connection_id.zig");
const ConnectionId = cid.ConnectionId;

pub const QUIC_VERSION_1: u32 = 0x0000_0001;
pub const QUIC_VERSION_2: u32 = 0x6b33_43cf;

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
/// v1 and v2 encode the same four types with different 2-bit patterns in bits 5–4
/// (RFC 9369 §3.1): v2 rotates v1's encoding by +1, so we rotate back by -1 (i.e., +3 mod 4).
pub fn longHeaderType(first_byte: u8, version: u32) PacketType {
    const raw: u8 = (first_byte >> 4) & 0x03;
    if (version == QUIC_VERSION_2) {
        return @enumFromInt((raw + 3) % 4);
    }
    return @enumFromInt(raw);
}

// ---------------------------------------------------------------------------
// Long Header
// ---------------------------------------------------------------------------

pub const LongHeader = struct {
    packet_type: PacketType,
    version: u32,
    dest_cid: ConnectionId,
    /// Actual wire length of the destination CID (0-20 bytes).
    dest_cid_len: u8,
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

    // Destination CID (RFC allows 0–20 bytes)
    if (pos >= buf.len) return error.PacketTooShort;
    const dcid_len = buf[pos];
    pos += 1;
    if (pos + dcid_len > buf.len) return error.PacketTooShort;
    // Reject CID lengths > 20 (RFC 9000 §17.2).
    if ((version == QUIC_VERSION_1 or version == QUIC_VERSION_2) and dcid_len > 20) return error.UnsupportedCidLength;
    var dest_cid: ConnectionId = .{};
    if (dcid_len > 0) {
        const copy_len = @min(dcid_len, cid.len);
        @memcpy(dest_cid.bytes[0..copy_len], buf[pos..][0..copy_len]);
    }
    pos += dcid_len;

    // Source CID (RFC allows 0–20 bytes)
    if (pos >= buf.len) return error.PacketTooShort;
    const scid_len = buf[pos];
    pos += 1;
    if (pos + scid_len > buf.len) return error.PacketTooShort;
    // Reject CID lengths > 20 (RFC 9000 §17.2).
    if ((version == QUIC_VERSION_1 or version == QUIC_VERSION_2) and scid_len > 20) return error.UnsupportedCidLength;
    var src_cid: ConnectionId = .{};
    if (scid_len > 0) {
        const copy_len = @min(scid_len, cid.len);
        @memcpy(src_cid.bytes[0..copy_len], buf[pos..][0..copy_len]);
    }
    pos += scid_len;

    const pkt_type = longHeaderType(first_byte, version);

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
            .dest_cid_len = dcid_len,
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
    // v2 rotates the 2-bit type encoding by +1 mod 4 (RFC 9369 §3.1).
    const raw_type: u8 = if (version == QUIC_VERSION_2)
        (@as(u8, @intFromEnum(pkt_type)) + 1) % 4
    else
        @as(u8, @intFromEnum(pkt_type));
    buf[pos] = 0xc0 | (raw_type << 4) | (pn_len - 1);
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

    // Supported Versions: QUIC v1 and v2.
    std.mem.writeInt(u32, buf[pos..][0..4], QUIC_VERSION_1, .big);
    pos += 4;
    std.mem.writeInt(u32, buf[pos..][0..4], QUIC_VERSION_2, .big);
    pos += 4;

    return pos;
}

/// Encode a Retry packet (RFC 9000 §17.2.5).
///
/// Retry wire format: 0xf0 | version (4) | DCID_len(1) + DCID(8) | SCID_len(1) + SCID(8) | token(N) | integrity_tag(16)
/// No packet number, no length prefix, no AEAD payload — completely different from Long Header.
///
/// `dcid` is the client's source CID from the Initial packet (echoed back as DCID in Retry).
/// `scid` is a new server CID used in the Retry packet.
/// `token` is the opaque address-validation token.
/// `odcid` is the original DCID from the Initial packet (used for Integrity Tag computation).
///
/// Returns the number of bytes written.
pub fn encodeRetry(
    buf: []u8,
    dcid: ConnectionId, // client's src CID → send back as DCID
    scid: ConnectionId, // new server CID used in Retry
    token: []const u8, // opaque address-validation token
    odcid: []const u8, // original DCID bytes (variable length, for Integrity Tag)
    version: u32,
) usize {
    var pos: usize = 0;

    // First byte: 1 (long) | 1 (fixed) | retry type bits | reserved | 0
    // v1: Retry raw bits = 0b11 → 0xf0; v2: Retry raw bits = 0b00 → 0xc0 (RFC 9369 §3.1).
    const retry_raw: u8 = if (version == QUIC_VERSION_2) 0b00 else 0b11;
    buf[pos] = 0xc0 | (retry_raw << 4);
    pos += 1;

    // Version (4 bytes)
    std.mem.writeInt(u32, buf[pos..][0..4], version, .big);
    pos += 4;

    // DCID (client's source CID from Initial)
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &dcid.bytes);
    pos += cid.len;

    // SCID (new server CID)
    buf[pos] = cid.len;
    pos += 1;
    @memcpy(buf[pos..][0..cid.len], &scid.bytes);
    pos += cid.len;

    // Token (variable length)
    pos += varint.encode(buf[pos..], @intCast(token.len));
    @memcpy(buf[pos..][0..token.len], token);
    pos += token.len;

    // Retry Integrity Tag (RFC 9001 §5.8, RFC 9369 §4.2.1)
    // Fixed key and nonce differ between v1 and v2.
    const integrity_key = if (version == QUIC_VERSION_2)
        [_]u8{
            0x8f, 0xb4, 0xb0, 0x1b, 0x56, 0xac, 0x48, 0xe2,
            0x60, 0xfb, 0xcb, 0xce, 0xad, 0x7c, 0xcc, 0x92,
        }
    else
        [_]u8{
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a,
            0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68, 0xc8, 0x4e,
        };
    const integrity_nonce = if (version == QUIC_VERSION_2)
        [_]u8{
            0xd8, 0x69, 0x69, 0xbc, 0x2d, 0x7c, 0x6d, 0x99,
            0x90, 0xef, 0xfd, 0x52,
        }
    else
        [_]u8{
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2,
            0xa1, 0x8b, 0x0d, 0x12,
        };

    // Pseudo-header for AAD: [odcid_len] ++ odcid_bytes ++ retry_packet_without_tag
    var aad_buf: [256]u8 = undefined;
    var aad_len: usize = 0;
    aad_buf[aad_len] = @intCast(odcid.len);
    aad_len += 1;
    @memcpy(aad_buf[aad_len..][0..odcid.len], odcid);
    aad_len += odcid.len;
    @memcpy(aad_buf[aad_len..][0..pos], buf[0..pos]);
    aad_len += pos;

    const aad = aad_buf[0..aad_len];

    // Encrypt empty plaintext to get the tag
    // Aes128Gcm.encrypt(ciphertext, tag, plaintext, ad, nonce, key)
    var tag: [16]u8 = undefined;
    std.crypto.aead.aes_gcm.Aes128Gcm.encrypt(&.{}, &tag, &.{}, aad, integrity_nonce, integrity_key);

    // Append integrity tag to buffer
    @memcpy(buf[pos..][0..16], &tag);
    pos += 16;

    return pos;
}

/// Compute the byte offset of the packet-number field in a long-header packet.
///
/// The packet type bits (5–4) are NOT header-protected, so this function is safe
/// to call on the raw (still-protected) buffer.  Call before header-protection
/// removal to locate the PN field and the HP sample (at pn_off + 4).
pub fn longHeaderPnOffset(buf: []const u8, version: u32) !usize {
    if (buf.len < 7) return error.PacketTooShort;

    const dcid_len = buf[5];
    if (buf.len < 6 + dcid_len + 1) return error.PacketTooShort;
    const scid_len = buf[6 + dcid_len];

    var pos: usize = 6 + dcid_len + 1 + scid_len;
    if (pos > buf.len) return error.PacketTooShort;

    // Initial packets carry a token before the payload-length field.
    const pkt_type = longHeaderType(buf[0], version);
    if (pkt_type == .initial) {
        const tr = varint.decode(buf[pos..]) orelse return error.PacketTooShort;
        pos += tr.len;
        const tok_len: usize = @intCast(tr.value);
        if (pos + tok_len > buf.len) return error.PacketTooShort;
        pos += tok_len;
    }

    // Payload-length varint (covers PN bytes + ciphertext + AEAD tag).
    const lr = varint.decode(buf[pos..]) orelse return error.PacketTooShort;
    pos += lr.len;

    return pos; // PN field starts here
}

/// Compute the byte offset of the packet-number field in a short-header packet.
/// Short header: first_byte(1) + DCID(dcid_len) + PN(...).
pub fn shortHeaderPnOffset(dcid_len: usize) usize {
    return 1 + dcid_len;
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

test "packet: long header with CID length > 20 returns UnsupportedCidLength" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    // Build a QUIC v1 Initial packet with a 21-byte DCID (exceeds RFC maximum of 20)
    buf[0] = 0xc0; // long header, Initial
    std.mem.writeInt(u32, buf[1..5], QUIC_VERSION_1, .big);
    buf[5] = 21; // DCID length = 21 (invalid; RFC allows 0-20)
    @memset(buf[6..27], 0xaa);
    buf[27] = 8; // SCID length
    @memset(buf[28..36], 0xbb);
    // pad rest
    @memset(buf[36..64], 0);
    try testing.expectError(error.UnsupportedCidLength, parseLongHeader(buf[0..64]));
}

test "packet: encodeVersionNegotiation structure" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;

    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const n = encodeVersionNegotiation(&buf, dcid, scid);

    // Exact wire size: 1 + 4 + 1 + 8 + 1 + 8 + 4 + 4 = 31 bytes (v1 + v2).
    try testing.expectEqual(@as(usize, 31), n);

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

    // Supported versions: QUIC v1 then v2.
    try testing.expectEqual(QUIC_VERSION_1, std.mem.readInt(u32, buf[23..27], .big));
    try testing.expectEqual(QUIC_VERSION_2, std.mem.readInt(u32, buf[27..31], .big));
}

test "packet: longHeaderType extracts all four packet types" {
    // First byte layout: 1 (long) | 1 (fixed) | type[1:0] | reserved | pn_len
    // Bits 5-4 encode the PacketType.
    try std.testing.expectEqual(PacketType.initial, longHeaderType(0xC0, QUIC_VERSION_1)); // type=0b00
    try std.testing.expectEqual(PacketType.zero_rtt, longHeaderType(0xD0, QUIC_VERSION_1)); // type=0b01
    try std.testing.expectEqual(PacketType.handshake, longHeaderType(0xE0, QUIC_VERSION_1)); // type=0b10
    try std.testing.expectEqual(PacketType.retry, longHeaderType(0xF0, QUIC_VERSION_1)); // type=0b11
}

test "packet: decodePacketNumber wrap-around" {
    // largest_acked=250, truncated=5, pn_bits=8:
    //   expected = 251, pn_win = 256, candidate = (251 & ~255) | 5 = 5
    //   5 <= 251 - 128 = 123  →  return 5 + 256 = 261
    try std.testing.expectEqual(@as(u64, 261), decodePacketNumber(250, 5, 8));
}

test "packet: parseLongHeader with non-empty Initial token" {
    const testing = std.testing;
    var buf: [300]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const tok = [_]u8{ 0xAB, 0xCD, 0xEF, 0x01 }; // 4-byte token

    const hdr_len = encodeLongHeader(&buf, .initial, QUIC_VERSION_1, dcid, scid, &tok, 99, 20);
    @memset(buf[hdr_len..][0..20], 0xBB);

    const result = try parseLongHeader(buf[0 .. hdr_len + 20]);
    try testing.expectEqual(PacketType.initial, result.header.packet_type);
    try testing.expectEqualSlices(u8, &tok, result.header.token);
    try testing.expectEqual(@as(u32, 99), result.header.packet_number);
}

test "packet: encodeRetry structure" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const odcid = ConnectionId{ .bytes = .{ 17, 18, 19, 20, 21, 22, 23, 24 } };
    const token = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

    const n = encodeRetry(&buf, dcid, scid, &token, &odcid.bytes, QUIC_VERSION_1);

    // Verify first byte is 0xf0 (Retry packet, v1: raw type bits 0b11)
    try testing.expectEqual(@as(u8, 0xf0), buf[0]);

    // Verify version is QUIC v1
    try testing.expectEqual(QUIC_VERSION_1, std.mem.readInt(u32, buf[1..5], .big));

    // Verify DCID length and content
    try testing.expectEqual(@as(u8, cid.len), buf[5]);
    try testing.expectEqualSlices(u8, &dcid.bytes, buf[6..14]);

    // Verify SCID length and content
    try testing.expectEqual(@as(u8, cid.len), buf[14]);
    try testing.expectEqualSlices(u8, &scid.bytes, buf[15..23]);

    // Verify token length and content
    var pos: usize = 23;
    const token_len_vi = varint.decode(buf[pos..]) orelse return error.InvalidFormat;
    try testing.expectEqual(@as(u62, 4), token_len_vi.value);
    pos += token_len_vi.len;
    try testing.expectEqualSlices(u8, &token, buf[pos..][0..4]);
    pos += 4;

    // Verify integrity tag is 16 bytes at the end
    try testing.expectEqual(@as(usize, 16), n - pos);
}

test "packet: encodeRetry integrity tag is 16 bytes" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const odcid = ConnectionId{ .bytes = .{ 17, 18, 19, 20, 21, 22, 23, 24 } };
    const token = [_]u8{0xAA} ** 62; // max size token

    const n = encodeRetry(&buf, dcid, scid, &token, &odcid.bytes, QUIC_VERSION_1);

    // Expected: 1 + 4 + 1 + 8 + 1 + 8 + varint(62) + 62 + 16
    // varint(62) = 1 byte, so total = 1 + 4 + 1 + 8 + 1 + 8 + 1 + 62 + 16 = 102
    try testing.expectEqual(@as(usize, 102), n);
}

test "packet: longHeaderType v2 rotates packet type bits" {
    // v2 raw bits are shifted by +1 relative to v1 (RFC 9369 §3.1).
    // raw 0b01 → Initial (v2), raw 0b10 → 0-RTT (v2), etc.
    try std.testing.expectEqual(PacketType.initial, longHeaderType(0xD0, QUIC_VERSION_2)); // raw 0b01
    try std.testing.expectEqual(PacketType.zero_rtt, longHeaderType(0xE0, QUIC_VERSION_2)); // raw 0b10
    try std.testing.expectEqual(PacketType.handshake, longHeaderType(0xF0, QUIC_VERSION_2)); // raw 0b11
    try std.testing.expectEqual(PacketType.retry, longHeaderType(0xC0, QUIC_VERSION_2)); // raw 0b00
}

test "packet: encodeLongHeader v2 encodes Initial with raw bits 0b01" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };

    const hdr_len = encodeLongHeader(&buf, .initial, QUIC_VERSION_2, dcid, scid, &.{}, 1, 20);
    @memset(buf[hdr_len..][0..20], 0xab);

    // First byte bits 5–4 must be 0b01 (v2 Initial raw bits).
    try testing.expectEqual(@as(u8, 0b01), (buf[0] >> 4) & 0x03);
    // Version field must be QUIC v2.
    try testing.expectEqual(QUIC_VERSION_2, std.mem.readInt(u32, buf[1..5], .big));

    // Round-trip: parseLongHeader must decode it as Initial.
    const result = try parseLongHeader(buf[0 .. hdr_len + 20]);
    try testing.expectEqual(PacketType.initial, result.header.packet_type);
    try testing.expectEqual(QUIC_VERSION_2, result.header.version);
}

test "packet: encodeVersionNegotiation lists v1 and v2" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    const dcid = ConnectionId{ .bytes = .{ 1, 2, 3, 4, 5, 6, 7, 8 } };
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const n = encodeVersionNegotiation(&buf, dcid, scid);

    // Wire size: 1 + 4 + 1 + 8 + 1 + 8 + 4 (v1) + 4 (v2) = 31 bytes.
    try testing.expectEqual(@as(usize, 31), n);
    try testing.expectEqual(QUIC_VERSION_1, std.mem.readInt(u32, buf[23..27], .big));
    try testing.expectEqual(QUIC_VERSION_2, std.mem.readInt(u32, buf[27..31], .big));
}
