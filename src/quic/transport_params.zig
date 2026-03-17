//! QUIC transport parameter encoding and decoding (RFC 9000 §18).
//!
//! Transport parameters are negotiated via the TLS handshake as a TLS extension
//! (type 0x0039).  Each parameter is TLV-encoded: (id: VarInt, length: VarInt, value).

const std = @import("std");
const varint = @import("varint.zig");
const cid = @import("connection_id.zig");
const ConnectionId = cid.ConnectionId;

// ---------------------------------------------------------------------------
// Transport parameter IDs (RFC 9000 §18.2)
// ---------------------------------------------------------------------------

const TP_ORIGINAL_DESTINATION_CONNECTION_ID: u62 = 0x00;
const TP_MAX_IDLE_TIMEOUT: u62 = 0x01;
const TP_STATELESS_RESET_TOKEN: u62 = 0x02;
const TP_MAX_UDP_PAYLOAD_SIZE: u62 = 0x03;
const TP_INITIAL_MAX_DATA: u62 = 0x04;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u62 = 0x05;
const TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u62 = 0x06;
const TP_INITIAL_MAX_STREAM_DATA_UNI: u62 = 0x07;
const TP_INITIAL_MAX_STREAMS_BIDI: u62 = 0x08;
const TP_INITIAL_MAX_STREAMS_UNI: u62 = 0x09;
const TP_ACK_DELAY_EXPONENT: u62 = 0x0a;
const TP_MAX_ACK_DELAY: u62 = 0x0b;
const TP_DISABLE_ACTIVE_MIGRATION: u62 = 0x0c;
const TP_PREFERRED_ADDRESS: u62 = 0x0d;
const TP_ACTIVE_CONNECTION_ID_LIMIT: u62 = 0x0e;
const TP_INITIAL_SOURCE_CONNECTION_ID: u62 = 0x0f;
const TP_RETRY_SOURCE_CONNECTION_ID: u62 = 0x10;
const TP_VERSION_INFORMATION: u62 = 0x11;

// ---------------------------------------------------------------------------
// TransportParams
// ---------------------------------------------------------------------------

pub const TransportParams = struct {
    max_idle_timeout_ms: u64 = 30_000,
    max_udp_payload_size: u64 = 65527,
    initial_max_data: u64 = 1024 * 1024,
    initial_max_stream_data_bidi_local: u64 = 256 * 1024,
    initial_max_stream_data_bidi_remote: u64 = 256 * 1024,
    initial_max_stream_data_uni: u64 = 256 * 1024,
    initial_max_streams_bidi: u64 = 32,
    initial_max_streams_uni: u64 = 32,
    ack_delay_exponent: u64 = 3,
    max_ack_delay_ms: u64 = 25,
    active_connection_id_limit: u64 = 2,
    disable_active_migration: bool = false,
    stateless_reset_token: ?[16]u8 = null,
    initial_source_connection_id: ?[20]u8 = null,
    initial_source_connection_id_len: u8 = 0,
    /// Original destination CID from the Initial packet (sent after Retry).
    /// RFC 9000 §18.2 parameter 0x00.  Variable length 0–20 bytes.
    original_destination_connection_id: ?[20]u8 = null,
    original_destination_connection_id_len: u8 = 0,
    /// Retry source CID from the Retry packet we sent.
    /// RFC 9000 §18.2 parameter 0x10.
    retry_source_connection_id: ?ConnectionId = null,
    /// Version information: list of supported QUIC versions.
    /// RFC 9369 parameter 0x11. Stored as raw bytes (4 bytes per version).
    version_information: ?[20]u8 = null,
    version_information_len: u8 = 0, // Number of bytes (multiple of 4)
    /// Preferred address for connection migration (RFC 9000 §18.2 parameter 0x0d).
    /// Contains IPv4, IPv6, connection ID, and stateless reset token.
    preferred_address: ?PreferredAddress = null,
};

pub const PreferredAddress = struct {
    ipv4_addr: [4]u8, // IPv4 address
    ipv4_port: u16, // IPv4 port
    ipv6_addr: [16]u8, // IPv6 address
    ipv6_port: u16, // IPv6 port
    cid: [20]u8, // Connection ID (max 20 bytes)
    cid_len: u8, // Actual length of connection ID
    reset_token: [16]u8, // Stateless reset token
};

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

/// Write a single transport parameter with a varint value.
/// Format: id (varint) || len (varint) || value (varint).
fn writeVarintParam(buf: []u8, id: u62, value: u62) usize {
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], id);
    const vlen: u62 = @intCast(varint.encodedLen(value));
    pos += varint.encode(buf[pos..], vlen);
    pos += varint.encode(buf[pos..], value);
    return pos;
}

/// Encode `params` into `buf`.  Returns the number of bytes written.
/// `buf` must have at least 200 bytes available to hold all parameters.
pub fn encode(params: TransportParams, buf: []u8) usize {
    var pos: usize = 0;

    // Mandatory varint-valued parameters.
    pos += writeVarintParam(buf[pos..], TP_MAX_IDLE_TIMEOUT, @intCast(params.max_idle_timeout_ms));
    pos += writeVarintParam(buf[pos..], TP_MAX_UDP_PAYLOAD_SIZE, @intCast(params.max_udp_payload_size));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_DATA, @intCast(params.initial_max_data));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL, @intCast(params.initial_max_stream_data_bidi_local));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, @intCast(params.initial_max_stream_data_bidi_remote));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_UNI, @intCast(params.initial_max_stream_data_uni));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAMS_BIDI, @intCast(params.initial_max_streams_bidi));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAMS_UNI, @intCast(params.initial_max_streams_uni));
    pos += writeVarintParam(buf[pos..], TP_ACK_DELAY_EXPONENT, @intCast(params.ack_delay_exponent));
    pos += writeVarintParam(buf[pos..], TP_MAX_ACK_DELAY, @intCast(params.max_ack_delay_ms));
    pos += writeVarintParam(buf[pos..], TP_ACTIVE_CONNECTION_ID_LIMIT, @intCast(params.active_connection_id_limit));

    // Optional / flag parameters.
    if (params.stateless_reset_token) |tok| {
        pos += varint.encode(buf[pos..], TP_STATELESS_RESET_TOKEN);
        pos += varint.encode(buf[pos..], 16);
        @memcpy(buf[pos..][0..16], &tok);
        pos += 16;
    }

    if (params.disable_active_migration) {
        pos += varint.encode(buf[pos..], TP_DISABLE_ACTIVE_MIGRATION);
        pos += varint.encode(buf[pos..], 0); // empty value
    }

    if (params.initial_source_connection_id) |isci| {
        const cid_len = params.initial_source_connection_id_len;
        pos += varint.encode(buf[pos..], TP_INITIAL_SOURCE_CONNECTION_ID);
        pos += varint.encode(buf[pos..], @intCast(cid_len));
        @memcpy(buf[pos..][0..cid_len], isci[0..cid_len]);
        pos += cid_len;
    }

    if (params.original_destination_connection_id) |odcid| {
        const odcid_len = params.original_destination_connection_id_len;
        pos += varint.encode(buf[pos..], TP_ORIGINAL_DESTINATION_CONNECTION_ID);
        pos += varint.encode(buf[pos..], odcid_len);
        @memcpy(buf[pos..][0..odcid_len], odcid[0..odcid_len]);
        pos += odcid_len;
    }

    if (params.retry_source_connection_id) |scid| {
        pos += varint.encode(buf[pos..], TP_RETRY_SOURCE_CONNECTION_ID);
        pos += varint.encode(buf[pos..], cid.len);
        @memcpy(buf[pos..][0..cid.len], &scid.bytes);
        pos += cid.len;
    }

    if (params.version_information) |vi| {
        pos += varint.encode(buf[pos..], TP_VERSION_INFORMATION);
        pos += varint.encode(buf[pos..], @intCast(params.version_information_len));
        @memcpy(buf[pos..][0..params.version_information_len], vi[0..params.version_information_len]);
        pos += params.version_information_len;
    }

    if (params.preferred_address) |pa| {
        // RFC 9000 §18.2.3: preferred_address = IPv4 + IPv4 port + IPv6 + IPv6 port + CID len + CID + reset token
        const pa_len = 4 + 2 + 16 + 2 + 1 + pa.cid_len + 16;
        pos += varint.encode(buf[pos..], TP_PREFERRED_ADDRESS);
        pos += varint.encode(buf[pos..], @intCast(pa_len));
        // IPv4 address
        @memcpy(buf[pos..][0..4], &pa.ipv4_addr);
        pos += 4;
        // IPv4 port (network byte order)
        buf[pos] = @intCast((pa.ipv4_port >> 8) & 0xff);
        buf[pos + 1] = @intCast(pa.ipv4_port & 0xff);
        pos += 2;
        // IPv6 address
        @memcpy(buf[pos..][0..16], &pa.ipv6_addr);
        pos += 16;
        // IPv6 port (network byte order)
        buf[pos] = @intCast((pa.ipv6_port >> 8) & 0xff);
        buf[pos + 1] = @intCast(pa.ipv6_port & 0xff);
        pos += 2;
        // Connection ID length
        buf[pos] = pa.cid_len;
        pos += 1;
        // Connection ID
        @memcpy(buf[pos..][0..pa.cid_len], pa.cid[0..pa.cid_len]);
        pos += pa.cid_len;
        // Stateless reset token
        @memcpy(buf[pos..][0..16], &pa.reset_token);
        pos += 16;
    }

    return pos;
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

/// Decode transport parameters from `buf`.
/// Unknown parameter IDs are silently skipped (RFC 9000 §18.1).
/// Duplicate known parameter IDs are rejected per RFC 9000 §18.1.
/// Parameters absent from `buf` retain their default values.
pub fn decode(buf: []const u8) !TransportParams {
    var params = TransportParams{};
    var pos: usize = 0;
    // Bitmask tracking which known parameter IDs have been seen.
    // bit 0 for ID 0x00, bits 1-15 for IDs 0x01..0x0f, bit 16 for ID 0x10
    var seen: u32 = 0;
    var param_count: usize = 0;

    while (pos < buf.len) {
        param_count += 1;
        if (param_count > 64) return error.InvalidParams;
        const id_vi = varint.decode(buf[pos..]) orelse return error.InvalidParams;
        pos += id_vi.len;

        const len_vi = varint.decode(buf[pos..]) orelse return error.InvalidParams;
        pos += len_vi.len;

        const param_len: usize = @intCast(len_vi.value);
        if (pos + param_len > buf.len) return error.InvalidParams;

        const param_data = buf[pos..][0..param_len];

        // Check for duplicates among known IDs 0x00, 0x01..0x0f, 0x10, 0x11
        if (id_vi.value == 0) {
            const bit: u32 = 1; // bit 0 for ID 0
            if (seen & bit != 0) return error.DuplicateParam;
            seen |= bit;
        } else if (id_vi.value >= 1 and id_vi.value <= 15) {
            const bit: u32 = @as(u32, 1) << @intCast(id_vi.value);
            if (seen & bit != 0) return error.DuplicateParam;
            seen |= bit;
        } else if (id_vi.value == 16) {
            const bit: u32 = @as(u32, 1) << 16; // bit 16 for ID 16 (0x10)
            if (seen & bit != 0) return error.DuplicateParam;
            seen |= bit;
        } else if (id_vi.value == 17) {
            const bit: u32 = @as(u32, 1) << 17; // bit 17 for ID 17 (0x11)
            if (seen & bit != 0) return error.DuplicateParam;
            seen |= bit;
        }

        switch (id_vi.value) {
            TP_MAX_IDLE_TIMEOUT => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                // Guard against u64 overflow when converting to nanoseconds (* 1_000_000).
                // maxInt(u64) / 1_000_000 = 18_446_744_073_709.
                if (v.value > 18_446_744_073_709) return error.InvalidParams;
                params.max_idle_timeout_ms = v.value;
            },
            TP_STATELESS_RESET_TOKEN => {
                if (param_len != 16) return error.InvalidParams;
                var tok: [16]u8 = undefined;
                @memcpy(&tok, param_data);
                params.stateless_reset_token = tok;
            },
            TP_MAX_UDP_PAYLOAD_SIZE => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                if (v.value < 1200) return error.InvalidParams; // RFC 9000 §18.2
                params.max_udp_payload_size = v.value;
            },
            TP_INITIAL_MAX_DATA => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_data = v.value;
            },
            TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_stream_data_bidi_local = v.value;
            },
            TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_stream_data_bidi_remote = v.value;
            },
            TP_INITIAL_MAX_STREAM_DATA_UNI => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_stream_data_uni = v.value;
            },
            TP_INITIAL_MAX_STREAMS_BIDI => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_streams_bidi = v.value;
            },
            TP_INITIAL_MAX_STREAMS_UNI => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.initial_max_streams_uni = v.value;
            },
            TP_ACK_DELAY_EXPONENT => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                if (v.value > 20) return error.InvalidParams; // RFC 9000 §18.2
                params.ack_delay_exponent = v.value;
            },
            TP_MAX_ACK_DELAY => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                if (v.value >= (1 << 14)) return error.InvalidParams; // RFC 9000 §18.2: < 2^14 ms
                params.max_ack_delay_ms = v.value;
            },
            TP_DISABLE_ACTIVE_MIGRATION => {
                params.disable_active_migration = true;
            },
            TP_ACTIVE_CONNECTION_ID_LIMIT => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                if (v.value < 2) return error.InvalidParams; // RFC 9000 §18.2
                params.active_connection_id_limit = v.value;
            },
            TP_INITIAL_SOURCE_CONNECTION_ID => {
                const copy_len: u8 = @intCast(@min(param_len, 20));
                var isci: [20]u8 = undefined;
                @memcpy(isci[0..copy_len], param_data[0..copy_len]);
                params.initial_source_connection_id = isci;
                params.initial_source_connection_id_len = copy_len;
            },
            TP_ORIGINAL_DESTINATION_CONNECTION_ID => {
                if (param_len > 20) return error.InvalidParams;
                var odcid: [20]u8 = [_]u8{0} ** 20;
                @memcpy(odcid[0..param_len], param_data);
                params.original_destination_connection_id = odcid;
                params.original_destination_connection_id_len = @intCast(param_len);
            },
            TP_RETRY_SOURCE_CONNECTION_ID => {
                if (param_len != cid.len) return error.InvalidParams;
                var scid: ConnectionId = .{};
                @memcpy(&scid.bytes, param_data);
                params.retry_source_connection_id = scid;
            },
            TP_VERSION_INFORMATION => {
                // RFC 9369: version_information is a list of 32-bit version numbers.
                // Must be multiple of 4 bytes and fit in our buffer (max 20 bytes).
                if (param_len % 4 != 0 or param_len > 20) return error.InvalidParams;
                var vi: [20]u8 = undefined;
                @memcpy(vi[0..param_len], param_data);
                params.version_information = vi;
                params.version_information_len = @intCast(param_len);
            },
            TP_PREFERRED_ADDRESS => {
                // RFC 9000 §18.2.3: preferred_address structure
                // IPv4 (4) + IPv4 port (2) + IPv6 (16) + IPv6 port (2) + CID len (1) + CID (0-20) + reset token (16)
                if (param_len < 41) return error.InvalidParams; // Minimum: 4+2+16+2+1+0+16 = 41
                if (param_len > 61) return error.InvalidParams; // Maximum: 4+2+16+2+1+20+16 = 61

                var pa: PreferredAddress = undefined;
                var pa_pos: usize = 0;

                // IPv4 address
                @memcpy(&pa.ipv4_addr, param_data[pa_pos..][0..4]);
                pa_pos += 4;

                // IPv4 port (network byte order / big-endian)
                pa.ipv4_port = (@as(u16, param_data[pa_pos]) << 8) | param_data[pa_pos + 1];
                pa_pos += 2;

                // IPv6 address
                @memcpy(&pa.ipv6_addr, param_data[pa_pos..][0..16]);
                pa_pos += 16;

                // IPv6 port (network byte order / big-endian)
                pa.ipv6_port = (@as(u16, param_data[pa_pos]) << 8) | param_data[pa_pos + 1];
                pa_pos += 2;

                // Connection ID length
                const cid_len = param_data[pa_pos];
                if (cid_len > 20) return error.InvalidParams;
                pa_pos += 1;

                // Validate total length matches 41 + cid_len
                if (param_len != 41 + cid_len) return error.InvalidParams;

                // Connection ID
                pa.cid_len = cid_len;
                @memcpy(pa.cid[0..cid_len], param_data[pa_pos..][0..cid_len]);
                pa_pos += cid_len;

                // Stateless reset token
                @memcpy(&pa.reset_token, param_data[pa_pos..][0..16]);

                params.preferred_address = pa;
            },
            else => {}, // Unknown parameters are silently skipped (RFC 9000 §18.1).
        }

        pos += param_len;
    }

    return params;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "transport_params: round-trip encode/decode with non-default values" {
    const testing = std.testing;

    const original = TransportParams{
        .max_idle_timeout_ms = 60_000,
        .max_udp_payload_size = 1200,
        .initial_max_data = 2 * 1024 * 1024,
        .initial_max_stream_data_bidi_local = 512 * 1024,
        .initial_max_stream_data_bidi_remote = 512 * 1024,
        .initial_max_stream_data_uni = 128 * 1024,
        .initial_max_streams_bidi = 200,
        .initial_max_streams_uni = 50,
        .ack_delay_exponent = 5,
        .max_ack_delay_ms = 50,
        .active_connection_id_limit = 8,
        .disable_active_migration = true,
        .stateless_reset_token = [_]u8{0xab} ** 16,
        .initial_source_connection_id = null,
        .initial_source_connection_id_len = 0,
    };

    var buf: [512]u8 = undefined;
    const n = encode(original, &buf);

    const decoded = try decode(buf[0..n]);

    try testing.expectEqual(original.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
    try testing.expectEqual(original.max_udp_payload_size, decoded.max_udp_payload_size);
    try testing.expectEqual(original.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(original.initial_max_stream_data_bidi_local, decoded.initial_max_stream_data_bidi_local);
    try testing.expectEqual(original.initial_max_stream_data_bidi_remote, decoded.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(original.initial_max_stream_data_uni, decoded.initial_max_stream_data_uni);
    try testing.expectEqual(original.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expectEqual(original.initial_max_streams_uni, decoded.initial_max_streams_uni);
    try testing.expectEqual(original.ack_delay_exponent, decoded.ack_delay_exponent);
    try testing.expectEqual(original.max_ack_delay_ms, decoded.max_ack_delay_ms);
    try testing.expectEqual(original.active_connection_id_limit, decoded.active_connection_id_limit);
    try testing.expectEqual(original.disable_active_migration, decoded.disable_active_migration);
    try testing.expectEqualSlices(u8, &original.stateless_reset_token.?, &decoded.stateless_reset_token.?);
}

test "transport_params: stateless_reset_token only encoded when non-null" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    const without = TransportParams{};
    const n_without = encode(without, &buf);
    const decoded_without = try decode(buf[0..n_without]);
    try testing.expect(decoded_without.stateless_reset_token == null);

    const with = TransportParams{ .stateless_reset_token = [_]u8{0x77} ** 16 };
    const n_with = encode(with, &buf);
    const decoded_with = try decode(buf[0..n_with]);
    try testing.expect(decoded_with.stateless_reset_token != null);
    try testing.expectEqualSlices(u8, &([_]u8{0x77} ** 16), &decoded_with.stateless_reset_token.?);

    // The buffer with token must be larger than without.
    try testing.expect(n_with > n_without);
}

test "transport_params: empty input decodes to defaults" {
    const testing = std.testing;
    const defaults = TransportParams{};
    const decoded = try decode(&.{});

    try testing.expectEqual(defaults.max_idle_timeout_ms, decoded.max_idle_timeout_ms);
    try testing.expectEqual(defaults.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(defaults.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expect(decoded.stateless_reset_token == null);
    try testing.expect(!decoded.disable_active_migration);
}

test "transport_params: unknown parameter IDs are skipped" {
    const testing = std.testing;
    // Build a buffer: known param (0x04 initial_max_data=999) + unknown (0x55) + known (0x08 streams_bidi=7)
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // 0x04 initial_max_data = 999
    pos += varint.encode(buf[pos..], 0x04);
    pos += varint.encode(buf[pos..], 2); // 2-byte varint value
    pos += varint.encode(buf[pos..], 999);

    // 0x55 unknown param with 3-byte payload
    pos += varint.encode(buf[pos..], 0x55);
    pos += varint.encode(buf[pos..], 3);
    buf[pos] = 0xde;
    buf[pos + 1] = 0xad;
    buf[pos + 2] = 0xbe;
    pos += 3;

    // 0x08 initial_max_streams_bidi = 7
    pos += varint.encode(buf[pos..], 0x08);
    pos += varint.encode(buf[pos..], 1);
    pos += varint.encode(buf[pos..], 7);

    const decoded = try decode(buf[0..pos]);
    // Known params are decoded correctly.
    try testing.expectEqual(@as(u64, 999), decoded.initial_max_data);
    try testing.expectEqual(@as(u64, 7), decoded.initial_max_streams_bidi);
    // Unknown param did not corrupt state.
    try testing.expect(decoded.stateless_reset_token == null);
}

test "transport_params: disable_active_migration encoded as empty value" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    const params = TransportParams{ .disable_active_migration = true };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);
    try testing.expect(decoded.disable_active_migration);

    const params_off = TransportParams{ .disable_active_migration = false };
    const n_off = encode(params_off, &buf);
    const decoded_off = try decode(buf[0..n_off]);
    try testing.expect(!decoded_off.disable_active_migration);
}

test "transport_params: duplicate param ID returns error" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Encode TP_INITIAL_MAX_DATA (0x04) twice — second occurrence is a violation.
    pos += varint.encode(buf[pos..], 0x04);
    pos += varint.encode(buf[pos..], 2);
    pos += varint.encode(buf[pos..], 1000);

    pos += varint.encode(buf[pos..], 0x04); // duplicate
    pos += varint.encode(buf[pos..], 2);
    pos += varint.encode(buf[pos..], 2000);

    try testing.expectError(error.DuplicateParam, decode(buf[0..pos]));
}

test "transport_params: unknown IDs are not subject to duplicate check" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Two unknown params with the same ID — silently skipped (no error)
    pos += varint.encode(buf[pos..], 0x55);
    pos += varint.encode(buf[pos..], 1);
    buf[pos] = 0xaa;
    pos += 1;

    pos += varint.encode(buf[pos..], 0x55); // duplicate unknown ID: allowed
    pos += varint.encode(buf[pos..], 1);
    buf[pos] = 0xbb;
    pos += 1;

    const decoded = try decode(buf[0..pos]);
    // Defaults should remain
    const defaults = TransportParams{};
    try testing.expectEqual(defaults.initial_max_data, decoded.initial_max_data);
}

test "transport_params: ack_delay_exponent > 20 returns error" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_ACK_DELAY_EXPONENT);
    pos += varint.encode(buf[pos..], 1); // length
    pos += varint.encode(buf[pos..], 21); // value 21 > max 20
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: active_connection_id_limit < 2 returns error" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_ACTIVE_CONNECTION_ID_LIMIT);
    pos += varint.encode(buf[pos..], 1); // length
    pos += varint.encode(buf[pos..], 1); // value 1 < min 2
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: max_udp_payload_size < 1200 returns error" {
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_UDP_PAYLOAD_SIZE);
    pos += varint.encode(buf[pos..], 2); // length
    pos += varint.encode(buf[pos..], 1199); // value < 1200
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: more than 64 params returns error" {
    const testing = std.testing;
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    // Write 65 unknown params
    var i: usize = 0;
    while (i < 65) : (i += 1) {
        pos += varint.encode(buf[pos..], 0x55 + @as(u62, @intCast(i)) * 2); // unique unknown IDs
        pos += varint.encode(buf[pos..], 0); // zero-length value
    }
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: max_ack_delay exactly 16383 is accepted" {
    // 16383 = (1<<14) - 1: the largest valid value (< 16384)
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_ACK_DELAY);
    pos += varint.encode(buf[pos..], 2); // 2-byte varint length
    pos += varint.encode(buf[pos..], 16383);
    const decoded = try decode(buf[0..pos]);
    try testing.expectEqual(@as(u64, 16383), decoded.max_ack_delay_ms);
}

test "transport_params: max_ack_delay 16384 returns error" {
    // 16384 = 1<<14: violates RFC 9000 §18.2 (must be < 2^14)
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_ACK_DELAY);
    pos += varint.encode(buf[pos..], 2);
    pos += varint.encode(buf[pos..], 16384);
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: max_udp_payload_size exactly 1200 is accepted" {
    // 1200 is the minimum allowed value (>= 1200)
    const testing = std.testing;
    var buf: [16]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_UDP_PAYLOAD_SIZE);
    pos += varint.encode(buf[pos..], 2);
    pos += varint.encode(buf[pos..], 1200);
    const decoded = try decode(buf[0..pos]);
    try testing.expectEqual(@as(u64, 1200), decoded.max_udp_payload_size);
}

test "transport_params: exactly 64 params is accepted" {
    // 64 params is at the limit; 65 is rejected (tested elsewhere)
    const testing = std.testing;
    var buf: [1024]u8 = undefined;
    var pos: usize = 0;
    var i: usize = 0;
    while (i < 64) : (i += 1) {
        pos += varint.encode(buf[pos..], 0x55 + @as(u62, @intCast(i)) * 2);
        pos += varint.encode(buf[pos..], 0); // zero-length unknown param
    }
    // Must not error — 64 is exactly at the limit; unknown params leave known defaults intact.
    const params = try decode(buf[0..pos]);
    const defaults: TransportParams = .{};
    try testing.expectEqual(defaults.initial_max_data, params.initial_max_data);
}

test "transport_params: initial_source_connection_id round-trip" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    var isci: [20]u8 = undefined;
    @memset(&isci, 0xcc);
    const params = TransportParams{
        .initial_source_connection_id = isci,
        .initial_source_connection_id_len = 8,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.initial_source_connection_id != null);
    try testing.expectEqual(@as(u8, 8), decoded.initial_source_connection_id_len);
    try testing.expectEqualSlices(u8, isci[0..8], decoded.initial_source_connection_id.?[0..8]);
}

test "transport_params: max_idle_timeout exceeding ns overflow limit returns error" {
    // Values > 18_446_744_073_709 ms would overflow u64 when converted to nanoseconds.
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_IDLE_TIMEOUT);
    // 18_446_744_073_710 fits in u62 (< 2^62-1) but would overflow u64 in ns conversion.
    const overflow_ms: u62 = 18_446_744_073_710;
    const vlen: u62 = @intCast(varint.encodedLen(overflow_ms));
    pos += varint.encode(buf[pos..], vlen);
    pos += varint.encode(buf[pos..], overflow_ms);
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: max_idle_timeout within safe limit is accepted" {
    const testing = std.testing;
    var buf: [32]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_MAX_IDLE_TIMEOUT);
    const safe_val: u62 = 3_600_000; // 1 hour in ms, well within the overflow limit
    const vlen: u62 = @intCast(varint.encodedLen(safe_val));
    pos += varint.encode(buf[pos..], vlen);
    pos += varint.encode(buf[pos..], safe_val);
    const decoded = try decode(buf[0..pos]);
    try testing.expectEqual(@as(u64, 3_600_000), decoded.max_idle_timeout_ms);
}

test "transport_params: original_destination_connection_id round-trip" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    // Use an 8-byte ODCID (common case)
    const odcid_bytes = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var odcid_raw: [20]u8 = [_]u8{0} ** 20;
    @memcpy(odcid_raw[0..8], &odcid_bytes);
    const params = TransportParams{
        .original_destination_connection_id = odcid_raw,
        .original_destination_connection_id_len = 8,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expectEqual(@as(u8, 8), decoded.original_destination_connection_id_len);
    try testing.expectEqualSlices(u8, &odcid_bytes, decoded.original_destination_connection_id.?[0..8]);
}

test "transport_params: retry_source_connection_id round-trip" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const params = TransportParams{
        .retry_source_connection_id = scid,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.retry_source_connection_id != null);
    try testing.expect(ConnectionId.eql(scid, decoded.retry_source_connection_id.?));
}

test "transport_params: both retry params encode/decode together" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    const odcid_bytes = [8]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    var odcid_raw: [20]u8 = [_]u8{0} ** 20;
    @memcpy(odcid_raw[0..8], &odcid_bytes);
    const scid = ConnectionId{ .bytes = .{ 9, 10, 11, 12, 13, 14, 15, 16 } };
    const params = TransportParams{
        .original_destination_connection_id = odcid_raw,
        .original_destination_connection_id_len = 8,
        .retry_source_connection_id = scid,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.original_destination_connection_id != null);
    try testing.expect(decoded.retry_source_connection_id != null);
    try testing.expectEqualSlices(u8, &odcid_bytes, decoded.original_destination_connection_id.?[0..8]);
    try testing.expect(ConnectionId.eql(scid, decoded.retry_source_connection_id.?));
}

test "transport_params: original_destination_connection_id with length > 20 returns error" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_ORIGINAL_DESTINATION_CONNECTION_ID);
    pos += varint.encode(buf[pos..], 21); // invalid: RFC max is 20 bytes
    @memset(buf[pos..][0..21], 0xaa);
    pos += 21;
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: version_information round-trip" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    // Version information: two versions (8 bytes total)
    var vi: [20]u8 = undefined;
    vi[0] = 0x00;
    vi[1] = 0x00;
    vi[2] = 0x00;
    vi[3] = 0x01; // QUIC v1 (0x00000001)
    vi[4] = 0x6b;
    vi[5] = 0x33;
    vi[6] = 0x43;
    vi[7] = 0x50; // QUIC v2 (0x6b3343c0)
    const params = TransportParams{
        .version_information = vi,
        .version_information_len = 8,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.version_information != null);
    try testing.expectEqual(@as(u8, 8), decoded.version_information_len);
    try testing.expectEqualSlices(u8, vi[0..8], decoded.version_information.?[0..8]);
}

test "transport_params: version_information with invalid length (not multiple of 4) returns error" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_VERSION_INFORMATION);
    pos += varint.encode(buf[pos..], 5); // invalid: not multiple of 4
    @memset(buf[pos..][0..5], 0xaa);
    pos += 5;
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: version_information with length > 20 returns error" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += varint.encode(buf[pos..], TP_VERSION_INFORMATION);
    pos += varint.encode(buf[pos..], 24); // invalid: > 20 bytes (6 versions)
    @memset(buf[pos..][0..24], 0xaa);
    pos += 24;
    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: preferred_address round-trip with 8-byte CID" {
    const testing = std.testing;

    const original = TransportParams{
        .max_idle_timeout_ms = 30_000,
        .preferred_address = PreferredAddress{
            .ipv4_addr = [_]u8{ 192, 168, 1, 100 },
            .ipv4_port = 443,
            .ipv6_addr = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
            .ipv6_port = 8443,
            .cid = [_]u8{ 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22 } ++ [_]u8{0} ** 12,
            .cid_len = 8,
            .reset_token = [_]u8{0x55} ** 16,
        },
    };

    var buf: [512]u8 = undefined;
    const n = encode(original, &buf);

    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.preferred_address != null);
    const pa = decoded.preferred_address.?;
    try testing.expectEqualSlices(u8, &original.preferred_address.?.ipv4_addr, &pa.ipv4_addr);
    try testing.expectEqual(original.preferred_address.?.ipv4_port, pa.ipv4_port);
    try testing.expectEqualSlices(u8, &original.preferred_address.?.ipv6_addr, &pa.ipv6_addr);
    try testing.expectEqual(original.preferred_address.?.ipv6_port, pa.ipv6_port);
    try testing.expectEqual(original.preferred_address.?.cid_len, pa.cid_len);
    try testing.expectEqualSlices(u8, original.preferred_address.?.cid[0..pa.cid_len], pa.cid[0..pa.cid_len]);
    try testing.expectEqualSlices(u8, &original.preferred_address.?.reset_token, &pa.reset_token);
}

test "transport_params: preferred_address with maximum 20-byte CID" {
    const testing = std.testing;

    const original = TransportParams{
        .preferred_address = PreferredAddress{
            .ipv4_addr = [_]u8{ 10, 0, 0, 1 },
            .ipv4_port = 1234,
            .ipv6_addr = [_]u8{0xfe} ++ [_]u8{0x80} ++ [_]u8{0} ** 6 ++ [_]u8{1} ** 8,
            .ipv6_port = 5678,
            .cid = [_]u8{0x12} ** 20,
            .cid_len = 20,
            .reset_token = [_]u8{0x77} ** 16,
        },
    };

    var buf: [512]u8 = undefined;
    const n = encode(original, &buf);

    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.preferred_address != null);
    const pa = decoded.preferred_address.?;
    try testing.expectEqual(20, pa.cid_len);
    try testing.expectEqualSlices(u8, original.preferred_address.?.cid[0..20], pa.cid[0..20]);
}

test "transport_params: preferred_address with zero-length CID" {
    const testing = std.testing;

    const original = TransportParams{
        .preferred_address = PreferredAddress{
            .ipv4_addr = [_]u8{ 127, 0, 0, 1 },
            .ipv4_port = 9999,
            .ipv6_addr = [_]u8{0} ** 16,
            .ipv6_port = 9998,
            .cid = [_]u8{0} ** 20,
            .cid_len = 0, // empty CID
            .reset_token = [_]u8{0xaa} ** 16,
        },
    };

    var buf: [512]u8 = undefined;
    const n = encode(original, &buf);

    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.preferred_address != null);
    const pa = decoded.preferred_address.?;
    try testing.expectEqual(0, pa.cid_len);
}

test "transport_params: preferred_address with invalid CID length > 20 returns error" {
    const testing = std.testing;
    var buf: [128]u8 = undefined;
    var pos: usize = 0;

    // Manually encode preferred_address with invalid CID length
    pos += varint.encode(buf[pos..], TP_PREFERRED_ADDRESS);
    const pa_len = 4 + 2 + 16 + 2 + 1 + 21 + 16; // CID length field says 21 (invalid)
    pos += varint.encode(buf[pos..], pa_len);

    // IPv4 address
    @memcpy(buf[pos..][0..4], &[_]u8{ 192, 168, 1, 1 });
    pos += 4;
    // IPv4 port
    buf[pos] = 0x01;
    buf[pos + 1] = 0xbb;
    pos += 2;
    // IPv6 address
    @memset(buf[pos..][0..16], 0);
    pos += 16;
    // IPv6 port
    buf[pos] = 0x27;
    buf[pos + 1] = 0x0e;
    pos += 2;
    // CID length (invalid: 21)
    buf[pos] = 21;
    pos += 1;
    // CID data (21 bytes)
    @memset(buf[pos..][0..21], 0xcc);
    pos += 21;
    // Reset token
    @memset(buf[pos..][0..16], 0xdd);
    pos += 16;

    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}

test "transport_params: preferred_address with invalid length returns error" {
    const testing = std.testing;
    var buf: [64]u8 = undefined;
    var pos: usize = 0;

    // Encode preferred_address with length < 41 (minimum)
    pos += varint.encode(buf[pos..], TP_PREFERRED_ADDRESS);
    pos += varint.encode(buf[pos..], 40); // Too short: 40 instead of 41
    @memset(buf[pos..][0..40], 0xaa);
    pos += 40;

    try testing.expectError(error.InvalidParams, decode(buf[0..pos]));
}
