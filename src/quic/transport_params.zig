//! QUIC transport parameter encoding and decoding (RFC 9000 §18).
//!
//! Transport parameters are negotiated via the TLS handshake as a TLS extension
//! (type 0x0039).  Each parameter is TLV-encoded: (id: VarInt, length: VarInt, value).

const std = @import("std");
const varint = @import("varint.zig");

// ---------------------------------------------------------------------------
// Transport parameter IDs (RFC 9000 §18.2)
// ---------------------------------------------------------------------------

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
const TP_ACTIVE_CONNECTION_ID_LIMIT: u62 = 0x0e;
const TP_INITIAL_SOURCE_CONNECTION_ID: u62 = 0x0f;

// ---------------------------------------------------------------------------
// TransportParams
// ---------------------------------------------------------------------------

pub const TransportParams = struct {
    max_idle_timeout_ms:                 u64     = 30_000,
    max_udp_payload_size:                u64     = 65527,
    initial_max_data:                    u64     = 1024 * 1024,
    initial_max_stream_data_bidi_local:  u64     = 256 * 1024,
    initial_max_stream_data_bidi_remote: u64     = 256 * 1024,
    initial_max_stream_data_uni:         u64     = 256 * 1024,
    initial_max_streams_bidi:            u64     = 100,
    initial_max_streams_uni:             u64     = 100,
    ack_delay_exponent:                  u64     = 3,
    max_ack_delay_ms:                    u64     = 25,
    active_connection_id_limit:          u64     = 2,
    disable_active_migration:            bool    = false,
    stateless_reset_token:               ?[16]u8 = null,
    initial_source_connection_id:        ?[20]u8 = null,
    initial_source_connection_id_len:    u8      = 0,
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
    pos += writeVarintParam(buf[pos..], TP_MAX_IDLE_TIMEOUT,
        @intCast(params.max_idle_timeout_ms));
    pos += writeVarintParam(buf[pos..], TP_MAX_UDP_PAYLOAD_SIZE,
        @intCast(params.max_udp_payload_size));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_DATA,
        @intCast(params.initial_max_data));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
        @intCast(params.initial_max_stream_data_bidi_local));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE,
        @intCast(params.initial_max_stream_data_bidi_remote));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAM_DATA_UNI,
        @intCast(params.initial_max_stream_data_uni));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAMS_BIDI,
        @intCast(params.initial_max_streams_bidi));
    pos += writeVarintParam(buf[pos..], TP_INITIAL_MAX_STREAMS_UNI,
        @intCast(params.initial_max_streams_uni));
    pos += writeVarintParam(buf[pos..], TP_ACK_DELAY_EXPONENT,
        @intCast(params.ack_delay_exponent));
    pos += writeVarintParam(buf[pos..], TP_MAX_ACK_DELAY,
        @intCast(params.max_ack_delay_ms));
    pos += writeVarintParam(buf[pos..], TP_ACTIVE_CONNECTION_ID_LIMIT,
        @intCast(params.active_connection_id_limit));

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
    // Bitmask tracking which known parameter IDs (0x01..0x0f) have been seen.
    // bit i set ⟺ parameter with ID (i+1) was already decoded.
    var seen: u16 = 0;

    while (pos < buf.len) {
        const id_vi = varint.decode(buf[pos..]) orelse return error.InvalidParams;
        pos += id_vi.len;

        const len_vi = varint.decode(buf[pos..]) orelse return error.InvalidParams;
        pos += len_vi.len;

        const param_len: usize = @intCast(len_vi.value);
        if (pos + param_len > buf.len) return error.InvalidParams;

        const param_data = buf[pos..][0..param_len];

        // Check for duplicates among known IDs 0x01..0x0f
        if (id_vi.value >= 1 and id_vi.value <= 15) {
            const bit: u16 = @as(u16, 1) << @intCast(id_vi.value - 1);
            if (seen & bit != 0) return error.DuplicateParam;
            seen |= bit;
        }

        switch (id_vi.value) {
            TP_MAX_IDLE_TIMEOUT => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
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
                params.ack_delay_exponent = v.value;
            },
            TP_MAX_ACK_DELAY => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.max_ack_delay_ms = v.value;
            },
            TP_DISABLE_ACTIVE_MIGRATION => {
                params.disable_active_migration = true;
            },
            TP_ACTIVE_CONNECTION_ID_LIMIT => {
                const v = varint.decode(param_data) orelse return error.InvalidParams;
                params.active_connection_id_limit = v.value;
            },
            TP_INITIAL_SOURCE_CONNECTION_ID => {
                const copy_len: u8 = @intCast(@min(param_len, 20));
                var isci: [20]u8 = undefined;
                @memcpy(isci[0..copy_len], param_data[0..copy_len]);
                params.initial_source_connection_id = isci;
                params.initial_source_connection_id_len = copy_len;
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
        .max_idle_timeout_ms                 = 60_000,
        .max_udp_payload_size                = 1350,
        .initial_max_data                    = 2 * 1024 * 1024,
        .initial_max_stream_data_bidi_local  = 512 * 1024,
        .initial_max_stream_data_bidi_remote = 512 * 1024,
        .initial_max_stream_data_uni         = 128 * 1024,
        .initial_max_streams_bidi            = 200,
        .initial_max_streams_uni             = 50,
        .ack_delay_exponent                  = 5,
        .max_ack_delay_ms                    = 50,
        .active_connection_id_limit          = 8,
        .disable_active_migration            = true,
        .stateless_reset_token               = [_]u8{0xab} ** 16,
        .initial_source_connection_id        = null,
        .initial_source_connection_id_len    = 0,
    };

    var buf: [512]u8 = undefined;
    const n = encode(original, &buf);

    const decoded = try decode(buf[0..n]);

    try testing.expectEqual(original.max_idle_timeout_ms,                 decoded.max_idle_timeout_ms);
    try testing.expectEqual(original.max_udp_payload_size,                decoded.max_udp_payload_size);
    try testing.expectEqual(original.initial_max_data,                    decoded.initial_max_data);
    try testing.expectEqual(original.initial_max_stream_data_bidi_local,  decoded.initial_max_stream_data_bidi_local);
    try testing.expectEqual(original.initial_max_stream_data_bidi_remote, decoded.initial_max_stream_data_bidi_remote);
    try testing.expectEqual(original.initial_max_stream_data_uni,         decoded.initial_max_stream_data_uni);
    try testing.expectEqual(original.initial_max_streams_bidi,            decoded.initial_max_streams_bidi);
    try testing.expectEqual(original.initial_max_streams_uni,             decoded.initial_max_streams_uni);
    try testing.expectEqual(original.ack_delay_exponent,                  decoded.ack_delay_exponent);
    try testing.expectEqual(original.max_ack_delay_ms,                    decoded.max_ack_delay_ms);
    try testing.expectEqual(original.active_connection_id_limit,          decoded.active_connection_id_limit);
    try testing.expectEqual(original.disable_active_migration,            decoded.disable_active_migration);
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

    try testing.expectEqual(defaults.max_idle_timeout_ms,    decoded.max_idle_timeout_ms);
    try testing.expectEqual(defaults.initial_max_data,       decoded.initial_max_data);
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
    buf[pos] = 0xde; buf[pos+1] = 0xad; buf[pos+2] = 0xbe;
    pos += 3;

    // 0x08 initial_max_streams_bidi = 7
    pos += varint.encode(buf[pos..], 0x08);
    pos += varint.encode(buf[pos..], 1);
    pos += varint.encode(buf[pos..], 7);

    const decoded = try decode(buf[0..pos]);
    // Known params are decoded correctly.
    try testing.expectEqual(@as(u64, 999), decoded.initial_max_data);
    try testing.expectEqual(@as(u64, 7),   decoded.initial_max_streams_bidi);
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
    buf[pos] = 0xaa; pos += 1;

    pos += varint.encode(buf[pos..], 0x55); // duplicate unknown ID: allowed
    pos += varint.encode(buf[pos..], 1);
    buf[pos] = 0xbb; pos += 1;

    const decoded = try decode(buf[0..pos]);
    // Defaults should remain
    const defaults = TransportParams{};
    try testing.expectEqual(defaults.initial_max_data, decoded.initial_max_data);
}

test "transport_params: initial_source_connection_id round-trip" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;

    var isci: [20]u8 = undefined;
    @memset(&isci, 0xcc);
    const params = TransportParams{
        .initial_source_connection_id     = isci,
        .initial_source_connection_id_len = 8,
    };
    const n = encode(params, &buf);
    const decoded = try decode(buf[0..n]);

    try testing.expect(decoded.initial_source_connection_id != null);
    try testing.expectEqual(@as(u8, 8), decoded.initial_source_connection_id_len);
    try testing.expectEqualSlices(u8, isci[0..8], decoded.initial_source_connection_id.?[0..8]);
}
