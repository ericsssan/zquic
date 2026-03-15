// QPACK decoder — RFC 9204, static table + optional dynamic table.
//
// Accepts header blocks with any Required Insert Count and Base.
//
// Field line representations handled:
//   §4.5.2  Indexed Field Line                  (static T=1, dynamic T=0)
//   §4.5.3  Indexed Field Line (post-base)       (dynamic, post-base index)
//   §4.5.4  Literal with Name Reference          (static T=1, dynamic T=0)
//   §4.5.5  Literal with Post-Base Name Ref      (dynamic, post-base index)
//   §4.5.6  Literal with Literal Name
//
// When dyn is null, any representation that references the dynamic table
// returns error.DynamicTableRequired.
//
// When dyn is provided and RIC > known_received_count, returns
// error.BlockedStream (caller must buffer and retry after insertions arrive).

const std = @import("std");
const static_table = @import("static_table.zig");
const int = @import("int.zig");
const huffman = @import("huffman.zig");
const string = @import("string.zig");
const DynamicTable = @import("dynamic_table.zig").DynamicTable;
pub const Field = @import("types.zig").Field;

pub const DecodeError = error{
    /// Header block references the dynamic table and dyn is null.
    DynamicTableRequired,
    /// RIC > known_received_count; the stream is blocked.
    BlockedStream,
    /// Malformed header block (invalid index, bad encoding, etc.).
    InvalidInput,
    /// Input is truncated.
    Incomplete,
    /// Integer overflow in a length or index field.
    Overflow,
    /// Invalid Huffman code.
    InvalidCode,
    /// EOS symbol appeared in a header string value.
    EosInValue,
    /// Output slice too small.
    BufferTooSmall,
};

/// Decodes a QPACK header block from `buf` into `out_fields`.
///
/// `strings` is a scratch buffer for Huffman-decoded string data.
/// `dyn` is the optional dynamic table; pass null for static-only decoding.
/// `known_received_count` is the decoder's current dynamic table insert count
/// (used to check whether the stream is blocked).
///
/// Returns the number of fields written to `out_fields`.
pub fn decode(
    buf: []const u8,
    out_fields: []Field,
    strings: []u8,
    dyn: ?*const DynamicTable,
    known_received_count: u64,
) DecodeError!usize {
    var pos: usize = 0;
    var str_pos: usize = 0;
    var field_count: usize = 0;

    // ---- Header block prefix (§4.5.1) ----------------------------------------

    // Required Insert Count (8-bit prefix integer).
    if (pos >= buf.len) return error.Incomplete;
    const ric_encoded = try int.decode(buf[pos..], 8);
    pos += ric_encoded.consumed;

    // S bit (bit7 of this byte) + Delta Base (7-bit prefix integer).
    if (pos >= buf.len) return error.Incomplete;
    const s_bit: u1 = @intCast((buf[pos] >> 7) & 1);
    const delta_base_r = try int.decode(buf[pos..], 7);
    pos += delta_base_r.consumed;

    // Decode the actual Required Insert Count.
    const actual_ric: u64 = if (ric_encoded.value == 0) 0 else blk: {
        if (dyn == null) return error.DynamicTableRequired;
        const d = dyn.?;
        const max_entries: u64 = @as(u64, d.max_capacity) / 32;
        if (max_entries == 0) return error.DynamicTableRequired;
        const full_range: u64 = 2 * max_entries;
        var r: u64 = (ric_encoded.value - 1) % full_range + 1;
        // Adjust r to be in (insert_count - full_range, insert_count].
        while (r + full_range <= d.insert_count) r += full_range;
        if (r > d.insert_count) return error.InvalidInput;
        break :blk r;
    };

    // Blocking check: if the decoder hasn't yet received all required insertions.
    if (actual_ric > known_received_count) return error.BlockedStream;

    // Compute base.
    const actual_base: u64 = if (s_bit == 0)
        actual_ric + delta_base_r.value
    else blk: {
        if (delta_base_r.value >= actual_ric) return error.InvalidInput;
        break :blk actual_ric - delta_base_r.value - 1;
    };

    // ---- Field lines ---------------------------------------------------------

    while (pos < buf.len) {
        if (field_count >= out_fields.len) return error.BufferTooSmall;
        const byte = buf[pos];

        if ((byte & 0x80) != 0) {
            // §4.5.2  Indexed Field Line: 1 T [6-bit index]
            const t_bit = (byte >> 6) & 1;
            if (t_bit == 0) {
                // Dynamic table: relative index.
                if (dyn == null) return error.DynamicTableRequired;
                const idx = try int.decode(buf[pos..], 6);
                pos += idx.consumed;
                const absolute = dynAbsolute(actual_base, idx.value, false) orelse
                    return error.InvalidInput;
                const entry = dyn.?.get(absolute) orelse return error.InvalidInput;
                out_fields[field_count] = .{ .name = entry.name, .value = entry.value };
            } else {
                // Static table.
                const idx = try int.decode(buf[pos..], 6);
                pos += idx.consumed;
                if (idx.value > 98) return error.InvalidInput;
                const entry = static_table.get(@intCast(idx.value)).?;
                out_fields[field_count] = .{ .name = entry.name, .value = entry.value };
            }
            field_count += 1;
        } else if ((byte & 0x40) != 0) {
            // §4.5.4  Literal Field Line with Name Reference: 0 1 N T [4-bit index]
            const t_bit = (byte >> 4) & 1;
            if (t_bit == 0) {
                // Dynamic table name reference.
                if (dyn == null) return error.DynamicTableRequired;
                const idx = try int.decode(buf[pos..], 4);
                pos += idx.consumed;
                const absolute = dynAbsolute(actual_base, idx.value, false) orelse
                    return error.InvalidInput;
                const entry = dyn.?.get(absolute) orelse return error.InvalidInput;

                const val = try string.decode(buf[pos..], strings[str_pos..]);
                pos += val.consumed;
                if (val.huffman_decoded) str_pos += val.value.len;

                out_fields[field_count] = .{ .name = entry.name, .value = val.value };
            } else {
                // Static table name reference.
                const idx = try int.decode(buf[pos..], 4);
                pos += idx.consumed;
                if (idx.value > 98) return error.InvalidInput;
                const entry = static_table.get(@intCast(idx.value)).?;

                const val = try string.decode(buf[pos..], strings[str_pos..]);
                pos += val.consumed;
                if (val.huffman_decoded) str_pos += val.value.len;

                out_fields[field_count] = .{ .name = entry.name, .value = val.value };
            }
            field_count += 1;
        } else if ((byte & 0x20) != 0) {
            // §4.5.6  Literal Field Line with Literal Name: 0 0 1 N H [3-bit name len]
            const name_is_huffman = (byte & 0x08) != 0;
            const name_len_r = try int.decode(buf[pos..], 3);
            pos += name_len_r.consumed;

            const name_len: usize = @intCast(name_len_r.value);
            if (pos + name_len > buf.len) return error.Incomplete;
            const name_raw = buf[pos .. pos + name_len];
            pos += name_len;

            const name: []const u8 = if (name_is_huffman) blk: {
                const n = try huffman.decode(name_raw, strings[str_pos..]);
                const s = strings[str_pos .. str_pos + n];
                str_pos += n;
                break :blk s;
            } else name_raw;

            const val = try string.decode(buf[pos..], strings[str_pos..]);
            pos += val.consumed;
            if (val.huffman_decoded) str_pos += val.value.len;

            out_fields[field_count] = .{ .name = name, .value = val.value };
            field_count += 1;
        } else if ((byte & 0x10) != 0) {
            // §4.5.3  Indexed Field Line with Post-Base Index: 0 0 0 1 [4-bit index]
            if (dyn == null) return error.DynamicTableRequired;
            const idx = try int.decode(buf[pos..], 4);
            pos += idx.consumed;
            const absolute = dynAbsolute(actual_base, idx.value, true) orelse
                return error.InvalidInput;
            const entry = dyn.?.get(absolute) orelse return error.InvalidInput;
            out_fields[field_count] = .{ .name = entry.name, .value = entry.value };
            field_count += 1;
        } else {
            // §4.5.5  Literal Field Line with Post-Base Name Reference: 0 0 0 0 N [3-bit index]
            if (dyn == null) return error.DynamicTableRequired;
            const idx = try int.decode(buf[pos..], 3);
            pos += idx.consumed;
            const absolute = dynAbsolute(actual_base, idx.value, true) orelse
                return error.InvalidInput;
            const entry = dyn.?.get(absolute) orelse return error.InvalidInput;

            const val = try string.decode(buf[pos..], strings[str_pos..]);
            pos += val.consumed;
            if (val.huffman_decoded) str_pos += val.value.len;

            out_fields[field_count] = .{ .name = entry.name, .value = val.value };
            field_count += 1;
        }
    }

    return field_count;
}

/// Convert a relative or post-base index to an absolute dynamic table index.
/// Returns null if the resulting index would underflow.
inline fn dynAbsolute(base: u64, idx: u64, post_base: bool) ?u64 {
    if (post_base) {
        return base +| idx;
    } else {
        // relative: absolute = base - 1 - idx
        if (idx + 1 > base) return null;
        return base - 1 - idx;
    }
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "decode: indexed field line (static)" {
    // [0x00, 0x00, 0xd1] → :method GET (static index 17)
    const buf = [_]u8{ 0x00, 0x00, 0xd1 };
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    const n = try decode(&buf, &fields, &strings, null, 0);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings(":method", fields[0].name);
    try std.testing.expectEqualStrings("GET", fields[0].value);
}

test "decode: indexed at index > 62 (multi-byte)" {
    // :status 500 = static index 71 → [0xff, 0x08] with T=1
    const buf = [_]u8{ 0x00, 0x00, 0xff, 0x08 };
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    const n = try decode(&buf, &fields, &strings, null, 0);
    try std.testing.expectEqual(@as(usize, 1), n);
    try std.testing.expectEqualStrings(":status", fields[0].name);
    try std.testing.expectEqualStrings("500", fields[0].value);
}

test "decode: dynamic table reference without table returns error" {
    // T=0 indexed (dynamic) with no dyn provided → DynamicTableRequired
    const buf = [_]u8{ 0x01, 0x00, 0x80 }; // RIC=1, base=0, indexed T=0 idx=0
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    try std.testing.expectError(
        error.DynamicTableRequired,
        decode(&buf, &fields, &strings, null, 0),
    );
}

test "decode: blocked stream" {
    // RIC=5, known_received_count=3 → BlockedStream
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var dyn = DynamicTable.init(&data, &slots, 512);
    // Insert 5 entries so RIC decoding succeeds.
    for (0..5) |i| {
        var n: [4]u8 = undefined;
        const name = std.fmt.bufPrint(&n, "h{d}", .{i}) catch unreachable;
        try dyn.insert(name, "v");
    }
    // encoded_ric = 5 (RIC=5, insert_count=5, full_range=2*(512/32)=32, (5-1)%32+1=5)
    const buf = [_]u8{ 0x05, 0x00 }; // RIC=5, base_delta=0, no field lines
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    try std.testing.expectError(
        error.BlockedStream,
        decode(&buf, &fields, &strings, &dyn, 3),
    );
}

test "decode: empty header block" {
    const buf = [_]u8{ 0x00, 0x00 };
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    const n = try decode(&buf, &fields, &strings, null, 0);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "decode: incomplete input" {
    const buf = [_]u8{0x00}; // only RIC byte, no Base byte
    var fields: [8]Field = undefined;
    var strings: [256]u8 = undefined;
    try std.testing.expectError(error.Incomplete, decode(&buf, &fields, &strings, null, 0));
}

test "encode/decode round-trip: static-only" {
    const encoder = @import("encoder.zig");

    const in_fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/hello" },
        .{ .name = ":authority", .value = "example.com" },
        .{ .name = "x-request-id", .value = "42" },
    };

    var enc_buf: [512]u8 = undefined;
    const enc_n = try encoder.encode(&in_fields, &enc_buf, null);

    var out_fields: [16]Field = undefined;
    var strings: [512]u8 = undefined;
    const dec_n = try decode(enc_buf[0..enc_n], &out_fields, &strings, null, 0);

    try std.testing.expectEqual(@as(usize, in_fields.len), dec_n);
    for (in_fields, out_fields[0..dec_n]) |expected, got| {
        try std.testing.expectEqualStrings(expected.name, got.name);
        try std.testing.expectEqualStrings(expected.value, got.value);
    }
}

test "round-trip: exact static table matches" {
    const encoder = @import("encoder.zig");
    const in_fields = [_]Field{
        .{ .name = ":method", .value = "POST" },
        .{ .name = ":status", .value = "200" },
        .{ .name = "cache-control", .value = "no-cache" },
        .{ .name = "content-encoding", .value = "gzip" },
    };

    var enc_buf: [256]u8 = undefined;
    const enc_n = try encoder.encode(&in_fields, &enc_buf, null);

    var out_fields: [16]Field = undefined;
    var strings: [256]u8 = undefined;
    const dec_n = try decode(enc_buf[0..enc_n], &out_fields, &strings, null, 0);

    try std.testing.expectEqual(@as(usize, in_fields.len), dec_n);
    for (in_fields, out_fields[0..dec_n]) |expected, got| {
        try std.testing.expectEqualStrings(expected.name, got.name);
        try std.testing.expectEqualStrings(expected.value, got.value);
    }
}

test "encode/decode round-trip: dynamic table entries" {
    const encoder = @import("encoder.zig");

    var data: [4096]u8 = undefined;
    var slots: [128]DynamicTable.Slot = undefined;
    var dyn = DynamicTable.init(&data, &slots, 4096);

    try dyn.insert("x-request-id", "abc-123");
    try dyn.insert("x-trace-id", "xyz-789");

    const in_fields = [_]Field{
        .{ .name = ":method", .value = "GET" },         // static indexed
        .{ .name = "x-request-id", .value = "abc-123" }, // dynamic indexed (exact)
        .{ .name = "x-trace-id", .value = "new-val" },   // dynamic name-ref
        .{ .name = "x-new", .value = "hello" },          // literal name
    };

    var enc_buf: [512]u8 = undefined;
    const enc_n = try encoder.encode(&in_fields, &enc_buf, &dyn);

    var out_fields: [16]Field = undefined;
    var strings: [512]u8 = undefined;
    const dec_n = try decode(enc_buf[0..enc_n], &out_fields, &strings, &dyn, dyn.insert_count);

    try std.testing.expectEqual(@as(usize, in_fields.len), dec_n);
    for (in_fields, out_fields[0..dec_n]) |expected, got| {
        try std.testing.expectEqualStrings(expected.name, got.name);
        try std.testing.expectEqualStrings(expected.value, got.value);
    }
}
