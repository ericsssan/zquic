// QPACK encoder — RFC 9204, static table + optional dynamic table.
//
// Field line representations used:
//   §4.5.2  Indexed Field Line          — exact name+value in static or dynamic table
//   §4.5.4  Literal with Name Reference — name in static or dynamic table, literal value
//   §4.5.6  Literal with Literal Name   — name not in either table
//
// When dyn is null, the header block prefix always has RIC=0 (static-only).
// When dyn is provided, dynamic table entries are referenced where beneficial.

const std = @import("std");
const static_table = @import("static_table.zig");
const int = @import("int.zig");
const huffman = @import("huffman.zig");
const string = @import("string.zig");
const DynamicTable = @import("dynamic_table.zig").DynamicTable;
pub const Field = @import("types.zig").Field;

/// Maximum field lines handled in a single header block.
const MAX_FIELDS = 64;

/// Encodes `fields` into a QPACK header block written to `buf`.
/// `dyn` is the optional dynamic table to use for additional compression.
/// Returns the number of bytes written.
pub fn encode(
    fields: []const Field,
    buf: []u8,
    dyn: ?*const DynamicTable,
) error{BufferTooSmall}!usize {
    if (fields.len > MAX_FIELDS) return error.BufferTooSmall;

    // Pass 1: determine representation for each field, track max dynamic index.
    const Rep = union(enum) {
        indexed_static: u7,
        indexed_dynamic: u64,
        name_ref_static: struct { idx: u7, value: []const u8 },
        name_ref_dynamic: struct { abs: u64, value: []const u8 },
        literal_name: Field,
    };

    var reps: [MAX_FIELDS]Rep = undefined;
    var max_dyn_abs: ?u64 = null;

    for (fields, 0..) |field, i| {
        reps[i] = blk: {
            if (static_table.findExact(field.name, field.value)) |idx| {
                break :blk Rep{ .indexed_static = idx };
            }
            if (dyn) |d| {
                if (d.findExact(field.name, field.value)) |abs| {
                    if (max_dyn_abs == null or abs > max_dyn_abs.?) max_dyn_abs = abs;
                    break :blk Rep{ .indexed_dynamic = abs };
                }
            }
            if (static_table.findName(field.name)) |idx| {
                break :blk Rep{ .name_ref_static = .{ .idx = idx, .value = field.value } };
            }
            if (dyn) |d| {
                if (d.findName(field.name)) |abs| {
                    if (max_dyn_abs == null or abs > max_dyn_abs.?) max_dyn_abs = abs;
                    break :blk Rep{ .name_ref_dynamic = .{ .abs = abs, .value = field.value } };
                }
            }
            break :blk Rep{ .literal_name = field };
        };
    }

    // Compute RIC, base and delta_base.
    // base = insert_count (we always use the current insert count as base,
    // so all relative indices are non-negative).
    const insert_count: u64 = if (dyn) |d| d.insert_count else 0;
    const ric: u64 = if (max_dyn_abs) |abs| abs + 1 else 0;
    const delta_base: u64 = insert_count - ric; // S=0, always ≥ 0

    // Encode RIC using the wraparound encoding (RFC 9204 §4.5.1).
    const encoded_ric: u64 = if (ric == 0) 0 else blk: {
        const max_entries: u64 = if (dyn) |d| @as(u64, d.max_capacity) / 32 else 0;
        const full_range = if (max_entries > 0) 2 * max_entries else 256; // fallback
        break :blk (ric - 1) % full_range + 1;
    };

    // Encode prefix into a small temp buffer (≤ 8 bytes is always sufficient).
    var prefix: [8]u8 = undefined;
    var p_pos: usize = 0;
    p_pos += try int.encode(prefix[p_pos..], 8, encoded_ric);
    p_pos += try int.encode(prefix[p_pos..], 7, delta_base);
    // S bit = 0 → bit7 of the second prefix byte is already 0.

    if (buf.len < p_pos) return error.BufferTooSmall;
    @memcpy(buf[0..p_pos], prefix[0..p_pos]);
    var pos: usize = p_pos;

    // Pass 2: encode each field line.
    for (fields, 0..) |_, i| {
        pos += try encodeRep(reps[i], insert_count, buf[pos..]);
    }

    return pos;
}

fn encodeRep(
    rep: anytype, // Rep union
    insert_count: u64,
    buf: []u8,
) error{BufferTooSmall}!usize {
    return switch (rep) {
        .indexed_static => |idx| {
            // §4.5.2  1 T=1 [6-bit static index]
            const n = try int.encode(buf, 6, idx);
            buf[0] |= 0b1100_0000;
            return n;
        },
        .indexed_dynamic => |abs| {
            // §4.5.2  1 T=0 [6-bit relative index]
            // relative = (base - 1) - abs = insert_count - 1 - abs
            const relative = insert_count - 1 - abs;
            const n = try int.encode(buf, 6, relative);
            buf[0] |= 0b1000_0000; // bit7=1, bit6=T=0
            return n;
        },
        .name_ref_static => |r| {
            // §4.5.4  0 1 N=0 T=1 [4-bit static index] + value
            var p: usize = 0;
            const n = try int.encode(buf[p..], 4, r.idx);
            buf[p] |= 0b0101_0000;
            p += n;
            p += try string.encode(r.value, buf[p..]);
            return p;
        },
        .name_ref_dynamic => |r| {
            // §4.5.4  0 1 N=0 T=0 [4-bit relative index] + value
            const relative = insert_count - 1 - r.abs;
            var p: usize = 0;
            const n = try int.encode(buf[p..], 4, relative);
            buf[p] |= 0b0100_0000; // bit7=0, bit6=1, bit5=N=0, bit4=T=0
            p += n;
            p += try string.encode(r.value, buf[p..]);
            return p;
        },
        .literal_name => |f| encodeLiteralName(f, buf),
    };
}

fn encodeLiteralName(field: Field, buf: []u8) error{BufferTooSmall}!usize {
    var pos: usize = 0;

    const name_huff_len = huffman.encodedLen(field.name);
    const use_name_huff = name_huff_len < field.name.len;
    const name_data_len: u64 = if (use_name_huff) name_huff_len else field.name.len;

    // §4.5.6  0 0 1 N=0 H [3-bit name length prefix]
    const name_hdr_written = try int.encode(buf[pos..], 3, name_data_len);
    buf[pos] |= 0b0010_0000;
    if (use_name_huff) buf[pos] |= 0b0000_1000;
    pos += name_hdr_written;

    const name_end = pos + @as(usize, @intCast(name_data_len));
    if (buf.len < name_end) return error.BufferTooSmall;
    if (use_name_huff) {
        _ = try huffman.encode(field.name, buf[pos..name_end]);
    } else {
        @memcpy(buf[pos..name_end], field.name);
    }
    pos = name_end;

    pos += try string.encode(field.value, buf[pos..]);
    return pos;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "encode: indexed field line (exact static match)" {
    // :method GET is static index 17 → [0x00, 0x00, 0xd1]
    var buf: [32]u8 = undefined;
    const n = try encode(&.{.{ .name = ":method", .value = "GET" }}, &buf, null);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);
    try std.testing.expectEqual(@as(u8, 0xd1), buf[2]);
}

test "encode: indexed at index > 62 (multi-byte integer)" {
    // :status 500 = static index 71 → first byte 0xff, second 0x08
    var buf: [32]u8 = undefined;
    const n = try encode(&.{.{ .name = ":status", .value = "500" }}, &buf, null);
    try std.testing.expectEqual(@as(usize, 4), n);
    try std.testing.expectEqual(@as(u8, 0xff), buf[2]);
    try std.testing.expectEqual(@as(u8, 0x08), buf[3]);
}

test "encode: literal with static name reference" {
    var buf: [64]u8 = undefined;
    const n = try encode(&.{.{ .name = ":path", .value = "/hello" }}, &buf, null);
    try std.testing.expect(n > 3);
    try std.testing.expectEqual(@as(u8, 0x51), buf[2]); // NameRef T=1, idx=1
}

test "encode: literal with literal name" {
    var buf: [128]u8 = undefined;
    const n = try encode(&.{.{ .name = "x-custom-header", .value = "foo" }}, &buf, null);
    try std.testing.expect(n > 2);
    try std.testing.expectEqual(@as(u8, 0b001), (buf[2] >> 5) & 0b111);
}

test "encode: multiple fields (static only)" {
    const fields = [_]Field{
        .{ .name = ":method", .value = "GET" },
        .{ .name = ":scheme", .value = "https" },
        .{ .name = ":path", .value = "/" },
        .{ .name = ":authority", .value = "example.com" },
    };
    var buf: [128]u8 = undefined;
    const n = try encode(&fields, &buf, null);
    try std.testing.expect(n > 4);
    try std.testing.expectEqual(@as(u8, 0x00), buf[0]);
    try std.testing.expectEqual(@as(u8, 0x00), buf[1]);
}

test "encode: buffer too small" {
    var buf: [1]u8 = undefined;
    try std.testing.expectError(
        error.BufferTooSmall,
        encode(&.{.{ .name = ":method", .value = "GET" }}, &buf, null),
    );
}

test "encode: dynamic table exact match produces RIC > 0" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var dyn = DynamicTable.init(&data, &slots, 512);
    try dyn.insert("x-custom", "value1");

    var buf: [128]u8 = undefined;
    const n = try encode(
        &.{.{ .name = "x-custom", .value = "value1" }},
        &buf,
        &dyn,
    );
    // RIC = 1 → encoded_ric = 1 → buf[0] = 0x01
    try std.testing.expect(n >= 3);
    try std.testing.expectEqual(@as(u8, 0x01), buf[0]); // encoded RIC = 1
    // First field byte: 1 T=0 [6-bit relative=0] = 0b1000_0000 = 0x80
    try std.testing.expectEqual(@as(u8, 0x80), buf[2]);
}

test "encode: dynamic table name reference" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var dyn = DynamicTable.init(&data, &slots, 512);
    try dyn.insert("x-custom", "value1");

    // Encode with same name but different value → name-ref to dynamic, literal value.
    var buf: [128]u8 = undefined;
    const n = try encode(
        &.{.{ .name = "x-custom", .value = "value2" }},
        &buf,
        &dyn,
    );
    try std.testing.expect(n >= 3);
    // First field byte: 0 1 N=0 T=0 [4-bit relative=0] = 0b0100_0000 = 0x40
    try std.testing.expectEqual(@as(u8, 0x40), buf[2]);
}
