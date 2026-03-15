// QPACK encoder stream — RFC 9204 §4.3
//
// Processes encoder stream instructions sent by the peer's QPACK encoder,
// updating the local (decoder-side) copy of the dynamic table.
//
// Instruction formats (first byte determines type):
//   §4.3.1  Insert With Name Reference  — bit7=1:  1 T [6-bit index] + value
//   §4.3.2  Insert With Literal Name    — bit7=0, bit6=1:  01 H [5-bit len] + name + value
//   §4.3.3  Set Dynamic Table Capacity  — bit7=0, bit6=0, bit5=1:  001 [5-bit capacity]

const std = @import("std");
const static_table = @import("static_table.zig");
const int = @import("int.zig");
const huffman = @import("huffman.zig");
const string = @import("string.zig");
const DynamicTable = @import("dynamic_table.zig").DynamicTable;

pub const Error = error{
    /// Input is truncated.
    Incomplete,
    /// Integer overflow in a length or index field.
    Overflow,
    /// Invalid Huffman code.
    InvalidCode,
    /// EOS symbol in a string value.
    EosInValue,
    /// Scratch buffer too small for Huffman-decoded strings.
    BufferTooSmall,
    /// Name reference index out of range.
    InvalidIndex,
    /// Dynamic table operation failed (entry too large or capacity exceeded).
    TableError,
};

/// Process one encoder stream instruction from `buf`.
///
/// `table`   – the decoder's copy of the dynamic table to update.
/// `scratch` – temporary buffer for Huffman-decoded name/value strings
///             during insertion (must be ≥ table.capacity bytes).
///
/// Returns the number of bytes consumed from `buf`.
pub fn processInstruction(
    buf: []const u8,
    table: *DynamicTable,
    scratch: []u8,
) Error!usize {
    if (buf.len == 0) return error.Incomplete;

    if ((buf[0] & 0x80) != 0) {
        return insertWithNameRef(buf, table, scratch);
    } else if ((buf[0] & 0x40) != 0) {
        return insertWithLiteralName(buf, table, scratch);
    } else {
        return setCapacity(buf, table);
    }
}

// §4.3.1  Insert With Name Reference
//   1 T [6-bit name index] + value string (8-bit prefix)
//   T=1: static table name  T=0: dynamic table name (relative index)
fn insertWithNameRef(buf: []const u8, table: *DynamicTable, scratch: []u8) Error!usize {
    const t_bit = (buf[0] >> 6) & 1;
    const name_idx = try int.decode(buf, 6);
    var pos = name_idx.consumed;

    const name: []const u8 = if (t_bit == 1) blk: {
        const entry = static_table.get(@intCast(name_idx.value)) orelse
            return error.InvalidIndex;
        break :blk entry.name;
    } else blk: {
        // Relative index into current dynamic table (0 = most recent).
        if (name_idx.value >= table.insert_count) return error.InvalidIndex;
        const abs = table.insert_count - 1 - name_idx.value;
        const entry = table.get(abs) orelse return error.InvalidIndex;
        break :blk entry.name;
    };

    if (pos >= buf.len) return error.Incomplete;
    const val = try string.decode(buf[pos..], scratch);
    pos += val.consumed;

    table.insert(name, val.value) catch return error.TableError;
    return pos;
}

// §4.3.2  Insert With Literal Name
//   01 H [5-bit name length] + name bytes + value string (8-bit prefix)
//   H=1: name is Huffman-encoded
fn insertWithLiteralName(buf: []const u8, table: *DynamicTable, scratch: []u8) Error!usize {
    const h_bit = (buf[0] >> 5) & 1;
    const name_len_r = try int.decode(buf, 5);
    var pos = name_len_r.consumed;

    const name_raw_len = @as(usize, @intCast(name_len_r.value));
    if (pos + name_raw_len > buf.len) return error.Incomplete;
    const name_raw = buf[pos .. pos + name_raw_len];
    pos += name_raw_len;

    var str_pos: usize = 0;
    const name: []const u8 = if (h_bit == 1) blk: {
        const n = try huffman.decode(name_raw, scratch[str_pos..]);
        const s = scratch[str_pos .. str_pos + n];
        str_pos += n;
        break :blk s;
    } else name_raw;

    if (pos >= buf.len) return error.Incomplete;
    const val = try string.decode(buf[pos..], scratch[str_pos..]);
    pos += val.consumed;

    table.insert(name, val.value) catch return error.TableError;
    return pos;
}

// §4.3.3  Set Dynamic Table Capacity
//   001 [5-bit capacity]
fn setCapacity(buf: []const u8, table: *DynamicTable) Error!usize {
    if ((buf[0] & 0x20) == 0) return error.Incomplete; // not 001xxxxx → malformed
    const cap = try int.decode(buf, 5);
    table.setCapacity(@intCast(cap.value)) catch return error.TableError;
    return cap.consumed;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "processInstruction: set capacity" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);
    var scratch: [512]u8 = undefined;

    // 001 [5-bit 256] → 0b0010_0000 | (256 encoded)
    // 256 >= 31 → first byte = 0x3f (001 11111), then 256-31 = 225 = 0xe1
    const buf = [_]u8{ 0x3f, 0xe1, 0x01 };
    const consumed = try processInstruction(&buf, &t, &scratch);
    try std.testing.expectEqual(@as(usize, 3), consumed);
    try std.testing.expectEqual(@as(usize, 256), t.capacity);
}

test "processInstruction: insert with static name reference" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);
    var scratch: [512]u8 = undefined;

    // §4.3.1  T=1, name index=1 (:path), value "/"
    // First byte: 1 1 [6-bit 1] = 0b1100_0001 = 0xc1
    // Value: not Huffman, length=1, byte='/' = 0x01 0x2f
    const buf = [_]u8{ 0xc1, 0x01, 0x2f };
    const consumed = try processInstruction(&buf, &t, &scratch);
    try std.testing.expectEqual(@as(usize, 3), consumed);
    try std.testing.expectEqual(@as(u64, 1), t.insert_count);
    const e = t.get(0).?;
    try std.testing.expectEqualStrings(":path", e.name);
    try std.testing.expectEqualStrings("/", e.value);
}

test "processInstruction: insert with literal name" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);
    var scratch: [512]u8 = undefined;

    // §4.3.2  H=0, name="x-foo" (5 bytes), value="bar" (3 bytes)
    // First byte: 01 0 [5-bit 5] = 0b0100_0101 = 0x45
    // name bytes: 'x' 'f' 'o' 'o'... wait, "x-foo" = 5 bytes
    // Value: not Huffman, length=3 = 0x03 0x62 0x61 0x72
    const buf = [_]u8{
        0x45, // 01 H=0 len=5
        'x', '-', 'f', 'o', 'o',
        0x03, 'b', 'a', 'r',
    };
    const consumed = try processInstruction(&buf, &t, &scratch);
    try std.testing.expectEqual(@as(usize, buf.len), consumed);
    try std.testing.expectEqual(@as(u64, 1), t.insert_count);
    const e = t.get(0).?;
    try std.testing.expectEqualStrings("x-foo", e.name);
    try std.testing.expectEqualStrings("bar", e.value);
}

test "processInstruction: insert with dynamic name reference" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);
    var scratch: [512]u8 = undefined;

    // First insert "my-header: first" manually
    try t.insert("my-header", "first");

    // Now insert with dynamic name reference (T=0, relative index=0 = "my-header")
    // value = "second"
    // First byte: 1 0 [6-bit 0] = 0b1000_0000 = 0x80
    // Value: not Huffman, length=6
    const buf = [_]u8{ 0x80, 0x06, 's', 'e', 'c', 'o', 'n', 'd' };
    const consumed = try processInstruction(&buf, &t, &scratch);
    try std.testing.expectEqual(@as(usize, buf.len), consumed);
    try std.testing.expectEqual(@as(u64, 2), t.insert_count);
    const e = t.get(1).?;
    try std.testing.expectEqualStrings("my-header", e.name);
    try std.testing.expectEqualStrings("second", e.value);
}
