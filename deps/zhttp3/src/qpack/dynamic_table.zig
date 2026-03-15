// QPACK dynamic table — RFC 9204 §3.2
//
// Maintains a bounded FIFO table of name/value header field entries.
// New entries are added at the "tail"; oldest entries are evicted from the
// "head" when the table would exceed its capacity.
//
// RFC 9204 §3.2.1 entry overhead: name.len + value.len + 32 bytes per entry.
//
// Storage is entirely pre-allocated:
//   data  — a flat byte buffer for name+value strings (compacting linear)
//   slots — a circular array of entry metadata
//
// Eviction compacts the string buffer in place (O(n) copy, n ≤ capacity bytes).
// This is acceptable for HTTP/3 workloads where capacity is ≤ a few KB.
//
// Absolute indexing: entry 0 = first entry ever inserted, irrespective of
// evictions. get() returns null for evicted or never-inserted indices.

const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

pub const Error = error{
    /// The entry alone exceeds the current table capacity.
    TableFull,
    /// new_capacity > max_capacity.
    InvalidCapacity,
};

/// QPACK dynamic table (RFC 9204 §3.2).
///
/// Caller allocates the backing storage:
///
///   var data:  [4096]u8              = undefined;
///   var slots: [128]DynamicTable.Slot = undefined;
///   var table = DynamicTable.init(&data, &slots, 4096);
///
/// Slices returned by get() are valid until the referenced entry is evicted.
pub const DynamicTable = struct {
    // String storage: densely packed from index 0, compacted on eviction.
    data: []u8,
    data_len: usize = 0,

    // Entry metadata: circular ring; slot_head = oldest active entry.
    slots: []Slot,
    slot_head: usize = 0,
    slot_count: usize = 0,

    // Table state.
    capacity: usize,      // current capacity limit (bytes)
    max_capacity: usize,  // max allowed (SETTINGS_QPACK_MAX_TABLE_CAPACITY)
    current_size: usize = 0,  // sum of (name_len + value_len + 32) per active entry
    insert_count: u64 = 0,    // total entries ever inserted (absolute index of next = this)

    pub const Slot = struct {
        name_offset: usize,
        name_len: usize,
        value_len: usize,
    };

    pub fn init(data: []u8, slots: []Slot, max_capacity: usize) DynamicTable {
        return .{
            .data = data,
            .slots = slots,
            .capacity = max_capacity,
            .max_capacity = max_capacity,
        };
    }

    /// Set the capacity limit. Evicts oldest entries until current_size ≤ new_capacity.
    pub fn setCapacity(self: *DynamicTable, new_capacity: usize) Error!void {
        if (new_capacity > self.max_capacity) return error.InvalidCapacity;
        self.capacity = new_capacity;
        while (self.current_size > self.capacity) self.evictOldest();
    }

    /// Insert a new entry, evicting oldest entries as needed to make room.
    /// Returns error.TableFull if entry_size > capacity (can never fit).
    pub fn insert(self: *DynamicTable, name: []const u8, value: []const u8) Error!void {
        const entry_size = name.len + value.len + 32;
        if (entry_size > self.capacity) return error.TableFull;
        if (self.slot_count >= self.slots.len) return error.TableFull;

        while (self.current_size + entry_size > self.capacity) self.evictOldest();

        const name_offset = self.data_len;
        @memcpy(self.data[name_offset..][0..name.len], name);
        @memcpy(self.data[name_offset + name.len..][0..value.len], value);
        self.data_len += name.len + value.len;

        const slot_idx = (self.slot_head + self.slot_count) % self.slots.len;
        self.slots[slot_idx] = .{
            .name_offset = name_offset,
            .name_len = name.len,
            .value_len = value.len,
        };
        self.slot_count += 1;
        self.current_size += entry_size;
        self.insert_count += 1;
    }

    /// Retrieve entry by absolute index (0 = first entry ever inserted).
    /// Returns null if the entry has been evicted or was never inserted.
    pub fn get(self: *const DynamicTable, absolute_index: u64) ?Entry {
        if (self.slot_count == 0) return null;
        const oldest = self.insert_count - @as(u64, self.slot_count);
        if (absolute_index < oldest or absolute_index >= self.insert_count) return null;

        const age = @as(usize, @intCast(absolute_index - oldest));
        const slot_idx = (self.slot_head + age) % self.slots.len;
        const slot = self.slots[slot_idx];
        return .{
            .name = self.data[slot.name_offset..][0..slot.name_len],
            .value = self.data[slot.name_offset + slot.name_len..][0..slot.value_len],
        };
    }

    /// Absolute index of the most recently inserted entry, or null if empty.
    pub fn newestAbsolute(self: *const DynamicTable) ?u64 {
        if (self.insert_count == 0) return null;
        return self.insert_count - 1;
    }

    /// Search for an exact name+value match, newest-first.
    /// Returns the absolute index of the matching entry, or null.
    pub fn findExact(self: *const DynamicTable, name: []const u8, value: []const u8) ?u64 {
        if (self.slot_count == 0) return null;
        const oldest = self.insert_count - @as(u64, self.slot_count);
        var i: usize = self.slot_count;
        while (i > 0) {
            i -= 1;
            const slot_idx = (self.slot_head + i) % self.slots.len;
            const slot = self.slots[slot_idx];
            const n = self.data[slot.name_offset..][0..slot.name_len];
            const v = self.data[slot.name_offset + slot.name_len..][0..slot.value_len];
            if (std.mem.eql(u8, name, n) and std.mem.eql(u8, value, v))
                return oldest + @as(u64, i);
        }
        return null;
    }

    /// Search for a name-only match, newest-first.
    /// Returns the absolute index of the matching entry, or null.
    pub fn findName(self: *const DynamicTable, name: []const u8) ?u64 {
        if (self.slot_count == 0) return null;
        const oldest = self.insert_count - @as(u64, self.slot_count);
        var i: usize = self.slot_count;
        while (i > 0) {
            i -= 1;
            const slot_idx = (self.slot_head + i) % self.slots.len;
            const slot = self.slots[slot_idx];
            const n = self.data[slot.name_offset..][0..slot.name_len];
            if (std.mem.eql(u8, name, n))
                return oldest + @as(u64, i);
        }
        return null;
    }

    fn evictOldest(self: *DynamicTable) void {
        if (self.slot_count == 0) return;

        const slot = self.slots[self.slot_head];
        const removed_bytes = slot.name_len + slot.value_len;

        if (removed_bytes > 0) {
            const remaining = self.data_len - removed_bytes;
            std.mem.copyForwards(u8, self.data[0..remaining], self.data[removed_bytes..self.data_len]);
            self.data_len -= removed_bytes;

            // Update offsets of all remaining slots.
            var i: usize = 1;
            while (i < self.slot_count) : (i += 1) {
                const idx = (self.slot_head + i) % self.slots.len;
                self.slots[idx].name_offset -= removed_bytes;
            }
        }

        self.slot_head = (self.slot_head + 1) % self.slots.len;
        self.slot_count -= 1;
        self.current_size -= slot.name_len + slot.value_len + 32;
    }
};

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "insert and get" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);

    try t.insert("content-type", "text/plain");
    try std.testing.expectEqual(@as(u64, 1), t.insert_count);

    const e = t.get(0).?;
    try std.testing.expectEqualStrings("content-type", e.name);
    try std.testing.expectEqualStrings("text/plain", e.value);
}

test "absolute indexing survives eviction" {
    // Capacity = 64 bytes. Each entry uses name+value+32 bytes.
    // "a: 1" = 1+1+32 = 34 bytes. Two entries = 68 > 64, so first is evicted.
    var data: [64]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 64);

    try t.insert("a", "1"); // absolute 0
    try t.insert("b", "2"); // absolute 1, evicts absolute 0

    try std.testing.expectEqual(@as(?Entry, null), t.get(0));
    const e = t.get(1).?;
    try std.testing.expectEqualStrings("b", e.name);
    try std.testing.expectEqualStrings("2", e.value);
}

test "findExact returns newest match" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);

    try t.insert("x-foo", "bar"); // absolute 0
    try t.insert("x-foo", "bar"); // absolute 1 (duplicate)
    try t.insert("x-foo", "baz"); // absolute 2 (same name, different value)

    // findExact "x-foo: bar" → newest is absolute 1
    try std.testing.expectEqual(@as(?u64, 1), t.findExact("x-foo", "bar"));
    // findExact "x-foo: baz" → absolute 2
    try std.testing.expectEqual(@as(?u64, 2), t.findExact("x-foo", "baz"));
    // findName → newest matching name is absolute 2
    try std.testing.expectEqual(@as(?u64, 2), t.findName("x-foo"));
}

test "setCapacity evicts as needed" {
    var data: [512]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 512);

    try t.insert("a", "1"); // 34 bytes
    try t.insert("b", "2"); // 34 bytes — total 68

    // Shrink capacity below current usage → both entries evicted
    try t.setCapacity(0);
    try std.testing.expectEqual(@as(usize, 0), t.slot_count);
    try std.testing.expectEqual(@as(usize, 0), t.current_size);
}

test "entry too large returns TableFull" {
    var data: [64]u8 = undefined;
    var slots: [16]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 64);

    // 35-byte name alone makes entry_size > 64 - ... well: 35+0+32 = 67 > 64
    const big_name = "a" ** 33; // 33 + 0 + 32 = 65 > 64
    try std.testing.expectError(error.TableFull, t.insert(big_name, ""));
}

test "multiple inserts and evictions preserve data integrity" {
    var data: [256]u8 = undefined;
    var slots: [32]DynamicTable.Slot = undefined;
    var t = DynamicTable.init(&data, &slots, 256);

    // Fill and evict in a loop, verify newest entry is always accessible.
    var i: u8 = 0;
    while (i < 20) : (i += 1) {
        var name_buf: [8]u8 = undefined;
        var val_buf: [8]u8 = undefined;
        const name = std.fmt.bufPrint(&name_buf, "h{d}", .{i}) catch unreachable;
        const val = std.fmt.bufPrint(&val_buf, "v{d}", .{i}) catch unreachable;
        try t.insert(name, val);

        const abs = t.newestAbsolute().?;
        const e = t.get(abs).?;
        try std.testing.expectEqualStrings(name, e.name);
        try std.testing.expectEqualStrings(val, e.value);
    }
}
