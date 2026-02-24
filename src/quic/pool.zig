//! O(1) fixed-capacity pool allocator.
//!
//! Backed by a statically-sized array. An index-based LIFO free-list avoids
//! dynamic allocation entirely. All acquire/release operations are O(1).
//!
//! Designed for use in the QUIC hot path: allocate once at startup, pass a
//! pointer to the pool rather than a `std.mem.Allocator`.

const std = @import("std");

pub fn Pool(comptime T: type, comptime capacity: usize) type {
    comptime std.debug.assert(capacity > 0);
    comptime std.debug.assert(capacity <= 65535); // index type is u16

    return struct {
        const Self = @This();

        items: [capacity]T = undefined,

        // LIFO stack of free indices.  Fully populated at init (all slots free).
        free: [capacity]u16 = blk: {
            var init: [capacity]u16 = undefined;
            for (&init, 0..) |*v, i| v.* = @intCast(i);
            break :blk init;
        },
        free_top: usize = capacity,

        /// Acquire a slot from the pool. Returns null when exhausted.
        pub fn acquire(self: *Self) ?*T {
            if (self.free_top == 0) return null;
            self.free_top -= 1;
            return &self.items[self.free[self.free_top]];
        }

        /// Return a previously acquired slot back to the pool.
        /// `ptr` must point into this pool's `items` array.
        pub fn release(self: *Self, ptr: *T) void {
            const idx = self.indexOf(ptr);
            self.free[self.free_top] = @intCast(idx);
            self.free_top += 1;
        }

        /// True if `ptr` was acquired from this pool and not yet released.
        pub fn owns(self: *const Self, ptr: *const T) bool {
            const base = @intFromPtr(&self.items[0]);
            const p = @intFromPtr(ptr);
            if (p < base) return false;
            const offset = p - base;
            return offset < capacity * @sizeOf(T) and offset % @sizeOf(T) == 0;
        }

        /// Number of available slots.
        pub fn available(self: *const Self) usize {
            return self.free_top;
        }

        fn indexOf(self: *const Self, ptr: *const T) usize {
            const base = @intFromPtr(&self.items[0]);
            const p = @intFromPtr(ptr);
            std.debug.assert(p >= base);
            const offset = p - base;
            std.debug.assert(offset % @sizeOf(T) == 0);
            const idx = offset / @sizeOf(T);
            std.debug.assert(idx < capacity);
            return idx;
        }
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "pool: acquire and release" {
    const testing = std.testing;
    var pool: Pool(u64, 4) = .{};

    try testing.expectEqual(@as(usize, 4), pool.available());

    const a = pool.acquire().?;
    try testing.expectEqual(@as(usize, 3), pool.available());

    const b = pool.acquire().?;
    try testing.expectEqual(@as(usize, 2), pool.available());

    pool.release(b);
    try testing.expectEqual(@as(usize, 3), pool.available());

    pool.release(a);
    try testing.expectEqual(@as(usize, 4), pool.available());
}

test "pool: exhaustion returns null" {
    const testing = std.testing;
    var pool: Pool(u32, 2) = .{};

    const a = pool.acquire();
    const b = pool.acquire();
    try testing.expect(a != null);
    try testing.expect(b != null);

    const c = pool.acquire();
    try testing.expect(c == null);

    pool.release(a.?);
    const d = pool.acquire();
    try testing.expect(d != null);
}

test "pool: released items are reused" {
    const testing = std.testing;
    var pool: Pool(u8, 2) = .{};

    const a = pool.acquire().?;
    a.* = 42;
    pool.release(a);

    const b = pool.acquire().?;
    b.* = 99; // overwrite recycled slot
    try testing.expect(pool.owns(b));
    pool.release(b);
    try testing.expectEqual(@as(usize, 2), pool.available());
}

test "pool: owns" {
    var pool: Pool(u32, 8) = .{};
    const p = pool.acquire().?;
    const testing = std.testing;
    try testing.expect(pool.owns(p));
    pool.release(p);
    try testing.expect(pool.owns(p)); // owns doesn't track allocation state
}
