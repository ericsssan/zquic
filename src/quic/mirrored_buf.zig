//! Double-mapped ring buffer: the same physical pages mapped twice contiguously
//! in virtual memory.  Reads and writes NEVER split at the wrap boundary —
//! peekAll() always returns a single contiguous slice.
//!
//!   Virtual address space:
//!     [Page A][Page B] [Page A'][Page B']
//!      ↑ first map      ↑ second map (same physical pages)
//!
//! Uses POSIX shm_open + mmap — works on Linux, macOS, FreeBSD, all POSIX.
//! Zig 0.16 std.posix lacks close/ftruncate/shm_open, so we use @cImport
//! for those three calls.  mmap/munmap use Zig's std.posix.

const std = @import("std");
const posix = std.posix;

const c = @cImport({
    @cInclude("sys/mman.h");
    @cInclude("fcntl.h");
    @cInclude("unistd.h");
});

/// A double-mapped ring buffer of `size` bytes.
/// `size` must be a multiple of the system page size AND a power of two.
pub fn MirroredRingBuf(comptime size: usize) type {
    comptime {
        std.debug.assert(size > 0);
        std.debug.assert(size & (size - 1) == 0); // power of two
    }

    return struct {
        const Self = @This();

        ptr: [*]align(std.heap.page_size_min) u8,
        rp: usize = 0,
        wp: usize = 0,

        pub fn init() !Self {
            const ptr = try mmapMirror(size);
            return .{ .ptr = ptr };
        }

        pub fn deinit(self: *Self) void {
            _ = c.munmap(@ptrCast(self.ptr), size * 2);
            self.ptr = undefined;
        }

        pub fn readable(self: *const Self) usize {
            return self.wp - self.rp;
        }

        pub fn writable(self: *const Self) usize {
            return size - (self.wp - self.rp);
        }

        /// Always returns a contiguous slice — even when data wraps.
        pub fn peekAll(self: *const Self) []const u8 {
            const n = self.readable();
            if (n == 0) return &.{};
            const start = self.rp & (size - 1);
            return self.ptr[start..][0..n];
        }

        pub fn peekAllMut(self: *Self) []u8 {
            const n = self.readable();
            if (n == 0) return &.{};
            const start = self.rp & (size - 1);
            return self.ptr[start..][0..n];
        }

        /// Alias for peekAll (MirroredRingBuf never splits).
        pub fn peekContiguous(self: *const Self) []const u8 {
            return self.peekAll();
        }

        pub fn consume(self: *Self, n: usize) void {
            self.rp += @min(n, self.readable());
        }

        pub fn write(self: *Self, data: []const u8) usize {
            const n = @min(data.len, self.writable());
            if (n == 0) return 0;
            const start = self.wp & (size - 1);
            @memcpy(self.ptr[start..][0..n], data[0..n]);
            self.wp += n;
            return n;
        }

        pub fn writeAt(self: *Self, rel_offset: usize, data: []const u8) usize {
            if (rel_offset >= size) return 0;
            const available = size - rel_offset;
            const n = @min(data.len, available);
            if (n == 0) return 0;
            const start = (self.rp + rel_offset) & (size - 1);
            @memcpy(self.ptr[start..][0..n], data[0..n]);
            return n;
        }

        pub fn read(self: *Self, out: []u8) usize {
            const n = @min(out.len, self.readable());
            if (n == 0) return 0;
            const start = self.rp & (size - 1);
            @memcpy(out[0..n], self.ptr[start..][0..n]);
            self.rp += n;
            return n;
        }

        pub fn discard(self: *Self, n: usize) usize {
            const actual = @min(n, self.readable());
            self.rp += actual;
            return actual;
        }
    };
}

/// Single POSIX implementation: shm_open + ftruncate + mmap × 2.
/// Works on Linux, macOS, FreeBSD, all POSIX systems.
fn mmapMirror(size: usize) ![*]align(std.heap.page_size_min) u8 {
    // Create anonymous shared memory object.
    // shm_open creates a POSIX shared memory object backed by physical pages.
    // O_EXCL excluded: allows retry if name exists from a crashed process.
    const name: [*:0]const u8 = "/zquic_mirr";
    const fd = c.shm_open(name, c.O_CREAT | c.O_RDWR, @as(c.mode_t, 0o600));
    if (fd < 0) return error.MmapFailed;
    defer _ = c.close(fd);
    // Unlink immediately: fd stays valid, namespace freed for next caller.
    _ = c.shm_unlink(name);

    if (c.ftruncate(fd, @intCast(size)) != 0) return error.MmapFailed;

    // Reserve 2× contiguous virtual address space.
    const base_raw = c.mmap(null, size * 2, c.PROT_NONE, c.MAP_PRIVATE | c.MAP_ANON, -1, 0);
    if (base_raw == c.MAP_FAILED) return error.MmapFailed;
    const base: [*]align(std.heap.page_size_min) u8 = @ptrCast(@alignCast(base_raw));

    // Map first half: physical pages at [base, base+size).
    if (c.mmap(@ptrCast(base), size, c.PROT_READ | c.PROT_WRITE, c.MAP_SHARED | c.MAP_FIXED, fd, 0) == c.MAP_FAILED) {
        _ = c.munmap(@ptrCast(base), size * 2);
        return error.MmapFailed;
    }

    // Map second half: SAME physical pages at [base+size, base+2×size).
    if (c.mmap(@ptrCast(base + size), size, c.PROT_READ | c.PROT_WRITE, c.MAP_SHARED | c.MAP_FIXED, fd, 0) == c.MAP_FAILED) {
        _ = c.munmap(@ptrCast(base), size * 2);
        return error.MmapFailed;
    }

    return base;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "basic write and peekAll" {
    var buf = try MirroredRingBuf(65536).init();
    defer buf.deinit();

    const data = "Hello, mirrored world!";
    try testing.expectEqual(data.len, buf.write(data));
    try testing.expectEqualSlices(u8, data, buf.peekAll());

    buf.consume(data.len);
    try testing.expectEqual(@as(usize, 0), buf.readable());
}

test "wrap-around read is contiguous" {
    const cap = 65536;
    var buf = try MirroredRingBuf(cap).init();
    defer buf.deinit();

    // Fill most of buffer, then consume to move rp near the end
    var fill_data: [cap - 10]u8 = undefined;
    @memset(&fill_data, 'A');
    _ = buf.write(&fill_data);
    buf.consume(cap - 10);

    // Write across the wrap boundary
    const wrap_data = "WRAP_AROUND_DATA!";
    _ = buf.write(wrap_data);

    // peekAll returns contiguous slice even though data wraps
    const peeked = buf.peekAll();
    try testing.expectEqual(wrap_data.len, peeked.len);
    try testing.expectEqualSlices(u8, wrap_data, peeked);
}

test "writeAt for out-of-order reassembly" {
    var buf = try MirroredRingBuf(65536).init();
    defer buf.deinit();

    _ = buf.writeAt(5, "world");
    _ = buf.writeAt(0, "hello");
    buf.wp += 10;

    try testing.expectEqualSlices(u8, "helloworld", buf.peekAll());
}

test "full capacity" {
    const cap = 65536;
    var buf = try MirroredRingBuf(cap).init();
    defer buf.deinit();

    try testing.expectEqual(cap, buf.writable());
    var data: [cap]u8 = undefined;
    @memset(&data, 0xAB);
    try testing.expectEqual(cap, buf.write(&data));
    try testing.expectEqual(@as(usize, 0), buf.writable());
    try testing.expectEqual(cap, buf.readable());
}
