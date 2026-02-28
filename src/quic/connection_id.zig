//! QUIC Connection ID generation and management.
//!
//! CIDs are 8 bytes.  The first byte encodes the thread index (reserved for
//! future BPF-based packet steering).  The remaining 7 bytes are random.

const std = @import("std");

pub const len: usize = 8;

pub const ConnectionId = struct {
    bytes: [len]u8 = [_]u8{0} ** len,

    pub const zero: ConnectionId = .{ .bytes = [_]u8{0} ** len };

    /// Generate a random CID tagged with `thread_id` in the first byte.
    /// Uses `io.random` for cryptographically strong randomness.
    pub fn generate(thread_id: u8, io: std.Io) ConnectionId {
        var cid: ConnectionId = undefined;
        io.random(&cid.bytes);
        cid.bytes[0] = thread_id;
        return cid;
    }

    /// Return the thread index encoded in the first byte.
    pub fn threadIndex(self: ConnectionId) u8 {
        return self.bytes[0];
    }

    pub fn eql(a: ConnectionId, b: ConnectionId) bool {
        return std.mem.eql(u8, &a.bytes, &b.bytes);
    }

    pub fn format(
        self: ConnectionId,
        comptime _: []const u8,
        _: std.fmt.FormatOptions,
        writer: anytype,
    ) !void {
        for (self.bytes) |b| try writer.print("{x:0>2}", .{b});
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "connection_id: generate encodes thread index" {
    const testing = std.testing;
    const io = std.testing.io;
    const cid = ConnectionId.generate(7, io);
    try testing.expectEqual(@as(u8, 7), cid.threadIndex());
}

test "connection_id: zero CID" {
    const testing = std.testing;
    try testing.expect(ConnectionId.eql(ConnectionId.zero, ConnectionId.zero));
}

test "connection_id: two generated CIDs are not equal" {
    const testing = std.testing;
    const io = std.testing.io;
    const a = ConnectionId.generate(0, io);
    const b = ConnectionId.generate(0, io);
    // 56 random bits — collision probability is negligible (~1 in 2^56)
    try testing.expect(!ConnectionId.eql(a, b));
}

test "connection_id: generate randomises the non-thread bytes" {
    const testing = std.testing;
    const io = std.testing.io;
    const cid = ConnectionId.generate(3, io);
    // Thread index preserved in byte 0
    try testing.expectEqual(@as(u8, 3), cid.bytes[0]);
    // At least one of the remaining 7 bytes must be non-zero
    // (std.testing.io fills with deterministic non-zero data)
    var any_nonzero = false;
    for (cid.bytes[1..]) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    try testing.expect(any_nonzero);
}
