//! QUIC stream multiplexing (RFC 9000 §2, §19.8).
//!
//! Stream ID encoding:
//!   bit 0: 0 = client-initiated, 1 = server-initiated
//!   bit 1: 0 = bidirectional,   1 = unidirectional

const std = @import("std");

pub const MAX_STREAMS: usize = 4;
pub const STREAM_BUF_SIZE: usize = 4096;

pub const StreamState = enum(u8) {
    open,
    half_closed_local, // we sent FIN
    half_closed_remote, // remote sent FIN
    closed,
    reset,
};

/// Direction of the stream from the perspective of this endpoint.
pub const StreamDir = enum(u1) {
    client_initiated = 0,
    server_initiated = 1,
};

pub const StreamKind = enum(u1) {
    bidirectional = 0,
    unidirectional = 1,
};

pub fn streamDir(id: u62) StreamDir {
    return @enumFromInt(@as(u1, @intCast(id & 1)));
}

pub fn streamKind(id: u62) StreamKind {
    return @enumFromInt(@as(u1, @intCast((id >> 1) & 1)));
}

/// A fixed-size ring buffer for stream receive data.
pub fn RingBuf(comptime cap: usize) type {
    return struct {
        const Self = @This();
        buf: [cap]u8 = undefined,
        rp: usize = 0,
        wp: usize = 0,

        pub fn writable(self: *const Self) usize {
            return cap - (self.wp - self.rp);
        }

        pub fn readable(self: *const Self) usize {
            return self.wp - self.rp;
        }

        pub fn write(self: *Self, data: []const u8) usize {
            const n = @min(data.len, self.writable());
            for (0..n) |i| {
                self.buf[(self.wp + i) % cap] = data[i];
            }
            self.wp += n;
            return n;
        }

        pub fn read(self: *Self, out: []u8) usize {
            const n = @min(out.len, self.readable());
            for (0..n) |i| {
                out[i] = self.buf[(self.rp + i) % cap];
            }
            self.rp += n;
            return n;
        }
    };
}

pub const Stream = struct {
    id: u62,
    state: StreamState,
    send_offset: u64,
    recv_offset: u64,
    recv_buf: RingBuf(STREAM_BUF_SIZE),
    /// Maximum bytes the remote is allowed to send on this stream.
    recv_max: u64,
    /// Maximum bytes we are allowed to send on this stream (set by remote).
    send_max: u64,

    pub fn init(id: u62) Stream {
        return .{
            .id = id,
            .state = .open,
            .send_offset = 0,
            .recv_offset = 0,
            .recv_buf = .{},
            .recv_max = STREAM_BUF_SIZE,
            .send_max = STREAM_BUF_SIZE,
        };
    }

    pub fn isReadable(self: *const Stream) bool {
        return self.recv_buf.readable() > 0;
    }

    pub fn canSend(self: *const Stream, bytes: u64) bool {
        return self.state != .half_closed_local and
            self.state != .closed and
            self.state != .reset and
            self.send_offset + bytes <= self.send_max;
    }

    /// Buffer incoming data. Returns error if exceeds receive window.
    pub fn receiveData(self: *Stream, offset: u64, data: []const u8, fin: bool) !void {
        if (offset + data.len > self.recv_max) return error.FlowControlViolation;

        // Simple in-order delivery only for Phase 1
        if (offset == self.recv_offset) {
            const written = self.recv_buf.write(data);
            self.recv_offset += written;
        }

        if (fin) {
            if (self.state == .half_closed_local) {
                self.state = .closed;
            } else {
                self.state = .half_closed_remote;
            }
        }
    }

    /// Read buffered receive data into `out`. Returns bytes read.
    pub fn read(self: *Stream, out: []u8) usize {
        return self.recv_buf.read(out);
    }

    /// Record that we sent `bytes` (advances send_offset).
    pub fn onSent(self: *Stream, bytes: usize) void {
        self.send_offset += bytes;
    }

    /// Mark local side as done sending.
    pub fn sendFin(self: *Stream) void {
        switch (self.state) {
            .open => self.state = .half_closed_local,
            .half_closed_remote => self.state = .closed,
            else => {},
        }
    }
};

// ---------------------------------------------------------------------------
// Stream table
// ---------------------------------------------------------------------------

pub const StreamTable = struct {
    streams: [MAX_STREAMS]Stream = undefined,
    used: [MAX_STREAMS]bool = [_]bool{false} ** MAX_STREAMS,

    /// Open or retrieve a stream by ID. Returns null if capacity exceeded.
    pub fn getOrCreate(self: *StreamTable, id: u62) ?*Stream {
        // Look for existing
        for (0..MAX_STREAMS) |i| {
            if (self.used[i] and self.streams[i].id == id) {
                return &self.streams[i];
            }
        }
        // Allocate a new slot
        for (0..MAX_STREAMS) |i| {
            if (!self.used[i]) {
                self.streams[i] = Stream.init(id);
                self.used[i] = true;
                return &self.streams[i];
            }
        }
        return null;
    }

    pub fn get(self: *StreamTable, id: u62) ?*Stream {
        for (0..MAX_STREAMS) |i| {
            if (self.used[i] and self.streams[i].id == id) {
                return &self.streams[i];
            }
        }
        return null;
    }

    pub fn close(self: *StreamTable, id: u62) void {
        for (0..MAX_STREAMS) |i| {
            if (self.used[i] and self.streams[i].id == id) {
                self.used[i] = false;
                return;
            }
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "stream: receive and read in-order" {
    const testing = std.testing;
    var s = Stream.init(4);
    try s.receiveData(0, "hello", false);
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..n]);
}

test "stream: fin transitions state" {
    const testing = std.testing;
    var s = Stream.init(0);
    try s.receiveData(0, "data", true);
    try testing.expectEqual(StreamState.half_closed_remote, s.state);
    s.sendFin();
    try testing.expectEqual(StreamState.closed, s.state);
}

test "stream: flow control violation" {
    var s = Stream.init(0);
    s.recv_max = 4;
    const err = s.receiveData(0, "12345", false);
    try std.testing.expectError(error.FlowControlViolation, err);
}

test "stream_table: getOrCreate and get" {
    const testing = std.testing;
    var table: StreamTable = .{};
    const s = table.getOrCreate(0).?;
    s.send_offset = 42;
    const s2 = table.get(0).?;
    try testing.expectEqual(@as(u64, 42), s2.send_offset);
}

test "stream_table: capacity limit" {
    var table: StreamTable = .{};
    var i: u62 = 0;
    while (i < MAX_STREAMS) : (i += 1) {
        _ = table.getOrCreate(i * 4);
    }
    // Next allocation should fail
    const overflow = table.getOrCreate(@intCast(MAX_STREAMS * 4));
    const testing = std.testing;
    try testing.expectEqual(@as(?*Stream, null), overflow);
}

test "stream: streamDir and streamKind decode ID bits" {
    const testing = std.testing;
    // ID bit 0: 0=client, 1=server.  Bit 1: 0=bidi, 1=uni.
    try testing.expectEqual(StreamDir.client_initiated, streamDir(0)); // 0b00
    try testing.expectEqual(StreamKind.bidirectional,   streamKind(0));
    try testing.expectEqual(StreamDir.server_initiated, streamDir(1)); // 0b01
    try testing.expectEqual(StreamKind.bidirectional,   streamKind(1));
    try testing.expectEqual(StreamDir.client_initiated, streamDir(2)); // 0b10
    try testing.expectEqual(StreamKind.unidirectional,  streamKind(2));
    try testing.expectEqual(StreamDir.server_initiated, streamDir(3)); // 0b11
    try testing.expectEqual(StreamKind.unidirectional,  streamKind(3));
}

test "stream: onSent advances send_offset" {
    const testing = std.testing;
    var s = Stream.init(0);
    try testing.expectEqual(@as(u64, 0), s.send_offset);
    s.onSent(100);
    try testing.expectEqual(@as(u64, 100), s.send_offset);
    s.onSent(200);
    try testing.expectEqual(@as(u64, 300), s.send_offset);
}

test "stream: out-of-order data is silently dropped" {
    const testing = std.testing;
    var s = Stream.init(0);
    // Data at offset 5 before offset 0 has been received — silently ignored
    try s.receiveData(5, "world", false);
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 0), n);
    // In-order data at offset 0 is buffered normally
    try s.receiveData(0, "hello", false);
    const n2 = s.read(&buf);
    try testing.expectEqual(@as(usize, 5), n2);
    try testing.expectEqualSlices(u8, "hello", buf[0..n2]);
}

test "ringbuf: wrap-around" {
    const testing = std.testing;
    var rb: RingBuf(8) = .{};
    _ = rb.write("abcdefg"); // 7 bytes
    var out: [4]u8 = undefined;
    _ = rb.read(&out); // consume 4 → "abcd"
    _ = rb.write("xyz"); // write 3 more, wrap
    var out2: [6]u8 = undefined;
    const n = rb.read(&out2);
    try testing.expectEqual(@as(usize, 6), n);
    try testing.expectEqualSlices(u8, "efgxyz", out2[0..n]);
}
