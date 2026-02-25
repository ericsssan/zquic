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

/// A fixed-size ring buffer for stream data (receive or send side).
/// `cap` must be a power of two (enforced by comptime assert).
pub fn RingBuf(comptime cap: usize) type {
    comptime {
        std.debug.assert(cap > 0 and cap & (cap - 1) == 0);
    }
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
            if (n == 0) return 0;
            const start = self.wp & (cap - 1);
            const first = @min(n, cap - start);
            @memcpy(self.buf[start..][0..first], data[0..first]);
            if (n > first) {
                @memcpy(self.buf[0..n - first], data[first..n]);
            }
            self.wp += n;
            return n;
        }

        pub fn read(self: *Self, out: []u8) usize {
            const n = @min(out.len, self.readable());
            if (n == 0) return 0;
            const start = self.rp & (cap - 1);
            const first = @min(n, cap - start);
            @memcpy(out[0..first], self.buf[start..][0..first]);
            if (n > first) {
                @memcpy(out[first..n], self.buf[0..n - first]);
            }
            self.rp += n;
            return n;
        }

        /// Read bytes at rel_offset from the read pointer without consuming.
        pub fn peek(self: *const Self, rel_offset: usize, out: []u8) usize {
            const avail = self.readable();
            if (rel_offset >= avail) return 0;
            const n = @min(out.len, avail - rel_offset);
            if (n == 0) return 0;
            const start = (self.rp + rel_offset) & (cap - 1);
            const first = @min(n, cap - start);
            @memcpy(out[0..first], self.buf[start..][0..first]);
            if (n > first) {
                @memcpy(out[first..n], self.buf[0..n - first]);
            }
            return n;
        }

        /// Discard n bytes from the read side (advance rp without copying).
        pub fn discard(self: *Self, n: usize) usize {
            const actual = @min(n, self.readable());
            self.rp += actual;
            return actual;
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

    // Send-side buffer: holds data until acknowledged (for retransmission).
    send_buf: RingBuf(STREAM_BUF_SIZE),
    /// Cumulative bytes acknowledged on the send side.
    send_acked: u64,
    /// FIN has been queued for sending.
    send_fin: bool,
    /// FIN has been acknowledged by the remote.
    fin_acked: bool,
    /// Pending RESET_STREAM to send (set by initiateReset / onStopSendingReceived).
    pending_reset: ?struct { error_code: u62, final_size: u62 },
    /// Pending STOP_SENDING error code (set when we want to stop receiving).
    pending_stop: ?u62,

    pub fn init(id: u62) Stream {
        return .{
            .id = id,
            .state = .open,
            .send_offset = 0,
            .recv_offset = 0,
            .recv_buf = .{},
            .recv_max = STREAM_BUF_SIZE,
            .send_max = STREAM_BUF_SIZE,
            .send_buf = .{},
            .send_acked = 0,
            .send_fin = false,
            .fin_acked = false,
            .pending_reset = null,
            .pending_stop = null,
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

    /// Buffer incoming data. Returns error if exceeds receive window or buffer is full.
    pub fn receiveData(self: *Stream, offset: u64, data: []const u8, fin: bool) !void {
        const end = std.math.add(u64, offset, data.len) catch return error.FlowControlViolation;
        if (end > self.recv_max) return error.FlowControlViolation;

        // Simple in-order delivery only for Phase 1
        if (offset == self.recv_offset) {
            const written = self.recv_buf.write(data);
            self.recv_offset += written;
            // If the ring buffer was full and couldn't accept all data, report the error.
            // The caller must drain the buffer before sending more data.
            if (written < data.len) return error.BufferFull;
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
    /// Advances recv_max to reflect freed buffer space, allowing the remote to send more.
    pub fn read(self: *Stream, out: []u8) usize {
        const n = self.recv_buf.read(out);
        if (n > 0) {
            // recv_buf.rp is the total bytes consumed (monotonically increasing).
            // New recv_max = consumed_so_far + STREAM_BUF_SIZE.
            self.recv_max = self.recv_buf.rp + STREAM_BUF_SIZE;
        }
        return n;
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

    // -----------------------------------------------------------------------
    // Send-side buffer API (Phase 3)
    // -----------------------------------------------------------------------

    /// Write data into the send buffer (retained until ACKed for retransmission).
    /// Returns the number of bytes actually buffered.
    pub fn bufferSendData(self: *Stream, data: []const u8) usize {
        return self.send_buf.write(data);
    }

    /// Called when the remote acknowledges bytes [offset, offset+len).
    /// Advances send_acked and frees the corresponding space in send_buf.
    pub fn onAcked(self: *Stream, offset: u64, len: u16) void {
        if (offset != self.send_acked) return; // only handle contiguous acks
        _ = self.send_buf.discard(len);
        self.send_acked += len;
    }

    /// Return a peek of buffered send data starting at `offset`.
    /// Returns 0 if offset is below send_acked (already freed).
    pub fn getSendData(self: *const Stream, offset: u64, out: []u8) usize {
        if (offset < self.send_acked) return 0;
        const rel: usize = @intCast(offset - self.send_acked);
        return self.send_buf.peek(rel, out);
    }

    // -----------------------------------------------------------------------
    // Reset / stop-sending state machine (Phase 3 / Step 6)
    // -----------------------------------------------------------------------

    /// Handle an incoming RESET_STREAM frame.
    pub fn onResetReceived(self: *Stream, error_code: u62, final_size: u62) !void {
        _ = error_code;
        // RFC 9000 §19.4: final_size must be >= bytes already received.
        if (final_size < self.recv_offset) return error.FinalSizeError;
        switch (self.state) {
            .open, .half_closed_remote => self.state = .reset,
            .half_closed_local => self.state = .closed,
            .closed, .reset => {},
        }
    }

    /// Handle an incoming STOP_SENDING frame — we respond by resetting the stream.
    pub fn onStopSendingReceived(self: *Stream, error_code: u62) void {
        self.pending_reset = .{
            .error_code = error_code,
            .final_size = @intCast(self.send_offset),
        };
    }

    /// Initiate a local reset of this stream.
    pub fn initiateReset(self: *Stream, error_code: u62) void {
        self.pending_reset = .{
            .error_code = error_code,
            .final_size = @intCast(self.send_offset),
        };
        switch (self.state) {
            .open, .half_closed_remote => self.state = .reset,
            .half_closed_local => self.state = .closed,
            .closed, .reset => {},
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

test "stream: receiveData returns BufferFull when ring buffer is full" {
    var s = Stream.init(0);
    // Fill the ring buffer to capacity with in-order data
    var data: [STREAM_BUF_SIZE]u8 = undefined;
    @memset(&data, 0xaa);
    try s.receiveData(0, &data, false);

    // Extend flow-control window so the check doesn't fire early
    s.recv_max = STREAM_BUF_SIZE + 100;

    // Buffer is full; another byte at the next offset must fail with BufferFull
    try std.testing.expectError(error.BufferFull, s.receiveData(STREAM_BUF_SIZE, &[_]u8{0x01}, false));
}

test "stream: recv_max extends after read" {
    const testing = std.testing;
    var s = Stream.init(4);
    const initial_max = s.recv_max; // STREAM_BUF_SIZE

    // Receive some data
    try s.receiveData(0, "hello world", false);

    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 11), n);

    // recv_max must grow: consumed (11) + STREAM_BUF_SIZE
    try testing.expect(s.recv_max > initial_max);
    try testing.expectEqual(STREAM_BUF_SIZE + @as(u64, 11), s.recv_max);
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

// ---------------------------------------------------------------------------
// New tests — send-side buffer (Step 2)
// ---------------------------------------------------------------------------

test "stream_send: bufferSendData and getSendData round-trip" {
    const testing = std.testing;
    var s = Stream.init(0);
    const n = s.bufferSendData("hello");
    try testing.expectEqual(@as(usize, 5), n);

    var buf: [16]u8 = undefined;
    const m = s.getSendData(0, &buf);
    try testing.expectEqual(@as(usize, 5), m);
    try testing.expectEqualSlices(u8, "hello", buf[0..m]);
}

test "stream_send: onAcked advances send_acked and frees send_buf space" {
    const testing = std.testing;
    var s = Stream.init(0);
    _ = s.bufferSendData("hello world"); // 11 bytes
    s.send_offset = 11; // simulate having sent all

    const writable_before = s.send_buf.writable();
    s.onAcked(0, 5); // ack first 5 bytes
    try testing.expectEqual(@as(u64, 5), s.send_acked);
    try testing.expect(s.send_buf.writable() > writable_before);
}

test "stream_send: getSendData returns data for un-acked offset" {
    const testing = std.testing;
    var s = Stream.init(0);
    _ = s.bufferSendData("abcdefgh"); // 8 bytes at offset 0

    var buf: [8]u8 = undefined;
    const n = s.getSendData(0, &buf);
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expectEqualSlices(u8, "abcdefgh", buf[0..n]);
}

test "stream_send: getSendData returns 0 for already-acked offset" {
    const testing = std.testing;
    var s = Stream.init(0);
    _ = s.bufferSendData("hello");
    s.onAcked(0, 5);

    var buf: [16]u8 = undefined;
    const n = s.getSendData(0, &buf); // offset 0 is already acked
    try testing.expectEqual(@as(usize, 0), n);
}

test "stream_send: send_fin and fin_acked flags" {
    const testing = std.testing;
    var s = Stream.init(0);
    try testing.expect(!s.send_fin);
    try testing.expect(!s.fin_acked);

    s.send_fin = true;
    try testing.expect(s.send_fin);
    s.fin_acked = true;
    try testing.expect(s.fin_acked);
}

test "ringbuf: peek does not consume" {
    const testing = std.testing;
    var rb: RingBuf(16) = .{};
    _ = rb.write("hello world");

    var buf1: [5]u8 = undefined;
    const n1 = rb.peek(0, &buf1);
    try testing.expectEqual(@as(usize, 5), n1);
    try testing.expectEqualSlices(u8, "hello", buf1[0..n1]);
    // readable count unchanged
    try testing.expectEqual(@as(usize, 11), rb.readable());

    var buf2: [5]u8 = undefined;
    const n2 = rb.peek(6, &buf2);
    try testing.expectEqual(@as(usize, 5), n2);
    try testing.expectEqualSlices(u8, "world", buf2[0..n2]);
}

test "ringbuf: discard advances rp" {
    const testing = std.testing;
    var rb: RingBuf(16) = .{};
    _ = rb.write("hello");
    const discarded = rb.discard(3);
    try testing.expectEqual(@as(usize, 3), discarded);
    try testing.expectEqual(@as(usize, 2), rb.readable());
    var buf: [4]u8 = undefined;
    const n = rb.read(&buf);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualSlices(u8, "lo", buf[0..n]);
}

// ---------------------------------------------------------------------------
// New tests — stream state machine (Step 6)
// ---------------------------------------------------------------------------

test "stream_reset: onResetReceived open to reset" {
    const testing = std.testing;
    var s = Stream.init(0);
    try s.onResetReceived(42, 0);
    try testing.expectEqual(StreamState.reset, s.state);
}

test "stream_reset: onResetReceived half_closed_local to closed" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.state = .half_closed_local;
    try s.onResetReceived(0, 0);
    try testing.expectEqual(StreamState.closed, s.state);
}

test "stream_reset: onResetReceived bad final_size returns FinalSizeError" {
    var s = Stream.init(0);
    s.recv_offset = 100;
    try std.testing.expectError(error.FinalSizeError, s.onResetReceived(0, 50));
}

test "stream_reset: onStopSendingReceived sets pending_reset" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.send_offset = 200;
    s.onStopSendingReceived(7);
    try testing.expect(s.pending_reset != null);
    try testing.expectEqual(@as(u62, 7), s.pending_reset.?.error_code);
    try testing.expectEqual(@as(u62, 200), s.pending_reset.?.final_size);
}

test "stream: receiveData overflow-safe offset + len check" {
    // offset near u64 max: offset + data.len would overflow — must return FlowControlViolation
    var s = Stream.init(0);
    s.recv_max = std.math.maxInt(u64);
    const err = s.receiveData(std.math.maxInt(u64) - 2, "hello", false);
    try std.testing.expectError(error.FlowControlViolation, err);
}

test "stream_reset: initiateReset sets pending and transitions state" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.send_offset = 100;
    s.initiateReset(5);
    try testing.expect(s.pending_reset != null);
    try testing.expectEqual(@as(u62, 5), s.pending_reset.?.error_code);
    try testing.expectEqual(@as(u62, 100), s.pending_reset.?.final_size);
    try testing.expectEqual(StreamState.reset, s.state);
}
