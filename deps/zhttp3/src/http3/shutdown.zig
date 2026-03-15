// HTTP/3 graceful shutdown — RFC 9114 §5.2
//
// Shutdown sequence:
//
//   1. Server calls initiateShutdown(last_stream_id, buf).
//        - Transitions state: running → draining.
//        - Writes a GOAWAY frame into buf (caller sends it on the control stream).
//        - last_stream_id: the highest request stream ID the server will process.
//          Requests on streams ≥ last_stream_id MUST NOT be processed.
//
//   2. Server continues processing in-flight requests.
//        - requestStarted() — must be called while still running, increments counter.
//        - requestFinished() — decrements counter, may trigger close.
//
//   3. When draining and in_flight == 0 → state transitions to closed.
//
//   4. isClosed() returns true — connection may be torn down.
//
// RFC 9114 §5.2 recommends sending an initial GOAWAY with stream_id = 2^62-4
// (the largest possible QUIC stream ID) to warn the client early, then a
// second GOAWAY with the actual last processed stream ID.  This model supports
// that by allowing initiateShutdown to be called a second time with a smaller
// last_stream_id; subsequent calls with a larger ID are rejected.

const frame = @import("frame.zig");

pub const Error = error{
    /// Output buffer too small for the GOAWAY frame.
    BufferTooSmall,
    /// Varint out of range.
    Overflow,
    /// initiateShutdown called with a larger last_stream_id than a previous
    /// call.  RFC 9114 §5.2 requires last_stream_id to be non-increasing.
    LastStreamIdIncreased,
    /// Operation not valid in the current shutdown state.
    InvalidState,
};

pub const ShutdownState = enum { running, draining, closed };

pub const Shutdown = struct {
    state: ShutdownState = .running,
    /// The last_stream_id from the most recently sent GOAWAY.
    /// Initialised to maxInt so the first call is always accepted.
    last_stream_id: u64 = std.math.maxInt(u64),
    /// Count of requests currently being processed.
    in_flight: usize = 0,

    /// Begin shutdown: write a GOAWAY frame into buf, transition to draining.
    ///
    /// May be called more than once to send a refined (smaller) last_stream_id
    /// per RFC 9114 §5.2.  Subsequent calls MUST pass a non-increasing value.
    ///
    /// Returns the number of bytes written — the caller sends them on the
    /// server's control stream.
    pub fn initiateShutdown(self: *Shutdown, last_stream_id: u64, buf: []u8) Error!usize {
        if (self.state == .closed) return error.InvalidState;
        if (self.state == .draining and last_stream_id > self.last_stream_id)
            return error.LastStreamIdIncreased;
        self.state = .draining;
        self.last_stream_id = last_stream_id;
        const n = frame.writeGoaway(buf, last_stream_id) catch return error.BufferTooSmall;
        self.maybeClose();
        return n;
    }

    /// Record that a new request has started.  Only valid in .running state.
    pub fn requestStarted(self: *Shutdown) Error!void {
        if (self.state != .running) return error.InvalidState;
        self.in_flight += 1;
    }

    /// Record that a request has finished.
    /// Transitions to .closed if draining and in_flight reaches zero.
    pub fn requestFinished(self: *Shutdown) void {
        if (self.in_flight > 0) self.in_flight -= 1;
        self.maybeClose();
    }

    pub fn isDraining(self: *const Shutdown) bool {
        return self.state == .draining;
    }

    pub fn isClosed(self: *const Shutdown) bool {
        return self.state == .closed;
    }

    fn maybeClose(self: *Shutdown) void {
        if (self.state == .draining and self.in_flight == 0) {
            self.state = .closed;
        }
    }
};

const std = @import("std");

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "Shutdown: initial state is running" {
    const std_ = @import("std");
    const s: Shutdown = .{};
    try std_.testing.expectEqual(ShutdownState.running, s.state);
    try std_.testing.expect(!s.isDraining());
    try std_.testing.expect(!s.isClosed());
}

test "Shutdown.initiateShutdown: writes GOAWAY and transitions to draining" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    // Keep one request in-flight so the state stays draining (not immediately closed).
    try s.requestStarted();
    var buf: [16]u8 = undefined;
    const n = try s.initiateShutdown(99, &buf);

    // Verify the GOAWAY frame bytes.
    const hdr = try frame.parseHeader(buf[0..n]);
    try std_.testing.expectEqual(frame.FrameType.goaway, hdr.frame_type);
    const payload_start = hdr.header_len;
    const stream_id = try frame.parseGoaway(buf[payload_start .. payload_start + @as(usize, @intCast(hdr.payload_len))]);
    try std_.testing.expectEqual(@as(u64, 99), stream_id);

    try std_.testing.expect(s.isDraining());
    try std_.testing.expect(!s.isClosed());
}

test "Shutdown.initiateShutdown: draining with no in-flight immediately closes" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    var buf: [16]u8 = undefined;
    _ = try s.initiateShutdown(0, &buf);
    // No in-flight requests → immediately closed.
    try std_.testing.expect(s.isClosed());
}

test "Shutdown.requestStarted + requestFinished: tracks in_flight" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    try s.requestStarted();
    try s.requestStarted();
    try std_.testing.expectEqual(@as(usize, 2), s.in_flight);
    s.requestFinished();
    try std_.testing.expectEqual(@as(usize, 1), s.in_flight);
    s.requestFinished();
    try std_.testing.expectEqual(@as(usize, 0), s.in_flight);
}

test "Shutdown.requestFinished: closes when draining and in_flight reaches zero" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    try s.requestStarted(); // in_flight = 1
    var buf: [16]u8 = undefined;
    _ = try s.initiateShutdown(0, &buf); // draining, in_flight=1 → NOT closed yet
    try std_.testing.expect(s.isDraining());
    try std_.testing.expect(!s.isClosed());

    s.requestFinished(); // in_flight = 0 → closed
    try std_.testing.expect(s.isClosed());
}

test "Shutdown.initiateShutdown: two-phase shutdown (decreasing last_stream_id)" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    try s.requestStarted(); // keep alive so it doesn't close immediately
    var buf: [16]u8 = undefined;

    // First GOAWAY: warn with large ID.
    _ = try s.initiateShutdown(1_000_000, &buf);
    try std_.testing.expectEqual(@as(u64, 1_000_000), s.last_stream_id);

    // Second GOAWAY: refined smaller ID — allowed.
    _ = try s.initiateShutdown(42, &buf);
    try std_.testing.expectEqual(@as(u64, 42), s.last_stream_id);
}

test "Shutdown.initiateShutdown: increasing last_stream_id returns error" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    try s.requestStarted();
    var buf: [16]u8 = undefined;
    _ = try s.initiateShutdown(42, &buf);
    try std_.testing.expectError(error.LastStreamIdIncreased, s.initiateShutdown(100, &buf));
}

test "Shutdown.initiateShutdown: closed state returns error" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    var buf: [16]u8 = undefined;
    _ = try s.initiateShutdown(0, &buf); // closes immediately (no in-flight)
    try std_.testing.expect(s.isClosed());
    try std_.testing.expectError(error.InvalidState, s.initiateShutdown(0, &buf));
}

test "Shutdown.requestStarted: draining returns error.InvalidState" {
    const std_ = @import("std");
    var s: Shutdown = .{};
    try s.requestStarted();
    var buf: [16]u8 = undefined;
    _ = try s.initiateShutdown(0, &buf);
    try std_.testing.expectError(error.InvalidState, s.requestStarted());
}
