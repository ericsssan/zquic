//! QUIC stream multiplexing (RFC 9000 §2, §19.8).
//!
//! Stream ID encoding:
//!   bit 0: 0 = client-initiated, 1 = server-initiated
//!   bit 1: 0 = bidirectional,   1 = unidirectional

const std = @import("std");

/// Maximum number of concurrent streams per connection.
/// Must be a power of two (used as hash table capacity).
/// In production, increase this and heap-allocate Connection via Pool(Connection, N).
pub const MAX_STREAMS: usize = 512;
comptime {
    std.debug.assert(MAX_STREAMS > 0 and (MAX_STREAMS & (MAX_STREAMS - 1)) == 0);
}
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
                @memcpy(self.buf[0 .. n - first], data[first..n]);
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
                @memcpy(out[first..n], self.buf[0 .. n - first]);
            }
            self.rp += n;
            return n;
        }

        /// Write data at `rel_offset` from the read pointer without advancing `wp`.
        /// Used by out-of-order reassembly; caller is responsible for advancing wp
        /// once contiguous bytes are determined.
        /// Returns the number of bytes actually written (capped by ring buffer window).
        pub fn writeAt(self: *Self, rel_offset: usize, data: []const u8) usize {
            if (rel_offset >= cap) return 0;
            const available = cap - rel_offset;
            const n = @min(data.len, available);
            if (n == 0) return 0;
            const start = (self.rp + rel_offset) & (cap - 1);
            const first = @min(n, cap - start);
            @memcpy(self.buf[start..][0..first], data[0..first]);
            if (n > first) @memcpy(self.buf[0 .. n - first], data[first..n]);
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
                @memcpy(out[first..n], self.buf[0 .. n - first]);
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

// ---------------------------------------------------------------------------
// Out-of-order reassembly: gap tracking (RFC 9000 §2.2)
// ---------------------------------------------------------------------------

pub const MAX_GAPS: usize = 8;

const Gap = struct {
    start: u64,
    end: u64,
};

/// Fixed-size sorted list of `[start, end)` byte ranges that have NOT yet been
/// received.  When a range is received (`fill`), overlapping gaps are trimmed,
/// split, or removed.  `contiguousFrom` returns how far from a base offset the
/// data stream is contiguous (no gaps).
pub const GapList = struct {
    gaps: [MAX_GAPS]Gap,
    count: usize,
    /// Highest stream offset we know about (highest `end` seen via `fill`).
    /// When `count == 0`, this is the contiguous frontier.
    window_end: u64,

    pub fn init(start: u64, end: u64) GapList {
        var gl = GapList{
            .gaps = undefined,
            .count = 1,
            .window_end = end,
        };
        gl.gaps[0] = .{ .start = start, .end = end };
        return gl;
    }

    /// Mark `[offset, offset+len)` as received.
    /// If `offset` is past the current window end, a gap for the hole is added.
    pub fn fill(self: *GapList, offset: u64, len: usize) void {
        if (len == 0) return;
        const fstart = offset;
        const fend = offset + @as(u64, len);

        // If the new data starts beyond our tracked window, create a gap for the hole.
        if (fstart > self.window_end) {
            if (self.count < MAX_GAPS) {
                self.gaps[self.count] = .{ .start = self.window_end, .end = fstart };
                self.count += 1;
            } else {
                // Too many gaps to track the hole.  Don't advance window_end;
                // the peer will retransmit to fill it.
                return;
            }
        }

        if (fend > self.window_end) self.window_end = fend;

        // Remove/trim gaps overlapping [fstart, fend).
        var i: usize = 0;
        while (i < self.count) {
            const g = &self.gaps[i];
            // No overlap: gap is entirely before or after the fill range.
            if (g.end <= fstart or g.start >= fend) {
                i += 1;
                continue;
            }
            if (fstart <= g.start and fend >= g.end) {
                // Fill covers entire gap → remove it.
                var j: usize = i;
                while (j + 1 < self.count) : (j += 1) {
                    self.gaps[j] = self.gaps[j + 1];
                }
                self.count -= 1;
                // Don't increment i (now points to the next gap after removal).
            } else if (fstart <= g.start and fend < g.end) {
                // Fill trims the start of the gap.
                g.start = fend;
                i += 1;
            } else if (fstart > g.start and fend >= g.end) {
                // Fill trims the end of the gap.
                g.end = fstart;
                i += 1;
            } else {
                // fstart > g.start and fend < g.end → split gap into two.
                if (self.count < MAX_GAPS) {
                    // Shift gaps right to make room for the trailing fragment.
                    var j: usize = self.count;
                    while (j > i + 1) : (j -= 1) {
                        self.gaps[j] = self.gaps[j - 1];
                    }
                    self.gaps[i + 1] = .{ .start = fend, .end = g.end };
                    g.end = fstart;
                    self.count += 1;
                    i += 2;
                } else {
                    // Can't split: drop the trailing fragment (peer retransmits).
                    g.end = fstart;
                    i += 1;
                }
            }
        }
    }

    /// Return the highest stream offset reachable from `base` without a gap.
    /// - If a gap starts at `base`, returns `base` (no progress).
    /// - If the first gap starts after `base`, returns that gap's start.
    /// - If no gaps remain, returns `window_end` (all received).
    pub fn contiguousFrom(self: *const GapList, base: u64) u64 {
        if (self.count == 0) return self.window_end;
        for (self.gaps[0..self.count]) |g| {
            if (g.start <= base and base < g.end) return base; // gap at base
            if (g.start > base) return g.start; // gap after base
        }
        return self.window_end; // all gaps are before base
    }
};

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
    /// Byte offset at which the remote sent FIN; null until FIN received.
    /// State transition is deferred until recv_offset reaches this value.
    fin_recv_offset: ?u64,
    /// Last recv_max value advertised to the peer via MAX_STREAM_DATA.
    /// When recv_max grows beyond this, a new MAX_STREAM_DATA frame is needed.
    last_sent_max_stream_data: u64,
    /// Gap list for out-of-order reassembly (RFC 9000 §2.2).
    /// Tracks missing byte ranges within the current receive window.
    gap_list: GapList,

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
            .fin_recv_offset = null,
            .last_sent_max_stream_data = STREAM_BUF_SIZE,
            .gap_list = GapList.init(0, STREAM_BUF_SIZE),
        };
    }

    pub fn isReadable(self: *const Stream) bool {
        return self.recv_buf.readable() > 0;
    }

    pub fn canSend(self: *const Stream, bytes: u64) bool {
        if (self.state == .half_closed_local or
            self.state == .closed or
            self.state == .reset) return false;
        // Use checked addition to prevent wrap-around bypassing flow control.
        const end = std.math.add(u64, self.send_offset, bytes) catch return false;
        return end <= self.send_max;
    }

    /// Buffer incoming data. Supports out-of-order reassembly via the gap list.
    /// Returns error if exceeds receive window, write overflows the ring buffer,
    /// or offset + len overflows u64.
    pub fn receiveData(self: *Stream, offset: u64, data: []const u8, fin: bool) !void {
        const end = std.math.add(u64, offset, data.len) catch return error.OffsetOverflow;
        if (end > self.recv_max) return error.FlowControlViolation;

        // RFC 9000 §3.3: once the final size is known, data at or beyond it is an error.
        // Case A: FIN received but not all preceding data yet (fin_recv_offset still set).
        if (self.fin_recv_offset) |fro| {
            if (end > fro) return error.FinalSizeError;
        }
        // Case B: All data delivered and state transitioned (fin_recv_offset cleared).
        // In half_closed_remote/closed, recv_offset == the final size.
        if (self.state == .half_closed_remote or self.state == .closed) {
            if (end > self.recv_offset) return error.FinalSizeError;
        }

        // Record the final byte offset when FIN is received; defer state transition
        // until recv_offset catches up (handles out-of-order FIN).
        if (fin) {
            if (self.fin_recv_offset) |existing| {
                // RFC 9000 §3.3: final size must not change once established.
                if (existing != end) return error.FinalSizeError;
            } else if (self.state == .half_closed_remote or self.state == .closed) {
                // FIN already processed: retransmitted FIN must match recv_offset (final size).
                if (end != self.recv_offset) return error.FinalSizeError;
                // Exact retransmission — fall through to duplicate detection.
            } else {
                // If bytes we already received are beyond this FIN, that's also an error.
                if (self.recv_offset > end) return error.FinalSizeError;
                self.fin_recv_offset = end;
            }
        }

        // Pure duplicate: all data already received.
        if (end <= self.recv_offset) {
            self.checkFinTransition();
            return;
        }

        // Trim leading overlap with already-received bytes.
        const effective_offset: u64 = if (offset < self.recv_offset) self.recv_offset else offset;
        const trim: usize = @intCast(effective_offset - offset);
        const effective_data = data[trim..];

        // Guard: if fill() would bail early (gap list full + data beyond known
        // window), the bytes would be written to the ring buffer but never
        // tracked — permanently unreachable.  Reject up-front instead.
        if (effective_offset > self.gap_list.window_end and
            self.gap_list.count >= MAX_GAPS)
        {
            return error.BufferFull;
        }

        // Write data at the correct position in the ring buffer.
        // rel = offset from rp (bytes the app has already consumed).
        const rel: usize = @intCast(effective_offset - @as(u64, self.recv_buf.rp));
        const written = self.recv_buf.writeAt(rel, effective_data);
        if (written < effective_data.len) return error.BufferFull;

        // Update the gap list to reflect the newly received range.
        self.gap_list.fill(effective_offset, effective_data.len);

        // Advance recv_offset to the new contiguous frontier and expose the
        // newly contiguous bytes to the reader by advancing recv_buf.wp.
        const new_recv_offset = self.gap_list.contiguousFrom(self.recv_offset);
        if (new_recv_offset > self.recv_offset) {
            const advance: usize = @intCast(new_recv_offset - self.recv_offset);
            self.recv_buf.wp += advance;
            self.recv_offset = new_recv_offset;
        }

        self.checkFinTransition();
    }

    /// Attempt to transition state when all bytes up to the FIN offset have arrived.
    fn checkFinTransition(self: *Stream) void {
        if (self.fin_recv_offset) |fro| {
            if (self.recv_offset >= fro) {
                if (self.state == .half_closed_local) {
                    self.state = .closed;
                } else {
                    self.state = .half_closed_remote;
                }
                self.fin_recv_offset = null;
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

    /// True when recv_max has grown beyond what we last advertised to the peer.
    /// The connection layer should send a MAX_STREAM_DATA frame when this returns true.
    pub fn shouldSendMaxStreamData(self: *const Stream) bool {
        return self.recv_max > self.last_sent_max_stream_data;
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

    /// Free space remaining in the send buffer.
    pub fn sendBufferFree(self: *const Stream) usize {
        return self.send_buf.writable();
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
        // RFC 9000 §3.3: if the FIN offset was already established (stream in
        // "Size Known" state), the reset final_size must agree with it exactly.
        if (self.fin_recv_offset) |fro| {
            if (@as(u64, final_size) != fro) return error.FinalSizeError;
        }
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
// Stream table — open-addressing hash map, O(1) amortised lookup.
// ---------------------------------------------------------------------------

const SlotState = enum(u8) { empty, occupied, tombstone };

/// Pre-allocated hash table for concurrent streams on a single connection.
/// Uses linear probing with tombstone deletion; capacity is MAX_STREAMS.
/// Hash: id & (MAX_STREAMS - 1) — works well because QUIC stream IDs increment
/// by 4 (bits 0-1 encode direction/kind), so consecutive IDs map to distinct slots.
/// No allocator needed: all memory is inline in the Connection struct.
pub const StreamTable = struct {
    streams: [MAX_STREAMS]Stream = undefined,
    ids: [MAX_STREAMS]u62 = undefined,
    states: [MAX_STREAMS]SlotState = [_]SlotState{.empty} ** MAX_STREAMS,
    count: usize = 0,

    /// Return true if slot i holds a live stream.
    pub fn occupied(self: *const StreamTable, i: usize) bool {
        return self.states[i] == .occupied;
    }

    /// Open or retrieve a stream by ID.
    /// Returns null only when all MAX_STREAMS slots are simultaneously active.
    pub fn getOrCreate(self: *StreamTable, id: u62) ?*Stream {
        if (self.count >= MAX_STREAMS) return null;
        const mask = MAX_STREAMS - 1;
        const start: usize = @as(usize, @intCast(id)) & mask;
        var first_tombstone: ?usize = null;
        var probe: usize = 0;
        while (probe < MAX_STREAMS) : (probe += 1) {
            const i = (start + probe) & mask;
            switch (self.states[i]) {
                .occupied => {
                    if (self.ids[i] == id) return &self.streams[i];
                },
                .tombstone => {
                    if (first_tombstone == null) first_tombstone = i;
                },
                .empty => {
                    // ID not present; insert at first tombstone (recycling) or here.
                    const slot = first_tombstone orelse i;
                    self.ids[slot] = id;
                    self.streams[slot] = Stream.init(id);
                    self.states[slot] = .occupied;
                    self.count += 1;
                    return &self.streams[slot];
                },
            }
        }
        // No empty slot — table is tombstone-saturated but count < MAX_STREAMS.
        if (first_tombstone) |slot| {
            self.ids[slot] = id;
            self.streams[slot] = Stream.init(id);
            self.states[slot] = .occupied;
            self.count += 1;
            return &self.streams[slot];
        }
        return null;
    }

    pub fn get(self: *StreamTable, id: u62) ?*Stream {
        const mask = MAX_STREAMS - 1;
        const start: usize = @as(usize, @intCast(id)) & mask;
        var probe: usize = 0;
        while (probe < MAX_STREAMS) : (probe += 1) {
            const i = (start + probe) & mask;
            switch (self.states[i]) {
                .occupied => {
                    if (self.ids[i] == id) return &self.streams[i];
                },
                .tombstone => {}, // keep probing
                .empty => return null, // id cannot be past an empty slot
            }
        }
        return null;
    }

    pub fn close(self: *StreamTable, id: u62) void {
        const mask = MAX_STREAMS - 1;
        const start: usize = @as(usize, @intCast(id)) & mask;
        var probe: usize = 0;
        while (probe < MAX_STREAMS) : (probe += 1) {
            const i = (start + probe) & mask;
            switch (self.states[i]) {
                .occupied => {
                    if (self.ids[i] == id) {
                        self.states[i] = .tombstone;
                        self.count -= 1;
                        return;
                    }
                },
                .tombstone => {}, // keep probing
                .empty => return, // not found
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
    try testing.expectEqual(StreamKind.bidirectional, streamKind(0));
    try testing.expectEqual(StreamDir.server_initiated, streamDir(1)); // 0b01
    try testing.expectEqual(StreamKind.bidirectional, streamKind(1));
    try testing.expectEqual(StreamDir.client_initiated, streamDir(2)); // 0b10
    try testing.expectEqual(StreamKind.unidirectional, streamKind(2));
    try testing.expectEqual(StreamDir.server_initiated, streamDir(3)); // 0b11
    try testing.expectEqual(StreamKind.unidirectional, streamKind(3));
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

test "stream: out-of-order receive and reassembly" {
    const testing = std.testing;
    var s = Stream.init(0);
    // Data at offset 5 arrives before offset 0 — buffered, not dropped.
    try s.receiveData(5, "world", false);
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    // No contiguous bytes yet (gap at [0, 5)).
    try testing.expectEqual(@as(usize, 0), n);
    // Fill the gap: now [0, 10) is contiguous.
    try s.receiveData(0, "hello", false);
    const n2 = s.read(&buf);
    try testing.expectEqual(@as(usize, 10), n2);
    try testing.expectEqualSlices(u8, "helloworld", buf[0..n2]);
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
    // offset near u64 max: offset + data.len would overflow — must return OffsetOverflow
    var s = Stream.init(0);
    s.recv_max = std.math.maxInt(u64);
    const err = s.receiveData(std.math.maxInt(u64) - 2, "hello", false);
    try std.testing.expectError(error.OffsetOverflow, err);
}

test "stream: out-of-order FIN does not prematurely close" {
    // FIN arrives with a future offset before the gap data arrives.
    // Stream state must remain open until recv_offset catches up.
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;

    // FIN at offset=10 with 5 bytes of data (bytes 10-14), but recv_offset=0.
    // Data is buffered; gap [0, 10) prevents recv_offset from advancing.
    try s.receiveData(10, "hello", true);
    try testing.expectEqual(StreamState.open, s.state);
    try testing.expectEqual(@as(u64, 0), s.recv_offset);
}

test "stream: FIN applied when recv_offset catches up" {
    // After the gap is filled, state must transition to half_closed_remote.
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;

    // FIN at offset=5 (10 bytes total: "world" at [5,10)), arrives out of order first.
    try s.receiveData(5, "world", true);
    try testing.expectEqual(StreamState.open, s.state); // gap [0,5) prevents advance

    // Fill the gap: [0,10) becomes fully contiguous.
    try s.receiveData(0, "hello", false);
    // recv_offset jumps to 10 (= fin_recv_offset=10) → state transitions immediately.
    try testing.expectEqual(StreamState.half_closed_remote, s.state);
    try testing.expectEqual(@as(u64, 10), s.recv_offset);

    // All 10 bytes are now readable: "helloworld".
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 10), n);
    try testing.expectEqualSlices(u8, "helloworld", buf[0..n]);
}

test "stream: in-order FIN still works" {
    // When FIN arrives in order with data, state transitions immediately.
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;

    try s.receiveData(0, "hello", true);
    try testing.expectEqual(StreamState.half_closed_remote, s.state);
    try testing.expectEqual(@as(u64, 5), s.recv_offset);
}

test "ringbuf: two-segment write and read crossing wrap boundary" {
    const testing = std.testing;
    var rb: RingBuf(8) = .{};
    _ = rb.write("abcdef");
    var sink: [5]u8 = undefined;
    _ = rb.read(&sink);

    const written = rb.write("WXYZ");
    try testing.expectEqual(@as(usize, 4), written);

    var out: [5]u8 = undefined;
    const n = rb.read(&out);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "fWXYZ", out[0..n]);
}

test "ringbuf: two-segment peek crossing wrap boundary" {
    const testing = std.testing;
    var rb: RingBuf(8) = .{};
    _ = rb.write("abcdef");
    var sink: [5]u8 = undefined;
    _ = rb.read(&sink);
    _ = rb.write("WXYZ");

    var p1: [3]u8 = undefined;
    const n1 = rb.peek(0, &p1);
    try testing.expectEqual(@as(usize, 3), n1);
    try testing.expectEqualSlices(u8, "fWX", p1[0..n1]);

    var p2: [2]u8 = undefined;
    const n2 = rb.peek(3, &p2); // should yield "YZ"
    try testing.expectEqual(@as(usize, 2), n2);
    try testing.expectEqualSlices(u8, "YZ", p2[0..n2]);

    // rp must be unchanged
    try testing.expectEqual(@as(usize, 5), rb.readable());
}

test "stream_table: getOrCreate after close still finds correct stream" {
    // Verify that a stream closed (tombstone) does not block retrieval of others.
    const testing = std.testing;
    var table: StreamTable = .{};
    _ = table.getOrCreate(10);
    _ = table.getOrCreate(20);
    _ = table.getOrCreate(30);
    table.close(20); // tombstone at 20's slot

    // New ID must be created successfully and be retrievable.
    const s = table.getOrCreate(99).?;
    try testing.expectEqual(@as(u62, 99), s.id);
    const s2 = table.get(99).?;
    try testing.expectEqual(@as(u62, 99), s2.id);
    // Previous streams still accessible.
    try testing.expect(table.get(10) != null);
    try testing.expect(table.get(30) != null);
    // Closed stream is gone.
    try testing.expect(table.get(20) == null);
}

test "stream_table: tombstone slot is recycled on insert" {
    // Tombstone recycling: inserting an id that hashes to the same bucket as a
    // tombstone should reuse that tombstone slot rather than a later empty slot.
    const testing = std.testing;
    var table: StreamTable = .{};
    // id=0 and id=512 both hash to slot 0 (0 & 511 == 0, 512 & 511 == 0).
    _ = table.getOrCreate(0); // slot 0
    _ = table.getOrCreate(512); // slot 1 (probe past occupied slot 0)
    table.close(0); // slot 0 becomes tombstone; count=1
    // id=1024 also hashes to slot 0: probe 0 (tombstone → record), 1 (id=512≠1024), 2 (empty).
    // Insert at first tombstone (slot 0), not slot 2.
    const s = table.getOrCreate(1024).?;
    try testing.expectEqual(@as(u62, 1024), s.id);
    try testing.expectEqual(&table.streams[0], s);
    try testing.expectEqual(@as(usize, 2), table.count);
}

test "stream_table: reuse after cycling MAX_STREAMS streams" {
    // Open and close MAX_STREAMS streams one at a time; table must stay usable.
    var table: StreamTable = .{};
    var i: u62 = 0;
    while (i < MAX_STREAMS) : (i += 1) {
        const s = table.getOrCreate(i * 4).?;
        _ = s;
        table.close(i * 4);
    }
    try std.testing.expectEqual(@as(usize, 0), table.count);
    // Table has tombstones but no occupied slots; must accept a new stream.
    const s = table.getOrCreate(9999).?;
    try std.testing.expectEqual(@as(u62, 9999), s.id);
    try std.testing.expectEqual(@as(usize, 1), table.count);
}

test "stream: receiveData exact-boundary: offset + len == u64 max is not overflow" {
    // offset + len == u64 max exactly (no overflow) — verified as OffsetOverflow-safe.
    // Data is astronomically far from the ring buffer window → BufferFull (not OffsetOverflow).
    var s = Stream.init(0);
    s.recv_max = std.math.maxInt(u64);
    const offset: u64 = std.math.maxInt(u64) - 4;
    const data = [_]u8{ 1, 2, 3, 4 }; // len=4; offset+4 == u64 max (no overflow)
    // rel = offset - recv_buf.rp(0) = u64 max - 4 >> cap(4096) → writeAt returns 0 → BufferFull.
    try std.testing.expectError(error.BufferFull, s.receiveData(offset, &data, false));
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

test "stream: canSend returns false in half_closed_local state" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.sendFin(); // transitions to half_closed_local
    try testing.expectEqual(StreamState.half_closed_local, s.state);
    try testing.expect(!s.canSend(1));
}

test "stream: canSend returns false in closed state" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.sendFin(); // half_closed_local
    // Simulate receiving FIN → closed
    try s.receiveData(0, &.{}, true); // fin on recv side → half_closed_remote then closed
    try testing.expectEqual(StreamState.closed, s.state);
    try testing.expect(!s.canSend(1));
}

test "stream: canSend returns false in reset state" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.initiateReset(0);
    try testing.expectEqual(StreamState.reset, s.state);
    try testing.expect(!s.canSend(1));
}

test "stream: canSend returns false when window exhausted" {
    const testing = std.testing;
    var s = Stream.init(0);
    // send_max = STREAM_BUF_SIZE = 4096, send_offset = 0
    // Asking for exactly send_max is fine (0 + 4096 <= 4096)
    try testing.expect(s.canSend(STREAM_BUF_SIZE));
    // Asking for one more byte exceeds window
    try testing.expect(!s.canSend(STREAM_BUF_SIZE + 1));
}

test "stream: onAcked with non-consecutive offset is a no-op" {
    const testing = std.testing;
    var s = Stream.init(0);
    const data = [_]u8{ 1, 2, 3, 4, 5, 6, 7, 8 };
    _ = s.bufferSendData(&data);
    s.onSent(data.len);
    // send_acked = 0, send_offset = 8; ack for offset=4 (non-consecutive) → no-op
    s.onAcked(4, 4);
    try testing.expectEqual(@as(u64, 0), s.send_acked); // must not advance
}

// ---------------------------------------------------------------------------
// New tests — MAX_STREAM_DATA signaling (Step 6)
// ---------------------------------------------------------------------------

test "stream: shouldSendMaxStreamData false initially" {
    const testing = std.testing;
    const s = Stream.init(0);
    // last_sent_max_stream_data = recv_max = STREAM_BUF_SIZE at init
    try testing.expect(!s.shouldSendMaxStreamData());
}

test "stream: shouldSendMaxStreamData true after read advances recv_max" {
    const testing = std.testing;
    var s = Stream.init(0);
    // Receive some data then read it — recv_max grows
    try s.receiveData(0, "hello world", false);
    var buf: [16]u8 = undefined;
    _ = s.read(&buf);
    // recv_max = recv_buf.rp + STREAM_BUF_SIZE = 11 + 4096 > 4096 = last_sent
    try testing.expect(s.shouldSendMaxStreamData());
    // After acknowledging the new max, flag clears
    s.last_sent_max_stream_data = s.recv_max;
    try testing.expect(!s.shouldSendMaxStreamData());
}

// ---------------------------------------------------------------------------
// New tests — Phase 4: writeAt, GapList, out-of-order reassembly
// ---------------------------------------------------------------------------

test "ringbuf: writeAt basic" {
    const testing = std.testing;
    var rb: RingBuf(16) = .{};
    // Write 5 bytes at rel_offset=0 without advancing wp.
    const n = rb.writeAt(0, "hello");
    try testing.expectEqual(@as(usize, 5), n);
    // wp was NOT advanced by writeAt; advance manually.
    rb.wp += 5;
    var buf: [8]u8 = undefined;
    const r = rb.read(&buf);
    try testing.expectEqual(@as(usize, 5), r);
    try testing.expectEqualSlices(u8, "hello", buf[0..r]);
}

test "ringbuf: writeAt fills gap before existing data" {
    const testing = std.testing;
    var rb: RingBuf(16) = .{};
    const n = rb.writeAt(5, "world");
    try testing.expectEqual(@as(usize, 5), n);
    const n2 = rb.writeAt(0, "hello");
    try testing.expectEqual(@as(usize, 5), n2);
    rb.wp += 10;
    var buf: [16]u8 = undefined;
    const r = rb.read(&buf);
    try testing.expectEqual(@as(usize, 10), r);
    try testing.expectEqualSlices(u8, "helloworld", buf[0..r]);
}

test "ringbuf: writeAt with wrap" {
    const testing = std.testing;
    var rb: RingBuf(16) = .{};
    _ = rb.write("0123456789ab");
    var sink: [10]u8 = undefined;
    _ = rb.read(&sink);
    const n = rb.writeAt(2, "UVWXYZ");
    try testing.expectEqual(@as(usize, 6), n);
    rb.wp += 6;

    var buf: [10]u8 = undefined;
    const r = rb.read(&buf);
    try testing.expectEqual(@as(usize, 8), r);
    try testing.expectEqualSlices(u8, "abUVWXYZ", buf[0..r]);
}

test "ringbuf: writeAt beyond cap returns 0" {
    const testing = std.testing;
    var rb: RingBuf(8) = .{};
    const n = rb.writeAt(8, "data");
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(@as(usize, 0), rb.readable());
}

test "gap_list: init creates single gap" {
    const testing = std.testing;
    const gl = GapList.init(0, 4096);
    try testing.expectEqual(@as(usize, 1), gl.count);
    try testing.expectEqual(@as(u64, 0), gl.gaps[0].start);
    try testing.expectEqual(@as(u64, 4096), gl.gaps[0].end);
    try testing.expectEqual(@as(u64, 4096), gl.window_end);
}

test "gap_list: fill removes gap entirely" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(0, 100);
    try testing.expectEqual(@as(usize, 0), gl.count);
    // No gaps → contiguousFrom returns window_end.
    try testing.expectEqual(@as(u64, 100), gl.contiguousFrom(0));
}

test "gap_list: fill trims gap start" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(0, 40);
    try testing.expectEqual(@as(usize, 1), gl.count);
    try testing.expectEqual(@as(u64, 40), gl.gaps[0].start);
    try testing.expectEqual(@as(u64, 100), gl.gaps[0].end);
    try testing.expectEqual(@as(u64, 40), gl.contiguousFrom(0));
}

test "gap_list: fill trims gap end" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(60, 40);
    try testing.expectEqual(@as(usize, 1), gl.count);
    try testing.expectEqual(@as(u64, 0), gl.gaps[0].start);
    try testing.expectEqual(@as(u64, 60), gl.gaps[0].end);
    try testing.expectEqual(@as(u64, 0), gl.contiguousFrom(0));
}

test "gap_list: fill splits gap" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(40, 20);
    try testing.expectEqual(@as(usize, 2), gl.count);
    try testing.expectEqual(@as(u64, 0), gl.gaps[0].start);
    try testing.expectEqual(@as(u64, 40), gl.gaps[0].end);
    try testing.expectEqual(@as(u64, 60), gl.gaps[1].start);
    try testing.expectEqual(@as(u64, 100), gl.gaps[1].end);
    try testing.expectEqual(@as(u64, 0), gl.contiguousFrom(0));
}

test "gap_list: fill overlap across multiple gaps" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(20, 20);
    gl.fill(60, 20);
    try testing.expectEqual(@as(usize, 3), gl.count);
    gl.fill(15, 50);
    try testing.expectEqual(@as(usize, 2), gl.count);
    try testing.expectEqual(@as(u64, 0), gl.gaps[0].start);
    try testing.expectEqual(@as(u64, 15), gl.gaps[0].end);
    try testing.expectEqual(@as(u64, 80), gl.gaps[1].start);
    try testing.expectEqual(@as(u64, 100), gl.gaps[1].end);
}

test "gap_list: contiguousFrom advances past filled gaps" {
    const testing = std.testing;
    var gl = GapList.init(0, 100);
    gl.fill(30, 30);
    try testing.expectEqual(@as(u64, 0), gl.contiguousFrom(0));
    gl.fill(0, 30);
    try testing.expectEqual(@as(u64, 60), gl.contiguousFrom(0));
    gl.fill(60, 40);
    try testing.expectEqual(@as(u64, 100), gl.contiguousFrom(0));
}

test "gap_list: MAX_GAPS overflow drops tail fragment" {
    const testing = std.testing;
    var gl = GapList.init(0, 1000);
    gl.fill(0, 50);
    gl.fill(100, 50);
    gl.fill(200, 50);
    gl.fill(300, 50);
    gl.fill(400, 50);
    gl.fill(500, 50);
    gl.fill(600, 50);
    gl.fill(700, 50);
    try testing.expectEqual(MAX_GAPS, gl.count);
    // Gap end is trimmed to fstart=800 instead of splitting.
    gl.fill(800, 50);
    try testing.expectEqual(MAX_GAPS, gl.count); // still 8, no overflow
    try testing.expectEqual(@as(u64, 800), gl.gaps[MAX_GAPS - 1].end);
}

test "stream: overlapping segments are harmless" {
    const testing = std.testing;
    var s = Stream.init(0);
    try s.receiveData(0, "hello", false);
    try s.receiveData(3, "loXYZ", false);
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 8), n);
    try testing.expectEqualSlices(u8, "helloXYZ", buf[0..n]);
}

test "stream: duplicate segment is harmless" {
    const testing = std.testing;
    var s = Stream.init(0);
    try s.receiveData(0, "hello", false);
    // Exact duplicate — should be a no-op.
    try s.receiveData(0, "hello", false);
    var buf: [16]u8 = undefined;
    const n = s.read(&buf);
    try testing.expectEqual(@as(usize, 5), n);
    try testing.expectEqualSlices(u8, "hello", buf[0..n]);
}

test "stream: FIN with out-of-order data defers transition" {
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;
    try s.receiveData(10, "final", true);
    try testing.expectEqual(StreamState.open, s.state);
    try testing.expectEqual(@as(u64, 0), s.recv_offset);

    try s.receiveData(0, "0123456789", false);
    try testing.expectEqual(StreamState.half_closed_remote, s.state);
    try testing.expectEqual(@as(u64, 15), s.recv_offset);
}

// BUG-2 regression: gap-list saturated + data beyond window_end must not
// write to the ring buffer and leave unreachable (phantom) bytes.
test "stream: gap-list saturated rejects data beyond window (no phantom write)" {
    const testing = std.testing;
    var s = Stream.init(0);
    // Simulate the app consuming 1 000 bytes so rp > 0 and rel < cap.
    s.recv_buf.rp = 1000;
    s.recv_buf.wp = 1000;
    s.recv_offset = 1000;
    // Extend the flow-control window to permit data at offset 3 000.
    s.recv_max = 1000 + STREAM_BUF_SIZE;
    // Fill the gap list to capacity with 8 synthetic gaps all within [0, 1000).
    s.gap_list.count = MAX_GAPS;
    for (0..MAX_GAPS) |i| {
        s.gap_list.gaps[i] = .{
            .start = @as(u64, i) * 128,
            .end = @as(u64, i) * 128 + 64,
        };
    }
    s.gap_list.window_end = 1000;
    // offset=3000: rel = 3000-1000 = 2000 < 4096 (ring buffer slot valid),
    // BUT fill() cannot record the hole [1000, 3000) — count == MAX_GAPS.
    // The fix must reject up-front to prevent phantom bytes in the ring buffer.
    try testing.expectError(error.BufferFull, s.receiveData(3000, "hello", false));
    // Ring buffer must be completely untouched.
    try testing.expectEqual(@as(usize, 0), s.recv_buf.readable());
}

// ---------------------------------------------------------------------------
// RFC 9000 §3.3 final-size enforcement tests
// ---------------------------------------------------------------------------

test "stream: conflicting FIN offsets return FinalSizeError" {
    // FIN at offset 10 (final_size=10) arrives first, then a second FIN at 20.
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;
    try s.receiveData(0, "hello", true); // FIN → final_size = 5
    // Second FIN with different final size must be rejected.
    try testing.expectError(error.FinalSizeError, s.receiveData(0, "hello world", true));
}

test "stream: duplicate FIN at same offset is silently accepted" {
    // Retransmitted FIN with the same final offset must not be an error.
    var s = Stream.init(0);
    s.recv_max = 1024;
    try s.receiveData(0, "hello", true); // FIN → final_size = 5
    // Exact retransmission: same data, same FIN offset.
    try s.receiveData(0, "hello", true); // must succeed
}

test "stream: data beyond established final size returns FinalSizeError" {
    // FIN received at offset 5 (final_size=5). Later data arrives beyond that.
    const testing = std.testing;
    var s = Stream.init(0);
    s.recv_max = 1024;
    try s.receiveData(0, "hello", true); // final_size = 5
    // Data frame ending at offset 7 violates the known final size.
    try testing.expectError(error.FinalSizeError, s.receiveData(3, "xyz", false));
}
