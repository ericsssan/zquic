//! Per-connection and per-stream flow control (RFC 9000 §4).

const std = @import("std");

pub const DEFAULT_MAX_DATA: u64 = 1024 * 1024; // 1 MiB
pub const DEFAULT_MAX_STREAM_DATA: u64 = 256 * 1024; // 256 KiB
pub const FlowController = struct {
    /// Maximum bytes the remote is allowed to send to us (receive window).
    recv_max: u64,
    /// Total bytes received so far.
    recv_total: u64,
    /// Maximum bytes we are allowed to send (send window set by remote).
    send_max: u64,
    /// Total bytes sent so far.
    send_total: u64,

    pub fn init(recv_max: u64, send_max: u64) FlowController {
        return .{
            .recv_max = recv_max,
            .recv_total = 0,
            .send_max = send_max,
            .send_total = 0,
        };
    }

    /// True when we can send `bytes` more bytes.
    pub fn canSend(self: *const FlowController, bytes: u64) bool {
        return self.send_total + bytes <= self.send_max;
    }

    /// True when receiving `bytes` more bytes would not exceed the receive window.
    pub fn canReceive(self: *const FlowController, bytes: u64) bool {
        return self.recv_total + bytes <= self.recv_max;
    }

    /// Record that we sent `bytes`.
    pub fn onSent(self: *FlowController, bytes: u64) void {
        self.send_total += bytes;
    }

    /// Record that we received `bytes` from the remote.
    pub fn onReceived(self: *FlowController, bytes: u64) void {
        self.recv_total += bytes;
    }

    /// True when we should emit a MAX_DATA frame to extend the peer's window.
    /// Uses integer arithmetic: recv_total/recv_max >= 3/4 ⟺ recv_total*4 >= recv_max*3.
    /// Safe from overflow because recv_total <= recv_max <= (1<<62)-1,
    /// so *4 stays within u64.
    pub fn shouldSendMaxData(self: *const FlowController) bool {
        if (self.recv_max == 0) return false; // guard: avoid divide-by-zero
        return self.recv_total * 4 >= self.recv_max * 3;
    }

    /// Compute the new MAX_DATA value to advertise (doubles the window).
    /// Saturates at the QUIC maximum varint value (2^62 - 1) to prevent overflow.
    pub fn nextMaxData(self: *const FlowController) u64 {
        const quic_max: u64 = (1 << 62) - 1;
        return @min(self.recv_max *| 2, quic_max);
    }

    /// Update the receive window.
    pub fn updateRecvMax(self: *FlowController, new_max: u64) void {
        if (new_max > self.recv_max) self.recv_max = new_max;
    }

    /// Update the send window (peer sent a MAX_DATA frame).
    pub fn updateSendMax(self: *FlowController, new_max: u64) void {
        if (new_max > self.send_max) self.send_max = new_max;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "flow_control: canSend respects window" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 500);
    try testing.expect(fc.canSend(500));
    try testing.expect(!fc.canSend(501));

    fc.onSent(200);
    try testing.expect(fc.canSend(300));
    try testing.expect(!fc.canSend(301));
}

test "flow_control: shouldSendMaxData threshold" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 1_000);
    fc.onReceived(750);
    try testing.expect(fc.shouldSendMaxData());

    var fc2 = FlowController.init(1_000, 1_000);
    fc2.onReceived(700);
    try testing.expect(!fc2.shouldSendMaxData());
}

test "flow_control: updateRecvMax ignores shrink" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 500);
    fc.updateRecvMax(500); // smaller → ignored
    try testing.expectEqual(@as(u64, 1_000), fc.recv_max);
    fc.updateRecvMax(2_000);
    try testing.expectEqual(@as(u64, 2_000), fc.recv_max);
}

test "flow_control: nextMaxData doubles recv window" {
    const testing = std.testing;
    const fc = FlowController.init(1_000, 500);
    try testing.expectEqual(@as(u64, 2_000), fc.nextMaxData());
}

test "flow_control: shouldSendMaxData with recv_max=0 returns false" {
    const testing = std.testing;
    var fc = FlowController.init(0, 0);
    fc.recv_total = 0;
    // Must not divide by zero
    try testing.expect(!fc.shouldSendMaxData());
}

test "flow_control: nextMaxData saturates at QUIC max varint" {
    const testing = std.testing;
    const quic_max: u64 = (1 << 62) - 1;
    // recv_max near overflow: doubling would exceed u64 max
    const fc = FlowController.init(quic_max, quic_max);
    try testing.expectEqual(quic_max, fc.nextMaxData());
}

test "flow_control: onReceived tracks total bytes received" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 1_000);
    try testing.expectEqual(@as(u64, 0), fc.recv_total);
    fc.onReceived(300);
    try testing.expectEqual(@as(u64, 300), fc.recv_total);
    fc.onReceived(200);
    try testing.expectEqual(@as(u64, 500), fc.recv_total);
    // Threshold not yet reached (50% < 75%)
    try testing.expect(!fc.shouldSendMaxData());
}

test "flow_control: shouldSendMaxData exact 75% boundary (integer arithmetic)" {
    // 75/100 = exactly 3/4: recv_total*4 == recv_max*3 → must trigger
    const testing = std.testing;
    var fc = FlowController.init(100, 100);
    fc.onReceived(75);
    try testing.expect(fc.shouldSendMaxData());

    // 74/100: 74*4=296 < 100*3=300 → must NOT trigger
    var fc2 = FlowController.init(100, 100);
    fc2.onReceived(74);
    try testing.expect(!fc2.shouldSendMaxData());
}

test "flow_control: shouldSendMaxData large-number overflow safety" {
    // recv_max near (1<<62)-1; recv_total*4 must not overflow u64.
    // recv_total = (recv_max * 3) / 4 rounded down → exactly at threshold.
    const testing = std.testing;
    const max: u64 = (1 << 62) - 1; // largest valid QUIC varint
    // max % 4 == 3, so plain (max/4)*3 truncates below 75%.
    // Correct minimum-passing value: ceil(max*3/4) = max*3/4 + 1.
    // max*3 fits in u64 since max < 2^62 → max*3 < 2^63.6 < 2^64.
    var fc = FlowController.init(max, max);
    fc.recv_total = max * 3 / 4 + 1; // ceil(75%): passes threshold
    try testing.expect(fc.shouldSendMaxData());

    // One byte below ceil threshold: must NOT trigger
    var fc2 = FlowController.init(max, max);
    fc2.recv_total = max * 3 / 4; // truncated floor: just below 75%
    try testing.expect(!fc2.shouldSendMaxData());
}

test "flow_control: canReceive respects window" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 500);
    try testing.expect(fc.canReceive(1000));
    try testing.expect(!fc.canReceive(1001));

    fc.onReceived(400);
    try testing.expect(fc.canReceive(600));
    try testing.expect(!fc.canReceive(601));
}

test "flow_control: updateSendMax ignores shrink" {
    const testing = std.testing;
    var fc = FlowController.init(1_000, 500);
    fc.updateSendMax(300); // smaller → ignored
    try testing.expectEqual(@as(u64, 500), fc.send_max);
    fc.updateSendMax(700);
    try testing.expectEqual(@as(u64, 700), fc.send_max);
}
