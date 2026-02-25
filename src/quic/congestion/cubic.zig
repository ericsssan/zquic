//! CUBIC congestion control (RFC 9438).
//!
//! Implements the core CUBIC window growth formula:
//!   W_cubic(t) = C × (t - K)³ + W_max
//! where t is time since the last reduction, K is the inflection point, and
//! C = 0.4.

const std = @import("std");

const C: f64 = 0.4;
const BETA_CUBIC: f64 = 0.7;
const INITIAL_CWND_PACKETS: u64 = 10;
const MSS: u64 = 1200; // Max segment size in bytes

pub const Cubic = struct {
    /// Congestion window in bytes.
    cwnd: u64,
    /// Slow-start threshold in bytes.
    ssthresh: u64,
    /// W_max: window at the last congestion event (bytes, as float for formula).
    w_max: f64,
    /// Epoch start timestamp (ns). 0 means not in a cubic epoch.
    epoch_start_ns: i64,
    /// K: time to reach W_max from cwnd_at_epoch (seconds).
    k: f64,
    /// cwnd at start of current epoch.
    cwnd_at_epoch: f64,

    pub fn init() Cubic {
        return .{
            .cwnd = INITIAL_CWND_PACKETS * MSS,
            .ssthresh = std.math.maxInt(u64),
            .w_max = 0,
            .epoch_start_ns = 0,
            .k = 0,
            .cwnd_at_epoch = 0,
        };
    }

    /// True when the congestion window allows sending.
    pub fn canSend(self: *const Cubic) bool {
        return self.cwnd > 0;
    }

    /// Called when an ACK is received.
    /// `bytes_acked` — bytes acknowledged.
    /// `rtt_ns`      — smoothed RTT in nanoseconds.
    /// `now_ns`      — current time in nanoseconds.
    pub fn onAckReceived(self: *Cubic, bytes_acked: u64, rtt_ns: u64, now_ns: i64) void {
        if (self.cwnd < self.ssthresh) {
            // Slow start
            self.cwnd += bytes_acked;
        } else {
            self.updateCwndCubic(bytes_acked, rtt_ns, now_ns);
        }
    }

    /// Called on packet loss (e.g., timeout or three duplicate ACKs).
    /// `now_ns` — current time in nanoseconds.
    pub fn onPacketLost(self: *Cubic, now_ns: i64) void {
        self.w_max = @floatFromInt(self.cwnd);
        self.cwnd = @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA_CUBIC);
        if (self.cwnd < MSS) self.cwnd = MSS;
        self.ssthresh = self.cwnd;
        self.epoch_start_ns = now_ns;
        self.cwnd_at_epoch = @floatFromInt(self.cwnd);
        self.k = computeK(self.w_max, self.cwnd_at_epoch);
    }

    fn updateCwndCubic(self: *Cubic, bytes_acked: u64, rtt_ns: u64, now_ns: i64) void {
        if (self.epoch_start_ns == 0) {
            self.epoch_start_ns = now_ns;
            self.cwnd_at_epoch = @floatFromInt(self.cwnd);
            if (self.w_max < self.cwnd_at_epoch) {
                self.w_max = self.cwnd_at_epoch;
                self.k = 0;
            } else {
                self.k = computeK(self.w_max, self.cwnd_at_epoch);
            }
        }

        const t_ns = now_ns - self.epoch_start_ns;
        const t_s: f64 = @as(f64, @floatFromInt(t_ns)) / 1e9;

        const w_cubic = cubicWindow(t_s, self.k, self.w_max);
        // TCP-friendly comparison
        const rtt_s: f64 = @as(f64, @floatFromInt(rtt_ns)) / 1e9;
        const w_est = tcpFriendlyWindow(bytes_acked, rtt_s);

        const target = @max(w_cubic, w_est);
        const target_bytes: u64 = @intFromFloat(@max(target, 0));

        if (target_bytes > self.cwnd) {
            // Increase towards target over one RTT
            const inc = (target_bytes - self.cwnd) * MSS / self.cwnd;
            self.cwnd += @max(inc, 1);
        }
    }
};

fn computeK(w_max: f64, cwnd: f64) f64 {
    const diff = (w_max - cwnd) / C;
    return std.math.cbrt(diff);
}

fn cubicWindow(t: f64, k: f64, w_max: f64) f64 {
    const dt = t - k;
    return C * dt * dt * dt + w_max;
}

fn tcpFriendlyWindow(bytes_acked: u64, rtt: f64) f64 {
    // W_est grows like TCP Reno: W_est += 3*beta/(2-beta) * (acked/cwnd)
    // Simplified: track linear growth
    if (rtt <= 0) return 0;
    const acked_f: f64 = @floatFromInt(bytes_acked);
    return acked_f * 3.0 * BETA_CUBIC / (2.0 - BETA_CUBIC);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "cubic: slow start doubles" {
    const testing = std.testing;
    var c = Cubic.init();
    const initial = c.cwnd;
    c.onAckReceived(initial, 10_000_000, 0);
    try testing.expect(c.cwnd >= initial);
}

test "cubic: loss reduces window" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 100 * MSS;
    const before = c.cwnd;
    c.onPacketLost(1_000_000_000);
    try testing.expect(c.cwnd < before);
    try testing.expectEqual(c.cwnd, c.ssthresh);
}

test "cubic: cwnd grows after loss" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 50 * MSS;
    c.onPacketLost(0);
    const after_loss = c.cwnd;
    const rtt_ns: u64 = 50_000_000; // 50ms
    // Simulate several ACK events
    var t: i64 = 100_000_000;
    var i: usize = 0;
    while (i < 10) : (i += 1) {
        c.onAckReceived(MSS, rtt_ns, t);
        t += @intCast(rtt_ns);
    }
    try testing.expect(c.cwnd >= after_loss);
}

test "cubic: canSend" {
    var c = Cubic.init();
    const testing = std.testing;
    try testing.expect(c.canSend());
    c.cwnd = 0;
    try testing.expect(!c.canSend());
}

test "cubic: onAckReceived with zero bytes is a no-op" {
    const testing = std.testing;
    var c = Cubic.init();
    const before = c.cwnd;
    c.onAckReceived(0, 50_000_000, 1_000_000_000);
    try testing.expectEqual(before, c.cwnd);
}

test "cubic: slow start adds bytes_acked directly to cwnd" {
    const testing = std.testing;
    var c = Cubic.init();
    // ssthresh = maxInt(u64) by default — we are in slow start
    const initial = c.cwnd;
    c.onAckReceived(MSS, 50_000_000, 1_000_000_000);
    try testing.expectEqual(initial + MSS, c.cwnd);
    c.onAckReceived(2 * MSS, 50_000_000, 1_050_000_000);
    try testing.expectEqual(initial + 3 * MSS, c.cwnd);
}

test "cubic: loss reduction is exactly BETA_CUBIC * cwnd" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 10 * MSS; // 12000 bytes
    c.onPacketLost(0);
    // Expected: floor(12000 * 0.7) = 8400
    try testing.expectEqual(@as(u64, 8400), c.cwnd);
    try testing.expectEqual(c.cwnd, c.ssthresh);
    try testing.expectEqual(@as(f64, 12000.0), c.w_max);
}
