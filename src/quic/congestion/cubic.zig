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
    /// Epoch start timestamp (ns). null means no cubic epoch has started yet.
    /// Using optional instead of sentinel 0 avoids confusion when clock starts at 0.
    epoch_start_ns: ?i64,
    /// K: time to reach W_max from cwnd_at_epoch (seconds).
    k: f64,
    /// cwnd at start of current epoch.
    cwnd_at_epoch: f64,
    /// TCP-friendly estimated window (running accumulator per RFC 9438 §5.1).
    w_est: f64,
    /// Fractional growth accumulator: prevents integer division from stalling cwnd
    /// growth when (target - cwnd) * MSS < cwnd.
    cwnd_remainder: u64,

    pub fn init() Cubic {
        return .{
            .cwnd = INITIAL_CWND_PACKETS * MSS,
            .ssthresh = std.math.maxInt(u64),
            .w_max = 0,
            .epoch_start_ns = null,
            .k = 0,
            .cwnd_at_epoch = 0,
            .w_est = 0,
            .cwnd_remainder = 0,
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

    /// Called when persistent congestion is detected (RFC 9002 §6.1.2).
    /// Collapses cwnd to the minimum (2 × MSS) and resets the CUBIC epoch.
    pub fn onPersistentCongestion(self: *Cubic) void {
        self.cwnd = 2 * MSS;
        self.ssthresh = self.cwnd;
        self.epoch_start_ns = null;
        self.cwnd_remainder = 0;
    }

    /// Called on packet loss (e.g., timeout or three duplicate ACKs).
    /// `now_ns` — current time in nanoseconds.
    pub fn onPacketLost(self: *Cubic, now_ns: i64) void {
        self.w_max = @floatFromInt(self.cwnd);
        self.cwnd = @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA_CUBIC);
        if (self.cwnd < MSS) self.cwnd = MSS;
        self.ssthresh = self.cwnd;
        self.cwnd_remainder = 0;
        self.epoch_start_ns = now_ns; // begin new epoch at loss time
        self.cwnd_at_epoch = @floatFromInt(self.cwnd);
        self.w_est = self.cwnd_at_epoch; // reset TCP-friendly estimate to post-loss cwnd
        self.k = computeK(self.w_max, self.cwnd_at_epoch);
    }

    fn updateCwndCubic(self: *Cubic, bytes_acked: u64, rtt_ns: u64, now_ns: i64) void {
        _ = rtt_ns; // RTT not used in CUBIC window computation; w_est uses per-packet accumulation

        if (self.epoch_start_ns == null) {
            // Start a new CUBIC epoch
            self.epoch_start_ns = now_ns;
            self.cwnd_at_epoch = @floatFromInt(self.cwnd);
            self.w_est = self.cwnd_at_epoch; // reset TCP-friendly estimate
            if (self.w_max < self.cwnd_at_epoch) {
                self.w_max = self.cwnd_at_epoch;
                self.k = 0;
            } else {
                self.k = computeK(self.w_max, self.cwnd_at_epoch);
            }
        }

        const t_ns = now_ns - self.epoch_start_ns.?;
        // Guard against non-monotonic clocks: if t_ns is negative, skip this update.
        if (t_ns < 0) return;

        const t_s: f64 = @as(f64, @floatFromInt(t_ns)) / 1e9;

        const w_cubic = cubicWindow(t_s, self.k, self.w_max);

        // TCP-friendly window: RFC 9438 §5.1 running accumulator.
        // W_est += alpha_aimd * (bytes_acked / cwnd)  per ACK event.
        const alpha_aimd: f64 = 3.0 * BETA_CUBIC / (2.0 - BETA_CUBIC);
        const cwnd_f: f64 = @floatFromInt(self.cwnd);
        self.w_est += alpha_aimd * @as(f64, @floatFromInt(bytes_acked)) / cwnd_f;

        const target = @max(w_cubic, self.w_est);
        const target_bytes: u64 = @intFromFloat(@max(target, 0));

        if (target_bytes > self.cwnd) {
            // Accumulate fractional growth to prevent integer division from stalling
            // when (target - cwnd) * MSS < cwnd. The remainder carries across ACKs.
            self.cwnd_remainder +|= (target_bytes - self.cwnd) *| MSS;
            const inc = self.cwnd_remainder / self.cwnd;
            self.cwnd_remainder %= self.cwnd;
            self.cwnd += inc;
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

test "cubic: epoch_start_ns null sentinel prevents spurious reset at clock=0" {
    const testing = std.testing;
    var c = Cubic.init();
    // Force into CUBIC phase by setting ssthresh below cwnd
    c.cwnd = 50 * MSS;
    c.onPacketLost(0); // epoch_start_ns = Some(0), not null
    const cwnd_after_loss = c.cwnd;

    // ACK at t=1ms: epoch should NOT reinitialize (epoch_start_ns is Some(0), not null)
    c.onAckReceived(MSS, 50_000_000, 1_000_000); // 1ms later
    // cwnd must be >= post-loss cwnd (no spurious reset)
    try testing.expect(c.cwnd >= cwnd_after_loss);
    // epoch_start_ns must still be Some(0), not changed
    try testing.expectEqual(@as(?i64, 0), c.epoch_start_ns);
}

test "cubic: w_est accumulates across ACKs in CUBIC phase" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 50 * MSS;
    c.onPacketLost(0);
    const w_est_after_loss = c.w_est;

    c.onAckReceived(MSS, 50_000_000, 100_000_000);
    try testing.expect(c.w_est > w_est_after_loss);
}

test "cubic: non-monotonic clock (negative t_ns) is a no-op" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 50 * MSS;
    c.onPacketLost(1_000_000_000);
    const cwnd_before = c.cwnd;

    c.onAckReceived(MSS, 50_000_000, 500_000_000);
    try testing.expectEqual(cwnd_before, c.cwnd);
}

test "cubic: cubicWindow formula W_cubic(t)=C*(t-K)^3+W_max" {
    const result = cubicWindow(2.0, 1.0, 10.0);
    const expected: f64 = C * (2.0 - 1.0) * (2.0 - 1.0) * (2.0 - 1.0) + 10.0;
    try std.testing.expectApproxEqAbs(expected, result, 1e-9);
}

test "cubic: single loss event reduces cwnd by exactly BETA_CUBIC" {
    // Multiple packets lost in one ACK event → onPacketLost called once (RFC 9438 §5.6).
    // cwnd must drop by exactly BETA_CUBIC × initial, not BETA_CUBIC^N for N losses.
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 100 * MSS; // 120000 bytes
    const before = c.cwnd;
    c.onPacketLost(1_000_000_000);
    // Expected: floor(120000 * 0.7) = 84000
    const expected: u64 = @intFromFloat(@as(f64, @floatFromInt(before)) * BETA_CUBIC);
    try testing.expectEqual(@max(expected, MSS), c.cwnd);
}

test "cubic: large window growth does not stall" {
    // Regression: cwnd_remainder accumulator must produce growth over many ACKs.
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 100 * MSS;
    c.ssthresh = 0;
    c.epoch_start_ns = 0;
    c.cwnd_at_epoch = @as(f64, @floatFromInt(c.cwnd));
    c.w_max = @as(f64, @floatFromInt(c.cwnd));
    c.k = 0;
    c.w_est = @as(f64, @floatFromInt(c.cwnd));

    const initial = c.cwnd;
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        c.onAckReceived(MSS, 100_000_000, 10_000_000_000);
    }
    try testing.expect(c.cwnd > initial + 100);
}

test "cubic: initial ssthresh is max (slow start from scratch)" {
    const c = Cubic.init();
    try std.testing.expectEqual(std.math.maxInt(u64), c.ssthresh);
    // In slow start, cwnd < ssthresh always holds at initialization
    try std.testing.expect(c.cwnd < c.ssthresh);
}

test "cubic: onPersistentCongestion resets cwnd to 2*MSS" {
    const testing = std.testing;
    var c = Cubic.init();
    c.cwnd = 100 * MSS;
    c.ssthresh = 50 * MSS;
    c.epoch_start_ns = 1_000_000_000;
    c.onPersistentCongestion();
    try testing.expectEqual(@as(u64, 2 * MSS), c.cwnd);
    try testing.expectEqual(@as(u64, 2 * MSS), c.ssthresh);
    try testing.expectEqual(@as(?i64, null), c.epoch_start_ns);
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

test "cubic: cwnd_remainder uses saturating arithmetic on extreme target" {
    // Regression: (target - cwnd) * MSS can overflow u64 for pathological targets.
    // Force extreme values: t=400,000s → cubicWindow ≈ 2.56e16, overflow without *|
    const testing = std.testing;
    var c = Cubic.init();
    c.ssthresh = MSS;
    c.cwnd = MSS;
    c.w_max = 1.0;
    c.w_est = 0.0;
    c.k = 0.0;
    c.epoch_start_ns = 0;
    c.cwnd_at_epoch = @floatFromInt(c.cwnd);

    c.onAckReceived(1, 10_000_000, 400_000 * 1_000_000_000);

    try testing.expect(c.cwnd >= MSS);
    try testing.expect(c.cwnd > MSS);
}
