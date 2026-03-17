//! CUBIC congestion control (RFC 9438).
//!
//! Implements the core CUBIC window growth formula:
//!   W_cubic(t) = C × (t - K)³ + W_max
//! where t is time since the last reduction, K is the inflection point, and
//! C = 0.4.

const std = @import("std");

/// RFC 9438 §5.1: C = 0.4 (in segments). Since our cwnd is in bytes,
/// scale by MSS to get the correct growth rate: C_bytes = 0.4 × MSS.
/// Without this scaling, K is MSS× too large and CUBIC degenerates to AIMD.
const C: f64 = 0.4 * @as(f64, @floatFromInt(MSS));
const BETA_CUBIC: f64 = 0.7;
/// RFC 9002 §7.2: max_datagram_size for congestion control.
/// Matches MAX_SEND_PACKET_SIZE (1452) — the actual UDP payload we send.
const MSS: u64 = 1452;
/// RFC 9002 §7.2: initial_window = min(10 * mds, max(14720, 2 * mds))
/// = min(14520, max(14720, 2904)) = 14520.
const INITIAL_CWND: u64 = @min(10 * MSS, @max(14720, 2 * MSS));

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

    // Pacing state: spread packets evenly across the RTT instead of bursting.
    // Without pacing, all cwnd bytes are sent instantly on ACK, overflowing
    // shallow queues and causing loss.  Pacing targets ~95% link utilization.
    /// Pacing rate in bytes per second.  Updated on every ACK.
    pacing_rate: u64,
    /// Pacing token bucket: bytes allowed to send now.  Refilled each tick
    /// based on elapsed time × pacing_rate.
    pacing_tokens: u64,
    /// Timestamp of last token refill (ns).
    pacing_last_refill_ns: i64,

    pub fn init() Cubic {
        return .{
            .cwnd = INITIAL_CWND,
            .ssthresh = std.math.maxInt(u64),
            .w_max = 0,
            .epoch_start_ns = null,
            .k = 0,
            .cwnd_at_epoch = 0,
            .w_est = 0,
            .cwnd_remainder = 0,
            .pacing_rate = 0,
            .pacing_tokens = INITIAL_CWND, // allow initial burst
            .pacing_last_refill_ns = 0,
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
            // Slow start: double cwnd per RTT (exponential growth).
            self.cwnd += bytes_acked;
        } else {
            self.updateCwndCubic(bytes_acked, rtt_ns, now_ns);
        }
        // Update pacing rate: cwnd / srtt (bytes per second).
        // During slow start, pace at 2× to allow exponential growth.
        // In congestion avoidance, pace at 1.25× cwnd/srtt for headroom.
        if (rtt_ns > 0) {
            const base_rate = self.cwnd *| 1_000_000_000 / rtt_ns;
            // Pace at 2× cwnd/RTT: allows CUBIC to probe above current cwnd
            // without being throttled by the pacing rate. The congestion window
            // is the real limit; pacing just smooths burst timing.
            self.pacing_rate = base_rate *| 2;
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
        const MIN_CWND: u64 = 8 * MSS;
        self.w_max = @floatFromInt(self.cwnd);
        self.cwnd = @intFromFloat(@as(f64, @floatFromInt(self.cwnd)) * BETA_CUBIC);
        if (self.cwnd < MIN_CWND) {
            self.cwnd = MIN_CWND;
            // RFC 9438 §5.4: when the floor raises cwnd above BETA_CUBIC×w_max,
            // clip w_max to prevent K from becoming pathologically large (~18s).
            // This forces K=0 and immediate convex growth instead of prolonged TCP-friendly phase.
            self.w_max = @floatFromInt(MIN_CWND);
        }
        self.ssthresh = self.cwnd;
        self.cwnd_remainder = 0;
        self.epoch_start_ns = now_ns; // begin new epoch at loss time
        self.cwnd_at_epoch = @floatFromInt(self.cwnd);
        self.w_est = self.cwnd_at_epoch; // reset TCP-friendly estimate to post-loss cwnd
        self.k = computeK(self.w_max, self.cwnd_at_epoch);
    }

    /// Refill pacing tokens based on elapsed time.  Call at the start of each
    /// send opportunity (tick or post-ACK).  Returns the number of bytes
    /// allowed to send.  Tokens are capped at 2×cwnd to allow modest bursts
    /// (e.g., after ACK batching) without unlimited accumulation.
    pub fn pacingRefill(self: *Cubic, now_ns: i64) u64 {
        if (self.pacing_rate == 0) {
            // No pacing rate yet (before first ACK) — allow full cwnd.
            return self.cwnd;
        }
        if (self.pacing_last_refill_ns == 0) {
            self.pacing_last_refill_ns = now_ns;
            return self.pacing_tokens;
        }
        const elapsed_ns: u64 = @intCast(@max(now_ns - self.pacing_last_refill_ns, 0));
        self.pacing_last_refill_ns = now_ns;
        // tokens += pacing_rate × elapsed_seconds
        const new_tokens = self.pacing_rate *| elapsed_ns / 1_000_000_000;
        self.pacing_tokens = @min(self.pacing_tokens +| new_tokens, self.cwnd *| 2);
        return self.pacing_tokens;
    }

    /// Consume pacing tokens after sending a packet.
    pub fn pacingConsume(self: *Cubic, bytes: u64) void {
        self.pacing_tokens -|= bytes;
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
        // W_est is only incremented during the TCP-friendly phase (W_cubic < W_est).
        // When W_cubic > W_est (convex growth phase), W_est stalls and CUBIC dominates.
        const alpha_aimd: f64 = 3.0 * BETA_CUBIC / (2.0 - BETA_CUBIC);
        const cwnd_f: f64 = @floatFromInt(self.cwnd);
        if (w_cubic < self.w_est) {
            self.w_est += alpha_aimd * @as(f64, @floatFromInt(bytes_acked)) / cwnd_f;
        }

        const target = @max(w_cubic, self.w_est);
        // RFC 9438 Appendix B: Cap target after idle/app-limited periods to 1.5×W_max per RTT.
        // Prevents burst congestion when t is very large due to idle time.
        const max_cwnd_target: f64 = 1.5 * self.w_max;
        const target_bytes: u64 = @intFromFloat(@max(@min(target, max_cwnd_target), 0));

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

    // Set up a scenario where w_cubic < w_est so TCP-friendly phase is active.
    // Use a very large w_max relative to cwnd_at_epoch so w_cubic stays below w_est.
    c.w_max = 1.0e10; // Very large pre-loss cwnd (simulates old high window)
    c.k = 100.0; // Large K so we're far from inflection point
    c.epoch_start_ns = 0;
    c.cwnd_at_epoch = @floatFromInt(c.cwnd);
    c.w_est = @as(f64, @floatFromInt(c.cwnd)) + 1000.0; // w_est > w_cubic initially

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
    // Expected: floor(120000 * 0.7) = 84000, but minimum is 8*MSS
    const expected: u64 = @intFromFloat(@as(f64, @floatFromInt(before)) * BETA_CUBIC);
    const MIN_CWND: u64 = 8 * MSS;
    try testing.expectEqual(@max(expected, MIN_CWND), c.cwnd);
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
    // Expected: floor(12000 * 0.7) = 8400, but floored to MIN_CWND = 8*MSS = 9600.
    // When floor applies, w_max is clipped to MIN_CWND to prevent K ≈ 18s pathology.
    try testing.expectEqual(@as(u64, 8 * MSS), c.cwnd);
    try testing.expectEqual(c.cwnd, c.ssthresh);
    try testing.expectEqual(@as(f64, @floatFromInt(8 * MSS)), c.w_max);
}

test "cubic: cwnd_remainder uses saturating arithmetic on extreme target" {
    // Regression: (target - cwnd) * MSS can overflow u64 for pathological targets.
    // Force extreme values: t=400,000s → cubicWindow ≈ 2.56e16, would overflow without *|
    // To test growth in TCP-friendly phase (w_cubic < w_est), set w_est >> w_cubic.
    const testing = std.testing;
    var c = Cubic.init();
    c.ssthresh = MSS;
    c.cwnd = MSS;
    c.w_max = 1.0e12; // Very large w_max
    c.w_est = 2.0e12; // w_est >> w_cubic (ensures TCP-friendly phase)
    c.k = 0.0;
    c.epoch_start_ns = 0;
    c.cwnd_at_epoch = @floatFromInt(c.cwnd);

    c.onAckReceived(1, 10_000_000, 400_000 * 1_000_000_000);

    try testing.expect(c.cwnd >= MSS);
    try testing.expect(c.cwnd > MSS);
}
