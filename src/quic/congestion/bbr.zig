//! BBR v3 congestion control.
//!
//! Model-based congestion control that explicitly estimates bandwidth and RTT
//! to operate at the optimal BDP point. Implements the BBR v3 state machine
//! with loss-based inflight bounding.
//!
//! References:
//!   - IETF draft-cardwell-iccrg-bbr-congestion-control
//!   - Linux kernel net/ipv4/tcp_bbr.c v3 branch

const std = @import("std");
const common = @import("common.zig");
const DeliveryRateSample = common.DeliveryRateSample;
const MSS = common.MSS;
const INITIAL_CWND = common.INITIAL_CWND;

// ---------------------------------------------------------------------------
// BBR-specific constants
// ---------------------------------------------------------------------------

/// Minimum cwnd: 4 packets (allows recovery even in ProbeRTT).
const BBR_MIN_CWND: u64 = 4 * MSS;
/// Startup pacing gain: 2/ln(2) ≈ 2.89.
const BBR_STARTUP_PACING_GAIN: f64 = 2.885;
/// Drain pacing gain: 1/startup_gain.
const BBR_DRAIN_PACING_GAIN: f64 = 1.0 / BBR_STARTUP_PACING_GAIN;
/// ProbeBW UP phase pacing gain.
const BBR_PROBE_BW_UP_PACING_GAIN: f64 = 1.25;
/// ProbeBW DOWN phase pacing gain.
const BBR_PROBE_BW_DOWN_PACING_GAIN: f64 = 0.9;
/// cwnd gain during Startup and Drain.
const BBR_CWND_GAIN: f64 = 2.0;
/// ProbeRTT interval: re-probe RTT every 10 seconds.
const BBR_PROBE_RTT_INTERVAL_NS: i64 = 10_000_000_000;
/// ProbeRTT hold duration: 200ms.
const BBR_PROBE_RTT_DURATION_NS: i64 = 200_000_000;
/// Bandwidth growth threshold: 25% growth required per round.
const BBR_FULL_BW_THRESHOLD: f64 = 1.25;
/// Rounds without growth before declaring pipe filled.
const BBR_FULL_BW_COUNT: u8 = 3;

// ---------------------------------------------------------------------------
// Windowed Filter
// ---------------------------------------------------------------------------

/// Fixed-size windowed max filter. Tracks the maximum value over a sliding
/// window of `window` rounds. No allocator needed.
fn WindowedFilter(comptime T: type, comptime window: u64) type {
    return struct {
        const Self = @This();

        val: [3]T,
        round: [3]u64,

        pub fn init(initial: T) Self {
            return .{
                .val = .{ initial, initial, initial },
                .round = .{ 0, 0, 0 },
            };
        }

        pub fn get(self: *const Self) T {
            return self.val[0];
        }

        pub fn update(self: *Self, val: T, round: u64) void {
            // If new value >= current best, it becomes the new best.
            if (val >= self.val[0]) {
                self.val = .{ val, val, val };
                self.round = .{ round, round, round };
                return;
            }

            // If current best has expired, promote.
            if (round -| self.round[0] >= window) {
                self.val[0] = val;
                self.round[0] = round;
                if (round -| self.round[1] >= window) {
                    self.val[1] = val;
                    self.round[1] = round;
                }
                if (round -| self.round[2] >= window) {
                    self.val[2] = val;
                    self.round[2] = round;
                }
                if (self.val[1] > self.val[0]) {
                    self.val[0] = self.val[1];
                    self.round[0] = self.round[1];
                }
                if (self.val[2] > self.val[0]) {
                    self.val[0] = self.val[2];
                    self.round[0] = self.round[2];
                }
                return;
            }

            // New value fits as second-best or third-best.
            if (val >= self.val[1]) {
                self.val[1] = val;
                self.round[1] = round;
                self.val[2] = val;
                self.round[2] = round;
            } else if (val >= self.val[2]) {
                self.val[2] = val;
                self.round[2] = round;
            }
        }

        pub fn reset(self: *Self, val: T, round: u64) void {
            self.val = .{ val, val, val };
            self.round = .{ round, round, round };
        }
    };
}

// ---------------------------------------------------------------------------
// BBR v3 State Machine
// ---------------------------------------------------------------------------

pub const State = enum { startup, drain, probe_bw, probe_rtt };
pub const ProbeBwPhase = enum { down, cruise, refill, up };

pub const Bbr = struct {
    // --- Public API fields ---
    cwnd: u64,
    pacing: common.Pacing,

    // --- State machine ---
    state: State,
    probe_bw_phase: ProbeBwPhase,

    // --- Bandwidth estimation ---
    max_bw: u64, // bytes/sec (windowed max, cached from filter)
    max_bw_filter: WindowedFilter(u64, 2), // 2-round window
    bw_hi: u64, // upper bound from loss

    // --- RTT estimation ---
    min_rtt_ns: u64, // nanoseconds (windowed min, ~10s)
    min_rtt_stamp_ns: i64, // when min_rtt was last updated
    probe_rtt_done_ns: ?i64, // when ProbeRTT 200ms hold ends
    probe_rtt_round_done: bool,

    // --- Round tracking ---
    round_count: u64,

    // --- Inflight bounds (BBR v3 loss-based) ---
    inflight_hi: u64, // upper inflight bound

    // --- Loss tracking ---
    loss_in_round: u64,
    bytes_in_round: u64,

    // --- Startup state ---
    full_bw: u64, // BW at last plateau check
    full_bw_count: u8, // rounds without 25% growth
    filled_pipe: bool,

    // --- Gains (current multipliers) ---
    pacing_gain: f64,
    cwnd_gain: f64,

    // --- Extra ACKed tracking (for cwnd headroom) ---
    extra_acked: u64, // cached from filter
    extra_acked_filter: WindowedFilter(u64, 2),
    extra_acked_in_interval: u64,

    // --- ProbeBW cruise timing ---
    probe_bw_rounds: u64, // rounds spent in current ProbeBW phase
    probe_up_rounds: u64, // rounds in UP phase

    pub fn init() Bbr {
        // Bootstrap pacing rate: initial_cwnd / initial_rtt (no startup gain).
        // Using startup_gain (2.885×) here causes the initial burst to overflow
        // shallow queues (25 packets fill in 12ms at 4.2 MB/s).  Without the
        // gain, rate ≈ 1.45 MB/s which stays close to typical link rates.
        // BBR still discovers capacity through cwnd doubling each round.
        const initial_rate: u64 = @intFromFloat(
            @as(f64, @floatFromInt(INITIAL_CWND)) * 1_000_000_000.0 /
                @as(f64, @floatFromInt(10_000_000)), // K_INITIAL_RTT_NS = 10ms
        );
        return .{
            .cwnd = INITIAL_CWND,
            .pacing = .{ .rate = initial_rate, .tokens = INITIAL_CWND, .last_refill_ns = 0 },
            .state = .startup,
            .probe_bw_phase = .down,
            .max_bw = 0,
            .max_bw_filter = WindowedFilter(u64, 2).init(0),
            .bw_hi = std.math.maxInt(u64),
            .min_rtt_ns = std.math.maxInt(u64),
            .min_rtt_stamp_ns = 0,
            .probe_rtt_done_ns = null,
            .probe_rtt_round_done = false,
            .round_count = 0,
            .inflight_hi = std.math.maxInt(u64),
            .loss_in_round = 0,
            .bytes_in_round = 0,
            .full_bw = 0,
            .full_bw_count = 0,
            .filled_pipe = false,
            .pacing_gain = BBR_STARTUP_PACING_GAIN,
            .cwnd_gain = BBR_CWND_GAIN,
            .extra_acked = 0,
            .extra_acked_filter = WindowedFilter(u64, 2).init(0),
            .extra_acked_in_interval = 0,
            .probe_bw_rounds = 0,
            .probe_up_rounds = 0,
        };
    }

    /// True when the congestion window allows sending.
    pub fn canSend(self: *const Bbr) bool {
        return self.cwnd > 0;
    }

    /// Whether the pacing gate should block sends.  Always true — the
    /// bootstrapped initial pacing rate prevents the low-estimate feedback
    /// loop while still smoothing bursts to avoid queue overflow.
    pub fn shouldPace(_: *const Bbr) bool {
        return true;
    }

    /// Called when an ACK is received with a delivery rate sample.
    pub fn onAckReceived(self: *Bbr, sample: DeliveryRateSample, now_ns: i64) void {
        // Increment round count (needed for filter windows), but DON'T reset
        // per-round loss counters yet — the state machine evaluates them first.
        if (sample.round_start) {
            self.round_count += 1;
        }

        // Update bandwidth estimate (ignore app-limited samples unless they exceed max).
        if (!sample.is_app_limited or sample.delivery_rate > self.max_bw) {
            self.max_bw_filter.update(sample.delivery_rate, self.round_count);
            self.max_bw = self.max_bw_filter.get();
        }

        // Update min RTT.
        if (sample.rtt_ns > 0 and sample.rtt_ns < self.min_rtt_ns) {
            self.min_rtt_ns = sample.rtt_ns;
            self.min_rtt_stamp_ns = now_ns;
        }

        // Update extra ACKed for cwnd headroom.
        self.updateExtraAcked(sample);

        // State machine transitions (evaluates accumulated round loss data).
        switch (self.state) {
            .startup => self.updateStartup(sample),
            .drain => self.updateDrain(sample),
            .probe_bw => self.updateProbeBw(sample),
            .probe_rtt => self.updateProbeRtt(sample, now_ns),
        }

        // NOW reset per-round counters and start accumulating for the new round.
        if (sample.round_start) {
            self.loss_in_round = 0;
            self.bytes_in_round = 0;
        }
        self.loss_in_round += sample.bytes_lost;
        self.bytes_in_round += sample.bytes_acked + sample.bytes_lost;

        // Update pacing rate and cwnd.
        self.updatePacingRate();
        self.updateCwnd(sample.bytes_acked);

        // Check if we should enter ProbeRTT (only from ProbeBW).
        if (self.state == .probe_bw) {
            self.checkProbeRtt(now_ns);
        }

    }

    /// Called on packet loss. BBR v3 uses loss for inflight bounding.
    pub fn onPacketLost(_: *Bbr, _: u64, _: i64) void {
        // Loss-based bounding is handled in onAckReceived via sample.bytes_lost.
        // BBR v3 does not do multiplicative decrease on loss events.
    }

    /// Called on persistent congestion: reset to Startup, clear estimates.
    pub fn onPersistentCongestion(self: *Bbr) void {
        self.state = .startup;
        self.filled_pipe = false;
        self.full_bw = 0;
        self.full_bw_count = 0;
        self.cwnd = BBR_MIN_CWND;
        self.pacing_gain = BBR_STARTUP_PACING_GAIN;
        self.cwnd_gain = BBR_CWND_GAIN;
        self.max_bw = 0;
        self.bw_hi = std.math.maxInt(u64);
        self.inflight_hi = BBR_MIN_CWND;
        // Reset round_count before filters so they store round 0.
        self.round_count = 0;
        self.max_bw_filter.reset(0, 0);
        self.extra_acked_filter.reset(0, 0);
        self.extra_acked = 0;
        self.extra_acked_in_interval = 0;
        // Reset per-round and phase counters to prevent stale data.
        self.loss_in_round = 0;
        self.bytes_in_round = 0;
        self.probe_bw_rounds = 0;
        self.probe_up_rounds = 0;
        // Clear stale RTT — path may have changed fundamentally.
        self.min_rtt_ns = std.math.maxInt(u64);
        self.min_rtt_stamp_ns = 0;
        // Reset pacing to allow initial burst on the new path.
        self.pacing = .{};
    }

    /// Called on ECN CE marks. BBR reduces inflight bounding, NOT multiplicative cwnd decrease.
    pub fn onEcnCe(self: *Bbr, _: u64, _: i64) void {
        // Treat ECN as a bounding signal: reduce inflight_hi.
        self.inflight_hi = @max(applyBeta(self.inflight_hi), @max(self.bdp(), BBR_MIN_CWND));
    }

    /// Refill pacing tokens. Delegates to shared Pacing.
    pub fn pacingRefill(self: *Bbr, now_ns: i64) u64 {
        return self.pacing.refill(self.cwnd, now_ns);
    }

    /// Consume pacing tokens after sending a packet.
    pub fn pacingConsume(self: *Bbr, bytes: u64) void {
        self.pacing.consume(bytes);
    }

    // -----------------------------------------------------------------------
    // Internal: BDP computation
    // -----------------------------------------------------------------------

    fn bdp(self: *const Bbr) u64 {
        if (self.min_rtt_ns == std.math.maxInt(u64) or self.max_bw == 0) {
            return INITIAL_CWND;
        }
        // BDP = max_bw × min_rtt (convert ns to seconds).
        const result: u64 = @intCast(@min(
            @as(u128, self.max_bw) *| @as(u128, self.min_rtt_ns) / 1_000_000_000,
            std.math.maxInt(u64),
        ));
        return @max(result, BBR_MIN_CWND);
    }

    // -----------------------------------------------------------------------
    // Internal: Pacing rate
    // -----------------------------------------------------------------------

    fn updatePacingRate(self: *Bbr) void {
        if (self.max_bw == 0) return;
        // Apply bw_hi bound (from loss bounding).
        const bw = @min(self.max_bw, self.bw_hi);
        const rate_f = @as(f64, @floatFromInt(bw)) * self.pacing_gain;
        self.pacing.rate = if (rate_f >= @as(f64, @floatFromInt(std.math.maxInt(u64))))
            std.math.maxInt(u64)
        else
            @intFromFloat(rate_f);
    }

    // -----------------------------------------------------------------------
    // Internal: cwnd
    // -----------------------------------------------------------------------

    fn updateCwnd(self: *Bbr, bytes_acked: u64) void {
        if (self.state == .probe_rtt) {
            self.cwnd = BBR_MIN_CWND;
            return;
        }

        // During Drain, use BDP × cwnd_gain as the target (same as ProbeBW)
        // so bytes_in_flight can actually drop below BDP, allowing Drain to
        // exit.  Previously cwnd was locked to inflight_hi (the Startup peak),
        // which kept bif far above BDP and trapped BBR in Drain permanently.

        // Target = BDP × cwnd_gain + extra_acked headroom.
        var target_f: f64 = @as(f64, @floatFromInt(self.bdp())) * self.cwnd_gain +
            @as(f64, @floatFromInt(self.extra_acked));

        // In ProbeBW, cap by inflight_hi — except during UP phase where we
        // intentionally probe above the current bound to discover more capacity.
        if (self.state == .probe_bw and self.probe_bw_phase != .up) {
            target_f = @min(target_f, @as(f64, @floatFromInt(self.inflight_hi)));
        }

        const max_u64_f = @as(f64, @floatFromInt(std.math.maxInt(u64)));
        const target: u64 = if (target_f >= max_u64_f) std.math.maxInt(u64) else @intFromFloat(@max(target_f, 0));
        const target_clamped = @max(target, BBR_MIN_CWND);

        if (self.filled_pipe) {
            // Post-startup: grow toward target, don't exceed it.
            self.cwnd = @min(self.cwnd +| bytes_acked, target_clamped);
        } else {
            // Startup: grow quickly (saturating to prevent overflow).
            self.cwnd +|= bytes_acked;
        }
        self.cwnd = @max(self.cwnd, BBR_MIN_CWND);
    }

    // -----------------------------------------------------------------------
    // Internal: Startup state
    // -----------------------------------------------------------------------

    fn updateStartup(self: *Bbr, sample: DeliveryRateSample) void {
        if (!sample.round_start) return;

        // Check for bandwidth plateau.
        if (self.max_bw >= @as(u64, @intFromFloat(@as(f64, @floatFromInt(self.full_bw)) * BBR_FULL_BW_THRESHOLD))) {
            // Still growing — reset counter.
            self.full_bw = self.max_bw;
            self.full_bw_count = 0;
        } else {
            self.full_bw_count += 1;
        }

        if (self.full_bw_count >= BBR_FULL_BW_COUNT or self.isExcessiveLoss()) {
            self.enterDrain();
        }
    }

    fn enterDrain(self: *Bbr) void {
        self.state = .drain;
        self.filled_pipe = true;
        self.pacing_gain = BBR_DRAIN_PACING_GAIN;
        self.cwnd_gain = BBR_CWND_GAIN;
        // If Startup exited due to loss, the cwnd is massively inflated.
        // Set inflight_hi to BDP so cwnd drains properly and ProbeBW starts
        // with a reasonable bound.  Without this, inflight_hi stays at the
        // Startup peak and cwnd never converges to the actual capacity.
        if (self.isExcessiveLoss()) {
            self.inflight_hi = @max(self.bdp(), BBR_MIN_CWND);
        } else {
            self.inflight_hi = self.cwnd;
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Drain state
    // -----------------------------------------------------------------------

    fn updateDrain(self: *Bbr, sample: DeliveryRateSample) void {
        // Apply loss bounding during Drain — continued loss from the Startup
        // burst should reduce inflight_hi toward BDP, not stay at the peak.
        if (sample.round_start and self.isExcessiveLoss()) {
            self.applyLossBounding(true);
        }
        // Exit Drain when bytes in flight ≤ BDP.
        if (sample.prior_inflight <= self.bdp()) {
            self.enterProbeBw(.down);
        }
    }

    // -----------------------------------------------------------------------
    // Internal: ProbeBW state (steady state)
    // -----------------------------------------------------------------------

    fn enterProbeBw(self: *Bbr, phase: ProbeBwPhase) void {
        self.state = .probe_bw;
        self.probe_bw_phase = phase;
        self.probe_bw_rounds = 0;
        self.probe_up_rounds = 0;
        // Use cwnd_gain = 2.0 to target 2×BDP — provides headroom for
        // retransmissions and ACK aggregation in real networks.
        self.cwnd_gain = BBR_CWND_GAIN;
        self.pacing_gain = switch (phase) {
            .down => BBR_PROBE_BW_DOWN_PACING_GAIN,
            .cruise, .refill => 1.0,
            .up => BBR_PROBE_BW_UP_PACING_GAIN,
        };
        if (phase == .refill) {
            // Reset bw_hi before probing up so previous reductions don't persist.
            self.bw_hi = std.math.maxInt(u64);
        }
    }

    fn updateProbeBw(self: *Bbr, sample: DeliveryRateSample) void {
        // Per-round loss bounding (applies to all phases).
        const had_excessive_loss = sample.round_start and self.isExcessiveLoss();
        if (sample.round_start) {
            self.applyLossBounding(had_excessive_loss);
            self.probe_bw_rounds += 1;
        }

        switch (self.probe_bw_phase) {
            .down => {
                if (sample.prior_inflight <= self.bdp()) {
                    self.enterProbeBw(.cruise);
                }
            },
            .cruise => {
                if (self.probe_bw_rounds >= 4) {
                    self.enterProbeBw(.refill);
                }
            },
            .refill => {
                if (sample.round_start and self.probe_bw_rounds >= 1) {
                    self.enterProbeBw(.up);
                }
            },
            .up => {
                if (sample.round_start) self.probe_up_rounds += 1;
                // applyLossBounding already reduced inflight_hi; just transition on loss.
                if (had_excessive_loss) {
                    self.enterProbeBw(.down);
                } else if (self.probe_up_rounds >= 2) {
                    self.inflight_hi = @max(self.inflight_hi, sample.prior_inflight);
                    self.enterProbeBw(.down);
                }
            },
        }
    }

    fn applyLossBounding(self: *Bbr, excessive_loss: bool) void {
        if (excessive_loss) {
            self.bw_hi = @max(applyBeta(self.bw_hi), self.max_bw);
            self.inflight_hi = @max(applyBeta(self.inflight_hi), self.bdp());
        }
    }

    // -----------------------------------------------------------------------
    // Internal: ProbeRTT state
    // -----------------------------------------------------------------------

    fn checkProbeRtt(self: *Bbr, now_ns: i64) void {
        if (self.state == .probe_rtt) return;
        if (self.min_rtt_ns == std.math.maxInt(u64)) return;

        // Enter ProbeRTT if min_rtt hasn't been updated for 10 seconds.
        if (now_ns - self.min_rtt_stamp_ns >= BBR_PROBE_RTT_INTERVAL_NS) {
            self.enterProbeRtt();
        }
    }

    fn enterProbeRtt(self: *Bbr) void {
        self.state = .probe_rtt;
        self.pacing_gain = 1.0;
        self.cwnd_gain = 1.0;
        self.probe_rtt_done_ns = null;
        self.probe_rtt_round_done = false;
        // Reset min_rtt to force re-measurement (Linux BBR v3 behavior).
        // Without this, a stale min_rtt from early Startup persists and
        // makes BDP permanently inaccurate.
        self.min_rtt_ns = std.math.maxInt(u64);
    }

    fn updateProbeRtt(self: *Bbr, sample: DeliveryRateSample, now_ns: i64) void {
        // Wait for inflight to drain to min cwnd.
        if (self.probe_rtt_done_ns == null) {
            if (sample.prior_inflight <= BBR_MIN_CWND) {
                // Inflight drained — start 200ms timer.
                self.probe_rtt_done_ns = now_ns + BBR_PROBE_RTT_DURATION_NS;
                self.probe_rtt_round_done = false;
            }
            return;
        }

        // Wait for one full round.
        if (sample.round_start) {
            self.probe_rtt_round_done = true;
        }

        // Exit when both 200ms elapsed AND one round completed.
        if (self.probe_rtt_round_done and now_ns >= self.probe_rtt_done_ns.?) {
            // Update min_rtt timestamp.
            self.min_rtt_stamp_ns = now_ns;
            self.exitProbeRtt();
        }
    }

    fn exitProbeRtt(self: *Bbr) void {
        if (!self.filled_pipe) {
            self.state = .startup;
            self.pacing_gain = BBR_STARTUP_PACING_GAIN;
            self.cwnd_gain = BBR_CWND_GAIN;
        } else {
            self.enterProbeBw(.cruise);
        }
    }

    // -----------------------------------------------------------------------
    // Internal: Helpers
    // -----------------------------------------------------------------------

    /// True if >2% of bytes in the current round were lost.
    /// Uses `loss * 50 > bytes` (equivalent to `loss / bytes > 0.02`) to stay in u64.
    fn isExcessiveLoss(self: *const Bbr) bool {
        return self.bytes_in_round > 0 and
            self.loss_in_round *| 50 > self.bytes_in_round;
    }

    /// Apply BBR_BETA (0.7) reduction to a u64 value using integer arithmetic.
    fn applyBeta(val: u64) u64 {
        return val *| 7 / 10;
    }

    // -----------------------------------------------------------------------
    // Internal: Extra ACKed tracking
    // -----------------------------------------------------------------------

    fn updateExtraAcked(self: *Bbr, sample: DeliveryRateSample) void {
        // Reset interval on round boundary unconditionally (even if early returns below skip accumulation).
        if (sample.round_start) {
            self.extra_acked_filter.update(self.extra_acked_in_interval, self.round_count);
            self.extra_acked = self.extra_acked_filter.get();
            self.extra_acked_in_interval = 0;
        }

        if (sample.bytes_acked == 0) return;
        if (self.max_bw == 0 or sample.rtt_ns == 0) return;

        // Expected delivery = max_bw × rtt_sample.
        const expected: u64 = @intCast(@min(
            @as(u128, self.max_bw) *| @as(u128, sample.rtt_ns) / 1_000_000_000,
            std.math.maxInt(u64),
        ));

        if (sample.bytes_acked > expected) {
            self.extra_acked_in_interval += sample.bytes_acked - expected;
        }
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "bbr: init sets startup state" {
    const b = Bbr.init();
    const testing = std.testing;
    try testing.expectEqual(State.startup, b.state);
    try testing.expectEqual(INITIAL_CWND, b.cwnd);
    try testing.expect(b.pacing_gain > 2.8);
    try testing.expect(!b.filled_pipe);
}

test "bbr: canSend" {
    var b = Bbr.init();
    const testing = std.testing;
    try testing.expect(b.canSend());
    b.cwnd = 0;
    try testing.expect(!b.canSend());
}

test "bbr: bdp computation" {
    var b = Bbr.init();
    // Set known values: 1 MB/s, 100ms RTT → BDP = 100,000 bytes.
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 100_000_000; // 100ms
    const expected: u64 = 100_000; // 1M × 0.1s
    try std.testing.expectEqual(expected, b.bdp());
}

test "bbr: bdp returns initial cwnd when no samples" {
    const b = Bbr.init();
    try std.testing.expectEqual(INITIAL_CWND, b.bdp());
}

test "bbr: startup exits on bandwidth plateau" {
    var b = Bbr.init();
    b.max_bw = 1000;
    b.full_bw = 1000; // Same as max_bw — no growth.
    b.min_rtt_ns = 50_000_000;

    // Simulate 3 rounds without 25% growth.
    var i: u8 = 0;
    while (i < 3) : (i += 1) {
        b.updateStartup(.{
            .delivery_rate = 1000,
            .round_start = true,
        });
    }
    try std.testing.expectEqual(State.drain, b.state);
    try std.testing.expect(b.filled_pipe);
}

test "bbr: startup exits on excessive loss" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.full_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.bytes_in_round = 10000;
    b.loss_in_round = 300; // 3% loss > 2% threshold

    b.updateStartup(.{ .delivery_rate = 1_000_000, .round_start = true });
    try std.testing.expectEqual(State.drain, b.state);
}

test "bbr: drain exits when inflight <= bdp" {
    var b = Bbr.init();
    b.state = .drain;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 100_000_000; // BDP = 100,000

    b.updateDrain(.{ .prior_inflight = 90_000 }); // below BDP
    try std.testing.expectEqual(State.probe_bw, b.state);
    try std.testing.expectEqual(ProbeBwPhase.down, b.probe_bw_phase);
}

test "bbr: probe_bw phase cycling" {
    var b = Bbr.init();
    b.state = .probe_bw;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;

    // DOWN → CRUISE when inflight <= bdp
    b.probe_bw_phase = .down;
    b.pacing_gain = BBR_PROBE_BW_DOWN_PACING_GAIN;
    b.updateProbeBw(.{ .prior_inflight = 1000, .round_start = true });
    try std.testing.expectEqual(ProbeBwPhase.cruise, b.probe_bw_phase);

    // CRUISE → REFILL after 4 rounds
    b.probe_bw_rounds = 0;
    var i: u8 = 0;
    while (i < 4) : (i += 1) {
        b.updateProbeBw(.{ .prior_inflight = 50_000, .round_start = true });
    }
    try std.testing.expectEqual(ProbeBwPhase.refill, b.probe_bw_phase);

    // REFILL → UP after 1 round
    b.probe_bw_rounds = 0;
    b.updateProbeBw(.{ .prior_inflight = 50_000, .round_start = true });
    b.updateProbeBw(.{ .prior_inflight = 50_000, .round_start = true });
    try std.testing.expectEqual(ProbeBwPhase.up, b.probe_bw_phase);
}

test "bbr: probe_rtt entry after 10s" {
    var b = Bbr.init();
    b.state = .probe_bw;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.min_rtt_stamp_ns = 0;

    // 10s later, should enter ProbeRTT.
    b.checkProbeRtt(10_000_000_001);
    try std.testing.expectEqual(State.probe_rtt, b.state);
}

test "bbr: probe_rtt exit after 200ms + 1 round" {
    var b = Bbr.init();
    b.state = .probe_rtt;
    b.filled_pipe = true;
    b.min_rtt_ns = 50_000_000;
    b.max_bw = 1_000_000;
    b.probe_rtt_done_ns = null;
    b.probe_rtt_round_done = false;

    // Step 1: inflight drains to min cwnd — starts 200ms timer.
    b.updateProbeRtt(.{ .prior_inflight = BBR_MIN_CWND, .round_start = false }, 1000);
    try std.testing.expect(b.probe_rtt_done_ns != null);
    try std.testing.expect(!b.probe_rtt_round_done);

    // Step 2: round completes.
    b.updateProbeRtt(.{ .prior_inflight = BBR_MIN_CWND, .round_start = true }, 1000 + 100_000_000);
    try std.testing.expect(b.probe_rtt_round_done);

    // Step 3: 200ms elapsed.
    b.updateProbeRtt(.{ .prior_inflight = BBR_MIN_CWND, .round_start = true }, 1000 + BBR_PROBE_RTT_DURATION_NS + 1);
    try std.testing.expectEqual(State.probe_bw, b.state);
}

test "bbr: windowed filter tracks max" {
    const Filter = WindowedFilter(u64, 2);
    var f = Filter.init(0);
    f.update(100, 1);
    try std.testing.expectEqual(@as(u64, 100), f.get());
    f.update(200, 2);
    try std.testing.expectEqual(@as(u64, 200), f.get());
    // Lower value doesn't displace max.
    f.update(50, 2);
    try std.testing.expectEqual(@as(u64, 200), f.get());
}

test "bbr: windowed filter expires old values" {
    const Filter = WindowedFilter(u64, 2);
    var f = Filter.init(0);
    f.update(200, 1);
    try std.testing.expectEqual(@as(u64, 200), f.get());
    // After window expires (round 4, window=2), old value should be replaced.
    f.update(100, 4);
    try std.testing.expectEqual(@as(u64, 100), f.get());
}

test "bbr: loss bounding reduces inflight_hi" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 100_000;
    b.bw_hi = 2_000_000;

    // 5% loss rate (> 2% threshold).
    b.bytes_in_round = 10000;
    b.loss_in_round = 500;

    const old_hi = b.inflight_hi;
    b.applyLossBounding(true);
    try std.testing.expect(b.inflight_hi < old_hi);
}

test "bbr: pacing refill with known rate" {
    var b = Bbr.init();
    b.pacing.rate = 1_000_000; // 1 MB/s
    b.pacing.tokens = 0;
    b.pacing.last_refill_ns = 1_000_000_000; // 1s

    const tokens = b.pacingRefill(1_001_000_000); // 1ms later
    // 1 MB/s × 0.001s = 1000 bytes.
    try std.testing.expectEqual(@as(u64, 1000), tokens);
}

test "bbr: pacing consume" {
    var b = Bbr.init();
    b.pacing.tokens = 5000;
    b.pacingConsume(3000);
    try std.testing.expectEqual(@as(u64, 2000), b.pacing.tokens);
}

test "bbr: persistent congestion resets to startup" {
    var b = Bbr.init();
    b.state = .probe_bw;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.cwnd = 100_000;
    b.onPersistentCongestion();
    try std.testing.expectEqual(State.startup, b.state);
    try std.testing.expect(!b.filled_pipe);
    try std.testing.expectEqual(BBR_MIN_CWND, b.cwnd);
    try std.testing.expectEqual(@as(u64, 0), b.max_bw);
}

test "bbr: ecn ce reduces inflight_hi" {
    var b = Bbr.init();
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 200_000;

    const old_hi = b.inflight_hi;
    b.onEcnCe(1, 0);
    try std.testing.expect(b.inflight_hi < old_hi);
}

test "bbr: startup grows cwnd on ack" {
    var b = Bbr.init();
    const initial = b.cwnd;
    b.min_rtt_ns = 50_000_000;
    b.onAckReceived(.{
        .delivery_rate = 500_000,
        .rtt_ns = 50_000_000,
        .bytes_acked = MSS,
        .round_start = false,
    }, 1_000_000_000);
    // Startup grows cwnd by bytes_acked.
    try std.testing.expect(b.cwnd > initial);
}

test "bbr: full state machine startup to probe_bw" {
    var b = Bbr.init();
    b.min_rtt_ns = 50_000_000;
    b.min_rtt_stamp_ns = 0;

    // Simulate startup with growing bandwidth.
    var bw: u64 = 100_000;
    var round: u64 = 0;
    while (b.state == .startup and round < 20) : (round += 1) {
        bw = bw * 3 / 2; // 50% growth per round.
        b.onAckReceived(.{
            .delivery_rate = bw,
            .rtt_ns = 50_000_000,
            .bytes_acked = 10 * MSS,
            .round_start = true,
        }, @intCast(round * 50_000_000));
    }

    // BW stabilizes — should plateau and exit startup.
    const stable_bw = bw;
    while (b.state == .startup and round < 40) : (round += 1) {
        b.onAckReceived(.{
            .delivery_rate = stable_bw,
            .rtt_ns = 50_000_000,
            .bytes_acked = 10 * MSS,
            .round_start = true,
        }, @intCast(round * 50_000_000));
    }
    // Should have transitioned through drain.
    try std.testing.expect(b.filled_pipe);

    // Drain until inflight ≤ BDP.
    while (b.state == .drain and round < 60) : (round += 1) {
        b.onAckReceived(.{
            .delivery_rate = stable_bw,
            .rtt_ns = 50_000_000,
            .bytes_acked = 10 * MSS,
            .prior_inflight = 1000, // way below BDP
            .round_start = true,
        }, @intCast(round * 50_000_000));
    }
    try std.testing.expectEqual(State.probe_bw, b.state);
}

// ---------------------------------------------------------------------------
// Regression tests (bugs found during code review)
// ---------------------------------------------------------------------------

test "bbr: regression — persistent congestion resets filters with round 0" {
    // Bug: onPersistentCongestion reset round_count to 0 AFTER calling
    // max_bw_filter.reset(0, self.round_count), storing a stale round number.
    // Future filter updates would not expire the old value for many rounds.
    var b = Bbr.init();
    b.round_count = 100;
    b.max_bw = 500_000;
    b.max_bw_filter.update(500_000, 100);

    b.onPersistentCongestion();

    // round_count must be 0 after reset.
    try std.testing.expectEqual(@as(u64, 0), b.round_count);
    // Filter must have been reset with round 0, not the stale 100.
    try std.testing.expectEqual(@as(u64, 0), b.max_bw_filter.round[0]);
    // A new value at round 1 should become the new best.
    b.max_bw_filter.update(1000, 1);
    try std.testing.expectEqual(@as(u64, 1000), b.max_bw_filter.get());
}

test "bbr: regression — persistent congestion resets min_rtt and pacing" {
    // Bug: onPersistentCongestion did not reset min_rtt_ns, min_rtt_stamp_ns,
    // pacing state, or extra_acked_in_interval. Stale values leaked into
    // the new Startup phase.
    var b = Bbr.init();
    b.min_rtt_ns = 10_000_000;
    b.min_rtt_stamp_ns = 5_000_000_000;
    b.pacing.rate = 1_000_000;
    b.pacing.tokens = 50_000;
    b.extra_acked_in_interval = 9999;

    b.onPersistentCongestion();

    try std.testing.expectEqual(std.math.maxInt(u64), b.min_rtt_ns);
    try std.testing.expectEqual(@as(i64, 0), b.min_rtt_stamp_ns);
    try std.testing.expectEqual(@as(u64, 0), b.pacing.rate);
    try std.testing.expectEqual(INITIAL_CWND, b.pacing.tokens); // default Pacing init
    try std.testing.expectEqual(@as(u64, 0), b.extra_acked_in_interval);
}

test "bbr: regression — no double inflight_hi reduction in ProbeBW UP" {
    // Bug: checkLossBounding reduced inflight_hi, then the UP branch applied
    // applyBeta again, double-reducing it.
    var b = Bbr.init();
    b.state = .probe_bw;
    b.probe_bw_phase = .up;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 200_000;
    b.bw_hi = std.math.maxInt(u64);

    // Simulate excessive loss in a round.
    b.bytes_in_round = 10000;
    b.loss_in_round = 500; // 5% > 2%

    // One round_start ACK should reduce inflight_hi exactly once.
    b.updateProbeBw(.{ .prior_inflight = 100_000, .round_start = true });

    // After single beta reduction: 200_000 * 7/10 = 140_000.
    // BDP = 1M * 50ms = 50_000. So max(140_000, 50_000) = 140_000.
    const expected = @max(Bbr.applyBeta(200_000), @as(u64, 50_000));
    try std.testing.expectEqual(expected, b.inflight_hi);
    // Must have transitioned to DOWN.
    try std.testing.expectEqual(ProbeBwPhase.down, b.probe_bw_phase);
}

test "bbr: regression — bw_hi restored in ProbeBW refill" {
    // Bug: bw_hi was only reduced, never restored. Once checkLossBounding
    // reduced it, the pacing rate was permanently suppressed.
    var b = Bbr.init();
    b.state = .probe_bw;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.bw_hi = 500_000; // previously reduced

    // Entering refill should restore bw_hi to maxInt.
    b.enterProbeBw(.refill);
    try std.testing.expectEqual(std.math.maxInt(u64), b.bw_hi);
}

test "bbr: regression — cwnd_gain is 2.0 in ProbeBW steady state" {
    // cwnd_gain = 2.0 in ProbeBW provides 2×BDP headroom for retransmissions
    // and ACK aggregation.
    var b = Bbr.init();
    b.enterProbeBw(.cruise);
    try std.testing.expectEqual(BBR_CWND_GAIN, b.cwnd_gain);
    b.enterProbeBw(.down);
    try std.testing.expectEqual(BBR_CWND_GAIN, b.cwnd_gain);
    b.enterProbeBw(.up);
    try std.testing.expectEqual(BBR_CWND_GAIN, b.cwnd_gain);
    b.enterProbeBw(.refill);
    try std.testing.expectEqual(BBR_CWND_GAIN, b.cwnd_gain);
}

test "bbr: regression — inflight_hi initialized to maxInt" {
    // Bug: inflight_hi was initialized to INITIAL_CWND, which would cap
    // cwnd in ProbeBW before enterDrain had a chance to set it properly.
    const b = Bbr.init();
    try std.testing.expectEqual(std.math.maxInt(u64), b.inflight_hi);
}

test "bbr: regression — loss counters evaluated before reset on round boundary" {
    // Bug: updateRoundCounters() zeroed loss_in_round/bytes_in_round before
    // the state machine could evaluate them, making isExcessiveLoss() see
    // only the current ACK's data instead of the full accumulated round.
    var b = Bbr.init();
    b.state = .probe_bw;
    b.probe_bw_phase = .up;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000;
    b.inflight_hi = 200_000;
    b.bw_hi = std.math.maxInt(u64);

    // Accumulate loss data over several non-round-start ACKs.
    b.onAckReceived(.{ .bytes_acked = 5000, .bytes_lost = 0 }, 100_000_000);
    b.onAckReceived(.{ .bytes_acked = 5000, .bytes_lost = 0 }, 200_000_000);
    b.onAckReceived(.{ .bytes_acked = 5000, .bytes_lost = 400 }, 300_000_000);
    // Now: bytes_in_round=15000, loss_in_round=400 (2.67% > 2%)
    try std.testing.expect(b.isExcessiveLoss());

    // The round_start ACK should see the accumulated loss and transition.
    const hi_before = b.inflight_hi;
    b.onAckReceived(.{ .bytes_acked = 1000, .round_start = true }, 400_000_000);

    // inflight_hi must have been reduced (loss bounding triggered).
    try std.testing.expect(b.inflight_hi < hi_before);
    // Must have transitioned to DOWN.
    try std.testing.expectEqual(ProbeBwPhase.down, b.probe_bw_phase);
}

test "bbr: regression — persistent congestion resets loss and phase counters" {
    // Bug: onPersistentCongestion didn't reset loss_in_round, bytes_in_round,
    // probe_bw_rounds, probe_up_rounds. Stale loss data could trigger false
    // Startup exit via isExcessiveLoss().
    var b = Bbr.init();
    b.loss_in_round = 500;
    b.bytes_in_round = 10000;
    b.probe_bw_rounds = 5;
    b.probe_up_rounds = 2;

    b.onPersistentCongestion();

    try std.testing.expectEqual(@as(u64, 0), b.loss_in_round);
    try std.testing.expectEqual(@as(u64, 0), b.bytes_in_round);
    try std.testing.expectEqual(@as(u64, 0), b.probe_bw_rounds);
    try std.testing.expectEqual(@as(u64, 0), b.probe_up_rounds);
}

test "bbr: regression — extra_acked capped by inflight_hi" {
    // Bug: extra_acked was added after inflight_hi cap, allowing cwnd to
    // exceed the loss-based inflight bound.
    var b = Bbr.init();
    b.state = .probe_bw;
    b.filled_pipe = true;
    b.max_bw = 1_000_000;
    b.min_rtt_ns = 50_000_000; // BDP = 50,000
    b.cwnd_gain = BBR_CWND_GAIN;
    b.inflight_hi = 60_000;
    b.extra_acked = 50_000; // large headroom

    b.updateCwnd(MSS);

    // cwnd must not exceed inflight_hi.
    try std.testing.expect(b.cwnd <= b.inflight_hi);
}

test "bbr: regression — ProbeRTT only enters from ProbeBW" {
    // Bug: checkProbeRtt could fire during Startup or Drain, entering
    // ProbeRTT before the pipe was filled.
    var b = Bbr.init();
    b.state = .startup;
    b.min_rtt_ns = 50_000_000;
    b.min_rtt_stamp_ns = 0;

    // 10s later — would trigger ProbeRTT from ProbeBW.
    // But from Startup, it should be ignored.
    b.onAckReceived(.{
        .delivery_rate = 500_000,
        .rtt_ns = 50_000_000,
        .bytes_acked = MSS,
    }, 10_000_000_001);

    // Must still be in Startup (or Drain if BW plateau hit), NOT ProbeRTT.
    try std.testing.expect(b.state != .probe_rtt);
}
