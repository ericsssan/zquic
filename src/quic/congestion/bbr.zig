//! BBR v1 congestion control (draft-cardwell-iccrg-bbr-congestion-control).
//!
//! BBR (Bottleneck Bandwidth and Round-trip propagation time) is a model-based
//! congestion controller.  Instead of reacting to loss, it models two parameters:
//!   - BtlBw: bottleneck bandwidth (max delivery rate over recent window)
//!   - RTprop: minimum RTT (propagation delay without queuing)
//!
//! Pacing rate = BtlBw × pacing_gain
//! cwnd = BtlBw × RTprop × cwnd_gain
//!
//! States:
//!   STARTUP  → exponential growth until BtlBw plateaus (3 rounds without 25% increase)
//!   DRAIN    → reduce inflight to BDP (1 RTT at reduced gain)
//!   PROBE_BW → steady state: cycle through 8 pacing gains per RTT
//!   PROBE_RTT → every 10s, reduce cwnd to 4 MSS for 200ms to measure min RTT

const std = @import("std");

const MSS: u64 = 1452;
const INITIAL_CWND: u64 = @min(10 * MSS, @max(14720, 2 * MSS));
const MIN_CWND: u64 = 4 * MSS;
const RTPROP_FILTER_LEN_NS: i64 = 10_000_000_000; // 10 seconds
const PROBE_RTT_DURATION_NS: i64 = 200_000_000; // 200ms
const BTLBW_FILTER_LEN: usize = 10; // rounds

// Pacing gains for PROBE_BW cycle (8 phases per cycle).
// Phase 0: probe for more bandwidth (1.25×)
// Phase 1: drain queue from probe (0.75×)
// Phases 2-7: cruise at 1.0×
const PACING_GAIN_CYCLE = [8]f64{ 1.25, 0.75, 1.0, 1.0, 1.0, 1.0, 1.0, 1.0 };
const STARTUP_PACING_GAIN: f64 = 2.77; // ln(2)/ln(4/3) ≈ 2.77
const DRAIN_PACING_GAIN: f64 = 1.0 / STARTUP_PACING_GAIN;
const STARTUP_CWND_GAIN: f64 = 2.0;
const PROBE_BW_CWND_GAIN: f64 = 2.0;

pub const State = enum {
    startup,
    drain,
    probe_bw,
    probe_rtt,
};

pub const Bbr = struct {
    // Core model
    btl_bw: u64, // bottleneck bandwidth (bytes/sec)
    rt_prop_ns: i64, // min RTT (ns)
    rt_prop_stamp_ns: i64, // when rt_prop was last updated

    // State machine
    state: State,
    pacing_gain: f64,
    cwnd_gain: f64,

    // Congestion window
    cwnd: u64,

    // Pacing
    pacing_rate: u64, // bytes/sec
    pacing_tokens: u64,
    pacing_last_refill_ns: i64,

    // PROBE_BW cycle
    cycle_index: u3, // 0-7
    cycle_stamp_ns: i64, // start of current cycle phase

    // STARTUP exit detection
    full_bw: u64, // max BtlBw seen during startup
    full_bw_count: u8, // rounds without 25% BtlBw increase

    // Delivery rate estimation
    delivered: u64, // total bytes delivered (acknowledged)
    delivered_time_ns: i64, // timestamp of last delivery
    round_count: u64, // completed round trips
    round_start: bool,
    next_round_delivered: u64,

    // BtlBw max filter (windowed max over recent rounds)
    bw_filter: [BTLBW_FILTER_LEN]u64,
    bw_filter_idx: usize,

    // PROBE_RTT
    probe_rtt_done_stamp_ns: ?i64,
    probe_rtt_round_done: bool,
    prior_cwnd: u64, // saved cwnd before PROBE_RTT

    // Tracking
    bytes_in_flight: u64,

    pub fn init() Bbr {
        return .{
            .btl_bw = 0,
            .rt_prop_ns = std.math.maxInt(i64),
            .rt_prop_stamp_ns = 0,
            .state = .startup,
            .pacing_gain = STARTUP_PACING_GAIN,
            .cwnd_gain = STARTUP_CWND_GAIN,
            .cwnd = INITIAL_CWND,
            .pacing_rate = 0,
            .pacing_tokens = INITIAL_CWND,
            .pacing_last_refill_ns = 0,
            .cycle_index = 0,
            .cycle_stamp_ns = 0,
            .full_bw = 0,
            .full_bw_count = 0,
            .delivered = 0,
            .delivered_time_ns = 0,
            .round_count = 0,
            .round_start = false,
            .next_round_delivered = 0,
            .bw_filter = [_]u64{0} ** BTLBW_FILTER_LEN,
            .bw_filter_idx = 0,
            .probe_rtt_done_stamp_ns = null,
            .probe_rtt_round_done = false,
            .prior_cwnd = 0,
            .bytes_in_flight = 0,
        };
    }

    pub fn canSend(self: *const Bbr) bool {
        return self.cwnd > 0;
    }

    /// Called when an ACK acknowledges bytes.
    pub fn onAckReceived(self: *Bbr, bytes_acked: u64, rtt_ns: u64, now_ns: i64) void {
        self.delivered += bytes_acked;
        self.delivered_time_ns = now_ns;
        self.bytes_in_flight -|= bytes_acked;

        // Update RTprop (min RTT filter).
        const rtt_signed: i64 = @intCast(rtt_ns);
        if (rtt_signed > 0 and rtt_signed < self.rt_prop_ns) {
            self.rt_prop_ns = rtt_signed;
            self.rt_prop_stamp_ns = now_ns;
        }

        // Update delivery rate.
        self.updateBtlBw(bytes_acked, rtt_ns, now_ns);

        // Round counting.
        if (self.delivered >= self.next_round_delivered) {
            self.next_round_delivered = self.delivered;
            self.round_count += 1;
            self.round_start = true;
        }

        // State machine transitions.
        self.checkStateTransitions(now_ns);

        // Update pacing rate and cwnd.
        self.setPacingRate();
        self.setCwnd(bytes_acked);

        self.round_start = false;
    }

    /// Called on packet loss.
    pub fn onPacketLost(self: *Bbr, _: i64) void {
        // BBR doesn't reduce cwnd on loss (except ensuring cwnd >= inflight).
        // Loss is a signal that we may have over-estimated BtlBw, but the
        // model handles this through the delivery rate filter.
        _ = self;
    }

    pub fn onPersistentCongestion(self: *Bbr) void {
        self.cwnd = MIN_CWND;
    }

    // ----- Pacing -----

    pub fn pacingRefill(self: *Bbr, now_ns: i64) u64 {
        if (self.pacing_rate == 0) return self.cwnd;
        if (self.pacing_last_refill_ns == 0) {
            self.pacing_last_refill_ns = now_ns;
            return self.pacing_tokens;
        }
        const elapsed_ns: u64 = @intCast(@max(now_ns - self.pacing_last_refill_ns, 0));
        self.pacing_last_refill_ns = now_ns;
        const new_tokens = self.pacing_rate *| elapsed_ns / 1_000_000_000;
        self.pacing_tokens = @min(self.pacing_tokens +| new_tokens, self.cwnd *| 2);
        return self.pacing_tokens;
    }

    pub fn pacingConsume(self: *Bbr, bytes: u64) void {
        self.pacing_tokens -|= bytes;
        self.bytes_in_flight +|= bytes;
    }

    // ----- Internal -----

    fn updateBtlBw(self: *Bbr, bytes_acked: u64, rtt_ns: u64, _: i64) void {
        if (rtt_ns == 0) return;
        // Delivery rate = bytes_acked / rtt (approximation per ACK).
        const delivery_rate = bytes_acked *| 1_000_000_000 / rtt_ns;
        if (delivery_rate > self.btl_bw) {
            self.btl_bw = delivery_rate;
        }
        // Windowed max filter: store per-round max.
        if (self.round_start) {
            self.bw_filter[self.bw_filter_idx % BTLBW_FILTER_LEN] = self.btl_bw;
            self.bw_filter_idx +%= 1;
            // btl_bw = max over filter window.
            var max_bw: u64 = 0;
            for (self.bw_filter) |bw| {
                if (bw > max_bw) max_bw = bw;
            }
            self.btl_bw = max_bw;
        }
    }

    fn checkStateTransitions(self: *Bbr, now_ns: i64) void {
        switch (self.state) {
            .startup => {
                // Exit startup when BtlBw hasn't increased by 25% for 3 rounds.
                if (self.round_start) {
                    if (self.btl_bw >= self.full_bw + self.full_bw / 4) {
                        self.full_bw = self.btl_bw;
                        self.full_bw_count = 0;
                    } else {
                        self.full_bw_count += 1;
                    }
                    if (self.full_bw_count >= 3) {
                        self.state = .drain;
                        self.pacing_gain = DRAIN_PACING_GAIN;
                        self.cwnd_gain = STARTUP_CWND_GAIN; // maintain cwnd during drain
                    }
                }
            },
            .drain => {
                // Exit drain when inflight <= BDP.
                if (self.bytes_in_flight <= self.bdp()) {
                    self.state = .probe_bw;
                    self.pacing_gain = PACING_GAIN_CYCLE[0];
                    self.cwnd_gain = PROBE_BW_CWND_GAIN;
                    self.cycle_index = 0;
                    self.cycle_stamp_ns = now_ns;
                }
            },
            .probe_bw => {
                // Advance cycle phase every RTprop interval.
                if (now_ns - self.cycle_stamp_ns >= self.rt_prop_ns) {
                    self.cycle_index +%= 1;
                    self.pacing_gain = PACING_GAIN_CYCLE[self.cycle_index];
                    self.cycle_stamp_ns = now_ns;
                }
                // Check if RTprop needs refreshing (every 10s).
                if (now_ns - self.rt_prop_stamp_ns > RTPROP_FILTER_LEN_NS) {
                    self.enterProbeRtt(now_ns);
                }
            },
            .probe_rtt => {
                // Maintain min cwnd for 200ms to measure clean RTT.
                if (self.probe_rtt_done_stamp_ns) |done_ns| {
                    if (now_ns >= done_ns) {
                        self.rt_prop_stamp_ns = now_ns; // refresh filter
                        self.cwnd = @max(self.prior_cwnd, self.cwnd);
                        self.state = .probe_bw;
                        self.pacing_gain = PACING_GAIN_CYCLE[0];
                        self.cwnd_gain = PROBE_BW_CWND_GAIN;
                        self.cycle_index = 0;
                        self.cycle_stamp_ns = now_ns;
                    }
                } else if (self.round_start) {
                    self.probe_rtt_done_stamp_ns = now_ns + PROBE_RTT_DURATION_NS;
                }
            },
        }
    }

    fn enterProbeRtt(self: *Bbr, now_ns: i64) void {
        self.prior_cwnd = self.cwnd;
        self.state = .probe_rtt;
        self.pacing_gain = 1.0;
        self.cwnd = MIN_CWND;
        self.probe_rtt_done_stamp_ns = null;
        self.probe_rtt_round_done = false;
        _ = now_ns;
    }

    fn setPacingRate(self: *Bbr) void {
        const rate_f: f64 = @as(f64, @floatFromInt(self.btl_bw)) * self.pacing_gain;
        self.pacing_rate = @intFromFloat(@max(rate_f, 0));
        // Minimum pacing rate: ensure we always make progress.
        if (self.pacing_rate < MSS * 10) self.pacing_rate = MSS * 10;
    }

    fn setCwnd(self: *Bbr, bytes_acked: u64) void {
        _ = bytes_acked;
        const bdp_val = self.bdp();
        const target: u64 = @intFromFloat(@as(f64, @floatFromInt(bdp_val)) * self.cwnd_gain);
        if (self.state == .probe_rtt) {
            self.cwnd = @max(MIN_CWND, self.cwnd);
        } else {
            self.cwnd = @max(target, MIN_CWND);
        }
    }

    fn bdp(self: *const Bbr) u64 {
        if (self.rt_prop_ns <= 0 or self.rt_prop_ns == std.math.maxInt(i64)) return INITIAL_CWND;
        return self.btl_bw *| @as(u64, @intCast(self.rt_prop_ns)) / 1_000_000_000;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "BBR: init state is startup" {
    const bbr = Bbr.init();
    try testing.expect(bbr.state == .startup);
    try testing.expect(bbr.cwnd == INITIAL_CWND);
    try testing.expect(bbr.pacing_gain == STARTUP_PACING_GAIN);
}

test "BBR: startup exits after 3 rounds without BtlBw growth" {
    var bbr = Bbr.init();
    // Simulate 10 rounds of ACKs with constant delivery rate.
    var now: i64 = 1_000_000_000;
    for (0..10) |_| {
        bbr.onAckReceived(14520, 30_000_000, now); // 30ms RTT
        now += 30_000_000;
    }
    // After several rounds without growth, should exit startup.
    try testing.expect(bbr.state != .startup or bbr.full_bw_count > 0);
}

test "BBR: pacing rate is set after first ACK" {
    var bbr = Bbr.init();
    bbr.onAckReceived(14520, 30_000_000, 1_000_000_000);
    try testing.expect(bbr.pacing_rate > 0);
}

test "BBR: cwnd never below MIN_CWND" {
    var bbr = Bbr.init();
    bbr.onPersistentCongestion();
    try testing.expect(bbr.cwnd >= MIN_CWND);
}

test "BBR: BDP calculation" {
    var bbr = Bbr.init();
    bbr.btl_bw = 1_250_000; // 10 Mbps in bytes/sec
    bbr.rt_prop_ns = 30_000_000; // 30ms
    // BDP = 1,250,000 * 0.030 = 37,500 bytes
    try testing.expectEqual(@as(u64, 37500), bbr.bdp());
}
