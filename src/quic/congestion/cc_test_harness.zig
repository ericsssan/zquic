//! Congestion control test harness — drive BBR or CUBIC with synthetic events.
//!
//! Inspired by quiche's `TestSender` and s2n-quic's `simulation.rs`.
//! Feeds ACK/loss/RTT events directly to the CC algorithm, bypassing the
//! full protocol stack. Records cwnd history for assertions.

const std = @import("std");
const common = @import("common.zig");
const DeliveryRateSample = common.DeliveryRateSample;
const MSS = common.MSS;
const INITIAL_CWND = common.INITIAL_CWND;
const bbr_mod = @import("bbr.zig");
const Bbr = bbr_mod.Bbr;
const cubic_mod = @import("cubic.zig");
const Cubic = cubic_mod.Cubic;

const MAX_HISTORY = 1024;

/// Generic CC test driver. Works with both Bbr and Cubic.
pub fn CcTestHarness(comptime CC: type) type {
    return struct {
        const Self = @This();

        cc: CC,
        now_ns: i64,
        round: u64,
        cwnd_history: [MAX_HISTORY]u64,
        history_len: usize,

        pub fn init() Self {
            var self = Self{
                .cc = CC.init(),
                .now_ns = 1_000_000_000, // start at 1s
                .round = 0,
                .cwnd_history = undefined,
                .history_len = 0,
            };
            self.recordCwnd();
            return self;
        }

        /// Send an ACK event with the given parameters.
        pub fn ack(self: *Self, bytes_acked: u64, rtt_ns: u64, delivery_rate: u64) void {
            self.cc.onAckReceived(.{
                .bytes_acked = bytes_acked,
                .rtt_ns = rtt_ns,
                .delivery_rate = delivery_rate,
                .round_start = false,
            }, self.now_ns);
            self.recordCwnd();
        }

        /// Send an ACK that marks the start of a new round.
        pub fn ackRoundStart(self: *Self, bytes_acked: u64, rtt_ns: u64, delivery_rate: u64) void {
            self.round += 1;
            self.cc.onAckReceived(.{
                .bytes_acked = bytes_acked,
                .rtt_ns = rtt_ns,
                .delivery_rate = delivery_rate,
                .round_start = true,
            }, self.now_ns);
            self.recordCwnd();
        }

        /// Send an ACK with full control over the sample.
        pub fn ackSample(self: *Self, sample: DeliveryRateSample) void {
            if (sample.round_start) self.round += 1;
            self.cc.onAckReceived(sample, self.now_ns);
            self.recordCwnd();
        }

        /// Report a loss event.
        pub fn loss(self: *Self, bytes_lost: u64) void {
            self.cc.onPacketLost(bytes_lost, self.now_ns);
            self.recordCwnd();
        }

        /// Trigger persistent congestion.
        pub fn persistentCongestion(self: *Self) void {
            self.cc.onPersistentCongestion();
            self.recordCwnd();
        }

        /// Advance virtual time by `ns` nanoseconds.
        pub fn advance(self: *Self, ns: i64) void {
            self.now_ns += ns;
        }

        /// Current cwnd.
        pub fn cwnd(self: *const Self) u64 {
            return self.cc.cwnd;
        }

        /// Last recorded cwnd (same as cwnd but from history).
        pub fn lastCwnd(self: *const Self) u64 {
            if (self.history_len == 0) return self.cc.cwnd;
            return self.cwnd_history[self.history_len - 1];
        }

        /// Simulate N rounds of steady ACKs (1 MSS per ACK, round_start on first).
        pub fn steadyRounds(self: *Self, n: usize, rtt_ns: u64, delivery_rate: u64) void {
            for (0..n) |_| {
                self.advance(@intCast(rtt_ns));
                self.ackRoundStart(MSS, rtt_ns, delivery_rate);
            }
        }

        /// Simulate slow start: N rounds where each round ACKs `cwnd` worth of bytes.
        /// Returns the cwnd after slow start.
        pub fn runSlowStart(self: *Self, rounds: usize, rtt_ns: u64) u64 {
            for (0..rounds) |_| {
                const bytes = self.cc.cwnd;
                self.advance(@intCast(rtt_ns));
                // Delivery rate = cwnd / rtt (in bytes/sec)
                const dr: u64 = @intCast(@as(u128, bytes) * 1_000_000_000 / rtt_ns);
                self.ackRoundStart(bytes, rtt_ns, dr);
            }
            return self.cc.cwnd;
        }

        fn recordCwnd(self: *Self) void {
            if (self.history_len < MAX_HISTORY) {
                self.cwnd_history[self.history_len] = self.cc.cwnd;
                self.history_len += 1;
            }
        }
    };
}

// ---------------------------------------------------------------------------
// CUBIC tests
// ---------------------------------------------------------------------------

test "cc harness: cubic slow start doubles cwnd per round" {
    const testing = std.testing;
    var h = CcTestHarness(Cubic).init();
    const rtt: u64 = 50_000_000; // 50ms

    const initial = h.cwnd();
    // In slow start, ACKing cwnd bytes adds cwnd to cwnd → doubles.
    const after = h.runSlowStart(1, rtt);
    try testing.expectEqual(initial * 2, after);

    // Second round: doubles again.
    const after2 = h.runSlowStart(1, rtt);
    try testing.expectEqual(initial * 4, after2);
}

test "cc harness: cubic loss reduces cwnd by beta" {
    const testing = std.testing;
    var h = CcTestHarness(Cubic).init();

    // Grow cwnd large enough that beta reduction stays above MIN_CWND.
    h.cc.cwnd = 100 * MSS;
    const before = h.cwnd();

    h.loss(0);
    const after = h.cwnd();

    // CUBIC beta = 0.7
    const expected: u64 = @intFromFloat(@as(f64, @floatFromInt(before)) * 0.7);
    try testing.expectEqual(expected, after);
    try testing.expect(after < before);
}

test "cc harness: cubic recovery — cwnd grows after loss" {
    const testing = std.testing;
    var h = CcTestHarness(Cubic).init();
    const rtt: u64 = 50_000_000;

    h.cc.cwnd = 50 * MSS;
    h.loss(0);
    const after_loss = h.cwnd();

    // Feed ACKs for several rounds
    h.steadyRounds(20, rtt, 1_000_000);
    try testing.expect(h.cwnd() > after_loss);
}

test "cc harness: cubic persistent congestion collapses to 2*MSS" {
    const testing = std.testing;
    var h = CcTestHarness(Cubic).init();

    h.cc.cwnd = 100 * MSS;
    h.persistentCongestion();

    try testing.expectEqual(2 * MSS, h.cwnd());
}

// ---------------------------------------------------------------------------
// BBR tests
// ---------------------------------------------------------------------------

test "cc harness: bbr startup grows cwnd" {
    const testing = std.testing;
    var h = CcTestHarness(Bbr).init();
    const rtt: u64 = 50_000_000;

    try testing.expectEqual(bbr_mod.State.startup, h.cc.state);
    const initial = h.cwnd();

    // Startup: cwnd grows by bytes_acked each ACK.
    h.advance(@intCast(rtt));
    h.ackRoundStart(MSS, rtt, 500_000);
    try testing.expect(h.cwnd() > initial);
}

test "cc harness: bbr startup → drain → probe_bw" {
    const testing = std.testing;
    var h = CcTestHarness(Bbr).init();
    const rtt: u64 = 50_000_000;

    // Simulate growing bandwidth to fill the pipe.
    var bw: u64 = 100_000;
    var round: usize = 0;
    while (h.cc.state == .startup and round < 20) : (round += 1) {
        bw = bw * 3 / 2;
        h.advance(@intCast(rtt));
        h.ackRoundStart(10 * MSS, rtt, bw);
    }

    // Stabilize bandwidth — should plateau and exit startup.
    const stable_bw = bw;
    while (h.cc.state == .startup and round < 40) : (round += 1) {
        h.advance(@intCast(rtt));
        h.ackRoundStart(10 * MSS, rtt, stable_bw);
    }
    try testing.expect(h.cc.filled_pipe);

    // Drain until inflight ≤ BDP.
    while (h.cc.state == .drain and round < 60) : (round += 1) {
        h.advance(@intCast(rtt));
        h.ackSample(.{
            .delivery_rate = stable_bw,
            .rtt_ns = rtt,
            .bytes_acked = 10 * MSS,
            .prior_inflight = 1000, // way below BDP
            .round_start = true,
        });
    }
    try testing.expectEqual(bbr_mod.State.probe_bw, h.cc.state);
}

test "cc harness: bbr persistent congestion resets to startup" {
    const testing = std.testing;
    var h = CcTestHarness(Bbr).init();

    // Move to probe_bw first.
    h.cc.state = .probe_bw;
    h.cc.filled_pipe = true;
    h.cc.cwnd = 100_000;

    h.persistentCongestion();

    try testing.expectEqual(bbr_mod.State.startup, h.cc.state);
    try testing.expect(!h.cc.filled_pipe);
    try testing.expectEqual(4 * MSS, h.cwnd()); // BBR_MIN_CWND
}

test "cc harness: bbr pacing rate tracks bandwidth" {
    const testing = std.testing;
    var h = CcTestHarness(Bbr).init();
    const rtt: u64 = 50_000_000;

    // Feed several rounds of ACKs with known delivery rate.
    const target_bw: u64 = 1_000_000; // 1 MB/s
    for (0..5) |_| {
        h.advance(@intCast(rtt));
        h.ackRoundStart(MSS, rtt, target_bw);
    }

    // Pacing rate should be based on max_bw.
    try testing.expect(h.cc.pacing.rate > 0);
    try testing.expect(h.cc.max_bw > 0);
}

test "cc harness: bbr loss bounding via sample" {
    const testing = std.testing;
    var h = CcTestHarness(Bbr).init();
    const rtt: u64 = 50_000_000;

    // Set up in probe_bw UP phase.
    h.cc.state = .probe_bw;
    h.cc.probe_bw_phase = .up;
    h.cc.filled_pipe = true;
    h.cc.max_bw = 1_000_000;
    h.cc.min_rtt_ns = rtt;
    h.cc.inflight_hi = 200_000;
    h.cc.bw_hi = std.math.maxInt(u64);

    const old_hi = h.cc.inflight_hi;

    // Accumulate excessive loss in round.
    h.ackSample(.{ .bytes_acked = 5000, .bytes_lost = 0 });
    h.ackSample(.{ .bytes_acked = 5000, .bytes_lost = 400 });
    // Round start triggers evaluation.
    h.advance(@intCast(rtt));
    h.ackSample(.{
        .bytes_acked = 1000,
        .bytes_lost = 0,
        .round_start = true,
        .prior_inflight = 100_000,
    });

    try testing.expect(h.cc.inflight_hi < old_hi);
}
