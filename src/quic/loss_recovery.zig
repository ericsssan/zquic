//! RFC 9002 Loss Detection and Recovery.
//!
//! Implements:
//!   - RTT estimation (§5)
//!   - Sent packet tracking via O(1) ring buffer (modular index on pn)
//!   - Packet-threshold and time-threshold loss detection (§6.1)
//!   - PTO calculation (§6.2)

const std = @import("std");

// ---------------------------------------------------------------------------
// Constants (RFC 9002)
// ---------------------------------------------------------------------------

pub const K_PACKET_THRESHOLD: u64 = 3; // §6.1.1
pub const K_TIME_THRESHOLD_NUM: u64 = 9; // 9/8 threshold (§6.1.2)
pub const K_TIME_THRESHOLD_DEN: u64 = 8;
pub const K_GRANULARITY_NS: u64 = 1_000_000; // 1ms minimum timer granularity
pub const K_INITIAL_RTT_NS: u64 = 333_000_000; // 333ms per §5.3
pub const MAX_SENT: usize = 256; // Ring buffer capacity
pub const MAX_FRAMES_PER_PACKET: usize = 4;
pub const MAX_LOSS_EVENTS: usize = 16;

// ---------------------------------------------------------------------------
// FrameInfo — per-frame metadata for retransmission
// ---------------------------------------------------------------------------

pub const FrameInfo = union(enum) {
    // `none` is listed first so its tag value is 0 — this allows std.mem.zeroes()
    // to produce a valid FrameInfo (zeroed bytes == .none tag).
    none,
    stream: struct { stream_id: u62, offset: u62, len: u16, fin: bool },
    crypto_frame: struct { offset: u62, len: u16 },
    ping,
    handshake_done,
    max_data: u62,
    max_stream_data: struct { stream_id: u62, max_data: u62 },
    reset_stream: struct { stream_id: u62, error_code: u62, final_size: u62 },
    connection_close,
};

pub const SentFrameInfo = struct {
    frames: [MAX_FRAMES_PER_PACKET]FrameInfo = .{.none} ** MAX_FRAMES_PER_PACKET,
    count: u8 = 0,
};

// ---------------------------------------------------------------------------
// RTT Estimator (RFC 9002 §5)
// ---------------------------------------------------------------------------

pub const RttEstimator = struct {
    min_rtt: u64 = K_INITIAL_RTT_NS,
    smoothed_rtt: u64 = K_INITIAL_RTT_NS,
    rtt_var: u64 = K_INITIAL_RTT_NS / 2,
    latest_rtt: u64 = K_INITIAL_RTT_NS,
    initialized: bool = false, // false until first real sample

    /// Update RTT estimates from a new ACK sample (RFC 9002 §5.3).
    pub fn update(self: *RttEstimator, sample_ns: u64, ack_delay_ns: u64, max_ack_delay_ns: u64) void {
        self.latest_rtt = sample_ns;
        if (sample_ns < self.min_rtt) self.min_rtt = sample_ns;

        if (!self.initialized) {
            self.smoothed_rtt = sample_ns;
            self.rtt_var = sample_ns / 2;
            self.initialized = true;
            return;
        }

        // Adjust sample by ack_delay (capped at max_ack_delay) if it would not
        // push the adjusted RTT below min_rtt.
        var adjusted_rtt = sample_ns;
        if (sample_ns > self.min_rtt) {
            const delay = @min(ack_delay_ns, max_ack_delay_ns);
            if (adjusted_rtt >= delay) {
                adjusted_rtt -= delay;
            }
        }

        // EWMA: rtt_var = 3/4*rtt_var + 1/4*|srtt - adjusted|
        // Use saturating arithmetic to prevent overflow with extreme RTT samples.
        const abs_diff = if (self.smoothed_rtt >= adjusted_rtt)
            self.smoothed_rtt - adjusted_rtt
        else
            adjusted_rtt - self.smoothed_rtt;
        self.rtt_var = (3 *| self.rtt_var +| abs_diff) / 4;

        // EWMA: smoothed_rtt = 7/8*smoothed_rtt + 1/8*adjusted
        self.smoothed_rtt = (7 *| self.smoothed_rtt +| adjusted_rtt) / 8;
    }

    /// PTO base value (RFC 9002 §6.2.1):
    ///   smoothed_rtt + max(4*rtt_var, K_GRANULARITY_NS) + max_ack_delay_ns
    /// Saturating arithmetic prevents overflow with extreme RTT values.
    pub fn ptoBase(self: *const RttEstimator, max_ack_delay_ns: u64) u64 {
        const var_term = @max(4 *| self.rtt_var, K_GRANULARITY_NS);
        return self.smoothed_rtt +| var_term +| max_ack_delay_ns;
    }
};

// ---------------------------------------------------------------------------
// Sent Packet Table — O(1) ring buffer
// ---------------------------------------------------------------------------

pub const SentPacket = struct {
    pn: u64,
    sent_ns: i64,
    size: u16,
    epoch: u8,
    ack_eliciting: bool,
    in_flight: bool,
    valid: bool, // true = slot occupied
};

pub const AckedRange = struct { low: u64, high: u64 };

pub const AckResult = struct {
    newly_acked: u32 = 0,
    bytes_acked: u64 = 0,
    newly_lost: u32 = 0,
    bytes_lost: u64 = 0,
    rtt_updated: bool = false,
    /// Set when loss span across ack-eliciting packets > 3×PTO (RFC 9002 §6.1.2).
    persistent_congestion: bool = false,
    /// Sent timestamp of the largest-acked packet (for ECN congestion reaction).
    largest_acked_sent_ns: ?i64 = null,
    /// Sent timestamp of the earliest ack-eliciting packet declared lost this round.
    earliest_lost_sent_ns: ?i64 = null,
    /// Sent timestamp of the latest ack-eliciting packet declared lost this round.
    latest_lost_sent_ns: ?i64 = null,
    lost_frames: [MAX_LOSS_EVENTS]SentFrameInfo = undefined,
    lost_frame_count: usize = 0,
    acked_frames: [MAX_LOSS_EVENTS]SentFrameInfo = undefined,
    acked_frame_count: usize = 0,
};

/// Returned by remove() — carries both the packet metadata and its frame info.
pub const RemovedPacket = struct {
    pkt: SentPacket,
    fi: SentFrameInfo,
};

pub const SentPacketTable = struct {
    slots: [MAX_SENT]SentPacket,
    frame_info: [MAX_SENT]SentFrameInfo,
    /// Count of valid (occupied) slots per epoch [Initial, Handshake, 1-RTT].
    /// Enables early exit in detectLoss() and lastAckElicitingNs() once all
    /// valid entries for an epoch have been visited.
    valid_per_epoch: [3]u16,

    pub fn init() SentPacketTable {
        var t: SentPacketTable = undefined;
        for (&t.slots) |*s| {
            s.* = .{ .pn = 0, .sent_ns = 0, .size = 0, .epoch = 0, .ack_eliciting = false, .in_flight = false, .valid = false };
        }
        for (&t.frame_info) |*fi| fi.* = .{};
        t.valid_per_epoch = .{ 0, 0, 0 };
        return t;
    }

    /// O(1) add. Modular index = pn & (MAX_SENT-1). Evicts any previous occupant.
    /// Returns the evicted packet (if any) so the caller can adjust bytes_in_flight.
    pub fn add(self: *SentPacketTable, pkt: SentPacket, fi: SentFrameInfo) ?SentPacket {
        const idx = pkt.pn & (MAX_SENT - 1);
        const evicted: ?SentPacket = if (self.slots[idx].valid) self.slots[idx] else null;
        // Decrement evicted slot's epoch count before overwriting.
        if (evicted) |ev| {
            if (ev.epoch < 3) self.valid_per_epoch[ev.epoch] -|= 1;
        }
        self.slots[idx] = pkt;
        self.slots[idx].valid = true;
        self.frame_info[idx] = fi;
        // Increment count for the new packet's epoch.
        if (pkt.epoch < 3) self.valid_per_epoch[pkt.epoch] += 1;
        return evicted;
    }

    /// O(1) lookup. Returns null if slot is empty or belongs to a different pn/epoch.
    pub fn get(self: *const SentPacketTable, pn: u64, epoch: u8) ?SentPacket {
        const idx = pn & (MAX_SENT - 1);
        const slot = self.slots[idx];
        if (slot.valid and slot.pn == pn and slot.epoch == epoch) return slot;
        return null;
    }

    /// O(1) remove. Returns the removed packet and its frame info, or null if not found.
    pub fn remove(self: *SentPacketTable, pn: u64, epoch: u8) ?RemovedPacket {
        const idx = pn & (MAX_SENT - 1);
        const slot = self.slots[idx];
        if (slot.valid and slot.pn == pn and slot.epoch == epoch) {
            self.slots[idx].valid = false;
            if (epoch < 3) self.valid_per_epoch[epoch] -|= 1;
            return .{ .pkt = slot, .fi = self.frame_info[idx] };
        }
        return null;
    }

    /// ACK all packets in [low, high] inclusive for the given epoch.  O(range_size).
    pub fn ackRange(self: *SentPacketTable, low: u64, high: u64, epoch: u8, result: *AckResult, bif: *u64) void {
        if (low > high) return;
        var pn = low;
        while (pn <= high) : (pn += 1) {
            if (self.remove(pn, epoch)) |entry| {
                result.newly_acked += 1;
                result.bytes_acked += entry.pkt.size;
                if (entry.pkt.in_flight) {
                    bif.* = if (bif.* >= entry.pkt.size) bif.* - entry.pkt.size else 0;
                }
                if (result.acked_frame_count < MAX_LOSS_EVENTS) {
                    result.acked_frames[result.acked_frame_count] = entry.fi;
                    result.acked_frame_count += 1;
                }
            }
        }
    }

    /// Scan all slots for packets in the given epoch that are now considered lost.
    /// Uses valid_per_epoch to exit early once all valid slots for this epoch are visited.
    pub fn detectLoss(
        self: *SentPacketTable,
        largest_acked: u64,
        time_threshold_ns: u64,
        now_ns: i64,
        epoch: u8,
        result: *AckResult,
        bif: *u64,
    ) void {
        // Snapshot the count before the loop; we decrement valid_per_epoch as packets
        // are declared lost, but to_find must not change so the early-exit stays correct.
        const to_find: u16 = if (epoch < 3) self.valid_per_epoch[epoch] else 0;
        var found: u16 = 0;
        for (&self.slots, 0..) |*slot, idx| {
            if (found >= to_find) break; // early exit: all valid slots for this epoch visited
            if (!slot.valid or slot.epoch != epoch) continue; // per packet number space
            found += 1;

            // Packet threshold: pn + K_PACKET_THRESHOLD <= largest_acked
            const pkt_threshold_lost = slot.pn + K_PACKET_THRESHOLD <= largest_acked;

            // Time threshold: elapsed since send >= time_threshold_ns
            const elapsed: u64 = if (now_ns >= slot.sent_ns)
                @intCast(now_ns - slot.sent_ns)
            else
                0;
            const time_threshold_lost = elapsed >= time_threshold_ns;

            if (pkt_threshold_lost or time_threshold_lost) {
                slot.valid = false;
                if (epoch < 3) self.valid_per_epoch[epoch] -|= 1;
                result.newly_lost += 1;
                result.bytes_lost += slot.size;
                if (slot.in_flight) {
                    bif.* -|= slot.size;
                }
                if (result.lost_frame_count < MAX_LOSS_EVENTS) {
                    result.lost_frames[result.lost_frame_count] = self.frame_info[idx];
                    result.lost_frame_count += 1;
                }
                // Track earliest/latest sent_ns for persistent congestion detection.
                if (slot.ack_eliciting) {
                    if (result.earliest_lost_sent_ns == null or slot.sent_ns < result.earliest_lost_sent_ns.?) {
                        result.earliest_lost_sent_ns = slot.sent_ns;
                    }
                    if (result.latest_lost_sent_ns == null or slot.sent_ns > result.latest_lost_sent_ns.?) {
                        result.latest_lost_sent_ns = slot.sent_ns;
                    }
                }
            }
        }
    }

    /// Return the sent_ns of the in-flight ack-eliciting packet with the highest pn,
    /// or null if none exist.  Used as the base for PTO timer calculation.
    /// Uses valid_per_epoch to exit early once all valid slots across all epochs are visited.
    pub fn lastAckElicitingNs(self: *const SentPacketTable) ?i64 {
        const to_find: u32 = @as(u32, self.valid_per_epoch[0]) +
            self.valid_per_epoch[1] +
            self.valid_per_epoch[2];
        if (to_find == 0) return null;
        var found: u32 = 0;
        var best_pn: u64 = 0;
        var best_ns: ?i64 = null;
        for (self.slots) |slot| {
            if (found >= to_find) break; // early exit: all valid slots visited
            if (!slot.valid) continue;
            found += 1;
            if (slot.ack_eliciting and slot.in_flight) {
                if (best_ns == null or slot.pn > best_pn) {
                    best_pn = slot.pn;
                    best_ns = slot.sent_ns;
                }
            }
        }
        return best_ns;
    }
};

// ---------------------------------------------------------------------------
// Loss Recovery — top-level coordinator
// ---------------------------------------------------------------------------

pub const LossRecovery = struct {
    rtt: RttEstimator,
    sent: SentPacketTable,
    bytes_in_flight: u64,
    largest_acked: [3]u64, // per epoch [Initial, Handshake, 1-RTT]
    last_ack_eliciting_ns: ?i64,
    pto_count: u32,

    pub fn init() LossRecovery {
        return .{
            .rtt = .{},
            .sent = SentPacketTable.init(),
            .bytes_in_flight = 0,
            .largest_acked = [_]u64{0} ** 3,
            .last_ack_eliciting_ns = null,
            .pto_count = 0,
        };
    }

    /// Record a newly-sent packet.
    pub fn onPacketSent(
        self: *LossRecovery,
        pn: u64,
        epoch: u8,
        size: usize,
        ack_eliciting: bool,
        now_ns: i64,
        frame_info: SentFrameInfo,
    ) void {
        const sz: u16 = @intCast(@min(size, @as(usize, 0xffff)));
        // add() evicts any existing occupant at pn % MAX_SENT.
        // If the evicted packet was still in flight, subtract its size from bytes_in_flight
        // to avoid double-counting (the in-flight accounting for the evicted packet is lost).
        if (self.sent.add(.{
            .pn = pn,
            .sent_ns = now_ns,
            .size = sz,
            .epoch = epoch,
            .ack_eliciting = ack_eliciting,
            .in_flight = ack_eliciting,
            .valid = true,
        }, frame_info)) |evicted| {
            if (evicted.in_flight) {
                self.bytes_in_flight -|= evicted.size;
            }
        }
        if (ack_eliciting) {
            self.bytes_in_flight += sz;
            self.last_ack_eliciting_ns = now_ns;
        }
    }

    /// Process a received ACK frame.  Returns loss/ack statistics.
    pub fn onAckReceived(
        self: *LossRecovery,
        largest_acked: u64,
        ack_delay_ns: u64,
        ranges: []const AckedRange,
        epoch: u8,
        now_ns: i64,
        max_ack_delay_ns: u64,
    ) AckResult {
        // 1. Update largest_acked per epoch
        if (largest_acked > self.largest_acked[epoch]) {
            self.largest_acked[epoch] = largest_acked;
        }

        var result = AckResult{};

        // 2. RTT sample: use the largest-acked packet if it's ack-eliciting
        if (self.sent.get(largest_acked, epoch)) |pkt| {
            result.largest_acked_sent_ns = pkt.sent_ns;
            if (pkt.ack_eliciting) {
                const sample: u64 = if (now_ns >= pkt.sent_ns)
                    @intCast(now_ns - pkt.sent_ns)
                else
                    0;
                self.rtt.update(sample, ack_delay_ns, max_ack_delay_ns);
                result.rtt_updated = true;
            }
        }

        // 3. Remove all acknowledged packets
        for (ranges) |r| {
            self.sent.ackRange(r.low, r.high, epoch, &result, &self.bytes_in_flight);
        }

        // 4. Compute time threshold: max(9/8 × max(srtt, latest_rtt), K_GRANULARITY_NS)
        const max_rtt = @max(self.rtt.smoothed_rtt, self.rtt.latest_rtt);
        const time_threshold_ns = @max(
            (max_rtt * K_TIME_THRESHOLD_NUM + K_TIME_THRESHOLD_DEN - 1) / K_TIME_THRESHOLD_DEN,
            K_GRANULARITY_NS,
        );

        // 5. Detect loss among remaining unacked packets in this epoch
        self.sent.detectLoss(
            self.largest_acked[epoch],
            time_threshold_ns,
            now_ns,
            epoch,
            &result,
            &self.bytes_in_flight,
        );

        // 6. Persistent congestion detection (RFC 9002 §6.1.2).
        // If the span between the earliest and latest ack-eliciting lost packets
        // exceeds 3×PTO, mark as persistent congestion.
        if (result.earliest_lost_sent_ns != null and result.latest_lost_sent_ns != null) {
            const e = result.earliest_lost_sent_ns.?;
            const l = result.latest_lost_sent_ns.?;
            if (l >= e) {
                const loss_span: u64 = @intCast(l - e);
                const pc_duration = self.persistentCongestionDuration(max_ack_delay_ns);
                if (loss_span > pc_duration) {
                    result.persistent_congestion = true;
                }
            }
        }

        // Note: last_ack_eliciting_ns is kept as-is (updated incrementally in
        // onPacketSent). A stale value causes PTO to fire slightly early, which
        // is safe — it just means an extra probe. This avoids an O(64) scan per ACK.

        return result;
    }

    /// Persistent congestion duration = ptoBase × 3 (RFC 9002 §6.1.2 multiplier).
    pub fn persistentCongestionDuration(self: *const LossRecovery, max_ack_delay_ns: u64) u64 {
        return self.rtt.ptoBase(max_ack_delay_ns) *| 3;
    }

    /// PTO deadline: null when nothing is in flight.
    /// Otherwise: last_ack_eliciting_ns + ptoBase × 2^min(pto_count, 20).
    /// Uses saturating arithmetic to avoid overflow when RTT or pto_count is extreme.
    pub fn ptoDeadline(self: *const LossRecovery, max_ack_delay_ns: u64) ?i64 {
        if (self.bytes_in_flight == 0) return null;
        const base_ns = self.last_ack_eliciting_ns orelse return null;
        const pto = self.rtt.ptoBase(max_ack_delay_ns);
        const shift: u6 = @intCast(@min(self.pto_count, 20));
        // Saturating multiply: prevents u64 overflow on extreme RTT values.
        const backoff: u64 = pto *| (@as(u64, 1) << shift);
        // Clamp to i64 max before casting, then add with saturation.
        const max_i64: u64 = @as(u64, std.math.maxInt(i64));
        const clamped: i64 = @intCast(@min(backoff, max_i64));
        return base_ns +| clamped;
    }

    pub fn onPtoFired(self: *LossRecovery) void {
        self.pto_count += 1;
    }

    pub fn resetPtoCount(self: *LossRecovery) void {
        self.pto_count = 0;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "rtt: initial defaults are K_INITIAL_RTT_NS" {
    const testing = std.testing;
    const rtt = RttEstimator{};
    try testing.expectEqual(K_INITIAL_RTT_NS, rtt.smoothed_rtt);
    try testing.expectEqual(K_INITIAL_RTT_NS, rtt.min_rtt);
    try testing.expectEqual(K_INITIAL_RTT_NS, rtt.latest_rtt);
    try testing.expectEqual(K_INITIAL_RTT_NS / 2, rtt.rtt_var);
    try testing.expect(!rtt.initialized);
}

test "rtt: first sample sets smoothed_rtt = sample, rtt_var = sample/2" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(100_000_000, 0, 25_000_000);
    try testing.expectEqual(@as(u64, 100_000_000), rtt.smoothed_rtt);
    try testing.expectEqual(@as(u64, 50_000_000), rtt.rtt_var);
    try testing.expectEqual(@as(u64, 100_000_000), rtt.latest_rtt);
    try testing.expect(rtt.initialized);
}

test "rtt: ack_delay capped at max_ack_delay when computing adjusted_rtt" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    // First sample to initialize
    rtt.update(100_000_000, 0, 25_000_000);
    const srtt_after_first = rtt.smoothed_rtt;
    // Second sample: sample=150ms, ack_delay=50ms capped to max_ack_delay=25ms
    // adjusted_rtt = 150ms - 25ms = 125ms  (not 100ms as it would be with 50ms)
    // smoothed_rtt grows toward 125ms, so it must exceed 100ms
    rtt.update(150_000_000, 50_000_000, 25_000_000);
    try testing.expect(rtt.smoothed_rtt > srtt_after_first);
}

test "rtt: min_rtt never increases after lower sample" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(200_000_000, 0, 25_000_000); // first sample
    try testing.expectEqual(@as(u64, 200_000_000), rtt.min_rtt);
    rtt.update(100_000_000, 0, 25_000_000); // lower sample
    try testing.expectEqual(@as(u64, 100_000_000), rtt.min_rtt);
    rtt.update(500_000_000, 0, 25_000_000); // higher sample — min_rtt must not change
    try testing.expectEqual(@as(u64, 100_000_000), rtt.min_rtt);
}

test "sent_table: add and get via modular index" {
    const testing = std.testing;
    var table = SentPacketTable.init();

    // pn=65 maps to slot 65 % 64 = 1
    const pkt = SentPacket{
        .pn = 65,
        .sent_ns = 1000,
        .size = 500,
        .epoch = 0,
        .ack_eliciting = true,
        .in_flight = true,
        .valid = true,
    };
    _ = table.add(pkt, .{});

    const found = table.get(65, 0);
    try testing.expect(found != null);
    try testing.expectEqual(@as(u64, 65), found.?.pn);
    try testing.expectEqual(@as(i64, 1000), found.?.sent_ns);

    // pn=1 maps to same slot but different pn → null
    try testing.expectEqual(@as(?SentPacket, null), table.get(1, 0));
    // same pn, different epoch → null
    try testing.expectEqual(@as(?SentPacket, null), table.get(65, 2));

    // remove works
    const removed = table.remove(65, 0);
    try testing.expect(removed != null);
    try testing.expectEqual(@as(?SentPacket, null), table.get(65, 0));
}

test "sent_table: onPacketSent increments bytes_in_flight; ackRange decrements it" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    lr.onPacketSent(5, 0, 1200, true, 0, .{});
    try testing.expectEqual(@as(u64, 1200), lr.bytes_in_flight);

    var result = AckResult{};
    lr.sent.ackRange(5, 5, 0, &result, &lr.bytes_in_flight);
    try testing.expectEqual(@as(u64, 0), lr.bytes_in_flight);
    try testing.expectEqual(@as(u32, 1), result.newly_acked);
    try testing.expectEqual(@as(u64, 1200), result.bytes_acked);
}

test "loss_detection: packet threshold — pn 1-7 declared lost when largest_acked=10" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send pn 1..10 all at time 0
    var pn: u64 = 1;
    while (pn <= 10) : (pn += 1) {
        lr.onPacketSent(pn, 0, 1200, true, 0, .{});
    }

    // ACK only pn=10; all others remain unacked
    const ranges = [_]AckedRange{.{ .low = 10, .high = 10 }};
    const result = lr.onAckReceived(10, 0, &ranges, 0, 0, 25_000_000);

    // pn 1-7: pn + 3 <= 10  →  lost (7 packets)
    // pn 8-9: 8+3=11 > 10, elapsed=0 < threshold  →  still in flight
    try testing.expectEqual(@as(u32, 1), result.newly_acked);
    try testing.expectEqual(@as(u32, 7), result.newly_lost);
}

test "loss_detection: time threshold — old packet detected as lost" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send pn=1000 at time 0; pn=1 not sent (not in table)
    lr.onPacketSent(1000, 0, 1200, true, 0, .{});

    // ACK pn=1 (not in table — no RTT update, initial values used)
    // Initial smoothed_rtt = 333ms, time_threshold ≈ 375ms
    // now_ns = 400ms > threshold → pn=1000 lost by time threshold
    const ranges = [_]AckedRange{.{ .low = 1, .high = 1 }};
    const result = lr.onAckReceived(1, 0, &ranges, 0, 400_000_000, 25_000_000);

    // pn 1000 + 3 = 1003 > 1 (packet threshold not met)
    // elapsed = 400ms >= ~375ms (time threshold met)
    try testing.expectEqual(@as(u32, 1), result.newly_lost);
    try testing.expectEqual(@as(u32, 0), result.newly_acked);
}

test "pto: deadline is null when no ack-eliciting packets in flight" {
    const testing = std.testing;
    const lr = LossRecovery.init();
    try testing.expectEqual(@as(?i64, null), lr.ptoDeadline(25_000_000));
}

test "sent_table: lastAckElicitingNs returns sent_ns of highest in-flight pn" {
    const testing = std.testing;
    var table = SentPacketTable.init();

    try testing.expectEqual(@as(?i64, null), table.lastAckElicitingNs());

    // Add two in-flight ack-eliciting packets
    _ = table.add(.{ .pn = 5, .sent_ns = 100, .size = 100, .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    _ = table.add(.{ .pn = 10, .sent_ns = 200, .size = 100, .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});

    // Should return sent_ns of pn=10 (highest pn)
    try testing.expectEqual(@as(?i64, 200), table.lastAckElicitingNs());

    // Non-ack-eliciting packets are ignored
    _ = table.add(.{ .pn = 20, .sent_ns = 999, .size = 100, .epoch = 0, .ack_eliciting = false, .in_flight = false, .valid = true }, .{});
    try testing.expectEqual(@as(?i64, 200), table.lastAckElicitingNs());
}

test "pto: deadline is clamped at 2^20 backoff" {
    const testing = std.testing;
    var lr = LossRecovery.init();
    lr.onPacketSent(1, 0, 1200, true, 0, .{});

    const d0 = lr.ptoDeadline(25_000_000).?;

    // Drive pto_count well past 20; backoff should saturate at 2^20
    lr.pto_count = 20;
    const d_at_20 = lr.ptoDeadline(25_000_000).?;

    lr.pto_count = 30; // beyond the clamp
    const d_at_30 = lr.ptoDeadline(25_000_000).?;

    // At count=20 and count=30 the deadline must be identical (clamped)
    try testing.expectEqual(d_at_20, d_at_30);
    // And both must be strictly larger than the base deadline
    try testing.expect(d_at_20 > d0);
}

test "rtt: ack_delay exceeding sample_ns does not underflow adjusted_rtt" {
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.update(100_000_000, 0, 25_000_000);
    rtt.update(50_000_000, 200_000_000, 25_000_000);
    try testing.expect(rtt.smoothed_rtt > 0);
    try testing.expect(rtt.min_rtt <= 50_000_000);
}

test "loss_recovery: onAckReceived with empty ranges slice is safe" {
    const testing = std.testing;
    var lr = LossRecovery.init();
    lr.onPacketSent(1, 0, 1200, true, 0, .{});
    const result = lr.onAckReceived(1, 0, &[_]AckedRange{}, 0, 0, 25_000_000);
    // No ranges → nothing acked, nothing lost
    try testing.expectEqual(@as(u32, 0), result.newly_acked);
    try testing.expectEqual(@as(u64, 1200), lr.bytes_in_flight); // still in flight
}

test "sent_table: eviction decrements bytes_in_flight to avoid double-counting" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send 64 packets (fills the ring buffer exactly)
    var pn: u64 = 0;
    while (pn < MAX_SENT) : (pn += 1) {
        lr.onPacketSent(pn, 0, 1200, true, 0, .{});
    }
    const bif_after_64 = lr.bytes_in_flight;
    try testing.expectEqual(@as(u64, MAX_SENT * 1200), bif_after_64);

    // Send packet pn=64: maps to slot 64 % 64 = 0, evicting pn=0 (still in flight).
    // bytes_in_flight should stay the same (evict 1200, add 1200).
    lr.onPacketSent(MAX_SENT, 0, 1200, true, 0, .{});
    try testing.expectEqual(bif_after_64, lr.bytes_in_flight);
}

test "loss_detection: last_ack_eliciting_ns updated after packets declared lost" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send one ack-eliciting packet
    lr.onPacketSent(1, 0, 1200, true, 0, .{});
    try testing.expect(lr.last_ack_eliciting_ns != null);

    // ACK a much higher pn to trigger loss via packet threshold for pn=1
    // Send pn 2..5 so we have some acked
    var i: u64 = 2;
    while (i <= 10) : (i += 1) {
        lr.onPacketSent(i, 0, 1200, true, 0, .{});
    }
    const ranges = [_]AckedRange{.{ .low = 10, .high = 10 }};
    _ = lr.onAckReceived(10, 0, &ranges, 0, 0, 25_000_000);

    // pn=1 lost (1 + 3 <= 10). All remaining in-flight acked/lost.
    // last_ack_eliciting_ns should be refreshed — pn 2..9 still in flight
    // (pn 1 lost, pn 10 acked)
    try testing.expect(lr.last_ack_eliciting_ns != null); // pn 2..9 still in flight
}

test "pto: deadline saturates on extreme pto values" {
    const testing = std.testing;
    var lr = LossRecovery.init();
    lr.onPacketSent(1, 0, 1200, true, 0, .{});

    // Force an extreme smoothed_rtt that would cause overflow without saturation
    lr.rtt.smoothed_rtt = std.math.maxInt(u64) / 4;
    lr.rtt.rtt_var = std.math.maxInt(u64) / 8;
    lr.pto_count = 20;

    // Must not panic and must return a valid (positive) deadline
    const d = lr.ptoDeadline(0);
    try testing.expect(d != null);
    try testing.expect(d.? > 0);
}

test "pto: deadline doubles per onPtoFired; resets after resetPtoCount" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send one ack-eliciting packet at time 0
    lr.onPacketSent(1, 0, 1200, true, 0, .{});

    const d0 = lr.ptoDeadline(25_000_000);
    try testing.expect(d0 != null);

    lr.onPtoFired(); // pto_count = 1
    const d1 = lr.ptoDeadline(25_000_000);
    try testing.expect(d1 != null);
    // PTO doubles: d1 = base + 2*pto, d0 = base + pto
    // Since base=0: d1 == 2 * d0
    try testing.expectEqual(d0.? * 2, d1.?);

    lr.resetPtoCount(); // pto_count = 0
    const d_reset = lr.ptoDeadline(25_000_000);
    try testing.expectEqual(d0, d_reset);
}

// ---------------------------------------------------------------------------
// New tests — FrameInfo tracking
// ---------------------------------------------------------------------------

test "frame_info: SentFrameInfo stores and retrieves stream frame info" {
    const testing = std.testing;
    var table = SentPacketTable.init();
    var fi = SentFrameInfo{};
    fi.frames[0] = .{ .stream = .{ .stream_id = 4, .offset = 100, .len = 500, .fin = false } };
    fi.count = 1;

    const pkt = SentPacket{
        .pn = 1,
        .sent_ns = 0,
        .size = 500,
        .epoch = 2,
        .ack_eliciting = true,
        .in_flight = true,
        .valid = true,
    };
    _ = table.add(pkt, fi);

    const removed = table.remove(1, 2).?;
    try testing.expectEqual(@as(u8, 1), removed.fi.count);
    switch (removed.fi.frames[0]) {
        .stream => |s| {
            try testing.expectEqual(@as(u62, 4), s.stream_id);
            try testing.expectEqual(@as(u62, 100), s.offset);
            try testing.expectEqual(@as(u16, 500), s.len);
        },
        else => try testing.expect(false),
    }
}

test "frame_info: detectLoss populates lost_frames in AckResult" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    var fi = SentFrameInfo{};
    fi.frames[0] = .{ .stream = .{ .stream_id = 0, .offset = 0, .len = 100, .fin = false } };
    fi.count = 1;
    lr.onPacketSent(1, 0, 100, true, 0, fi);
    lr.onPacketSent(10, 0, 100, true, 0, .{});

    const ranges = [_]AckedRange{.{ .low = 10, .high = 10 }};
    const result = lr.onAckReceived(10, 0, &ranges, 0, 0, 25_000_000);

    // pn=1 lost by packet threshold (1 + 3 <= 10)
    try testing.expectEqual(@as(u32, 1), result.newly_lost);
    try testing.expectEqual(@as(usize, 1), result.lost_frame_count);
    try testing.expectEqual(@as(u8, 1), result.lost_frames[0].count);
    switch (result.lost_frames[0].frames[0]) {
        .stream => |s| try testing.expectEqual(@as(u62, 0), s.stream_id),
        else => try testing.expect(false),
    }
}

test "frame_info: acked packets appear in acked_frames not lost_frames" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    var fi = SentFrameInfo{};
    fi.frames[0] = .ping;
    fi.count = 1;
    lr.onPacketSent(1, 0, 50, true, 0, fi);

    const ranges = [_]AckedRange{.{ .low = 1, .high = 1 }};
    const result = lr.onAckReceived(1, 0, &ranges, 0, 0, 25_000_000);

    try testing.expectEqual(@as(u32, 1), result.newly_acked);
    try testing.expectEqual(@as(usize, 1), result.acked_frame_count);
    try testing.expectEqual(@as(usize, 0), result.lost_frame_count);
    switch (result.acked_frames[0].frames[0]) {
        .ping => {},
        else => try testing.expect(false),
    }
}

test "frame_info: MAX_LOSS_EVENTS caps lost_frames output" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send enough packets so that MAX_LOSS_EVENTS+1 are lost by pkt threshold.
    // Need: top_pn - 3 - 0 + 1 > MAX_LOSS_EVENTS  →  top_pn > MAX_LOSS_EVENTS + 2
    // Use N = MAX_LOSS_EVENTS + 4 packets (pn 0..N-1), ACK pn=N-1.
    // Lost: pn+3 <= N-1  →  pn <= N-4. Count = N-3 = MAX_LOSS_EVENTS+1.
    const N: u64 = MAX_LOSS_EVENTS + 4;
    var pn: u64 = 0;
    while (pn < N) : (pn += 1) {
        lr.onPacketSent(pn, 0, 100, true, 0, .{});
    }
    const top_pn = N - 1;
    const ranges = [_]AckedRange{.{ .low = top_pn, .high = top_pn }};
    const result = lr.onAckReceived(top_pn, 0, &ranges, 0, 0, 25_000_000);

    // lost_frame_count capped at MAX_LOSS_EVENTS, newly_lost exceeds it
    try testing.expectEqual(@as(usize, MAX_LOSS_EVENTS), result.lost_frame_count);
    try testing.expect(result.newly_lost > @as(u32, MAX_LOSS_EVENTS));
}

test "sent_table: power-of-two slot collision evicts correctly" {
    // pn=0 and pn=256 map to the same slot (0 & 255 == 0, 256 & 255 == 0).
    // Adding pn=256 must evict pn=0; get(0, 0) must then return null.
    const testing = std.testing;
    var lr = LossRecovery.init();

    lr.onPacketSent(0, 0, 1200, true, 1_000, .{});
    try testing.expect(lr.sent.get(0, 0) != null);

    lr.onPacketSent(MAX_SENT, 0, 1200, true, 2_000, .{}); // maps to slot 0, evicts pn=0
    try testing.expectEqual(@as(?SentPacket, null), lr.sent.get(0, 0)); // pn=0 gone
    try testing.expect(lr.sent.get(MAX_SENT, 0) != null); // pn=256 present
}

test "sent_table: epoch mismatch in same slot returns null" {
    // Two packets with different epochs that land in the same slot.
    const testing = std.testing;
    var table = SentPacketTable.init();
    _ = table.add(.{ .pn = 1, .sent_ns = 0, .size = 100, .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    // pn=257 & 255 == 1, same slot, different epoch
    _ = table.add(.{ .pn = 257, .sent_ns = 0, .size = 100, .epoch = 2, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    try testing.expectEqual(@as(?SentPacket, null), table.get(1, 0)); // evicted
    try testing.expect(table.get(257, 2) != null); // present
}

test "frame_info: ring buffer eviction preserves new packet frame info" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Fill the ring buffer with MAX_SENT packets (no frame info)
    var pn: u64 = 0;
    while (pn < MAX_SENT) : (pn += 1) {
        lr.onPacketSent(pn, 0, 100, true, 0, .{});
    }

    // Send one more that evicts slot 0 (pn=0), record handshake_done frame info
    var fi = SentFrameInfo{};
    fi.frames[0] = .handshake_done;
    fi.count = 1;
    lr.onPacketSent(MAX_SENT, 0, 100, true, 0, fi);

    // The new packet's frame info should be stored at slot MAX_SENT % MAX_SENT = 0
    const removed = lr.sent.remove(MAX_SENT, 0).?;
    try testing.expectEqual(@as(u8, 1), removed.fi.count);
    switch (removed.fi.frames[0]) {
        .handshake_done => {},
        else => try testing.expect(false),
    }
}

test "sent_table: 128 concurrent unacked packets coexist without eviction" {
    // Verify that 128 packets (half of MAX_SENT=256) can be tracked simultaneously
    // without any eviction occurring due to slot collision.
    const testing = std.testing;
    var lr = LossRecovery.init();

    // Send 128 packets with distinct packet numbers 0..127
    var pn: u64 = 0;
    while (pn < 128) : (pn += 1) {
        lr.onPacketSent(pn, 0, 1200, true, @as(i64, @intCast(pn)) * 1000, .{});
    }

    // All 128 must still be present (no eviction for pn < MAX_SENT/2)
    pn = 0;
    while (pn < 128) : (pn += 1) {
        try testing.expect(lr.sent.get(pn, 0) != null);
    }
}

test "valid_per_epoch: add increments, remove decrements" {
    const testing = std.testing;
    var table = SentPacketTable.init();

    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[0]);
    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[1]);
    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[2]);

    _ = table.add(.{ .pn = 1, .sent_ns = 0, .size = 100, .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    try testing.expectEqual(@as(u16, 1), table.valid_per_epoch[0]);

    _ = table.add(.{ .pn = 2, .sent_ns = 0, .size = 100, .epoch = 1, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    try testing.expectEqual(@as(u16, 1), table.valid_per_epoch[1]);

    _ = table.remove(1, 0);
    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[0]);
    try testing.expectEqual(@as(u16, 1), table.valid_per_epoch[1]);
}

test "valid_per_epoch: eviction decrements old epoch, add increments new epoch" {
    const testing = std.testing;
    var table = SentPacketTable.init();

    // Add pn=0 in epoch 0 (slot 0)
    _ = table.add(.{ .pn = 0, .sent_ns = 0, .size = 100, .epoch = 0, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    try testing.expectEqual(@as(u16, 1), table.valid_per_epoch[0]);

    // Add pn=256 in epoch 1 (same slot 0, evicts epoch 0 packet)
    _ = table.add(.{ .pn = MAX_SENT, .sent_ns = 0, .size = 100, .epoch = 1, .ack_eliciting = true, .in_flight = true, .valid = true }, .{});
    try testing.expectEqual(@as(u16, 0), table.valid_per_epoch[0]); // evicted
    try testing.expectEqual(@as(u16, 1), table.valid_per_epoch[1]); // new packet
}

test "valid_per_epoch: detectLoss decrements on loss" {
    const testing = std.testing;
    var lr = LossRecovery.init();

    lr.onPacketSent(1, 0, 100, true, 0, .{});
    lr.onPacketSent(5, 0, 100, true, 0, .{});
    try testing.expectEqual(@as(u16, 2), lr.sent.valid_per_epoch[0]);

    // ACK pn=5, which triggers loss detection for pn=1 (pn+3 <= 5)
    const ranges = [_]AckedRange{.{ .low = 5, .high = 5 }};
    const result = lr.onAckReceived(5, 0, &ranges, 0, 0, 25_000_000);

    try testing.expectEqual(@as(u32, 1), result.newly_lost);
    // pn=1 lost → valid_per_epoch[0] decremented; pn=5 acked → also decremented
    try testing.expectEqual(@as(u16, 0), lr.sent.valid_per_epoch[0]);
}

// ---------------------------------------------------------------------------
// Persistent congestion tests (Step 7)
// ---------------------------------------------------------------------------

test "persistent_congestion: loss span > 3xPTO sets flag" {
    // Send pn=1..4 at t=0, pn=5 at t=3.2s (> 3×PTO with default RTT).
    // ACK pn=8 → pn=1..5 are lost with span = 3.2s > 3×PTO.
    const testing = std.testing;
    var lr = LossRecovery.init();

    lr.onPacketSent(1, 0, 1200, true, 0, .{});
    lr.onPacketSent(2, 0, 1200, true, 0, .{});
    lr.onPacketSent(3, 0, 1200, true, 0, .{});
    lr.onPacketSent(4, 0, 1200, true, 0, .{});
    lr.onPacketSent(5, 0, 1200, true, 3_200_000_000, .{});
    lr.onPacketSent(8, 0, 1200, true, 3_200_000_000, .{});

    const ranges = [_]AckedRange{.{ .low = 8, .high = 8 }};
    const result = lr.onAckReceived(8, 0, &ranges, 0, 3_200_000_000, 25_000_000);

    try testing.expect(result.persistent_congestion);
    try testing.expect(result.newly_lost >= 5);
}

test "persistent_congestion: loss span <= 3xPTO does not set flag" {
    // All lost packets sent at the same time → span = 0 → no persistent congestion.
    const testing = std.testing;
    var lr = LossRecovery.init();

    lr.onPacketSent(1, 0, 1200, true, 0, .{});
    lr.onPacketSent(2, 0, 1200, true, 0, .{});
    lr.onPacketSent(3, 0, 1200, true, 0, .{});
    lr.onPacketSent(8, 0, 1200, true, 0, .{});

    const ranges = [_]AckedRange{.{ .low = 8, .high = 8 }};
    const result = lr.onAckReceived(8, 0, &ranges, 0, 0, 25_000_000);

    try testing.expect(!result.persistent_congestion);
    try testing.expect(result.newly_lost >= 3);
}

test "valid_per_epoch: lastAckElicitingNs returns null immediately when no valid slots" {
    const testing = std.testing;
    const table = SentPacketTable.init();
    // valid_per_epoch all zeros → to_find == 0 → returns null without scanning
    try testing.expectEqual(@as(?i64, null), table.lastAckElicitingNs());
}

test "rtt: ptoBase saturates instead of overflowing with extreme rtt_var" {
    // If rtt_var is near u64 max, 4*rtt_var would overflow without saturation.
    // With *| the multiply saturates; +| prevents the sum from overflowing.
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.smoothed_rtt = std.math.maxInt(u64) / 2;
    rtt.rtt_var = std.math.maxInt(u64) / 4 + 1; // 4 * this overflows u64 without saturation
    const pto = rtt.ptoBase(0);
    // With saturation: 4 *| rtt_var = maxInt(u64), then +| smoothed = maxInt(u64). Must not panic.
    try testing.expectEqual(std.math.maxInt(u64), pto);
}

test "rtt: ptoBase saturates sum of smoothed + var_term + max_ack_delay" {
    // Verify the three-term sum in ptoBase saturates rather than wrapping.
    const testing = std.testing;
    var rtt = RttEstimator{};
    rtt.smoothed_rtt = std.math.maxInt(u64) - 1;
    rtt.rtt_var = 1; // var_term = max(4, K_GRAN) — either way large
    const pto = rtt.ptoBase(1_000_000); // +1ms would overflow without saturation
    try testing.expectEqual(std.math.maxInt(u64), pto);
}

// ============================================================================
// Regression tests for loss detection optimizations
// ============================================================================

test "loss_recovery: detectLoss in-flight bytes saturate on subtraction" {
    // Regression: in-flight byte accounting uses saturating subtraction
    // to prevent underflow when lost packet size exceeds in-flight bytes.
    const testing = std.testing;
    var table = SentPacketTable.init();

    // Add one packet: 100 bytes, in-flight
    const pkt = SentPacket{
        .pn = 0,
        .sent_ns = 0,
        .size = 100,
        .epoch = 0,
        .in_flight = true,
        .ack_eliciting = false,
        .valid = true,
    };
    _ = table.add(pkt, .{});

    // Simulate initial in-flight state: 50 bytes (less than packet size)
    var bif: u64 = 50;
    var result = AckResult{};

    // Declare packet as lost (via time threshold)
    table.detectLoss(10, 1_000_000_000, 2_000_000_000, 0, &result, &bif);

    // bif should saturate to 0, not wrap around
    try testing.expectEqual(@as(u64, 0), bif);
    try testing.expectEqual(@as(u64, 1), result.newly_lost);
    try testing.expectEqual(@as(u64, 100), result.bytes_lost);
}

test "loss_recovery: detectLoss multiple packets in-flight accounting" {
    // Regression: multiple lost packets properly decrement in-flight bytes
    const testing = std.testing;
    var table = SentPacketTable.init();

    // Add 3 packets
    const pkt1 = SentPacket{.pn = 0, .sent_ns = 0, .size = 30, .epoch = 0, .in_flight = true, .ack_eliciting = false, .valid = true};
    const pkt2 = SentPacket{.pn = 1, .sent_ns = 100, .size = 40, .epoch = 0, .in_flight = true, .ack_eliciting = false, .valid = true};
    const pkt3 = SentPacket{.pn = 2, .sent_ns = 200, .size = 50, .epoch = 0, .in_flight = true, .ack_eliciting = false, .valid = true};
    _ = table.add(pkt1, .{});
    _ = table.add(pkt2, .{});
    _ = table.add(pkt3, .{});

    var bif: u64 = 120; // 30 + 40 + 50
    var result = AckResult{};

    // Declare all 3 packets as lost via packet threshold
    table.detectLoss(2 + 3, 0, 100, 0, &result, &bif); // largest_acked = 5, pkt_threshold = 3

    // All 3 should be lost, in-flight decremented by 120 total
    try testing.expectEqual(@as(u64, 3), result.newly_lost);
    try testing.expectEqual(@as(u64, 120), result.bytes_lost);
    try testing.expectEqual(@as(u64, 0), bif); // 120 - 120 = 0
}

test "loss_recovery: detectLoss partial in-flight decrement" {
    // Regression: partial loss of in-flight bytes (not saturating underflow)
    const testing = std.testing;
    var table = SentPacketTable.init();

    const pkt = SentPacket{.pn = 0, .sent_ns = 0, .size = 50, .epoch = 0, .in_flight = true, .ack_eliciting = false, .valid = true};
    _ = table.add(pkt, .{});

    var bif: u64 = 200;
    var result = AckResult{};

    table.detectLoss(3, 1_000_000_000, 2_000_000_000, 0, &result, &bif);

    // 200 - 50 = 150 (normal subtraction, no underflow)
    try testing.expectEqual(@as(u64, 150), bif);
}
