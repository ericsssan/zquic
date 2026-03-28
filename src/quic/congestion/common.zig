//! Shared types and constants for congestion control algorithms.
//!
//! Defined here (in the congestion directory) so that congestion modules
//! can import it without reaching outside their module path.

const std = @import("std");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// RFC 9002 §7.2: max_datagram_size for congestion control.
/// Matches MAX_SEND_PACKET_SIZE (1452) — the actual UDP payload we send.
pub const MSS: u64 = 1452;
/// RFC 9002 §7.2: initial_window = min(10 * mds, max(14720, 2 * mds))
/// = min(14520, max(14720, 2904)) = 14520.
pub const INITIAL_CWND: u64 = @min(10 * MSS, @max(14720, 2 * MSS));

// ---------------------------------------------------------------------------
// Delivery Rate Sample
// ---------------------------------------------------------------------------

/// Per-ACK delivery rate sample, computed by LossRecovery and passed to
/// the congestion controller.
pub const DeliveryRateSample = struct {
    delivery_rate: u64 = 0, // bytes/sec
    is_app_limited: bool = false,
    rtt_ns: u64 = 0, // latest RTT sample
    bytes_acked: u64 = 0,
    bytes_lost: u64 = 0,
    prior_inflight: u64 = 0, // bytes_in_flight before this ACK
    round_start: bool = false, // did a new round start?
};

// ---------------------------------------------------------------------------
// Pacing — shared token bucket used by both BBR and CUBIC
// ---------------------------------------------------------------------------

/// Token bucket pacer. Spread packets evenly across the RTT instead of
/// bursting. Embedded by both Bbr and Cubic.
pub const Pacing = struct {
    /// Pacing rate in bytes per second. Updated by the congestion controller.
    rate: u64 = 0,
    /// Token bucket: bytes allowed to send now.
    tokens: u64 = INITIAL_CWND, // allow initial burst
    /// Timestamp of last token refill (ns).
    last_refill_ns: i64 = 0,

    /// Refill tokens based on elapsed time. Returns bytes allowed to send.
    /// Tokens are capped at 2×cwnd to allow modest bursts without unlimited accumulation.
    pub fn refill(self: *Pacing, cwnd: u64, now_ns: i64) u64 {
        if (self.rate == 0) {
            // No pacing rate yet (before first ACK) — allow full cwnd.
            return cwnd;
        }
        if (self.last_refill_ns == 0) {
            self.last_refill_ns = now_ns;
            return self.tokens;
        }
        const elapsed_ns: u64 = @intCast(@max(now_ns - self.last_refill_ns, 0));
        // Only advance the timestamp when time has actually elapsed.
        // Repeated calls with the same now_ns (within a drainSend batch)
        // must NOT reset last_refill_ns, otherwise nextSendTime() computes
        // a deadline that's already in the past, causing the event loop to
        // spin instead of sleeping until enough tokens accumulate.
        if (elapsed_ns > 0) {
            self.last_refill_ns = now_ns;
        }
        // Use u128 to avoid saturation on fast links (e.g., 1 GB/s × 1s overflows u64).
        const new_tokens: u64 = @intCast(@min(
            @as(u128, self.rate) * elapsed_ns / 1_000_000_000,
            std.math.maxInt(u64),
        ));
        self.tokens = @min(self.tokens +| new_tokens, cwnd *| 2);
        return self.tokens;
    }

    /// Consume tokens after sending a packet.
    pub fn consume(self: *Pacing, bytes: u64) void {
        self.tokens -|= bytes;
    }

    /// Returns the nanosecond deadline when enough tokens will be available
    /// to send one MSS-sized packet, or null if tokens are already sufficient
    /// or pacing is not active (rate == 0).
    pub fn nextSendTime(self: *const Pacing) ?i64 {
        if (self.rate == 0) return null;
        if (self.tokens >= MSS) return null;
        const deficit = MSS - self.tokens;
        const wait_ns: i64 = @intCast(@min(
            @as(u128, deficit) * 1_000_000_000 / self.rate,
            @as(u128, std.math.maxInt(i64)),
        ));
        return self.last_refill_ns +| wait_ns;
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pacing: regression — u128 prevents overflow on fast links" {
    // Bug: `rate *| elapsed_ns / 1_000_000_000` used u64 saturating multiply.
    // At 1 GB/s with 1s elapsed, rate × elapsed = 1e18 which fits u64, but
    // at 10 GB/s × 1s = 1e19 which overflows u64 (max ~1.8e19). With the old
    // saturating mul, tokens would cap at maxInt instead of the correct value.
    var p = Pacing{
        .rate = 10_000_000_000, // 10 GB/s
        .tokens = 0,
        .last_refill_ns = 1_000_000_000,
    };
    const tokens = p.refill(20_000_000_000, 2_000_000_000); // 1s later
    // Expected: 10 GB/s × 1s = 10,000,000,000 bytes.
    try std.testing.expectEqual(@as(u64, 10_000_000_000), tokens);
}

test "pacing: refill and consume basic" {
    var p = Pacing{
        .rate = 1_000_000, // 1 MB/s
        .tokens = 0,
        .last_refill_ns = 1_000_000_000,
    };
    _ = p.refill(1_000_000, 1_001_000_000); // 1ms later → 1000 bytes
    try std.testing.expectEqual(@as(u64, 1000), p.tokens);
    p.consume(600);
    try std.testing.expectEqual(@as(u64, 400), p.tokens);
}

test "pacing: tokens capped at 2*cwnd" {
    var p = Pacing{
        .rate = 1_000_000_000, // 1 GB/s
        .tokens = 0,
        .last_refill_ns = 1_000_000_000, // initialized
    };
    const cwnd: u64 = 100_000;
    _ = p.refill(cwnd, 2_000_000_000); // 1s later → 1 GB, but capped at 200_000
    try std.testing.expectEqual(cwnd * 2, p.tokens);
}
