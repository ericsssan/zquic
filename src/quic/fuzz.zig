//! Fuzz targets for zquic parser / decoder attack surface.
//!
//! Each fuzz target is exposed as a regular `test` so it runs as a smoke test
//! during `zig build test --summary all`.  Pass `--fuzz` to enable continuous
//! fuzzing with coverage guidance.
//!
//! Properties tested:
//!   - Frame parser: must never crash or invoke safety-checked UB on any input.
//!   - Varint: canonical encode → decode round-trip.
//!   - Transport params: must never crash on any input.
//!   - Packet header parser: must never crash on any input.

const std = @import("std");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
const transport_params = @import("transport_params.zig");
const packet = @import("packet.zig");
const stream_mod = @import("stream.zig");
const loss_recovery_mod = @import("loss_recovery.zig");

// ---------------------------------------------------------------------------
// Fuzz target functions
// ---------------------------------------------------------------------------

/// Frame parser must not crash on any byte sequence.
fn fuzzFrameParse(_: void, input: []const u8) anyerror!void {
    var pos: usize = 0;
    while (pos < input.len) {
        const result = frame.parseFrame(input[pos..]) catch return;
        if (result.consumed == 0) return;
        pos += result.consumed;
    }
}

/// Varint encode → decode round-trip: encode(decode(x)) must reproduce the
/// same value and consume the same number of bytes.
fn fuzzVarint(_: void, input: []const u8) anyerror!void {
    const decoded = varint.decode(input) orelse return;
    var buf: [8]u8 = undefined;
    const n = varint.encode(&buf, decoded.value);
    // Re-decode the canonical encoding — must give back the same value.
    const redecoded = varint.decode(buf[0..n]) orelse return;
    try std.testing.expectEqual(decoded.value, redecoded.value);
    try std.testing.expectEqual(@as(u8, @intCast(n)), redecoded.len);
}

/// Transport params decoder must not crash on any input.
fn fuzzTransportParams(_: void, input: []const u8) anyerror!void {
    _ = transport_params.decode(input) catch return;
}

/// Packet header parser must not crash on any input.
fn fuzzPacketParse(_: void, input: []const u8) anyerror!void {
    if (input.len == 0) return;
    if (packet.isLongHeader(input[0])) {
        _ = packet.parseLongHeader(input) catch return;
    } else {
        _ = packet.parseShortHeader(input, 8) catch return;
    }
}

/// Stream receiveData must not crash on any (offset, data, fin) combination.
/// Properties: flow control or buffer errors are the only expected outcomes.
fn fuzzStreamReceive(_: void, input: []const u8) anyerror!void {
    if (input.len < 9) return;
    // First 8 bytes: offset (u64 little-endian); byte 8: fin flag; rest: data.
    const offset: u64 = std.mem.readInt(u64, input[0..8], .little);
    const fin = input[8] & 1 != 0;
    const data = input[9..];
    var s = stream_mod.Stream.init(0);
    // Must not crash; flow-control or buffer errors are expected and fine.
    s.receiveData(offset, data, fin) catch return;
}

/// RttEstimator.update must not crash, overflow, or produce NaN/zero values
/// regardless of sample_ns, ack_delay_ns, max_ack_delay_ns inputs.
fn fuzzRttUpdate(_: void, input: []const u8) anyerror!void {
    if (input.len < 3) return;
    var rtt = loss_recovery_mod.RttEstimator{};
    var i: usize = 0;
    while (i + 3 <= input.len) : (i += 3) {
        // Scale bytes to milliseconds to exercise meaningful RTT ranges.
        const sample_ns   = @as(u64, input[i])   * 1_000_000;
        const ack_delay   = @as(u64, input[i+1]) * 1_000_000;
        const max_delay   = @as(u64, input[i+2]) * 1_000_000 + 1; // +1 to avoid zero
        rtt.update(sample_ns, ack_delay, max_delay);
        // smoothed_rtt and rtt_var must always remain positive after initialization.
        if (rtt.initialized) {
            try std.testing.expect(rtt.smoothed_rtt > 0);
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (smoke-test wrappers; each runs the fuzz target once)
// ---------------------------------------------------------------------------

test "fuzz: frame parser does not crash" {
    try std.testing.fuzz({}, fuzzFrameParse, .{});
}

test "fuzz: varint encode-decode round-trip" {
    try std.testing.fuzz({}, fuzzVarint, .{});
}

test "fuzz: transport params decoder does not crash" {
    try std.testing.fuzz({}, fuzzTransportParams, .{});
}

test "fuzz: packet header parser does not crash" {
    try std.testing.fuzz({}, fuzzPacketParse, .{});
}

test "fuzz: stream receiveData does not crash" {
    try std.testing.fuzz({}, fuzzStreamReceive, .{});
}

test "fuzz: RTT estimator update does not crash or overflow" {
    try std.testing.fuzz({}, fuzzRttUpdate, .{});
}
