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
