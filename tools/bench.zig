//! QUIC throughput benchmark — in-process client ↔ server via netsim.
//!
//! Build:  zig build bench
//! Usage:  zig-out/bin/bench
//!
//! Reports goodput kbps and handshake microseconds for several scenarios.

const std = @import("std");
const zquic = @import("zquic");
const Connection = zquic.Connection;
const NetSim = zquic.netsim.NetSim;
const TestClient = zquic.test_harness.TestClient;

const Scenario = struct {
    name: []const u8,
    data_bytes: usize,
    stream_count: u8,
    rtt_ms: u32,
};

const scenarios = [_]Scenario{
    .{ .name = "1KB x 1 stream, 50ms RTT", .data_bytes = 1024, .stream_count = 1, .rtt_ms = 50 },
    .{ .name = "64KB x 1 stream, 50ms RTT", .data_bytes = 64 * 1024, .stream_count = 1, .rtt_ms = 50 },
    .{ .name = "256KB x 1 stream, 50ms RTT", .data_bytes = 256 * 1024, .stream_count = 1, .rtt_ms = 50 },
    .{ .name = "1MB x 1 stream, 50ms RTT", .data_bytes = 1024 * 1024, .stream_count = 1, .rtt_ms = 50 },
    .{ .name = "64KB x 3 streams, 50ms RTT", .data_bytes = 64 * 1024, .stream_count = 3, .rtt_ms = 50 },
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("\n=== zquic throughput benchmark ===\n\n", .{});
    try stdout.print("{s:<35} {s:>10} {s:>12} {s:>12}\n", .{ "Scenario", "Received", "Goodput kbps", "Handshake us" });
    try stdout.print("{s:-<71}\n", .{""});

    for (scenarios) |s| {
        const result = runScenario(s) catch |err| {
            try stdout.print("{s:<35} ERROR: {}\n", .{ s.name, err });
            continue;
        };
        try stdout.print("{s:<35} {d:>8}KB {d:>12.0} {d:>12}\n", .{
            s.name,
            result.bytes_received / 1024,
            result.goodput_kbps,
            result.handshake_us,
        });
    }
    try stdout.print("\n", .{});
}

const BenchResult = struct {
    goodput_kbps: f64,
    handshake_us: i64,
    bytes_received: usize,
};

fn runScenario(s: Scenario) !BenchResult {
    const io = std.testing.io;
    const delay_ns: i64 = @intCast(@as(u64, s.rtt_ms) * 1_000_000 / 2);
    var sim = NetSim.init(.{ .delay_ns = delay_ns, .seed = 1 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    // Handshake
    const hs_start = sim.now_ns;
    const ok = try sim.runHandshake(&client, &server, io);
    if (!ok) return error.HandshakeFailed;
    const hs_end = sim.now_ns;
    const handshake_us = @divFloor(hs_end - hs_start, 1000);

    // Transfer data on each stream
    const per_stream = s.data_bytes / s.stream_count;
    const transfer_start = sim.now_ns;
    var total_received: usize = 0;

    for (0..s.stream_count) |si| {
        const stream_id: u62 = @intCast(1 + si * 4);
        const received = try sim.runTransfer(&client, &server, io, stream_id, per_stream);
        total_received += received;
    }

    const transfer_end = sim.now_ns;
    const transfer_ns = transfer_end - transfer_start;

    const goodput_kbps: f64 = if (transfer_ns > 0)
        @as(f64, @floatFromInt(total_received)) * 8.0 / @as(f64, @floatFromInt(transfer_ns)) * 1_000_000_000.0 / 1000.0
    else
        0;

    return .{
        .goodput_kbps = goodput_kbps,
        .handshake_us = handshake_us,
        .bytes_received = total_received,
    };
}
