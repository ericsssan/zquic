//! QUIC throughput benchmark — in-process client <-> server via netsim.
//!
//! Build:  zig build bench
//! Usage:  zig-out/bin/bench
//!
//! Reports goodput kbps and handshake microseconds for several scenarios.
//! Runs multiple iterations per scenario and reports median + stdev.

const std = @import("std");
const zquic = @import("zquic");
const Connection = zquic.Connection;
const NetSim = zquic.netsim.NetSim;
const TestClient = zquic.test_harness.TestClient;

const ITERATIONS = 5;

const ScenarioKind = enum { transfer, handshake_only };

const Scenario = struct {
    name: []const u8,
    data_bytes: usize = 0,
    stream_count: u8 = 1,
    rtt_ms: u32,
    loss_pct: u8 = 0,
    kind: ScenarioKind = .transfer,
};

const scenarios = [_]Scenario{
    // Handshake-only
    .{ .name = "handshake only, 50ms RTT", .rtt_ms = 50, .kind = .handshake_only },
    .{ .name = "handshake only, 200ms RTT", .rtt_ms = 200, .kind = .handshake_only },
    .{ .name = "handshake only, 50ms RTT 10% loss", .rtt_ms = 50, .loss_pct = 10, .kind = .handshake_only },

    // Clean transfers
    .{ .name = "1KB x 1 stream, 50ms RTT", .data_bytes = 1024, .rtt_ms = 50 },
    .{ .name = "64KB x 1 stream, 50ms RTT", .data_bytes = 64 * 1024, .rtt_ms = 50 },
    .{ .name = "256KB x 1 stream, 50ms RTT", .data_bytes = 256 * 1024, .rtt_ms = 50 },
    .{ .name = "1MB x 1 stream, 50ms RTT", .data_bytes = 1024 * 1024, .rtt_ms = 50 },
    .{ .name = "64KB x 3 streams, 50ms RTT", .data_bytes = 64 * 1024, .stream_count = 3, .rtt_ms = 50 },

    // Loss scenarios
    .{ .name = "4KB x 1 stream, 50ms RTT 2% loss", .data_bytes = 4096, .rtt_ms = 50, .loss_pct = 2 },
    .{ .name = "64KB x 1 stream, 50ms RTT 2% loss", .data_bytes = 64 * 1024, .rtt_ms = 50, .loss_pct = 2 },
};

pub fn main() !void {
    std.debug.print("\n=== zquic throughput benchmark ({} iterations/scenario) ===\n\n", .{ITERATIONS});

    // Handshake-only section
    std.debug.print("{s:<40} {s:>12} {s:>12}\n", .{ "Scenario", "Median us", "Stdev us" });
    std.debug.print("{s:-<66}\n", .{""});

    for (scenarios) |s| {
        if (s.kind != .handshake_only) continue;
        var hs_samples: [ITERATIONS]f64 = undefined;
        var ok_count: usize = 0;

        for (0..ITERATIONS) |i| {
            if (runScenario(s, i)) |result| {
                hs_samples[ok_count] = @floatFromInt(result.handshake_us);
                ok_count += 1;
            } else |_| {}
        }

        if (ok_count > 0) {
            const med = median(hs_samples[0..ok_count]);
            const sd = stdev(hs_samples[0..ok_count]);
            std.debug.print("{s:<40} {d:>12.0} {d:>12.1}\n", .{ s.name, med, sd });
        } else {
            std.debug.print("{s:<40} FAILED\n", .{s.name});
        }
    }

    // Transfer section
    std.debug.print("\n{s:<40} {s:>10} {s:>14} {s:>12} {s:>12}\n", .{ "Scenario", "Received", "Median kbps", "Stdev kbps", "HS us" });
    std.debug.print("{s:-<90}\n", .{""});

    for (scenarios) |s| {
        if (s.kind != .transfer) continue;
        var goodput_samples: [ITERATIONS]f64 = undefined;
        var hs_samples: [ITERATIONS]f64 = undefined;
        var bytes_received: usize = 0;
        var ok_count: usize = 0;

        for (0..ITERATIONS) |i| {
            if (runScenario(s, i)) |result| {
                goodput_samples[ok_count] = result.goodput_kbps;
                hs_samples[ok_count] = @floatFromInt(result.handshake_us);
                bytes_received = result.bytes_received;
                ok_count += 1;
            } else |_| {}
        }

        if (ok_count > 0) {
            const gp_med = median(goodput_samples[0..ok_count]);
            const gp_sd = stdev(goodput_samples[0..ok_count]);
            const hs_med = median(hs_samples[0..ok_count]);
            std.debug.print("{s:<40} {d:>8}KB {d:>14.0} {d:>12.0} {d:>12.0}\n", .{
                s.name,
                bytes_received / 1024,
                gp_med,
                gp_sd,
                hs_med,
            });
        } else {
            std.debug.print("{s:<40} FAILED\n", .{s.name});
        }
    }
    std.debug.print("\n", .{});
}

const BenchResult = struct {
    goodput_kbps: f64,
    handshake_us: i64,
    bytes_received: usize,
};

var io_instance: std.Io.Threaded = undefined;
var io_initialized = false;

fn getIo() std.Io {
    if (!io_initialized) {
        io_instance = std.Io.Threaded.init(std.heap.page_allocator, .{});
        io_initialized = true;
    }
    return io_instance.io();
}

fn runScenario(s: Scenario, iteration: usize) !BenchResult {
    const io = getIo();
    const delay_ns: i64 = @intCast(@as(u64, s.rtt_ms) * 1_000_000 / 2);
    const seed: u64 = 1 + iteration;
    var sim = NetSim.init(.{ .delay_ns = delay_ns, .loss_pct = s.loss_pct, .seed = seed });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    // Handshake
    const hs_start = sim.now_ns;
    const ok = try sim.runHandshake(&client, &server, io);
    if (!ok) return error.HandshakeFailed;
    const hs_end = sim.now_ns;
    const handshake_us = @divFloor(hs_end - hs_start, 1000);

    if (s.kind == .handshake_only) {
        return .{
            .goodput_kbps = 0,
            .handshake_us = handshake_us,
            .bytes_received = 0,
        };
    }

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

// ---------------------------------------------------------------------------
// Statistics helpers
// ---------------------------------------------------------------------------

fn median(samples: []f64) f64 {
    if (samples.len == 0) return 0;
    std.mem.sort(f64, samples, {}, std.sort.asc(f64));
    const mid = samples.len / 2;
    if (samples.len % 2 == 0) {
        return (samples[mid - 1] + samples[mid]) / 2.0;
    }
    return samples[mid];
}

fn stdev(samples: []const f64) f64 {
    if (samples.len < 2) return 0;
    var sum: f64 = 0;
    for (samples) |v| sum += v;
    const mean = sum / @as(f64, @floatFromInt(samples.len));

    var sq_sum: f64 = 0;
    for (samples) |v| {
        const d = v - mean;
        sq_sum += d * d;
    }
    return @sqrt(sq_sum / @as(f64, @floatFromInt(samples.len - 1)));
}
