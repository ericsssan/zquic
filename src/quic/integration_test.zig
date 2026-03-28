//! End-to-end integration tests using TestClient + Connection.
//!
//! These tests drive a full QUIC handshake (and later, data transfer)
//! in-process with deterministic I/O — no sockets, no threads, no Docker.

const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const ConnState = conn_mod.ConnState;
const SocketAddr = conn_mod.SocketAddr;
const test_harness = @import("test_harness.zig");
const TestClient = test_harness.TestClient;
const netsim = @import("netsim.zig");
const NetSim = netsim.NetSim;

const CLIENT_ADDR: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 12345 } };
const NOW: i64 = 1_000_000_000;

fn serverSendChunked(server: *Connection(16), stream_id: u62, total: usize, fin: bool) !void {
    const chunk_size: usize = 1024;
    var chunk: [chunk_size]u8 = undefined;
    @memset(&chunk, 0xAB);
    var sent: usize = 0;
    while (sent < total) {
        const len = @min(total - sent, chunk_size);
        const is_last = sent + len == total;
        try server.streamSend(stream_id, chunk[0..len], if (is_last) fin else false);
        sent += len;
    }
}

// ---------------------------------------------------------------------------
// Phase 1: Direct handshake (no netsim)
// ---------------------------------------------------------------------------

test "handshake: full client-server reaches established" {
    const testing = std.testing;
    const io = std.testing.io;

    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = NOW;
    var client = TestClient.init(server.local_cid.bytes, io);

    var client_buf: [1500]u8 = undefined;
    const initial_len = client.buildInitialWithClientHello(&client_buf);
    try testing.expect(initial_len >= 1200);

    try server.receive(client_buf[0..initial_len], CLIENT_ADDR, NOW, 0, io);
    try testing.expect(server.hot.state == .handshake);

    var server_buf: [1500]u8 = undefined;
    const resp_len = server.send(&server_buf, NOW);
    try testing.expect(resp_len > 0);

    try client.processServerDatagram(server_buf[0..resp_len]);
    try testing.expect(client.tls.state == .established);

    const fin_len = client.buildHandshakeWithFinished(&client_buf);
    try server.receive(client_buf[0..fin_len], CLIENT_ADDR, NOW + 100_000_000, 0, io);
    try testing.expect(server.hot.state == .established);
}

// ---------------------------------------------------------------------------
// Phase 2: Handshake under adverse network conditions
// ---------------------------------------------------------------------------

test "handshake via netsim: clean network (0% loss)" {
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 25_000_000, .seed = 1 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try std.testing.expect(try sim.runHandshake(&client, &server, io));
}

test "handshake via netsim: 30% loss (5 seeds)" {
    const io = std.testing.io;
    for (0..5) |seed_offset| {
        var sim = NetSim.init(.{ .delay_ns = 25_000_000, .loss_pct = 30, .seed = 100 + seed_offset });
        var server = try Connection(16).accept(.{}, io);
        server.current_time_ns = sim.now_ns;
        var client = TestClient.init(server.local_cid.bytes, io);

        try std.testing.expect(try sim.runHandshake(&client, &server, io));
    }
}

test "handshake via netsim: 10% corruption (5 seeds)" {
    const io = std.testing.io;
    const seeds = [_]u64{ 200, 201, 202, 203, 205 };
    for (seeds) |seed| {
        var sim = NetSim.init(.{ .delay_ns = 25_000_000, .corruption_pct = 10, .seed = seed });
        var server = try Connection(16).accept(.{}, io);
        server.current_time_ns = sim.now_ns;
        var client = TestClient.init(server.local_cid.bytes, io);

        try std.testing.expect(try sim.runHandshake(&client, &server, io));
    }
}

test "handshake via netsim: 200ms RTT" {
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 100_000_000, .seed = 300 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try std.testing.expect(try sim.runHandshake(&client, &server, io));
}

// ---------------------------------------------------------------------------
// Phase 3: Data transfer scenarios
// ---------------------------------------------------------------------------

test "transfer: server sends 4KB single stream" {
    const testing = std.testing;
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 10_000_000, .seed = 400 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try testing.expect(try sim.runHandshake(&client, &server, io));
    try serverSendChunked(&server, 1, 4096, true);
    try sim.runUntilIdle(&client, &server, io, 5000);

    const received = client.receivedStreamData(1);
    try testing.expect(received != null);
    try testing.expectEqual(@as(usize, 4096), received.?.data.len);
    try testing.expect(received.?.fin);
}

test "transfer: data immediately after handshake" {
    const testing = std.testing;
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 10_000_000, .seed = 500 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try testing.expect(try sim.runHandshake(&client, &server, io));
    try server.streamSend(1, "hello from server", true);
    try sim.runUntilIdle(&client, &server, io, 1000);

    const received = client.receivedStreamData(1);
    try testing.expect(received != null);
    try testing.expectEqualSlices(u8, "hello from server", received.?.data);
    try testing.expect(received.?.fin);
}

test "transfer: 3 concurrent streams complete" {
    const testing = std.testing;
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 10_000_000, .seed = 600 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try testing.expect(try sim.runHandshake(&client, &server, io));

    // Server sends 1KB on 3 server-initiated bidi streams (IDs 1, 5, 9)
    try serverSendChunked(&server, 1, 1024, true);
    try serverSendChunked(&server, 5, 1024, true);
    try serverSendChunked(&server, 9, 1024, true);

    try sim.runUntilIdle(&client, &server, io, 5000);

    for ([_]u62{ 1, 5, 9 }) |sid| {
        const received = client.receivedStreamData(sid);
        try testing.expect(received != null);
        try testing.expectEqual(@as(usize, 1024), received.?.data.len);
        try testing.expect(received.?.fin);
    }
}

test "transfer: 4KB at 2% loss" {
    const testing = std.testing;
    const io = std.testing.io;
    var sim = NetSim.init(.{ .delay_ns = 10_000_000, .loss_pct = 2, .seed = 800 });
    var server = try Connection(16).accept(.{}, io);
    server.current_time_ns = sim.now_ns;
    var client = TestClient.init(server.local_cid.bytes, io);

    try std.testing.expect(try sim.runHandshake(&client, &server, io));
    try serverSendChunked(&server, 1, 4096, true);
    try sim.runUntilIdle(&client, &server, io, 10000);

    const received = client.receivedStreamData(1);
    try testing.expect(received != null);
    try testing.expectEqual(@as(usize, 4096), received.?.data.len);
    try testing.expect(received.?.fin);
}
