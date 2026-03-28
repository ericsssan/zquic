//! Deterministic in-process network simulator for QUIC testing.
//!
//! Virtual time, configurable delay/loss/corruption/bandwidth, and a seeded
//! PRNG guarantee bit-exact reproducibility.  Runs the entire handshake and
//! data transfer in < 1 second of wall clock.

const std = @import("std");
const conn_mod = @import("connection.zig");
const Connection = conn_mod.Connection;
const ConnState = conn_mod.ConnState;
const SocketAddr = conn_mod.SocketAddr;
const test_harness = @import("test_harness.zig");
const TestClient = test_harness.TestClient;

/// Maximum UDP datagram size in the simulation.
const MAX_DGRAM = 1500;
/// Maximum packets in flight at once.
const MAX_QUEUE = 256;

pub const Direction = enum { c2s, s2c };

const QueuedPacket = struct {
    data: [MAX_DGRAM]u8,
    len: usize,
    delivery_ns: i64,
    dir: Direction,
};

pub const NetSimConfig = struct {
    /// One-way delay in nanoseconds (RTT = 2 * delay).
    delay_ns: i64 = 25_000_000, // 25ms → 50ms RTT
    /// Packet loss probability [0..100].
    loss_pct: u8 = 0,
    /// Byte corruption probability [0..100].
    corruption_pct: u8 = 0,
    /// Bandwidth cap in bytes/second (0 = unlimited).
    bandwidth_bps: u64 = 0,
    /// Maximum queue depth (packets). Excess packets are silently dropped.
    max_queue: usize = MAX_QUEUE,
    /// PRNG seed for deterministic loss/corruption.
    seed: u64 = 42,
};

pub const NetSim = struct {
    config: NetSimConfig,
    now_ns: i64,
    queue: [MAX_QUEUE]QueuedPacket,
    queue_len: usize,
    prng: std.Random.DefaultPrng,

    pub fn init(config: NetSimConfig) NetSim {
        return .{
            .config = config,
            .now_ns = 1_000_000_000, // start at 1 second
            .queue = undefined,
            .queue_len = 0,
            .prng = std.Random.DefaultPrng.init(config.seed),
        };
    }

    /// Enqueue a packet in the given direction. Applies loss/corruption.
    pub fn send(self: *NetSim, data: []const u8, dir: Direction) void {
        if (data.len == 0 or data.len > MAX_DGRAM) return;
        if (self.queue_len >= self.config.max_queue) return;

        // Loss: randomly drop the packet
        if (self.config.loss_pct > 0) {
            const roll = self.prng.random().intRangeAtMost(u8, 0, 99);
            if (roll < self.config.loss_pct) return;
        }

        var pkt = &self.queue[self.queue_len];
        @memcpy(pkt.data[0..data.len], data);
        pkt.len = data.len;
        pkt.delivery_ns = self.now_ns + self.config.delay_ns;
        pkt.dir = dir;

        // Corruption: flip random bytes
        if (self.config.corruption_pct > 0) {
            const roll = self.prng.random().intRangeAtMost(u8, 0, 99);
            if (roll < self.config.corruption_pct) {
                const idx = self.prng.random().intRangeLessThan(usize, 0, data.len);
                pkt.data[idx] ^= 0xff;
            }
        }

        self.queue_len += 1;
    }

    /// Deliver the next packet (earliest delivery time). Returns null if queue
    /// is empty or no packet is ready (all delivery times in the future).
    /// Advances `now_ns` to the delivery time.
    pub fn deliver(self: *NetSim) ?struct { data: []u8, dir: Direction } {
        if (self.queue_len == 0) return null;

        // Find packet with earliest delivery time
        var min_idx: usize = 0;
        var min_time: i64 = self.queue[0].delivery_ns;
        for (1..self.queue_len) |i| {
            if (self.queue[i].delivery_ns < min_time) {
                min_time = self.queue[i].delivery_ns;
                min_idx = i;
            }
        }

        // Advance virtual clock
        if (min_time > self.now_ns) self.now_ns = min_time;

        const pkt = &self.queue[min_idx];
        const dir = pkt.dir;
        const len = pkt.len;

        // Swap-remove
        if (min_idx != self.queue_len - 1) {
            self.queue[min_idx] = self.queue[self.queue_len - 1];
        }
        self.queue_len -= 1;

        // Return the data (still in the removed slot — safe until next send/deliver)
        const removed = &self.queue[self.queue_len]; // now the swapped-out slot
        _ = removed;
        return .{ .data = pkt.data[0..len], .dir = dir };
    }

    /// Return the earliest delivery time, or null if queue is empty.
    pub fn nextDeliveryTime(self: *const NetSim) ?i64 {
        if (self.queue_len == 0) return null;
        var min_time: i64 = self.queue[0].delivery_ns;
        for (1..self.queue_len) |i| {
            if (self.queue[i].delivery_ns < min_time) {
                min_time = self.queue[i].delivery_ns;
            }
        }
        return min_time;
    }

    /// Advance time to the given nanosecond (does not deliver packets).
    pub fn advanceTo(self: *NetSim, ns: i64) void {
        if (ns > self.now_ns) self.now_ns = ns;
    }

    /// Run a full handshake between a TestClient and a Connection.
    /// Returns true if both sides reach established state.
    pub fn runHandshake(
        self: *NetSim,
        client: *TestClient,
        server: *Connection(16),
        io: std.Io,
    ) !bool {
        return self.runUntilEstablished(client, server, io, 10000);
    }

    /// Drive both endpoints until both are established, or max_ticks is reached.
    /// Implements client-side retransmit: if packets are lost, the client
    /// re-sends its Initial or Finished on a simple timer.
    pub fn runUntilEstablished(
        self: *NetSim,
        client: *TestClient,
        server: *Connection(16),
        io: std.Io,
        max_ticks: usize,
    ) !bool {
        // Client PTO: simple exponential backoff starting at 1× RTT.
        const base_pto: i64 = self.config.delay_ns * 2; // 1 RTT
        var client_pto_count: u8 = 0;
        var client_next_pto: i64 = self.now_ns + base_pto;
        var client_finished_sent = false;

        // Send initial ClientHello (plaintext saved in client for retransmit)
        {
            var buf: [MAX_DGRAM]u8 = undefined;
            const initial_len = client.buildInitialWithClientHello(&buf);
            self.send(buf[0..initial_len], .c2s);
        }

        var ticks: usize = 0;
        while (ticks < max_ticks) : (ticks += 1) {
            // Check completion
            if (client.tls.state == .established and
                server.hot.state == .established)
            {
                return true;
            }

            // Determine next event time (network, server timer, or client PTO)
            const net_time = self.nextDeliveryTime();
            const server_time = server.nextTimeout();
            var next_time = minOptional(net_time, server_time) orelse client_next_pto;
            next_time = @min(next_time, client_next_pto);

            // Safety: don't run forever
            if (next_time > self.now_ns + 30_000_000_000) break; // 30s wall clock limit

            self.advanceTo(next_time);

            // Fire server timer if needed
            if (server_time) |st| {
                if (self.now_ns >= st) {
                    server.tick(self.now_ns);
                    // Drain server send queue after tick
                    var out: [MAX_DGRAM]u8 = undefined;
                    while (true) {
                        const n = server.send(&out, self.now_ns);
                        if (n == 0) break;
                        self.send(out[0..n], .s2c);
                    }
                }
            }

            // Client PTO: retransmit if we haven't made progress
            if (self.now_ns >= client_next_pto) {
                if (client.tls.state == .wait_server_hello or client.tls.state == .wait_encrypted) {
                    // Retransmit Initial with fresh PN — prompts server to resend SH+HS
                    var buf: [MAX_DGRAM]u8 = undefined;
                    const len = client.retransmitInitial(&buf);
                    self.send(buf[0..len], .c2s);
                } else if (client.tls.state == .established and server.hot.state != .established) {
                    // Retransmit Finished
                    var buf: [MAX_DGRAM]u8 = undefined;
                    const len = client.buildHandshakeWithFinished(&buf);
                    self.send(buf[0..len], .c2s);
                }
                client_pto_count +|= 1;
                const backoff: i64 = base_pto * (@as(i64, 1) << @min(client_pto_count, 6));
                client_next_pto = self.now_ns + backoff;
            }

            // Deliver network packets
            while (self.deliver()) |pkt| {
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        // Drain server send queue
                        var out: [MAX_DGRAM]u8 = undefined;
                        while (true) {
                            const n = server.send(&out, self.now_ns);
                            if (n == 0) break;
                            self.send(out[0..n], .s2c);
                        }
                    },
                    .s2c => {
                        client.processServerDatagram(pkt.data) catch {};

                        // If client just became established, send Finished
                        if (client.tls.state == .established and !client_finished_sent) {
                            var fin_buf: [MAX_DGRAM]u8 = undefined;
                            const fin_len = client.buildHandshakeWithFinished(&fin_buf);
                            self.send(fin_buf[0..fin_len], .c2s);
                            client_finished_sent = true;
                        }
                    },
                }
            }
        }

        return client.tls.state == .established and server.hot.state == .established;
    }

    /// Drive data transfer after handshake: pump server → client data until
    /// the server has nothing more to send or max_ticks is reached.
    /// Client automatically ACKs received packets to drive flow/congestion control.
    pub fn runUntilIdle(
        self: *NetSim,
        client: *TestClient,
        server: *Connection(16),
        io: std.Io,
        max_ticks: usize,
    ) !void {
        var ticks: usize = 0;
        while (ticks < max_ticks) : (ticks += 1) {
            // Drain server send queue
            self.drainServerSend(server);

            const net_time = self.nextDeliveryTime();
            const server_time = server.nextTimeout();
            const next_time = minOptional(net_time, server_time) orelse break;

            self.advanceTo(next_time);

            // Fire server timer
            if (server_time) |st| {
                if (self.now_ns >= st) {
                    server.tick(self.now_ns);
                    self.drainServerSend(server);
                }
            }

            // Deliver network packets
            while (self.deliver()) |pkt| {
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        self.drainServerSend(server);
                    },
                    .s2c => {
                        const prev_pn = client.largest_rx_pn;
                        client.processServerDatagram(pkt.data) catch {};
                        // ACK every received packet to drive congestion/flow control
                        if (client.largest_rx_pn > prev_pn or (prev_pn == 0 and client.tls.state == .established)) {
                            var ack_buf: [MAX_DGRAM]u8 = undefined;
                            const ack_len = client.buildAck(&ack_buf, @intCast(client.largest_rx_pn));
                            self.send(ack_buf[0..ack_len], .c2s);
                        }
                    },
                }
            }
        }
    }

    fn drainServerSend(self: *NetSim, server: *Connection(16)) void {
        var out: [MAX_DGRAM]u8 = undefined;
        while (true) {
            const n = server.send(&out, self.now_ns);
            if (n == 0) break;
            self.send(out[0..n], .s2c);
        }
    }
};

const CLIENT_ADDR: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 12345 } };

fn minOptional(a: ?i64, b: ?i64) ?i64 {
    if (a == null and b == null) return null;
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}
