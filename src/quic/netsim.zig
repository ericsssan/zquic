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
    /// Reorder probability [0..100]. Affected packets get 2× extra delay.
    reorder_pct: u8 = 0,
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
        pkt.dir = dir;

        // Reorder: some packets get extra delay, arriving after later packets
        var delay = self.config.delay_ns;
        if (self.config.reorder_pct > 0) {
            const roll = self.prng.random().intRangeAtMost(u8, 0, 99);
            if (roll < self.config.reorder_pct) {
                delay *= 2; // arrives 2× later → out of order
            }
        }
        pkt.delivery_ns = self.now_ns + delay;

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
    ///
    /// The returned data slice is valid until the next call to send() or deliver().
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

        const dir = self.queue[min_idx].dir;
        const len = self.queue[min_idx].len;

        // Swap-remove: move the packet we want to deliver to the end
        // so its data survives the removal (valid until next send/deliver).
        const last = self.queue_len - 1;
        if (min_idx != last) {
            const tmp = self.queue[last];
            self.queue[last] = self.queue[min_idx];
            self.queue[min_idx] = tmp;
        }
        self.queue_len -= 1;

        // Data is now in self.queue[self.queue_len] (the just-removed slot).
        return .{ .data = self.queue[self.queue_len].data[0..len], .dir = dir };
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
                        const prev_rx = client.totalReceivedBytes();
                        const prev_pn = client.largest_rx_pn;
                        client.processServerDatagram(pkt.data) catch {};
                        // Only ACK packets that carried new stream data (avoid ACK ping-pong)
                        if (client.totalReceivedBytes() > prev_rx and
                            (client.largest_rx_pn > prev_pn or (prev_pn == 0 and client.tls.state == .established)))
                        {
                            var ack_buf: [MAX_DGRAM]u8 = undefined;
                            const ack_len = client.buildAck(&ack_buf, @intCast(client.largest_rx_pn));
                            self.send(ack_buf[0..ack_len], .c2s);
                        }
                    },
                }
            }
        }
    }

    /// Send `total_bytes` on `stream_id`, interleaving with the event loop
    /// so the congestion window can grow via ACKs. Returns bytes received.
    pub fn runTransfer(
        self: *NetSim,
        client: *TestClient,
        server: *Connection(16),
        io: std.Io,
        stream_id: u62,
        total_bytes: usize,
    ) !usize {
        const chunk_size: usize = 1024;
        var chunk: [chunk_size]u8 = undefined;
        @memset(&chunk, 0xAB);
        var queued: usize = 0;

        var ticks: usize = 0;
        while (ticks < 500000) : (ticks += 1) {
            // Try to queue as much as cwnd allows
            while (queued < total_bytes) {
                const len = @min(total_bytes - queued, chunk_size);
                const fin = queued + len == total_bytes;
                server.streamSend(stream_id, chunk[0..len], fin) catch break;
                queued += len;
            }

            self.drainServerSend(server);

            // Check if THIS stream's data has been fully received
            if (client.receivedStreamData(stream_id)) |r| {
                if (r.data.len >= total_bytes) break;
            }

            // Check for next event — network delivery or server timer
            const net_time = self.nextDeliveryTime();
            const server_time = server.nextTimeout();
            const next_time = minOptional(net_time, server_time) orelse {
                // No network or timer events pending.
                // Advance by 1 RTT to let pacing tokens refill, then tick + drain.
                self.advanceTo(self.now_ns + self.config.delay_ns * 2);
                server.tick(self.now_ns);
                while (queued < total_bytes) {
                    const len2 = @min(total_bytes - queued, chunk_size);
                    const fin2 = queued + len2 == total_bytes;
                    server.streamSend(stream_id, chunk[0..len2], fin2) catch break;
                    queued += len2;
                }
                self.drainServerSend(server);
                // If still no events after refill, we're stuck — break.
                if (self.nextDeliveryTime() == null and server.nextTimeout() == null) break;
                continue;
            };

            self.advanceTo(next_time);

            if (server_time) |st| {
                if (self.now_ns >= st) {
                    server.tick(self.now_ns);
                    self.drainServerSend(server);
                }
            }

            // Deliver packets in batches. Limit prevents infinite loops from
            // control frame ping-pong. Scale with transfer size for larger xfers.
            const deliver_limit: usize = @max(1000, total_bytes / 10);
            var deliver_count: usize = 0;
            while (deliver_count < deliver_limit) : (deliver_count += 1) {
                const pkt = self.deliver() orelse break;
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        // ACK opened cwnd — push more data immediately
                        while (queued < total_bytes) {
                            const len2 = @min(total_bytes - queued, chunk_size);
                            const fin2 = queued + len2 == total_bytes;
                            server.streamSend(stream_id, chunk[0..len2], fin2) catch break;
                            queued += len2;
                        }
                        self.drainServerSend(server);
                    },
                    .s2c => {
                        const prev_rx = client.totalReceivedBytes();
                        const prev_pn = client.largest_rx_pn;
                        client.processServerDatagram(pkt.data) catch {};
                        const cur_rx = client.totalReceivedBytes();
                        // Only ACK packets that carried new stream data (avoid ACK-of-ACK ping-pong)
                        if (cur_rx > prev_rx and (client.largest_rx_pn > prev_pn or (prev_pn == 0 and client.tls.state == .established))) {
                            var ack_buf: [MAX_DGRAM]u8 = undefined;
                            const ack_len = client.buildAck(&ack_buf, @intCast(client.largest_rx_pn));
                            self.send(ack_buf[0..ack_len], .c2s);
                            // Send MAX_STREAM_DATA to keep the flow control window open
                            const new_max: u62 = @intCast(cur_rx + total_bytes);
                            var msd_buf: [MAX_DGRAM]u8 = undefined;
                            const msd_len = client.buildMaxStreamData(&msd_buf, stream_id, new_max);
                            self.send(msd_buf[0..msd_len], .c2s);
                        }
                    },
                }
            }
        }

        if (client.receivedStreamData(stream_id)) |r| return r.data.len;
        return 0;
    }

    fn drainServerSend(self: *NetSim, server: *Connection(16)) void {
        var out: [MAX_DGRAM]u8 = undefined;
        while (true) {
            const n = server.send(&out, self.now_ns);
            if (n == 0) break;
            self.send(out[0..n], .s2c);
        }
    }

    /// Drive a client Connection + server Connection until both reach established state.
    /// Both endpoints use real Connection instances (not TestClient).
    pub fn runPairHandshake(
        self: *NetSim,
        client: *Connection(16),
        server: *Connection(16),
        io: std.Io,
    ) !bool {
        // Drain client's initial send queue (contains ClientHello Initial).
        self.drainEndpointSend(client, .c2s);

        var ticks: usize = 0;
        while (ticks < 10000) : (ticks += 1) {
            if (client.hot.state == .established and server.hot.state == .established)
                return true;

            // Find next event time
            const net_time = self.nextDeliveryTime();
            const client_time = client.nextTimeout();
            const server_time = server.nextTimeout();
            const next_time = minOptional(net_time, minOptional(client_time, server_time)) orelse self.now_ns + 1_000_000;
            if (next_time > self.now_ns + 30_000_000_000) break;
            self.advanceTo(next_time);

            // Fire timers
            if (client_time) |ct| {
                if (self.now_ns >= ct) {
                    client.tick(self.now_ns);
                    self.drainEndpointSend(client, .c2s);
                }
            }
            if (server_time) |st| {
                if (self.now_ns >= st) {
                    server.tick(self.now_ns);
                    self.drainEndpointSend(server, .s2c);
                }
            }

            // Deliver all ready packets
            var delivered: usize = 0;
            while (delivered < 64) : (delivered += 1) {
                const pkt = self.deliver() orelse break;
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(server, .s2c);
                    },
                    .s2c => {
                        client.receive(pkt.data, SERVER_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(client, .c2s);
                    },
                }
            }
        }
        return false;
    }

    /// Drive a transfer from sender to receiver. Returns total bytes received on the stream.
    pub fn runPairTransfer(
        self: *NetSim,
        client: *Connection(16),
        server: *Connection(16),
        io: std.Io,
        sender_is_client: bool,
        stream_id: u62,
        total_bytes: usize,
    ) !usize {
        const sender = if (sender_is_client) client else server;
        const receiver = if (sender_is_client) server else client;
        const send_dir: Direction = if (sender_is_client) .c2s else .s2c;
        const chunk_size: usize = 1024;

        var sent: usize = 0;
        var total_received: usize = 0;
        var recv_drain: [4096]u8 = undefined;

        var ticks: usize = 0;
        while (ticks < 500000) : (ticks += 1) {
            // Try to enqueue more data
            while (sent < total_bytes) {
                const remaining = total_bytes - sent;
                const this_chunk = @min(remaining, chunk_size);
                var payload: [1024]u8 = undefined;
                @memset(payload[0..this_chunk], 0xAB);
                const fin = (sent + this_chunk >= total_bytes);
                sender.streamSend(stream_id, payload[0..this_chunk], fin) catch break;
                sent += this_chunk;
            }
            self.drainEndpointSend(sender, send_dir);

            // Drain received data (advances flow control so peer can send more)
            while (true) {
                const n = receiver.streamRecv(stream_id, &recv_drain);
                if (n == 0) break;
                total_received += n;
            }

            if (total_received >= total_bytes) return total_received;

            const net_time = self.nextDeliveryTime();
            const ct = client.nextTimeout();
            const st_time = server.nextTimeout();
            var next_time = minOptional(net_time, ct) orelse self.now_ns + 10_000_000; // 10ms default
            if (st_time) |s| next_time = @min(next_time, s);
            if (next_time > self.now_ns + 30_000_000_000) break;
            if (next_time <= self.now_ns) next_time = self.now_ns + 1_000_000; // 1ms min advance
            self.advanceTo(next_time);

            // Fire timers
            if (ct) |t| {
                if (self.now_ns >= t) {
                    client.tick(self.now_ns);
                    self.drainEndpointSend(client, .c2s);
                }
            }
            if (st_time) |t| {
                if (self.now_ns >= t) {
                    server.tick(self.now_ns);
                    self.drainEndpointSend(server, .s2c);
                }
            }

            // Try draining sender again (pacing tokens may have refilled)
            self.drainEndpointSend(sender, send_dir);
            // If sender still has queued packets, advance time to refill pacing tokens
            if (sender.sq_head != sender.sq_tail) {
                self.now_ns += 1_000_000; // 1ms — enough for pacing refill
                self.drainEndpointSend(sender, send_dir);
            }

            // Deliver all ready packets
            var delivered: usize = 0;
            while (delivered < 32) : (delivered += 1) {
                const pkt = self.deliver() orelse break;
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(server, .s2c);
                    },
                    .s2c => {
                        client.receive(pkt.data, SERVER_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(client, .c2s);
                    },
                }
            }
        }

        // Final drain
        while (true) {
            const n = receiver.streamRecv(stream_id, &recv_drain);
            if (n == 0) break;
            total_received += n;
        }
        return total_received;
    }

    /// Drive both endpoints until no packets remain in flight and no timers are pending.
    pub fn runPairIdle(
        self: *NetSim,
        client: *Connection(16),
        server: *Connection(16),
        io: std.Io,
    ) !void {
        var ticks: usize = 0;
        while (ticks < 1000) : (ticks += 1) {
            const net_time = self.nextDeliveryTime();
            const ct = client.nextTimeout();
            const st = server.nextTimeout();
            const next_time = minOptional(net_time, minOptional(ct, st)) orelse break;
            if (next_time > self.now_ns + 5_000_000_000) break; // 5s limit
            self.advanceTo(next_time);

            if (ct) |t| {
                if (self.now_ns >= t) {
                    client.tick(self.now_ns);
                    self.drainEndpointSend(client, .c2s);
                }
            }
            if (st) |t| {
                if (self.now_ns >= t) {
                    server.tick(self.now_ns);
                    self.drainEndpointSend(server, .s2c);
                }
            }
            if (self.deliver()) |pkt| {
                switch (pkt.dir) {
                    .c2s => {
                        server.receive(pkt.data, CLIENT_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(server, .s2c);
                    },
                    .s2c => {
                        client.receive(pkt.data, SERVER_ADDR, self.now_ns, 0, io) catch {};
                        self.drainEndpointSend(client, .c2s);
                    },
                }
            }
        }
    }

    fn drainEndpointSend(self: *NetSim, endpoint: *Connection(16), dir: Direction) void {
        var out: [MAX_DGRAM]u8 = undefined;
        while (true) {
            const n = endpoint.send(&out, self.now_ns);
            if (n == 0) break;
            self.send(out[0..n], dir);
        }
    }
};

const CLIENT_ADDR: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 12345 } };
const SERVER_ADDR: SocketAddr = .{ .v4 = .{ .addr = .{ 127, 0, 0, 1 }, .port = 4433 } };

fn minOptional(a: ?i64, b: ?i64) ?i64 {
    if (a == null and b == null) return null;
    if (a == null) return b;
    if (b == null) return a;
    return @min(a.?, b.?);
}
