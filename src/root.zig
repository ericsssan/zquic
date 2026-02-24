//! zquic — a sans-I/O QUIC protocol library.
//!
//! The public API surface. Import this as @import("zquic").
//!
//! ## Sans-I/O design
//!
//! zquic owns the QUIC state machine; the caller owns the UDP socket.
//! Drive a connection with:
//!
//!   var conn = try quic.Connection.accept(config, io);
//!   // On datagram receipt:
//!   try conn.receive(udp_payload, src_addr, now_ns, io);
//!   // Drain outgoing datagrams:
//!   while (conn.send(&out_buf)) |n| { socket.send(out_buf[0..n]); }
//!   // Timer:
//!   if (conn.nextTimeout()) |deadline_ns| { ... }
//!   conn.tick(now_ns);

pub const varint = @import("quic/varint.zig");
pub const pool = @import("quic/pool.zig");
pub const crypto = @import("quic/crypto.zig");
pub const packet = @import("quic/packet.zig");
pub const frame = @import("quic/frame.zig");
pub const tls = @import("quic/tls.zig");
pub const stream = @import("quic/stream.zig");
pub const flow_control = @import("quic/flow_control.zig");
pub const congestion = struct {
    pub const cubic = @import("quic/congestion/cubic.zig");
};
pub const connection_id = @import("quic/connection_id.zig");

// Top-level re-exports for the most common types
pub const Connection = @import("quic/connection.zig").Connection;
pub const Config = @import("quic/connection.zig").Config;
pub const ConnState = @import("quic/connection.zig").ConnState;
pub const SocketAddr = @import("quic/connection.zig").SocketAddr;
pub const ConnectionId = @import("quic/connection_id.zig").ConnectionId;
pub const PacketKeys = @import("quic/crypto.zig").PacketKeys;

test {
    // Pull in all module tests via a recursive comptime import.
    const std = @import("std");
    std.testing.refAllDecls(@This());
}
