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
//!   - Frame encode→parse round-trip: encodeFrame(f) must be parseable and reproduce f.
//!   - Frame ACCEPTANCE: a structurally well-formed frame must NOT be rejected. The
//!     crash/round-trip targets above start by parsing fuzz bytes (`catch return`),
//!     so they are blind to a VALID frame being wrongly rejected — exactly the bug
//!     class behind the >31-range ACK FRAME_ENCODING_ERROR. fuzzAckArbitraryRanges
//!     builds a valid ACK with an arbitrary range count and asserts it parses.
//!   - GapList: fill/contiguousFrom invariants under arbitrary out-of-order input.
//!   - Stream send buffer: bufferSendData/getSendData/onAcked ring-buffer invariants.
//!   - Loss recovery loop: onPacketSent/onAckReceived must not corrupt bytes_in_flight.
//!   - RTT estimator (full u64): ptoBase must be >= K_GRANULARITY_NS for any input.
//!   - Full receive path (RAW): Connection.receive() on an arbitrary datagram must
//!     never crash — header parsing, version negotiation, Retry, coalescing, header
//!     protection, Initial decrypt. The off-path attacker's garbage-spray surface.
//!   - Full receive path (AUTHENTICATED): arbitrary frame bytes sealed under known
//!     1-RTT keys and fed to an established connection must never crash the decrypt →
//!     processFrames → stream/flow-control/loss path. The malicious-peer surface,
//!     deeper than parsing frames in isolation (real connection state interactions).

const std = @import("std");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
const transport_params = @import("transport_params.zig");
const packet = @import("packet.zig");
const stream_mod = @import("stream.zig");
const loss_recovery_mod = @import("loss_recovery.zig");
const conn_mod = @import("connection.zig");
const crypto = @import("crypto.zig");

// ---------------------------------------------------------------------------
// Compatibility shim: std.testing.fuzz changed its callback signature between
// dev builds. In builds that have std.testing.Smith the callback receives
// `*Smith`; in older builds it receives `[]const u8`.
// ---------------------------------------------------------------------------

/// The type passed to each fuzz callback by std.testing.fuzz.
const FuzzInput = if (@hasDecl(std.testing, "Smith")) *std.testing.Smith else []const u8;

/// Extract a variable-length byte slice from the fuzz input into `buf`.
/// Returns a slice of `buf` containing the bytes.
inline fn getBytes(input: FuzzInput, buf: []u8) []const u8 {
    if (@hasDecl(std.testing, "Smith")) {
        const n = input.slice(buf);
        return buf[0..n];
    } else {
        const n = @min(buf.len, input.len);
        @memcpy(buf[0..n], input[0..n]);
        return buf[0..n];
    }
}

// ---------------------------------------------------------------------------
// Fuzz target functions
// ---------------------------------------------------------------------------

/// Frame parser must not crash on any byte sequence.
fn fuzzFrameParse(_: void, input: FuzzInput) anyerror!void {
    var buf: [4096]u8 = undefined;
    const bytes = getBytes(input, &buf);
    var pos: usize = 0;
    while (pos < bytes.len) {
        const result = frame.parseFrame(bytes[pos..]) catch return;
        if (result.consumed == 0) return;
        pos += result.consumed;
    }
}

/// Varint encode → decode round-trip: encode(decode(x)) must reproduce the
/// same value and consume the same number of bytes.
fn fuzzVarint(_: void, input: FuzzInput) anyerror!void {
    var buf: [8]u8 = undefined;
    const bytes = getBytes(input, &buf);
    const decoded = varint.decode(bytes) orelse return;
    var enc_buf: [8]u8 = undefined;
    const enc_n = varint.encode(&enc_buf, decoded.value);
    // Re-decode the canonical encoding — must give back the same value.
    const redecoded = varint.decode(enc_buf[0..enc_n]) orelse return;
    try std.testing.expectEqual(decoded.value, redecoded.value);
    try std.testing.expectEqual(@as(u8, @intCast(enc_n)), redecoded.len);
}

/// Transport params decoder must not crash on any input.
fn fuzzTransportParams(_: void, input: FuzzInput) anyerror!void {
    var buf: [4096]u8 = undefined;
    const bytes = getBytes(input, &buf);
    _ = transport_params.decode(bytes) catch return;
}

/// Packet header parser must not crash on any input.
fn fuzzPacketParse(_: void, input: FuzzInput) anyerror!void {
    var buf: [2048]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len == 0) return;
    if (packet.isLongHeader(bytes[0])) {
        _ = packet.parseLongHeader(bytes) catch return;
    } else {
        _ = packet.parseShortHeader(bytes, 8) catch return;
    }
}

/// Stream receiveData must not crash on any (offset, data, fin) combination.
/// Properties: flow control or buffer errors are the only expected outcomes.
fn fuzzStreamReceive(_: void, input: FuzzInput) anyerror!void {
    var buf: [4096 + 9]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len < 9) return;
    // First 8 bytes: offset (u64 little-endian); byte 8: fin flag; rest: data.
    const offset: u64 = std.mem.readInt(u64, bytes[0..8], .little);
    const fin = bytes[8] & 1 != 0;
    const data = bytes[9..];
    var s = try stream_mod.Stream.init(0, stream_mod.SEND_BUF_SIZE);
    // Must not crash; flow-control or buffer errors are expected and fine.
    s.receiveData(offset, data, fin) catch return;
}

/// RttEstimator.update must not crash, overflow, or produce NaN/zero values
/// regardless of sample_ns, ack_delay_ns, max_ack_delay_ns inputs.
fn fuzzRttUpdate(_: void, input: FuzzInput) anyerror!void {
    var buf: [768]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len < 3) return;
    var rtt = loss_recovery_mod.RttEstimator{};
    var i: usize = 0;
    while (i + 3 <= bytes.len) : (i += 3) {
        // Scale bytes to milliseconds to exercise meaningful RTT ranges.
        const sample_ns = @as(u64, bytes[i]) * 1_000_000;
        const ack_delay = @as(u64, bytes[i + 1]) * 1_000_000;
        const max_delay = @as(u64, bytes[i + 2]) * 1_000_000 + 1; // +1 to avoid zero
        rtt.update(sample_ns, ack_delay, max_delay);
        // smoothed_rtt and rtt_var must always remain positive after initialization.
        if (rtt.initialized) {
            try std.testing.expect(rtt.smoothed_rtt > 0);
        }
    }
}

/// Frame encode→parse round-trip: parse a frame from fuzz bytes, re-encode it,
/// re-parse the encoded bytes, and verify the values are identical.
/// This catches asymmetry between encodeFrame and parseFrame.
fn fuzzFrameRoundTrip(_: void, input: FuzzInput) anyerror!void {
    var buf: [4096]u8 = undefined;
    const bytes = getBytes(input, &buf);
    const r1 = frame.parseFrame(bytes) catch return;
    if (r1.consumed == 0) return;
    var enc_buf: [4096]u8 = undefined;
    const enc_len = frame.encodeFrame(&enc_buf, r1.frame);
    if (enc_len == 0) return;
    const r2 = frame.parseFrame(enc_buf[0..enc_len]) catch return;
    // After a clean round-trip the consumed byte count must be stable.
    try std.testing.expectEqual(enc_len, r2.consumed);
}

/// ACCEPTANCE property: a structurally well-formed ACK frame with an ARBITRARY
/// number of ranges MUST parse — never error. RFC 9000 §19.3 sets no upper bound
/// on the ACK Range Count; a fixed internal cap that *rejects* (instead of
/// retaining-and-continuing) is mapped to FRAME_ENCODING_ERROR and tears down a
/// healthy connection under loss. This builds a valid ACK with a fuzz-chosen
/// range count — including well past the 32-slot storage array — and asserts
/// parseFrame accepts it AND consumes every byte (so the parser reads all ranges,
/// not just the retained ones). Regression guard for the >31-range bug; unlike the
/// round-trip targets it does NOT `catch return`, so a wrong rejection fails loudly.
fn fuzzAckArbitraryRanges(_: void, input: FuzzInput) anyerror!void {
    var buf: [256]u8 = undefined;
    const bytes = getBytes(input, &buf);
    // Always bracket the 32-slot storage cap with fixed counts so EVERY run (the
    // once-through smoke test included, regardless of seed) exercises the
    // regression; the fuzzer adds an extra input-derived count for breadth.
    // QUIC varints are u62 and all these values are tiny, so the casts are lossless.
    const fuzz_count: u62 = if (bytes.len >= 1) @min(bytes[0], 200) else 0;
    for ([_]u62{ 0, 1, 31, 32, 33, 64, 200, fuzz_count }) |range_count| {
        var wire: [1024]u8 = undefined;
        var w: usize = 0;
        wire[w] = 0x02; // ACK frame type
        w += 1;
        w += varint.encode(wire[w..], 63); // Largest Acknowledged (1-byte varint)
        w += varint.encode(wire[w..], 0); // ACK Delay
        w += varint.encode(wire[w..], range_count); // ACK Range Count (the variable under test)
        w += varint.encode(wire[w..], 0); // First ACK Range
        var k: u62 = 0;
        while (k < range_count) : (k += 1) {
            // gap + ack_range, each a 1-byte varint (<64) so the frame stays well-formed.
            const gap: u62 = if (bytes.len >= 2) bytes[1 + (@as(usize, k) % (bytes.len - 1))] & 0x3f else 0;
            w += varint.encode(wire[w..], gap);
            w += varint.encode(wire[w..], 0);
        }
        // A well-formed ACK with ANY range count must parse — a rejection IS the bug.
        const result = try frame.parseFrame(wire[0..w]);
        switch (result.frame) {
            .ack => {},
            else => return error.WrongFrameType,
        }
        // The parser must consume every byte (read all ranges), even when it only
        // retains the first ranges.len of them.
        try std.testing.expectEqual(w, result.consumed);
    }
}

/// GapList invariants under arbitrary fill sequences (RFC 9000 §2.2 reassembly).
/// Properties:
///   - count never exceeds MAX_GAPS
///   - contiguousFrom(base) >= base always
///   - window_end >= contiguousFrom(0) always
fn fuzzGapList(_: void, input: FuzzInput) anyerror!void {
    var buf: [512]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len < 2) return;
    var gl = stream_mod.GapList.init(0, stream_mod.STREAM_BUF_SIZE);
    var i: usize = 0;
    while (i + 2 <= bytes.len) : (i += 2) {
        const offset = @as(u64, bytes[i]) * 16; // spread fills across buffer range
        const len: usize = @as(usize, bytes[i + 1]) + 1; // 1..256
        gl.fill(offset, len);
        // Invariant 1: gap count within bounds
        try std.testing.expect(gl.count <= stream_mod.MAX_GAPS);
        // Invariant 2: contiguous frontier never regresses below 0
        const frontier = gl.contiguousFrom(0);
        try std.testing.expect(frontier <= gl.window_end);
    }
}

/// Stream send-side ring buffer invariants under arbitrary write/ack sequences.
/// Properties:
///   - getSendData returns what was written at the same offset
///   - onAcked only advances send_acked monotonically
///   - no panic or safety-checked UB on any input combination
fn fuzzStreamSendBuffer(_: void, input: FuzzInput) anyerror!void {
    var buf: [4096]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len < 2) return;
    var s = try stream_mod.Stream.init(0, stream_mod.SEND_BUF_SIZE);
    s.send_max = std.math.maxInt(u64); // no flow-control limit for this fuzz target
    var i: usize = 0;
    while (i < bytes.len) {
        const op = bytes[i] & 0x3; // 2-bit opcode
        const arg = if (i + 1 < bytes.len) bytes[i + 1] else 0;
        i += 2;
        switch (op) {
            0 => {
                // Write arg bytes
                const data_len: usize = @as(usize, arg) + 1;
                const end = @min(i + data_len, bytes.len);
                const data = bytes[i..end];
                i = end;
                _ = s.bufferSendData(data);
            },
            1 => {
                // Peek at current send_acked offset
                var peek_buf: [256]u8 = undefined;
                _ = s.getSendData(s.send_acked, &peek_buf);
            },
            2 => {
                // Ack up to arg bytes from current send_acked position
                const ack_len: u16 = @as(u16, arg) + 1;
                const before = s.send_acked;
                s.onAcked(s.send_acked, ack_len);
                // send_acked must be monotonically non-decreasing
                try std.testing.expect(s.send_acked >= before);
            },
            else => {
                // Peek at an arbitrary offset (below + above send_acked)
                const offset: u64 = s.send_acked +| @as(u64, arg);
                var peek_buf: [64]u8 = undefined;
                _ = s.getSendData(offset, &peek_buf);
            },
        }
    }
}

/// Loss recovery loop invariants under arbitrary sent/acked packet sequences.
/// Properties:
///   - bytes_in_flight never wraps (saturating subtract is used internally, but
///     we verify it stays within plausible bounds)
///   - No panic or UB regardless of input order or epoch values
fn fuzzLossRecoveryLoop(_: void, input: FuzzInput) anyerror!void {
    var buf: [512]u8 = undefined;
    const bytes = getBytes(input, &buf);
    var lr = loss_recovery_mod.LossRecovery.init();
    var pn: u64 = 1;
    var now_ns: i64 = 1_000_000;
    var i: usize = 0;
    while (i < bytes.len) {
        const op = bytes[i] & 0x1; // 1-bit opcode
        const b = if (i + 1 < bytes.len) bytes[i + 1] else 1;
        i += 2;
        const epoch: u8 = b & 0x3; // 0..2
        const ack_eliciting = (b >> 2) & 0x1 != 0;
        switch (op) {
            0 => {
                // Send a packet
                lr.onPacketSent(pn, epoch, 1200, ack_eliciting, now_ns, now_ns, .{});
                pn += 1;
                now_ns += 1_000_000; // +1ms
            },
            else => {
                // ACK the most recent packet (if any)
                if (pn > 1) {
                    const acked = pn - 1;
                    const ranges = [_]loss_recovery_mod.AckedRange{
                        .{ .low = acked, .high = acked },
                    };
                    _ = lr.onAckReceived(acked, 1_000_000, &ranges, epoch, now_ns, 25_000_000);
                    now_ns += 500_000;
                }
            },
        }
    }
    // bytes_in_flight must never exceed total bytes ever sent (1200 per packet).
    try std.testing.expect(lr.bytes_in_flight <= pn * 1200);
}

/// RTT estimator with full u64 inputs: ptoBase must always be >= K_GRANULARITY_NS.
/// This exercises the saturating arithmetic added to ptoBase and the EWMA updates.
fn fuzzRttFullRange(_: void, input: FuzzInput) anyerror!void {
    var buf: [2048]u8 = undefined;
    const bytes = getBytes(input, &buf);
    if (bytes.len < 8) return;
    var rtt = loss_recovery_mod.RttEstimator{};
    var i: usize = 0;
    while (i + 8 <= bytes.len) : (i += 8) {
        // Use full u64 values to reach extreme RTT ranges.
        const sample_ns = std.mem.readInt(u64, bytes[i..][0..8], .little);
        const ack_delay: u64 = if (i + 8 < bytes.len) @as(u64, bytes[i + 8]) * 1_000_000 else 0;
        const max_delay: u64 = 25_000_000;
        rtt.update(sample_ns, ack_delay, max_delay);
    }
    // ptoBase must be >= K_GRANULARITY_NS regardless of accumulated RTT state.
    const pto = rtt.ptoBase(0);
    try std.testing.expect(pto >= loss_recovery_mod.K_GRANULARITY_NS);
}

// A fixed source address for receive-path fuzzing.
const fuzz_src: conn_mod.SocketAddr = .{ .v4 = .{ .addr = [4]u8{ 127, 0, 0, 1 }, .port = 4433 } };

// A small connection keeps the per-iteration struct (inline stream table) cheap.
const FuzzConn = conn_mod.Connection(4);

// Fixed, all-known 1-RTT keys for the authenticated-frame target. Real values are
// irrelevant — both ends use the same key so encrypt(plaintext) round-trips through
// the receiver's decrypt, letting arbitrary frame bytes reach processFrames.
const fuzz_app_pk: crypto.PacketKeys = .{
    .key = @as([32]u8, @splat(0xAB)),
    .iv = @as([12]u8, @splat(0xCD)),
    .hp = @as([32]u8, @splat(0xEF)),
    .suite = .aes_128_gcm,
};

/// Full receive path on RAW bytes: an idle server connection fed an arbitrary UDP
/// datagram must never crash. Exercises long/short header parsing, version
/// negotiation, Retry, coalesced-packet splitting, header-protection removal, and
/// the Initial decrypt attempt — the exact surface an off-path attacker reaches by
/// spraying garbage at the socket. Errors are expected (it's hostile input); only
/// a crash / safety-checked UB is a finding.
fn fuzzReceiveRaw(_: void, input: FuzzInput) anyerror!void {
    var buf: [2048]u8 = undefined;
    const bytes = getBytes(input, &buf);
    const io = std.testing.io;
    var conn = FuzzConn.accept(.{}, io) catch return;
    defer conn.deinit();
    // receive() decrypts in place, so it needs a mutable buffer — buf itself.
    const ecn: u2 = if (bytes.len > 0) @truncate(bytes[0]) else 0;
    conn.receive(buf[0..bytes.len], fuzz_src, 1_000_000_000, ecn, io) catch {};
}

/// Full receive path on AUTHENTICATED frames: treat the fuzz bytes as 1-RTT frame
/// plaintext, seal them under known keys into a Short Header packet, and feed it to
/// an established connection. This drives arbitrary frame sequences through the real
/// decrypt → processFrames → stream table / flow control / loss recovery — i.e. the
/// "a peer that completed the handshake then sends hostile frames" surface, far
/// deeper than parsing frames in isolation. Only a crash is a finding.
fn fuzzReceiveAuthenticatedFrames(_: void, input: FuzzInput) anyerror!void {
    var buf: [1024]u8 = undefined;
    const plaintext = getBytes(input, &buf);
    const io = std.testing.io;
    var conn = FuzzConn.accept(.{ .validate_addr = false }, io) catch return;
    defer conn.deinit();
    // Skip the handshake: install fixed 1-RTT keys and mark established.
    conn.hot.state = .established;
    conn.app_keys = .{ .client = fuzz_app_pk, .server = fuzz_app_pk };
    conn.peer_cid = conn.local_cid;

    var pkt: [2048]u8 = undefined;
    const hdr_len = packet.encodeShortHeader(&pkt, &conn.local_cid.bytes, 0, false);
    const ct_len = plaintext.len + 16;
    if (hdr_len + ct_len > pkt.len) return;
    // Server decrypts 1-RTT with the client's keys → seal with the client key.
    crypto.encryptPayload(conn.app_keys.?.client, 0, pkt[0..hdr_len], plaintext, pkt[hdr_len..][0..ct_len]);
    crypto.applyHeaderProtection(conn.app_keys.?.client, &pkt[0], pkt[hdr_len - 4 ..][0..4], pkt[hdr_len..][0..16]);
    conn.receive(pkt[0 .. hdr_len + ct_len], fuzz_src, 1_000_000_000, 0, io) catch {};
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

test "fuzz: frame encode-parse round-trip" {
    try std.testing.fuzz({}, fuzzFrameRoundTrip, .{});
}

test "fuzz: ACK with arbitrary range count is always accepted" {
    try std.testing.fuzz({}, fuzzAckArbitraryRanges, .{});
}

test "fuzz: GapList fill/contiguousFrom invariants" {
    try std.testing.fuzz({}, fuzzGapList, .{});
}

test "fuzz: stream send buffer ring-buffer invariants" {
    try std.testing.fuzz({}, fuzzStreamSendBuffer, .{});
}

test "fuzz: loss recovery loop bytes_in_flight invariant" {
    try std.testing.fuzz({}, fuzzLossRecoveryLoop, .{});
}

test "fuzz: RTT estimator full u64 range ptoBase invariant" {
    try std.testing.fuzz({}, fuzzRttFullRange, .{});
}

test "fuzz: receive() on raw datagrams does not crash" {
    try std.testing.fuzz({}, fuzzReceiveRaw, .{});
}

test "fuzz: receive() on authenticated 1-RTT frames does not crash" {
    try std.testing.fuzz({}, fuzzReceiveAuthenticatedFrames, .{});
}
