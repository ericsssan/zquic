//! QUIC hot-path micro-benchmarks.
//!
//! Build:  zig build microbench
//! Usage:  zig-out/bin/microbench
//!
//! Reports ns/op for critical encode/decode and crypto operations.
//! Built with ReleaseFast for realistic numbers.

const std = @import("std");
const zquic = @import("zquic");
const varint = zquic.varint;
const frame = zquic.frame;
const crypto = zquic.crypto;
const packet = zquic.packet;
const FAST_ITERATIONS: usize = 10_000_000;
const SLOW_ITERATIONS: usize = 100_000;

// ---------------------------------------------------------------------------
// Cross-platform nanosecond timer
// ---------------------------------------------------------------------------

extern "c" fn mach_absolute_time() u64;

fn nanotime() u64 {
    // On Apple Silicon, mach_absolute_time() returns nanoseconds directly.
    return mach_absolute_time();
}

// ---------------------------------------------------------------------------
// Bench runner
// ---------------------------------------------------------------------------

const Bench = struct {
    name: []const u8,
    run_fn: *const fn () void,
    iterations: usize,
};

const benches = [_]Bench{
    .{ .name = "varint encode 1-byte (63)", .run_fn = benchVarintEncode1, .iterations = FAST_ITERATIONS },
    .{ .name = "varint decode 1-byte", .run_fn = benchVarintDecode1, .iterations = FAST_ITERATIONS },
    .{ .name = "varint encode 2-byte (16383)", .run_fn = benchVarintEncode2, .iterations = FAST_ITERATIONS },
    .{ .name = "varint decode 2-byte", .run_fn = benchVarintDecode2, .iterations = FAST_ITERATIONS },
    .{ .name = "varint encode 4-byte (1073741823)", .run_fn = benchVarintEncode4, .iterations = FAST_ITERATIONS },
    .{ .name = "varint decode 4-byte", .run_fn = benchVarintDecode4, .iterations = FAST_ITERATIONS },
    .{ .name = "varint encode 8-byte (max)", .run_fn = benchVarintEncode8, .iterations = FAST_ITERATIONS },
    .{ .name = "varint decode 8-byte", .run_fn = benchVarintDecode8, .iterations = FAST_ITERATIONS },
    .{ .name = "STREAM frame encode", .run_fn = benchStreamFrameEncode, .iterations = FAST_ITERATIONS },
    .{ .name = "STREAM frame decode", .run_fn = benchStreamFrameDecode, .iterations = FAST_ITERATIONS },
    .{ .name = "short header encode", .run_fn = benchShortHeaderEncode, .iterations = FAST_ITERATIONS },
    .{ .name = "AES-128-GCM encrypt 1200B", .run_fn = benchAeadEncrypt, .iterations = SLOW_ITERATIONS },
    .{ .name = "AES-128-GCM decrypt 1200B", .run_fn = benchAeadDecrypt, .iterations = SLOW_ITERATIONS },
    .{ .name = "header protection apply", .run_fn = benchHpApply, .iterations = FAST_ITERATIONS },
    .{ .name = "header protection remove", .run_fn = benchHpRemove, .iterations = FAST_ITERATIONS },
    .{ .name = "initial key derivation", .run_fn = benchInitialKeys, .iterations = SLOW_ITERATIONS },
};

// Runtime-initialized keys (can't be comptime due to eval branch quota).
var cached_keys: crypto.InitialKeys = undefined;
var keys_initialized: bool = false;

fn getKeys() crypto.InitialKeys {
    if (!keys_initialized) {
        const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
        cached_keys = crypto.deriveInitialKeys(&dcid, packet.QUIC_VERSION_1);
        keys_initialized = true;
    }
    return cached_keys;
}

pub fn main() !void {
    // Force key init before benchmarks.
    _ = getKeys();

    std.debug.print("\n=== zquic micro-benchmarks ===\n\n", .{});
    std.debug.print("{s:<38} {s:>10} {s:>12}\n", .{ "Benchmark", "ns/op", "ops/sec" });
    std.debug.print("{s:-<62}\n", .{""});

    for (benches) |b| {
        const iters = b.iterations;

        // Warmup
        for (0..@min(iters / 10, 10000)) |_| b.run_fn();

        const t1 = nanotime();
        for (0..iters) |_| b.run_fn();
        const t2 = nanotime();

        const elapsed_ns = t2 - t1;
        const ns_per_op: f64 = @as(f64, @floatFromInt(elapsed_ns)) / @as(f64, @floatFromInt(iters));
        const ops_per_sec: f64 = if (ns_per_op > 0)
            1_000_000_000.0 / ns_per_op
        else
            0;

        std.debug.print("{s:<38} {d:>10.1} {d:>12.0}\n", .{ b.name, ns_per_op, ops_per_sec });
    }
    std.debug.print("\n", .{});
}

// ---------------------------------------------------------------------------
// Varint benchmarks
// ---------------------------------------------------------------------------

var sink: [8]u8 = undefined;

fn benchVarintEncode1() void {
    const n = varint.encode(&sink, 63);
    std.mem.doNotOptimizeAway(sink[0]);
    std.mem.doNotOptimizeAway(n);
}
fn benchVarintDecode1() void {
    const encoded = [_]u8{63};
    const r = varint.decode(&encoded);
    std.mem.doNotOptimizeAway(r);
}
fn benchVarintEncode2() void {
    const n = varint.encode(&sink, 16383);
    std.mem.doNotOptimizeAway(sink[0]);
    std.mem.doNotOptimizeAway(n);
}
fn benchVarintDecode2() void {
    const encoded = [_]u8{ 0x7f, 0xff };
    const r = varint.decode(&encoded);
    std.mem.doNotOptimizeAway(r);
}
fn benchVarintEncode4() void {
    const n = varint.encode(&sink, 1073741823);
    std.mem.doNotOptimizeAway(sink[0]);
    std.mem.doNotOptimizeAway(n);
}
fn benchVarintDecode4() void {
    const encoded = [_]u8{ 0xbf, 0xff, 0xff, 0xff };
    const r = varint.decode(&encoded);
    std.mem.doNotOptimizeAway(r);
}
fn benchVarintEncode8() void {
    const n = varint.encode(&sink, varint.max_value);
    std.mem.doNotOptimizeAway(sink[0]);
    std.mem.doNotOptimizeAway(n);
}
fn benchVarintDecode8() void {
    const encoded = [_]u8{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    const r = varint.decode(&encoded);
    std.mem.doNotOptimizeAway(r);
}

// ---------------------------------------------------------------------------
// Frame benchmarks
// ---------------------------------------------------------------------------

var frame_buf: [1500]u8 = undefined;

fn benchStreamFrameEncode() void {
    const payload = "hello from server";
    const f = frame.Frame{ .stream = .{
        .stream_id = 4,
        .offset = 1024,
        .fin = false,
        .data = payload,
    } };
    const n = frame.encodeFrame(&frame_buf, f);
    std.mem.doNotOptimizeAway(frame_buf[0]);
    std.mem.doNotOptimizeAway(n);
}

fn benchStreamFrameDecode() void {
    // Pre-encoded STREAM frame: type=0x0e (OFF+LEN), stream_id=4, offset=1024, len=17
    const encoded = comptime blk: {
        var buf: [64]u8 = undefined;
        const payload = "hello from server";
        const f = frame.Frame{ .stream = .{
            .stream_id = 4,
            .offset = 1024,
            .fin = false,
            .data = payload,
        } };
        const n = frame.encodeFrame(&buf, f);
        break :blk buf[0..n].*;
    };
    std.mem.doNotOptimizeAway(frame.parseFrame(&encoded) catch unreachable);
}

// ---------------------------------------------------------------------------
// Packet header benchmarks
// ---------------------------------------------------------------------------

var pkt_buf: [1500]u8 = undefined;

fn benchShortHeaderEncode() void {
    const cid = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const n = packet.encodeShortHeader(&pkt_buf, &cid, 42, false);
    std.mem.doNotOptimizeAway(pkt_buf[0]);
    std.mem.doNotOptimizeAway(n);
}

// ---------------------------------------------------------------------------
// AEAD benchmarks
// ---------------------------------------------------------------------------

var aead_plaintext: [1200]u8 = [_]u8{0xAB} ** 1200;
var aead_ciphertext: [1200 + 16]u8 = undefined;
var aead_header: [20]u8 = [_]u8{0x40} ++ [_]u8{0x01} ** 19;

fn benchAeadEncrypt() void {
    const keys = getKeys();
    crypto.encryptPayload(
        keys.server,
        42,
        &aead_header,
        &aead_plaintext,
        &aead_ciphertext,
    );
}

fn benchAeadDecrypt() void {
    const keys = getKeys();
    // Encrypt first to have valid ciphertext
    crypto.encryptPayload(
        keys.server,
        42,
        &aead_header,
        &aead_plaintext,
        &aead_ciphertext,
    );
    var decrypted: [1200]u8 = undefined;
    crypto.decryptPayload(
        keys.server,
        42,
        &aead_header,
        &aead_ciphertext,
        &decrypted,
    ) catch {};
    std.mem.doNotOptimizeAway(decrypted);
}

// ---------------------------------------------------------------------------
// Header protection benchmarks
// ---------------------------------------------------------------------------

fn benchHpApply() void {
    const keys = getKeys();
    var first_byte: u8 = 0x43; // short header
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x2a };
    const sample = [_]u8{0xDE} ** 16;
    crypto.applyHeaderProtection(keys.server, &first_byte, &pn_bytes, &sample);
    std.mem.doNotOptimizeAway(first_byte);
}

fn benchHpRemove() void {
    const keys = getKeys();
    var first_byte: u8 = 0x43;
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x2a };
    const sample = [_]u8{0xDE} ** 16;
    // Apply then remove
    crypto.applyHeaderProtection(keys.server, &first_byte, &pn_bytes, &sample);
    _ = crypto.removeHeaderProtection(keys.server, &first_byte, &pn_bytes, &sample);
    std.mem.doNotOptimizeAway(first_byte);
}

// ---------------------------------------------------------------------------
// Key derivation benchmarks
// ---------------------------------------------------------------------------

fn benchInitialKeys() void {
    const dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };
    std.mem.doNotOptimizeAway(crypto.deriveInitialKeys(&dcid, packet.QUIC_VERSION_1));
}
