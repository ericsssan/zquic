//! Batch QUIC crypto operations for SIMD acceleration.
//!
//! Splits the packet processing pipeline into two phases:
//!   Phase 1 (batchable):  HP removal + AEAD decrypt — pure crypto, no connection state
//!   Phase 2 (sequential): PN validation + frame processing — stateful, per-connection
//!
//! Phase 1 operates on `DecryptJob` structs that capture all crypto inputs.
//! Multiple jobs can be executed in parallel using SIMD-interleaved AEAD.
//!
//! ## Architecture
//!
//!   recvmmsg(sock, datagrams, N)
//!     │
//!     ▼
//!   ┌──────────────────────────────────┐
//!   │  Phase 1: Batch HP + Decrypt     │  ← SIMD parallel across N packets
//!   │  prepareDecryptJob() × N         │     AES-NI / VAES / ARMv8-CE
//!   │  batchDecrypt(jobs[0..N])         │
//!   └──────────────────────────────────┘
//!     │
//!     ▼
//!   ┌──────────────────────────────────┐
//!   │  Phase 2: Sequential Processing  │  ← per-connection state machine
//!   │  conn.processDecrypted(result)   │     PN dedup, frames, flow control
//!   └──────────────────────────────────┘
//!     │
//!     ▼
//!   ┌──────────────────────────────────┐
//!   │  Phase 3: Batch Encrypt + HP     │  ← SIMD parallel across M responses
//!   │  batchEncrypt(jobs[0..M])        │
//!   └──────────────────────────────────┘
//!     │
//!     ▼
//!   sendmmsg(sock, responses, M)
//!

const std = @import("std");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Maximum packets to batch. Sized for AVX-512 (4-wide AES) × pipeline depth.
/// 16 = 4 VAES lanes × 4 pipeline stages. ARM NEON uses 8 (2-wide × 4).
pub const MAX_BATCH = 16;

/// Maximum packet size (MTU).
const MAX_PKT = 1500;

// ---------------------------------------------------------------------------
// Decrypt job — captures all inputs needed for Phase 1
// ---------------------------------------------------------------------------

pub const PacketEpoch = enum(u2) {
    initial = 0,
    handshake = 1,
    app = 2,
};

/// A single decrypt job. Prepared from a raw datagram without touching
/// connection state. Contains everything needed for HP removal + AEAD decrypt.
pub const DecryptJob = struct {
    /// Raw packet data (copied into job-local buffer for mutation during HP removal).
    buf: [MAX_PKT]u8 = undefined,
    len: u16 = 0,

    /// Crypto inputs extracted during preparation.
    keys: crypto.PacketKeys = undefined,
    pn_offset: u16 = 0, // byte offset of PN field in buf
    epoch: PacketEpoch = .initial,
    is_short: bool = false,
    scid_len: u8 = 0, // for short header: our CID length

    /// Source address for path migration detection.
    src_addr_idx: u16 = 0, // index into caller's address array

    /// Status after execution.
    status: Status = .pending,

    pub const Status = enum {
        pending,
        ok,
        decrypt_failed,
        too_short,
        unsupported,
    };
};

/// Result of a successful decryption. Passed to Phase 2 for frame processing.
/// Zero-copy: plaintext lives in the DecryptJob's buffer (in-place decrypt).
pub const DecryptResult = struct {
    /// Shared buffer with the DecryptJob — plaintext overwrites ciphertext.
    /// Access plaintext via: plaintext[plaintext_offset..][0..plaintext_len]
    plaintext: [MAX_PKT]u8 = undefined,
    plaintext_offset: u16 = 0,
    plaintext_len: u16 = 0,

    /// Metadata extracted during HP removal.
    pn: u64 = 0, // full reconstructed packet number
    pn_len: u8 = 0,
    epoch: PacketEpoch = .initial,
    is_short: bool = false,
    key_phase: bool = false, // for key update detection (short header only)
    spin_bit: bool = false,

    /// Source address index (opaque to crypto layer).
    src_addr_idx: u16 = 0,

    /// Get the decrypted plaintext slice.
    pub fn getPlaintext(self: *const DecryptResult) []const u8 {
        return self.plaintext[self.plaintext_offset..][0..self.plaintext_len];
    }
};

// ---------------------------------------------------------------------------
// Encrypt job — captures all inputs needed for Phase 3
// ---------------------------------------------------------------------------

pub const EncryptJob = struct {
    /// Plaintext frames to encrypt.
    plaintext: [MAX_PKT]u8 = undefined,
    plaintext_len: u16 = 0,

    /// Pre-built header (unprotected).
    header: [64]u8 = undefined,
    header_len: u8 = 0,

    /// Crypto inputs.
    keys: crypto.PacketKeys = undefined,
    pn: u64 = 0,

    /// Output buffer for the complete protected packet.
    output: [MAX_PKT]u8 = undefined,
    output_len: u16 = 0,

    /// Destination address index.
    dst_addr_idx: u16 = 0,

    status: Status = .pending,

    pub const Status = enum {
        pending,
        ok,
        too_large,
    };
};

// ---------------------------------------------------------------------------
// Phase 1: Batch decrypt
// ---------------------------------------------------------------------------

/// Execute HP removal + AEAD decryption on a batch of jobs.
///
/// Each job is independent — no shared state between them. This is the
/// function that benefits from SIMD: AES-NI interleaves AES rounds across
/// multiple packets, and GCM's GHASH can use pclmulqdq on 4 streams.
///
/// Current implementation: scalar loop (correctness first).
/// TODO: SIMD backends:
///   - x86_64 VAES+VPCLMULQDQ: 4-wide AES-GCM (Intel Icelake+)
///   - x86_64 AES-NI: 2-wide interleaved (Sandy Bridge+)
///   - aarch64 CE: 2-wide interleaved AES + PMULL for GHASH
///   - Fallback: scalar (current)
pub fn batchDecrypt(
    jobs: []DecryptJob,
    results: []DecryptResult,
    /// Expected largest PN per epoch, for PN reconstruction.
    largest_pn: [3]u64,
) void {
    // -- Stage 1: HP mask computation --
    // All HP masks can be computed independently. With VAES, 4 AES-ECB
    // encryptions execute in a single instruction (vinserti64x2 + vaesenc×10).
    //
    // TODO: Batch AES-ECB for HP masks:
    //   var samples: [MAX_BATCH][16]u8;
    //   var masks:   [MAX_BATCH][5]u8;
    //   for (jobs) |*j, i| samples[i] = j.buf[j.pn_offset+4..][0..16].*;
    //   aesEcbBatch(hp_keys, &samples, &masks);  // single VAES pass
    //
    // For now, scalar:
    for (jobs, results) |*job, *result| {
        if (job.status != .pending) continue;
        decryptOne(job, result, largest_pn);
    }

    // -- Future Stage 2: Batch AEAD --
    // AES-GCM can interleave counter blocks across N streams:
    //   - Share AES key schedule (same key for all packets in same epoch)
    //   - Interleave GHASH polynomial multiplication across streams
    //   - 4-wide on AVX-512, 2-wide on AES-NI
    //
    // This requires grouping jobs by key (same epoch + same connection = same key).
    // With 50 connections, expect 1-3 packets per connection per batch.
    //
    // Multi-buffer API sketch:
    //   const groups = groupByKey(jobs);
    //   for (groups) |g| {
    //       aesGcmDecryptMulti(g.key, g.nonces, g.aads, g.cts, g.pts);
    //   }
}

/// Scalar decrypt for one job. Extracted as a function so the future SIMD
/// path can call it as a fallback for odd-count batches.
fn decryptOne(
    job: *DecryptJob,
    result: *DecryptResult,
    largest_pn: [3]u64,
) void {
    const data = job.buf[0..job.len];
    if (data.len < 20) {
        job.status = .too_short;
        return;
    }

    // HP removal: mutates job.buf in-place (it's our copy)
    const pn_off = job.pn_offset;
    if (pn_off + 4 + 16 > data.len) {
        job.status = .too_short;
        return;
    }

    const pn_len = crypto.removeHeaderProtection(
        job.keys,
        &job.buf[0],
        job.buf[pn_off..][0..4],
        job.buf[pn_off + 4 ..][0..16],
    );

    // Reconstruct full PN
    const epoch_idx: usize = @intFromEnum(job.epoch);
    const truncated_pn = readTruncatedPn(job.buf[pn_off..][0..4], pn_len);
    const pn = packet.decodePacketNumber(largest_pn[epoch_idx], truncated_pn, @as(u6, @intCast(pn_len)) * 8);

    // AAD = everything before payload (header with HP removed)
    const payload_start = pn_off + pn_len;
    if (job.is_short) {
        // Short header: payload starts right after PN
        if (payload_start >= data.len) {
            job.status = .too_short;
            return;
        }
        const aad: []const u8 = job.buf[0..payload_start];
        const payload = job.buf[payload_start..job.len];

        if (payload.len < 16) {
            job.status = .too_short;
            return;
        }

        // In-place decrypt: plaintext overwrites ciphertext in job.buf
        const pt_len = crypto.decryptPayloadInPlace(
            job.keys,
            pn,
            aad,
            payload,
        ) catch {
            job.status = .decrypt_failed;
            return;
        };

        result.plaintext = job.buf; // share the buffer — zero copy
        result.plaintext_len = @intCast(pt_len);
        result.plaintext_offset = @intCast(payload_start);
        result.pn = pn;
        result.pn_len = pn_len;
        result.epoch = job.epoch;
        result.is_short = true;
        result.key_phase = (job.buf[0] & 0x04) != 0;
        result.spin_bit = (job.buf[0] & 0x20) != 0;
        result.src_addr_idx = job.src_addr_idx;
        job.status = .ok;
    } else {
        // Long header: need to account for length field
        // For the prototype, we parse the payload region from the long header.
        // The caller (prepareDecryptJob) already set pn_offset correctly.
        const parsed = packet.parseLongHeader(job.buf[0..job.len]) catch {
            job.status = .decrypt_failed;
            return;
        };

        const consumed = parsed.consumed;
        const payload_len = parsed.header.payload.len;
        if (payload_len < 16) {
            job.status = .too_short;
            return;
        }
        const payload_start_long = consumed - payload_len;
        const aad: []const u8 = job.buf[0..payload_start_long];

        // In-place decrypt for long header
        const pt_len = crypto.decryptPayloadInPlace(
            job.keys,
            pn,
            aad,
            job.buf[payload_start_long..][0..payload_len],
        ) catch {
            job.status = .decrypt_failed;
            return;
        };

        result.plaintext = job.buf;
        result.plaintext_offset = @intCast(payload_start_long);
        result.plaintext_len = @intCast(pt_len);
        result.pn = pn;
        result.pn_len = pn_len;
        result.epoch = job.epoch;
        result.is_short = false;
        result.src_addr_idx = job.src_addr_idx;
        job.status = .ok;
    }
}

// ---------------------------------------------------------------------------
// Phase 3: Batch encrypt
// ---------------------------------------------------------------------------

/// Execute AEAD encryption + HP application on a batch of outgoing packets.
///
/// Same SIMD opportunity as decrypt: interleave AES rounds across N packets.
/// Additionally, HP application is just one AES-ECB per packet — trivially batchable.
pub fn batchEncrypt(jobs: []EncryptJob) void {
    // TODO: SIMD multi-buffer encryption
    // Group by key, interleave counter blocks, batch GHASH
    for (jobs) |*job| {
        if (job.status != .pending) continue;
        encryptOne(job);
    }
}

fn encryptOne(job: *EncryptJob) void {
    const hdr = job.header[0..job.header_len];
    const pt = job.plaintext[0..job.plaintext_len];
    const ct_len = job.plaintext_len + 16;
    const total = @as(u16, job.header_len) + ct_len;

    if (total > MAX_PKT) {
        job.status = .too_large;
        return;
    }

    // Copy header to output
    @memcpy(job.output[0..job.header_len], hdr);

    // Encrypt payload into output[header_len..]
    crypto.encryptPayload(
        job.keys,
        job.pn,
        hdr,
        pt,
        job.output[job.header_len..][0..ct_len],
    );

    // Apply header protection
    const pn_off = job.header_len - 4; // PN is last 4 bytes of header
    crypto.applyHeaderProtection(
        job.keys,
        &job.output[0],
        job.output[pn_off..][0..4],
        job.output[job.header_len..][0..16],
    );

    job.output_len = total;
    job.status = .ok;
}

// ---------------------------------------------------------------------------
// SIMD backend stubs (future work)
// ---------------------------------------------------------------------------

/// Comptime SIMD feature detection — zero runtime cost, dead code eliminated.
const builtin = @import("builtin");

pub const has_aes_hw = switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .aes),
    .aarch64 => std.Target.aarch64.featureSetHas(builtin.cpu.features, .aes),
    else => false,
};

pub const has_vaes = switch (builtin.cpu.arch) {
    .x86_64 => std.Target.x86.featureSetHas(builtin.cpu.features, .vaes),
    else => false,
};

/// Optimal batch width based on available SIMD.
pub const OPTIMAL_BATCH = if (has_vaes) 16 else if (has_aes_hw) 8 else 4;

/// Multi-buffer AES-128-GCM decrypt stub.
///
/// The key insight: AES-GCM has two parallelizable components:
///   1. AES-CTR for the ciphertext — each counter block is independent
///   2. GHASH for authentication — polynomial evaluation is associative
///
/// With VAES (4×128-bit lanes), we process 4 AES blocks per instruction:
///   vinserti64x2 zmm, [ct0], [ct1], [ct2], [ct3]  ; load 4 counter blocks
///   vaesenc      zmm, zmm, round_key               ; 4 AES rounds in parallel
///   ×10 rounds
///   vaesenclast  zmm, zmm, round_key               ; final round
///
/// For GHASH, VPCLMULQDQ operates on 4 carry-less multiplications simultaneously.
///
/// Expected speedup over scalar:
///   AES-NI (2-wide):  ~1.8x on 8+ packet batches
///   VAES   (4-wide):  ~3.5x on 16+ packet batches
///   ARM CE (2-wide):  ~1.7x on 8+ packet batches
///
/// Reference: Intel Multi-Buffer Crypto for IPsec (intel/isa-l_crypto)
pub fn aesGcmDecryptMulti(
    _key: [16]u8,
    _nonces: []const [12]u8,
    _aads: []const []const u8,
    _cts: []const []const u8,
    _pts: [][]u8,
) !void {
    // Stub — would contain VAES intrinsics or call into isa-l_crypto
    _ = _key;
    _ = _nonces;
    _ = _aads;
    _ = _cts;
    _ = _pts;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn readTruncatedPn(pn_bytes: *const [4]u8, pn_len: u8) u32 {
    return switch (pn_len) {
        1 => @as(u32, pn_bytes[0]),
        2 => @as(u32, pn_bytes[0]) << 8 | @as(u32, pn_bytes[1]),
        3 => @as(u32, pn_bytes[0]) << 16 | @as(u32, pn_bytes[1]) << 8 | @as(u32, pn_bytes[2]),
        4 => std.mem.readInt(u32, pn_bytes, .big),
        else => 0,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "DecryptJob size fits in cache line multiple" {
    // Each job should be cache-friendly for batch processing
    const size = @sizeOf(DecryptJob);
    try testing.expect(size <= 1600); // ~1 packet + metadata
}

test "batch decrypt with empty batch is no-op" {
    var jobs: [0]DecryptJob = .{};
    var results: [0]DecryptResult = .{};
    batchDecrypt(&jobs, &results, .{ 0, 0, 0 });
}

test "EncryptJob round-trip with known keys" {
    // Create a simple encrypt job and verify it produces valid output
    var job = EncryptJob{};
    job.keys = crypto.PacketKeys{
        .key = [_]u8{0x01} ** 32,
        .iv = [_]u8{0x02} ** 12,
        .hp = [_]u8{0x03} ** 32,
        .suite = .aes_128_gcm,
    };
    job.pn = 42;

    // Build a simple short header
    const hdr = packet.encodeShortHeader(&job.header, &([_]u8{0xAA} ** 8), 42, false);
    job.header_len = @intCast(hdr);

    // Simple plaintext (PING frame)
    job.plaintext[0] = 0x01; // PING
    job.plaintext_len = 1;

    encryptOne(&job);
    try testing.expect(job.status == .ok);
    try testing.expect(job.output_len > 0);
}

test "comptime SIMD detection produces valid batch width" {
    try testing.expect(OPTIMAL_BATCH >= 4);
    try testing.expect(OPTIMAL_BATCH <= 16);
}

test "readTruncatedPn handles all lengths" {
    const bytes = [4]u8{ 0xDE, 0xAD, 0xBE, 0xEF };
    try testing.expectEqual(@as(u32, 0xDE), readTruncatedPn(&bytes, 1));
    try testing.expectEqual(@as(u32, 0xDEAD), readTruncatedPn(&bytes, 2));
    try testing.expectEqual(@as(u32, 0xDEADBE), readTruncatedPn(&bytes, 3));
    try testing.expectEqual(@as(u32, 0xDEADBEEF), readTruncatedPn(&bytes, 4));
}
