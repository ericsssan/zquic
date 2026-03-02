//! PEM → DER decoder and PKCS#8 private-key extractor.
//!
//! Supports Ed25519 and P-256 ECDSA (prime256v1) private keys.
//! Pure functions, no allocator, no I/O dependencies.

const std = @import("std");

/// Private-key algorithm detected from PKCS#8 DER.
pub const KeyAlgorithm = enum { ed25519, p256 };

/// Parsed private key: algorithm tag + 32-byte raw key material.
/// For Ed25519 this is the seed; for P-256 this is the private scalar.
pub const KeyMaterial = struct {
    algorithm: KeyAlgorithm,
    seed: [32]u8,
};

// prime256v1 OID bytes inside a PKCS#8 AlgorithmIdentifier:
// OBJECT IDENTIFIER 1.2.840.10045.3.1.7
const P256_OID = [_]u8{ 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07 };

/// Detect key algorithm and extract the 32-byte private key from PKCS#8 DER.
/// Works for both Ed25519 (seed) and P-256 (private scalar).
/// Both formats store the key as an inner OCTET STRING with tag 0x04 length 0x20.
pub fn parsePrivateKey(der: []const u8) !KeyMaterial {
    // Detect P-256 by looking for the prime256v1 OID in the DER.
    const algorithm: KeyAlgorithm = blk: {
        var i: usize = 0;
        while (i + P256_OID.len <= der.len) : (i += 1) {
            if (std.mem.eql(u8, der[i..][0..P256_OID.len], &P256_OID)) break :blk .p256;
        }
        break :blk .ed25519;
    };
    // Both Ed25519 and P-256 PKCS#8 store the 32-byte key as 0x04 0x20 <key>.
    const seed = try pkcs8Ed25519Seed(der);
    return .{ .algorithm = algorithm, .seed = seed };
}

/// Decode the first PEM block between "-----BEGIN ..." and "-----END ...".
/// Returns number of DER bytes written into `out`.
pub fn pemToDer(pem_input: []const u8, out: []u8) !usize {
    return pemToDerBlock(pem_input, null, out);
}

/// Decode the first PEM block whose header line contains `header_filter` (case-sensitive).
/// Pass `null` for `header_filter` to accept any block (same as pemToDer).
/// Returns number of DER bytes written into `out`.
pub fn pemToDerBlock(pem_input: []const u8, header_filter: ?[]const u8, out: []u8) !usize {
    var search_pos: usize = 0;
    while (true) {
        const begin = std.mem.indexOfPos(u8, pem_input, search_pos, "-----BEGIN ") orelse return error.NoPemMarker;
        const header_end = std.mem.indexOfPos(u8, pem_input, begin, "\n") orelse return error.NoPemMarker;
        const header_line = pem_input[begin..header_end];
        if (header_filter == null or std.mem.indexOf(u8, header_line, header_filter.?) != null) {
            const body_start = header_end + 1;
            const end_marker = std.mem.indexOfPos(u8, pem_input, body_start, "-----END ") orelse return error.NoPemMarker;
            const body = pem_input[body_start..end_marker];
            return pemDecodeBody(std.mem.trim(u8, body, " \t\r\n"), out);
        }
        // Skip past this block's end marker and continue searching.
        const end_marker = std.mem.indexOfPos(u8, pem_input, begin, "-----END ") orelse return error.NoPemMarker;
        search_pos = end_marker + 9; // past "-----END "
    }
}

fn pemDecodeBody(body: []const u8, out: []u8) !usize {
    // Strip all line endings from the base64 body.
    var clean: [16384]u8 = undefined;
    var ci: usize = 0;
    for (body) |c| {
        if (c != '\n' and c != '\r') {
            if (ci >= clean.len) return error.OutputTooSmall;
            clean[ci] = c;
            ci += 1;
        }
    }
    const decoder = std.base64.standard.Decoder;
    const decoded_len = try decoder.calcSizeForSlice(clean[0..ci]);
    if (decoded_len > out.len) return error.OutputTooSmall;
    try decoder.decode(out[0..decoded_len], clean[0..ci]);
    return decoded_len;
}

/// Extract 32-byte Ed25519 seed from PKCS#8 DER.
/// Searches for the inner OCTET STRING pattern: 0x04 0x20 <32 bytes seed>.
pub fn pkcs8Ed25519Seed(der: []const u8) ![32]u8 {
    var i: usize = 0;
    while (i + 34 <= der.len) : (i += 1) {
        if (der[i] == 0x04 and der[i + 1] == 0x20) {
            var seed: [32]u8 = undefined;
            @memcpy(&seed, der[i + 2 ..][0..32]);
            return seed;
        }
    }
    return error.Ed25519SeedNotFound;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "pem: decode certificate" {
    const testing = std.testing;

    // Minimal PEM block containing base64("hello world")
    const hello_b64 = "aGVsbG8gd29ybGQ=";
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        hello_b64 ++ "\n" ++
        "-----END CERTIFICATE-----\n";
    var out: [32]u8 = undefined;
    const n = try pemToDer(pem, &out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
}

test "pem: decode multiline base64" {
    const testing = std.testing;

    // Split the same base64 across lines (as real PEM files do, 64 chars/line).
    const pem =
        "-----BEGIN CERTIFICATE-----\n" ++
        "aGVs\n" ++
        "bG8g\n" ++
        "d29y\n" ++
        "bGQ=\n" ++
        "-----END CERTIFICATE-----\n";
    var out: [32]u8 = undefined;
    const n = try pemToDer(pem, &out);
    try testing.expectEqualSlices(u8, "hello world", out[0..n]);
}

test "pem: decode Ed25519 PKCS8" {
    const testing = std.testing;

    // Minimal PKCS#8 DER for Ed25519: the seed sits at bytes [16..48].
    // Structure: SEQUENCE { version, AlgorithmIdentifier, OCTET STRING { OCTET STRING { seed } } }
    // The pattern we search for is 0x04 0x20 <32 seed bytes>.
    var der: [50]u8 = [_]u8{0} ** 50;
    // Put the inner OCTET STRING at offset 16
    der[16] = 0x04;
    der[17] = 0x20;
    const expected_seed = [_]u8{0xab} ** 32;
    @memcpy(der[18..50], &expected_seed);

    const seed = try pkcs8Ed25519Seed(der[0..50]);
    try testing.expectEqual(expected_seed, seed);
}

test "pem: pkcs8Ed25519Seed finds seed at various offsets" {
    const testing = std.testing;

    // Seed pattern at offset 0
    var der0: [34]u8 = undefined;
    der0[0] = 0x04;
    der0[1] = 0x20;
    const s0 = [_]u8{0x11} ** 32;
    @memcpy(der0[2..34], &s0);
    try testing.expectEqual(s0, try pkcs8Ed25519Seed(&der0));

    // Seed pattern at offset 10
    var der10: [44]u8 = [_]u8{0xff} ** 44;
    der10[10] = 0x04;
    der10[11] = 0x20;
    const s10 = [_]u8{0x22} ** 32;
    @memcpy(der10[12..44], &s10);
    try testing.expectEqual(s10, try pkcs8Ed25519Seed(&der10));
}

test "pem: no PEM marker returns error" {
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.NoPemMarker, pemToDer("just some text", &out));
}

test "pem: seed not found returns error" {
    const der = [_]u8{0x30} ** 32; // all 0x30, no 0x04 0x20 pattern
    try std.testing.expectError(error.Ed25519SeedNotFound, pkcs8Ed25519Seed(&der));
}

test "pem: pemToDerBlock skips EC PARAMETERS to find EC PRIVATE KEY" {
    // Simulates an openssl ecparam -genkey output: EC PARAMETERS first, then EC PRIVATE KEY.
    const pem_input =
        "-----BEGIN EC PARAMETERS-----\n" ++
        "BggqhkjOPQMBBw==\n" ++
        "-----END EC PARAMETERS-----\n" ++
        "-----BEGIN EC PRIVATE KEY-----\n" ++
        "aGVsbG8gd29ybGQ=\n" ++
        "-----END EC PRIVATE KEY-----\n";
    var out: [32]u8 = undefined;
    // Without filter: returns the first block (EC PARAMETERS)
    const n_first = try pemToDer(pem_input, &out);
    try std.testing.expectEqualSlices(u8, "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07", out[0..n_first]);
    // With "PRIVATE KEY" filter: skips EC PARAMETERS, returns EC PRIVATE KEY body
    const n_key = try pemToDerBlock(pem_input, "PRIVATE KEY", &out);
    try std.testing.expectEqualSlices(u8, "hello world", out[0..n_key]);
}

test "pem: pemToDerBlock with no matching block returns NoPemMarker" {
    const pem_input =
        "-----BEGIN EC PARAMETERS-----\n" ++
        "BggqhkjOPQMBBw==\n" ++
        "-----END EC PARAMETERS-----\n";
    var out: [32]u8 = undefined;
    try std.testing.expectError(error.NoPemMarker, pemToDerBlock(pem_input, "PRIVATE KEY", &out));
}
