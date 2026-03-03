//! QUIC packet-level cryptography (RFC 9001).
//!
//! Implements:
//!   - Initial secret derivation (§5.2)
//!   - HKDF-Expand-Label (RFC 8446 §7.1 with "tls13 " prefix)
//!   - AES-128-GCM payload encryption/decryption (§5.3)
//!   - AES-128-ECB header protection (§5.4)

const std = @import("std");
const packet = @import("packet.zig");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = std.crypto.core.aes.Aes128;
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Keys for one direction of a QUIC epoch.
pub const PacketKeys = struct {
    key: [16]u8,
    iv: [12]u8,
    hp: [16]u8,
};

/// Keys for both directions of the Initial epoch.
pub const InitialKeys = struct {
    client: PacketKeys,
    server: PacketKeys,
};

/// QUIC v1 initial salt (RFC 9001 §5.2).
const initial_salt_v1 = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
};

/// QUIC v2 initial salt (RFC 9369 §3.3).
const initial_salt_v2 = [_]u8{
    0x0d, 0xed, 0xe3, 0xde, 0xf7, 0x00, 0xa6, 0xdb,
    0x81, 0x93, 0x81, 0xbe, 0x6e, 0x26, 0x9d, 0xcb,
    0xf9, 0xbd, 0x2e, 0xd9,
};

/// Build an HkdfLabel byte string as specified in RFC 8446 §7.1.
///
///   struct {
///     uint16 length;
///     opaque label<7..255> = "tls13 " + Label;
///     opaque context<0..255> = Context;
///   } HkdfLabel;
///
/// The returned slice points into `buf` which must be large enough
/// (2 + 1 + 6 + label.len + 1 + context.len bytes).
fn buildHkdfLabel(
    buf: []u8,
    length: u16,
    label: []const u8,
    context: []const u8,
) []const u8 {
    var pos: usize = 0;
    std.mem.writeInt(u16, buf[pos..][0..2], length, .big);
    pos += 2;
    buf[pos] = @intCast(6 + label.len);
    pos += 1;
    @memcpy(buf[pos..][0..6], "tls13 ");
    pos += 6;
    @memcpy(buf[pos..][0..label.len], label);
    pos += label.len;
    buf[pos] = @intCast(context.len);
    pos += 1;
    @memcpy(buf[pos..][0..context.len], context);
    pos += context.len;
    return buf[0..pos];
}

/// HKDF-Expand-Label (RFC 8446 §7.1).
pub fn hkdfExpandLabel(
    out: []u8,
    secret: [32]u8,
    label: []const u8,
    context: []const u8,
) void {
    // Max needed for QUIC: 2 + 1 + 6 + 12 ("c ap traffic") + 1 + 32 (hash) = 54.
    std.debug.assert(2 + 1 + 6 + label.len + 1 + context.len <= 64);
    var info_buf: [64]u8 = undefined;
    const info = buildHkdfLabel(&info_buf, @intCast(out.len), label, context);
    HkdfSha256.expand(out, info, secret);
}

/// Derive both client and server Initial keys from the destination CID
/// of the client's first Initial packet (RFC 9001 §5.2, RFC 9369 §3.3).
pub fn deriveInitialKeys(dcid: []const u8, version: u32) InitialKeys {
    const salt = if (version == packet.QUIC_VERSION_2) &initial_salt_v2 else &initial_salt_v1;
    const prk = HkdfSha256.extract(salt, dcid);

    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");
    hkdfExpandLabel(&server_secret, prk, "server in", "");

    return .{
        .client = derivePacketKeys(client_secret, version),
        .server = derivePacketKeys(server_secret, version),
    };
}

/// Derive key/iv/hp from a traffic secret (RFC 9001 §5.1, RFC 9369 §3.2).
pub fn derivePacketKeys(secret: [32]u8, version: u32) PacketKeys {
    var keys: PacketKeys = undefined;
    const is_v2 = version == packet.QUIC_VERSION_2;
    hkdfExpandLabel(&keys.key, secret, if (is_v2) "quicv2 key" else "quic key", "");
    hkdfExpandLabel(&keys.iv, secret, if (is_v2) "quicv2 iv" else "quic iv", "");
    hkdfExpandLabel(&keys.hp, secret, if (is_v2) "quicv2 hp" else "quic hp", "");
    return keys;
}

/// Derive the next-generation application traffic secret for key update
/// (RFC 9001 §6.1, RFC 9369 §3.2).  Labels differ between v1 and v2.
pub fn deriveNextAppSecret(current: [32]u8, version: u32) [32]u8 {
    var next: [32]u8 = undefined;
    hkdfExpandLabel(&next, current, if (version == packet.QUIC_VERSION_2) "quicv2 ku" else "quic ku", "");
    return next;
}

/// Encrypt a QUIC packet payload in-place (RFC 9001 §5.3).
///
/// `header` — the unprotected header bytes used as AAD.
/// `payload` — plaintext in, ciphertext + 16-byte tag out.
///             `payload` must have 16 extra bytes at the end for the tag.
pub fn encryptPayload(
    keys: PacketKeys,
    pn: u64,
    header: []const u8,
    plaintext: []const u8,
    ciphertext_tag_out: []u8,
) void {
    std.debug.assert(ciphertext_tag_out.len == plaintext.len + Aes128Gcm.tag_length);

    const nonce = buildNonce(keys.iv, pn);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    Aes128Gcm.encrypt(
        ciphertext_tag_out[0..plaintext.len],
        &tag,
        plaintext,
        header,
        nonce,
        keys.key,
    );
    @memcpy(ciphertext_tag_out[plaintext.len..], &tag);
}

/// Decrypt a QUIC packet payload in-place (RFC 9001 §5.3).
/// `ciphertext_tag` is ciphertext followed by the 16-byte auth tag.
/// On success, `plaintext_out` (length = ciphertext_tag.len - 16) holds the
/// decrypted payload.
pub fn decryptPayload(
    keys: PacketKeys,
    pn: u64,
    header: []const u8,
    ciphertext_tag: []const u8,
    plaintext_out: []u8,
) !void {
    if (ciphertext_tag.len < Aes128Gcm.tag_length) return error.TooShort;
    const ct_len = ciphertext_tag.len - Aes128Gcm.tag_length;
    std.debug.assert(plaintext_out.len == ct_len);

    const nonce = buildNonce(keys.iv, pn);
    var tag: [Aes128Gcm.tag_length]u8 = undefined;
    @memcpy(&tag, ciphertext_tag[ct_len..]);
    try Aes128Gcm.decrypt(
        plaintext_out,
        ciphertext_tag[0..ct_len],
        tag,
        header,
        nonce,
        keys.key,
    );
}

/// Apply or remove header protection (RFC 9001 §5.4).
///
/// `header_first_byte` — pointer to the first byte of the packet (mutated).
/// `pn_bytes`          — the packet-number bytes in the header (mutated).
/// `sample`            — 16 bytes from the ciphertext starting at
///                       offset 4 past the packet-number field.
pub fn applyHeaderProtection(
    hp_key: [16]u8,
    header_first_byte: *u8,
    pn_bytes: []u8,
    sample: *const [16]u8,
) void {
    var mask: [16]u8 = undefined;
    const aes = Aes128.initEnc(hp_key);
    aes.encrypt(&mask, sample);

    // Long header: mask bits 0..3 of first byte; short header: bits 0..4
    // We detect by checking whether bit 7 is set (long header flag = 1).
    if (header_first_byte.* & 0x80 != 0) {
        header_first_byte.* ^= mask[0] & 0x0f;
    } else {
        header_first_byte.* ^= mask[0] & 0x1f;
    }

    for (pn_bytes, 1..) |*b, i| {
        b.* ^= mask[i];
    }
}

/// Remove header protection from a received QUIC packet (RFC 9001 §5.4).
///
/// Performs two-step removal:
///   1. Unmask `first_byte` to recover the real bits (including pn_len).
///   2. Use the recovered pn_len to unmask exactly that many PN bytes.
///
/// `pn_field` must point to at least 4 bytes starting at the PN offset.
/// Returns the actual packet-number length (1..4) decoded from `first_byte`.
pub fn removeHeaderProtection(
    hp_key: [16]u8,
    first_byte: *u8,
    pn_field: *[4]u8,
    sample: *const [16]u8,
) u8 {
    var mask: [16]u8 = undefined;
    const aes = Aes128.initEnc(hp_key);
    aes.encrypt(&mask, sample);

    // Long header: mask bits 0..3; short header: mask bits 0..4.
    if (first_byte.* & 0x80 != 0) {
        first_byte.* ^= mask[0] & 0x0f;
    } else {
        first_byte.* ^= mask[0] & 0x1f;
    }

    const pn_len: u8 = (first_byte.* & 0x03) + 1;
    // Unroll the PN XOR loop (always 1-4 iterations) to avoid loop overhead
    switch (pn_len) {
        1 => pn_field[0] ^= mask[1],
        2 => {
            pn_field[0] ^= mask[1];
            pn_field[1] ^= mask[2];
        },
        3 => {
            pn_field[0] ^= mask[1];
            pn_field[1] ^= mask[2];
            pn_field[2] ^= mask[3];
        },
        4 => {
            pn_field[0] ^= mask[1];
            pn_field[1] ^= mask[2];
            pn_field[2] ^= mask[3];
            pn_field[3] ^= mask[4];
        },
        else => unreachable,
    }
    return pn_len;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn buildNonce(iv: [12]u8, pn: u64) [12]u8 {
    var nonce = iv;
    // XOR packet number into the low-order bytes (big-endian, left-padded).
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, pn));
    // Unroll the 8-byte XOR loop to eliminate loop overhead
    nonce[4] ^= pn_bytes[0];
    nonce[5] ^= pn_bytes[1];
    nonce[6] ^= pn_bytes[2];
    nonce[7] ^= pn_bytes[3];
    nonce[8] ^= pn_bytes[4];
    nonce[9] ^= pn_bytes[5];
    nonce[10] ^= pn_bytes[6];
    nonce[11] ^= pn_bytes[7];
    return nonce;
}

// ---------------------------------------------------------------------------
// Tests — RFC 9001 Appendix A test vectors
// ---------------------------------------------------------------------------
// Client destination connection ID: 0x8394c8f03e515708
const test_dcid = [_]u8{ 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08 };

test "crypto: RFC 9001 A — client initial secret" {
    const testing = std.testing;
    // RFC 9001 Appendix A.1 client_initial_secret
    const expected_secret = [_]u8{
        0xc0, 0x0c, 0xf1, 0x51, 0xca, 0x5b, 0xe0, 0x75,
        0xed, 0x0e, 0xbf, 0xb5, 0xc8, 0x03, 0x23, 0xc4,
        0x2d, 0x6b, 0x7d, 0xb6, 0x78, 0x81, 0x28, 0x9a,
        0xf4, 0x00, 0x8f, 0x1f, 0x6c, 0x35, 0x7a, 0xea,
    };
    const prk = HkdfSha256.extract(&initial_salt_v1, &test_dcid);
    var client_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");
    try testing.expectEqualSlices(u8, &expected_secret, &client_secret);
}

test "crypto: RFC 9001 A — client key/iv/hp" {
    const testing = std.testing;
    const keys = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1);

    const expected_key = [_]u8{
        0x1f, 0x36, 0x96, 0x13, 0xdd, 0x76, 0xd5, 0x46,
        0x77, 0x30, 0xef, 0xcb, 0xe3, 0xb1, 0xa2, 0x2d,
    };
    const expected_iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b,
        0x46, 0xfb, 0x25, 0x5c,
    };
    const expected_hp = [_]u8{
        0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
        0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2,
    };

    try testing.expectEqualSlices(u8, &expected_key, &keys.client.key);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.client.iv);
    try testing.expectEqualSlices(u8, &expected_hp, &keys.client.hp);
}

test "crypto: RFC 9001 A — server key/iv/hp" {
    const testing = std.testing;
    const keys = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1);

    const expected_key = [_]u8{
        0xcf, 0x3a, 0x53, 0x31, 0x65, 0x3c, 0x36, 0x4c,
        0x88, 0xf0, 0xf3, 0x79, 0xb6, 0x06, 0x7e, 0x37,
    };
    const expected_iv = [_]u8{
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53,
        0xb0, 0xbb, 0xa0, 0x3e,
    };
    const expected_hp = [_]u8{
        0xc2, 0x06, 0xb8, 0xd9, 0xb9, 0xf0, 0xf3, 0x76,
        0x44, 0x43, 0x0b, 0x49, 0x0e, 0xea, 0xa3, 0x14,
    };

    try testing.expectEqualSlices(u8, &expected_key, &keys.server.key);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.server.iv);
    try testing.expectEqualSlices(u8, &expected_hp, &keys.server.hp);
}

test "crypto: encrypt-decrypt round-trip" {
    const testing = std.testing;
    const keys = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1);
    const ck = keys.client;

    const pn: u64 = 2;
    const header = [_]u8{ 0xc3, 0x00, 0x00, 0x00, 0x01 };
    const plaintext = [_]u8{ 0x06, 0x00, 0x40, 0xf1, 0x01, 0x00, 0x00 };

    var ct: [plaintext.len + Aes128Gcm.tag_length]u8 = undefined;
    encryptPayload(ck, pn, &header, &plaintext, &ct);

    var recovered: [plaintext.len]u8 = undefined;
    try decryptPayload(ck, pn, &header, &ct, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "crypto: decryptPayload short buffer (< tag_length) returns TooShort" {
    const ck = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1).client;
    const short: [15]u8 = .{0} ** 15; // one byte short of the 16-byte tag
    var out: [0]u8 = .{};
    try std.testing.expectError(error.TooShort, decryptPayload(ck, 0, &.{}, &short, &out));
}

test "crypto: decryptPayload with corrupted authentication tag returns error" {
    const ck = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1).client;
    const pn: u64 = 7;
    const header = [_]u8{0xC3}; // arbitrary header byte
    const plaintext = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    // Encrypt first
    var ct_tag: [plaintext.len + 16]u8 = undefined;
    encryptPayload(ck, pn, &header, &plaintext, &ct_tag);

    // Corrupt the last byte of the authentication tag
    ct_tag[ct_tag.len - 1] ^= 0xFF;

    var recovered: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed, decryptPayload(ck, pn, &header, &ct_tag, &recovered));
}

test "crypto: applyHeaderProtection is self-inverse (XOR involution)" {
    const hp_key = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    // Use a non-zero sample to get a non-trivial mask
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    var first_byte: u8 = 0xC3; // long header (bit 7 = 1)
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 }; // 4-byte PN

    const orig_first = first_byte;
    const orig_pn = pn_bytes;

    // Apply once (protect)
    applyHeaderProtection(hp_key, &first_byte, &pn_bytes, &sample);
    // Apply again (remove — same XOR operation)
    applyHeaderProtection(hp_key, &first_byte, &pn_bytes, &sample);

    try std.testing.expectEqual(orig_first, first_byte);
    try std.testing.expectEqualSlices(u8, &orig_pn, &pn_bytes);
}

test "crypto: removeHeaderProtection handles all pn_len values (1-4)" {
    const testing = std.testing;
    const hp_key = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

    // Compute actual mask using AES
    var mask: [5]u8 = undefined;
    {
        var cipher = std.crypto.core.aes.Aes128.initEnc(hp_key);
        var mask_full: [16]u8 = undefined;
        cipher.encrypt(&mask_full, &sample);
        for (0..5) |i| {
            mask[i] = mask_full[i];
        }
    }

    // Test pn_len = 1 (first_byte pn_len bits = 00)
    {
        const unmasked_first: u8 = 0xC0; // long header, pn_len = 1
        const unmasked_pn = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

        // Apply mask to create the "wire" format
        var first_byte: u8 = unmasked_first ^ (mask[0] & 0x0f);
        var pn_field = unmasked_pn;
        pn_field[0] ^= mask[1]; // Only first byte masked since pn_len = 1

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 1), pn_len);
        try testing.expectEqual(unmasked_first, first_byte);
        try testing.expectEqual(unmasked_pn[0], pn_field[0]);
    }

    // Test pn_len = 2 (first_byte pn_len bits = 01)
    {
        const unmasked_first: u8 = 0xC1;
        const unmasked_pn = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

        var first_byte: u8 = unmasked_first ^ (mask[0] & 0x0f);
        var pn_field = unmasked_pn;
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 2), pn_len);
        try testing.expectEqual(unmasked_first, first_byte);
        try testing.expectEqual(unmasked_pn[0], pn_field[0]);
        try testing.expectEqual(unmasked_pn[1], pn_field[1]);
    }

    // Test pn_len = 3 (first_byte pn_len bits = 10)
    {
        const unmasked_first: u8 = 0xC2;
        const unmasked_pn = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

        var first_byte: u8 = unmasked_first ^ (mask[0] & 0x0f);
        var pn_field = unmasked_pn;
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];
        pn_field[2] ^= mask[3];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 3), pn_len);
        try testing.expectEqual(unmasked_first, first_byte);
        try testing.expectEqual(unmasked_pn[0], pn_field[0]);
        try testing.expectEqual(unmasked_pn[1], pn_field[1]);
        try testing.expectEqual(unmasked_pn[2], pn_field[2]);
    }

    // Test pn_len = 4 (first_byte pn_len bits = 11)
    {
        const unmasked_first: u8 = 0xC3;
        const unmasked_pn = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };

        var first_byte: u8 = unmasked_first ^ (mask[0] & 0x0f);
        var pn_field = unmasked_pn;
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];
        pn_field[2] ^= mask[3];
        pn_field[3] ^= mask[4];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 4), pn_len);
        try testing.expectEqual(unmasked_first, first_byte);
        try testing.expectEqual(unmasked_pn[0], pn_field[0]);
        try testing.expectEqual(unmasked_pn[1], pn_field[1]);
        try testing.expectEqual(unmasked_pn[2], pn_field[2]);
        try testing.expectEqual(unmasked_pn[3], pn_field[3]);
    }
}

test "crypto: nonce build" {
    // iv = 0xfa044b2f42a3fd3b46fb255c, pn = 2
    // nonce = iv XOR (pn left-padded to 12 bytes)
    // = iv XOR 0x000000000000000000000002
    const iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    };
    const pn: u64 = 2;
    const nonce = buildNonce(iv, pn);
    // Only the last byte should differ
    const expected = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5e,
    };
    const testing = std.testing;
    try testing.expectEqualSlices(u8, &expected, &nonce);
}

test "crypto: deriveNextAppSecret is deterministic and differs from input" {
    const testing = std.testing;
    // Use the client initial secret as a stand-in for an app traffic secret.
    const prk = HkdfSha256.extract(&initial_salt_v1, &test_dcid);
    var client_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");

    const next1 = deriveNextAppSecret(client_secret, packet.QUIC_VERSION_1);
    const next2 = deriveNextAppSecret(client_secret, packet.QUIC_VERSION_1);

    // Deterministic: two calls with the same input must produce the same output.
    try testing.expectEqualSlices(u8, &next1, &next2);
    // Output must differ from the input (KDF advances the secret).
    try testing.expect(!std.mem.eql(u8, &next1, &client_secret));
    // Chaining: deriving a second generation must also differ from the first.
    const next3 = deriveNextAppSecret(next1, packet.QUIC_VERSION_1);
    try testing.expect(!std.mem.eql(u8, &next3, &next1));
}

test "crypto: v2 initial keys differ from v1 for same DCID" {
    const testing = std.testing;
    const keys_v1 = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1);
    const keys_v2 = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_2);
    // v2 uses a different salt and labels, so keys must differ.
    try testing.expect(!std.mem.eql(u8, &keys_v1.client.key, &keys_v2.client.key));
    try testing.expect(!std.mem.eql(u8, &keys_v1.client.iv, &keys_v2.client.iv));
    try testing.expect(!std.mem.eql(u8, &keys_v1.server.key, &keys_v2.server.key));
}

test "crypto: v2 derivePacketKeys uses quicv2 labels" {
    const testing = std.testing;
    // Same secret, different version → different keys.
    const prk = HkdfSha256.extract(&initial_salt_v1, &test_dcid);
    var secret: [32]u8 = undefined;
    hkdfExpandLabel(&secret, prk, "client in", "");
    const k_v1 = derivePacketKeys(secret, packet.QUIC_VERSION_1);
    const k_v2 = derivePacketKeys(secret, packet.QUIC_VERSION_2);
    try testing.expect(!std.mem.eql(u8, &k_v1.key, &k_v2.key));
    try testing.expect(!std.mem.eql(u8, &k_v1.iv, &k_v2.iv));
    try testing.expect(!std.mem.eql(u8, &k_v1.hp, &k_v2.hp));
}

// ---------------------------------------------------------------------------
// REGRESSION TESTS: CPU OPTIMIZATIONS
// ---------------------------------------------------------------------------

test "regression: buildNonce unrolled loop correctness" {
    // Regression test for nonce building optimization (loop unrolling).
    // Verifies that the unrolled 8-byte XOR produces correct byte-by-byte results.
    const testing = std.testing;

    const iv = [_]u8{ 0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c };

    // Test PN = 0 (no change to any byte)
    {
        const nonce = buildNonce(iv, 0);
        try testing.expectEqualSlices(u8, &iv, &nonce);
    }

    // Test PN = 1: only bytes 4-11 should be affected (XOR with big-endian 0x0000000000000001)
    // pn_bytes = [0,0,0,0,0,0,0,1], so only nonce[11] ^= 1
    {
        const nonce = buildNonce(iv, 1);
        // First 4 bytes should be unchanged
        try testing.expectEqualSlices(u8, iv[0..4], nonce[0..4]);
        // Bytes 4-10 should be unchanged (no XOR with zero)
        try testing.expectEqualSlices(u8, iv[4..11], nonce[4..11]);
        // Last byte should be XOR'd with 1
        try testing.expectEqual(@as(u8, iv[11] ^ 1), nonce[11]);
    }

    // Test PN = 256 (0x0000000000000100): affects nonce[10] and nonce[11]
    // pn_bytes = [0,0,0,0,0,0,1,0], so nonce[10] ^= 1, nonce[11] ^= 0
    {
        const nonce = buildNonce(iv, 256);
        try testing.expectEqualSlices(u8, iv[0..4], nonce[0..4]); // unchanged
        try testing.expectEqualSlices(u8, iv[4..10], nonce[4..10]); // unchanged
        try testing.expectEqual(@as(u8, iv[10] ^ 1), nonce[10]); // XOR'd
        try testing.expectEqual(iv[11], nonce[11]); // unchanged (XOR with 0)
    }

    // Test PN = 0xFFFFFFFF: affects nonce[8..12]
    // pn_bytes = [0,0,0,0,FF,FF,FF,FF], so nonce[8..12] ^= FF
    {
        const nonce = buildNonce(iv, 0xFFFFFFFF);
        try testing.expectEqualSlices(u8, iv[0..4], nonce[0..4]); // unchanged
        try testing.expectEqualSlices(u8, iv[4..8], nonce[4..8]); // unchanged
        // Bytes 8-11 should be XOR'd with FF
        try testing.expectEqual(@as(u8, iv[8] ^ 0xFF), nonce[8]);
        try testing.expectEqual(@as(u8, iv[9] ^ 0xFF), nonce[9]);
        try testing.expectEqual(@as(u8, iv[10] ^ 0xFF), nonce[10]);
        try testing.expectEqual(@as(u8, iv[11] ^ 0xFF), nonce[11]);
    }
}

test "regression: removeHeaderProtection switch unrolling all pn_len values" {
    // Regression test for header protection removal optimization (switch unrolling).
    // Verifies that all 4 pn_len cases (1, 2, 3, 4) work correctly with the
    // switch statement optimization.
    const testing = std.testing;
    const hp_key = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

    // Compute the actual mask
    var mask: [5]u8 = undefined;
    {
        var cipher = std.crypto.core.aes.Aes128.initEnc(hp_key);
        var mask_full: [16]u8 = undefined;
        cipher.encrypt(&mask_full, &sample);
        for (0..5) |i| {
            mask[i] = mask_full[i];
        }
    }

    // Test pn_len = 1
    {
        const unmasked = 0xC0;
        var first_byte: u8 = unmasked ^ (mask[0] & 0x0f);
        var pn_field = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        pn_field[0] ^= mask[1];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 1), pn_len);
        try testing.expectEqual(unmasked, first_byte);
        try testing.expectEqual(@as(u8, 0xAA), pn_field[0]);
    }

    // Test pn_len = 2
    {
        const unmasked = 0xC1;
        var first_byte: u8 = unmasked ^ (mask[0] & 0x0f);
        var pn_field = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 2), pn_len);
        try testing.expectEqual(unmasked, first_byte);
    }

    // Test pn_len = 3
    {
        const unmasked = 0xC2;
        var first_byte: u8 = unmasked ^ (mask[0] & 0x0f);
        var pn_field = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];
        pn_field[2] ^= mask[3];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 3), pn_len);
        try testing.expectEqual(unmasked, first_byte);
    }

    // Test pn_len = 4
    {
        const unmasked = 0xC3;
        var first_byte: u8 = unmasked ^ (mask[0] & 0x0f);
        var pn_field = [_]u8{ 0xAA, 0xBB, 0xCC, 0xDD };
        pn_field[0] ^= mask[1];
        pn_field[1] ^= mask[2];
        pn_field[2] ^= mask[3];
        pn_field[3] ^= mask[4];

        const pn_len = removeHeaderProtection(hp_key, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 4), pn_len);
        try testing.expectEqual(unmasked, first_byte);
    }
}
