//! QUIC packet-level cryptography (RFC 9001).
//!
//! Implements:
//!   - Initial secret derivation (§5.2)
//!   - HKDF-Expand-Label (RFC 8446 §7.1 with "tls13 " prefix)
//!   - AES-128-GCM payload encryption/decryption (§5.3)
//!   - AES-128-ECB header protection (§5.4)

const std = @import("std");
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
const initial_salt = [_]u8{
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3,
    0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
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
/// of the client's first Initial packet (RFC 9001 §5.2).
pub fn deriveInitialKeys(dcid: []const u8) InitialKeys {
    const prk = HkdfSha256.extract(&initial_salt, dcid);

    var client_secret: [32]u8 = undefined;
    var server_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");
    hkdfExpandLabel(&server_secret, prk, "server in", "");

    return .{
        .client = derivePacketKeys(client_secret),
        .server = derivePacketKeys(server_secret),
    };
}

/// Derive key/iv/hp from a traffic secret.
pub fn derivePacketKeys(secret: [32]u8) PacketKeys {
    var keys: PacketKeys = undefined;
    hkdfExpandLabel(&keys.key, secret, "quic key", "");
    hkdfExpandLabel(&keys.iv, secret, "quic iv", "");
    hkdfExpandLabel(&keys.hp, secret, "quic hp", "");
    return keys;
}

/// Derive the next-generation application traffic secret for key update
/// (RFC 9001 §6.1).  The label "quic ku" is used; `hkdfExpandLabel` prepends
/// "tls13 " automatically.
pub fn deriveNextAppSecret(current: [32]u8) [32]u8 {
    var next: [32]u8 = undefined;
    hkdfExpandLabel(&next, current, "quic ku", "");
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

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn buildNonce(iv: [12]u8, pn: u64) [12]u8 {
    var nonce = iv;
    // XOR packet number into the low-order bytes (big-endian, left-padded).
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, pn));
    for (0..8) |i| {
        nonce[4 + i] ^= pn_bytes[i];
    }
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
    const prk = HkdfSha256.extract(&initial_salt, &test_dcid);
    var client_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");
    try testing.expectEqualSlices(u8, &expected_secret, &client_secret);
}

test "crypto: RFC 9001 A — client key/iv/hp" {
    const testing = std.testing;
    const keys = deriveInitialKeys(&test_dcid);

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
    const keys = deriveInitialKeys(&test_dcid);

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
    const keys = deriveInitialKeys(&test_dcid);
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
    const ck = deriveInitialKeys(&test_dcid).client;
    const short: [15]u8 = .{0} ** 15; // one byte short of the 16-byte tag
    var out: [0]u8 = .{};
    try std.testing.expectError(error.TooShort, decryptPayload(ck, 0, &.{}, &short, &out));
}

test "crypto: decryptPayload with corrupted authentication tag returns error" {
    const ck = deriveInitialKeys(&test_dcid).client;
    const pn: u64 = 7;
    const header = [_]u8{0xC3}; // arbitrary header byte
    const plaintext = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF };

    // Encrypt first
    var ct_tag: [plaintext.len + 16]u8 = undefined;
    encryptPayload(ck, pn, &header, &plaintext, &ct_tag);

    // Corrupt the last byte of the authentication tag
    ct_tag[ct_tag.len - 1] ^= 0xFF;

    var recovered: [plaintext.len]u8 = undefined;
    try std.testing.expectError(error.AuthenticationFailed,
        decryptPayload(ck, pn, &header, &ct_tag, &recovered));
}

test "crypto: applyHeaderProtection is self-inverse (XOR involution)" {
    const hp_key = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10,
                          0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    // Use a non-zero sample to get a non-trivial mask
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
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
    const prk = HkdfSha256.extract(&initial_salt, &test_dcid);
    var client_secret: [32]u8 = undefined;
    hkdfExpandLabel(&client_secret, prk, "client in", "");

    const next1 = deriveNextAppSecret(client_secret);
    const next2 = deriveNextAppSecret(client_secret);

    // Deterministic: two calls with the same input must produce the same output.
    try testing.expectEqualSlices(u8, &next1, &next2);
    // Output must differ from the input (KDF advances the secret).
    try testing.expect(!std.mem.eql(u8, &next1, &client_secret));
    // Chaining: deriving a second generation must also differ from the first.
    const next3 = deriveNextAppSecret(next1);
    try testing.expect(!std.mem.eql(u8, &next3, &next1));
}
