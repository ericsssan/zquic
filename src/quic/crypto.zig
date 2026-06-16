//! QUIC packet-level cryptography (RFC 9001).
//!
//! Implements:
//!   - Initial secret derivation (§5.2)
//!   - HKDF-Expand-Label (RFC 8446 §7.1 with "tls13 " prefix)
//!   - AES-128-GCM and ChaCha20-Poly1305 payload encryption/decryption (§5.3)
//!   - AES-128-ECB and ChaCha20 header protection (§5.4)

const std = @import("std");
const packet = @import("packet.zig");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Aes128 = std.crypto.core.aes.Aes128;
const Sha256 = std.crypto.hash.sha2.Sha256;
const ChaCha20Poly1305 = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
const ChaCha20IETF = std.crypto.stream.chacha.ChaCha20IETF;

pub const CipherSuite = enum(u16) {
    aes_128_gcm = 0x1301,
    chacha20_poly1305 = 0x1303,
};

/// Keys for one direction of a QUIC epoch.
/// key/hp are 32 bytes (max size); AES-128-GCM uses first 16, ChaCha20 uses all 32.
pub const PacketKeys = struct {
    key: [32]u8,
    iv: [12]u8,
    hp: [32]u8,
    suite: CipherSuite,
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
    return derivePacketKeysWithSuite(secret, version, .aes_128_gcm);
}

/// Derive key/iv/hp for a specific cipher suite.
pub fn derivePacketKeysWithSuite(secret: [32]u8, version: u32, suite: CipherSuite) PacketKeys {
    var keys: PacketKeys = .{
        .key = @as([32]u8, @splat(0)),
        .iv = undefined,
        .hp = @as([32]u8, @splat(0)),
        .suite = suite,
    };
    const is_v2 = version == packet.QUIC_VERSION_2;
    const key_label = if (is_v2) "quicv2 key" else "quic key";
    const iv_label = if (is_v2) "quicv2 iv" else "quic iv";
    const hp_label = if (is_v2) "quicv2 hp" else "quic hp";
    switch (suite) {
        .aes_128_gcm => {
            hkdfExpandLabel(keys.key[0..16], secret, key_label, "");
            hkdfExpandLabel(&keys.iv, secret, iv_label, "");
            hkdfExpandLabel(keys.hp[0..16], secret, hp_label, "");
        },
        .chacha20_poly1305 => {
            hkdfExpandLabel(&keys.key, secret, key_label, "");
            hkdfExpandLabel(&keys.iv, secret, iv_label, "");
            hkdfExpandLabel(&keys.hp, secret, hp_label, "");
        },
    }
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
    std.debug.assert(ciphertext_tag_out.len == plaintext.len + 16);

    const nonce = buildNonce(keys.iv, pn);
    var tag: [16]u8 = undefined;
    switch (keys.suite) {
        .aes_128_gcm => {
            Aes128Gcm.encrypt(
                ciphertext_tag_out[0..plaintext.len],
                &tag,
                plaintext,
                header,
                nonce,
                keys.key[0..16].*,
            );
        },
        .chacha20_poly1305 => {
            ChaCha20Poly1305.encrypt(
                ciphertext_tag_out[0..plaintext.len],
                &tag,
                plaintext,
                header,
                nonce,
                keys.key,
            );
        },
    }
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
    if (ciphertext_tag.len < 16) return error.TooShort;
    const ct_len = ciphertext_tag.len - 16;
    std.debug.assert(plaintext_out.len == ct_len);

    const nonce = buildNonce(keys.iv, pn);
    var tag: [16]u8 = undefined;
    @memcpy(&tag, ciphertext_tag[ct_len..]);
    switch (keys.suite) {
        .aes_128_gcm => {
            try Aes128Gcm.decrypt(
                plaintext_out,
                ciphertext_tag[0..ct_len],
                tag,
                header,
                nonce,
                keys.key[0..16].*,
            );
        },
        .chacha20_poly1305 => {
            try ChaCha20Poly1305.decrypt(
                plaintext_out,
                ciphertext_tag[0..ct_len],
                tag,
                header,
                nonce,
                keys.key,
            );
        },
    }
}

/// Decrypt a QUIC packet payload in-place: plaintext overwrites ciphertext
/// in the same buffer.  Eliminates the separate plaintext output buffer,
/// reducing one full-packet memcpy on the receive hot path.
///
/// `payload` must contain ciphertext followed by the 16-byte AEAD auth tag.
/// On success, `payload[0..payload.len-16]` holds the decrypted plaintext.
/// On failure (auth tag mismatch), the buffer contents are **undefined** —
/// the caller must not read from it.  Save any data needed for fallback
/// (e.g., stateless reset token) BEFORE calling this function.
///
/// Returns the plaintext length (payload.len - 16).
pub fn decryptPayloadInPlace(
    keys: PacketKeys,
    pn: u64,
    header: []const u8,
    payload: []u8,
) !usize {
    if (payload.len < 16) return error.TooShort;
    const ct_len = payload.len - 16;

    const nonce = buildNonce(keys.iv, pn);
    // Extract tag before decrypt — AES-GCM processes blocks in-place and
    // the tag region may be read during GHASH before we need it for verify.
    var tag: [16]u8 = undefined;
    @memcpy(&tag, payload[ct_len..][0..16]);

    // Both AES-128-GCM and ChaCha20-Poly1305 support aliased m==c:
    //   AES-GCM:    GHASH each block before CTR-decrypt overwrites it.
    //   ChaCha20:   Poly1305 authenticates all ciphertext before any XOR.
    const ct: []const u8 = payload[0..ct_len];
    switch (keys.suite) {
        .aes_128_gcm => {
            try Aes128Gcm.decrypt(
                payload[0..ct_len],
                ct,
                tag,
                header,
                nonce,
                keys.key[0..16].*,
            );
        },
        .chacha20_poly1305 => {
            try ChaCha20Poly1305.decrypt(
                payload[0..ct_len],
                ct,
                tag,
                header,
                nonce,
                keys.key,
            );
        },
    }
    return ct_len;
}

/// Apply or remove header protection (RFC 9001 §5.4).
///
/// `keys`              — packet keys (suite determines AES vs ChaCha20 HP).
/// `header_first_byte` — pointer to the first byte of the packet (mutated).
/// `pn_bytes`          — the packet-number bytes in the header (mutated).
/// `sample`            — 16 bytes from the ciphertext starting at
///                       offset 4 past the packet-number field.
pub fn applyHeaderProtection(
    keys: PacketKeys,
    header_first_byte: *u8,
    pn_bytes: []u8,
    sample: *const [16]u8,
) void {
    const mask = hpMask(keys, sample);
    applyMask(header_first_byte, pn_bytes, mask);
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
    keys: PacketKeys,
    first_byte: *u8,
    pn_field: *[4]u8,
    sample: *const [16]u8,
) u8 {
    const mask = hpMask(keys, sample);

    // Long header: mask bits 0..3; short header: mask bits 0..4.
    if (first_byte.* & 0x80 != 0) {
        first_byte.* ^= mask[0] & 0x0f;
    } else {
        first_byte.* ^= mask[0] & 0x1f;
    }

    const pn_len: u8 = (first_byte.* & 0x03) + 1;
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

/// Compute 5-byte header protection mask (RFC 9001 §5.4.3 / §5.4.4).
fn hpMask(keys: PacketKeys, sample: *const [16]u8) [5]u8 {
    switch (keys.suite) {
        .aes_128_gcm => {
            var mask_full: [16]u8 = undefined;
            const aes = Aes128.initEnc(keys.hp[0..16].*);
            aes.encrypt(&mask_full, sample);
            return mask_full[0..5].*;
        },
        .chacha20_poly1305 => {
            // RFC 9001 §5.4.4: counter = sample[0..4] (LE), nonce = sample[4..16]
            const counter = std.mem.readInt(u32, sample[0..4], .little);
            const nonce = sample[4..16].*;
            var mask: [5]u8 = undefined;
            const zeros = @as([5]u8, @splat(0));
            ChaCha20IETF.xor(&mask, &zeros, counter, keys.hp, nonce);
            return mask;
        },
    }
}

/// Apply a 5-byte HP mask to the first byte and PN bytes.
fn applyMask(header_first_byte: *u8, pn_bytes: []u8, mask: [5]u8) void {
    if (header_first_byte.* & 0x80 != 0) {
        header_first_byte.* ^= mask[0] & 0x0f;
    } else {
        header_first_byte.* ^= mask[0] & 0x1f;
    }
    for (pn_bytes, 1..) |*b, i| {
        b.* ^= mask[i];
    }
}

pub fn buildNonce(iv: [12]u8, pn: u64) [12]u8 {
    var nonce = iv;
    // XOR packet number into the low-order bytes (big-endian, left-padded).
    const pn_bytes = std.mem.toBytes(std.mem.nativeToBig(u64, pn));
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

    try testing.expectEqualSlices(u8, &expected_key, keys.client.key[0..16]);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.client.iv);
    try testing.expectEqualSlices(u8, &expected_hp, keys.client.hp[0..16]);
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

    try testing.expectEqualSlices(u8, &expected_key, keys.server.key[0..16]);
    try testing.expectEqualSlices(u8, &expected_iv, &keys.server.iv);
    try testing.expectEqualSlices(u8, &expected_hp, keys.server.hp[0..16]);
}

test "crypto: RFC 9001 A.2 — AES header protection (client Initial)" {
    const testing = std.testing;
    const ck = deriveInitialKeys(&test_dcid, packet.QUIC_VERSION_1).client;
    // RFC 9001 A.2: 16-byte sample taken from the protected payload.
    const sample = [_]u8{
        0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8,
        0xec, 0x11, 0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b,
    };
    // Unprotected: long header, 4-byte PN encoding (0xc3), packet number 2.
    var first_byte: u8 = 0xc3;
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x02 };
    applyHeaderProtection(ck, &first_byte, &pn_bytes, &sample);
    // RFC 9001 A.2 protected header = c0...449e 7b9aec34.
    try testing.expectEqual(@as(u8, 0xc0), first_byte);
    try testing.expectEqualSlices(u8, &[_]u8{ 0x7b, 0x9a, 0xec, 0x34 }, &pn_bytes);
}

// RFC 9001 A.5 application traffic secret for the ChaCha20-Poly1305 example.
const a5_secret = [_]u8{
    0x9a, 0xc3, 0x12, 0xa7, 0xf8, 0x77, 0x46, 0x8e,
    0xbe, 0x69, 0x42, 0x27, 0x48, 0xad, 0x00, 0xa1,
    0x54, 0x43, 0xf1, 0x82, 0x03, 0xa0, 0x7d, 0x60,
    0x60, 0xf6, 0x88, 0xf3, 0x0f, 0x21, 0x63, 0x2b,
};
const a5_key = [_]u8{
    0xc6, 0xd9, 0x8f, 0xf3, 0x44, 0x1c, 0x3f, 0xe1,
    0xb2, 0x18, 0x20, 0x94, 0xf6, 0x9c, 0xaa, 0x2e,
    0xd4, 0xb7, 0x16, 0xb6, 0x54, 0x88, 0x96, 0x0a,
    0x7a, 0x98, 0x49, 0x79, 0xfb, 0x23, 0xe1, 0xc8,
};
const a5_iv = [_]u8{ 0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44 };
const a5_hp = [_]u8{
    0x25, 0xa2, 0x82, 0xb9, 0xe8, 0x2f, 0x06, 0xf2,
    0x1f, 0x48, 0x89, 0x17, 0xa4, 0xfc, 0x8f, 0x1b,
    0x73, 0x57, 0x36, 0x85, 0x60, 0x85, 0x97, 0xd0,
    0xef, 0xcb, 0x07, 0x6b, 0x0a, 0xb7, 0xa7, 0xa4,
};

test "crypto: RFC 9001 A.5 — ChaCha20 key/iv/hp from secret" {
    const testing = std.testing;
    const keys = derivePacketKeysWithSuite(a5_secret, packet.QUIC_VERSION_1, .chacha20_poly1305);
    try testing.expectEqualSlices(u8, &a5_key, &keys.key);
    try testing.expectEqualSlices(u8, &a5_iv, &keys.iv);
    try testing.expectEqualSlices(u8, &a5_hp, &keys.hp);
}

test "crypto: RFC 9001 A.5 — ChaCha20 short-header packet protection" {
    const testing = std.testing;
    const keys = PacketKeys{ .key = a5_key, .iv = a5_iv, .hp = a5_hp, .suite = .chacha20_poly1305 };

    // Short header, 3-byte PN encoding; packet number 654360564; PING frame.
    const pn: u64 = 654360564;
    const header = [_]u8{ 0x42, 0x00, 0xbf, 0xf4 }; // unprotected header (AEAD AAD)
    const plaintext = [_]u8{0x01};

    // AEAD: ciphertext+tag must match RFC A.5 exactly.
    var ct: [plaintext.len + 16]u8 = undefined;
    encryptPayload(keys, pn, &header, &plaintext, &ct);
    const expected_ct = [_]u8{
        0x65, 0x5e, 0x5c, 0xd5, 0x5c, 0x41, 0xf6, 0x90,
        0x80, 0x57, 0x5d, 0x79, 0x99, 0xc2, 0x5a, 0x5b,
        0xfb,
    };
    try testing.expectEqualSlices(u8, &expected_ct, &ct);

    // Header protection: sample starts at PN_offset+4. PN is 3 bytes, so skip 1
    // ciphertext byte. sample = ct[1..17].
    var first_byte: u8 = header[0];
    var pn_bytes = [_]u8{ header[1], header[2], header[3] };
    const sample: [16]u8 = ct[1..17].*;
    applyHeaderProtection(keys, &first_byte, &pn_bytes, &sample);
    try testing.expectEqual(@as(u8, 0x4c), first_byte);
    try testing.expectEqualSlices(u8, &[_]u8{ 0xfe, 0x41, 0x89 }, &pn_bytes);

    // Full protected packet == RFC A.5 (21 bytes).
    var pkt: [21]u8 = undefined;
    pkt[0] = first_byte;
    @memcpy(pkt[1..4], &pn_bytes);
    @memcpy(pkt[4..21], &ct);
    const expected_pkt = [_]u8{
        0x4c, 0xfe, 0x41, 0x89, 0x65, 0x5e, 0x5c, 0xd5,
        0x5c, 0x41, 0xf6, 0x90, 0x80, 0x57, 0x5d, 0x79,
        0x99, 0xc2, 0x5a, 0x5b, 0xfb,
    };
    try testing.expectEqualSlices(u8, &expected_pkt, &pkt);
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
    const short: [15]u8 = @splat(0); // one byte short of the 16-byte tag
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
    var hp32: [32]u8 = @as([32]u8, @splat(0));
    @memcpy(hp32[0..16], &[_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 });
    const keys = PacketKeys{ .key = @as([32]u8, @splat(0)), .iv = @as([12]u8, @splat(0)), .hp = hp32, .suite = .aes_128_gcm };
    // Use a non-zero sample to get a non-trivial mask
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    var first_byte: u8 = 0xC3; // long header (bit 7 = 1)
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x01 }; // 4-byte PN

    const orig_first = first_byte;
    const orig_pn = pn_bytes;

    // Apply once (protect)
    applyHeaderProtection(keys, &first_byte, &pn_bytes, &sample);
    // Apply again (remove — same XOR operation)
    applyHeaderProtection(keys, &first_byte, &pn_bytes, &sample);

    try std.testing.expectEqual(orig_first, first_byte);
    try std.testing.expectEqualSlices(u8, &orig_pn, &pn_bytes);
}

test "crypto: removeHeaderProtection handles all pn_len values (1-4)" {
    const testing = std.testing;
    var hp32: [32]u8 = @as([32]u8, @splat(0));
    const hp16 = [_]u8{ 0x9f, 0x50, 0x44, 0x9e, 0x04, 0xa0, 0xe8, 0x10, 0x28, 0x3a, 0x1e, 0x99, 0x33, 0xad, 0xed, 0xd2 };
    @memcpy(hp32[0..16], &hp16);
    const keys = PacketKeys{ .key = @as([32]u8, @splat(0)), .iv = @as([12]u8, @splat(0)), .hp = hp32, .suite = .aes_128_gcm };
    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };

    // Compute actual mask using AES
    var mask: [5]u8 = undefined;
    {
        var cipher = std.crypto.core.aes.Aes128.initEnc(hp16);
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

        const pn_len = removeHeaderProtection(keys, &first_byte, &pn_field, &sample);
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

        const pn_len = removeHeaderProtection(keys, &first_byte, &pn_field, &sample);
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

        const pn_len = removeHeaderProtection(keys, &first_byte, &pn_field, &sample);
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

        const pn_len = removeHeaderProtection(keys, &first_byte, &pn_field, &sample);
        try testing.expectEqual(@as(u8, 4), pn_len);
        try testing.expectEqual(unmasked_first, first_byte);
        try testing.expectEqual(unmasked_pn[0], pn_field[0]);
        try testing.expectEqual(unmasked_pn[1], pn_field[1]);
        try testing.expectEqual(unmasked_pn[2], pn_field[2]);
        try testing.expectEqual(unmasked_pn[3], pn_field[3]);
    }
}

test "crypto: nonce build" {
    // iv = 0xfa044b2f42a3fd3b46fb255c (RFC 9001 Appendix A client IV)
    // nonce = iv XOR (pn left-padded to 12 bytes, big-endian)
    const iv = [_]u8{
        0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5c,
    };
    const testing = std.testing;

    // RFC 9001 Appendix A: pn=2 → only last byte differs (iv[11] ^ 2 = 0x5e)
    {
        const nonce = buildNonce(iv, 2);
        const expected = [_]u8{
            0xfa, 0x04, 0x4b, 0x2f, 0x42, 0xa3, 0xfd, 0x3b, 0x46, 0xfb, 0x25, 0x5e,
        };
        try testing.expectEqualSlices(u8, &expected, &nonce);
    }

    // pn=0: XOR with zero → nonce identical to IV
    {
        const nonce = buildNonce(iv, 0);
        try testing.expectEqualSlices(u8, &iv, &nonce);
    }

    // pn=1: only nonce[11] changes (iv[11] ^ 1)
    {
        const nonce = buildNonce(iv, 1);
        try testing.expectEqualSlices(u8, iv[0..11], nonce[0..11]);
        try testing.expectEqual(@as(u8, iv[11] ^ 1), nonce[11]);
    }

    // pn=256 (0x100): nonce[10] ^= 1, nonce[11] unchanged
    {
        const nonce = buildNonce(iv, 256);
        try testing.expectEqualSlices(u8, iv[0..10], nonce[0..10]);
        try testing.expectEqual(@as(u8, iv[10] ^ 1), nonce[10]);
        try testing.expectEqual(iv[11], nonce[11]);
    }

    // pn=0xFFFFFFFF: nonce[8..12] all XOR'd with 0xFF
    {
        const nonce = buildNonce(iv, 0xFFFFFFFF);
        try testing.expectEqualSlices(u8, iv[0..8], nonce[0..8]);
        try testing.expectEqual(@as(u8, iv[8] ^ 0xFF), nonce[8]);
        try testing.expectEqual(@as(u8, iv[9] ^ 0xFF), nonce[9]);
        try testing.expectEqual(@as(u8, iv[10] ^ 0xFF), nonce[10]);
        try testing.expectEqual(@as(u8, iv[11] ^ 0xFF), nonce[11]);
    }
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
    try testing.expect(!std.mem.eql(u8, keys_v1.client.key[0..16], keys_v2.client.key[0..16]));
    try testing.expect(!std.mem.eql(u8, &keys_v1.client.iv, &keys_v2.client.iv));
    try testing.expect(!std.mem.eql(u8, keys_v1.server.key[0..16], keys_v2.server.key[0..16]));
}

test "crypto: v2 derivePacketKeys uses quicv2 labels" {
    const testing = std.testing;
    // Same secret, different version → different keys.
    const prk = HkdfSha256.extract(&initial_salt_v1, &test_dcid);
    var secret: [32]u8 = undefined;
    hkdfExpandLabel(&secret, prk, "client in", "");
    const k_v1 = derivePacketKeys(secret, packet.QUIC_VERSION_1);
    const k_v2 = derivePacketKeys(secret, packet.QUIC_VERSION_2);
    try testing.expect(!std.mem.eql(u8, k_v1.key[0..16], k_v2.key[0..16]));
    try testing.expect(!std.mem.eql(u8, &k_v1.iv, &k_v2.iv));
    try testing.expect(!std.mem.eql(u8, k_v1.hp[0..16], k_v2.hp[0..16]));
}

test "crypto: RFC 9369 — v2 client key/iv/hp derived correctly" {
    const testing = std.testing;
    // QUIC v2 initial keys must be correctly derived using v2 salt and labels.
    // Test with a specific DCID to verify the derivation produces consistent results.
    const test_dcid_v2 = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    const keys = deriveInitialKeys(&test_dcid_v2, packet.QUIC_VERSION_2);

    // Initial keys always use AES-128-GCM.
    try testing.expectEqual(CipherSuite.aes_128_gcm, keys.client.suite);
    try testing.expectEqual(32, keys.client.key.len);
    try testing.expectEqual(12, keys.client.iv.len);
    try testing.expectEqual(32, keys.client.hp.len);

    // v2 keys must differ from v1 keys for the same DCID.
    const keys_v1 = deriveInitialKeys(&test_dcid_v2, packet.QUIC_VERSION_1);
    try testing.expect(!std.mem.eql(u8, keys.client.key[0..16], keys_v1.client.key[0..16]));
    try testing.expect(!std.mem.eql(u8, &keys.client.iv, &keys_v1.client.iv));
    try testing.expect(!std.mem.eql(u8, keys.client.hp[0..16], keys_v1.client.hp[0..16]));
}

test "crypto: ChaCha20-Poly1305 encrypt-decrypt round-trip" {
    const testing = std.testing;
    const secret = @as([32]u8, @splat(0x42));
    const keys = derivePacketKeysWithSuite(secret, packet.QUIC_VERSION_1, .chacha20_poly1305);
    try testing.expectEqual(CipherSuite.chacha20_poly1305, keys.suite);

    const pn: u64 = 5;
    const header = [_]u8{ 0x40, 0x01 };
    const plaintext = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE };

    var ct: [plaintext.len + 16]u8 = undefined;
    encryptPayload(keys, pn, &header, &plaintext, &ct);

    var recovered: [plaintext.len]u8 = undefined;
    try decryptPayload(keys, pn, &header, &ct, &recovered);
    try testing.expectEqualSlices(u8, &plaintext, &recovered);
}

test "crypto: ChaCha20-Poly1305 header protection round-trip" {
    const testing = std.testing;
    const secret = @as([32]u8, @splat(0x42));
    const keys = derivePacketKeysWithSuite(secret, packet.QUIC_VERSION_1, .chacha20_poly1305);

    const sample = [_]u8{ 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
    var first_byte: u8 = 0x40; // short header
    var pn_bytes = [_]u8{ 0x00, 0x00, 0x00, 0x05 };

    const orig_first = first_byte;
    const orig_pn = pn_bytes;

    applyHeaderProtection(keys, &first_byte, &pn_bytes, &sample);
    // Must have changed
    try testing.expect(first_byte != orig_first or !std.mem.eql(u8, &pn_bytes, &orig_pn));
    // Apply again to remove (self-inverse)
    applyHeaderProtection(keys, &first_byte, &pn_bytes, &sample);
    try testing.expectEqual(orig_first, first_byte);
    try testing.expectEqualSlices(u8, &orig_pn, &pn_bytes);
}

test "crypto: ChaCha20 keys differ from AES keys for same secret" {
    const testing = std.testing;
    const secret = @as([32]u8, @splat(0x42));
    const aes_keys = derivePacketKeysWithSuite(secret, packet.QUIC_VERSION_1, .aes_128_gcm);
    const cc_keys = derivePacketKeysWithSuite(secret, packet.QUIC_VERSION_1, .chacha20_poly1305);
    // Suite must be recorded correctly.
    try testing.expectEqual(CipherSuite.aes_128_gcm, aes_keys.suite);
    try testing.expectEqual(CipherSuite.chacha20_poly1305, cc_keys.suite);
    // HKDF-Expand-Label output depends on the requested output length, so AES (16-byte key)
    // and ChaCha20 (32-byte key) produce entirely different key material.
    try testing.expect(!std.mem.eql(u8, &aes_keys.key, &cc_keys.key));
    // HP keys also differ: AES derives 16 bytes (zero-padded to 32), ChaCha20 derives 32 bytes.
    try testing.expect(!std.mem.eql(u8, &aes_keys.hp, &cc_keys.hp));
}
