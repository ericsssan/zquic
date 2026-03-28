//! Client-side TLS 1.3 state machine for QUIC test framework.
//!
//! Mirrors TlsServer in tls.zig — same key schedule, same message format —
//! but drives the client side: produces ClientHello, processes ServerHello +
//! EncryptedExtensions + Certificate + CertificateVerify + Finished, builds
//! client Finished.
//!
//! Does NOT verify server certificate (no CA store).
//! DOES verify server Finished (key correctness guarantee).

const std = @import("std");
const crypto = @import("crypto.zig");
const packet_mod = @import("packet.zig");
const transport_params = @import("transport_params.zig");
const tls = @import("tls.zig");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

// TLS constants (matching tls.zig)
const TLS_VERSION_LEGACY: u16 = 0x0303;
const TLS_VERSION_1_3: u16 = 0x0304;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_FINISHED: u8 = 20;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 0x0039;
const GROUP_X25519: u16 = 0x001d;
const CIPHER_AES_128_GCM: u16 = @intFromEnum(crypto.CipherSuite.aes_128_gcm);

pub const TlsClientState = enum(u8) {
    idle,
    wait_server_hello,
    wait_encrypted,
    established,
};

pub const TlsClient = struct {
    state: TlsClientState,
    ecdh_kp: X25519.KeyPair,
    client_random: [32]u8,
    legacy_session_id: [32]u8,
    session_id_len: u8,
    transcript: Sha256,

    // Key schedule
    handshake_secret: [32]u8,
    master_secret: [32]u8,
    client_hs_secret: [32]u8,
    server_hs_secret: [32]u8,
    client_app_secret: [32]u8,
    server_app_secret: [32]u8,

    // Derived QUIC packet keys
    handshake_keys: tls.HandshakeKeys,
    app_keys: tls.AppKeys,

    negotiated_cipher: crypto.CipherSuite,
    quic_version: u32,
    peer_transport_params: transport_params.TransportParams,

    pub fn init(io: std.Io) TlsClient {
        const ecdh_kp = X25519.KeyPair.generate(io);
        var random: [32]u8 = undefined;
        io.random(&random);
        var session_id: [32]u8 = undefined;
        io.random(&session_id);

        return .{
            .state = .idle,
            .ecdh_kp = ecdh_kp,
            .client_random = random,
            .legacy_session_id = session_id,
            .session_id_len = 32,
            .transcript = Sha256.init(.{}),
            .handshake_secret = [_]u8{0} ** 32,
            .master_secret = [_]u8{0} ** 32,
            .client_hs_secret = [_]u8{0} ** 32,
            .server_hs_secret = [_]u8{0} ** 32,
            .client_app_secret = [_]u8{0} ** 32,
            .server_app_secret = [_]u8{0} ** 32,
            .handshake_keys = undefined,
            .app_keys = undefined,
            .negotiated_cipher = .aes_128_gcm,
            .quic_version = packet_mod.QUIC_VERSION_1,
            .peer_transport_params = .{},
        };
    }

    // -----------------------------------------------------------------------
    // ClientHello
    // -----------------------------------------------------------------------

    /// Build a TLS ClientHello handshake message. Returns bytes written.
    /// The message includes X25519 key share, AES-128-GCM cipher suite, and
    /// QUIC transport parameters.
    pub fn buildClientHello(self: *TlsClient, out: []u8) usize {
        var pos: usize = 4; // skip handshake header, fill later

        // legacy_version (0x0303)
        std.mem.writeInt(u16, out[pos..][0..2], TLS_VERSION_LEGACY, .big);
        pos += 2;

        // client_random (32 bytes)
        @memcpy(out[pos..][0..32], &self.client_random);
        pos += 32;

        // legacy_session_id
        out[pos] = self.session_id_len;
        pos += 1;
        @memcpy(out[pos..][0..self.session_id_len], self.legacy_session_id[0..self.session_id_len]);
        pos += self.session_id_len;

        // cipher_suites: AES-128-GCM only
        std.mem.writeInt(u16, out[pos..][0..2], 2, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], CIPHER_AES_128_GCM, .big);
        pos += 2;

        // compression_methods: null only
        out[pos] = 1;
        pos += 1;
        out[pos] = 0x00;
        pos += 1;

        // Extensions
        const ext_start = pos;
        pos += 2; // placeholder for total extensions length

        // supported_versions (0x002b): TLS 1.3
        std.mem.writeInt(u16, out[pos..][0..2], EXT_SUPPORTED_VERSIONS, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 3, .big); // ext data = 3 bytes
        pos += 2;
        out[pos] = 2; // list length = 2 bytes (one version)
        pos += 1;
        std.mem.writeInt(u16, out[pos..][0..2], TLS_VERSION_1_3, .big);
        pos += 2;

        // key_share (0x0033): X25519 public key
        std.mem.writeInt(u16, out[pos..][0..2], EXT_KEY_SHARE, .big);
        pos += 2;
        // ext data: ks_list_len(2) + group(2) + key_len(2) + key(32) = 38
        std.mem.writeInt(u16, out[pos..][0..2], 38, .big);
        pos += 2;
        // client_shares list: group(2) + key_len(2) + key(32) = 36
        std.mem.writeInt(u16, out[pos..][0..2], 36, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], GROUP_X25519, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 32, .big);
        pos += 2;
        @memcpy(out[pos..][0..32], &self.ecdh_kp.public_key);
        pos += 32;

        // quic_transport_parameters (0x0039)
        std.mem.writeInt(u16, out[pos..][0..2], EXT_QUIC_TRANSPORT_PARAMS, .big);
        pos += 2;
        const tp_len_pos = pos;
        pos += 2; // ext data length placeholder
        const tp_len = transport_params.encode(.{}, out[pos..]);
        pos += tp_len;
        std.mem.writeInt(u16, out[tp_len_pos..][0..2], @intCast(tp_len), .big);

        // Fill extensions total length
        std.mem.writeInt(u16, out[ext_start..][0..2], @intCast(pos - ext_start - 2), .big);

        // Fill handshake header: type(1) + length(3)
        out[0] = HS_CLIENT_HELLO;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        // Hash into transcript
        self.transcript.update(out[0..pos]);
        self.state = .wait_server_hello;

        return pos;
    }

    // -----------------------------------------------------------------------
    // ServerHello processing
    // -----------------------------------------------------------------------

    /// Process ServerHello from Initial-epoch CRYPTO data.
    /// Computes ECDH shared secret, runs key schedule, derives handshake keys.
    pub fn processServerHello(self: *TlsClient, data: []const u8) !void {
        if (self.state != .wait_server_hello) return error.UnexpectedState;
        if (data.len < 4) return error.TooShort;
        if (data[0] != HS_SERVER_HELLO) return error.NotServerHello;

        const msg_len = readU24(data[1..4]);
        if (data.len < 4 + msg_len) return error.TooShort;
        const sh_end = 4 + msg_len;

        // Parse ServerHello fields
        var pos: usize = 4;
        pos += 2; // legacy_version
        pos += 32; // server_random
        if (pos >= sh_end) return error.TooShort;
        const sid_len: usize = data[pos];
        pos += 1 + sid_len; // session_id echo

        if (pos + 3 > sh_end) return error.TooShort;
        const cs = std.mem.readInt(u16, data[pos..][0..2], .big);
        if (cs == @intFromEnum(crypto.CipherSuite.aes_128_gcm)) {
            self.negotiated_cipher = .aes_128_gcm;
        } else if (cs == @intFromEnum(crypto.CipherSuite.chacha20_poly1305)) {
            self.negotiated_cipher = .chacha20_poly1305;
        } else {
            return error.UnsupportedCipher;
        }
        pos += 2;
        pos += 1; // compression

        // Parse extensions
        if (pos + 2 > sh_end) return error.TooShort;
        const ext_total = std.mem.readInt(u16, data[pos..][0..2], .big);
        pos += 2;
        const ext_end = @min(pos + ext_total, sh_end);

        var server_pub: [32]u8 = undefined;
        var has_key_share = false;

        while (pos + 4 <= ext_end) {
            const ext_type = std.mem.readInt(u16, data[pos..][0..2], .big);
            const ext_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
            pos += 4;
            if (pos + ext_len > ext_end) break;

            if (ext_type == EXT_KEY_SHARE and ext_len >= 36) {
                const group = std.mem.readInt(u16, data[pos..][0..2], .big);
                const key_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
                if (group == GROUP_X25519 and key_len == 32) {
                    @memcpy(&server_pub, data[pos + 4 ..][0..32]);
                    has_key_share = true;
                }
            }
            pos += ext_len;
        }

        if (!has_key_share) return error.NoKeyShare;

        // ECDH shared secret
        const shared = try X25519.scalarmult(self.ecdh_kp.secret_key, server_pub);

        // Hash ServerHello into transcript (transcript = H(CH || SH))
        self.transcript.update(data[0..sh_end]);

        // Run TLS 1.3 key schedule (RFC 8446 §7.1)
        try self.runKeySchedule(shared);

        self.state = .wait_encrypted;
    }

    fn runKeySchedule(self: *TlsClient, shared_secret: [32]u8) !void {
        const zero32 = [_]u8{0} ** 32;

        // Early Secret (no PSK)
        const early_secret = HkdfSha256.extract(&zero32, &zero32);

        // Handshake Secret
        var derived: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&derived, early_secret, "derived", &tls.sha256_empty);
        self.handshake_secret = HkdfSha256.extract(&derived, &shared_secret);

        // Transcript hash = H(CH || SH)
        var transcript_copy = self.transcript;
        var th_hello: [32]u8 = undefined;
        transcript_copy.final(&th_hello);

        // Handshake traffic secrets
        crypto.hkdfExpandLabel(&self.client_hs_secret, self.handshake_secret, "c hs traffic", &th_hello);
        crypto.hkdfExpandLabel(&self.server_hs_secret, self.handshake_secret, "s hs traffic", &th_hello);

        // Derive QUIC handshake packet keys
        self.handshake_keys = .{
            .client = crypto.derivePacketKeysWithSuite(self.client_hs_secret, self.quic_version, self.negotiated_cipher),
            .server = crypto.derivePacketKeysWithSuite(self.server_hs_secret, self.quic_version, self.negotiated_cipher),
        };

        // Master Secret
        var derived2: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&derived2, self.handshake_secret, "derived", &tls.sha256_empty);
        self.master_secret = HkdfSha256.extract(&derived2, &zero32);
    }

    // -----------------------------------------------------------------------
    // Handshake messages: EE + Cert + CertVerify + Finished
    // -----------------------------------------------------------------------

    /// Process Handshake-epoch CRYPTO data: EncryptedExtensions + Certificate +
    /// CertificateVerify + Finished.  Skips cert verification; verifies Finished.
    /// After this call, app_keys are available.
    pub fn processHandshakeMessages(self: *TlsClient, data: []const u8) !void {
        if (self.state != .wait_encrypted) return error.UnexpectedState;

        var pos: usize = 0;

        while (pos < data.len) {
            if (pos + 4 > data.len) return error.TooShort;
            const msg_type = data[pos];
            const msg_len = readU24(data[pos + 1 ..][0..3]);
            const msg_end = pos + 4 + msg_len;
            if (msg_end > data.len) return error.TooShort;

            if (msg_type == HS_FINISHED) {
                if (msg_len != 32) return error.BadFinished;

                // Transcript hash before Finished = H(CH || SH || EE || Cert || CV)
                var snap = self.transcript;
                var transcript_hash: [32]u8 = undefined;
                snap.final(&transcript_hash);

                // Verify server Finished
                var finished_key: [32]u8 = undefined;
                crypto.hkdfExpandLabel(&finished_key, self.server_hs_secret, "finished", "");
                var expected: [32]u8 = undefined;
                Hmac256.create(&expected, &transcript_hash, &finished_key);

                if (!std.crypto.timing_safe.eql([32]u8, expected, data[pos + 4 ..][0..32].*)) {
                    return error.BadFinished;
                }

                // Add ServerFinished to transcript
                self.transcript.update(data[pos..msg_end]);

                // Derive application keys using H(CH || SH || ... || SF)
                self.deriveAppKeys();
                self.state = .established;
                return;
            }

            // Non-Finished message: add to transcript and skip
            self.transcript.update(data[pos..msg_end]);
            pos = msg_end;
        }

        return error.NoFinished;
    }

    fn deriveAppKeys(self: *TlsClient) void {
        var snap = self.transcript;
        var app_hash: [32]u8 = undefined;
        snap.final(&app_hash);

        crypto.hkdfExpandLabel(&self.client_app_secret, self.master_secret, "c ap traffic", &app_hash);
        crypto.hkdfExpandLabel(&self.server_app_secret, self.master_secret, "s ap traffic", &app_hash);

        self.app_keys = .{
            .client = crypto.derivePacketKeysWithSuite(self.client_app_secret, self.quic_version, self.negotiated_cipher),
            .server = crypto.derivePacketKeysWithSuite(self.server_app_secret, self.quic_version, self.negotiated_cipher),
        };
    }

    // -----------------------------------------------------------------------
    // Client Finished
    // -----------------------------------------------------------------------

    /// Build the client Finished TLS message. Returns bytes written (always 36).
    pub fn buildClientFinished(self: *TlsClient, out: []u8) usize {
        var finished_key: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&finished_key, self.client_hs_secret, "finished", "");

        // verify_data = HMAC(finished_key, H(CH || SH || ... || SF))
        var snap = self.transcript;
        var transcript_hash: [32]u8 = undefined;
        snap.final(&transcript_hash);

        var verify_data: [32]u8 = undefined;
        Hmac256.create(&verify_data, &transcript_hash, &finished_key);

        // Finished message: type(1) + length(3) + verify_data(32)
        out[0] = HS_FINISHED;
        out[1] = 0;
        out[2] = 0;
        out[3] = 32;
        @memcpy(out[4..][0..32], &verify_data);

        return 36;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "tls_client: buildClientHello round-trips through parseClientHello" {
    const testing = std.testing;
    const io = std.testing.io;

    var client = TlsClient.init(io);
    var buf: [1024]u8 = undefined;
    const ch_len = client.buildClientHello(&buf);

    // Server's parseClientHello should successfully parse our ClientHello
    const ch = try tls.parseClientHello(buf[0..ch_len]);
    try testing.expect(ch.has_x25519);
    try testing.expect(ch.has_aes_128_gcm);
    try testing.expect(std.mem.eql(u8, &ch.client_x25519_pub, &client.ecdh_kp.public_key));
}

test "tls_client: full key schedule matches server" {
    const testing = std.testing;
    const io = std.testing.io;

    // Build a client and a server, run the handshake through TLS only (no packets).
    var client = TlsClient.init(io);

    var ch_buf: [1024]u8 = undefined;
    const ch_len = client.buildClientHello(&ch_buf);

    // Server processes ClientHello
    var server = try tls.TlsServer.init(io);
    var server_out: [8192]u8 = undefined;
    const server_out_len = try server.processCrypto(ch_buf[0..ch_len], &server_out, io);

    // Server output: ServerHello + EE + Cert + CertVerify + Finished
    // Split at ServerHello boundary (type 0x02, length in bytes 1-3)
    const sh_len = 4 + readU24(server_out[1..4]);

    // Client processes ServerHello
    try client.processServerHello(server_out[0..sh_len]);

    // Verify handshake keys match
    try testing.expectEqualSlices(u8, &server.handshake_keys.client.key, &client.handshake_keys.client.key);
    try testing.expectEqualSlices(u8, &server.handshake_keys.server.key, &client.handshake_keys.server.key);

    // Client processes EE + Cert + CertVerify + Finished
    try client.processHandshakeMessages(server_out[sh_len..server_out_len]);

    try testing.expect(client.state == .established);

    // Verify app keys match (server derives after verifying client Finished)
    // Build and feed client Finished to server
    var fin_buf: [36]u8 = undefined;
    _ = client.buildClientFinished(&fin_buf);
    _ = try server.processCrypto(&fin_buf, &server_out, io);

    try testing.expect(server.state == .established);
    try testing.expectEqualSlices(u8, &server.app_keys.client.key, &client.app_keys.client.key);
    try testing.expectEqualSlices(u8, &server.app_keys.server.key, &client.app_keys.server.key);
}

fn readU24(data: *const [3]u8) usize {
    return (@as(usize, data[0]) << 16) | (@as(usize, data[1]) << 8) | data[2];
}
