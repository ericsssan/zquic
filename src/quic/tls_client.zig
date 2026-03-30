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

/// Opaque session ticket for PSK resumption across connections.
pub const SessionTicket = struct {
    identity: [256]u8,
    identity_len: u16,
    psk: [32]u8,
    age_add: u32,
    cipher: crypto.CipherSuite,
    received_ns: i64,
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

    // Our transport parameters to send in ClientHello (set by Connection).
    our_transport_params: transport_params.TransportParams = .{},

    // ALPN to offer in ClientHello.
    alpn: [32]u8 = [_]u8{0} ** 32,
    alpn_len: u8 = 0,

    // PSK / session resumption fields
    resumption_master_secret: [32]u8,
    /// Received session ticket (opaque identity for PSK extension).
    ticket_identity: [256]u8 = [_]u8{0} ** 256,
    ticket_identity_len: u16 = 0,
    /// PSK derived from resumption_master_secret + ticket_nonce.
    ticket_psk: [32]u8 = [_]u8{0} ** 32,
    /// Obfuscated ticket age (from NewSessionTicket.ticket_age_add).
    ticket_age_add: u32 = 0,
    /// Timestamp (ns) when ticket was received — used to compute ticket age.
    ticket_received_ns: i64 = 0,
    /// True when a valid session ticket is stored and can be used for PSK.
    has_ticket: bool = false,
    /// Stored ticket to offer in the next ClientHello (set externally).
    /// When set, buildClientHello includes pre_shared_key extension.
    offer_ticket: bool = false,

    // CRYPTO data accumulation buffer (matches TlsServer pattern for fragmented data).
    read_buf: [8192]u8,
    read_len: usize,
    crypto_bytes_total: u32,

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
            .resumption_master_secret = [_]u8{0} ** 32,
            .read_buf = undefined,
            .read_len = 0,
            .crypto_bytes_total = 0,
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
        const tp_len = transport_params.encode(self.our_transport_params, out[pos..]);
        pos += tp_len;
        std.mem.writeInt(u16, out[tp_len_pos..][0..2], @intCast(tp_len), .big);

        // ALPN (0x0010) — application_layer_protocol_negotiation
        if (self.alpn_len > 0) {
            const alpn_data = self.alpn[0..self.alpn_len];
            std.mem.writeInt(u16, out[pos..][0..2], 0x0010, .big);
            pos += 2;
            // ext data length: 2 (list len) + 1 (proto len) + proto
            const alpn_ext_len: u16 = @intCast(2 + 1 + alpn_data.len);
            std.mem.writeInt(u16, out[pos..][0..2], alpn_ext_len, .big);
            pos += 2;
            // protocol list length
            const alpn_list_len: u16 = @intCast(1 + alpn_data.len);
            std.mem.writeInt(u16, out[pos..][0..2], alpn_list_len, .big);
            pos += 2;
            // protocol entry: length(1) + name
            out[pos] = @intCast(alpn_data.len);
            pos += 1;
            @memcpy(out[pos..][0..alpn_data.len], alpn_data);
            pos += alpn_data.len;
        }

        // PSK extensions (must be last — RFC 8446 §4.2.11)
        var binder_pos: usize = 0; // position of the binder for later fixup
        if (self.offer_ticket and self.has_ticket) {
            // psk_key_exchange_modes (0x002d): psk_dhe_ke(1)
            std.mem.writeInt(u16, out[pos..][0..2], 0x002d, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 2, .big); // ext len
            pos += 2;
            out[pos] = 1; // modes list len
            pos += 1;
            out[pos] = 1; // psk_dhe_ke
            pos += 1;

            // early_data (0x002a): signal willingness for 0-RTT
            std.mem.writeInt(u16, out[pos..][0..2], 0x002a, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 0, .big); // empty ext
            pos += 2;

            // pre_shared_key (0x0029) — MUST be last
            std.mem.writeInt(u16, out[pos..][0..2], 0x0029, .big);
            pos += 2;
            const psk_ext_start = pos;
            pos += 2; // ext length placeholder

            // identities list: len(2) + [identity_len(2) + identity + obfuscated_age(4)]
            const id_entry_len: u16 = 2 + self.ticket_identity_len + 4;
            std.mem.writeInt(u16, out[pos..][0..2], id_entry_len, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], self.ticket_identity_len, .big);
            pos += 2;
            @memcpy(out[pos..][0..self.ticket_identity_len], self.ticket_identity[0..self.ticket_identity_len]);
            pos += self.ticket_identity_len;
            // obfuscated_ticket_age: ticket_age_ms + ticket_age_add
            std.mem.writeInt(u32, out[pos..][0..4], self.ticket_age_add, .big);
            pos += 4;

            // binders list: len(2) + [binder_len(1) + binder(32)]
            std.mem.writeInt(u16, out[pos..][0..2], 33, .big); // 1 + 32
            pos += 2;
            out[pos] = 32; // binder length
            pos += 1;
            binder_pos = pos;
            @memset(out[pos..][0..32], 0); // placeholder, computed below
            pos += 32;

            std.mem.writeInt(u16, out[psk_ext_start..][0..2], @intCast(pos - psk_ext_start - 2), .big);
        }

        // Fill extensions total length
        std.mem.writeInt(u16, out[ext_start..][0..2], @intCast(pos - ext_start - 2), .big);

        // Fill handshake header: type(1) + length(3)
        out[0] = HS_CLIENT_HELLO;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        // Compute PSK binder if offering a ticket
        if (self.offer_ticket and self.has_ticket and binder_pos > 0) {
            // early_secret = HKDF-Extract(0, PSK)
            const zero32 = [_]u8{0} ** 32;
            const early_secret = HkdfSha256.extract(&zero32, &self.ticket_psk);

            // binder_key = Derive-Secret(early_secret, "res binder", "")
            var binder_key: [32]u8 = undefined;
            crypto.hkdfExpandLabel(&binder_key, early_secret, "res binder", &tls.sha256_empty);

            // finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
            var finished_key: [32]u8 = undefined;
            crypto.hkdfExpandLabel(&finished_key, binder_key, "finished", "");

            // Transcript hash = H(truncated ClientHello) — everything before binders list
            // binder_pos - 33 points to binders_list_len; binder_pos - 32 is start of binder
            const truncated_len = binder_pos - 33; // up to (not including) binders list len
            var trunc_hash: Sha256 = Sha256.init(.{});
            trunc_hash.update(out[0..truncated_len]);
            var trunc_digest: [32]u8 = undefined;
            trunc_hash.final(&trunc_digest);

            // binder = HMAC(finished_key, truncated_transcript_hash)
            var binder: [32]u8 = undefined;
            Hmac256.create(&binder, &trunc_digest, &finished_key);
            @memcpy(out[binder_pos..][0..32], &binder);
        }

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

            // EncryptedExtensions: extract server's transport parameters.
            if (msg_type == 8) {
                self.parseEncryptedExtensions(data[pos + 4 .. msg_end]);
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

        // Add client Finished to transcript for resumption_master_secret derivation.
        self.transcript.update(out[0..36]);

        // Derive resumption_master_secret (RFC 8446 §7.1):
        // res_master = Derive-Secret(master_secret, "res master", transcript_through_CF)
        var cf_snap = self.transcript;
        var cf_hash: [32]u8 = undefined;
        cf_snap.final(&cf_hash);
        crypto.hkdfExpandLabel(&self.resumption_master_secret, self.master_secret, "res master", &cf_hash);

        return 36;
    }

    // -----------------------------------------------------------------------
    // Unified interface (matches TlsServer API)
    // -----------------------------------------------------------------------

    /// Feed incoming CRYPTO frame bytes into the state machine.
    /// Returns the number of bytes written to `out` (to be sent as CRYPTO frames).
    pub fn processCrypto(self: *TlsClient, data: []const u8, out: []u8, io: std.Io) !usize {
        _ = io;

        // Cumulative CRYPTO cap (matches TlsServer).
        const incoming: u32 = @intCast(@min(data.len, std.math.maxInt(u32)));
        const new_total = self.crypto_bytes_total +| incoming;
        if (new_total > 65536) return error.CryptoDataTooLarge;
        self.crypto_bytes_total = new_total;

        // Accumulate data
        if (self.read_len + data.len > self.read_buf.len) return error.BufferOverflow;
        @memcpy(self.read_buf[self.read_len..][0..data.len], data);
        self.read_len += data.len;

        switch (self.state) {
            .idle => {
                // Build ClientHello — input data is ignored (there is none).
                const len = self.buildClientHello(out);
                self.read_len = 0;
                return len;
            },
            .wait_server_hello => {
                // ServerHello may arrive in fragments; wait until parseable.
                self.processServerHello(self.read_buf[0..self.read_len]) catch |err| switch (err) {
                    error.TooShort => return 0, // not enough data yet
                    else => return err,
                };
                self.read_len = 0;
                return 0;
            },
            .wait_encrypted => {
                // EE + Cert + CertVerify + Finished may arrive in fragments.
                self.processHandshakeMessages(self.read_buf[0..self.read_len]) catch |err| switch (err) {
                    error.TooShort, error.NoFinished => return 0, // not enough data yet
                    else => return err,
                };
                self.read_len = 0;
                return self.buildClientFinished(out);
            },
            .established => {
                // Post-handshake messages: NewSessionTicket (type 4).
                self.processPostHandshake(self.read_buf[0..self.read_len]);
                self.read_len = 0;
                return 0;
            },
        }
    }

    pub fn isComplete(self: *const TlsClient) bool {
        return self.state == .established;
    }

    /// Zero all secret key material.
    pub fn deinit(self: *TlsClient) void {
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.handshake_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.master_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.client_hs_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.server_hs_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.client_app_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.server_app_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.ecdh_kp.secret_key)));
    }

    /// Parse post-handshake TLS messages (NewSessionTicket = type 4).
    fn processPostHandshake(self: *TlsClient, data: []const u8) void {
        var pos: usize = 0;
        while (pos + 4 <= data.len) {
            const msg_type = data[pos];
            const msg_len = readU24(data[pos + 1 ..][0..3]);
            const msg_end = pos + 4 + msg_len;
            if (msg_end > data.len) break;

            if (msg_type == 4) { // NewSessionTicket
                self.parseNewSessionTicket(data[pos + 4 .. msg_end]);
            }
            pos = msg_end;
        }
    }

    /// Parse NewSessionTicket body and store ticket for future resumption.
    fn parseNewSessionTicket(self: *TlsClient, body: []const u8) void {
        // ticket_lifetime(4) + ticket_age_add(4) + ticket_nonce_len(1) + nonce + ticket_len(2) + ticket + extensions
        if (body.len < 13) return;
        var p: usize = 0;

        // ticket_lifetime (4 bytes, seconds)
        _ = std.mem.readInt(u32, body[p..][0..4], .big);
        p += 4;

        // ticket_age_add (4 bytes)
        self.ticket_age_add = std.mem.readInt(u32, body[p..][0..4], .big);
        p += 4;

        // ticket_nonce (variable length)
        const nonce_len = body[p];
        p += 1;
        if (p + nonce_len > body.len) return;
        const nonce = body[p..][0..nonce_len];
        p += nonce_len;

        // ticket (variable length — this is the opaque identity)
        if (p + 2 > body.len) return;
        const ticket_len = @as(u16, body[p]) << 8 | body[p + 1];
        p += 2;
        if (p + ticket_len > body.len) return;
        if (ticket_len > self.ticket_identity.len) return; // too large
        @memcpy(self.ticket_identity[0..ticket_len], body[p..][0..ticket_len]);
        self.ticket_identity_len = ticket_len;
        p += ticket_len;

        // Derive PSK from resumption_master_secret + nonce (RFC 8446 §4.6.1)
        crypto.hkdfExpandLabel(&self.ticket_psk, self.resumption_master_secret, "resumption", nonce);

        self.has_ticket = true;
    }

    /// Returns the stored session ticket for use in a future connection.
    /// Caller should save this and pass it to a new TlsClient via `setTicket()`.
    pub fn getTicket(self: *const TlsClient) ?SessionTicket {
        if (!self.has_ticket) return null;
        return .{
            .identity = self.ticket_identity,
            .identity_len = self.ticket_identity_len,
            .psk = self.ticket_psk,
            .age_add = self.ticket_age_add,
            .cipher = self.negotiated_cipher,
            .received_ns = self.ticket_received_ns,
        };
    }

    /// Set a previously received session ticket for PSK resumption.
    pub fn setTicket(self: *TlsClient, ticket: SessionTicket) void {
        self.ticket_identity = ticket.identity;
        self.ticket_identity_len = ticket.identity_len;
        self.ticket_psk = ticket.psk;
        self.ticket_age_add = ticket.age_add;
        self.negotiated_cipher = ticket.cipher;
        self.has_ticket = true;
        self.offer_ticket = true;
    }

    pub fn peerTransportParams(self: *const TlsClient) transport_params.TransportParams {
        return self.peer_transport_params;
    }

    /// Parse EncryptedExtensions body to extract QUIC transport params and
    /// perform compatible version negotiation (RFC 9369).
    fn parseEncryptedExtensions(self: *TlsClient, body: []const u8) void {
        if (body.len < 2) return;
        const ext_list_len = @as(u16, body[0]) << 8 | body[1];
        var epos: usize = 2;
        const ext_end = @min(2 + @as(usize, ext_list_len), body.len);
        while (epos + 4 <= ext_end) {
            const ext_type = @as(u16, body[epos]) << 8 | body[epos + 1];
            const ext_len = @as(u16, body[epos + 2]) << 8 | body[epos + 3];
            epos += 4;
            if (epos + ext_len > ext_end) break;
            if (ext_type == EXT_QUIC_TRANSPORT_PARAMS) {
                self.peer_transport_params = transport_params.decode(body[epos..][0..ext_len]) catch .{};
                self.negotiateVersion();
            }
            epos += ext_len;
        }
    }

    /// Compatible version negotiation (RFC 9369): if we sent version_information
    /// and the server's version_information contains our preferred version,
    /// upgrade quic_version so app keys use the negotiated version.
    fn negotiateVersion(self: *TlsClient) void {
        const our_vi = self.our_transport_params.version_information orelse return;
        const server_vi = self.peer_transport_params.version_information orelse return;
        const server_vi_len = self.peer_transport_params.version_information_len;
        // Our preferred version is the first entry in our version_information.
        const our_preferred = std.mem.readInt(u32, our_vi[0..4], .big);
        if (our_preferred == self.quic_version) return; // already using preferred
        // Check if server supports our preferred version.
        if (server_vi_len >= 4 and server_vi_len % 4 == 0) {
            var i: u8 = 0;
            while (i < server_vi_len) : (i += 4) {
                const ver = std.mem.readInt(u32, server_vi[i..][0..4], .big);
                if (ver == our_preferred) {
                    self.quic_version = our_preferred;
                    return;
                }
            }
        }
    }
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
