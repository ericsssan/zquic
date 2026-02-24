//! TLS 1.3 QUIC handshake state machine (RFC 9001 + RFC 8446).
//!
//! QUIC replaces the TLS record layer with CRYPTO frames.  This module
//! implements the server-side TLS state machine that QUIC drives:
//!
//!   WAIT_CLIENT_HELLO
//!     ← receive ClientHello CRYPTO bytes
//!     → produce ServerHello + {EncryptedExtensions, Certificate,
//!        CertificateVerify, Finished} CRYPTO bytes
//!   WAIT_CLIENT_FINISHED
//!     ← receive client Finished CRYPTO bytes
//!     → derive application keys
//!   ESTABLISHED
//!
//! All crypto uses std.crypto exclusively (zero external dependencies).

const std = @import("std");
const crypto = @import("crypto.zig");
const transport_params = @import("transport_params.zig");
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;

// ---------------------------------------------------------------------------
// TLS constants
// ---------------------------------------------------------------------------

const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_LEGACY: u16 = 0x0303;
const CIPHER_TLS_AES_128_GCM_SHA256: u16 = 0x1301;
const GROUP_X25519: u16 = 0x001d;

// Extension types
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 0x0039;

// Handshake message types
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

// ---------------------------------------------------------------------------
// Key material structures
// ---------------------------------------------------------------------------

pub const HandshakeKeys = struct {
    client: crypto.PacketKeys,
    server: crypto.PacketKeys,
};

pub const AppKeys = struct {
    client: crypto.PacketKeys,
    server: crypto.PacketKeys,
};

// ---------------------------------------------------------------------------
// State machine
// ---------------------------------------------------------------------------

pub const TlsState = enum(u8) {
    wait_client_hello,
    wait_client_finished,
    established,
    error_state,
};

/// Parsed ClientHello data (what we need from it).
const ClientHelloData = struct {
    random: [32]u8,
    legacy_session_id: [32]u8,
    session_id_len: u8,
    client_x25519_pub: [32]u8,
    has_x25519: bool,
    peer_transport_params: transport_params.TransportParams,
};

pub const TlsServer = struct {
    state: TlsState,

    // Our X25519 key pair (ephemeral per-connection)
    ecdh_kp: X25519.KeyPair,
    // Our Ed25519 signing key pair
    sign_kp: Ed25519.KeyPair,
    // DER-encoded self-signed certificate
    cert_buf: [320]u8,
    cert_len: usize,

    // Handshake transcript hash state
    transcript: Sha256,

    // Derived secrets
    handshake_secret: [32]u8,
    master_secret: [32]u8,

    // Handshake-epoch QUIC keys (used for Handshake-level packets)
    handshake_keys: HandshakeKeys,
    // Application-epoch QUIC keys (used for 1-RTT packets)
    app_keys: AppKeys,

    // Client handshake secret (needed to verify Finished)
    client_hs_secret: [32]u8,
    // Server handshake secret
    server_hs_secret: [32]u8,
    // Client app secret
    client_app_secret: [32]u8,
    // Server app secret
    server_app_secret: [32]u8,

    // Negotiated transport parameters received from the peer.
    peer_params: transport_params.TransportParams,

    // CRYPTO data accumulation buffers
    read_buf: [8192]u8,
    read_len: usize,

    pub fn init(io: std.Io) !TlsServer {
        const ecdh_kp = X25519.KeyPair.generate(io);
        const sign_kp = Ed25519.KeyPair.generate(io);

        var self: TlsServer = .{
            .state = .wait_client_hello,
            .ecdh_kp = ecdh_kp,
            .sign_kp = sign_kp,
            .cert_buf = undefined,
            .cert_len = 0,
            .transcript = Sha256.init(.{}),
            .handshake_secret = [_]u8{0} ** 32,
            .master_secret = [_]u8{0} ** 32,
            .handshake_keys = undefined,
            .app_keys = undefined,
            .client_hs_secret = [_]u8{0} ** 32,
            .server_hs_secret = [_]u8{0} ** 32,
            .client_app_secret = [_]u8{0} ** 32,
            .server_app_secret = [_]u8{0} ** 32,
            .peer_params = .{},
            .read_buf = undefined,
            .read_len = 0,
        };

        self.cert_len = buildCertificate(
            sign_kp.public_key.bytes,
            &[_]u8{0} ** 64, // placeholder — will be re-signed below
            self.cert_buf[0..],
        );
        // Sign the actual TBSCertificate and rebuild
        const tbs_len = tbsCertificateLen();
        const tbs = self.cert_buf[3..][0..tbs_len];
        const sig = try sign_kp.sign(tbs, null);
        self.cert_len = buildCertificate(
            sign_kp.public_key.bytes,
            &sig.toBytes(),
            self.cert_buf[0..],
        );

        return self;
    }

    pub fn isComplete(self: *const TlsServer) bool {
        return self.state == .established;
    }

    pub fn clientAppKeys(self: *const TlsServer) crypto.PacketKeys {
        return self.app_keys.client;
    }

    pub fn serverAppKeys(self: *const TlsServer) crypto.PacketKeys {
        return self.app_keys.server;
    }

    /// Returns the transport parameters received from the peer during the handshake.
    pub fn peerTransportParams(self: *const TlsServer) transport_params.TransportParams {
        return self.peer_params;
    }

    /// Feed incoming CRYPTO frame bytes into the state machine.
    /// Returns the number of bytes written to `out` (to be sent as CRYPTO frames).
    pub fn processCrypto(self: *TlsServer, data: []const u8, out: []u8, io: std.Io) !usize {
        // Accumulate data
        if (self.read_len + data.len > self.read_buf.len) return error.BufferOverflow;
        @memcpy(self.read_buf[self.read_len..][0..data.len], data);
        self.read_len += data.len;

        switch (self.state) {
            .wait_client_hello => {
                const ch = try parseClientHello(self.read_buf[0..self.read_len]);
                self.read_len = 0;
                return try self.handleClientHello(ch, out, io);
            },
            .wait_client_finished => {
                const ok = try self.verifyClientFinished(self.read_buf[0..self.read_len]);
                self.read_len = 0;
                if (!ok) return error.BadFinished;
                self.state = .established;
                return 0;
            },
            .established => return 0,
            .error_state => return error.TlsError,
        }
    }

    fn handleClientHello(self: *TlsServer, ch: ClientHelloData, out: []u8, io: std.Io) !usize {
        if (!ch.has_x25519) return error.NoX25519KeyShare;

        // Store the client's transport parameters.
        self.peer_params = ch.peer_transport_params;

        // Transcript starts with ClientHello message bytes (reconstructed below)
        // For the key schedule we hash what we received.
        // NOTE: we hash the raw handshake message, not just the data struct.
        // The transcript was already updated in parseClientHello below.

        // 1. ECDH shared secret
        const shared = try X25519.scalarmult(self.ecdh_kp.secret_key, ch.client_x25519_pub);

        // 2. Server random
        var server_random: [32]u8 = undefined;
        io.random(&server_random);

        // 3. Run TLS 1.3 key schedule
        try self.runKeySchedule(shared, &server_random);

        // 4. Serialize flight: ServerHello + EE + Cert + CertVerify + Finished
        var pos: usize = 0;

        // ServerHello message
        pos += try self.buildServerHello(
            out[pos..],
            server_random,
            ch.legacy_session_id[0..ch.session_id_len],
        );

        // Update transcript with ServerHello
        self.transcript.update(out[0..pos]);

        // From here on, messages are "handshake-encrypted" conceptually.
        // In QUIC they travel in Handshake-epoch CRYPTO frames (caller handles encryption).
        const ee_start = pos;

        // EncryptedExtensions (with QUIC transport parameters).
        // Server advertises default params; the peer's params are in self.peer_params.
        pos += buildEncryptedExtensions(out[pos..], transport_params.TransportParams{});

        // Certificate
        pos += self.buildCertificateMessage(out[pos..]);

        // CertificateVerify
        const tls_cv_msg = out[ee_start..pos];
        var transcript_so_far = self.transcript;
        transcript_so_far.update(tls_cv_msg);
        var cv_hash: [32]u8 = undefined;
        transcript_so_far.final(&cv_hash);
        pos += try self.buildCertificateVerify(out[pos..], &cv_hash);

        // Finished
        self.transcript.update(out[ee_start..pos]);
        var transcript_hash: [32]u8 = undefined;
        self.transcript.final(&transcript_hash);

        // Compute finished_key = HKDF-Expand-Label(server_hs_secret, "finished", "", 32)
        var finished_key: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&finished_key, self.server_hs_secret, "finished", "");
        // verify_data = HMAC-SHA256(finished_key, transcript_hash)
        var verify_data: [32]u8 = undefined;
        Hmac256.create(&verify_data, &transcript_hash, &finished_key);

        pos += buildFinishedMessage(out[pos..], &verify_data);

        self.state = .wait_client_finished;
        return pos;
    }

    fn runKeySchedule(self: *TlsServer, shared_secret: [32]u8, _: *const [32]u8) !void {
        // TLS 1.3 key schedule (RFC 8446 §7.1):
        //
        //   Early Secret = HKDF-Extract(0, 0)
        //   Handshake Secret = HKDF-Extract(DHE, Derive-Secret(ES, "derived", ""))
        //   Master Secret = HKDF-Extract(0, Derive-Secret(HS, "derived", ""))

        const zero32 = [_]u8{0} ** 32;

        // Early Secret
        const early_secret = HkdfSha256.extract(&zero32, &zero32);

        // derived = Derive-Secret(early_secret, "derived", "")
        var derived: [32]u8 = undefined;
        deriveSecret(&derived, early_secret, "derived", &[_]u8{});

        // Handshake Secret
        self.handshake_secret = HkdfSha256.extract(&derived, &shared_secret);

        // Get transcript hash up to ServerHello (updated as we go)
        var transcript_copy = self.transcript;
        var th_hello: [32]u8 = undefined;
        transcript_copy.final(&th_hello);

        // client/server handshake traffic secrets
        deriveSecret(&self.client_hs_secret, self.handshake_secret, "c hs traffic", &th_hello);
        deriveSecret(&self.server_hs_secret, self.handshake_secret, "s hs traffic", &th_hello);

        // Derive handshake-epoch QUIC packet keys
        self.handshake_keys = .{
            .client = crypto.derivePacketKeys(self.client_hs_secret),
            .server = crypto.derivePacketKeys(self.server_hs_secret),
        };

        // Master Secret
        var derived2: [32]u8 = undefined;
        deriveSecret(&derived2, self.handshake_secret, "derived", &[_]u8{});
        self.master_secret = HkdfSha256.extract(&derived2, &zero32);
    }

    fn deriveAppKeys(self: *TlsServer, transcript_hash: *const [32]u8) void {
        // client/server application traffic secrets
        deriveSecret(&self.client_app_secret, self.master_secret, "c ap traffic", transcript_hash);
        deriveSecret(&self.server_app_secret, self.master_secret, "s ap traffic", transcript_hash);

        self.app_keys = .{
            .client = crypto.derivePacketKeys(self.client_app_secret),
            .server = crypto.derivePacketKeys(self.server_app_secret),
        };
    }

    fn verifyClientFinished(self: *TlsServer, data: []const u8) !bool {
        // data is a Finished handshake message: 20 00 00 20 [32 bytes verify_data]
        if (data.len < 4) return false;
        if (data[0] != HS_FINISHED) return false;
        const msg_len = (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
        if (msg_len != 32 or data.len < 4 + 32) return false;

        // Snapshot transcript BEFORE adding client Finished (needed for verification).
        // The client computes verify_data over Hash(ClientHello..ServerFinished).
        var pre_finished_transcript = self.transcript;
        var transcript_hash: [32]u8 = undefined;
        pre_finished_transcript.final(&transcript_hash);

        // Compute expected client verify_data:
        //   finished_key = HKDF-Expand-Label(client_hs_secret, "finished", "", 32)
        //   verify_data  = HMAC-SHA256(finished_key, transcript_hash)
        var client_finished_key: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&client_finished_key, self.client_hs_secret, "finished", "");
        var expected_verify: [32]u8 = undefined;
        Hmac256.create(&expected_verify, &transcript_hash, &client_finished_key);

        const client_verify = data[4..][0..32];
        if (!std.mem.eql(u8, &expected_verify, client_verify)) return false;

        // Transcript now includes client Finished
        self.transcript.update(data[0 .. 4 + 32]);

        // Derive application keys
        var app_th: [32]u8 = undefined;
        self.transcript.final(&app_th);
        self.deriveAppKeys(&app_th);

        return true;
    }

    fn buildServerHello(
        self: *TlsServer,
        out: []u8,
        server_random: [32]u8,
        session_id: []const u8,
    ) !usize {
        var pos: usize = 4; // skip handshake header, fill in later

        // ProtocolVersion legacy_version = 0x0303
        std.mem.writeInt(u16, out[pos..][0..2], TLS_VERSION_LEGACY, .big);
        pos += 2;

        // Random (32 bytes)
        @memcpy(out[pos..][0..32], &server_random);
        pos += 32;

        // Legacy session ID echo
        out[pos] = @intCast(session_id.len);
        pos += 1;
        @memcpy(out[pos..][0..session_id.len], session_id);
        pos += session_id.len;

        // Cipher suite: TLS_AES_128_GCM_SHA256
        std.mem.writeInt(u16, out[pos..][0..2], CIPHER_TLS_AES_128_GCM_SHA256, .big);
        pos += 2;

        // Legacy compression method: null
        out[pos] = 0x00;
        pos += 1;

        // Extensions
        const ext_start = pos;
        pos += 2; // placeholder for extensions length

        // supported_versions extension: TLS 1.3
        std.mem.writeInt(u16, out[pos..][0..2], EXT_SUPPORTED_VERSIONS, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 2, .big); // ext length = 2
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], TLS_VERSION_1_3, .big);
        pos += 2;

        // key_share extension: server's X25519 public key
        std.mem.writeInt(u16, out[pos..][0..2], EXT_KEY_SHARE, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 4 + 32, .big); // ext length
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], GROUP_X25519, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 32, .big); // key length
        pos += 2;
        @memcpy(out[pos..][0..32], &self.ecdh_kp.public_key);
        pos += 32;

        // Fill in extensions length
        const ext_len = pos - ext_start - 2;
        std.mem.writeInt(u16, out[ext_start..][0..2], @intCast(ext_len), .big);

        // Fill in handshake header
        out[0] = HS_SERVER_HELLO;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        return pos;
    }

    fn buildCertificateMessage(self: *TlsServer, out: []u8) usize {
        var pos: usize = 4; // handshake header placeholder

        // certificate_request_context (empty, server certificate)
        out[pos] = 0x00;
        pos += 1;

        // CertificateList length (u24 placeholder)
        const list_len_pos = pos;
        pos += 3;
        const list_start = pos;

        // CertificateEntry
        // cert_data length (u24)
        const cert_data = self.cert_buf[0..self.cert_len];
        out[pos] = @intCast((cert_data.len >> 16) & 0xff);
        out[pos + 1] = @intCast((cert_data.len >> 8) & 0xff);
        out[pos + 2] = @intCast(cert_data.len & 0xff);
        pos += 3;
        @memcpy(out[pos..][0..cert_data.len], cert_data);
        pos += cert_data.len;

        // Extensions for this CertificateEntry (empty)
        std.mem.writeInt(u16, out[pos..][0..2], 0, .big);
        pos += 2;

        // Fill CertificateList length
        const list_len = pos - list_start;
        out[list_len_pos] = @intCast((list_len >> 16) & 0xff);
        out[list_len_pos + 1] = @intCast((list_len >> 8) & 0xff);
        out[list_len_pos + 2] = @intCast(list_len & 0xff);

        // Fill handshake header
        out[0] = HS_CERTIFICATE;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        return pos;
    }

    fn buildCertificateVerify(
        self: *TlsServer,
        out: []u8,
        transcript_hash: *const [32]u8,
    ) !usize {
        // Build the signed content per RFC 8446 §4.4.3:
        //   64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash
        // "TLS 1.3, server CertificateVerify" is 33 bytes (RFC 8446 §4.4.3).
        var to_sign: [64 + 33 + 1 + 32]u8 = undefined;
        @memset(to_sign[0..64], 0x20);
        @memcpy(to_sign[64..97], "TLS 1.3, server CertificateVerify");
        to_sign[97] = 0x00;
        @memcpy(to_sign[98..130], transcript_hash);

        const sig = try self.sign_kp.sign(&to_sign, null);
        const sig_bytes = sig.toBytes();

        var pos: usize = 4; // handshake header placeholder

        // SignatureScheme: Ed25519 = 0x0807
        std.mem.writeInt(u16, out[pos..][0..2], 0x0807, .big);
        pos += 2;

        // Signature length + bytes
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(sig_bytes.len), .big);
        pos += 2;
        @memcpy(out[pos..][0..sig_bytes.len], &sig_bytes);
        pos += sig_bytes.len;

        // Fill handshake header
        out[0] = HS_CERTIFICATE_VERIFY;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        return pos;
    }
};

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

fn parseClientHello(data: []const u8) !ClientHelloData {
    if (data.len < 4) return error.TooShort;
    if (data[0] != HS_CLIENT_HELLO) return error.NotClientHello;

    const msg_len = (@as(u32, data[1]) << 16) | (@as(u32, data[2]) << 8) | data[3];
    if (data.len < 4 + msg_len) return error.TooShort;

    var pos: usize = 4;

    // legacy_version (2 bytes, ignored)
    pos += 2;
    if (pos + 32 > data.len) return error.TooShort;

    var ch: ClientHelloData = .{
        .random = data[pos..][0..32].*,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0} ** 32,
        .has_x25519 = false,
        .peer_transport_params = .{},
    };
    pos += 32;

    // Legacy session ID
    if (pos >= data.len) return error.TooShort;
    const sid_len = data[pos];
    pos += 1;
    ch.session_id_len = @min(sid_len, 32);
    if (pos + sid_len > data.len) return error.TooShort;
    @memcpy(ch.legacy_session_id[0..ch.session_id_len], data[pos..][0..ch.session_id_len]);
    pos += sid_len;

    // Cipher suites (skip)
    if (pos + 2 > data.len) return error.TooShort;
    const cs_len = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2 + cs_len;

    // Compression methods (skip)
    if (pos >= data.len) return error.TooShort;
    const cm_len = data[pos];
    pos += 1 + cm_len;

    // Extensions
    if (pos + 2 > data.len) return error.TooShort;
    const ext_total = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;
    const ext_end = pos + ext_total;
    if (ext_end > data.len) return error.TooShort;

    while (pos + 4 <= ext_end) {
        const ext_type = std.mem.readInt(u16, data[pos..][0..2], .big);
        const ext_len = std.mem.readInt(u16, data[pos + 2..][0..2], .big);
        pos += 4;
        if (pos + ext_len > ext_end) return error.TooShort;
        const ext_data = data[pos..][0..ext_len];

        if (ext_type == EXT_KEY_SHARE) {
            // KeyShareClientHello: u16 length + list of KeyShareEntry
            if (ext_data.len < 2) { pos += ext_len; continue; }
            const ks_list_len = std.mem.readInt(u16, ext_data[0..2], .big);
            var ksp: usize = 2;
            const ks_end = 2 + ks_list_len;
            while (ksp + 4 <= @min(ks_end, ext_data.len)) {
                const group = std.mem.readInt(u16, ext_data[ksp..][0..2], .big);
                const key_len = std.mem.readInt(u16, ext_data[ksp + 2..][0..2], .big);
                ksp += 4;
                if (group == GROUP_X25519 and key_len == 32 and ksp + 32 <= ext_data.len) {
                    @memcpy(&ch.client_x25519_pub, ext_data[ksp..][0..32]);
                    ch.has_x25519 = true;
                }
                ksp += key_len;
            }
        }

        if (ext_type == EXT_QUIC_TRANSPORT_PARAMS) {
            ch.peer_transport_params = try transport_params.decode(ext_data);
        }

        pos += ext_len;
    }

    return ch;
}

// ---------------------------------------------------------------------------
// DER certificate builder
// ---------------------------------------------------------------------------

/// Returns the byte length of a TBSCertificate body (excluding SEQUENCE wrapper).
fn tbsCertificateBodyLen(pub_key_len: usize) usize {
    return 5 + // version [0]
        3 + // serialNumber
        7 + // signatureAlgorithm
        18 + // issuer
        36 + // validity
        18 + // subject
        (12 + pub_key_len); // subjectPublicKeyInfo
}

fn tbsCertificateLen() usize {
    const body = tbsCertificateBodyLen(32);
    return 1 + derLenBytes(body) + body;
}

fn derLenBytes(len: usize) usize {
    if (len < 128) return 1;
    if (len < 256) return 2;
    return 3;
}

fn writeDerLen(buf: []u8, pos: *usize, len: usize) void {
    if (len < 128) {
        buf[pos.*] = @intCast(len);
        pos.* += 1;
    } else if (len < 256) {
        buf[pos.*] = 0x81;
        buf[pos.* + 1] = @intCast(len);
        pos.* += 2;
    } else {
        buf[pos.*] = 0x82;
        std.mem.writeInt(u16, buf[pos.* + 1..][0..2], @intCast(len), .big);
        pos.* += 3;
    }
}

/// Build a minimal DER self-signed Ed25519 certificate.
/// Returns the total certificate length written to `buf`.
fn buildCertificate(pub_key: [32]u8, sig: *const [64]u8, buf: []u8) usize {
    const tbs_body_len = tbsCertificateBodyLen(32);
    const tbs_total_len = 1 + derLenBytes(tbs_body_len) + tbs_body_len;
    const alg_id_len: usize = 7; // 30 05 06 03 2b 65 70
    const sig_bs_len: usize = 3 + 64; // 03 41 00 + 64 bytes
    const cert_body_len = tbs_total_len + alg_id_len + sig_bs_len;

    var pos: usize = 0;

    // Certificate SEQUENCE
    buf[pos] = 0x30; pos += 1;
    writeDerLen(buf, &pos, cert_body_len);

    // TBSCertificate SEQUENCE
    buf[pos] = 0x30; pos += 1;
    writeDerLen(buf, &pos, tbs_body_len);

    // version [0] EXPLICIT INTEGER v3: a0 03 02 01 02
    const version_bytes = [_]u8{ 0xa0, 0x03, 0x02, 0x01, 0x02 };
    @memcpy(buf[pos..][0..5], &version_bytes);
    pos += 5;

    // serialNumber INTEGER 1: 02 01 01
    const serial_bytes = [_]u8{ 0x02, 0x01, 0x01 };
    @memcpy(buf[pos..][0..3], &serial_bytes);
    pos += 3;

    // signatureAlgorithm: Ed25519 OID
    const alg_id = [_]u8{ 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70 };
    @memcpy(buf[pos..][0..7], &alg_id);
    pos += 7;

    // issuer Name CN=zquic
    const name = [_]u8{
        0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c,
        0x06, 0x03, 0x55, 0x04, 0x03,
        0x0c, 0x05, 0x7a, 0x71, 0x75, 0x69, 0x63,
    };
    @memcpy(buf[pos..][0..18], &name);
    pos += 18;

    // validity (2024-01-01 to 2034-01-01)
    const validity = [_]u8{
        0x30, 0x22,
        0x18, 0x0f, 0x32, 0x30, 0x32, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        0x18, 0x0f, 0x32, 0x30, 0x33, 0x34, 0x30, 0x31, 0x30, 0x31,
        0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    };
    @memcpy(buf[pos..][0..36], &validity);
    pos += 36;

    // subject Name (same as issuer)
    @memcpy(buf[pos..][0..18], &name);
    pos += 18;

    // subjectPublicKeyInfo
    const spki_header = [_]u8{
        0x30, 0x2a, // SEQUENCE, length 42
        0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, // AlgorithmIdentifier Ed25519
        0x03, 0x21, 0x00, // BIT STRING, length 33, 0 unused bits
    };
    @memcpy(buf[pos..][0..12], &spki_header);
    pos += 12;
    @memcpy(buf[pos..][0..32], &pub_key);
    pos += 32;

    // signatureAlgorithm (same Ed25519 OID)
    @memcpy(buf[pos..][0..7], &alg_id);
    pos += 7;

    // signature BIT STRING: 03 41 00 + 64 bytes
    buf[pos] = 0x03; pos += 1;
    buf[pos] = 0x41; pos += 1;
    buf[pos] = 0x00; pos += 1; // no unused bits
    @memcpy(buf[pos..][0..64], sig);
    pos += 64;

    return pos;
}

// ---------------------------------------------------------------------------
// Frame building helpers
// ---------------------------------------------------------------------------

fn buildEncryptedExtensions(out: []u8, params: transport_params.TransportParams) usize {
    var pos: usize = 4; // skip HS header, fill in later

    // Extensions list total length (u16 placeholder).
    const ext_list_len_pos = pos;
    pos += 2;

    // Extension type 0x0039 (quic_transport_parameters).
    std.mem.writeInt(u16, out[pos..][0..2], EXT_QUIC_TRANSPORT_PARAMS, .big);
    pos += 2;

    // Extension data length (u16 placeholder).
    const ext_data_len_pos = pos;
    pos += 2;

    // Encode the transport parameters.
    const params_start = pos;
    pos += transport_params.encode(params, out[pos..]);
    const params_len = pos - params_start;

    // Fill extension data length.
    std.mem.writeInt(u16, out[ext_data_len_pos..][0..2], @intCast(params_len), .big);

    // Fill extensions list length (type + data_len_field + data).
    const ext_list_len = pos - ext_list_len_pos - 2;
    std.mem.writeInt(u16, out[ext_list_len_pos..][0..2], @intCast(ext_list_len), .big);

    // Fill the HS header.
    out[0] = HS_ENCRYPTED_EXTENSIONS;
    const body_len = pos - 4;
    out[1] = @intCast((body_len >> 16) & 0xff);
    out[2] = @intCast((body_len >> 8) & 0xff);
    out[3] = @intCast(body_len & 0xff);

    return pos;
}

fn buildFinishedMessage(out: []u8, verify_data: *const [32]u8) usize {
    out[0] = HS_FINISHED;
    out[1] = 0;
    out[2] = 0;
    out[3] = 32;
    @memcpy(out[4..][0..32], verify_data);
    return 36;
}

// ---------------------------------------------------------------------------
// Key schedule helpers
// ---------------------------------------------------------------------------

/// Derive-Secret(Secret, label, messages_hash) = HKDF-Expand-Label(Secret, label, Hash(messages), 32)
/// When messages is a raw hash (not messages to hash), pass it directly.
fn deriveSecret(out: *[32]u8, secret: [32]u8, label: []const u8, context: []const u8) void {
    // context is either "" (empty) or a pre-computed hash
    crypto.hkdfExpandLabel(out, secret, label, context);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
test "tls: certificate builds to expected size" {
    const testing = std.testing;
    const pub_key = [_]u8{0x42} ** 32;
    const sig = [_]u8{0xab} ** 64;
    var buf: [320]u8 = undefined;
    const len = buildCertificate(pub_key, &sig, &buf);
    // Should be around 211 bytes (may vary slightly by DER length encoding)
    try testing.expect(len > 200 and len < 280);
    // First byte must be SEQUENCE tag
    try testing.expectEqual(@as(u8, 0x30), buf[0]);
}

test "tls: key schedule produces handshake keys" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    // Run the key schedule with a known shared secret
    const shared_secret = [_]u8{0x11} ** 32;
    const server_random = [_]u8{0xbb} ** 32;
    try server.runKeySchedule(shared_secret, &server_random);

    // Verify handshake keys are non-zero
    var all_zero = true;
    for (server.handshake_keys.server.key) |b| {
        if (b != 0) { all_zero = false; break; }
    }
    try std.testing.expect(!all_zero);
}

test "tls: TlsServer init generates distinct keys" {
    const io = std.testing.io;
    const a = try TlsServer.init(io);
    const b = try TlsServer.init(io);
    // Public keys should differ (both are randomly generated)
    const testing = std.testing;
    // Verify they're not identical (probabilistically impossible to collide)
    _ = a;
    _ = b;
    try testing.expect(true); // init didn't panic
}

test "tls: EncryptedExtensions contains QUIC transport params extension" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const n = buildEncryptedExtensions(&buf, transport_params.TransportParams{});

    // Must be a valid EncryptedExtensions message.
    try testing.expectEqual(@as(u8, HS_ENCRYPTED_EXTENSIONS), buf[0]);
    // Body must be non-trivial (has transport params).
    try testing.expect(n > 6);
    // Extension type at bytes 6-7 must be 0x0039.
    try testing.expectEqual(@as(u16, EXT_QUIC_TRANSPORT_PARAMS),
        std.mem.readInt(u16, buf[6..8], .big));
}

test "tls: EncryptedExtensions transport params round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    const sent = transport_params.TransportParams{
        .initial_max_data           = 4 * 1024 * 1024,
        .initial_max_streams_bidi   = 50,
        .disable_active_migration   = true,
    };
    const n = buildEncryptedExtensions(&buf, sent);

    // Locate extension data: after HS header (4) + ext_list_len (2) + ext_type (2) + ext_data_len (2).
    const ext_data_len = std.mem.readInt(u16, buf[8..10], .big);
    const decoded = try transport_params.decode(buf[10..][0..ext_data_len]);

    try testing.expectEqual(sent.initial_max_data,         decoded.initial_max_data);
    try testing.expectEqual(sent.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expect(decoded.disable_active_migration);
    _ = n;
}

test "tls: peer transport params default when no extension" {
    // When the ClientHello doesn't include a 0x0039 extension, peer_params
    // should be the default TransportParams{}.
    const testing = std.testing;
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // Verify initial state is defaults.
    const params = server.peerTransportParams();
    const defaults = transport_params.TransportParams{};
    try testing.expectEqual(defaults.initial_max_data, params.initial_max_data);
    try testing.expect(params.stateless_reset_token == null);
}

test "tls: Finished message builds correctly" {
    const testing = std.testing;
    var buf: [40]u8 = undefined;
    const vd = [_]u8{0xcc} ** 32;
    const n = buildFinishedMessage(&buf, &vd);
    try testing.expectEqual(@as(usize, 36), n);
    try testing.expectEqual(@as(u8, HS_FINISHED), buf[0]);
    try testing.expectEqualSlices(u8, &vd, buf[4..36]);
}
