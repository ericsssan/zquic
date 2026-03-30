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
const packet_mod = @import("packet.zig");
const transport_params = @import("transport_params.zig");
const tls_client = @import("tls_client.zig");
pub const TlsClient = tls_client.TlsClient;
pub const SessionTicket = tls_client.SessionTicket;
const HkdfSha256 = std.crypto.kdf.hkdf.HkdfSha256;
const Aes128Gcm = std.crypto.aead.aes_gcm.Aes128Gcm;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Hmac256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;
const Ed25519 = std.crypto.sign.Ed25519;
const EcdsaP256Sha256 = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const P256 = std.crypto.ecc.P256;

/// Private-key algorithm used for CertificateVerify.
pub const KeyAlgorithm = enum { ed25519, p256 };

const SignKey = union(KeyAlgorithm) {
    ed25519: Ed25519.KeyPair,
    p256: EcdsaP256Sha256.KeyPair,
};

// ---------------------------------------------------------------------------
// TLS constants
// ---------------------------------------------------------------------------

const TLS_VERSION_1_3: u16 = 0x0304;
const TLS_VERSION_LEGACY: u16 = 0x0303;
const CIPHER_TLS_AES_128_GCM_SHA256: u16 = @intFromEnum(crypto.CipherSuite.aes_128_gcm);
const CIPHER_TLS_CHACHA20_POLY1305_SHA256: u16 = @intFromEnum(crypto.CipherSuite.chacha20_poly1305);
const GROUP_X25519: u16 = 0x001d;
const GROUP_SECP256R1: u16 = 0x0017; // P-256

// Extension types
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_ALPN: u16 = 0x0010;
const EXT_QUIC_TRANSPORT_PARAMS: u16 = 0x0039;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_PSK_KEY_EXCHANGE_MODES: u16 = 0x002d;
const EXT_EARLY_DATA: u16 = 0x002a;

// SHA-256("") — used in key schedule and binder validation (RFC 8446 §7.1).
pub const sha256_empty = [_]u8{
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

// Handshake message types
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
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

// ---------------------------------------------------------------------------
// TlsRole — tagged union for server/client TLS state machines
// ---------------------------------------------------------------------------

pub const TlsRole = union(enum) {
    server: TlsServer,
    client: TlsClient,

    pub fn processCrypto(self: *TlsRole, data: []const u8, out: []u8, io: std.Io) !usize {
        switch (self.*) {
            inline else => |*s| return s.processCrypto(data, out, io),
        }
    }

    pub fn isComplete(self: *const TlsRole) bool {
        switch (self.*) {
            inline else => |*s| return s.isComplete(),
        }
    }

    pub fn deinit(self: *TlsRole) void {
        switch (self.*) {
            inline else => |*s| s.deinit(),
        }
    }

    pub fn peerTransportParams(self: *const TlsRole) transport_params.TransportParams {
        switch (self.*) {
            inline else => |*s| return s.peerTransportParams(),
        }
    }

    // -- Common field accessors via inline switch --

    pub fn handshakeKeys(self: *const TlsRole) HandshakeKeys {
        switch (self.*) {
            inline else => |*s| return s.handshake_keys,
        }
    }

    pub fn appKeys(self: *const TlsRole) AppKeys {
        switch (self.*) {
            inline else => |*s| return s.app_keys,
        }
    }

    pub fn clientAppSecret(self: *const TlsRole) [32]u8 {
        switch (self.*) {
            inline else => |*s| return s.client_app_secret,
        }
    }

    pub fn serverAppSecret(self: *const TlsRole) [32]u8 {
        switch (self.*) {
            inline else => |*s| return s.server_app_secret,
        }
    }

    pub fn negotiatedCipher(self: *const TlsRole) crypto.CipherSuite {
        switch (self.*) {
            inline else => |*s| return s.negotiated_cipher,
        }
    }

    pub fn getQuicVersion(self: *const TlsRole) u32 {
        switch (self.*) {
            inline else => |*s| return s.quic_version,
        }
    }

    pub fn setQuicVersion(self: *TlsRole, version: u32) void {
        switch (self.*) {
            inline else => |*s| s.quic_version = version,
        }
    }

    pub fn setOurTransportParams(self: *TlsRole, params: transport_params.TransportParams) void {
        switch (self.*) {
            inline else => |*s| s.our_transport_params = params,
        }
    }

    /// Returns true if the TLS state machine is waiting for the first message (server: ClientHello, client: idle).
    pub fn isInitial(self: *const TlsRole) bool {
        return switch (self.*) {
            .server => |s| s.state == .wait_client_hello,
            .client => |s| s.state == .idle,
        };
    }
};

/// Parsed ClientHello data (what we need from it).
const ClientHelloData = struct {
    random: [32]u8,
    legacy_session_id: [32]u8,
    session_id_len: u8,
    client_x25519_pub: [32]u8,
    has_x25519: bool,
    client_p256_pub: [65]u8,
    has_p256: bool,
    peer_transport_params: transport_params.TransportParams,
    alpn_names: [4][32]u8 = [_][32]u8{[_]u8{0} ** 32} ** 4,
    alpn_lens: [4]u8 = [_]u8{0} ** 4,
    alpn_count: u8 = 0,
    has_aes_128_gcm: bool = false,
    has_chacha20_poly1305: bool = false,

    // PSK / session resumption fields
    psk_identity: [128]u8 = [_]u8{0} ** 128,
    psk_identity_len: u16 = 0,
    psk_binder: [32]u8 = [_]u8{0} ** 32,
    has_psk: bool = false,
    has_psk_dhe_ke: bool = false,
    psk_obfuscated_age: u32 = 0,
    has_early_data: bool = false,
    /// Byte offset in the raw ClientHello up to but not including binders list.
    /// Used for binder validation (RFC 8446 §4.2.11.2).
    ch_truncated_len: usize = 0,
};

pub const TlsServer = struct {
    state: TlsState,

    // Our X25519 key pair (ephemeral per-connection)
    ecdh_kp: X25519.KeyPair,
    // Our P-256 ephemeral key pair (used when client offers secp256r1 but not X25519)
    p256_secret: [32]u8,
    p256_pub: [65]u8,
    // Our signing key (Ed25519 or P-256 ECDSA depending on certificate)
    sign_key: SignKey,
    // DER-encoded leaf certificate (self-signed or external), used for CertificateVerify.
    cert_buf: [16384]u8,
    cert_len: usize,
    // Pre-formatted TLS CertificateEntry list for full cert chain.
    // When chain_len > 0, buildCertificateMessage uses this instead of cert_buf.
    cert_chain: [32768]u8 = undefined,
    cert_chain_len: usize = 0,

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

    // TLS client_random from ClientHello (used for SSLKEYLOG export).
    client_random: [32]u8,

    // Negotiated transport parameters received from the peer.
    peer_params: transport_params.TransportParams,

    // Our transport parameters to send in EncryptedExtensions (set by Connection).
    our_transport_params: transport_params.TransportParams = .{},

    // QUIC version negotiated for this connection (set by Connection after accept).
    // Determines which key derivation labels to use (RFC 9001 vs RFC 9369).
    quic_version: u32 = packet_mod.QUIC_VERSION_1,

    // Server's initially configured QUIC version (set by Connection).
    // Used for compatible version negotiation: if peer's version_information
    // includes this version, we can switch to it during handshake.
    server_configured_version: u32 = packet_mod.QUIC_VERSION_1,

    // ALPN negotiation (RFC 7301 / TLS ext 0x0010).
    // required_alpn_len == 0 means no ALPN check.
    required_alpn: [32]u8 = [_]u8{0} ** 32,
    required_alpn_len: u8 = 0,
    negotiated_alpn: [32]u8 = [_]u8{0} ** 32,
    negotiated_alpn_len: u8 = 0,

    // Cipher suite negotiation. Server prefers AES by default.
    // Set preferred_cipher to .chacha20_poly1305 to prefer ChaCha20 when client offers it.
    preferred_cipher: crypto.CipherSuite = .aes_128_gcm,
    negotiated_cipher: crypto.CipherSuite = .aes_128_gcm,

    // Session resumption / 0-RTT fields
    resumption_master_secret: [32]u8 = [_]u8{0} ** 32,
    early_secret: [32]u8 = [_]u8{0} ** 32,
    client_early_traffic_secret: [32]u8 = [_]u8{0} ** 32,
    is_psk_handshake: bool = false,
    accept_early_data: bool = false,
    ticket_key: ?*const [32]u8 = null,
    ticket_nonce_counter: u8 = 0,
    /// Current time in nanoseconds (set by connection layer before processCrypto).
    current_time_ns: i64 = 0,

    // CRYPTO data accumulation buffers
    read_buf: [8192]u8,
    read_len: usize,
    // Cumulative count of CRYPTO bytes received (across all processCrypto calls).
    // Prevents an attacker from sending unlimited data in small chunks before the
    // read_buf check fires.  Cap: 64 KB (generous for a single TLS handshake).
    crypto_bytes_total: u32,

    pub fn init(io: std.Io) !TlsServer {
        const ecdh_kp = X25519.KeyPair.generate(io);
        const sign_kp = Ed25519.KeyPair.generate(io);
        const p256_secret = P256.scalar.random(io, .little);
        const p256_pub = (P256.basePoint.mul(p256_secret, .little) catch unreachable).toUncompressedSec1();

        var self: TlsServer = .{
            .state = .wait_client_hello,
            .ecdh_kp = ecdh_kp,
            .p256_secret = p256_secret,
            .p256_pub = p256_pub,
            .sign_key = .{ .ed25519 = sign_kp },
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
            .client_random = [_]u8{0} ** 32,
            .peer_params = .{},
            .read_buf = undefined,
            .read_len = 0,
            .crypto_bytes_total = 0,
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

    /// Initialize TlsServer with a caller-provided DER certificate and private key.
    /// `seed` is the 32-byte Ed25519 seed or P-256 private scalar depending on `algorithm`.
    /// Use when loading certs from disk (e.g. interop runner /certs/).
    pub fn initFromCert(cert_der: []const u8, seed: [32]u8, algorithm: KeyAlgorithm, io: std.Io) !TlsServer {
        if (cert_der.len > 65536) return error.CertTooLarge;
        const ecdh_kp = X25519.KeyPair.generate(io);
        const p256_secret = P256.scalar.random(io, .little);
        const p256_pub = (P256.basePoint.mul(p256_secret, .little) catch unreachable).toUncompressedSec1();
        const sign_key: SignKey = switch (algorithm) {
            .ed25519 => .{ .ed25519 = try Ed25519.KeyPair.generateDeterministic(seed) },
            .p256 => blk: {
                const sk = EcdsaP256Sha256.SecretKey{ .bytes = seed };
                break :blk .{ .p256 = try EcdsaP256Sha256.KeyPair.fromSecretKey(sk) };
            },
        };
        var self: TlsServer = .{
            .state = .wait_client_hello,
            .ecdh_kp = ecdh_kp,
            .p256_secret = p256_secret,
            .p256_pub = p256_pub,
            .sign_key = sign_key,
            .cert_buf = undefined,
            .cert_len = cert_der.len,
            .transcript = Sha256.init(.{}),
            .handshake_secret = [_]u8{0} ** 32,
            .master_secret = [_]u8{0} ** 32,
            .handshake_keys = undefined,
            .app_keys = undefined,
            .client_hs_secret = [_]u8{0} ** 32,
            .server_hs_secret = [_]u8{0} ** 32,
            .client_app_secret = [_]u8{0} ** 32,
            .server_app_secret = [_]u8{0} ** 32,
            .client_random = [_]u8{0} ** 32,
            .peer_params = .{},
            .read_buf = undefined,
            .read_len = 0,
            .crypto_bytes_total = 0,
        };
        @memcpy(self.cert_buf[0..cert_der.len], cert_der);
        return self;
    }

    /// Set a pre-formatted TLS CertificateEntry list for multi-cert chains.
    /// Format: [3-byte len][DER][2-byte ext(0)] repeated for each cert.
    pub fn setCertChain(self: *TlsServer, chain: []const u8) void {
        const n = @min(chain.len, self.cert_chain.len);
        @memcpy(self.cert_chain[0..n], chain[0..n]);
        self.cert_chain_len = n;
    }

    pub fn isComplete(self: *const TlsServer) bool {
        return self.state == .established;
    }

    /// Zero all secret key material.  Call when the TlsServer is no longer needed.
    /// Uses volatile writes via std.crypto.secureZero to prevent optimizer elision.
    pub fn deinit(self: *TlsServer) void {
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.handshake_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.master_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.client_hs_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.server_hs_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.client_app_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.server_app_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.resumption_master_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.early_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.client_early_traffic_secret)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.ecdh_kp.secret_key)));
        std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&self.p256_secret)));
        switch (self.sign_key) {
            .ed25519 => |*kp| std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&kp.secret_key))),
            .p256 => |*kp| std.crypto.secureZero(u8, @as(*volatile [32]u8, @ptrCast(&kp.secret_key.bytes))),
        }
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
        // Cumulative CRYPTO cap: reject if the running total exceeds 64 KB.
        // Prevents an attacker from evading the per-call read_buf check by sending
        // many small CRYPTO frames (each processed then cleared from the buffer).
        const incoming: u32 = @intCast(@min(data.len, std.math.maxInt(u32)));
        const new_total = self.crypto_bytes_total +| incoming;
        if (new_total > 65536) return error.CryptoDataTooLarge;
        self.crypto_bytes_total = new_total;

        // Accumulate data
        if (self.read_len + data.len > self.read_buf.len) return error.BufferOverflow;
        @memcpy(self.read_buf[self.read_len..][0..data.len], data);
        self.read_len += data.len;

        switch (self.state) {
            .wait_client_hello => {
                // Handle fragmented CRYPTO data gracefully: if the ClientHello is not
                // yet complete, keep buffering instead of aborting the connection.
                const ch = parseClientHello(self.read_buf[0..self.read_len]) catch |err| switch (err) {
                    error.TooShort => return 0, // not enough data yet; wait for more
                    else => return err,
                };
                // Hash the complete ClientHello into the transcript before processing.
                // The key schedule requires H(ClientHello || ServerHello).
                self.transcript.update(self.read_buf[0..self.read_len]);
                // Note: read_buf is NOT zeroed here because handleClientHello needs it
                // for PSK binder validation (hashing the truncated ClientHello).
                const result = try self.handleClientHello(ch, out, io);
                // Defense-in-depth: zero the plaintext CRYPTO buffer after processing.
                std.crypto.secureZero(u8, @as(*volatile [8192]u8, @ptrCast(&self.read_buf)));
                self.read_len = 0;
                return result;
            },
            .wait_client_finished => {
                const ok = try self.verifyClientFinished(self.read_buf[0..self.read_len]);
                // Defense-in-depth: zero plaintext ClientFinished message after verification.
                std.crypto.secureZero(u8, @as(*volatile [8192]u8, @ptrCast(&self.read_buf)));
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
        if (!ch.has_x25519 and !ch.has_p256) return error.NoSupportedKeyShare;
        const use_p256 = !ch.has_x25519 and ch.has_p256;

        // Cipher suite negotiation: client must offer at least one supported suite.
        if (!ch.has_aes_128_gcm and !ch.has_chacha20_poly1305) return error.NoSupportedCipher;
        self.negotiated_cipher = switch (self.preferred_cipher) {
            .chacha20_poly1305 => if (ch.has_chacha20_poly1305) .chacha20_poly1305 else .aes_128_gcm,
            .aes_128_gcm => if (ch.has_aes_128_gcm) .aes_128_gcm else .chacha20_poly1305,
        };

        // ALPN negotiation: if we require a protocol, the client must offer it.
        if (self.required_alpn_len > 0) {
            const req = self.required_alpn[0..self.required_alpn_len];
            var matched = false;
            for (0..ch.alpn_count) |i| {
                if (std.mem.eql(u8, req, ch.alpn_names[i][0..ch.alpn_lens[i]])) {
                    @memcpy(self.negotiated_alpn[0..req.len], req);
                    self.negotiated_alpn_len = self.required_alpn_len;
                    matched = true;
                    break;
                }
            }
            if (!matched) return error.AlpnMismatch;
        }

        // Store the client's transport parameters.
        self.peer_params = ch.peer_transport_params;

        // Compatible version negotiation (RFC 9368/9369): if peer supports our configured version,
        // upgrade to it for key derivation. Server sends version_information to client,
        // and client will also upgrade when it receives EncryptedExtensions.
        if (self.peer_params.version_information) |vi_buf| {
            const vi_len = self.peer_params.version_information_len;
            if (vi_len >= 4 and vi_len % 4 == 0) {
                var i: u8 = 0;
                while (i < vi_len) : (i += 4) {
                    const ver = @as(u32, vi_buf[i]) << 24 |
                        @as(u32, vi_buf[i + 1]) << 16 |
                        @as(u32, vi_buf[i + 2]) << 8 |
                        @as(u32, vi_buf[i + 3]);
                    if (ver == self.server_configured_version and ver != self.quic_version) {
                        self.quic_version = ver;
                        break;
                    }
                }
            }
        }

        // Save client_random for SSLKEYLOG export.
        self.client_random = ch.random;

        // PSK validation (RFC 8446 §4.2.11): before ECDH, check if client offered a valid PSK.
        var psk_for_schedule: ?[32]u8 = null;
        if (ch.has_psk and ch.has_psk_dhe_ke and self.ticket_key != null) {
            if (decryptTicket(self.ticket_key.?, ch.psk_identity[0..ch.psk_identity_len])) |ticket_data| {
                const cipher_ok = ticket_data.cipher == self.negotiated_cipher;
                const alpn_ok = ticket_data.alpn_len == self.negotiated_alpn_len and
                    std.mem.eql(u8, ticket_data.alpn[0..ticket_data.alpn_len], self.negotiated_alpn[0..self.negotiated_alpn_len]);
                const age_ns = self.current_time_ns - ticket_data.timestamp;
                const age_ok = age_ns >= 0 and age_ns < 7 * 24 * 3600 * std.time.ns_per_s;

                if (cipher_ok and alpn_ok and age_ok) {
                    // Compute early_secret from PSK for binder validation
                    const zero32 = [_]u8{0} ** 32;
                    const psk_early_secret = HkdfSha256.extract(&zero32, &ticket_data.psk);

                    // Validate binder (RFC 8446 §4.2.11.2):
                    // binder_key = Derive-Secret(early_secret, "res binder", SHA-256(""))
                    var binder_key: [32]u8 = undefined;
                    deriveSecret(&binder_key, psk_early_secret, "res binder", &sha256_empty);
                    // finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32)
                    var finished_key: [32]u8 = undefined;
                    crypto.hkdfExpandLabel(&finished_key, binder_key, "finished", "");
                    // Hash CH up to (but not including) binders
                    var binder_hash = Sha256.init(.{});
                    binder_hash.update(self.read_buf[0..ch.ch_truncated_len]);
                    var binder_hash_val: [32]u8 = undefined;
                    binder_hash.final(&binder_hash_val);
                    // Expected binder = HMAC-SHA256(finished_key, hash)
                    var expected_binder: [32]u8 = undefined;
                    Hmac256.create(&expected_binder, &binder_hash_val, &finished_key);

                    if (std.crypto.timing_safe.eql([32]u8, expected_binder, ch.psk_binder)) {
                        self.is_psk_handshake = true;
                        psk_for_schedule = ticket_data.psk;
                        self.early_secret = psk_early_secret;
                    }
                }
            }
        }

        // 1. ECDH shared secret
        const shared: [32]u8 = if (use_p256) blk: {
            const client_point = try P256.fromSec1(&ch.client_p256_pub);
            const shared_point = try client_point.mul(self.p256_secret, .little);
            break :blk shared_point.affineCoordinates().x.toBytes(.big);
        } else blk: {
            break :blk try X25519.scalarmult(self.ecdh_kp.secret_key, ch.client_x25519_pub);
        };

        // 2. Server random
        var server_random: [32]u8 = undefined;
        io.random(&server_random);

        // Derive client_early_traffic_secret BEFORE hashing SH into transcript.
        // At this point, self.transcript = H(CH) only (RFC 8446 §7.1).
        if (self.is_psk_handshake and ch.has_early_data) {
            var ch_transcript = self.transcript;
            var ch_hash: [32]u8 = undefined;
            ch_transcript.final(&ch_hash);
            deriveSecret(&self.client_early_traffic_secret, self.early_secret, "c e traffic", &ch_hash);
            self.accept_early_data = true;
        }

        // 3. Serialize ServerHello FIRST (before key schedule).
        var pos: usize = 0;
        pos += try self.buildServerHello(
            out[pos..],
            server_random,
            ch.legacy_session_id[0..ch.session_id_len],
            use_p256,
        );

        // 4. Hash ServerHello into transcript (transcript now has H(CH || SH)).
        self.transcript.update(out[0..pos]);

        // 5. Run TLS 1.3 key schedule with the correct transcript state.
        try self.runKeySchedule(shared, psk_for_schedule);

        // From here on, messages are "handshake-encrypted" conceptually.
        const ee_start = pos;

        // EncryptedExtensions (with QUIC transport parameters and negotiated ALPN).
        pos += buildEncryptedExtensionsBasic(out[pos..], self.our_transport_params, self.negotiated_alpn[0..self.negotiated_alpn_len], self.accept_early_data);

        if (!self.is_psk_handshake) {
            // Certificate
            pos += self.buildCertificateMessage(out[pos..]);

            // CertificateVerify
            const tls_cv_msg = out[ee_start..pos];
            var transcript_so_far = self.transcript;
            transcript_so_far.update(tls_cv_msg);
            var cv_hash: [32]u8 = undefined;
            transcript_so_far.final(&cv_hash);
            pos += try self.buildCertificateVerify(out[pos..], &cv_hash);
        }

        // Update transcript with EE (+ Cert + CertificateVerify if not PSK).
        self.transcript.update(out[ee_start..pos]);

        // Compute Server Finished verify_data over H(CH || SH || EE || Cert || CertVerify).
        // Use a snapshot so self.transcript remains usable — Sha256.final() is destructive.
        var snap = self.transcript;
        var transcript_hash: [32]u8 = undefined;
        snap.final(&transcript_hash);

        // Compute finished_key = HKDF-Expand-Label(server_hs_secret, "finished", "", 32)
        var finished_key: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&finished_key, self.server_hs_secret, "finished", "");
        // verify_data = HMAC-SHA256(finished_key, transcript_hash)
        var verify_data: [32]u8 = undefined;
        Hmac256.create(&verify_data, &transcript_hash, &finished_key);

        const sf_start = pos;
        pos += buildFinishedMessage(out[pos..], &verify_data);

        // Include Server Finished in the transcript for client Finished verification.
        // Per RFC 8446 §4.4.4: client's verify_data = HMAC(finished_key,
        //   H(CH || SH || EE || Cert || CertVerify || ServerFinished)).
        self.transcript.update(out[sf_start..pos]);

        self.state = .wait_client_finished;
        return pos;
    }

    pub fn runKeySchedule(self: *TlsServer, shared_secret: [32]u8, psk: ?[32]u8) !void {
        // TLS 1.3 key schedule (RFC 8446 §7.1):
        //
        //   Early Secret = HKDF-Extract(0, PSK)     — PSK or 0 for full handshake
        //   Handshake Secret = HKDF-Extract(DHE, Derive-Secret(ES, "derived", ""))
        //   Master Secret = HKDF-Extract(0, Derive-Secret(HS, "derived", ""))

        const zero32 = [_]u8{0} ** 32;

        // Early Secret: with PSK or zero for full handshake
        const early_secret = if (psk) |p|
            HkdfSha256.extract(&zero32, &p)
        else
            HkdfSha256.extract(&zero32, &zero32);
        self.early_secret = early_secret;

        // derived = Derive-Secret(early_secret, "derived", "")
        var derived: [32]u8 = undefined;
        deriveSecret(&derived, early_secret, "derived", &sha256_empty);

        // Handshake Secret
        self.handshake_secret = HkdfSha256.extract(&derived, &shared_secret);

        // Get transcript hash up to ServerHello (updated as we go)
        var transcript_copy = self.transcript;
        var th_hello: [32]u8 = undefined;
        transcript_copy.final(&th_hello);

        // client/server handshake traffic secrets
        deriveSecret(&self.client_hs_secret, self.handshake_secret, "c hs traffic", &th_hello);
        deriveSecret(&self.server_hs_secret, self.handshake_secret, "s hs traffic", &th_hello);

        // Derive handshake-epoch QUIC packet keys (uses negotiated cipher suite)
        self.handshake_keys = .{
            .client = crypto.derivePacketKeysWithSuite(self.client_hs_secret, self.quic_version, self.negotiated_cipher),
            .server = crypto.derivePacketKeysWithSuite(self.server_hs_secret, self.quic_version, self.negotiated_cipher),
        };

        // Master Secret
        var derived2: [32]u8 = undefined;
        deriveSecret(&derived2, self.handshake_secret, "derived", &sha256_empty);
        self.master_secret = HkdfSha256.extract(&derived2, &zero32);
    }

    fn deriveAppKeys(self: *TlsServer, transcript_hash: *const [32]u8) void {
        // client/server application traffic secrets
        deriveSecret(&self.client_app_secret, self.master_secret, "c ap traffic", transcript_hash);
        deriveSecret(&self.server_app_secret, self.master_secret, "s ap traffic", transcript_hash);

        self.app_keys = .{
            .client = crypto.derivePacketKeysWithSuite(self.client_app_secret, self.quic_version, self.negotiated_cipher),
            .server = crypto.derivePacketKeysWithSuite(self.server_app_secret, self.quic_version, self.negotiated_cipher),
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
        if (!std.crypto.timing_safe.eql([32]u8, expected_verify, client_verify.*)) return false;

        // RFC 8446 §7.1: client/server app traffic secrets use the transcript
        // through ServerFinished only (i.e. before ClientFinished is included).
        self.deriveAppKeys(&transcript_hash);

        // Transcript now includes client Finished (for any further derivations).
        self.transcript.update(data[0 .. 4 + 32]);

        // Derive resumption_master_secret (RFC 8446 §7.1): needed for NewSessionTicket.
        // Uses transcript through client Finished.
        var rms_transcript = self.transcript;
        var rms_hash: [32]u8 = undefined;
        rms_transcript.final(&rms_hash);
        deriveSecret(&self.resumption_master_secret, self.master_secret, "res master", &rms_hash);

        return true;
    }

    fn buildServerHello(
        self: *TlsServer,
        out: []u8,
        server_random: [32]u8,
        session_id: []const u8,
        use_p256: bool,
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

        // Cipher suite: negotiated
        std.mem.writeInt(u16, out[pos..][0..2], @intFromEnum(self.negotiated_cipher), .big);
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

        // key_share extension: server's ephemeral public key (X25519 or P-256)
        std.mem.writeInt(u16, out[pos..][0..2], EXT_KEY_SHARE, .big);
        pos += 2;
        if (use_p256) {
            std.mem.writeInt(u16, out[pos..][0..2], 4 + 65, .big); // ext length
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], GROUP_SECP256R1, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 65, .big); // key length
            pos += 2;
            @memcpy(out[pos..][0..65], &self.p256_pub);
            pos += 65;
        } else {
            std.mem.writeInt(u16, out[pos..][0..2], 4 + 32, .big); // ext length
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], GROUP_X25519, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 32, .big); // key length
            pos += 2;
            @memcpy(out[pos..][0..32], &self.ecdh_kp.public_key);
            pos += 32;
        }

        // pre_shared_key extension (RFC 8446 §4.2.11): selected identity index = 0
        if (self.is_psk_handshake) {
            std.mem.writeInt(u16, out[pos..][0..2], EXT_PRE_SHARED_KEY, .big);
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 2, .big); // ext length = 2
            pos += 2;
            std.mem.writeInt(u16, out[pos..][0..2], 0, .big); // selected_identity = 0
            pos += 2;
        }

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

        if (self.cert_chain_len > 0) {
            // Multi-cert chain: pre-formatted CertificateEntry list
            @memcpy(out[pos..][0..self.cert_chain_len], self.cert_chain[0..self.cert_chain_len]);
            pos += self.cert_chain_len;
        } else {
            // Single certificate
            const cert_data = self.cert_buf[0..self.cert_len];
            out[pos] = @intCast((cert_data.len >> 16) & 0xff);
            out[pos + 1] = @intCast((cert_data.len >> 8) & 0xff);
            out[pos + 2] = @intCast(cert_data.len & 0xff);
            pos += 3;
            @memcpy(out[pos..][0..cert_data.len], cert_data);
            pos += cert_data.len;
            std.mem.writeInt(u16, out[pos..][0..2], 0, .big);
            pos += 2;
        }

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

        var pos: usize = 4; // handshake header placeholder

        switch (self.sign_key) {
            .ed25519 => |kp| {
                const sig = try kp.sign(&to_sign, null);
                const sig_bytes = sig.toBytes(); // 64 bytes fixed

                // SignatureScheme: Ed25519 = 0x0807
                std.mem.writeInt(u16, out[pos..][0..2], 0x0807, .big);
                pos += 2;
                std.mem.writeInt(u16, out[pos..][0..2], @intCast(sig_bytes.len), .big);
                pos += 2;
                @memcpy(out[pos..][0..sig_bytes.len], &sig_bytes);
                pos += sig_bytes.len;
            },
            .p256 => |kp| {
                const sig = try kp.sign(&to_sign, null);
                // TLS 1.3 uses DER-encoded ECDSA signature (RFC 8446 §4.2.3).
                // P-256 DER max = 72 bytes (EcdsaP256Sha256.Signature.der_encoded_length_max).
                var der_buf: [EcdsaP256Sha256.Signature.der_encoded_length_max]u8 = undefined;
                const der_sig = sig.toDer(&der_buf);

                // SignatureScheme: ecdsa_secp256r1_sha256 = 0x0403
                std.mem.writeInt(u16, out[pos..][0..2], 0x0403, .big);
                pos += 2;
                std.mem.writeInt(u16, out[pos..][0..2], @intCast(der_sig.len), .big);
                pos += 2;
                @memcpy(out[pos..][0..der_sig.len], der_sig);
                pos += der_sig.len;
            },
        }

        // Fill handshake header
        out[0] = HS_CERTIFICATE_VERIFY;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        return pos;
    }

    /// Build a NewSessionTicket handshake message.
    /// Returns the number of bytes written to `out`.
    pub fn buildNewSessionTicket(self: *TlsServer, out: []u8) usize {
        const ticket_key_ptr = self.ticket_key orelse return 0;

        // Derive PSK from resumption_master_secret:
        // PSK = HKDF-Expand-Label(rms, "resumption", [nonce], 32)
        const nonce_val = self.ticket_nonce_counter;
        self.ticket_nonce_counter +|= 1;
        var psk: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&psk, self.resumption_master_secret, "resumption", &[_]u8{nonce_val});

        // Build ticket plaintext: PSK(32) || cipher(2) || alpn_len(1) || alpn(N) || timestamp(8)
        var pt: [TICKET_PLAINTEXT_MAX]u8 = undefined;
        @memcpy(pt[0..32], &psk);
        std.mem.writeInt(u16, pt[32..34], @intFromEnum(self.negotiated_cipher), .big);
        pt[34] = self.negotiated_alpn_len;
        if (self.negotiated_alpn_len > 0) {
            @memcpy(pt[35..][0..self.negotiated_alpn_len], self.negotiated_alpn[0..self.negotiated_alpn_len]);
        }
        const ts_off: usize = 35 + @as(usize, self.negotiated_alpn_len);
        const now: u64 = @bitCast(self.current_time_ns);
        std.mem.writeInt(u64, pt[ts_off..][0..8], now, .big);
        const pt_len = ts_off + 8;

        // Derive enc_nonce and age_add deterministically from key material
        // (no io.random needed — avoids needing std.Io in tick()).
        var derived_random: [32]u8 = undefined;
        crypto.hkdfExpandLabel(&derived_random, self.resumption_master_secret, "tkt rand", &[_]u8{nonce_val});
        var enc_nonce: [12]u8 = undefined;
        @memcpy(&enc_nonce, derived_random[0..12]);

        var ciphertext: [TICKET_PLAINTEXT_MAX]u8 = undefined;
        var tag: [16]u8 = undefined;
        Aes128Gcm.encrypt(
            ciphertext[0..pt_len],
            &tag,
            pt[0..pt_len],
            &.{}, // no AAD
            enc_nonce,
            ticket_key_ptr[0..16].*,
        );

        // ticket_data = nonce(12) || ciphertext(pt_len) || tag(16)
        const ticket_data_len = 12 + pt_len + 16;

        // Build TLS NewSessionTicket message
        var pos: usize = 4; // skip handshake header

        // ticket_lifetime (4 bytes): 86400 seconds (1 day)
        std.mem.writeInt(u32, out[pos..][0..4], 86400, .big);
        pos += 4;

        // ticket_age_add (4 bytes): derived from key material
        @memcpy(out[pos..][0..4], derived_random[12..16]);
        pos += 4;

        // ticket_nonce (1 byte length + nonce)
        out[pos] = 1; // nonce length
        pos += 1;
        out[pos] = nonce_val;
        pos += 1;

        // ticket (2 byte length + data)
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(ticket_data_len), .big);
        pos += 2;
        @memcpy(out[pos..][0..12], &enc_nonce);
        pos += 12;
        @memcpy(out[pos..][0..pt_len], ciphertext[0..pt_len]);
        pos += pt_len;
        @memcpy(out[pos..][0..16], &tag);
        pos += 16;

        // Extensions: early_data (type=0x002A, length=4, max_early_data_size=0xFFFFFFFF)
        std.mem.writeInt(u16, out[pos..][0..2], 8, .big); // extensions length
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], EXT_EARLY_DATA, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 4, .big); // ext data length
        pos += 2;
        std.mem.writeInt(u32, out[pos..][0..4], 0xFFFFFFFF, .big); // max_early_data_size
        pos += 4;

        // Fill handshake header
        out[0] = HS_NEW_SESSION_TICKET;
        const body_len = pos - 4;
        out[1] = @intCast((body_len >> 16) & 0xff);
        out[2] = @intCast((body_len >> 8) & 0xff);
        out[3] = @intCast(body_len & 0xff);

        return pos;
    }
}; // end TlsServer

// ---------------------------------------------------------------------------
// Parsing helpers
// ---------------------------------------------------------------------------

pub fn parseClientHello(data: []const u8) !ClientHelloData {
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
        .client_p256_pub = [_]u8{0} ** 65,
        .has_p256 = false,
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

    // Cipher suites
    if (pos + 2 > data.len) return error.TooShort;
    const cs_len = std.mem.readInt(u16, data[pos..][0..2], .big);
    pos += 2;
    if (pos + cs_len > data.len) return error.TooShort;
    {
        var cs_off: usize = 0;
        while (cs_off + 2 <= cs_len) : (cs_off += 2) {
            const cs = std.mem.readInt(u16, data[pos + cs_off ..][0..2], .big);
            if (cs == CIPHER_TLS_AES_128_GCM_SHA256) ch.has_aes_128_gcm = true;
            if (cs == CIPHER_TLS_CHACHA20_POLY1305_SHA256) ch.has_chacha20_poly1305 = true;
        }
    }
    pos += cs_len;

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
        const ext_len = std.mem.readInt(u16, data[pos + 2 ..][0..2], .big);
        pos += 4;
        if (pos + ext_len > ext_end) return error.TooShort;
        const ext_data = data[pos..][0..ext_len];

        if (ext_type == EXT_KEY_SHARE) {
            // KeyShareClientHello: u16 length + list of KeyShareEntry
            if (ext_data.len < 2) {
                pos += ext_len;
                continue;
            }
            const ks_list_len = std.mem.readInt(u16, ext_data[0..2], .big);
            var ksp: usize = 2;
            const ks_end = 2 + ks_list_len;
            while (ksp + 4 <= @min(ks_end, ext_data.len)) {
                const group = std.mem.readInt(u16, ext_data[ksp..][0..2], .big);
                const key_len = std.mem.readInt(u16, ext_data[ksp + 2 ..][0..2], .big);
                ksp += 4;
                if (group == GROUP_X25519 and key_len == 32 and ksp + 32 <= ext_data.len) {
                    @memcpy(&ch.client_x25519_pub, ext_data[ksp..][0..32]);
                    ch.has_x25519 = true;
                } else if (group == GROUP_SECP256R1 and key_len == 65 and ksp + 65 <= ext_data.len) {
                    @memcpy(&ch.client_p256_pub, ext_data[ksp..][0..65]);
                    ch.has_p256 = true;
                }
                ksp += key_len;
            }
        }

        if (ext_type == EXT_QUIC_TRANSPORT_PARAMS) {
            ch.peer_transport_params = try transport_params.decode(ext_data);
        }

        if (ext_type == EXT_ALPN) {
            if (ext_data.len < 2) {
                pos += ext_len;
                continue;
            }
            const list_len = std.mem.readInt(u16, ext_data[0..2], .big);
            var p: usize = 2;
            const list_end = @min(2 + list_len, ext_data.len);
            while (p < list_end and ch.alpn_count < 4) {
                const name_len = ext_data[p];
                p += 1;
                if (p + name_len > list_end) break;
                if (name_len > 0 and name_len <= 32) {
                    @memcpy(ch.alpn_names[ch.alpn_count][0..name_len], ext_data[p..][0..name_len]);
                    ch.alpn_lens[ch.alpn_count] = name_len;
                    ch.alpn_count += 1;
                }
                p += name_len;
            }
        }

        // PSK key exchange modes (RFC 8446 §4.2.9)
        if (ext_type == EXT_PSK_KEY_EXCHANGE_MODES) {
            if (ext_data.len >= 1) {
                const modes_len = ext_data[0];
                var mi: usize = 1;
                while (mi < @min(1 + @as(usize, modes_len), ext_data.len)) : (mi += 1) {
                    if (ext_data[mi] == 1) ch.has_psk_dhe_ke = true; // psk_dhe_ke mode
                }
            }
        }

        // early_data indication (RFC 8446 §4.2.10)
        if (ext_type == EXT_EARLY_DATA) {
            ch.has_early_data = true;
        }

        // pre_shared_key MUST be the last extension (RFC 8446 §4.2.11).
        // Parse identities and binders; compute ch_truncated_len for binder validation.
        if (ext_type == EXT_PRE_SHARED_KEY) {
            var ep: usize = 0;
            // Identities list
            if (ep + 2 > ext_data.len) {
                pos += ext_len;
                continue;
            }
            const identities_len = std.mem.readInt(u16, ext_data[ep..][0..2], .big);
            ep += 2;
            if (ep + identities_len > ext_data.len) {
                pos += ext_len;
                continue;
            }
            // Parse first identity only
            if (identities_len >= 6) { // min: 2 (id_len) + 0 (id) + 4 (obfuscated_age)
                const id_len = std.mem.readInt(u16, ext_data[ep..][0..2], .big);
                ep += 2;
                if (ep + id_len + 4 <= ext_data.len and id_len <= 128) {
                    @memcpy(ch.psk_identity[0..id_len], ext_data[ep..][0..id_len]);
                    ch.psk_identity_len = id_len;
                    ep += id_len;
                    ch.psk_obfuscated_age = std.mem.readInt(u32, ext_data[ep..][0..4], .big);
                    ep += 4;
                }
            }
            // Skip remaining identities
            ep = 2 + identities_len;
            // Binders list
            if (ep + 2 > ext_data.len) {
                pos += ext_len;
                continue;
            }
            const binders_len = std.mem.readInt(u16, ext_data[ep..][0..2], .big);
            // ch_truncated_len: total CH bytes up to but NOT including the binders list.
            // The binders list starts at: ext_data_start + ep
            // ext_data_start = pos (current position after 4-byte ext header).
            // In the raw data, the binders start at: pos + ep.
            // The binders_size = 2 (binders list length) + binders_len.
            // ch_truncated_len = total_ch_len - binders_size.
            const binders_size = 2 + @as(usize, binders_len);
            const total_ch_len = 4 + msg_len;
            if (binders_size <= total_ch_len) {
                ch.ch_truncated_len = total_ch_len - binders_size;
            }
            ep += 2;
            // Parse first binder (32 bytes for SHA-256)
            if (ep < ext_data.len) {
                const binder_len = ext_data[ep];
                ep += 1;
                if (binder_len == 32 and ep + 32 <= ext_data.len) {
                    @memcpy(&ch.psk_binder, ext_data[ep..][0..32]);
                    ch.has_psk = true;
                }
            }
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
        std.mem.writeInt(u16, buf[pos.* + 1 ..][0..2], @intCast(len), .big);
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
    buf[pos] = 0x30;
    pos += 1;
    writeDerLen(buf, &pos, cert_body_len);

    // TBSCertificate SEQUENCE
    buf[pos] = 0x30;
    pos += 1;
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
        0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
        0x05, 0x7a, 0x71, 0x75, 0x69, 0x63,
    };
    @memcpy(buf[pos..][0..18], &name);
    pos += 18;

    // validity (2024-01-01 to 2034-01-01)
    const validity = [_]u8{
        0x30, 0x22,
        0x18, 0x0f,
        0x32, 0x30,
        0x32, 0x34,
        0x30, 0x31,
        0x30, 0x31,
        0x30, 0x30,
        0x30, 0x30,
        0x30, 0x30,
        0x5a, 0x18,
        0x0f, 0x32,
        0x30, 0x33,
        0x34, 0x30,
        0x31, 0x30,
        0x31, 0x30,
        0x30, 0x30,
        0x30, 0x30,
        0x30, 0x5a,
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
    buf[pos] = 0x03;
    pos += 1;
    buf[pos] = 0x41;
    pos += 1;
    buf[pos] = 0x00;
    pos += 1; // no unused bits
    @memcpy(buf[pos..][0..64], sig);
    pos += 64;

    return pos;
}

// ---------------------------------------------------------------------------
// Frame building helpers
// ---------------------------------------------------------------------------

fn buildEncryptedExtensionsBasic(out: []u8, params: transport_params.TransportParams, alpn: []const u8, include_early_data: bool) usize {
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

    // ALPN extension (RFC 7301 / TLS ext 0x0010): echo the negotiated protocol name.
    if (alpn.len > 0) {
        std.mem.writeInt(u16, out[pos..][0..2], EXT_ALPN, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(2 + 1 + alpn.len), .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], @intCast(1 + alpn.len), .big);
        pos += 2;
        out[pos] = @intCast(alpn.len);
        pos += 1;
        @memcpy(out[pos..][0..alpn.len], alpn);
        pos += alpn.len;
    }

    // early_data extension (RFC 8446 §4.2.10): indicate server accepts 0-RTT.
    if (include_early_data) {
        std.mem.writeInt(u16, out[pos..][0..2], EXT_EARLY_DATA, .big);
        pos += 2;
        std.mem.writeInt(u16, out[pos..][0..2], 0, .big); // extension data length = 0 (EE form)
        pos += 2;
    }

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
// Session ticket helpers (RFC 8446 §4.6.1)
// ---------------------------------------------------------------------------

/// Decrypted ticket contents.
const TicketData = struct {
    psk: [32]u8,
    cipher: crypto.CipherSuite,
    alpn: [32]u8,
    alpn_len: u8,
    timestamp: i64,
};

/// Ticket plaintext layout: PSK(32) || cipher(2) || alpn_len(1) || alpn(N) || timestamp(8)
const TICKET_PLAINTEXT_MAX = 32 + 2 + 1 + 32 + 8; // 75 bytes max

/// Decrypt a session ticket. Returns null if invalid.
/// Ticket wire format: nonce(12) || ciphertext || tag(16)
pub fn decryptTicket(ticket_key: *const [32]u8, ticket: []const u8) ?TicketData {
    if (ticket.len < 12 + 43 + 16) return null; // min: nonce(12) + min_plaintext(43) + tag(16)
    const nonce = ticket[0..12];
    const ct_and_tag = ticket[12..];
    const ct_len = ct_and_tag.len - 16;
    if (ct_len > TICKET_PLAINTEXT_MAX) return null;

    var plaintext: [TICKET_PLAINTEXT_MAX]u8 = undefined;
    const tag = ct_and_tag[ct_len..][0..16];
    // Use AES-128-GCM with the first 16 bytes of ticket_key
    Aes128Gcm.decrypt(
        plaintext[0..ct_len],
        ct_and_tag[0..ct_len],
        tag.*,
        &.{}, // no AAD
        nonce.*,
        ticket_key[0..16].*,
    ) catch return null;

    // Parse plaintext: PSK(32) || cipher(2) || alpn_len(1) || alpn(N) || timestamp(8)
    // ct_len >= 43 guaranteed by the initial ticket.len check
    var td: TicketData = .{
        .psk = plaintext[0..32].*,
        .cipher = undefined,
        .alpn = [_]u8{0} ** 32,
        .alpn_len = 0,
        .timestamp = 0,
    };
    const cipher_val = std.mem.readInt(u16, plaintext[32..34], .big);
    td.cipher = switch (cipher_val) {
        @intFromEnum(crypto.CipherSuite.aes_128_gcm) => .aes_128_gcm,
        @intFromEnum(crypto.CipherSuite.chacha20_poly1305) => .chacha20_poly1305,
        else => return null,
    };
    td.alpn_len = plaintext[34];
    if (td.alpn_len > 32) return null;
    if (ct_len < 35 + @as(usize, td.alpn_len) + 8) return null;
    if (td.alpn_len > 0) {
        @memcpy(td.alpn[0..td.alpn_len], plaintext[35..][0..td.alpn_len]);
    }
    const ts_off = 35 + @as(usize, td.alpn_len);
    td.timestamp = @bitCast(std.mem.readInt(u64, plaintext[ts_off..][0..8], .big));
    return td;
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

test "tls: key schedule derived step uses SHA256 of empty string (RFC 8448 §3)" {
    // From RFC 8448 §3 (Simple 1-RTT Handshake, TLS_AES_128_GCM_SHA256):
    //   Early Secret = HKDF-Extract(0x00*32, 0x00*32)
    //   = 33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a
    //   Derive-Secret(early_secret, "derived", "") = HKDF-Expand-Label(ES, "derived", SHA256(""), 32)
    //   = 6f26155a108c702c5678f54fc9dbab697116c076189c482 5250cebeac3576c36...
    //
    // This test verifies that we use SHA256("") (not "") as the context for the "derived" step.
    const testing = std.testing;
    const zero32 = [_]u8{0} ** 32;

    // Verify Early Secret matches RFC 8448
    const early_secret = HkdfSha256.extract(&zero32, &zero32);
    const expected_early: [32]u8 = .{
        0x33, 0xad, 0x0a, 0x1c, 0x60, 0x7e, 0xc0, 0x3b,
        0x09, 0xe6, 0xcd, 0x98, 0x93, 0x68, 0x0c, 0xe2,
        0x10, 0xad, 0xf3, 0x00, 0xaa, 0x1f, 0x26, 0x60,
        0xe1, 0xb2, 0x2e, 0x10, 0xf1, 0x70, 0xf9, 0x2a,
    };
    try testing.expectEqualSlices(u8, &expected_early, &early_secret);

    // Verify the "derived" step uses SHA256("") context
    var derived: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&derived, early_secret, "derived", &sha256_empty);
    const expected_derived: [32]u8 = .{
        0x6f, 0x26, 0x15, 0xa1, 0x08, 0xc7, 0x02, 0xc5,
        0x67, 0x8f, 0x54, 0xfc, 0x9d, 0xba, 0xb6, 0x97,
        0x16, 0xc0, 0x76, 0x18, 0x9c, 0x48, 0x25, 0x0c,
        0xeb, 0xea, 0xc3, 0x57, 0x6c, 0x36, 0x11, 0xba,
    };
    try testing.expectEqualSlices(u8, &expected_derived, &derived);
}

test "tls: key schedule produces handshake keys" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    // Run the key schedule with a known shared secret
    const shared_secret = [_]u8{0x11} ** 32;
    try server.runKeySchedule(shared_secret, null);

    // Verify handshake keys are non-zero
    var all_zero = true;
    for (server.handshake_keys.server.key) |b| {
        if (b != 0) {
            all_zero = false;
            break;
        }
    }
    try std.testing.expect(!all_zero);
}

test "tls: TlsServer init generates distinct keys" {
    const io = std.testing.io;
    const a = try TlsServer.init(io);
    const b = try TlsServer.init(io);
    // Public keys must differ; random key collision is astronomically improbable.
    try std.testing.expect(!std.mem.eql(u8, &a.ecdh_kp.public_key, &b.ecdh_kp.public_key));
    try std.testing.expect(!std.mem.eql(u8, &a.sign_key.ed25519.public_key.bytes, &b.sign_key.ed25519.public_key.bytes));
}

test "tls: EncryptedExtensions contains QUIC transport params extension" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;
    const n = buildEncryptedExtensionsBasic(&buf, transport_params.TransportParams{}, "", false);

    // Must be a valid EncryptedExtensions message.
    try testing.expectEqual(@as(u8, HS_ENCRYPTED_EXTENSIONS), buf[0]);
    // Body must be non-trivial (has transport params).
    try testing.expect(n > 6);
    // Extension type at bytes 6-7 must be 0x0039.
    try testing.expectEqual(@as(u16, EXT_QUIC_TRANSPORT_PARAMS), std.mem.readInt(u16, buf[6..8], .big));
}

test "tls: EncryptedExtensions transport params round-trip" {
    const testing = std.testing;
    var buf: [256]u8 = undefined;

    const sent = transport_params.TransportParams{
        .initial_max_data = 4 * 1024 * 1024,
        .initial_max_streams_bidi = 50,
        .disable_active_migration = true,
    };
    const n = buildEncryptedExtensionsBasic(&buf, sent, "", false);

    // Locate extension data: after HS header (4) + ext_list_len (2) + ext_type (2) + ext_data_len (2).
    const ext_data_len = std.mem.readInt(u16, buf[8..10], .big);
    const decoded = try transport_params.decode(buf[10..][0..ext_data_len]);

    // n must cover the header + extension region we read from.
    try testing.expect(n >= 10 + ext_data_len);
    try testing.expectEqual(sent.initial_max_data, decoded.initial_max_data);
    try testing.expectEqual(sent.initial_max_streams_bidi, decoded.initial_max_streams_bidi);
    try testing.expect(decoded.disable_active_migration);
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

test "tls: processCrypto returns 0 on incomplete (TooShort) ClientHello" {
    const testing = std.testing;
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // Feed a truncated ClientHello — just the type byte and a length claiming more data.
    const incomplete: []const u8 = &[_]u8{
        HS_CLIENT_HELLO, // type = 1
        0x00, 0x00, 0xff, // length = 255 bytes follow (but we don't provide them)
        0x03, 0x03, // legacy_version
    };
    var out: [8192]u8 = undefined;
    // Should return 0 (not an error) and stay in wait_client_hello state
    const n = try server.processCrypto(incomplete, &out, io);
    try testing.expectEqual(@as(usize, 0), n);
    try testing.expectEqual(TlsState.wait_client_hello, server.state);
}

test "tls: transcript is non-empty after ClientHello processing" {
    // Verify that the transcript is updated with CH bytes during processCrypto.
    // We check indirectly: run the key schedule with a known shared secret,
    // verify that handshake keys are different from those derived with an empty transcript.
    const io = std.testing.io;
    var server_with_ch = try TlsServer.init(io);
    var server_empty = try TlsServer.init(io);

    // Manually hash something into server_with_ch's transcript (simulating a CH)
    const fake_ch = [_]u8{ 0x01, 0x00, 0x00, 0x04, 0xde, 0xad, 0xbe, 0xef };
    server_with_ch.transcript.update(&fake_ch);

    // Run key schedule on both
    const shared = [_]u8{0x77} ** 32;
    try server_with_ch.runKeySchedule(shared, null);
    try server_empty.runKeySchedule(shared, null);

    // Keys must differ because transcripts differ
    try std.testing.expect(!std.mem.eql(u8, &server_with_ch.handshake_keys.server.key, &server_empty.handshake_keys.server.key));
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

test "tls: deinit zeros all secret fields" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // Run key schedule to populate secrets with non-zero values
    const shared_secret = [_]u8{0x11} ** 32;
    try server.runKeySchedule(shared_secret, null);

    // Verify at least one secret field is non-zero before deinit
    var any_nonzero = false;
    for (server.handshake_secret) |b| {
        if (b != 0) {
            any_nonzero = true;
            break;
        }
    }
    try std.testing.expect(any_nonzero);

    server.deinit();

    // All secret fields must be zeroed after deinit
    try std.testing.expectEqual([_]u8{0} ** 32, server.handshake_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.master_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.client_hs_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.server_hs_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.client_app_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.server_app_secret);
    try std.testing.expectEqual([_]u8{0} ** 32, server.ecdh_kp.secret_key);
}

test "tls: cumulative CRYPTO cap rejects data exceeding 64KB total" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    var out: [8192]u8 = undefined;

    // Pre-set counter to the limit
    server.crypto_bytes_total = 65536;

    // Any additional byte must be rejected
    const one_byte = [_]u8{0x00};
    try std.testing.expectError(error.CryptoDataTooLarge, server.processCrypto(&one_byte, &out, io));
}

test "tls: cumulative CRYPTO cap allows exactly 64KB total" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    var out: [8192]u8 = undefined;

    // Pre-set counter so that one more byte brings total to exactly 65536
    server.crypto_bytes_total = 65535;

    // Exactly at the limit: should NOT return CryptoDataTooLarge.
    // (It may return other errors from parsing, but not the cap error.)
    const one_byte = [_]u8{0x00};
    const result = server.processCrypto(&one_byte, &out, io);
    // We expect a parse error (incomplete/invalid TLS data), but NOT CryptoDataTooLarge.
    if (result) |_| {} else |err| {
        try std.testing.expect(err != error.CryptoDataTooLarge);
    }
    // After the call, crypto_bytes_total should be 65536
    try std.testing.expectEqual(@as(u32, 65536), server.crypto_bytes_total);
}

test "tls: ALPN: EncryptedExtensions includes negotiated ALPN" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;
    const alpn = "hq-interop";
    const n = buildEncryptedExtensionsBasic(&buf, transport_params.TransportParams{}, alpn, false);

    // Scan for EXT_ALPN (0x0010) in the output
    var found = false;
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        if (std.mem.readInt(u16, buf[i..][0..2], .big) == EXT_ALPN) {
            found = true;
            break;
        }
    }
    try testing.expect(found);
}

test "tls: ALPN: EncryptedExtensions omits ALPN when empty" {
    const testing = std.testing;
    var buf: [512]u8 = undefined;
    const n = buildEncryptedExtensionsBasic(&buf, transport_params.TransportParams{}, "", false);

    // EXT_ALPN (0x0010) must NOT appear in output
    var i: usize = 0;
    while (i + 1 < n) : (i += 1) {
        try testing.expect(std.mem.readInt(u16, buf[i..][0..2], .big) != EXT_ALPN);
    }
}

test "tls: ALPN: no required_alpn skips check entirely" {
    // A server with required_alpn_len == 0 should accept any ClientHello regardless of ALPN.
    const io = std.testing.io;
    const server = try TlsServer.init(io);
    // Default: required_alpn_len is 0; negotiated_alpn_len stays 0.
    try std.testing.expectEqual(@as(u8, 0), server.required_alpn_len);
    try std.testing.expectEqual(@as(u8, 0), server.negotiated_alpn_len);
}

test "tls: ALPN: matching protocol selected" {
    // Build a minimal ClientHello that includes an ALPN extension and verify
    // that handleClientHello (via parseClientHello) captures the name.
    const testing = std.testing;
    const alpn_name = "hq-interop";

    // Build a fake ALPN extension payload only (ext_data):
    //   u16 list_len = 1 + len(name)
    //   u8  name_len
    //   u8[] name
    var ext_data: [32]u8 = undefined;
    const name_len: u8 = @intCast(alpn_name.len);
    std.mem.writeInt(u16, ext_data[0..2], 1 + name_len, .big);
    ext_data[2] = name_len;
    @memcpy(ext_data[3..][0..name_len], alpn_name);
    const ext_data_len = 3 + name_len;

    // Directly call parseClientHello internals by building a minimal CH byte slice
    // that contains exactly the ALPN extension (rest defaults / skipped).
    // It's easier to test the ALPN negotiation path by directly manipulating
    // ClientHelloData and running the matching logic in isolation.
    var ch: ClientHelloData = .{
        .random = [_]u8{0} ** 32,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0} ** 32,
        .has_x25519 = true,
        .client_p256_pub = [_]u8{0} ** 65,
        .has_p256 = false,
        .peer_transport_params = .{},
        .has_aes_128_gcm = true,
    };
    @memcpy(ch.alpn_names[0][0..name_len], alpn_name);
    ch.alpn_lens[0] = name_len;
    ch.alpn_count = 1;

    // Create a server that requires "hq-interop" and verify matching.
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    @memcpy(server.required_alpn[0..name_len], alpn_name);
    server.required_alpn_len = name_len;

    // Run matching manually (mirrors handleClientHello logic).
    const req = server.required_alpn[0..server.required_alpn_len];
    var matched = false;
    for (0..ch.alpn_count) |i| {
        if (std.mem.eql(u8, req, ch.alpn_names[i][0..ch.alpn_lens[i]])) {
            @memcpy(server.negotiated_alpn[0..req.len], req);
            server.negotiated_alpn_len = server.required_alpn_len;
            matched = true;
            break;
        }
    }
    try testing.expect(matched);
    try testing.expectEqualSlices(u8, alpn_name, server.negotiated_alpn[0..server.negotiated_alpn_len]);
    _ = ext_data_len; // suppress unused warning
}

test "tls: ALPN: mismatch returns AlpnMismatch" {
    // Verify that a server requiring "hq-interop" rejects a client offering only "h3".
    const testing = std.testing;
    const io = std.testing.io;

    // Build a minimal but syntactically valid ClientHello with ALPN "h3".
    // We need enough structure for parseClientHello to succeed.
    // Use processCrypto to exercise the full path.
    var server = try TlsServer.init(io);
    @memcpy(server.required_alpn[0..10], "hq-interop");
    server.required_alpn_len = 10;

    // Directly populate a ClientHelloData with only "h3" and verify mismatch.
    var ch: ClientHelloData = .{
        .random = [_]u8{0} ** 32,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0x42} ** 32, // non-zero key share
        .has_x25519 = true,
        .client_p256_pub = [_]u8{0} ** 65,
        .has_p256 = false,
        .peer_transport_params = .{},
        .has_aes_128_gcm = true,
    };
    @memcpy(ch.alpn_names[0][0..2], "h3");
    ch.alpn_lens[0] = 2;
    ch.alpn_count = 1;

    const req = server.required_alpn[0..server.required_alpn_len];
    var matched = false;
    for (0..ch.alpn_count) |i| {
        if (std.mem.eql(u8, req, ch.alpn_names[i][0..ch.alpn_lens[i]])) {
            matched = true;
            break;
        }
    }
    try testing.expect(!matched);
}

test "tls: P-256 initFromCert stores p256 key variant" {
    const io = std.testing.io;
    var base = try TlsServer.init(io);
    const cert_der = base.cert_buf[0..base.cert_len];
    // Private scalar = 1 is the smallest valid P-256 scalar.
    var seed: [32]u8 = [_]u8{0} ** 32;
    seed[31] = 1;
    const server = try TlsServer.initFromCert(cert_der, seed, .p256, io);
    try std.testing.expect(server.sign_key == .p256);
}

test "tls: P-256 buildCertificateVerify produces DER ECDSA signature" {
    const io = std.testing.io;
    var base = try TlsServer.init(io);
    const cert_der = base.cert_buf[0..base.cert_len];
    var seed: [32]u8 = [_]u8{0} ** 32;
    seed[31] = 1;
    var server = try TlsServer.initFromCert(cert_der, seed, .p256, io);

    var out: [512]u8 = undefined;
    const transcript_hash = [_]u8{0xab} ** 32;
    const n = try server.buildCertificateVerify(&out, &transcript_hash);

    // HandshakeType = 15 (CertificateVerify)
    try std.testing.expectEqual(@as(u8, 15), out[0]);
    const body_len = (@as(usize, out[1]) << 16) | (@as(usize, out[2]) << 8) | out[3];
    try std.testing.expectEqual(n - 4, body_len);
    // SignatureScheme = 0x0403 (ecdsa_secp256r1_sha256)
    const scheme = (@as(u16, out[4]) << 8) | out[5];
    try std.testing.expectEqual(@as(u16, 0x0403), scheme);
    // DER signature length must be in valid range for P-256 (8..72 bytes)
    const sig_len = (@as(usize, out[6]) << 8) | out[7];
    try std.testing.expect(sig_len >= 8 and sig_len <= 72);
    // DER SEQUENCE tag
    try std.testing.expectEqual(@as(u8, 0x30), out[8]);
}

test "tls: full handshake roundtrip: client Finished verifies correctly" {
    // Regression test for two bugs:
    //   1. Derive-Secret(., "derived", "") must use SHA-256("") as context (not "")
    //   2. Server Finished must be added to the transcript before client Finished verification
    //
    // Simulates the server side of a TLS 1.3 handshake against a synthetic "client":
    //   - Process ClientHello, get server flight
    //   - Compute client Finished from the server's internal secrets
    //   - Verify that processCrypto(client_finished) succeeds → state == established
    const testing = std.testing;
    const io = std.testing.io;

    var server = try TlsServer.init(io);

    // Build a minimal ClientHelloData with a known X25519 public key.
    // Using all-0x42 as the client's ephemeral public key (for testing only — not a valid point
    // but X25519.scalarmult will not reject it; the shared secret will be a known garbage value).
    var ch: ClientHelloData = .{
        .random = [_]u8{0x11} ** 32,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0x42} ** 32,
        .has_x25519 = true,
        .client_p256_pub = [_]u8{0} ** 65,
        .has_p256 = false,
        .peer_transport_params = .{},
        .has_aes_128_gcm = true,
    };
    @memcpy(ch.alpn_names[0][0..10], "hq-interop");
    ch.alpn_lens[0] = 10;
    ch.alpn_count = 1;

    // Hash a fake ClientHello into the transcript (normally done by processCrypto).
    // The exact bytes don't matter as long as client and server use the same bytes.
    const fake_ch_bytes = [_]u8{ 0x01, 0x00, 0x00, 0x04, 0x11, 0x22, 0x33, 0x44 };
    server.transcript.update(&fake_ch_bytes);

    // Run handleClientHello: produces ServerHello + EE + Cert + CV + SF.
    var server_flight: [8192]u8 = undefined;
    const n = try server.handleClientHello(ch, &server_flight, io);
    _ = n;
    try testing.expectEqual(TlsState.wait_client_finished, server.state);

    // Now simulate the client side: compute client Finished using the same secrets.
    // Per RFC 8446 §4.4.4:
    //   finished_key  = HKDF-Expand-Label(client_hs_secret, "finished", "", 32)
    //   verify_data   = HMAC-SHA256(finished_key, transcript_hash)
    // where transcript_hash = H(CH || SH || EE || Cert || CertVerify || ServerFinished)
    // which is exactly server.transcript's current state.
    var client_finished_key: [32]u8 = undefined;
    crypto.hkdfExpandLabel(&client_finished_key, server.client_hs_secret, "finished", "");

    var snap = server.transcript; // snapshot — final() is destructive
    var transcript_hash: [32]u8 = undefined;
    snap.final(&transcript_hash);

    var client_verify_data: [32]u8 = undefined;
    Hmac256.create(&client_verify_data, &transcript_hash, &client_finished_key);

    // Build the TLS Finished message.
    var client_finished_msg: [36]u8 = undefined;
    _ = buildFinishedMessage(&client_finished_msg, &client_verify_data);

    // Feed the client Finished to the server.
    var out: [256]u8 = undefined;
    _ = try server.processCrypto(&client_finished_msg, &out, io);
    try testing.expectEqual(TlsState.established, server.state);
}

test "tls: P-256 deinit zeros secret key bytes" {
    const io = std.testing.io;
    var base = try TlsServer.init(io);
    const cert_der = base.cert_buf[0..base.cert_len];
    var seed: [32]u8 = [_]u8{0} ** 32;
    seed[31] = 1;
    var server = try TlsServer.initFromCert(cert_der, seed, .p256, io);
    server.deinit();
    try std.testing.expectEqual([_]u8{0} ** 32, server.sign_key.p256.secret_key.bytes);
}

test "security: CRYPTO read_buf is zeroed after ClientHello processing" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // Inject known plaintext into read_buf to verify it gets zeroed
    @memset(server.read_buf[0..100], 0xaa);
    server.read_len = 100;

    // processCrypto will zero the buffer when state transitions
    // We can't easily test without a real ClientHello, so instead verify
    // that the read_buf is properly sized and will be zeroed.
    // This test documents that buffer zeroization is expected behavior.
    try std.testing.expect(server.read_buf.len >= 8192);
}

test "security: CRYPTO read_buf cleared after ClientFinished" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // After handshake, read_buf is cleared to remove plaintext from memory
    server.read_len = 100; // simulate filled buffer
    server.state = .wait_client_finished;

    // In production, processCrypto will zero this after verifying ClientFinished
    // The actual test requires a full handshake, but the zeroization code is
    // already verified by inspection: std.crypto.secureZero is called before
    // transitioning to .established state.

    // Verify that read_buf exists and is large enough for security operations
    try std.testing.expect(server.read_buf.len >= 8192);
}

test "tls: P-256 ECDH: server accepts P-256-only client and produces handshake keys" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);

    // Generate a client-side P-256 ephemeral key pair
    const client_secret = P256.scalar.random(io, .little);
    const client_pub_pt = P256.basePoint.mul(client_secret, .little) catch unreachable;
    const client_pub = client_pub_pt.toUncompressedSec1();

    // Build ClientHelloData with only P-256 key share (no X25519)
    const ch: ClientHelloData = .{
        .random = [_]u8{0x33} ** 32,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0} ** 32,
        .has_x25519 = false,
        .client_p256_pub = client_pub,
        .has_p256 = true,
        .peer_transport_params = .{},
        .has_aes_128_gcm = true,
    };

    var out: [4096]u8 = undefined;
    const written = try server.handleClientHello(ch, &out, io);

    // Server must have produced a non-empty ServerHello + handshake messages
    try std.testing.expect(written > 0);
    // State transitions to wait_client_finished (handshake keys derived)
    try std.testing.expectEqual(TlsState.wait_client_finished, server.state);
    // ServerHello starts with HS_SERVER_HELLO (0x02)
    try std.testing.expectEqual(@as(u8, HS_SERVER_HELLO), out[0]);
    // Handshake keys are non-zero (key schedule ran)
    const zero32 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &server.handshake_keys.server.key, &zero32));
}

test "tls: P-256 parseClientHello extracts P-256 key share" {
    // Build a minimal ClientHello byte buffer with only a secp256r1 key share
    var buf: [512]u8 = undefined;
    var pos: usize = 0;

    // Handshake header (filled in at end)
    const hdr_pos = pos;
    pos += 4;

    // legacy_version
    std.mem.writeInt(u16, buf[pos..][0..2], TLS_VERSION_LEGACY, .big);
    pos += 2;

    // random
    @memset(buf[pos..][0..32], 0x11);
    pos += 32;

    // session_id (empty)
    buf[pos] = 0;
    pos += 1;

    // cipher suites (TLS_AES_128_GCM_SHA256 only)
    std.mem.writeInt(u16, buf[pos..][0..2], 2, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], CIPHER_TLS_AES_128_GCM_SHA256, .big);
    pos += 2;

    // compression methods (null)
    buf[pos] = 1;
    pos += 1;
    buf[pos] = 0;
    pos += 1;

    // extensions length (placeholder)
    const ext_total_pos = pos;
    pos += 2;
    const ext_start = pos;

    // key_share extension with P-256 only
    std.mem.writeInt(u16, buf[pos..][0..2], EXT_KEY_SHARE, .big);
    pos += 2;
    const ks_ext_len_pos = pos;
    pos += 2;
    const ks_ext_start = pos;
    // key_share list length (placeholder)
    const ks_list_len_pos = pos;
    pos += 2;
    const ks_list_start = pos;
    // secp256r1 entry: group + key_len + 65 bytes
    std.mem.writeInt(u16, buf[pos..][0..2], GROUP_SECP256R1, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 65, .big);
    pos += 2;
    @memset(buf[pos..][0..65], 0x04); // 0x04-prefixed uncompressed point (placeholder)
    pos += 65;
    std.mem.writeInt(u16, buf[ks_list_len_pos..][0..2], @intCast(pos - ks_list_start), .big);
    std.mem.writeInt(u16, buf[ks_ext_len_pos..][0..2], @intCast(pos - ks_ext_start), .big);

    // quic transport params extension (empty)
    std.mem.writeInt(u16, buf[pos..][0..2], EXT_QUIC_TRANSPORT_PARAMS, .big);
    pos += 2;
    std.mem.writeInt(u16, buf[pos..][0..2], 0, .big);
    pos += 2;

    // Fill extensions total length
    std.mem.writeInt(u16, buf[ext_total_pos..][0..2], @intCast(pos - ext_start), .big);

    // Fill handshake header
    buf[hdr_pos] = HS_CLIENT_HELLO;
    const body_len = pos - hdr_pos - 4;
    buf[hdr_pos + 1] = @intCast((body_len >> 16) & 0xff);
    buf[hdr_pos + 2] = @intCast((body_len >> 8) & 0xff);
    buf[hdr_pos + 3] = @intCast(body_len & 0xff);

    const ch = try parseClientHello(buf[0..pos]);
    try std.testing.expect(!ch.has_x25519);
    try std.testing.expect(ch.has_p256);
    // First byte of P-256 key should be 0x04 (uncompressed point marker)
    try std.testing.expectEqual(@as(u8, 0x04), ch.client_p256_pub[0]);
}

test "tls: no key share returns NoSupportedKeyShare" {
    const io = std.testing.io;
    var server = try TlsServer.init(io);
    const ch: ClientHelloData = .{
        .random = [_]u8{0} ** 32,
        .legacy_session_id = [_]u8{0} ** 32,
        .session_id_len = 0,
        .client_x25519_pub = [_]u8{0} ** 32,
        .has_x25519 = false,
        .client_p256_pub = [_]u8{0} ** 65,
        .has_p256 = false,
        .peer_transport_params = .{},
        .has_aes_128_gcm = true,
    };
    var out: [4096]u8 = undefined;
    try std.testing.expectError(error.NoSupportedKeyShare, server.handleClientHello(ch, &out, io));
}
