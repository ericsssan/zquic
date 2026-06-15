//! Packet-level test client for driving QUIC handshakes and data transfer
//! against a real Connection instance.
//!
//! TestClient wraps TlsClient (tls_client.zig) with QUIC packet encryption,
//! header protection, and frame encoding — everything needed to act as a real
//! QUIC client without sockets or threads.

const std = @import("std");
const crypto = @import("crypto.zig");
const packet = @import("packet.zig");
const frame = @import("frame.zig");
const varint = @import("varint.zig");
const tls = @import("tls.zig");
const tls_client = @import("tls_client.zig");
const TlsClient = tls_client.TlsClient;
const cid_mod = @import("connection_id.zig");

const CID_LEN = cid_mod.len;

/// Maximum received stream data buffer.
const MAX_STREAM_DATA = 1024 * 1024 + 4096;
/// Maximum number of tracked streams.
const MAX_STREAMS = 8;

const RecvStream = struct {
    stream_id: u62,
    data: [MAX_STREAM_DATA]u8,
    len: usize,
    fin: bool,
    active: bool,
};

pub const TestClient = struct {
    tls: TlsClient,
    /// DCID used in the first Initial packet (server's CID before handshake).
    initial_dcid: [CID_LEN]u8,
    /// Server's SCID extracted from its Initial response (used as DCID for
    /// Handshake and 1-RTT packets).
    server_scid: [CID_LEN]u8,
    server_scid_valid: bool,
    /// Our SCID sent in the first Initial.
    client_scid: [CID_LEN]u8,
    initial_keys: crypto.InitialKeys,
    /// Per-epoch TX packet number.
    tx_pn: [3]u64,
    /// Saved Initial plaintext for retransmit (CRYPTO frame + padding).
    saved_initial_pt: [1200]u8,
    saved_initial_pt_len: usize,
    /// Largest received 1-RTT packet number (for ACK generation).
    largest_rx_pn: u64,
    /// Received stream data buffers.
    recv_streams: [MAX_STREAMS]RecvStream,
    /// True if a CONNECTION_CLOSE frame was received.
    received_close: bool,
    /// Error code from the received CONNECTION_CLOSE frame.
    close_error_code: u62,

    pub fn init(server_dcid_bytes: [CID_LEN]u8, io: std.Io) TestClient {
        var client_scid: [CID_LEN]u8 = undefined;
        io.random(&client_scid);
        return .{
            .tls = TlsClient.init(io),
            .initial_dcid = server_dcid_bytes,
            .server_scid = @as([CID_LEN]u8, @splat(0)),
            .server_scid_valid = false,
            .client_scid = client_scid,
            .initial_keys = crypto.deriveInitialKeys(&server_dcid_bytes, packet.QUIC_VERSION_1),
            .tx_pn = .{ 0, 0, 0 },
            .saved_initial_pt = undefined,
            .saved_initial_pt_len = 0,
            .largest_rx_pn = 0,
            .recv_streams = @as([MAX_STREAMS]RecvStream, @splat(.{
                .stream_id = 0,
                .data = undefined,
                .len = 0,
                .fin = false,
                .active = false,
            })),
            .received_close = false,
            .close_error_code = 0,
        };
    }

    // -----------------------------------------------------------------------
    // Build packets
    // -----------------------------------------------------------------------

    /// Build an Initial packet containing a CRYPTO frame with the ClientHello.
    /// Padded to >= 1200 bytes per RFC 9000 §14.1.  Returns bytes written.
    /// Saves plaintext for retransmit via `retransmitInitial()`.
    pub fn buildInitialWithClientHello(self: *TestClient, out: []u8) usize {
        // 1. Build ClientHello TLS message
        var ch_buf: [1024]u8 = undefined;
        const ch_len = self.tls.buildClientHello(&ch_buf);

        // 2. Encode CRYPTO frame
        var pt_len = frame.encodeFrame(&self.saved_initial_pt, .{ .crypto = .{
            .offset = 0,
            .data = ch_buf[0..ch_len],
        } });

        // 3. Pad to make total datagram >= 1200 bytes
        // Header overhead: 1+4+1+8+1+8+1+2+4 = 30 bytes, tag = 16
        const overhead = 30 + 16;
        const min_pt = if (1200 > overhead) 1200 - overhead else 0;
        if (pt_len < min_pt) {
            @memset(self.saved_initial_pt[pt_len..min_pt], 0x00);
            pt_len = min_pt;
        }
        self.saved_initial_pt_len = pt_len;

        return self.encryptInitial(out, self.saved_initial_pt[0..pt_len]);
    }

    /// Re-encrypt the saved Initial plaintext with a fresh packet number.
    /// Used for retransmit when the first Initial is lost.
    pub fn retransmitInitial(self: *TestClient, out: []u8) usize {
        return self.encryptInitial(out, self.saved_initial_pt[0..self.saved_initial_pt_len]);
    }

    /// Build a Handshake packet containing a CRYPTO frame with the client
    /// Finished message.  Returns bytes written.
    pub fn buildHandshakeWithFinished(self: *TestClient, out: []u8) usize {
        var fin_buf: [36]u8 = undefined;
        const fin_len = self.tls.buildClientFinished(&fin_buf);

        var plaintext: [256]u8 = undefined;
        const pt_len = frame.encodeFrame(&plaintext, .{ .crypto = .{
            .offset = 0,
            .data = fin_buf[0..fin_len],
        } });

        return self.encryptHandshake(out, plaintext[0..pt_len]);
    }

    /// Build a 1-RTT (short header) packet containing a STREAM frame.
    /// Returns bytes written.
    pub fn buildShortHeaderWithStream(
        self: *TestClient,
        out: []u8,
        stream_id: u62,
        data: []const u8,
        fin: bool,
    ) usize {
        var plaintext: [1500]u8 = undefined;
        const pt_len = frame.encodeFrame(&plaintext, .{ .stream = .{
            .stream_id = stream_id,
            .offset = 0,
            .fin = fin,
            .data = data,
        } });

        return self.encrypt1Rtt(out, plaintext[0..pt_len]);
    }

    /// Build a 1-RTT MAX_STREAM_DATA frame to allow the server to send more data.
    pub fn buildMaxStreamData(self: *TestClient, out: []u8, stream_id: u62, max_data: u62) usize {
        var plaintext: [64]u8 = undefined;
        const pt_len = frame.encodeFrame(&plaintext, .{ .max_stream_data = .{
            .stream_id = stream_id,
            .max_data = max_data,
        } });
        return self.encrypt1Rtt(out, plaintext[0..pt_len]);
    }

    /// Build a 1-RTT ACK packet for the given largest packet number.
    pub fn buildAck(self: *TestClient, out: []u8, largest_pn: u62) usize {
        var plaintext: [128]u8 = undefined;
        var ranges: [32]frame.AckRange = @as([32]frame.AckRange, @splat(.{ .gap = 0, .ack_range = 0 }));
        ranges[0] = .{ .gap = 0, .ack_range = largest_pn };
        const pt_len = frame.encodeFrame(&plaintext, .{ .ack = .{
            .largest_acked = largest_pn,
            .ack_delay = 0,
            .ranges = ranges,
            .range_count = 1,
            .ect0 = 0,
            .ect1 = 0,
            .ecn_ce = 0,
            .has_ecn = false,
        } });

        return self.encrypt1Rtt(out, plaintext[0..pt_len]);
    }

    // -----------------------------------------------------------------------
    // Process server datagrams
    // -----------------------------------------------------------------------

    /// Process a UDP datagram from the server (may contain coalesced packets).
    /// Silently ignores corrupted or malformed packets.
    pub fn processServerDatagram(self: *TestClient, data: []u8) !void {
        var offset: usize = 0;
        while (offset < data.len) {
            if (data[offset] == 0) break; // trailing padding
            if (data[offset] & 0x80 != 0) {
                // Long header packet
                const consumed = self.processLongHeaderPacket(data[offset..]) catch break;
                if (consumed == 0) break;
                offset += consumed;
            } else if (data[offset] & 0x40 != 0) {
                // Short header (1-RTT) — process rest of datagram as one packet
                self.processShortHeaderPacket(data[offset..]) catch {};
                break;
            } else {
                break; // invalid
            }
        }
    }

    /// Return received data for a stream, or null if no data yet.
    pub fn receivedStreamData(self: *const TestClient, stream_id: u62) ?struct { data: []const u8, fin: bool } {
        for (&self.recv_streams) |*rs| {
            if (rs.active and rs.stream_id == stream_id and rs.len > 0) {
                return .{ .data = rs.data[0..rs.len], .fin = rs.fin };
            }
        }
        return null;
    }

    /// Total bytes received across all streams.
    pub fn totalReceivedBytes(self: *const TestClient) usize {
        var total: usize = 0;
        for (&self.recv_streams) |*rs| {
            if (rs.active) total += rs.len;
        }
        return total;
    }

    fn processLongHeaderPacket(self: *TestClient, data: []u8) !usize {
        if (data.len < 7) return error.TooShort;

        // Sanity-check CID lengths before any arithmetic (corrupted packets may
        // have huge dcid_len/scid_len that cause integer overflow in packet.zig).
        const dcid_len: usize = data[5];
        if (dcid_len > 20) return error.TooShort; // RFC 9000 §17.2: max CID = 20
        if (6 + dcid_len + 1 > data.len) return error.TooShort;
        const scid_len: usize = data[6 + dcid_len];
        if (scid_len > 20) return error.TooShort;
        if (7 + dcid_len + scid_len > data.len) return error.TooShort;

        // Packet type from unmasked bits 5-4 (HP only masks bits 0-3 for long headers)
        const pkt_type = packet.longHeaderType(data[0], packet.QUIC_VERSION_1);

        // Extract server SCID from Initial response
        if (pkt_type == .initial and !self.server_scid_valid) {
            if (scid_len == CID_LEN) {
                @memcpy(&self.server_scid, data[7 + dcid_len ..][0..CID_LEN]);
                self.server_scid_valid = true;
            }
        }

        // Find PN offset (works on protected packets — type bits are unmasked)
        const pn_offset = packet.longHeaderPnOffset(data, packet.QUIC_VERSION_1) catch
            return error.TooShort;

        // Parse Length varint to determine total packet size
        // Re-walk header to find the Length field position (reuse dcid_len/scid_len from above)
        var pos: usize = 5; // past first_byte + version
        pos += 1 + dcid_len;
        pos += 1 + scid_len;
        if (pkt_type == .initial) {
            const tr = varint.decode(data[pos..]) orelse return error.TooShort;
            pos += tr.len + @as(usize, @intCast(tr.value));
        }
        const lr = varint.decode(data[pos..]) orelse return error.TooShort;
        pos += lr.len;
        const payload_length: usize = @intCast(lr.value);
        const total_len = pn_offset + payload_length;
        if (total_len > data.len) return error.TooShort;

        // Select decryption keys
        const keys: crypto.PacketKeys = switch (pkt_type) {
            .initial => self.initial_keys.server,
            .handshake => blk: {
                if (self.tls.state != .wait_encrypted and self.tls.state != .established)
                    return error.NoHandshakeKeys;
                break :blk self.tls.handshake_keys.server;
            },
            else => return error.UnexpectedPacketType,
        };

        // HP sample at pn_offset + 4
        if (pn_offset + 4 + 16 > total_len) return error.TooShort;

        // Remove header protection
        const pn_len = crypto.removeHeaderProtection(
            keys,
            &data[0],
            data[pn_offset..][0..4],
            data[pn_offset + 4 ..][0..16],
        );

        // Decode packet number
        const truncated_pn = decodePnBytes(data[pn_offset..], pn_len);
        const full_pn = packet.decodePacketNumber(0, truncated_pn, pn_len * 8);

        // Decrypt payload
        const encrypted_start = pn_offset + pn_len;
        const encrypted_len = payload_length - pn_len;
        const header = data[0..encrypted_start];
        const pt_len = try crypto.decryptPayloadInPlace(
            keys,
            full_pn,
            header,
            data[encrypted_start..][0..encrypted_len],
        );

        // Parse frames and extract CRYPTO data
        const plaintext = data[encrypted_start..][0..pt_len];
        try self.processFrames(@as(?packet.PacketType, pkt_type), plaintext);

        return total_len;
    }

    fn processShortHeaderPacket(self: *TestClient, data: []u8) !void {
        if (self.tls.state != .established) return error.NotEstablished;

        const pn_offset = packet.shortHeaderPnOffset(CID_LEN);
        if (pn_offset + 4 + 16 > data.len) return error.TooShort;

        const keys = self.tls.app_keys.server;

        // Remove header protection
        const pn_len = crypto.removeHeaderProtection(
            keys,
            &data[0],
            data[pn_offset..][0..4],
            data[pn_offset + 4 ..][0..16],
        );

        // Decode packet number
        const truncated_pn = decodePnBytes(data[pn_offset..], pn_len);
        const full_pn = packet.decodePacketNumber(self.largest_rx_pn, truncated_pn, pn_len * 8);
        if (full_pn > self.largest_rx_pn) self.largest_rx_pn = full_pn;

        // Decrypt payload (everything after header)
        const encrypted_start = pn_offset + pn_len;
        const encrypted_len = data.len - encrypted_start;
        const header = data[0..encrypted_start];

        const pt_len = try crypto.decryptPayloadInPlace(
            keys,
            full_pn,
            header,
            data[encrypted_start..][0..encrypted_len],
        );

        try self.processFrames(null, data[encrypted_start..][0..pt_len]);
    }

    fn processFrames(self: *TestClient, pkt_type: ?packet.PacketType, plaintext: []const u8) !void {
        var fpos: usize = 0;
        while (fpos < plaintext.len) {
            const result = frame.parseFrame(plaintext[fpos..]) catch break;
            fpos += result.consumed;

            switch (result.frame) {
                .crypto => |cf| {
                    if (pkt_type) |pt| switch (pt) {
                        .initial => try self.tls.processServerHello(cf.data),
                        .handshake => _ = try self.tls.processHandshakeMessages(cf.data),
                        else => {},
                    };
                },
                .stream => |sf| self.bufferStreamData(sf),
                .connection_close => |cc| {
                    self.received_close = true;
                    self.close_error_code = cc.error_code;
                },
                else => {},
            }
        }
    }

    fn bufferStreamData(self: *TestClient, sf: frame.StreamFrame) void {
        // Find or allocate a receive buffer for this stream
        var slot: ?*RecvStream = null;
        for (&self.recv_streams) |*rs| {
            if (rs.active and rs.stream_id == sf.stream_id) {
                slot = rs;
                break;
            }
        }
        if (slot == null) {
            for (&self.recv_streams) |*rs| {
                if (!rs.active) {
                    rs.active = true;
                    rs.stream_id = sf.stream_id;
                    rs.len = 0;
                    rs.fin = false;
                    slot = rs;
                    break;
                }
            }
        }
        const rs = slot orelse return; // no free slots

        // Append data at the given offset
        const offset: usize = @intCast(sf.offset);
        const end = offset + sf.data.len;
        if (end > MAX_STREAM_DATA) return; // overflow
        @memcpy(rs.data[offset..end], sf.data);
        if (end > rs.len) rs.len = end;
        if (sf.fin) rs.fin = true;
    }

    // -----------------------------------------------------------------------
    // Encryption helpers
    // -----------------------------------------------------------------------

    fn encryptInitial(self: *TestClient, out: []u8, plaintext: []const u8) usize {
        const pn = self.tx_pn[0];
        self.tx_pn[0] += 1;
        const ct_len = plaintext.len + 16;

        const hdr_len = packet.encodeLongHeader(
            out,
            .initial,
            packet.QUIC_VERSION_1,
            &self.initial_dcid,
            &self.client_scid,
            &.{},
            @intCast(pn),
            ct_len,
        );

        crypto.encryptPayload(self.initial_keys.client, pn, out[0..hdr_len], plaintext, out[hdr_len..][0..ct_len]);
        crypto.applyHeaderProtection(self.initial_keys.client, &out[0], out[hdr_len - 4 ..][0..4], out[hdr_len..][0..16]);

        return hdr_len + ct_len;
    }

    fn encryptHandshake(self: *TestClient, out: []u8, plaintext: []const u8) usize {
        const pn = self.tx_pn[1];
        self.tx_pn[1] += 1;
        const ct_len = plaintext.len + 16;
        const dcid = if (self.server_scid_valid) &self.server_scid else &self.initial_dcid;

        const hdr_len = packet.encodeLongHeader(
            out,
            .handshake,
            packet.QUIC_VERSION_1,
            dcid,
            &self.client_scid,
            &.{},
            @intCast(pn),
            ct_len,
        );

        const hs_keys = self.tls.handshake_keys;
        crypto.encryptPayload(hs_keys.client, pn, out[0..hdr_len], plaintext, out[hdr_len..][0..ct_len]);
        crypto.applyHeaderProtection(hs_keys.client, &out[0], out[hdr_len - 4 ..][0..4], out[hdr_len..][0..16]);

        return hdr_len + ct_len;
    }

    fn encrypt1Rtt(self: *TestClient, out: []u8, plaintext: []const u8) usize {
        const pn = self.tx_pn[2];
        self.tx_pn[2] += 1;
        const ct_len = plaintext.len + 16;
        const dcid = if (self.server_scid_valid) &self.server_scid else &self.initial_dcid;

        const hdr_len = packet.encodeShortHeader(out, dcid, @intCast(pn), false);

        const app_keys = self.tls.app_keys;
        crypto.encryptPayload(app_keys.client, pn, out[0..hdr_len], plaintext, out[hdr_len..][0..ct_len]);

        const pn_offset = packet.shortHeaderPnOffset(CID_LEN);
        crypto.applyHeaderProtection(app_keys.client, &out[0], out[pn_offset..][0..4], out[pn_offset + 4 ..][0..16]);

        return hdr_len + ct_len;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn decodePnBytes(buf: []const u8, pn_len: u8) u32 {
        var pn: u32 = 0;
        switch (pn_len) {
            1 => pn = buf[0],
            2 => pn = (@as(u32, buf[0]) << 8) | buf[1],
            3 => pn = (@as(u32, buf[0]) << 16) | (@as(u32, buf[1]) << 8) | buf[2],
            4 => pn = (@as(u32, buf[0]) << 24) | (@as(u32, buf[1]) << 16) | (@as(u32, buf[2]) << 8) | buf[3],
            else => unreachable,
        }
        return pn;
    }
};
