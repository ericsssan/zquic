// HTTP/3 connection state — RFC 9114
//
// Connection wires together all layers of the stack:
//
//   QPACK encode/decode  (static-only; dynamic table is future work)
//   Control stream       SETTINGS exchange, MAX_PUSH_ID, GOAWAY processing
//   Request streams      HEADERS+DATA → Request → handler → response wire bytes
//   Server push          PUSH_PROMISE frames + push stream opening
//   Shutdown             GOAWAY state machine
//
// Usage: always access through a pointer after init() — the Connection holds
// request-scratch slices that must not be invalidated by a copy.
//
// Named imports required in build.zig:
//   "qpack"        → src/qpack/root.zig module
//   "server_types" → src/server/types.zig module

const std = @import("std");
const frame = @import("frame.zig");
const settings_mod = @import("settings.zig");
const stream_mod = @import("stream.zig");
const push_mod = @import("push.zig");
const shutdown_mod = @import("shutdown.zig");
const varint = @import("varint.zig");

const qpack = @import("qpack");
const qpack_enc = qpack.encoder;
const qpack_dec = qpack.decoder;
const QpackField = qpack.Field;

const server_types = @import("server_types");
const Request = server_types.Request;
const Response = server_types.Response;
const Handler = server_types.Handler;
const PushPromise = server_types.PushPromise;

const Settings = settings_mod.Settings;
const Shutdown = shutdown_mod.Shutdown;

// ----------------------------------------------------------------------------
// Config and Error
// ----------------------------------------------------------------------------

/// Compile-time configuration — all buffer sizes fixed, no heap allocation.
pub const Config = struct {
    /// Maximum number of decoded header fields per request.
    max_header_fields: usize = 64,
    /// Scratch buffer size for QPACK Huffman-decoded strings (per request).
    max_header_string_buf: usize = 4096,
};

pub const Error = error{
    /// Input buffer is truncated or payload is incomplete.
    Incomplete,
    /// Output buffer is too small.
    BufferTooSmall,
    /// A varint value is out of range.
    Overflow,
    /// Expected a different frame type.
    UnexpectedFrame,
    /// QPACK decoding of request headers failed.
    InvalidHeaders,
    /// Peer sent SETTINGS twice on the control stream.
    DuplicateSettings,
    /// Non-SETTINGS frame arrived before the peer's first SETTINGS frame.
    MissingSettings,
    /// A settings payload or frame payload was malformed.
    InvalidFrame,
    /// The client has not issued MAX_PUSH_ID or the push ID limit is exhausted.
    PushNotAllowed,
    /// Shutdown state machine rejected the operation.
    ShutdownError,
};

// ----------------------------------------------------------------------------
// Connection
// ----------------------------------------------------------------------------

pub fn Connection(comptime cfg: Config) type {
    return struct {
        const Self = @This();

        // ---- Settings -------------------------------------------------------

        /// Settings we advertise to the peer (sent in our SETTINGS frame).
        local_settings: Settings = .{},
        /// Settings received from the peer.
        peer_settings: Settings = .{},
        /// True once we have processed the peer's SETTINGS frame.
        peer_settings_received: bool = false,

        // ---- Shutdown -------------------------------------------------------

        shutdown: Shutdown = .{},

        // ---- Server push ----------------------------------------------------

        /// Next push ID to allocate (server-side counter).
        next_push_id: u64 = 0,
        /// Highest push ID allowed by the client's MAX_PUSH_ID frame.
        /// null = client has not sent MAX_PUSH_ID; no pushes permitted.
        max_push_id: ?u64 = null,

        // ---- Per-request decode scratch -------------------------------------
        // Reused across requests (single-threaded model).

        req_fields: [cfg.max_header_fields]QpackField = undefined,
        req_strings: [cfg.max_header_string_buf]u8 = undefined,

        // ---- Lifecycle ------------------------------------------------------

        /// Set local settings. Call once before using the connection.
        /// (Default construction with `.{}` is also valid for zero-config use.)
        pub fn init(self: *Self, local_settings: Settings) void {
            self.local_settings = local_settings;
        }

        // ---- Control stream -------------------------------------------------

        /// Produce the bytes to send when opening the server's control stream.
        ///
        /// Wire format: stream_type(0x00) | SETTINGS frame
        ///
        /// The caller sends these bytes on a freshly opened unidirectional QUIC
        /// stream before any other frames.
        pub fn buildControlStreamOpening(self: *const Self, buf: []u8) Error!usize {
            // Inline the stream opening rather than delegating, to keep the
            // error set narrow (stream_mod.Error includes DuplicateSetting
            // which cannot be returned from a write operation).
            var pos: usize = 0;
            pos += varint.encode(buf[pos..], stream_mod.StreamType.control) catch return error.BufferTooSmall;
            pos += settings_mod.encodeFrame(self.local_settings, buf[pos..]) catch return error.BufferTooSmall;
            return pos;
        }

        /// Process bytes received on the peer's control stream.
        ///
        /// Handles: SETTINGS, GOAWAY, MAX_PUSH_ID, CANCEL_PUSH, unknown frames.
        /// Processes as many complete frames as possible; stops silently at an
        /// incomplete frame (streaming: caller retains unconsumed bytes).
        ///
        /// Returns the number of bytes consumed.
        pub fn processControlBytes(self: *Self, buf: []const u8) Error!usize {
            var pos: usize = 0;
            while (pos < buf.len) {
                const hdr = frame.parseHeader(buf[pos..]) catch break;
                const payload_start = pos + hdr.header_len;
                const payload_len: usize = @intCast(hdr.payload_len);
                const payload_end = payload_start + payload_len;
                if (payload_end > buf.len) break; // incomplete payload
                try self.handleControlFrame(hdr.frame_type, buf[payload_start..payload_end]);
                pos = payload_end;
            }
            return pos;
        }

        fn handleControlFrame(self: *Self, frame_type: u64, payload: []const u8) Error!void {
            // Per RFC 9114 §6.2.1, the first frame on the control stream MUST be SETTINGS.
            if (!self.peer_settings_received and frame_type != frame.FrameType.settings)
                return error.MissingSettings;

            switch (frame_type) {
                frame.FrameType.settings => {
                    if (self.peer_settings_received) return error.DuplicateSettings;
                    self.peer_settings = settings_mod.decodePayload(payload) catch
                        return error.InvalidFrame;
                    self.peer_settings_received = true;
                },
                frame.FrameType.goaway => {
                    _ = frame.parseGoaway(payload) catch return error.InvalidFrame;
                    // Peer is shutting down. Future work: reject new requests.
                },
                frame.FrameType.max_push_id => {
                    const push_id = frame.parseMaxPushId(payload) catch return error.InvalidFrame;
                    // MAX_PUSH_ID is only valid if it does not decrease — RFC 9114 §7.2.7.
                    if (self.max_push_id == null or push_id >= self.max_push_id.?) {
                        self.max_push_id = push_id;
                    }
                },
                frame.FrameType.cancel_push => {
                    _ = frame.parseCancelPush(payload) catch return error.InvalidFrame;
                    // Future work: cancel the identified push stream.
                },
                else => {
                    // Unknown frame types on the control stream MUST be ignored
                    // unless they are reserved critical types — RFC 9114 §7.2.8.
                },
            }
        }

        // ---- Request stream processing --------------------------------------

        /// Process a complete request stream buffer.
        ///
        /// in_buf: raw bytes of the request stream — HEADERS frame (required)
        ///         followed by zero or more DATA frames.
        ///
        /// out_buf: destination for response stream bytes.  Written in order:
        ///         PUSH_PROMISE frames (one per queued push, if any)
        ///         HEADERS frame (response headers)
        ///         DATA frame    (response body, omitted if empty)
        ///
        /// handler: the protocol-agnostic handler to dispatch to.
        ///
        /// Returns the number of bytes written to out_buf.
        pub fn processRequest(
            self: *Self,
            in_buf: []const u8,
            out_buf: []u8,
            handler: Handler,
        ) Error!usize {
            // -- 1. Parse HEADERS frame ---------------------------------------
            const hdr = frame.parseHeader(in_buf) catch return error.Incomplete;
            if (hdr.frame_type != frame.FrameType.headers) return error.UnexpectedFrame;
            const header_block_start = hdr.header_len;
            const header_block_len: usize = @intCast(hdr.payload_len);
            const header_block_end = header_block_start + header_block_len;
            if (header_block_end > in_buf.len) return error.Incomplete;

            // -- 2. QPACK-decode the header block (static-only) ---------------
            const field_count = qpack_dec.decode(
                in_buf[header_block_start..header_block_end],
                &self.req_fields,
                &self.req_strings,
                null, // static-only
                0,
            ) catch return error.InvalidHeaders;

            // -- 3. Build Request from decoded pseudo-headers + regular headers
            var req: Request = .{
                .method = "",
                .path = "",
                .query = "",
                .headers = .{},
                .body = "",
            };
            for (self.req_fields[0..field_count]) |f| {
                if (std.mem.eql(u8, f.name, ":method")) {
                    req.method = f.value;
                } else if (std.mem.eql(u8, f.name, ":path")) {
                    if (std.mem.indexOfScalar(u8, f.value, '?')) |q| {
                        req.path = f.value[0..q];
                        req.query = f.value[q + 1 ..];
                    } else {
                        req.path = f.value;
                    }
                } else if (!std.mem.startsWith(u8, f.name, ":")) {
                    req.headers.add(f.name, f.value);
                }
                // :scheme, :authority — consumed by HTTP/3 framing, not passed to handler
            }

            // -- 4. Read optional DATA frames (request body) ------------------
            var body_pos: usize = header_block_end;
            while (body_pos < in_buf.len) {
                const data_hdr = frame.parseHeader(in_buf[body_pos..]) catch break;
                if (data_hdr.frame_type != frame.FrameType.data) break;
                const data_start = body_pos + data_hdr.header_len;
                const data_len: usize = @intCast(data_hdr.payload_len);
                const data_end = data_start + data_len;
                if (data_end > in_buf.len) break;
                req.body = in_buf[data_start..data_end]; // last DATA frame wins
                body_pos = data_end;
            }

            // -- 5. Dispatch to handler ---------------------------------------
            var res: Response = .{};
            handler(&req, &res);

            // -- 6. Write response to out_buf ---------------------------------
            var out_pos: usize = 0;

            // 6a. PUSH_PROMISE frames (one per queued push).
            for (res.pushes()) |*p| {
                if (self.allocatePushId()) |push_id| {
                    const n = self.buildPushPromise(push_id, p, out_buf[out_pos..]) catch continue;
                    out_pos += n;
                } else |_| {
                    // PushNotAllowed — skip silently.
                }
            }

            // 6b. HEADERS frame (response headers).
            // Stack-allocate encoding scratch — avoids heap, avoids struct growth.
            var enc_fields: [cfg.max_header_fields]QpackField = undefined;
            var enc_count: usize = 0;
            var enc_buf: [4096]u8 = undefined;

            // :status pseudo-header (3-char ASCII decimal).
            var status_buf: [3]u8 = undefined;
            const status_str = std.fmt.bufPrint(&status_buf, "{d}", .{res.status}) catch
                return error.BufferTooSmall;
            enc_fields[enc_count] = .{ .name = ":status", .value = status_str };
            enc_count += 1;

            for (res.headers.items()) |h| {
                if (enc_count >= cfg.max_header_fields) return error.BufferTooSmall;
                enc_fields[enc_count] = .{ .name = h.name, .value = h.value };
                enc_count += 1;
            }

            const qpack_len = qpack_enc.encode(enc_fields[0..enc_count], &enc_buf, null) catch
                return error.BufferTooSmall;

            const h_hdr_len = frame.writeHeader(out_buf[out_pos..], frame.FrameType.headers, qpack_len) catch
                return error.BufferTooSmall;
            out_pos += h_hdr_len;
            if (out_pos + qpack_len > out_buf.len) return error.BufferTooSmall;
            @memcpy(out_buf[out_pos .. out_pos + qpack_len], enc_buf[0..qpack_len]);
            out_pos += qpack_len;

            // 6c. DATA frame (response body) — omitted if empty.
            if (res.body.len > 0) {
                const d_hdr_len = frame.writeHeader(out_buf[out_pos..], frame.FrameType.data, res.body.len) catch
                    return error.BufferTooSmall;
                out_pos += d_hdr_len;
                if (out_pos + res.body.len > out_buf.len) return error.BufferTooSmall;
                @memcpy(out_buf[out_pos .. out_pos + res.body.len], res.body);
                out_pos += res.body.len;
            }

            return out_pos;
        }

        // ---- Server push ----------------------------------------------------

        /// Allocate the next push ID.
        ///
        /// Returns error.PushNotAllowed if:
        ///   - the client has not sent MAX_PUSH_ID, or
        ///   - next_push_id > max_push_id (limit exhausted).
        pub fn allocatePushId(self: *Self) Error!u64 {
            const max = self.max_push_id orelse return error.PushNotAllowed;
            if (self.next_push_id > max) return error.PushNotAllowed;
            const id = self.next_push_id;
            self.next_push_id += 1;
            return id;
        }

        /// Write a PUSH_PROMISE frame for a push promise into buf.
        ///
        /// Encodes the push's :method, :path, and extra headers via QPACK
        /// (static-only).  Returns bytes written.
        pub fn buildPushPromise(
            _: *const Self,
            push_id: u64,
            p: *const PushPromise,
            buf: []u8,
        ) Error!usize {
            var enc_fields: [cfg.max_header_fields]QpackField = undefined;
            var enc_count: usize = 0;
            var enc_buf: [4096]u8 = undefined;

            enc_fields[enc_count] = .{ .name = ":method", .value = p.method };
            enc_count += 1;
            enc_fields[enc_count] = .{ .name = ":path", .value = p.path };
            enc_count += 1;
            for (p.headers.items()) |h| {
                if (enc_count >= cfg.max_header_fields) return error.BufferTooSmall;
                enc_fields[enc_count] = .{ .name = h.name, .value = h.value };
                enc_count += 1;
            }

            const qpack_len = qpack_enc.encode(enc_fields[0..enc_count], &enc_buf, null) catch
                return error.BufferTooSmall;
            return push_mod.writePushPromise(buf, push_id, enc_buf[0..qpack_len]) catch
                return error.BufferTooSmall;
        }

        /// Write a push stream opening (stream_type=0x01 + push_id) into buf.
        ///
        /// The caller opens a new unidirectional QUIC stream, sends these bytes
        /// first, then sends HEADERS + DATA frames for the pushed response.
        pub fn buildPushStreamOpening(_: *const Self, push_id: u64, buf: []u8) Error!usize {
            return push_mod.writePushStreamOpening(buf, push_id) catch return error.BufferTooSmall;
        }

        // ---- Shutdown -------------------------------------------------------

        /// Begin graceful shutdown. Writes a GOAWAY frame into buf.
        ///
        /// Transitions state to draining; no new requestStarted() calls allowed.
        /// Returns bytes written (the caller sends them on the control stream).
        ///
        /// May be called twice with a decreasing last_stream_id per RFC 9114 §5.2.
        pub fn initiateShutdown(self: *Self, last_stream_id: u64, buf: []u8) Error!usize {
            return self.shutdown.initiateShutdown(last_stream_id, buf) catch
                return error.ShutdownError;
        }

        /// Record that a request has started. Only valid while running.
        pub fn requestStarted(self: *Self) Error!void {
            return self.shutdown.requestStarted() catch return error.ShutdownError;
        }

        /// Record that a request has finished.
        /// Transitions to closed if draining and no more in-flight requests.
        pub fn requestFinished(self: *Self) void {
            self.shutdown.requestFinished();
        }

        pub fn isDraining(self: *const Self) bool {
            return self.shutdown.isDraining();
        }

        pub fn isClosed(self: *const Self) bool {
            return self.shutdown.isClosed();
        }
    };
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const DefaultConn = Connection(.{});

test "Connection: default state" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};
    try std_.testing.expect(!conn.peer_settings_received);
    try std_.testing.expect(!conn.isDraining());
    try std_.testing.expect(!conn.isClosed());
    try std_.testing.expectEqual(@as(?u64, null), conn.max_push_id);
    try std_.testing.expectEqual(@as(u64, 0), conn.next_push_id);
}

test "Connection.buildControlStreamOpening: correct bytes" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};
    conn.init(.{ .qpack_max_table_capacity = 4096 });

    var buf: [64]u8 = undefined;
    const n = try conn.buildControlStreamOpening(&buf);

    // First byte: stream type 0x00 (control).
    try std_.testing.expectEqual(@as(u8, 0x00), buf[0]);

    // Remaining bytes: SETTINGS frame.
    const hdr = try frame.parseHeader(buf[1..n]);
    try std_.testing.expectEqual(frame.FrameType.settings, hdr.frame_type);

    const payload_start = 1 + hdr.header_len;
    const payload_end = payload_start + @as(usize, @intCast(hdr.payload_len));
    const decoded = try settings_mod.decodePayload(buf[payload_start..payload_end]);
    try std_.testing.expectEqual(@as(u64, 4096), decoded.qpack_max_table_capacity);
}

test "Connection.processControlBytes: processes SETTINGS frame" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    // Build a SETTINGS frame with qpack_max_table_capacity = 8192.
    var buf: [64]u8 = undefined;
    const n = try settings_mod.encodeFrame(.{ .qpack_max_table_capacity = 8192 }, &buf);

    const consumed = try conn.processControlBytes(buf[0..n]);
    try std_.testing.expectEqual(n, consumed);
    try std_.testing.expect(conn.peer_settings_received);
    try std_.testing.expectEqual(@as(u64, 8192), conn.peer_settings.qpack_max_table_capacity);
}

test "Connection.processControlBytes: SETTINGS + MAX_PUSH_ID" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try settings_mod.encodeFrame(.{}, &buf);
    pos += try frame.writeMaxPushId(buf[pos..], 99);

    _ = try conn.processControlBytes(buf[0..pos]);
    try std_.testing.expectEqual(@as(?u64, 99), conn.max_push_id);
}

test "Connection.processControlBytes: partial buffer stops cleanly" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var full_buf: [64]u8 = undefined;
    const n = try settings_mod.encodeFrame(.{}, &full_buf);

    // Feed only half the frame — should consume 0 bytes, no error.
    const consumed = try conn.processControlBytes(full_buf[0 .. n / 2]);
    try std_.testing.expectEqual(@as(usize, 0), consumed);
    try std_.testing.expect(!conn.peer_settings_received);
}

test "Connection.processControlBytes: non-SETTINGS first frame is an error" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var buf: [16]u8 = undefined;
    const n = try frame.writeGoaway(&buf, 0);
    try std_.testing.expectError(error.MissingSettings, conn.processControlBytes(buf[0..n]));
}

test "Connection.processControlBytes: duplicate SETTINGS returns error" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};
    var buf: [64]u8 = undefined;
    var pos: usize = 0;
    pos += try settings_mod.encodeFrame(.{}, buf[0..]);
    pos += try settings_mod.encodeFrame(.{}, buf[pos..]);
    try std_.testing.expectError(error.DuplicateSettings, conn.processControlBytes(buf[0..pos]));
}

// -- helpers for request-processing tests ------------------------------------

fn okHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 200;
    res.body = "OK";
}

fn echoMethodHandler(req: *const Request, res: *Response) void {
    res.status = 200;
    res.body = req.method;
}

fn echoBodyHandler(req: *const Request, res: *Response) void {
    res.status = 200;
    res.body = req.body;
}

fn echoPathHandler(req: *const Request, res: *Response) void {
    res.status = 200;
    res.body = req.path;
}

fn echoQueryHandler(req: *const Request, res: *Response) void {
    res.status = 200;
    res.body = req.query;
}

fn notFoundHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 404;
    res.body = "not found";
}

fn pushHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 200;
    res.body = "main";
    _ = res.addPush("GET", "/style.css");
}

/// Build a minimal QPACK-encoded request stream into buf.
/// Returns bytes written.
fn buildRequestStream(
    method: []const u8,
    path: []const u8,
    body: []const u8,
    buf: []u8,
) !usize {
    var qpack_buf: [512]u8 = undefined;
    var fields_buf: [8]QpackField = undefined;
    var fc: usize = 0;
    fields_buf[fc] = .{ .name = ":method", .value = method };     fc += 1;
    fields_buf[fc] = .{ .name = ":path",   .value = path };       fc += 1;
    fields_buf[fc] = .{ .name = ":scheme", .value = "https" };    fc += 1;
    fields_buf[fc] = .{ .name = ":authority", .value = "host" };  fc += 1;
    const ql = try qpack_enc.encode(fields_buf[0..fc], &qpack_buf, null);

    var pos: usize = 0;
    pos += try frame.writeHeader(buf[pos..], frame.FrameType.headers, ql);
    @memcpy(buf[pos .. pos + ql], qpack_buf[0..ql]);
    pos += ql;

    if (body.len > 0) {
        pos += try frame.writeHeader(buf[pos..], frame.FrameType.data, body.len);
        @memcpy(buf[pos .. pos + body.len], body);
        pos += body.len;
    }
    return pos;
}

/// Parse a QPACK header block from a HEADERS frame in buf.
/// Returns the number of fields written to out.
fn parseResponseHeaders(
    buf: []const u8,
    out: []QpackField,
    strings: []u8,
) !usize {
    const hdr = try frame.parseHeader(buf);
    const payload_start = hdr.header_len;
    const payload_len: usize = @intCast(hdr.payload_len);
    return try qpack_dec.decode(
        buf[payload_start .. payload_start + payload_len],
        out,
        strings,
        null,
        0,
    );
}

test "Connection.processRequest: GET → 200 + body" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("GET", "/hello", "", &in_buf);

    var out_buf: [512]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, okHandler);

    // Parse the response HEADERS frame.
    var resp_fields: [16]QpackField = undefined;
    var resp_strings: [512]u8 = undefined;
    const fc = try parseResponseHeaders(out_buf[0..out_len], &resp_fields, &resp_strings);

    var status: ?[]const u8 = null;
    for (resp_fields[0..fc]) |f| {
        if (std_.mem.eql(u8, f.name, ":status")) status = f.value;
    }
    try std_.testing.expectEqualStrings("200", status.?);

    // Parse the DATA frame following the HEADERS frame.
    const h_hdr = try frame.parseHeader(out_buf[0..out_len]);
    const headers_end = h_hdr.header_len + @as(usize, @intCast(h_hdr.payload_len));
    const d_hdr = try frame.parseHeader(out_buf[headers_end..out_len]);
    try std_.testing.expectEqual(frame.FrameType.data, d_hdr.frame_type);
    const data_start = headers_end + d_hdr.header_len;
    const data_end = data_start + @as(usize, @intCast(d_hdr.payload_len));
    try std_.testing.expectEqualStrings("OK", out_buf[data_start..data_end]);
}

test "Connection.processRequest: path with query string" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    const S = struct {
        var captured_path: []const u8 = "";
        var captured_query: []const u8 = "";
        fn h(req: *const Request, res: *Response) void {
            captured_path = req.path;
            captured_query = req.query;
            res.status = 200;
        }
    };

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("GET", "/search?q=zig", "", &in_buf);
    var out_buf: [512]u8 = undefined;
    _ = try conn.processRequest(in_buf[0..in_len], &out_buf, S.h);

    try std_.testing.expectEqualStrings("/search", S.captured_path);
    try std_.testing.expectEqualStrings("q=zig", S.captured_query);
}

test "Connection.processRequest: POST with body reaches handler" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var in_buf: [512]u8 = undefined;
    const in_len = try buildRequestStream("POST", "/echo", "hello body", &in_buf);
    var out_buf: [512]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, echoBodyHandler);

    const h_hdr = try frame.parseHeader(out_buf[0..out_len]);
    const headers_end = h_hdr.header_len + @as(usize, @intCast(h_hdr.payload_len));
    const d_hdr = try frame.parseHeader(out_buf[headers_end..out_len]);
    const data_start = headers_end + d_hdr.header_len;
    const data_end = data_start + @as(usize, @intCast(d_hdr.payload_len));
    try std_.testing.expectEqualStrings("hello body", out_buf[data_start..data_end]);
}

test "Connection.processRequest: 404 response encodes correct :status" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("GET", "/nope", "", &in_buf);
    var out_buf: [512]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, notFoundHandler);

    var resp_fields: [16]QpackField = undefined;
    var resp_strings: [512]u8 = undefined;
    const fc = try parseResponseHeaders(out_buf[0..out_len], &resp_fields, &resp_strings);

    var status: ?[]const u8 = null;
    for (resp_fields[0..fc]) |f| {
        if (std.mem.eql(u8, f.name, ":status")) status = f.value;
    }
    try std_.testing.expectEqualStrings("404", status.?);
}

test "Connection.processRequest: empty body → no DATA frame" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    const S = struct {
        fn h(req: *const Request, res: *Response) void {
            _ = req;
            res.status = 204; // No Content — intentionally no body
        }
    };

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("DELETE", "/item/1", "", &in_buf);
    var out_buf: [512]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, S.h);

    // Only one frame in the response — the HEADERS frame. No DATA frame.
    const h_hdr = try frame.parseHeader(out_buf[0..out_len]);
    const total = h_hdr.header_len + @as(usize, @intCast(h_hdr.payload_len));
    try std_.testing.expectEqual(out_len, total);
    try std_.testing.expectEqual(frame.FrameType.headers, h_hdr.frame_type);
}

test "Connection.processRequest: response headers forwarded" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    const S = struct {
        fn h(req: *const Request, res: *Response) void {
            _ = req;
            res.status = 200;
            res.headers.add("content-type", "application/json");
            res.body = "{}";
        }
    };

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("GET", "/api", "", &in_buf);
    var out_buf: [512]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, S.h);

    var resp_fields: [16]QpackField = undefined;
    var resp_strings: [512]u8 = undefined;
    const fc = try parseResponseHeaders(out_buf[0..out_len], &resp_fields, &resp_strings);

    var ct: ?[]const u8 = null;
    for (resp_fields[0..fc]) |f| {
        if (std_.mem.eql(u8, f.name, "content-type")) ct = f.value;
    }
    try std_.testing.expectEqualStrings("application/json", ct.?);
}

test "Connection.allocatePushId: sequential, respects max_push_id" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    // No MAX_PUSH_ID yet.
    try std_.testing.expectError(error.PushNotAllowed, conn.allocatePushId());

    conn.max_push_id = 2; // IDs 0, 1, 2 allowed.
    try std_.testing.expectEqual(@as(u64, 0), try conn.allocatePushId());
    try std_.testing.expectEqual(@as(u64, 1), try conn.allocatePushId());
    try std_.testing.expectEqual(@as(u64, 2), try conn.allocatePushId());
    try std_.testing.expectError(error.PushNotAllowed, conn.allocatePushId());
}

test "Connection.buildPushPromise: produces valid PUSH_PROMISE frame" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};

    var p: PushPromise = .{ .method = "GET", .path = "/style.css", .headers = .{} };
    var buf: [256]u8 = undefined;
    const n = try conn.buildPushPromise(7, &p, &buf);

    const hdr = try frame.parseHeader(buf[0..n]);
    try std_.testing.expectEqual(frame.FrameType.push_promise, hdr.frame_type);

    const payload_start = hdr.header_len;
    const payload_len: usize = @intCast(hdr.payload_len);
    const parsed = try push_mod.parsePushPromise(buf[payload_start .. payload_start + payload_len]);
    try std_.testing.expectEqual(@as(u64, 7), parsed.push_id);

    // Decode the QPACK header block and check :method + :path.
    var resp_fields: [8]QpackField = undefined;
    var resp_strings: [256]u8 = undefined;
    const fc = try qpack_dec.decode(parsed.header_block, &resp_fields, &resp_strings, null, 0);
    var has_method = false;
    var has_path = false;
    for (resp_fields[0..fc]) |f| {
        if (std_.mem.eql(u8, f.name, ":method") and std_.mem.eql(u8, f.value, "GET")) has_method = true;
        if (std_.mem.eql(u8, f.name, ":path") and std_.mem.eql(u8, f.value, "/style.css")) has_path = true;
    }
    try std_.testing.expect(has_method);
    try std_.testing.expect(has_path);
}

test "Connection.processRequest: push promises emitted when max_push_id set" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};
    conn.max_push_id = 10;

    var in_buf: [256]u8 = undefined;
    const in_len = try buildRequestStream("GET", "/index.html", "", &in_buf);
    var out_buf: [1024]u8 = undefined;
    const out_len = try conn.processRequest(in_buf[0..in_len], &out_buf, pushHandler);

    // First frame should be a PUSH_PROMISE.
    const first_hdr = try frame.parseHeader(out_buf[0..out_len]);
    try std_.testing.expectEqual(frame.FrameType.push_promise, first_hdr.frame_type);

    // Second frame should be HEADERS (response).
    const push_end = first_hdr.header_len + @as(usize, @intCast(first_hdr.payload_len));
    const second_hdr = try frame.parseHeader(out_buf[push_end..out_len]);
    try std_.testing.expectEqual(frame.FrameType.headers, second_hdr.frame_type);
}

test "Connection.initiateShutdown: writes GOAWAY, transitions to draining" {
    const std_ = @import("std");
    var conn: DefaultConn = .{};
    try conn.requestStarted();
    var buf: [16]u8 = undefined;
    const n = try conn.initiateShutdown(42, &buf);

    const hdr = try frame.parseHeader(buf[0..n]);
    try std_.testing.expectEqual(frame.FrameType.goaway, hdr.frame_type);
    try std_.testing.expect(conn.isDraining());
    try std_.testing.expect(!conn.isClosed());

    conn.requestFinished();
    try std_.testing.expect(conn.isClosed());
}
