// HTTP-semantic types — protocol-agnostic.
//
// Handlers never see frame types, stream IDs, or QPACK state.
// The HTTP/3 adapter layer translates between wire protocol and these types.

pub const MAX_HEADERS = 64;

pub const HeaderField = struct {
    name: []const u8,
    value: []const u8,
};

pub const Headers = struct {
    fields: [MAX_HEADERS]HeaderField = undefined,
    len: usize = 0,

    pub fn add(self: *Headers, name: []const u8, value: []const u8) void {
        self.fields[self.len] = .{ .name = name, .value = value };
        self.len += 1;
    }

    pub fn get(self: *const Headers, name: []const u8) ?[]const u8 {
        for (self.fields[0..self.len]) |f| {
            if (std.mem.eql(u8, f.name, name)) return f.value;
        }
        return null;
    }

    pub fn items(self: *const Headers) []const HeaderField {
        return self.fields[0..self.len];
    }
};

pub const Request = struct {
    method: []const u8,
    path: []const u8,
    query: []const u8,
    headers: Headers,
    body: []const u8,
};

/// A server push promise: a resource the server will proactively push.
/// Handlers add push promises to Response before (or alongside) the response.
/// The HTTP/3 adapter layer translates these into PUSH_PROMISE frames and
/// push streams on the wire.
pub const PushPromise = struct {
    method: []const u8,
    path: []const u8,
    headers: Headers,
};

pub const MAX_PUSH_PROMISES = 4;

pub const Response = struct {
    status: u16 = 200,
    headers: Headers = .{},
    body: []const u8 = "",
    push_promises: [MAX_PUSH_PROMISES]PushPromise = undefined,
    push_count: usize = 0,

    /// Enqueue a server push promise. Returns a pointer to the new slot so
    /// the handler can add headers to it. Asserts push_count < MAX_PUSH_PROMISES.
    pub fn addPush(self: *Response, method: []const u8, path: []const u8) *PushPromise {
        std.debug.assert(self.push_count < MAX_PUSH_PROMISES);
        const p = &self.push_promises[self.push_count];
        self.push_count += 1;
        p.* = .{ .method = method, .path = path, .headers = .{} };
        return p;
    }

    /// Return a slice over the enqueued push promises.
    pub fn pushes(self: *const Response) []const PushPromise {
        return self.push_promises[0..self.push_count];
    }
};

/// Protocol-agnostic request handler.
/// Operates on pre-allocated buffers — no allocator in the signature.
pub const Handler = *const fn (req: *const Request, res: *Response) void;

/// Middleware function: calls next() to continue the chain.
pub const MiddlewareFn = *const fn (req: *const Request, res: *Response, next: Handler) void;

const std = @import("std");

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "Headers: add and get" {
    const std_ = @import("std");
    var h: Headers = .{};
    h.add("content-type", "application/json");
    h.add("x-request-id", "abc-123");

    try std_.testing.expectEqualStrings("application/json", h.get("content-type").?);
    try std_.testing.expectEqualStrings("abc-123", h.get("x-request-id").?);
    try std_.testing.expectEqual(@as(?[]const u8, null), h.get("authorization"));
}

test "Headers: items slice" {
    const std_ = @import("std");
    var h: Headers = .{};
    h.add("a", "1");
    h.add("b", "2");

    const s = h.items();
    try std_.testing.expectEqual(@as(usize, 2), s.len);
    try std_.testing.expectEqualStrings("a", s[0].name);
    try std_.testing.expectEqualStrings("2", s[1].value);
}

test "Response: default values" {
    const std_ = @import("std");
    const res: Response = .{};
    try std_.testing.expectEqual(@as(u16, 200), res.status);
    try std_.testing.expectEqualStrings("", res.body);
    try std_.testing.expectEqual(@as(usize, 0), res.headers.len);
    try std_.testing.expectEqual(@as(usize, 0), res.push_count);
}

test "Response.addPush: enqueues a push promise" {
    const std_ = @import("std");
    var res: Response = .{};
    _ = res.addPush("GET", "/style.css");
    try std_.testing.expectEqual(@as(usize, 1), res.push_count);
    try std_.testing.expectEqualStrings("GET", res.pushes()[0].method);
    try std_.testing.expectEqualStrings("/style.css", res.pushes()[0].path);
}

test "Response.addPush: returned pointer allows header mutation" {
    const std_ = @import("std");
    var res: Response = .{};
    const p = res.addPush("GET", "/app.js");
    p.headers.add("cache-control", "max-age=3600");
    try std_.testing.expectEqualStrings("max-age=3600", res.pushes()[0].headers.get("cache-control").?);
}

test "Response.addPush: multiple pushes" {
    const std_ = @import("std");
    var res: Response = .{};
    _ = res.addPush("GET", "/a.css");
    _ = res.addPush("GET", "/b.js");
    _ = res.addPush("GET", "/c.woff2");
    try std_.testing.expectEqual(@as(usize, 3), res.push_count);
    try std_.testing.expectEqualStrings("/b.js", res.pushes()[1].path);
}
