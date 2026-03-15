// Comptime perfect-hash router — RFC-agnostic.
//
// Routes are registered as comptime tuples:
//   .{ "GET",  "/path",  handlerFn }
//   .{ "POST", "/path",  handlerFn }
//
// Route key: "METHOD PATH" (space-separated).
// Hash function: FNV-1a 64-bit with a comptime-searched seed for zero collisions.
// Table size: smallest power-of-two >= 2 * num_routes.
//
// Runtime dispatch is a single hash + table lookup — no string comparison, no
// heap allocation, no linked list traversal.

const types = @import("types.zig");
const Request = types.Request;
const Response = types.Response;
const Handler = types.Handler;

fn fnv1a(comptime seed: u64, key: []const u8) u64 {
    var h: u64 = seed;
    for (key) |b| {
        h ^= @as(u64, b);
        h *%= 0x00000100000001B3;
    }
    return h;
}

fn nextPow2(n: usize) usize {
    var p: usize = 1;
    while (p < n) p <<= 1;
    return p;
}

const Entry = struct {
    key: []const u8,
    handler: Handler,
};

/// Build a comptime perfect-hash router from a tuple of .{ method, path, handler } triples.
pub fn Router(comptime routes: anytype) type {
    const num_routes = routes.len;
    comptime std.debug.assert(num_routes > 0);

    // Build route keys at comptime.
    comptime var keys: [num_routes][]const u8 = undefined;
    comptime var handlers_arr: [num_routes]Handler = undefined;
    comptime {
        for (0..num_routes) |i| {
            keys[i] = routes[i][0] ++ " " ++ routes[i][1];
            handlers_arr[i] = routes[i][2];
        }
    }

    const table_size = comptime nextPow2(num_routes * 2);

    // Find a seed that produces zero collisions.
    comptime var seed: u64 = 0x811c9dc5; // FNV offset basis
    comptime var table: [table_size]?Entry = [_]?Entry{null} ** table_size;
    comptime found: {
        while (true) : (seed +%= 1) {
            var t: [table_size]?Entry = [_]?Entry{null} ** table_size;
            var ok = true;
            for (0..num_routes) |i| {
                const slot = fnv1a(seed, keys[i]) & (table_size - 1);
                if (t[slot] != null) { ok = false; break; }
                t[slot] = .{ .key = keys[i], .handler = handlers_arr[i] };
            }
            if (ok) {
                table = t;
                break :found;
            }
        }
    }

    return struct {
        const TABLE: [table_size]?Entry = table;
        const SEED: u64 = seed;
        const MASK: u64 = table_size - 1;

        /// Dispatch a request. Writes 404 into res if no route matches.
        pub fn dispatch(req: *const Request, res: *Response) void {
            // Build the lookup key: "METHOD PATH" using a stack buffer.
            var key_buf: [256]u8 = undefined;
            const method_len = req.method.len;
            const path_len = req.path.len;
            if (method_len + 1 + path_len > key_buf.len) {
                res.status = 404;
                return;
            }
            @memcpy(key_buf[0..method_len], req.method);
            key_buf[method_len] = ' ';
            @memcpy(key_buf[method_len + 1 .. method_len + 1 + path_len], req.path);
            const key = key_buf[0 .. method_len + 1 + path_len];

            const slot = fnv1a(SEED, key) & MASK;
            if (TABLE[slot]) |e| {
                if (std.mem.eql(u8, e.key, key)) {
                    e.handler(req, res);
                    return;
                }
            }
            res.status = 404;
        }

        pub fn handler(_: @This()) Handler {
            return dispatch;
        }
    };
}

const std = @import("std");

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

fn helloHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 200;
    res.body = "hello";
}

fn echoHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 200;
    res.body = "echo";
}

fn postHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 201;
    res.body = "created";
}

const TestRouter = Router(.{
    .{ "GET",  "/hello",   helloHandler },
    .{ "GET",  "/echo",    echoHandler  },
    .{ "POST", "/submit",  postHandler  },
});

test "Router: known GET route dispatches correctly" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "GET",
        .path = "/hello",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    TestRouter.dispatch(&req, &res);
    try std_.testing.expectEqual(@as(u16, 200), res.status);
    try std_.testing.expectEqualStrings("hello", res.body);
}

test "Router: second GET route dispatches correctly" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "GET",
        .path = "/echo",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    TestRouter.dispatch(&req, &res);
    try std_.testing.expectEqual(@as(u16, 200), res.status);
    try std_.testing.expectEqualStrings("echo", res.body);
}

test "Router: POST route dispatches correctly" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "POST",
        .path = "/submit",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    TestRouter.dispatch(&req, &res);
    try std_.testing.expectEqual(@as(u16, 201), res.status);
    try std_.testing.expectEqualStrings("created", res.body);
}

test "Router: unknown path returns 404" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "GET",
        .path = "/not-found",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    TestRouter.dispatch(&req, &res);
    try std_.testing.expectEqual(@as(u16, 404), res.status);
}

test "Router: wrong method returns 404" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "DELETE",
        .path = "/hello",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    TestRouter.dispatch(&req, &res);
    try std_.testing.expectEqual(@as(u16, 404), res.status);
}

test "Router: handler() accessor returns same function" {
    const std_ = @import("std");
    var req: Request = .{
        .method = "GET",
        .path = "/hello",
        .query = "",
        .headers = .{},
        .body = "",
    };
    var res: Response = .{};
    const r = TestRouter{};
    r.handler()(&req, &res);
    try std_.testing.expectEqual(@as(u16, 200), res.status);
}
