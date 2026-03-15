// Comptime middleware chain.
//
// Middleware functions have the signature:
//   fn(req: *const Request, res: *Response, next: Handler) void
//
// The terminal entry in the chain is a plain Handler (same signature as the
// wrapped result), so the router's dispatch function can be passed directly:
//
//   const chain = comptime Middleware.chain(.{
//       logMiddleware,
//       authMiddleware,
//       router.handler(),
//   });
//
// The chain is resolved entirely at compile time — no vtable, no heap
// allocation, no runtime linked list.  The result is a single Handler pointer.

const types = @import("types.zig");
const Request = types.Request;
const Response = types.Response;
const Handler = types.Handler;
const MiddlewareFn = types.MiddlewareFn;

/// Build a comptime-composed middleware runner starting at index `i`.
/// The last element must be a Handler (terminal); all prior elements are
/// MiddlewareFn (they receive `next`).
fn makeRunner(comptime i: usize, comptime fns: anytype) Handler {
    const last = fns.len - 1;
    if (i == last) {
        // Terminal: must be a plain Handler.
        return fns[i];
    }
    // Capture the next handler at comptime.
    const next: Handler = comptime makeRunner(i + 1, fns);
    return struct {
        fn run(req: *const Request, res: *Response) void {
            fns[i](req, res, next);
        }
    }.run;
}

pub const Middleware = struct {
    /// Compose a chain of middleware + terminal handler into a single Handler.
    ///
    /// `fns` is a comptime tuple:
    ///   - All entries except the last: MiddlewareFn
    ///   - Last entry: Handler (the terminal, e.g. router.dispatch)
    ///
    /// Returns a Handler that runs the full chain.
    pub fn chain(comptime fns: anytype) Handler {
        comptime std.debug.assert(fns.len > 0);
        return comptime makeRunner(0, fns);
    }
};

const std = @import("std");

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

const testing = @import("std").testing;

// Logs that it ran by setting a header, then calls next.
fn logMiddleware(req: *const Request, res: *Response, next: Handler) void {
    res.headers.add("x-log", "ran");
    next(req, res);
}

// Sets auth header, calls next.
fn authMiddleware(req: *const Request, res: *Response, next: Handler) void {
    res.headers.add("x-auth", "ok");
    next(req, res);
}

// Terminal handler — sets status 200.
fn terminalHandler(req: *const Request, res: *Response) void {
    _ = req;
    res.status = 200;
    res.body = "done";
}

// Short-circuit handler — does NOT call next.
fn shortCircuit(req: *const Request, res: *Response, next: Handler) void {
    _ = req;
    _ = next;
    res.status = 403;
    res.body = "forbidden";
}

test "Middleware.chain: single terminal handler" {
    var req: Request = .{
        .method = "GET", .path = "/", .query = "", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    const h = comptime Middleware.chain(.{terminalHandler});
    h(&req, &res);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("done", res.body);
}

test "Middleware.chain: two middleware + terminal" {
    var req: Request = .{
        .method = "GET", .path = "/", .query = "", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    const h = comptime Middleware.chain(.{ logMiddleware, authMiddleware, terminalHandler });
    h(&req, &res);
    try testing.expectEqual(@as(u16, 200), res.status);
    try testing.expectEqualStrings("done", res.body);
    try testing.expectEqualStrings("ran", res.headers.get("x-log").?);
    try testing.expectEqualStrings("ok", res.headers.get("x-auth").?);
}

test "Middleware.chain: short-circuit stops chain" {
    var req: Request = .{
        .method = "GET", .path = "/", .query = "", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    const h = comptime Middleware.chain(.{ shortCircuit, terminalHandler });
    h(&req, &res);
    try testing.expectEqual(@as(u16, 403), res.status);
    try testing.expectEqualStrings("forbidden", res.body);
    // terminalHandler was never called — no x-log header
    try testing.expectEqual(@as(?[]const u8, null), res.headers.get("x-log"));
}

test "Middleware.chain: order is preserved" {
    // First middleware sets body to "a", second appends " b", terminal appends " c".
    // Use a global buffer to track call order.
    const S = struct {
        var order: [3]u8 = undefined;
        var pos: usize = 0;

        fn m1(req: *const Request, res: *Response, next: Handler) void {
            order[pos] = '1'; pos += 1;
            next(req, res);
        }
        fn m2(req: *const Request, res: *Response, next: Handler) void {
            order[pos] = '2'; pos += 1;
            next(req, res);
        }
        fn term(req: *const Request, res: *Response) void {
            _ = req; _ = res;
            order[pos] = '3'; pos += 1;
        }
    };
    S.pos = 0;

    var req: Request = .{
        .method = "GET", .path = "/", .query = "", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    const h = comptime Middleware.chain(.{ S.m1, S.m2, S.term });
    h(&req, &res);
    try testing.expectEqualStrings("123", S.order[0..3]);
}
