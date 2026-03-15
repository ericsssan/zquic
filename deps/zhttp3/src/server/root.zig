// Opinionated HTTP/3 server layer — protocol-agnostic.
// Comptime router, handler ABI, middleware chain.

pub const types = @import("types.zig");
pub const router = @import("router.zig");
pub const middleware = @import("middleware.zig");
pub const handlers = struct {
    pub const kv = @import("handlers/kv.zig");
};

pub const Request = types.Request;
pub const Response = types.Response;
pub const Headers = types.Headers;
pub const HeaderField = types.HeaderField;
pub const Handler = types.Handler;
pub const MiddlewareFn = types.MiddlewareFn;

pub const Router = router.Router;
pub const Middleware = middleware.Middleware;
