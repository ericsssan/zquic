// In-memory key/value handler — benchmark endpoint.
//
// Routes:
//   GET  /v1/get?key=<key>    → 200 body=value  |  404 body="not found"
//   POST /v1/set              → body="key=value" → 204
//
// Storage: fixed-size table, no allocator, no mutex (single-threaded model).
// Values are stored by copying into slot-owned arrays — zero heap allocation.
//
// This is an intentionally simple benchmark endpoint, not a production store.

const types = @import("../types.zig");
const Request = types.Request;
const Response = types.Response;

pub const MAX_ENTRIES = 256;
pub const MAX_KEY_LEN = 128;
pub const MAX_VAL_LEN = 1024;

const Slot = struct {
    key_buf: [MAX_KEY_LEN]u8 = undefined,
    val_buf: [MAX_VAL_LEN]u8 = undefined,
    key_len: usize = 0,
    val_len: usize = 0,
    used: bool = false,
};

pub const KvStore = struct {
    slots: [MAX_ENTRIES]Slot = [_]Slot{.{}} ** MAX_ENTRIES,

    pub fn get(self: *const KvStore, key: []const u8) ?[]const u8 {
        for (&self.slots) |*s| {
            if (s.used and std.mem.eql(u8, s.key_buf[0..s.key_len], key)) {
                return s.val_buf[0..s.val_len];
            }
        }
        return null;
    }

    /// Insert or update. Returns false if the store is full and the key is new.
    pub fn set(self: *KvStore, key: []const u8, value: []const u8) bool {
        if (key.len > MAX_KEY_LEN or value.len > MAX_VAL_LEN) return false;
        // Update existing.
        for (&self.slots) |*s| {
            if (s.used and std.mem.eql(u8, s.key_buf[0..s.key_len], key)) {
                @memcpy(s.val_buf[0..value.len], value);
                s.val_len = value.len;
                return true;
            }
        }
        // Insert into first free slot.
        for (&self.slots) |*s| {
            if (!s.used) {
                @memcpy(s.key_buf[0..key.len], key);
                s.key_len = key.len;
                @memcpy(s.val_buf[0..value.len], value);
                s.val_len = value.len;
                s.used = true;
                return true;
            }
        }
        return false; // full
    }
};

// Module-level store — shared across all requests.
var _store: KvStore = .{};

/// Parse ?key=<value> from a query string. Returns the value slice if found.
fn queryParam(query: []const u8, param: []const u8) ?[]const u8 {
    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (std.mem.startsWith(u8, pair, param)) {
            const rest = pair[param.len..];
            if (rest.len > 0 and rest[0] == '=') return rest[1..];
        }
    }
    return null;
}

/// GET /v1/get?key=<key>
pub fn kvGet(req: *const Request, res: *Response) void {
    const key = queryParam(req.query, "key") orelse {
        res.status = 400;
        res.body = "missing key";
        return;
    };
    if (_store.get(key)) |value| {
        res.status = 200;
        res.body = value;
    } else {
        res.status = 404;
        res.body = "not found";
    }
}

/// POST /v1/set  body: key=value
///
/// Body format: "key=value" (first '=' splits key from value).
pub fn kvSet(req: *const Request, res: *Response) void {
    const eq = std.mem.indexOfScalar(u8, req.body, '=') orelse {
        res.status = 400;
        res.body = "invalid body";
        return;
    };
    const key = req.body[0..eq];
    const value = req.body[eq + 1 ..];
    if (key.len == 0) {
        res.status = 400;
        res.body = "empty key";
        return;
    }
    if (_store.set(key, value)) {
        res.status = 204;
    } else {
        res.status = 507; // Insufficient Storage
        res.body = "store full";
    }
}

/// Reset the store — for testing only.
pub fn resetStore() void {
    _store = .{};
}

const std = @import("std");

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "KvStore: get on empty store returns null" {
    const std_ = @import("std");
    var store: KvStore = .{};
    try std_.testing.expectEqual(@as(?[]const u8, null), store.get("hello"));
}

test "KvStore: set and get round-trip" {
    const std_ = @import("std");
    var store: KvStore = .{};
    try std_.testing.expect(store.set("hello", "world"));
    try std_.testing.expectEqualStrings("world", store.get("hello").?);
}

test "KvStore: update existing key" {
    const std_ = @import("std");
    var store: KvStore = .{};
    _ = store.set("k", "v1");
    _ = store.set("k", "v2");
    try std_.testing.expectEqualStrings("v2", store.get("k").?);
}

test "KvStore: multiple keys" {
    const std_ = @import("std");
    var store: KvStore = .{};
    _ = store.set("a", "1");
    _ = store.set("b", "2");
    _ = store.set("c", "3");
    try std_.testing.expectEqualStrings("1", store.get("a").?);
    try std_.testing.expectEqualStrings("2", store.get("b").?);
    try std_.testing.expectEqualStrings("3", store.get("c").?);
}

test "kvGet: missing key param returns 400" {
    const std_ = @import("std");
    resetStore();
    var req: Request = .{
        .method = "GET", .path = "/v1/get", .query = "", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    kvGet(&req, &res);
    try std_.testing.expectEqual(@as(u16, 400), res.status);
}

test "kvGet: not-found key returns 404" {
    const std_ = @import("std");
    resetStore();
    var req: Request = .{
        .method = "GET", .path = "/v1/get", .query = "key=missing", .headers = .{}, .body = "",
    };
    var res: Response = .{};
    kvGet(&req, &res);
    try std_.testing.expectEqual(@as(u16, 404), res.status);
}

test "kvSet then kvGet round-trip" {
    const std_ = @import("std");
    resetStore();

    var set_req: Request = .{
        .method = "POST", .path = "/v1/set", .query = "", .headers = .{}, .body = "greeting=hello",
    };
    var set_res: Response = .{};
    kvSet(&set_req, &set_res);
    try std_.testing.expectEqual(@as(u16, 204), set_res.status);

    var get_req: Request = .{
        .method = "GET", .path = "/v1/get", .query = "key=greeting", .headers = .{}, .body = "",
    };
    var get_res: Response = .{};
    kvGet(&get_req, &get_res);
    try std_.testing.expectEqual(@as(u16, 200), get_res.status);
    try std_.testing.expectEqualStrings("hello", get_res.body);
}

test "kvSet: invalid body returns 400" {
    const std_ = @import("std");
    resetStore();
    var req: Request = .{
        .method = "POST", .path = "/v1/set", .query = "", .headers = .{}, .body = "no-equals-sign",
    };
    var res: Response = .{};
    kvSet(&req, &res);
    try std_.testing.expectEqual(@as(u16, 400), res.status);
}

test "kvSet: empty key returns 400" {
    const std_ = @import("std");
    resetStore();
    var req: Request = .{
        .method = "POST", .path = "/v1/set", .query = "", .headers = .{}, .body = "=value",
    };
    var res: Response = .{};
    kvSet(&req, &res);
    try std_.testing.expectEqual(@as(u16, 400), res.status);
}
