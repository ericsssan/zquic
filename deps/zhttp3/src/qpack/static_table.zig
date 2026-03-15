// QPACK static table — RFC 9204 Appendix A
// 99 entries, indices 0-98. Fixed for the lifetime of the protocol.

const std = @import("std");

pub const Entry = struct {
    name: []const u8,
    value: []const u8,
};

/// The 99-entry QPACK static table. Index is the position in this array.
pub const table: [99]Entry = .{
    // 0-14: common header names with empty values
    .{ .name = ":authority",          .value = "" },
    .{ .name = ":path",               .value = "/" },
    .{ .name = "age",                 .value = "0" },
    .{ .name = "content-disposition", .value = "" },
    .{ .name = "content-length",      .value = "0" },
    .{ .name = "cookie",              .value = "" },
    .{ .name = "date",                .value = "" },
    .{ .name = "etag",                .value = "" },
    .{ .name = "if-modified-since",   .value = "" },
    .{ .name = "if-none-match",       .value = "" },
    .{ .name = "last-modified",       .value = "" },
    .{ .name = "link",                .value = "" },
    .{ .name = "location",            .value = "" },
    .{ .name = "referer",             .value = "" },
    .{ .name = "set-cookie",          .value = "" },
    // 15-21: :method
    .{ .name = ":method",             .value = "CONNECT" },
    .{ .name = ":method",             .value = "DELETE" },
    .{ .name = ":method",             .value = "GET" },
    .{ .name = ":method",             .value = "HEAD" },
    .{ .name = ":method",             .value = "OPTIONS" },
    .{ .name = ":method",             .value = "POST" },
    .{ .name = ":method",             .value = "PUT" },
    // 22-23: :scheme
    .{ .name = ":scheme",             .value = "http" },
    .{ .name = ":scheme",             .value = "https" },
    // 24-28: :status (informational + common)
    .{ .name = ":status",             .value = "103" },
    .{ .name = ":status",             .value = "200" },
    .{ .name = ":status",             .value = "304" },
    .{ .name = ":status",             .value = "404" },
    .{ .name = ":status",             .value = "503" },
    // 29-35: accept + access-control
    .{ .name = "accept",                         .value = "*/*" },
    .{ .name = "accept",                         .value = "application/dns-message" },
    .{ .name = "accept-encoding",                .value = "gzip, deflate, br" },
    .{ .name = "accept-ranges",                  .value = "bytes" },
    .{ .name = "access-control-allow-headers",   .value = "cache-control" },
    .{ .name = "access-control-allow-headers",   .value = "content-type" },
    .{ .name = "access-control-allow-origin",    .value = "*" },
    // 36-41: cache-control
    .{ .name = "cache-control",       .value = "max-age=0" },
    .{ .name = "cache-control",       .value = "max-age=2592000" },
    .{ .name = "cache-control",       .value = "max-age=604800" },
    .{ .name = "cache-control",       .value = "no-cache" },
    .{ .name = "cache-control",       .value = "no-store" },
    .{ .name = "cache-control",       .value = "public, max-age=31536000" },
    // 42-43: content-encoding
    .{ .name = "content-encoding",    .value = "br" },
    .{ .name = "content-encoding",    .value = "gzip" },
    // 44-54: content-type
    .{ .name = "content-type",        .value = "application/dns-message" },
    .{ .name = "content-type",        .value = "application/javascript" },
    .{ .name = "content-type",        .value = "application/json" },
    .{ .name = "content-type",        .value = "application/x-www-form-urlencoded" },
    .{ .name = "content-type",        .value = "image/gif" },
    .{ .name = "content-type",        .value = "image/jpeg" },
    .{ .name = "content-type",        .value = "image/png" },
    .{ .name = "content-type",        .value = "text/css" },
    .{ .name = "content-type",        .value = "text/html; charset=utf-8" },
    .{ .name = "content-type",        .value = "text/plain" },
    .{ .name = "content-type",        .value = "text/plain;charset=utf-8" },
    // 55: range
    .{ .name = "range",               .value = "bytes=0-" },
    // 56-58: strict-transport-security
    .{ .name = "strict-transport-security", .value = "max-age=31536000" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains" },
    .{ .name = "strict-transport-security", .value = "max-age=31536000; includesubdomains; preload" },
    // 59-60: vary
    .{ .name = "vary",                .value = "accept-encoding" },
    .{ .name = "vary",                .value = "origin" },
    // 61-62: security headers
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "x-xss-protection",       .value = "1; mode=block" },
    // 63-71: :status (remaining)
    .{ .name = ":status",             .value = "100" },
    .{ .name = ":status",             .value = "204" },
    .{ .name = ":status",             .value = "206" },
    .{ .name = ":status",             .value = "302" },
    .{ .name = ":status",             .value = "400" },
    .{ .name = ":status",             .value = "403" },
    .{ .name = ":status",             .value = "421" },
    .{ .name = ":status",             .value = "425" },
    .{ .name = ":status",             .value = "500" },
    // 72: accept-language (name only)
    .{ .name = "accept-language",     .value = "" },
    // 73-78: access-control
    .{ .name = "access-control-allow-credentials", .value = "FALSE" },
    .{ .name = "access-control-allow-credentials", .value = "TRUE" },
    .{ .name = "access-control-allow-headers",     .value = "*" },
    .{ .name = "access-control-allow-methods",     .value = "get" },
    .{ .name = "access-control-allow-methods",     .value = "get, post, options" },
    .{ .name = "access-control-allow-methods",     .value = "options" },
    // 79-83: more access-control + alt-svc
    .{ .name = "access-control-expose-headers",  .value = "content-length" },
    .{ .name = "access-control-request-headers", .value = "content-type" },
    .{ .name = "access-control-request-method",  .value = "get" },
    .{ .name = "access-control-request-method",  .value = "post" },
    .{ .name = "alt-svc",             .value = "clear" },
    // 84-98: remaining headers
    .{ .name = "authorization",        .value = "" },
    .{ .name = "content-security-policy", .value = "script-src 'none'; object-src 'none'; base-uri 'none'" },
    .{ .name = "early-data",           .value = "1" },
    .{ .name = "expect-ct",            .value = "" },
    .{ .name = "forwarded",            .value = "" },
    .{ .name = "if-range",             .value = "" },
    .{ .name = "origin",               .value = "" },
    .{ .name = "purpose",              .value = "prefetch" },
    .{ .name = "server",               .value = "" },
    .{ .name = "timing-allow-origin",  .value = "*" },
    .{ .name = "upgrade-insecure-requests", .value = "1" },
    .{ .name = "user-agent",           .value = "" },
    .{ .name = "x-forwarded-for",      .value = "" },
    .{ .name = "x-frame-options",      .value = "deny" },
    .{ .name = "x-frame-options",      .value = "sameorigin" },
};

comptime {
    std.debug.assert(table.len == 99);
}

/// Returns the static table entry at the given index.
/// Returns null if index is out of range (>= 99).
pub fn get(index: u7) ?Entry {
    if (index >= table.len) return null;
    return table[index];
}

/// Returns the index of the first entry with exact name+value match.
/// Returns null if no match.
pub fn findExact(name: []const u8, value: []const u8) ?u7 {
    for (table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name) and std.mem.eql(u8, entry.value, value)) {
            return @intCast(i);
        }
    }
    return null;
}

/// Returns the index of the first entry matching the given name (any value).
/// Returns null if no match.
pub fn findName(name: []const u8) ?u7 {
    for (table, 0..) |entry, i| {
        if (std.mem.eql(u8, entry.name, name)) {
            return @intCast(i);
        }
    }
    return null;
}

// ----------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------

test "table has 99 entries" {
    try std.testing.expectEqual(@as(usize, 99), table.len);
}

test "get: boundary entries" {
    const first = get(0).?;
    try std.testing.expectEqualStrings(":authority", first.name);
    try std.testing.expectEqualStrings("", first.value);

    const last = get(98).?;
    try std.testing.expectEqualStrings("x-frame-options", last.name);
    try std.testing.expectEqualStrings("sameorigin", last.value);
}

test "get: out of range returns null" {
    try std.testing.expect(get(99) == null);
    try std.testing.expect(get(127) == null);
}

test "get: spot checks from RFC 9204 Appendix A" {
    // Index 1: :path /
    const e1 = get(1).?;
    try std.testing.expectEqualStrings(":path", e1.name);
    try std.testing.expectEqualStrings("/", e1.value);

    // Index 17: :method GET
    const e17 = get(17).?;
    try std.testing.expectEqualStrings(":method", e17.name);
    try std.testing.expectEqualStrings("GET", e17.value);

    // Index 25: :status 200
    const e25 = get(25).?;
    try std.testing.expectEqualStrings(":status", e25.name);
    try std.testing.expectEqualStrings("200", e25.value);

    // Index 31: accept-encoding gzip, deflate, br
    const e31 = get(31).?;
    try std.testing.expectEqualStrings("accept-encoding", e31.name);
    try std.testing.expectEqualStrings("gzip, deflate, br", e31.value);

    // Index 52: content-type text/html; charset=utf-8
    const e52 = get(52).?;
    try std.testing.expectEqualStrings("content-type", e52.name);
    try std.testing.expectEqualStrings("text/html; charset=utf-8", e52.value);

    // Index 85: content-security-policy
    const e85 = get(85).?;
    try std.testing.expectEqualStrings("content-security-policy", e85.name);
    try std.testing.expectEqualStrings("script-src 'none'; object-src 'none'; base-uri 'none'", e85.value);
}

test "findExact: known entries" {
    try std.testing.expectEqual(@as(?u7, 17), findExact(":method", "GET"));
    try std.testing.expectEqual(@as(?u7, 20), findExact(":method", "POST"));
    try std.testing.expectEqual(@as(?u7, 25), findExact(":status", "200"));
    try std.testing.expectEqual(@as(?u7, 0),  findExact(":authority", ""));
    try std.testing.expectEqual(@as(?u7, 98), findExact("x-frame-options", "sameorigin"));
}

test "findExact: no match returns null" {
    try std.testing.expect(findExact(":method", "PATCH") == null);
    try std.testing.expect(findExact("x-custom-header", "value") == null);
    try std.testing.expect(findExact(":status", "418") == null);
}

test "findName: returns first matching index" {
    // :method appears at indices 15-21; findName returns 15 (CONNECT)
    try std.testing.expectEqual(@as(?u7, 15), findName(":method"));

    // :status appears at 24-28 then 63-71; first is 24
    try std.testing.expectEqual(@as(?u7, 24), findName(":status"));

    // unique name
    try std.testing.expectEqual(@as(?u7, 55), findName("range"));
}

test "findName: no match returns null" {
    try std.testing.expect(findName("x-custom-header") == null);
    try std.testing.expect(findName("") == null);
}
