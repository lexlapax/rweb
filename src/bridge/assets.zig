//! The frontend, embedded in the binary. Nothing is loaded from a CDN. xterm.js is vendored
//! with its licence (`web/vendor/LICENSE-xterm.txt`; versions and hashes in docs/phase2-result.md).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Asset = struct {
    path: []const u8,
    content_type: []const u8,
    body: []const u8,
};

pub const all = [_]Asset{
    .{ .path = "/", .content_type = "text/html; charset=utf-8", .body = @embedFile("web/index.html") },
    .{ .path = "/lab", .content_type = "text/html; charset=utf-8", .body = @embedFile("web/lab.html") },
    .{ .path = "/lab.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/lab.js") },
    .{ .path = "/app.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/app.js") },
    .{ .path = "/app.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/app.css") },
    .{ .path = "/vendor/xterm.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/xterm.js") },
    .{ .path = "/vendor/xterm.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/vendor/xterm.css") },
    .{ .path = "/vendor/addon-fit.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/addon-fit.js") },
    .{ .path = "/vendor/LICENSE-xterm.txt", .content_type = "text/plain; charset=utf-8", .body = @embedFile("web/vendor/LICENSE-xterm.txt") },
};

pub fn find(path: []const u8) ?Asset {
    for (all) |a| if (std.mem.eql(u8, a.path, path)) return a;
    return null;
}

pub fn indexOf(path: []const u8) ?usize {
    for (all, 0..) |a, i| if (std.mem.eql(u8, a.path, path)) return i;
    return null;
}

/// The strong validator for an asset: a quoted hex prefix of its SHA-256. Computed once.
pub fn etag(buf: *[2 + 32]u8, body: []const u8) []const u8 {
    var digest: [std.crypto.hash.sha2.Sha256.digest_length]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &digest, .{});
    buf[0] = '"';
    const hex = std.fmt.bytesToHex(digest[0..16].*, .lower);
    @memcpy(buf[1..33], &hex);
    buf[33] = '"';
    return buf[0..34];
}

/// Compress `body` as gzip. Caller frees.
pub fn gzip(gpa: Allocator, body: []const u8) ![]u8 {
    var out: Io.Writer.Allocating = try .initCapacity(gpa, body.len / 3 + 64);
    errdefer out.deinit();
    const window = try gpa.alloc(u8, std.compress.flate.max_window_len);
    defer gpa.free(window);
    var c = try std.compress.flate.Compress.init(&out.writer, window, .gzip, .default);
    try c.writer.writeAll(body);
    try c.finish();
    return out.toOwnedSlice();
}

/// Whether an `Accept-Encoding` header value allows gzip.
pub fn acceptsGzip(value: []const u8) bool {
    var it = std.mem.tokenizeAny(u8, value, ", ");
    while (it.next()) |tok| {
        const semi = std.mem.indexOfScalar(u8, tok, ';') orelse tok.len;
        if (std.ascii.eqlIgnoreCase(tok[0..semi], "gzip")) return !std.mem.eql(u8, std.mem.trim(u8, tok[semi..], "; "), "q=0");
    }
    return false;
}

test "gzip round trips and shrinks the page assets" {
    const gpa = std.testing.allocator;
    const a = find("/app.js").?;
    const z = try gzip(gpa, a.body);
    defer gpa.free(z);
    try std.testing.expect(z.len < a.body.len / 2);
    var in: Io.Reader = .fixed(z);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var d = std.compress.flate.Decompress.init(&in, .gzip, &window);
    var back: Io.Writer.Allocating = .init(gpa);
    defer back.deinit();
    _ = try d.reader.streamRemaining(&back.writer);
    try std.testing.expectEqualSlices(u8, a.body, back.written());
}

test "etag is stable and quoted; acceptsGzip" {
    var b1: [34]u8 = undefined;
    var b2: [34]u8 = undefined;
    try std.testing.expectEqualStrings(etag(&b1, "abc"), etag(&b2, "abc"));
    try std.testing.expect(etag(&b1, "abc")[0] == '"' and etag(&b1, "abc")[33] == '"');
    try std.testing.expect(!std.mem.eql(u8, etag(&b1, "abc"), etag(&b2, "abd")));
    try std.testing.expect(acceptsGzip("gzip, deflate, br"));
    try std.testing.expect(acceptsGzip("br;q=1.0, gzip;q=0.8"));
    try std.testing.expect(!acceptsGzip("br, deflate"));
    try std.testing.expect(!acceptsGzip("gzip;q=0"));
    try std.testing.expect(!acceptsGzip(""));
}
