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
    .{ .path = "/labsel", .content_type = "text/html; charset=utf-8", .body = @embedFile("web/labsel.html") },
    .{ .path = "/labsel.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/labsel.js") },
    .{ .path = "/app.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/app.js") },
    .{ .path = "/keys.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/keys.js") },
    .{ .path = "/app.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/app.css") },
    .{ .path = "/vendor/xterm.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/xterm.js") },
    .{ .path = "/vendor/xterm.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/vendor/xterm.css") },
    .{ .path = "/vendor/addon-fit.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/addon-fit.js") },
    .{ .path = "/wterm-shim.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/wterm-shim.js") },
    .{ .path = "/vendor/wterm.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/wterm.js") },
    .{ .path = "/vendor/wterm.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/vendor/wterm.css") },
    .{ .path = "/vendor/ghostty-vt.wasm", .content_type = "application/wasm", .body = @embedFile("web/vendor/ghostty-vt.wasm") },
    .{ .path = "/vendor/LICENSE-wterm.txt", .content_type = "text/plain; charset=utf-8", .body = @embedFile("web/vendor/LICENSE-wterm.txt") },
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

test "the page references only files that are embedded, and carries no inline code" {
    const page = find("/").?.body;
    var rest: []const u8 = page;
    var refs: usize = 0;
    // Every src="..." and href="..." on the page is a local path that exists.
    for ([_][]const u8{ "src=\"", "href=\"" }) |attr| {
        rest = page;
        while (std.mem.indexOf(u8, rest, attr)) |i| {
            rest = rest[i + attr.len ..];
            const end = std.mem.indexOfScalar(u8, rest, '"').?;
            const url = rest[0..end];
            try std.testing.expect(url.len > 0 and (url[0] == '/' or url[0] == '#'));
            if (url[0] == '/') try std.testing.expect(find(url) != null);
            refs += 1;
        }
    }
    try std.testing.expect(refs >= 5);
    // A strict content security policy forbids inline scripts, so there must be none.
    var scripts = std.mem.splitSequence(u8, page, "<script");
    _ = scripts.next();
    while (scripts.next()) |s| try std.testing.expect(std.mem.startsWith(u8, s, " src=\""));
    try std.testing.expect(std.mem.indexOf(u8, page, " onclick=") == null);
    try std.testing.expect(std.mem.indexOf(u8, page, "<style") == null);
}

test "the page script uses no browser pop-ups and no HTML injection" {
    const js = find("/app.js").?.body;
    try std.testing.expect(std.mem.indexOf(u8, js, "confirm(") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "prompt(") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "alert(") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "innerHTML") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "outerHTML") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "insertAdjacentHTML") == null);
    try std.testing.expect(std.mem.indexOf(u8, js, "eval(") == null);
}

// Vendored code runs in the owner's browser with the page's authority. Each file's hash is pinned
// in `web/vendor/SHA256SUMS` (made when the file was fetched, see docs/phase3-result.md); a changed
// file fails this test until a person updates the manifest on purpose.
test "vendored files match their pinned checksums" {
    const manifest = @embedFile("web/vendor/SHA256SUMS");
    var seen: usize = 0;
    var lines = std.mem.tokenizeScalar(u8, manifest, '\n');
    while (lines.next()) |line| {
        var parts = std.mem.tokenizeAny(u8, line, " \t");
        const want = parts.next() orelse continue;
        const name = parts.next() orelse return error.BadManifest;
        var path_buf: [64]u8 = undefined;
        const path = try std.fmt.bufPrint(&path_buf, "/vendor/{s}", .{name});
        const a = find(path) orelse return error.NotEmbedded;
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(a.body, &digest, .{});
        const got = std.fmt.bytesToHex(digest, .lower);
        try std.testing.expectEqualStrings(want, &got);
        seen += 1;
    }
    // Every vendored asset is in the manifest.
    var vendored: usize = 0;
    for (all) |a| if (std.mem.startsWith(u8, a.path, "/vendor/")) {
        vendored += 1;
    };
    try std.testing.expectEqual(vendored, seen);
}
