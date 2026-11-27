//! The page's files, embedded in the binary, and how each is encoded for the wire. Only std: the
//! build runs `tools/assetgen.zig` over this table to make every asset's ETag and gzip body before the
//! bridge is compiled (`assets.zig` embeds what it made), so nothing is computed on a request.

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
    .{ .path = "/diag.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/diag.js") },
    .{ .path = "/app.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/app.css") },
    // The token form (token mode only; see `server.loginAsset`).
    .{ .path = "/login.html", .content_type = "text/html; charset=utf-8", .body = @embedFile("web/login.html") },
    .{ .path = "/login.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/login.js") },
    .{ .path = "/login.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/login.css") },
    .{ .path = "/manifest.webmanifest", .content_type = "application/manifest+json", .body = @embedFile("web/manifest.webmanifest") },
    .{ .path = "/icons/favicon.svg", .content_type = "image/svg+xml", .body = @embedFile("web/icons/favicon.svg") },
    .{ .path = "/icons/favicon.ico", .content_type = "image/x-icon", .body = @embedFile("web/icons/favicon.ico") },
    .{ .path = "/icons/apple-touch-icon.png", .content_type = "image/png", .body = @embedFile("web/icons/apple-touch-icon.png") },
    .{ .path = "/icons/icon-192.png", .content_type = "image/png", .body = @embedFile("web/icons/icon-192.png") },
    .{ .path = "/icons/icon-512.png", .content_type = "image/png", .body = @embedFile("web/icons/icon-512.png") },
    .{ .path = "/icons/icon-maskable-512.png", .content_type = "image/png", .body = @embedFile("web/icons/icon-maskable-512.png") },
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

/// The strong validator for an asset: a quoted hex prefix of its SHA-256.
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
