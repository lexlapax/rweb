//! The frontend, embedded in the binary. Nothing is loaded from a CDN. xterm.js is vendored
//! with its licence (`web/vendor/LICENSE-xterm.txt`; versions and hashes in docs/phase2-result.md).

pub const Asset = struct {
    path: []const u8,
    content_type: []const u8,
    body: []const u8,
};

pub const all = [_]Asset{
    .{ .path = "/", .content_type = "text/html; charset=utf-8", .body = @embedFile("web/index.html") },
    .{ .path = "/app.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/app.js") },
    .{ .path = "/app.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/app.css") },
    .{ .path = "/vendor/xterm.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/xterm.js") },
    .{ .path = "/vendor/xterm.css", .content_type = "text/css; charset=utf-8", .body = @embedFile("web/vendor/xterm.css") },
    .{ .path = "/vendor/addon-fit.js", .content_type = "text/javascript; charset=utf-8", .body = @embedFile("web/vendor/addon-fit.js") },
    .{ .path = "/vendor/LICENSE-xterm.txt", .content_type = "text/plain; charset=utf-8", .body = @embedFile("web/vendor/LICENSE-xterm.txt") },
};

pub fn find(path: []const u8) ?Asset {
    for (all) |a| if (@import("std").mem.eql(u8, a.path, path)) return a;
    return null;
}
