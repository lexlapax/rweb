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
            // The one link out (to rweb's own page, opened in a new tab; checked in the test below)
            // loads nothing into this page.
            if (std.mem.eql(u8, attr, "href=\"") and std.mem.eql(u8, url, rweb_home)) continue;
            // Relative, so the page also works under a path prefix (the SSH-tunnel cookie path).
            try std.testing.expect(url.len > 0 and url[0] != '/' and std.mem.indexOf(u8, url, "//") == null);
            if (url[0] != '#') {
                var buf: [96]u8 = undefined;
                try std.testing.expect(find(try std.fmt.bufPrint(&buf, "/{s}", .{url})) != null);
            }
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

// The manifest's addresses resolve against its own URL, so relative ones also work under the tunnel's
// path prefix; each icon it names is embedded and has the type it claims.
test "the web app manifest names only embedded icons, by relative paths" {
    const gpa = std.testing.allocator;
    const m = find("/manifest.webmanifest").?.body;
    const Icon = struct { src: []const u8, sizes: []const u8, type: []const u8, purpose: ?[]const u8 = null };
    const Manifest = struct {
        name: []const u8,
        short_name: []const u8,
        start_url: []const u8,
        scope: []const u8,
        display: []const u8,
        background_color: []const u8,
        theme_color: []const u8,
        icons: []const Icon,
    };
    const parsed = try std.json.parseFromSlice(Manifest, gpa, m, .{});
    defer parsed.deinit();
    const v = parsed.value;
    try std.testing.expectEqualStrings("./", v.start_url);
    try std.testing.expectEqualStrings("./", v.scope);
    var maskable = false;
    for (v.icons) |icon| {
        try std.testing.expect(icon.src.len > 0 and icon.src[0] != '/' and std.mem.indexOf(u8, icon.src, "//") == null);
        var buf: [96]u8 = undefined;
        const a = find(try std.fmt.bufPrint(&buf, "/{s}", .{icon.src})) orelse return error.NotEmbedded;
        try std.testing.expectEqualStrings(icon.type, a.content_type);
        // A PNG's width and height are in its header; both must match `sizes`.
        try std.testing.expect(std.mem.startsWith(u8, a.body, "\x89PNG\r\n\x1a\n"));
        const w = std.mem.readInt(u32, a.body[16..20], .big);
        const h = std.mem.readInt(u32, a.body[20..24], .big);
        try std.testing.expectEqualStrings(icon.sizes, try std.fmt.bufPrint(&buf, "{d}x{d}", .{ w, h }));
        if (icon.purpose) |p| maskable = maskable or std.mem.eql(u8, p, "maskable");
    }
    try std.testing.expect(maskable);
}

test "page scripts load and connect by relative paths only" {
    // A root-absolute path would leave the SSH-tunnel path prefix, and its path-scoped cookie, behind.
    for ([_][]const u8{ "/app.js", "/wterm-shim.js", "/lab.js", "/labsel.js", "/lab", "/labsel" }) |name| {
        const body = find(name).?.body;
        for ([_][]const u8{ "'/vendor/", "'/xfer/", "'/wterm-shim", "`/api/", "'/api/", "}/ws", "'/labws", "src=\"/", "href=\"/" }) |bad| {
            if (std.mem.indexOf(u8, body, bad) != null) {
                std.debug.print("{s} contains {s}\n", .{ name, bad });
                return error.AbsolutePath;
            }
        }
    }
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

// All of app.js runs inside `main()`, where `send`, `state` and the rest live. Code added after the
// closing `main().catch(…)` line would run outside it and fail at run time with "send is not defined",
// which nothing else here would notice.
test "app.js has nothing after its main() call" {
    const a = find("/app.js").?;
    const trimmed = std.mem.trimEnd(u8, a.body, " \t\r\n");
    const last_nl = std.mem.lastIndexOfScalar(u8, trimmed, '\n') orelse 0;
    const last_line = std.mem.trim(u8, trimmed[last_nl..], " \t\r\n");
    try std.testing.expect(std.mem.startsWith(u8, last_line, "main().catch("));
}

test "the token form is static: relative embedded files, no inline code, a password field, no address for the token" {
    const page = find("/login.html").?.body;
    for ([_][]const u8{ "src=\"", "href=\"" }) |attr| {
        var rest: []const u8 = page;
        while (std.mem.indexOf(u8, rest, attr)) |i| {
            rest = rest[i + attr.len ..];
            const url = rest[0..std.mem.indexOfScalar(u8, rest, '"').?];
            try std.testing.expect(url.len > 0 and url[0] != '/' and std.mem.indexOf(u8, url, "//") == null);
            var buf: [96]u8 = undefined;
            try std.testing.expect(find(try std.fmt.bufPrint(&buf, "/{s}", .{url})) != null);
        }
    }
    var scripts = std.mem.splitSequence(u8, page, "<script");
    _ = scripts.next();
    while (scripts.next()) |s| try std.testing.expect(std.mem.startsWith(u8, s, " src=\""));
    try std.testing.expect(std.mem.indexOf(u8, page, "<style") == null and std.mem.indexOf(u8, page, " style=") == null);
    for ([_][]const u8{ " onclick=", " onsubmit=", " onload=", " oninput=" }) |h| try std.testing.expect(std.mem.indexOf(u8, page, h) == null);
    try std.testing.expect(std.mem.indexOf(u8, page, "type=\"password\"") != null);
    // A form that submitted itself would put the token somewhere: it has no action, posts, and the
    // page's CSP (`form-action 'none'`) blocks a submission anyway.
    try std.testing.expect(std.mem.indexOf(u8, page, "action=") == null and std.mem.indexOf(u8, page, "method=\"post\"") != null);
    const js = find("/login.js").?.body;
    try std.testing.expect(std.mem.indexOf(u8, js, "'rweb-token'") != null);
    for ([_][]const u8{ "location.search", "innerHTML", "eval(", "localStorage.", "sessionStorage.", "console." }) |bad| {
        try std.testing.expect(std.mem.indexOf(u8, js, bad) == null);
    }
}

/// rweb's own page: the page's only link out (the logo, and "About rweb" in the menu).
pub const rweb_home = "https://github.com/lexlapax/rweb";

test "the page's one link out goes to rweb's own page, in a new tab, with no referrer or opener" {
    const page: []const u8 = @embedFile("web/index.html");
    var links: usize = 0;
    var it = std.mem.splitSequence(u8, page, "<a ");
    _ = it.next();
    while (it.next()) |rest| {
        const tag = rest[0 .. std.mem.indexOfScalar(u8, rest, '>') orelse return error.TestUnexpectedResult];
        if (std.mem.indexOf(u8, tag, "href=\"http") == null) continue;
        links += 1;
        // This page's address names the machine and, through an SSH tunnel, the token's path: none of
        // it may reach the other site, and the other site gets no handle on this window.
        try std.testing.expect(std.mem.indexOf(u8, tag, "href=\"https://github.com/lexlapax/rweb\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, tag, "target=\"_blank\"") != null);
        try std.testing.expect(std.mem.indexOf(u8, tag, "rel=\"noopener noreferrer\"") != null);
    }
    try std.testing.expectEqual(@as(usize, 1), links);
    const script: []const u8 = @embedFile("web/app.js");
    try std.testing.expect(std.mem.indexOf(u8, script, "'_blank', 'noopener,noreferrer'") != null);
}
