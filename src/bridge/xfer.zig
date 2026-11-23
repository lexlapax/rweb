//! File transfer, the parts that are about trust rather than bytes.
//!
//! A transfer is two steps. The page asks over its authenticated WebSocket (`dl` / `ul`); the
//! bridge checks the request, and answers with a **token**: 128 random bits, valid for 30
//! seconds, good for exactly one request. The page then fetches `GET /xfer/<token>` (download)
//! or `PUT /xfer/<token>` (upload). So no file is reachable by a URL a web page could guess or
//! be tricked into requesting: the token exists only inside the page that asked.
//!
//! Downloads read through Rex (`download_begin`), which opens regular files only. Uploads are
//! written by the bridge itself into one directory the owner named, never anywhere else, under
//! a sanitized name that cannot replace an existing file; then the quoted path is pasted into the
//! terminal.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Config = struct {
    /// Off unless the owner turns it on: it gives the page the owner's file access.
    enabled: bool = false,
    /// Where uploads go. Null: uploads are off (downloads can still be on).
    upload_dir: ?[]const u8 = null,
    /// The most bytes one transfer may carry, either way.
    max_bytes: u64 = 256 * 1024 * 1024,
};

pub const Kind = enum { download, upload };

/// How long a token lives, how many may be waiting, and how many transfers may run at once.
pub const token_ttl_ms: i64 = 30_000;
pub const max_waiting: usize = 16;
pub const max_running: u32 = 4;

pub const Entry = struct {
    token: [32]u8,
    kind: Kind,
    expires_ms: i64,
    /// Download: the ticket for Rex's bytes stream. Unused for an upload.
    ticket: [16]u8 = @splat(0),
    /// What the file is called (a download: Rex's name for it; an upload: the browser's, to be sanitized).
    name: []u8,
    /// A download: the size Rex reported. An upload: the exact size the browser announced.
    size: u64,
    /// Upload: where to paste the new file's path.
    session_id: []u8 = &.{},
    block_id: []u8 = &.{},

    pub fn deinit(e: *Entry, gpa: Allocator) void {
        gpa.free(e.name);
        gpa.free(e.session_id);
        gpa.free(e.block_id);
    }
};

pub const Registry = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    items: std.ArrayList(Entry) = .empty,
    running: std.atomic.Value(u32) = .init(0),

    pub fn init(gpa: Allocator, io: Io) Registry {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(r: *Registry) void {
        for (r.items.items) |*e| e.deinit(r.gpa);
        r.items.deinit(r.gpa);
    }

    fn now(r: *Registry) i64 {
        return Io.Clock.awake.now(r.io).toMilliseconds();
    }

    /// Take ownership of `e` (its strings), give it a token and a deadline, and return the token.
    /// Fails when too many are waiting; expired entries are dropped first.
    pub fn add(r: *Registry, e_in: Entry) error{TooMany}![32]u8 {
        var e = e_in;
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.sweepLocked();
        if (r.items.items.len >= max_waiting) {
            e.deinit(r.gpa);
            return error.TooMany;
        }
        var raw: [16]u8 = undefined;
        r.io.random(&raw);
        e.token = std.fmt.bytesToHex(raw, .lower);
        e.expires_ms = r.now() + token_ttl_ms;
        r.items.append(r.gpa, e) catch {
            e.deinit(r.gpa);
            return error.TooMany;
        };
        return e.token;
    }

    /// The entry for `token` if it exists, has not expired and is of `kind`; removed, so it is
    /// good once. The caller owns what is returned. The token is compared in constant time.
    pub fn take(r: *Registry, token: []const u8, kind: Kind) ?Entry {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.sweepLocked();
        var found: ?usize = null;
        for (r.items.items, 0..) |e, i| {
            if (token.len != e.token.len) continue;
            var diff: u8 = 0;
            for (e.token, token) |a, b| diff |= a ^ b;
            if (diff == 0) found = i;
        }
        const i = found orelse return null;
        if (r.items.items[i].kind != kind) return null; // a download token cannot start an upload
        return r.items.swapRemove(i);
    }

    fn sweepLocked(r: *Registry) void {
        const t = r.now();
        var i: usize = 0;
        while (i < r.items.items.len) {
            if (r.items.items[i].expires_ms <= t) {
                var e = r.items.swapRemove(i);
                e.deinit(r.gpa);
            } else i += 1;
        }
    }

    /// Reserve one of the running-transfer slots; false when all are in use.
    pub fn acquire(r: *Registry) bool {
        while (true) {
            const n = r.running.load(.acquire);
            if (n >= max_running) return false;
            if (r.running.cmpxchgWeak(n, n + 1, .acq_rel, .acquire) == null) return true;
        }
    }

    pub fn release(r: *Registry) void {
        _ = r.running.fetchSub(1, .acq_rel);
    }
};

/// A file name that is safe to create in the upload directory and to put on a shell line: letters,
/// digits and `. _ - + @ , ( )` and space survive, everything else (including `/`, `\`, control
/// characters and non-ASCII) becomes `_`; leading dots and spaces go (no hidden or `..` names);
/// at most 100 bytes, extension kept. Never empty.
pub fn safeName(out: []u8, name: []const u8) []const u8 {
    std.debug.assert(out.len >= 101);
    // The last path component only, whichever slash the browser used.
    var base = name;
    if (std.mem.lastIndexOfAny(u8, base, "/\\")) |i| base = base[i + 1 ..];
    // A long name is cut in the middle: the start and a short extension survive.
    var stem = base;
    var ext: []const u8 = "";
    if (base.len > 100) {
        const dot = std.mem.lastIndexOfScalar(u8, base, '.');
        if (dot != null and base.len - dot.? <= 12) {
            ext = base[dot.?..];
            stem = base[0 .. 100 - ext.len];
        } else stem = base[0..100];
    }
    var n: usize = 0;
    for ([_][]const u8{ stem, ext }) |part| for (part) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-' or c == '+' or c == '@' or c == ',' or c == '(' or c == ')' or c == ' ';
        out[n] = if (ok) c else '_';
        n += 1;
    };
    const trimmed = std.mem.trim(u8, out[0..n], ". ");
    if (trimmed.len == 0) {
        const fallback = "upload";
        @memcpy(out[0..fallback.len], fallback);
        return out[0..fallback.len];
    }
    if (trimmed.ptr != out.ptr) std.mem.copyForwards(u8, out[0..trimmed.len], trimmed);
    return out[0..trimmed.len];
}

/// The path wrapped for a POSIX shell: single quotes, with `'` written as `'\''`.
pub fn shellQuote(gpa: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, '\'');
    for (s) |c| {
        if (c == '\'') try out.appendSlice(gpa, "'\\''") else try out.append(gpa, c);
    }
    try out.append(gpa, '\'');
    return out.toOwnedSlice(gpa);
}

/// `attachment; filename="<ascii>"; filename*=UTF-8''<percent-encoded>` for any name, in `buf`.
pub fn contentDisposition(buf: []u8, name: []const u8) []const u8 {
    var w: Io.Writer = .fixed(buf);
    w.writeAll("attachment; filename=\"") catch return "attachment";
    var shown: usize = 0;
    for (name) |c| {
        if (shown >= 80) break;
        const ok = c >= 0x20 and c < 0x7f and c != '"' and c != '\\' and c != '%' and c != '/' and c != ';';
        w.writeByte(if (ok) c else '_') catch return "attachment";
        shown += 1;
    }
    w.writeAll("\"; filename*=UTF-8''") catch return "attachment";
    for (name[0..@min(name.len, 120)]) |c| {
        const unreserved = std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
        if (unreserved) {
            w.writeByte(c) catch return "attachment";
        } else {
            w.print("%{X:0>2}", .{c}) catch return "attachment";
        }
    }
    return w.buffered();
}

// ---- tests ----

const testing = std.testing;

fn entry(gpa: Allocator, kind: Kind, name: []const u8) !Entry {
    return .{ .token = undefined, .kind = kind, .expires_ms = 0, .name = try gpa.dupe(u8, name), .size = 3 };
}

test "a token works once, for its own kind only" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .download, "a.txt"));
    try testing.expectEqual(@as(usize, 32), t.len);
    // The wrong kind does not use it up.
    try testing.expect(r.take(&t, .upload) == null);
    var e = r.take(&t, .download).?;
    defer e.deinit(testing.allocator);
    try testing.expectEqualStrings("a.txt", e.name);
    // Used.
    try testing.expect(r.take(&t, .download) == null);
}

test "an unknown, short or altered token is nothing" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .upload, "b.bin"));
    var wrong = t;
    wrong[31] = if (t[31] == 'a') 'b' else 'a';
    try testing.expect(r.take(&wrong, .upload) == null);
    try testing.expect(r.take(t[0..31], .upload) == null);
    try testing.expect(r.take("", .upload) == null);
    var e = r.take(&t, .upload).?; // the real one was not harmed
    e.deinit(testing.allocator);
}

test "tokens are random, and at most max_waiting wait" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    var seen: [max_waiting][32]u8 = undefined;
    for (0..max_waiting) |i| seen[i] = try r.add(try entry(testing.allocator, .download, "x"));
    for (0..max_waiting) |i| for (i + 1..max_waiting) |j| try testing.expect(!std.mem.eql(u8, &seen[i], &seen[j]));
    try testing.expectError(error.TooMany, r.add(try entry(testing.allocator, .download, "x")));
}

test "running transfers are limited" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    for (0..max_running) |_| try testing.expect(r.acquire());
    try testing.expect(!r.acquire());
    r.release();
    try testing.expect(r.acquire());
}

test "safeName keeps names harmless" {
    var buf: [128]u8 = undefined;
    const cases = [_][2][]const u8{
        .{ "report.pdf", "report.pdf" },
        .{ "../../etc/passwd", "passwd" },
        .{ "C:\\Users\\x\\evil.exe", "evil.exe" },
        .{ ".bashrc", "bashrc" },
        .{ "..", "upload" },
        .{ "", "upload" },
        .{ "   ", "upload" },
        .{ "a b (1).txt", "a b (1).txt" },
        .{ "x;rm -rf ~.txt", "x_rm -rf _.txt" },
        .{ "$(reboot)`id`.sh", "_(reboot)_id_.sh" },
        .{ "naïve\x00name\n.txt", "na__ve_name_.txt" },
        .{ "dir/", "upload" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], safeName(&buf, c[0]));
    // Long names are cut and keep their extension.
    var long_buf: [307]u8 = undefined;
    @memset(long_buf[0..300], 'a');
    @memcpy(long_buf[300..], ".tar.gz");
    const out = safeName(&buf, &long_buf);
    try testing.expect(out.len <= 100);
    try testing.expect(std.mem.endsWith(u8, out, ".gz"));
}

test "shellQuote survives anything" {
    const a = testing.allocator;
    for ([_][2][]const u8{
        .{ "/tmp/a b.txt", "'/tmp/a b.txt'" },
        .{ "it's", "'it'\\''s'" },
        .{ "$(x)`y`;|&", "'$(x)`y`;|&'" },
        .{ "", "''" },
    }) |c| {
        const q = try shellQuote(a, c[0]);
        defer a.free(q);
        try testing.expectEqualStrings(c[1], q);
    }
}

test "contentDisposition is an attachment, with a safe ASCII name and the real one encoded" {
    var buf: [400]u8 = undefined;
    try testing.expectEqualStrings("attachment; filename=\"a.txt\"; filename*=UTF-8''a.txt", contentDisposition(&buf, "a.txt"));
    const evil = contentDisposition(&buf, "x\"; filename=\"y\r\nSet-Cookie: a=b");
    try testing.expect(std.mem.indexOfAny(u8, evil, "\r\n") == null);
    try testing.expect(std.mem.indexOf(u8, evil, "filename=\"y") == null);
    try testing.expect(std.mem.startsWith(u8, evil, "attachment; filename=\""));
    const uni = contentDisposition(&buf, "é.txt");
    try testing.expect(std.mem.indexOf(u8, uni, "%C3%A9.txt") != null);
}

test "a token that has expired is nothing, and is dropped" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .download, "old.txt"));
    // Make it 30 seconds old.
    r.mu.lockUncancelable(r.io);
    r.items.items[0].expires_ms = r.now() - 1;
    r.mu.unlock(r.io);
    try testing.expect(r.take(&t, .download) == null);
    try testing.expectEqual(@as(usize, 0), r.items.items.len); // swept, and its memory freed
}
