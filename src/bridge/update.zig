//! The update check (owner, 2026-11-27). The bridge asks GitHub's API for rweb's latest release: 10
//! minutes after it starts, then once a day with up to an hour's random spread, so many bridges that
//! started together do not ask together. A newer version is told, never fetched: one line in the log, the
//! page's ⋯ menu (`Hub.setUpdate`), and `rweb doctor`. `--no-update-check` turns it off.
//!
//! What GitHub learns: this machine's address, that it runs rweb, and its version (the User-Agent).
//! The request is plain HTTPS to a fixed address with std's TLS and the system's certificates, answered
//! within 10 seconds and in at most 64 KiB, or it counts as failed and waits for the next round. Only the
//! release's tag and its draft and pre-release flags are read; the link the page shows is made from the
//! version, never taken from the answer.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

const log = std.log.scoped(.rweb);

pub const latest_url = "https://api.github.com/repos/lexlapax/rweb/releases/latest";
/// A release's notes, with its version appended (`Version.format`).
pub const release_page = "https://github.com/lexlapax/rweb/releases/tag/v";

pub const first_check_ms: u64 = 10 * 60 * 1000;
pub const interval_ms: u64 = 24 * 60 * 60 * 1000;
pub const max_spread_ms: u64 = 60 * 60 * 1000;
/// The deadline for one check. It holds while connecting, in TLS and while reading, and on Linux (Zig's
/// own resolver) while looking up the name. On macOS std looks the name up with the system's
/// `getaddrinfo`, which cannot be cancelled, so a stalled resolver holds a check until it gives up; the
/// bridge's checker runs in a task of its own, and only `rweb doctor` waits that long.
pub const timeout_ms: u64 = 10 * 1000;
pub const max_answer = 64 * 1024;

/// A release version, `MAJOR.MINOR.PATCH`. Tags with a pre-release or build suffix are not releases.
pub const Version = struct {
    major: u32,
    minor: u32,
    patch: u32,

    /// `0.2.1` or `v0.2.1`; null for anything else.
    pub fn parse(text: []const u8) ?Version {
        const t = if (std.mem.startsWith(u8, text, "v")) text[1..] else text;
        var it = std.mem.splitScalar(u8, t, '.');
        const v: Version = .{
            .major = part(it.next()) orelse return null,
            .minor = part(it.next()) orelse return null,
            .patch = part(it.next()) orelse return null,
        };
        if (it.next() != null) return null;
        return v;
    }

    fn part(p: ?[]const u8) ?u32 {
        const s = p orelse return null;
        if (s.len == 0 or s.len > 9) return null;
        for (s) |c| if (!std.ascii.isDigit(c)) return null;
        if (s.len > 1 and s[0] == '0') return null; // semver: no leading zeros
        return std.fmt.parseInt(u32, s, 10) catch null;
    }

    pub fn newerThan(a: Version, b: Version) bool {
        if (a.major != b.major) return a.major > b.major;
        if (a.minor != b.minor) return a.minor > b.minor;
        return a.patch > b.patch;
    }

    pub fn eql(a: Version, b: Version) bool {
        return a.major == b.major and a.minor == b.minor and a.patch == b.patch;
    }

    pub fn format(v: Version, w: *Io.Writer) Io.Writer.Error!void {
        try w.print("{d}.{d}.{d}", .{ v.major, v.minor, v.patch });
    }
};

/// The release in an answer of the latest-release API: its version, or null for a draft, a pre-release
/// or a tag that is not a plain version. `error.BadAnswer` when it is not such an answer at all.
pub fn parseLatest(arena: Allocator, body: []const u8) error{ BadAnswer, OutOfMemory }!?Version {
    const Answer = struct { tag_name: []const u8, draft: bool = false, prerelease: bool = false };
    const a = std.json.parseFromSliceLeaky(Answer, arena, body, .{ .ignore_unknown_fields = true }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadAnswer,
    };
    if (a.draft or a.prerelease) return null;
    return Version.parse(a.tag_name);
}

pub const CheckError = error{ Timeout, Failed, BadAnswer, OutOfMemory, Canceled };

/// A failed check in words, for `rweb doctor` and the log.
pub fn errorText(e: CheckError) []const u8 {
    return switch (e) {
        error.Timeout => "no answer within 10 s",
        error.Failed => "the request failed, or GitHub did not answer with the release",
        error.BadAnswer => "GitHub's answer was not a release",
        error.OutOfMemory => "out of memory",
        error.Canceled => "cancelled",
    };
}

/// Ask `url` once for the latest release, within `timeout_ms`. `current` names this rweb in the
/// User-Agent.
pub fn checkOnce(gpa: Allocator, io: Io, url: []const u8, current: Version) CheckError!?Version {
    var buf: [2]Race = undefined;
    var select: Io.Select(Race) = .init(io, &buf);
    select.concurrent(.answer, fetch, .{ gpa, io, url, current }) catch return error.Failed;
    select.concurrent(.deadline, deadline, .{io}) catch {
        _ = select.cancel();
        return error.Failed;
    };
    const first = select.await() catch |e| {
        _ = select.cancel();
        return e;
    };
    _ = select.cancel(); // the other one: its result, if any, is not wanted
    return switch (first) {
        .answer => |r| r,
        .deadline => error.Timeout,
    };
}

const Race = union(enum) { answer: CheckError!?Version, deadline: void };

fn deadline(io: Io) void {
    io.sleep(.fromMilliseconds(timeout_ms), .awake) catch {}; // cancelled: the answer came first
}

fn fetch(gpa: Allocator, io: Io, url: []const u8, current: Version) CheckError!?Version {
    var client: std.http.Client = .{ .allocator = gpa, .io = io };
    defer client.deinit();
    const body = try gpa.alloc(u8, max_answer);
    defer gpa.free(body);
    var w: Io.Writer = .fixed(body);
    var ua_buf: [48]u8 = undefined;
    const ua = std.fmt.bufPrint(&ua_buf, "rweb/{f}", .{current}) catch unreachable; // 6 + 3 * 10 + 2 bytes at most
    const res = client.fetch(.{
        .location = .{ .url = url },
        .response_writer = &w,
        .keep_alive = false,
        // A redirect is not followed: std would follow one to any host, plain HTTP included, and the
        // answer is wanted from GitHub's API over HTTPS only. A 3xx is just not 200 below.
        .redirect_behavior = .unhandled,
        .headers = .{ .user_agent = .{ .override = ua } },
        .extra_headers = &.{
            .{ .name = "accept", .value = "application/vnd.github+json" },
            .{ .name = "x-github-api-version", .value = "2022-11-28" },
        },
    }) catch |e| {
        if (e == error.Canceled) return error.Canceled;
        if (e == error.OutOfMemory) return error.OutOfMemory;
        log.debug("update check: {t}", .{e});
        return error.Failed; // an answer over `max_answer` (WriteFailed) included
    };
    if (res.status != .ok) {
        log.debug("update check: GitHub answered {d}", .{@backingInt(res.status)});
        return error.Failed;
    }
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    return parseLatest(arena.allocator(), w.buffered());
}

/// When the next check is due after one at `now_ms`: a day later plus `spread` (taken from 0 up to
/// `max_spread_ms`).
pub fn nextDue(now_ms: i64, spread: u64) i64 {
    return now_ms + @as(i64, @intCast(interval_ms + spread % (max_spread_ms + 1)));
}

/// The bridge's checker: `run` checks until cancelled and calls `found` once for each newer release.
pub const Checker = struct {
    gpa: Allocator,
    io: Io,
    current: Version,
    url: []const u8 = latest_url,
    ctx: *anyopaque,
    found: *const fn (ctx: *anyopaque, v: Version) void,
    /// The newest release already told about.
    told: ?Version = null,

    pub fn run(c: *Checker) void {
        c.io.sleep(.fromMilliseconds(first_check_ms), .awake) catch return;
        while (true) {
            c.checkAndTell() catch |e| if (e == error.Canceled) return;
            var r: [8]u8 = undefined;
            c.io.random(&r);
            const now = Io.Clock.awake.now(c.io).toMilliseconds();
            const due = nextDue(now, std.mem.readInt(u64, &r, .little));
            c.io.sleep(.fromMilliseconds(due - now), .awake) catch return;
        }
    }

    fn checkAndTell(c: *Checker) error{Canceled}!void {
        const latest = checkOnce(c.gpa, c.io, c.url, c.current) catch |e| {
            if (e == error.Canceled) return error.Canceled;
            log.debug("update check failed: {s}; the next is in a day", .{errorText(e)});
            return;
        } orelse return;
        if (!latest.newerThan(c.current)) return;
        if (c.told) |t| if (!latest.newerThan(t)) return;
        c.told = latest;
        log.info("rweb {f} is available (this is {f}): {s}{f}", .{ latest, c.current, release_page, latest });
        c.found(c.ctx, latest);
    }
};

// ---- tests ----

const testing = std.testing;

test "update: versions parse as plain releases only, and compare" {
    const v = Version.parse("v0.2.1").?;
    try testing.expect(v.eql(.{ .major = 0, .minor = 2, .patch = 1 }));
    try testing.expect(Version.parse("0.10.0").?.newerThan(Version.parse("0.9.9").?));
    try testing.expect(Version.parse("1.0.0").?.newerThan(Version.parse("0.99.99").?));
    try testing.expect(!Version.parse("0.2.0").?.newerThan(Version.parse("0.2.0").?));
    for ([_][]const u8{ "", "v", "0.2", "0.2.0.1", "0.2.0-rc1", "0.2.0+b", "01.2.0", "0.2.x", "v-1.0.0", "1234567890.0.0" }) |bad|
        try testing.expect(Version.parse(bad) == null);
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0.2.1", try std.fmt.bufPrint(&buf, "{f}", .{v}));
}

test "update: the latest-release answer gives its version, never a draft or a pre-release" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expect((try parseLatest(a, "{\"tag_name\":\"v0.3.0\",\"draft\":false,\"prerelease\":false,\"html_url\":\"https://example.com/elsewhere\"}")).?.eql(.{ .major = 0, .minor = 3, .patch = 0 }));
    try testing.expect(try parseLatest(a, "{\"tag_name\":\"v0.3.0\",\"prerelease\":true}") == null);
    try testing.expect(try parseLatest(a, "{\"tag_name\":\"v0.3.0\",\"draft\":true}") == null);
    try testing.expect(try parseLatest(a, "{\"tag_name\":\"nightly\"}") == null);
    try testing.expectError(error.BadAnswer, parseLatest(a, "{\"message\":\"Not Found\"}"));
    try testing.expectError(error.BadAnswer, parseLatest(a, "[]"));
    try testing.expectError(error.BadAnswer, parseLatest(a, "{\"tag_name\":7}"));
}

test "update: the next check is a day later, plus up to an hour" {
    try testing.expectEqual(@as(i64, 1000 + interval_ms), nextDue(1000, 0));
    try testing.expectEqual(@as(i64, 1000 + interval_ms + max_spread_ms), nextDue(1000, max_spread_ms));
    try testing.expect(nextDue(0, std.math.maxInt(u64)) <= interval_ms + max_spread_ms);
}

/// A one-shot HTTP server on 127.0.0.1 that answers the first request with `status`, `extra` header
/// lines and `body`, or never answers (`hang`), for the checker's tests. `asked` is set once a request
/// has arrived.
const TestServer = struct {
    server: Io.net.Server,
    port: u16,
    status: []const u8,
    body: []const u8,
    hang: bool = false,
    extra: []const u8 = "",
    asked: std.atomic.Value(bool) = .init(false),

    fn init(io: Io, status: []const u8, body: []const u8, hang: bool) !TestServer {
        const addr: Io.net.IpAddress = .{ .ip4 = .loopback(0) };
        var server = try addr.listen(io, .{});
        return .{ .server = server, .port = server.socket.address.getPort(), .status = status, .body = body, .hang = hang };
    }

    fn serveOne(t: *TestServer, io: Io) void {
        const conn = t.server.accept(io) catch return;
        defer conn.close(io);
        var rbuf: [4096]u8 = undefined;
        var r = conn.reader(io, &rbuf);
        while (true) {
            const line = r.interface.takeDelimiterInclusive('\n') catch return;
            if (std.mem.trimEnd(u8, line, "\r\n").len == 0) break;
        }
        t.asked.store(true, .release);
        if (t.hang) {
            io.sleep(.fromSeconds(60), .awake) catch {}; // until the test cancels it
            return;
        }
        var wbuf: [1024]u8 = undefined;
        var w = conn.writer(io, &wbuf);
        w.interface.print("HTTP/1.1 {s}\r\ncontent-type: application/json\r\ncontent-length: {d}\r\nconnection: close\r\n{s}\r\n{s}", .{ t.status, t.body.len, t.extra, t.body }) catch return;
        w.interface.flush() catch {}; // the test reads what arrived
    }
};

test "update: one check reads the answer, refuses errors and big answers" {
    const io = testing.io;
    const gpa = testing.allocator;
    const current: Version = .{ .major = 0, .minor = 2, .patch = 0 };
    var url_buf: [64]u8 = undefined;
    {
        var s = try TestServer.init(io, "200 OK", "{\"tag_name\":\"v0.2.1\",\"draft\":false,\"prerelease\":false}", false);
        defer s.server.deinit(io);
        var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
        defer task.cancel(io);
        const got = try checkOnce(gpa, io, try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port}), current);
        try testing.expect(got.?.eql(.{ .major = 0, .minor = 2, .patch = 1 }));
    }
    {
        var s = try TestServer.init(io, "404 Not Found", "{\"message\":\"Not Found\"}", false);
        defer s.server.deinit(io);
        var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
        defer task.cancel(io);
        try testing.expectError(error.Failed, checkOnce(gpa, io, try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port}), current));
    }
    {
        const big = try gpa.alloc(u8, max_answer + 1);
        defer gpa.free(big);
        @memset(big, ' ');
        var s = try TestServer.init(io, "200 OK", big, false);
        defer s.server.deinit(io);
        var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
        defer task.cancel(io);
        try testing.expectError(error.Failed, checkOnce(gpa, io, try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port}), current));
    }
}

test "update: a redirect is not followed, and where it points is never asked" {
    const io = testing.io;
    const gpa = testing.allocator;
    const current: Version = .{ .major = 0, .minor = 2, .patch = 0 };
    // Where the redirect points: it would answer with a newer release.
    var there = try TestServer.init(io, "200 OK", "{\"tag_name\":\"v9.9.9\"}", false);
    defer there.server.deinit(io);
    var there_task = try io.concurrent(TestServer.serveOne, .{ &there, io });
    defer there_task.cancel(io);
    var url_buf: [64]u8 = undefined;
    var loc_buf: [96]u8 = undefined;
    for ([_][]const u8{ "301 Moved Permanently", "302 Found", "307 Temporary Redirect", "308 Permanent Redirect" }) |status| {
        var s = try TestServer.init(io, status, "", false);
        defer s.server.deinit(io);
        s.extra = try std.fmt.bufPrint(&loc_buf, "location: http://127.0.0.1:{d}/latest\r\n", .{there.port});
        var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
        defer task.cancel(io);
        try testing.expectError(error.Failed, checkOnce(gpa, io, try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port}), current));
        try testing.expect(s.asked.load(.acquire));
    }
    try testing.expect(!there.asked.load(.acquire));
}

test "update: a server that never answers is given up after the deadline" {
    const io = testing.io;
    var s = try TestServer.init(io, "200 OK", "", true);
    defer s.server.deinit(io);
    var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
    defer task.cancel(io);
    var url_buf: [64]u8 = undefined;
    const t0 = Io.Clock.awake.now(io).toMilliseconds();
    try testing.expectError(error.Timeout, checkOnce(testing.allocator, io, try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port}), .{ .major = 0, .minor = 2, .patch = 0 }));
    const took = Io.Clock.awake.now(io).toMilliseconds() - t0;
    try testing.expect(took >= timeout_ms - 100 and took < timeout_ms + 5000);
}

test "update: a newer release is told once, an older or equal one never" {
    const Seen = struct {
        n: u32 = 0,
        last: ?Version = null,
        fn found(ctx: *anyopaque, v: Version) void {
            const s: *@This() = @ptrCast(@alignCast(ctx));
            s.n += 1;
            s.last = v;
        }
    };
    const io = testing.io;
    var seen: Seen = .{};
    var url_buf: [64]u8 = undefined;
    var c: Checker = .{ .gpa = testing.allocator, .io = io, .current = .{ .major = 0, .minor = 2, .patch = 0 }, .ctx = &seen, .found = Seen.found };
    for ([_][]const u8{ "v0.1.9", "v0.2.0", "v0.2.1", "v0.2.1", "v0.3.0" }) |tag| {
        var body_buf: [96]u8 = undefined;
        const body = try std.fmt.bufPrint(&body_buf, "{{\"tag_name\":\"{s}\"}}", .{tag});
        var s = try TestServer.init(io, "200 OK", body, false);
        defer s.server.deinit(io);
        var task = try io.concurrent(TestServer.serveOne, .{ &s, io });
        defer task.cancel(io);
        c.url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/latest", .{s.port});
        try c.checkAndTell();
    }
    try testing.expectEqual(@as(u32, 2), seen.n); // 0.2.1 once, then 0.3.0
    try testing.expect(seen.last.?.eql(.{ .major = 0, .minor = 3, .patch = 0 }));
}
