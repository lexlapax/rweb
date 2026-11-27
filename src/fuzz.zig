//! Fuzz targets for every parser that reads bytes from outside. They live apart from the
//! rest because `zig build fuzz` builds without Ghostty (its C++ is not instrumented for
//! fuzzing, so linking it fails); nothing here needs it. They also run as ordinary tests.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ws = @import("rex/ws.zig");
const rex1 = @import("rex/rex1.zig");
const wire = @import("rex/wire.zig");
const protocol = @import("bridge/protocol.zig");
const access = @import("bridge/access.zig");
const fsparse = @import("bridge/fsparse.zig");
const escape = @import("rex/escape.zig");

/// A corpus entry for a target that reads its input with `smith.slice`: the length first.
fn seed(comptime bytes: []const u8) []const u8 {
    const n = bytes.len;
    return &[4]u8{ n & 0xff, (n >> 8) & 0xff, (n >> 16) & 0xff, n >> 24 } ++ bytes;
}

test "fuzz parseHeader" {
    try std.testing.fuzz({}, struct {
        fn run(_: void, smith: *std.testing.Smith) anyerror!void {
            var buf: [32]u8 = undefined;
            const n = smith.slice(&buf);
            if (ws.parseHeader(buf[0..n], 1 << 20)) |h| {
                try std.testing.expect(h.size <= n and h.size <= 14 and h.len <= 1 << 20);
            } else |_| {}
        }
    }.run, .{});
}

test "fuzz parseHandshake" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [40]u8 = undefined;
            const n = smith.slice(&buf);
            _ = wire.parseHandshake(buf[0..n]) catch {};
        }
    }.run, .{});
}

test "fuzz parseWelcome" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            const w = wire.parseWelcome(testing.allocator, buf[0..n]) catch return;
            if (w.token) |t| testing.allocator.free(t);
        }
    }.run, .{});
}

test "fuzz parseBody" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            _ = rex1.parseBody(arena.allocator(), buf[0..n]) catch {};
        }
    }.run, .{});
}

/// Builds a stream for the splitter from fuzz input: bytes below 0xf0 stand for themselves, and
/// the others for pieces that are rare by chance (the real prefix, a body near `max_body`).
fn splitterStream(gpa: Allocator, ops: []const u8, out: *std.ArrayList(u8)) !void {
    const prefix = "\x1b_rex1;1;";
    var i: usize = 0;
    while (i < ops.len and out.items.len < 1 << 20) : (i += 1) {
        const b = ops[i];
        if (b < 0xf0) {
            try out.append(gpa, b);
            continue;
        }
        const arg: u8 = if (i + 1 < ops.len) ops[i + 1] else 0;
        switch (b - 0xf0) {
            0 => try out.appendSlice(gpa, prefix),
            1 => try out.appendSlice(gpa, "\x1b_rex1;2;"),
            2 => try out.appendSlice(gpa, "\x1b\\"),
            3 => try out.appendSlice(gpa, "{\"type\":\"child_exited\",\"exit_code\":1}"),
            4 => try out.appendSlice(gpa, "{\"type\":\"resize\",\"cols\":2,\"rows\":3,\"owner\":\"o\"}"),
            5 => {
                // A body run of max_body - 2 to max_body + 1 bytes.
                try out.appendNTimes(gpa, 'p', rex1.max_body - 2 + @as(usize, arg % 4));
                i += 1;
            },
            6 => {
                try out.appendSlice(gpa, prefix[0 .. arg % prefix.len]);
                i += 1;
            },
            else => try out.append(gpa, b),
        }
    }
}

test "fuzz: the streaming splitter agrees with the reference, however the stream is cut" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            const a = testing.allocator;
            var ops: [2048]u8 = undefined;
            const n = smith.slice(&ops);
            const cut_seed = smith.value(u32);
            var input: std.ArrayList(u8) = .empty;
            defer input.deinit(a);
            try splitterStream(a, ops[0..n], &input);

            var want: rex1.Trace = .{ .gpa = a };
            defer want.deinit();
            try rex1.referenceSplit(a, 1, input.items, &want);
            try testing.expect(want.plain_bytes.items.len <= input.items.len);

            var whole: rex1.Trace = .{ .gpa = a };
            defer whole.deinit();
            try rex1.streamSplit(a, 1, input.items, &.{}, &whole);
            try want.expectSame(&whole);
            // Fed in one piece, program output between two messages is one call; only a
            // candidate the stream ends inside goes separately, at `finish`.
            try testing.expect(whole.adjacent_plain <= 1);

            // One cut anywhere, then pieces of a varying size.
            const cut = if (input.items.len == 0) 0 else cut_seed % (input.items.len + 1);
            var s = try rex1.Splitter.init(a, 1);
            defer s.deinit();
            var two: rex1.Trace = .{ .gpa = a };
            defer two.deinit();
            try s.feed(input.items[0..cut], &two);
            try s.feed(input.items[cut..], &two);
            try s.finish(&two);
            try want.expectSame(&two);

            var pieces: rex1.Trace = .{ .gpa = a };
            defer pieces.deinit();
            try rex1.streamSplit(a, 1, input.items, &.{ 1 + cut_seed % 61, 1 + (cut_seed >> 8) % 4099 }, &pieces);
            try want.expectSame(&pieces);
        }
    }.run, .{
        .corpus = &.{
            seed("x\x1b_rex1;1;{\"type\":\"child_exited\",\"exit_code\":3}\x1b\\y"),
            seed("\x1b_rex1;1;ab\x1b[31mz"),
            seed("\x1b_rex1;1;{\"type\":\"resize\",\"cols\":80,\"rows\":24}\x1b\x1b_rex1;1;{}\x1b\\"),
            seed("\xf0\xf3\xf2\xf1\xf4\xf2\xf0\xf6\x05"),
            seed("\xf0\xf5\x02\xf2"), // a body of exactly max_body
            seed("\xf0\xf5\x03\xf2"), // one byte over
            seed("\xf0\xf5\x01\x1b[\xf0\xf3\xf2"),
        },
    });
}

test "fuzz snapshotEnd: reading the framing in pieces agrees with reading it whole" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [512]u8 = undefined;
            const n = smith.slice(&buf);
            const step = 1 + smith.value(u8) % 13;
            const limit: usize = 64 + smith.value(u16) % 1024;
            var scan: usize = 0;
            const whole = wire.snapshotEnd(buf[0..n], &scan, limit);
            if (whole) |w| {
                if (w) |end| try testing.expect(end <= n and end <= limit);
            } else |_| {}
            scan = 0;
            var k: usize = 0;
            while (true) : (k = @min(n, k + step)) {
                const part = wire.snapshotEnd(buf[0..k], &scan, limit);
                if (part) |p| {
                    if (p) |end| {
                        try testing.expectEqual(whole, end);
                        break;
                    }
                } else |e| {
                    try testing.expectError(e, whole);
                    break;
                }
                if (k == n) {
                    try testing.expectEqual(@as(?usize, null), try whole);
                    break;
                }
            }
        }
    }.run, .{ .corpus = &.{
        seed("GHOSTSNP\x01\x00" ++ "\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        seed("GHOSTSNP\x01\x00" ++ "\x01\x00\x04\x00\x00\x00\x00\x00\x00\x00abcd" ++ "\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00"),
        seed("GHOSTSNP\x01\x00" ++ "\x02\x00\xff\xff\xff\xff\x00\x00\x00\x00"),
        seed("GHX"),
    } });
}

/// 100 empty pings then 100 empty pongs, unmasked (from a server).
const control_run = blk: {
    var b: [400]u8 = undefined;
    for (0..200) |i| {
        b[2 * i] = if (i < 100) 0x89 else 0x8a;
        b[2 * i + 1] = 0;
    }
    break :blk b;
};

test "fuzz ws readMessage: reassembly over a fixed reader" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [4096]u8 = undefined;
            const n = smith.slice(&buf);
            if (n == 0) return;
            // The first byte picks the side (bit 0: client) and the message limit.
            const is_client = buf[0] & 1 == 1;
            const max_message: u64 = 16 + @as(u64, buf[0] >> 1) * 64;
            var r: std.Io.Reader = .fixed(buf[1..n]);
            var out_buf: [256]u8 = undefined;
            var out: std.Io.Writer.Discarding = .init(&out_buf);
            var c: ws.Conn = .{
                .io = testing.io,
                .stream = undefined,
                .reader = undefined,
                .writer = undefined,
                .http = .{ .r = &r, .w = &out.writer },
                .owns_stream = false,
                .is_client = is_client,
                .max_message = max_message,
                // The real limit (64 a second) would end every input after 64 pings or pongs, so
                // the fuzzer could never reach what follows a long run of them. The limit itself
                // has its own unit tests in ws.zig.
                .control_limit = std.math.maxInt(u32),
            };
            var messages: usize = 0;
            while (messages < 64) : (messages += 1) {
                const m = c.readMessage(testing.allocator) catch break;
                defer testing.allocator.free(m.data);
                try testing.expect(m.data.len <= max_message);
                if (m.opcode == .close) break;
                try testing.expect(m.opcode == .text or m.opcode == .binary);
            }
        }
    }.run, .{
        .corpus = &.{
            seed("\x01\x81\x02hi"), // a client: an unmasked text frame
            seed("\x00\x81\x82\x11\x22\x33\x44\x79\x4b"), // a server: masked "hi"
            seed("\x01\x01\x01a\x89\x00\x80\x01b\x82\x00"), // fragments with a ping between, then binary
            seed("\x01\x88\x02\x03\xe8"), // close 1000
            seed("\x01\x81\x7e\x01\x00"), // a length past the limit
            seed("\x01" ++ &control_run ++ "\x82\x01z"), // 200 control frames, then a message
        },
    });
}

test "fuzz browser protocol" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [1024]u8 = undefined;
            const n = smith.slice(&buf);
            var arena = std.heap.ArenaAllocator.init(testing.allocator);
            defer arena.deinit();
            _ = protocol.parse(arena.allocator(), buf[0..n]) catch {};
        }
    }.run, .{});
}

test "fuzz access decision" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            // Split the bytes into header values; whatever they are, a request that is not
            // exactly the owner's must never be allowed.
            const third = n / 3;
            const hs = [_]access.Header{
                .{ .name = "Tailscale-User-Login", .value = buf[0..third] },
                .{ .name = "X-Forwarded-For", .value = buf[third .. 2 * third] },
                .{ .name = "Origin", .value = buf[2 * third .. n] },
            };
            const cfg: access.Config = .{ .owner = "owner@example.com", .own_addresses = &access.ips(&.{"100.64.0.5"}) };
            const d = access.decide(cfg, .{ .headers = &hs, .is_websocket_upgrade = true });
            if (d == .allow) try testing.expectEqualStrings("owner@example.com", buf[0..third]);
        }
    }.run, .{});
}

test "fuzz originMatches: a match is the page's scheme and the very host asked for" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n = smith.slice(&buf);
            if (n == 0) return;
            const scheme: access.Scheme = if (buf[0] & 1 == 0) .http else .https;
            const half = (n + 1) / 2;
            const o = buf[1..half];
            const h = buf[half..n];
            if (!access.originMatches(scheme, o, h)) return;
            // The origin is the page's scheme and an authority; that authority and the host are the
            // same text, in any case, once a written default port is dropped from either.
            const prefix = switch (scheme) {
                .http => "http://",
                .https => "https://",
            };
            const default = switch (scheme) {
                .http => ":80",
                .https => ":443",
            };
            try testing.expect(o.len > prefix.len and std.ascii.eqlIgnoreCase(o[0..prefix.len], prefix));
            const a = o[prefix.len..];
            const bare_a = if (std.mem.endsWith(u8, a, default)) a[0 .. a.len - default.len] else a;
            const bare_h = if (std.mem.endsWith(u8, h, default)) h[0 .. h.len - default.len] else h;
            try testing.expect(bare_h.len > 0 and std.ascii.eqlIgnoreCase(bare_a, bare_h));
            try testing.expect(std.mem.indexOfAny(u8, a, "/?#@ \t") == null);
        }
    }.run, .{});
}

test "fuzz cleanPaste: no ESC or C1 control survives, and the rest is kept as it was" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const text = buf[0..smith.slice(&buf)];
            const out = protocol.cleanPaste(testing.allocator, text) catch |e| switch (e) {
                error.InvalidUtf8 => return testing.expect(!std.unicode.utf8ValidateSlice(text)),
                error.OutOfMemory => return e,
            };
            defer testing.allocator.free(out);
            try testing.expect(std.unicode.utf8ValidateSlice(out));
            try testing.expect(std.mem.indexOfScalar(u8, out, 0x1b) == null);
            var it = std.unicode.Utf8View.initUnchecked(out).iterator();
            while (it.nextCodepoint()) |c| try testing.expect(c < 0x80 or c > 0x9f);
            // Only removed, never changed: the input with ESC and C1 taken out, by code point.
            var want: std.ArrayList(u8) = .empty;
            defer want.deinit(testing.allocator);
            var in = std.unicode.Utf8View.initUnchecked(text).iterator();
            while (in.nextCodepointSlice()) |c| {
                const cp = std.unicode.utf8Decode(c) catch unreachable; // validated above
                if (cp != 0x1b and (cp < 0x80 or cp > 0x9f)) try want.appendSlice(testing.allocator, c);
            }
            try testing.expectEqualSlices(u8, want.items, out);
        }
    }.run, .{ .corpus = &.{
        seed("plain text\n"),
        seed("a\x1b[31mred\x1b[0m \xc2\x9b2J \xc2\xa0 it\xe2\x80\x99s \xf0\x9f\x98\x80"),
        seed("x\x9by"),
        seed("\xc2"),
    } });
}

test "fuzz escCut: a write ends where it was asked or at the ESC of the sequence it would split" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const text = buf[0..smith.slice(&buf)];
            const n = smith.value(u16) % (text.len + 2);
            const cut = escape.escCut(text, n);
            if (n >= text.len) return testing.expectEqual(n, cut);
            try testing.expect(cut <= n);
            // A cut short of `n` is at an ESC and leaves something to send.
            if (cut < n) try testing.expect(cut > 0 and text[cut] == 0x1b);
        }
    }.run, .{ .corpus = &.{
        seed("abc\x1b[12;3...."),
        seed("ab\x1b]0;title\x07cd...."),
        seed("a\x1b[M\x1b\x1b\x1bb...."),
        seed("x\x1b[<0;12;34M\x1b[<0;12...."),
    } });
}

test "fuzz parseMountInfoLine: fields are pieces of the line, and a line is found by its id" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const line = buf[0..smith.slice(&buf)];
            const mi = fsparse.parseMountInfoLine(line) orelse return;
            const lo = @intFromPtr(line.ptr);
            const hi = lo + line.len;
            for ([_][]const u8{ mi.mount_point, mi.options, mi.fstype, mi.source, mi.super_options }) |f| {
                try testing.expect(std.mem.indexOfScalar(u8, f, ' ') == null);
                if (f.len > 0) try testing.expect(@intFromPtr(f.ptr) >= lo and @intFromPtr(f.ptr) + f.len <= hi);
            }
            // The same line inside a file is found by its id, unless an earlier line has that id.
            if (std.mem.indexOfScalar(u8, line, '\n') == null) {
                const found = fsparse.findMountInfo(line, mi.id) orelse return error.TestExpectedFound;
                try testing.expectEqualStrings(mi.mount_point, found.mount_point);
            }
        }
    }.run, .{ .corpus = &.{
        seed("36 35 98:0 /mnt1 /mnt2 rw,noatime master:1 - ext3 /dev/root rw,errors=continue"),
        seed("22 1 8:1 / / rw - ext4 /dev/sda1 rw"),
        seed("22 1 8:1 / / rw shared:1"),
        seed("x 1 8:1 / / rw - ext4 /dev/sda1"),
    } });
}

test "fuzz checkPosixAcl: a refusal names whom it refuses, and an ACL without write is never refused for it" {
    try testing.fuzz({}, struct {
        const Groups = struct {
            safe_gid: u32,
            fn safe(g: Groups, gid: u32) bool {
                return gid == g.safe_gid;
            }
        };
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const blob = buf[0..smith.slice(&buf)];
            const uid = smith.value(u32) % 4;
            const file_gid = smith.value(u32) % 4;
            const g: Groups = .{ .safe_gid = smith.value(u32) % 4 };
            var who: fsparse.AclWho = .none;
            const got = fsparse.checkPosixAcl(blob, uid, file_gid, g, Groups.safe, &who);
            if (got) |_| {
                try testing.expect(who == .none);
            } else |e| switch (e) {
                error.AclUnreadable => try testing.expect(who == .none),
                error.AclGivesOthersWrite => try testing.expect(who == .user and who.user != 0 and who.user != uid),
                error.AclGivesGroupWrite => try testing.expect(who == .group and !g.safe(who.group)),
            }
            // The same list with every write bit cleared: as readable as before, and never refused
            // for giving write.
            if (blob.len < 4 or (blob.len - 4) % 8 != 0) return testing.expectError(error.AclUnreadable, got);
            var i: usize = 4;
            while (i < blob.len) : (i += 8) blob[i + 2] &= ~@as(u8, fsparse.posix_acl.write);
            const quiet = fsparse.checkPosixAcl(blob, uid, file_gid, g, Groups.safe, null);
            if (got == error.AclUnreadable) {
                try testing.expectError(error.AclUnreadable, quiet);
            } else try quiet;
        }
    }.run, .{
        .corpus = &.{
            // version 2; user_obj rwx, a named user 5 with rwx, group_obj r-x, mask rwx, other r-x
            seed("\x02\x00\x00\x00" ++ "\x01\x00\x07\x00\xff\xff\xff\xff" ++ "\x02\x00\x07\x00\x05\x00\x00\x00" ++
                "\x04\x00\x05\x00\xff\xff\xff\xff" ++ "\x10\x00\x07\x00\xff\xff\xff\xff" ++ "\x20\x00\x05\x00\xff\xff\xff\xff"),
            // a named group 9 with write, under a mask that allows it
            seed("\x02\x00\x00\x00" ++ "\x08\x00\x02\x00\x09\x00\x00\x00" ++ "\x10\x00\x07\x00\xff\xff\xff\xff"),
            seed("\x02\x00\x00\x00\x01"),
            seed("\x01\x00\x00\x00"),
        },
    });
}
