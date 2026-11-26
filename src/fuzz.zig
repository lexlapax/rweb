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
                .r = &r,
                .w = &out.writer,
                .owns_stream = false,
                .is_client = is_client,
                .max_message = max_message,
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
            const cfg: access.Config = .{ .owner = "owner@example.com", .own_addresses = &.{"100.64.0.5"} };
            const d = access.decide(cfg, .{ .headers = &hs, .is_websocket_upgrade = true });
            if (d == .allow) try testing.expectEqualStrings("owner@example.com", buf[0..third]);
        }
    }.run, .{});
}

test "fuzz originMatchesHost never matches a different host" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [128]u8 = undefined;
            const n = smith.slice(&buf);
            const half = n / 2;
            if (access.originMatchesHost(buf[0..half], buf[half..n])) {
                // Whatever matched must end in the host, case-insensitively.
                const o = buf[0..half];
                const h = buf[half..n];
                try testing.expect(h.len > 0 and o.len >= h.len);
                try testing.expect(std.ascii.eqlIgnoreCase(o[o.len - h.len ..], h));
            }
        }
    }.run, .{});
}
