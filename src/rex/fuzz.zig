//! Fuzz targets for every parser that reads bytes from outside. They live apart from the
//! rest because `zig build fuzz` builds without Ghostty (its C++ is not instrumented for
//! fuzzing, so linking it fails); nothing here needs it. They also run as ordinary tests.

const std = @import("std");
const testing = std.testing;
const Allocator = std.mem.Allocator;
const ws = @import("ws.zig");
const rex1 = @import("rex1.zig");
const wire = @import("wire.zig");

/// Collects what the splitter emits, counting bytes.
const Count = struct {
    plain_bytes: usize = 0,
    messages: usize = 0,
    pub fn plain(c: *Count, b: []const u8) !void {
        c.plain_bytes += b.len;
    }
    pub fn message(c: *Count, _: rex1.Message) !void {
        c.messages += 1;
    }
};

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


test "fuzz: splitting the stream anywhere gives the same output and messages" {
    try testing.fuzz({}, struct {
        fn run(_: void, smith: *testing.Smith) anyerror!void {
            var buf: [256]u8 = undefined;
            const n = smith.slice(&buf);
            // Bias towards the interesting bytes.
            for (buf[0..n]) |*b| switch (b.* % 8) {
                0 => b.* = 0x1b,
                1 => b.* = '_',
                2 => b.* = '\\',
                3 => b.* = ';',
                else => {},
            };
            const cut = if (n == 0) 0 else smith.value(u8) % (n + 1);

            var whole = try rex1.Splitter.init(testing.allocator, 1);
            defer whole.deinit();
            var cw: Count = .{};
            try whole.feed(buf[0..n], &cw);
            try whole.finish(&cw);

            var split = try rex1.Splitter.init(testing.allocator, 1);
            defer split.deinit();
            var cs: Count = .{};
            try split.feed(buf[0..cut], &cs);
            try split.feed(buf[cut..n], &cs);
            try split.finish(&cs);

            try testing.expectEqual(cw.plain_bytes, cs.plain_bytes);
            try testing.expectEqual(cw.messages, cs.messages);
            // Never more output than input.
            try testing.expect(cw.plain_bytes <= n);
        }
    }.run, .{});
}
