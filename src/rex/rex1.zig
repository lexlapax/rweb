//! Splits a terminal stream into program output and Rex's own messages.
//!
//! Rex marks its messages as APC sequences, `ESC _ rex1;<nonce>;<json> ESC \`, where the
//! nonce is the data connection's WELCOME nonce in decimal. A sequence with another nonce is
//! something a program printed, so it stays program output. Input may be split at any byte.
//! Pure: no I/O, so it can be fuzzed.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Longest message body accepted; anything longer is treated as program output.
pub const max_body = 64 * 1024;

pub const Message = union(enum) {
    resize: struct { cols: u16, rows: u16, cell_width_px: u32, cell_height_px: u32, owner: ?[]const u8 },
    theme: struct {
        foreground: ?[]const u8,
        background: ?[]const u8,
        cursor: ?[]const u8,
        scheme: ?[]const u8,
        /// Each `index=RRGGBB`.
        palette: []const []const u8,
    },
    child_exited: struct { exit_code: i64 },
    /// A well-formed message of a type this client does not know, or a malformed body.
    unknown,
};

pub const Splitter = struct {
    gpa: Allocator,
    /// `ESC _ rex1;<nonce>;`
    prefix: []u8,
    /// Bytes held back because they might start a message.
    held: std.ArrayList(u8) = .empty,

    pub fn init(gpa: Allocator, nonce: u64) !Splitter {
        return .{ .gpa = gpa, .prefix = try std.fmt.allocPrint(gpa, "\x1b_rex1;{d};", .{nonce}) };
    }

    pub fn deinit(s: *Splitter) void {
        s.gpa.free(s.prefix);
        s.held.deinit(s.gpa);
    }

    /// Feed stream bytes. `sink.plain(bytes)` gets program output in order; `sink.message(m)`
    /// gets each Rex message (its slices are valid only during the call).
    pub fn feed(s: *Splitter, bytes: []const u8, sink: anytype) anyerror!void {
        var i: usize = 0;
        var plain_start: usize = 0;
        while (i < bytes.len) {
            if (s.held.items.len == 0) {
                // Ground: look for an ESC.
                const esc = std.mem.indexOfScalarPos(u8, bytes, i, 0x1b) orelse {
                    i = bytes.len;
                    break;
                };
                if (esc > plain_start) try sink.plain(bytes[plain_start..esc]);
                plain_start = esc;
                i = esc;
                try s.held.append(s.gpa, bytes[i]);
                i += 1;
                plain_start = i;
                continue;
            }
            // Holding a candidate: take one byte and decide.
            const b = bytes[i];
            i += 1;
            plain_start = i;
            try s.held.append(s.gpa, b);
            const h = s.held.items;
            if (h.len <= s.prefix.len) {
                if (!std.mem.eql(u8, h, s.prefix[0..h.len])) try s.flushHeld(sink);
                continue;
            }
            // Past the prefix: the body runs to ESC \.
            if (h.len > s.prefix.len + max_body + 2) {
                try s.flushHeld(sink);
                continue;
            }
            if (b == 0x1b) {
                // Could be the ST's ESC; or a new candidate. Wait for the next byte.
                continue;
            }
            if (b == '\\' and h[h.len - 2] == 0x1b) {
                const body = h[s.prefix.len .. h.len - 2];
                try s.deliver(body, sink);
                s.held.clearRetainingCapacity();
                continue;
            }
            if (h[h.len - 2] == 0x1b) {
                // ESC not followed by `\` inside a body: not ours. Give back all but the
                // final byte, which may itself start something; re-scan it.
                const last = h[h.len - 1];
                s.held.items.len -= 1;
                try s.flushHeld(sink);
                if (last == 0x1b) {
                    try s.held.append(s.gpa, last);
                } else try sink.plain(&.{last});
            }
        }
        if (s.held.items.len == 0 and plain_start < bytes.len) try sink.plain(bytes[plain_start..]);
    }

    fn flushHeld(s: *Splitter, sink: anytype) anyerror!void {
        if (s.held.items.len == 0) return;
        // A mismatch at byte k means bytes before k are plain, but the mismatching byte could
        // itself be an ESC that starts a real message. Re-scan from there.
        const h = s.held.items;
        const again = std.mem.indexOfScalarPos(u8, h, 1, 0x1b);
        if (again) |k| {
            const rest = try s.gpa.dupe(u8, h[k..]);
            defer s.gpa.free(rest);
            try sink.plain(h[0..k]);
            s.held.clearRetainingCapacity();
            return s.feed(rest, sink);
        }
        try sink.plain(h);
        s.held.clearRetainingCapacity();
    }

    /// Flush what is held as program output (the stream ended).
    pub fn finish(s: *Splitter, sink: anytype) !void {
        try s.flushHeld(sink);
        if (s.held.items.len > 0) {
            try sink.plain(s.held.items);
            s.held.clearRetainingCapacity();
        }
    }

    fn deliver(s: *Splitter, body: []const u8, sink: anytype) !void {
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const msg = parseBody(arena_state.allocator(), body) catch Message.unknown;
        try sink.message(msg);
    }
};

/// Parse a message body. Allocations (the palette list) come from `arena`.
pub fn parseBody(arena: Allocator, body: []const u8) !Message {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{});
    if (v != .object) return .unknown;
    const o = v.object;
    const ty = (o.get("type") orelse return .unknown);
    if (ty != .string) return .unknown;
    if (std.mem.eql(u8, ty.string, "resize")) {
        return .{ .resize = .{
            .cols = u16Field(o, "cols") orelse return .unknown,
            .rows = u16Field(o, "rows") orelse return .unknown,
            .cell_width_px = u32Field(o, "cell_width_px") orelse 0,
            .cell_height_px = u32Field(o, "cell_height_px") orelse 0,
            .owner = strField(o, "owner"),
        } };
    } else if (std.mem.eql(u8, ty.string, "theme")) {
        var palette: std.ArrayList([]const u8) = .empty;
        if (o.get("palette")) |p| if (p == .array) for (p.array.items) |e| if (e == .string) try palette.append(arena, e.string);
        return .{ .theme = .{
            .foreground = strField(o, "foreground"),
            .background = strField(o, "background"),
            .cursor = strField(o, "cursor"),
            .scheme = strField(o, "scheme"),
            .palette = palette.items,
        } };
    } else if (std.mem.eql(u8, ty.string, "child_exited")) {
        const c = o.get("exit_code") orelse return .unknown;
        return if (c == .integer) .{ .child_exited = .{ .exit_code = c.integer } } else .unknown;
    }
    return .unknown;
}

fn strField(o: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = o.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

fn u16Field(o: std.json.ObjectMap, name: []const u8) ?u16 {
    const v = o.get(name) orelse return null;
    return if (v == .integer and v.integer >= 0 and v.integer <= std.math.maxInt(u16)) @intCast(v.integer) else null;
}

fn u32Field(o: std.json.ObjectMap, name: []const u8) ?u32 {
    const v = o.get(name) orelse return null;
    return if (v == .integer and v.integer >= 0 and v.integer <= std.math.maxInt(u32)) @intCast(v.integer) else null;
}

// ---- tests ----

const testing = std.testing;

/// Collects what the splitter emits, as text, for assertions.
const Collect = struct {
    gpa: Allocator,
    plain_bytes: std.ArrayList(u8) = .empty,
    log: std.ArrayList(u8) = .empty,

    fn deinit(c: *Collect) void {
        c.plain_bytes.deinit(c.gpa);
        c.log.deinit(c.gpa);
    }
    pub fn plain(c: *Collect, b: []const u8) !void {
        try c.plain_bytes.appendSlice(c.gpa, b);
    }
    pub fn message(c: *Collect, m: Message) !void {
        switch (m) {
            .resize => |r| try c.log.print(c.gpa, "resize {d}x{d} owner={?s};", .{ r.cols, r.rows, r.owner }),
            .theme => |t| try c.log.print(c.gpa, "theme bg={?s} palette={d};", .{ t.background, t.palette.len }),
            .child_exited => |e| try c.log.print(c.gpa, "exit {d};", .{e.exit_code}),
            .unknown => try c.log.appendSlice(c.gpa, "unknown;"),
        }
    }
};

fn feedAll(nonce: u64, chunks: []const []const u8) !Collect {
    var s = try Splitter.init(testing.allocator, nonce);
    defer s.deinit();
    var c: Collect = .{ .gpa = testing.allocator };
    errdefer c.deinit();
    for (chunks) |ch| try s.feed(ch, &c);
    try s.finish(&c);
    return c;
}

test "splits plain output and messages" {
    var c = try feedAll(42, &.{"abc\x1b_rex1;42;{\"type\":\"resize\",\"cols\":80,\"rows\":24,\"owner\":null}\x1b\\def"});
    defer c.deinit();
    try testing.expectEqualStrings("abcdef", c.plain_bytes.items);
    try testing.expectEqualStrings("resize 80x24 owner=null;", c.log.items);
}

test "a message split at every byte boundary is the same" {
    const input = "x\x1b_rex1;7;{\"type\":\"child_exited\",\"exit_code\":3}\x1b\\y\x1b[31mz";
    for (0..input.len) |cut| {
        var c = try feedAll(7, &.{ input[0..cut], input[cut..] });
        defer c.deinit();
        try testing.expectEqualStrings("xy\x1b[31mz", c.plain_bytes.items);
        try testing.expectEqualStrings("exit 3;", c.log.items);
    }
}

test "a look-alike with another nonce is program output" {
    const lookalike = "\x1b_rex1;99;{\"type\":\"resize\",\"cols\":1,\"rows\":1}\x1b\\";
    var c = try feedAll(42, &.{lookalike});
    defer c.deinit();
    try testing.expectEqualStrings(lookalike, c.plain_bytes.items);
    try testing.expectEqualStrings("", c.log.items);
}

test "other escape sequences pass through, including ones that start like ours" {
    const input = "\x1b[1m\x1b_G\x1b\\\x1b_rex2;1;x\x1b\\\x1b\x1b_rex1;5;{\"type\":\"child_exited\",\"exit_code\":0}\x1b\\";
    var c = try feedAll(5, &.{input});
    defer c.deinit();
    try testing.expectEqualStrings("\x1b[1m\x1b_G\x1b\\\x1b_rex2;1;x\x1b\\\x1b", c.plain_bytes.items);
    try testing.expectEqualStrings("exit 0;", c.log.items);
}

test "unknown and malformed bodies become unknown, not errors" {
    var c = try feedAll(1, &.{ "\x1b_rex1;1;{\"type\":\"future\"}\x1b\\", "\x1b_rex1;1;not json\x1b\\", "\x1b_rex1;1;{\"type\":\"resize\"}\x1b\\" });
    defer c.deinit();
    try testing.expectEqualStrings("unknown;unknown;unknown;", c.log.items);
    try testing.expectEqualStrings("", c.plain_bytes.items);
}

test "theme message" {
    var c = try feedAll(1, &.{"\x1b_rex1;1;{\"type\":\"theme\",\"background\":\"#101010\",\"palette\":[\"1=ff0000\",\"2=00ff00\"]}\x1b\\"});
    defer c.deinit();
    try testing.expectEqualStrings("theme bg=#101010 palette=2;", c.log.items);
}

test "an unfinished message at the end is flushed as program output" {
    var c = try feedAll(3, &.{"a\x1b_rex1;3;{\"type\":"});
    defer c.deinit();
    try testing.expectEqualStrings("a\x1b_rex1;3;{\"type\":", c.plain_bytes.items);
}
