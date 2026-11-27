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
    /// `ESC _ rex1;<nonce>;`. ESC appears in it only at index 0, which the state machine relies
    /// on: after a mismatch inside the prefix, only the mismatching byte can start a new message.
    prefix: []u8,
    /// The candidate message so far: a prefix of `prefix`, or all of it and then the body (which
    /// never holds an ESC), plus a trailing ESC when `esc_pending`. Nothing before it is held, and
    /// it is copied in once; it never exceeds `prefix.len + max_body + 1` bytes.
    held: std.ArrayList(u8) = .empty,
    /// The last byte held is an ESC inside the body: `\` next ends the message, anything else
    /// means the candidate was program output.
    esc_pending: bool = false,

    pub fn init(gpa: Allocator, nonce: u64) !Splitter {
        return .{ .gpa = gpa, .prefix = try gpa.print("\x1b_rex1;{d};", .{nonce}) };
    }

    pub fn deinit(s: *Splitter) void {
        s.gpa.free(s.prefix);
        s.held.deinit(s.gpa);
    }

    /// Feed stream bytes. `sink.plain(bytes)` gets program output in order; `sink.message(m)`
    /// gets each Rex message (its slices are valid only during the call). Plain bytes and messages
    /// reach the sink in exactly the order they appear in the stream. Iterative: each input byte
    /// is looked at once, or twice when it ends a candidate (it may start the next one).
    ///
    /// Program output that is contiguous in `bytes` reaches the sink in one `plain` call, escape
    /// sequences included: a candidate that turns out not to be a message is not passed on by
    /// itself but joins the plain run it sits in (ordinary colour output is one call, not one per
    /// ESC). Only a candidate begun in an earlier call is passed on separately.
    pub fn feed(s: *Splitter, bytes: []const u8, sink: anytype) anyerror!void {
        // Program output in `bytes[pending..]` not yet passed on: it ends where the current
        // candidate begins (`cand`), or at `i` when there is none.
        var pending: ?usize = null;
        // Where the held candidate begins in `bytes`, if it began in this call (then `held` is a
        // copy of `bytes[cand..i]`).
        var cand: ?usize = null;
        var i: usize = 0;
        while (i < bytes.len) {
            const h = s.held.items.len;
            if (h == 0) {
                // Ground: everything up to the next ESC is program output.
                if (pending == null) pending = i;
                const esc = std.mem.indexOfScalarPos(u8, bytes, i, 0x1b) orelse bytes.len;
                if (esc == bytes.len) break;
                try s.held.append(s.gpa, 0x1b);
                cand = esc;
                i = esc + 1;
                continue;
            }
            const b = bytes[i];
            if (h < s.prefix.len) {
                if (b == s.prefix[h]) {
                    try s.held.append(s.gpa, b);
                    i += 1;
                } else {
                    // Not ours. The held bytes hold no other ESC, so they are all program output;
                    // `b` is looked at again from ground, where an ESC starts a new candidate.
                    try s.dropCandidate(&cand, sink);
                }
                continue;
            }
            if (s.esc_pending) {
                s.esc_pending = false;
                if (b == '\\') {
                    i += 1;
                    // A message: the program output before it goes first.
                    if (pending) |p| if (cand.? > p) try sink.plain(bytes[p..cand.?]);
                    pending = null;
                    cand = null;
                    defer s.held.clearRetainingCapacity();
                    try s.deliver(s.held.items[s.prefix.len .. h - 1], sink);
                    continue;
                }
                // An ESC inside the body that is not the terminator: the candidate was program
                // output up to that ESC, and the ESC may start a new candidate with `b`.
                if (cand == null) {
                    try sink.plain(s.held.items[0 .. h - 1]);
                    // The ESC is the last byte held; if it came in this call, the output after
                    // the candidate can still join it in one run.
                    if (i > 0) pending = i - 1;
                }
                if (i > 0) cand = i - 1;
                s.held.items[0] = 0x1b;
                s.held.items.len = 1;
                continue;
            }
            if (b == 0x1b) {
                try s.held.append(s.gpa, b);
                s.esc_pending = true;
                i += 1;
                continue;
            }
            // Body bytes up to the next ESC, while they fit.
            const room = max_body - (h - s.prefix.len);
            const run_end = std.mem.indexOfScalarPos(u8, bytes, i, 0x1b) orelse bytes.len;
            if (run_end - i > room) {
                // Too long to be a message: program output. The bytes after the held ones are
                // plain too (no ESC among them), and ground passes them on.
                try s.dropCandidate(&cand, sink);
                continue;
            }
            try s.held.appendSlice(s.gpa, bytes[i..run_end]);
            i = run_end;
        }
        // The program output not passed on yet: up to the candidate still held, or all of it.
        if (pending) |p| {
            const end = if (s.held.items.len > 0) cand.? else bytes.len;
            if (end > p) try sink.plain(bytes[p..end]);
        }
    }

    /// The held candidate is program output. One that began in this call stays in `bytes` and
    /// joins the pending run; one from an earlier call is passed on now.
    fn dropCandidate(s: *Splitter, cand: *?usize, sink: anytype) anyerror!void {
        if (cand.* != null) {
            s.held.clearRetainingCapacity();
            s.esc_pending = false;
            cand.* = null;
            return;
        }
        try s.flushHeld(sink);
    }

    /// Hand everything held to the sink as program output.
    fn flushHeld(s: *Splitter, sink: anytype) anyerror!void {
        defer {
            s.held.clearRetainingCapacity();
            s.esc_pending = false;
        }
        if (s.held.items.len > 0) try sink.plain(s.held.items);
    }

    /// Flush what is held as program output (the stream ended).
    pub fn finish(s: *Splitter, sink: anytype) !void {
        try s.flushHeld(sink);
    }

    fn deliver(s: *Splitter, body: []const u8, sink: anytype) !void {
        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        // A malformed body is a message of no known type; running out of memory is an error.
        const msg = parseBody(arena_state.allocator(), body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => Message.unknown,
        };
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

// ---- test support: a reference splitter, also used by the fuzz target ----

/// The splitter's rules applied to a whole stream at once: no state across calls, written for
/// clarity, to check `Splitter` against. A candidate at an ESC is the prefix, then a body of at
/// most `max_body` bytes without an ESC, then `ESC \`. A mismatch in the prefix makes the bytes
/// matched so far program output and the mismatching byte is looked at again; an ESC in the body
/// not followed by `\` makes everything before it program output and starts again at that ESC;
/// a body byte past `max_body` makes the candidate, that byte included, program output; a
/// candidate the stream ends inside is program output.
pub fn referenceSplit(gpa: Allocator, nonce: u64, input: []const u8, sink: anytype) !void {
    var buf: [32]u8 = undefined;
    const prefix = std.fmt.bufPrint(&buf, "\x1b_rex1;{d};", .{nonce}) catch unreachable;
    var i: usize = 0;
    while (i < input.len) {
        if (input[i] != 0x1b) {
            const next = std.mem.indexOfScalarPos(u8, input, i, 0x1b) orelse input.len;
            try sink.plain(input[i..next]);
            i = next;
            continue;
        }
        var j = i + 1;
        while (j < input.len and j - i < prefix.len and input[j] == prefix[j - i]) j += 1;
        if (j - i < prefix.len) {
            try sink.plain(input[i..j]);
            i = j;
            continue;
        }
        const body_end = std.mem.indexOfScalarPos(u8, input, j, 0x1b) orelse input.len;
        if (body_end - j > max_body) {
            try sink.plain(input[i .. j + max_body + 1]);
            i = j + max_body + 1;
            continue;
        }
        if (body_end + 1 >= input.len) {
            try sink.plain(input[i..]);
            return;
        }
        if (input[body_end + 1] == '\\') {
            var arena = std.heap.ArenaAllocator.init(gpa);
            defer arena.deinit();
            try sink.message(parseBody(arena.allocator(), input[j..body_end]) catch |e| switch (e) {
                error.OutOfMemory => return error.OutOfMemory,
                else => Message.unknown,
            });
            i = body_end + 2;
        } else {
            try sink.plain(input[i..body_end]);
            i = body_end;
        }
    }
}

/// A sink that records program output and messages in order, so two splitters can be compared
/// byte for byte and message for message.
pub const Trace = struct {
    gpa: Allocator,
    plain_bytes: std.ArrayList(u8) = .empty,
    /// One entry per message: how many plain bytes came before it, then what it said.
    log: std.ArrayList(u8) = .empty,
    messages: usize = 0,
    /// `plain` calls that came right after another `plain` call: program output split in two
    /// where nothing came between.
    adjacent_plain: usize = 0,
    last_was_plain: bool = false,

    pub fn deinit(t: *Trace) void {
        t.plain_bytes.deinit(t.gpa);
        t.log.deinit(t.gpa);
    }

    pub fn plain(t: *Trace, b: []const u8) !void {
        try std.testing.expect(b.len > 0);
        if (t.last_was_plain) t.adjacent_plain += 1;
        t.last_was_plain = true;
        try t.plain_bytes.appendSlice(t.gpa, b);
    }

    pub fn message(t: *Trace, m: Message) !void {
        t.last_was_plain = false;
        t.messages += 1;
        try t.log.print(t.gpa, "@{d} ", .{t.plain_bytes.items.len});
        switch (m) {
            .resize => |r| try t.log.print(t.gpa, "resize {d}x{d} owner={?s};", .{ r.cols, r.rows, r.owner }),
            .theme => |th| try t.log.print(t.gpa, "theme fg={?s} bg={?s} palette={d};", .{ th.foreground, th.background, th.palette.len }),
            .child_exited => |e| try t.log.print(t.gpa, "exit {d};", .{e.exit_code}),
            .unknown => try t.log.appendSlice(t.gpa, "unknown;"),
        }
    }

    pub fn expectSame(want: *const Trace, got: *const Trace) !void {
        try std.testing.expectEqualSlices(u8, want.plain_bytes.items, got.plain_bytes.items);
        try std.testing.expectEqualStrings(want.log.items, got.log.items);
    }
};

/// Feed `input` to a `Splitter` in pieces of the given sizes (cycling), then finish.
pub fn streamSplit(gpa: Allocator, nonce: u64, input: []const u8, chunks: []const usize, sink: anytype) !void {
    var s = try Splitter.init(gpa, nonce);
    defer s.deinit();
    var off: usize = 0;
    var k: usize = 0;
    while (off < input.len) : (k += 1) {
        const n = if (chunks.len == 0) input.len else @max(1, chunks[k % chunks.len]);
        const end = @min(input.len, off + n);
        try s.feed(input[off..end], sink);
        off = end;
    }
    try s.finish(sink);
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

test "an ESC inside a body that is not the terminator keeps its place in the output" {
    // The old splitter gave "[" before the ESC here.
    const input = "\x1b_rex1;5;ab\x1b[31mz";
    for (0..input.len + 1) |cut| {
        var c = try feedAll(5, &.{ input[0..cut], input[cut..] });
        defer c.deinit();
        try testing.expectEqualStrings(input, c.plain_bytes.items);
        try testing.expectEqualStrings("", c.log.items);
    }
    // ...and the ESC can still start a real message.
    var c = try feedAll(5, &.{"\x1b_rex1;5;ab\x1b\x1b_rex1;5;{\"type\":\"child_exited\",\"exit_code\":4}\x1b\\z"});
    defer c.deinit();
    try testing.expectEqualStrings("\x1b_rex1;5;ab\x1bz", c.plain_bytes.items);
    try testing.expectEqualStrings("exit 4;", c.log.items);
}

/// Compare the streaming splitter with the reference on `input`, whole and in pieces.
fn checkAgainstReference(input: []const u8, every_split: bool, rnd: std.Random) !void {
    const a = testing.allocator;
    var want: Trace = .{ .gpa = a };
    defer want.deinit();
    try referenceSplit(a, 7, input, &want);
    try testing.expect(want.plain_bytes.items.len <= input.len);

    var whole: Trace = .{ .gpa = a };
    defer whole.deinit();
    try streamSplit(a, 7, input, &.{}, &whole);
    try want.expectSame(&whole);
    try testing.expect(whole.adjacent_plain <= 1); // one call per run of output (see `feed`)

    var bytewise: Trace = .{ .gpa = a };
    defer bytewise.deinit();
    try streamSplit(a, 7, input, &.{1}, &bytewise);
    try want.expectSame(&bytewise);

    var sizes: [4]usize = undefined;
    for (&sizes) |*z| z.* = 1 + rnd.uintLessThan(usize, 40);
    var random: Trace = .{ .gpa = a };
    defer random.deinit();
    try streamSplit(a, 7, input, &sizes, &random);
    try want.expectSame(&random);

    if (!every_split) return;
    // One splitter and trace for every cut, emptied in between: allocation is the slow part.
    var s = try Splitter.init(a, 7);
    defer s.deinit();
    var got: Trace = .{ .gpa = a };
    defer got.deinit();
    for (0..input.len + 1) |cut| {
        try s.feed(input[0..cut], &got);
        try s.feed(input[cut..], &got);
        try s.finish(&got);
        try want.expectSame(&got);
        got.plain_bytes.clearRetainingCapacity();
        got.log.clearRetainingCapacity();
    }
}

test "the streaming splitter agrees with the reference on random streams" {
    const fragments = [_][]const u8{
        "\x1b_rex1;7;",                                                "\x1b_rex1;8;", "\x1b_rex1;77;", "\x1b_rex1;",
        "\x1b_rex",                                                    "\x1b",         "\\",            "\x1b\\",
        "[",                                                           "_",            ";",             "abc",
        "\x1b[31m",                                                    "\x1b_G",       "7;",            "{\"type\":\"child_exited\",\"exit_code\":2}",
        "{\"type\":\"resize\",\"cols\":3,\"rows\":2,\"owner\":\"o\"}", "{\"type\":",   "not json",
    };
    var prng = std.Random.DefaultPrng.init(0x5eed_0f_5711);
    const rnd = prng.random();
    var input: std.ArrayList(u8) = .empty;
    defer input.deinit(testing.allocator);
    for (0..1500) |round| {
        input.clearRetainingCapacity();
        const n = 1 + rnd.uintLessThan(usize, 16);
        for (0..n) |_| {
            if (rnd.uintLessThan(u8, 10) == 0) {
                try input.append(testing.allocator, rnd.int(u8));
            } else try input.appendSlice(testing.allocator, fragments[rnd.uintLessThan(usize, fragments.len)]);
        }
        try checkAgainstReference(input.items, input.items.len <= 64 or round % 100 == 0, rnd);
    }
}

test "a body of exactly max_body is a message; one byte more is program output" {
    const a = testing.allocator;
    var prng = std.Random.DefaultPrng.init(42);
    const rnd = prng.random();
    const head = "{\"type\":\"child_exited\",\"exit_code\":9,\"pad\":\"";
    const tail = "\"}";
    for ([_]usize{ max_body - 1, max_body, max_body + 1, max_body + 2 }) |body_len| {
        var input: std.ArrayList(u8) = .empty;
        defer input.deinit(a);
        try input.appendSlice(a, "x\x1b_rex1;7;");
        try input.appendSlice(a, head);
        try input.appendNTimes(a, 'p', body_len - head.len - tail.len);
        try input.appendSlice(a, tail);
        try input.appendSlice(a, "\x1b\\y");
        var want: Trace = .{ .gpa = a };
        defer want.deinit();
        try referenceSplit(a, 7, input.items, &want);
        if (body_len <= max_body) {
            try testing.expectEqualStrings("@1 exit 9;", want.log.items);
            try testing.expectEqualStrings("xy", want.plain_bytes.items);
        } else {
            try testing.expectEqual(@as(usize, 0), want.messages);
            try testing.expectEqualSlices(u8, input.items, want.plain_bytes.items);
        }
        try checkAgainstReference(input.items, false, rnd);
        // Cut right around the limit, too.
        const limit_at = 1 + "\x1b_rex1;7;".len + max_body;
        for (limit_at - 2..limit_at + 3) |cut| {
            var s = try Splitter.init(a, 7);
            defer s.deinit();
            var got: Trace = .{ .gpa = a };
            defer got.deinit();
            try s.feed(input.items[0..cut], &got);
            try s.feed(input.items[cut..], &got);
            try s.finish(&got);
            try want.expectSame(&got);
        }
    }
}

/// Counts `plain` calls and keeps their bytes, for the tests of how output is grouped.
const Calls = struct {
    gpa: Allocator,
    plain_calls: usize = 0,
    bytes: std.ArrayList(u8) = .empty,
    messages: usize = 0,

    fn deinit(c: *Calls) void {
        c.bytes.deinit(c.gpa);
    }
    pub fn plain(c: *Calls, b: []const u8) !void {
        try testing.expect(b.len > 0);
        c.plain_calls += 1;
        try c.bytes.appendSlice(c.gpa, b);
    }
    pub fn message(c: *Calls, _: Message) !void {
        c.messages += 1;
    }
};

test "contiguous program output reaches the sink in one call, escape sequences and all" {
    const a = testing.allocator;
    const cases = [_]struct { input: []const u8, calls: usize, messages: usize }{
        .{ .input = "\x1b[31mred\x1b[0m", .calls = 1, .messages = 0 },
        .{ .input = "a\x1b[1;32mb\x1b[0m\x1b]0;title\x07\x1b_G\x1b\\c", .calls = 1, .messages = 0 },
        // An ESC that ends the chunk may start a message: it waits for the next chunk (here the
        // stream's end) and goes on its own.
        .{ .input = "c\x1b[0m\x1b", .calls = 2, .messages = 0 },
        // A look-alike with another nonce, and a body ESC that is not the terminator.
        .{ .input = "x\x1b_rex1;8;{}\x1b\\y\x1b_rex1;7;ab\x1b[0mz", .calls = 1, .messages = 0 },
        // Output, a message, output: one call on each side of it.
        .{ .input = "\x1b[1mA\x1b_rex1;7;{\"type\":\"child_exited\",\"exit_code\":0}\x1b\\\x1b[0mB", .calls = 2, .messages = 1 },
        // Output, then a candidate the chunk ends inside: one call now, the rest held.
        .{ .input = "\x1b[2Jq\x1b_rex1;7;{\"ty", .calls = 2, .messages = 0 },
    };
    for (cases) |cs| {
        var s = try Splitter.init(a, 7);
        defer s.deinit();
        var c: Calls = .{ .gpa = a };
        defer c.deinit();
        try s.feed(cs.input, &c);
        try s.finish(&c);
        try testing.expectEqual(cs.calls, c.plain_calls);
        try testing.expectEqual(cs.messages, c.messages);
        // And the bytes are exactly the reference's.
        var want: Trace = .{ .gpa = a };
        defer want.deinit();
        try referenceSplit(a, 7, cs.input, &want);
        try testing.expectEqualSlices(u8, want.plain_bytes.items, c.bytes.items);
    }
    // Typical colour output in one chunk, many escapes: still one call.
    var big: std.ArrayList(u8) = .empty;
    defer big.deinit(a);
    for (0..2000) |i| try big.print(a, "\x1b[3{d}mword{d}\x1b[0m ", .{ i % 8, i });
    var s = try Splitter.init(a, 7);
    defer s.deinit();
    var c: Calls = .{ .gpa = a };
    defer c.deinit();
    try s.feed(big.items, &c);
    try testing.expectEqual(@as(usize, 1), c.plain_calls);
    try testing.expectEqualSlices(u8, big.items, c.bytes.items);
}

fn bodiesInArena(a: Allocator, bodies: []const []const u8) !void {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    for (bodies) |b| _ = try parseBody(arena.allocator(), b);
}

test "parseBody fails cleanly at every allocation" {
    const bodies = [_][]const u8{
        "{\"type\":\"resize\",\"cols\":80,\"rows\":24,\"owner\":\"client:1\"}",
        "{\"type\":\"theme\",\"foreground\":\"#ffffff\",\"background\":\"#000000\",\"palette\":[\"#000000\",\"#ff0000\",\"#00ff00\"]}",
        "{\"type\":\"child_exited\",\"exit_code\":2}",
        "{\"type\":\"something_new\"}",
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, bodiesInArena, .{@as([]const []const u8, &bodies)});
}
