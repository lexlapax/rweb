//! The terminal mirror: a libghostty-vt terminal that follows one block's stream.
//!
//! It decodes the snapshot the stream starts with, strips Rex's own messages from the
//! output, applies the output, and can produce a VT redraw that recreates its state on a
//! fresh terminal (what a browser needs on connect, and after every Rex resize, because
//! reflow differs between emulators).
//!
//! One mutex guards everything. The data reader task feeds it; viewers call `redraw` and the
//! getters. Observer callbacks run under the mutex on the feeding task, so they must be
//! quick and must not call back into the mirror.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ghostty_vt = @import("ghostty-vt");
const rex1 = @import("rex1.zig");
const data = @import("data.zig");

const log = std.log.scoped(.rex_mirror);

/// Biggest snapshot accepted.
pub const max_snapshot = 256 * 1024 * 1024;

pub const Status = enum { waiting_for_snapshot, live, failed };

/// The terminal's default colors, as Rex sent them (`RRGGBB` or `#RRGGBB`).
pub const Theme = struct {
    arena: std.heap.ArenaAllocator,
    foreground: ?[]const u8 = null,
    background: ?[]const u8 = null,
    cursor: ?[]const u8 = null,
    scheme: ?[]const u8 = null,
    /// Each `index=RRGGBB`.
    palette: []const []const u8 = &.{},
};

pub const Observer = struct {
    ctx: *anyopaque,
    /// Program output, already applied to the mirror. Rex's messages are not in it.
    output: ?*const fn (ctx: *anyopaque, bytes: []const u8) void = null,
    /// The size changed, so viewers need a fresh `redraw`.
    resized: ?*const fn (ctx: *anyopaque, cols: u16, rows: u16) void = null,
    theme: ?*const fn (ctx: *anyopaque, theme: *const Theme) void = null,
    exited: ?*const fn (ctx: *anyopaque, exit_code: i64) void = null,
};

pub const Mirror = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    observer: ?Observer = null,

    status: Status = .waiting_for_snapshot,
    snap: std.ArrayList(u8) = .empty,
    term: ghostty_vt.Terminal = undefined,
    vt: ghostty_vt.TerminalStream = undefined,
    /// Set once the channel nonce is known.
    splitter: ?rex1.Splitter = null,
    theme: ?Theme = null,
    /// Owner of the block when it was last sized, if any.
    owner: ?[]u8 = null,
    exit_code: ?i64 = null,
    /// Goes up on every change a viewer could see.
    version: u64 = 0,
    snapshot_bytes: usize = 0,

    /// A mirror that learns its nonce from the data connection's welcome (see `sink`).
    pub fn initPending(gpa: Allocator, io: Io) !*Mirror {
        const m = try gpa.create(Mirror);
        m.* = .{ .gpa = gpa, .io = io };
        return m;
    }

    pub fn init(gpa: Allocator, io: Io, nonce: u64) !*Mirror {
        const m = try initPending(gpa, io);
        errdefer m.deinit();
        try m.setNonce(nonce);
        return m;
    }

    pub fn setNonce(m: *Mirror, nonce: u64) !void {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.splitter) |*s| s.deinit();
        m.splitter = try rex1.Splitter.init(m.gpa, nonce);
    }

    pub fn deinit(m: *Mirror) void {
        if (m.status == .live) m.term.deinit(m.gpa);
        m.snap.deinit(m.gpa);
        if (m.splitter) |*s| s.deinit();
        if (m.theme) |*t| t.arena.deinit();
        if (m.owner) |o| m.gpa.free(o);
        m.gpa.destroy(m);
    }

    /// Adapter for `data.Data`. The mirror must outlive the stream.
    pub fn sink(m: *Mirror) data.Sink {
        return .{ .ctx = m, .bytes = sinkBytes, .ended = sinkEnded, .welcome = sinkWelcome };
    }

    fn sinkBytes(ctx: *anyopaque, bytes: []const u8) void {
        const m: *Mirror = @ptrCast(@alignCast(ctx));
        m.feed(bytes) catch |e| {
            log.err("mirror failed: {t}", .{e});
            m.mu.lockUncancelable(m.io);
            m.status = .failed;
            m.mu.unlock(m.io);
        };
    }

    fn sinkWelcome(ctx: *anyopaque, nonce: u64) void {
        const m: *Mirror = @ptrCast(@alignCast(ctx));
        m.setNonce(nonce) catch |e| log.err("nonce: {t}", .{e});
    }

    fn sinkEnded(_: *anyopaque, _: data.End) void {}

    pub fn setObserver(m: *Mirror, o: ?Observer) void {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        m.observer = o;
    }

    /// Feed stream bytes, in order, exactly as received.
    pub fn feed(m: *Mirror, bytes: []const u8) !void {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        switch (m.status) {
            .failed => return error.MirrorFailed,
            .live => return m.splitter.?.feed(bytes, m),
            .waiting_for_snapshot => {},
        }
        if (m.splitter == null) return error.NoNonce;
        try m.snap.appendSlice(m.gpa, bytes);
        var reader: Io.Reader = .fixed(m.snap.items);
        var decoded = ghostty_vt.snapshot.decode(m.gpa, m.io, &reader, .{
            .max_continuation_bytes = 1 << 20,
        }) catch |e| switch (e) {
            error.EndOfStream => {
                if (m.snap.items.len > max_snapshot) return error.SnapshotTooLarge;
                return; // wait for more bytes
            },
            else => return e,
        };
        defer decoded.deinit(m.gpa);
        const used = reader.seek;
        m.term = decoded.toOwned();
        m.vt = m.term.vtStream();
        switch (decoded.continuation) {
            .ground => {},
            .bytes => |b| m.vt.nextSlice(b),
        }
        m.status = .live;
        m.snapshot_bytes = used;
        m.version += 1;
        const rest = try m.gpa.dupe(u8, m.snap.items[used..]);
        defer m.gpa.free(rest);
        m.snap.clearAndFree(m.gpa);
        try m.splitter.?.feed(rest, m);
    }

    // Splitter sink.
    pub fn plain(m: *Mirror, bytes: []const u8) !void {
        if (bytes.len == 0) return;
        m.vt.nextSlice(bytes);
        m.version += 1;
        if (m.observer) |o| if (o.output) |f| f(o.ctx, bytes);
    }

    pub fn message(m: *Mirror, msg: rex1.Message) !void {
        switch (msg) {
            .resize => |r| {
                try m.term.resize(m.gpa, .{ .cols = r.cols, .rows = r.rows });
                if (m.owner) |old| m.gpa.free(old);
                m.owner = if (r.owner) |ow| try m.gpa.dupe(u8, ow) else null;
                m.version += 1;
                if (m.observer) |o| if (o.resized) |f| f(o.ctx, r.cols, r.rows);
            },
            .theme => |t| {
                var arena = std.heap.ArenaAllocator.init(m.gpa);
                errdefer arena.deinit();
                const a = arena.allocator();
                const palette = try a.alloc([]const u8, t.palette.len);
                for (t.palette, palette) |src, *dst| dst.* = try a.dupe(u8, src);
                const new: Theme = .{
                    .arena = arena,
                    .foreground = if (t.foreground) |s| try a.dupe(u8, s) else null,
                    .background = if (t.background) |s| try a.dupe(u8, s) else null,
                    .cursor = if (t.cursor) |s| try a.dupe(u8, s) else null,
                    .scheme = if (t.scheme) |s| try a.dupe(u8, s) else null,
                    .palette = palette,
                };
                if (m.theme) |*old| old.arena.deinit();
                m.theme = new;
                m.version += 1;
                if (m.observer) |o| if (o.theme) |f| f(o.ctx, &m.theme.?);
            },
            .child_exited => |e| {
                m.exit_code = e.exit_code;
                m.version += 1;
                if (m.observer) |o| if (o.exited) |f| f(o.ctx, e.exit_code);
            },
            .unknown => {},
        }
    }

    pub const Size = struct { cols: u16, rows: u16 };

    pub fn size(m: *Mirror) ?Size {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return null;
        return .{ .cols = m.term.cols, .rows = m.term.rows };
    }

    pub fn getStatus(m: *Mirror) Status {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        return m.status;
    }

    /// Keep trailing blank rows so the viewer's screen top matches the mirror's.
    const redraw_opts: ghostty_vt.formatter.Options = .{ .emit = .vt, .trim = false };

    /// A VT byte stream that recreates the mirror's state on a fresh terminal. Caller frees.
    pub fn redraw(m: *Mirror, gpa: Allocator) ![]u8 {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return error.NotLive;
        var out: Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll("\x1bc"); // RIS: start the viewer from a clean terminal
        // The formatter draws only the active screen. While a full-screen program has the
        // alternate screen, draw the primary screen first; the modes that follow switch the
        // viewer to the alternate screen (saving this cursor).
        if (m.term.screens.active_key == .alternate) {
            if (m.term.screens.get(.primary)) |primary| {
                var pf: ghostty_vt.formatter.ScreenFormatter = .init(primary, redraw_opts);
                pf.extra = .all;
                try pf.format(w);
            }
        }
        var f: ghostty_vt.formatter.TerminalFormatter = .init(&m.term, redraw_opts);
        f.extra = .all;
        try f.format(w);
        return out.toOwnedSlice();
    }

    /// The visible screen as plain text, for tests and logs. Caller frees.
    pub fn plainText(m: *Mirror, gpa: Allocator) ![]u8 {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return error.NotLive;
        var out: Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        var f: ghostty_vt.formatter.TerminalFormatter = .init(&m.term, .plain);
        try f.format(&out.writer);
        return out.toOwnedSlice();
    }
};

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");
const Control = @import("control.zig").Control;

fn makeStream(gpa: Allocator, nonce: u64, cols: u16, rows: u16, program_output: []const u8) ![]u8 {
    var t = try ghostty_vt.Terminal.init(testing.io, gpa, .{ .cols = cols, .rows = rows });
    defer t.deinit(gpa);
    var vt = t.vtStream();
    vt.nextSlice(program_output);
    var aw: Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try ghostty_vt.snapshot.encode(gpa, &aw.writer, &t, .{ .continuation = .ground });
    try aw.writer.print("\x1b_rex1;{d};{{\"type\":\"resize\",\"cols\":{d},\"rows\":{d},\"owner\":null}}\x1b\\", .{ nonce, cols, rows });
    return aw.toOwnedSlice();
}

test "mirror: snapshot, then output, fed one byte at a time" {
    const a = testing.allocator;
    const stream = try makeStream(a, 9, 40, 5, "first line\r\n");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 9);
    defer m.deinit();
    for (stream) |b| try m.feed(&.{b});
    try m.feed("second \x1b[31mred\x1b[0m\r\n");
    try testing.expectEqual(Status.live, m.getStatus());
    try testing.expectEqual(Mirror.Size{ .cols = 40, .rows = 5 }, m.size().?);
    const text = try m.plainText(a);
    defer a.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "first line") != null);
    try testing.expect(std.mem.indexOf(u8, text, "second red") != null);
}

test "mirror: output before the snapshot completes is not lost" {
    const a = testing.allocator;
    const stream = try makeStream(a, 4, 20, 3, "snap\r\n");
    defer a.free(stream);
    const tail = "after";
    const all = try std.mem.concat(a, u8, &.{ stream, tail });
    defer a.free(all);
    const m = try Mirror.init(a, testing.io, 4);
    defer m.deinit();
    try m.feed(all[0 .. all.len / 2]);
    try m.feed(all[all.len / 2 ..]);
    const text = try m.plainText(a);
    defer a.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "snap") != null);
    try testing.expect(std.mem.indexOf(u8, text, "after") != null);
}

test "mirror: a resize message changes the size and tells the observer; theme and exit are kept" {
    const a = testing.allocator;
    const stream = try makeStream(a, 2, 20, 4, "x");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 2);
    defer m.deinit();
    const Obs = struct {
        var resized: ?Mirror.Size = null;
        var exit: ?i64 = null;
        var out_len: usize = 0;
        fn onResize(_: *anyopaque, c: u16, r: u16) void {
            resized = .{ .cols = c, .rows = r };
        }
        fn onExit(_: *anyopaque, code: i64) void {
            exit = code;
        }
        fn onOut(_: *anyopaque, b: []const u8) void {
            out_len += b.len;
        }
    };
    var dummy: u8 = 0;
    try m.feed(stream);
    m.setObserver(.{ .ctx = &dummy, .resized = Obs.onResize, .exited = Obs.onExit, .output = Obs.onOut });
    try m.feed("\x1b_rex1;2;{\"type\":\"resize\",\"cols\":30,\"rows\":8,\"owner\":\"client:1\"}\x1b\\");
    try m.feed("\x1b_rex1;2;{\"type\":\"theme\",\"background\":\"#102030\",\"palette\":[\"1=ff0000\"]}\x1b\\");
    try m.feed("hi\x1b_rex1;2;{\"type\":\"child_exited\",\"exit_code\":7}\x1b\\");
    try testing.expectEqual(Mirror.Size{ .cols = 30, .rows = 8 }, m.size().?);
    try testing.expectEqual(Mirror.Size{ .cols = 30, .rows = 8 }, Obs.resized.?);
    try testing.expectEqual(@as(i64, 7), m.exit_code.?);
    try testing.expectEqual(@as(i64, 7), Obs.exit.?);
    try testing.expectEqual(@as(usize, 2), Obs.out_len); // "hi", not the messages
    try testing.expectEqualStrings("client:1", m.owner.?);
    try testing.expectEqualStrings("#102030", m.theme.?.background.?);
}

/// Feed a redraw into a fresh terminal and return its plain text.
fn replay(a: Allocator, bytes: []const u8, cols: u16, rows: u16, alt: *bool) ![]u8 {
    var t = try ghostty_vt.Terminal.init(testing.io, a, .{ .cols = cols, .rows = rows });
    defer t.deinit(a);
    var vt = t.vtStream();
    vt.nextSlice(bytes);
    alt.* = t.screens.active_key == .alternate;
    var out: Io.Writer.Allocating = .init(a);
    errdefer out.deinit();
    var f: ghostty_vt.formatter.TerminalFormatter = .init(&t, .plain);
    try f.format(&out.writer);
    return out.toOwnedSlice();
}

test "mirror: redraw recreates the screen on a fresh terminal, including the alternate screen" {
    const a = testing.allocator;
    const stream = try makeStream(a, 1, 30, 6, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try m.feed(stream);
    try m.feed("primary text \x1b[1;32mbold green\x1b[0m\r\n");

    var alt = false;
    {
        const bytes = try m.redraw(a);
        defer a.free(bytes);
        const text = try replay(a, bytes, 30, 6, &alt);
        defer a.free(text);
        try testing.expect(!alt);
        try testing.expect(std.mem.indexOf(u8, text, "primary text bold green") != null);
    }
    // A full-screen program: the redraw must leave the viewer on the alternate screen.
    try m.feed("\x1b[?1049h\x1b[2J\x1b[HALT SCREEN");
    {
        const bytes = try m.redraw(a);
        defer a.free(bytes);
        const text = try replay(a, bytes, 30, 6, &alt);
        defer a.free(text);
        try testing.expect(alt);
        try testing.expect(std.mem.indexOf(u8, text, "ALT SCREEN") != null);
        // ...and leaving it shows the primary screen again.
        var t2 = try ghostty_vt.Terminal.init(testing.io, a, .{ .cols = 30, .rows = 6 });
        defer t2.deinit(a);
        var vt2 = t2.vtStream();
        vt2.nextSlice(bytes);
        vt2.nextSlice("\x1b[?1049l");
        var out: Io.Writer.Allocating = .init(a);
        defer out.deinit();
        var f: ghostty_vt.formatter.TerminalFormatter = .init(&t2, .plain);
        try f.format(&out.writer);
        try testing.expect(std.mem.indexOf(u8, out.written(), "primary text") != null);
    }
}

test "mirror: not live until the snapshot has arrived" {
    const m = try Mirror.init(testing.allocator, testing.io, 1);
    defer m.deinit();
    try testing.expectError(error.NotLive, m.redraw(testing.allocator));
    try testing.expect(m.size() == null);
}

test "mirror: garbage instead of a snapshot fails cleanly" {
    const m = try Mirror.init(testing.allocator, testing.io, 1);
    defer m.deinit();
    const junk: [64]u8 = @splat(0xff);
    try testing.expect(std.meta.isError(m.feed(&junk)));
}

test "mirror: follows a stream from the fake server through Control and Data" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const made = try f.createSession("rweb-test-mirror");
    const body = try std.fmt.allocPrint(a, "{{\"session_id\":\"{s}\"}}", .{made.session_id});
    defer a.free(body);
    var at = try ctl.call("session.attach", body);
    at.deinit();
    try f.feed(made.block_id, "before connect\r\n");

    const m = try Mirror.initPending(a, testing.io);
    defer m.deinit();
    const d = try data.Data.openTerminal(a, testing.io, ctl, made.session_id, made.block_id, m.sink());
    defer d.close();
    try f.feed(made.block_id, "after connect\r\n");

    var tries: u32 = 0;
    while (tries < 600) : (tries += 1) {
        if (m.getStatus() == .live) {
            const text = try m.plainText(a);
            defer a.free(text);
            if (std.mem.indexOf(u8, text, "after connect") != null) {
                try testing.expect(std.mem.indexOf(u8, text, "before connect") != null);
                try testing.expectEqual(Mirror.Size{ .cols = 80, .rows = 24 }, m.size().?);
                return;
            }
        }
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    return error.TimedOut;
}

fn normalize(a: Allocator, text: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| {
        try out.appendSlice(a, std.mem.trimEnd(u8, line, " \t\r"));
        try out.append(a, '\n');
    }
    const trimmed = std.mem.trimEnd(u8, out.items, "\n");
    const res = try a.dupe(u8, trimmed);
    out.deinit(a);
    return res;
}

test "live: the mirror agrees with Rex's own capture of a throwaway terminal (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();

    var made = try ctl.call("session.create", "{\"label\":\"rweb-test-live-mirror\",\"initial_windows\":[{\"layout\":{\"block\":{\"flavor\":\"com.superlogical.terminal.shell\"}}}]}");
    defer made.deinit();
    const p = (try made.ok()).object;
    const sid = try a.dupe(u8, p.get("session_id").?.string);
    defer a.free(sid);
    const bid = try a.dupe(u8, p.get("initial_windows").?.array.items[0].object.get("block_ids").?.array.items[0].string);
    defer a.free(bid);
    const sid_body = try std.fmt.allocPrint(a, "{{\"session_id\":\"{s}\"}}", .{sid});
    defer a.free(sid_body);
    defer {
        if (ctl.call("session.destroy", sid_body)) |r| {
            var rr = r;
            rr.deinit();
        } else |_| {}
    }
    var at = try ctl.call("session.attach", sid_body);
    at.deinit();

    const m = try Mirror.initPending(a, testing.io);
    defer m.deinit();
    const d = try data.Data.openTerminal(a, testing.io, ctl, sid, bid, m.sink());
    defer d.close();

    const wr = try std.fmt.allocPrint(a, "{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"data\":\"printf 'plain \\\\033[31mred\\\\033[0m wide:\\\\xe4\\\\xb8\\\\xad e\\\\xcc\\\\x81\\\\n'; echo done-$((6*7))\\n\"}}}}", .{ sid, bid });
    defer a.free(wr);
    var w = try ctl.call("com.superlogical.terminal.write", wr);
    w.deinit();

    const fmt_body = try std.fmt.allocPrint(a, "{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"format\":\"text\",\"trim\":true}}}}", .{ sid, bid });
    defer a.free(fmt_body);

    // Poll until the two agree (the shell prompt may still be arriving); fail if they never do.
    var last_mirror: ?[]u8 = null;
    var last_rex: ?[]u8 = null;
    defer if (last_mirror) |x| a.free(x);
    defer if (last_rex) |x| a.free(x);
    var tries: u32 = 0;
    while (tries < 200) : (tries += 1) {
        try testing.io.sleep(.fromMilliseconds(25), .awake);
        if (m.getStatus() != .live) continue;
        const mt = try m.plainText(a);
        defer a.free(mt);
        var fr = try ctl.call("com.superlogical.terminal.format", fmt_body);
        defer fr.deinit();
        const content = (try fr.ok()).object.get("content").?.string;
        const mn = try normalize(a, mt);
        const rn = try normalize(a, content);
        if (last_mirror) |x| a.free(x);
        if (last_rex) |x| a.free(x);
        last_mirror = mn;
        last_rex = rn;
        if (std.mem.indexOf(u8, rn, "done-42\n") != null and std.mem.eql(u8, mn, rn)) return;
    }
    std.debug.print("\nmirror:\n{s}\n--- rex:\n{s}\n", .{ last_mirror orelse "", last_rex orelse "" });
    return error.MirrorDiffersFromRex;
}
