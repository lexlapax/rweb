//! Typed calls for what the first version needs: list and inspect sessions and blocks,
//! create, rename and close, terminal resize, format and process, and block ownership.
//! Each returns its result in an `Owned` value; nothing else knows Rex's JSON shapes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Control = @import("control.zig").Control;

pub const Error = error{
    /// Rex answered with an error; see `Api.last_error`.
    RexError,
    /// The answer did not have the shape this client expects.
    BadShape,
} || Allocator.Error;

/// A result with its memory.
pub fn Owned(comptime T: type) type {
    return struct {
        arena: std.heap.ArenaAllocator,
        value: T,

        pub fn deinit(o: *@This()) void {
            o.arena.deinit();
        }
    };
}

pub const Session = struct { session_id: []const u8, label: []const u8 };

pub const Block = struct {
    block_id: []const u8,
    label: []const u8,
    flavor: ?[]const u8,
    creator_name: ?[]const u8,
    /// `placed` or `detached`.
    placement: []const u8,
    window_id: ?[]const u8,
    owner: ?[]const u8,
};

pub const Created = struct { session_id: []const u8, window_id: []const u8, block_id: []const u8 };
pub const NewTerminal = struct { window_id: []const u8, block_id: []const u8 };

pub const BlockOwner = struct { block_id: []const u8, owner: ?[]const u8 };

pub const ProcessInfo = struct {
    /// Null while the program runs.
    exit_code: ?i64,
    foreground_name: ?[]const u8,
    child_pid: ?i64,
};

pub const shell_flavor = "com.superlogical.terminal.shell";

pub const OwnMode = enum { take, request };

pub const Api = struct {
    gpa: Allocator,
    ctl: *Control,
    /// Code and message of the last `RexError`, for logs and the browser. Owned by `gpa`.
    last_error: ?[]u8 = null,

    pub fn init(gpa: Allocator, ctl: *Control) Api {
        return .{ .gpa = gpa, .ctl = ctl };
    }

    pub fn deinit(a: *Api) void {
        if (a.last_error) |e| a.gpa.free(e);
    }

    // ---- plumbing ----

    fn q(a: *Api, value: []const u8) ![]u8 {
        return std.json.Stringify.valueAlloc(a.gpa, value, .{});
    }

    /// Call and, on success, copy the payload into an arena so the response can be freed.
    fn run(a: *Api, method: []const u8, body: ?[]const u8) Error!Owned(std.json.Value) {
        var r = a.ctl.call(method, body) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return error.RexError,
        };
        defer r.deinit();
        if (r.err) |er| {
            if (a.last_error) |old| a.gpa.free(old);
            a.last_error = std.fmt.allocPrint(a.gpa, "{s}: {s}", .{ er.code, er.message }) catch null;
            return error.RexError;
        }
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const v = try cloneValue(arena.allocator(), r.payload orelse .{ .object = .empty });
        return .{ .arena = arena, .value = v };
    }

    fn sessionBody(a: *Api, sid: []const u8, rest: []const u8) ![]u8 {
        const s = try a.q(sid);
        defer a.gpa.free(s);
        return std.fmt.allocPrint(a.gpa, "{{\"session_id\":{s}{s}}}", .{ s, rest });
    }

    fn blockBody(a: *Api, sid: []const u8, bid: []const u8, rest: []const u8) ![]u8 {
        const s = try a.q(sid);
        defer a.gpa.free(s);
        const b = try a.q(bid);
        defer a.gpa.free(b);
        return std.fmt.allocPrint(a.gpa, "{{\"session_id\":{s},\"block_id\":{s}{s}}}", .{ s, b, rest });
    }

    // ---- sessions ----

    pub fn sessions(a: *Api) Error!Owned([]Session) {
        var res = try a.run("session.list", null);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const items = try arr(res.value, "sessions");
        const out = try arena.allocator().alloc(Session, items.len);
        for (items, out) |it, *o| o.* = .{
            .session_id = try dupe(arena.allocator(), try str(it, "session_id")),
            .label = try dupe(arena.allocator(), try str(it, "label")),
        };
        return .{ .arena = arena, .value = out };
    }

    /// A session with one window holding one shell.
    pub fn createSession(a: *Api, label: ?[]const u8) Error!Owned(Created) {
        const lab = if (label) |l| try std.fmt.allocPrint(a.gpa, "\"label\":{f},", .{std.json.fmt(l, .{})}) else null;
        defer if (lab) |x| a.gpa.free(x);
        const fixed = try std.fmt.allocPrint(a.gpa, "{{{s}\"initial_windows\":[{{\"layout\":{{\"block\":{{\"flavor\":\"{s}\"}}}}}}]}}", .{ lab orelse "", shell_flavor });
        defer a.gpa.free(fixed);
        var res = try a.run("session.create", fixed);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const w = try arr(res.value, "initial_windows");
        if (w.len != 1) return error.BadShape;
        const ids = try arr(w[0], "block_ids");
        if (ids.len != 1 or ids[0] != .string) return error.BadShape;
        const value: Created = .{
            .session_id = try dupe(arena.allocator(), try str(res.value, "session_id")),
            .window_id = try dupe(arena.allocator(), try str(w[0], "window_id")),
            .block_id = try dupe(arena.allocator(), ids[0].string),
        };
        return .{ .arena = arena, .value = value };
    }

    pub fn renameSession(a: *Api, sid: []const u8, label: []const u8) Error!void {
        const l = try a.q(label);
        defer a.gpa.free(l);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"label\":{s}", .{l});
        defer a.gpa.free(rest);
        const body = try a.sessionBody(sid, rest);
        defer a.gpa.free(body);
        var r = try a.run("session.set_label", body);
        r.deinit();
    }

    pub fn destroySession(a: *Api, sid: []const u8) Error!void {
        const body = try a.sessionBody(sid, "");
        defer a.gpa.free(body);
        var r = try a.run("session.destroy", body);
        r.deinit();
    }

    /// Receive session-level events for the whole server (not `block_event`s) and get the
    /// session list. Must be repeated after every reconnect as a new client.
    pub fn attachAll(a: *Api) Error!void {
        var r = try a.run("session.attach_all", "{\"event_scope\":\"session\"}");
        r.deinit();
    }

    /// Attach this connection to a session, so its events and data connections work.
    pub fn attach(a: *Api, sid: []const u8) Error!void {
        const body = try a.sessionBody(sid, "");
        defer a.gpa.free(body);
        var r = try a.run("session.attach", body);
        r.deinit();
    }

    pub fn detach(a: *Api, sid: []const u8) Error!void {
        const body = try a.sessionBody(sid, "");
        defer a.gpa.free(body);
        var r = try a.run("session.detach", body);
        r.deinit();
    }

    // ---- blocks ----

    pub fn blocks(a: *Api, sid: []const u8) Error!Owned([]Block) {
        const body = try a.sessionBody(sid, "");
        defer a.gpa.free(body);
        var res = try a.run("session.list_blocks", body);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        const items = try arr(res.value, "blocks");
        const out = try al.alloc(Block, items.len);
        for (items, out) |it, *o| o.* = .{
            .block_id = try dupe(al, try str(it, "block_id")),
            .label = try dupe(al, try str(it, "label")),
            .flavor = try dupeOpt(al, optStr(it, "flavor")),
            .creator_name = try dupeOpt(al, optStr(it, "creator_name")),
            .placement = try dupe(al, try str(it, "placement")),
            .window_id = try dupeOpt(al, optStr(it, "window_id")),
            .owner = try dupeOpt(al, optStr(it, "owner")),
        };
        return .{ .arena = arena, .value = out };
    }

    /// A new window holding a shell. It becomes the active window only if `focus`.
    pub fn newTerminal(a: *Api, sid: []const u8, focus: bool) Error!Owned(NewTerminal) {
        const rest = try std.fmt.allocPrint(a.gpa, ",\"focus\":{s},\"layout\":{{\"block\":{{\"flavor\":\"{s}\"}}}}", .{ if (focus) "true" else "false", shell_flavor });
        defer a.gpa.free(rest);
        const body = try a.sessionBody(sid, rest);
        defer a.gpa.free(body);
        var res = try a.run("session.new_window", body);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const ids = try arr(res.value, "block_ids");
        if (ids.len != 1 or ids[0] != .string) return error.BadShape;
        const value: NewTerminal = .{
            .window_id = try dupe(arena.allocator(), try str(res.value, "window_id")),
            .block_id = try dupe(arena.allocator(), ids[0].string),
        };
        return .{ .arena = arena, .value = value };
    }

    pub fn closeBlock(a: *Api, sid: []const u8, bid: []const u8) Error!void {
        const b = try a.q(bid);
        defer a.gpa.free(b);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"block_id\":{s}", .{b});
        defer a.gpa.free(rest);
        const body = try a.sessionBody(sid, rest);
        defer a.gpa.free(body);
        var r = try a.run("block.close", body);
        r.deinit();
    }

    pub fn renameBlock(a: *Api, sid: []const u8, bid: []const u8, label: []const u8) Error!void {
        const l = try a.q(label);
        defer a.gpa.free(l);
        const b = try a.q(bid);
        defer a.gpa.free(b);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"block_id\":{s},\"label\":{s}", .{ b, l });
        defer a.gpa.free(rest);
        const body = try a.sessionBody(sid, rest);
        defer a.gpa.free(body);
        var r = try a.run("session.set_block_label", body);
        r.deinit();
    }

    // ---- terminal ----

    /// Ask for a size. It applies at once if the caller owns the block or nobody does.
    pub fn resize(a: *Api, sid: []const u8, bid: []const u8, cols: u16, rows: u16) Error!void {
        const rest = try std.fmt.allocPrint(a.gpa, ",\"args\":{{\"columns\":{d},\"rows\":{d}}}", .{ cols, rows });
        defer a.gpa.free(rest);
        const body = try a.blockBody(sid, bid, rest);
        defer a.gpa.free(body);
        var r = try a.run("com.superlogical.terminal.resize", body);
        r.deinit();
    }

    /// The screen and scrollback as `text`, `html` or `vt`. Caller frees with `deinit`.
    pub fn format(a: *Api, sid: []const u8, bid: []const u8, kind: []const u8) Error!Owned([]const u8) {
        const k = try a.q(kind);
        defer a.gpa.free(k);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"args\":{{\"format\":{s}}}", .{k});
        defer a.gpa.free(rest);
        const body = try a.blockBody(sid, bid, rest);
        defer a.gpa.free(body);
        var res = try a.run("com.superlogical.terminal.format", body);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const value = try dupe(arena.allocator(), try str(res.value, "content"));
        return .{ .arena = arena, .value = value };
    }

    pub fn process(a: *Api, sid: []const u8, bid: []const u8) Error!Owned(ProcessInfo) {
        const body = try a.blockBody(sid, bid, ",\"args\":{}");
        defer a.gpa.free(body);
        var res = try a.run("com.superlogical.terminal.process", body);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        var info: ProcessInfo = .{ .exit_code = null, .foreground_name = null, .child_pid = null };
        if (res.value == .object) {
            if (res.value.object.get("last_exit")) |le| if (le == .object) if (le.object.get("exit_code")) |c| if (c == .integer) {
                info.exit_code = c.integer;
            };
            if (res.value.object.get("foreground")) |fg| if (fg == .object) {
                info.foreground_name = try dupeOpt(arena.allocator(), optStr(fg, "name"));
            };
            if (res.value.object.get("child")) |ch| if (ch == .object) if (ch.object.get("pid")) |p| if (p == .integer) {
                info.child_pid = p.integer;
            };
        }
        return .{ .arena = arena, .value = info };
    }

    // ---- ownership ----

    /// Claim a block. While a terminal has an owner it takes its size and colors from it.
    pub fn own(a: *Api, sid: []const u8, bid: []const u8, mode: OwnMode) Error!Owned(BlockOwner) {
        return a.ownership("session.own_block", sid, bid, if (mode == .take) "take" else "request");
    }

    pub fn disown(a: *Api, sid: []const u8, bid: []const u8) Error!Owned(BlockOwner) {
        return a.ownership("session.disown_block", sid, bid, null);
    }

    fn ownership(a: *Api, method: []const u8, sid: []const u8, bid: []const u8, mode: ?[]const u8) Error!Owned(BlockOwner) {
        const b = try a.q(bid);
        defer a.gpa.free(b);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"block_ids\":[{s}]{s}{s}{s}", .{
            b,
            if (mode != null) ",\"mode\":\"" else "",
            mode orelse "",
            if (mode != null) "\"" else "",
        });
        defer a.gpa.free(rest);
        const body = try a.sessionBody(sid, rest);
        defer a.gpa.free(body);
        var res = try a.run(method, body);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const items = try arr(res.value, "blocks");
        if (items.len != 1) return error.BadShape;
        const value: BlockOwner = .{
            .block_id = try dupe(arena.allocator(), try str(items[0], "block_id")),
            .owner = try dupeOpt(arena.allocator(), optStr(items[0], "owner")),
        };
        return .{ .arena = arena, .value = value };
    }
};

// ---- JSON helpers: strict about shape, so a Rex change fails loudly here ----

fn arr(v: std.json.Value, name: []const u8) Error![]const std.json.Value {
    if (v != .object) return error.BadShape;
    const x = v.object.get(name) orelse return error.BadShape;
    return switch (x) {
        .array => |a| a.items,
        .null => &.{}, // Rex writes "array or null"
        else => error.BadShape,
    };
}

fn str(v: std.json.Value, name: []const u8) Error![]const u8 {
    if (v != .object) return error.BadShape;
    const x = v.object.get(name) orelse return error.BadShape;
    return if (x == .string) x.string else error.BadShape;
}

fn optStr(v: std.json.Value, name: []const u8) ?[]const u8 {
    if (v != .object) return null;
    const x = v.object.get(name) orelse return null;
    return if (x == .string) x.string else null;
}

fn dupe(al: Allocator, s: []const u8) Allocator.Error![]const u8 {
    return al.dupe(u8, s);
}

fn dupeOpt(al: Allocator, s: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (s) |x| try al.dupe(u8, x) else null;
}

fn cloneValue(al: Allocator, v: std.json.Value) Allocator.Error!std.json.Value {
    return switch (v) {
        .null, .bool, .integer, .float => v,
        .number_string => |s| .{ .number_string = try al.dupe(u8, s) },
        .string => |s| .{ .string = try al.dupe(u8, s) },
        .array => |a| blk: {
            var out = try std.json.Array.initCapacity(al, a.items.len);
            for (a.items) |i| out.appendAssumeCapacity(try cloneValue(al, i));
            break :blk .{ .array = out };
        },
        .object => |o| blk: {
            var out: std.json.ObjectMap = .empty;
            try out.ensureTotalCapacity(al, o.count());
            var it = o.iterator();
            while (it.next()) |e| out.putAssumeCapacity(try al.dupe(u8, e.key_ptr.*), try cloneValue(al, e.value_ptr.*));
            break :blk .{ .object = out };
        },
    };
}

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");

test "api: sessions, create, rename, attach and destroy against the fake" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    var api = Api.init(a, ctl);
    defer api.deinit();

    var made = try api.createSession("rweb-test-api");
    defer made.deinit();
    try api.attach(made.value.session_id);
    {
        var list = try api.sessions();
        defer list.deinit();
        try testing.expectEqual(@as(usize, 1), list.value.len);
        try testing.expectEqualStrings("rweb-test-api", list.value[0].label);
        try testing.expectEqualStrings(made.value.session_id, list.value[0].session_id);
    }
    try api.destroySession(made.value.session_id);
    var list2 = try api.sessions();
    defer list2.deinit();
    try testing.expectEqual(@as(usize, 0), list2.value.len);
    // A destroyed session is an error with a readable message.
    try testing.expectError(error.RexError, api.attach(made.value.session_id));
    try testing.expect(std.mem.indexOf(u8, api.last_error.?, "session_not_found") != null);
}

test "live: every typed call on a throwaway session, and what ownership does (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();
    var api = Api.init(a, ctl);
    defer api.deinit();

    var made = try api.createSession("rweb-test-live-api");
    defer made.deinit();
    const sid = made.value.session_id;
    defer api.destroySession(sid) catch {};
    try api.attach(sid);

    // list and rename
    {
        var list = try api.sessions();
        defer list.deinit();
        var found = false;
        for (list.value) |s| if (std.mem.eql(u8, s.session_id, sid)) {
            found = true;
        };
        try testing.expect(found);
    }
    try api.renameSession(sid, "rweb-test-live-api-2");
    try api.renameBlock(sid, made.value.block_id, "rweb-test-first");
    {
        var bl = try api.blocks(sid);
        defer bl.deinit();
        try testing.expectEqual(@as(usize, 1), bl.value.len);
        try testing.expectEqualStrings("rweb-test-first", bl.value[0].label);
        try testing.expectEqualStrings(shell_flavor, bl.value[0].flavor.?);
        try testing.expectEqualStrings("placed", bl.value[0].placement);
    }

    // a second terminal, then close it
    var second = try api.newTerminal(sid, false);
    defer second.deinit();
    {
        var bl = try api.blocks(sid);
        defer bl.deinit();
        try testing.expectEqual(@as(usize, 2), bl.value.len);
    }
    try api.closeBlock(sid, second.value.block_id);
    {
        var bl = try api.blocks(sid);
        defer bl.deinit();
        try testing.expectEqual(@as(usize, 1), bl.value.len);
    }

    // process and format
    {
        var pr = try api.process(sid, made.value.block_id);
        defer pr.deinit();
        try testing.expect(pr.value.exit_code == null);
        try testing.expect(pr.value.child_pid != null);
        var fm = try api.format(sid, made.value.block_id, "text");
        defer fm.deinit();
    }

    // Ownership (finding 7). Watch the stream's resize message and the control events.
    const mirror = @import("mirror.zig");
    const m = try mirror.Mirror.initPending(a, testing.io);
    defer m.deinit();
    const d = try @import("data.zig").Data.openTerminal(a, testing.io, ctl, sid, made.value.block_id, m.sink());
    defer d.close();
    var tries: u32 = 0;
    while (m.getStatus() != .live and tries < 400) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectEqual(mirror.Status.live, m.getStatus());
    {
        m.mu.lockUncancelable(testing.io);
        defer m.mu.unlock(testing.io);
        std.debug.print("\nownership: after attach the stream's owner is {?s}\n", .{m.owner});
    }
    while (try ctl.nextEvent(100)) |e| e.deinit(a); // drain

    var owned = try api.own(sid, made.value.block_id, .take);
    defer owned.deinit();
    std.debug.print("ownership: own_block(take) result owner = {?s}\n", .{owned.value.owner});
    try testing.expect(owned.value.owner != null);

    try api.resize(sid, made.value.block_id, 100, 30);
    tries = 0;
    while (tries < 400) : (tries += 1) {
        try testing.io.sleep(.fromMilliseconds(10), .awake);
        if (m.size()) |sz| if (sz.cols == 100 and sz.rows == 30) break;
    }
    {
        m.mu.lockUncancelable(testing.io);
        defer m.mu.unlock(testing.io);
        std.debug.print("ownership: after owned resize the stream's resize owner = {?s}; size {d}x{d}\n", .{ m.owner, m.term.cols, m.term.rows });
        try testing.expectEqual(@as(u16, 100), m.term.cols);
        try testing.expectEqual(@as(u16, 30), m.term.rows);
    }
    var saw_owner_event = false;
    while (try ctl.nextEvent(300)) |e| {
        defer e.deinit(a);
        if (e == .server and std.mem.indexOf(u8, e.server.json, "block_owner_changed") != null) {
            saw_owner_event = true;
            std.debug.print("ownership: event {s}\n", .{e.server.json});
        }
    }
    try testing.expect(saw_owner_event);

    var released = try api.disown(sid, made.value.block_id);
    defer released.deinit();
    std.debug.print("ownership: disown result owner = {?s}\n", .{released.value.owner});
    try testing.expect(released.value.owner == null);
}
