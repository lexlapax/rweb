//! Typed calls for what the first version needs: list and inspect sessions and blocks,
//! create, rename and close, terminal resize, format and process, and block ownership.
//! Each returns its result in an `Owned` value; nothing else knows Rex's JSON shapes.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Control = @import("control.zig").Control;
const wire = @import("wire.zig");

pub const Error = error{
    /// Rex answered with an error, or the call did not get an answer (the connection is down,
    /// it timed out); `Api.last_error` says which.
    RexError,
    /// The answer did not have the shape this client expects (or nests deeper than
    /// `max_json_depth`).
    BadShape,
    /// The task making the call was cancelled.
    Canceled,
} || Allocator.Error;

/// Deepest JSON nesting copied out of an answer; deeper is `BadShape`.
pub const max_json_depth = 64;

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

/// How long the calls a browser waits on interactively (directory listings, the start of a
/// download, terminal info) wait for Rex, instead of the connection's 30 seconds.
pub const quick_call_timeout_ms: u32 = 5_000;

pub const Api = struct {
    gpa: Allocator,
    ctl: *Control,
    /// Code and message of the last `RexError`, for logs and the browser. Owned by `gpa`.
    last_error: ?[]u8 = null,
    /// The timeout of `listDir`, `downloadBegin` and `termInfo` (each call `termInfo` makes).
    quick_timeout_ms: u32 = quick_call_timeout_ms,

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
        return a.runTimeout(method, body, a.ctl.opts.call_timeout_ms);
    }

    /// As `run`, waiting at most `timeout_ms` for the answer.
    fn runTimeout(a: *Api, method: []const u8, body: ?[]const u8, timeout_ms: u32) Error!Owned(std.json.Value) {
        var r = a.ctl.callTimeout(method, body, timeout_ms) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.Canceled => return error.Canceled,
            else => {
                // No answer from Rex: say why, rather than leave an older call's message.
                a.setLastError("{s}", .{@errorName(e)});
                return error.RexError;
            },
        };
        defer r.deinit();
        if (r.err) |er| {
            a.setLastError("{s}: {s}", .{ er.code, er.message });
            return error.RexError;
        }
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const v = try cloneValue(arena.allocator(), r.payload orelse .{ .object = .empty }, 0);
        return .{ .arena = arena, .value = v };
    }

    fn setLastError(a: *Api, comptime fmt: []const u8, args: anytype) void {
        if (a.last_error) |old| a.gpa.free(old);
        a.last_error = std.fmt.allocPrint(a.gpa, fmt, args) catch null;
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

    // ---- files ----

    /// What `download_begin` returns: the ticket for the bytes stream, and what Rex says the file is.
    pub const DownloadTicket = struct { ticket: [16]u8, name: []const u8, path: []const u8, size: u64 };

    /// Ask Rex to open `path` (absolute, `~/...`, or relative to the terminal's foreground
    /// process) for download. `ref` is `download:` and a new lower-case UUID.
    pub fn downloadBegin(a: *Api, sid: []const u8, bid: []const u8, ref: []const u8, path: []const u8) Error!Owned(DownloadTicket) {
        const args = std.json.Stringify.valueAlloc(a.gpa, .{ .ref = ref, .path = path }, .{}) catch return error.OutOfMemory;
        defer a.gpa.free(args);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"args\":{s}", .{args});
        defer a.gpa.free(rest);
        const body = try a.blockBody(sid, bid, rest);
        defer a.gpa.free(body);
        var res = try a.runTimeout("com.superlogical.terminal.download_begin", body, a.quick_timeout_ms);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        const ticket = try ticketOf(res.value);
        const size_v = if (res.value == .object) res.value.object.get("size") else null;
        const size: u64 = if (size_v) |sv| (if (sv == .integer and sv.integer >= 0) @intCast(sv.integer) else 0) else 0;
        // Allocate first, then move the arena into the result: a literal would copy it empty.
        const name = try dupe(al, try str(res.value, "name"));
        const path_out = try dupe(al, optStr(res.value, "path") orelse "");
        return .{ .arena = arena, .value = .{ .ticket = ticket, .name = name, .path = path_out, .size = size } };
    }

    /// Paste `text` into the terminal, as if the user had pasted it (no Enter is sent).
    pub fn paste(a: *Api, sid: []const u8, bid: []const u8, text: []const u8) Error!void {
        const payload = std.json.Stringify.valueAlloc(a.gpa, .{ .text = text }, .{}) catch return error.OutOfMemory;
        defer a.gpa.free(payload);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"event\":{{\"type\":\"paste\",\"payload\":{s}}}", .{payload});
        defer a.gpa.free(rest);
        const body = try a.blockBody(sid, bid, rest);
        defer a.gpa.free(body);
        var res = try a.run("block.event", body);
        res.deinit();
    }

    pub const DirEntry = struct { name: []const u8, dir: bool };
    pub const Dir = struct { path: []const u8, home: []const u8, status: []const u8, entries: []const DirEntry, truncated: bool };

    /// List a directory (empty `path`: the terminal's working directory), files included.
    pub fn listDir(a: *Api, sid: []const u8, bid: []const u8, path: []const u8) Error!Owned(Dir) {
        const args = std.json.Stringify.valueAlloc(a.gpa, .{ .path = path, .files = true, .limit = 1000 }, .{}) catch return error.OutOfMemory;
        defer a.gpa.free(args);
        const rest = try std.fmt.allocPrint(a.gpa, ",\"args\":{s}", .{args});
        defer a.gpa.free(rest);
        const body = try a.blockBody(sid, bid, rest);
        defer a.gpa.free(body);
        var res = try a.runTimeout("com.superlogical.terminal.list_dir", body, a.quick_timeout_ms);
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        var list: std.ArrayList(DirEntry) = .empty;
        if (res.value == .object) if (res.value.object.get("entries")) |es| if (es == .array) for (es.array.items) |e| {
            const name = optStr(e, "name") orelse continue;
            const is_file = if (e == .object) (if (e.object.get("file")) |f| f == .bool and f.bool else false) else false;
            try list.append(al, .{ .name = try dupe(al, name), .dir = !is_file });
        };
        const trunc = if (res.value == .object) (if (res.value.object.get("truncated")) |t| t == .bool and t.bool else false) else false;
        const path_out = try dupe(al, optStr(res.value, "path") orelse "");
        const home = try dupe(al, optStr(res.value, "home") orelse "");
        const status = try dupe(al, optStr(res.value, "status") orelse "ok");
        const entries = try list.toOwnedSlice(al);
        return .{ .arena = arena, .value = .{ .path = path_out, .home = home, .status = status, .entries = entries, .truncated = trunc } };
    }

    fn ticketOf(v: std.json.Value) Error![16]u8 {
        const t = optStr(v, "ticket") orelse return error.BadShape;
        return wire.decodeTicket(t) catch error.BadShape;
    }

    /// Clear the screen and scrollback (`clear`) or return the terminal to its starting state (`reset`).
    pub fn termAction(a: *Api, sid: []const u8, bid: []const u8, action: []const u8) Error!void {
        const body = try a.blockBody(sid, bid, ",\"args\":{}");
        defer a.gpa.free(body);
        var res = try a.run(if (std.mem.eql(u8, action, "clear")) "com.superlogical.terminal.clear" else "com.superlogical.terminal.reset", body);
        res.deinit();
    }

    /// The newest text a program in the terminal copied (up to 48 KiB), or null if nothing was copied.
    pub fn clipboard(a: *Api, sid: []const u8, bid: []const u8) Error!?Owned([]const u8) {
        const body = try a.blockBody(sid, bid, ",\"args\":{}");
        defer a.gpa.free(body);
        var res = a.run("com.superlogical.terminal.clipboard_read", body) catch |e| {
            if (e == error.RexError) return null; // not_found: nothing copied yet
            return e;
        };
        defer res.deinit();
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const data = optStr(res.value, "data") orelse return null;
        const value = try dupe(arena.allocator(), data);
        return .{ .arena = arena, .value = value };
    }

    /// What a terminal is showing the person: its title, working directory, foreground program and
    /// listening ports. Each piece is optional; a piece Rex can't give is left out.
    pub const TermInfo = struct { state: ?[]const u8 = null, status_msg: ?[]const u8 = null, progress: ?i64 = null, title: ?[]const u8 = null, pwd: ?[]const u8 = null, program: ?[]const u8 = null, exit_code: ?i64 = null, ports: []const u16 = &.{} };

    /// Every piece is a separate call, each with the quick timeout; a piece Rex refuses or does
    /// not answer in time is left out. Cancellation and running out of memory end it.
    pub fn termInfo(a: *Api, sid: []const u8, bid: []const u8) Error!Owned(TermInfo) {
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        var info: TermInfo = .{};
        const body = try a.blockBody(sid, bid, ",\"args\":{}");
        defer a.gpa.free(body);
        if (a.runTimeout("com.superlogical.terminal.title", body, a.quick_timeout_ms)) |r| {
            var res = r;
            defer res.deinit();
            info.title = try dupeOpt(al, optStr(res.value, "title"));
        } else |e| try passThrough(e);
        if (a.runTimeout("com.superlogical.terminal.pwd", body, a.quick_timeout_ms)) |r| {
            var res = r;
            defer res.deinit();
            info.pwd = try dupeOpt(al, optStr(res.value, "pwd"));
        } else |e| try passThrough(e);
        if (a.runTimeout("com.superlogical.terminal.process", body, a.quick_timeout_ms)) |r| {
            var res = r;
            defer res.deinit();
            const v = res.value;
            if (v == .object) {
                if (v.object.get("last_exit")) |le| if (le == .object) if (le.object.get("exit_code")) |c| if (c == .integer) {
                    info.exit_code = c.integer;
                };
                if (v.object.get("foreground")) |fg| if (fg == .object) {
                    info.program = try dupeOpt(al, optStr(fg, "name"));
                    // A shell that never reports its folder: the program's own folder is the same place.
                    if (info.pwd == null) info.pwd = try dupeOpt(al, optStr(fg, "cwd"));
                };
            }
        } else |e| try passThrough(e);
        if (a.runTimeout("com.superlogical.terminal.program_status", body, a.quick_timeout_ms)) |r| {
            var res = r;
            defer res.deinit();
            // The most urgent record wins: error, then blocked, then working, then done.
            var best: u8 = 0;
            if (res.value == .object) if (res.value.object.get("records")) |recs| if (recs == .array) for (recs.array.items) |rec| {
                const st = optStr(rec, "state") orelse continue;
                const rank: u8 = if (std.mem.eql(u8, st, "error")) 4 else if (std.mem.eql(u8, st, "blocked")) 3 else if (std.mem.eql(u8, st, "working")) 2 else if (std.mem.eql(u8, st, "done")) 1 else 0;
                if (rank >= best and rank > 0) {
                    best = rank;
                    info.state = try dupeOpt(al, st);
                    info.status_msg = try dupeOpt(al, optStr(rec, "msg") orelse optStr(rec, "title"));
                    info.progress = if (rec.object.get("progress")) |pg| (if (pg == .integer) pg.integer else null) else null;
                }
            };
        } else |e| try passThrough(e);
        if (a.runTimeout("com.superlogical.terminal.ports", body, a.quick_timeout_ms)) |r| {
            var res = r;
            defer res.deinit();
            if (res.value == .object) if (res.value.object.get("ports")) |ps| if (ps == .array) {
                var list: std.ArrayList(u16) = .empty;
                for (ps.array.items) |it| {
                    if (it != .object) continue;
                    const pv = it.object.get("port") orelse continue;
                    if (pv != .integer or pv.integer < 1 or pv.integer > 65535) continue;
                    const port: u16 = @intCast(pv.integer);
                    if (std.mem.indexOfScalar(u16, list.items, port) == null) try list.append(al, port);
                    if (list.items.len >= 8) break;
                }
                info.ports = try list.toOwnedSlice(al);
            };
        } else |e| try passThrough(e);
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

/// For a call whose failure is not fatal: return the errors that must end the caller anyway.
fn passThrough(e: Error) Error!void {
    switch (e) {
        error.OutOfMemory, error.Canceled => return e,
        error.RexError, error.BadShape => {},
    }
}

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

/// A deep copy of `v` into `al`. Recursion is bounded: nesting deeper than `max_json_depth` is
/// `BadShape` (a hostile answer cannot use up the stack).
fn cloneValue(al: Allocator, v: std.json.Value, depth: u32) Error!std.json.Value {
    return switch (v) {
        .null, .bool, .integer, .float => v,
        .number_string => |s| .{ .number_string = try al.dupe(u8, s) },
        .string => |s| .{ .string = try al.dupe(u8, s) },
        .array => |a| blk: {
            if (depth >= max_json_depth) return error.BadShape;
            var out = try std.json.Array.initCapacity(al, a.items.len);
            for (a.items) |i| out.appendAssumeCapacity(try cloneValue(al, i, depth + 1));
            break :blk .{ .array = out };
        },
        .object => |o| blk: {
            if (depth >= max_json_depth) return error.BadShape;
            var out: std.json.ObjectMap = .empty;
            try out.ensureTotalCapacity(al, o.count());
            var it = o.iterator();
            while (it.next()) |e| out.putAssumeCapacity(try al.dupe(u8, e.key_ptr.*), try cloneValue(al, e.value_ptr.*, depth + 1));
            break :blk .{ .object = out };
        },
    };
}

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");
const Io = std.Io;

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

test "api: cloneValue stops at max_json_depth" {
    const a = testing.allocator;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const al = arena.allocator();
    for ([_]usize{ max_json_depth, max_json_depth + 1, 5000 }) |depth| {
        var text: std.ArrayList(u8) = .empty;
        defer text.deinit(a);
        try text.appendNTimes(a, '[', depth);
        try text.appendNTimes(a, ']', depth);
        const v = try std.json.parseFromSliceLeaky(std.json.Value, al, text.items, .{});
        if (depth <= max_json_depth) {
            _ = try cloneValue(al, v, 0);
        } else try testing.expectError(error.BadShape, cloneValue(al, v, 0));
    }
}

test "api: a call that gets no answer says why, and does not keep an older message" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path, .call_timeout_ms = 100 });
    defer ctl.close();
    var api = Api.init(a, ctl);
    defer api.deinit();
    try testing.expectError(error.RexError, api.attach("session:none"));
    try testing.expect(std.mem.indexOf(u8, api.last_error.?, "session_not_found") != null);
    try testing.expectError(error.RexError, api.run("rweb.test.no_answer", null));
    try testing.expectEqualStrings("Timeout", api.last_error.?);
}

/// A fake with one attached session, and an Api on a control connection to it.
const ApiRig = struct {
    f: *fake.Fake,
    ctl: *Control,
    api: Api,
    sid: []const u8,
    bid: []const u8,

    fn init(a: Allocator) !*ApiRig {
        const r = try a.create(ApiRig);
        errdefer a.destroy(r);
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const made = try f.createSession("rweb-test-api-rig");
        r.* = .{ .f = f, .ctl = ctl, .api = Api.init(a, ctl), .sid = made.session_id, .bid = made.block_id };
        try r.api.attach(r.sid);
        return r;
    }

    fn deinit(r: *ApiRig, a: Allocator) void {
        r.api.deinit();
        r.ctl.close();
        r.f.deinit();
        a.destroy(r);
    }

    fn waitPending(r: *ApiRig) !void {
        var tries: u32 = 0;
        while (tries < 400) : (tries += 1) {
            r.ctl.mu.lockUncancelable(testing.io);
            const waiting = r.ctl.pending.count() == 1;
            r.ctl.mu.unlock(testing.io);
            if (waiting) return;
            try testing.io.sleep(.fromMilliseconds(5), .awake);
        }
        return error.TimedOut;
    }
};

test "api: cancellation passes through termInfo instead of being taken for a missing piece" {
    const a = testing.allocator;
    const r = try ApiRig.init(a);
    defer r.deinit(a);
    r.f.silent_method = "com.superlogical.terminal.title";
    r.api.quick_timeout_ms = 60_000;
    const T = struct {
        fn run(rr: *ApiRig) Error!void {
            var info = try rr.api.termInfo(rr.sid, rr.bid);
            info.deinit();
        }
    };
    var fut = try testing.io.concurrent(T.run, .{r});
    try r.waitPending();
    try testing.expectError(error.Canceled, fut.cancel(testing.io));
}

test "api: listings, downloads and terminal info wait for Rex only as long as the quick timeout" {
    const a = testing.allocator;
    const r = try ApiRig.init(a);
    defer r.deinit(a);
    try testing.expectEqual(@as(u32, 5_000), r.api.quick_timeout_ms);
    try testing.expectEqual(@as(u32, 30_000), r.ctl.opts.call_timeout_ms);
    r.api.quick_timeout_ms = 200;
    for ([_][]const u8{ "com.superlogical.terminal.list_dir", "com.superlogical.terminal.download_begin", "com.superlogical.terminal.pwd" }) |method| {
        r.f.silent_method = method;
        const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
        if (std.mem.endsWith(u8, method, "list_dir")) {
            try testing.expectError(error.RexError, r.api.listDir(r.sid, r.bid, ""));
            try testing.expectEqualStrings("Timeout", r.api.last_error.?);
        } else if (std.mem.endsWith(u8, method, "download_begin")) {
            try testing.expectError(error.RexError, r.api.downloadBegin(r.sid, r.bid, "download:x", "/nope"));
            try testing.expectEqualStrings("Timeout", r.api.last_error.?);
        } else {
            var info = try r.api.termInfo(r.sid, r.bid); // a piece that timed out is left out
            defer info.deinit();
            try testing.expect(info.value.pwd == null);
        }
        try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 3000);
    }
}

test "fake: downloads and listings are served only from the fake's own folder" {
    const a = testing.allocator;
    const io = testing.io;
    const r = try ApiRig.init(a);
    defer r.deinit(a);
    const root = r.f.files_root.?;
    // A file inside, a folder inside, and a file outside.
    const inside = try std.fmt.allocPrint(a, "{s}/in.txt", .{root});
    defer a.free(inside);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = inside, .data = "inside" });
    const sub = try std.fmt.allocPrint(a, "{s}/sub", .{root});
    defer a.free(sub);
    try Io.Dir.cwd().createDirPath(io, sub);
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    var ob: [64]u8 = undefined;
    const outside_dir = try std.fmt.bufPrint(&ob, "/tmp/rweb-test-outside-{x}", .{rnd});
    try Io.Dir.cwd().createDirPath(io, outside_dir);
    defer Io.Dir.cwd().deleteTree(io, outside_dir) catch {};
    const outside = try std.fmt.allocPrint(a, "{s}/out.txt", .{outside_dir});
    defer a.free(outside);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = outside, .data = "outside" });
    // A link inside that points outside, and a path that climbs out.
    const link = try std.fmt.allocPrint(a, "{s}/link.txt", .{root});
    defer a.free(link);
    try Io.Dir.cwd().symLink(io, outside, link, .{});
    const climb = try std.fmt.allocPrint(a, "{s}/sub/../../{s}/out.txt", .{ root, std.fs.path.basename(outside_dir) });
    defer a.free(climb);

    {
        var t = try r.api.downloadBegin(r.sid, r.bid, "download:1", inside);
        defer t.deinit();
        try testing.expectEqual(@as(u64, 6), t.value.size);
        var st = try @import("transfer.zig").Stream.open(a, io, r.f.path, t.value.ticket);
        defer st.deinit();
        try testing.expectEqual(wire.data_max_message, st.conn.max_message); // the stream's limit, after its handshake
        const chunk = (try st.next()).?;
        defer a.free(chunk);
        try testing.expectEqualStrings("inside", chunk);
    }
    for ([_][]const u8{ outside, link, climb, "/etc/hosts", "", root }) |p| {
        try testing.expectError(error.RexError, r.api.downloadBegin(r.sid, r.bid, "download:2", p));
    }
    {
        var d = try r.api.listDir(r.sid, r.bid, ""); // the terminal's folder: the root
        defer d.deinit();
        try testing.expectEqualStrings("ok", d.value.status);
        try testing.expectEqual(@as(usize, 3), d.value.entries.len);
        var s2 = try r.api.listDir(r.sid, r.bid, sub);
        defer s2.deinit();
        try testing.expectEqualStrings("ok", s2.value.status);
    }
    for ([_][]const u8{ outside_dir, "/", "/tmp", climb }) |p| {
        var d = try r.api.listDir(r.sid, r.bid, p);
        defer d.deinit();
        try testing.expectEqualStrings("missing", d.value.status);
    }
    // No folder at all: nothing is served.
    try r.f.setFilesRoot(null);
    try testing.expectError(error.RexError, r.api.downloadBegin(r.sid, r.bid, "download:3", inside));
    var none = try r.api.listDir(r.sid, r.bid, "");
    defer none.deinit();
    try testing.expectEqualStrings("missing", none.value.status);
}
