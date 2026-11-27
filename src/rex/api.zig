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
    /// The answer did not have the shape this client expects (a field missing, or of another type).
    BadShape,
    /// The task making the call was cancelled.
    Canceled,
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
    flavor: ?[]const u8 = null,
    creator_name: ?[]const u8 = null,
    /// `placed` or `detached`.
    placement: []const u8,
    window_id: ?[]const u8 = null,
    owner: ?[]const u8 = null,
};

pub const Created = struct { session_id: []const u8, window_id: []const u8, block_id: []const u8 };
pub const NewTerminal = struct { window_id: []const u8, block_id: []const u8 };

pub const BlockOwner = struct { block_id: []const u8, owner: ?[]const u8 = null };

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

/// The answers this client reads, as Rex sends them: fields it does not read are ignored, a field
/// it needs that is missing or of another type makes the answer `BadShape`.
pub const Payload = struct {
    pub const SessionList = struct { sessions: ?[]Session };
    pub const SessionCreate = struct {
        session_id: []const u8,
        initial_windows: []const struct { window_id: []const u8, block_ids: []const []const u8 },
    };
    pub const BlockList = struct { blocks: ?[]Block };
    pub const NewWindow = struct { window_id: []const u8, block_ids: []const []const u8 };
    pub const Format = struct { content: []const u8 };
    pub const Process = struct {
        last_exit: ?struct { exit_code: ?i64 = null } = null,
        foreground: ?struct { name: ?[]const u8 = null, cwd: ?[]const u8 = null } = null,
        child: ?struct { pid: ?i64 = null } = null,
    };
    pub const DownloadBegin = struct { ticket: []const u8, name: []const u8, path: ?[]const u8 = null, size: ?i64 = null };
    pub const ListDir = struct {
        entries: ?[]const struct { name: ?[]const u8 = null, file: ?bool = null } = null,
        truncated: ?bool = null,
        path: ?[]const u8 = null,
        home: ?[]const u8 = null,
        status: ?[]const u8 = null,
    };
    pub const Clipboard = struct { data: ?[]const u8 = null };
    pub const Title = struct { title: ?[]const u8 = null };
    pub const Pwd = struct { pwd: ?[]const u8 = null };
    pub const ProgramStatus = struct { records: ?[]const struct { state: ?[]const u8 = null, msg: ?[]const u8 = null, title: ?[]const u8 = null, progress: ?i64 = null } = null };
    pub const Ports = struct { ports: ?[]const struct { port: ?i64 = null } = null };
    pub const Ownership = struct { blocks: []const BlockOwner };
};

/// Read `payload` as a `T` into `arena` (strings copied), unknown fields ignored; any mismatch is
/// `BadShape`.
pub fn decode(comptime T: type, arena: Allocator, payload: std.json.Value) Error!T {
    return std.json.parseFromValueLeaky(T, arena, payload, .{ .ignore_unknown_fields = true }) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadShape,
    };
}

/// An empty JSON object. (`.{}` would be an empty tuple, which `std.json` writes as `[]`, and Rex
/// refuses a list where it wants an object.)
const no_args: struct {} = .{};

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

    /// Call `method` with `payload` (written by `std.json.Stringify`; null optional fields are left
    /// out) and read the answer's payload as a `T`, unknown fields ignored. Strings are copied into
    /// the result's arena, so the reply is freed before this returns. A payload that is not a `T`
    /// (a field missing or of another type) is `BadShape`. `T == void` reads nothing.
    fn callTyped(a: *Api, comptime T: type, method: []const u8, payload: anytype, timeout_ms: u32) Error!Owned(T) {
        var r = a.ctl.callValue(method, payload, timeout_ms) catch |e| switch (e) {
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
        if (T == void) return .{ .arena = arena, .value = {} };
        const value = try decode(T, arena.allocator(), r.payload orelse .{ .object = .empty });
        return .{ .arena = arena, .value = value };
    }

    /// As `callTyped` with the connection's own timeout.
    fn callT(a: *Api, comptime T: type, method: []const u8, payload: anytype) Error!Owned(T) {
        return a.callTyped(T, method, payload, a.ctl.opts.call_timeout_ms);
    }

    /// A call whose answer carries nothing this client uses.
    fn callVoid(a: *Api, method: []const u8, payload: anytype) Error!void {
        var r = try a.callT(void, method, payload);
        r.deinit();
    }

    /// For the tests that reach Rex with a method of their choosing.
    fn run(a: *Api, method: []const u8, body: ?[]const u8) Error!Owned(void) {
        return a.callT(void, method, @import("control.zig").RawJson{ .json = body });
    }

    fn setLastError(a: *Api, comptime fmt: []const u8, args: anytype) void {
        if (a.last_error) |old| a.gpa.free(old);
        a.last_error = a.gpa.print(fmt, args) catch null;
    }

    /// A payload's result moved into an `Owned` of another type (same arena).
    fn into(comptime U: type, res: anytype, value: U) Owned(U) {
        return .{ .arena = res.arena, .value = value };
    }

    // ---- sessions ----

    pub fn sessions(a: *Api) Error!Owned([]Session) {
        const res = try a.callT(Payload.SessionList, "session.list", no_args);
        return into([]Session, res, res.value.sessions orelse &.{});
    }

    /// A session with one window holding one shell.
    pub fn createSession(a: *Api, label: ?[]const u8) Error!Owned(Created) {
        var res = try a.callT(Payload.SessionCreate, "session.create", .{
            .label = label,
            .initial_windows = .{.{ .layout = .{ .block = .{ .flavor = shell_flavor } } }},
        });
        errdefer res.deinit();
        const w = res.value.initial_windows;
        if (w.len != 1 or w[0].block_ids.len != 1) return error.BadShape;
        return into(Created, res, .{ .session_id = res.value.session_id, .window_id = w[0].window_id, .block_id = w[0].block_ids[0] });
    }

    pub fn renameSession(a: *Api, sid: []const u8, label: []const u8) Error!void {
        return a.callVoid("session.set_label", .{ .session_id = sid, .label = label });
    }

    pub fn destroySession(a: *Api, sid: []const u8) Error!void {
        return a.callVoid("session.destroy", .{ .session_id = sid });
    }

    /// Receive session-level events for the whole server (not `block_event`s) and get the
    /// session list. Must be repeated after every reconnect as a new client.
    pub fn attachAll(a: *Api) Error!void {
        return a.callVoid("session.attach_all", .{ .event_scope = "session" });
    }

    /// Attach this connection to a session, so its events and data connections work.
    pub fn attach(a: *Api, sid: []const u8) Error!void {
        return a.callVoid("session.attach", .{ .session_id = sid });
    }

    pub fn detach(a: *Api, sid: []const u8) Error!void {
        return a.callVoid("session.detach", .{ .session_id = sid });
    }

    // ---- blocks ----

    pub fn blocks(a: *Api, sid: []const u8) Error!Owned([]Block) {
        const res = try a.callT(Payload.BlockList, "session.list_blocks", .{ .session_id = sid });
        return into([]Block, res, res.value.blocks orelse &.{});
    }

    /// A new window holding a shell. It becomes the active window only if `focus`.
    pub fn newTerminal(a: *Api, sid: []const u8, focus: bool) Error!Owned(NewTerminal) {
        var res = try a.callT(Payload.NewWindow, "session.new_window", .{ .session_id = sid, .focus = focus, .layout = .{ .block = .{ .flavor = shell_flavor } } });
        errdefer res.deinit();
        if (res.value.block_ids.len != 1) return error.BadShape;
        return into(NewTerminal, res, .{ .window_id = res.value.window_id, .block_id = res.value.block_ids[0] });
    }

    pub fn closeBlock(a: *Api, sid: []const u8, bid: []const u8) Error!void {
        return a.callVoid("block.close", .{ .session_id = sid, .block_id = bid });
    }

    pub fn renameBlock(a: *Api, sid: []const u8, bid: []const u8, label: []const u8) Error!void {
        return a.callVoid("session.set_block_label", .{ .session_id = sid, .block_id = bid, .label = label });
    }

    // ---- terminal ----

    /// Ask for a size. It applies at once if the caller owns the block or nobody does.
    pub fn resize(a: *Api, sid: []const u8, bid: []const u8, cols: u16, rows: u16) Error!void {
        return a.callVoid("com.superlogical.terminal.resize", .{ .session_id = sid, .block_id = bid, .args = .{ .columns = cols, .rows = rows } });
    }

    /// The screen and scrollback as `text`, `html` or `vt`. Caller frees with `deinit`.
    pub fn format(a: *Api, sid: []const u8, bid: []const u8, kind: []const u8) Error!Owned([]const u8) {
        const res = try a.callT(Payload.Format, "com.superlogical.terminal.format", .{ .session_id = sid, .block_id = bid, .args = .{ .format = kind } });
        return into([]const u8, res, res.value.content);
    }

    pub fn process(a: *Api, sid: []const u8, bid: []const u8) Error!Owned(ProcessInfo) {
        const res = try a.callT(Payload.Process, "com.superlogical.terminal.process", .{ .session_id = sid, .block_id = bid, .args = no_args });
        const v = res.value;
        return into(ProcessInfo, res, .{
            .exit_code = if (v.last_exit) |le| le.exit_code else null,
            .foreground_name = if (v.foreground) |fg| fg.name else null,
            .child_pid = if (v.child) |ch| ch.pid else null,
        });
    }

    // ---- files ----

    /// What `download_begin` returns: the ticket for the bytes stream, and what Rex says the file is.
    pub const DownloadTicket = struct { ticket: [16]u8, name: []const u8, path: []const u8, size: u64 };

    /// Ask Rex to open `path` (absolute, `~/...`, or relative to the terminal's foreground
    /// process) for download. `ref` is `download:` and a new lower-case UUID.
    pub fn downloadBegin(a: *Api, sid: []const u8, bid: []const u8, ref: []const u8, path: []const u8) Error!Owned(DownloadTicket) {
        var res = try a.callTyped(Payload.DownloadBegin, "com.superlogical.terminal.download_begin", .{ .session_id = sid, .block_id = bid, .args = .{ .ref = ref, .path = path } }, a.quick_timeout_ms);
        errdefer res.deinit();
        const v = res.value;
        const ticket = wire.decodeTicket(v.ticket) catch return error.BadShape;
        const size: u64 = if (v.size) |n| (if (n >= 0) @intCast(n) else 0) else 0;
        return into(DownloadTicket, res, .{ .ticket = ticket, .name = v.name, .path = v.path orelse "", .size = size });
    }

    /// Paste `text` into the terminal, as if the user had pasted it (no Enter is sent).
    pub fn paste(a: *Api, sid: []const u8, bid: []const u8, text: []const u8) Error!void {
        return a.callVoid("block.event", .{ .session_id = sid, .block_id = bid, .event = .{ .type = "paste", .payload = .{ .text = text } } });
    }

    pub const DirEntry = struct { name: []const u8, dir: bool };
    pub const Dir = struct { path: []const u8, home: []const u8, status: []const u8, entries: []const DirEntry, truncated: bool };

    /// List a directory (empty `path`: the terminal's working directory), files included.
    pub fn listDir(a: *Api, sid: []const u8, bid: []const u8, path: []const u8) Error!Owned(Dir) {
        var res = try a.callTyped(Payload.ListDir, "com.superlogical.terminal.list_dir", .{ .session_id = sid, .block_id = bid, .args = .{ .path = path, .files = true, .limit = 1000 } }, a.quick_timeout_ms);
        errdefer res.deinit();
        const v = res.value;
        const in = v.entries orelse &.{};
        // An entry without a name is skipped.
        const out = try res.arena.allocator().alloc(DirEntry, in.len);
        var n: usize = 0;
        for (in) |e| if (e.name) |name| {
            out[n] = .{ .name = name, .dir = !(e.file orelse false) };
            n += 1;
        };
        return into(Dir, res, .{ .path = v.path orelse "", .home = v.home orelse "", .status = v.status orelse "ok", .entries = out[0..n], .truncated = v.truncated orelse false });
    }

    /// Clear the screen and scrollback (`clear`) or return the terminal to its starting state (`reset`).
    pub fn termAction(a: *Api, sid: []const u8, bid: []const u8, action: []const u8) Error!void {
        const method = if (std.mem.eql(u8, action, "clear")) "com.superlogical.terminal.clear" else "com.superlogical.terminal.reset";
        return a.callVoid(method, .{ .session_id = sid, .block_id = bid, .args = no_args });
    }

    /// The newest text a program in the terminal copied (up to 48 KiB), or null if nothing was copied.
    pub fn clipboard(a: *Api, sid: []const u8, bid: []const u8) Error!?Owned([]const u8) {
        var res = a.callT(Payload.Clipboard, "com.superlogical.terminal.clipboard_read", .{ .session_id = sid, .block_id = bid, .args = no_args }) catch |e| {
            if (e == error.RexError) return null; // not_found: nothing copied yet
            return e;
        };
        const data = res.value.data orelse {
            res.deinit();
            return null;
        };
        return into([]const u8, res, data);
    }

    /// What a terminal is showing the person: its title, working directory, foreground program and
    /// listening ports. Each piece is optional; a piece Rex can't give is left out.
    pub const TermInfo = struct { state: ?[]const u8 = null, status_msg: ?[]const u8 = null, progress: ?i64 = null, title: ?[]const u8 = null, pwd: ?[]const u8 = null, program: ?[]const u8 = null, exit_code: ?i64 = null, ports: []const u16 = &.{} };

    /// Every piece is a separate call, each with the quick timeout; a piece Rex refuses, does not
    /// answer in time or answers in another shape is left out. Cancellation and running out of
    /// memory end it.
    pub fn termInfo(a: *Api, sid: []const u8, bid: []const u8) Error!Owned(TermInfo) {
        var arena = std.heap.ArenaAllocator.init(a.gpa);
        errdefer arena.deinit();
        const al = arena.allocator();
        var info: TermInfo = .{};
        const body = .{ .session_id = sid, .block_id = bid, .args = no_args };
        const t = a.quick_timeout_ms;
        if (a.callTyped(Payload.Title, "com.superlogical.terminal.title", body, t)) |r| {
            var res = r;
            defer res.deinit();
            info.title = try dupeOpt(al, res.value.title);
        } else |e| try passThrough(e);
        if (a.callTyped(Payload.Pwd, "com.superlogical.terminal.pwd", body, t)) |r| {
            var res = r;
            defer res.deinit();
            info.pwd = try dupeOpt(al, res.value.pwd);
        } else |e| try passThrough(e);
        if (a.callTyped(Payload.Process, "com.superlogical.terminal.process", body, t)) |r| {
            var res = r;
            defer res.deinit();
            if (res.value.last_exit) |le| info.exit_code = le.exit_code;
            if (res.value.foreground) |fg| {
                info.program = try dupeOpt(al, fg.name);
                // A shell that never reports its folder: the program's own folder is the same place.
                if (info.pwd == null) info.pwd = try dupeOpt(al, fg.cwd);
            }
        } else |e| try passThrough(e);
        if (a.callTyped(Payload.ProgramStatus, "com.superlogical.terminal.program_status", body, t)) |r| {
            var res = r;
            defer res.deinit();
            // The most urgent record wins: error, then blocked, then working, then done.
            var best: u8 = 0;
            for (res.value.records orelse &.{}) |rec| {
                const st = rec.state orelse continue;
                const rank: u8 = if (std.mem.eql(u8, st, "error")) 4 else if (std.mem.eql(u8, st, "blocked")) 3 else if (std.mem.eql(u8, st, "working")) 2 else if (std.mem.eql(u8, st, "done")) 1 else 0;
                if (rank >= best and rank > 0) {
                    best = rank;
                    info.state = try dupeOpt(al, st);
                    info.status_msg = try dupeOpt(al, rec.msg orelse rec.title);
                    info.progress = rec.progress;
                }
            }
        } else |e| try passThrough(e);
        if (a.callTyped(Payload.Ports, "com.superlogical.terminal.ports", body, t)) |r| {
            var res = r;
            defer res.deinit();
            var list: std.ArrayList(u16) = .empty;
            for (res.value.ports orelse &.{}) |it| {
                const pv = it.port orelse continue;
                if (pv < 1 or pv > 65535) continue;
                const port: u16 = @intCast(pv);
                if (std.mem.indexOfScalar(u16, list.items, port) == null) try list.append(al, port);
                if (list.items.len >= 8) break;
            }
            info.ports = try list.toOwnedSlice(al);
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
        var res = try a.callT(Payload.Ownership, method, .{ .session_id = sid, .block_ids = .{bid}, .mode = mode });
        errdefer res.deinit();
        if (res.value.blocks.len != 1) return error.BadShape;
        return into(BlockOwner, res, res.value.blocks[0]);
    }
};

/// For a call whose failure is not fatal: return the errors that must end the caller anyway.
fn passThrough(e: Error) Error!void {
    switch (e) {
        error.OutOfMemory, error.Canceled => return e,
        error.RexError, error.BadShape => {},
    }
}

fn dupeOpt(al: Allocator, s: ?[]const u8) Allocator.Error!?[]const u8 {
    return if (s) |x| try al.dupe(u8, x) else null;
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

/// `decode(T, json)` in a test arena: the value, or the error.
fn decodeText(comptime T: type, arena: Allocator, text: []const u8) Error!T {
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch return error.BadShape;
    return decode(T, arena, v);
}

test "api: every answer type takes a well-formed answer, ignores an extra field, and refuses a missing or wrong-typed one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const ar = arena_state.allocator();
    // For each type: an answer as Rex sends it (with an extra field, which is ignored), one with a
    // field it needs left out, and one with a field of another type. For a type whose every field is
    // optional, "missing" is the empty object and must pass.
    const Case = struct { ok: []const u8, missing: []const u8, wrong: []const u8 };
    inline for (.{
        .{ Payload.SessionList, Case{ .ok = "{\"sessions\":[{\"session_id\":\"s\",\"label\":\"l\",\"new\":1}],\"x\":true}", .missing = "{}", .wrong = "{\"sessions\":[{\"session_id\":5,\"label\":\"l\"}]}" } },
        .{ Payload.SessionCreate, Case{ .ok = "{\"session_id\":\"s\",\"initial_windows\":[{\"window_id\":\"w\",\"block_ids\":[\"b\"],\"x\":0}]}", .missing = "{\"initial_windows\":[]}", .wrong = "{\"session_id\":\"s\",\"initial_windows\":\"w\"}" } },
        .{ Payload.BlockList, Case{ .ok = "{\"blocks\":[{\"block_id\":\"b\",\"label\":\"l\",\"placement\":\"placed\",\"owner\":null,\"x\":[]}]}", .missing = "{\"blocks\":[{\"block_id\":\"b\",\"label\":\"l\"}]}", .wrong = "{\"blocks\":[{\"block_id\":\"b\",\"label\":\"l\",\"placement\":\"placed\",\"owner\":7}]}" } },
        .{ Payload.NewWindow, Case{ .ok = "{\"window_id\":\"w\",\"block_ids\":[\"b\"],\"x\":1}", .missing = "{\"window_id\":\"w\"}", .wrong = "{\"window_id\":\"w\",\"block_ids\":[1]}" } },
        // std.json reads a list of small numbers into a text field as bytes, and a numeric string into an
        // integer field: both harmless here, so the wrong types below are numbers, booleans or objects.
        .{ Payload.Format, Case{ .ok = "{\"content\":\"text\",\"x\":1}", .missing = "{}", .wrong = "{\"content\":5}" } },
        .{ Payload.DownloadBegin, Case{ .ok = "{\"ticket\":\"t\",\"name\":\"n\",\"size\":3,\"x\":1}", .missing = "{\"ticket\":\"t\"}", .wrong = "{\"ticket\":\"t\",\"name\":\"n\",\"size\":true}" } },
        .{ Payload.Ownership, Case{ .ok = "{\"blocks\":[{\"block_id\":\"b\",\"owner\":\"c\",\"x\":1}]}", .missing = "{}", .wrong = "{\"blocks\":[{\"block_id\":\"b\",\"owner\":true}]}" } },
    }) |pair| {
        const T = pair[0];
        const c: Case = pair[1];
        _ = try decodeText(T, ar, c.ok);
        try testing.expectError(error.BadShape, decodeText(T, ar, c.missing));
        try testing.expectError(error.BadShape, decodeText(T, ar, c.wrong));
    }
    // Types whose every field is optional: the empty object passes; a field of another type does not.
    inline for (.{
        .{ Payload.Process, "{\"last_exit\":{\"exit_code\":{}}}" },
        .{ Payload.ListDir, "{\"entries\":\"\"}" },
        .{ Payload.Clipboard, "{\"data\":1}" },
        .{ Payload.Title, "{\"title\":{}}" },
        .{ Payload.Pwd, "{\"pwd\":true}" },
        .{ Payload.ProgramStatus, "{\"records\":[{\"progress\":\"half\"}]}" },
        .{ Payload.Ports, "{\"ports\":[{\"port\":true}]}" },
    }) |pair| {
        _ = try decodeText(pair[0], ar, "{\"extra\":true}");
        try testing.expectError(error.BadShape, decodeText(pair[0], ar, pair[1]));
    }
    // Not an object at all, and a hostile nesting where a list is wanted.
    try testing.expectError(error.BadShape, decodeText(Payload.SessionList, ar, "[1,2]"));
    var deep: std.ArrayList(u8) = .empty;
    try deep.appendSlice(ar, "{\"sessions\":");
    try deep.appendNTimes(ar, '[', 5000);
    try deep.appendNTimes(ar, ']', 5000);
    try deep.append(ar, '}');
    try testing.expectError(error.BadShape, decodeText(Payload.SessionList, ar, deep.items));
    // What the result holds is a copy: it outlives the parsed answer.
    const kept = blk: {
        var tmp = std.heap.ArenaAllocator.init(testing.allocator);
        defer tmp.deinit();
        const v = try std.json.parseFromSliceLeaky(std.json.Value, tmp.allocator(), "{\"content\":\"still here\"}", .{});
        break :blk try decode(Payload.Format, ar, v);
    };
    try testing.expectEqualStrings("still here", kept.content);
}

test "api: an empty payload or args is written as an object, never as a list" {
    const a = testing.allocator;
    // The trap: an empty anonymous literal is a tuple, written as a list, which Rex refuses.
    const as_tuple = try std.json.Stringify.valueAlloc(a, .{ .args = .{} }, .{});
    defer a.free(as_tuple);
    try testing.expectEqualStrings("{\"args\":[]}", as_tuple);
    const as_object = try std.json.Stringify.valueAlloc(a, .{ .args = no_args }, .{});
    defer a.free(as_object);
    try testing.expectEqualStrings("{\"args\":{}}", as_object);
    const bare = try std.json.Stringify.valueAlloc(a, no_args, .{});
    defer a.free(bare);
    try testing.expectEqualStrings("{}", bare);
    // And the fake now refuses a list where Rex does.
    const r = try ApiRig.init(a);
    defer r.deinit(a);
    try testing.expectError(error.RexError, r.api.callVoid("session.list", .{}));
    try testing.expect(std.mem.indexOf(u8, r.api.last_error.?, "payload must be an object") != null);
    try testing.expectError(error.RexError, r.api.callVoid("com.superlogical.terminal.process", .{ .session_id = r.sid, .block_id = r.bid, .args = .{} }));
    try testing.expect(std.mem.indexOf(u8, r.api.last_error.?, "args must be an object") != null);
    try r.api.resize(r.sid, r.bid, 90, 30); // a call with real args still goes through
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
    const inside = try a.print("{s}/in.txt", .{root});
    defer a.free(inside);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = inside, .data = "inside" });
    const sub = try a.print("{s}/sub", .{root});
    defer a.free(sub);
    try Io.Dir.cwd().createDirPath(io, sub);
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    var ob: [64]u8 = undefined;
    const outside_dir = try std.fmt.bufPrint(&ob, "/tmp/rweb-test-outside-{x}", .{rnd});
    try Io.Dir.cwd().createDirPath(io, outside_dir);
    defer Io.Dir.cwd().deleteTree(io, outside_dir) catch {};
    const outside = try a.print("{s}/out.txt", .{outside_dir});
    defer a.free(outside);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = outside, .data = "outside" });
    // A link inside that points outside, and a path that climbs out.
    const link = try a.print("{s}/link.txt", .{root});
    defer a.free(link);
    try Io.Dir.cwd().symLink(io, outside, link, .{});
    const climb = try a.print("{s}/sub/../../{s}/out.txt", .{ root, std.fs.path.basename(outside_dir) });
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
