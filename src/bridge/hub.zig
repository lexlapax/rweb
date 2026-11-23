//! The bridge's core: one Rex client, the session tree, the open terminals, and the browsers
//! (viewers) looking at them. It knows nothing about HTTP; a viewer is a bounded queue of
//! frames that a connection drains, so it is tested without sockets.
//!
//! Lock order, outermost first: `Hub.mu`, `Terminal.tmu`, the mirror's lock, `Terminal.vmu`,
//! `Viewer.mu`. Output reaches viewers from the mirror's lock, so pushing to a viewer never
//! blocks: queues are bounded and an overflowing viewer is told to redraw instead.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const rex = @import("rex");
const Control = rex.control.Control;
const Api = rex.api.Api;
const Mirror = rex.mirror.Mirror;
const Data = rex.data.Data;
const Input = rex.input.Input;
const protocol = @import("protocol.zig");

const log = std.log.scoped(.hub);

pub const Config = struct {
    /// The bridge never writes, resizes or takes ownership, whatever a browser asks.
    observe_only: bool = false,
    /// Scrollback rows sent when a terminal is opened. `more_history` sends everything.
    history_lines: u32 = 1000,
    /// Live output held for one viewer before it is dropped to a redraw.
    max_live_bytes: usize = 1 << 20,
};

pub const Frame = struct {
    binary: bool,
    data: []u8,

    pub fn deinit(f: Frame, gpa: Allocator) void {
        gpa.free(f.data);
    }
};

/// Most text the Copy view is sent (the end of the scrollback if there is more).
pub const max_copy_bytes: usize = 1 << 20;
/// Most control frames held for one viewer.
pub const max_text_frames = 256;

pub const Viewer = struct {
    hub: *Hub,
    mu: Io.Mutex = .init,
    wake: Io.Event = .unset,
    frames: std.ArrayList(Frame) = .empty,
    /// Bytes of live output in `frames`.
    live_bytes: usize = 0,
    closed: bool = false,
    needs_redraw: bool = false,
    /// Rows of scrollback in the next redraw; null for all of it.
    history_lines: ?u32,
    /// This viewer's read-only switch.
    observe: bool,
    /// The terminal being viewed. Guarded by `mu`; `in_redraw` keeps it alive.
    term: ?*Terminal = null,
    in_redraw: bool = false,
    /// Frames dropped because the viewer fell behind, for tests and logs.
    overflows: u32 = 0,
    /// Calls that make Rex or the mirror do real work (info, clipboard, text, redraw, history),
    /// counted per second: a page cannot turn one browser tab into a load on Rex.
    heavy_window_start: i64 = 0,
    heavy_count: u32 = 0,

    /// Wait up to `timeout_ms` for the next frame; null on timeout or when closed. Does any
    /// pending redraw first. The caller frees the frame.
    pub fn next(v: *Viewer, timeout_ms: u32) !?Frame {
        while (true) {
            v.mu.lockUncancelable(v.hub.io);
            if (v.closed) {
                v.mu.unlock(v.hub.io);
                return null;
            }
            const redraw = v.needs_redraw and v.term != null;
            if (!redraw and v.frames.items.len > 0) {
                const f = v.frames.orderedRemove(0);
                if (f.binary) v.live_bytes -|= f.data.len;
                v.mu.unlock(v.hub.io);
                return f;
            }
            if (redraw) {
                v.mu.unlock(v.hub.io);
                v.hub.redrawFor(v) catch |e| log.debug("redraw: {t}", .{e});
                continue;
            }
            v.wake.reset();
            v.mu.unlock(v.hub.io);
            v.wake.waitTimeout(v.hub.io, .{ .duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => return null,
                else => |x| return x,
            };
        }
    }

    pub fn pushText(v: *Viewer, text: []const u8) void {
        const copy = v.hub.gpa.dupe(u8, text) catch return;
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        if (v.closed or v.frames.items.len >= max_text_frames) {
            v.hub.gpa.free(copy);
            return;
        }
        v.frames.append(v.hub.gpa, .{ .binary = false, .data = copy }) catch {
            v.hub.gpa.free(copy);
            return;
        };
        v.wake.set(v.hub.io);
    }

    /// Live terminal output. Never blocks and never fails: past the cap the queue is dropped and
    /// the viewer is marked for a redraw.
    pub fn pushLive(v: *Viewer, bytes: []const u8) void {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        if (v.closed or v.needs_redraw) return; // a redraw is coming, which includes this
        if (v.live_bytes + bytes.len > v.hub.cfg.max_live_bytes) {
            v.dropLiveLocked();
            v.needs_redraw = true;
            v.overflows += 1;
            v.wake.set(v.hub.io);
            return;
        }
        const copy = v.hub.gpa.dupe(u8, bytes) catch {
            v.dropLiveLocked();
            v.needs_redraw = true;
            v.wake.set(v.hub.io);
            return;
        };
        v.frames.append(v.hub.gpa, .{ .binary = true, .data = copy }) catch {
            v.hub.gpa.free(copy);
            v.dropLiveLocked();
            v.needs_redraw = true;
            v.wake.set(v.hub.io);
            return;
        };
        v.live_bytes += bytes.len;
        v.wake.set(v.hub.io);
    }

    fn dropLiveLocked(v: *Viewer) void {
        var i: usize = 0;
        while (i < v.frames.items.len) {
            if (v.frames.items[i].binary) {
                v.hub.gpa.free(v.frames.items[i].data);
                _ = v.frames.orderedRemove(i);
            } else i += 1;
        }
        v.live_bytes = 0;
    }

    pub fn isClosed(v: *Viewer) bool {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        return v.closed;
    }

    pub fn requestRedraw(v: *Viewer) void {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        v.needs_redraw = true;
        v.wake.set(v.hub.io);
    }
};

/// One open Rex terminal, shared by every viewer of it.
pub const Terminal = struct {
    hub: *Hub,
    session_id: []u8,
    block_id: []u8,
    input: *Input,
    /// Guards `mirror` and `data`, which `restart` replaces.
    tmu: Io.Mutex = .init,
    mirror: *Mirror,
    data: *Data,
    /// Guards `viewers`.
    vmu: Io.Mutex = .init,
    viewers: std.ArrayList(*Viewer) = .empty,
    /// Viewers subscribed (guarded by `Hub.mu`).
    refs: u32 = 0,
    /// Set by the mirror when its stream ended; read by the supervisor.
    ended: std.atomic.Value(u8) = .init(0), // 0 none, else 1 + End
    restart_after_ms: i64 = 0,
    restarts: u32 = 0,

    fn observer(t: *Terminal) rex.mirror.Observer {
        return .{ .ctx = t, .output = onOutput, .resized = onResized, .theme = onTheme, .exited = onExited, .ended = onEnded };
    }

    // Callbacks run under the mirror's lock.
    fn onOutput(ctx: *anyopaque, bytes: []const u8) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        t.vmu.lockUncancelable(t.hub.io);
        defer t.vmu.unlock(t.hub.io);
        for (t.viewers.items) |v| v.pushLive(bytes);
    }

    fn onResized(ctx: *anyopaque, _: u16, _: u16) void {
        // Reflow differs between emulators: every viewer gets an authoritative redraw.
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        t.vmu.lockUncancelable(t.hub.io);
        defer t.vmu.unlock(t.hub.io);
        for (t.viewers.items) |v| v.requestRedraw();
    }

    fn onTheme(ctx: *anyopaque, theme: *const rex.mirror.Theme) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        const text = themeFrame(t.hub.gpa, theme) catch return;
        defer t.hub.gpa.free(text);
        t.vmu.lockUncancelable(t.hub.io);
        defer t.vmu.unlock(t.hub.io);
        for (t.viewers.items) |v| v.pushText(text);
    }

    fn onExited(ctx: *anyopaque, code: i64) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        var buf: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{{\"t\":\"exited\",\"code\":{d}}}", .{code}) catch return;
        t.vmu.lockUncancelable(t.hub.io);
        defer t.vmu.unlock(t.hub.io);
        for (t.viewers.items) |v| v.pushText(text);
    }

    fn onEnded(ctx: *anyopaque, why: rex.data.End) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        if (why == .closed_by_us) return;
        t.ended.store(1 + @as(u8, @intFromEnum(why)), .release);
        t.hub.supervisor_wake.set(t.hub.io);
    }
};

fn themeFrame(gpa: Allocator, theme: *const rex.mirror.Theme) ![]u8 {
    return std.json.Stringify.valueAlloc(gpa, .{
        .t = "theme",
        .foreground = theme.foreground,
        .background = theme.background,
        .cursor = theme.cursor,
        .scheme = theme.scheme,
        .palette = theme.palette,
    }, .{});
}

pub const Hub = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    ctl: *Control,
    api: Api,
    /// Serialises calls through `api` (it keeps `last_error`).
    api_mu: Io.Mutex = .init,

    mu: Io.Mutex = .init,
    terminals: std.StringHashMapUnmanaged(*Terminal) = .empty,
    viewers: std.ArrayList(*Viewer) = .empty,
    /// Sessions this bridge has attached (to open data streams), to redo after a reconnect.
    attached: std.StringHashMapUnmanaged(void) = .empty,
    tree_json: ?[]u8 = null,
    tree_dirty: bool = true,
    rex_up: bool = true,
    closing: bool = false,
    /// The control connection's generation this hub has already set itself up for.
    seen_generation: u32 = 0,

    supervisor: ?Io.Future(void) = null,
    supervisor_wake: Io.Event = .unset,

    pub fn open(gpa: Allocator, io: Io, ctl: *Control, cfg: Config) !*Hub {
        const h = try gpa.create(Hub);
        errdefer gpa.destroy(h);
        h.* = .{ .gpa = gpa, .io = io, .cfg = cfg, .ctl = ctl, .api = Api.init(gpa, ctl) };
        ctl.mu.lockUncancelable(io);
        h.seen_generation = ctl.generation;
        ctl.mu.unlock(io);
        try h.subscribeAndRefresh();
        h.supervisor = try io.concurrent(supervise, .{h});
        return h;
    }

    pub fn close(h: *Hub) void {
        h.mu.lockUncancelable(h.io);
        h.closing = true;
        h.mu.unlock(h.io);
        if (h.supervisor) |*s| s.cancel(h.io);
        // Viewers are the connections' to close; terminals are ours.
        var it = h.terminals.iterator();
        while (it.next()) |e| h.destroyTerminal(e.value_ptr.*);
        h.terminals.deinit(h.gpa);
        var ai = h.attached.keyIterator();
        while (ai.next()) |k| h.gpa.free(k.*);
        h.attached.deinit(h.gpa);
        h.viewers.deinit(h.gpa);
        if (h.tree_json) |t| h.gpa.free(t);
        h.api.deinit();
        h.gpa.destroy(h);
    }

    // ---- viewers ----

    pub fn addViewer(h: *Hub) !*Viewer {
        const v = try h.gpa.create(Viewer);
        errdefer h.gpa.destroy(v);
        v.* = .{ .hub = h, .history_lines = h.cfg.history_lines, .observe = h.cfg.observe_only };
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        try h.viewers.append(h.gpa, v);
        // First frames: the mode, the Rex state and the tree.
        h.pushModeLocked(v);
        if (h.tree_json) |t| v.pushText(t);
        return v;
    }

    /// Detach and free a viewer. The caller has stopped using it.
    pub fn removeViewer(h: *Hub, v: *Viewer) void {
        h.unsubscribe(v);
        h.mu.lockUncancelable(h.io);
        for (h.viewers.items, 0..) |x, i| if (x == v) {
            _ = h.viewers.swapRemove(i);
            break;
        };
        h.mu.unlock(h.io);
        v.mu.lockUncancelable(h.io);
        v.closed = true;
        for (v.frames.items) |f| f.deinit(h.gpa);
        v.frames.deinit(h.gpa);
        v.mu.unlock(h.io);
        h.gpa.destroy(v);
    }

    /// Wake a viewer's waiting `next` so its connection can notice it is going away.
    pub fn closeViewer(h: *Hub, v: *Viewer) void {
        v.mu.lockUncancelable(h.io);
        v.closed = true;
        v.wake.set(h.io);
        v.mu.unlock(h.io);
    }

    /// Caller holds `mu`.
    fn pushModeLocked(h: *Hub, v: *Viewer) void {
        v.mu.lockUncancelable(h.io);
        const observe = v.observe;
        v.mu.unlock(h.io);
        const text = std.json.Stringify.valueAlloc(h.gpa, .{
            .t = "mode",
            .observe = observe,
            .locked = h.cfg.observe_only,
            .rex_up = h.rex_up,
        }, .{}) catch return;
        defer h.gpa.free(text);
        v.pushText(text);
    }

    // ---- commands from a browser ----

    /// Run one message from a viewer. Problems are answered as `error` frames, not returned.
    /// At most this many heavy requests a second from one browser.
    pub const max_heavy_per_second: u32 = 8;

    fn allowHeavy(h: *Hub, v: *Viewer) bool {
        const now = std.Io.Clock.awake.now(h.io).toMilliseconds();
        v.mu.lockUncancelable(h.io);
        defer v.mu.unlock(h.io);
        if (now - v.heavy_window_start >= 1000) {
            v.heavy_window_start = now;
            v.heavy_count = 0;
        }
        v.heavy_count += 1;
        return v.heavy_count <= max_heavy_per_second;
    }

    pub fn handle(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        switch (msg) {
            .text, .info, .clip, .redraw, .more_history => if (!h.allowHeavy(v)) return h.refuse(v, "rate", "too many requests"),
            else => {},
        }
        switch (msg) {
            .ping => v.pushText("{\"t\":\"pong\"}"),
            .dbg => {},
            .text => h.sendText(v),
            .info => h.sendInfo(v),
            .clip => {
                v.mu.lockUncancelable(h.io);
                const t = v.term;
                v.mu.unlock(h.io);
                const term = t orelse return h.refuse(v, "clip", "no terminal open");
                h.api_mu.lockUncancelable(h.io);
                const got = h.api.clipboard(term.session_id, term.block_id);
                h.api_mu.unlock(h.io);
                var res = (got catch |e| return h.fail(v, "clip", e)) orelse return v.pushText("{\"t\":\"clip\",\"text\":null}");
                defer res.deinit();
                const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "clip", .text = res.value }, .{}) catch return;
                defer h.gpa.free(out);
                v.pushText(out);
            },
            .term_action => |act| {
                if (h.isObserving(v)) return h.refuse(v, "term_action", "read-only");
                v.mu.lockUncancelable(h.io);
                const t = v.term;
                v.mu.unlock(h.io);
                const term = t orelse return h.refuse(v, "term_action", "no terminal open");
                h.api_mu.lockUncancelable(h.io);
                defer h.api_mu.unlock(h.io);
                h.api.termAction(term.session_id, term.block_id, @tagName(act)) catch |e| h.fail(v, "term_action", e);
            },
            .tree => {
                h.mu.lockUncancelable(h.io);
                defer h.mu.unlock(h.io);
                if (h.tree_json) |t| v.pushText(t);
            },
            .open => |o| h.openTerminal(v, o.session, o.block) catch |e| h.fail(v, "open", e),
            .close_view => h.unsubscribe(v),
            .redraw => {
                v.mu.lockUncancelable(h.io);
                v.history_lines = h.cfg.history_lines;
                v.mu.unlock(h.io);
                v.requestRedraw();
            },
            .more_history => {
                v.mu.lockUncancelable(h.io);
                v.history_lines = null;
                v.mu.unlock(h.io);
                v.requestRedraw();
            },
            .observe => |on| {
                v.mu.lockUncancelable(h.io);
                // A locked bridge cannot be unlocked from a browser.
                v.observe = on or h.cfg.observe_only;
                v.mu.unlock(h.io);
                h.mu.lockUncancelable(h.io);
                defer h.mu.unlock(h.io);
                h.pushModeLocked(v);
            },
            .in, .key, .paste, .fit => h.input(v, msg),
            .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session => h.manage(v, msg),
        }
    }

    /// The Copy view: the terminal's whole text, for the browser to select from.
    fn sendInfo(h: *Hub, v: *Viewer) void {
        v.mu.lockUncancelable(h.io);
        const t = v.term;
        v.mu.unlock(h.io);
        const term = t orelse return;
        h.api_mu.lockUncancelable(h.io);
        var res = h.api.termInfo(term.session_id, term.block_id) catch |e| {
            h.api_mu.unlock(h.io);
            return h.fail(v, "info", e);
        };
        h.api_mu.unlock(h.io);
        defer res.deinit();
        const i = res.value;
        const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "info", .state = i.state, .status_msg = i.status_msg, .progress = i.progress, .title = i.title, .pwd = i.pwd, .program = i.program, .exit_code = i.exit_code, .ports = i.ports }, .{}) catch return;
        defer h.gpa.free(out);
        v.pushText(out);
    }

    fn sendText(h: *Hub, v: *Viewer) void {
        v.mu.lockUncancelable(h.io);
        const t = v.term;
        if (t != null) v.in_redraw = true; // keeps the terminal alive, as a redraw does
        v.mu.unlock(h.io);
        const term = t orelse return h.refuse(v, "text", "no terminal open");
        defer {
            v.mu.lockUncancelable(h.io);
            v.in_redraw = false;
            v.mu.unlock(h.io);
        }
        term.tmu.lockUncancelable(h.io);
        const res = term.mirror.plainTextAll(h.gpa, max_copy_bytes);
        term.tmu.unlock(h.io);
        const pt = res catch |e| return h.fail(v, "text", e);
        defer h.gpa.free(pt.text);
        const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "text", .text = pt.text, .truncated = pt.truncated }, .{}) catch return;
        defer h.gpa.free(out);
        v.pushText(out);
    }

    fn fail(h: *Hub, v: *Viewer, what: []const u8, e: anyerror) void {
        const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = what, .msg = @errorName(e) }, .{}) catch return;
        defer h.gpa.free(text);
        v.pushText(text);
    }

    fn refuse(h: *Hub, v: *Viewer, what: []const u8, msg: []const u8) void {
        const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = what, .msg = msg }, .{}) catch return;
        defer h.gpa.free(text);
        v.pushText(text);
    }

    fn isObserving(h: *Hub, v: *Viewer) bool {
        v.mu.lockUncancelable(h.io);
        defer v.mu.unlock(h.io);
        return v.observe or h.cfg.observe_only;
    }

    fn input(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        if (h.isObserving(v)) return h.refuse(v, "input", "read-only");
        v.mu.lockUncancelable(h.io);
        const t = v.term;
        v.mu.unlock(h.io);
        const term = t orelse return h.refuse(v, "input", "no terminal open");
        switch (msg) {
            .in => |d| term.input.writeText(d) catch |e| h.fail(v, "in", e),
            .paste => |d| {
                const body = std.json.Stringify.valueAlloc(h.gpa, .{ .text = d }, .{}) catch return;
                defer h.gpa.free(body);
                term.input.blockEvent("paste", body) catch |e| h.fail(v, "paste", e);
            },
            .key => |k| term.input.key(k) catch |e| h.fail(v, "key", e),
            .fit => |f| {
                // Only on request: take the block, then ask for the size.
                h.api_mu.lockUncancelable(h.io);
                defer h.api_mu.unlock(h.io);
                var own = h.api.own(term.session_id, term.block_id, .take) catch |e| return h.fail(v, "fit", e);
                own.deinit();
                h.api.resize(term.session_id, term.block_id, f.cols, f.rows) catch |e| h.fail(v, "fit", e);
            },
            else => unreachable,
        }
    }

    fn manage(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        if (h.isObserving(v)) return h.refuse(v, "manage", "read-only");
        h.api_mu.lockUncancelable(h.io);
        defer h.api_mu.unlock(h.io);
        const api = &h.api;
        const result: anyerror!void = switch (msg) {
            .new_session => |label| blk: {
                var made = api.createSession(label) catch |e| break :blk e;
                made.deinit();
                break :blk {};
            },
            .new_terminal => |sid| blk: {
                var nt = api.newTerminal(sid, false) catch |e| break :blk e;
                nt.deinit();
                break :blk {};
            },
            .rename_session => |r| api.renameSession(r.session, r.label),
            .rename_block => |r| api.renameBlock(r.session, r.block, r.label),
            .close_block => |r| api.closeBlock(r.session, r.block),
            .destroy_session => |sid| blk: {
                // destroy needs an attachment
                api.attach(sid) catch |e| break :blk e;
                break :blk api.destroySession(sid);
            },
            else => unreachable,
        };
        result catch |e| {
            const detail = api.last_error orelse @errorName(e);
            h.refuse(v, "manage", detail);
            return;
        };
        h.markTreeDirty();
    }

    // ---- terminals ----

    fn terminalKey(buf: []u8, sid: []const u8, bid: []const u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{s}|{s}", .{ sid, bid });
    }

    fn openTerminal(h: *Hub, v: *Viewer, sid: []const u8, bid: []const u8) !void {
        h.unsubscribe(v);
        var kb: [512]u8 = undefined;
        const key = try terminalKey(&kb, sid, bid);

        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        const term = if (h.terminals.get(key)) |t| t else blk: {
            const t = try h.createTerminalLocked(sid, bid);
            break :blk t;
        };
        term.refs += 1;
        errdefer term.refs -= 1;
        v.mu.lockUncancelable(h.io);
        v.term = term;
        v.history_lines = h.cfg.history_lines;
        v.mu.unlock(h.io);
        try h.subscribeTo(v, term);
    }

    /// Caller holds `mu`. Opens a stream and waits for the first snapshot.
    fn createTerminalLocked(h: *Hub, sid: []const u8, bid: []const u8) !*Terminal {
        const gpa = h.gpa;
        try h.ensureAttachedLocked(sid);

        const t = try gpa.create(Terminal);
        errdefer gpa.destroy(t);
        const sid_c = try gpa.dupe(u8, sid);
        errdefer gpa.free(sid_c);
        const bid_c = try gpa.dupe(u8, bid);
        errdefer gpa.free(bid_c);
        t.* = .{ .hub = h, .session_id = sid_c, .block_id = bid_c, .input = undefined, .mirror = undefined, .data = undefined };

        const live = try h.openStream(sid, bid, t);
        errdefer {
            live.data.close();
            live.mirror.deinit();
        }
        t.mirror = live.mirror;
        t.data = live.data;
        t.input = try Input.open(gpa, h.io, rex.input.Sender.forControl(h.ctl), sid, bid);
        errdefer t.input.close();

        var kb: [512]u8 = undefined;
        const key = try gpa.dupe(u8, try terminalKey(&kb, sid, bid));
        errdefer gpa.free(key);
        try h.terminals.put(gpa, key, t);
        return t;
    }

    const Stream = struct { mirror: *Mirror, data: *Data };

    /// A new mirror following a new data stream, live and observed by `t`.
    fn openStream(h: *Hub, sid: []const u8, bid: []const u8, t: *Terminal) !Stream {
        const m = try Mirror.initPending(h.gpa, h.io);
        errdefer m.deinit();
        m.setObserver(t.observer());
        const d = try Data.openTerminal(h.gpa, h.io, h.ctl, sid, bid, m.sink());
        errdefer d.close();
        var waited: u32 = 0;
        while (m.getStatus() != .live) : (waited += 1) {
            if (waited > 1000 or m.endReason() != null or m.getStatus() == .failed) return error.NoSnapshot;
            try h.io.sleep(.fromMilliseconds(5), .awake);
        }
        return .{ .mirror = m, .data = d };
    }

    fn ensureAttachedLocked(h: *Hub, sid: []const u8) !void {
        if (h.attached.contains(sid)) return;
        {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            try h.api.attach(sid);
        }
        try h.attached.put(h.gpa, try h.gpa.dupe(u8, sid), {});
    }

    fn subscribeTo(h: *Hub, v: *Viewer, t: *Terminal) !void {
        v.mu.lockUncancelable(h.io);
        v.needs_redraw = false;
        v.mu.unlock(h.io);
        try h.redrawInto(v, t, true);
    }

    /// Build a redraw for `v` from `t`'s mirror and, atomically with the mirror's live output,
    /// swap it in for whatever `v` had queued. With `subscribe`, also add `v` to the viewers.
    fn redrawInto(h: *Hub, v: *Viewer, t: *Terminal, subscribe: bool) !void {
        const Ctx = struct {
            h: *Hub,
            v: *Viewer,
            t: *Terminal,
            subscribe: bool,
            fn deliver(ctx: *anyopaque, bytes: []const u8) anyerror!void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                const gpa = c.h.gpa;
                const m = c.t.mirror;
                const sz = m.term.cols;
                _ = sz;
                // The mirror is locked: read its state directly.
                const opened = try std.json.Stringify.valueAlloc(gpa, .{
                    .t = "opened",
                    .session = c.t.session_id,
                    .block = c.t.block_id,
                    .cols = m.term.cols,
                    .rows = m.term.rows,
                    .history_rows = blk: {
                        const primary = m.term.screens.get(.primary) orelse break :blk @as(usize, 0);
                        const total = primary.pages.total_rows;
                        break :blk if (total > m.term.rows) total - m.term.rows else 0;
                    },
                    .owner = m.owner,
                    .exited = m.exit_code,
                }, .{});
                errdefer gpa.free(opened);
                const theme = if (m.theme) |*th| try themeFrame(gpa, th) else null;
                errdefer if (theme) |x| gpa.free(x);
                const body = try gpa.dupe(u8, bytes);
                errdefer gpa.free(body);

                if (c.subscribe) {
                    c.t.vmu.lockUncancelable(c.h.io);
                    defer c.t.vmu.unlock(c.h.io);
                    var present = false;
                    for (c.t.viewers.items) |x| if (x == c.v) {
                        present = true;
                    };
                    if (!present) try c.t.viewers.append(gpa, c.v);
                }
                const v2 = c.v;
                v2.mu.lockUncancelable(c.h.io);
                defer v2.mu.unlock(c.h.io);
                v2.dropLiveLocked();
                // Control frames queued before the redraw stay; the redraw frames go last.
                try v2.frames.ensureUnusedCapacity(gpa, 3);
                v2.frames.appendAssumeCapacity(.{ .binary = false, .data = opened });
                if (theme) |x| v2.frames.appendAssumeCapacity(.{ .binary = false, .data = x });
                // The redraw is a binary frame but not "live": it is not counted against the cap.
                v2.frames.appendAssumeCapacity(.{ .binary = true, .data = body });
                v2.needs_redraw = false;
                v2.wake.set(c.h.io);
            }
        };
        var ctx: Ctx = .{ .h = h, .v = v, .t = t, .subscribe = subscribe };
        v.mu.lockUncancelable(h.io);
        const lines = v.history_lines;
        v.mu.unlock(h.io);
        t.tmu.lockUncancelable(h.io);
        defer t.tmu.unlock(h.io);
        try t.mirror.redrawLocked(h.gpa, .{ .history_lines = lines }, &ctx, Ctx.deliver);
    }

    /// From a viewer's own `next`: its queue is stale (overflow, resize, history request).
    fn redrawFor(h: *Hub, v: *Viewer) !void {
        v.mu.lockUncancelable(h.io);
        const t = v.term;
        if (t == null) {
            v.needs_redraw = false;
            v.mu.unlock(h.io);
            return;
        }
        v.in_redraw = true;
        v.mu.unlock(h.io);
        defer {
            v.mu.lockUncancelable(h.io);
            v.in_redraw = false;
            v.mu.unlock(h.io);
        }
        h.redrawInto(v, t.?, false) catch |e| {
            // A restart can leave a moment with no live mirror; try again shortly.
            v.mu.lockUncancelable(h.io);
            v.needs_redraw = false;
            v.mu.unlock(h.io);
            return e;
        };
    }

    /// Stop viewing; the last viewer to leave closes the terminal.
    fn unsubscribe(h: *Hub, v: *Viewer) void {
        v.mu.lockUncancelable(h.io);
        const t = v.term orelse {
            v.mu.unlock(h.io);
            return;
        };
        v.term = null;
        v.mu.unlock(h.io);
        // Let a redraw in progress finish before the terminal can go away.
        while (true) {
            v.mu.lockUncancelable(h.io);
            const busy = v.in_redraw;
            v.mu.unlock(h.io);
            if (!busy) break;
            h.io.sleep(.fromMilliseconds(1), .awake) catch break;
        }
        t.vmu.lockUncancelable(h.io);
        for (t.viewers.items, 0..) |x, i| if (x == v) {
            _ = t.viewers.swapRemove(i);
            break;
        };
        t.vmu.unlock(h.io);

        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        t.refs -|= 1;
        if (t.refs == 0) h.removeTerminalLocked(t);
    }

    fn removeTerminalLocked(h: *Hub, t: *Terminal) void {
        var it = h.terminals.iterator();
        while (it.next()) |e| if (e.value_ptr.* == t) {
            const key = e.key_ptr.*;
            h.terminals.removeByPtr(e.key_ptr);
            h.gpa.free(key);
            break;
        };
        h.destroyTerminal(t);
    }

    fn destroyTerminal(h: *Hub, t: *Terminal) void {
        t.data.close();
        t.input.close();
        t.mirror.deinit();
        t.viewers.deinit(h.gpa);
        h.gpa.free(t.session_id);
        h.gpa.free(t.block_id);
        h.gpa.destroy(t);
    }

    // ---- the tree ----

    /// A copy of the current tree JSON, or null before the first read. Caller frees.
    pub fn treeJson(h: *Hub) ?[]u8 {
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        const t = h.tree_json orelse return null;
        return h.gpa.dupe(u8, t) catch null;
    }

    pub fn markTreeDirty(h: *Hub) void {
        h.mu.lockUncancelable(h.io);
        h.tree_dirty = true;
        h.mu.unlock(h.io);
        h.supervisor_wake.set(h.io);
    }

    fn subscribeAndRefresh(h: *Hub) !void {
        {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            try h.api.attachAll();
        }
        try h.refreshTree();
    }

    /// Re-read sessions and blocks and send the tree to every viewer.
    pub fn refreshTree(h: *Hub) !void {
        const gpa = h.gpa;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();

        const Blk = struct { id: []const u8, label: []const u8, flavor: ?[]const u8, owner: ?[]const u8, window: ?[]const u8, placement: []const u8 };
        const Ses = struct { id: []const u8, label: []const u8, blocks: []Blk };
        var out: std.ArrayList(Ses) = .empty;

        h.api_mu.lockUncancelable(h.io);
        var sessions = h.api.sessions() catch |e| {
            h.api_mu.unlock(h.io);
            return e;
        };
        defer sessions.deinit();
        for (sessions.value) |s| {
            var blocks = h.api.blocks(s.session_id) catch continue; // a session that just went away
            defer blocks.deinit();
            const bl = try arena.alloc(Blk, blocks.value.len);
            for (blocks.value, bl) |b, *o| o.* = .{
                .id = try arena.dupe(u8, b.block_id),
                .label = try arena.dupe(u8, b.label),
                .flavor = if (b.flavor) |f| try arena.dupe(u8, f) else null,
                .owner = if (b.owner) |ow| try arena.dupe(u8, ow) else null,
                .window = if (b.window_id) |w| try arena.dupe(u8, w) else null,
                .placement = try arena.dupe(u8, b.placement),
            };
            try out.append(arena, .{ .id = try arena.dupe(u8, s.session_id), .label = try arena.dupe(u8, s.label), .blocks = bl });
        }
        h.api_mu.unlock(h.io);

        const text = try std.json.Stringify.valueAlloc(gpa, .{
            .t = "tree",
            .observe_only = h.cfg.observe_only,
            .sessions = out.items,
        }, .{});
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        if (h.tree_json) |old| gpa.free(old);
        h.tree_json = text;
        h.tree_dirty = false;
        for (h.viewers.items) |v| v.pushText(text);
    }

    // ---- supervisor: Rex events, reconnects, stream restarts ----

    fn supervise(h: *Hub) void {
        var last_tree_ms: i64 = 0;
        while (true) {
            const ev = h.ctl.nextEvent(200) catch return;
            if (ev) |e| {
                defer e.deinit(h.gpa);
                h.onEvent(e);
            }
            h.mu.lockUncancelable(h.io);
            const closing = h.closing;
            h.mu.unlock(h.io);
            if (closing) return;
            h.restartEnded();
            const now = std.Io.Clock.awake.now(h.io).toMilliseconds();
            h.mu.lockUncancelable(h.io);
            const dirty = h.tree_dirty;
            h.mu.unlock(h.io);
            if (dirty and now - last_tree_ms >= 150 and h.ctl.isConnected()) {
                last_tree_ms = now;
                h.refreshTree() catch |e| log.debug("tree: {t}", .{e});
            }
        }
    }

    fn broadcastRexState(h: *Hub, up: bool) void {
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        h.rex_up = up;
        const text = if (up) "{\"t\":\"rex\",\"up\":true}" else "{\"t\":\"rex\",\"up\":false}";
        for (h.viewers.items) |v| v.pushText(text);
    }

    fn onEvent(h: *Hub, e: rex.control.Event) void {
        switch (e) {
            .disconnected => h.broadcastRexState(false),
            .connected => |c| {
                h.broadcastRexState(true);
                // Generations up to the one `open` used are already set up.
                if (c.generation > h.seen_generation) {
                    h.seen_generation = c.generation;
                    if (!c.resumed) h.reattachAfterRestart();
                }
                h.markTreeDirty();
            },
            .dropped => h.markTreeDirty(),
            .server => |s| {
                const interesting = [_][]const u8{ "session_created", "session_destroyed", "session_label_changed", "session_view_changed", "block_created", "block_closed", "block_owner_changed", "window_created", "window_closed" };
                for (interesting) |name| if (std.mem.indexOf(u8, s.json, name) != null) {
                    h.markTreeDirty();
                    break;
                };
                if (std.mem.indexOf(u8, s.json, "session_destroyed") != null or std.mem.indexOf(u8, s.json, "block_closed") != null)
                    h.dropGoneTerminals();
            },
        }
    }

    /// A restarted Rex knows nothing about this client: attach again, and rebuild every stream.
    fn reattachAfterRestart(h: *Hub) void {
        {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            h.api.attachAll() catch |e| log.debug("attach_all: {t}", .{e});
        }
        h.mu.lockUncancelable(h.io);
        var ids: std.ArrayList([]u8) = .empty;
        defer {
            for (ids.items) |x| h.gpa.free(x);
            ids.deinit(h.gpa);
        }
        var it = h.attached.keyIterator();
        while (it.next()) |k| ids.append(h.gpa, h.gpa.dupe(u8, k.*) catch continue) catch {};
        h.mu.unlock(h.io);
        h.api_mu.lockUncancelable(h.io);
        for (ids.items) |sid| h.api.attach(sid) catch |e| log.debug("re-attach: {t}", .{e});
        h.api_mu.unlock(h.io);
        // Every stream is gone: rebuild each from a new snapshot.
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        var ti = h.terminals.valueIterator();
        while (ti.next()) |t| {
            t.*.ended.store(1 + @as(u8, @intFromEnum(rex.data.End.restart_needed)), .release);
            t.*.restart_after_ms = 0;
        }
        h.supervisor_wake.set(h.io);
    }

    /// Terminals whose block or session no longer exists: tell their viewers and drop them.
    fn dropGoneTerminals(h: *Hub) void {
        h.refreshTree() catch return;
        // The tree is fresh; a terminal not in it has gone.
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        const tree = h.tree_json orelse return;
        var gone: std.ArrayList(*Terminal) = .empty;
        defer gone.deinit(h.gpa);
        var it = h.terminals.valueIterator();
        while (it.next()) |t| {
            if (std.mem.indexOf(u8, tree, t.*.block_id) == null) gone.append(h.gpa, t.*) catch {};
        }
        for (gone.items) |t| h.closeTerminalLocked(t, "closed");
    }

    /// Caller holds `mu`. Tell the viewers, detach them, and destroy the terminal.
    fn closeTerminalLocked(h: *Hub, t: *Terminal, reason: []const u8) void {
        const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "closed", .block = t.block_id, .reason = reason }, .{}) catch null;
        defer if (text) |x| h.gpa.free(x);
        t.vmu.lockUncancelable(h.io);
        const vs = h.gpa.dupe(*Viewer, t.viewers.items) catch &[_]*Viewer{};
        t.vmu.unlock(h.io);
        defer if (vs.len > 0) h.gpa.free(vs);
        for (vs) |v| {
            v.mu.lockUncancelable(h.io);
            v.term = null;
            v.mu.unlock(h.io);
            while (true) {
                v.mu.lockUncancelable(h.io);
                const busy = v.in_redraw;
                v.mu.unlock(h.io);
                if (!busy) break;
                h.io.sleep(.fromMilliseconds(1), .awake) catch break;
            }
            if (text) |x| v.pushText(x);
        }
        h.removeTerminalLocked(t);
    }

    /// Rebuild the stream of every terminal whose stream ended.
    fn restartEnded(h: *Hub) void {
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        var todo: std.ArrayList(*Terminal) = .empty;
        defer todo.deinit(h.gpa);
        var it = h.terminals.valueIterator();
        while (it.next()) |t| if (t.*.ended.load(.acquire) != 0) todo.append(h.gpa, t.*) catch {};
        const now = std.Io.Clock.awake.now(h.io).toMilliseconds();
        for (todo.items) |t| {
            const code = t.ended.load(.acquire);
            const why: rex.data.End = @enumFromInt(code - 1);
            if (why == .block_closed) {
                h.closeTerminalLocked(t, "closed");
                continue;
            }
            if (now < t.restart_after_ms) continue;
            h.restartTerminalLocked(t) catch |e| {
                log.debug("restart {s}: {t}", .{ t.block_id, e });
                t.restarts += 1;
                t.restart_after_ms = now + @min(@as(i64, 500) << @intCast(@min(t.restarts, 4)), 8000);
            };
        }
    }

    fn restartTerminalLocked(h: *Hub, t: *Terminal) !void {
        // A block that has gone is not a restart: the tree says so.
        const live = try h.openStream(t.session_id, t.block_id, t);
        t.tmu.lockUncancelable(h.io);
        const old_m = t.mirror;
        const old_d = t.data;
        t.mirror = live.mirror;
        t.data = live.data;
        t.tmu.unlock(h.io);
        t.ended.store(0, .release);
        t.restarts = 0;
        old_d.close();
        old_m.deinit();
        // Viewers get a fresh redraw from the new stream, and are told why.
        t.vmu.lockUncancelable(h.io);
        defer t.vmu.unlock(h.io);
        for (t.viewers.items) |v| {
            v.pushText("{\"t\":\"notice\",\"msg\":\"Rex restarted this terminal; the screen was reset\"}");
            v.requestRedraw();
        }
    }
};

// ---- tests ----

const testing = std.testing;
const fake = rex.fake;

const Harness = struct {
    f: *fake.Fake,
    ctl: *Control,
    hub: *Hub,
    session_id: []const u8,
    block_id: []const u8,

    fn init(cfg: Config) !Harness {
        const a = testing.allocator;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const made = try f.createSession("rweb-test-hub");
        const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const h = try Hub.open(a, testing.io, ctl, cfg);
        return .{ .f = f, .ctl = ctl, .hub = h, .session_id = made.session_id, .block_id = made.block_id };
    }

    fn deinit(hs: Harness) void {
        hs.hub.close();
        hs.ctl.close();
        hs.f.deinit();
    }

    fn openViewer(hs: Harness) !*Viewer {
        const v = try hs.hub.addViewer();
        hs.hub.handle(v, .{ .open = .{ .session = hs.session_id, .block = hs.block_id } });
        return v;
    }
};

/// Collects frames from a viewer until `pred` says one matches (or 3 s pass).
fn waitFrame(v: *Viewer, comptime pred: fn ([]const u8, bool) bool) !?Frame {
    var tries: u32 = 0;
    while (tries < 60) : (tries += 1) {
        const f = (try v.next(50)) orelse continue;
        if (pred(f.data, f.binary)) return f;
        f.deinit(testing.allocator);
    }
    return null;
}

fn isOpened(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"opened\"") != null;
}
fn isRedraw(d: []const u8, bin: bool) bool {
    return bin and std.mem.startsWith(u8, d, "\x1bc");
}
fn isTree(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"tree\"") != null;
}
fn isError(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"error\"") != null;
}
fn isNotice(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"notice\"") != null;
}
fn hasHi(d: []const u8, bin: bool) bool {
    return bin and std.mem.indexOf(u8, d, "hi-there") != null;
}

test "hub: a viewer gets mode, tree, then an opened terminal with a redraw" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    try hs.f.feed(hs.block_id, "already here\r\n");
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);

    const tree = (try waitFrame(v, isTree)).?;
    defer tree.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, tree.data, hs.session_id) != null);
    try testing.expect(std.mem.indexOf(u8, tree.data, hs.block_id) != null);

    const opened = (try waitFrame(v, isOpened)).?;
    defer opened.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, opened.data, "\"cols\":80") != null);
    const redraw = (try waitFrame(v, isRedraw)).?;
    defer redraw.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, redraw.data, "already here") != null);
}

test "hub: live output and typed input reach the viewer" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    const redraw = (try waitFrame(v, isRedraw)).?;
    redraw.deinit(testing.allocator);

    hs.hub.handle(v, .{ .in = "hi-there\n" });
    const live = (try waitFrame(v, hasHi)).?;
    live.deinit(testing.allocator);
}

test "hub: two viewers share one terminal and one stream; the last to leave closes it" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const a = try hs.openViewer();
    const b = try hs.openViewer();
    hs.hub.mu.lockUncancelable(testing.io);
    try testing.expectEqual(@as(u32, 1), hs.hub.terminals.count());
    hs.hub.mu.unlock(testing.io);
    for ([_]*Viewer{ a, b }) |v| (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);

    try hs.f.feed(hs.block_id, "hi-there");
    for ([_]*Viewer{ a, b }) |v| (try waitFrame(v, hasHi)).?.deinit(testing.allocator);

    hs.hub.removeViewer(a);
    hs.hub.mu.lockUncancelable(testing.io);
    try testing.expectEqual(@as(u32, 1), hs.hub.terminals.count());
    hs.hub.mu.unlock(testing.io);
    hs.hub.removeViewer(b);
    hs.hub.mu.lockUncancelable(testing.io);
    try testing.expectEqual(@as(u32, 0), hs.hub.terminals.count());
    hs.hub.mu.unlock(testing.io);
}

test "hub: observe mode refuses input, resize and management" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .observe = true });
    hs.hub.handle(v, .{ .in = "hi-there\n" });
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .fit = .{ .cols = 100, .rows = 30 } });
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .new_session = "x" });
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
    // Nothing reached Rex: no echo, same size, one session.
    try testing.expect((try waitFrame(v, hasHi)) == null);
    hs.f.mu.lockUncancelable(testing.io);
    defer hs.f.mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 1), hs.f.sessions.items.len);
    try testing.expectEqual(@as(u16, 80), hs.f.sessions.items[0].block.term.cols);
}

test "hub: a bridge started observe-only cannot be unlocked from a browser" {
    const hs = try Harness.init(.{ .observe_only = true });
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .observe = false });
    hs.hub.handle(v, .{ .in = "hi-there\n" });
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
    try testing.expect((try waitFrame(v, hasHi)) == null);
}

fn isBig(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"cols\":100") != null and std.mem.indexOf(u8, d, "\"t\":\"opened\"") != null;
}

test "hub: fit takes ownership and resizes, and every viewer gets a fresh redraw" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const a = try hs.openViewer();
    defer hs.hub.removeViewer(a);
    const b = try hs.openViewer();
    defer hs.hub.removeViewer(b);
    for ([_]*Viewer{ a, b }) |v| (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(a, .{ .fit = .{ .cols = 100, .rows = 30 } });
    for ([_]*Viewer{ a, b }) |v| {
        (try waitFrame(v, isBig)).?.deinit(testing.allocator);
        (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    }
}

test "hub: a viewer that falls behind is dropped to a redraw, never buffered without limit" {
    const cap: usize = 16 * 1024;
    const hs = try Harness.init(.{ .max_live_bytes = cap });
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    // Flood without reading.
    const chunk: [4096]u8 = @splat('x');
    var i: usize = 0;
    while (i < cap / chunk.len + 4) : (i += 1) try hs.f.feed(hs.block_id, &chunk);
    var tries: u32 = 0;
    while (v.overflows == 0 and tries < 400) : (tries += 1) {
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    try testing.expect(v.overflows >= 1);
    v.mu.lockUncancelable(testing.io);
    try testing.expect(v.live_bytes <= cap);
    v.mu.unlock(testing.io);
    // Reading now yields a fresh redraw, and the viewer is current again.
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
}

test "hub: new sessions show up in the tree for everyone" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isTree)).?.deinit(testing.allocator);
    _ = try hs.f.createSession("rweb-test-second");
    hs.f.broadcastEvent("{\"type\":\"session_event\",\"payload\":{\"event\":{\"type\":\"session_created\"}}}");
    var found = false;
    var tries: u32 = 0;
    while (!found and tries < 40) : (tries += 1) {
        const f = (try waitFrame(v, isTree)) orelse break;
        defer f.deinit(testing.allocator);
        found = std.mem.indexOf(u8, f.data, "rweb-test-second") != null;
    }
    try testing.expect(found);
}

test "hub: a Rex restart rebuilds the stream and tells the viewer" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    try hs.f.feed(hs.block_id, "before-restart\r\n");
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);

    try hs.f.restart();
    (try waitFrame(v, isNotice)).?.deinit(testing.allocator);
    const redraw = (try waitFrame(v, isRedraw)).?;
    defer redraw.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, redraw.data, "before-restart") == null); // the screen was reset
    // And it works again.
    hs.hub.handle(v, .{ .in = "hi-there\n" });
    (try waitFrame(v, hasHi)).?.deinit(testing.allocator);
}

test "hub: a stream that needs a new snapshot (1013) is rebuilt" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.f.endStreams(hs.block_id, 1013, "data reconnect required");
    (try waitFrame(v, isNotice)).?.deinit(testing.allocator);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .in = "hi-there\n" });
    (try waitFrame(v, hasHi)).?.deinit(testing.allocator);
}

fn isText(d: []const u8, bin: bool) bool {
    return !bin and std.mem.startsWith(u8, d, "{\"t\":\"text\"");
}

test "hub: the Copy view gets the screen and scrollback as plain text" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    var i: u32 = 0;
    while (i < 120) : (i += 1) {
        var buf: [40]u8 = undefined;
        try hs.f.feed(hs.block_id, try std.fmt.bufPrint(&buf, "copy-line-{d:0>3} \x1b[31mred\x1b[0m\r\n", .{i}));
    }
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .text);
    const f = (try waitFrame(v, isText)).?;
    defer f.deinit(testing.allocator);
    // Whole history, no escape sequences, nothing cut.
    try testing.expect(std.mem.indexOf(u8, f.data, "copy-line-000 red") != null);
    try testing.expect(std.mem.indexOf(u8, f.data, "copy-line-119 red") != null);
    try testing.expect(std.mem.indexOf(u8, f.data, "\\u001b") == null);
    try testing.expect(std.mem.indexOf(u8, f.data, "\"truncated\":false") != null);
}

test "hub: Copy with no terminal open is an error frame" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    hs.hub.handle(v, .text);
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
}

test "hub: opening a terminal that does not exist is an error frame" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    hs.hub.handle(v, .{ .open = .{ .session = "session:nope", .block = "block:nope" } });
    (try waitFrame(v, isError)).?.deinit(testing.allocator);
}
