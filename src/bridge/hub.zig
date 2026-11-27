//! The bridge's core: one Rex client, the session tree, the open terminals, and the browsers
//! (viewers) looking at them. It knows nothing about HTTP; a viewer is a bounded queue of
//! frames that a connection drains, so it is tested without sockets.
//!
//! Lock order, outermost first: `Hub.mu`, `Terminal.tmu`, the mirror's lock, `Terminal.vmu`,
//! `Viewer.mu`. `api_mu` and `Hub.mu` are never held together. Nothing waits on Rex (a call, a
//! stream, a snapshot) while holding `Hub.mu`. Output reaches viewers from the mirror's lock, so
//! pushing to a viewer never blocks: queues are bounded and an overflowing viewer is told to
//! redraw instead.
//!
//! A terminal lives while anything holds a reference to it (`Terminal.refs`, under `Hub.mu`): each
//! viewer looking at it (`Viewer.term`), and each task using it for a while (a handler, a redraw, a
//! restart; see `pin`). The last reference to go destroys it, outside `Hub.mu`.

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
const xfer = @import("xfer.zig");

const log = std.log.scoped(.hub);

pub const Config = struct {
    /// The bridge never writes, resizes or takes ownership, whatever a browser asks.
    observe_only: bool = false,
    /// Scrollback rows sent when a terminal is opened. `more_history` sends more (see
    /// `max_redraw_history_rows`).
    history_lines: u32 = 1000,
    /// Live output held for one viewer before it is dropped to a redraw.
    max_live_bytes: usize = 1 << 20,
    /// File transfer: off unless the owner turns it on. See `xfer.zig`.
    transfer: xfer.Config = .{},
    /// The bridge logs what the page reports about typing (`--debug-input`); the page sends those
    /// reports only when the mode frame says this is on.
    debug_input: bool = false,
    /// Browsers sign in with a token (the SSH-tunnel layout): the page then reconnects only when asked,
    /// so a credential is never re-sent to a local port nobody checked after the tunnel dropped.
    token_mode: bool = false,
};

/// What a queued frame is, so that stale ones are replaced instead of piling up.
pub const Kind = enum { live, reply, copy, opened, theme, redraw, mode, rex, tree, closed, exited };

pub const Frame = struct {
    binary: bool,
    data: []u8,
    kind: Kind = .reply,
    /// `data` is the front of a live buffer of `max_live_frame` bytes (see `Viewer.pushLive`), which is
    /// handed back to the viewer's pool after sending (`Viewer.recycle`) or freed whole.
    pooled: bool = false,

    pub fn deinit(f: Frame, gpa: Allocator) void {
        gpa.free(if (f.pooled) f.data.ptr[0..max_live_frame] else f.data);
    }
};

/// Live buffers a viewer keeps for reuse once sent: with one being written to the browser and one
/// being filled, live output needs no allocation once warm. At most this many times `max_live_frame`
/// stays allocated per viewer.
pub const live_pool_max = 2;

/// Most text the Copy view is sent (the end of the scrollback if there is more), and most rows it is
/// built from: the rows are chosen before anything is formatted.
pub const max_copy_bytes: usize = 1 << 20;
pub const max_copy_rows: u32 = 20_000;
/// Most scrollback rows in a redraw, even when a viewer asked for all of it.
pub const max_redraw_history_rows: u32 = 10_000;
/// Most reply frames, and their bytes, held for one viewer. State frames (mode, Rex state, theme)
/// and the tree replace their own queued copy instead; `closed` and `exited` always get through. With the
/// live-output cap and at most one queued redraw (bounded in rows), this bounds a viewer's queue.
pub const max_text_frames = 256;
pub const max_text_bytes: usize = 8 << 20;
/// Live output joins the last unsent live frame up to this size, and every live frame is charged this
/// much on top of its bytes, so output in tiny pieces cannot fill a queue with tiny frames.
pub const max_live_frame: usize = 64 << 10;
pub const live_frame_overhead: usize = 64;
/// Cells (rows times columns) a redraw's scrollback, or the Copy view's text, is built from at most.
pub const max_redraw_cells: usize = 1_000_000;
pub const max_copy_cells: usize = 2_000_000;
/// A viewer that fell behind is redrawn at most this often.
pub const overflow_redraw_ms: i64 = 1000;

pub const Viewer = struct {
    hub: *Hub,
    /// Unique for the hub's lifetime; upload tokens name it (see `Hub.mayUpload`).
    id: u64 = 0,
    mu: Io.Mutex = .init,
    wake: Io.Event = .unset,
    /// Queued frames; those before `head` are sent.
    frames: std.ArrayList(Frame) = .empty,
    head: usize = 0,
    /// Sent live buffers kept for reuse (see `Frame.pooled`), guarded by `mu`.
    live_pool: [live_pool_max][]u8 = undefined,
    live_pool_len: usize = 0,
    /// Bytes of live output queued.
    live_bytes: usize = 0,
    /// Reply frames queued, and their bytes.
    text_frames: usize = 0,
    text_bytes: usize = 0,
    closed: bool = false,
    needs_redraw: bool = false,
    /// Goes up with every redraw request, so a redraw that fails clears only the requests it saw.
    redraw_seq: u64 = 0,
    /// No redraw before this time (awake clock, ms): set when the viewer falls behind.
    redraw_after_ms: i64 = 0,
    /// The tree generation last queued for this viewer.
    tree_gen: u64 = 0,
    /// Rows of scrollback in the next redraw; null for as much as a redraw may carry.
    history_lines: ?u32,
    /// This viewer's read-only switch.
    observe: bool,
    /// The terminal being viewed. Set and cleared holding both `Hub.mu` and `mu`, so either lock
    /// reads it. While set, the viewer holds one of the terminal's references.
    term: ?*Terminal = null,
    /// Raised each time `term` is set or cleared (guarded by `mu`), so an upload started before
    /// switching away from a terminal cannot finish or paste even if the viewer switches back.
    view_gen: u64 = 0,
    /// The `closed` frame for `term`, made when the viewer was pointed at it (guarded by `mu`). With
    /// the frame slot every queueing keeps free (see `reserveLocked`), telling a viewer that its
    /// terminal went never needs memory: the page must not go on showing a terminal that is gone.
    closed_frame: ?[]u8 = null,
    /// Frames dropped because the viewer fell behind, for tests and logs.
    overflows: u32 = 0,
    /// Calls that make Rex or the mirror do real work, counted per second: a page cannot turn one
    /// browser tab into a load on Rex.
    heavy_window_start: i64 = 0,
    heavy_count: u32 = 0,
    read_window_start: i64 = 0,
    read_count: u32 = 0,

    /// Wait up to `timeout_ms` for the next frame; null on timeout or when closed. Does any
    /// pending redraw first. The caller frees the frame.
    pub fn next(v: *Viewer, timeout_ms: u32) !?Frame {
        while (true) {
            v.mu.lockUncancelable(v.hub.io);
            if (v.closed) {
                v.mu.unlock(v.hub.io);
                return null;
            }
            const now = std.Io.Clock.awake.now(v.hub.io).toMilliseconds();
            const due = v.needs_redraw and v.term != null;
            const redraw = due and now >= v.redraw_after_ms;
            // Queued frames go out while a paced redraw waits (output was dropped; replies stay).
            if (!redraw and v.head < v.frames.items.len) {
                const f = v.frames.items[v.head];
                v.head += 1;
                if (v.head == v.frames.items.len) {
                    v.frames.clearRetainingCapacity();
                    v.head = 0;
                } else if (v.head >= 64 and v.head * 2 >= v.frames.items.len) v.compactLocked();
                switch (f.kind) {
                    .live => v.live_bytes -|= f.data.len + live_frame_overhead,
                    .reply, .copy => {
                        v.text_frames -|= 1;
                        v.text_bytes -|= f.data.len;
                    },
                    else => {},
                }
                v.mu.unlock(v.hub.io);
                return f;
            }
            if (redraw) {
                v.mu.unlock(v.hub.io);
                v.hub.redrawFor(v) catch |e| log.debug("redraw: {t}", .{e});
                continue;
            }
            // A redraw that is due later: wait for it (or for anything else) at most that long.
            const wait: u32 = if (due) @intCast(std.math.clamp(v.redraw_after_ms - now, 1, @as(i64, timeout_ms))) else timeout_ms;
            v.wake.reset();
            v.mu.unlock(v.hub.io);
            v.wake.waitTimeout(v.hub.io, .{ .duration = .{ .raw = .fromMilliseconds(wait), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => if (due) continue else return null,
                else => |x| return x,
            };
        }
    }

    /// Move the unsent frames to the front of the list.
    fn compactLocked(v: *Viewer) void {
        const rest = v.frames.items[v.head..];
        std.mem.copyForwards(Frame, v.frames.items[0..rest.len], rest);
        v.frames.items.len = rest.len;
        v.head = 0;
    }

    /// A reply to something this viewer asked. Dropped when the viewer's reply budget is full.
    pub fn pushText(v: *Viewer, text: []const u8) void {
        v.push(.reply, text);
    }

    /// A text frame of `kind`. Never blocks. Mode, Rex state and theme frames replace a queued
    /// copy of themselves; `closed` and `exited` are always queued; replies count against the
    /// budget.
    pub fn push(v: *Viewer, kind: Kind, text: []const u8) void {
        const gpa = v.hub.gpa;
        const copy = gpa.dupe(u8, text) catch return;
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        if (v.closed) return gpa.free(copy);
        switch (kind) {
            // Latest value wins: the first queued copy takes the new value, any later copy goes.
            .mode, .rex, .theme, .tree => {
                var placed = false;
                var w: usize = v.head;
                for (v.frames.items[v.head..]) |f| {
                    if (f.kind == kind) {
                        gpa.free(f.data);
                        if (placed) continue;
                        v.frames.items[w] = .{ .binary = false, .data = copy, .kind = kind };
                        placed = true;
                    } else v.frames.items[w] = f;
                    w += 1;
                }
                v.frames.items.len = w;
                if (placed) {
                    v.wake.set(v.hub.io);
                    return;
                }
            },
            .reply, .copy => if (v.text_frames >= max_text_frames or v.text_bytes + copy.len > max_text_bytes) {
                v.overflows +|= 1;
                return gpa.free(copy);
            },
            else => {},
        }
        v.reserveLocked(1) catch return gpa.free(copy);
        v.frames.appendAssumeCapacity(.{ .binary = false, .data = copy, .kind = kind });
        if (kind == .reply or kind == .copy) {
            v.text_frames += 1;
            v.text_bytes += copy.len;
        }
        v.wake.set(v.hub.io);
    }

    /// Live terminal output. Never blocks and never fails: past the cap the queue is dropped and
    /// the viewer is marked for a redraw.
    pub fn pushLive(v: *Viewer, bytes: []const u8) void {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        if (v.closed or v.needs_redraw) return; // a redraw is coming, which includes this
        const gpa = v.hub.gpa;
        // Join the last unsent live frame when there is room: output often arrives in tiny pieces.
        if (v.frames.items.len > v.head) {
            const last = &v.frames.items[v.frames.items.len - 1];
            if (last.kind == .live and last.data.len + bytes.len <= max_live_frame) {
                if (v.live_bytes + bytes.len > v.hub.cfg.max_live_bytes) return v.overflowLocked();
                if (last.pooled) {
                    // The buffer is `max_live_frame` long: there is room in place.
                    const n = last.data.len;
                    last.data = last.data.ptr[0 .. n + bytes.len];
                    @memcpy(last.data[n..], bytes);
                    v.live_bytes += bytes.len;
                    v.wake.set(v.hub.io);
                    return;
                }
                if (gpa.realloc(last.data, last.data.len + bytes.len)) |grown| {
                    @memcpy(grown[last.data.len..], bytes);
                    last.data = grown;
                    v.live_bytes += bytes.len;
                    v.wake.set(v.hub.io);
                    return;
                } else |_| return v.overflowLocked();
            }
        }
        if (v.live_bytes + bytes.len + live_frame_overhead > v.hub.cfg.max_live_bytes) return v.overflowLocked();
        v.reserveLocked(1) catch return v.overflowLocked();
        if (bytes.len <= max_live_frame) {
            // A pooled buffer when one is free, else a new one of the full size (kept for reuse).
            const buf = if (v.live_pool_len > 0) blk: {
                v.live_pool_len -= 1;
                break :blk v.live_pool[v.live_pool_len];
            } else gpa.alloc(u8, max_live_frame) catch return v.overflowLocked();
            @memcpy(buf[0..bytes.len], bytes);
            v.frames.appendAssumeCapacity(.{ .binary = true, .data = buf[0..bytes.len], .kind = .live, .pooled = true });
        } else {
            const copy = gpa.dupe(u8, bytes) catch return v.overflowLocked();
            v.frames.appendAssumeCapacity(.{ .binary = true, .data = copy, .kind = .live });
        }
        v.live_bytes += bytes.len + live_frame_overhead;
        v.wake.set(v.hub.io);
    }

    /// The viewer fell behind: drop its queued screen content and redraw it, at most once a second.
    fn overflowLocked(v: *Viewer) void {
        v.dropScreenLocked();
        v.needs_redraw = true;
        v.redraw_seq +%= 1;
        v.overflows +|= 1;
        const now = std.Io.Clock.awake.now(v.hub.io).toMilliseconds();
        v.redraw_after_ms = @max(v.redraw_after_ms, now + overflow_redraw_ms);
        v.wake.set(v.hub.io);
    }

    /// Room for `n` more frames, and one slot more that only `queueClosedLocked` uses. Every other
    /// queueing goes through here, so once a viewer has been pointed at a terminal (`claimLocked`
    /// reserves the slot) a `closed` always has room.
    fn reserveLocked(v: *Viewer, n: usize) Allocator.Error!void {
        try v.frames.ensureUnusedCapacity(v.hub.gpa, n + 1);
    }

    /// Tell the viewer its terminal went, with the frame made when it was opened. Never allocates.
    fn queueClosedLocked(v: *Viewer) void {
        const text = v.closed_frame orelse return;
        v.closed_frame = null;
        if (v.closed) return v.hub.gpa.free(text);
        // The kept slot is there (see `reserveLocked`); the screen content queued for a terminal that
        // is gone goes first anyway, so this frame cannot be left out.
        if (v.frames.items.len == v.frames.capacity) v.dropScreenLocked();
        if (v.frames.items.len == v.frames.capacity) {
            log.warn("no room to tell a viewer its terminal closed", .{});
            return v.hub.gpa.free(text);
        }
        v.frames.appendAssumeCapacity(.{ .binary = false, .data = text, .kind = .closed });
        v.wake.set(v.hub.io);
    }

    /// Drop queued screen content (live output, and any earlier redraw with its `opened` and theme
    /// frames): a redraw replaces all of it. Replies and state frames stay, in order.
    fn dropScreenLocked(v: *Viewer) void {
        const gpa = v.hub.gpa;
        var w: usize = 0;
        for (v.frames.items[v.head..]) |f| switch (f.kind) {
            .live, .redraw, .opened, .theme => f.deinit(gpa), // a redraw brings the current theme
            else => {
                v.frames.items[w] = f;
                w += 1;
            },
        };
        v.frames.items.len = w;
        v.head = 0;
        v.live_bytes = 0;
    }

    pub fn isClosed(v: *Viewer) bool {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        return v.closed;
    }

    /// The view generation if `term` is the terminal this viewer looks at now, else null. Returns
    /// with the lock released, so the caller may answer the viewer.
    fn viewGenOf(v: *Viewer, term: *const Terminal) ?u64 {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        return if (v.term == term) v.view_gen else null;
    }

    pub fn viewGen(v: *Viewer) u64 {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        return v.view_gen;
    }

    pub fn requestRedraw(v: *Viewer) void {
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        v.needs_redraw = true;
        v.redraw_seq +%= 1;
        v.wake.set(v.hub.io);
    }

    /// A frame the writer has sent: a live buffer goes back to the pool (if there is room and the
    /// viewer is still open), anything else is freed.
    pub fn recycle(v: *Viewer, f: Frame) void {
        if (!f.pooled) return f.deinit(v.hub.gpa);
        v.mu.lockUncancelable(v.hub.io);
        defer v.mu.unlock(v.hub.io);
        if (v.closed or v.live_pool_len == live_pool_max) return f.deinit(v.hub.gpa);
        v.live_pool[v.live_pool_len] = f.data.ptr[0..max_live_frame];
        v.live_pool_len += 1;
    }

    fn freeFrames(v: *Viewer) void {
        for (v.live_pool[0..v.live_pool_len]) |b| v.hub.gpa.free(b);
        v.live_pool_len = 0;
        if (v.closed_frame) |x| v.hub.gpa.free(x);
        v.closed_frame = null;
        for (v.frames.items[v.head..]) |f| f.deinit(v.hub.gpa);
        v.frames.deinit(v.hub.gpa);
        v.frames = .empty;
        v.head = 0;
    }
};

/// One open Rex terminal, shared by every viewer of it.
pub const Terminal = struct {
    hub: *Hub,
    session_id: []u8,
    block_id: []u8,
    input: *Input,
    /// Guards `mirror` and `data`, which a restart replaces.
    tmu: Io.Mutex = .init,
    mirror: *Mirror,
    data: *Data,
    /// Guards `viewers`: who gets live output.
    vmu: Io.Mutex = .init,
    viewers: std.ArrayList(*Viewer) = .empty,
    /// References (guarded by `Hub.mu`): viewers looking at it plus tasks using it. At zero it is
    /// destroyed.
    refs: u32 = 0,
    /// In `Hub.terminals` (guarded by `Hub.mu`). A closed terminal is taken out at once and destroyed
    /// when its last reference goes.
    registered: bool = false,
    /// A restart is under way (guarded by `Hub.mu`).
    restarting: bool = false,
    /// Set by the mirror when its stream ended; read by the supervisor.
    ended: std.atomic.Value(u8) = .init(0), // 0 none, else 1 + End
    restart_after_ms: i64 = 0,
    restarts: u32 = 0,
    /// The next terminal in a list one supervisor pass makes (ended, to restart, to destroy), so
    /// making it never needs memory. Written under `Hub.mu`; a list used after `mu` is released
    /// holds only terminals no other task links: being restarted (`restarting`), or closed with no
    /// reference left.
    link: ?*Terminal = null,

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
        for (t.viewers.items) |v| v.push(.theme, text);
    }

    fn onExited(ctx: *anyopaque, code: i64) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        var buf: [64]u8 = undefined;
        const text = std.fmt.bufPrint(&buf, "{{\"t\":\"exited\",\"code\":{d}}}", .{code}) catch return;
        t.vmu.lockUncancelable(t.hub.io);
        defer t.vmu.unlock(t.hub.io);
        for (t.viewers.items) |v| v.push(.exited, text);
    }

    fn onEnded(ctx: *anyopaque, why: rex.data.End) void {
        const t: *Terminal = @ptrCast(@alignCast(ctx));
        if (why == .closed_by_us) return;
        t.ended.store(1 + @as(u8, @backingInt(why)), .release);
        t.hub.supervisor_wake.set(t.hub.io);
    }
};

/// `text` without ESC and without the C1 controls (U+0080 to U+009F, which UTF-8 encodes as C2 80 to
/// C2 9F). Every other character is kept whole: bytes 0x80 to 0x9F are also the continuation bytes of
/// ordinary characters (’ € ß emoji), so only the two-byte C1 sequences are removed. The result is valid
/// UTF-8 when `text` is (the browser's JSON always is); `error.InvalidUtf8` otherwise. Caller frees.
fn cleanPaste(gpa: Allocator, text: []const u8) ![]u8 {
    if (!std.unicode.utf8ValidateSlice(text)) return error.InvalidUtf8;
    var out = try std.ArrayList(u8).initCapacity(gpa, text.len);
    errdefer out.deinit(gpa);
    var i: usize = 0;
    while (i < text.len) {
        const c = text[i];
        if (c == 0x1b) {
            i += 1;
            continue;
        }
        if (c == 0xc2 and i + 1 < text.len and text[i + 1] >= 0x80 and text[i + 1] <= 0x9f) {
            i += 2;
            continue;
        }
        out.appendAssumeCapacity(c);
        i += 1;
    }
    return out.toOwnedSlice(gpa);
}

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

/// Immutable text shared by reference (the session tree): copied for each viewer outside `Hub.mu`.
const SharedText = struct {
    refs: std.atomic.Value(u32) = .init(1),
    bytes: []u8,

    fn retain(t: *SharedText) void {
        _ = t.refs.fetchAdd(1, .monotonic);
    }

    fn release(t: *SharedText, gpa: Allocator) void {
        if (t.refs.fetchSub(1, .acq_rel) != 1) return;
        gpa.free(t.bytes);
        gpa.destroy(t);
    }
};

/// Server events that change the tree.
const tree_events = [_][]const u8{ "session_created", "session_destroyed", "session_label_changed", "session_view_changed", "block_created", "block_closed", "block_owner_changed", "window_created", "window_closed" };

/// A server event's name: the payload's `type`, or for an event inside a session, the `type` of the
/// `session_event`'s inner event (see Rex's llms.txt, "Events").
fn eventType(gpa: Allocator, json: []const u8) ?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return null;
    defer parsed.deinit();
    const pl = field(parsed.value, "payload") orelse return null;
    const ty = field(pl, "type") orelse return null;
    if (ty != .string) return null;
    if (!std.mem.eql(u8, ty.string, "session_event")) return gpa.dupe(u8, ty.string) catch null;
    const inner = field(field(field(pl, "payload") orelse return null, "event") orelse return null, "type") orelse return null;
    if (inner != .string) return null;
    return gpa.dupe(u8, inner.string) catch null;
}

fn field(v: std.json.Value, name: []const u8) ?std.json.Value {
    if (v != .object) return null;
    return v.object.get(name);
}

pub const Hub = struct {
    gpa: Allocator,
    io: Io,
    cfg: Config,
    ctl: *Control,
    api: Api,
    /// Serialises calls through `api` (it keeps `last_error`). Never held with `mu`.
    api_mu: Io.Mutex = .init,
    /// One-time tokens for file transfers (see `xfer.zig`).
    xfers: xfer.Registry,

    mu: Io.Mutex = .init,
    terminals: std.StringHashMapUnmanaged(*Terminal) = .empty,
    viewers: std.ArrayList(*Viewer) = .empty,
    next_viewer_id: u64 = 0,
    /// Sessions this bridge has attached (to open data streams), to redo after a reconnect.
    attached: std.StringHashMapUnmanaged(void) = .empty,
    /// The session tree as JSON, and its generation (goes up with every new tree).
    tree: ?*SharedText = null,
    tree_gen: u64 = 0,
    /// The hub-wide budget for work done under a mirror's lock (redraws, Copy), over all
    /// viewers. Guarded by `rate_mu`.
    rate_mu: Io.Mutex = .init,
    work_window_start: i64 = 0,
    work_count: u32 = 0,
    /// Terminal keys (`session|block`) in the last tree, and `session|*` for a session whose blocks
    /// could not be read (its terminals are kept). Null before the first tree.
    known: ?Known = null,
    tree_dirty: bool = true,
    rex_up: bool = true,
    closing: bool = false,
    /// The control connection's generation this hub has already set itself up for.
    seen_generation: u32 = 0,

    supervisor: ?Io.Future(void) = null,
    supervisor_wake: Io.Event = .unset,

    const Known = struct {
        arena: std.heap.ArenaAllocator,
        keys: std.StringHashMapUnmanaged(void) = .empty,
    };

    pub fn open(gpa: Allocator, io: Io, ctl: *Control, cfg: Config) !*Hub {
        const h = try gpa.create(Hub);
        errdefer gpa.destroy(h);
        h.* = .{ .gpa = gpa, .io = io, .cfg = cfg, .ctl = ctl, .api = Api.init(gpa, ctl), .xfers = xfer.Registry.init(gpa, io) };
        ctl.mu.lockUncancelable(io);
        h.seen_generation = ctl.generation;
        ctl.mu.unlock(io);
        // A failed open (Rex not ready yet: main tries again) frees what it made so far.
        errdefer {
            var ai = h.attached.keyIterator();
            while (ai.next()) |k| gpa.free(k.*);
            h.attached.deinit(gpa);
            if (h.tree) |t| t.release(gpa);
            if (h.known) |*k| k.arena.deinit();
            h.api.deinit();
            h.xfers.deinit();
        }
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
        while (it.next()) |e| {
            h.gpa.free(e.key_ptr.*);
            h.destroyTerminal(e.value_ptr.*);
        }
        h.terminals.deinit(h.gpa);
        var ai = h.attached.keyIterator();
        while (ai.next()) |k| h.gpa.free(k.*);
        h.attached.deinit(h.gpa);
        h.viewers.deinit(h.gpa);
        if (h.tree) |t| t.release(h.gpa);
        if (h.known) |*k| k.arena.deinit();
        h.api.deinit();
        h.xfers.deinit();
        h.gpa.destroy(h);
    }

    // ---- viewers ----

    pub fn addViewer(h: *Hub) !*Viewer {
        const v = try h.gpa.create(Viewer);
        errdefer h.gpa.destroy(v);
        v.* = .{ .hub = h, .history_lines = h.cfg.history_lines, .observe = h.cfg.observe_only };
        // Room for the mode, the tree and the slot kept for a `closed`.
        try v.frames.ensureTotalCapacity(h.gpa, 3);
        errdefer v.frames.deinit(h.gpa);
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        // The first frame is always the mode (with the Rex state): a page in token mode closes a
        // connection whose first frame is anything else. A viewer it cannot be made for is not added.
        const mode = try h.modeJson(v.observe);
        errdefer h.gpa.free(mode);
        try h.viewers.append(h.gpa, v);
        h.next_viewer_id += 1;
        v.id = h.next_viewer_id;
        v.frames.appendAssumeCapacity(.{ .binary = false, .data = mode, .kind = .mode });
        if (h.tree) |t| {
            v.push(.tree, t.bytes);
            v.tree_gen = h.tree_gen;
        }
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
        h.xfers.revokeViewer(v.id);
        v.mu.lockUncancelable(h.io);
        v.closed = true;
        v.freeFrames();
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
        const text = h.modeJson(observe) catch return;
        defer h.gpa.free(text);
        v.push(.mode, text);
    }

    /// The `mode` frame for a viewer whose read-only switch is `observe`. Caller holds `mu`
    /// (`rex_up`) and frees the result.
    fn modeJson(h: *Hub, observe: bool) Allocator.Error![]u8 {
        return std.json.Stringify.valueAlloc(h.gpa, .{
            .t = "mode",
            .observe = observe,
            .locked = h.cfg.observe_only,
            .rex_up = h.rex_up,
            .download = h.cfg.transfer.enabled and !h.cfg.observe_only,
            .upload = h.cfg.transfer.enabled and !h.cfg.observe_only and h.cfg.transfer.upload_dir != null,
            .debug = h.cfg.debug_input,
            .auth = if (h.cfg.token_mode) "token" else null,
        }, .{ .emit_null_optional_fields = false });
    }

    /// Whether an upload token issued to viewer `viewer_id` for view `view_gen` of this terminal may
    /// still be used: the viewer is still here, may write, and is still in that same view of that
    /// terminal (switching away and back raises `view_gen`). Checked when the upload arrives and
    /// again before its path is pasted. Do not call holding `api_mu`.
    pub fn mayUpload(h: *Hub, viewer_id: u64, session_id: []const u8, block_id: []const u8, view_gen: u64) bool {
        if (h.cfg.observe_only) return false;
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        for (h.viewers.items) |v| if (v.id == viewer_id) {
            v.mu.lockUncancelable(h.io);
            defer v.mu.unlock(h.io);
            if (v.closed or v.observe or v.view_gen != view_gen) return false;
            const t = v.term orelse return false;
            return std.mem.eql(u8, t.session_id, session_id) and std.mem.eql(u8, t.block_id, block_id);
        };
        return false;
    }

    /// Paste an uploaded file's path into the terminal its token was issued for, if viewer
    /// `viewer_id` is still here, may write, and is still in view `view_gen` of that terminal. The
    /// check and the queueing are one step under the viewer's lock, and the paste goes into the
    /// terminal's own input queue: it is ordered against that page's switching terminals, turning
    /// read-only or leaving exactly as its typing is, and against the typing itself. False: not
    /// pasted. Do not call holding `api_mu`.
    pub fn pasteUpload(h: *Hub, viewer_id: u64, session_id: []const u8, block_id: []const u8, view_gen: u64, text: []const u8) bool {
        if (h.cfg.observe_only) return false;
        const body = std.json.Stringify.valueAlloc(h.gpa, .{ .text = text }, .{}) catch return false;
        defer h.gpa.free(body);
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        for (h.viewers.items) |v| if (v.id == viewer_id) {
            v.mu.lockUncancelable(h.io);
            defer v.mu.unlock(h.io);
            if (v.closed or v.observe or v.view_gen != view_gen) return false;
            const t = v.term orelse return false;
            if (!std.mem.eql(u8, t.session_id, session_id) or !std.mem.eql(u8, t.block_id, block_id)) return false;
            // Only queues (the terminal's input worker makes the Rex call), so nothing waits here.
            t.input.blockEvent("paste", body) catch return false;
            return true;
        };
        return false;
    }

    // ---- commands from a browser ----

    /// At most this many requests a second from one browser that make Rex or the mirror work
    /// (opening, sizing, redraws, Copy, transfers, terminal actions, management), and this many reads
    /// (info, clipboard, tree): a tab switch (open, fit, two info polls) stays well inside both.
    pub const max_heavy_per_second: u32 = 8;
    pub const max_reads_per_second: u32 = 16;
    /// Work under a mirror's lock (open, redraw, more history, Copy) a second over all browsers.
    pub const max_hub_work_per_second: u32 = 32;

    const Class = enum { free, read, work };
    const MsgTag = std.meta.Tag(protocol.Msg);

    /// Every message type is listed, with no `else`: a new one does not compile until someone
    /// decides its rate class.
    fn classOf(tag: MsgTag) Class {
        return switch (tag) {
            .info, .clip, .tree => .read,
            .text, .ls, .dl, .ul, .redraw, .more_history, .open, .fit, .term_action, .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session => .work,
            // Typing and pastes are bounded by the connection's message rate and the input limits;
            // `observe` only narrows what the viewer may do.
            .close_view, .in, .key, .paste, .observe, .ping, .dbg => .free,
        };
    }

    /// Work under a mirror's lock counted against the hub-wide budget. Opening is not: one viewer's
    /// open is already limited by its own allowance, and a refused open costs the user their view.
    fn underMirrorLock(tag: MsgTag) bool {
        return switch (tag) {
            .redraw, .more_history, .text => true,
            .tree, .open, .close_view, .in, .key, .paste, .fit, .info, .ls, .dl, .ul, .clip, .term_action, .observe, .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session, .ping, .dbg => false,
        };
    }

    comptime {
        // Every message type has a class, and work under a mirror's lock is never free.
        for (std.meta.tags(MsgTag)) |tag| {
            if (underMirrorLock(tag) and classOf(tag) == .free) @compileError("message under a mirror's lock without a rate class: " ++ @tagName(tag));
        }
    }

    fn allowRate(h: *Hub, v: *Viewer, msg: protocol.Msg) bool {
        const tag = std.meta.activeTag(msg);
        const class = classOf(tag);
        if (class == .free) return true;
        const now = std.Io.Clock.awake.now(h.io).toMilliseconds();
        {
            v.mu.lockUncancelable(h.io);
            defer v.mu.unlock(h.io);
            const start = if (class == .read) &v.read_window_start else &v.heavy_window_start;
            const count = if (class == .read) &v.read_count else &v.heavy_count;
            if (now - start.* >= 1000) {
                start.* = now;
                count.* = 0;
            }
            count.* +|= 1;
            if (count.* > (if (class == .read) max_reads_per_second else max_heavy_per_second)) return false;
        }
        if (!underMirrorLock(tag)) return true;
        h.rate_mu.lockUncancelable(h.io);
        defer h.rate_mu.unlock(h.io);
        if (now - h.work_window_start >= 1000) {
            h.work_window_start = now;
            h.work_count = 0;
        }
        h.work_count +|= 1;
        return h.work_count <= max_hub_work_per_second;
    }

    /// Run one message from a viewer. Problems are answered as `error` frames, not returned.
    pub fn handle(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        if (!h.allowRate(v, msg)) {
            // A refused open still leaves the terminal being viewed: the page has already switched
            // its view, and typing must not go to a terminal it no longer shows.
            if (msg == .open) {
                h.unsubscribe(v);
                return h.refuseOpen(v, msg.open.session, msg.open.block, "too many requests", true, true);
            }
            const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = @tagName(msg), .msg = "too many requests", .rate = true }, .{}) catch return;
            defer h.gpa.free(text);
            return v.pushText(text);
        }
        switch (msg) {
            .ping => v.pushText("{\"t\":\"pong\"}"),
            .dbg => {},
            .text => h.sendText(v),
            .info => h.sendInfo(v),
            .ls, .dl, .ul => h.transfer(v, msg),
            .clip => {
                const term = h.pin(v) orelse return h.refuse(v, "clip", "no terminal open");
                defer h.unpin(term);
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
                const term = h.pin(v) orelse return h.refuse(v, "term_action", "no terminal open");
                defer h.unpin(term);
                if (!h.forTerminal(v, "term_action", term, act.at)) return;
                h.api_mu.lockUncancelable(h.io);
                defer h.api_mu.unlock(h.io);
                h.api.termAction(term.session_id, term.block_id, @tagName(act.action)) catch |e| h.fail(v, "term_action", e);
            },
            .tree => h.sendTree(v),
            // A refusal names the terminal it was for, so a page that has moved on can ignore it, and
            // says whether it may pass (Rex not answering, a snapshot that did not come) or not (Rex
            // refused: no such terminal).
            .open => |o| h.openTerminal(v, o.session, o.block) catch |e| h.refuseOpen(v, o.session, o.block, @errorName(e), false, e != error.RexError),
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
                const now_observing = v.observe;
                v.mu.unlock(h.io);
                if (now_observing) h.xfers.revokeViewer(v.id);
                h.mu.lockUncancelable(h.io);
                defer h.mu.unlock(h.io);
                h.pushModeLocked(v);
            },
            .in, .key, .paste, .fit => h.input(v, msg),
            .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session => h.manage(v, msg),
        }
    }

    /// Directory listings and the first step of a download or upload: checked here, answered with a
    /// token the page then presents over HTTP (see `server.zig`).
    fn transfer(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        const what = @tagName(msg);
        if (!h.cfg.transfer.enabled) return h.refuse(v, what, "file transfer is off on this bridge");
        if (h.isObserving(v)) return h.refuse(v, what, "read-only");
        const term = h.pin(v) orelse return h.refuse(v, what, "no terminal open");
        defer h.unpin(term);

        switch (msg) {
            .ls => |l| {
                if (!h.forTerminal(v, what, term, l.at)) return;
                const path = l.path;
                h.api_mu.lockUncancelable(h.io);
                defer h.api_mu.unlock(h.io);
                var d = h.api.listDir(term.session_id, term.block_id, path) catch |e| return h.fail(v, what, e);
                defer d.deinit();
                const Out = struct { n: []const u8, d: bool };
                var list: std.ArrayList(Out) = .empty;
                defer list.deinit(h.gpa);
                for (d.value.entries) |e| list.append(h.gpa, .{ .n = e.name, .d = e.dir }) catch return;
                const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "ls", .path = d.value.path, .home = d.value.home, .status = d.value.status, .entries = list.items, .truncated = d.value.truncated }, .{}) catch return;
                defer h.gpa.free(out);
                v.pushText(out);
            },
            .dl => |d| {
                if (!h.forTerminal(v, what, term, d.at)) return;
                const path = d.path;
                const ref = rex.transfer.newRef(h.io, "download:");
                h.api_mu.lockUncancelable(h.io);
                defer h.api_mu.unlock(h.io);
                var t_info = h.api.downloadBegin(term.session_id, term.block_id, &ref, path) catch |e| {
                    return h.refuse(v, what, if (h.api.last_error) |le| le else @errorName(e));
                };
                defer t_info.deinit();
                if (t_info.value.size > h.cfg.transfer.max_bytes) {
                    var buf: [96]u8 = undefined;
                    return h.refuse(v, what, std.fmt.bufPrint(&buf, "too large: the limit is {d} MB", .{h.cfg.transfer.max_bytes / (1024 * 1024)}) catch "too large");
                }
                const name = h.gpa.dupe(u8, t_info.value.name) catch return;
                const token = h.xfers.add(.{ .token = undefined, .kind = .download, .expires_ms = 0, .ticket = t_info.value.ticket, .name = name, .size = t_info.value.size, .viewer_id = v.id }) catch |e| return h.refuse(v, what, transferRefusal(e));
                const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "xfer", .kind = "download", .token = token, .name = t_info.value.name, .size = t_info.value.size }, .{}) catch return;
                defer h.gpa.free(out);
                v.pushText(out);
            },
            .ul => |u| {
                if (h.cfg.transfer.upload_dir == null) return h.refuse(v, what, "uploads are off on this bridge");
                if (!h.forTerminal(v, what, term, u.at)) return;
                if (u.size > h.cfg.transfer.max_bytes) {
                    var buf: [96]u8 = undefined;
                    return h.refuse(v, what, std.fmt.bufPrint(&buf, "too large: the limit is {d} MB", .{h.cfg.transfer.max_bytes / (1024 * 1024)}) catch "too large");
                }
                // The terminal can close under the page between the pin above and here (another task
                // clears `v.term`). The refusal is sent after the viewer's lock is released: sending
                // takes that lock.
                const view_gen = v.viewGenOf(term) orelse return h.refuse(v, what, "the page showed another terminal when this was asked");
                const name = h.gpa.dupe(u8, u.name) catch return;
                const sid = h.gpa.dupe(u8, term.session_id) catch return h.gpa.free(name);
                const bid = h.gpa.dupe(u8, term.block_id) catch {
                    h.gpa.free(name);
                    return h.gpa.free(sid);
                };
                // `add` owns the strings from here, on success or failure.
                const token = h.xfers.add(.{ .token = undefined, .kind = .upload, .expires_ms = 0, .name = name, .size = u.size, .session_id = sid, .block_id = bid, .viewer_id = v.id, .view_gen = view_gen }) catch |e| return h.refuse(v, what, transferRefusal(e));
                const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "xfer", .kind = "upload", .token = token, .size = u.size }, .{}) catch return;
                defer h.gpa.free(out);
                v.pushText(out);
            },
            else => unreachable,
        }
    }

    /// What the page is told when a transfer could not be registered.
    fn transferRefusal(e: error{ TooMany, OutOfMemory }) []const u8 {
        return switch (e) {
            error.TooMany => "too many transfers waiting",
            error.OutOfMemory => "out of memory",
        };
    }

    fn sendInfo(h: *Hub, v: *Viewer) void {
        const term = h.pin(v) orelse return;
        defer h.unpin(term);
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

    /// The Copy view: the terminal's text, for the browser to select from.
    fn sendText(h: *Hub, v: *Viewer) void {
        // One Copy reply at a time, refused before any work when it could not be queued (its JSON
        // can be up to six times the text).
        const busy = blk: {
            v.mu.lockUncancelable(h.io);
            defer v.mu.unlock(h.io);
            for (v.frames.items[v.head..]) |f| if (f.kind == .copy) break :blk true;
            break :blk v.text_bytes + 6 * max_copy_bytes > max_text_bytes;
        };
        if (busy) return h.refuse(v, "text", "busy: the last Copy has not been sent yet");
        const term = h.pin(v) orelse return h.refuse(v, "text", "no terminal open");
        defer h.unpin(term);
        term.tmu.lockUncancelable(h.io);
        // Capped in rows and in cells (rows times columns, read under the mirror's lock).
        const res = term.mirror.plainTextAllCells(h.gpa, max_copy_bytes, max_copy_rows, max_copy_cells);
        term.tmu.unlock(h.io);
        const pt = res catch |e| return h.fail(v, "text", e);
        defer h.gpa.free(pt.text);
        const out = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "text", .text = pt.text, .truncated = pt.truncated }, .{}) catch return;
        defer h.gpa.free(out);
        v.push(.copy, out);
    }

    fn refuseOpen(h: *Hub, v: *Viewer, session: []const u8, block: []const u8, msg: []const u8, rate: bool, transient: bool) void {
        const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = "open", .session = session, .block = block, .msg = msg, .rate = rate, .transient = transient }, .{}) catch return;
        defer h.gpa.free(text);
        v.pushText(text);
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

    /// Whether a message that names its terminal (`protocol.Target`) is for `term`, the one this
    /// viewer has open. What the page sends after a wait (the clipboard, a question, an upload's turn)
    /// was asked of the terminal on screen then; if the page shows another by the time it is sent, it
    /// must reach neither. The page checks that itself; this is the second line. Refused and answered
    /// here when not: `stale` for another terminal, `reload` for a page that names none (one an
    /// earlier rweb served, which could not make the promise).
    fn forTerminal(h: *Hub, v: *Viewer, what: []const u8, term: *const Terminal, at: ?protocol.Target) bool {
        const code: []const u8, const msg: []const u8 = blk: {
            const t = at orelse break :blk .{ "reload", "this page is from an earlier rweb: reload it" };
            if (std.mem.eql(u8, t.session, term.session_id) and std.mem.eql(u8, t.block, term.block_id)) return true;
            break :blk .{ "stale", "the page showed another terminal when this was asked" };
        };
        const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = what, .code = code, .msg = msg }, .{}) catch return false;
        defer h.gpa.free(text);
        v.pushText(text);
        return false;
    }

    fn isObserving(h: *Hub, v: *Viewer) bool {
        v.mu.lockUncancelable(h.io);
        defer v.mu.unlock(h.io);
        return v.observe or h.cfg.observe_only;
    }

    fn input(h: *Hub, v: *Viewer, msg: protocol.Msg) void {
        if (h.isObserving(v)) return h.refuse(v, "input", "read-only");
        const term = h.pin(v) orelse return h.refuse(v, "input", "no terminal open");
        defer h.unpin(term);
        switch (msg) {
            .in => |d| term.input.writeText(d) catch |e| h.fail(v, "in", e),
            .paste => |p| {
                if (!h.forTerminal(v, "paste", term, p.at)) return;
                // ESC and C1 never go through: a pasted "end of paste" would type the rest. The page
                // removes them too; this is the second line.
                const clean = cleanPaste(h.gpa, p.text) catch |e| return h.fail(v, "paste", e);
                defer h.gpa.free(clean);
                // Without bracketed paste a program reads a pasted newline as Enter: several lines
                // would run one by one. The page asks the user, then sends `force`.
                // Read under `tmu`: a stream restart swaps (and frees) the mirror.
                const bracketed = blk: {
                    term.tmu.lockUncancelable(h.io);
                    defer term.tmu.unlock(h.io);
                    break :blk term.mirror.bracketedPaste();
                };
                if (!p.force and std.mem.indexOfAny(u8, clean, "\r\n") != null and !bracketed) {
                    const text = std.json.Stringify.valueAlloc(h.gpa, .{ .t = "error", .@"for" = "paste", .code = "confirm_multiline", .msg = "this program does not take pastes as one block; each line would run on its own" }, .{}) catch return;
                    defer h.gpa.free(text);
                    return v.pushText(text);
                }
                const body = std.json.Stringify.valueAlloc(h.gpa, .{ .text = clean }, .{}) catch return;
                defer h.gpa.free(body);
                term.input.blockEvent("paste", body) catch |e| h.fail(v, "paste", e);
            },
            .key => |k| term.input.key(k) catch |e| h.fail(v, "key", e),
            .fit => |f| {
                if (!h.forTerminal(v, "fit", term, f.at)) return;
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
        const ok = blk: {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            const api = &h.api;
            const result: anyerror!void = switch (msg) {
                .new_session => |label| r: {
                    var made = api.createSession(label) catch |e| break :r e;
                    made.deinit();
                    break :r {};
                },
                .new_terminal => |sid| r: {
                    var nt = api.newTerminal(sid, false) catch |e| break :r e;
                    nt.deinit();
                    break :r {};
                },
                .rename_session => |r| api.renameSession(r.session, r.label),
                .rename_block => |r| api.renameBlock(r.session, r.block, r.label),
                .close_block => |r| api.closeBlock(r.session, r.block),
                .destroy_session => |sid| r: {
                    // destroy needs an attachment
                    api.attach(sid) catch |e| break :r e;
                    break :r api.destroySession(sid);
                },
                else => unreachable,
            };
            result catch |e| {
                h.refuse(v, "manage", api.last_error orelse @errorName(e));
                break :blk false;
            };
            break :blk true;
        };
        // After `api_mu` is released: this takes `mu`.
        if (ok) h.markTreeDirty();
    }

    // ---- terminals ----

    fn terminalKey(buf: []u8, sid: []const u8, bid: []const u8) ![]u8 {
        return std.fmt.bufPrint(buf, "{s}|{s}", .{ sid, bid });
    }

    /// The terminal `v` looks at, with a reference the caller gives back with `unpin`: it stays alive
    /// meanwhile even if it is closed or the viewer moves on.
    fn pin(h: *Hub, v: *Viewer) ?*Terminal {
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        v.mu.lockUncancelable(h.io);
        const t = v.term;
        v.mu.unlock(h.io);
        if (t) |x| x.refs += 1;
        return t;
    }

    fn unpin(h: *Hub, t: *Terminal) void {
        h.mu.lockUncancelable(h.io);
        const dead = h.unrefLocked(t);
        h.mu.unlock(h.io);
        if (dead) h.destroyTerminal(t);
    }

    /// Drop one reference; true when it was the last, and the caller must destroy `t` (after
    /// releasing `mu`).
    fn unrefLocked(h: *Hub, t: *Terminal) bool {
        t.refs -= 1;
        if (t.refs > 0) return false;
        h.unregisterLocked(t);
        return true;
    }

    /// Caller holds `mu`. Forget every attached session; each is attached again when needed.
    fn forgetAttachedLocked(h: *Hub) void {
        var it = h.attached.keyIterator();
        while (it.next()) |k| h.gpa.free(k.*);
        h.attached.clearRetainingCapacity();
    }

    fn unregisterLocked(h: *Hub, t: *Terminal) void {
        if (!t.registered) return;
        var it = h.terminals.iterator();
        while (it.next()) |e| if (e.value_ptr.* == t) {
            const key = e.key_ptr.*;
            h.terminals.removeByPtr(e.key_ptr);
            h.gpa.free(key);
            break;
        };
        t.registered = false;
    }

    /// Point `v` at `t` with a viewer's reference, plus one the caller gives back with `unpin`. The
    /// `closed` frame for `t` and a slot for it are made first: on failure nothing has changed.
    /// Caller holds `mu`.
    fn claimLocked(h: *Hub, v: *Viewer, t: *Terminal) Allocator.Error!void {
        const closed = try std.json.Stringify.valueAlloc(h.gpa, .{ .t = "closed", .session = t.session_id, .block = t.block_id, .reason = "closed" }, .{});
        v.mu.lockUncancelable(h.io);
        defer v.mu.unlock(h.io);
        v.reserveLocked(0) catch |e| {
            h.gpa.free(closed);
            return e;
        };
        if (v.closed_frame) |old| h.gpa.free(old);
        v.closed_frame = closed;
        t.refs += 2;
        v.term = t;
        v.view_gen +%= 1;
        v.history_lines = h.cfg.history_lines;
    }

    fn openTerminal(h: *Hub, v: *Viewer, sid: []const u8, bid: []const u8) !void {
        h.unsubscribe(v);
        var kb: [512]u8 = undefined;
        const key = try terminalKey(&kb, sid, bid);

        const term: *Terminal = blk: {
            h.mu.lockUncancelable(h.io);
            if (h.terminals.get(key)) |t| {
                h.claimLocked(v, t) catch |e| {
                    h.mu.unlock(h.io);
                    return e;
                };
                h.mu.unlock(h.io);
                break :blk t;
            }
            h.mu.unlock(h.io);
            // Opening waits for Rex (an attach, a stream and its snapshot): never while holding
            // `mu`, which every other viewer needs. Another viewer may open the same terminal
            // meanwhile; then the first one registered is kept and the other is closed.
            try h.ensureAttached(sid);
            const fresh = try h.newTerminal(sid, bid);
            h.mu.lockUncancelable(h.io);
            if (h.closing) {
                h.mu.unlock(h.io);
                h.destroyTerminal(fresh);
                return error.Closing;
            }
            if (h.terminals.get(key)) |other| {
                const claimed = h.claimLocked(v, other);
                h.mu.unlock(h.io);
                h.destroyTerminal(fresh);
                try claimed;
                break :blk other;
            }
            const k = h.gpa.dupe(u8, key) catch |e| {
                h.mu.unlock(h.io);
                h.destroyTerminal(fresh);
                return e;
            };
            h.terminals.put(h.gpa, k, fresh) catch |e| {
                h.mu.unlock(h.io);
                h.gpa.free(k);
                h.destroyTerminal(fresh);
                return e;
            };
            fresh.registered = true;
            h.claimLocked(v, fresh) catch |e| {
                h.unregisterLocked(fresh);
                h.mu.unlock(h.io);
                h.destroyTerminal(fresh);
                return e;
            };
            h.mu.unlock(h.io);
            break :blk fresh;
        };
        defer h.unpin(term);
        h.subscribeTo(v, term) catch |e| {
            h.unsubscribe(v); // gives back the viewer's reference
            return e;
        };
    }

    /// Opens a stream and waits for the first snapshot. Called without `mu`; the session must be
    /// attached. The caller registers the terminal.
    fn newTerminal(h: *Hub, sid: []const u8, bid: []const u8) !*Terminal {
        const gpa = h.gpa;

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
        return t;
    }

    const Stream = struct { mirror: *Mirror, data: *Data };

    /// Longest wait for a new stream's snapshot.
    const snapshot_wait_ms = 5000;

    /// A new mirror following a new data stream, live and observed by `t`.
    fn openStream(h: *Hub, sid: []const u8, bid: []const u8, t: *Terminal) !Stream {
        const m = try Mirror.initPending(h.gpa, h.io);
        errdefer m.deinit();
        m.setObserver(t.observer());
        const d = try Data.openTerminal(h.gpa, h.io, h.ctl, sid, bid, m.sink());
        errdefer d.close();
        var waited: u32 = 0;
        while (m.getStatus() != .live) : (waited += 5) {
            if (waited > snapshot_wait_ms or m.endReason() != null or m.getStatus() == .failed) return error.NoSnapshot;
            try h.io.sleep(.fromMilliseconds(5), .awake);
        }
        return .{ .mirror = m, .data = d };
    }

    /// Attach `sid` once, so its streams can be opened. Takes `mu` and `api_mu`, never both.
    fn ensureAttached(h: *Hub, sid: []const u8) !void {
        h.mu.lockUncancelable(h.io);
        const have = h.attached.contains(sid);
        h.mu.unlock(h.io);
        if (have) return;
        {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            try h.api.attach(sid);
        }
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        if (h.attached.contains(sid)) return;
        const k = try h.gpa.dupe(u8, sid);
        h.attached.put(h.gpa, k, {}) catch |e| {
            h.gpa.free(k);
            return e;
        };
    }

    fn subscribeTo(h: *Hub, v: *Viewer, t: *Terminal) !void {
        v.mu.lockUncancelable(h.io);
        v.needs_redraw = false;
        v.mu.unlock(h.io);
        try h.redrawInto(v, t, true);
    }

    /// Build a redraw for `v` from `t`'s mirror and, atomically with the mirror's live output,
    /// swap it in for whatever screen content `v` had queued. With `subscribe`, also add `v` to the
    /// viewers. Nothing happens if `v` no longer looks at `t` (it moved on, or `t` was closed).
    /// The caller holds a reference to `t`.
    fn redrawInto(h: *Hub, v: *Viewer, t: *Terminal, subscribe: bool) !void {
        const Ctx = struct {
            h: *Hub,
            v: *Viewer,
            t: *Terminal,
            subscribe: bool,
            /// The viewer's redraw requests seen when this redraw started.
            seq: u64,
            fn deliver(ctx: *anyopaque, bytes: []const u8) anyerror!void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                const gpa = c.h.gpa;
                const m = c.t.mirror;
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
                    .history_max = max_redraw_history_rows,
                    .owner = m.owner,
                    .exited = m.exit_code,
                }, .{});
                var queued = false;
                defer if (!queued) gpa.free(opened);
                const theme = if (m.theme) |*th| try themeFrame(gpa, th) else null;
                defer if (!queued) if (theme) |x| gpa.free(x);
                const body = try gpa.dupe(u8, bytes);
                defer if (!queued) gpa.free(body);

                c.t.vmu.lockUncancelable(c.h.io);
                defer c.t.vmu.unlock(c.h.io);
                const vw = c.v;
                vw.mu.lockUncancelable(c.h.io);
                defer vw.mu.unlock(c.h.io);
                if (vw.term != c.t) return; // closed, or the viewer moved on: nothing to show
                if (c.subscribe) {
                    var present = false;
                    for (c.t.viewers.items) |x| if (x == vw) {
                        present = true;
                    };
                    if (!present) try c.t.viewers.append(gpa, vw);
                }
                vw.dropScreenLocked();
                // Replies and state frames queued before the redraw stay; the redraw frames go last.
                try vw.reserveLocked(3);
                vw.frames.appendAssumeCapacity(.{ .binary = false, .data = opened, .kind = .opened });
                if (theme) |x| vw.frames.appendAssumeCapacity(.{ .binary = false, .data = x, .kind = .theme });
                // Not live output: one redraw at most is queued, and its rows are capped.
                vw.frames.appendAssumeCapacity(.{ .binary = true, .data = body, .kind = .redraw });
                queued = true;
                if (vw.redraw_seq == c.seq) vw.needs_redraw = false; // a later request still stands
                if (vw.history_lines == null) vw.history_lines = c.h.cfg.history_lines; // "all" is once
                vw.wake.set(c.h.io);
            }
        };
        var ctx: Ctx = .{ .h = h, .v = v, .t = t, .subscribe = subscribe, .seq = 0 };
        v.mu.lockUncancelable(h.io);
        ctx.seq = v.redraw_seq;
        const wanted = @min(v.history_lines orelse max_redraw_history_rows, max_redraw_history_rows);
        v.mu.unlock(h.io);
        t.tmu.lockUncancelable(h.io);
        defer t.tmu.unlock(h.io);
        // Scrollback is capped in cells too, so a very wide terminal sends fewer rows.
        try t.mirror.redrawLocked(h.gpa, .{ .history_lines = wanted, .history_cells = max_redraw_cells }, &ctx, Ctx.deliver);
    }

    /// From a viewer's own `next`: its queue is stale (overflow, resize, history request).
    fn redrawFor(h: *Hub, v: *Viewer) !void {
        const t = h.pin(v) orelse {
            v.mu.lockUncancelable(h.io);
            v.needs_redraw = false;
            v.mu.unlock(h.io);
            return;
        };
        defer h.unpin(t);
        v.mu.lockUncancelable(h.io);
        const seq = v.redraw_seq;
        v.mu.unlock(h.io);
        h.redrawInto(v, t, false) catch |e| {
            // A restart can leave a moment with no live mirror; the restart asks again. Clear only
            // the requests this redraw saw: one that came meanwhile (the restart's) still stands.
            v.mu.lockUncancelable(h.io);
            if (v.redraw_seq == seq) v.needs_redraw = false;
            v.mu.unlock(h.io);
            return e;
        };
    }

    /// Stop viewing; the last reference to go closes the terminal. Also revokes waiting upload
    /// tokens for this viewer so leaving a terminal invalidates uploads started before the switch.
    fn unsubscribe(h: *Hub, v: *Viewer) void {
        h.mu.lockUncancelable(h.io);
        v.mu.lockUncancelable(h.io);
        const got = v.term;
        v.term = null;
        v.view_gen +%= 1;
        v.mu.unlock(h.io);
        const t = got orelse {
            h.mu.unlock(h.io);
            return;
        };
        t.vmu.lockUncancelable(h.io);
        for (t.viewers.items, 0..) |x, i| if (x == v) {
            _ = t.viewers.swapRemove(i);
            break;
        };
        t.vmu.unlock(h.io);
        const dead = h.unrefLocked(t);
        h.mu.unlock(h.io);
        h.xfers.revokeViewerUploads(v.id);
        if (dead) h.destroyTerminal(t);
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
        const t = h.tree orelse return null;
        return h.gpa.dupe(u8, t.bytes) catch null;
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
        var known: Known = .{ .arena = std.heap.ArenaAllocator.init(gpa) };
        var keep_known = false;
        defer if (!keep_known) known.arena.deinit();
        const ka = known.arena.allocator();

        {
            h.api_mu.lockUncancelable(h.io);
            defer h.api_mu.unlock(h.io);
            var sessions = try h.api.sessions();
            defer sessions.deinit();
            for (sessions.value) |s| {
                var blocks = h.api.blocks(s.session_id) catch {
                    // A session that just went away, or one that failed to answer: keep its
                    // terminals until a tree says which blocks it has.
                    try known.keys.put(ka, try ka.print("{s}|*", .{s.session_id}), {});
                    continue;
                };
                defer blocks.deinit();
                const bl = try arena.alloc(Blk, blocks.value.len);
                for (blocks.value, bl) |b, *o| {
                    o.* = .{
                        .id = try arena.dupe(u8, b.block_id),
                        .label = try arena.dupe(u8, b.label),
                        .flavor = if (b.flavor) |f| try arena.dupe(u8, f) else null,
                        .owner = if (b.owner) |ow| try arena.dupe(u8, ow) else null,
                        .window = if (b.window_id) |w| try arena.dupe(u8, w) else null,
                        .placement = try arena.dupe(u8, b.placement),
                    };
                    try known.keys.put(ka, try ka.print("{s}|{s}", .{ s.session_id, b.block_id }), {});
                }
                try out.append(arena, .{ .id = try arena.dupe(u8, s.session_id), .label = try arena.dupe(u8, s.label), .blocks = bl });
            }
        }

        const text = try std.json.Stringify.valueAlloc(gpa, .{
            .t = "tree",
            .observe_only = h.cfg.observe_only,
            .sessions = out.items,
        }, .{});
        const shared = gpa.create(SharedText) catch |e| {
            gpa.free(text);
            return e;
        };
        shared.* = .{ .bytes = text };
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        if (h.tree) |old| old.release(gpa);
        h.tree = shared;
        h.tree_gen += 1;
        if (h.known) |*old| old.arena.deinit();
        h.known = known;
        keep_known = true;
        h.tree_dirty = false;
        for (h.viewers.items) |v| {
            v.push(.tree, text);
            v.mu.lockUncancelable(h.io);
            v.tree_gen = h.tree_gen;
            v.mu.unlock(h.io);
        }
    }

    /// The tree, for a viewer that asks: only if it does not have the current one queued or sent
    /// already, and copied outside `mu`.
    fn sendTree(h: *Hub, v: *Viewer) void {
        h.mu.lockUncancelable(h.io);
        const t = h.tree orelse return h.mu.unlock(h.io);
        const gen = h.tree_gen;
        t.retain();
        h.mu.unlock(h.io);
        defer t.release(h.gpa);
        v.mu.lockUncancelable(h.io);
        const have = v.tree_gen == gen;
        v.mu.unlock(h.io);
        if (have) return;
        v.push(.tree, t.bytes);
        v.mu.lockUncancelable(h.io);
        v.tree_gen = gen;
        v.mu.unlock(h.io);
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
        for (h.viewers.items) |v| v.push(.rex, text);
    }

    fn onEvent(h: *Hub, e: rex.control.Event) void {
        switch (e) {
            .disconnected => h.broadcastRexState(false),
            .connected => |c| {
                // Generations up to the one `open` used are already set up (its own first connection
                // included): nothing to announce or re-read.
                if (c.generation <= h.seen_generation) return;
                h.seen_generation = c.generation;
                h.broadcastRexState(true);
                if (!c.resumed) h.reattachAfterRestart();
                h.markTreeDirty();
            },
            .dropped => h.markTreeDirty(),
            .server => |s| {
                const ty = eventType(h.gpa, s.json) orelse return;
                defer h.gpa.free(ty);
                for (tree_events) |name| if (std.mem.eql(u8, ty, name)) {
                    h.markTreeDirty();
                    break;
                };
                if (std.mem.eql(u8, ty, "session_destroyed") or std.mem.eql(u8, ty, "block_closed"))
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
        // The sessions to attach again. Their ids are the set's own keys, borrowed: a key is freed
        // only below (on this task) and by `close`, which stops this task first. A session that is
        // not attached again is forgotten, and attached when its terminal restarts or is next opened
        // (`ensureAttached`), so no failure here leaves a terminal without its session.
        const Id = struct { sid: []const u8, ok: bool = true };
        var ids: std.ArrayList(Id) = .empty;
        defer ids.deinit(h.gpa);
        h.mu.lockUncancelable(h.io);
        if (ids.ensureTotalCapacityPrecise(h.gpa, h.attached.count())) {
            var it = h.attached.keyIterator();
            while (it.next()) |k| ids.appendAssumeCapacity(.{ .sid = k.* });
        } else |_| h.forgetAttachedLocked();
        h.mu.unlock(h.io);
        h.api_mu.lockUncancelable(h.io);
        for (ids.items) |*id| h.api.attach(id.sid) catch |e| {
            log.debug("re-attach: {t}", .{e});
            id.ok = false;
        };
        h.api_mu.unlock(h.io);
        // Every stream is gone: rebuild each from a new snapshot.
        h.mu.lockUncancelable(h.io);
        defer h.mu.unlock(h.io);
        for (ids.items) |id| if (!id.ok) if (h.attached.fetchRemove(id.sid)) |kv| h.gpa.free(kv.key);
        var ti = h.terminals.valueIterator();
        while (ti.next()) |t| {
            t.*.ended.store(1 + @as(u8, @backingInt(rex.data.End.restart_needed)), .release);
            t.*.restart_after_ms = 0;
        }
        h.supervisor_wake.set(h.io);
    }

    /// Terminals whose block or session is not in a fresh tree: tell their viewers and drop them.
    /// Needs no memory past the tree.
    fn dropGoneTerminals(h: *Hub) void {
        h.refreshTree() catch return;
        h.mu.lockUncancelable(h.io);
        const dead = h.closeGoneLocked();
        h.mu.unlock(h.io);
        h.destroyList(dead);
    }

    /// Caller holds `mu`. Close every terminal the last tree does not have; returns those the caller
    /// destroys after releasing `mu`.
    fn closeGoneLocked(h: *Hub) ?*Terminal {
        const known = if (h.known) |*k| k else return null;
        var dead: ?*Terminal = null;
        // One at a time: closing takes a terminal out of `terminals`, which must not change while it
        // is iterated.
        while (h.goneLocked(known)) |t| if (h.closeTerminalLocked(t)) {
            t.link = dead;
            dead = t;
        };
        return dead;
    }

    /// Caller holds `mu`. A terminal whose block, and whose session's blocks, are not in `known`.
    fn goneLocked(h: *Hub, known: *const Known) ?*Terminal {
        var it = h.terminals.valueIterator();
        while (it.next()) |tp| {
            const t = tp.*;
            var kb: [512]u8 = undefined;
            const key = terminalKey(&kb, t.session_id, t.block_id) catch continue;
            if (known.keys.contains(key)) continue;
            var ab: [512]u8 = undefined;
            const session_unknown = terminalKey(&ab, t.session_id, "*") catch continue;
            if (known.keys.contains(session_unknown)) continue;
            return t;
        }
        return null;
    }

    /// Destroy every terminal on a list of closed ones (linked by `link`). Call without `mu`.
    fn destroyList(h: *Hub, first: ?*Terminal) void {
        var next = first;
        while (next) |t| {
            next = t.link;
            h.destroyTerminal(t);
        }
    }

    /// Caller holds `mu`. Take `t` out, tell its viewers and detach them. True when no reference is
    /// left and the caller must destroy `t` after releasing `mu`; otherwise the last task holding
    /// it does. Never allocates: every viewer of `t` is told `closed` (see `Viewer.closed_frame`).
    fn closeTerminalLocked(h: *Hub, t: *Terminal) bool {
        h.unregisterLocked(t);
        // Detach every viewer and empty the list in one step under `vmu`: a subscribe in progress
        // either finishes before (and is emptied out) or finds `term` cleared (and adds nothing).
        t.vmu.lockUncancelable(h.io);
        for (h.viewers.items) |v| {
            v.mu.lockUncancelable(h.io);
            defer v.mu.unlock(h.io);
            if (v.term != t) continue;
            v.term = null;
            v.queueClosedLocked();
            t.refs -= 1;
        }
        t.viewers.clearRetainingCapacity();
        t.vmu.unlock(h.io);
        return t.refs == 0;
    }

    /// Rebuild the stream of every terminal whose stream ended. The streams are opened without
    /// `mu`; a terminal is held by a reference meanwhile, and gets its new stream only if it is still
    /// open by then.
    fn restartEnded(h: *Hub) void {
        // Lists linked through `Terminal.link`: no memory needed, so no terminal is skipped or leaked.
        var todo: ?*Terminal = null;
        var dead: ?*Terminal = null;
        const now = std.Io.Clock.awake.now(h.io).toMilliseconds();
        {
            h.mu.lockUncancelable(h.io);
            defer h.mu.unlock(h.io);
            // Listed first: closing takes a terminal out of `terminals`.
            var ended: ?*Terminal = null;
            var it = h.terminals.valueIterator();
            while (it.next()) |tp| {
                const t = tp.*;
                if (t.ended.load(.acquire) == 0 or t.restarting) continue;
                t.link = ended;
                ended = t;
            }
            while (ended) |t| {
                ended = t.link;
                t.link = null;
                const why: rex.data.End = @fromBackingInt(@intCast(t.ended.load(.acquire) - 1));
                if (why == .block_closed) {
                    if (h.closeTerminalLocked(t)) {
                        t.link = dead;
                        dead = t;
                    }
                    continue;
                }
                if (now < t.restart_after_ms) continue;
                t.refs += 1;
                t.restarting = true;
                t.link = todo;
                todo = t;
            }
        }
        h.destroyList(dead);
        while (todo) |t| {
            todo = t.link;
            t.link = null;
            h.restartTerminal(t) catch |e| {
                log.debug("restart {s}: {t}", .{ t.block_id, e });
                h.mu.lockUncancelable(h.io);
                t.restarts += 1;
                t.restart_after_ms = std.Io.Clock.awake.now(h.io).toMilliseconds() + @min(@as(i64, 500) << @intCast(@min(t.restarts, 4)), 8000);
                h.mu.unlock(h.io);
            };
            h.mu.lockUncancelable(h.io);
            t.restarting = false;
            h.mu.unlock(h.io);
            h.unpin(t);
        }
    }

    /// Open a new stream for `t` (the caller holds a reference) and swap it in.
    fn restartTerminal(h: *Hub, t: *Terminal) !void {
        // After a Rex restart its session may not be attached yet (see `reattachAfterRestart`).
        try h.ensureAttached(t.session_id);
        // Taken now, so an end of the new stream that comes while it opens is not lost.
        const code = t.ended.swap(0, .acq_rel);
        const live = h.openStream(t.session_id, t.block_id, t) catch |e| {
            // Still to do; unless the new stream already said why it ended.
            _ = t.ended.cmpxchgStrong(0, code, .acq_rel, .acquire);
            return e;
        };
        h.mu.lockUncancelable(h.io);
        const current = t.registered;
        if (current) t.restarts = 0;
        h.mu.unlock(h.io);
        if (!current) {
            // Closed while the stream opened: nobody will look at it.
            live.data.close();
            live.mirror.deinit();
            return;
        }
        t.tmu.lockUncancelable(h.io);
        const old_m = t.mirror;
        const old_d = t.data;
        t.mirror = live.mirror;
        t.data = live.data;
        t.tmu.unlock(h.io);
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

    /// The harness's terminal, as a message names it.
    fn at(hs: Harness) protocol.Target {
        return .{ .session = hs.session_id, .block = hs.block_id };
    }

    fn init(cfg: Config) !Harness {
        return initAlloc(testing.allocator, cfg);
    }

    /// With the hub (and the streams it opens) on `gpa`.
    fn initAlloc(gpa: Allocator, cfg: Config) !Harness {
        const a = testing.allocator;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const made = try f.createSession("rweb-test-hub");
        const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const h = try Hub.open(gpa, testing.io, ctl, cfg);
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

test "hub: a terminal whose snapshot is slow does not hold up other viewers" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    hs.f.mu.lockUncancelable(testing.io);
    hs.f.hold_data_ms = 1500;
    hs.f.mu.unlock(testing.io);
    // One viewer opens the terminal and waits for its snapshot...
    var opening = try testing.io.concurrent(Harness.openViewer, .{hs});
    try testing.io.sleep(.fromMilliseconds(200), .awake);
    // ...while the hub keeps answering everyone else.
    const t0 = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    const tree = hs.hub.treeJson();
    if (tree) |t| testing.allocator.free(t);
    const other = try hs.hub.addViewer();
    hs.hub.removeViewer(other);
    const waited = std.Io.Clock.awake.now(testing.io).toMilliseconds() - t0;
    try testing.expect(waited < 500);
    const v = try opening.await(testing.io);
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.mu.lockUncancelable(testing.io);
    try testing.expectEqual(@as(u32, 1), hs.hub.terminals.count());
    hs.hub.mu.unlock(testing.io);
}

test "hub: two viewers opening one terminal at once end up sharing one" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    hs.f.mu.lockUncancelable(testing.io);
    hs.f.hold_data_ms = 300;
    hs.f.mu.unlock(testing.io);
    var fa = try testing.io.concurrent(Harness.openViewer, .{hs});
    var fb = try testing.io.concurrent(Harness.openViewer, .{hs});
    const a = try fa.await(testing.io);
    const b = try fb.await(testing.io);
    for ([_]*Viewer{ a, b }) |v| (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.mu.lockUncancelable(testing.io);
    try testing.expectEqual(@as(u32, 1), hs.hub.terminals.count());
    hs.hub.mu.unlock(testing.io);
    try hs.f.feed(hs.block_id, "hi-there");
    for ([_]*Viewer{ a, b }) |v| (try waitFrame(v, hasHi)).?.deinit(testing.allocator);
    hs.hub.removeViewer(a);
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
    hs.hub.handle(v, .{ .fit = .{ .cols = 100, .rows = 30, .at = hs.at() } });
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
    hs.hub.handle(a, .{ .fit = .{ .cols = 100, .rows = 30, .at = hs.at() } });
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
    const e = (try waitFrame(v, isError)).?;
    defer e.deinit(testing.allocator);
    // It names the terminal, and Rex's refusal is not something to retry.
    try testing.expect(std.mem.indexOf(u8, e.data, "\"session\":\"session:nope\"") != null);
    try testing.expect(std.mem.indexOf(u8, e.data, "\"block\":\"block:nope\"") != null);
    try testing.expect(std.mem.indexOf(u8, e.data, "\"transient\":false") != null);
}

fn isClosed(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"closed\"") != null;
}

fn terminalCount(hs: Harness) u32 {
    hs.hub.mu.lockUncancelable(testing.io);
    defer hs.hub.mu.unlock(testing.io);
    return hs.hub.terminals.count();
}

test "hub: event names are read from the payload, and from inside a session event" {
    const a = testing.allocator;
    const top = eventType(a, "{\"type\":\"event\",\"seq\":1,\"payload\":{\"type\":\"session_created\",\"payload\":{}}}").?;
    defer a.free(top);
    try testing.expectEqualStrings("session_created", top);
    const inner = eventType(a, "{\"type\":\"event\",\"seq\":2,\"payload\":{\"type\":\"session_event\",\"payload\":{\"session_id\":\"s\",\"event\":{\"type\":\"block_closed\",\"payload\":{}}}}}").?;
    defer a.free(inner);
    try testing.expectEqualStrings("block_closed", inner);
    // A name that only appears inside some text is not an event of that name.
    const other = eventType(a, "{\"type\":\"event\",\"seq\":3,\"payload\":{\"type\":\"session_label_changed\",\"payload\":{\"label\":\"block_closed\"}}}").?;
    defer a.free(other);
    try testing.expectEqualStrings("session_label_changed", other);
    try testing.expect(eventType(a, "{\"type\":\"event\",\"payload\":[]}") == null);
}

test "hub: state frames replace their queued copy; closed gets through a full reply queue" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    for (0..50) |_| v.push(.tree, "{\"t\":\"tree\"}");
    for (0..max_text_frames + 50) |_| v.pushText("{\"t\":\"pong\"}");
    v.push(.closed, "{\"t\":\"closed\"}");
    v.mu.lockUncancelable(testing.io);
    var trees: u32 = 0;
    var closed: u32 = 0;
    for (v.frames.items[v.head..]) |f| switch (f.kind) {
        .tree => trees += 1,
        .closed => closed += 1,
        else => {},
    };
    const replies = v.text_frames;
    v.mu.unlock(testing.io);
    try testing.expectEqual(@as(u32, 1), trees);
    try testing.expectEqual(@as(u32, 1), closed);
    try testing.expectEqual(@as(usize, max_text_frames), replies);
}

test "hub: opening again and again without reading keeps one redraw queued" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    for (0..Hub.max_heavy_per_second) |_| hs.hub.handle(v, .{ .open = .{ .session = hs.session_id, .block = hs.block_id } });
    v.mu.lockUncancelable(testing.io);
    var screens: u32 = 0;
    for (v.frames.items[v.head..]) |f| if (f.kind == .redraw or f.kind == .opened) {
        screens += 1;
    };
    v.mu.unlock(testing.io);
    try testing.expectEqual(@as(u32, 2), screens); // one `opened` and its redraw
}

test "hub: a closed block reaches its viewers while they type and leave, without a crash" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    for (0..5) |_| {
        const v = try hs.openViewer();
        (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
        const Typer = struct {
            fn run(h: *Hub, vw: *Viewer) void {
                for (0..200) |_| h.handle(vw, .{ .in = "x" });
            }
        };
        var typing = try testing.io.concurrent(Typer.run, .{ hs.hub, v });
        hs.f.endStreams(hs.block_id, 4000, "block closed");
        typing.await(testing.io);
        hs.hub.removeViewer(v);
    }
}

test "hub: a block that closes is told to its viewer, and the terminal goes" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.f.endStreams(hs.block_id, 4000, "block closed");
    (try waitFrame(v, isClosed)).?.deinit(testing.allocator);
    try testing.expectEqual(@as(u32, 0), terminalCount(hs));
    v.mu.lockUncancelable(testing.io);
    const t = v.term;
    v.mu.unlock(testing.io);
    try testing.expect(t == null);
}

test "hub: a slow stream restart does not hold up other viewers" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.f.mu.lockUncancelable(testing.io);
    hs.f.hold_data_ms = 1500;
    hs.f.mu.unlock(testing.io);
    hs.f.endStreams(hs.block_id, 1013, "data reconnect required");
    try testing.io.sleep(.fromMilliseconds(300), .awake); // the supervisor is now opening the new stream
    const t0 = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    const other = try hs.hub.addViewer();
    hs.hub.handle(other, .{ .tree = {} });
    hs.hub.removeViewer(other);
    try testing.expect(std.Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 500);
    (try waitFrame(v, isNotice)).?.deinit(testing.allocator);
}

test "hub: management calls racing the first open of new sessions do not deadlock" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    var ids: [6][]const u8 = undefined;
    var blocks: [6][]const u8 = undefined;
    for (&ids, &blocks) |*s, *b| {
        const made = try hs.f.createSession(null);
        s.* = made.session_id;
        b.* = made.block_id;
    }
    const Manager = struct {
        fn run(h: *Hub, vw: *Viewer, sid: []const u8) void {
            for (0..40) |i| {
                h.handle(vw, .{ .rename_session = .{ .session = sid, .label = if (i % 2 == 0) "rweb-test-a" else "rweb-test-b" } });
                vw.mu.lockUncancelable(testing.io);
                vw.heavy_window_start = 0; // not what this test is about
                vw.mu.unlock(testing.io);
            }
        }
    };
    const m = try hs.hub.addViewer();
    defer hs.hub.removeViewer(m);
    var managing = try testing.io.concurrent(Manager.run, .{ hs.hub, m, hs.session_id });
    const o = try hs.hub.addViewer();
    defer hs.hub.removeViewer(o);
    for (ids, blocks) |sid, bid| hs.hub.handle(o, .{ .open = .{ .session = sid, .block = bid } });
    managing.await(testing.io);
}

test "hub: an upload token is good only while its viewer stays in that view of that terminal" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    const gen = v.viewGen();
    try testing.expect(hs.hub.mayUpload(v.id, hs.session_id, hs.block_id, gen));
    try testing.expect(!hs.hub.mayUpload(v.id, hs.session_id, "block:other", gen));
    try testing.expect(!hs.hub.mayUpload(v.id + 100, hs.session_id, hs.block_id, gen));
    hs.hub.handle(v, .{ .observe = true });
    try testing.expect(!hs.hub.mayUpload(v.id, hs.session_id, hs.block_id, gen));
    hs.hub.handle(v, .{ .observe = false });
    hs.hub.handle(v, .{ .close_view = {} });
    try testing.expect(!hs.hub.mayUpload(v.id, hs.session_id, hs.block_id, gen));
    // Switching away and back to the same terminal is a new view: the earlier upload is still refused.
    hs.hub.handle(v, .{ .open = .{ .session = hs.session_id, .block = hs.block_id } });
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    try testing.expect(!hs.hub.mayUpload(v.id, hs.session_id, hs.block_id, gen));
    try testing.expect(hs.hub.mayUpload(v.id, hs.session_id, hs.block_id, v.viewGen()));
    const id = v.id;
    const gen2 = v.viewGen();
    hs.hub.removeViewer(v);
    try testing.expect(!hs.hub.mayUpload(id, hs.session_id, hs.block_id, gen2));
}

test "hub: an upload's path is pasted in the terminal's input order, and only while its viewer stays in that view" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    const gen = v.viewGen();
    // Between two pieces of typing it arrives between them: it went through the same queue.
    hs.hub.handle(v, .{ .in = "one-" });
    try testing.expect(hs.hub.pasteUpload(v.id, hs.session_id, hs.block_id, gen, "'/up/a.txt' "));
    hs.hub.handle(v, .{ .in = "-two" });
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(testing.allocator);
    var tries: u32 = 0;
    while (std.mem.indexOf(u8, seen.items, "one-'/up/a.txt' -two") == null and tries < 200) : (tries += 1) {
        const f = (try v.next(20)) orelse continue;
        defer f.deinit(testing.allocator);
        if (f.binary) try seen.appendSlice(testing.allocator, f.data);
    }
    try testing.expect(std.mem.indexOf(u8, seen.items, "one-'/up/a.txt' -two") != null);
    // Another terminal, another viewer, read-only, no terminal, away-and-back, gone: refused.
    try testing.expect(!hs.hub.pasteUpload(v.id, hs.session_id, "block:other", gen, "x"));
    try testing.expect(!hs.hub.pasteUpload(v.id + 100, hs.session_id, hs.block_id, gen, "x"));
    hs.hub.handle(v, .{ .observe = true });
    try testing.expect(!hs.hub.pasteUpload(v.id, hs.session_id, hs.block_id, gen, "x"));
    hs.hub.handle(v, .{ .observe = false });
    hs.hub.handle(v, .{ .close_view = {} });
    try testing.expect(!hs.hub.pasteUpload(v.id, hs.session_id, hs.block_id, gen, "x"));
    hs.hub.handle(v, .{ .open = .{ .session = hs.session_id, .block = hs.block_id } });
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    try testing.expect(!hs.hub.pasteUpload(v.id, hs.session_id, hs.block_id, gen, "x"));
    const id = v.id;
    const gen2 = v.viewGen();
    hs.hub.removeViewer(v);
    try testing.expect(!hs.hub.pasteUpload(id, hs.session_id, hs.block_id, gen2, "x"));
}

test "hub: an upload asked for as its terminal closes is refused, and the viewer is not left locked" {
    const hs = try Harness.init(.{ .transfer = .{ .enabled = true, .upload_dir = "/nonexistent" } });
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    // The viewer's terminal, pinned as a message handler pins it; then the view ends, as when the
    // terminal closes between the pin and the check.
    const term = hs.hub.pin(v).?;
    defer hs.hub.unpin(term);
    try testing.expect(v.viewGenOf(term) != null);
    hs.hub.handle(v, .{ .close_view = {} });
    try testing.expect(v.viewGenOf(term) == null);
    // The lock is free again: the viewer can be answered and asked.
    v.pushText("{\"t\":\"pong\"}");
    _ = v.viewGen();
    hs.hub.handle(v, .{ .ul = .{ .name = "a.txt", .size = 1, .at = hs.at() } });
    const f = (try waitFrame(v, isError)) orelse return error.TestUnexpectedResult;
    defer f.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, f.data, "no terminal open") != null);
}

test "hub: live output reuses a viewer's sent buffers, joins in place, and frees what it cannot keep" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    // What a new viewer is sent first (its mode, the tree) is not live output.
    while (try v.next(100)) |f| v.recycle(f);
    // A frame, sent and handed back: the next output goes into the same buffer.
    v.pushLive("first");
    const f1 = (try v.next(100)).?;
    try testing.expect(f1.pooled);
    try testing.expectEqualStrings("first", f1.data);
    const p1 = f1.data.ptr;
    v.recycle(f1);
    try testing.expectEqual(@as(usize, 1), v.live_pool_len);
    v.pushLive("second");
    // Output before the frame is sent joins it in place.
    v.pushLive(" and more");
    const f2 = (try v.next(100)).?;
    try testing.expectEqual(p1, f2.data.ptr);
    try testing.expectEqualStrings("second and more", f2.data);
    try testing.expectEqual(@as(usize, 0), v.live_pool_len);
    // Output larger than a live frame gets its own buffer, which is freed, not pooled.
    const huge = try testing.allocator.alloc(u8, max_live_frame + 1);
    defer testing.allocator.free(huge);
    @memset(huge, 'h');
    v.recycle(f2);
    v.pushLive(huge);
    const f3 = (try v.next(100)).?;
    try testing.expect(!f3.pooled);
    v.recycle(f3);
    try testing.expectEqual(@as(usize, 1), v.live_pool_len);
    // The pool holds at most `live_pool_max`; one more is freed.
    var held: [live_pool_max + 1]Frame = undefined;
    for (&held, 0..) |*h, i| {
        var b: [8]u8 = undefined;
        v.pushLive(try std.fmt.bufPrint(&b, "f{d}", .{i}));
        h.* = (try v.next(100)).?;
    }
    for (held) |h| v.recycle(h);
    try testing.expectEqual(@as(usize, live_pool_max), v.live_pool_len);
    // A closed viewer keeps nothing new; its pool is freed with it (the testing allocator checks).
    v.pushLive("last"); // takes a buffer from the pool
    const f4 = (try v.next(100)).?;
    const kept = v.live_pool_len;
    hs.hub.closeViewer(v);
    v.recycle(f4);
    try testing.expectEqual(kept, v.live_pool_len);
}

test "hub: opening, sizing and terminal actions count against the heavy-request limit" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    for (0..Hub.max_heavy_per_second + 2) |_| hs.hub.handle(v, .{ .fit = .{ .cols = 90, .rows = 30, .at = hs.at() } });
    var refused = false;
    var tries: u32 = 0;
    while (!refused and tries < 200) : (tries += 1) {
        const f = (try v.next(20)) orelse break;
        defer f.deinit(testing.allocator);
        refused = !f.binary and std.mem.indexOf(u8, f.data, "too many requests") != null;
    }
    try testing.expect(refused);
}

fn liveFrames(v: *Viewer) usize {
    v.mu.lockUncancelable(testing.io);
    defer v.mu.unlock(testing.io);
    var n: usize = 0;
    for (v.frames.items[v.head..]) |f| if (f.kind == .live) {
        n += 1;
    };
    return n;
}

fn hasText(comptime needle: []const u8) fn ([]const u8, bool) bool {
    return struct {
        fn f(d: []const u8, bin: bool) bool {
            return bin and std.mem.indexOf(u8, d, needle) != null;
        }
    }.f;
}

test "hub: an open refused by the rate limit also leaves the terminal being viewed" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    // Use up this second's work allowance, then ask to open again.
    for (0..Hub.max_heavy_per_second) |_| hs.hub.handle(v, .{ .redraw = {} });
    hs.hub.handle(v, .{ .open = .{ .session = hs.session_id, .block = hs.block_id } });
    v.mu.lockUncancelable(testing.io);
    const t = v.term;
    v.mu.unlock(testing.io);
    try testing.expect(t == null); // typing now goes nowhere, not into the old terminal
    var named = false;
    var tries: u32 = 0;
    while (!named and tries < 200) : (tries += 1) {
        const f = (try v.next(20)) orelse break;
        defer f.deinit(testing.allocator);
        named = !f.binary and std.mem.indexOf(u8, f.data, "\"for\":\"open\"") != null and std.mem.indexOf(u8, f.data, "\"rate\":true") != null;
    }
    try testing.expect(named);
    hs.hub.handle(v, .{ .in = "x" });
    (try waitFrame(v, isError)).?.deinit(testing.allocator); // "no terminal open"
}

test "hub: reads and work have separate allowances, so a tab switch's info polls do not block opening" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    for (0..Hub.max_reads_per_second) |_| try testing.expect(hs.hub.allowRate(v, .{ .tree = {} }));
    try testing.expect(!hs.hub.allowRate(v, .{ .tree = {} }));
    for (0..Hub.max_heavy_per_second) |_| try testing.expect(hs.hub.allowRate(v, .{ .fit = .{ .cols = 80, .rows = 24, .at = hs.at() } }));
    try testing.expect(!hs.hub.allowRate(v, .{ .fit = .{ .cols = 80, .rows = 24, .at = hs.at() } }));
    try testing.expect(hs.hub.allowRate(v, .{ .ping = {} }));
}

test "hub: work under a mirror's lock has a budget over all viewers" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    var vs: [8]*Viewer = undefined;
    for (&vs) |*v| v.* = try hs.hub.addViewer();
    defer for (vs) |v| hs.hub.removeViewer(v);
    var allowed: u32 = 0;
    for (0..Hub.max_heavy_per_second) |_| for (vs) |v| {
        if (hs.hub.allowRate(v, .{ .redraw = {} })) allowed += 1;
    };
    try testing.expectEqual(Hub.max_hub_work_per_second, allowed);
}

test "hub: output in tiny pieces joins one frame, and each frame costs its overhead" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    for (0..1000) |_| v.pushLive("\x1b");
    try testing.expectEqual(@as(usize, 1), liveFrames(v));
    v.mu.lockUncancelable(testing.io);
    const bytes = v.live_bytes;
    v.mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 1000 + live_frame_overhead), bytes);
    // A frame that is already sent is not added to: the next piece starts a new frame.
    while (try v.next(10)) |g| {
        const was_live = g.kind == .live;
        g.deinit(testing.allocator);
        if (was_live) break;
    }
    v.pushLive("y");
    try testing.expectEqual(@as(usize, 1), liveFrames(v));
}

test "hub: at most one theme is queued, the newest, whatever redraws and updates interleave" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    v.push(.theme, "{\"t\":\"theme\",\"n\":1}");
    v.mu.lockUncancelable(testing.io);
    // As a redraw's delivery does: drop the screen, then queue its own theme.
    v.dropScreenLocked();
    v.frames.append(testing.allocator, .{ .binary = false, .data = try testing.allocator.dupe(u8, "{\"t\":\"theme\",\"n\":2}"), .kind = .theme }) catch unreachable;
    // And a stray older copy behind it, as before this fix.
    v.frames.append(testing.allocator, .{ .binary = false, .data = try testing.allocator.dupe(u8, "{\"t\":\"theme\",\"n\":0}"), .kind = .theme }) catch unreachable;
    v.mu.unlock(testing.io);
    v.push(.theme, "{\"t\":\"theme\",\"n\":3}");
    v.mu.lockUncancelable(testing.io);
    defer v.mu.unlock(testing.io);
    var themes: u32 = 0;
    var last: []const u8 = "";
    for (v.frames.items[v.head..]) |f| if (f.kind == .theme) {
        themes += 1;
        last = f.data;
    };
    try testing.expectEqual(@as(u32, 1), themes);
    try testing.expectEqualStrings("{\"t\":\"theme\",\"n\":3}", last);
}

test "hub: a viewer that already has the current tree is not sent another copy" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isTree)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .tree = {} });
    v.mu.lockUncancelable(testing.io);
    const queued = v.frames.items.len - v.head;
    v.mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 0), queued);
    try hs.hub.refreshTree();
    (try waitFrame(v, isTree)).?.deinit(testing.allocator); // a new tree is sent once
}

test "hub: a second Copy before the first is sent is refused before any work" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .text = {} });
    hs.hub.handle(v, .{ .text = {} });
    v.mu.lockUncancelable(testing.io);
    var copies: u32 = 0;
    var busy = false;
    for (v.frames.items[v.head..]) |f| {
        if (f.kind == .copy) copies += 1;
        if (std.mem.indexOf(u8, f.data, "busy") != null) busy = true;
    }
    v.mu.unlock(testing.io);
    try testing.expectEqual(@as(u32, 1), copies);
    try testing.expect(busy);
}

test "hub: a multi-line paste needs confirming when the program has no bracketed paste; ESC never goes through" {
    const hs = try Harness.init(.{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    hs.hub.handle(v, .{ .paste = .{ .text = "one\ntwo", .at = hs.at() } });
    const asked = (try waitFrame(v, isError)).?;
    defer asked.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, asked.data, "confirm_multiline") != null);
    hs.hub.handle(v, .{ .paste = .{ .text = "line-a\x1b[201~line-b\xc2\x9b\nnext", .force = true, .at = hs.at() } });
    (try waitFrame(v, hasText("line-a[201~line-b\nnext"))).?.deinit(testing.allocator);
    // Once the program turns bracketed paste on, no confirmation is needed.
    try hs.f.feed(hs.block_id, "\x1b[?2004h");
    try testing.io.sleep(.fromMilliseconds(50), .awake);
    hs.hub.handle(v, .{ .paste = .{ .text = "three\nfour", .at = hs.at() } });
    (try waitFrame(v, hasText("three\nfour"))).?.deinit(testing.allocator);
}

test "hub: a paste, a resize, a terminal action, an upload or a file request for another terminal than the one open is refused" {
    const hs = try Harness.init(.{ .transfer = .{ .enabled = true, .upload_dir = "/nonexistent" } });
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    const other: protocol.Target = .{ .session = hs.session_id, .block = "block:other" };
    const elsewhere: protocol.Target = .{ .session = "session:other", .block = hs.block_id };
    // Asked of another terminal (the page switched while the clipboard or a question was pending).
    // (Few enough of the counted kinds to stay inside one second's allowance.)
    const msgs = [_]protocol.Msg{
        .{ .paste = .{ .text = "SECRET-CLIPBOARD", .force = true, .at = other } },
        .{ .paste = .{ .text = "SECRET-CLIPBOARD", .force = true, .at = elsewhere } },
        .{ .fit = .{ .cols = 91, .rows = 31, .at = other } },
        .{ .term_action = .{ .action = .reset, .at = elsewhere } },
        .{ .ul = .{ .name = "a.txt", .size = 1, .at = other } },
        .{ .ls = .{ .path = "/", .at = elsewhere } },
        .{ .dl = .{ .path = "/etc/hosts", .at = other } },
    };
    for (msgs) |m| {
        hs.hub.handle(v, m);
        const f = (try waitFrame(v, isError)) orelse return error.TestUnexpectedResult;
        defer f.deinit(testing.allocator);
        try testing.expect(std.mem.indexOf(u8, f.data, "\"code\":\"stale\"") != null);
    }
    // Naming none (a page an earlier rweb served): refused too, with what to do.
    hs.hub.handle(v, .{ .paste = .{ .text = "SECRET-CLIPBOARD" } });
    const reload = (try waitFrame(v, isError)) orelse return error.TestUnexpectedResult;
    defer reload.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, reload.data, "\"code\":\"reload\"") != null);
    // None of it reached the terminal, and no upload token was issued; the terminal that is open
    // takes the same paste when it is named.
    hs.hub.handle(v, .{ .paste = .{ .text = "for-this-one", .at = hs.at() } });
    var seen: std.ArrayList(u8) = .empty;
    defer seen.deinit(testing.allocator);
    var tries: u32 = 0;
    while (std.mem.indexOf(u8, seen.items, "for-this-one") == null and tries < 200) : (tries += 1) {
        const f = (try v.next(20)) orelse continue;
        defer f.deinit(testing.allocator);
        try testing.expect(std.mem.indexOf(u8, f.data, "\"t\":\"xfer\"") == null);
        if (f.binary) try seen.appendSlice(testing.allocator, f.data);
    }
    try testing.expect(std.mem.indexOf(u8, seen.items, "for-this-one") != null);
    try testing.expect(std.mem.indexOf(u8, seen.items, "SECRET-CLIPBOARD") == null);
}

test "hub: cleanPaste removes ESC and C1 and keeps every other character whole" {
    const a = testing.allocator;
    const out = try cleanPaste(a, "a\x1bb\xc2\x9bc\xc2\xa0e\u{00e9}\t\n");
    defer a.free(out);
    try testing.expectEqualStrings("abc\xc2\xa0e\u{00e9}\t\n", out);
    // Characters whose UTF-8 holds bytes 0x80 to 0x9f are ordinary text, not C1 controls.
    const text = "it\u{2019}s \u{201c}fine\u{201d} \u{2014} 5\u{20ac} Stra\u{00df}e \u{0410}\u{0411} \u{1f600} \u{65e5}\u{672c}";
    const kept = try cleanPaste(a, text);
    defer a.free(kept);
    try testing.expectEqualStrings(text, kept);
    // A bare 0x9b is not UTF-8: refused, never sent half-cleaned.
    try testing.expectError(error.InvalidUtf8, cleanPaste(a, "x\x9by"));
}

test "hub: a viewer that falls behind is redrawn at most once a second" {
    const hs = try Harness.init(.{ .max_live_bytes = 4096 });
    defer hs.deinit();
    const v = try hs.hub.addViewer();
    defer hs.hub.removeViewer(v);
    const before = std.Io.Clock.awake.now(testing.io).toMilliseconds();
    var big: [5000]u8 = @splat('x');
    v.pushLive(&big);
    v.mu.lockUncancelable(testing.io);
    defer v.mu.unlock(testing.io);
    try testing.expect(v.needs_redraw);
    try testing.expect(v.redraw_after_ms >= before + overflow_redraw_ms);
}

fn isMode(d: []const u8, bin: bool) bool {
    return !bin and std.mem.indexOf(u8, d, "\"t\":\"mode\"") != null;
}

test "hub: the mode frame says token mode only when the bridge signs in with a token" {
    {
        const hs = try Harness.init(.{ .token_mode = true });
        defer hs.deinit();
        const v = try hs.hub.addViewer();
        defer hs.hub.removeViewer(v);
        const m = (try waitFrame(v, isMode)).?;
        defer m.deinit(testing.allocator);
        try testing.expect(std.mem.indexOf(u8, m.data, "\"auth\":\"token\"") != null);
    }
    {
        const hs = try Harness.init(.{});
        defer hs.deinit();
        const v = try hs.hub.addViewer();
        defer hs.hub.removeViewer(v);
        const m = (try waitFrame(v, isMode)).?;
        defer m.deinit(testing.allocator);
        try testing.expect(std.mem.indexOf(u8, m.data, "\"auth\"") == null);
    }
}

// ---- running out of memory (F7) ----

/// An allocator that refuses every allocation while `fail` is set, and is safe to switch while the
/// hub's own tasks allocate (`std.testing.FailingAllocator` counts without atomics, and the hub's
/// supervisor runs beside the test). Frees always go through.
const Flaky = struct {
    inner: Allocator,
    fail: std.atomic.Value(bool) = .init(false),

    fn allocator(f: *Flaky) Allocator {
        return .{ .ptr = f, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (f.fail.load(.acquire)) return null;
        return f.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and f.fail.load(.acquire)) return false;
        return f.inner.rawResize(buf, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and f.fail.load(.acquire)) return null;
        return f.inner.rawRemap(buf, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const f: *Flaky = @ptrCast(@alignCast(ctx));
        f.inner.rawFree(buf, a, ra);
    }
};

fn viewedTerminal(v: *Viewer) ?*Terminal {
    v.mu.lockUncancelable(testing.io);
    defer v.mu.unlock(testing.io);
    return v.term;
}

/// The `closed` frame names the terminal it is about.
fn expectClosedFor(v: *Viewer, hs: Harness) !void {
    const f = (try waitFrame(v, isClosed)) orelse return error.NoClosedFrame;
    defer f.deinit(testing.allocator);
    try testing.expect(std.mem.indexOf(u8, f.data, hs.session_id) != null);
    try testing.expect(std.mem.indexOf(u8, f.data, hs.block_id) != null);
}

test "hub: every message type has a rate class; only typing, pastes and housekeeping are free" {
    const free = [_]Hub.MsgTag{ .close_view, .in, .key, .paste, .observe, .ping, .dbg };
    for (std.meta.tags(Hub.MsgTag)) |tag| {
        const is_free = std.mem.indexOfScalar(Hub.MsgTag, &free, tag) != null;
        try testing.expectEqual(is_free, Hub.classOf(tag) == .free);
        if (Hub.underMirrorLock(tag)) try testing.expect(Hub.classOf(tag) == .work);
    }
}

test "hub: a block that closes while no memory can be had is still told to its viewer, and freed" {
    var flaky: Flaky = .{ .inner = testing.allocator };
    const hs = try Harness.initAlloc(flaky.allocator(), .{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    const t = viewedTerminal(v).?;
    flaky.fail.store(true, .release);
    // What the stream's end does; the supervisor may get to it first, either way with no memory.
    t.ended.store(1 + @as(u8, @backingInt(rex.data.End.block_closed)), .release);
    hs.hub.restartEnded();
    flaky.fail.store(false, .release);
    try expectClosedFor(v, hs);
    try testing.expect(viewedTerminal(v) == null);
    try testing.expectEqual(@as(u32, 0), terminalCount(hs));
    // The terminal itself was destroyed: the leak check at the end of the test says so.
}

test "hub: a terminal gone from the tree is closed and told without memory" {
    var flaky: Flaky = .{ .inner = testing.allocator };
    const hs = try Harness.initAlloc(flaky.allocator(), .{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    const dead = blk: {
        hs.hub.mu.lockUncancelable(testing.io);
        defer hs.hub.mu.unlock(testing.io);
        // As if the last tree had neither the block nor its session.
        hs.hub.known.?.keys.clearRetainingCapacity();
        flaky.fail.store(true, .release);
        defer flaky.fail.store(false, .release);
        break :blk hs.hub.closeGoneLocked();
    };
    try testing.expect(dead != null);
    hs.hub.destroyList(dead);
    try expectClosedFor(v, hs);
    try testing.expectEqual(@as(u32, 0), terminalCount(hs));
}

test "hub: a viewer that cannot be pointed at a terminal is left as it was" {
    var flaky: Flaky = .{ .inner = testing.allocator };
    const hs = try Harness.initAlloc(flaky.allocator(), .{});
    defer hs.deinit();
    const a = try hs.openViewer();
    defer hs.hub.removeViewer(a);
    (try waitFrame(a, isRedraw)).?.deinit(testing.allocator);
    const b = try hs.hub.addViewer();
    defer hs.hub.removeViewer(b);
    const t = viewedTerminal(a).?;
    {
        hs.hub.mu.lockUncancelable(testing.io);
        defer hs.hub.mu.unlock(testing.io);
        const refs = t.refs;
        flaky.fail.store(true, .release);
        defer flaky.fail.store(false, .release);
        try testing.expectError(error.OutOfMemory, hs.hub.claimLocked(b, t));
        try testing.expectEqual(refs, t.refs);
    }
    try testing.expect(viewedTerminal(b) == null);
    // A viewer that cannot be sent its mode frame first is not added at all.
    flaky.fail.store(true, .release);
    const added = hs.hub.addViewer();
    flaky.fail.store(false, .release);
    try testing.expectError(error.OutOfMemory, added);
    hs.hub.mu.lockUncancelable(testing.io);
    const viewers = hs.hub.viewers.items.len;
    hs.hub.mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 2), viewers);
}

test "hub: re-attaching after a Rex restart with no memory forgets the sessions, and the terminal comes back" {
    var flaky: Flaky = .{ .inner = testing.allocator };
    const hs = try Harness.initAlloc(flaky.allocator(), .{});
    defer hs.deinit();
    const v = try hs.openViewer();
    defer hs.hub.removeViewer(v);
    (try waitFrame(v, isRedraw)).?.deinit(testing.allocator);
    flaky.fail.store(true, .release);
    hs.hub.reattachAfterRestart();
    flaky.fail.store(false, .release);
    // The stream is rebuilt, its session attached again on the way (restarts back off: wait a while).
    var told = false;
    var tries: u32 = 0;
    while (!told and tries < 200) : (tries += 1) {
        const f = (try v.next(50)) orelse continue;
        defer f.deinit(testing.allocator);
        told = isNotice(f.data, f.binary);
    }
    try testing.expect(told);
    hs.hub.mu.lockUncancelable(testing.io);
    const attached = hs.hub.attached.contains(hs.session_id);
    hs.hub.mu.unlock(testing.io);
    try testing.expect(attached);
}

fn cleanAndFree(a: Allocator, text: []const u8) !void {
    a.free(try cleanPaste(a, text));
}

test "hub: cleanPaste fails cleanly at every allocation" {
    try testing.checkAllAllocationFailures(testing.allocator, cleanAndFree, .{"a\x1bb\xc2\x9bc it\u{2019}s \u{1f600}\n"});
}

/// Fails every allocation from the `fail_from`th on (counted from 0), like `std.testing.FailingAllocator`,
/// but safe to share with the hub's own tasks (atomic counters). Frees and shrinking always go through.
const FailFrom = struct {
    inner: Allocator,
    fail_from: usize,
    count: std.atomic.Value(usize) = .init(0),
    induced: std.atomic.Value(bool) = .init(false),

    fn allocator(f: *FailFrom) Allocator {
        return .{ .ptr = f, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn refuse(f: *FailFrom) bool {
        if (f.count.fetchAdd(1, .monotonic) < f.fail_from) return false;
        f.induced.store(true, .monotonic);
        return true;
    }
    fn alloc(ctx: *anyopaque, len: usize, a: std.mem.Alignment, ra: usize) ?[*]u8 {
        const f: *FailFrom = @ptrCast(@alignCast(ctx));
        if (f.refuse()) return null;
        return f.inner.rawAlloc(len, a, ra);
    }
    fn resize(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const f: *FailFrom = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and f.refuse()) return false;
        return f.inner.rawResize(buf, a, new_len, ra);
    }
    fn remap(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const f: *FailFrom = @ptrCast(@alignCast(ctx));
        if (new_len > buf.len and f.refuse()) return null;
        return f.inner.rawRemap(buf, a, new_len, ra);
    }
    fn free(ctx: *anyopaque, buf: []u8, a: std.mem.Alignment, ra: usize) void {
        const f: *FailFrom = @ptrCast(@alignCast(ctx));
        f.inner.rawFree(buf, a, ra);
    }
};

/// One of every browser message, as `handle` gets it (targets filled in by `oneOfEach`).
fn oneOfEach(sid: []const u8, bid: []const u8) [@typeInfo(protocol.Msg).@"union".field_names.len]protocol.Msg {
    const at: protocol.Target = .{ .session = sid, .block = bid };
    return .{
        .tree,
        .{ .open = .{ .session = sid, .block = bid } },
        .{ .in = "echo typed\r" },
        .{ .key = "{\"key\":\"enter\",\"action\":\"press\"}" },
        .{ .paste = .{ .text = "pasted", .at = at } },
        .{ .fit = .{ .cols = 90, .rows = 30, .at = at } },
        .redraw,
        .more_history,
        .text,
        .info,
        .{ .ls = .{ .path = "", .at = at } },
        .{ .dl = .{ .path = "/nonexistent/file", .at = at } },
        .{ .ul = .{ .name = "a.txt", .size = 3, .at = at } },
        .clip,
        .{ .term_action = .{ .action = .clear, .at = at } },
        .{ .observe = true },
        .{ .new_session = "rweb-test-oom" },
        .{ .new_terminal = sid },
        .{ .rename_session = .{ .session = sid, .label = "renamed" } },
        .{ .rename_block = .{ .session = sid, .block = bid, .label = "renamed" } },
        .{ .close_block = .{ .session = "session:none", .block = "block:none" } },
        .{ .destroy_session = "session:none" },
        .ping,
        .dbg,
        .close_view,
    };
}

comptime {
    // Every message type is in `oneOfEach`: a new one does not compile until it is added.
    var seen: std.EnumSet(std.meta.Tag(protocol.Msg)) = .init(.{});
    for (oneOfEach("s", "b")) |m| seen.insert(std.meta.activeTag(m));
    if (seen.count() != @typeInfo(protocol.Msg).@"union".field_names.len) @compileError("hub: oneOfEach needs every message type");
}

/// A hub on `a`, a viewer, one of every message (observe turned off again before the ones that
/// write), then everything closed. Anything may fail for want of memory; nothing may leak or crash.
fn hubRound(a: Allocator, f: *fake.Fake, ctl: *Control, sid: []const u8, bid: []const u8) void {
    const h = Hub.open(a, testing.io, ctl, .{ .transfer = .{ .enabled = true, .upload_dir = "/nonexistent" } }) catch return;
    defer h.close();
    _ = f;
    const v = h.addViewer() catch return;
    defer h.removeViewer(v);
    for (oneOfEach(sid, bid)) |m| {
        h.handle(v, m);
        if (m == .observe) h.handle(v, .{ .observe = false });
    }
    // What was queued for the viewer is freed with it (`removeViewer`); take a few to exercise that too.
    var n: u32 = 0;
    while (n < 8) : (n += 1) {
        const fr = (v.next(20) catch break) orelse break;
        v.recycle(fr);
    }
}

test "hub: a hub and every message type, with allocations failing from each point on, leak nothing" {
    const fk = try fake.Fake.start(testing.allocator, testing.io);
    defer fk.deinit();
    const made = try fk.createSession("rweb-test-oom");
    const ctl = try Control.open(testing.allocator, testing.io, .{ .socket_path = fk.path });
    defer ctl.close();
    // How many allocations a whole round makes, then a round failing from each of them on (every
    // `stride`th, to keep the test's time bounded; the hub's tasks make the count vary a little).
    var full: FailFrom = .{ .inner = testing.allocator, .fail_from = std.math.maxInt(usize) };
    hubRound(full.allocator(), fk, ctl, made.session_id, made.block_id);
    const total = full.count.load(.monotonic);
    try testing.expect(total > 50);
    const stride = @max(1, total / 150);
    var rounds: usize = 0;
    var i: usize = 0;
    while (i < total) : (i += stride) {
        var fa: FailFrom = .{ .inner = testing.allocator, .fail_from = i };
        hubRound(fa.allocator(), fk, ctl, made.session_id, made.block_id);
        rounds += 1;
    }
    std.debug.print("hub out-of-memory rounds: {d} (a whole round makes {d} allocations)\n", .{ rounds, total });
}
