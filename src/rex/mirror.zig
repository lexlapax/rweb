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
//!
//! A renderer, not a full terminal: it keeps what a viewer is shown and turns off what rweb
//! never shows, so a program's output cannot make it hold more than this per terminal
//! (pinned Ghostty, checked against its source):
//!
//! - Snapshot: at most `max_snapshot` bytes (256 MiB) while it arrives, with a continuation of
//!   at most 1 MiB, and at most `max_resize_cells` cells (and `max_resize_axis` a side), checked
//!   from its first record before it is decoded and again after.
//! - Scrollback: at most `max_scrollback_lines` (10,000) rows and `max_scrollback_bytes`
//!   (32 MiB) of pages, or Rex's own limits where they are smaller (Ghostty keeps at least one
//!   page of history, and prunes whole pages, so the effective bound is the larger of these and
//!   one page). The alternate screen has no scrollback.
//! - Kitty graphics: off. The snapshot is decoded with an image storage limit of 0 (Ghostty's
//!   "off": images in it are dropped and live commands do nothing), and the APC handler ignores
//!   kitty graphics and glyph protocol commands, so their bytes are not even buffered.
//! - Other APC strings: dropped as they arrive (Ghostty's default, `unknown_max_bytes` 0).
//! - OSC strings: at most `max_control_string` (64 KiB) for those Ghostty buffers on the heap
//!   (clipboard OSC 52 and the like; Ghostty's default is 8 MiB); every other OSC uses a fixed
//!   2 KiB buffer, and unknown ones are dropped. Kitty clipboard writes (OSC 5522) are refused
//!   without buffering, as the mirror has no clipboard. Kitty drag and drop (OSC 72) keeps at
//!   most two MIME lists of 1 MiB each (Ghostty's fixed limit).
//! - DCS strings (XTGETTCAP, tmux control mode lines): at most `max_control_string` (Ghostty's
//!   default is 1 MiB); DECRQSS has a small fixed buffer.
//! - A string that passes its bound is dropped, and the parser returns to ordinary output at its
//!   terminator (or a CAN or SUB). The bytes still reach observers unchanged.
//! - Redraw: at most `max_redraw_bytes` (16 MiB) per call (`redraw_budget`); Copy text: at most
//!   8 times its `max_bytes` formatted (see `plainTextAllCells`).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ghostty_vt = @import("ghostty-vt");
const rex1 = @import("rex1.zig");
const data = @import("data.zig");
const wire = @import("wire.zig");

const log = std.log.scoped(.rex_mirror);

/// Biggest snapshot accepted.
pub const max_snapshot = 256 * 1024 * 1024;

/// Largest terminal side, and most cells, a Rex resize may ask for; any other resize is ignored.
/// A snapshot of a larger terminal fails as `error.BadSnapshot`.
pub const max_resize_axis: u32 = 4096;
pub const max_resize_cells: u32 = 1_048_576;

/// Most scrollback a mirror keeps, whatever Rex allows (see the top of this file).
pub const max_scrollback_lines: usize = 10_000;
pub const max_scrollback_bytes: usize = 32 * 1024 * 1024;

/// Most bytes of one OSC or DCS string the VT parser buffers.
pub const max_control_string: usize = 64 * 1024;

/// Most bytes one redraw may take (see `Mirror.redrawLockedInfo`).
pub const max_redraw_bytes: usize = 16 * 1024 * 1024;

/// Copy text is formatted into at most this many times its `max_bytes`.
pub const copy_format_factor: usize = 8;

pub fn resizeAllowed(cols: u32, rows: u32) bool {
    if (cols < 1 or rows < 1 or cols > max_resize_axis or rows > max_resize_axis) return false;
    const cells = std.math.mul(u32, cols, rows) catch return false;
    return cells <= max_resize_cells;
}

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
    /// The data stream ended (see `data.End`); no more output will arrive.
    ended: ?*const fn (ctx: *anyopaque, why: data.End) void = null,
};

pub const Mirror = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    observer: ?Observer = null,

    status: Status = .waiting_for_snapshot,
    snap: std.ArrayList(u8) = .empty,
    /// Where the next snapshot record header starts in `snap` (0: the envelope is not checked yet).
    snap_scan: usize = 0,
    term: ghostty_vt.Terminal = undefined,
    vt: ghostty_vt.TerminalStream = undefined,
    /// `term` and `vt` exist (from the snapshot on), whatever `status` says since; `deinit`
    /// frees them. The VT stream holds OSC, APC and DCS buffers a program can fill.
    term_made: bool = false,
    /// A resize outside the limits was logged (once per mirror).
    logged_bad_resize: bool = false,
    /// Set once the channel nonce is known.
    splitter: ?rex1.Splitter = null,
    theme: ?Theme = null,
    /// Owner of the block when it was last sized, if any.
    owner: ?[]u8 = null,
    exit_code: ?i64 = null,
    /// Goes up on every change a viewer could see.
    version: u64 = 0,
    snapshot_bytes: usize = 0,
    /// Why the stream ended, once it has (see `data.End`).
    ended: ?data.End = null,
    /// Most bytes one redraw may take; tests lower it.
    redraw_budget: usize = max_redraw_bytes,

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
        // The new splitter first: if it cannot be made, the old one is still whole (and freed once,
        // with the mirror), rather than freed here and freed again later.
        const fresh = try rex1.Splitter.init(m.gpa, nonce);
        if (m.splitter) |*s| s.deinit();
        m.splitter = fresh;
    }

    pub fn deinit(m: *Mirror) void {
        if (m.term_made) {
            m.vt.deinit();
            m.term.deinit(m.gpa);
        }
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
        m.feed(bytes) catch |e| m.fail(e);
    }

    /// The mirror cannot follow the stream any more (a bad snapshot, or out of memory while live):
    /// stop applying bytes, and report it once, as the end of the stream (`mirror_failed`), so its
    /// owner can start a new one. Later bytes are dropped without a word.
    fn fail(m: *Mirror, e: anyerror) void {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status == .failed) return;
        m.status = .failed;
        log.warn("mirror failed, so its stream ends: {t}", .{e});
        m.ended = .mirror_failed;
        if (m.observer) |o| if (o.ended) |f| f(o.ctx, .mirror_failed);
    }

    fn sinkWelcome(ctx: *anyopaque, nonce: u64) void {
        const m: *Mirror = @ptrCast(@alignCast(ctx));
        // As for bytes: a mirror that cannot take the stream's nonce cannot follow it, so it ends
        // the stream now (its owner starts a new one) rather than fail on the first bytes.
        m.setNonce(nonce) catch |e| m.fail(e);
    }

    fn sinkEnded(ctx: *anyopaque, why: data.End) void {
        const m: *Mirror = @ptrCast(@alignCast(ctx));
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        m.ended = why;
        if (m.observer) |o| if (o.ended) |f| f(o.ctx, why);
    }

    pub fn endReason(m: *Mirror) ?data.End {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        return m.ended;
    }

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
        // Every byte so far belongs to a record that ends within the limit (checked below), so the
        // buffer can pass it only by the trailing bytes of one chunk.
        if (m.snap.items.len > max_snapshot) return error.SnapshotTooLarge;
        try m.snap.appendSlice(m.gpa, bytes);
        // Decode once, when the whole snapshot is here: finding its end from the record headers is
        // cheap, while decoding the growing buffer after every chunk would cost quadratic time.
        const end = (try snapshotEnd(m.snap.items, &m.snap_scan, max_snapshot)) orelse {
            // A terminal larger than a resize may make is refused from its first record, before
            // the rest arrives and long before anything is allocated for it.
            if (wire.snapshotSize(m.snap.items)) |sz| if (!resizeAllowed(sz.cols, sz.rows)) return error.BadSnapshot;
            return;
        };
        if (wire.snapshotSize(m.snap.items)) |sz| if (!resizeAllowed(sz.cols, sz.rows)) return error.BadSnapshot;
        var reader: Io.Reader = .fixed(m.snap.items[0..end]);
        var decoded = ghostty_vt.snapshot.decode(m.gpa, m.io, &reader, .{
            .max_continuation_bytes = 1 << 20,
            // Off: images in the snapshot are dropped, and live kitty commands do nothing.
            .kitty_image_storage_limit = 0,
        }) catch |e| switch (e) {
            error.EndOfStream => return error.BadSnapshot, // its own framing said it was complete
            else => return e,
        };
        defer decoded.deinit(m.gpa);
        const used = reader.seek;
        if (used != end) return error.BadSnapshot;
        // The decoder's own word on the size, whatever the first record looked like.
        const dt = &decoded.terminal.?;
        if (!resizeAllowed(dt.cols, dt.rows)) return error.BadSnapshot;
        m.term = decoded.toOwned();
        capScrollback(&m.term);
        m.vt = m.term.vtStream();
        limitStream(&m.vt);
        m.term_made = true;
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

    /// See `wire.snapshotEnd`.
    pub const snapshotEnd = wire.snapshotEnd;

    /// Keep at most `max_scrollback_lines` and `max_scrollback_bytes` of scrollback, or Rex's own
    /// limits (from the snapshot) where they are smaller.
    fn capScrollback(t: *ghostty_vt.Terminal) void {
        const primary = t.screens.get(.primary) orelse return;
        const limits = &primary.pages.limits; // Rex's explicit limits; maxInt for none
        t.setScrollbackMaxBytes(@min(limits.bytes.explicit, max_scrollback_bytes));
        t.setScrollbackMaxLines(@min(limits.lines.explicit, max_scrollback_lines));
    }

    /// Turn off what the mirror never shows, and bound the strings the parser buffers (see the
    /// top of this file). Before any byte reaches the stream, the snapshot's continuation included.
    fn limitStream(vt: *ghostty_vt.TerminalStream) void {
        vt.handler.apc_handler.enable(.kitty, false);
        vt.handler.apc_handler.enable(.glyph, false);
        vt.handler.apc_handler.unknown_max_bytes = 0;
        vt.parser.osc_parser.max_allocating_bytes = max_control_string;
        vt.parser.osc_parser.unknown_max_bytes = 0;
        vt.handler.dcs_handler.max_bytes = max_control_string;
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
                if (!resizeAllowed(r.cols, r.rows)) {
                    if (!m.logged_bad_resize) log.warn("ignoring a resize to {d}x{d} (limits: 1 to {d} per side, {d} cells)", .{ r.cols, r.rows, max_resize_axis, max_resize_cells });
                    m.logged_bad_resize = true;
                    return;
                }
                // Everything that can fail first, then the swap: a failure leaves the old owner.
                const new_owner = if (r.owner) |ow| try m.gpa.dupe(u8, ow) else null;
                errdefer if (new_owner) |o| m.gpa.free(o);
                try m.term.resize(m.gpa, .{ .cols = r.cols, .rows = r.rows });
                if (m.owner) |old| m.gpa.free(old);
                m.owner = new_owner;
                m.version += 1;
                if (m.observer) |o| if (o.resized) |f| f(o.ctx, r.cols, r.rows);
            },
            .theme => |t| {
                var arena = std.heap.ArenaAllocator.init(m.gpa);
                errdefer arena.deinit();
                const a = arena.allocator();
                // Allocate everything first, then build the struct: a literal that copies `arena`
                // before its other fields allocate would keep a stale copy and leak the rest.
                const palette = try a.alloc([]const u8, t.palette.len);
                for (t.palette, palette) |src, *dst| dst.* = try a.dupe(u8, src);
                const foreground = if (t.foreground) |s| try a.dupe(u8, s) else null;
                const background = if (t.background) |s| try a.dupe(u8, s) else null;
                const cursor = if (t.cursor) |s| try a.dupe(u8, s) else null;
                const scheme = if (t.scheme) |s| try a.dupe(u8, s) else null;
                const new: Theme = .{
                    .arena = arena,
                    .foreground = foreground,
                    .background = background,
                    .cursor = cursor,
                    .scheme = scheme,
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

    /// Whether the program has bracketed paste on (DEC mode 2004), so a paste reaches it marked
    /// as one rather than as typed lines. False before the snapshot.
    pub fn bracketedPaste(m: *Mirror) bool {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (!m.term_made) return false;
        return m.term.modes.get(.bracketed_paste);
    }

    pub fn getStatus(m: *Mirror) Status {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        return m.status;
    }

    /// Keep trailing blank rows so the viewer's screen top matches the mirror's.
    const redraw_opts: ghostty_vt.formatter.Options = .{ .emit = .vt, .trim = false };

    pub const RedrawOptions = struct {
        /// Include at most this many rows of scrollback above the visible screen; null for all.
        history_lines: ?u32 = null,
        /// And at most this many cells of scrollback (rows times the columns at the time of the
        /// redraw, read under the mirror's lock); null for no cap in cells.
        history_cells: ?u64 = null,
    };

    /// A VT byte stream that recreates the mirror's state on a fresh terminal. Caller frees.
    pub fn redraw(m: *Mirror, gpa: Allocator) ![]u8 {
        return m.redrawWith(gpa, .{});
    }

    pub fn redrawWith(m: *Mirror, gpa: Allocator, opts: RedrawOptions) ![]u8 {
        var out: ?[]u8 = null;
        const Cap = struct {
            gpa: Allocator,
            out: *?[]u8,
            fn take(ctx: *anyopaque, bytes: []u8) !void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                c.out.* = bytes;
            }
        };
        var cap: Cap = .{ .gpa = gpa, .out = &out };
        try m.redrawLocked(gpa, opts, &cap, Cap.take);
        return out.?;
    }

    /// What a redraw carried.
    pub const Redrawn = struct {
        /// Rows of scrollback above the visible primary screen it carries.
        history_rows: u32,
        /// Fewer than `opts` asked for (and the history had): the byte budget did not hold them.
        history_cut: bool,
    };

    /// Build a redraw and hand it to `deliver` while the mirror is still locked, so nothing the
    /// mirror receives afterwards can be missed or repeated by whoever switches to it (live
    /// output reaches observers under the same lock). `deliver` must not call into the mirror. It
    /// takes the redraw, made with `gpa`: it owns it from then on, whether it succeeds or not.
    /// As `redrawLockedInfo`, without saying how much history it carried.
    pub fn redrawLocked(
        m: *Mirror,
        gpa: Allocator,
        opts: RedrawOptions,
        ctx: *anyopaque,
        deliver: *const fn (ctx: *anyopaque, bytes: []u8) anyerror!void,
    ) !void {
        _ = try m.redrawLockedInfo(gpa, opts, ctx, deliver);
    }

    /// As `redrawLocked`, saying how many history rows the redraw carried. A redraw is at most
    /// `redraw_budget` bytes: one that would pass it is built again with half the history rows,
    /// down to none (the visible screen alone); if even that does not fit, `error.RedrawTooLarge`
    /// and nothing is delivered.
    pub fn redrawLockedInfo(
        m: *Mirror,
        gpa: Allocator,
        opts: RedrawOptions,
        ctx: *anyopaque,
        deliver: *const fn (ctx: *anyopaque, bytes: []u8) anyerror!void,
    ) !Redrawn {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return error.NotLive;
        const have = m.historyRowsLocked();
        const wanted: u32 = if (historyCap(opts, m.term.cols)) |c| @min(c, have) else have;
        var rows = wanted;
        while (true) {
            var out: Budget = .init(gpa, m.redraw_budget);
            defer out.deinit();
            m.formatRedraw(&out.writer, rows) catch |e| {
                if (out.oom) return error.OutOfMemory;
                if (!out.over) return e;
                if (rows == 0) return error.RedrawTooLarge;
                rows /= 2;
                continue;
            };
            // Handed over, not copied (a redraw can be megabytes).
            try deliver(ctx, try out.toOwnedSlice());
            return .{ .history_rows = rows, .history_cut = rows < wanted };
        }
    }

    /// The redraw with `rows` history rows above the visible primary screen, into `w` (flushed).
    /// Under `mu`.
    fn formatRedraw(m: *Mirror, w: *Io.Writer, rows: u32) Io.Writer.Error!void {
        try w.writeAll("\x1bc"); // RIS: start the viewer from a clean terminal
        // The formatter draws only the active screen. While a full-screen program has the
        // alternate screen, draw the primary screen first; the modes that follow switch the
        // viewer to the alternate screen (saving this cursor).
        if (m.term.screens.active_key == .alternate) {
            if (m.term.screens.get(.primary)) |primary| {
                var pf: ghostty_vt.formatter.ScreenFormatter = .init(primary, redraw_opts);
                pf.extra = .all;
                pf.content = .{ .selection = historySelection(primary, rows) };
                try pf.format(w);
            }
        }
        var f: ghostty_vt.formatter.TerminalFormatter = .init(&m.term, redraw_opts);
        f.extra = .all;
        if (m.term.screens.active_key == .primary) f.content = .{ .selection = historySelection(m.term.screens.active, rows) };
        try f.format(w);
        try w.flush();
    }

    /// The visible rows of `screen` and `n` rows of history above them (all there is, if fewer).
    fn historySelection(screen: *ghostty_vt.Screen, n: u32) ?ghostty_vt.Selection {
        const top = screen.pages.getTopLeft(.active);
        const start = top.up(n) orelse screen.pages.getTopLeft(.screen);
        const end = screen.pages.getBottomRight(.screen) orelse return null;
        return ghostty_vt.Selection.init(start, end, false);
    }

    /// The history rows `opts` allows at `cols` columns; null for no cap.
    fn historyCap(opts: RedrawOptions, cols: u16) ?u32 {
        const by_cells: ?u32 = if (opts.history_cells) |cells| @intCast(@min(cells / @max(cols, 1), std.math.maxInt(u32))) else null;
        if (opts.history_lines) |lines| return if (by_cells) |c| @min(lines, c) else lines;
        return by_cells;
    }

    /// Rows of scrollback above the visible screen on the primary screen.
    pub fn historyRows(m: *Mirror) usize {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return 0;
        return m.historyRowsLocked();
    }

    fn historyRowsLocked(m: *Mirror) u32 {
        const primary = m.term.screens.get(.primary) orelse return 0;
        const total = primary.pages.total_rows;
        return @intCast(@min(if (total > m.term.rows) total - m.term.rows else 0, std.math.maxInt(u32)));
    }

    pub const PlainAll = struct { text: []u8, truncated: bool };

    /// The screen and scrollback as plain text, soft-wrapped lines joined, trailing spaces
    /// trimmed. Only the last `max_rows` rows are formatted at all (from the first line that starts
    /// within them), and of that text at most `max_bytes` are kept (the end, cut at a line start).
    /// `truncated` says either cut something. Caller frees `text`.
    pub fn plainTextAll(m: *Mirror, gpa: Allocator, max_bytes: usize, max_rows: u32) !PlainAll {
        return m.plainTextAllCells(gpa, max_bytes, max_rows, null);
    }

    /// As `plainTextAll`, also formatting at most `max_cells` cells: rows times the columns at
    /// the time of the call, read under the mirror's lock (so a resize between asking for the
    /// size and this call cannot make the cap wrong). Null for no cap in cells. At most
    /// `copy_format_factor` times `max_bytes` are formatted: rows whose text would pass that are
    /// formatted again from half as many rows (the last ones), down to none.
    pub fn plainTextAllCells(m: *Mirror, gpa: Allocator, max_bytes: usize, max_rows_in: u32, max_cells: ?u64) !PlainAll {
        m.mu.lockUncancelable(m.io);
        defer m.mu.unlock(m.io);
        if (m.status != .live) return error.NotLive;
        var max_rows: u32 = if (max_cells) |cells| @intCast(@min(max_rows_in, cells / @max(m.term.cols, 1))) else max_rows_in;
        const screen = m.term.screens.active;
        var rows_cut = screen.pages.total_rows > max_rows;
        if (!rows_cut) max_rows = @intCast(screen.pages.total_rows); // so halving it cuts at once
        const budget = std.math.mul(usize, max_bytes, copy_format_factor) catch std.math.maxInt(usize);
        while (true) {
            if (max_rows == 0) return .{ .text = try gpa.alloc(u8, 0), .truncated = rows_cut };
            var out: Budget = .init(gpa, budget);
            defer out.deinit();
            var f: ghostty_vt.formatter.TerminalFormatter = .init(&m.term, .{ .emit = .plain, .unwrap = true, .trim = true });
            if (rows_cut) f.content = .{ .selection = lastRows(screen, max_rows) };
            formatAll(&f, &out.writer) catch |e| {
                if (out.oom) return error.OutOfMemory;
                if (!out.over) return e;
                max_rows /= 2;
                rows_cut = true;
                continue;
            };
            const all = out.written();
            if (all.len <= max_bytes) return .{ .text = try out.toOwnedSlice(), .truncated = rows_cut };
            var start = all.len - max_bytes;
            while (start < all.len and all[start - 1] != '\n') start += 1; // begin at a line start
            return .{ .text = try gpa.dupe(u8, all[start..]), .truncated = true };
        }
    }

    fn formatAll(f: *ghostty_vt.formatter.TerminalFormatter, w: *Io.Writer) Io.Writer.Error!void {
        try f.format(w);
        try w.flush();
    }

    /// The last `n` (at least 1) rows of `screen`, starting at a line start: a row that continues a
    /// soft-wrapped line from above the cut is skipped. Null if the screen has no more than `n` rows.
    fn lastRows(screen: *ghostty_vt.Screen, n: u32) ?ghostty_vt.Selection {
        const end = screen.pages.getBottomRight(.screen) orelse return null;
        var bottom_left = end;
        bottom_left.x = 0;
        var start = bottom_left.up(n - 1) orelse return null;
        while (start.rowAndCell().row.wrap_continuation) start = start.down(1) orelse break;
        return ghostty_vt.Selection.init(start, end, false);
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

/// A writer into memory that fails (`error.WriteFailed`, with `over` set) rather than hold more
/// than `limit` bytes, so formatting cheap input into expensive output stops at a budget.
const Budget = struct {
    gpa: Allocator,
    list: std.ArrayList(u8) = .empty,
    limit: usize,
    /// A write failed because it would pass `limit`.
    over: bool = false,
    /// A write failed for want of memory.
    oom: bool = false,
    writer: Io.Writer,

    fn init(gpa: Allocator, limit: usize) Budget {
        return .{ .gpa = gpa, .limit = limit, .writer = .{ .vtable = &.{ .drain = drain }, .buffer = &.{} } };
    }

    fn deinit(b: *Budget) void {
        b.list.deinit(b.gpa);
    }

    /// What was written. Valid until `deinit` or `toOwnedSlice`.
    fn written(b: *Budget) []const u8 {
        return b.list.items;
    }

    fn toOwnedSlice(b: *Budget) Allocator.Error![]u8 {
        return b.list.toOwnedSlice(b.gpa);
    }

    /// Room for `n` more bytes, or fail.
    fn room(b: *Budget, n: usize) Io.Writer.Error!void {
        if (n > b.limit - b.list.items.len) {
            b.over = true;
            return error.WriteFailed;
        }
        b.list.ensureUnusedCapacity(b.gpa, n) catch {
            b.oom = true;
            return error.WriteFailed;
        };
    }

    fn drain(w: *Io.Writer, parts: []const []const u8, splat: usize) Io.Writer.Error!usize {
        const b: *Budget = @alignCast(@fieldParentPtr("writer", w));
        // No buffer of its own (`buffer` is empty), so everything arrives in `parts`.
        var n: usize = 0;
        for (parts[0 .. parts.len - 1]) |d| {
            try b.room(d.len);
            b.list.appendSliceAssumeCapacity(d);
            n += d.len;
        }
        const pattern = parts[parts.len - 1];
        const total = std.math.mul(usize, pattern.len, splat) catch {
            b.over = true;
            return error.WriteFailed;
        };
        try b.room(total);
        for (0..splat) |_| b.list.appendSliceAssumeCapacity(pattern);
        return n + total;
    }
};

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");
const Control = @import("control.zig").Control;

fn makeStream(gpa: Allocator, nonce: u64, cols: u16, rows: u16, program_output: []const u8) ![]u8 {
    return makeStreamOpts(gpa, nonce, .{ .cols = cols, .rows = rows }, program_output, null);
}

/// A stream from Rex: the snapshot of a terminal made with `opts` that ran `program_output`, then
/// a resize message. `check`, if set, looks at that terminal before it is encoded.
fn makeStreamOpts(gpa: Allocator, nonce: u64, opts: ghostty_vt.Terminal.Options, program_output: []const u8, check: ?*const fn (t: *ghostty_vt.Terminal) anyerror!void) ![]u8 {
    var t = try ghostty_vt.Terminal.init(testing.io, gpa, opts);
    defer t.deinit(gpa);
    var vt = t.vtStream();
    defer vt.deinit();
    vt.nextSlice(program_output);
    if (check) |c| try c(&t);
    var aw: Io.Writer.Allocating = .init(gpa);
    errdefer aw.deinit();
    try ghostty_vt.snapshot.encode(gpa, &aw.writer, &t, .{ .continuation = .ground });
    try aw.writer.print("\x1b_rex1;{d};{{\"type\":\"resize\",\"cols\":{d},\"rows\":{d},\"owner\":null}}\x1b\\", .{ nonce, opts.cols, opts.rows });
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

test "mirror: a redraw can cap how much scrollback it carries" {
    const a = testing.allocator;
    const stream = try makeStream(a, 1, 30, 5, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try m.feed(stream);
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        var buf: [32]u8 = undefined;
        try m.feed(try std.fmt.bufPrint(&buf, "line-{d:0>3}\r\n", .{i}));
    }
    try testing.expect(m.historyRows() >= 190);
    var alt = false;
    {
        const full = try m.redraw(a);
        defer a.free(full);
        const text = try replay(a, full, 30, 5, &alt);
        defer a.free(text);
        try testing.expect(std.mem.indexOf(u8, text, "line-000") != null);
        try testing.expect(std.mem.indexOf(u8, text, "line-199") != null);
    }
    {
        const full_len = (try m.redraw(a));
        defer a.free(full_len);
        const capped = try m.redrawWith(a, .{ .history_lines = 10 });
        defer a.free(capped);
        const text = try replay(a, capped, 30, 5, &alt);
        defer a.free(text);
        try testing.expect(std.mem.indexOf(u8, text, "line-000") == null);
        try testing.expect(std.mem.indexOf(u8, text, "line-150") == null);
        try testing.expect(std.mem.indexOf(u8, text, "line-190") != null); // within 10 + 5 rows
        try testing.expect(std.mem.indexOf(u8, text, "line-199") != null);
        // The fixed state (modes, palette) is most of a small redraw; the dropped rows are the rest.
        try testing.expect(capped.len + 1500 < full_len.len);
    }
    // More history than exists: everything.
    const all = try m.redrawWith(a, .{ .history_lines = 100000 });
    defer a.free(all);
    const text2 = try replay(a, all, 30, 5, &alt);
    defer a.free(text2);
    try testing.expect(std.mem.indexOf(u8, text2, "line-000") != null);
}

test "mirror: plainTextAll joins wrapped lines and keeps the end when it must cut" {
    const a = testing.allocator;
    const stream = try makeStream(a, 1, 20, 4, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try m.feed(stream);
    // One 50-character line wraps on a 20-column terminal; it must come back as one line.
    try m.feed("0123456789012345678901234567890123456789ABCDEFGHIJ\r\n");
    var i: u32 = 0;
    while (i < 100) : (i += 1) {
        var buf: [24]u8 = undefined;
        try m.feed(try std.fmt.bufPrint(&buf, "row-{d:0>3}\r\n", .{i}));
    }
    const all = try m.plainTextAll(a, 1 << 20, 100_000);
    defer a.free(all.text);
    try testing.expect(!all.truncated);
    try testing.expect(std.mem.indexOf(u8, all.text, "0123456789012345678901234567890123456789ABCDEFGHIJ\n") != null);
    const cut = try m.plainTextAll(a, 200, 100_000);
    defer a.free(cut.text);
    try testing.expect(cut.truncated and cut.text.len <= 200);
    try testing.expect(std.mem.indexOf(u8, cut.text, "row-099") != null);
    try testing.expect(cut.text[0] == 'r'); // starts at a line start
}

test "mirror: plainTextAll formats only the last rows when there are more" {
    const a = testing.allocator;
    const stream = try makeStream(a, 1, 20, 4, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try m.feed(stream);
    var i: u32 = 0;
    while (i < 300) : (i += 1) {
        var buf: [24]u8 = undefined;
        try m.feed(try std.fmt.bufPrint(&buf, "row-{d:0>3}\r\n", .{i}));
    }
    const cut = try m.plainTextAll(a, 1 << 20, 50);
    defer a.free(cut.text);
    try testing.expect(cut.truncated); // the byte cap did not cut: the row cap did
    try testing.expect(std.mem.indexOf(u8, cut.text, "row-299") != null);
    try testing.expect(std.mem.indexOf(u8, cut.text, "row-200") == null);
    try testing.expect(std.mem.count(u8, cut.text, "\n") <= 50);
    try testing.expect(std.mem.startsWith(u8, cut.text, "row-"));
    // Both caps: the bytes cut what the rows left.
    const both = try m.plainTextAll(a, 40, 50);
    defer a.free(both.text);
    try testing.expect(both.truncated and both.text.len <= 40);
    try testing.expect(std.mem.indexOf(u8, both.text, "row-299") != null);
    // A cap above the history: everything, not truncated.
    const all = try m.plainTextAll(a, 1 << 20, 100_000);
    defer a.free(all.text);
    try testing.expect(!all.truncated);
    try testing.expect(std.mem.indexOf(u8, all.text, "row-000") != null);
}

/// Counts what a mirror tells its observer.
const Counter = struct {
    resized: u32 = 0,
    ended: u32 = 0,
    last_end: ?data.End = null,
    fn onResize(ctx: *anyopaque, _: u16, _: u16) void {
        const c: *Counter = @ptrCast(@alignCast(ctx));
        c.resized += 1;
    }
    fn onEnded(ctx: *anyopaque, why: data.End) void {
        const c: *Counter = @ptrCast(@alignCast(ctx));
        c.ended += 1;
        c.last_end = why;
    }
    fn observer(c: *Counter) Observer {
        return .{ .ctx = c, .resized = onResize, .ended = onEnded };
    }
};

fn resizeMsg(buf: []u8, nonce: u64, cols: u32, rows: u32) ![]const u8 {
    return std.fmt.bufPrint(buf, "\x1b_rex1;{d};{{\"type\":\"resize\",\"cols\":{d},\"rows\":{d},\"owner\":\"client:2\"}}\x1b\\", .{ nonce, cols, rows });
}

test "mirror: a resize outside the limits is ignored, and the limits themselves work" {
    const a = testing.allocator;
    const stream = try makeStream(a, 3, 20, 4, "x");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 3);
    defer m.deinit();
    try m.feed(stream);
    var count: Counter = .{};
    m.setObserver(count.observer());
    var buf: [160]u8 = undefined;
    const refused = [_][2]u32{ .{ 0, 24 }, .{ 80, 0 }, .{ 4097, 10 }, .{ 10, 4097 }, .{ 2048, 1024 }, .{ 1025, 1024 } };
    for (refused) |r| {
        try m.feed(try resizeMsg(&buf, 3, r[0], r[1]));
        try testing.expectEqual(Mirror.Size{ .cols = 20, .rows = 4 }, m.size().?);
        try testing.expectEqual(Status.live, m.getStatus());
    }
    try testing.expectEqual(@as(u32, 0), count.resized);
    try testing.expect(m.logged_bad_resize);
    try testing.expect(m.owner == null); // an ignored resize changes nothing, the owner included
    try testing.expect(!resizeAllowed(65535, 65535));
    // The boundaries: 4096 on a side, and exactly 1,048,576 cells.
    try m.feed(try resizeMsg(&buf, 3, 4096, 256));
    try testing.expectEqual(Mirror.Size{ .cols = 4096, .rows = 256 }, m.size().?);
    try m.feed(try resizeMsg(&buf, 3, 1, 1));
    try testing.expectEqual(Mirror.Size{ .cols = 1, .rows = 1 }, m.size().?);
    try testing.expectEqual(@as(u32, 2), count.resized);
    try testing.expectEqualStrings("client:2", m.owner.?);
    try testing.expect(resizeAllowed(1024, 1024));
}

test "mirror: an unterminated OSC 52 is freed with the mirror" {
    const a = testing.allocator;
    const stream = try makeStream(a, 5, 20, 4, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 5);
    defer m.deinit(); // testing.allocator reports what the VT stream's buffers would leak
    try m.feed(stream);
    try m.feed("\x1b]52;c;");
    const blob = try a.alloc(u8, 400 * 1024);
    defer a.free(blob);
    @memset(blob, 'A');
    var off: usize = 0;
    while (off < blob.len) : (off += 4096) try m.feed(blob[off..@min(blob.len, off + 4096)]);
}

test "mirror: a theme with no palette leaks nothing" {
    const a = testing.allocator;
    const stream = try makeStream(a, 6, 20, 4, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 6);
    defer m.deinit();
    try m.feed(stream);
    try m.feed("\x1b_rex1;6;{\"type\":\"theme\",\"foreground\":\"#eeeeee\",\"background\":\"#111111\",\"cursor\":\"#ff0000\",\"scheme\":\"dark\"}\x1b\\");
    try m.feed("\x1b_rex1;6;{\"type\":\"theme\",\"background\":\"#222222\"}\x1b\\");
    try testing.expectEqualStrings("#222222", m.theme.?.background.?);
    try testing.expect(m.theme.?.foreground == null);
}

test "mirror: a failure after going live ends the stream once, and later bytes are dropped" {
    // Fail each allocation in turn while a resize (with an owner) is applied: whichever fails,
    // the mirror reports `mirror_failed` once, stops, and frees everything without a double free.
    const a = testing.allocator;
    const stream = try makeStream(a, 8, 20, 4, "x");
    defer a.free(stream);
    var failed_at_least_once = false;
    var k: usize = 0;
    while (k < 200) : (k += 1) {
        var fa = std.testing.FailingAllocator.init(a, .{});
        const m = try Mirror.init(fa.allocator(), testing.io, 8);
        defer m.deinit();
        const s = m.sink();
        s.bytes(s.ctx, stream);
        try testing.expectEqual(Status.live, m.getStatus());
        var count: Counter = .{};
        m.setObserver(count.observer());
        fa.fail_index = fa.alloc_index + k;
        var buf: [160]u8 = undefined;
        s.bytes(s.ctx, try resizeMsg(&buf, 8, 30, 9));
        if (!fa.has_induced_failure) {
            try testing.expectEqual(Status.live, m.getStatus());
            try testing.expectEqual(Mirror.Size{ .cols = 30, .rows = 9 }, m.size().?);
            try testing.expectEqual(@as(u32, 0), count.ended);
            break;
        }
        failed_at_least_once = true;
        try testing.expectEqual(Status.failed, m.getStatus());
        try testing.expectEqual(@as(u32, 1), count.ended);
        try testing.expectEqual(@as(?data.End, .mirror_failed), count.last_end);
        try testing.expectEqual(@as(?data.End, .mirror_failed), m.endReason());
        // More bytes: not applied, not reported again.
        s.bytes(s.ctx, "more output");
        s.bytes(s.ctx, try resizeMsg(&buf, 8, 40, 10));
        try testing.expectEqual(@as(u32, 1), count.ended);
        try testing.expect(m.owner == null);
    } else return error.TestUnexpectedResult;
    try testing.expect(failed_at_least_once);
}

test "mirror: not live until the snapshot has arrived" {
    const m = try Mirror.init(testing.allocator, testing.io, 1);
    defer m.deinit();
    try testing.expectError(error.NotLive, m.redraw(testing.allocator));
    try testing.expect(m.size() == null);
}

test "mirror: the snapshot's end is found from its framing, and a size over the limit fails early" {
    const a = testing.allocator;
    const stream = try makeStream(a, 9, 40, 5, "first line\r\n");
    defer a.free(stream);
    // The real snapshot: its end is where the decoder stops (the resize message follows it).
    var scan: usize = 0;
    const end = (try Mirror.snapshotEnd(stream, &scan, max_snapshot)).?;
    var reader: Io.Reader = .fixed(stream);
    var d = try ghostty_vt.snapshot.decode(a, testing.io, &reader, .{ .max_continuation_bytes = 1 << 20 });
    d.deinit(a);
    try testing.expectEqual(reader.seek, end);
    // Fed in pieces, the end is found once, when the last piece arrives.
    scan = 0;
    for (1..end) |n| try testing.expect((try Mirror.snapshotEnd(stream[0..n], &scan, max_snapshot)) == null);
    try testing.expectEqual(end, (try Mirror.snapshotEnd(stream[0..end], &scan, max_snapshot)).?);
    // A limit smaller than the snapshot: refused, without waiting for the rest.
    scan = 0;
    try testing.expectError(error.SnapshotTooLarge, Mirror.snapshotEnd(stream[0..40], &scan, 30));
    // A record header announcing 4 GiB: refused from its header alone, long before the limit's bytes.
    var big: [20]u8 = undefined;
    @memcpy(big[0..10], stream[0..10]);
    std.mem.writeInt(u16, big[10..12], 3, .little);
    std.mem.writeInt(u32, big[12..16], 0xffff_ffff, .little);
    @memset(big[16..20], 0);
    scan = 0;
    try testing.expectError(error.SnapshotTooLarge, Mirror.snapshotEnd(&big, &scan, max_snapshot));
    const m = try Mirror.init(a, testing.io, 9);
    defer m.deinit();
    try testing.expectError(error.SnapshotTooLarge, m.feed(&big));
    // Not a snapshot at all, even one byte of it.
    scan = 0;
    try testing.expectError(error.BadSnapshot, Mirror.snapshotEnd("GHX", &scan, max_snapshot));
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
    const body = try a.print("{{\"session_id\":\"{s}\"}}", .{made.session_id});
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
    const sid_body = try a.print("{{\"session_id\":\"{s}\"}}", .{sid});
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

    const wr = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"data\":\"printf 'plain \\\\033[31mred\\\\033[0m wide:\\\\xe4\\\\xb8\\\\xad e\\\\xcc\\\\x81\\\\n'; echo done-$((6*7))\\n\"}}}}", .{ sid, bid });
    defer a.free(wr);
    var w = try ctl.call("com.superlogical.terminal.write", wr);
    w.deinit();

    const fmt_body = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"format\":\"text\",\"trim\":true}}}}", .{ sid, bid });
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

test "live: recovery across a real Rex server restart (needs REX_SOCKET, REX_RESTART_OK=1, REX_RESTART_CMD)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    // Restarting ends every program in every session: only when the owner has said so.
    const ok = std.testing.environ.getPosix("REX_RESTART_OK") orelse return error.SkipZigTest;
    if (!std.mem.eql(u8, ok, "1")) return error.SkipZigTest;
    const cmd = std.testing.environ.getPosix("REX_RESTART_CMD") orelse return error.SkipZigTest;

    const ctl = try Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();
    var api = @import("api.zig").Api.init(a, ctl);
    defer api.deinit();

    var made = try api.createSession("rweb-test-live-restart");
    defer made.deinit();
    const sid = made.value.session_id;
    const bid = made.value.block_id;
    var destroyed = false;
    defer if (!destroyed) api.destroySession(sid) catch {};
    try api.attach(sid);

    const m1 = try Mirror.initPending(a, testing.io);
    defer m1.deinit();
    const d1 = try data.Data.openTerminal(a, testing.io, ctl, sid, bid, m1.sink());
    defer d1.close();
    const q = try @import("input.zig").Input.open(a, testing.io, @import("input.zig").Sender.forControl(ctl), sid, bid);
    defer q.close();
    try q.writeText("echo before-restart-$((6*7))\n");
    try q.flush(10000);
    try waitText(m1, "before-restart-42", true);

    // Drain events, then restart the server.
    while (try ctl.nextEvent(50)) |e| e.deinit(a);
    const manual = std.mem.eql(u8, cmd, "manual");
    if (manual) {
        std.debug.print("\nrestart: MANUAL: restart the Rex server now (waiting up to 5 minutes)\n", .{});
    } else {
        var argv: std.ArrayList([]const u8) = .empty;
        defer argv.deinit(a);
        var it = std.mem.tokenizeScalar(u8, cmd, ' ');
        while (it.next()) |w| try argv.append(a, w);
        std.debug.print("\nrestart: running `{s}`\n", .{cmd});
        const res = try std.process.run(a, testing.io, .{ .argv = argv.items });
        defer a.free(res.stdout);
        defer a.free(res.stderr);
        try testing.expectEqual(std.process.Child.Term{ .exited = 0 }, res.term);
    }

    // The old stream must end with "restart needed", and the control connection must come
    // back as a NEW client.
    var tries: u32 = 0;
    const wait_ticks: u32 = if (manual) 30_000 else 1000;
    while (m1.endReason() == null and tries < wait_ticks) : (tries += 1) try testing.io.sleep(.fromMilliseconds(10), .awake);
    std.debug.print("restart: old stream ended: {?}\n", .{m1.endReason()});
    try testing.expectEqual(@as(?data.End, .restart_needed), m1.endReason());

    var generation: u32 = 1;
    var resumed = true;
    tries = 0;
    while (generation == 1 and tries < (if (manual) @as(u32, 3000) else 200)) : (tries += 1) {
        const e = (try ctl.nextEvent(100)) orelse continue;
        defer e.deinit(a);
        if (e == .connected) {
            generation = e.connected.generation;
            resumed = e.connected.resumed;
        }
    }
    std.debug.print("restart: control reconnected generation={d} resumed={}\n", .{ generation, resumed });
    try testing.expectEqual(@as(u32, 2), generation);
    try testing.expect(!resumed);

    // Same session and block IDs; re-attach; a new stream starts from an empty screen.
    {
        var list = try api.sessions();
        defer list.deinit();
        var found = false;
        for (list.value) |s| if (std.mem.eql(u8, s.session_id, sid)) {
            found = true;
        };
        try testing.expect(found);
    }
    try api.attach(sid);
    const m2 = try Mirror.initPending(a, testing.io);
    defer m2.deinit();
    const d2 = try data.Data.openTerminal(a, testing.io, ctl, sid, bid, m2.sink());
    defer d2.close();
    tries = 0;
    while (m2.getStatus() != .live and tries < 600) : (tries += 1) try testing.io.sleep(.fromMilliseconds(10), .awake);
    try testing.expectEqual(Status.live, m2.getStatus());
    {
        const text = try m2.plainText(a);
        defer a.free(text);
        std.debug.print("restart: new screen contains the old output: {}\n", .{std.mem.indexOf(u8, text, "before-restart-42") != null});
        try testing.expect(std.mem.indexOf(u8, text, "before-restart-42") == null);
    }
    // Input works again through the same queue (its calls just needed the connection back).
    try q.writeText("echo after-restart-$((6*7))\n");
    try q.flush(10000);
    try waitText(m2, "after-restart-42", true);
    try api.destroySession(sid);
    destroyed = true;
}

fn waitText(m: *Mirror, needle: []const u8, want: bool) !void {
    var tries: u32 = 0;
    while (tries < 800) : (tries += 1) {
        try testing.io.sleep(.fromMilliseconds(10), .awake);
        if (m.getStatus() != .live) continue;
        const text = try m.plainText(testing.allocator);
        defer testing.allocator.free(text);
        if ((std.mem.indexOf(u8, text, needle) != null) == want) return;
    }
    return error.TimedOut;
}

test "mirror: bracketedPaste follows the program's mode 2004" {
    const a = testing.allocator;
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try testing.expect(!m.bracketedPaste()); // no snapshot yet
    const stream = try makeStream(a, 1, 20, 4, "");
    defer a.free(stream);
    try m.feed(stream);
    try testing.expect(!m.bracketedPaste());
    try m.feed("\x1b[?2004h");
    try testing.expect(m.bracketedPaste());
    try m.feed("prompt$ \x1b[?2004l");
    try testing.expect(!m.bracketedPaste());
    // A snapshot taken while it was on carries it.
    const on = try makeStream(a, 2, 20, 4, "\x1b[?2004h$ ");
    defer a.free(on);
    const m2 = try Mirror.init(a, testing.io, 2);
    defer m2.deinit();
    try m2.feed(on);
    try testing.expect(m2.bracketedPaste());
}

test "mirror: Copy text and redraw history can be capped in cells" {
    const a = testing.allocator;
    const stream = try makeStream(a, 1, 40, 5, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 1);
    defer m.deinit();
    try m.feed(stream);
    var i: u32 = 0;
    while (i < 300) : (i += 1) {
        var buf: [32]u8 = undefined;
        try m.feed(try std.fmt.bufPrint(&buf, "line-{d:0>3}\r\n", .{i}));
    }
    // 400 cells at 40 columns: the last 10 rows, whatever the row cap.
    const capped = try m.plainTextAllCells(a, 1 << 20, 100_000, 400);
    defer a.free(capped.text);
    try testing.expect(capped.truncated);
    try testing.expect(std.mem.indexOf(u8, capped.text, "line-299") != null);
    try testing.expect(std.mem.indexOf(u8, capped.text, "line-290") == null);
    try testing.expect(std.mem.count(u8, capped.text, "\n") <= 10);
    // The smaller of the two caps wins.
    const by_rows = try m.plainTextAllCells(a, 1 << 20, 3, 400);
    defer a.free(by_rows.text);
    try testing.expect(std.mem.count(u8, by_rows.text, "line-") <= 3);
    // No cap in cells: as plainTextAll.
    const plain = try m.plainTextAll(a, 1 << 20, 100_000);
    defer a.free(plain.text);
    const same = try m.plainTextAllCells(a, 1 << 20, 100_000, null);
    defer a.free(same.text);
    try testing.expectEqualStrings(plain.text, same.text);
    // Zero cells: nothing.
    const none = try m.plainTextAllCells(a, 1 << 20, 100_000, 0);
    defer a.free(none.text);
    try testing.expectEqual(@as(usize, 0), none.text.len);

    // A redraw's history: 20 rows' worth of cells at 40 columns, and the row cap when smaller.
    var alt = false;
    const r = try m.redrawWith(a, .{ .history_cells = 20 * 40 });
    defer a.free(r);
    const text = try replay(a, r, 40, 5, &alt);
    defer a.free(text);
    try testing.expect(std.mem.indexOf(u8, text, "line-299") != null);
    try testing.expect(std.mem.indexOf(u8, text, "line-280") != null); // within 20 + 5 rows
    try testing.expect(std.mem.indexOf(u8, text, "line-200") == null);
    try testing.expectEqual(@as(?u32, 5), Mirror.historyCap(.{ .history_lines = 5, .history_cells = 20 * 40 }, 40));
    try testing.expectEqual(@as(?u32, 20), Mirror.historyCap(.{ .history_lines = 50, .history_cells = 20 * 40 }, 40));
    try testing.expectEqual(@as(?u32, null), Mirror.historyCap(.{}, 40));
}

/// Bytes `fa` has handed out and not had back.
fn liveBytes(fa: *const std.testing.FailingAllocator) usize {
    return fa.allocated_bytes - fa.freed_bytes;
}

/// Feed `bytes` in pieces of `step`.
fn feedChunked(m: *Mirror, bytes: []const u8, step: usize) !void {
    var off: usize = 0;
    while (off < bytes.len) : (off += step) try m.feed(bytes[off..@min(bytes.len, off + step)]);
}

fn expectText(m: *Mirror, needle: []const u8) !void {
    const text = try m.plainText(testing.allocator);
    defer testing.allocator.free(text);
    if (std.mem.indexOf(u8, text, needle) == null) {
        std.debug.print("\nmissing {s} in:\n{s}\n", .{ needle, text });
        return error.TestExpectedText;
    }
}

const kitty_image = "\x1b_Ga=T,f=24,s=1,v=1,i=7,q=2;AAAA\x1b\\"; // a 1x1 RGB image, shown

test "mirror: a snapshot that carried kitty images decodes, without them" {
    const a = testing.allocator;
    const Check = struct {
        fn hasImage(t: *ghostty_vt.Terminal) anyerror!void {
            try testing.expectEqual(@as(usize, 1), t.screens.active.kitty_images.images.count());
        }
    };
    const stream = try makeStreamOpts(a, 3, .{ .cols = 30, .rows = 5 }, "before " ++ kitty_image ++ " after\r\n", Check.hasImage);
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 3);
    defer m.deinit();
    try m.feed(stream);
    try testing.expectEqual(Status.live, m.getStatus());
    try expectText(m, "after");
    try testing.expectEqual(@as(usize, 0), m.term.screens.active.kitty_images.images.count());
    try testing.expectEqual(@as(usize, 0), m.term.screens.active.kitty_images.total_limit);
}

test "mirror: kitty graphics and glyph commands in live output are dropped unbuffered and unapplied" {
    const a = testing.allocator;
    const stream = try makeStream(a, 4, 40, 6, "");
    defer a.free(stream);
    var fa = std.testing.FailingAllocator.init(a, .{});
    const m = try Mirror.init(fa.allocator(), testing.io, 4);
    defer m.deinit();
    try m.feed(stream);
    const base = liveBytes(&fa);

    // A whole image command: nothing stored.
    try m.feed(kitty_image);
    try testing.expectEqual(@as(usize, 0), m.term.screens.active.kitty_images.images.count());
    // A long unterminated transmission, in pieces: nothing buffered (Ghostty would hold up to
    // 65 MiB of it with the kitty handler on).
    try m.feed("\x1b_Ga=t,f=24,s=1024,v=1024,i=9;");
    const blob = try a.alloc(u8, 4 << 20);
    defer a.free(blob);
    @memset(blob, 'A');
    try feedChunked(m, blob, 64 * 1024);
    try testing.expect(liveBytes(&fa) - base < 64 * 1024);
    try m.feed("\x1b\\");
    // Many placements: nothing stored either.
    var buf: [64]u8 = undefined;
    for (0..10_000) |i| try m.feed(try std.fmt.bufPrint(&buf, "\x1b_Ga=p,i=7,p={d},q=2\x1b\\", .{i + 1}));
    try testing.expectEqual(@as(usize, 0), m.term.screens.active.kitty_images.images.count());
    // A glyph protocol registration, unterminated and long: not buffered.
    try m.feed("\x1b_25a1;");
    try feedChunked(m, blob[0 .. 2 << 20], 64 * 1024);
    try testing.expect(liveBytes(&fa) - base < 64 * 1024);
    try m.feed("\x1b\\after the strings");
    try expectText(m, "after the strings");
    try testing.expect(liveBytes(&fa) - base < 64 * 1024);
}

test "mirror: scrollback is capped at 10,000 lines and 32 MiB, or Rex's smaller limits" {
    const a = testing.allocator;
    {
        // Rex says unlimited: the mirror's own caps.
        const stream = try makeStreamOpts(a, 5, .{ .cols = 40, .rows = 5, .max_scrollback_bytes = null, .max_scrollback_lines = null }, "", null);
        defer a.free(stream);
        const m = try Mirror.init(a, testing.io, 5);
        defer m.deinit();
        try m.feed(stream);
        const limits = &m.term.screens.get(.primary).?.pages.limits;
        try testing.expectEqual(max_scrollback_lines, limits.lines.explicit);
        try testing.expectEqual(max_scrollback_bytes, limits.bytes.explicit);
        // 12,000 lines of output keep at most 10,000 of history.
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(a);
        for (0..12_000) |i| try out.print(a, "line-{d:0>5}\r\n", .{i});
        try m.feed(out.items);
        const kept = m.historyRows();
        try testing.expect(kept <= max_scrollback_lines and kept > 1000);
        try expectText(m, "line-11999");
        // A reset (RIS) keeps the caps.
        try m.feed("\x1bc");
        try testing.expectEqual(max_scrollback_lines, limits.lines.explicit);
        try testing.expectEqual(max_scrollback_bytes, limits.bytes.explicit);
    }
    {
        // Rex's own limits, smaller than the mirror's: kept.
        const stream = try makeStreamOpts(a, 6, .{ .cols = 40, .rows = 5, .max_scrollback_bytes = 1 << 20, .max_scrollback_lines = 500 }, "", null);
        defer a.free(stream);
        const m = try Mirror.init(a, testing.io, 6);
        defer m.deinit();
        try m.feed(stream);
        const limits = &m.term.screens.get(.primary).?.pages.limits;
        try testing.expectEqual(@as(usize, 500), limits.lines.explicit);
        try testing.expectEqual(@as(usize, 1 << 20), limits.bytes.explicit);
    }
}

test "mirror: OSC and DCS strings are bounded, split anywhere, and output after them renders" {
    const a = testing.allocator;
    const stream = try makeStream(a, 7, 40, 6, "");
    defer a.free(stream);
    var fa = std.testing.FailingAllocator.init(a, .{});
    const m = try Mirror.init(fa.allocator(), testing.io, 7);
    defer m.deinit();
    try m.feed(stream);
    const base = liveBytes(&fa);
    const blob = try a.alloc(u8, 2 << 20);
    defer a.free(blob);
    @memset(blob, 'A');
    const slack = 2 * max_control_string; // the bound, and the growing buffer's last step

    // OSC 52 (a clipboard write, which Ghostty buffers on the heap: 8 MiB by default), 2 MiB in
    // odd-sized pieces, ended by ESC \ split across two feeds.
    try m.feed("\x1b]52;c;");
    try feedChunked(m, blob, 4093);
    try testing.expect(liveBytes(&fa) - base < slack);
    try m.feed("\x1b");
    try m.feed("\\one");
    try expectText(m, "one");
    // The same ended by BEL.
    try m.feed("\x1b]52;c;");
    try feedChunked(m, blob, 65537);
    try testing.expect(liveBytes(&fa) - base < slack);
    try m.feed("\x07two");
    try expectText(m, "onetwo");
    // DCS (XTGETTCAP, buffered up to 1 MiB by default).
    try m.feed("\x1bP+q");
    try feedChunked(m, blob, 3001);
    try testing.expect(liveBytes(&fa) - base < slack);
    try m.feed("\x1b");
    try m.feed("\\three");
    try expectText(m, "onetwothree");
    // A string cancelled by CAN, then ordinary output.
    try m.feed("\x1b]52;c;AAAA\x18four");
    try expectText(m, "onetwothreefour");
    // A short OSC still works: the title.
    try m.feed("\x1b]2;rweb title\x1b");
    try m.feed("\\");
    try testing.expectEqualStrings("rweb title", m.term.getTitle().?);
    try testing.expect(liveBytes(&fa) - base < slack);
}

test "mirror: a snapshot of a terminal larger than a resize may make fails as a bad snapshot" {
    const a = testing.allocator;
    // Within the axis limit but over the cell limit: 2048 x 1024.
    const big = try makeStreamOpts(a, 8, .{ .cols = 2048, .rows = 1024 }, "", null);
    defer a.free(big);
    try testing.expectEqual(wire.SnapshotSize{ .cols = 2048, .rows = 1024 }, wire.snapshotSize(big).?);
    {
        const m = try Mirror.init(a, testing.io, 8);
        defer m.deinit();
        try testing.expectError(error.BadSnapshot, m.feed(big));
    }
    {
        // Refused from its first record: before the rest of it arrives.
        const m = try Mirror.init(a, testing.io, 8);
        defer m.deinit();
        try testing.expectError(error.BadSnapshot, m.feed(big[0..64]));
    }
    {
        // Exactly at the limit (1024 x 1024): fine.
        const at = try makeStreamOpts(a, 9, .{ .cols = 1024, .rows = 1024 }, "corner", null);
        defer a.free(at);
        const m = try Mirror.init(a, testing.io, 9);
        defer m.deinit();
        try m.feed(at);
        try testing.expectEqual(Mirror.Size{ .cols = 1024, .rows = 1024 }, m.size().?);
    }
}

/// `rows` rows of output where every cell has its own colour (style-dense) or its own link
/// (hyperlink-dense), each row ending with its number.
fn denseOutput(a: Allocator, rows: usize, cols: usize, links: bool) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    for (0..rows) |r| {
        for (0..cols - 6) |c| {
            if (links) {
                try out.print(a, "\x1b]8;;https://example.com/{d}/{d}/", .{ r, c });
                try out.appendNTimes(a, 'p', 150);
                try out.appendSlice(a, "\x1b\\x\x1b]8;;\x1b\\");
            } else {
                try out.print(a, "\x1b[38;2;{d};{d};{d};48;2;{d};{d};{d};1;3;4mx", .{ r % 256, c % 256, (r + c) % 256, c % 256, r % 256, (r * c) % 256 });
            }
        }
        try out.print(a, "\x1b[0m{d:0>5}\r\n", .{r});
    }
    return out.toOwnedSlice(a);
}

test "mirror: a redraw stays within its byte budget by carrying less history, down to the screen alone" {
    const a = testing.allocator;
    for ([_]bool{ false, true }) |links| {
        const stream = try makeStreamOpts(a, 10, .{ .cols = 80, .rows = 10, .max_scrollback_bytes = null, .max_scrollback_lines = null }, "", null);
        defer a.free(stream);
        const m = try Mirror.init(a, testing.io, 10);
        defer m.deinit();
        try m.feed(stream);
        const rows: usize = if (links) 60 else 400; // a link costs far more than a colour
        const out = try denseOutput(a, rows, 80, links);
        defer a.free(out);
        try m.feed(out);
        try testing.expect(m.historyRows() >= rows - 10);

        // With room for everything, everything comes.
        const Cap = struct {
            gpa: Allocator,
            bytes: ?[]u8 = null,
            fn take(ctx: *anyopaque, b: []u8) !void {
                const c: *@This() = @ptrCast(@alignCast(ctx));
                if (c.bytes) |old| c.gpa.free(old);
                c.bytes = b; // the redraw is handed over
            }
        };
        var cap: Cap = .{ .gpa = a };
        defer if (cap.bytes) |b| a.free(b);
        const full = try m.redrawLockedInfo(a, .{}, &cap, Cap.take);
        try testing.expectEqual(@as(u32, @intCast(m.historyRows())), full.history_rows);
        try testing.expect(!full.history_cut);
        const full_len = cap.bytes.?.len;
        try testing.expect(full_len > 200 * 1024); // dense indeed

        // A budget of a fifth of that: less history, within the budget, the screen intact.
        m.redraw_budget = full_len / 5;
        const less = try m.redrawLockedInfo(a, .{}, &cap, Cap.take);
        try testing.expect(less.history_cut and less.history_rows < full.history_rows);
        try testing.expect(cap.bytes.?.len <= m.redraw_budget);
        var alt = false;
        const text = try replay(a, cap.bytes.?, 80, 10, &alt);
        defer a.free(text);
        var last: [5]u8 = undefined;
        try testing.expect(std.mem.indexOf(u8, text, try std.fmt.bufPrint(&last, "{d:0>5}", .{rows - 1})) != null);
        // The default path (no report) obeys the budget too.
        const plain = try m.redrawWith(a, .{ .history_lines = 300 });
        defer a.free(plain);
        try testing.expect(plain.len <= m.redraw_budget);

        // Room for the screen alone: no history at all.
        m.redraw_budget = max_redraw_bytes;
        const alone = try m.redrawWith(a, .{ .history_lines = 0 });
        defer a.free(alone);
        m.redraw_budget = alone.len;
        const screen = try m.redrawLockedInfo(a, .{}, &cap, Cap.take);
        try testing.expectEqual(@as(u32, 0), screen.history_rows);
        try testing.expect(screen.history_cut);
        // Not even that: an error, and nothing delivered.
        m.redraw_budget = 1024;
        if (cap.bytes) |b| a.free(b);
        cap.bytes = null;
        try testing.expectError(error.RedrawTooLarge, m.redrawLockedInfo(a, .{}, &cap, Cap.take));
        try testing.expect(cap.bytes == null);
    }
}

/// An allocator that remembers the largest single block it was asked for (to see how large a
/// buffer grew).
const Largest = struct {
    child: Allocator,
    largest: usize = 0,

    fn allocator(l: *Largest) Allocator {
        return .{ .ptr = l, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const l: *Largest = @ptrCast(@alignCast(ctx));
        l.largest = @max(l.largest, len);
        return l.child.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, len: usize, ra: usize) bool {
        const l: *Largest = @ptrCast(@alignCast(ctx));
        l.largest = @max(l.largest, len);
        return l.child.rawResize(mem, al, len, ra);
    }
    fn remap(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, len: usize, ra: usize) ?[*]u8 {
        const l: *Largest = @ptrCast(@alignCast(ctx));
        l.largest = @max(l.largest, len);
        return l.child.rawRemap(mem, al, len, ra);
    }
    fn free(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, ra: usize) void {
        const l: *Largest = @ptrCast(@alignCast(ctx));
        l.child.rawFree(mem, al, ra);
    }
};

test "mirror: Copy text is formatted within 8 times its byte cap and keeps the end" {
    const a = testing.allocator;
    for ([_]bool{ false, true }) |links| {
        const stream = try makeStreamOpts(a, 11, .{ .cols = 80, .rows = 10, .max_scrollback_bytes = null, .max_scrollback_lines = null }, "", null);
        defer a.free(stream);
        const m = try Mirror.init(a, testing.io, 11);
        defer m.deinit();
        try m.feed(stream);
        const rows: usize = if (links) 60 else 400; // a link costs far more than a colour
        const out = try denseOutput(a, rows, 80, links);
        defer a.free(out);
        try m.feed(out);
        // About 81 bytes a row of text: a cap of 1000 bytes formats at most 8000.
        var big: Largest = .{ .child = a };
        const cut = try m.plainTextAllCells(big.allocator(), 1000, 100_000, null);
        defer a.free(cut.text);
        try testing.expect(cut.truncated and cut.text.len <= 1000);
        try testing.expect(big.largest <= 2 * copy_format_factor * 1000); // the buffer's growth step included
        var last: [5]u8 = undefined;
        try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, cut.text, "\n"), try std.fmt.bufPrint(&last, "{d:0>5}", .{rows - 1})));
        try testing.expect(cut.text[0] == 'x'); // a line start
        // A cap that holds everything: everything.
        const all = try m.plainTextAllCells(a, 1 << 20, 100_000, null);
        defer a.free(all.text);
        try testing.expect(!all.truncated);
        try testing.expect(std.mem.indexOf(u8, all.text, "00000") != null);
    }
    // Grapheme-dense text (marks on each character: more bytes than cells) is bounded the same way.
    const stream = try makeStream(a, 12, 40, 5, "");
    defer a.free(stream);
    const m = try Mirror.init(a, testing.io, 12);
    defer m.deinit();
    try m.feed(stream);
    var g: std.ArrayList(u8) = .empty;
    defer g.deinit(a);
    for (0..300) |r| {
        for (0..2) |_| {
            try g.append(a, 'e');
            for (0..8) |_| try g.appendSlice(a, "\xcc\x81");
        }
        try g.print(a, "{d:0>5}\r\n", .{r});
    }
    try m.feed(g.items);
    // About 40 bytes a row of text, 305 rows: a cap of 500 bytes formats at most 4000.
    var big: Largest = .{ .child = a };
    const cut = try m.plainTextAllCells(big.allocator(), 500, 100_000, null);
    defer a.free(cut.text);
    try testing.expect(cut.truncated and cut.text.len <= 500);
    try testing.expect(big.largest <= 2 * copy_format_factor * 500);
    try testing.expect(std.mem.endsWith(u8, std.mem.trimEnd(u8, cut.text, "\n"), "00299"));
}

test "mirror: a new nonce that cannot be stored leaves the old splitter whole, freed once" {
    // A stream that reconnects gets a second nonce. If storing it runs out of memory, the mirror must
    // still hold a splitter it can free exactly once (the testing allocator reports a double free).
    var fa = std.testing.FailingAllocator.init(testing.allocator, .{});
    const m = try Mirror.initPending(fa.allocator(), testing.io);
    defer m.deinit();
    try m.setNonce(1);
    fa.fail_index = fa.alloc_index; // the next allocation fails
    try testing.expectError(error.OutOfMemory, m.setNonce(2));
    try testing.expect(m.splitter != null);
}
