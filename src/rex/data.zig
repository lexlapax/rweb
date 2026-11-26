//! A Rex data connection: one block's output stream. Ticket and HELLO, WELCOME, byte
//! counting, resume within the server's window, and the end states a caller must act on.
//!
//! Bytes are handed to the sink in order, each counted once after the sink has taken it.
//! The sink runs on the reader task. The stream's first bytes are a snapshot; this layer
//! does not interpret them.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ws = @import("ws.zig");
const Control = @import("control.zig").Control;
const wire = @import("wire.zig");

pub const parseHandshake = wire.parseHandshake;
pub const decodeTicket = wire.decodeTicket;
pub const Handshake = wire.Handshake;

const log = std.log.scoped(.rex_data);

pub const subprotocol = "rex.data.terminal.v1";

/// Why a stream ended. Anything but `closed_by_us` means the caller should decide whether to
/// start a new stream (new ticket, new snapshot).
pub const End = enum {
    /// We closed it.
    closed_by_us,
    /// The block closed (4000). Do not reconnect.
    block_closed,
    /// The server needs a new stream: 1013, a refused resume, the server stopped the data
    /// source (1001 `data provider canceled`, as on a Rex restart), or the resume window passed.
    restart_needed,
    /// The server could not serve it (REJECT, 1008, 1011, or a protocol error).
    failed,
    /// The stream may be fine but the mirror following it is not (a bad snapshot, or out of memory):
    /// it stopped applying bytes. Reported by `mirror.Mirror`, never by `Data`. Start a new stream.
    mirror_failed,
};

pub const Sink = struct {
    ctx: *anyopaque,
    bytes: *const fn (ctx: *anyopaque, bytes: []const u8) void,
    ended: *const fn (ctx: *anyopaque, why: End) void,
    /// Called once, after the first WELCOME and before any bytes, with the channel nonce.
    welcome: ?*const fn (ctx: *anyopaque, nonce: u64) void = null,
};

pub const Data = struct {
    gpa: Allocator,
    io: Io,
    socket_path: []const u8,
    sink: Sink,

    /// The channel nonce from the WELCOME, which marks Rex's messages in the stream.
    nonce: u64,
    /// Stream bytes handed to the sink, across every connection of the stream.
    received: u64 = 0,
    token: [16]u8,
    /// How long the server keeps the stream for a resume.
    resume_window_ms: u32,
    conn: ?*ws.Conn,
    /// The socket of a connection still in its handshake (a resume), so `close` can shut it.
    connecting: ?Io.net.Stream = null,
    /// Guards `conn` and `connecting`, which the reader replaces when it resumes.
    conn_mu: Io.Mutex = .init,
    /// Longest wait for a connection's upgrade and WELCOME.
    handshake_timeout_ms: u32 = ws.handshake_timeout_ms,
    closing: std.atomic.Value(bool) = .init(false),
    reader: ?Io.Future(void) = null,
    /// The last close status seen, for tests and logs.
    last_close: u16 = 0,
    /// Resumes since the stream last showed it works: the count `received` had when the streak
    /// began, when it began, and how long to wait before the next try. A stream that keeps
    /// dropping without delivering a byte runs out of its resume window instead of resuming
    /// forever. A connection that delivered a byte, or stayed up for `resume_stable_ms`, ends the
    /// streak, so an idle terminal dropped now and then resumes every time.
    streak_received: u64 = std.math.maxInt(u64),
    streak_start_ms: i64 = 0,
    resume_backoff_ms: u64 = 0,
    /// When the current connection's handshake finished.
    conn_up_ms: i64 = 0,
    /// How long a connection must stay up to end a resume streak (tests shorten it).
    resume_stable_ms: u32 = default_resume_stable_ms,

    pub const default_resume_stable_ms: u32 = 5_000;

    pub const OpenError = error{ Rejected, BadHandshake } || Allocator.Error;

    pub const Options = struct {
        /// Longest wait for each connection's upgrade and WELCOME (the first, and every resume).
        handshake_timeout_ms: u32 = ws.handshake_timeout_ms,
    };

    /// Open with a ticket from `data.connect` and complete the handshake.
    pub fn open(gpa: Allocator, io: Io, socket_path: []const u8, ticket: [16]u8, sink: Sink) !*Data {
        return openWith(gpa, io, socket_path, ticket, sink, .{});
    }

    pub fn openWith(gpa: Allocator, io: Io, socket_path: []const u8, ticket: [16]u8, sink: Sink, opts: Options) !*Data {
        const d = try gpa.create(Data);
        errdefer gpa.destroy(d);
        const path = try gpa.dupe(u8, socket_path);
        errdefer gpa.free(path);
        d.* = .{
            .gpa = gpa,
            .io = io,
            .socket_path = path,
            .sink = sink,
            .nonce = 0,
            .token = undefined,
            .resume_window_ms = 0,
            .conn = null,
            .handshake_timeout_ms = opts.handshake_timeout_ms,
        };
        var hello: [17]u8 = undefined;
        hello[0] = 0x01;
        @memcpy(hello[1..], &ticket);
        try d.handshake(&hello);
        errdefer if (d.conn) |c| c.deinit(gpa);
        if (sink.welcome) |f| f(sink.ctx, d.nonce);
        d.reader = try io.concurrent(readerMain, .{d});
        return d;
    }

    /// Get a ticket over `control` and open the stream of `block_id`. The control connection
    /// must be attached to the session.
    pub fn openTerminal(gpa: Allocator, io: Io, control: *Control, session_id: []const u8, block_id: []const u8, sink: Sink) !*Data {
        const sid = try std.json.Stringify.valueAlloc(gpa, session_id, .{});
        defer gpa.free(sid);
        const bid = try std.json.Stringify.valueAlloc(gpa, block_id, .{});
        defer gpa.free(bid);
        const body = try gpa.print("{{\"session_id\":{s},\"block_id\":{s},\"data_ref_id\":\"terminal\",\"subprotocol\":\"{s}\"}}", .{ sid, bid, subprotocol });
        defer gpa.free(body);
        var r = try control.call("data.connect", body);
        defer r.deinit();
        const p = r.ok() catch return error.TicketRefused;
        if (p != .object) return error.BadHandshake;
        const t = p.object.get("ticket") orelse return error.BadHandshake;
        if (t != .string) return error.BadHandshake;
        const ticket = try decodeTicket(t.string);
        return openWith(gpa, io, control.opts.socket_path, ticket, sink, .{ .handshake_timeout_ms = control.opts.handshake_timeout_ms });
    }

    /// How long `close` waits for its close frame to be written before it cuts the socket.
    pub const close_write_ms: u32 = 1000;

    pub fn close(d: *Data) void {
        d.closing.store(true, .release);
        d.conn_mu.lockUncancelable(d.io);
        if (d.conn) |c| {
            // A 1000 close ends the stream on Rex's side (otherwise it stays resumable until its
            // window passes). The frame goes first, while the socket still works; a watchdog
            // cuts the socket if Rex does not take it in time, counting from now (so a pong
            // still being written by the reader does not lengthen it). Holding `conn_mu` keeps
            // the reader from replacing the connection meanwhile.
            if (ws.Watchdog.start(d.io, c.stream, close_write_ms)) |dog_| {
                var dog = dog_;
                c.writeFrameTimeout(.close, &.{ 0x03, 0xe8 }, null) catch {};
                dog.stop(d.io);
            } else |_| {}
            // Then shut it: cancelling a task blocked in a read is not reliable, but a read on a
            // shut socket returns at once, and the reader sees `closing` and exits.
            c.stream.shutdown(d.io, .both) catch {};
        }
        if (d.connecting) |st| st.shutdown(d.io, .both) catch {};
        d.conn_mu.unlock(d.io);
        if (d.reader) |*r| r.cancel(d.io);
        if (d.conn) |c| c.deinit(d.gpa);
        d.gpa.free(d.socket_path);
        d.gpa.destroy(d);
    }

    /// Open a socket and run the handshake `first` (HELLO or RESUME); sets `conn`, `token`,
    /// `nonce` and `resume_window_ms` from the WELCOME.
    fn handshake(d: *Data, first: []const u8) !void {
        const io = d.io;
        const stream = try ws.connectUnix(io, d.socket_path);
        // While the handshake runs, `close` can shut the socket. On failure it is unpublished
        // (and the watchdog stopped) before it is closed: defers run in reverse order.
        errdefer stream.close(io);
        try d.setConnecting(stream);
        defer d.setConnecting(null) catch {};
        var dog = try ws.Watchdog.start(io, stream, d.handshake_timeout_ms);
        defer dog.stop(io);
        const c = try ws.Conn.upgrade(d.gpa, io, stream, "/api/data", subprotocol, "");
        c.owns_stream = false; // until published; the errdefer above closes it
        errdefer c.deinit(d.gpa);
        c.max_message = ws.handshake_max_message; // the WELCOME; the stream's limit is set below
        try c.writeFrame(.binary, first);
        const m = try c.readMessage(d.gpa);
        defer d.gpa.free(m.data);
        if (m.opcode != .binary) return error.BadHandshake;
        const w = parseHandshake(m.data) catch |e| return e;
        // A watchdog that fired has shut the socket, even if the WELCOME got in first.
        try dog.finish(io);
        switch (w) {
            .reject => return error.Rejected,
            .welcome => |wl| {
                // A resume must keep the channel nonce: the stream continues.
                if (d.nonce != 0 and wl.nonce != d.nonce) return error.BadHandshake;
                d.nonce = wl.nonce;
                d.token = wl.token;
                d.resume_window_ms = wl.window_ms;
            },
        }
        d.conn_mu.lockUncancelable(d.io);
        defer d.conn_mu.unlock(d.io);
        if (d.closing.load(.acquire)) return error.Canceled; // closed while connecting
        c.owns_stream = true;
        c.max_message = wire.data_max_message;
        c.write_timeout_ms = ws.write_timeout_ms; // pongs
        d.conn = c;
        d.conn_up_ms = Io.Clock.awake.now(d.io).toMilliseconds();
    }

    fn setConnecting(d: *Data, stream: ?Io.net.Stream) error{Canceled}!void {
        d.conn_mu.lockUncancelable(d.io);
        defer d.conn_mu.unlock(d.io);
        if (stream != null and d.closing.load(.acquire)) return error.Canceled;
        d.connecting = stream;
    }

    fn readerMain(d: *Data) void {
        while (true) {
            const why = d.serve();
            if (d.closing.load(.acquire)) return;
            switch (why) {
                .reconnect => if (d.tryResume()) continue else {
                    if (d.closing.load(.acquire)) return; // closed while resuming: not an end
                    d.sink.ended(d.sink.ctx, .restart_needed);
                    return;
                },
                .done => |e| {
                    d.sink.ended(d.sink.ctx, e);
                    return;
                },
            }
        }
    }

    const Served = union(enum) { reconnect, done: End };

    /// Read until the connection ends, handing bytes to the sink.
    fn serve(d: *Data) Served {
        const c = d.conn.?;
        while (true) {
            const m = c.readMessage(d.gpa) catch |e| switch (e) {
                // The server sent what this protocol does not allow (a frame over the limit, a
                // reserved bit, a ping flood): resuming would get the same again. End the stream.
                error.TooLarge, error.Protocol, error.BadControl => {
                    log.warn("data stream ended: {t}", .{e});
                    return .{ .done = .failed };
                },
                error.OutOfMemory => return .{ .done = .failed },
                // The connection dropped: resume.
                else => return .reconnect,
            };
            defer d.gpa.free(m.data);
            switch (m.opcode) {
                .binary => {
                    if (m.data.len == 0) continue;
                    d.sink.bytes(d.sink.ctx, m.data);
                    d.received += m.data.len;
                },
                .close => {
                    const code: u16 = if (m.data.len >= 2) std.mem.readInt(u16, m.data[0..2], .big) else 1005;
                    const reason = if (m.data.len > 2) m.data[2..] else "";
                    d.last_close = code;
                    log.debug("data closed {d} {s}", .{ code, reason });
                    return switch (code) {
                        1000 => .{ .done = .restart_needed }, // the stream ended on the server's side
                        4000 => .{ .done = .block_closed },
                        1013 => .{ .done = .restart_needed },
                        1001 => if (std.mem.eql(u8, reason, "keepalive timeout")) .reconnect else .{ .done = .restart_needed },
                        else => .{ .done = .failed },
                    };
                },
                else => return .{ .done = .failed },
            }
        }
    }

    /// Resume with the latest token and the exact count, retrying until the window passes. The
    /// window counts from the first resume of the streak (see `streak_received`), so a server that
    /// takes every resume and drops it again at once without sending a byte cannot keep the
    /// stream resuming forever; and resumes that bring nothing back off as failed tries do.
    fn tryResume(d: *Data) bool {
        d.conn_mu.lockUncancelable(d.io);
        const old = d.conn;
        d.conn = null;
        d.conn_mu.unlock(d.io);
        if (old) |c| c.deinit(d.gpa);
        const window: i64 = if (d.resume_window_ms == 0) 60_000 else d.resume_window_ms;
        const up_ms = Io.Clock.awake.now(d.io).toMilliseconds() - d.conn_up_ms;
        if (d.received != d.streak_received or up_ms >= d.resume_stable_ms) {
            d.streak_received = d.received;
            d.streak_start_ms = Io.Clock.awake.now(d.io).toMilliseconds();
            d.resume_backoff_ms = 0;
        }
        while (true) {
            if (d.closing.load(.acquire)) return false;
            if (d.resume_backoff_ms > 0) d.io.sleep(.fromMilliseconds(@intCast(d.resume_backoff_ms)), .awake) catch return false;
            if (d.closing.load(.acquire)) return false;
            if (Io.Clock.awake.now(d.io).toMilliseconds() - d.streak_start_ms >= window) return false;
            d.resume_backoff_ms = @min(@max(d.resume_backoff_ms * 2, 50), 1000);
            var r: [25]u8 = undefined;
            r[0] = 0x02;
            @memcpy(r[1..17], &d.token);
            std.mem.writeInt(u64, r[17..25], d.received, .little);
            if (d.handshake(&r)) |_| return true else |e| switch (e) {
                // The server answered and said no: start over.
                error.Rejected, error.BadHandshake => return false,
                error.Canceled => return false,
                else => {},
            }
        }
    }
};

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");

/// Test sink: collects bytes and the end reason.
const Capture = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    bytes: std.ArrayList(u8) = .empty,
    end: ?End = null,

    fn deinit(c: *Capture) void {
        c.bytes.deinit(c.gpa);
    }
    fn onBytes(ctx: *anyopaque, b: []const u8) void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.bytes.appendSlice(c.gpa, b) catch {};
    }
    fn onEnded(ctx: *anyopaque, why: End) void {
        const c: *Capture = @ptrCast(@alignCast(ctx));
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.end = why;
    }
    fn sink(c: *Capture) Sink {
        return .{ .ctx = c, .bytes = onBytes, .ended = onEnded };
    }
    fn has(c: *Capture, needle: []const u8) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return std.mem.indexOf(u8, c.bytes.items, needle) != null;
    }
    fn len(c: *Capture) usize {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.bytes.items.len;
    }
    fn ended(c: *Capture) ?End {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.end;
    }
    /// Wait up to ~3 s for `needle`.
    fn waitFor(c: *Capture, needle: []const u8) !void {
        var i: u32 = 0;
        while (i < 600) : (i += 1) {
            if (c.has(needle)) return;
            try c.io.sleep(.fromMilliseconds(5), .awake);
        }
        return error.TimedOut;
    }
    fn waitEnd(c: *Capture) !End {
        var i: u32 = 0;
        while (i < 600) : (i += 1) {
            if (c.ended()) |e| return e;
            try c.io.sleep(.fromMilliseconds(5), .awake);
        }
        return error.TimedOut;
    }
};

const Setup = struct {
    f: *fake.Fake,
    ctl: *Control,
    session_id: []u8,
    block_id: []u8,

    fn init() !Setup {
        const a = testing.allocator;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        var r = try ctl.call("session.create", "{\"label\":\"rweb-test-data\"}");
        defer r.deinit();
        const p = (try r.ok()).object;
        const sid = try a.dupe(u8, p.get("session_id").?.string);
        errdefer a.free(sid);
        const bid = try a.dupe(u8, p.get("initial_windows").?.array.items[0].object.get("block_ids").?.array.items[0].string);
        errdefer a.free(bid);
        const body = try a.print("{{\"session_id\":\"{s}\"}}", .{sid});
        defer a.free(body);
        var at = try ctl.call("session.attach", body);
        at.deinit();
        return .{ .f = f, .ctl = ctl, .session_id = sid, .block_id = bid };
    }

    fn deinit(s: Setup) void {
        testing.allocator.free(s.session_id);
        testing.allocator.free(s.block_id);
        s.ctl.close();
        s.f.deinit();
    }
};

test "data: opens a terminal stream and counts bytes" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");
    try s.f.feed(s.block_id, "hello");
    try cap.waitFor("hello");
    try testing.expectEqual(@as(u64, cap.len()), d.received);
    try testing.expect(d.nonce != 0);
}

test "data: resumes after a drop with no gap and no duplicate" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");
    try s.f.feed(s.block_id, "one ");
    try cap.waitFor("one ");
    s.f.dropDataConnections();
    try s.f.feed(s.block_id, "two ");
    try s.f.feed(s.block_id, "three");
    try cap.waitFor("three");
    cap.mu.lockUncancelable(testing.io);
    defer cap.mu.unlock(testing.io);
    const at = std.mem.indexOf(u8, cap.bytes.items, "one ").?;
    try testing.expectEqualStrings("one two three", cap.bytes.items[at..]);
    try testing.expectEqual(@as(?End, null), cap.end);
}

test "data: block closed (4000), reconnect required (1013) and provider canceled (1001)" {
    const a = testing.allocator;
    const cases = [_]struct { code: u16, reason: []const u8, want: End }{
        .{ .code = 4000, .reason = "block closed", .want = .block_closed },
        .{ .code = 1013, .reason = "data reconnect required", .want = .restart_needed },
        .{ .code = 1001, .reason = "data provider canceled", .want = .restart_needed },
        .{ .code = 1011, .reason = "data provider failed", .want = .failed },
    };
    for (cases) |cs| {
        const s = try Setup.init();
        defer s.deinit();
        var cap: Capture = .{ .gpa = a, .io = testing.io };
        defer cap.deinit();
        const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
        defer d.close();
        try cap.waitFor("\"type\":\"resize\"");
        s.f.endStreams(s.block_id, cs.code, cs.reason);
        try testing.expectEqual(cs.want, try cap.waitEnd());
    }
}

test "data: a used ticket is rejected" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const sid = s.session_id;
    const body = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"data_ref_id\":\"terminal\"}}", .{ sid, s.block_id });
    defer a.free(body);
    var r = try s.ctl.call("data.connect", body);
    defer r.deinit();
    const ticket = try decodeTicket((try r.ok()).object.get("ticket").?.string);
    const d = try Data.open(a, testing.io, s.f.path, ticket, cap.sink());
    d.close();
    try testing.expectError(error.Rejected, Data.open(a, testing.io, s.f.path, ticket, cap.sink()));
}

test "data: after a server restart the stream needs restarting, and a new one works" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");
    try s.f.restart();
    try testing.expectEqual(End.restart_needed, try cap.waitEnd());

    // Re-attach on the new control connection, then a new stream shows the empty screen.
    var tries: u32 = 0;
    while (!s.ctl.isConnected() and tries < 400) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
    // The new control connection is a new client: attach again.
    var gen2: ?u32 = null;
    while (try s.ctl.nextEvent(500)) |e| {
        defer e.deinit(a);
        if (e == .connected and e.connected.generation == 2) {
            gen2 = e.connected.generation;
            break;
        }
    }
    try testing.expect(gen2 != null);
    const body = try a.print("{{\"session_id\":\"{s}\"}}", .{s.session_id});
    defer a.free(body);
    var at = try s.ctl.call("session.attach", body);
    at.deinit();
    var cap2: Capture = .{ .gpa = a, .io = testing.io };
    defer cap2.deinit();
    const d2 = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap2.sink());
    defer d2.close();
    try cap2.waitFor("\"type\":\"resize\"");
}

test "live: stream a throwaway terminal on a real Rex (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();

    var made = try ctl.call("session.create", "{\"label\":\"rweb-test-live-data\",\"initial_windows\":[{\"layout\":{\"block\":{\"flavor\":\"com.superlogical.terminal.shell\"}}}]}");
    defer made.deinit();
    const p = (try made.ok()).object;
    const sid = try a.dupe(u8, p.get("session_id").?.string);
    defer a.free(sid);
    const bid = try a.dupe(u8, p.get("initial_windows").?.array.items[0].object.get("block_ids").?.array.items[0].string);
    defer a.free(bid);
    const sid_body = try a.print("{{\"session_id\":\"{s}\"}}", .{sid});
    defer a.free(sid_body);
    // Always destroy the throwaway session, whatever happens below.
    defer {
        if (ctl.call("session.destroy", sid_body)) |r| {
            var rr = r;
            rr.deinit();
        } else |_| {}
    }
    var at = try ctl.call("session.attach", sid_body);
    at.deinit();

    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, ctl, sid, bid, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");

    const wr = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"data\":\"echo rweb-live-$((6*7))\\n\"}}}}", .{ sid, bid });
    defer a.free(wr);
    var w = try ctl.call("com.superlogical.terminal.write", wr);
    defer w.deinit();
    _ = try w.ok();
    try cap.waitFor("rweb-live-42");
    try testing.expectEqual(@as(u64, cap.len()), d.received);
}

test "data: a data.connect payload that is not an object is an error, not a crash" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    for ([_][]const u8{ "[1,2]", "\"ticket\"", "7", "null" }) |raw| {
        s.f.data_connect_payload = raw;
        try testing.expectError(error.BadHandshake, Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink()));
    }
}

test "data: the handshake has a deadline" {
    const a = testing.allocator;
    const silent = try fake.Silent.start(a, testing.io, null);
    defer silent.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    const ticket: [16]u8 = @splat(1);
    try testing.expect(std.meta.isError(Data.openWith(a, testing.io, silent.path, ticket, cap.sink(), .{ .handshake_timeout_ms = 200 })));
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5000);
}

test "data: close shuts a resume still in its handshake, and that is not an end" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    const path = try a.dupe(u8, f.path);
    defer a.free(path);
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = blk: {
        const ctl = try Control.open(a, testing.io, .{ .socket_path = path, .reconnect = false });
        defer ctl.close();
        const made = try f.createSession("rweb-test-resume");
        const body = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"data_ref_id\":\"terminal\"}}", .{ made.session_id, made.block_id });
        defer a.free(body);
        const sb = try a.print("{{\"session_id\":\"{s}\"}}", .{made.session_id});
        defer a.free(sb);
        var at = try ctl.call("session.attach", sb);
        at.deinit();
        var r = try ctl.call("data.connect", body);
        defer r.deinit();
        const ticket = try decodeTicket((try r.ok()).object.get("ticket").?.string);
        break :blk try Data.openWith(a, testing.io, path, ticket, cap.sink(), .{ .handshake_timeout_ms = 60_000 });
    };
    try cap.waitFor("\"type\":\"resize\"");
    // The server goes away without a close frame, and something that never answers takes its
    // socket: the resume connects and waits for a WELCOME that never comes.
    f.deinit();
    const silent = try fake.Silent.start(a, testing.io, path);
    defer silent.deinit();
    var tries: u32 = 0;
    while (silent.acceptedCount() == 0 and tries < 1000) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
    try testing.expect(silent.acceptedCount() > 0);
    try testing.io.sleep(.fromMilliseconds(50), .awake);
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    d.close();
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5000);
    try testing.expectEqual(@as(?End, null), cap.ended());
}

test "data: a protocol or size error from the server ends the stream instead of resuming" {
    const a = testing.allocator;
    // A frame with a reserved bit set, and a frame header announcing more than the stream's limit.
    var too_large: [10]u8 = .{ 0x82, 127, 0, 0, 0, 0, 0, 0, 0, 0 };
    std.mem.writeInt(u64, too_large[2..10], wire.data_max_message + 1, .big);
    for ([_][]const u8{ &.{ 0xc2, 0x00 }, &too_large }) |raw| {
        const s = try Setup.init();
        defer s.deinit();
        var cap: Capture = .{ .gpa = a, .io = testing.io };
        defer cap.deinit();
        const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
        defer d.close();
        try cap.waitFor("\"type\":\"resize\"");
        // Every connection has the stream's limit once its handshake is done.
        try testing.expectEqual(wire.data_max_message, d.conn.?.max_message);
        try s.f.injectRaw(s.block_id, raw);
        try testing.expectEqual(End.failed, try cap.waitEnd());
        try testing.expectEqual(@as(u32, 0), s.f.dataResumes());
    }
}

test "data: a server that takes every resume and drops it again runs out of the resume window" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    s.f.resume_window_ms = 400;
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");
    {
        s.f.mu.lockUncancelable(testing.io);
        defer s.f.mu.unlock(testing.io);
        s.f.drop_resumes = true;
    }
    s.f.dropDataConnections();
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    try testing.expectEqual(End.restart_needed, try cap.waitEnd());
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 2500);
    // Each resume that brought nothing back waited longer than the one before.
    const resumes = s.f.dataResumes();
    try testing.expect(resumes >= 1 and resumes <= 8);
}

test "data: an idle stream dropped twice, further apart than the resume window, resumes both times" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    s.f.resume_window_ms = 400;
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    defer d.close();
    try cap.waitFor("\"type\":\"resize\"");
    try testing.expectEqual(@as(u32, 400), d.resume_window_ms);
    d.resume_stable_ms = 100; // instead of 5 s, so the test is short; read only when a connection drops
    for (1..3) |n| {
        s.f.dropDataConnections();
        var tries: u32 = 0;
        while (s.f.dataResumes() < n and tries < 400) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
        try testing.expectEqual(@as(u32, @intCast(n)), s.f.dataResumes());
        // No output meanwhile: only the time the resumed connection stayed up ends the streak.
        try testing.io.sleep(.fromMilliseconds(600), .awake);
        try testing.expectEqual(@as(?End, null), cap.ended());
    }
    try s.f.feed(s.block_id, "still here");
    try cap.waitFor("still here");
    try testing.expectEqual(@as(?End, null), cap.ended());
}

test "data: close sends a 1000 close frame that reaches the server" {
    const a = testing.allocator;
    const s = try Setup.init();
    defer s.deinit();
    var cap: Capture = .{ .gpa = a, .io = testing.io };
    defer cap.deinit();
    const d = try Data.openTerminal(a, testing.io, s.ctl, s.session_id, s.block_id, cap.sink());
    try cap.waitFor("\"type\":\"resize\"");
    d.close();
    var codes: [8]u16 = undefined;
    var tries: u32 = 0;
    while (s.f.dataCloseCodes(&codes).len == 0 and tries < 400) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
    try testing.expectEqualSlices(u16, &.{1000}, s.f.dataCloseCodes(&codes));
    try testing.expectEqual(@as(?End, null), cap.ended()); // closing it ourselves is not an end
}
