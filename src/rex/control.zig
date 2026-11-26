//! The Rex control connection: hello and revision negotiation, request/response calls,
//! events, and reconnecting (with the reconnect token, so a short drop keeps the same client
//! and a Rex restart gives a new one).
//!
//! One reader task owns the socket's read side. Calls from any task are matched to their
//! responses by id. The consumer sees server events and `connected` notices through
//! `nextEvent`, and must re-read its state after every `connected` (events during a gap are
//! lost, and after a restart `resumed` is false and nothing is attached any more).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ws = @import("ws.zig");
const wire = @import("wire.zig");

const log = std.log.scoped(.rex_control);

pub const subprotocol = "rex.control.v1";

/// The Rex API revisions this client speaks (newest and oldest); `rweb --version` reports them.
pub const api_max_supported: u32 = 19;
pub const api_min_supported: u32 = 18;

pub const Options = struct {
    socket_path: []const u8,
    /// Newest and oldest API revision the client can use.
    /// 19 adds `event_dropped` (an oversize event no longer closes the connection) and is
    /// otherwise the same as 18 for every call this library makes.
    api_max: u32 = api_max_supported,
    api_min: u32 = api_min_supported,
    client_name: []const u8 = "rweb",
    client_version: []const u8 = "0.0.0",
    /// Reconnect after a drop. Off for one-shot tools and tests that want to see the drop.
    reconnect: bool = true,
    /// Longest wait for a response.
    call_timeout_ms: u32 = 30_000,
    /// Longest wait for a connection's HTTP upgrade, hello and welcome.
    handshake_timeout_ms: u32 = ws.handshake_timeout_ms,
};

pub const Error = error{
    NotConnected,
    ConnectionLost,
    Timeout,
    Closed,
    BadWelcome,
    /// The server closed the connection during the hello (no common revision, say).
    Refused,
    /// The hello does not fit `max_hello` (a very long client name or version).
    HelloTooLarge,
    /// A response that is not a JSON object.
    BadResponse,
    OutOfMemory,
};

/// Most bytes a hello may take. The reconnect token in it is at most `wire.max_reconnect_token`.
pub const max_hello = 1024;

/// Most events held for `nextEvent`, and most bytes of server event JSON among them. Past either,
/// the queued server events are replaced by one `dropped` (see `Control.pushLocked`).
pub const max_queued_events = 1024;
pub const max_queued_event_bytes = 4 * 1024 * 1024;

/// What `nextEvent` returns. Owned by the caller; free with `deinit`.
pub const Event = union(enum) {
    /// A server event: `seq` and the raw JSON of the whole `event` message.
    server: struct { seq: u64, json: []u8 },
    /// Events were lost: Rex dropped one that was too large for the connection (revision 19 and
    /// up; at 18 it would have closed the connection), or the consumer fell so far behind that
    /// this queue dropped some. State may have changed without a notice: re-read it.
    dropped: struct { seq: u64 },
    /// A (re)connection finished its welcome. `resumed` false means a new client: nothing is
    /// attached, and any stream or ticket from before is gone.
    connected: struct { generation: u32, resumed: bool },
    /// The connection dropped; a reconnect follows unless it was turned off.
    disconnected,

    pub fn deinit(e: Event, gpa: Allocator) void {
        switch (e) {
            .server => |s| gpa.free(s.json),
            else => {},
        }
    }
};

/// The answer to a call. Holds the parsed JSON; free with `deinit`.
pub const Response = struct {
    parsed: std.json.Parsed(std.json.Value),
    /// The event `seq` current when the server started the request.
    seq: u64,
    payload: ?std.json.Value,
    err: ?RexError,

    pub const RexError = struct { code: []const u8, message: []const u8, status: u16 };

    pub fn deinit(r: *Response) void {
        r.parsed.deinit();
    }

    /// The payload, or `error.RexError` when the call failed (details in `err`). The payload can
    /// be any JSON value: check its shape before using it.
    pub fn ok(r: Response) error{RexError}!std.json.Value {
        if (r.err != null) return error.RexError;
        return r.payload orelse .{ .object = .empty };
    }
};

const Pending = struct {
    done: Io.Event = .unset,
    /// Raw response message, or null if the connection was lost first.
    text: ?[]u8 = null,
};

pub const Control = struct {
    gpa: Allocator,
    io: Io,
    opts: Options,

    mu: Io.Mutex = .init,
    conn: ?*ws.Conn = null,
    /// The socket of a connection still in its handshake, so `close` can shut it.
    connecting: ?Io.net.Stream = null,
    token: ?[]u8 = null,
    generation: u32 = 0,
    revision: u32 = 0,
    max_message: u64 = 1 << 20,
    /// Set by `close`: no new calls, and no connection is published.
    closing: bool = false,
    /// Callers writing to `conn`; the reader waits for them before freeing a dead connection.
    writers: u32 = 0,
    /// Calls in progress; `close` waits for them before freeing anything.
    calls: u32 = 0,
    /// Broadcast (under `mu`) when `writers` or `calls` drops to zero.
    quiet: Io.Condition = .init,
    next_id: u64 = 1,
    pending: std.StringHashMapUnmanaged(*Pending) = .empty,
    /// Events for `nextEvent`: a ring of `ev_len` events from `ev_head`.
    events: [max_queued_events]Event = undefined,
    ev_head: usize = 0,
    ev_len: usize = 0,
    /// Bytes of server event JSON in `events`.
    ev_bytes: usize = 0,
    signal: Io.Event = .unset,
    reader: ?Io.Future(void) = null,

    /// Connect and complete the welcome. Fails if it cannot, so a caller sees a bad socket or
    /// revision at once; later drops are handled by the reader task.
    pub fn open(gpa: Allocator, io: Io, opts: Options) !*Control {
        const c = try gpa.create(Control);
        errdefer gpa.destroy(c);
        c.* = .{ .gpa = gpa, .io = io, .opts = opts };
        errdefer c.freeState();
        try c.connectOnce();
        c.reader = try io.concurrent(readerMain, .{c});
        return c;
    }

    /// Stop the reader, fail the calls waiting for answers, wait for every call still inside,
    /// and free everything. Calls made from now on fail with `error.Closed`.
    pub fn close(c: *Control) void {
        c.mu.lockUncancelable(c.io);
        c.closing = true;
        // Shut the sockets so a reader blocked in a read, or in a handshake, returns at once
        // (cancelling it is not reliable on its own).
        if (c.conn) |cn| cn.stream.shutdown(c.io, .both) catch {};
        if (c.connecting) |st| st.shutdown(c.io, .both) catch {};
        c.mu.unlock(c.io);
        if (c.reader) |*r| r.cancel(c.io);
        c.reader = null;
        c.failPending();
        // Calls woken above, or failing on the shut socket, still use `mu`, `pending` and `conn`.
        c.mu.lockUncancelable(c.io);
        while (c.calls > 0) c.quiet.waitUncancelable(c.io, &c.mu);
        c.mu.unlock(c.io);
        c.freeState();
        c.gpa.destroy(c);
    }

    fn freeState(c: *Control) void {
        if (c.conn) |cn| cn.deinit(c.gpa);
        c.conn = null;
        if (c.token) |t| c.gpa.free(t);
        c.token = null;
        while (c.popLocked()) |e| e.deinit(c.gpa);
        c.pending.deinit(c.gpa);
    }

    /// The hello, with the reconnect token if there is one, in `buf`.
    fn buildHello(c: *Control, buf: []u8) error{HelloTooLarge}![]const u8 {
        var w: Io.Writer = .fixed(buf);
        std.json.Stringify.value(.{
            .type = "hello",
            .api_revision = c.opts.api_max,
            .api_min_revision = c.opts.api_min,
            .reconnect_token = c.token,
            .client = .{ .kind = "other", .platform = "web", .name = c.opts.client_name, .version = c.opts.client_version },
        }, .{ .emit_null_optional_fields = false }, &w) catch return error.HelloTooLarge;
        return w.buffered();
    }

    /// Open the socket, send the hello (with the reconnect token if there is one), read the
    /// welcome, all within `opts.handshake_timeout_ms`. Replaces `conn`; the caller made sure the
    /// old one is gone. Nothing is published into the Control until every fallible step is done.
    fn connectOnce(c: *Control) !void {
        const gpa = c.gpa;
        const io = c.io;
        var hello_buf: [max_hello]u8 = undefined;
        const hello = try c.buildHello(&hello_buf);

        const stream = try ws.connectUnix(io, c.opts.socket_path);
        // While the handshake runs, `close` can shut the socket. On failure it is unpublished
        // (and the watchdog stopped) before it is closed: defers run in reverse order.
        errdefer stream.close(io);
        try c.setConnecting(stream);
        defer c.setConnecting(null) catch {};
        var dog = try ws.Watchdog.start(io, stream, c.opts.handshake_timeout_ms);
        defer dog.stop(io);

        const cn = try ws.Conn.upgrade(gpa, io, stream, "/api/control", subprotocol, "");
        cn.owns_stream = false; // until published; the errdefer above closes it
        errdefer cn.deinit(gpa);
        cn.max_message = ws.handshake_max_message; // the WELCOME; raised to Rex's limit below
        try cn.writeFrame(.text, hello);
        const m = try cn.readMessage(gpa);
        defer gpa.free(m.data);
        if (m.opcode == .close) return error.Refused;
        if (m.opcode != .text) return error.BadWelcome;
        const w = try wire.parseWelcome(gpa, m.data);
        errdefer if (w.token) |t| gpa.free(t);
        if (w.revision < c.opts.api_min or w.revision > c.opts.api_max) return error.BadWelcome;
        // A watchdog that fired has shut the socket, even if the WELCOME got in first.
        try dog.finish(io);

        // Publish. Nothing below can fail, except finding the Control closing.
        c.mu.lockUncancelable(io);
        defer c.mu.unlock(io);
        if (c.closing) return error.Closed;
        cn.owns_stream = true;
        if (w.max_message) |mm| c.max_message = mm;
        cn.max_message = c.max_message;
        cn.write_timeout_ms = ws.write_timeout_ms; // pongs; a call's request has its own deadline
        if (c.token) |t| gpa.free(t);
        c.token = w.token;
        c.conn = cn;
        c.revision = w.revision;
        c.generation += 1;
        c.pushLocked(.{ .connected = .{ .generation = c.generation, .resumed = w.resumed } });
    }

    fn setConnecting(c: *Control, stream: ?Io.net.Stream) error{Closed}!void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        if (stream != null and c.closing) return error.Closed;
        c.connecting = stream;
    }

    // ---- the event queue: a fixed ring, O(1) push and pop, never fails ----

    fn slot(c: *Control, k: usize) *Event {
        return &c.events[(c.ev_head + k) % max_queued_events];
    }

    /// Queue an event for `nextEvent`. Caller holds `mu`. Never fails and never blocks: when the
    /// ring is full, or server events would pass `max_queued_event_bytes`, the queued server
    /// events are replaced by one `dropped` (which already means "re-read your state").
    /// `connected` and `disconnected` are never dropped (see `mergeNoticesLocked`).
    fn pushLocked(c: *Control, e: Event) void {
        defer c.signal.set(c.io);
        const full = c.ev_len == max_queued_events;
        switch (e) {
            .server => |s| {
                if (full or c.ev_bytes + s.json.len > max_queued_event_bytes) {
                    c.gpa.free(s.json);
                    c.collapseLocked(s.seq);
                    return;
                }
            },
            .dropped => |d| if (full) {
                c.collapseLocked(d.seq);
                return;
            },
            .connected, .disconnected => if (full) c.collapseLocked(null),
        }
        c.appendLocked(e);
    }

    fn appendLocked(c: *Control, e: Event) void {
        if (c.ev_len == max_queued_events) c.mergeNoticesLocked();
        if (c.ev_len == max_queued_events) {
            // Cannot happen: a full ring of notices always merges (see `mergeNoticesLocked`).
            // Keep the newest rather than fail.
            c.popLocked().?.deinit(c.gpa);
        }
        if (e == .server) c.ev_bytes += e.server.json.len;
        c.slot(c.ev_len).* = e;
        c.ev_len += 1;
    }

    fn popLocked(c: *Control) ?Event {
        if (c.ev_len == 0) return null;
        const e = c.events[c.ev_head];
        c.ev_head = (c.ev_head + 1) % max_queued_events;
        c.ev_len -= 1;
        if (e == .server) c.ev_bytes -= e.server.json.len;
        return e;
    }

    /// Drop every queued `server` and `dropped` event, keeping the connection notices in order,
    /// and queue one `dropped` carrying the latest `seq` lost (`seq` included, if not null).
    fn collapseLocked(c: *Control, seq: ?u64) void {
        var lost = seq;
        var kept: usize = 0;
        for (0..c.ev_len) |k| {
            const e = c.slot(k).*;
            switch (e) {
                .server => |s| {
                    lost = @max(lost orelse 0, s.seq);
                    c.gpa.free(s.json);
                },
                .dropped => |d| lost = @max(lost orelse 0, d.seq),
                .connected, .disconnected => {
                    c.slot(kept).* = e;
                    kept += 1;
                },
            }
        }
        c.ev_len = kept;
        c.ev_bytes = 0;
        if (lost) |s| c.appendLocked(.{ .dropped = .{ .seq = s } });
    }

    /// The ring is full of connection notices (only a consumer that has not read for about a
    /// thousand reconnects gets here). Merge runs that tell the consumer nothing more than their
    /// result: two `disconnected` in a row become one, two `connected` become the later one, and
    /// `connected, disconnected, connected` becomes `disconnected, connected` (the later
    /// generation; not resumed if either was not). A consumer re-reads its state after every
    /// `connected` anyway. A run of notices shrinks to at most three, so a full ring always
    /// makes room.
    fn mergeNoticesLocked(c: *Control) void {
        var out: usize = 0;
        for (0..c.ev_len) |k| {
            c.slot(out).* = c.slot(k).*;
            out += 1;
            while (true) {
                if (out >= 2) {
                    const x = c.slot(out - 2);
                    const y = c.slot(out - 1);
                    if (x.* == .disconnected and y.* == .disconnected) {
                        out -= 1;
                        continue;
                    }
                    if (x.* == .connected and y.* == .connected) {
                        x.* = .{ .connected = .{ .generation = y.connected.generation, .resumed = x.connected.resumed and y.connected.resumed } };
                        out -= 1;
                        continue;
                    }
                }
                if (out >= 3) {
                    const x = c.slot(out - 3);
                    const y = c.slot(out - 2);
                    const z = c.slot(out - 1);
                    if (x.* == .connected and y.* == .disconnected and z.* == .connected) {
                        const merged: Event = .{ .connected = .{ .generation = z.connected.generation, .resumed = x.connected.resumed and z.connected.resumed } };
                        x.* = .disconnected;
                        y.* = merged;
                        out -= 1;
                        continue;
                    }
                    if (x.* == .disconnected and y.* == .disconnected and z.* == .connected) {
                        y.* = z.*;
                        out -= 1;
                        continue;
                    }
                }
                break;
            }
        }
        c.ev_len = out;
    }

    /// The next event, waiting up to `timeout_ms`; null on timeout. Caller calls `deinit` on it.
    pub fn nextEvent(c: *Control, timeout_ms: u32) !?Event {
        while (true) {
            c.mu.lockUncancelable(c.io);
            if (c.popLocked()) |e| {
                c.mu.unlock(c.io);
                return e;
            }
            c.signal.reset();
            c.mu.unlock(c.io);
            c.signal.waitTimeout(c.io, .{ .duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake } }) catch |e| switch (e) {
                error.Timeout => return null,
                else => |x| return x,
            };
        }
    }

    /// The largest message the connection takes (the server's limit, at most
    /// `wire.client_max_message`).
    pub fn maxMessage(c: *Control) u64 {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.max_message;
    }

    pub fn isConnected(c: *Control) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.conn != null;
    }

    /// Call `method` with `payload_json` (a JSON object text, or null for none) and wait for
    /// the response, up to `opts.call_timeout_ms`. A failed call comes back as a `Response` with
    /// `err` set; transport problems are Zig errors.
    pub fn call(c: *Control, method: []const u8, payload_json: ?[]const u8) !Response {
        return c.callTimeout(method, payload_json, c.opts.call_timeout_ms);
    }

    /// As `call`, waiting at most `timeout_ms` for the answer.
    pub fn callTimeout(c: *Control, method: []const u8, payload_json: ?[]const u8, timeout_ms: u32) !Response {
        const gpa = c.gpa;
        var pend: Pending = .{};
        var idbuf: [24]u8 = undefined;
        var id: []const u8 = undefined;
        var cn: *ws.Conn = undefined;
        var max_message: u64 = undefined;
        {
            // One locked step: a call is either refused, or registered where `close` and the
            // reader's `failPending` will find it.
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            if (c.closing) return error.Closed;
            cn = c.conn orelse return error.NotConnected;
            id = std.fmt.bufPrint(&idbuf, "{d}", .{c.next_id}) catch unreachable;
            try c.pending.put(gpa, id, &pend);
            c.next_id += 1;
            max_message = c.max_message;
            c.calls += 1;
            c.writers += 1;
        }
        // Runs last: once `calls` is back down, `close` may free everything.
        defer c.endCall();
        // Whatever way this returns: forget the call, and free a response that arrived after
        // we stopped waiting (the dispatcher writes `pend.text` under `mu`).
        defer {
            c.mu.lockUncancelable(c.io);
            _ = c.pending.remove(id);
            const leftover = pend.text;
            pend.text = null;
            c.mu.unlock(c.io);
            if (leftover) |t| gpa.free(t);
        }
        var writing = true;
        defer if (writing) c.releaseWriter();

        const method_json = try std.json.Stringify.valueAlloc(gpa, method, .{});
        defer gpa.free(method_json);
        const req = try std.fmt.allocPrint(gpa, "{{\"type\":\"request\",\"id\":\"{s}\",\"method\":{s}{s}{s}}}", .{
            id,
            method_json,
            if (payload_json != null) ",\"payload\":" else "",
            payload_json orelse "",
        });
        defer gpa.free(req);
        if (req.len > max_message) return error.MessageTooLarge;
        // The request must be written within the call's own timeout: a Rex that stops reading
        // gets its connection shut (by the write's deadline) rather than holding this task.
        const wrote = cn.writeFrameTimeout(.text, req, timeout_ms);
        // A failed write may have left part of a frame on the socket, and every frame after it
        // would be read as garbage: shut it, so the reader drops the connection and reconnects.
        // (`writers` keeps the connection alive until `releaseWriter`.) Only a write that could
        // not start its deadline wrote nothing.
        if (wrote) |_| {} else |e| if (e != error.ConcurrencyUnavailable) cn.stream.shutdown(c.io, .both) catch {};
        c.releaseWriter();
        writing = false;
        wrote catch return error.ConnectionLost;

        pend.done.waitTimeout(c.io, .{ .duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake } }) catch |e| switch (e) {
            error.Timeout => return error.Timeout,
            else => |x| return x,
        };
        c.mu.lockUncancelable(c.io);
        _ = c.pending.remove(id);
        const taken = pend.text;
        pend.text = null;
        c.mu.unlock(c.io);
        const text = taken orelse return error.ConnectionLost;
        defer gpa.free(text);

        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        errdefer parsed.deinit();
        if (parsed.value != .object) return error.BadResponse; // `dispatch` checked; cheap to keep
        const o = parsed.value.object;
        var r: Response = .{
            .parsed = parsed,
            .seq = if (o.get("seq")) |s| (if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0) else 0,
            .payload = o.get("payload"),
            .err = null,
        };
        if (o.get("error")) |e| if (e == .object) {
            const eo = e.object;
            r.err = .{
                .code = if (eo.get("code")) |v| (if (v == .string) v.string else "internal") else "internal",
                .message = if (eo.get("message")) |v| (if (v == .string) v.string else "") else "",
                .status = if (eo.get("status")) |v| (if (v == .integer and v.integer > 0 and v.integer < 1000) @intCast(v.integer) else 500) else 500,
            };
        };
        return r;
    }

    fn releaseWriter(c: *Control) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.writers -= 1;
        if (c.writers == 0) c.quiet.broadcast(c.io);
    }

    fn endCall(c: *Control) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        c.calls -= 1;
        if (c.calls == 0) c.quiet.broadcast(c.io);
    }

    /// Fail every waiting call (the connection is gone; the server may still have run them).
    fn failPending(c: *Control) void {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        var it = c.pending.iterator();
        while (it.next()) |e| e.value_ptr.*.done.set(c.io);
        c.pending.clearRetainingCapacity();
    }

    // ---- reader task ----

    fn readerMain(c: *Control) void {
        var backoff_ms: u32 = 100;
        while (true) {
            c.readLoop();
            // The connection ended.
            c.mu.lockUncancelable(c.io);
            const closing = c.closing;
            const dead = c.conn;
            c.conn = null; // no new writers from here on
            if (!closing) c.pushLocked(.disconnected);
            // Writers already on it fail fast once the socket is shut; wait them out, even when
            // cancelled (`close` cancels this task and frees the Control afterwards).
            if (dead) |cn| {
                cn.stream.shutdown(c.io, .both) catch {};
                while (c.writers > 0) c.quiet.waitUncancelable(c.io, &c.mu);
            }
            c.mu.unlock(c.io);
            if (dead) |cn| cn.deinit(c.gpa);
            c.failPending();
            if (closing or !c.opts.reconnect) return;

            while (true) {
                // `close` may have come while Rex is down; its cancel request can be used up by a
                // connect that fails anyway, so look at `closing` itself on every round.
                if (c.isClosing()) return;
                c.io.sleep(.fromMilliseconds(backoff_ms), .awake) catch return;
                if (c.isClosing()) return;
                if (c.connectOnce()) |_| {
                    backoff_ms = 100;
                    break;
                } else |e| {
                    if (e == error.Closed or e == error.Canceled) return;
                    log.debug("reconnect: {t}", .{e});
                    backoff_ms = @min(backoff_ms * 2, 2000);
                }
            }
        }
    }

    fn isClosing(c: *Control) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.closing;
    }

    fn readLoop(c: *Control) void {
        const gpa = c.gpa;
        c.mu.lockUncancelable(c.io);
        const conn = c.conn;
        c.mu.unlock(c.io);
        const cn = conn orelse return;
        while (true) {
            const m = cn.readMessage(gpa) catch return;
            defer gpa.free(m.data);
            if (m.opcode != .text) return; // close or something we do not speak
            c.dispatch(m.data) catch |e| {
                log.debug("dropping a message: {t}", .{e});
            };
        }
    }

    fn dispatch(c: *Control, text: []const u8) !void {
        const gpa = c.gpa;
        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        defer parsed.deinit();
        if (parsed.value != .object) return;
        const o = parsed.value.object;
        const ty = o.get("type") orelse return;
        if (ty != .string) return;
        if (std.mem.eql(u8, ty.string, "response")) {
            const id = o.get("id") orelse return;
            if (id != .string) return;
            const copy = try gpa.dupe(u8, text);
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            if (c.pending.get(id.string)) |p| {
                // A second response for the same id replaces an unclaimed first one.
                if (p.text) |old| gpa.free(old);
                p.text = copy;
                p.done.set(c.io);
            } else gpa.free(copy); // a late answer to a call that timed out
        } else if (std.mem.eql(u8, ty.string, "event")) {
            const seq: u64 = if (o.get("seq")) |s| (if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0) else 0;
            const is_dropped = blk: {
                const pl = o.get("payload") orelse break :blk false;
                if (pl != .object) break :blk false;
                const t = pl.object.get("type") orelse break :blk false;
                break :blk t == .string and std.mem.eql(u8, t.string, "event_dropped");
            };
            if (is_dropped) {
                c.mu.lockUncancelable(c.io);
                defer c.mu.unlock(c.io);
                return c.pushLocked(.{ .dropped = .{ .seq = seq } });
            }
            const copy = try gpa.dupe(u8, text);
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            c.pushLocked(.{ .server = .{ .seq = seq, .json = copy } });
        }
        // Skip a type we do not know: newer servers add them.
    }
};

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");

test "control: connects, negotiates and calls" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    try testing.expectEqual(@as(u32, 18), c.revision); // the fake speaks 18

    var r = try c.call("session.create", "{\"label\":\"rweb-test-ctl\"}");
    defer r.deinit();
    const p = try r.ok();
    try testing.expect(std.mem.startsWith(u8, p.object.get("session_id").?.string, "session:"));

    var bad = try c.call("nope", null);
    defer bad.deinit();
    try testing.expectEqualStrings("method_not_found", bad.err.?.code);
    try testing.expectError(error.RexError, bad.ok());

    const e = (try c.nextEvent(1000)).?;
    defer e.deinit(testing.allocator);
    try testing.expect(e == .connected and e.connected.generation == 1 and !e.connected.resumed);
}

test "control: concurrent calls are matched to their responses" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    const T = struct {
        fn run(ctl: *Control, label: []const u8, ok: *bool) void {
            const body = std.fmt.allocPrint(testing.allocator, "{{\"label\":\"{s}\"}}", .{label}) catch return;
            defer testing.allocator.free(body);
            var r = ctl.call("session.create", body) catch return;
            defer r.deinit();
            ok.* = r.err == null;
        }
    };
    var oks: [8]bool = @splat(false);
    var group: Io.Group = .init;
    for (&oks, 0..) |*ok, i| {
        var lb: [16]u8 = undefined;
        const label = std.fmt.bufPrint(&lb, "rweb-test-{d}", .{i}) catch unreachable;
        _ = label;
        try group.concurrent(testing.io, T.run, .{ c, "rweb-test-x", ok });
    }
    try group.await(testing.io);
    for (oks) |ok| try testing.expect(ok);
    var list = try c.call("session.list", null);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 8), (try list.ok()).object.get("sessions").?.array.items.len);
}

test "control: no common revision is refused" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    try testing.expectError(error.Refused, Control.open(testing.allocator, testing.io, .{ .socket_path = f.path, .api_max = 25, .api_min = 19 }));
}

test "control: a missing socket fails to open" {
    try testing.expect(std.meta.isError(Control.open(testing.allocator, testing.io, .{ .socket_path = "/tmp/rweb-no-such.sock" })));
}

test "control: after a server restart it reconnects as a new client" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    var made = try c.call("session.create", "{\"label\":\"rweb-test-restart\"}");
    made.deinit();

    try f.restart();

    var saw_disconnect = false;
    var generation: u32 = 1;
    var resumed = true;
    var tries: u32 = 0;
    while (tries < 50 and generation == 1) : (tries += 1) {
        const e = (try c.nextEvent(200)) orelse continue;
        defer e.deinit(testing.allocator);
        switch (e) {
            .disconnected => saw_disconnect = true,
            .connected => |cn| {
                generation = cn.generation;
                resumed = cn.resumed;
            },
            else => {},
        }
    }
    try testing.expect(saw_disconnect);
    try testing.expectEqual(@as(u32, 2), generation);
    try testing.expect(!resumed); // finding 11: the old token is refused
    var list = try c.call("session.list", null);
    defer list.deinit();
    try testing.expectEqual(@as(usize, 1), (try list.ok()).object.get("sessions").?.array.items.len);
}

test "control: a short drop resumes the same client" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    // Drop only the control connection, as a lost network would.
    f.dropControlConnections();
    var generation: u32 = 1;
    var resumed = false;
    var tries: u32 = 0;
    while (tries < 50 and generation == 1) : (tries += 1) {
        const e = (try c.nextEvent(200)) orelse continue;
        defer e.deinit(testing.allocator);
        if (e == .connected) {
            generation = e.connected.generation;
            resumed = e.connected.resumed;
        }
    }
    try testing.expectEqual(@as(u32, 2), generation);
    try testing.expect(resumed);
}

test "live: session.list and server.version on a real Rex (needs REX_SOCKET)" {
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = sock });
    defer c.close();
    try testing.expect(c.revision >= 18 and c.revision <= 19);
    std.debug.print("\nlive: negotiated API revision {d}\n", .{c.revision});
    var l = try c.call("session.list", null);
    defer l.deinit();
    try testing.expect((try l.ok()).object.get("sessions") != null);
    var v = try c.call("server.version", null);
    defer v.deinit();
    _ = try v.ok();
}

test "control: a fake that speaks 19 is used at 19, and event_dropped is surfaced" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    f.api_max = 19;
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    try testing.expectEqual(@as(u32, 19), c.revision);
    var first = (try c.nextEvent(1000)).?; // connected
    first.deinit(testing.allocator);
    f.broadcastEvent("{\"type\":\"event_dropped\"}");
    f.broadcastEvent("{\"type\":\"hosts_changed\"}");
    const e1 = (try c.nextEvent(2000)).?;
    defer e1.deinit(testing.allocator);
    try testing.expect(e1 == .dropped);
    const e2 = (try c.nextEvent(2000)).?;
    defer e2.deinit(testing.allocator);
    try testing.expect(e2 == .server);
    try testing.expect(e2.server.seq > e1.dropped.seq);
}

test "control: an old server (18 only) still works with a client that asks 18 to 19" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    f.api_max = 18;
    const c = try Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer c.close();
    try testing.expectEqual(@as(u32, 18), c.revision);
}

test "control: a hello too large for its buffer is an error, not an assertion" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const long: [max_hello]u8 = @splat('n');
    try testing.expectError(error.HelloTooLarge, Control.open(testing.allocator, testing.io, .{ .socket_path = f.path, .client_name = &long }));
}

/// A Control with no connection, for the queue and dispatch alone.
fn bareControl() !*Control {
    const c = try testing.allocator.create(Control);
    c.* = .{ .gpa = testing.allocator, .io = testing.io, .opts = .{ .socket_path = "" } };
    return c;
}

fn freeBare(c: *Control) void {
    c.freeState();
    testing.allocator.destroy(c);
}

fn pushServer(c: *Control, seq: u64, len: usize) !void {
    const json = try testing.allocator.alloc(u8, len);
    @memset(json, 'x');
    c.pushLocked(.{ .server = .{ .seq = seq, .json = json } });
}

test "control: the event queue is a bounded ring; overflow becomes one dropped, notices stay" {
    const c = try bareControl();
    defer freeBare(c);
    c.pushLocked(.{ .connected = .{ .generation = 1, .resumed = false } });
    var seq: u64 = 1;
    while (seq <= 3000) : (seq += 1) {
        try pushServer(c, seq, 100);
        if (seq == 1500) {
            c.pushLocked(.disconnected);
            c.pushLocked(.{ .connected = .{ .generation = 2, .resumed = true } });
        }
        try testing.expect(c.ev_len <= max_queued_events);
    }
    var got: std.ArrayList(Event) = .empty;
    defer {
        for (got.items) |e| e.deinit(testing.allocator);
        got.deinit(testing.allocator);
    }
    while (c.popLocked()) |e| try got.append(testing.allocator, e);
    try testing.expectEqual(@as(usize, 0), c.ev_bytes);
    try testing.expect(got.items.len <= max_queued_events);
    // The notices, in order, then one dropped, then the server events since.
    try testing.expect(got.items[0] == .connected and got.items[0].connected.generation == 1);
    try testing.expect(got.items[1] == .disconnected);
    try testing.expect(got.items[2] == .connected and got.items[2].connected.generation == 2);
    try testing.expect(got.items[3] == .dropped);
    var last_seq = got.items[3].dropped.seq;
    for (got.items[4..]) |e| {
        try testing.expect(e == .server);
        try testing.expect(e.server.seq > last_seq);
        last_seq = e.server.seq;
    }
    try testing.expectEqual(@as(u64, 3000), last_seq);
}

test "control: server events have a byte budget" {
    const c = try bareControl();
    defer freeBare(c);
    for (1..6) |i| try pushServer(c, i, 1024 * 1024);
    try testing.expect(c.ev_bytes <= max_queued_event_bytes);
    // Four fit exactly; the fifth replaced them with a dropped carrying its seq.
    try testing.expectEqual(@as(usize, 1), c.ev_len);
    const e = c.popLocked().?;
    try testing.expect(e == .dropped and e.dropped.seq == 5);
    // One event over the whole budget is dropped too.
    try pushServer(c, 6, max_queued_event_bytes + 1);
    try testing.expect(c.popLocked().? == .dropped);
}

test "control: a queue full of connection notices merges them without losing the last state" {
    const c = try bareControl();
    defer freeBare(c);
    c.pushLocked(.{ .connected = .{ .generation = 1, .resumed = false } });
    var gen: u32 = 2;
    while (gen < 3000) : (gen += 1) {
        c.pushLocked(.disconnected);
        c.pushLocked(.{ .connected = .{ .generation = gen, .resumed = gen != 700 } });
        try testing.expect(c.ev_len <= max_queued_events);
    }
    try pushServer(c, 1, 10);
    var last_connected: ?Event = null;
    var saw_unresumed = false;
    var prev: ?std.meta.Tag(Event) = null;
    while (c.popLocked()) |e| {
        defer e.deinit(testing.allocator);
        if (e == .connected) {
            last_connected = e;
            if (!e.connected.resumed) saw_unresumed = true;
        }
        // Merged notices still alternate.
        if (prev) |p| if (e != .server) try testing.expect(p != std.meta.activeTag(e));
        prev = std.meta.activeTag(e);
    }
    try testing.expectEqual(@as(u32, 2999), last_connected.?.connected.generation);
    try testing.expect(saw_unresumed); // generation 700 was a new client: the merge keeps that
}

test "control: with a producer faster than the consumer, events are bounded and the last ones arrive" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const c = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer c.close();
    for (0..3000) |_| f.broadcastEvent("{\"type\":\"hosts_changed\"}");
    // A call answered after them: every event before it has been queued.
    var r = try c.call("session.list", null);
    r.deinit();
    var n: usize = 0;
    var dropped = false;
    var last: u64 = 0;
    while (try c.nextEvent(50)) |e| {
        defer e.deinit(a);
        n += 1;
        switch (e) {
            .dropped => dropped = true,
            .server => |s| last = s.seq,
            else => {},
        }
    }
    try testing.expect(n <= max_queued_events);
    try testing.expect(dropped);
    try testing.expectEqual(@as(u64, 3000), last);
}

test "control: open publishes nothing that a failed step frees (every allocation failing in turn)" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    var i: usize = 0;
    while (i < 500) : (i += 1) {
        var fa = std.testing.FailingAllocator.init(a, .{ .fail_index = i });
        const c = Control.open(fa.allocator(), testing.io, .{ .socket_path = f.path, .reconnect = false }) catch |e| {
            try testing.expect(fa.has_induced_failure);
            try testing.expectEqual(error.OutOfMemory, e);
            continue;
        };
        c.close();
        if (!fa.has_induced_failure) break;
    } else return error.TestUnexpectedResult;
}

test "control: a second response for the same id frees the first" {
    const c = try bareControl();
    defer freeBare(c);
    var pend: Pending = .{};
    try c.pending.put(testing.allocator, "7", &pend);
    try c.dispatch("{\"type\":\"response\",\"id\":\"7\",\"payload\":{\"n\":1}}");
    try c.dispatch("{\"type\":\"response\",\"id\":\"7\",\"payload\":{\"n\":2}}");
    _ = c.pending.remove("7");
    try testing.expect(std.mem.indexOf(u8, pend.text.?, "\"n\":2") != null);
    testing.allocator.free(pend.text.?);
}

test "control: close waits for a call still waiting for its answer" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const c = try Control.open(a, testing.io, .{ .socket_path = f.path });
    const T = struct {
        fn run(ctl: *Control, out: *?anyerror) void {
            if (ctl.call("rweb.test.no_answer", null)) |r| {
                var rr = r;
                rr.deinit();
            } else |e| out.* = e;
        }
    };
    var result: ?anyerror = null;
    var group: Io.Group = .init;
    try group.concurrent(testing.io, T.run, .{ c, &result });
    var tries: u32 = 0;
    while (tries < 400) : (tries += 1) {
        c.mu.lockUncancelable(testing.io);
        const waiting = c.pending.count() == 1;
        c.mu.unlock(testing.io);
        if (waiting) break;
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    c.close(); // returns only once the call is out of the Control
    try group.await(testing.io);
    try testing.expectEqual(@as(?anyerror, error.ConnectionLost), result);
}

test "control: the handshake has a deadline" {
    const a = testing.allocator;
    const s = try fake.Silent.start(a, testing.io, null);
    defer s.deinit();
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    try testing.expect(std.meta.isError(Control.open(a, testing.io, .{ .socket_path = s.path, .handshake_timeout_ms = 200 })));
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5000);
}

test "control: close shuts a reconnect still in its handshake" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    const path = try a.dupe(u8, f.path);
    defer a.free(path);
    const c = try Control.open(a, testing.io, .{ .socket_path = path, .handshake_timeout_ms = 60_000 });
    // The server goes away, and something that never answers takes its socket.
    f.deinit();
    const s = try fake.Silent.start(a, testing.io, path);
    defer s.deinit();
    var tries: u32 = 0;
    while (s.acceptedCount() == 0 and tries < 1000) : (tries += 1) try testing.io.sleep(.fromMilliseconds(5), .awake);
    try testing.expect(s.acceptedCount() > 0);
    try testing.io.sleep(.fromMilliseconds(50), .awake); // into the upgrade's read
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    c.close();
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5000);
}

test "control: a write that fails part-way drops the connection, and it reconnects" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const c = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer c.close();
    var first = (try c.nextEvent(1000)).?;
    first.deinit(a);
    // Writes on the connection now fail, but reads still work: without dropping the connection
    // the reader would wait on it forever, and every call after would fail.
    {
        c.mu.lockUncancelable(testing.io);
        defer c.mu.unlock(testing.io);
        try c.conn.?.stream.shutdown(testing.io, .send);
    }
    try testing.expectError(error.ConnectionLost, c.call("session.list", null));
    var reconnected = false;
    var tries: u32 = 0;
    while (!reconnected and tries < 50) : (tries += 1) {
        const e = (try c.nextEvent(100)) orelse continue;
        defer e.deinit(a);
        if (e == .connected and e.connected.generation == 2) reconnected = true;
    }
    try testing.expect(reconnected);
    var r = try c.call("session.list", null);
    r.deinit();
}

test "control: a Rex that stops reading cannot hold a call's write past the call's timeout" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    // The fake reads the hello and answers it, then reads nothing more.
    f.stall_control_reads = true;
    const c = try Control.open(a, testing.io, .{ .socket_path = f.path, .call_timeout_ms = 300 });
    defer c.close();
    var first = (try c.nextEvent(1000)).?;
    first.deinit(a);
    try testing.expectEqual(@as(?u32, ws.write_timeout_ms), c.conn.?.write_timeout_ms); // pongs
    // A request far larger than the socket buffers (but within the message limit): its write
    // blocks once they are full, and the call's own timeout shuts the connection.
    const filler = try a.alloc(u8, 900 * 1024);
    defer a.free(filler);
    @memset(filler, 'x');
    const body = try std.fmt.allocPrint(a, "{{\"label\":\"{s}\"}}", .{filler});
    defer a.free(body);
    const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
    try testing.expectError(error.ConnectionLost, c.call("session.create", body));
    try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5000);
    {
        f.mu.lockUncancelable(testing.io);
        defer f.mu.unlock(testing.io);
        f.stall_control_reads = false;
    }
    // The reader saw the shut socket and reconnected; calls work again.
    var reconnected = false;
    var tries: u32 = 0;
    while (!reconnected and tries < 50) : (tries += 1) {
        const e = (try c.nextEvent(100)) orelse continue;
        defer e.deinit(a);
        if (e == .connected and e.connected.generation == 2) reconnected = true;
    }
    try testing.expect(reconnected);
    var r = try c.call("session.list", null);
    r.deinit();
}

test "control: close while Rex is down returns at once" {
    const a = testing.allocator;
    // Close at different moments of the reconnect loop: in its sleep, in a connect that fails.
    for (0..12) |i| {
        const f = try fake.Fake.start(a, testing.io);
        const path = try a.dupe(u8, f.path);
        defer a.free(path);
        const c = try Control.open(a, testing.io, .{ .socket_path = path });
        f.deinit(); // Rex is gone, and so is its socket
        try testing.io.sleep(.fromMilliseconds(@intCast(i * 37 % 300)), .awake);
        const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
        c.close();
        try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 1000);
    }
}

test "control: a connection's limit is set from its first read" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const c = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer c.close();
    c.mu.lockUncancelable(testing.io);
    defer c.mu.unlock(testing.io);
    try testing.expectEqual(@as(u64, 1 << 20), c.conn.?.max_message); // the fake's WELCOME limit
}
