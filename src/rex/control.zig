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


pub const Options = struct {
    socket_path: []const u8,
    /// Newest and oldest API revision the client can use.
    api_max: u32 = 18,
    api_min: u32 = 18,
    client_name: []const u8 = "rweb",
    client_version: []const u8 = "0.0.0",
    /// Reconnect after a drop. Off for one-shot tools and tests that want to see the drop.
    reconnect: bool = true,
    /// Longest wait for a response.
    call_timeout_ms: u32 = 30_000,
};

pub const Error = error{
    NotConnected,
    ConnectionLost,
    Timeout,
    Closed,
    BadWelcome,
    /// The server closed the connection during the hello (no common revision, say).
    Refused,
    OutOfMemory,
};

/// What `nextEvent` returns. Owned by the caller; free with `deinit`.
pub const Event = union(enum) {
    /// A server event: `seq` and the raw JSON of the whole `event` message.
    server: struct { seq: u64, json: []u8 },
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

    /// The payload, or `error.RexError` when the call failed (details in `err`).
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
    token: ?[]u8 = null,
    generation: u32 = 0,
    revision: u32 = 0,
    max_message: u64 = 1 << 20,
    closing: bool = false,
    next_id: u64 = 1,
    pending: std.StringHashMapUnmanaged(*Pending) = .empty,
    events: std.ArrayList(Event) = .empty,
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

    pub fn close(c: *Control) void {
        c.mu.lockUncancelable(c.io);
        c.closing = true;
        c.mu.unlock(c.io);
        if (c.reader) |*r| r.cancel(c.io);
        c.reader = null;
        c.failPending();
        c.freeState();
        c.gpa.destroy(c);
    }

    fn freeState(c: *Control) void {
        if (c.conn) |cn| cn.deinit(c.gpa);
        c.conn = null;
        if (c.token) |t| c.gpa.free(t);
        c.token = null;
        for (c.events.items) |e| e.deinit(c.gpa);
        c.events.deinit(c.gpa);
        c.pending.deinit(c.gpa);
    }

    /// Open the socket, send the hello (with the reconnect token if there is one), read the
    /// welcome. Replaces `conn`; the caller made sure the old one is gone.
    fn connectOnce(c: *Control) !void {
        const gpa = c.gpa;
        const cn = try ws.Conn.connect(gpa, c.io, c.opts.socket_path, "/api/control", subprotocol);
        errdefer cn.deinit(gpa);

        const hello = try std.json.Stringify.valueAlloc(gpa, .{
            .type = "hello",
            .api_revision = c.opts.api_max,
            .api_min_revision = c.opts.api_min,
            .reconnect_token = c.token,
            .client = .{ .kind = "other", .platform = "web", .name = c.opts.client_name, .version = c.opts.client_version },
        }, .{ .emit_null_optional_fields = false });
        defer gpa.free(hello);
        std.debug.assert(hello.len < 512);
        try cn.writeFrame(.text, hello);

        const m = try cn.readMessage(gpa);
        defer gpa.free(m.data);
        if (m.opcode == .close) return error.Refused;
        if (m.opcode != .text) return error.BadWelcome;
        const w = wire.parseWelcome(gpa, m.data) catch |e| switch (e) {
            error.OutOfMemory => return error.OutOfMemory,
            error.BadWelcome => return error.BadWelcome,
        };
        errdefer if (w.token) |t| gpa.free(t);
        if (w.revision < c.opts.api_min or w.revision > c.opts.api_max) return error.BadWelcome;
        if (w.max_message) |mm| c.max_message = mm;
        cn.max_message = c.max_message;
        const new_token = w.token;
        const resumed = w.resumed;
        const rev = w.revision;

        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        if (c.token) |t| gpa.free(t);
        c.token = new_token;
        c.conn = cn;
        c.revision = rev;
        c.generation += 1;
        try c.pushLocked(.{ .connected = .{ .generation = c.generation, .resumed = resumed } });
    }

    fn pushLocked(c: *Control, e: Event) !void {
        try c.events.append(c.gpa, e);
        c.signal.set(c.io);
    }

    /// The next event, waiting up to `timeout_ms`; null on timeout. Caller calls `deinit` on it.
    pub fn nextEvent(c: *Control, timeout_ms: u32) !?Event {
        while (true) {
            c.mu.lockUncancelable(c.io);
            if (c.events.items.len > 0) {
                const e = c.events.orderedRemove(0);
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

    pub fn isConnected(c: *Control) bool {
        c.mu.lockUncancelable(c.io);
        defer c.mu.unlock(c.io);
        return c.conn != null;
    }

    /// Call `method` with `payload_json` (a JSON object text, or null for none) and wait for
    /// the response. A failed call comes back as a `Response` with `err` set; transport
    /// problems are Zig errors.
    pub fn call(c: *Control, method: []const u8, payload_json: ?[]const u8) !Response {
        const gpa = c.gpa;
        var pend: Pending = .{};

        c.mu.lockUncancelable(c.io);
        const cn = c.conn orelse {
            c.mu.unlock(c.io);
            return error.NotConnected;
        };
        const id_num = c.next_id;
        c.next_id += 1;
        var idbuf: [24]u8 = undefined;
        const id_tmp = std.fmt.bufPrint(&idbuf, "{d}", .{id_num}) catch unreachable;
        const id = gpa.dupe(u8, id_tmp) catch |e| {
            c.mu.unlock(c.io);
            return e;
        };
        defer gpa.free(id);
        c.pending.put(gpa, id, &pend) catch |e| {
            c.mu.unlock(c.io);
            return e;
        };
        c.mu.unlock(c.io);
        errdefer self_remove: {
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            _ = c.pending.remove(id);
            break :self_remove;
        }

        const id_json = try std.json.Stringify.valueAlloc(gpa, id, .{});
        defer gpa.free(id_json);
        const method_json = try std.json.Stringify.valueAlloc(gpa, method, .{});
        defer gpa.free(method_json);
        const req = try std.fmt.allocPrint(gpa, "{{\"type\":\"request\",\"id\":{s},\"method\":{s}{s}{s}}}", .{
            id_json,
            method_json,
            if (payload_json != null) ",\"payload\":" else "",
            payload_json orelse "",
        });
        defer gpa.free(req);
        if (req.len > c.max_message) return error.MessageTooLarge;
        cn.writeFrame(.text, req) catch return error.ConnectionLost;

        pend.done.waitTimeout(c.io, .{ .duration = .{ .raw = .fromMilliseconds(c.opts.call_timeout_ms), .clock = .awake } }) catch |e| switch (e) {
            error.Timeout => return error.Timeout,
            else => |x| return x,
        };
        c.mu.lockUncancelable(c.io);
        _ = c.pending.remove(id);
        c.mu.unlock(c.io);
        const text = pend.text orelse return error.ConnectionLost;
        defer gpa.free(text);

        var parsed = try std.json.parseFromSlice(std.json.Value, gpa, text, .{});
        errdefer parsed.deinit();
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
            if (c.conn) |cn| {
                cn.deinit(c.gpa);
                c.conn = null;
            }
            if (!closing) c.pushLocked(.disconnected) catch {};
            c.mu.unlock(c.io);
            c.failPending();
            if (closing or !c.opts.reconnect) return;

            while (true) {
                c.io.sleep(.fromMilliseconds(backoff_ms), .awake) catch return;
                if (c.connectOnce()) |_| {
                    backoff_ms = 100;
                    break;
                } else |e| {
                    log.debug("reconnect: {t}", .{e});
                    backoff_ms = @min(backoff_ms * 2, 2000);
                }
            }
        }
    }

    fn readLoop(c: *Control) void {
        const gpa = c.gpa;
        const cn = c.conn orelse return;
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
                p.text = copy;
                p.done.set(c.io);
            } else gpa.free(copy); // a late answer to a call that timed out
        } else if (std.mem.eql(u8, ty.string, "event")) {
            const seq: u64 = if (o.get("seq")) |s| (if (s == .integer and s.integer >= 0) @intCast(s.integer) else 0) else 0;
            const copy = try gpa.dupe(u8, text);
            errdefer gpa.free(copy);
            c.mu.lockUncancelable(c.io);
            defer c.mu.unlock(c.io);
            try c.pushLocked(.{ .server = .{ .seq = seq, .json = copy } });
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
    try testing.expectEqual(@as(u32, 18), c.revision);

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
    try testing.expectEqual(@as(u32, 18), c.revision);
    var l = try c.call("session.list", null);
    defer l.deinit();
    try testing.expect((try l.ok()).object.get("sessions") != null);
    var v = try c.call("server.version", null);
    defer v.deinit();
    _ = try v.ok();
}
