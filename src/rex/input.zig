//! One ordered input queue per terminal.
//!
//! Rex runs `terminal.write` calls concurrently, so two in flight can be applied out of order
//! (Phase 0: `echo` arrived as `ehco`), and a `client.key` or `block.event` is ordered only
//! among the ordered methods. So this keeps exactly one call in flight per terminal, in the
//! order the input arrived. Text that piles up while a call is in flight is coalesced into one
//! write. Input that arrives while the connection is down is dropped, not replayed: the server
//! may or may not have run what was in flight, and repeating keystrokes is worse than losing
//! them.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const Control = @import("control.zig").Control;

const log = std.log.scoped(.rex_input);

/// How the queue makes a call. The control connection implements it; tests substitute a
/// recorder.
pub const Sender = struct {
    ctx: *anyopaque,
    /// Make the call and return when it has been answered. An error means it failed.
    call: *const fn (ctx: *anyopaque, method: []const u8, payload_json: []const u8) anyerror!void,
    /// The largest request the connection takes now (Rex's `max_message_bytes`); null for
    /// `default_max_message`.
    max_message: ?*const fn (ctx: *anyopaque) u64 = null,

    pub fn forControl(ctl: *Control) Sender {
        return .{ .ctx = ctl, .call = controlCall, .max_message = controlMaxMessage };
    }

    fn controlMaxMessage(ctx: *anyopaque) u64 {
        const ctl: *Control = @ptrCast(@alignCast(ctx));
        return ctl.maxMessage();
    }

    fn controlCall(ctx: *anyopaque, method: []const u8, payload_json: []const u8) anyerror!void {
        const ctl: *Control = @ptrCast(@alignCast(ctx));
        var r = try ctl.call(method, payload_json);
        defer r.deinit();
        _ = try r.ok();
    }
};

const Item = union(enum) {
    /// Bytes for `terminal.write`.
    text: std.ArrayList(u8),
    /// The JSON of a `client.key` key object.
    key: []u8,
    /// A `block.event`: its type and the JSON of its payload.
    event: struct { kind: []u8, payload: []u8 },

    /// Bytes it holds, counted against `Input.max_queued_bytes`.
    fn size(i: Item) usize {
        return switch (i) {
            .text => |t| t.items.len,
            .key => |k| k.len,
            .event => |e| e.kind.len + e.payload.len,
        };
    }

    fn deinit(i: *Item, gpa: Allocator) void {
        switch (i.*) {
            .text => |*t| t.deinit(gpa),
            .key => |k| gpa.free(k),
            .event => |e| {
                gpa.free(e.kind);
                gpa.free(e.payload);
            },
        }
    }
};

pub const Stats = struct {
    /// Calls made, by kind.
    writes: u64 = 0,
    keys: u64 = 0,
    events: u64 = 0,
    /// Text submissions that were merged into an earlier write.
    coalesced: u64 = 0,
    /// Calls that failed (the input is lost).
    failed: u64 = 0,
};

pub const Input = struct {
    gpa: Allocator,
    io: Io,
    sender: Sender,
    session_id: []u8,
    block_id: []u8,

    mu: Io.Mutex = .init,
    queue: std.ArrayList(Item) = .empty,
    queued_bytes: usize = 0,
    in_flight: bool = false,
    closed: bool = false,
    wake: Io.Event = .unset,
    idle: Io.Event = .is_set,
    stats: Stats = .{},
    worker: ?Io.Future(void) = null,

    /// Most bytes held back (text, keys and events alike) before a submission gets `Backpressure`.
    pub const max_queued_bytes = 1 << 20;
    /// The request limit assumed when the sender does not say.
    pub const default_max_message: u64 = 1 << 20;
    /// Room for everything in a `terminal.write` request except the escaped IDs and text: the
    /// request envelope (type, id, method) and the payload's keys.
    const request_overhead = 256;

    pub const SubmitError = error{ Backpressure, Closed, InvalidUtf8 } || Allocator.Error;

    pub fn open(gpa: Allocator, io: Io, sender: Sender, session_id: []const u8, block_id: []const u8) !*Input {
        const q = try gpa.create(Input);
        errdefer gpa.destroy(q);
        const sid = try gpa.dupe(u8, session_id);
        errdefer gpa.free(sid);
        const bid = try gpa.dupe(u8, block_id);
        errdefer gpa.free(bid);
        q.* = .{ .gpa = gpa, .io = io, .sender = sender, .session_id = sid, .block_id = bid };
        q.worker = try io.concurrent(workerMain, .{q});
        return q;
    }

    pub fn close(q: *Input) void {
        q.mu.lockUncancelable(q.io);
        q.closed = true;
        q.mu.unlock(q.io);
        q.wake.set(q.io);
        if (q.worker) |*w| w.cancel(q.io);
        for (q.queue.items) |*i| i.deinit(q.gpa);
        q.queue.deinit(q.gpa);
        q.gpa.free(q.session_id);
        q.gpa.free(q.block_id);
        q.gpa.destroy(q);
    }

    pub fn getStats(q: *Input) Stats {
        q.mu.lockUncancelable(q.io);
        defer q.mu.unlock(q.io);
        return q.stats;
    }

    /// Typed or composed text, pasted text and mouse reports sent as terminal input.
    pub fn writeText(q: *Input, bytes: []const u8) SubmitError!void {
        if (bytes.len == 0) return;
        if (!std.unicode.utf8ValidateSlice(bytes)) return error.InvalidUtf8;
        q.mu.lockUncancelable(q.io);
        defer q.mu.unlock(q.io);
        if (q.closed) return error.Closed;
        if (q.queued_bytes + bytes.len > max_queued_bytes) return error.Backpressure;
        // Merge into the text item at the tail, if the tail is text.
        if (q.queue.items.len > 0) {
            const last = &q.queue.items[q.queue.items.len - 1];
            if (last.* == .text) {
                try last.text.appendSlice(q.gpa, bytes);
                q.queued_bytes += bytes.len;
                q.stats.coalesced += 1;
                return;
            }
        }
        var t: std.ArrayList(u8) = .empty;
        errdefer t.deinit(q.gpa);
        try t.appendSlice(q.gpa, bytes);
        try q.queue.append(q.gpa, .{ .text = t });
        q.queued_bytes += bytes.len;
        q.kick();
    }

    /// A key event (the `key` object of `client.key`, as JSON).
    pub fn key(q: *Input, key_json: []const u8) SubmitError!void {
        const copy = try q.gpa.dupe(u8, key_json);
        return q.push(.{ .key = copy }); // `push` owns it, even when it fails
    }

    /// A `block.event`, such as `paste` or `mouse`, with its payload as JSON.
    pub fn blockEvent(q: *Input, kind: []const u8, payload_json: []const u8) SubmitError!void {
        const k = try q.gpa.dupe(u8, kind);
        const p = q.gpa.dupe(u8, payload_json) catch |e| {
            q.gpa.free(k);
            return e;
        };
        return q.push(.{ .event = .{ .kind = k, .payload = p } }); // `push` owns them, even when it fails
    }

    /// Queue `item`, which this owns from now on: on failure it is freed.
    fn push(q: *Input, item: Item) SubmitError!void {
        var it = item;
        q.mu.lockUncancelable(q.io);
        defer q.mu.unlock(q.io);
        if (q.closed) {
            it.deinit(q.gpa);
            return error.Closed;
        }
        if (q.queue.items.len >= 4096 or q.queued_bytes + it.size() > max_queued_bytes) {
            it.deinit(q.gpa);
            return error.Backpressure;
        }
        q.queue.append(q.gpa, it) catch |e| {
            it.deinit(q.gpa);
            return e;
        };
        q.queued_bytes += it.size();
        q.kick();
    }

    /// Caller holds `mu`.
    fn kick(q: *Input) void {
        q.idle.reset();
        q.wake.set(q.io);
    }

    /// Wait until everything submitted so far has been sent and answered. For tests and for
    /// closing a viewer politely.
    pub fn flush(q: *Input, timeout_ms: u32) !void {
        try q.idle.waitTimeout(q.io, .{ .duration = .{ .raw = .fromMilliseconds(timeout_ms), .clock = .awake } });
    }

    fn workerMain(q: *Input) void {
        while (true) {
            q.wake.wait(q.io) catch return;
            while (true) {
                q.mu.lockUncancelable(q.io);
                if (q.closed) {
                    q.mu.unlock(q.io);
                    return;
                }
                if (q.queue.items.len == 0) {
                    q.wake.reset();
                    q.in_flight = false;
                    q.idle.set(q.io);
                    q.mu.unlock(q.io);
                    break;
                }
                var item = q.takeHead();
                q.in_flight = true;
                q.queued_bytes -= item.size();
                q.mu.unlock(q.io);
                defer item.deinit(q.gpa);

                const started = std.Io.Clock.awake.now(q.io).toMilliseconds();
                const ok = q.send(&item);
                const took = std.Io.Clock.awake.now(q.io).toMilliseconds() - started;
                if (took > 500) log.warn("a Rex input call took {d} ms", .{took});
                q.mu.lockUncancelable(q.io);
                switch (item) {
                    .text => q.stats.writes += 1,
                    .key => q.stats.keys += 1,
                    .event => q.stats.events += 1,
                }
                if (!ok) q.stats.failed += 1;
                q.mu.unlock(q.io);
            }
        }
    }

    /// Take the next item to send. Caller holds `mu`; the queue is not empty. Text longer than
    /// one write may carry is cut at a character boundary, and the rest stays at the head.
    fn takeHead(q: *Input) Item {
        const head = &q.queue.items[0];
        if (head.* == .text) {
            const t = &head.text;
            const n = utf8Cut(t.items, q.maxWriteBytes());
            if (n < t.items.len) cut: {
                var part: std.ArrayList(u8) = .empty;
                // Out of memory: send it whole; Rex refuses it if it is too large.
                part.appendSlice(q.gpa, t.items[0..n]) catch break :cut;
                t.replaceRangeAssumeCapacity(0, n, &.{});
                return .{ .text = part };
            }
        }
        return q.queue.orderedRemove(0);
    }

    /// Most text bytes one `terminal.write` may carry so its request fits the connection's
    /// message limit: JSON escapes a byte to at most 6 (`\u00XX`), the IDs included.
    fn maxWriteBytes(q: *Input) usize {
        const limit: u64 = if (q.sender.max_message) |f| f(q.sender.ctx) else default_max_message;
        const overhead: u64 = request_overhead + 6 * (q.session_id.len + q.block_id.len);
        if (limit <= overhead + 6) return 1;
        return @intCast(@min((limit - overhead) / 6, std.math.maxInt(usize)));
    }

    fn send(q: *Input, item: *Item) bool {
        const gpa = q.gpa;
        const sid = std.json.Stringify.valueAlloc(gpa, q.session_id, .{}) catch return false;
        defer gpa.free(sid);
        const bid = std.json.Stringify.valueAlloc(gpa, q.block_id, .{}) catch return false;
        defer gpa.free(bid);
        var method: []const u8 = undefined;
        const body = switch (item.*) {
            .text => |t| blk: {
                method = "com.superlogical.terminal.write";
                const data = std.json.Stringify.valueAlloc(gpa, t.items, .{}) catch return false;
                defer gpa.free(data);
                break :blk std.fmt.allocPrint(gpa, "{{\"session_id\":{s},\"block_id\":{s},\"args\":{{\"data\":{s}}}}}", .{ sid, bid, data }) catch return false;
            },
            .key => |k| blk: {
                method = "client.key";
                break :blk std.fmt.allocPrint(gpa, "{{\"session_id\":{s},\"block_id\":{s},\"key\":{s}}}", .{ sid, bid, k }) catch return false;
            },
            .event => |e| blk: {
                method = "block.event";
                const kind = std.json.Stringify.valueAlloc(gpa, e.kind, .{}) catch return false;
                defer gpa.free(kind);
                break :blk std.fmt.allocPrint(gpa, "{{\"session_id\":{s},\"block_id\":{s},\"event\":{{\"type\":{s},\"payload\":{s}}}}}", .{ sid, bid, kind, e.payload }) catch return false;
            },
        };
        defer gpa.free(body);
        q.sender.call(q.sender.ctx, method, body) catch |e| {
            log.debug("{s} failed: {t}", .{ method, e });
            return false;
        };
        return true;
    }
};

/// The longest prefix of UTF-8 `text` of at most `max` bytes that ends at a character boundary,
/// but at least one whole character.
fn utf8Cut(text: []const u8, max: usize) usize {
    if (text.len <= max) return text.len;
    var n = max;
    while (n > 0 and text[n] & 0xc0 == 0x80) n -= 1;
    if (n == 0) n = @min(text.len, std.unicode.utf8ByteSequenceLength(text[0]) catch 1);
    return n;
}

// ---- tests ----

const testing = std.testing;
const fake = @import("fake.zig");

/// A sender that records what it was asked, checks that calls never overlap, and is slow
/// enough for input to pile up behind it.
const Recorder = struct {
    io: Io,
    gpa: Allocator,
    mu: Io.Mutex = .init,
    active: u32 = 0,
    max_active: u32 = 0,
    log: std.ArrayList(u8) = .empty,
    delay_ms: i64 = 15,
    fail_next: bool = false,

    fn deinit(r: *Recorder) void {
        r.log.deinit(r.gpa);
    }

    fn call(ctx: *anyopaque, method: []const u8, payload: []const u8) anyerror!void {
        const r: *Recorder = @ptrCast(@alignCast(ctx));
        r.mu.lockUncancelable(r.io);
        r.active += 1;
        r.max_active = @max(r.max_active, r.active);
        const fail = r.fail_next;
        r.fail_next = false;
        r.mu.unlock(r.io);
        try r.io.sleep(.fromMilliseconds(r.delay_ms), .awake);
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.active -= 1;
        // Record the method and the payload's essence.
        const short = if (std.mem.eql(u8, method, "com.superlogical.terminal.write")) "write" else method;
        r.log.print(r.gpa, "{s}:{s}\n", .{ short, essence(payload) }) catch {};
        if (fail) return error.Failed;
    }

    fn essence(payload: []const u8) []const u8 {
        // For a write: the data string; for anything else: the whole payload.
        if (std.mem.indexOf(u8, payload, "\"data\":\"")) |i| {
            const s = payload[i + 8 ..];
            return s[0 .. std.mem.indexOfScalar(u8, s, '"') orelse s.len];
        }
        return payload;
    }

    fn sender(r: *Recorder) Sender {
        return .{ .ctx = r, .call = call };
    }
};

test "input: one call in flight at a time, in order, with text coalesced" {
    const a = testing.allocator;
    var rec: Recorder = .{ .io = testing.io, .gpa = a };
    defer rec.deinit();
    const q = try Input.open(a, testing.io, rec.sender(), "session:1", "block:1");
    defer q.close();

    // "echo" typed a letter at a time, then Enter as a key, then more text.
    for ("echo") |c| try q.writeText(&.{c});
    try q.key("{\"key\":\"enter\"}");
    try q.writeText("ls");
    try q.blockEvent("paste", "{\"text\":\"P\"}");
    try q.writeText("x");
    try q.writeText("y");
    try q.flush(3000);

    try testing.expectEqual(@as(u32, 1), rec.max_active);
    // The first letter went out alone; the rest piled up behind it and went as one write.
    // Whatever the grouping, the order of the characters and of the key between them holds.
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(a);
    var it = std.mem.splitScalar(u8, rec.log.items, '\n');
    while (it.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "write:")) try joined.appendSlice(a, line[6..]) else if (std.mem.startsWith(u8, line, "client.key:")) try joined.appendSlice(a, "<K>") else if (std.mem.startsWith(u8, line, "block.event:")) try joined.appendSlice(a, "<P>");
    }
    try testing.expectEqualStrings("echo<K>ls<P>xy", joined.items);
    const st = q.getStats();
    try testing.expect(st.coalesced > 0);
    try testing.expect(st.writes < 8); // fewer writes than the 8 text submissions
    try testing.expectEqual(@as(u64, 1), st.keys);
    try testing.expectEqual(@as(u64, 1), st.events);
}

test "input: a failed call loses that input but not the queue" {
    const a = testing.allocator;
    var rec: Recorder = .{ .io = testing.io, .gpa = a, .delay_ms = 1, .fail_next = true };
    defer rec.deinit();
    const q = try Input.open(a, testing.io, rec.sender(), "s", "b");
    defer q.close();
    try q.writeText("a");
    try q.flush(2000);
    try q.writeText("b");
    try q.flush(2000);
    try testing.expectEqual(@as(u64, 1), q.getStats().failed);
    try testing.expect(std.mem.indexOf(u8, rec.log.items, "write:b") != null);
}

test "input: invalid UTF-8 and oversize backlogs are refused" {
    const a = testing.allocator;
    var rec: Recorder = .{ .io = testing.io, .gpa = a, .delay_ms = 200 };
    defer rec.deinit();
    const q = try Input.open(a, testing.io, rec.sender(), "s", "b");
    defer q.close();
    try testing.expectError(error.InvalidUtf8, q.writeText(&.{ 0xff, 0xfe }));
    try q.writeText("go"); // goes in flight and sits for 200 ms
    try testing.io.sleep(.fromMilliseconds(30), .awake);
    const big = try a.alloc(u8, Input.max_queued_bytes);
    defer a.free(big);
    @memset(big, 'x');
    try q.writeText("a");
    try testing.expectError(error.Backpressure, q.writeText(big));
}

test "input: through the control connection to the fake, the echo arrives in order" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const made = try f.createSession("rweb-test-input");
    const body = try std.fmt.allocPrint(a, "{{\"session_id\":\"{s}\"}}", .{made.session_id});
    defer a.free(body);
    var at = try ctl.call("session.attach", body);
    at.deinit();

    const mirror = @import("mirror.zig");
    const m = try mirror.Mirror.initPending(a, testing.io);
    defer m.deinit();
    const d = try @import("data.zig").Data.openTerminal(a, testing.io, ctl, made.session_id, made.block_id, m.sink());
    defer d.close();

    const q = try Input.open(a, testing.io, Sender.forControl(ctl), made.session_id, made.block_id);
    defer q.close();
    for ("echo hello world") |c| try q.writeText(&.{c});
    try q.flush(5000);

    var tries: u32 = 0;
    while (tries < 400) : (tries += 1) {
        if (m.getStatus() == .live) {
            const text = try m.plainText(a);
            defer a.free(text);
            if (std.mem.indexOf(u8, text, "echo hello world") != null) return;
        }
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    return error.TimedOut;
}

test "live: characters submitted one at a time reach a real shell in order (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();
    var made = try ctl.call("session.create", "{\"label\":\"rweb-test-live-input\",\"initial_windows\":[{\"layout\":{\"block\":{\"flavor\":\"com.superlogical.terminal.shell\"}}}]}");
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

    const mirror = @import("mirror.zig");
    const m = try mirror.Mirror.initPending(a, testing.io);
    defer m.deinit();
    const d = try @import("data.zig").Data.openTerminal(a, testing.io, ctl, sid, bid, m.sink());
    defer d.close();
    const q = try Input.open(a, testing.io, Sender.forControl(ctl), sid, bid);
    defer q.close();

    // Without the queue, concurrent writes arrived as "ehco". Submit a character at a time,
    // as fast as possible, ten commands in a row.
    var n: u32 = 0;
    while (n < 10) : (n += 1) {
        var buf: [64]u8 = undefined;
        const line = try std.fmt.bufPrint(&buf, "echo ord-$((1000+{d}))\n", .{n});
        for (line) |c| try q.writeText(&.{c});
    }
    try q.flush(20000);
    var tries: u32 = 0;
    while (tries < 400) : (tries += 1) {
        try testing.io.sleep(.fromMilliseconds(25), .awake);
        if (m.getStatus() != .live) continue;
        const text = try m.plainText(a);
        defer a.free(text);
        var all = true;
        var k: u32 = 0;
        while (k < 10) : (k += 1) {
            var nb: [24]u8 = undefined;
            const want = try std.fmt.bufPrint(&nb, "\nord-{d}", .{1000 + k});
            if (std.mem.indexOf(u8, text, want) == null) all = false;
        }
        if (all) return;
    }
    return error.OutOfOrderOrLost;
}

test "input: keys and events count against the byte cap too" {
    const a = testing.allocator;
    var rec: Recorder = .{ .io = testing.io, .gpa = a, .delay_ms = 300 };
    defer rec.deinit();
    const q = try Input.open(a, testing.io, rec.sender(), "s", "b");
    defer q.close();
    try q.writeText("go"); // in flight for a while
    try testing.io.sleep(.fromMilliseconds(30), .awake);
    const key = try a.alloc(u8, 64 * 1024);
    defer a.free(key);
    @memset(key, 'k');
    var accepted: usize = 0;
    while (accepted < 100) : (accepted += 1) {
        q.key(key) catch |e| {
            try testing.expectEqual(error.Backpressure, e);
            break;
        };
    }
    try testing.expectEqual(Input.max_queued_bytes / key.len, accepted);
    try testing.expectError(error.Backpressure, q.blockEvent("paste", key));
}

/// A sender with a small message limit that keeps every payload it gets.
const Bodies = struct {
    gpa: Allocator,
    limit: u64,
    bodies: std.ArrayList([]u8) = .empty,

    fn deinit(b: *Bodies) void {
        for (b.bodies.items) |x| b.gpa.free(x);
        b.bodies.deinit(b.gpa);
    }
    fn call(ctx: *anyopaque, _: []const u8, payload: []const u8) anyerror!void {
        const b: *Bodies = @ptrCast(@alignCast(ctx));
        try b.bodies.append(b.gpa, try b.gpa.dupe(u8, payload));
    }
    fn maxMessage(ctx: *anyopaque) u64 {
        const b: *Bodies = @ptrCast(@alignCast(ctx));
        return b.limit;
    }
    fn sender(b: *Bodies) Sender {
        return .{ .ctx = b, .call = call, .max_message = maxMessage };
    }
};

test "input: a coalesced write is cut so each request fits the message limit" {
    const a = testing.allocator;
    var b: Bodies = .{ .gpa = a, .limit = 4096 };
    defer b.deinit();
    const q = try Input.open(a, testing.io, b.sender(), "session:1", "block:1");
    defer q.close();
    // Control bytes escape to six bytes each, the worst case; a two-byte character must not be split.
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(a);
    for (0..3000) |i| try text.appendSlice(a, if (i % 3 == 0) "\x01" else if (i % 3 == 1) "\xc3\xa9" else "x");
    try q.writeText(text.items);
    try q.flush(5000);
    try testing.expect(b.bodies.items.len > 1);
    var joined: std.ArrayList(u8) = .empty;
    defer joined.deinit(a);
    for (b.bodies.items) |body| {
        // What Control.call wraps around the payload, with the longest id.
        const envelope = "{\"type\":\"request\",\"id\":\"18446744073709551615\",\"method\":\"com.superlogical.terminal.write\",\"payload\":}".len;
        try testing.expect(body.len + envelope <= b.limit);
        const p = try std.json.parseFromSlice(std.json.Value, a, body, .{});
        defer p.deinit();
        try joined.appendSlice(a, p.value.object.get("args").?.object.get("data").?.string);
    }
    try testing.expectEqualStrings(text.items, joined.items);
}
