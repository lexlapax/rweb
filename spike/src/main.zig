//! Phase 0 spike: show one live Rex terminal in a browser.
//!
//! Creates a throwaway `rweb-test-` session, streams its terminal through a
//! libghostty-vt mirror and serves an xterm.js page on 127.0.0.1 behind a
//! random token. Throwaway code; not the bridge.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ghostty_vt = @import("ghostty-vt");
const ws = @import("ws.zig");

const index_html = @embedFile("index.html");
const log = std.log.scoped(.spike);

const Viewer = struct {
    socket: *std.http.Server.WebSocket,
    alive: bool = true,
};

const App = struct {
    gpa: Allocator,
    io: Io,
    ctl: *ws.Client,
    session_id: []const u8,
    block_id: []const u8,
    next_id: std.atomic.Value(u32) = .init(100),
    port: u16,
    token: [32]u8,
    /// Browser origin to accept on the WebSocket upgrade instead of the loopback one
    /// (the Tailscale Serve address during the phone test).
    origin: ?[]const u8 = null,
    /// When set, every request must carry this Tailscale-User-Login and no Funnel marker.
    ts_user: ?[]const u8 = null,
    capture: Io.File,
    screen_path: []const u8,

    /// Guards everything below.
    mu: Io.Mutex = .init,
    mirror: Mirror,
    viewers: std.ArrayList(*Viewer) = .empty,
    data_bytes: u64 = 0,
    ended: bool = false,

    /// Typed input. Rex runs `terminal.write` calls concurrently, so two calls in
    /// flight can be applied out of order: keep one in flight and coalesce the rest.
    input_mu: Io.Mutex = .init,
    input_queue: std.ArrayList(u8) = .empty,
    input_inflight: ?u32 = null,
    input_writes: u32 = 0,

    fn nextId(app: *App, buf: []u8) []const u8 {
        const n = app.next_id.fetchAdd(1, .monotonic);
        return std.fmt.bufPrint(buf, "{d}", .{n}) catch unreachable;
    }

    /// Fire-and-forget request on the control connection. Errors are logged by the reader.
    fn send(app: *App, method: []const u8, payload: anytype) void {
        var idbuf: [16]u8 = undefined;
        const id = app.nextId(&idbuf);
        const text = std.json.Stringify.valueAlloc(app.gpa, .{
            .type = "request",
            .id = id,
            .method = method,
            .payload = payload,
        }, .{}) catch return;
        defer app.gpa.free(text);
        app.ctl.writeFrame(.text, text) catch |e| log.err("send {s}: {t}", .{ method, e });
    }

    fn typeText(app: *App, text: []const u8) void {
        app.input_mu.lockUncancelable(app.io);
        defer app.input_mu.unlock(app.io);
        app.input_queue.appendSlice(app.gpa, text) catch return;
        if (app.input_inflight == null) app.flushInputLocked();
    }

    /// Caller holds input_mu.
    fn flushInputLocked(app: *App) void {
        if (app.input_queue.items.len == 0) {
            app.input_inflight = null;
            return;
        }
        const n = app.next_id.fetchAdd(1, .monotonic);
        var idbuf: [16]u8 = undefined;
        const id = std.fmt.bufPrint(&idbuf, "{d}", .{n}) catch unreachable;
        const text = std.json.Stringify.valueAlloc(app.gpa, .{
            .type = "request",
            .id = id,
            .method = "com.superlogical.terminal.write",
            .payload = .{ .session_id = app.session_id, .block_id = app.block_id, .args = .{ .data = app.input_queue.items } },
        }, .{}) catch return;
        defer app.gpa.free(text);
        app.input_queue.clearRetainingCapacity();
        app.input_inflight = n;
        app.input_writes += 1;
        app.ctl.writeFrame(.text, text) catch |e| log.err("write: {t}", .{e});
    }

    /// Called by the control reader for every response id.
    fn onResponse(app: *App, id: []const u8) void {
        const n = std.fmt.parseInt(u32, id, 10) catch return;
        app.input_mu.lockUncancelable(app.io);
        defer app.input_mu.unlock(app.io);
        if (app.input_inflight == n) app.flushInputLocked();
    }

    /// Send bytes or a control message to every viewer. Caller holds `mu`.
    fn broadcast(app: *App, op: std.http.Server.WebSocket.Opcode, data: []const u8) void {
        for (app.viewers.items) |v| {
            if (!v.alive) continue;
            v.socket.writeMessage(data, op) catch {
                v.alive = false;
            };
        }
    }
};

/// The bridge-side terminal: decodes Rex's snapshot, strips Rex's APC
/// messages from the live output and keeps a libghostty-vt terminal current.
const Mirror = struct {
    gpa: Allocator,
    io: Io,
    nonce: [24]u8 = undefined,
    nonce_len: usize = 0,
    live: bool = false,
    snap: std.ArrayList(u8) = .empty,
    pending: std.ArrayList(u8) = .empty,
    term: ghostty_vt.Terminal = undefined,
    stream: ghostty_vt.TerminalStream = undefined,
    snapshot_len: usize = 0,
    snapshot_version: u16 = 0,
    theme_json: ?[]u8 = null,
    rex_messages: u32 = 0,

    fn setNonce(m: *Mirror, nonce: u64) void {
        const s = std.fmt.bufPrint(&m.nonce, "{d}", .{nonce}) catch unreachable;
        m.nonce_len = s.len;
    }

    fn nonceStr(m: *const Mirror) []const u8 {
        return m.nonce[0..m.nonce_len];
    }

    /// Feed stream bytes. Caller holds app.mu.
    fn feed(m: *Mirror, app: *App, bytes: []const u8) !void {
        if (!m.live) {
            try m.snap.appendSlice(m.gpa, bytes);
            var reader: Io.Reader = .fixed(m.snap.items);
            var decoded = ghostty_vt.snapshot.decode(m.gpa, m.io, &reader, .{
                .max_continuation_bytes = 1 << 20,
            }) catch |e| switch (e) {
                error.EndOfStream => {
                    if (m.snap.items.len > 256 * 1024 * 1024) return error.SnapshotTooLarge;
                    return; // wait for more bytes
                },
                else => return e,
            };
            m.snapshot_len = reader.seek;
            m.snapshot_version = std.mem.readInt(u16, m.snap.items[8..10], .little);
            m.term = decoded.toOwned();
            m.stream = m.term.vtStream();
            switch (decoded.continuation) {
                .ground => {},
                .bytes => |b| m.stream.nextSlice(b),
            }
            decoded.deinit(m.gpa);
            m.live = true;
            log.info("snapshot decoded: {d} bytes, version {d}, {d}x{d}", .{
                m.snapshot_len, m.snapshot_version, m.term.cols, m.term.rows,
            });
            const rest = try m.gpa.dupe(u8, m.snap.items[m.snapshot_len..]);
            defer m.gpa.free(rest);
            m.snap.clearAndFree(m.gpa);
            return m.feedLive(app, rest);
        }
        return m.feedLive(app, bytes);
    }

    fn feedLive(m: *Mirror, app: *App, bytes: []const u8) !void {
        try m.pending.appendSlice(m.gpa, bytes);
        const work = try m.gpa.dupe(u8, m.pending.items);
        defer m.gpa.free(work);
        m.pending.clearRetainingCapacity();

        const prefix = "\x1b_rex1;";
        var i: usize = 0;
        var start: usize = 0;
        var carry_from: ?usize = null;
        while (i < work.len) {
            if (work[i] != 0x1b) {
                i += 1;
                continue;
            }
            const rem = work[i..];
            if (rem.len < prefix.len) {
                if (std.mem.startsWith(u8, prefix, rem)) {
                    carry_from = i;
                    break;
                }
                i += 1;
                continue;
            }
            if (!std.mem.startsWith(u8, rem, prefix)) {
                i += 1;
                continue;
            }
            const end = std.mem.indexOf(u8, rem, "\x1b\\") orelse {
                if (rem.len > 1 << 20) {
                    i += 1; // not a Rex message we can hold; let it through
                    continue;
                }
                carry_from = i;
                break;
            };
            const body = rem[prefix.len..end];
            const ns = m.nonceStr();
            if (body.len > ns.len and std.mem.startsWith(u8, body, ns) and body[ns.len] == ';') {
                m.emit(app, work[start..i]);
                m.rexMessage(app, body[ns.len + 1 ..]);
                i += end + 2;
                start = i;
            } else {
                i += 1; // printed by a program: pass through
            }
        }
        const stop = carry_from orelse work.len;
        m.emit(app, work[start..stop]);
        if (carry_from) |c| try m.pending.appendSlice(m.gpa, work[c..]);
    }

    fn emit(m: *Mirror, app: *App, out: []const u8) void {
        if (out.len == 0) return;
        m.stream.nextSlice(out);
        app.broadcast(.binary, out);
    }

    fn rexMessage(m: *Mirror, app: *App, json: []const u8) void {
        m.rex_messages += 1;
        const parsed = std.json.parseFromSlice(std.json.Value, m.gpa, json, .{}) catch {
            log.warn("bad rex message: {s}", .{json});
            return;
        };
        defer parsed.deinit();
        const obj = parsed.value.object;
        const kind = (obj.get("type") orelse return).string;
        log.info("rex message: {s}", .{json});
        if (std.mem.eql(u8, kind, "resize")) {
            const cols: u16 = @intCast((obj.get("cols") orelse return).integer);
            const rows: u16 = @intCast((obj.get("rows") orelse return).integer);
            m.term.resize(m.gpa, .{ .cols = cols, .rows = rows }) catch |e| {
                log.err("mirror resize: {t}", .{e});
                return;
            };
            // Reflow differs between emulators: give viewers an authoritative redraw.
            for (app.viewers.items) |v| {
                if (v.alive) sendRedraw(app, v) catch {
                    v.alive = false;
                };
            }
        } else if (std.mem.eql(u8, kind, "theme")) {
            if (m.theme_json) |t| m.gpa.free(t);
            m.theme_json = m.gpa.dupe(u8, json) catch null;
            const msg = std.fmt.allocPrint(m.gpa, "{{\"t\":\"theme\",\"theme\":{s}}}", .{json}) catch return;
            defer m.gpa.free(msg);
            app.broadcast(.text, msg);
        } else if (std.mem.eql(u8, kind, "child_exited")) {
            const msg = std.fmt.allocPrint(m.gpa, "{{\"t\":\"exited\",\"msg\":{s}}}", .{json}) catch return;
            defer m.gpa.free(msg);
            app.broadcast(.text, msg);
        }
    }

    /// Keep trailing blank rows so the viewer's screen top matches the mirror's.
    const redraw_opts: ghostty_vt.formatter.Options = .{ .emit = .vt, .trim = false };

    /// A VT byte stream that recreates the mirror's state on a fresh terminal.
    fn redraw(m: *Mirror, gpa: Allocator) ![]u8 {
        var out: Io.Writer.Allocating = .init(gpa);
        errdefer out.deinit();
        const w = &out.writer;
        try w.writeAll("\x1bc"); // RIS: start the viewer from a clean terminal
        // The formatter draws only the active screen. While a full-screen program
        // has the alternate screen, draw the primary screen first; the modes below
        // then switch the viewer to the alternate screen (saving this cursor).
        if (m.term.screens.active_key == .alternate) {
            if (m.term.screens.get(.primary)) |primary| {
                var pf: ghostty_vt.formatter.ScreenFormatter = .init(primary, redraw_opts);
                pf.extra = .all;
                try pf.format(w);
            }
        }
        var f: ghostty_vt.formatter.TerminalFormatter = .init(&m.term, redraw_opts);
        f.extra = .all;
        try f.format(w);
        return out.toOwnedSlice();
    }
};

/// Send size, theme and a redraw to one viewer. Caller holds app.mu.
fn sendRedraw(app: *App, v: *Viewer) !void {
    const m = &app.mirror;
    var sizebuf: [96]u8 = undefined;
    const size = try std.fmt.bufPrint(&sizebuf, "{{\"t\":\"size\",\"cols\":{d},\"rows\":{d}}}", .{ m.term.cols, m.term.rows });
    try v.socket.writeMessage(size, .text);
    if (m.theme_json) |t| {
        const msg = try std.fmt.allocPrint(app.gpa, "{{\"t\":\"theme\",\"theme\":{s}}}", .{t});
        defer app.gpa.free(msg);
        try v.socket.writeMessage(msg, .text);
    }
    const bytes = try m.redraw(app.gpa);
    defer app.gpa.free(bytes);
    try v.socket.writeMessage(bytes, .binary);
}

// ---------------------------------------------------------------- control setup

/// Send a request and wait for its response, skipping events. Setup only:
/// before the control reader task starts.
fn callSync(app: *App, method: []const u8, payload: anytype) !std.json.Parsed(std.json.Value) {
    var idbuf: [16]u8 = undefined;
    const id = app.nextId(&idbuf);
    const text = try std.json.Stringify.valueAlloc(app.gpa, .{
        .type = "request",
        .id = id,
        .method = method,
        .payload = payload,
    }, .{});
    defer app.gpa.free(text);
    try app.ctl.writeFrame(.text, text);
    while (true) {
        const msg = try app.ctl.readMessage(app.gpa);
        defer app.gpa.free(msg.data);
        if (msg.opcode == .close) return error.ControlClosed;
        var parsed = try std.json.parseFromSlice(std.json.Value, app.gpa, msg.data, .{});
        const obj = parsed.value.object;
        const t = obj.get("type").?.string;
        if (std.mem.eql(u8, t, "response") and std.mem.eql(u8, obj.get("id").?.string, id)) {
            if (obj.get("error")) |err| {
                log.err("{s} failed: {s}", .{ method, msg.data });
                _ = err;
                parsed.deinit();
                return error.RequestFailed;
            }
            return parsed;
        }
        parsed.deinit();
    }
}

fn controlReader(app: *App) void {
    while (true) {
        const msg = app.ctl.readMessage(app.gpa) catch |e| {
            log.err("control connection: {t}", .{e});
            return;
        };
        defer app.gpa.free(msg.data);
        if (msg.opcode == .close) {
            log.err("control connection closed", .{});
            return;
        }
        if (std.mem.startsWith(u8, msg.data, "{\"type\":\"response\",\"id\":\"")) {
            const rest = msg.data["{\"type\":\"response\",\"id\":\"".len..];
            if (std.mem.indexOfScalar(u8, rest, '"')) |q| app.onResponse(rest[0..q]);
        }
        if (std.mem.indexOf(u8, msg.data, "\"error\"") != null and std.mem.startsWith(u8, msg.data, "{\"type\":\"response\"")) {
            log.err("request failed: {s}", .{msg.data});
        } else if (std.mem.startsWith(u8, msg.data, "{\"type\":\"event\"")) {
            log.debug("event: {s}", .{msg.data[0..@min(msg.data.len, 160)]});
        }
    }
}

// ---------------------------------------------------------------- data stream

fn dataReader(app: *App, socket_path: []const u8, ticket_b64: []const u8) void {
    dataReaderInner(app, socket_path, ticket_b64) catch |e| log.err("data stream: {t}", .{e});
    app.mu.lockUncancelable(app.io);
    app.ended = true;
    app.mu.unlock(app.io);
}

fn dataReaderInner(app: *App, socket_path: []const u8, ticket_b64: []const u8) !void {
    const dc = try ws.Client.connect(app.gpa, app.io, socket_path, "/api/data", "rex.data.terminal.v1");
    defer dc.deinit(app.gpa);

    var hello: [17]u8 = undefined;
    hello[0] = 0x01;
    try std.base64.url_safe_no_pad.Decoder.decode(hello[1..], ticket_b64);
    try dc.writeFrame(.binary, &hello);

    const welcome = try dc.readMessage(app.gpa);
    defer app.gpa.free(welcome.data);
    if (welcome.data.len < 2 or welcome.data[0] != 0x81) {
        log.err("data handshake rejected: {x}", .{welcome.data});
        return error.DataRejected;
    }
    if (welcome.data.len != 32) return error.BadWelcome;
    const nonce = std.mem.readInt(u64, welcome.data[24..32], .little);
    const keep_ms = std.mem.readInt(u32, welcome.data[20..24], .little);
    log.info("data connection open: nonce {d}, resume window {d} ms", .{ nonce, keep_ms });

    app.mu.lockUncancelable(app.io);
    app.mirror.setNonce(nonce);
    app.mu.unlock(app.io);

    while (true) {
        const t0 = Io.Timestamp.now(app.io, .awake);
        const msg = try dc.readMessage(app.gpa);
        defer app.gpa.free(msg.data);
        const t1 = Io.Timestamp.now(app.io, .awake);
        if (msg.opcode == .close) {
            const code: u16 = if (msg.data.len >= 2) std.mem.readInt(u16, msg.data[0..2], .big) else 0;
            log.info("data connection closed: {d} {s}", .{ code, if (msg.data.len > 2) msg.data[2..] else "" });
            return;
        }
        app.capture.writeStreamingAll(app.io, msg.data) catch {};
        const tc = Io.Timestamp.now(app.io, .awake);
        app.mu.lockUncancelable(app.io);
        defer app.mu.unlock(app.io);
        app.data_bytes += msg.data.len;
        app.mirror.feed(app, msg.data) catch |e| {
            log.err("mirror: {t}", .{e});
            return e;
        };
        if (msg.data.len >= 32 * 1024) {
            const t2 = Io.Timestamp.now(app.io, .awake);
            log.info("timing: {d} bytes, read {d} us, capture {d} us, feed {d} us", .{
                msg.data.len,
                @divTrunc(t0.durationTo(t1).toNanoseconds(), 1000),
                @divTrunc(t1.durationTo(tc).toNanoseconds(), 1000),
                @divTrunc(tc.durationTo(t2).toNanoseconds(), 1000),
            });
        }
    }
}

// ---------------------------------------------------------------- http

fn queryToken(target: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "token=")) return kv["token=".len..];
    }
    return null;
}

fn httpServer(app: *App) void {
    var addr = Io.net.IpAddress.parseIp4("127.0.0.1", app.port) catch unreachable;
    var server = addr.listen(app.io, .{ .reuse_address = true }) catch |e| {
        log.err("listen: {t}", .{e});
        return;
    };
    defer server.deinit(app.io);
    var group: Io.Group = .init;
    defer group.cancel(app.io);
    while (true) {
        const conn = server.accept(app.io) catch |e| switch (e) {
            error.Canceled => return,
            else => {
                log.err("accept: {t}", .{e});
                continue;
            },
        };
        group.concurrent(app.io, handleConn, .{ app, conn }) catch {
            conn.close(app.io);
        };
    }
}

fn handleConn(app: *App, conn: Io.net.Stream) void {
    defer conn.close(app.io);
    handleConnInner(app, conn) catch |e| log.debug("http connection: {t}", .{e});
}

fn handleConnInner(app: *App, conn: Io.net.Stream) !void {
    var recv_buf: [16 * 1024]u8 = undefined;
    var send_buf: [64 * 1024]u8 = undefined;
    var r = conn.reader(app.io, &recv_buf);
    var w = conn.writer(app.io, &send_buf);
    var server = std.http.Server.init(&r.interface, &w.interface);
    var req = try server.receiveHead();
    const target = req.head.target;

    const token_ok = if (queryToken(target)) |t| std.mem.eql(u8, t, &app.token) else false;
    var ts_ok = app.ts_user == null;
    if (app.ts_user) |want| {
        var funnel = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "tailscale-user-login") and std.mem.eql(u8, h.value, want)) ts_ok = true;
            if (std.ascii.eqlIgnoreCase(h.name, "tailscale-funnel-request")) funnel = true;
        }
        if (funnel) ts_ok = false;
    }
    if (!token_ok or !ts_ok) {
        log.info("refused request: token {}, tailscale identity {}", .{ token_ok, ts_ok });
        try req.respond("forbidden\n", .{ .status = .forbidden, .keep_alive = false });
        return;
    }

    if (std.mem.startsWith(u8, target, "/ws")) {
        var origin_buf: [64]u8 = undefined;
        const want_origin = app.origin orelse try std.fmt.bufPrint(&origin_buf, "http://127.0.0.1:{d}", .{app.port});
        var origin_ok = false;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "origin") and std.mem.eql(u8, h.value, want_origin)) origin_ok = true;
        }
        if (!origin_ok) {
            try req.respond("bad origin\n", .{ .status = .forbidden, .keep_alive = false });
            return;
        }
        const key = switch (req.upgradeRequested()) {
            .websocket => |k| k orelse return error.NoKey,
            else => return error.NotWebSocket,
        };
        var sock = try req.respondWebSocket(.{ .key = key });
        try sock.flush();
        return viewerLoop(app, &sock);
    }

    if (std.mem.eql(u8, target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len], "/")) {
        try req.respond(index_html, .{
            .keep_alive = false,
            .extra_headers = &.{
                .{ .name = "content-type", .value = "text/html; charset=utf-8" },
                .{ .name = "cache-control", .value = "no-store" },
            },
        });
        return;
    }
    try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false });
}

fn viewerLoop(app: *App, sock: *std.http.Server.WebSocket) !void {
    var viewer: Viewer = .{ .socket = sock };
    {
        app.mu.lockUncancelable(app.io);
        defer app.mu.unlock(app.io);
        if (!app.mirror.live) return error.NotReady;
        try sendRedraw(app, &viewer);
        try app.viewers.append(app.gpa, &viewer);
        log.info("viewer joined ({d} now)", .{app.viewers.items.len});
    }
    defer {
        app.mu.lockUncancelable(app.io);
        for (app.viewers.items, 0..) |v, i| if (v == &viewer) {
            _ = app.viewers.swapRemove(i);
            break;
        };
        log.info("viewer left ({d} now)", .{app.viewers.items.len});
        app.mu.unlock(app.io);
    }

    while (true) {
        const msg = sock.readSmallMessage() catch return;
        switch (msg.opcode) {
            .connection_close => return,
            .text => handleViewerMessage(app, sock, msg.data),
            else => {},
        }
        app.mu.lockUncancelable(app.io);
        const alive = viewer.alive;
        app.mu.unlock(app.io);
        if (!alive) return;
    }
}

fn handleViewerMessage(app: *App, sock: *std.http.Server.WebSocket, text: []const u8) void {
    const parsed = std.json.parseFromSlice(std.json.Value, app.gpa, text, .{}) catch return;
    defer parsed.deinit();
    const obj = parsed.value.object;
    const t = (obj.get("t") orelse return).string;
    const sid = app.session_id;
    const bid = app.block_id;
    if (std.mem.eql(u8, t, "in")) {
        app.typeText((obj.get("d") orelse return).string);
    } else if (std.mem.eql(u8, t, "paste")) {
        const d = (obj.get("d") orelse return).string;
        app.send("block.event", .{ .session_id = sid, .block_id = bid, .event = .{ .type = "paste", .payload = .{ .text = d } } });
    } else if (std.mem.eql(u8, t, "key")) {
        const k = obj.get("key") orelse return;
        app.send("client.key", .{ .session_id = sid, .block_id = bid, .key = k });
    } else if (std.mem.eql(u8, t, "mouse")) {
        const p = obj.get("payload") orelse return;
        app.send("block.event", .{ .session_id = sid, .block_id = bid, .event = .{ .type = "mouse", .payload = p } });
    } else if (std.mem.eql(u8, t, "fit")) {
        const cols = (obj.get("cols") orelse return).integer;
        const rows = (obj.get("rows") orelse return).integer;
        app.send("session.own_block", .{ .session_id = sid, .block_ids = &[_][]const u8{bid}, .mode = "take" });
        app.send("com.superlogical.terminal.resize", .{ .session_id = sid, .block_id = bid, .args = .{ .columns = cols, .rows = rows } });
    } else if (std.mem.eql(u8, t, "dump")) {
        // Test hook: write the browser's rows to <capture>.screen.json.
        const rows = obj.get("rows") orelse return;
        const out = std.json.Stringify.valueAlloc(app.gpa, rows, .{}) catch return;
        defer app.gpa.free(out);
        const f = Io.Dir.cwd().createFile(app.io, app.screen_path, .{}) catch return;
        defer f.close(app.io);
        f.writeStreamingAll(app.io, out) catch {};
    } else if (std.mem.eql(u8, t, "settheme")) {
        const bg = (obj.get("background") orelse return).string;
        const fg = (obj.get("foreground") orelse return).string;
        app.send("com.superlogical.terminal.set_theme", .{ .session_id = sid, .block_id = bid, .args = .{ .background = bg, .foreground = fg } });
    } else if (std.mem.eql(u8, t, "dbg")) {
        // Phone test: the page reports its keyboard, input and composition events.
        log.info("dbg {s}", .{text});
    } else if (std.mem.eql(u8, t, "redraw")) {
        app.mu.lockUncancelable(app.io);
        defer app.mu.unlock(app.io);
        var v: Viewer = .{ .socket = sock };
        sendRedraw(app, &v) catch {};
    }
}

// ---------------------------------------------------------------- main

fn field(v: std.json.Value, name: []const u8) !std.json.Value {
    if (v != .object) return error.BadResponse;
    return v.object.get(name) orelse error.BadResponse;
}

fn killSession(app: *App, session_id: []const u8) void {
    if (callSync(app, "session.destroy", .{ .session_id = session_id })) |p| p.deinit() else |e|
        log.err("destroy {s}: {t}", .{ session_id, e });
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var port: u16 = 7690;
    var capture_path: []const u8 = "rweb-spike-capture.bin";
    var origin: ?[]const u8 = null;
    var ts_user: ?[]const u8 = null;
    var args = init.minimal.args.iterate();
    _ = args.next();
    while (args.next()) |a| {
        if (std.mem.eql(u8, a, "--port")) port = try std.fmt.parseInt(u16, args.next() orelse return error.Usage, 10);
        if (std.mem.eql(u8, a, "--capture")) capture_path = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, a, "--origin")) origin = args.next() orelse return error.Usage;
        if (std.mem.eql(u8, a, "--ts-user")) ts_user = args.next() orelse return error.Usage;
    }

    const runtime = init.environ_map.get("XDG_RUNTIME_DIR") orelse return error.NoRuntimeDir;
    const socket_path = try std.fmt.allocPrint(gpa, "{s}/rex/server.sock", .{runtime});
    defer gpa.free(socket_path);

    const capture = try Io.Dir.cwd().createFile(io, capture_path, .{});
    defer capture.close(io);

    const screen_path = try std.fmt.allocPrint(gpa, "{s}.screen.json", .{capture_path});
    defer gpa.free(screen_path);

    var token_raw: [16]u8 = undefined;
    io.random(&token_raw);
    const token = std.fmt.bytesToHex(token_raw, .lower);

    const ctl = try ws.Client.connect(gpa, io, socket_path, "/api/control", "rex.control.v1");
    defer ctl.deinit(gpa);
    try ctl.writeFrame(.text, "{\"type\":\"hello\",\"api_revision\":19,\"api_min_revision\":18," ++
        "\"client\":{\"kind\":\"other\",\"platform\":\"web\",\"name\":\"rweb-spike\",\"version\":\"0.0.1\"}}");
    {
        const welcome = try ctl.readMessage(gpa);
        defer gpa.free(welcome.data);
        log.info("welcome: {s}", .{welcome.data[0..@min(welcome.data.len, 400)]});
    }

    const app = try gpa.create(App);
    defer gpa.destroy(app);
    app.* = .{
        .gpa = gpa,
        .io = io,
        .ctl = ctl,
        .session_id = "",
        .block_id = "",
        .port = port,
        .token = token,
        .origin = origin,
        .ts_user = ts_user,
        .capture = capture,
        .screen_path = screen_path,
        .mirror = .{ .gpa = gpa, .io = io },
    };

    var label_raw: [3]u8 = undefined;
    io.random(&label_raw);
    const label = try std.fmt.allocPrint(gpa, "rweb-test-{s}", .{std.fmt.bytesToHex(label_raw, .lower)});
    defer gpa.free(label);

    const created = try callSync(app, "session.create", .{
        .label = label,
        .initial_windows = &[_]struct { layout: struct { block: struct { flavor: []const u8 } } }{
            .{ .layout = .{ .block = .{ .flavor = "com.superlogical.terminal.shell" } } },
        },
    });
    defer created.deinit();
    const cp = try field(created.value, "payload");
    const session_id = try gpa.dupe(u8, (try field(cp, "session_id")).string);
    defer gpa.free(session_id);
    errdefer killSession(app, session_id);
    const win0 = (try field(cp, "initial_windows")).array.items[0];
    const block_id = try gpa.dupe(u8, (try field(win0, "block_ids")).array.items[0].string);
    defer gpa.free(block_id);
    app.session_id = session_id;
    app.block_id = block_id;
    log.info("created session {s} ({s}), block {s}", .{ label, session_id, block_id });

    defer {
        // Close the test session whatever happens.
        if (callSync(app, "session.destroy", .{ .session_id = session_id })) |p| {
            p.deinit();
            log.info("destroyed session {s}", .{label});
        } else |e| log.err("destroy {s}: {t}; close it with: rex session close {s}", .{ label, e, session_id });
    }

    (try callSync(app, "session.attach", .{ .session_id = session_id })).deinit();
    const ticket = try callSync(app, "data.connect", .{
        .session_id = session_id,
        .block_id = block_id,
        .data_ref_id = "terminal",
        .subprotocol = "rex.data.terminal.v1",
    });
    defer ticket.deinit();
    const ticket_str = (try field(try field(ticket.value, "payload"), "ticket")).string;

    var data_task = try io.concurrent(dataReader, .{ app, socket_path, ticket_str });
    // Wait for the snapshot before serving viewers.
    var waited: u32 = 0;
    while (waited < 100) : (waited += 1) {
        app.mu.lockUncancelable(io);
        const live = app.mirror.live;
        const ended = app.ended;
        app.mu.unlock(io);
        if (live or ended) break;
        try io.sleep(.fromMilliseconds(50), .awake);
    }

    var ctl_task = try io.concurrent(controlReader, .{app});
    _ = &ctl_task;
    var http_task = try io.concurrent(httpServer, .{app});
    _ = &http_task;

    var base_buf: [64]u8 = undefined;
    const base = origin orelse try std.fmt.bufPrint(&base_buf, "http://127.0.0.1:{d}", .{port});
    std.debug.print(
        "\nrweb spike ready: {s}/?token={s}\nsession {s} block {s}\nstop with: touch {s}.stop\n\n",
        .{ base, &token, session_id, block_id, capture_path },
    );

    // Run until the stop file appears or the stream ends.
    const stop_path = try std.fmt.allocPrint(gpa, "{s}.stop", .{capture_path});
    defer gpa.free(stop_path);
    while (true) {
        try io.sleep(.fromMilliseconds(250), .awake);
        if (Io.Dir.cwd().access(io, stop_path, .{})) |_| {
            Io.Dir.cwd().deleteFile(io, stop_path) catch {};
            break;
        } else |_| {}
        app.mu.lockUncancelable(io);
        const ended = app.ended;
        app.mu.unlock(io);
        if (ended) break;
    }
    log.info("stopping: {d} stream bytes, {d} rex messages, {d} write calls", .{ app.data_bytes, app.mirror.rex_messages, app.input_writes });
    http_task.cancel(io);
    data_task.cancel(io);
    // Control reader is blocked on a read; destroy uses its own read loop, so stop it first.
    ctl_task.cancel(io);
}
