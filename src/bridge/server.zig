//! HTTP and WebSocket front of the bridge. Every request passes `access.decide` before
//! anything else happens; refusals are answered with a bare 403 and logged by reason only
//! (never with header values or tokens).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const rex = @import("rex");
const access = @import("access.zig");
const protocol = @import("protocol.zig");
const hub_mod = @import("hub.zig");
const assets = @import("assets.zig");
const Hub = hub_mod.Hub;

const log = std.log.scoped(.server);

pub const Listen = union(enum) {
    /// A unix socket: created 0600 in a directory that must not be open to others.
    unix: []const u8,
    /// Loopback TCP only (port 0 picks one).
    tcp_loopback: u16,
};

pub const Options = struct {
    listen: Listen,
    access: access.Config,
    max_connections: u32 = 64,
    /// Log what browsers send, typed text included. For keyboard testing only.
    debug_input: bool = false,
};

const security_headers = [_]std.http.Header{
    .{ .name = "content-security-policy", .value = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
    .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
};

/// `security_headers` plus `extra`, in `buf`.
fn withSecurity(buf: []std.http.Header, extra: []const std.http.Header) []const std.http.Header {
    var n: usize = 0;
    for (security_headers) |h| {
        buf[n] = h;
        n += 1;
    }
    for (extra) |h| {
        buf[n] = h;
        n += 1;
    }
    return buf[0..n];
}

const no_store = [_]std.http.Header{.{ .name = "cache-control", .value = "no-store" }};

/// Sustained message rate from one browser above which it is cut off.
pub const max_messages_per_second: u32 = 200;

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    hub: *Hub,
    opts: Options,
    listener: Io.net.Server,
    /// The TCP port, once listening.
    port: u16 = 0,
    accept_task: ?Io.Future(void) = null,
    group: Io.Group = .init,
    active: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),
    /// Accepted streams, so `stop` can shut them (cancelling a task blocked in a read is not
    /// reliable on its own).
    conns_mu: Io.Mutex = .init,
    conns: std.ArrayList(Io.net.Stream) = .empty,
    /// Per-asset validators and gzip bodies, made on first use.
    cache_mu: Io.Mutex = .init,
    etags: [assets.all.len]?[34]u8 = @splat(null),
    gz: [assets.all.len]?[]u8 = @splat(null),
    /// Requests refused by `access`, and the last reason, for tests and logs.
    refusals: std.atomic.Value(u32) = .init(0),
    last_refusal: std.atomic.Value(u8) = .init(255),

    pub fn start(gpa: Allocator, io: Io, hub: *Hub, opts: Options) !*Server {
        if (opts.access.owner == null and opts.access.token == null) return error.AccessNotConfigured;
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .hub = hub, .opts = opts, .listener = undefined };
        switch (opts.listen) {
            .unix => |path| {
                try prepareSocketDir(io, path);
                Io.Dir.deleteFileAbsolute(io, path) catch {};
                const old = umask(0o177); // the socket is created 0600
                defer _ = umask(old);
                const addr = try Io.net.UnixAddress.init(path);
                s.listener = try addr.listen(io, .{});
            },
            .tcp_loopback => |port| {
                var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(port) };
                s.listener = try addr.listen(io, .{ .reuse_address = true });
                s.port = s.listener.socket.address.getPort();
            },
        }
        errdefer s.listener.deinit(io);
        s.accept_task = try io.concurrent(acceptLoop, .{s});
        return s;
    }

    pub fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        s.conns_mu.lockUncancelable(s.io);
        for (s.conns.items) |c| c.shutdown(s.io, .both) catch {};
        s.conns_mu.unlock(s.io);
        s.wakeAccept();
        if (s.accept_task) |*t| t.cancel(s.io);
        s.group.cancel(s.io);
        s.conns.deinit(s.gpa);
        for (s.gz) |z| if (z) |bytes| s.gpa.free(bytes);
        s.listener.deinit(s.io);
        if (s.opts.listen == .unix) Io.Dir.deleteFileAbsolute(s.io, s.opts.listen.unix) catch {};
        s.gpa.destroy(s);
    }

    /// Make a blocked `accept` return, by connecting to ourselves.
    fn wakeAccept(s: *Server) void {
        switch (s.opts.listen) {
            .unix => |path| {
                const addr = Io.net.UnixAddress.init(path) catch return;
                const c = addr.connect(s.io) catch return;
                c.close(s.io);
            },
            .tcp_loopback => {
                var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(s.port) };
                const c = addr.connect(s.io, .{ .mode = .stream }) catch return;
                c.close(s.io);
            },
        }
    }

    fn acceptLoop(s: *Server) void {
        while (true) {
            if (s.stopping.load(.acquire)) return;
            const conn = s.listener.accept(s.io) catch |e| switch (e) {
                error.Canceled => return,
                else => {
                    log.err("accept: {t}", .{e});
                    s.io.sleep(.fromMilliseconds(100), .awake) catch return;
                    continue;
                },
            };
            if (s.stopping.load(.acquire)) {
                conn.close(s.io);
                return;
            }
            if (s.active.load(.acquire) >= s.opts.max_connections) {
                conn.close(s.io);
                continue;
            }
            _ = s.active.fetchAdd(1, .acq_rel);
            s.group.concurrent(s.io, handleConn, .{ s, conn }) catch {
                _ = s.active.fetchSub(1, .acq_rel);
                conn.close(s.io);
            };
        }
    }

    fn handleConn(s: *Server, conn: Io.net.Stream) void {
        s.conns_mu.lockUncancelable(s.io);
        s.conns.append(s.gpa, conn) catch {};
        s.conns_mu.unlock(s.io);
        defer {
            s.conns_mu.lockUncancelable(s.io);
            for (s.conns.items, 0..) |c, i| if (c.socket.handle == conn.socket.handle) {
                _ = s.conns.swapRemove(i);
                break;
            };
            s.conns_mu.unlock(s.io);
            _ = s.active.fetchSub(1, .acq_rel);
            conn.close(s.io);
        }
        s.serve(conn) catch |e| log.debug("connection ended: {t}", .{e});
    }

    fn serve(s: *Server, conn: Io.net.Stream) !void {
        const gpa = s.gpa;
        const recv = try gpa.alloc(u8, 16 * 1024);
        defer gpa.free(recv);
        const send = try gpa.alloc(u8, 32 * 1024);
        defer gpa.free(send);
        var r = conn.reader(s.io, recv);
        var w = conn.writer(s.io, send);
        var http = std.http.Server.init(&r.interface, &w.interface);
        var req = try http.receiveHead();
        const t_head = std.Io.Clock.awake.now(s.io).toMilliseconds();
        defer log.info("request {s} {s} (head read at {d}, handled in {d} ms)", .{ @tagName(req.head.method), pathOf(req.head.target), t_head, std.Io.Clock.awake.now(s.io).toMilliseconds() - t_head });

        // ---- access: before anything else ----
        var hdrs: [48]access.Header = undefined;
        var n: usize = 0;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (n == hdrs.len) break;
            hdrs[n] = .{ .name = h.name, .value = h.value };
            n += 1;
        }
        const target = req.head.target;
        const upgrade = req.upgradeRequested();
        const areq: access.Request = .{
            .peer_uid = if (s.opts.listen == .unix) peerUid(conn) else null,
            .headers = hdrs[0..n],
            .query_token = access.queryToken(target),
            .is_websocket_upgrade = upgrade == .websocket,
        };
        switch (access.decide(s.opts.access, areq)) {
            .allow => {},
            .deny => |why| {
                s.last_refusal.store(@intFromEnum(why), .release);
                _ = s.refusals.fetchAdd(1, .acq_rel);
                log.info("refused: {s}", .{why.text()});
                try req.respond("forbidden\n", .{ .status = .forbidden, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            },
        }

        if (req.head.method != .GET) {
            try req.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];

        if (std.mem.eql(u8, path, "/ws")) {
            const key = switch (upgrade) {
                .websocket => |k| k orelse return error.NoKey,
                else => {
                    try req.respond("expected a WebSocket upgrade\n", .{ .status = .bad_request, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                    return;
                },
            };
            var sock = try req.respondWebSocket(.{ .key = key });
            try sock.flush();
            return s.viewerSession(conn, &sock);
        }
        if (std.mem.eql(u8, path, "/labws")) {
            const key = switch (upgrade) {
                .websocket => |k| k orelse return error.NoKey,
                else => return,
            };
            var sock = try req.respondWebSocket(.{ .key = key });
            try sock.flush();
            return s.labSession(conn, &sock);
        }
        if (std.mem.eql(u8, path, "/api/lab/hb")) {
            try req.respond("{\"ok\":true}", .{ .keep_alive = false, .extra_headers = &(security_headers ++ no_store ++ [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }}) });
            return;
        }
        if (std.mem.eql(u8, path, "/api/lab/result")) {
            log.info("lab result: {s}", .{target[@min(target.len, (std.mem.indexOfScalar(u8, target, '?') orelse target.len - 1) + 1)..]});
            try req.respond("{\"ok\":true}", .{ .keep_alive = false, .extra_headers = &(security_headers ++ no_store ++ [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }}) });
            return;
        }
        if (std.mem.eql(u8, path, "/api/tree")) {
            const owned = s.hub.treeJson();
            defer if (owned) |t| s.gpa.free(t);
            const tree = owned orelse "{\"t\":\"tree\",\"sessions\":[]}";
            try req.respond(tree, .{ .keep_alive = false, .extra_headers = &(security_headers ++ no_store ++ [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }}) });
            return;
        }
        if (assets.indexOf(path)) |idx| return s.serveAsset(&req, idx, areq.query_token, hdrs[0..n]);
        try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
    }

    fn etagFor(s: *Server, idx: usize) []const u8 {
        s.cache_mu.lockUncancelable(s.io);
        defer s.cache_mu.unlock(s.io);
        if (s.etags[idx] == null) {
            var b: [34]u8 = undefined;
            _ = assets.etag(&b, assets.all[idx].body);
            s.etags[idx] = b;
        }
        return &s.etags[idx].?;
    }

    /// The gzip body of an asset, if gzip makes it smaller. Made once.
    fn gzipFor(s: *Server, idx: usize) ?[]const u8 {
        s.cache_mu.lockUncancelable(s.io);
        defer s.cache_mu.unlock(s.io);
        if (s.gz[idx]) |z| return if (z.len < assets.all[idx].body.len) z else null;
        const z = assets.gzip(s.gpa, assets.all[idx].body) catch return null;
        s.gz[idx] = z;
        return if (z.len < assets.all[idx].body.len) z else null;
    }

    /// A page asset: validated with an ETag, compressed when the browser accepts it, and kept
    /// by the browser (private, never by a shared cache). The vendored files cannot change
    /// without a new binary, so they are kept for a day; the page's own files are revalidated.
    fn serveAsset(s: *Server, req: *std.http.Server.Request, idx: usize, query_token: ?[]const u8, headers: []const access.Header) !void {
        const a = assets.all[idx];
        const is_root = std.mem.eql(u8, a.path, "/");
        // A page opened with `?token=` keeps the token in a same-site cookie, so its scripts,
        // styles and socket need no query string. That response is never a 304.
        var cookie_buf: [128]u8 = undefined;
        const cookie: ?[]const u8 = if (s.opts.access.token != null and query_token != null and is_root)
            std.fmt.bufPrint(&cookie_buf, "rweb-token={s}; Path=/; HttpOnly; SameSite=Strict", .{query_token.?}) catch null
        else
            null;

        const tag = s.etagFor(idx);
        var if_none_match: ?[]const u8 = null;
        var accept_encoding: ?[]const u8 = null;
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "if-none-match")) if_none_match = h.value;
            if (std.ascii.eqlIgnoreCase(h.name, "accept-encoding")) accept_encoding = h.value;
        }
        const cache_control = if (std.mem.startsWith(u8, a.path, "/vendor/")) "private, max-age=86400" else "private, no-cache";

        var hb: [16]std.http.Header = undefined;
        var extra: [8]std.http.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "content-type", .value = a.content_type };
        n += 1;
        extra[n] = .{ .name = "cache-control", .value = cache_control };
        n += 1;
        extra[n] = .{ .name = "etag", .value = tag };
        n += 1;
        extra[n] = .{ .name = "vary", .value = "accept-encoding" };
        n += 1;
        if (cookie) |ck| {
            extra[n] = .{ .name = "set-cookie", .value = ck };
            n += 1;
        }

        if (cookie == null) if (if_none_match) |inm| if (std.mem.eql(u8, inm, tag)) {
            return req.respond("", .{ .status = .not_modified, .keep_alive = false, .extra_headers = withSecurity(&hb, extra[0..n]) });
        };

        var body: []const u8 = a.body;
        if (accept_encoding) |ae| if (assets.acceptsGzip(ae)) if (s.gzipFor(idx)) |z| {
            body = z;
            extra[n] = .{ .name = "content-encoding", .value = "gzip" };
            n += 1;
        };
        try req.respond(body, .{ .keep_alive = false, .extra_headers = withSecurity(&hb, extra[0..n]) });
    }

    /// Transport lab: echo what a browser sends, and push a message a second, so the page can
    /// measure round trips and silences on this connection. Touches no terminal.
    fn labSession(s: *Server, conn: Io.net.Stream, sock: *std.http.Server.WebSocket) !void {
        const gpa = s.gpa;
        const c = try rex.ws.Conn.fromHttp(gpa, s.io, conn, sock.input, sock.output, 4096);
        defer c.deinit(gpa);
        var pusher = try s.io.concurrent(labPush, .{ s, c });
        defer pusher.cancel(s.io);
        while (true) {
            const m = c.readMessage(gpa) catch return;
            defer gpa.free(m.data);
            switch (m.opcode) {
                .text, .binary => c.writeFrame(m.opcode, m.data) catch return,
                .close => return,
                else => {},
            }
        }
    }

    fn labPush(s: *Server, c: *rex.ws.Conn) void {
        var n: u32 = 0;
        while (true) {
            s.io.sleep(.fromMilliseconds(1000), .awake) catch return;
            n += 1;
            var buf: [48]u8 = undefined;
            const text = std.fmt.bufPrint(&buf, "{{\"push\":{d}}}", .{n}) catch return;
            c.writeFrame(.text, text) catch return;
        }
    }

    /// One browser: a writer task drains the viewer's queue; this task reads commands.
    fn viewerSession(s: *Server, conn: Io.net.Stream, sock: *std.http.Server.WebSocket) !void {
        const gpa = s.gpa;
        const c = try rex.ws.Conn.fromHttp(gpa, s.io, conn, sock.input, sock.output, protocol.max_message_bytes);
        defer c.deinit(gpa);
        const v = try s.hub.addViewer();
        var last_rx: std.atomic.Value(i64) = .init(std.Io.Clock.awake.now(s.io).toMilliseconds());
        var writer = try s.io.concurrent(writerLoop, .{ s, c, v, &last_rx });

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        // A browser sends a few messages a second at most while someone types. A page stuck in a
        // loop would otherwise fill the connection with traffic, so past `max_messages_per_second`
        // for two seconds in a row the socket is closed.
        var window_start: i64 = std.Io.Clock.awake.now(s.io).toMilliseconds();
        var window_count: u32 = 0;
        var hot_windows: u32 = 0;
        while (true) {
            const m = c.readMessage(gpa) catch break;
            defer gpa.free(m.data);
            last_rx.store(std.Io.Clock.awake.now(s.io).toMilliseconds(), .release);
            window_count += 1;
            const now = std.Io.Clock.awake.now(s.io).toMilliseconds();
            if (now - window_start >= 1000) {
                hot_windows = if (window_count > max_messages_per_second) hot_windows + 1 else 0;
                window_start = now;
                window_count = 0;
                if (hot_windows >= 2) {
                    log.warn("closing a browser that sent more than {d} messages a second", .{max_messages_per_second});
                    break;
                }
            }
            switch (m.opcode) {
                .close => break,
                .text => {
                    if (s.opts.debug_input) log.info("browser at {d}: {s}", .{ std.Io.Clock.awake.now(s.io).toMilliseconds(), m.data });
                    _ = arena_state.reset(.retain_capacity);
                    const msg = protocol.parse(arena_state.allocator(), m.data) catch |e| {
                        const text = std.fmt.allocPrint(gpa, "{{\"t\":\"error\",\"for\":\"message\",\"msg\":\"{t}\"}}", .{e}) catch continue;
                        defer gpa.free(text);
                        v.pushText(text);
                        continue;
                    };
                    s.hub.handle(v, msg);
                },
                else => {}, // binary from a browser is not part of the protocol
            }
        }
        s.hub.closeViewer(v);
        writer.cancel(s.io);
        c.writeFrame(.close, &.{ 0x03, 0xe8 }) catch {};
        s.hub.removeViewer(v);
    }

    /// A browser that has said nothing for this long (the page pings every 3 s, and answers
    /// our pings) is gone: a connection through Serve can die without telling anyone.
    const silent_limit_ms: i64 = 20_000;

    fn writerLoop(s: *Server, c: *rex.ws.Conn, v: *hub_mod.Viewer, last_rx: *std.atomic.Value(i64)) void {
        var idle: u32 = 0;
        defer if (s.opts.debug_input) log.info("writer task ended", .{});
        while (true) {
            const f = (v.next(3000) catch return) orelse {
                if (v.isClosed()) return;
                // Quiet for a moment: a ping every ~3 s keeps a phone's path through Serve warm.
                idle += 1;
                c.writeFrame(.ping, "") catch return;
                const quiet = std.Io.Clock.awake.now(s.io).toMilliseconds() - last_rx.load(.acquire);
                if (quiet > silent_limit_ms) {
                    log.info("dropping a browser that has been silent for {d} s", .{@divTrunc(quiet, 1000)});
                    c.stream.shutdown(s.io, .both) catch {}; // wakes the reader, which cleans up
                    return;
                }
                continue;
            };
            defer f.deinit(s.gpa);
            idle = 0;
            const t0 = std.Io.Clock.awake.now(s.io).toMilliseconds();
            c.writeFrame(if (f.binary) .binary else .text, f.data) catch |e| {
                if (s.opts.debug_input) log.info("send failed after {d} ms: {t}", .{ std.Io.Clock.awake.now(s.io).toMilliseconds() - t0, e });
                return;
            };
            if (s.opts.debug_input) {
                const took = std.Io.Clock.awake.now(s.io).toMilliseconds() - t0;
                if (took > 50 or f.binary) log.info("sent {s} {d} bytes at {d} (write took {d} ms)", .{ if (f.binary) "bin" else "text", f.data.len, t0, took });
            }
        }
    }
};

/// A request target without its query string (which may hold a token).
fn pathOf(target: []const u8) []const u8 {
    return target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];
}

// ---- OS bits ----

extern "c" fn umask(mask: c_uint) c_uint;

/// Create the socket's directory 0700 if it is missing; refuse one that others can enter.
fn prepareSocketDir(io: Io, socket_path: []const u8) !void {
    const dir = std.fs.path.dirname(socket_path) orelse return error.BadSocketPath;
    _ = Io.Dir.cwd().createDirPathStatus(io, dir, @enumFromInt(0o700)) catch {}; // new directories are 0700
    var d = try Io.Dir.cwd().openDir(io, dir, .{});
    defer d.close(io);
    const st = try d.stat(io);
    if (@intFromEnum(st.permissions) & 0o077 != 0) return error.SocketDirNotPrivate;
}

/// The uid of the process on the other end of a unix socket, if the OS will say.
pub fn peerUid(conn: Io.net.Stream) ?u32 {
    const fd = conn.socket.handle;
    switch (builtin.os.tag) {
        .macos, .freebsd, .netbsd, .openbsd => {
            var uid: std.c.uid_t = undefined;
            var gid: std.c.gid_t = undefined;
            if (getpeereid(fd, &uid, &gid) != 0) return null;
            return uid;
        },
        .linux => {
            var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
            var len: std.c.socklen_t = @sizeOf(@TypeOf(cred));
            const SOL_SOCKET = 1;
            const SO_PEERCRED = 17;
            if (std.c.getsockopt(fd, SOL_SOCKET, SO_PEERCRED, @ptrCast(&cred), &len) != 0) return null;
            return cred.uid;
        },
        else => return null,
    }
}

extern "c" fn getpeereid(fd: c_int, uid: *std.c.uid_t, gid: *std.c.gid_t) c_int;

// ---- tests ----

const testing = std.testing;
const fake = rex.fake;

const token = "test-token-0123456789abcdef";

const Rig = struct {
    f: *fake.Fake,
    ctl: *rex.control.Control,
    hub: *Hub,
    srv: *Server,
    session_id: []const u8,
    block_id: []const u8,

    fn init(hub_cfg: hub_mod.Config, acc: access.Config, listen: Listen) !Rig {
        const a = testing.allocator;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const made = try f.createSession("rweb-test-server");
        const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const h = try Hub.open(a, testing.io, ctl, hub_cfg);
        errdefer h.close();
        const srv = try Server.start(a, testing.io, h, .{ .listen = listen, .access = acc });
        return .{ .f = f, .ctl = ctl, .hub = h, .srv = srv, .session_id = made.session_id, .block_id = made.block_id };
    }

    fn deinit(r: Rig) void {
        r.srv.stop();
        r.hub.close();
        r.ctl.close();
        r.f.deinit();
    }

    fn tcp(r: Rig) !Io.net.Stream {
        var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(r.srv.port) };
        return addr.connect(testing.io, .{ .mode = .stream });
    }
};

const Http = struct { status: u16, head: []u8, body: []u8 };

fn freeHttp(h: Http) void {
    testing.allocator.free(h.head);
    testing.allocator.free(h.body);
}

/// One plain HTTP/1.1 request over `stream`; reads to the end of the response.
fn httpRequest(stream: Io.net.Stream, request: []const u8) !Http {
    defer stream.close(testing.io);
    var rb: [4096]u8 = undefined;
    var wb: [4096]u8 = undefined;
    var r = stream.reader(testing.io, &rb);
    var w = stream.writer(testing.io, &wb);
    try w.interface.writeAll(request);
    try w.interface.flush();
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(testing.allocator);
    r.interface.appendRemainingUnlimited(testing.allocator, &all) catch {};
    const text = all.items;
    const split = std.mem.indexOf(u8, text, "\r\n\r\n") orelse return error.NoResponse;
    const status = try std.fmt.parseInt(u16, text[9..12], 10);
    return .{ .status = status, .head = try testing.allocator.dupe(u8, text[0..split]), .body = try testing.allocator.dupe(u8, text[split + 4 ..]) };
}

fn get(r: Rig, path: []const u8, headers: []const u8) !Http {
    const req = try std.fmt.allocPrint(testing.allocator, "GET {s} HTTP/1.1\r\nHost: localhost\r\n{s}Connection: close\r\n\r\n", .{ path, headers });
    defer testing.allocator.free(req);
    return httpRequest(try r.tcp(), req);
}

const token_cfg: access.Config = .{ .token = token };

test "server: assets are served with a strict content security policy" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const h = try get(rig, "/?token=" ++ token, "");
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 200), h.status);
    try testing.expect(std.mem.indexOf(u8, h.body, "<title>rweb</title>") != null);
    try testing.expect(std.mem.indexOf(u8, h.head, "content-security-policy") != null or std.mem.indexOf(u8, h.head, "Content-Security-Policy") != null);
    try testing.expect(std.mem.indexOf(u8, h.head, "frame-ancestors 'none'") != null);
    // Nothing in the page loads from elsewhere.
    try testing.expect(std.mem.indexOf(u8, h.body, "http://") == null and std.mem.indexOf(u8, h.body, "https://") == null);

    for ([_][]const u8{ "/app.js", "/keys.js", "/lab", "/lab.js", "/app.css", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js", "/vendor/LICENSE-xterm.txt" }) |p| {
        const path = try std.fmt.allocPrint(testing.allocator, "{s}?token={s}", .{ p, token });
        defer testing.allocator.free(path);
        const a = try get(rig, path, "");
        defer freeHttp(a);
        try testing.expectEqual(@as(u16, 200), a.status);
        try testing.expect(a.body.len > 100);
    }
    const nf = try get(rig, "/nope?token=" ++ token, "");
    defer freeHttp(nf);
    try testing.expectEqual(@as(u16, 404), nf.status);
    const tree = try get(rig, "/api/tree?token=" ++ token, "");
    defer freeHttp(tree);
    try testing.expectEqual(@as(u16, 200), tree.status);
    try testing.expect(std.mem.indexOf(u8, tree.body, rig.session_id) != null);
}

fn headerValue(head: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.splitSequence(u8, head, "\r\n");
    while (it.next()) |line| {
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        if (std.ascii.eqlIgnoreCase(line[0..colon], name)) return std.mem.trim(u8, line[colon + 1 ..], " ");
    }
    return null;
}

test "server: assets are compressed, validated and cached, so a phone loads them fast" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const path = "/vendor/xterm.js?token=" ++ token;
    const original = assets.find("/vendor/xterm.js").?.body.len;

    // Without Accept-Encoding: the whole file.
    const plain = try get(rig, path, "");
    defer freeHttp(plain);
    try testing.expectEqual(original, plain.body.len);
    try testing.expect(headerValue(plain.head, "content-encoding") == null);

    // With gzip accepted: far fewer bytes, and a validator and caching headers.
    const z = try get(rig, path, "Accept-Encoding: gzip, br\r\n");
    defer freeHttp(z);
    try testing.expectEqualStrings("gzip", headerValue(z.head, "content-encoding").?);
    try testing.expect(z.body.len < original / 2);
    try testing.expectEqualStrings("private, max-age=86400", headerValue(z.head, "cache-control").?);
    const tag = headerValue(z.head, "etag").?;
    try testing.expect(tag.len == 34 and tag[0] == '"');

    // A browser that has it asks "still this?" and gets no body.
    const hdr = try std.fmt.allocPrint(testing.allocator, "If-None-Match: {s}\r\n", .{tag});
    defer testing.allocator.free(hdr);
    const nm = try get(rig, path, hdr);
    defer freeHttp(nm);
    try testing.expectEqual(@as(u16, 304), nm.status);
    try testing.expectEqual(@as(usize, 0), nm.body.len);
    // A different validator gets the file.
    const other = try get(rig, path, "If-None-Match: \"nope\"\r\n");
    defer freeHttp(other);
    try testing.expectEqual(@as(u16, 200), other.status);

    // The page itself is revalidated, and a token page is never a 304 (it sets the cookie).
    const page = try get(rig, "/?token=" ++ token, "");
    defer freeHttp(page);
    try testing.expectEqualStrings("private, no-cache", headerValue(page.head, "cache-control").?);
    try testing.expect(headerValue(page.head, "set-cookie") != null);
    const page_tag = headerValue(page.head, "etag").?;
    const hdr2 = try std.fmt.allocPrint(testing.allocator, "If-None-Match: {s}\r\n", .{page_tag});
    defer testing.allocator.free(hdr2);
    const page2 = try get(rig, "/?token=" ++ token, hdr2);
    defer freeHttp(page2);
    try testing.expectEqual(@as(u16, 200), page2.status);

    // Errors are never cached.
    const forbidden = try get(rig, "/vendor/xterm.js", "");
    defer freeHttp(forbidden);
    try testing.expectEqual(@as(u16, 403), forbidden.status);
    try testing.expectEqualStrings("no-store", headerValue(forbidden.head, "cache-control").?);
}

test "server: refuses a request with no token or the wrong one" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const a = try get(rig, "/", "");
    defer freeHttp(a);
    try testing.expectEqual(@as(u16, 403), a.status);
    try testing.expectEqualStrings("forbidden\n", a.body);
    const b = try get(rig, "/?token=wrong", "");
    defer freeHttp(b);
    try testing.expectEqual(@as(u16, 403), b.status);
    try testing.expectEqual(@intFromEnum(access.Refusal.bad_token), rig.srv.last_refusal.load(.acquire));
    try testing.expect(rig.srv.refusals.load(.acquire) >= 2);
    // A refused request never reaches Rex or the tree.
    const t = try get(rig, "/api/tree", "");
    defer freeHttp(t);
    try testing.expectEqual(@as(u16, 403), t.status);
    try testing.expect(std.mem.indexOf(u8, t.body, rig.session_id) == null);
}

const owner_cfg: access.Config = .{ .owner = "owner@example.com", .own_addresses = &.{"100.64.0.5"} };

fn expectRefusedWith(rig: Rig, headers: []const u8, why: access.Refusal) !void {
    const h = try get(rig, "/", headers);
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 403), h.status);
    try testing.expectEqual(@intFromEnum(why), rig.srv.last_refusal.load(.acquire));
}

test "server: Tailscale identity rules, each shown to refuse" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    // The owner: allowed.
    const ok = try get(rig, "/", "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.9\r\n");
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
    // No identity, someone else, Funnel, and the node's own address.
    try expectRefusedWith(rig, "", .no_identity);
    try expectRefusedWith(rig, "Tailscale-User-Login: someone@example.com\r\n", .wrong_user);
    try expectRefusedWith(rig, "Tailscale-User-Login: owner@example.com\r\nTailscale-Funnel-Request: ?1\r\n", .funnel);
    try expectRefusedWith(rig, "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.5\r\n", .own_address);
}

test "server: a WebSocket needs a matching Origin" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const path = "/ws?token=" ++ token;
    // Another site's page: refused at the upgrade.
    try testing.expectError(error.UpgradeRefused, rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, "Origin: https://evil.example\r\n"));
    try testing.expectEqual(@intFromEnum(access.Refusal.bad_origin), rig.srv.last_refusal.load(.acquire));
    // No Origin at all: refused.
    try testing.expectError(error.UpgradeRefused, rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, ""));
    try testing.expectEqual(@intFromEnum(access.Refusal.no_origin), rig.srv.last_refusal.load(.acquire));
    // The page's own origin: accepted.
    const c = try rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, "Origin: http://localhost\r\n");
    c.deinit(testing.allocator);
}

/// Read text frames from a browser socket until one contains `needle`; binary frames are
/// returned through `bin` when given (the latest).
fn waitText(c: *rex.ws.Conn, needle: []const u8) !void {
    var i: u32 = 0;
    while (i < 80) : (i += 1) {
        const m = try c.readMessage(testing.allocator);
        defer testing.allocator.free(m.data);
        if (m.opcode == .text and std.mem.indexOf(u8, m.data, needle) != null) return;
        if (m.opcode == .close) return error.Closed;
    }
    return error.NotSeen;
}

fn waitBinary(c: *rex.ws.Conn, needle: []const u8) !void {
    var i: u32 = 0;
    while (i < 3000) : (i += 1) {
        const m = try c.readMessage(testing.allocator);
        defer testing.allocator.free(m.data);
        if (m.opcode == .binary and std.mem.indexOf(u8, m.data, needle) != null) return;
        if (m.opcode == .close) return error.Closed;
    }
    return error.NotSeen;
}

fn browser(rig: Rig) !*rex.ws.Conn {
    return rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), "/ws?token=" ++ token, null, "Origin: http://localhost\r\n");
}

fn sendJson(c: *rex.ws.Conn, comptime fmt: []const u8, args: anytype) !void {
    const text = try std.fmt.allocPrint(testing.allocator, fmt, args);
    defer testing.allocator.free(text);
    try c.writeFrame(.text, text);
}

test "server: a browser lists, opens, types and sees output, end to end" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    try rig.f.feed(rig.block_id, "from the shell\r\n");
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    try waitBinary(c, "from the shell");
    try sendJson(c, "{{\"t\":\"in\",\"d\":\"typed-text\\n\"}}", .{});
    try waitBinary(c, "typed-text");
    try sendJson(c, "{{\"t\":\"ping\"}}", .{});
    try waitText(c, "pong");
}

test "server: observe-only never writes, resizes or changes anything, over the wire" {
    const rig = try Rig.init(.{ .observe_only = true }, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try waitText(c, "\"locked\":true");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    try sendJson(c, "{{\"t\":\"in\",\"d\":\"nope\"}}", .{});
    try waitText(c, "read-only");
    try sendJson(c, "{{\"t\":\"fit\",\"cols\":100,\"rows\":30}}", .{});
    try waitText(c, "read-only");
    try sendJson(c, "{{\"t\":\"destroy_session\",\"session\":\"{s}\"}}", .{rig.session_id});
    try waitText(c, "read-only");
    try sendJson(c, "{{\"t\":\"observe\",\"on\":false}}", .{});
    try waitText(c, "\"observe\":true"); // still on: the bridge is locked
    // Rex saw nothing: same size, session still there, nothing typed.
    rig.f.mu.lockUncancelable(testing.io);
    defer rig.f.mu.unlock(testing.io);
    try testing.expectEqual(@as(usize, 1), rig.f.sessions.items.len);
    try testing.expectEqual(@as(u16, 80), rig.f.sessions.items[0].block.term.cols);
}

test "server: a browser stuck in a message loop is cut off" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    // About 1,200 messages a second for four seconds: six times the limit.
    var sent_after_cut = false;
    var round: u32 = 0;
    while (round < 40) : (round += 1) {
        var k: u32 = 0;
        while (k < 120) : (k += 1) c.writeFrame(.text, "{\"t\":\"ping\"}") catch {
            sent_after_cut = true;
            break;
        };
        if (sent_after_cut) break;
        try testing.io.sleep(.fromMilliseconds(100), .awake);
    }
    // Whatever came back, the server ends the conversation: reading finishes with a close or
    // an error instead of going on for ever.
    var ended = false;
    var frames: u32 = 0;
    while (frames < 200000) : (frames += 1) {
        const m = c.readMessage(testing.allocator) catch {
            ended = true;
            break;
        };
        defer testing.allocator.free(m.data);
        if (m.opcode == .close) {
            ended = true;
            break;
        }
    }
    try testing.expect(ended);
    // A well-behaved browser on the same server is unaffected.
    const ok = try browser(rig);
    defer ok.deinit(testing.allocator);
    try sendJson(ok, "{{\"t\":\"ping\"}}", .{});
    try waitText(ok, "pong");
}

test "server: malformed browser messages are answered, not trusted" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try c.writeFrame(.text, "not json at all");
    try waitText(c, "\"t\":\"error\"");
    try c.writeFrame(.text, "{\"t\":\"fit\",\"cols\":99999,\"rows\":1}");
    try waitText(c, "BadField");
    try c.writeFrame(.text, "{\"t\":\"in\",\"d\":\"x\"}"); // no terminal open
    try waitText(c, "no terminal open");
    try sendJson(c, "{{\"t\":\"ping\"}}", .{});
    try waitText(c, "pong"); // still alive
}

fn tmpSocketPath(buf: []u8, io: Io) ![]const u8 {
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    return std.fmt.bufPrint(buf, "/tmp/rweb-test-{x}/bridge.sock", .{rnd});
}

fn unixGet(rig: Rig, path: []const u8) !Http {
    const addr = try Io.net.UnixAddress.init(rig.srv.opts.listen.unix);
    const stream = try addr.connect(testing.io);
    const req = try std.fmt.allocPrint(testing.allocator, "GET {s} HTTP/1.1\r\nHost: localhost\r\nTailscale-User-Login: owner@example.com\r\nConnection: close\r\n\r\n", .{path});
    defer testing.allocator.free(req);
    return httpRequest(stream, req);
}

test "server: a unix socket is private, and only the allowed peers get in" {
    var pb: [96]u8 = undefined;
    const path = try tmpSocketPath(&pb, testing.io);
    const my_uid: u32 = @intCast(std.c.getuid());
    const dir = std.fs.path.dirname(path).?;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};

    // Our own uid allowed: served. The socket file is 0600 and the directory 0700.
    {
        const uids = [_]u32{my_uid};
        var cfg = owner_cfg;
        cfg.allowed_peer_uids = &uids;
        const rig = try Rig.init(.{}, cfg, .{ .unix = path });
        defer rig.deinit();
        const st = try Io.Dir.cwd().statFile(testing.io, path, .{});
        try testing.expectEqual(@as(u32, 0o600), @intFromEnum(st.permissions) & 0o777);
        var d = try Io.Dir.cwd().openDir(testing.io, dir, .{});
        defer d.close(testing.io);
        const ds = try d.stat(testing.io);
        try testing.expectEqual(@as(u32, 0o700), @intFromEnum(ds.permissions) & 0o777);
        const ok = try unixGet(rig, "/");
        defer freeHttp(ok);
        try testing.expectEqual(@as(u16, 200), ok.status);
    }
    // Only root allowed (what tailscaled is): this process is refused.
    {
        const uids = [_]u32{0};
        var cfg = owner_cfg;
        cfg.allowed_peer_uids = &uids;
        const rig = try Rig.init(.{}, cfg, .{ .unix = path });
        defer rig.deinit();
        const no = try unixGet(rig, "/");
        defer freeHttp(no);
        try testing.expectEqual(@as(u16, 403), no.status);
        try testing.expectEqual(@intFromEnum(access.Refusal.wrong_peer), rig.srv.last_refusal.load(.acquire));
    }
}

test "server: refuses to start without any access rule, and in a directory others can enter" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();
    try testing.expectError(error.AccessNotConfigured, Server.start(a, testing.io, h, .{ .listen = .{ .tcp_loopback = 0 }, .access = .{} }));

    var pb: [96]u8 = undefined;
    const path = try tmpSocketPath(&pb, testing.io);
    const dir = std.fs.path.dirname(path).?;
    try Io.Dir.cwd().createDirPath(testing.io, dir);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    {
        var z: [128:0]u8 = undefined;
        const dz = try std.fmt.bufPrintSentinel(&z, "{s}", .{dir}, 0);
        try testing.expectEqual(@as(c_int, 0), std.c.chmod(dz, 0o755));
    }
    try testing.expectError(error.SocketDirNotPrivate, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = owner_cfg }));
}

test "live: a browser socket drives a throwaway terminal on a real Rex (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();
    const srv = try Server.start(a, testing.io, h, .{ .listen = .{ .tcp_loopback = 0 }, .access = token_cfg });
    defer srv.stop();

    // A throwaway session, made through the bridge's own protocol.
    var api = rex.api.Api.init(a, ctl);
    defer api.deinit();
    var made = try api.createSession("rweb-test-live-bridge");
    defer made.deinit();
    const sid = made.value.session_id;
    defer api.destroySession(sid) catch {};
    const bid = made.value.block_id;

    var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(srv.port) };
    const stream = try addr.connect(testing.io, .{ .mode = .stream });
    const c = try rex.ws.Conn.connectStream(a, testing.io, stream, "/ws?token=" ++ token, null, "Origin: http://localhost\r\n");
    defer c.deinit(a);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ sid, bid });
    try waitText(c, "\"t\":\"opened\"");
    // The shell may still be starting; type once it has drawn something.
    try waitBinary(c, "\x1bc");
    try sendJson(c, "{{\"t\":\"in\",\"d\":\"echo bridge-live-$((6*7))\\n\"}}", .{});
    try waitBinary(c, "bridge-live-42");
    // Read-only: refused, and the shell does not run it.
    try sendJson(c, "{{\"t\":\"observe\",\"on\":true}}", .{});
    try waitText(c, "\"observe\":true");
    try sendJson(c, "{{\"t\":\"in\",\"d\":\"echo should-not-run-$((1+1))\\n\"}}", .{});
    try waitText(c, "read-only");
}
