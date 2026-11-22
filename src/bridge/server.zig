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
};

const security_headers = [_]std.http.Header{
    .{ .name = "content-security-policy", .value = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
    .{ .name = "cache-control", .value = "no-store" },
    .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
};

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
                try req.respond("forbidden\n", .{ .status = .forbidden, .keep_alive = false, .extra_headers = &security_headers });
                return;
            },
        }

        if (req.head.method != .GET) {
            try req.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = &security_headers });
            return;
        }
        const path = target[0 .. std.mem.indexOfScalar(u8, target, '?') orelse target.len];

        if (std.mem.eql(u8, path, "/ws")) {
            const key = switch (upgrade) {
                .websocket => |k| k orelse return error.NoKey,
                else => {
                    try req.respond("expected a WebSocket upgrade\n", .{ .status = .bad_request, .keep_alive = false, .extra_headers = &security_headers });
                    return;
                },
            };
            var sock = try req.respondWebSocket(.{ .key = key });
            try sock.flush();
            return s.viewerSession(conn, &sock);
        }
        if (std.mem.eql(u8, path, "/api/tree")) {
            const owned = s.hub.treeJson();
            defer if (owned) |t| s.gpa.free(t);
            const tree = owned orelse "{\"t\":\"tree\",\"sessions\":[]}";
            try req.respond(tree, .{ .keep_alive = false, .extra_headers = &(security_headers ++ [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }}) });
            return;
        }
        if (assets.find(path)) |a| {
            try req.respond(a.body, .{ .keep_alive = false, .extra_headers = &(security_headers ++ [_]std.http.Header{.{ .name = "content-type", .value = a.content_type }}) });
            return;
        }
        try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &security_headers });
    }

    /// One browser: a writer task drains the viewer's queue; this task reads commands.
    fn viewerSession(s: *Server, conn: Io.net.Stream, sock: *std.http.Server.WebSocket) !void {
        const gpa = s.gpa;
        const c = try rex.ws.Conn.fromHttp(gpa, s.io, conn, sock.input, sock.output, protocol.max_message_bytes);
        defer c.deinit(gpa);
        const v = try s.hub.addViewer();
        var writer = try s.io.concurrent(writerLoop, .{ s, c, v });

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        while (true) {
            const m = c.readMessage(gpa) catch break;
            defer gpa.free(m.data);
            switch (m.opcode) {
                .close => break,
                .text => {
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

    fn writerLoop(s: *Server, c: *rex.ws.Conn, v: *hub_mod.Viewer) void {
        var idle: u32 = 0;
        while (true) {
            const f = (v.next(5000) catch return) orelse {
                if (v.isClosed()) return;
                idle += 1;
                if (idle >= 4) { // a ping every ~20 s keeps Serve and phones' networks from idling the socket out
                    idle = 0;
                    c.writeFrame(.ping, "") catch return;
                }
                continue;
            };
            defer f.deinit(s.gpa);
            idle = 0;
            c.writeFrame(if (f.binary) .binary else .text, f.data) catch return;
        }
    }
};

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

    for ([_][]const u8{ "/app.js", "/app.css", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js", "/vendor/LICENSE-xterm.txt" }) |p| {
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
    while (i < 80) : (i += 1) {
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
        var d = try Io.Dir.cwd().openDir(testing.io, dir, .{});
        defer d.close(testing.io);
        try d.setPermissions(testing.io, @enumFromInt(0o755));
    }
    try testing.expectError(error.SocketDirNotPrivate, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = owner_cfg }));
}
