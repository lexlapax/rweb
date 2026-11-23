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
const xfer = @import("xfer.zig");
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
    /// A secret first path segment every request must carry, for a loopback TCP listener where
    /// any local process could otherwise forge the proxy's identity headers: Tailscale Serve is
    /// pointed at `http://127.0.0.1:PORT/<secret>` and adds it, a local process does not know it.
    /// Requests without it get a plain 404 before anything else is looked at.
    backend_secret: ?[]const u8 = null,
    /// Serve the transport-lab and selection-lab pages and endpoints (diagnostics, off by default).
    lab: bool = false,
    /// How long a new connection may take to send its request head.
    head_timeout_ms: u32 = 10_000,
    /// Connections that have not yet passed the access check, at most. The rest of
    /// `max_connections` is for requests that did.
    max_pending: u32 = 16,
};

const security_headers = [_]std.http.Header{
    .{ .name = "content-security-policy", .value = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
    .{ .name = "x-content-type-options", .value = "nosniff" },
    .{ .name = "referrer-policy", .value = "no-referrer" },
    .{ .name = "cross-origin-opener-policy", .value = "same-origin" },
    .{ .name = "cross-origin-resource-policy", .value = "same-origin" },
    .{ .name = "x-frame-options", .value = "DENY" },
    .{ .name = "permissions-policy", .value = "camera=(), microphone=(), geolocation=(), payment=(), usb=(), serial=(), bluetooth=()" },
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
    /// Connections accepted but not yet through the access check.
    pending: std.atomic.Value(u32) = .init(0),
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
                try clearStaleSocket(io, path);
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
            // A unix peer is checked at once, before it can hold anything.
            if (s.opts.listen == .unix) if (s.opts.access.allowed_peer_uids) |uids| {
                const uid = peerUid(conn);
                const ok = if (uid) |u| std.mem.indexOfScalar(u32, uids, u) != null else false;
                if (!ok) {
                    s.last_refusal.store(@intFromEnum(access.Refusal.wrong_peer), .release);
                    _ = s.refusals.fetchAdd(1, .acq_rel);
                    log.info("refused: {s}", .{access.Refusal.wrong_peer.text()});
                    conn.close(s.io);
                    continue;
                }
            };
            if (s.active.load(.acquire) >= s.opts.max_connections or s.pending.load(.acquire) >= s.opts.max_pending) {
                conn.close(s.io);
                continue;
            }
            _ = s.active.fetchAdd(1, .acq_rel);
            _ = s.pending.fetchAdd(1, .acq_rel);
            s.group.concurrent(s.io, handleConn, .{ s, conn }) catch {
                _ = s.active.fetchSub(1, .acq_rel);
                _ = s.pending.fetchSub(1, .acq_rel);
                conn.close(s.io);
            };
        }
    }

    /// Cuts a connection that has not sent a complete request head in time.
    fn headWatchdog(s: *Server, conn: Io.net.Stream, done: *std.atomic.Value(bool)) void {
        s.io.sleep(.fromMilliseconds(s.opts.head_timeout_ms), .awake) catch return;
        if (!done.load(.acquire)) {
            log.info("dropping a connection that sent no request in {d} ms", .{s.opts.head_timeout_ms});
            conn.shutdown(s.io, .both) catch {};
        }
    }

    fn handleConn(s: *Server, conn: Io.net.Stream) void {
        s.conns_mu.lockUncancelable(s.io);
        s.conns.append(s.gpa, conn) catch {};
        s.conns_mu.unlock(s.io);
        var pending = true;
        var head_done: std.atomic.Value(bool) = .init(false);
        var watchdog: ?Io.Future(void) = s.io.concurrent(headWatchdog, .{ s, conn, &head_done }) catch null;
        defer {
            if (watchdog) |*w| w.cancel(s.io);
            if (pending) _ = s.pending.fetchSub(1, .acq_rel);
            s.conns_mu.lockUncancelable(s.io);
            for (s.conns.items, 0..) |c, i| if (c.socket.handle == conn.socket.handle) {
                _ = s.conns.swapRemove(i);
                break;
            };
            s.conns_mu.unlock(s.io);
            _ = s.active.fetchSub(1, .acq_rel);
            conn.close(s.io);
        }
        s.serve(conn, &pending, &head_done) catch |e| log.debug("connection ended: {t}", .{e});
    }

    fn serve(s: *Server, conn: Io.net.Stream, pending: *bool, head_done: *std.atomic.Value(bool)) !void {
        const gpa = s.gpa;
        const recv = try gpa.alloc(u8, 16 * 1024);
        defer gpa.free(recv);
        const send = try gpa.alloc(u8, 32 * 1024);
        defer gpa.free(send);
        var r = conn.reader(s.io, recv);
        var w = conn.writer(s.io, send);
        var http = std.http.Server.init(&r.interface, &w.interface);
        var req = try http.receiveHead();
        head_done.store(true, .release);
        const t_head = std.Io.Clock.awake.now(s.io).toMilliseconds();
        // The request log names only a path the bridge knows (never the secret prefix, a query,
        // or text a client chose, which could carry a token or forge log lines).
        var logged_path: []const u8 = "(unparsed)";
        defer log.info("request {s} {s} (head read at {d}, handled in {d} ms)", .{ @tagName(req.head.method), logged_path, t_head, std.Io.Clock.awake.now(s.io).toMilliseconds() - t_head });

        // ---- the backend secret, if there is one: first, and answered with a bare 404 ----
        const rest: []const u8 = if (s.opts.backend_secret) |secret|
            (stripSecret(req.head.target, secret) orelse {
                logged_path = "(wrong prefix)";
                s.last_refusal.store(@intFromEnum(access.Refusal.wrong_peer), .release);
                _ = s.refusals.fetchAdd(1, .acq_rel);
                try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            })
        else
            req.head.target;
        const path_part = rest[0 .. std.mem.indexOfScalar(u8, rest, '?') orelse rest.len];
        const path = if (path_part.len == 0) "/" else path_part;
        logged_path = knownPath(path);

        // ---- access: before anything else ----
        var hdrs: [64]access.Header = undefined;
        var n: usize = 0;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (n == hdrs.len) { // never judge a request on part of its headers
                s.last_refusal.store(@intFromEnum(access.Refusal.ambiguous_header), .release);
                _ = s.refusals.fetchAdd(1, .acq_rel);
                log.info("refused: too many headers", .{});
                try req.respond("too many headers\n", .{ .status = .request_header_fields_too_large, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            }
            hdrs[n] = .{ .name = h.name, .value = h.value };
            n += 1;
        }
        const upgrade = req.upgradeRequested();
        const areq: access.Request = .{
            .peer_uid = if (s.opts.listen == .unix) peerUid(conn) else null,
            .headers = hdrs[0..n],
            .query_token = access.queryToken(rest),
            .is_websocket_upgrade = upgrade == .websocket,
            .requires_origin = req.head.method != .GET and req.head.method != .HEAD,
        };
        switch (access.decide(s.opts.access, areq)) {
            .allow => {
                if (pending.*) {
                    pending.* = false;
                    _ = s.pending.fetchSub(1, .acq_rel);
                }
            },
            .deny => |why| {
                s.last_refusal.store(@intFromEnum(why), .release);
                _ = s.refusals.fetchAdd(1, .acq_rel);
                log.info("refused: {s}", .{why.text()});
                try req.respond("forbidden\n", .{ .status = .forbidden, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            },
        }

        const is_xfer = std.mem.startsWith(u8, path, "/xfer/");
        if (is_xfer and (req.head.method == .GET or req.head.method == .PUT)) {
            if (!s.hub.cfg.transfer.enabled) {
                try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            }
            // The token is the whole of the path after `/xfer/`; copy it, as reading a body
            // invalidates the request's strings.
            const tail = path["/xfer/".len..];
            if (tail.len != 32) {
                try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            }
            var xtoken: [32]u8 = undefined;
            @memcpy(&xtoken, tail);
            return if (req.head.method == .GET) s.serveDownload(&req, &xtoken) else s.serveUpload(&req, &xtoken);
        }
        if (req.head.method != .GET) {
            try req.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }
        const is_lab = std.mem.startsWith(u8, path, "/lab") or std.mem.startsWith(u8, path, "/api/lab");
        if (is_lab and !s.opts.lab) {
            try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }

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
            log.info("lab result received", .{}); // never the query: it can carry a token
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
        var cookie_buf: [160]u8 = undefined;
        var behind_https = false;
        for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-proto") and std.ascii.eqlIgnoreCase(h.value, "https")) {
            behind_https = true;
        };
        const cookie: ?[]const u8 = if (s.opts.access.token != null and query_token != null and is_root)
            std.fmt.bufPrint(&cookie_buf, "rweb-token={s}; Path=/; HttpOnly; SameSite=Strict{s}", .{ query_token.?, if (behind_https) "; Secure" else "" }) catch null
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

    fn refuseXfer(req: *std.http.Server.Request, status: std.http.Status, text: []const u8) !void {
        try req.respond(text, .{ .status = status, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
    }

    /// `GET /xfer/<token>`: stream the file Rex opened for the token.
    fn serveDownload(s: *Server, req: *std.http.Server.Request, xtoken: []const u8) !void {
        var entry = s.hub.xfers.take(xtoken, .download) orelse return refuseXfer(req, .not_found, "not found\n");
        defer entry.deinit(s.gpa);
        if (!s.hub.xfers.acquire()) return refuseXfer(req, .too_many_requests, "too many transfers\n");
        defer s.hub.xfers.release();

        const max = s.hub.cfg.transfer.max_bytes;
        var st = rex.transfer.Stream.open(s.gpa, s.io, s.hub.ctl.opts.socket_path, entry.ticket) catch |e| {
            log.info("download: Rex refused the stream: {t}", .{e});
            return refuseXfer(req, .bad_gateway, "Rex did not give the file\n");
        };
        defer st.deinit();

        var nb: [128]u8 = undefined;
        const shown = xfer.safeName(&nb, entry.name);
        log.info("download start: {s} ({d} bytes announced)", .{ shown, entry.size });

        var cd_buf: [400]u8 = undefined;
        var hb: [16]std.http.Header = undefined;
        const extra = [_]std.http.Header{
            .{ .name = "content-type", .value = "application/octet-stream" },
            .{ .name = "content-disposition", .value = xfer.contentDisposition(&cd_buf, entry.name) },
            .{ .name = "cache-control", .value = "no-store" },
        };
        var out_buf: [16 * 1024]u8 = undefined;
        var body = try req.respondStreaming(&out_buf, .{ .respond_options = .{ .keep_alive = false, .extra_headers = withSecurity(&hb, &extra) } });
        var total: u64 = 0;
        while (true) {
            const chunk = (st.next() catch |e| {
                log.info("download failed after {d} bytes: {t}", .{ total, e });
                return error.TransferFailed; // the connection is cut: the browser sees a failed download
            }) orelse break;
            defer s.gpa.free(chunk);
            total += chunk.len;
            if (total > max) {
                st.abort();
                log.info("download stopped: more than {d} bytes", .{max});
                return error.TransferTooLarge;
            }
            try body.writer.writeAll(chunk);
        }
        try body.end();
        log.info("download done: {s} {d} bytes", .{ shown, total });
    }

    /// `PUT /xfer/<token>`: write the body into the upload directory under a safe, new name, then
    /// paste its quoted path into the terminal.
    fn serveUpload(s: *Server, req: *std.http.Server.Request, xtoken: []const u8) !void {
        var entry = s.hub.xfers.take(xtoken, .upload) orelse return refuseXfer(req, .not_found, "not found\n");
        defer entry.deinit(s.gpa);
        const dir_path = s.hub.cfg.transfer.upload_dir orelse return refuseXfer(req, .not_found, "not found\n");
        if (!s.hub.xfers.acquire()) return refuseXfer(req, .too_many_requests, "too many transfers\n");
        defer s.hub.xfers.release();

        const len = req.head.content_length orelse return refuseXfer(req, .length_required, "length required\n");
        if (len != entry.size) return refuseXfer(req, .bad_request, "the size is not what was announced\n");
        if (len > s.hub.cfg.transfer.max_bytes) return refuseXfer(req, .payload_too_large, "too large\n");

        var dir = Io.Dir.cwd().openDir(s.io, dir_path, .{}) catch return refuseXfer(req, .internal_server_error, "the upload folder cannot be opened\n");
        defer dir.close(s.io);

        // A name that is safe, and that does not replace anything: "a.txt", "a (1).txt", ...
        var nb: [128]u8 = undefined;
        const safe = xfer.safeName(&nb, entry.name);
        var name_buf: [160]u8 = undefined;
        var final: []const u8 = safe;
        var file: ?Io.File = null;
        var attempt: u32 = 0;
        while (attempt < 100) : (attempt += 1) {
            if (attempt > 0) {
                const dot = std.mem.lastIndexOfScalar(u8, safe, '.');
                const stem = if (dot) |d| (if (d == 0) safe else safe[0..d]) else safe;
                const ext = if (dot) |d| (if (d == 0) "" else safe[d..]) else "";
                final = std.fmt.bufPrint(&name_buf, "{s} ({d}){s}", .{ stem, attempt, ext }) catch return refuseXfer(req, .internal_server_error, "name\n");
            }
            if (dir.createFile(s.io, final, .{ .exclusive = true, .permissions = @enumFromInt(0o600) })) |f| {
                file = f;
                break;
            } else |e| switch (e) {
                error.PathAlreadyExists => continue,
                else => return refuseXfer(req, .internal_server_error, "cannot create the file\n"),
            }
        }
        const f = file orelse return refuseXfer(req, .internal_server_error, "no free name\n");
        var keep = false;
        defer {
            f.close(s.io);
            if (!keep) dir.deleteFile(s.io, final) catch {};
        }

        // The body, exactly `len` bytes.
        var body_buf: [16 * 1024]u8 = undefined;
        const reader = try req.readerExpectContinue(&body_buf);
        var chunk: [64 * 1024]u8 = undefined;
        var left: u64 = len;
        while (left > 0) {
            const want: usize = @intCast(@min(left, chunk.len));
            const n = reader.readSliceShort(chunk[0..want]) catch return error.UploadFailed;
            if (n == 0) return error.UploadFailed; // the browser stopped early
            f.writeStreamingAll(s.io, chunk[0..n]) catch return error.UploadFailed;
            left -= n;
        }
        keep = true;
        log.info("upload done: {s} {d} bytes", .{ final, len });

        // Tell the terminal where it is: the quoted path, as if pasted (no Enter).
        const full = try std.fs.path.join(s.gpa, &.{ dir_path, final });
        defer s.gpa.free(full);
        const quoted = try xfer.shellQuote(s.gpa, full);
        defer s.gpa.free(quoted);
        // A space after it, so that several uploads paste as separate words, not one glued together.
        const typed = try std.fmt.allocPrint(s.gpa, "{s} ", .{quoted});
        defer s.gpa.free(typed);
        s.hub.api_mu.lockUncancelable(s.io);
        const pasted = s.hub.api.paste(entry.session_id, entry.block_id, typed);
        s.hub.api_mu.unlock(s.io);
        pasted catch |e| log.info("upload: the path could not be pasted: {t}", .{e});

        const reply = try std.json.Stringify.valueAlloc(s.gpa, .{ .ok = true, .name = final, .path = full }, .{});
        defer s.gpa.free(reply);
        try req.respond(reply, .{ .keep_alive = false, .extra_headers = &(security_headers ++ no_store ++ [_]std.http.Header{.{ .name = "content-type", .value = "application/json" }}) });
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

/// What follows the secret first segment of `target` (`/<secret>` then nothing, `/` or `?`),
/// or null when the target does not start with the secret. The comparison takes the same time
/// wherever the first difference is.
pub fn stripSecret(target: []const u8, secret: []const u8) ?[]const u8 {
    if (secret.len == 0 or target.len < 1 + secret.len or target[0] != '/') return null;
    var diff: u8 = 0;
    for (target[1 .. 1 + secret.len], secret) |a, b| diff |= a ^ b;
    if (diff != 0) return null;
    const rest = target[1 + secret.len ..];
    if (rest.len != 0 and rest[0] != '/' and rest[0] != '?') return null; // a longer first segment
    return rest;
}

/// The path to write in the log: one the bridge serves, or a fixed word. Never client text.
fn knownPath(path: []const u8) []const u8 {
    if (assets.indexOf(path)) |i| return assets.all[i].path;
    for ([_][]const u8{ "/ws", "/labws", "/api/tree", "/api/lab/hb", "/api/lab/result" }) |k| if (std.mem.eql(u8, path, k)) return k;
    if (std.mem.startsWith(u8, path, "/xfer/")) return "/xfer/(token)"; // never the token itself
    return "(other)";
}

/// Remove a stale socket file at `path`, but never anything else: a file that is not a socket,
/// or a socket something is still listening on, is an error.
fn clearStaleSocket(io: Io, path: []const u8) !void {
    const st = Io.Dir.cwd().statFile(io, path, .{}) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    if (st.kind != .unix_domain_socket) return error.NotASocket;
    const addr = try Io.net.UnixAddress.init(path);
    if (addr.connect(io)) |c| {
        c.close(io);
        return error.AddressInUse;
    } else |_| {}
    try Io.Dir.deleteFileAbsolute(io, path);
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

    const Extra = struct { backend_secret: ?[]const u8 = null, head_timeout_ms: u32 = 10_000, max_pending: u32 = 16, lab: bool = true };

    fn init(hub_cfg: hub_mod.Config, acc: access.Config, listen: Listen) !Rig {
        return initExtra(hub_cfg, acc, listen, .{});
    }

    fn initExtra(hub_cfg: hub_mod.Config, acc: access.Config, listen: Listen, extra: Extra) !Rig {
        const a = testing.allocator;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const made = try f.createSession("rweb-test-server");
        const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const h = try Hub.open(a, testing.io, ctl, hub_cfg);
        errdefer h.close();
        const srv = try Server.start(a, testing.io, h, .{ .listen = listen, .access = acc, .backend_secret = extra.backend_secret, .head_timeout_ms = extra.head_timeout_ms, .max_pending = extra.max_pending, .lab = extra.lab });
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

    for ([_][]const u8{ "/app.js", "/keys.js", "/lab", "/lab.js", "/app.css", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js", "/vendor/LICENSE-xterm.txt", "/wterm-shim.js", "/vendor/wterm.js", "/vendor/wterm.css", "/vendor/ghostty-vt.wasm", "/vendor/LICENSE-wterm.txt" }) |p| {
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
    const req = try std.fmt.allocPrint(testing.allocator, "GET {s} HTTP/1.1\r\nHost: localhost\r\nTailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.9\r\nConnection: close\r\n\r\n", .{path});
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
        // Refused at accept: the connection is closed without a word.
        if (unixGet(rig, "/")) |no| {
            freeHttp(no);
            return error.PeerWasServed;
        } else |_| {}
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

// ---- the fixes from the 2026-11-23 security review ----

const owner_hdrs = "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.9\r\n";

test "server: headers past the 48th can no longer hide a refusal" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    // The node's own address in the 70th header: before, it was never looked at.
    var hdrs: std.ArrayList(u8) = .empty;
    defer hdrs.deinit(testing.allocator);
    for (0..68) |i| try hdrs.print(testing.allocator, "X-Filler-{d}: x\r\n", .{i});
    try hdrs.appendSlice(testing.allocator, "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.5\r\n");
    const h = try get(rig, "/", hdrs.items);
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 431), h.status);
    // A request with room to spare, in the same shape, is judged normally.
    var few: std.ArrayList(u8) = .empty;
    defer few.deinit(testing.allocator);
    for (0..20) |i| try few.print(testing.allocator, "X-Filler-{d}: x\r\n", .{i});
    try few.appendSlice(testing.allocator, "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.5\r\n");
    try expectRefusedWith(rig, few.items, .own_address);
}

test "server: a repeated identity header is refused" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    try expectRefusedWith(rig, owner_hdrs ++ "Tailscale-User-Login: owner@example.com\r\n", .ambiguous_header);
    try expectRefusedWith(rig, owner_hdrs ++ "X-Forwarded-For: 100.64.0.5\r\n", .ambiguous_header);
    // A missing X-Forwarded-For, with the own-address rule on, is refused too.
    try expectRefusedWith(rig, "Tailscale-User-Login: owner@example.com\r\n", .no_forwarded_for);
}

test "server: the backend secret keeps local processes out, whatever headers they forge" {
    const secret = "0123456789abcdef0123456789abcdef";
    const rig = try Rig.initExtra(.{}, owner_cfg, .{ .tcp_loopback = 0 }, .{ .backend_secret = secret });
    defer rig.deinit();
    // The owner's identity, forged by a local process that does not know the secret: a bare 404,
    // not even a 403 that would say the identity was looked at.
    const forged = try get(rig, "/", owner_hdrs);
    defer freeHttp(forged);
    try testing.expectEqual(@as(u16, 404), forged.status);
    const forged_api = try get(rig, "/api/tree", owner_hdrs);
    defer freeHttp(forged_api);
    try testing.expectEqual(@as(u16, 404), forged_api.status);
    // A near miss: a longer first segment, a prefix of the secret, the secret with a typo.
    for ([_][]const u8{ "/" ++ secret ++ "x/", "/0123456789abcdef0123456789abcde/", "/0123456789abcdef0123456789abcdeX/" }) |p| {
        const h = try get(rig, p, owner_hdrs);
        defer freeHttp(h);
        try testing.expectEqual(@as(u16, 404), h.status);
    }
    // What Serve sends: the page and the tree under the secret, with the identity it adds.
    const page = try get(rig, "/" ++ secret ++ "/", owner_hdrs);
    defer freeHttp(page);
    try testing.expectEqual(@as(u16, 200), page.status);
    try testing.expect(std.mem.indexOf(u8, page.body, "<title>rweb</title>") != null);
    const bare = try get(rig, "/" ++ secret, owner_hdrs);
    defer freeHttp(bare);
    try testing.expectEqual(@as(u16, 200), bare.status);
    const js = try get(rig, "/" ++ secret ++ "/app.js", owner_hdrs);
    defer freeHttp(js);
    try testing.expectEqual(@as(u16, 200), js.status);
    // With the secret, the identity rules still apply.
    const wrong = try get(rig, "/" ++ secret ++ "/", "Tailscale-User-Login: someone@example.com\r\nX-Forwarded-For: 100.64.0.9\r\n");
    defer freeHttp(wrong);
    try testing.expectEqual(@as(u16, 403), wrong.status);
}

test "server: stripSecret" {
    try testing.expectEqualStrings("/a", stripSecret("/abc/a", "abc").?);
    try testing.expectEqualStrings("", stripSecret("/abc", "abc").?);
    try testing.expectEqualStrings("?x=1", stripSecret("/abc?x=1", "abc").?);
    try testing.expect(stripSecret("/abcd/a", "abc") == null);
    try testing.expect(stripSecret("/ab", "abc") == null);
    try testing.expect(stripSecret("abc/", "abc") == null);
    try testing.expect(stripSecret("/abc/", "") == null);
}

test "server: the diagnostic pages are off unless asked for, and never log a query" {
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .lab = false });
    defer rig.deinit();
    for ([_][]const u8{ "/lab", "/lab.js", "/labsel", "/labsel.js", "/api/lab/hb", "/api/lab/result" }) |p| {
        const path = try std.fmt.allocPrint(testing.allocator, "{s}?token={s}", .{ p, token });
        defer testing.allocator.free(path);
        const h = try get(rig, path, "");
        defer freeHttp(h);
        try testing.expectEqual(@as(u16, 404), h.status);
    }
    const ok = try get(rig, "/?token=" ++ token, "");
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
}

test "server: a connection that never sends a request is cut, and cannot fill the slots" {
    // Two unauthenticated slots, 300 ms to send a head.
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .max_pending = 2, .head_timeout_ms = 300 });
    defer rig.deinit();
    const idle1 = try rig.tcp();
    defer idle1.close(testing.io);
    const idle2 = try rig.tcp();
    defer idle2.close(testing.io);
    try testing.io.sleep(.fromMilliseconds(100), .awake);
    // The slots for unauthenticated connections are full: a third is turned away at once.
    const third = try rig.tcp();
    var buf: [64]u8 = undefined;
    var rd = third.reader(testing.io, &buf);
    try testing.expectError(error.EndOfStream, rd.interface.takeByte());
    third.close(testing.io);
    // After the deadline the idle ones are gone and a real request is served.
    try testing.io.sleep(.fromMilliseconds(600), .awake);
    const ok = try get(rig, "/?token=" ++ token, "");
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
}

test "server: a unix socket path that is a file, or in use, is never replaced" {
    var pb: [96]u8 = undefined;
    const path = try tmpSocketPath(&pb, testing.io);
    const dir = std.fs.path.dirname(path).?;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    try prepareSocketDir(testing.io, path);

    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();

    // A regular file is not ours to delete.
    {
        const file = try Io.Dir.cwd().createFile(testing.io, path, .{});
        file.close(testing.io);
        try testing.expectError(error.NotASocket, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = token_cfg }));
        const st = try Io.Dir.cwd().statFile(testing.io, path, .{});
        try testing.expect(st.kind == .file);
        try Io.Dir.cwd().deleteFile(testing.io, path);
    }
    // A live listener is not ours to replace; once it is gone, its stale file is.
    const first = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = token_cfg });
    try testing.expectError(error.AddressInUse, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = token_cfg }));
    first.stop();
    const again = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = token_cfg });
    again.stop();
}

test "server: a browser cannot make Rex do heavy work more than a few times a second" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    // Twenty in a burst: the first few are answered, the rest are refused with a reason.
    for (0..20) |_| try sendJson(c, "{{\"t\":\"info\"}}", .{});
    try waitText(c, "too many requests");
}

// ---- file transfer ----

/// Read text frames until one contains `needle`; return that message (owned by the caller).
fn textWith(c: *rex.ws.Conn, needle: []const u8) ![]u8 {
    var i: u32 = 0;
    while (i < 200) : (i += 1) {
        const m = try c.readMessage(testing.allocator);
        if (m.opcode == .text and std.mem.indexOf(u8, m.data, needle) != null) return m.data;
        testing.allocator.free(m.data);
        if (m.opcode == .close) return error.Closed;
    }
    return error.NotSeen;
}

/// The value of `"token":"…"` in a message.
fn tokenIn(msg: []const u8) ![]const u8 {
    const k = "\"token\":\"";
    const at = std.mem.indexOf(u8, msg, k) orelse return error.NoToken;
    return msg[at + k.len ..][0..32];
}

/// A throwaway directory under /tmp, removed by the caller.
fn tmpDir(buf: []u8) ![]const u8 {
    var rnd: [4]u8 = undefined;
    testing.io.random(&rnd);
    const dir = try std.fmt.bufPrint(buf, "/tmp/rweb-test-xfer-{x}", .{rnd});
    try Io.Dir.cwd().createDirPath(testing.io, dir);
    return dir;
}

const Opened = struct { rig: Rig, c: *rex.ws.Conn };

fn openRig(cfg: hub_mod.Config) !Opened {
    const rig = try Rig.init(cfg, token_cfg, .{ .tcp_loopback = 0 });
    errdefer rig.deinit();
    const c = try browser(rig);
    errdefer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    return .{ .rig = rig, .c = c };
}

fn put(rig: Rig, token_path: []const u8, headers: []const u8, body: []const u8) !Http {
    const req = try std.fmt.allocPrint(testing.allocator, "PUT {s}?token={s} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n{s}Connection: close\r\n\r\n", .{ token_path, token, body.len, headers });
    defer testing.allocator.free(req);
    const all = try testing.allocator.alloc(u8, req.len + body.len);
    defer testing.allocator.free(all);
    @memcpy(all[0..req.len], req);
    @memcpy(all[req.len..], body);
    return httpRequest(try rig.tcp(), all);
}

test "server: file transfer is off by default, and says so" {
    const o = try openRig(.{});
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"/etc/hosts\"}}", .{});
    const e = try textWith(o.c, "file transfer is off");
    testing.allocator.free(e);
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"a\",\"size\":1}}", .{});
    testing.allocator.free(try textWith(o.c, "file transfer is off"));
    // And its address answers nothing.
    const h = try get(o.rig, "/xfer/00000000000000000000000000000000?token=" ++ token, "");
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 404), h.status);
}

test "server: a download goes through a one-time token and nothing else" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const path = try std.fmt.allocPrint(testing.allocator, "{s}/my notes.txt", .{dir});
    defer testing.allocator.free(path);
    const content = try testing.allocator.alloc(u8, 200_000);
    defer testing.allocator.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);
    {
        const f = try Io.Dir.cwd().createFile(testing.io, path, .{});
        defer f.close(testing.io);
        try f.writeStreamingAll(testing.io, content);
    }
    const o = try openRig(.{ .transfer = .{ .enabled = true, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);

    // Without a token, nothing: not even a guess at the shape.
    for ([_][]const u8{ "/xfer/", "/xfer/short", "/xfer/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "/xfer/00000000000000000000000000000000" }) |p| {
        const pp = try std.fmt.allocPrint(testing.allocator, "{s}?token={s}", .{ p, token });
        defer testing.allocator.free(pp);
        const h = try get(o.rig, pp, "");
        defer freeHttp(h);
        try testing.expectEqual(@as(u16, 404), h.status);
    }

    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}\"}}", .{path});
    const msg = try textWith(o.c, "\"t\":\"xfer\"");
    defer testing.allocator.free(msg);
    try testing.expect(std.mem.indexOf(u8, msg, "\"kind\":\"download\"") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "\"name\":\"my notes.txt\"") != null);
    const tok = try tokenIn(msg);
    const url = try std.fmt.allocPrint(testing.allocator, "/xfer/{s}?token={s}", .{ tok, token });
    defer testing.allocator.free(url);

    const h = try get(o.rig, url, "");
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 200), h.status);
    const joined = try dechunk(h.body);
    defer testing.allocator.free(joined);
    try testing.expectEqualSlices(u8, content, joined);
    try testing.expectEqualStrings("application/octet-stream", headerValue(h.head, "content-type").?);
    try testing.expect(std.mem.startsWith(u8, headerValue(h.head, "content-disposition").?, "attachment;"));
    try testing.expectEqualStrings("no-store", headerValue(h.head, "cache-control").?);
    try testing.expect(headerValue(h.head, "content-security-policy") != null);

    // The token is spent.
    const again = try get(o.rig, url, "");
    defer freeHttp(again);
    try testing.expectEqual(@as(u16, 404), again.status);
}

/// The body of a chunked response, joined; the caller frees it.
fn dechunk(body: []const u8) ![]u8 {
    const a = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(a);
    var rest = body;
    while (true) {
        const eol = std.mem.indexOf(u8, rest, "\r\n") orelse return error.BadChunks;
        const n = try std.fmt.parseInt(usize, rest[0..eol], 16);
        if (n == 0) break;
        try out.appendSlice(a, rest[eol + 2 ..][0..n]);
        rest = rest[eol + 2 + n + 2 ..];
    }
    return out.toOwnedSlice(a);
}

test "server: a download of a missing file, or one over the size limit, is refused" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const big = try std.fmt.allocPrint(testing.allocator, "{s}/big.bin", .{dir});
    defer testing.allocator.free(big);
    {
        const f = try Io.Dir.cwd().createFile(testing.io, big, .{});
        defer f.close(testing.io);
        const chunk: [4096]u8 = @splat('x');
        for (0..300) |_| try f.writeStreamingAll(testing.io, &chunk); // 1.2 MB
    }
    const o = try openRig(.{ .transfer = .{ .enabled = true, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}/nope\"}}", .{dir});
    testing.allocator.free(try textWith(o.c, "\"for\":\"dl\""));
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}\"}}", .{big});
    const e = try textWith(o.c, "too large");
    testing.allocator.free(e);
}

test "server: observe-only viewers cannot start a transfer" {
    const o = try openRig(.{ .observe_only = true, .transfer = .{ .enabled = true } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"/etc/hosts\"}}", .{});
    testing.allocator.free(try textWith(o.c, "read-only"));
    try sendJson(o.c, "{{\"t\":\"ls\",\"path\":\"/\"}}", .{});
    testing.allocator.free(try textWith(o.c, "read-only"));
}

test "server: a directory listing for the picker" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const sub = try std.fmt.allocPrint(testing.allocator, "{s}/sub", .{dir});
    defer testing.allocator.free(sub);
    try Io.Dir.cwd().createDirPath(testing.io, sub);
    const fp = try std.fmt.allocPrint(testing.allocator, "{s}/a.txt", .{dir});
    defer testing.allocator.free(fp);
    (try Io.Dir.cwd().createFile(testing.io, fp, .{})).close(testing.io);
    const o = try openRig(.{ .transfer = .{ .enabled = true } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try sendJson(o.c, "{{\"t\":\"ls\",\"path\":\"{s}\"}}", .{dir});
    const m = try textWith(o.c, "\"t\":\"ls\"");
    defer testing.allocator.free(m);
    try testing.expect(std.mem.indexOf(u8, m, "\"n\":\"a.txt\",\"d\":false") != null);
    try testing.expect(std.mem.indexOf(u8, m, "\"n\":\"sub\",\"d\":true") != null);
    try testing.expect(std.mem.indexOf(u8, m, "\"status\":\"ok\"") != null);
}

test "server: an upload lands only in the upload folder, under a safe new name, and its path is pasted" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = dir, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    const content = "hello from a phone\nsecond line\n";

    // A hostile name: path parts and shell characters.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"../../etc/evil;rm -rf ~.txt\",\"size\":{d}}}", .{content.len});
    const msg = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(msg);
    const url = try std.fmt.allocPrint(testing.allocator, "/xfer/{s}", .{try tokenIn(msg)});
    defer testing.allocator.free(url);
    const r = try put(o.rig, url, "Origin: http://localhost\r\n", content);
    defer freeHttp(r);
    try testing.expectEqual(@as(u16, 200), r.status);

    // Only the safe name, in the folder, with the content, closed to others.
    const saved = try std.fmt.allocPrint(testing.allocator, "{s}/evil_rm -rf _.txt", .{dir});
    defer testing.allocator.free(saved);
    const got = try Io.Dir.cwd().readFileAlloc(testing.io, saved, testing.allocator, .limited(1 << 16));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(content, got);
    const st = try Io.Dir.cwd().statFile(testing.io, saved, .{});
    try testing.expectEqual(@as(u32, 0o600), @intFromEnum(st.permissions) & 0o777);
    try testing.expect(std.mem.indexOf(u8, r.body, "evil_rm -rf _.txt") != null);
    // Nothing escaped into the folders above it.
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, "/tmp/etc/evil;rm -rf ~.txt", .{}));

    // The terminal was given the quoted path, to type or not.
    const quoted = try std.fmt.allocPrint(testing.allocator, "'{s}' ", .{saved}); // with the space that separates it from the next
    defer testing.allocator.free(quoted);
    try waitBinary(o.c, quoted);

    // The same name again does not replace it.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"evil;rm -rf ~.txt\",\"size\":3}}", .{});
    const msg2 = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(msg2);
    const url2 = try std.fmt.allocPrint(testing.allocator, "/xfer/{s}", .{try tokenIn(msg2)});
    defer testing.allocator.free(url2);
    const r2 = try put(o.rig, url2, "Origin: http://localhost\r\n", "new");
    defer freeHttp(r2);
    try testing.expectEqual(@as(u16, 200), r2.status);
    const second = try std.fmt.allocPrint(testing.allocator, "{s}/evil_rm -rf _ (1).txt", .{dir});
    defer testing.allocator.free(second);
    const got2 = try Io.Dir.cwd().readFileAlloc(testing.io, second, testing.allocator, .limited(64));
    defer testing.allocator.free(got2);
    try testing.expectEqualStrings("new", got2);
    const got1 = try Io.Dir.cwd().readFileAlloc(testing.io, saved, testing.allocator, .limited(1 << 16));
    defer testing.allocator.free(got1);
    try testing.expectEqualStrings(content, got1); // the first is untouched
}

test "server: an upload is refused without the page's Origin, with the wrong size, twice, or too big" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = dir, .max_bytes = 1000 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);

    // Too big, said at the first step.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"big\",\"size\":5000}}", .{});
    testing.allocator.free(try textWith(o.c, "too large"));

    // Another site's page (a cross-site PUT carries its own Origin): 403 and the token is not spent.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"a.txt\",\"size\":4}}", .{});
    const m = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(m);
    const url = try std.fmt.allocPrint(testing.allocator, "/xfer/{s}", .{try tokenIn(m)});
    defer testing.allocator.free(url);
    const evil = try put(o.rig, url, "Origin: https://evil.example\r\n", "data");
    defer freeHttp(evil);
    try testing.expectEqual(@as(u16, 403), evil.status);
    const noorigin = try put(o.rig, url, "", "data");
    defer freeHttp(noorigin);
    try testing.expectEqual(@as(u16, 403), noorigin.status);

    // The wrong length spends the token (so a guess cannot be refined) and writes nothing.
    const wrong = try put(o.rig, url, "Origin: http://localhost\r\n", "toolong!");
    defer freeHttp(wrong);
    try testing.expectEqual(@as(u16, 400), wrong.status);
    const reuse = try put(o.rig, url, "Origin: http://localhost\r\n", "data");
    defer freeHttp(reuse);
    try testing.expectEqual(@as(u16, 404), reuse.status);
    const ghost = try std.fmt.allocPrint(testing.allocator, "{s}/a.txt", .{dir});
    defer testing.allocator.free(ghost);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, ghost, .{}));

    // A download token cannot be used to upload.
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"/etc/hosts\"}}", .{});
    const d = try textWith(o.c, "\"kind\":\"download\"");
    defer testing.allocator.free(d);
    const durl = try std.fmt.allocPrint(testing.allocator, "/xfer/{s}", .{try tokenIn(d)});
    defer testing.allocator.free(durl);
    const swap = try put(o.rig, durl, "Origin: http://localhost\r\n", "x");
    defer freeHttp(swap);
    try testing.expectEqual(@as(u16, 404), swap.status);
}
