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
const layout = @import("layout.zig");
const Hub = hub_mod.Hub;

const log = std.log.scoped(.server);

pub const Listen = union(enum) {
    /// A unix socket, by absolute path: created 0600 in a folder of ours that is closed to others,
    /// under folders only we or root can change, none of them a link (Tailscale Serve reaches the
    /// socket by this path, so the path itself must stay ours).
    unix: []const u8,
    /// Loopback TCP only (port 0 picks one): `127.0.0.1` and, where the system has IPv6 loopback,
    /// `[::1]` on the same port, so `localhost` cannot reach another account's listener.
    tcp_loopback: u16,
};

/// A listener taken before anything else at startup and kept through outages of Rex and Tailscale,
/// so the port or socket is never free for another account to take while rweb waits. Connections
/// wait in the kernel's listen queue until `Server.startBound` accepts them; no request is read
/// before the access rules are complete.
pub const Bound = struct {
    listen: Listen,
    listener: Io.net.Server,
    /// `[::1]` on the TCP port; null for a unix socket, or when the system has no IPv6 loopback.
    listener6: ?Io.net.Server = null,
    /// Why `[::1]` is not held on a TCP listener, when it is not.
    v6_missing: ?anyerror = null,
    /// The TCP port.
    port: u16 = 0,
    sock_dir: ?std.posix.fd_t = null,
    sock_name: []const u8 = "",
    sock_id: ?SockId = null,

    /// Release it: close the listeners and remove the unix socket this process made (only that).
    pub fn deinit(b: *Bound, io: Io) void {
        b.listener.deinit(io);
        if (b.listener6) |*l| l.deinit(io);
        if (b.sock_dir) |fd| {
            const dir: Io.Dir = .{ .handle = fd };
            if (socketInPlace(fd, b.sock_name, b.sock_id)) dir.deleteFile(io, b.sock_name) catch {};
            dir.close(io);
        }
        b.* = undefined;
    }
};

const SockId = struct { dev: u64, ino: u64 };

/// Whether `name` in folder `fd` is still the socket with identity `id`.
fn socketInPlace(fd: std.posix.fd_t, name: []const u8, id: ?SockId) bool {
    const want = id orelse return false;
    const n = xfer.statAt(fd, name) catch return false;
    return n.dev == want.dev and n.ino == want.ino;
}

/// The longest unix socket path the system takes, NUL included (`sockaddr_un.sun_path`: 104 bytes on
/// macOS, 108 on Linux).
pub const max_unix_path = @typeInfo(@FieldType(std.posix.sockaddr.un, "path")).array.len;

/// Whether `path` fits in a unix socket address, with its NUL.
pub fn unixPathFits(path: []const u8) bool {
    return path.len < max_unix_path;
}

/// Take the listener `listen` names. A unix socket: in a folder that passes the checks (see
/// `Listen.unix`), created 0600. TCP: `127.0.0.1` and `[::1]` on the same port, without
/// `SO_REUSEPORT` (with it, another socket that also sets it could bind the same port and take
/// connections); a port of 0 picks one free on both. A `[::1]` already taken by another socket is
/// an error; a system with no IPv6 loopback is not (`Bound.v6_missing` says why).
pub fn bind(gpa: Allocator, io: Io, listen: Listen, problem: ?*xfer.Problem) !Bound {
    switch (listen) {
        .unix => |path| {
            // Before anything is made: a path the system cannot bind would fail only after the
            // folders were made.
            if (!unixPathFits(path)) return error.NameTooLong;
            var own_problem: xfer.Problem = .{};
            const dir = try openSocketDir(gpa, io, path, problem orelse &own_problem);
            errdefer (Io.Dir{ .handle = dir.fd }).close(io);
            try clearStaleSocket(io, dir.fd, dir.name, path);
            var b: Bound = .{ .listen = listen, .listener = undefined, .sock_dir = dir.fd, .sock_name = dir.name };
            {
                const old = std.c.umask(0o177); // the socket is created 0600
                defer _ = std.c.umask(old);
                // Bound by path: every folder on it was just checked (only we or root can change
                // them), so the path leads into the folder that is held open.
                const addr = try Io.net.UnixAddress.init(path);
                b.listener = try addr.listen(io, .{});
            }
            errdefer b.listener.deinit(io);
            // What was bound, seen in the kept folder: removed at the end only if still the same.
            const n = try xfer.statAt(dir.fd, dir.name);
            if (!xfer.isSocket(n)) return error.NotASocket;
            b.sock_id = .{ .dev = n.dev, .ino = n.ino };
            return b;
        },
        .tcp_loopback => |want_port| {
            // With port 0, the port picked on 127.0.0.1 may be taken on ::1: try a few.
            var tries: u32 = if (want_port == 0) 16 else 1;
            while (true) {
                tries -= 1;
                var l4 = try listenLoopback(.v4, want_port);
                errdefer l4.deinit(io);
                const port = l4.socket.address.getPort();
                var b: Bound = .{ .listen = .{ .tcp_loopback = port }, .listener = l4, .port = port };
                if (listenLoopback(.v6, port)) |l6| {
                    b.listener6 = l6;
                    return b;
                } else |e| switch (e) {
                    // No IPv6 loopback here: nothing to hold.
                    error.AddressNotAvailable, error.AddressFamilyUnsupported => {
                        b.v6_missing = e;
                        return b;
                    },
                    error.AddressInUse => if (tries > 0) {
                        l4.deinit(io);
                        continue;
                    } else return error.Ip6AddressInUse,
                    else => return e,
                }
            }
        },
    }
}

const Family = enum { v4, v6 };

/// A listening loopback TCP socket on `port`: `SO_REUSEADDR` (a restart is not held up by old
/// connections in TIME_WAIT) and never `SO_REUSEPORT`; IPv6 is `IPV6_V6ONLY`.
fn listenLoopback(family: Family, port: u16) !Io.net.Server {
    const posix = std.posix;
    const af: c_uint = if (family == .v4) posix.AF.INET else posix.AF.INET6;
    const fd = std.c.socket(af, posix.SOCK.STREAM, 0);
    if (fd < 0) return switch (posix.errno(fd)) {
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        else => error.SocketFailed,
    };
    errdefer _ = std.c.close(fd);
    // Without close-on-exec the `tailscale` child would inherit the listener.
    if (std.c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) != 0) return error.SocketFailed;
    const one: c_int = 1;
    if (std.c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int)) != 0) return error.SocketFailed;
    var address: Io.net.IpAddress = undefined;
    const rc = switch (family) {
        .v4 => blk: {
            var sa: posix.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
            address = .{ .ip4 = Io.net.Ip4Address.loopback(port) };
            break :blk std.c.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
        },
        .v6 => blk: {
            if (std.c.setsockopt(fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, &one, @sizeOf(c_int)) != 0) return error.SocketFailed;
            var sa: posix.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = Io.net.Ip6Address.loopback(0).bytes, .scope_id = 0 };
            address = .{ .ip6 = Io.net.Ip6Address.loopback(port) };
            break :blk std.c.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
        },
    };
    if (rc != 0) return switch (posix.errno(rc)) {
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .ACCES => error.AccessDenied,
        else => error.BindFailed,
    };
    if (std.c.listen(fd, 128) != 0) return switch (posix.errno(@as(c_int, -1))) {
        .ADDRINUSE => error.AddressInUse,
        else => error.ListenFailed,
    };
    if (port == 0) {
        var got: posix.sockaddr.in = undefined;
        var len: posix.socklen_t = @sizeOf(posix.sockaddr.in);
        if (std.c.getsockname(fd, @ptrCast(&got), &len) != 0) return error.SocketFailed;
        address = .{ .ip4 = Io.net.Ip4Address.loopback(std.mem.bigToNative(u16, got.port)) };
    }
    return .{ .socket = .{ .handle = fd, .address = address }, .options = {} };
}

pub const Options = struct {
    listen: Listen,
    access: access.Config,
    max_connections: u32 = 64,
    /// WebSocket viewers at once, at most. Fewer than `max_connections`, so plain requests (the
    /// page's files, transfers) always find a connection slot; one more upgrade gets 503.
    max_viewers: u32 = 32,
    /// With a unix listener: where a failed check of the socket's folders was, for the message.
    problem: ?*xfer.Problem = null,
    /// Wrong tokens (in the header or the query, from this origin) counted in any `token_window_ms`:
    /// past them every wrong one gets 429 until the window ends, so a token cannot be guessed online
    /// at any useful rate (it is all one budget: every local account reaches a loopback port from the
    /// same address). A right token always gets in (see `TokenLimiter`).
    /// With own addresses read from Tailscale while running: how long the list may go without being
    /// confirmed (`refreshOwnAddresses`) before requests are refused until it is again. The time is
    /// judged at each request, so a refresh that hangs or stops closes the door by itself. Null: the
    /// list is the owner's own (`--own-address`) and never goes out of date.
    own_address_max_age_ms: ?i64 = null,
    /// When the own addresses in `access` were read from Tailscale (the server may start long after:
    /// the wait for Rex). Null: now.
    own_addresses_read_ms: ?i64 = null,
    max_token_failures: u32 = 10,
    token_window_ms: u32 = 60_000,
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
    /// `max_connections` is for requests that did. When they are all taken, a new connection
    /// evicts the oldest one that has not sent a request head yet, so idle connections from a
    /// local process cannot keep the owner out (Serve sends its request at once).
    max_pending: u32 = 16,
    /// A browser that has said nothing for this long (the page pings every 3 s, and answers our
    /// pings) is gone: a connection through Serve can die without telling anyone.
    silent_limit_ms: u32 = 20_000,
    /// The longest one WebSocket frame may take to write: a browser that stops reading is dropped
    /// instead of holding its writer (and the connection) for ever.
    write_deadline_ms: u32 = 30_000,
    /// A transfer that moves no bytes for this long is cut (and a partial upload removed).
    transfer_idle_ms: u32 = 30_000,
};

const security_headers = [_]std.http.Header{
    .{ .name = "content-security-policy", .value = "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; manifest-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" },
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

/// Messages one browser may send in any one-second window; one more and it is cut off.
pub const max_messages_per_second: u32 = 200;

/// Flush a file or folder to the disk itself. On macOS `fsync` stops at the drive's own cache, so the
/// full flush is asked for first (only when the filesystem does not support it do we fall back to
/// `fsync`; an I/O, space, quota or permission error fails at once).
fn syncToDisk(io: Io, f: Io.File) Io.File.SyncError!void {
    if (comptime builtin.os.tag.isDarwin()) {
        while (true) {
            if (std.c.fcntl(f.handle, std.c.F.FULLFSYNC, @as(c_int, 0)) == 0) return;
            switch (std.c._errno().*) {
                @backingInt(std.c.E.INTR) => continue,
                @backingInt(std.c.E.OPNOTSUPP),
                @backingInt(std.c.E.INVAL),
                @backingInt(std.c.E.NOTTY),
                @backingInt(std.c.E.NODEV),
                @backingInt(std.c.E.NOSYS),
                => break,
                @backingInt(std.c.E.IO) => return error.InputOutput,
                @backingInt(std.c.E.NOSPC) => return error.NoSpaceLeft,
                @backingInt(std.c.E.DQUOT) => return error.DiskQuota,
                @backingInt(std.c.E.ACCES), @backingInt(std.c.E.PERM), @backingInt(std.c.E.ROFS) => return error.AccessDenied,
                // Any other answer is taken as "no full flush here": `fsync` below still reports a
                // real failure, and an errno nobody listed must not make every upload fail.
                else => break,
            }
        }
    }
    return f.sync(io);
}

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

/// The boot clock keeps counting while the machine sleeps, so an own-address list cannot stay
/// "fresh" across a suspend (during which Tailscale may have changed addresses or stopped).
fn bootNowMs(io: Io) i64 {
    return Io.Clock.boot.now(io).toMilliseconds();
}

/// A request target is printable ASCII without spaces (RFC 9112): anything else is refused before
/// it is routed, so no control byte can reach a header, a log or a redirect.
pub fn targetIsClean(target: []const u8) bool {
    for (target) |c| if (c <= 0x20 or c == 0x7f) return false;
    return true;
}

/// Whether a viewer's connection is still alive: what the reader last heard, when the frame being
/// written started (0 while none is), and since when the reader has been busy in a handler (0 while
/// it is not): a reader waiting on Rex cannot hear the browser, which is not silent for that.
const Liveness = struct {
    last_rx: std.atomic.Value(i64),
    write_since: std.atomic.Value(i64) = .init(0),
    busy_since: std.atomic.Value(i64) = .init(0),
};

/// Whether the watchdog should drop a viewer as silent: quiet for longer than the limit, and its
/// reader not busy in a handler (a handler waiting on Rex keeps the reader from hearing the browser;
/// Rex calls end on their own timeout).
fn isSilent(now: i64, last_rx: i64, busy_since: i64, limit_ms: u32) bool {
    return busy_since == 0 and now - last_rx > limit_ms;
}

/// What the page is told before a connection that sent a message over the limit is closed (the
/// stream cannot be resynchronized, so it is closed either way).
const too_large_text = "{\"t\":\"error\",\"for\":\"message\",\"msg\":\"too large\"}";

fn freeList(gpa: Allocator, list: [][]u8) void {
    for (list) |a| gpa.free(a);
    gpa.free(list);
}

/// Whether `list` holds the address `a` (compared as addresses, see `access.sameAddressList`).
fn containsAddress(list: []const []const u8, a: []const u8) bool {
    for (list) |x| if (access.sameAddressList(&.{x}, &.{a})) return true;
    return false;
}

/// One budget of wrong tokens for the whole server, per window. Only a wrong token in the header or
/// the query counts, and only from a request that passed every other check and came from this
/// origin (`access.checkToken`): a refused request, a page elsewhere and a planted cookie take
/// nothing from it. A right token is compared first and always gets in, so the budget caps how fast
/// tokens can be guessed without ever locking the owner out; and comparing while over the budget
/// tells a guesser nothing a right guess would not give anyway.
const TokenLimiter = struct {
    mu: Io.Mutex = .init,
    window_start: i64 = 0,
    used: u32 = 0,
    /// Whether this window's "over the limit" was logged.
    logged: bool = false,

    /// Count one wrong token; false when the window's budget was already used up (answer 429).
    fn fail(l: *TokenLimiter, io: Io, now: i64, max: u32, window_ms: u32) bool {
        l.mu.lockUncancelable(io);
        defer l.mu.unlock(io);
        if (now - l.window_start >= window_ms) {
            l.window_start = now;
            l.used = 0;
            l.logged = false;
        }
        if (l.used >= max) {
            if (!l.logged) log.warn("wrong tokens over the limit ({d} in {d} s): every wrong one is answered 429 until the window ends", .{ max, window_ms / 1000 });
            l.logged = true;
            return false;
        }
        l.used += 1;
        return true;
    }
};

/// The token form's files, served without a token in token mode: the form at `/` and its script
/// and style. Static; nothing from the bridge is in them.
fn loginAsset(path: []const u8) ?[]const u8 {
    if (std.mem.eql(u8, path, "/")) return "/login.html";
    if (std.mem.eql(u8, path, "/login.js") or std.mem.eql(u8, path, "/login.css")) return path;
    return null;
}

/// When a transfer last moved bytes.
const Progress = struct {
    last_ms: std.atomic.Value(i64),

    fn touch(p: *Progress, io: Io) void {
        p.last_ms.store(nowMs(io), .release);
    }
};

pub const Server = struct {
    gpa: Allocator,
    io: Io,
    hub: *Hub,
    opts: Options,
    listener: Io.net.Server,
    /// `[::1]` on the TCP port, when the system has it.
    listener6: ?Io.net.Server = null,
    /// The TCP port, once listening.
    port: u16 = 0,
    accept_task: ?Io.Future(void) = null,
    accept_task6: ?Io.Future(void) = null,
    group: Io.Group = .init,
    active: std.atomic.Value(u32) = .init(0),
    /// Connections accepted but not yet through the access check.
    pending: std.atomic.Value(u32) = .init(0),
    stopping: std.atomic.Value(bool) = .init(false),
    /// Accepted streams, so `stop` can shut them (cancelling a task blocked in a read is not
    /// reliable on its own).
    conns_mu: Io.Mutex = .init,
    conns: std.ArrayList(Io.net.Stream) = .empty,
    /// WebSocket viewers (and lab sockets) open now, at most `opts.max_viewers`.
    viewers: std.atomic.Value(u32) = .init(0),
    /// A unix listener's folder, checked and kept open for the server's life; the socket's name in
    /// it; and the device and inode of the socket this server bound, so `stop` removes only that.
    sock_dir: ?std.posix.fd_t = null,
    sock_name: []const u8 = "",
    sock_id: ?SockId = null,
    /// Guards `opts.access.own_addresses`, which `setOwnAddresses` replaces while requests are judged.
    access_mu: Io.Mutex = .init,
    /// The own-address list `setOwnAddresses` made (ours to free), if any.
    own_owned: ?[][]u8 = null,
    /// When the own addresses were last confirmed: at start, and at each refresh that Tailscale
    /// answered with a usable list (see `Options.own_address_max_age_ms`).
    own_checked_ms: std.atomic.Value(i64) = .init(0),
    /// Whether the last request found the list out of date, to log the change once each way.
    own_stale_logged: std.atomic.Value(bool) = .init(false),
    /// Failed token checks in the current window (see `Options.max_token_failures`).
    limiter: TokenLimiter = .{},
    /// Accepted connections that have not sent a request head yet, oldest first (under `conns_mu`).
    waiting: std.ArrayList(Io.net.Stream) = .empty,
    /// Connections evicted from `waiting`, for tests and logs.
    evicted: std.atomic.Value(u32) = .init(0),
    /// Per-asset validators and gzip bodies, made on first use.
    cache_mu: Io.Mutex = .init,
    etags: [assets.all.len]?[34]u8 = @splat(null),
    gz: [assets.all.len]?[]u8 = @splat(null),
    /// Requests refused by `access`, and the last reason, for tests and logs.
    refusals: std.atomic.Value(u32) = .init(0),
    last_refusal: std.atomic.Value(u8) = .init(255),
    /// With a token: the path the page is served under, `/s/<32 hex>`, derived from the token. The
    /// token's cookie is scoped to it, because cookies are shared by every port on a host: an
    /// unrelated service on another loopback port must never receive it, and two SSH tunnels on two
    /// ports must not overwrite each other's cookie. Not a secret (the token is).
    token_prefix_buf: [3 + 32]u8 = undefined,
    token_prefix: ?[]const u8 = null,

    /// `bind` then `startBound`.
    pub fn start(gpa: Allocator, io: Io, hub: *Hub, opts: Options) !*Server {
        if (opts.access.owner == null and opts.access.token == null) return error.AccessNotConfigured;
        var b = try bind(gpa, io, opts.listen, opts.problem);
        errdefer b.deinit(io);
        return startBound(gpa, io, hub, opts, b);
    }

    /// Serve on a listener taken earlier with `bind` (`opts.listen` is replaced by what was bound).
    /// On success the server owns `b`; on failure it is still the caller's.
    pub fn startBound(gpa: Allocator, io: Io, hub: *Hub, opts_in: Options, b: Bound) !*Server {
        if (opts_in.access.owner == null and opts_in.access.token == null) return error.AccessNotConfigured;
        var opts = opts_in;
        opts.listen = b.listen;
        const s = try gpa.create(Server);
        errdefer gpa.destroy(s);
        s.* = .{
            .gpa = gpa,
            .io = io,
            .hub = hub,
            .opts = opts,
            .listener = b.listener,
            .listener6 = b.listener6,
            .port = b.port,
            .sock_dir = b.sock_dir,
            .sock_name = b.sock_name,
            .sock_id = b.sock_id,
            .own_checked_ms = .init(opts.own_addresses_read_ms orelse bootNowMs(io)),
        };
        if (opts.access.token) |t| s.token_prefix = tokenPrefix(&s.token_prefix_buf, t);
        s.accept_task = try io.concurrent(acceptLoop, .{ s, &s.listener });
        if (s.listener6 != null) s.accept_task6 = io.concurrent(acceptLoop, .{ s, &s.listener6.? }) catch |e| {
            s.stopping.store(true, .release);
            s.wakeAccept();
            s.accept_task.?.cancel(io);
            return e;
        };
        return s;
    }

    /// Replace this node's own addresses (refreshed from Tailscale while running). Copied; the old
    /// list is freed once no request is being judged against it.
    pub fn setOwnAddresses(s: *Server, list: []const []const u8) Allocator.Error!void {
        const copy = try s.gpa.alloc([]u8, list.len);
        var made: usize = 0;
        errdefer {
            for (copy[0..made]) |a| s.gpa.free(a);
            s.gpa.free(copy);
        }
        for (list, 0..) |a, i| {
            copy[i] = try s.gpa.dupe(u8, a);
            made += 1;
        }
        s.access_mu.lockUncancelable(s.io);
        const old = s.own_owned;
        s.own_owned = copy;
        s.opts.access.own_addresses = @ptrCast(copy);
        s.access_mu.unlock(s.io);
        if (old) |o| freeList(s.gpa, o);
    }

    /// This node's own addresses now (a copy in `arena`).
    pub fn ownAddresses(s: *Server, arena: Allocator) Allocator.Error![]const []const u8 {
        s.access_mu.lockUncancelable(s.io);
        defer s.access_mu.unlock(s.io);
        const out = try arena.alloc([]const u8, s.opts.access.own_addresses.len);
        for (s.opts.access.own_addresses, 0..) |a, i| out[i] = try arena.dupe(u8, a);
        return out;
    }

    pub const Refresh = enum { unchanged, added, failed, invalid };

    /// One refresh of the own addresses from what was `fetched`: addresses not yet on the list are
    /// added (each logged), and none is ever taken off while rweb runs, so a request from an address
    /// this node had a minute ago is still refused. A failed fetch, an empty list or one with
    /// something that is not an address changes nothing, and does not count as confirming the list:
    /// only a usable answer that is on the list afterwards does (`own_checked_ms`).
    pub fn refreshOwnAddresses(s: *Server, fetched: anyerror![]const []const u8) Refresh {
        const list = fetched catch return .failed;
        if (list.len == 0) return .invalid;
        for (list) |a| if (!access.isAddress(a)) return .invalid;

        var arena_state = std.heap.ArenaAllocator.init(s.gpa);
        defer arena_state.deinit();
        const arena = arena_state.allocator();
        const now = s.ownAddresses(arena) catch return .failed;
        var all: std.ArrayList([]const u8) = .empty;
        all.appendSlice(arena, now) catch return .failed;
        for (list) |a| {
            if (containsAddress(all.items, a)) continue;
            all.append(arena, a) catch return .failed;
        }
        if (all.items.len == now.len) {
            s.own_checked_ms.store(bootNowMs(s.io), .release);
            return .unchanged;
        }
        s.setOwnAddresses(all.items) catch return .failed;
        s.own_checked_ms.store(bootNowMs(s.io), .release);
        for (all.items[now.len..]) |a| log.info("a new address of this node, {s}: requests from it are refused from now on (the earlier ones still are)", .{a});
        return .added;
    }

    fn decideAllButToken(s: *Server, request: access.Request) access.Decision {
        const stale = s.ownAddressesStale();
        if (stale != s.own_stale_logged.swap(stale, .acq_rel)) {
            if (stale)
                log.warn("this node's Tailscale addresses have not been confirmed for over {d} s: requests are refused until Tailscale answers again", .{@divTrunc(s.opts.own_address_max_age_ms.?, 1000)})
            else
                log.info("this node's Tailscale addresses are confirmed again: requests are judged as usual", .{});
        }
        s.access_mu.lockUncancelable(s.io);
        defer s.access_mu.unlock(s.io);
        var cfg = s.opts.access;
        cfg.own_addresses_stale = stale;
        return access.decideAllButToken(cfg, request);
    }

    /// Whether the own addresses, read from Tailscale while running, have gone unconfirmed for longer
    /// than `Options.own_address_max_age_ms` (boot clock, so machine sleep counts against the age).
    pub fn ownAddressesStale(s: *Server) bool {
        const max_age = s.opts.own_address_max_age_ms orelse return false;
        return bootNowMs(s.io) - s.own_checked_ms.load(.acquire) > max_age;
    }

    pub fn stop(s: *Server) void {
        s.stopping.store(true, .release);
        s.conns_mu.lockUncancelable(s.io);
        for (s.conns.items) |c| c.shutdown(s.io, .both) catch {};
        s.conns_mu.unlock(s.io);
        s.wakeAccept();
        if (s.accept_task) |*t| t.cancel(s.io);
        if (s.accept_task6) |*t| t.cancel(s.io);
        s.group.cancel(s.io);
        s.conns.deinit(s.gpa);
        s.waiting.deinit(s.gpa);
        for (s.gz) |z| if (z) |bytes| s.gpa.free(bytes);
        if (s.own_owned) |o| freeList(s.gpa, o);
        s.listener.deinit(s.io);
        if (s.listener6) |*l| l.deinit(s.io);
        if (s.sock_dir) |fd| {
            const dir: Io.Dir = .{ .handle = fd };
            // Only the socket this server made: something put in its place is left alone.
            if (s.ownSocketInPlace()) dir.deleteFile(s.io, s.sock_name) catch {};
            dir.close(s.io);
        }
        s.gpa.destroy(s);
    }

    /// Whether the unix socket's name in its folder is still the socket this server bound (same
    /// device and inode).
    fn ownSocketInPlace(s: *Server) bool {
        const fd = s.sock_dir orelse return false;
        return socketInPlace(fd, s.sock_name, s.sock_id);
    }

    /// Make a blocked `accept` return, by connecting to ourselves.
    fn wakeAccept(s: *Server) void {
        switch (s.opts.listen) {
            .unix => |path| {
                // Only while the path still names our socket: something put in its place is not
                // ours to connect to (and the task's cancellation wakes `accept` anyway).
                if (!s.ownSocketInPlace()) return;
                const addr = Io.net.UnixAddress.init(path) catch return;
                const c = addr.connect(s.io) catch return;
                c.close(s.io);
            },
            .tcp_loopback => {
                var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(s.port) };
                if (addr.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
                if (s.listener6 != null) {
                    var addr6 = Io.net.IpAddress{ .ip6 = Io.net.Ip6Address.loopback(s.port) };
                    if (addr6.connect(s.io, .{ .mode = .stream })) |c| c.close(s.io) else |_| {}
                }
            },
        }
    }

    fn acceptLoop(s: *Server, listener: *Io.net.Server) void {
        while (true) {
            if (s.stopping.load(.acquire)) return;
            const conn = listener.accept(s.io) catch |e| switch (e) {
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
                const uid = rex.ws.peerUid(conn);
                const ok = if (uid) |u| std.mem.indexOfScalar(u32, uids, u) != null else false;
                if (!ok) {
                    s.last_refusal.store(@backingInt(access.Refusal.wrong_peer), .release);
                    _ = s.refusals.fetchAdd(1, .acq_rel);
                    log.info("refused: {s}", .{access.Refusal.wrong_peer.text()});
                    conn.close(s.io);
                    continue;
                }
            };
            if (s.pending.load(.acquire) >= s.opts.max_pending) s.evictOldestWaiting();
            // An evicted connection leaves `pending` when its task unwinds, which is at once; the
            // hard limit only matters if eviction cannot keep up.
            if (s.active.load(.acquire) >= s.opts.max_connections or s.pending.load(.acquire) >= 2 * s.opts.max_pending) {
                conn.close(s.io);
                continue;
            }
            s.conns_mu.lockUncancelable(s.io);
            const listed = if (s.waiting.append(s.gpa, conn)) true else |_| false;
            s.conns_mu.unlock(s.io);
            if (!listed) {
                conn.close(s.io);
                continue;
            }
            _ = s.active.fetchAdd(1, .acq_rel);
            _ = s.pending.fetchAdd(1, .acq_rel);
            s.group.concurrent(s.io, handleConn, .{ s, conn }) catch {
                s.conns_mu.lockUncancelable(s.io);
                s.unlistWaiting(conn);
                s.conns_mu.unlock(s.io);
                _ = s.active.fetchSub(1, .acq_rel);
                _ = s.pending.fetchSub(1, .acq_rel);
                conn.close(s.io);
            };
        }
    }

    /// Shut the oldest connection that has not sent a request head; its task then ends and frees
    /// its slot. A connection is unlisted (under `conns_mu`) before its task closes it, so the
    /// stream shut here is always still open.
    fn evictOldestWaiting(s: *Server) void {
        s.conns_mu.lockUncancelable(s.io);
        defer s.conns_mu.unlock(s.io);
        if (s.waiting.items.len == 0) return;
        const oldest = s.waiting.orderedRemove(0);
        oldest.shutdown(s.io, .both) catch {};
        _ = s.evicted.fetchAdd(1, .acq_rel);
        log.info("pending connections full: dropped the oldest one that had sent no request", .{});
    }

    /// Caller holds `conns_mu`.
    fn unlistWaiting(s: *Server, conn: Io.net.Stream) void {
        for (s.waiting.items, 0..) |c, i| if (c.socket.handle == conn.socket.handle) {
            _ = s.waiting.orderedRemove(i);
            return;
        };
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
        // A connection `stop` could not shut is not served.
        const tracked = if (s.conns.append(s.gpa, conn)) true else |_| false;
        s.conns_mu.unlock(s.io);
        if (!tracked) {
            _ = s.pending.fetchSub(1, .acq_rel);
            conn.close(s.io);
            return;
        }
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
            s.unlistWaiting(conn);
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
        s.conns_mu.lockUncancelable(s.io);
        s.unlistWaiting(conn); // it has spoken: no longer the one to evict
        s.conns_mu.unlock(s.io);
        const t_head = std.Io.Clock.awake.now(s.io).toMilliseconds();
        // The request log names only a path the bridge knows (never the secret prefix, a query,
        // or text a client chose, which could carry a token or forge log lines).
        var logged_path: []const u8 = "(unparsed)";
        defer log.info("request {s} {s} (head read at {d}, handled in {d} ms)", .{ @tagName(req.head.method), logged_path, t_head, std.Io.Clock.awake.now(s.io).toMilliseconds() - t_head });

        // ---- a target with a control byte or a space: refused before anything looks at it ----
        if (!targetIsClean(req.head.target)) {
            logged_path = "(bad target)";
            try req.respond("bad request\n", .{ .status = .bad_request, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }

        // ---- the backend secret, if there is one: first, and answered with a bare 404 ----
        const outer: []const u8 = if (s.opts.backend_secret) |secret|
            (stripSecret(req.head.target, secret) orelse {
                logged_path = "(wrong prefix)";
                s.last_refusal.store(@backingInt(access.Refusal.wrong_peer), .release);
                _ = s.refusals.fetchAdd(1, .acq_rel);
                try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
                return;
            })
        else
            req.head.target;
        // ---- the token's path prefix: `/s/<id>/...` is served like `/...` ----
        var under_prefix = false;
        // `/s/<id>` with no slash: the page needs one, and gets a redirect once access allows it.
        var bare_prefix = false;
        const rest: []const u8 = if (s.token_prefix) |pfx| if (stripPrefix(outer, pfx)) |inner| blk: {
            under_prefix = true;
            bare_prefix = inner.len == 0 or inner[0] == '?';
            break :blk inner;
        } else outer else outer;
        const path_part = rest[0 .. std.mem.indexOfScalar(u8, rest, '?') orelse rest.len];
        const path = if (path_part.len == 0) "/" else path_part;
        logged_path = if (bare_prefix) "(prefix)" else knownPath(path);

        // ---- access: before anything else ----
        var hdrs: [64]access.Header = undefined;
        var n: usize = 0;
        var it = req.iterateHeaders();
        while (it.next()) |h| {
            if (n == hdrs.len) { // never judge a request on part of its headers
                s.last_refusal.store(@backingInt(access.Refusal.ambiguous_header), .release);
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
            .peer_uid = if (s.opts.listen == .unix) rex.ws.peerUid(conn) else null,
            .headers = hdrs[0..n],
            .query_token = access.queryToken(rest),
            .is_websocket_upgrade = upgrade == .websocket,
            .requires_origin = req.head.method != .GET and req.head.method != .HEAD,
        };
        // Every check but the token's first: a request refused for anything else never counts as a
        // guess. Then the token (`access.checkToken`): a right one gets in whatever the budget; a
        // wrong one in the header or the query from this origin is counted, and over the budget it
        // gets 429; a wrong cookie and a token sent from another origin are refused uncounted.
        var why: ?access.Refusal = switch (s.decideAllButToken(areq)) {
            .allow => null,
            .deny => |refusal| refusal,
        };
        if (why == null) switch (access.checkToken(s.opts.access, areq)) {
            .none, .right => {},
            .missing => why = .no_token,
            .wrong_cookie => why = .bad_token,
            .cross_site => why = .cross_site_token,
            .wrong => {
                if (!s.limiter.fail(s.io, nowMs(s.io), s.opts.max_token_failures, s.opts.token_window_ms)) {
                    s.last_refusal.store(@backingInt(access.Refusal.bad_token), .release);
                    _ = s.refusals.fetchAdd(1, .acq_rel);
                    try req.respond("too many wrong tokens: try again in a minute\n", .{ .status = .too_many_requests, .keep_alive = false, .extra_headers = &(security_headers ++ no_store ++ [_]std.http.Header{.{ .name = "retry-after", .value = "60" }}) });
                    return;
                }
                why = .bad_token;
            },
        };
        if (why) |refusal| {
            // Token mode: the token form, at `/` (outside the prefix) for a page load that carries
            // no token in its header or address (every other check passed to get here).
            if (s.token_prefix != null and (refusal == .no_token or refusal == .bad_token) and !under_prefix and
                req.head.method == .GET and upgrade == .none and areq.query_token == null and areq.header("rweb-token") == null)
            {
                if (loginAsset(path)) |p| {
                    logged_path = if (std.mem.eql(u8, path, "/")) "(token form)" else p;
                    return s.serveAsset(&req, assets.indexOf(p).?, null, hdrs[0..n]);
                }
            }
            s.last_refusal.store(@backingInt(refusal), .release);
            _ = s.refusals.fetchAdd(1, .acq_rel);
            log.info("refused: {s}", .{refusal.text()});
            try req.respond("forbidden\n", .{ .status = .forbidden, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }
        if (pending.*) {
            pending.* = false;
            _ = s.pending.fetchSub(1, .acq_rel);
        }
        if (bare_prefix) return s.redirect(&req, s.token_prefix.?, rest, false, false);

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
            return if (req.head.method == .GET) s.serveDownload(conn, &req, &xtoken) else s.serveUpload(conn, &req, &xtoken);
        }
        if (req.head.method != .GET) {
            try req.respond("method not allowed\n", .{ .status = .method_not_allowed, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
            return;
        }
        // `/api/tree` is a diagnostic too: the page reads the tree over its socket.
        const is_lab = std.mem.startsWith(u8, path, "/lab") or std.mem.startsWith(u8, path, "/api/lab") or std.mem.eql(u8, path, "/api/tree");
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
            if (!s.takeViewerSlot()) return s.refuseViewer(&req);
            defer _ = s.viewers.fetchSub(1, .acq_rel);
            var sock = try req.respondWebSocket(.{ .key = key });
            try sock.flush();
            return s.viewerSession(conn, &sock);
        }
        if (std.mem.eql(u8, path, "/labws")) {
            const key = switch (upgrade) {
                .websocket => |k| k orelse return error.NoKey,
                else => return,
            };
            if (!s.takeViewerSlot()) return s.refuseViewer(&req);
            defer _ = s.viewers.fetchSub(1, .acq_rel);
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
        // The page opened with `?token=` outside its prefix, or the token form sent the token in its
        // header: move to the prefix, where the token's cookie lives, and take the token out of the
        // address.
        if (s.token_prefix) |pfx| if (!under_prefix and (areq.query_token != null or areq.header("rweb-token") != null) and std.mem.eql(u8, path, "/")) {
            return s.redirect(&req, pfx, rest[std.mem.indexOfScalar(u8, rest, '?') orelse rest.len ..], true, behindHttps(hdrs[0..n]));
        };
        if (assets.indexOf(path)) |idx| return s.serveAsset(&req, idx, if (under_prefix) areq.query_token else null, hdrs[0..n]);
        try req.respond("not found\n", .{ .status = .not_found, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
    }

    const cookie_max = 640;

    /// `rweb-token=<token>` scoped to the token's prefix. Null if it does not fit (it always does
    /// for a token rweb accepts: at most a few hundred URL-safe characters).
    fn tokenCookie(s: *Server, buf: []u8, secure: bool) ?[]const u8 {
        return std.fmt.bufPrint(buf, "rweb-token={s}; Path={s}/; HttpOnly; SameSite=Strict{s}", .{ s.opts.access.token.?, s.token_prefix.?, if (secure) "; Secure" else "" }) catch null;
    }

    /// Redirect to `<prefix>/` keeping `query` without its `token`. With `set_cookie`, also store the
    /// token in its prefix-scoped cookie and delete the site-wide cookie that rweb 0.1.0 set.
    fn redirect(s: *Server, req: *std.http.Server.Request, prefix: []const u8, query: []const u8, set_cookie: bool, secure: bool) !void {
        var loc_buf: [1024]u8 = undefined;
        var lw: std.Io.Writer = .fixed(&loc_buf);
        lw.print("{s}/", .{prefix}) catch unreachable;
        if (query.len > 1) {
            var first = true;
            var it = std.mem.tokenizeScalar(u8, query[1..], '&');
            while (it.next()) |kv| {
                if (std.mem.eql(u8, kv, "token") or std.mem.startsWith(u8, kv, "token=")) continue;
                writeQueryPart(&lw, if (first) "?" else "&", kv) catch {
                    lw.end = prefix.len + 1; // too long: drop the query
                    break;
                };
                first = false;
            }
        }
        var cookie_buf: [cookie_max]u8 = undefined;
        var hb: [16]std.http.Header = undefined;
        var extra: [4]std.http.Header = undefined;
        var n: usize = 0;
        extra[n] = .{ .name = "location", .value = lw.buffered() };
        n += 1;
        extra[n] = no_store[0];
        n += 1;
        if (set_cookie) {
            if (s.tokenCookie(&cookie_buf, secure)) |ck| {
                extra[n] = .{ .name = "set-cookie", .value = ck };
                n += 1;
            }
            extra[n] = .{ .name = "set-cookie", .value = "rweb-token=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict" };
            n += 1;
        }
        try req.respond("", .{ .status = if (set_cookie) .see_other else .found, .keep_alive = false, .extra_headers = withSecurity(&hb, extra[0..n]) });
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
    /// by the browser (private, never by a shared cache) but revalidated on every use, the
    /// vendored files too, so a new binary's files are used at once. A response that sets the
    /// token cookie is never stored.
    fn serveAsset(s: *Server, req: *std.http.Server.Request, idx: usize, query_token: ?[]const u8, headers: []const access.Header) !void {
        const a = assets.all[idx];
        const is_root = std.mem.eql(u8, a.path, "/");
        // A page opened with `?token=` under its prefix keeps the token in a cookie scoped to that
        // prefix, so its scripts, styles and socket need no query string. Never a 304.
        var cookie_buf: [cookie_max]u8 = undefined;
        const cookie: ?[]const u8 = if (s.token_prefix != null and query_token != null and is_root)
            s.tokenCookie(&cookie_buf, behindHttps(headers))
        else
            null;

        const tag = s.etagFor(idx);
        var if_none_match: ?[]const u8 = null;
        var accept_encoding: ?[]const u8 = null;
        for (headers) |h| {
            if (std.ascii.eqlIgnoreCase(h.name, "if-none-match")) if_none_match = h.value;
            if (std.ascii.eqlIgnoreCase(h.name, "accept-encoding")) accept_encoding = h.value;
        }
        const cache_control = if (cookie != null) "no-store" else "private, no-cache";

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

    /// Reserve one of the `max_viewers` WebSocket places; false when all are taken.
    fn takeViewerSlot(s: *Server) bool {
        while (true) {
            const n = s.viewers.load(.acquire);
            if (n >= s.opts.max_viewers) return false;
            if (s.viewers.cmpxchgWeak(n, n + 1, .acq_rel, .acquire) == null) return true;
        }
    }

    fn refuseViewer(s: *Server, req: *std.http.Server.Request) !void {
        _ = s;
        log.warn("refused a WebSocket: every viewer place is taken", .{});
        try req.respond("too many viewers\n", .{ .status = .service_unavailable, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
    }

    fn refuseXfer(req: *std.http.Server.Request, status: std.http.Status, text: []const u8) !void {
        try req.respond(text, .{ .status = status, .keep_alive = false, .extra_headers = &(security_headers ++ no_store) });
    }

    /// Cuts a transfer that has moved no bytes for `transfer_idle_ms`: shuts the browser's
    /// connection and, for a download, Rex's stream, so whichever side is blocked returns.
    fn progressWatchdog(s: *Server, p: *Progress, browser_conn: Io.net.Stream, rex_stream: ?Io.net.Stream) void {
        const limit: i64 = s.opts.transfer_idle_ms;
        const step: i64 = @max(10, @min(1000, s.opts.transfer_idle_ms / 4));
        while (true) {
            s.io.sleep(.fromMilliseconds(step), .awake) catch return;
            if (nowMs(s.io) - p.last_ms.load(.acquire) > limit) {
                log.info("transfer stalled: no bytes for {d} ms; cut", .{limit});
                browser_conn.shutdown(s.io, .both) catch {};
                if (rex_stream) |r| r.shutdown(s.io, .both) catch {};
                return;
            }
        }
    }

    /// `GET /xfer/<token>`: stream the file Rex opened for the token. A transfer slot is taken
    /// before the token, so a busy bridge does not use the token up.
    fn serveDownload(s: *Server, conn: Io.net.Stream, req: *std.http.Server.Request, xtoken: []const u8) !void {
        if (!s.hub.xfers.acquire()) return refuseXfer(req, .too_many_requests, "too many transfers\n");
        defer s.hub.xfers.release();
        var entry = s.hub.xfers.take(xtoken, .download) orelse return refuseXfer(req, .not_found, "not found\n");
        defer entry.deinit(s.gpa);

        const max = s.hub.cfg.transfer.max_bytes;
        var st = rex.transfer.Stream.open(s.gpa, s.io, s.hub.ctl.opts.socket_path, entry.ticket) catch |e| {
            log.info("download: Rex refused the stream: {t}", .{e});
            return refuseXfer(req, .bad_gateway, "Rex did not give the file\n");
        };
        defer st.deinit();
        var progress: Progress = .{ .last_ms = .init(nowMs(s.io)) };
        var dog = s.io.concurrent(progressWatchdog, .{ s, &progress, conn, st.conn.stream }) catch return refuseXfer(req, .service_unavailable, "busy\n");
        defer dog.cancel(s.io);

        var nb: [128]u8 = undefined;
        const shown = xfer.safeName(&nb, entry.name);
        log.info("download start: {s} ({d} bytes announced)", .{ shown, entry.size });

        var cd_buf: [512]u8 = undefined;
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
            progress.touch(s.io);
        }
        try body.end();
        log.info("download done: {s} {d} bytes", .{ shown, total });
    }

    /// `PUT /xfer/<token>`: write the body into the upload directory under a safe, new name, then
    /// paste its quoted path into the terminal. The file is created relative to the folder opened
    /// at startup (`upload_dir_handle`), never by path.
    fn serveUpload(s: *Server, conn: Io.net.Stream, req: *std.http.Server.Request, xtoken: []const u8) !void {
        // The folder's real path, resolved when it was opened, not the path as given (a link in it
        // could later lead elsewhere).
        const dir_path = s.hub.cfg.transfer.upload_dir_real orelse s.hub.cfg.transfer.upload_dir orelse return refuseXfer(req, .not_found, "not found\n");
        const dir = s.hub.cfg.transfer.upload_dir_handle orelse return refuseXfer(req, .not_found, "not found\n");
        const parts = s.hub.cfg.transfer.upload_parts_handle orelse return refuseXfer(req, .not_found, "not found\n");
        if (!s.hub.xfers.acquire()) return refuseXfer(req, .too_many_requests, "too many transfers\n");
        defer s.hub.xfers.release();
        var entry = s.hub.xfers.take(xtoken, .upload) orelse return refuseXfer(req, .not_found, "not found\n");
        defer entry.deinit(s.gpa);
        // The page that asked must still be allowed to write to that view of the terminal (it may
        // have turned read-only, moved away — even if it later came back — or gone): checked now,
        // and again before the path is pasted.
        if (!s.hub.mayUpload(entry.viewer_id, entry.session_id, entry.block_id, entry.view_gen)) return refuseXfer(req, .forbidden, "this page can no longer write to that terminal\n");

        const len = req.head.content_length orelse return refuseXfer(req, .length_required, "length required\n");
        if (len != entry.size) return refuseXfer(req, .bad_request, "the size is not what was announced\n");
        if (len > s.hub.cfg.transfer.max_bytes) return refuseXfer(req, .payload_too_large, "too large\n");

        // The bytes go into a part file first, in rweb's own folder for unfinished uploads, and the
        // file gets its real name only when all of them are in and on disk: a stop, a crash or a
        // power cut in the middle never leaves a file that looks whole in the upload folder. The part
        // file stays locked while this writes it, so a starting rweb that shares the folder leaves it
        // alone and removes only what a stopped one left (`xfer.sweepUploadParts`).
        var part = xfer.createUploadPart(s.io, parts) catch return refuseXfer(req, .internal_server_error, "cannot create the file\n");
        defer part.remove(s.io, parts); // the part file never stays: done, the file has its real name too
        const f = part.file;

        // The body, exactly `len` bytes, each read within `transfer_idle_ms` of the last. The watchdog
        // is for the browser's silences only: it ends with the body, so a slow flush to disk below
        // is not taken for one.
        {
            var progress: Progress = .{ .last_ms = .init(nowMs(s.io)) };
            var dog = s.io.concurrent(progressWatchdog, .{ s, &progress, conn, null }) catch return refuseXfer(req, .service_unavailable, "busy\n");
            defer dog.cancel(s.io);
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
                progress.touch(s.io);
            }
        }
        if (!s.hub.mayUpload(entry.viewer_id, entry.session_id, entry.block_id, entry.view_gen)) return refuseXfer(req, .forbidden, "this page can no longer write to that terminal\n");
        // On disk before it is named: after a power cut, a file under its real name has all its bytes.
        syncToDisk(s.io, f) catch return refuseXfer(req, .internal_server_error, "cannot save the file\n");
        // Its real name: one that is safe, and that replaces nothing ("a.txt", "a (1).txt", ...). A hard
        // link fails if the name exists, so nothing is ever replaced, even by a racing upload.
        var nb: [128]u8 = undefined;
        const safe = xfer.safeName(&nb, entry.name);
        var name_buf: [161]u8 = undefined;
        var final: [:0]const u8 = "";
        var named = false;
        var attempt: u32 = 0;
        while (attempt < 100) : (attempt += 1) {
            const dot = std.mem.lastIndexOfScalar(u8, safe, '.');
            const stem = if (dot) |d| (if (d == 0) safe else safe[0..d]) else safe;
            const ext = if (dot) |d| (if (d == 0) "" else safe[d..]) else "";
            final = (if (attempt == 0)
                std.fmt.bufPrintSentinel(&name_buf, "{s}", .{safe}, 0)
            else
                std.fmt.bufPrintSentinel(&name_buf, "{s} ({d}){s}", .{ stem, attempt, ext }, 0)) catch return refuseXfer(req, .internal_server_error, "name\n");
            if (std.c.linkat(parts.handle, part.name(), dir.handle, final, 0) == 0) {
                named = true;
                break;
            }
            const errno = std.c._errno().*;
            if (errno != @backingInt(std.c.E.EXIST)) {
                log.info("upload: the finished file could not be named in the upload folder (errno {d})", .{errno});
                return refuseXfer(req, .internal_server_error, "cannot create the file\n");
            }
        }
        if (!named) return refuseXfer(req, .internal_server_error, "no free name\n");
        // The name is on disk too before success is reported. If that cannot be done the name is
        // taken back and the page is told the upload failed. (Past this point the file stays whatever
        // happens to the reply: it is whole and durable.)
        syncToDisk(s.io, .{ .handle = dir.handle, .flags = .{ .nonblocking = false } }) catch {
            dir.deleteFile(s.io, final) catch {}; // best effort: the failure is reported either way
            return refuseXfer(req, .internal_server_error, "cannot save the file\n");
        };
        log.info("upload done: {s} {d} bytes", .{ final, len });

        // Tell the terminal where it is: the quoted path, as if pasted (no Enter).
        const full = try std.fs.path.join(s.gpa, &.{ dir_path, final });
        defer s.gpa.free(full);
        const quoted = try xfer.shellQuote(s.gpa, full);
        defer s.gpa.free(quoted);
        // A space after it, so that several uploads paste as separate words, not one glued together.
        const typed = try s.gpa.print("{s} ", .{quoted});
        defer s.gpa.free(typed);
        // Checked and queued in one step, in the terminal's own input order (`Hub.pasteUpload`): a page
        // that has switched terminals, gone or turned read-only since gets the file but no paste.
        const pasted = s.hub.pasteUpload(entry.viewer_id, entry.session_id, entry.block_id, entry.view_gen, typed);
        if (!pasted) log.info("upload: the path was not pasted: the page no longer writes to that terminal", .{});

        const reply = try std.json.Stringify.valueAlloc(s.gpa, .{ .ok = true, .name = final, .path = full, .pasted = pasted }, .{});
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

    /// One browser: a writer task drains the viewer's queue; this task reads commands; a watchdog
    /// drops the connection when the browser goes silent or stops reading.
    fn viewerSession(s: *Server, conn: Io.net.Stream, sock: *std.http.Server.WebSocket) !void {
        const gpa = s.gpa;
        const c = try rex.ws.Conn.fromHttp(gpa, s.io, conn, sock.input, sock.output, protocol.max_message_bytes);
        defer c.deinit(gpa);
        const v = try s.hub.addViewer();
        errdefer {
            s.hub.closeViewer(v);
            s.hub.removeViewer(v);
        }
        var live: Liveness = .{ .last_rx = .init(nowMs(s.io)) };
        var watchdog = try s.io.concurrent(viewerWatchdog, .{ s, c, &live });
        defer watchdog.cancel(s.io);
        var writer = try s.io.concurrent(writerLoop, .{ s, c, v, &live });

        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        // A browser sends a few messages a second at most while someone types. A page stuck in a
        // loop would otherwise fill the connection with traffic, so the message past
        // `max_messages_per_second` in any one-second window closes the socket.
        var window_start: i64 = nowMs(s.io);
        var window_count: u32 = 0;
        var too_large = false;
        // One buffer for the socket: a message is parsed into the arena before the next read.
        var read_buf: rex.ws.Conn.ReadBuffer = .{};
        defer read_buf.deinit(gpa);
        while (true) {
            const m = c.readMessageInto(gpa, &read_buf) catch |e| {
                too_large = e == error.TooLarge;
                if (too_large) log.warn("closing a browser that sent a message over {d} bytes", .{protocol.max_message_bytes});
                break;
            };
            const now = nowMs(s.io);
            live.last_rx.store(now, .release);
            if (now - window_start >= 1000) {
                window_start = now;
                window_count = 0;
            }
            window_count += 1;
            if (window_count > max_messages_per_second) {
                log.warn("closing a browser that sent more than {d} messages in a second", .{max_messages_per_second});
                break;
            }
            switch (m.opcode) {
                .close => break,
                .text => {
                    if (s.opts.debug_input) log.info("browser at {d}: {s}", .{ std.Io.Clock.awake.now(s.io).toMilliseconds(), m.data });
                    _ = arena_state.reset(.retain_capacity);
                    const msg = protocol.parse(arena_state.allocator(), m.data) catch |e| {
                        const text = gpa.print("{{\"t\":\"error\",\"for\":\"message\",\"msg\":\"{t}\"}}", .{e}) catch continue;
                        defer gpa.free(text);
                        v.pushText(text);
                        continue;
                    };
                    // While the handler waits (on Rex, say) this reader cannot hear the browser: it
                    // counts as alive meanwhile, and its silence is measured from the handler's end.
                    live.busy_since.store(@max(1, nowMs(s.io)), .release);
                    s.hub.handle(v, msg);
                    live.last_rx.store(nowMs(s.io), .release);
                    live.busy_since.store(0, .release);
                },
                else => {}, // binary from a browser is not part of the protocol
            }
        }
        s.hub.closeViewer(v);
        writer.cancel(s.io);
        // The rest of an oversize message is never read, so the stream cannot go on; the page is
        // told why first. Written under the same deadline as any frame (the watchdog still runs).
        if (too_large) s.writeTimed(c, &live, .text, too_large_text) catch {};
        s.writeTimed(c, &live, .close, &.{ 0x03, 0xe8 }) catch {};
        s.hub.removeViewer(v);
    }

    /// Write one frame with the watchdog watching its deadline.
    fn writeTimed(s: *Server, c: *rex.ws.Conn, live: *Liveness, op: rex.ws.Opcode, data: []const u8) !void {
        live.write_since.store(@max(1, nowMs(s.io)), .release);
        defer live.write_since.store(0, .release);
        try c.writeFrame(op, data);
    }

    /// Shut a viewer's connection if its browser has gone silent or a frame has taken longer than
    /// the write deadline (the browser stopped reading); true if it did. Shutting it wakes the
    /// reader and the writer, which then clean up.
    fn dropIfDead(s: *Server, c: *rex.ws.Conn, live: *Liveness) bool {
        const now = nowMs(s.io);
        const last = live.last_rx.load(.acquire);
        const quiet = now - last;
        if (isSilent(now, last, live.busy_since.load(.acquire), s.opts.silent_limit_ms)) {
            log.info("dropping a browser that has been silent for {d} s", .{@divTrunc(quiet, 1000)});
            c.stream.shutdown(s.io, .both) catch {};
            return true;
        }
        const since = live.write_since.load(.acquire);
        if (since != 0 and now - since > s.opts.write_deadline_ms) {
            log.info("dropping a browser that has not read a frame in {d} ms", .{now - since});
            c.stream.shutdown(s.io, .both) catch {};
            return true;
        }
        return false;
    }

    /// Checks a viewer's liveness while its writer may be blocked in a write.
    fn viewerWatchdog(s: *Server, c: *rex.ws.Conn, live: *Liveness) void {
        const step: i64 = @max(10, @min(1000, @min(s.opts.silent_limit_ms, s.opts.write_deadline_ms) / 4));
        while (true) {
            s.io.sleep(.fromMilliseconds(step), .awake) catch return;
            if (s.dropIfDead(c, live)) return;
        }
    }

    fn writerLoop(s: *Server, c: *rex.ws.Conn, v: *hub_mod.Viewer, live: *Liveness) void {
        defer if (s.opts.debug_input) log.info("writer task ended", .{});
        while (true) {
            // On every turn, busy or not: a queue that never empties must not hide a silent browser.
            if (s.dropIfDead(c, live)) return;
            const f = (v.next(3000) catch return) orelse {
                if (v.isClosed()) return;
                // Quiet for a moment: a ping every ~3 s keeps a phone's path through Serve warm.
                s.writeTimed(c, live, .ping, "") catch return;
                continue;
            };
            defer v.recycle(f); // a live buffer is reused for the next output
            const t0 = std.Io.Clock.awake.now(s.io).toMilliseconds();
            s.writeTimed(c, live, if (f.binary) .binary else .text, f.data) catch |e| {
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

/// `sep` then `part` (one `key=value` of a query) into a Location header: bytes that are not
/// plainly safe in a URL are percent-encoded, so nothing a client sent reaches the header raw.
fn writeQueryPart(w: *Io.Writer, sep: []const u8, part: []const u8) Io.Writer.Error!void {
    try w.writeAll(sep);
    for (part) |c| {
        const safe = std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "-._~!$'()*+,;=:@/?%", c) != null;
        if (safe) try w.writeByte(c) else try w.print("%{X:0>2}", .{c});
    }
}

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

/// `/s/` and the first 16 bytes of SHA-256("rweb cookie path" NUL token), in hex. Stable for a token
/// (a bookmark survives a restart with the same token file), different for each token, and it tells
/// nothing about the token.
pub fn tokenPrefix(buf: *[3 + 32]u8, secret: []const u8) []const u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("rweb cookie path\x00");
    h.update(secret);
    const digest = h.finalResult();
    buf[0..3].* = "/s/".*;
    buf[3..].* = std.fmt.bytesToHex(digest[0..16].*, .lower);
    return buf;
}

/// `target` without `prefix`, if it starts with it as a whole path segment.
pub fn stripPrefix(target: []const u8, prefix: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, target, prefix)) return null;
    const rest = target[prefix.len..];
    if (rest.len != 0 and rest[0] != '/' and rest[0] != '?') return null;
    return rest;
}

fn behindHttps(headers: []const access.Header) bool {
    for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, "x-forwarded-proto") and std.ascii.eqlIgnoreCase(h.value, "https")) return true;
    return false;
}

/// The path to write in the log: one the bridge serves, or a fixed word. Never client text.
fn knownPath(path: []const u8) []const u8 {
    if (assets.indexOf(path)) |i| return assets.all[i].path;
    for ([_][]const u8{ "/ws", "/labws", "/api/tree", "/api/lab/hb", "/api/lab/result" }) |k| if (std.mem.eql(u8, path, k)) return k;
    if (std.mem.startsWith(u8, path, "/xfer/")) return "/xfer/(token)"; // never the token itself
    return "(other)";
}

/// Remove a stale socket `name` in the socket's folder `dir_fd` (at `path`), but never anything
/// else: an entry that is not a socket (a link included: it is never followed), or a socket
/// something is still listening on, is an error.
fn clearStaleSocket(io: Io, dir_fd: std.posix.fd_t, name: []const u8, path: []const u8) !void {
    const n = xfer.statAt(dir_fd, name) catch |e| switch (e) {
        error.FileNotFound => return,
        else => return e,
    };
    if (!xfer.isSocket(n)) return error.NotASocket;
    const addr = try Io.net.UnixAddress.init(path);
    if (addr.connect(io)) |c| {
        c.close(io);
        return error.AddressInUse;
    } else |_| {}
    try (Io.Dir{ .handle = dir_fd }).deleteFile(io, name);
}

// ---- OS bits ----

/// The unix socket's folder, opened and checked: every folder above it passes `xfer.checkAncestor`
/// (walked from `/` without following a link; missing ones are made 0700 inside their checked
/// parent), and the folder itself, made 0700 if missing, must be ours and closed to others
/// (`xfer.checkPrivateDirFd`: by mode and ACL), or another user could replace the socket; every
/// folder, this one included, must also have no ACL that lets another user write and be on a
/// filesystem whose owners mean what they say. The caller keeps the descriptor; `name` is the socket's
/// name in it (a slice of `socket_path`).
fn openSocketDir(gpa: Allocator, io: Io, socket_path: []const u8, problem: *xfer.Problem) !struct { fd: std.posix.fd_t, name: []const u8 } {
    problem.setPath(socket_path);
    if (socket_path.len == 0 or socket_path[0] != '/') return error.SocketPathNotAbsolute;
    const name = std.fs.path.basename(socket_path);
    if (socket_path[socket_path.len - 1] == '/' or name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) return error.BadSocketPath;
    const dir = std.fs.path.dirname(socket_path) orelse return error.BadSocketPath;
    const above = std.fs.path.dirname(dir) orelse return error.SocketDirNotOurs; // the socket right in `/`
    const dir_name = std.fs.path.basename(dir);
    if (std.mem.eql(u8, dir_name, ".") or std.mem.eql(u8, dir_name, "..")) return error.BadSocketPath;
    const parent = try xfer.openChain(gpa, io, above, true, problem);
    defer (Io.Dir{ .handle = parent }).close(io);
    problem.setPath(dir);
    const fd = try xfer.openFolderAt(io, parent, dir_name, true);
    errdefer (Io.Dir{ .handle = fd }).close(io);
    // Ours and closed to others, by mode and by ACL, on a filesystem whose owners mean what they say.
    xfer.checkPrivateDirFdDetailed(gpa, io, fd, problem) catch |e| return switch (e) {
        error.NotOwned => error.SocketDirNotOurs,
        error.TooOpen, error.StatFailed => error.SocketDirNotPrivate,
        else => e,
    };
    problem.setPath(socket_path);
    return .{ .fd = fd, .name = name };
}

// ---- tests ----

const testing = std.testing;
const fake = rex.fake;

/// A fresh random token for one test bridge: 32 hex characters from `io.random`, never a constant,
/// so no other local process can guess its way into a test server.
fn randomToken(buf: *[32]u8) []const u8 {
    var raw: [16]u8 = undefined;
    testing.io.random(&raw);
    buf.* = std.fmt.bytesToHex(raw, .lower);
    return buf;
}

const Rig = struct {
    f: *fake.Fake,
    ctl: *rex.control.Control,
    hub: *Hub,
    srv: *Server,
    session_id: []const u8,
    block_id: []const u8,
    /// This rig's own random token (used when its access rule has one).
    tok: *[32]u8,

    const Extra = struct {
        backend_secret: ?[]const u8 = null,
        head_timeout_ms: u32 = 10_000,
        max_pending: u32 = 16,
        max_viewers: u32 = 32,
        lab: bool = true,
        silent_limit_ms: u32 = 20_000,
        write_deadline_ms: u32 = 30_000,
        transfer_idle_ms: u32 = 30_000,
    };

    fn init(hub_cfg: hub_mod.Config, acc: access.Config, listen: Listen) !Rig {
        return initExtra(hub_cfg, acc, listen, .{});
    }

    /// `acc.token`, when set, only says "use a token": the rig makes its own random one.
    fn initExtra(hub_cfg: hub_mod.Config, acc_in: access.Config, listen: Listen, extra: Extra) !Rig {
        const a = testing.allocator;
        const tok = try a.create([32]u8);
        errdefer a.destroy(tok);
        var acc = acc_in;
        const random = randomToken(tok);
        if (acc.token != null) acc.token = random;
        const f = try fake.Fake.start(a, testing.io);
        errdefer f.deinit();
        const made = try f.createSession("rweb-test-server");
        const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
        errdefer ctl.close();
        const h = try Hub.open(a, testing.io, ctl, hub_cfg);
        errdefer h.close();
        const srv = try Server.start(a, testing.io, h, .{
            .listen = listen,
            .access = acc,
            .backend_secret = extra.backend_secret,
            .head_timeout_ms = extra.head_timeout_ms,
            .max_pending = extra.max_pending,
            .max_viewers = extra.max_viewers,
            .lab = extra.lab,
            .silent_limit_ms = extra.silent_limit_ms,
            .write_deadline_ms = extra.write_deadline_ms,
            .transfer_idle_ms = extra.transfer_idle_ms,
        });
        return .{ .f = f, .ctl = ctl, .hub = h, .srv = srv, .session_id = made.session_id, .block_id = made.block_id, .tok = tok };
    }

    fn deinit(r: Rig) void {
        r.srv.stop();
        r.hub.close();
        r.ctl.close();
        r.f.deinit();
        testing.allocator.destroy(r.tok);
    }

    fn token(r: Rig) []const u8 {
        return r.tok;
    }

    /// `path` with this rig's token added to its query. The caller frees it.
    fn withToken(r: Rig, path: []const u8) ![]u8 {
        const sep: []const u8 = if (std.mem.indexOfScalar(u8, path, '?') != null) "&" else "?";
        return testing.allocator.print("{s}{s}token={s}", .{ path, sep, r.tok });
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
    const req = try testing.allocator.print("GET {s} HTTP/1.1\r\nHost: localhost\r\n{s}Connection: close\r\n\r\n", .{ path, headers });
    defer testing.allocator.free(req);
    return httpRequest(try r.tcp(), req);
}

/// `get` with the rig's token added to the query.
fn getT(r: Rig, path: []const u8, headers: []const u8) !Http {
    const p = try r.withToken(path);
    defer testing.allocator.free(p);
    return get(r, p, headers);
}

/// A token rule; each rig replaces the placeholder with its own random token (`Rig.initExtra`).
const token_cfg: access.Config = .{ .token = "replaced-by-each-rig" };

/// The page's address under the rig token's prefix, with the token: `/s/<id>/?token=...`.
fn pagePath(rig: Rig, buf: []u8) []const u8 {
    var pb: [35]u8 = undefined;
    return std.fmt.bufPrint(buf, "{s}/?token={s}", .{ tokenPrefix(&pb, rig.token()), rig.token() }) catch unreachable;
}

test "server: assets are served with a strict content security policy" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    var ppb: [128]u8 = undefined;
    const h = try get(rig, pagePath(rig, &ppb), "");
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 200), h.status);
    try testing.expect(std.mem.indexOf(u8, h.body, "<title>rweb</title>") != null);
    try testing.expect(std.mem.indexOf(u8, h.head, "content-security-policy") != null or std.mem.indexOf(u8, h.head, "Content-Security-Policy") != null);
    try testing.expect(std.mem.indexOf(u8, h.head, "frame-ancestors 'none'") != null);
    // The web app manifest is same-origin; without `manifest-src`, `default-src 'none'` would block it.
    try testing.expect(std.mem.indexOf(u8, h.head, "manifest-src 'self'") != null);
    // Nothing in the page loads from elsewhere: its one outside address is a link to rweb's own page,
    // opened in a new tab (`assets.zig` checks it), which loads nothing here.
    try testing.expect(std.mem.indexOf(u8, h.body, "http://") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, h.body, "https://"));
    try testing.expect(std.mem.indexOf(u8, h.body, "href=\"" ++ assets.rweb_home ++ "\"") != null);

    for ([_][]const u8{ "/app.js", "/keys.js", "/lab", "/lab.js", "/app.css", "/vendor/xterm.js", "/vendor/xterm.css", "/vendor/addon-fit.js", "/vendor/LICENSE-xterm.txt", "/wterm-shim.js", "/vendor/wterm.js", "/vendor/wterm.css", "/vendor/ghostty-vt.wasm", "/vendor/LICENSE-wterm.txt" }) |p| {
        const a = try getT(rig, p, "");
        defer freeHttp(a);
        try testing.expectEqual(@as(u16, 200), a.status);
        try testing.expect(a.body.len > 100);
    }
    // The icons and the manifest, with the types browsers need to use them (nosniff is on).
    for ([_][2][]const u8{
        .{ "/manifest.webmanifest", "application/manifest+json" },
        .{ "/icons/favicon.svg", "image/svg+xml" },
        .{ "/icons/favicon.ico", "image/x-icon" },
        .{ "/icons/apple-touch-icon.png", "image/png" },
        .{ "/icons/icon-192.png", "image/png" },
        .{ "/icons/icon-512.png", "image/png" },
        .{ "/icons/icon-maskable-512.png", "image/png" },
    }) |pt| {
        const a = try getT(rig, pt[0], "");
        defer freeHttp(a);
        try testing.expectEqual(@as(u16, 200), a.status);
        try testing.expectEqualStrings(pt[1], headerValue(a.head, "content-type").?);
        try testing.expectEqualSlices(u8, assets.find(pt[0]).?.body, a.body);
    }
    const nf = try getT(rig, "/nope", "");
    defer freeHttp(nf);
    try testing.expectEqual(@as(u16, 404), nf.status);
    const tree = try getT(rig, "/api/tree", "");
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
    const path = try rig.withToken("/vendor/xterm.js");
    defer testing.allocator.free(path);
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
    // Kept, but revalidated: a new binary's vendored files are used at once.
    try testing.expectEqualStrings("private, no-cache", headerValue(z.head, "cache-control").?);
    const tag = headerValue(z.head, "etag").?;
    try testing.expect(tag.len == 34 and tag[0] == '"');

    // A browser that has it asks "still this?" and gets no body.
    const hdr = try testing.allocator.print("If-None-Match: {s}\r\n", .{tag});
    defer testing.allocator.free(hdr);
    const nm = try get(rig, path, hdr);
    defer freeHttp(nm);
    try testing.expectEqual(@as(u16, 304), nm.status);
    try testing.expectEqual(@as(usize, 0), nm.body.len);
    // A different validator gets the file.
    const other = try get(rig, path, "If-None-Match: \"nope\"\r\n");
    defer freeHttp(other);
    try testing.expectEqual(@as(u16, 200), other.status);

    // A token page sets the cookie: never stored, and never a 304.
    var ppb: [128]u8 = undefined;
    const page = try get(rig, pagePath(rig, &ppb), "");
    defer freeHttp(page);
    try testing.expectEqualStrings("no-store", headerValue(page.head, "cache-control").?);
    try testing.expect(headerValue(page.head, "set-cookie") != null);
    const page_tag = headerValue(page.head, "etag").?;
    const hdr2 = try testing.allocator.print("If-None-Match: {s}\r\n", .{page_tag});
    defer testing.allocator.free(hdr2);
    const page2 = try get(rig, pagePath(rig, &ppb), hdr2);
    defer freeHttp(page2);
    try testing.expectEqual(@as(u16, 200), page2.status);

    // Errors are never cached.
    const forbidden = try get(rig, "/vendor/xterm.js", "");
    defer freeHttp(forbidden);
    try testing.expectEqual(@as(u16, 403), forbidden.status);
    try testing.expectEqualStrings("no-store", headerValue(forbidden.head, "cache-control").?);
}

test "server: the token cookie is scoped to the token's own path, never to the whole host" {
    // Cookies are shared by every port on a host: a cookie for `/` on 127.0.0.1 would also go to any
    // other loopback service the browser visits, and two tunnels would overwrite each other's.
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const token = rig.token();
    var pb: [35]u8 = undefined;
    const pfx = tokenPrefix(&pb, token);
    try testing.expect(std.mem.startsWith(u8, pfx, "/s/") and pfx.len == 35);
    try testing.expect(std.mem.indexOf(u8, pfx, token) == null);
    var pb2: [35]u8 = undefined;
    try testing.expect(!std.mem.eql(u8, pfx, tokenPrefix(&pb2, "another-token-0123456789")));

    // Opening `/?token=` moves to the prefix, keeps other parameters, drops the token, sets the
    // prefix-scoped cookie and deletes 0.1.0's site-wide one.
    var tb: [96]u8 = undefined;
    const r = try get(rig, try std.fmt.bufPrint(&tb, "/?dbg=1&token={s}&term=xterm", .{token}), "");
    defer freeHttp(r);
    try testing.expectEqual(@as(u16, 303), r.status);
    var lb: [128]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&lb, "{s}/?dbg=1&term=xterm", .{pfx}), headerValue(r.head, "location").?);
    try testing.expect(std.mem.indexOf(u8, r.head, try std.fmt.bufPrint(&tb, "{s}&", .{token})) == null and std.mem.indexOf(u8, headerValue(r.head, "location").?, token) == null);
    var cb: [160]u8 = undefined;
    const want_cookie = try std.fmt.bufPrint(&cb, "rweb-token={s}; Path={s}/; HttpOnly; SameSite=Strict", .{ token, pfx });
    try testing.expect(std.mem.indexOf(u8, r.head, want_cookie) != null);
    try testing.expect(std.mem.indexOf(u8, r.head, "rweb-token=; Path=/; Max-Age=0") != null);
    try testing.expect(std.mem.indexOf(u8, r.head, "Path=/;") == null or std.mem.indexOf(u8, r.head, "Max-Age=0") != null);

    // A wrong token is refused before any redirect.
    const bad = try get(rig, "/?token=wrong", "");
    defer freeHttp(bad);
    try testing.expectEqual(@as(u16, 403), bad.status);

    // `/s/<id>` without its slash gets one (relative paths need it), but only once access allows
    // the request; no cookie is set there.
    var hb: [96]u8 = undefined;
    const ck = try std.fmt.bufPrint(&hb, "Cookie: rweb-token={s}\r\n", .{token});
    const anon = try get(rig, pfx, "");
    defer freeHttp(anon);
    try testing.expectEqual(@as(u16, 403), anon.status);
    try testing.expect(headerValue(anon.head, "location") == null);
    const ns = try get(rig, pfx, ck);
    defer freeHttp(ns);
    try testing.expectEqual(@as(u16, 302), ns.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&lb, "{s}/", .{pfx}), headerValue(ns.head, "location").?);
    try testing.expect(headerValue(ns.head, "set-cookie") == null);
    // What it copies from the query is percent-encoded.
    var qb: [96]u8 = undefined;
    const nq = try get(rig, try std.fmt.bufPrint(&qb, "{s}?a=\xc3\xa9\"<&b=1", .{pfx}), ck);
    defer freeHttp(nq);
    try testing.expectEqual(@as(u16, 302), nq.status);
    try testing.expectEqualStrings(try std.fmt.bufPrint(&lb, "{s}/?a=%C3%A9%22%3C&b=1", .{pfx}), headerValue(nq.head, "location").?);

    // Under the prefix the cookie authenticates the page, its files, the tree and the socket.
    for ([_][]const u8{ "/", "/app.js", "/vendor/wterm.js", "/api/tree" }) |p| {
        var ub: [96]u8 = undefined;
        const page = try get(rig, try std.fmt.bufPrint(&ub, "{s}{s}", .{ pfx, p }), ck);
        defer freeHttp(page);
        try testing.expectEqual(@as(u16, 200), page.status);
    }
    var wb: [96]u8 = undefined;
    var wh: [96]u8 = undefined;
    const c = try rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), try std.fmt.bufPrint(&wb, "{s}/ws", .{pfx}), null, try std.fmt.bufPrint(&wh, "Origin: http://localhost\r\nCookie: rweb-token={s}\r\n", .{token}));
    c.deinit(testing.allocator);
    // Without the cookie or token, under the prefix: refused.
    var ub2: [96]u8 = undefined;
    const no = try get(rig, try std.fmt.bufPrint(&ub2, "{s}/app.js", .{pfx}), "");
    defer freeHttp(no);
    try testing.expectEqual(@as(u16, 403), no.status);
    // A path that only begins like the prefix is not under it.
    var ub3: [96]u8 = undefined;
    const longer = try get(rig, try std.fmt.bufPrint(&ub3, "{s}x/app.js", .{pfx}), ck);
    defer freeHttp(longer);
    try testing.expectEqual(@as(u16, 404), longer.status);
    try testing.expect(stripPrefix("/s/ab/x", "/s/ab").?.len == 2);
    try testing.expect(stripPrefix("/s/abc", "/s/ab") == null);
    try testing.expectEqualStrings("?q", stripPrefix("/s/ab?q", "/s/ab").?);
}

test "server: refuses a request with no token or the wrong one" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    // Without a token, `/` is the token form (below); any other path is refused.
    const a = try get(rig, "/app.js", "");
    defer freeHttp(a);
    try testing.expectEqual(@as(u16, 403), a.status);
    try testing.expectEqualStrings("forbidden\n", a.body);
    try testing.expectEqual(@backingInt(access.Refusal.no_token), rig.srv.last_refusal.load(.acquire));
    const b = try get(rig, "/?token=wrong", "");
    defer freeHttp(b);
    try testing.expectEqual(@as(u16, 403), b.status);
    try testing.expectEqual(@backingInt(access.Refusal.bad_token), rig.srv.last_refusal.load(.acquire));
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
    try testing.expectEqual(@backingInt(why), rig.srv.last_refusal.load(.acquire));
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
    const path = try rig.withToken("/ws");
    defer testing.allocator.free(path);
    // Another site's page: refused at the upgrade.
    try testing.expectError(error.UpgradeRefused, rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, "Origin: https://evil.example\r\n"));
    try testing.expectEqual(@backingInt(access.Refusal.bad_origin), rig.srv.last_refusal.load(.acquire));
    // No Origin at all: refused.
    try testing.expectError(error.UpgradeRefused, rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, ""));
    try testing.expectEqual(@backingInt(access.Refusal.no_origin), rig.srv.last_refusal.load(.acquire));
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
    const path = try rig.withToken("/ws");
    defer testing.allocator.free(path);
    return rex.ws.Conn.connectStream(testing.allocator, testing.io, try rig.tcp(), path, null, "Origin: http://localhost\r\n");
}

fn sendJson(c: *rex.ws.Conn, comptime fmt: []const u8, args: anytype) !void {
    const text = try testing.allocator.print(fmt, args);
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
    try sendJson(c, "{{\"t\":\"fit\",\"cols\":100,\"rows\":30,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
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

/// `/tmp` by its real path: a socket's path may not pass through a link, and on macOS `/tmp` is one.
const tmp_root = if (builtin.os.tag.isDarwin()) "/private/tmp" else "/tmp";

fn tmpSocketPath(buf: []u8, io: Io) ![]const u8 {
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    return std.fmt.bufPrint(buf, tmp_root ++ "/rweb-test-{x}/bridge.sock", .{rnd});
}

fn unixGet(rig: Rig, path: []const u8) !Http {
    const addr = try Io.net.UnixAddress.init(rig.srv.opts.listen.unix);
    const stream = try addr.connect(testing.io);
    const req = try testing.allocator.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nTailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.9\r\nConnection: close\r\n\r\n", .{path});
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
        try testing.expectEqual(@as(u32, 0o600), @backingInt(st.permissions) & 0o777);
        var d = try Io.Dir.cwd().openDir(testing.io, dir, .{});
        defer d.close(testing.io);
        const ds = try d.stat(testing.io);
        try testing.expectEqual(@as(u32, 0o700), @backingInt(ds.permissions) & 0o777);
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
        try testing.expectEqual(@backingInt(access.Refusal.wrong_peer), rig.srv.last_refusal.load(.acquire));
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
    // A folder that is not ours (here root's /tmp) is refused too: its owner could replace the socket.
    if (std.c.getuid() != 0) try testing.expectError(error.SocketDirNotOurs, Server.start(a, testing.io, h, .{ .listen = .{ .unix = tmp_root ++ "/rweb-test-not-ours.sock" }, .access = owner_cfg }));
}

test "live: a browser socket drives a throwaway terminal on a real Rex (needs REX_SOCKET)" {
    const a = testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = sock });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();
    var tb: [32]u8 = undefined;
    const tk = randomToken(&tb);
    const srv = try Server.start(a, testing.io, h, .{ .listen = .{ .tcp_loopback = 0 }, .access = .{ .token = tk } });
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
    var wp: [64]u8 = undefined;
    const c = try rex.ws.Conn.connectStream(a, testing.io, stream, try std.fmt.bufPrint(&wp, "/ws?token={s}", .{tk}), null, "Origin: http://localhost\r\n");
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
    for ([_][]const u8{ "/lab", "/lab.js", "/labsel", "/labsel.js", "/api/lab/hb", "/api/lab/result", "/api/tree" }) |p| {
        const h = try getT(rig, p, "");
        defer freeHttp(h);
        try testing.expectEqual(@as(u16, 404), h.status);
    }
    var ppb: [128]u8 = undefined;
    const ok = try get(rig, pagePath(rig, &ppb), "");
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
    try testing.io.sleep(.fromMilliseconds(600), .awake);
    // After the deadline the idle ones are gone and a real request is served.
    var ppb: [128]u8 = undefined;
    const ok = try get(rig, pagePath(rig, &ppb), "");
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
}

test "server: idle connections filling the pending slots do not keep a real request out" {
    // Two pending slots and a long head deadline: without eviction, two idle sockets would hold
    // every new connection off for the whole deadline, and a process reconnecting would forever.
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .max_pending = 2, .head_timeout_ms = 30_000 });
    defer rig.deinit();
    var idle: [6]Io.net.Stream = undefined;
    for (&idle) |*c| {
        c.* = try rig.tcp();
        try testing.io.sleep(.fromMilliseconds(20), .awake);
    }
    defer for (idle) |c| c.close(testing.io);
    // A real request still gets through, at once, and more than once.
    for (0..3) |_| {
        var ppb: [128]u8 = undefined;
        const t0 = Io.Clock.awake.now(testing.io).toMilliseconds();
        const ok = try get(rig, pagePath(rig, &ppb), "");
        defer freeHttp(ok);
        try testing.expectEqual(@as(u16, 200), ok.status);
        try testing.expect(Io.Clock.awake.now(testing.io).toMilliseconds() - t0 < 5_000);
    }
    try testing.expect(rig.srv.evicted.load(.acquire) >= 4);
    // The oldest idle connection was the one dropped.
    var buf: [16]u8 = undefined;
    var rd = idle[0].reader(testing.io, &buf);
    try testing.expectError(error.EndOfStream, rd.interface.takeByte());
}

test "server: a unix socket path that is a file, or in use, is never replaced" {
    var pb: [96]u8 = undefined;
    const path = try tmpSocketPath(&pb, testing.io);
    const dir = std.fs.path.dirname(path).?;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    _ = try Io.Dir.cwd().createDirPathStatus(testing.io, dir, @fromBackingInt(@intCast(0o700)));

    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();
    var tb: [32]u8 = undefined;
    const acc: access.Config = .{ .token = randomToken(&tb) };

    // A regular file is not ours to delete, nor a link (never followed, even to a socket).
    {
        const file = try Io.Dir.cwd().createFile(testing.io, path, .{});
        file.close(testing.io);
        try testing.expectError(error.NotASocket, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc }));
        const st = try Io.Dir.cwd().statFile(testing.io, path, .{});
        try testing.expect(st.kind == .file);
        try Io.Dir.cwd().deleteFile(testing.io, path);
        try Io.Dir.cwd().symLink(testing.io, f.path, path, .{});
        try testing.expectError(error.NotASocket, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc }));
        const ls = try Io.Dir.cwd().statFile(testing.io, path, .{ .follow_symlinks = false });
        try testing.expect(ls.kind == .sym_link);
        try Io.Dir.cwd().deleteFile(testing.io, path);
    }
    // A live listener is not ours to replace.
    const first = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc });
    try testing.expectError(error.AddressInUse, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc }));
    first.stop();
    // A stale socket, left by a bridge that did not exit cleanly, is replaced.
    {
        const addr = try Io.net.UnixAddress.init(path);
        var stale = try addr.listen(testing.io, .{});
        stale.deinit(testing.io); // closed, its file left behind
        _ = try Io.Dir.cwd().statFile(testing.io, path, .{});
    }
    const again = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc });
    again.stop();
}

test "server: the unix socket's folders are checked to the root, and only our own socket is removed" {
    const a = testing.allocator;
    const f = try fake.Fake.start(a, testing.io);
    defer f.deinit();
    const ctl = try rex.control.Control.open(a, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const h = try Hub.open(a, testing.io, ctl, .{});
    defer h.close();
    var tb: [32]u8 = undefined;
    const acc: access.Config = .{ .token = randomToken(&tb) };
    var rnd: [4]u8 = undefined;
    testing.io.random(&rnd);
    var bb: [64]u8 = undefined;
    const base = try std.fmt.bufPrint(&bb, tmp_root ++ "/rweb-test-{x}", .{rnd});
    try Io.Dir.cwd().createDirPath(testing.io, base);
    defer Io.Dir.cwd().deleteTree(testing.io, base) catch {};
    var pb: [128]u8 = undefined;
    var problem: xfer.Problem = .{};

    // The documented layout: a 0700 folder of ours (made if missing) under a safe chain.
    {
        const path = try std.fmt.bufPrint(&pb, "{s}/run/rweb/bridge.sock", .{base});
        const srv = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc, .problem = &problem });
        const st = try Io.Dir.cwd().statFile(testing.io, path, .{ .follow_symlinks = false });
        try testing.expect(st.kind == .unix_domain_socket);
        srv.stop();
        // Its own socket is removed at shutdown.
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, path, .{ .follow_symlinks = false }));
    }
    // A private folder of ours under a folder others can write to (not sticky): refused, and named.
    {
        var ob: [128]u8 = undefined;
        const open = try std.fmt.bufPrint(&ob, "{s}/open", .{base});
        try Io.Dir.cwd().createDirPath(testing.io, open);
        var z: [128:0]u8 = undefined;
        try testing.expectEqual(@as(c_int, 0), std.c.chmod(try std.fmt.bufPrintSentinel(&z, "{s}", .{open}, 0), 0o777));
        _ = try Io.Dir.cwd().createDirPathStatus(testing.io, try std.fmt.bufPrint(&pb, "{s}/priv", .{open}), @fromBackingInt(@intCast(0o700)));
        const path = try std.fmt.bufPrint(&pb, "{s}/priv/bridge.sock", .{open});
        try testing.expectError(error.FolderWritableByOthers, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc, .problem = &problem }));
        try testing.expectEqualStrings(open, problem.pathText());
    }
    // Through a link of ours in a checked folder: followed during the checked walk, so it serves.
    {
        _ = try Io.Dir.cwd().createDirPathStatus(testing.io, try std.fmt.bufPrint(&pb, "{s}/real/sock", .{base}), @fromBackingInt(@intCast(0o700)));
        var lb: [128]u8 = undefined;
        try Io.Dir.cwd().symLink(testing.io, try std.fmt.bufPrint(&lb, "{s}/real", .{base}), try std.fmt.bufPrint(&pb, "{s}/link", .{base}), .{});
        const path = try std.fmt.bufPrint(&pb, "{s}/link/sock/bridge.sock", .{base});
        const srv = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc });
        srv.stop();
    }
    // A link in a folder others can write (who could point it elsewhere): refused at that folder.
    {
        var ob: [128]u8 = undefined;
        const open = try std.fmt.bufPrint(&ob, "{s}/open2", .{base});
        try Io.Dir.cwd().createDirPath(testing.io, open);
        var z: [128:0]u8 = undefined;
        try testing.expectEqual(@as(c_int, 0), std.c.chmod(try std.fmt.bufPrintSentinel(&z, "{s}", .{open}, 0), 0o777));
        var lb: [128]u8 = undefined;
        try Io.Dir.cwd().symLink(testing.io, try std.fmt.bufPrint(&lb, "{s}/real", .{base}), try std.fmt.bufPrint(&pb, "{s}/lnk", .{open}), .{});
        const path = try std.fmt.bufPrint(&pb, "{s}/lnk/sock/bridge.sock", .{open});
        var lp: xfer.Problem = .{};
        try testing.expectError(error.FolderWritableByOthers, Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc, .problem = &lp }));
        try testing.expectEqualStrings(open, lp.pathText());
    }
    // A relative path, or one with `..`, is refused.
    try testing.expectError(error.SocketPathNotAbsolute, Server.start(a, testing.io, h, .{ .listen = .{ .unix = "rweb/bridge.sock" }, .access = acc }));
    try testing.expectError(error.BadPath, Server.start(a, testing.io, h, .{ .listen = .{ .unix = try std.fmt.bufPrint(&pb, "{s}/real/../real/sock/bridge.sock", .{base}) }, .access = acc }));
    // Shutdown leaves alone whatever was put in the socket's place.
    {
        const path = try std.fmt.bufPrint(&pb, "{s}/real/sock/bridge.sock", .{base});
        const srv = try Server.start(a, testing.io, h, .{ .listen = .{ .unix = path }, .access = acc });
        var mb: [128]u8 = undefined;
        try Io.Dir.cwd().rename(path, Io.Dir.cwd(), try std.fmt.bufPrint(&mb, "{s}/real/sock/moved.sock", .{base}), testing.io);
        const other = try Io.Dir.cwd().createFile(testing.io, path, .{});
        other.close(testing.io);
        srv.stop();
        const st = try Io.Dir.cwd().statFile(testing.io, path, .{ .follow_symlinks = false });
        try testing.expect(st.kind == .file);
    }
}

test "server: at most max_viewers WebSockets, and plain requests still get in" {
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .max_viewers = 2 });
    defer rig.deinit();
    try testing.expect((Options{ .listen = .{ .tcp_loopback = 0 }, .access = .{} }).max_viewers < (Options{ .listen = .{ .tcp_loopback = 0 }, .access = .{} }).max_connections);
    const one = try browser(rig);
    defer one.deinit(testing.allocator);
    try waitText(one, "\"t\":\"tree\"");
    const two = try browser(rig);
    defer two.deinit(testing.allocator);
    try waitText(two, "\"t\":\"tree\"");
    // The third upgrade: 503, before any WebSocket is made.
    const path = try rig.withToken("/ws");
    defer testing.allocator.free(path);
    const req = try testing.allocator.print("GET {s} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n", .{path});
    defer testing.allocator.free(req);
    const third = try httpRequest(try rig.tcp(), req);
    defer freeHttp(third);
    try testing.expectEqual(@as(u16, 503), third.status);
    // The page's files are still served.
    var ppb: [128]u8 = undefined;
    const page = try get(rig, pagePath(rig, &ppb), "");
    defer freeHttp(page);
    try testing.expectEqual(@as(u16, 200), page.status);
    // A viewer that leaves frees its place.
    try one.writeFrame(.close, &.{ 0x03, 0xe8 });
    const t0 = nowMs(testing.io);
    while (rig.srv.viewers.load(.acquire) >= 2) {
        if (nowMs(testing.io) - t0 > 3_000) return error.PlaceNotFreed;
        try testing.io.sleep(.fromMilliseconds(20), .awake);
    }
    const again = try browser(rig);
    defer again.deinit(testing.allocator);
    try waitText(again, "\"t\":\"tree\"");
}

test "server: a viewer is silent only when its reader is not busy in a handler" {
    try testing.expect(isSilent(10_000, 1_000, 0, 5_000));
    try testing.expect(!isSilent(10_000, 6_000, 0, 5_000));
    // Busy waiting on Rex since long ago: not dropped, however old the last message is.
    try testing.expect(!isSilent(100_000, 1_000, 2_000, 5_000));
}

test "server: a browser whose handler waits on Rex is not dropped as silent" {
    const o = try openRigExtra(.{}, .{ .silent_limit_ms = 600 });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    // Rex is slow: the call this message needs waits far past the silence limit.
    o.rig.hub.api_mu.lockUncancelable(testing.io);
    var locked = true;
    defer if (locked) o.rig.hub.api_mu.unlock(testing.io);
    try sendJson(o.c, "{{\"t\":\"clip\"}}", .{});
    try testing.io.sleep(.fromMilliseconds(2_000), .awake);
    try testing.expectEqual(@as(u32, 1), o.rig.srv.active.load(.acquire));
    o.rig.hub.api_mu.unlock(testing.io);
    locked = false;
    // The reply arrives, and the connection goes on.
    try waitText(o.c, "\"t\":\"clip\"");
    try sendJson(o.c, "{{\"t\":\"ping\"}}", .{});
    try waitText(o.c, "pong");
}

test "server: a message over the limit is answered with an error, then the socket is closed" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    const big = try testing.allocator.alloc(u8, protocol.max_message_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, 'a');
    try c.writeFrame(.text, big);
    const msg = try textWith(c, "too large");
    defer testing.allocator.free(msg);
    try testing.expectEqualStrings(too_large_text, msg);
    // Then the conversation ends.
    var ended = false;
    for (0..1000) |_| {
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

/// A new upload folder under /tmp, made and opened as the bridge does at startup. The caller closes
/// `dir` and removes `path`.
const UploadDir = struct { path: []const u8, dir: Io.Dir, parts: Io.Dir };

fn uploadDir(buf: []u8) !UploadDir {
    var rnd: [4]u8 = undefined;
    testing.io.random(&rnd);
    const path = try std.fmt.bufPrint(buf, "/tmp/rweb-test-up-{x}", .{rnd});
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    var problem: xfer.Problem = .{};
    const up = try xfer.openUploadDir(arena.allocator(), testing.io, path, &problem);
    return .{ .path = path, .dir = up.dir, .parts = up.parts };
}

const Opened = struct { rig: Rig, c: *rex.ws.Conn };

fn openRig(cfg: hub_mod.Config) !Opened {
    return openRigExtra(cfg, .{});
}

fn openRigExtra(cfg: hub_mod.Config, extra: Rig.Extra) !Opened {
    const rig = try Rig.initExtra(cfg, token_cfg, .{ .tcp_loopback = 0 }, extra);
    errdefer rig.deinit();
    const c = try browser(rig);
    errdefer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    return .{ .rig = rig, .c = c };
}

fn put(rig: Rig, token_path: []const u8, headers: []const u8, body: []const u8) !Http {
    const req = try testing.allocator.print("PUT {s}?token={s} HTTP/1.1\r\nHost: localhost\r\nContent-Length: {d}\r\n{s}Connection: close\r\n\r\n", .{ token_path, rig.token(), body.len, headers });
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
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"/etc/hosts\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const e = try textWith(o.c, "file transfer is off");
    testing.allocator.free(e);
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"a\",\"size\":1,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    testing.allocator.free(try textWith(o.c, "file transfer is off"));
    // And its address answers nothing.
    const h = try getT(o.rig, "/xfer/00000000000000000000000000000000", "");
    defer freeHttp(h);
    try testing.expectEqual(@as(u16, 404), h.status);
}

test "server: a download goes through a one-time token and nothing else" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const path = try testing.allocator.print("{s}/my notes.txt", .{dir});
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
    try o.rig.f.setFilesRoot(dir); // the fake serves only this folder

    // Without a token, nothing: not even a guess at the shape.
    for ([_][]const u8{ "/xfer/", "/xfer/short", "/xfer/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz", "/xfer/00000000000000000000000000000000" }) |p| {
        const h = try getT(o.rig, p, "");
        defer freeHttp(h);
        try testing.expectEqual(@as(u16, 404), h.status);
    }

    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ path, o.rig.session_id, o.rig.block_id });
    const msg = try textWith(o.c, "\"t\":\"xfer\"");
    defer testing.allocator.free(msg);
    try testing.expect(std.mem.indexOf(u8, msg, "\"kind\":\"download\"") != null);
    try testing.expect(std.mem.indexOf(u8, msg, "\"name\":\"my notes.txt\"") != null);
    const tok = try tokenIn(msg);
    const url = try testing.allocator.print("/xfer/{s}?token={s}", .{ tok, o.rig.token() });
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
    const big = try testing.allocator.print("{s}/big.bin", .{dir});
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
    try o.rig.f.setFilesRoot(dir); // the fake serves only this folder
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}/nope\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ dir, o.rig.session_id, o.rig.block_id });
    testing.allocator.free(try textWith(o.c, "\"for\":\"dl\""));
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ big, o.rig.session_id, o.rig.block_id });
    const e = try textWith(o.c, "too large");
    testing.allocator.free(e);
}

test "server: observe-only viewers cannot start a transfer" {
    const o = try openRig(.{ .observe_only = true, .transfer = .{ .enabled = true } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"/etc/hosts\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    testing.allocator.free(try textWith(o.c, "read-only"));
    try sendJson(o.c, "{{\"t\":\"ls\",\"path\":\"/\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    testing.allocator.free(try textWith(o.c, "read-only"));
}

test "server: a directory listing for the picker" {
    var db: [64]u8 = undefined;
    const dir = try tmpDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    const sub = try testing.allocator.print("{s}/sub", .{dir});
    defer testing.allocator.free(sub);
    try Io.Dir.cwd().createDirPath(testing.io, sub);
    const fp = try testing.allocator.print("{s}/a.txt", .{dir});
    defer testing.allocator.free(fp);
    (try Io.Dir.cwd().createFile(testing.io, fp, .{})).close(testing.io);
    const o = try openRig(.{ .transfer = .{ .enabled = true } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    try o.rig.f.setFilesRoot(dir); // the fake serves only this folder
    try sendJson(o.c, "{{\"t\":\"ls\",\"path\":\"{s}\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ dir, o.rig.session_id, o.rig.block_id });
    const m = try textWith(o.c, "\"t\":\"ls\"");
    defer testing.allocator.free(m);
    try testing.expect(std.mem.indexOf(u8, m, "\"n\":\"a.txt\",\"d\":false") != null);
    try testing.expect(std.mem.indexOf(u8, m, "\"n\":\"sub\",\"d\":true") != null);
    try testing.expect(std.mem.indexOf(u8, m, "\"status\":\"ok\"") != null);
}

test "server: an upload lands only in the upload folder, under a safe new name, and its path is pasted" {
    var db: [64]u8 = undefined;
    const up = try uploadDir(&db);
    const dir = up.path;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    // What is pasted and returned is the folder's real path (on macOS `/tmp` is a link).
    const real = try Io.Dir.cwd().realPathFileAlloc(testing.io, dir, testing.allocator);
    defer testing.allocator.free(real);
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = dir, .upload_dir_real = real, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);
    const content = "hello from a phone\nsecond line\n";

    // A hostile name: path parts and shell characters.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"../../etc/evil;rm -rf ~.txt\",\"size\":{d},\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ content.len, o.rig.session_id, o.rig.block_id });
    const msg = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(msg);
    const url = try testing.allocator.print("/xfer/{s}", .{try tokenIn(msg)});
    defer testing.allocator.free(url);
    const r = try put(o.rig, url, "Origin: http://localhost\r\n", content);
    defer freeHttp(r);
    try testing.expectEqual(@as(u16, 200), r.status);

    // Only the safe name, in the folder, with the content, closed to others.
    const saved = try testing.allocator.print("{s}/evil_rm -rf _.txt", .{dir});
    defer testing.allocator.free(saved);
    const got = try Io.Dir.cwd().readFileAlloc(testing.io, saved, testing.allocator, .limited(1 << 16));
    defer testing.allocator.free(got);
    try testing.expectEqualStrings(content, got);
    const st = try Io.Dir.cwd().statFile(testing.io, saved, .{});
    try testing.expectEqual(@as(u32, 0o600), @backingInt(st.permissions) & 0o777);
    const saved_real = try testing.allocator.print("{s}/evil_rm -rf _.txt", .{real});
    defer testing.allocator.free(saved_real);
    try testing.expect(std.mem.indexOf(u8, r.body, saved_real) != null);
    try testing.expect(std.mem.indexOf(u8, r.body, "\"pasted\":true") != null);
    // Written in the folder for unfinished uploads, and nothing is left there.
    try testing.expectEqual(@as(usize, 0), countParts(up.parts));
    var staged = up.parts.iterate();
    try testing.expect((try staged.next(testing.io)) == null);
    // Nothing escaped into the folders above it.
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, "/tmp/etc/evil;rm -rf ~.txt", .{}));

    // The terminal was given the quoted real path, to type or not.
    const quoted = try testing.allocator.print("'{s}' ", .{saved_real}); // with the space that separates it from the next
    defer testing.allocator.free(quoted);
    try waitBinary(o.c, quoted);

    // The same name again does not replace it.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"evil;rm -rf ~.txt\",\"size\":3,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const msg2 = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(msg2);
    const url2 = try testing.allocator.print("/xfer/{s}", .{try tokenIn(msg2)});
    defer testing.allocator.free(url2);
    const r2 = try put(o.rig, url2, "Origin: http://localhost\r\n", "new");
    defer freeHttp(r2);
    try testing.expectEqual(@as(u16, 200), r2.status);
    const second = try testing.allocator.print("{s}/evil_rm -rf _ (1).txt", .{dir});
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
    const up = try uploadDir(&db);
    const dir = up.path;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = dir, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1000 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);

    // Too big, said at the first step.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"big\",\"size\":5000,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    testing.allocator.free(try textWith(o.c, "too large"));

    // Another site's page (a cross-site PUT carries its own Origin): 403 and the token is not spent.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"a.txt\",\"size\":4,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const m = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(m);
    const url = try testing.allocator.print("/xfer/{s}", .{try tokenIn(m)});
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
    const ghost = try testing.allocator.print("{s}/a.txt", .{dir});
    defer testing.allocator.free(ghost);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, ghost, .{}));

    // A download token cannot be used to upload.
    const served = try testing.allocator.print("{s}/served.txt", .{o.rig.f.files_root.?});
    defer testing.allocator.free(served);
    (try Io.Dir.cwd().createFile(testing.io, served, .{})).close(testing.io);
    try sendJson(o.c, "{{\"t\":\"dl\",\"path\":\"{s}\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ served, o.rig.session_id, o.rig.block_id });
    const d = try textWith(o.c, "\"kind\":\"download\"");
    defer testing.allocator.free(d);
    const durl = try testing.allocator.print("/xfer/{s}", .{try tokenIn(d)});
    defer testing.allocator.free(durl);
    const swap = try put(o.rig, durl, "Origin: http://localhost\r\n", "x");
    defer freeHttp(swap);
    try testing.expectEqual(@as(u16, 404), swap.status);
}

// ---- the fixes from the 2026-11-25 round-2 review ----

test "server: a target with a control byte or a space is refused before routing" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const token = rig.token();
    var pb: [35]u8 = undefined;
    const pfx = tokenPrefix(&pb, token);
    for ([_][]const u8{ "\x01", "\x7f", "\t", "\r", "\x00" }) |bad| {
        // Bare `/s/<id>` (once a redirect that copied the query) and a plain path.
        for ([_][]const u8{ pfx, "/" }) |base| {
            const req = try testing.allocator.print("GET {s}?a={s}x&token={s} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", .{ base, bad, token });
            defer testing.allocator.free(req);
            if (httpRequest(try rig.tcp(), req)) |h| {
                defer freeHttp(h);
                try testing.expectEqual(@as(u16, 400), h.status);
                try testing.expect(headerValue(h.head, "location") == null);
            } else |_| {} // the HTTP parser may refuse it first: just as good
        }
    }
    try testing.expect(targetIsClean("/s/ab/?x=%0d%0a"));
    try testing.expect(!targetIsClean("/a b") and !targetIsClean("/a\x1b") and !targetIsClean("/\x7f"));
    try testing.expect(targetIsClean("/\xc3\xa9")); // not ASCII, but not a control byte: encoded where copied
}

test "server: an upload token stops working once its page turns read-only or leaves the terminal" {
    var db: [64]u8 = undefined;
    const up = try uploadDir(&db);
    const dir = up.path;
    defer Io.Dir.cwd().deleteTree(testing.io, dir) catch {};
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = dir, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(testing.allocator);

    // Read-only after asking: the token is gone.
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"a.txt\",\"size\":3,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const m1 = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(m1);
    const url1 = try testing.allocator.print("/xfer/{s}", .{try tokenIn(m1)});
    defer testing.allocator.free(url1);
    try sendJson(o.c, "{{\"t\":\"observe\",\"on\":true}}", .{});
    testing.allocator.free(try textWith(o.c, "\"observe\":true"));
    const r1 = try put(o.rig, url1, "Origin: http://localhost\r\n", "one");
    defer freeHttp(r1);
    try testing.expectEqual(@as(u16, 404), r1.status);

    // Left the terminal after asking: the token is gone, and no file is made.
    try sendJson(o.c, "{{\"t\":\"observe\",\"on\":false}}", .{});
    testing.allocator.free(try textWith(o.c, "\"observe\":false"));
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"b.txt\",\"size\":3,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const m2 = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(m2);
    const url2 = try testing.allocator.print("/xfer/{s}", .{try tokenIn(m2)});
    defer testing.allocator.free(url2);
    try sendJson(o.c, "{{\"t\":\"close_view\"}}", .{});
    try sendJson(o.c, "{{\"t\":\"ping\"}}", .{});
    testing.allocator.free(try textWith(o.c, "\"pong\""));
    const r2 = try put(o.rig, url2, "Origin: http://localhost\r\n", "two");
    defer freeHttp(r2);
    try testing.expectEqual(@as(u16, 404), r2.status);

    // Reopening the same terminal does not revive an earlier view's upload token.
    try sendJson(o.c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    try waitText(o.c, "\"t\":\"opened\"");
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"c.txt\",\"size\":3,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const m3 = try textWith(o.c, "\"kind\":\"upload\"");
    defer testing.allocator.free(m3);
    const url3 = try testing.allocator.print("/xfer/{s}", .{try tokenIn(m3)});
    defer testing.allocator.free(url3);
    try sendJson(o.c, "{{\"t\":\"close_view\"}}", .{});
    try sendJson(o.c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    try waitText(o.c, "\"t\":\"opened\"");
    const r3 = try put(o.rig, url3, "Origin: http://localhost\r\n", "thr");
    defer freeHttp(r3);
    try testing.expectEqual(@as(u16, 404), r3.status);
    for ([_][]const u8{ "a.txt", "b.txt", "c.txt" }) |name| {
        const path = try testing.allocator.print("{s}/{s}", .{ dir, name });
        defer testing.allocator.free(path);
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, path, .{}));
    }
}

test "server: an upload goes into the folder opened at startup, whatever replaces its path" {
    var db: [64]u8 = undefined;
    const up = try uploadDir(&db);
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    const a = testing.allocator;
    const moved = try a.print("{s}.moved", .{up.path});
    defer a.free(moved);
    const elsewhere = try a.print("{s}.elsewhere", .{up.path});
    defer a.free(elsewhere);
    defer for ([_][]const u8{ up.path, moved, elsewhere }) |p| Io.Dir.cwd().deleteTree(testing.io, p) catch {};
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = up.path, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(a);

    // The folder is renamed away and a new one, then a link to another, put at its path.
    try Io.Dir.renameAbsolute(up.path, moved, testing.io);
    try Io.Dir.cwd().createDirPath(testing.io, up.path);
    try Io.Dir.cwd().createDirPath(testing.io, elsewhere);
    for ([_][]const u8{ "first.txt", "second.txt" }, 0..) |name, round| {
        if (round == 1) {
            try Io.Dir.cwd().deleteTree(testing.io, up.path);
            try Io.Dir.cwd().symLink(testing.io, elsewhere, up.path, .{});
        }
        try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"{s}\",\"size\":2,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ name, o.rig.session_id, o.rig.block_id });
        const msg = try textWith(o.c, "\"kind\":\"upload\"");
        defer a.free(msg);
        const url = try a.print("/xfer/{s}", .{try tokenIn(msg)});
        defer a.free(url);
        const r = try put(o.rig, url, "Origin: http://localhost\r\n", "hi");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 200), r.status);
        // In the original folder, under its new name; not in what took its place.
        const kept = try a.print("{s}/{s}", .{ moved, name });
        defer a.free(kept);
        const got = try Io.Dir.cwd().readFileAlloc(testing.io, kept, a, .limited(64));
        defer a.free(got);
        try testing.expectEqualStrings("hi", got);
        for ([_][]const u8{ up.path, elsewhere }) |d| {
            const ghost = try a.print("{s}/{s}", .{ d, name });
            defer a.free(ghost);
            try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, ghost, .{}));
        }
    }
}

/// Part files in the folder for unfinished uploads.
fn countParts(parts: Io.Dir) usize {
    var n: usize = 0;
    var it = parts.iterate();
    while (it.next(testing.io) catch null) |e| {
        if (xfer.isUploadPartName(e.name)) n += 1;
    }
    return n;
}

test "server: an upload that stops sending is cut, and its partial file removed" {
    var db: [64]u8 = undefined;
    const up = try uploadDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, up.path) catch {};
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    const a = testing.allocator;
    const o = try openRigExtra(.{ .transfer = .{ .enabled = true, .upload_dir = up.path, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1 << 20 } }, .{ .transfer_idle_ms = 300 });
    defer o.rig.deinit();
    defer o.c.deinit(a);
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"stall.bin\",\"size\":100,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const msg = try textWith(o.c, "\"kind\":\"upload\"");
    defer a.free(msg);
    // Ten of the hundred bytes announced, then nothing.
    const req = try a.print("PUT /xfer/{s}?token={s} HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost\r\nContent-Length: 100\r\n\r\n0123456789", .{ try tokenIn(msg), o.rig.token() });
    defer a.free(req);
    const stream = try o.rig.tcp();
    defer stream.close(testing.io);
    var wb: [512]u8 = undefined;
    var w = stream.writer(testing.io, &wb);
    try w.interface.writeAll(req);
    try w.interface.flush();
    const t0 = nowMs(testing.io);
    // While the bytes are still coming, the file has no real name yet: only a part file exists. A stop
    // or a crash now leaves nothing that looks like a finished upload.
    const partial = try a.print("{s}/stall.bin", .{up.path});
    defer a.free(partial);
    var saw_part = false;
    for (0..100) |_| {
        if (countParts(up.parts) == 1) {
            saw_part = true;
            break;
        }
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    try testing.expect(saw_part);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(testing.io, partial, .{}));
    var rb: [256]u8 = undefined;
    var r = stream.reader(testing.io, &rb);
    while (true) _ = r.interface.takeByte() catch break; // until the bridge cuts it
    try testing.expect(nowMs(testing.io) - t0 < 5_000);
    // The part file goes as the handler unwinds, and the real name was never made.
    for (0..100) |_| {
        if (countParts(up.parts) == 0) break;
        try testing.io.sleep(.fromMilliseconds(10), .awake);
    }
    try testing.expectEqual(@as(usize, 0), countParts(up.parts));
    var gone = false;
    for (0..100) |_| {
        if (Io.Dir.cwd().statFile(testing.io, partial, .{})) |_| {} else |_| {
            gone = true;
            break;
        }
        try testing.io.sleep(.fromMilliseconds(20), .awake);
    }
    try testing.expect(gone);
}

/// Wait up to `ms` for the server to have no connections left.
fn waitNoConnections(rig: Rig, ms: i64) !void {
    const t0 = nowMs(testing.io);
    while (rig.srv.active.load(.acquire) != 0) {
        if (nowMs(testing.io) - t0 > ms) return error.StillConnected;
        try testing.io.sleep(.fromMilliseconds(20), .awake);
    }
}

test "server: a silent browser is dropped even while its terminal keeps the queue busy" {
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .silent_limit_ms = 800 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    // From now on the browser says nothing, while output arrives every 50 ms.
    const t0 = nowMs(testing.io);
    while (rig.srv.active.load(.acquire) != 0 and nowMs(testing.io) - t0 < 6_000) {
        try rig.f.feed(rig.block_id, "more output\r\n");
        try testing.io.sleep(.fromMilliseconds(50), .awake);
    }
    try waitNoConnections(rig, 1_000);
}

test "server: a browser that stops reading is dropped at the write deadline" {
    const rig = try Rig.initExtra(.{}, token_cfg, .{ .tcp_loopback = 0 }, .{ .write_deadline_ms = 500 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    try waitText(c, "\"t\":\"tree\"");
    try sendJson(c, "{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ rig.session_id, rig.block_id });
    try waitText(c, "\"t\":\"opened\"");
    // It keeps talking (so it is not silent) but never reads, while a lot of output arrives.
    var line: [64 * 1024]u8 = undefined;
    // Rewrites of one line (no scrolling, which is slow for the fake's terminal in a debug build).
    for (&line, 0..) |*b, i| b.* = if (i % 64 == 0) '\r' else 'a' + @as(u8, @intCast(i % 26));
    const t0 = nowMs(testing.io);
    var round: u32 = 0;
    while (rig.srv.active.load(.acquire) != 0 and nowMs(testing.io) - t0 < 15_000) : (round += 1) {
        try rig.f.feed(rig.block_id, &line);
        if (round % 10 == 0) sendJson(c, "{{\"t\":\"ping\"}}", .{}) catch {};
        try testing.io.sleep(.fromMilliseconds(5), .awake);
    }
    try waitNoConnections(rig, 2_000);
}

test "server: one hot second is enough to be cut off" {
    // Before, a page could send far past the limit every other second and stay connected.
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const c = try browser(rig);
    defer c.deinit(testing.allocator);
    for (0..max_messages_per_second + 20) |_| c.writeFrame(.text, "{\"t\":\"ping\"}") catch break;
    var ended = false;
    var frames: u32 = 0;
    while (frames < 100_000) : (frames += 1) {
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
}

test "server: a busy bridge does not use up a transfer token" {
    var db: [64]u8 = undefined;
    const up = try uploadDir(&db);
    defer Io.Dir.cwd().deleteTree(testing.io, up.path) catch {};
    defer up.dir.close(testing.io);
    defer up.parts.close(testing.io);
    const a = testing.allocator;
    const o = try openRig(.{ .transfer = .{ .enabled = true, .upload_dir = up.path, .upload_dir_handle = up.dir, .upload_parts_handle = up.parts, .max_bytes = 1 << 20 } });
    defer o.rig.deinit();
    defer o.c.deinit(a);
    try sendJson(o.c, "{{\"t\":\"ul\",\"name\":\"later.txt\",\"size\":2,\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ o.rig.session_id, o.rig.block_id });
    const msg = try textWith(o.c, "\"kind\":\"upload\"");
    defer a.free(msg);
    const url = try a.print("/xfer/{s}", .{try tokenIn(msg)});
    defer a.free(url);
    // Every slot taken: refused, and the token is still good afterwards.
    for (0..xfer.max_running) |_| try testing.expect(o.rig.hub.xfers.acquire());
    const busy = try put(o.rig, url, "Origin: http://localhost\r\n", "hi");
    defer freeHttp(busy);
    try testing.expectEqual(@as(u16, 429), busy.status);
    for (0..xfer.max_running) |_| o.rig.hub.xfers.release();
    const ok = try put(o.rig, url, "Origin: http://localhost\r\n", "hi");
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
}

test "server: token mode serves the token form at / without a token, and only there" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const form = try get(rig, "/", "");
    defer freeHttp(form);
    try testing.expectEqual(@as(u16, 200), form.status);
    try testing.expectEqualStrings(assets.find("/login.html").?.body, form.body);
    try testing.expect(headerValue(form.head, "set-cookie") == null);
    try testing.expect(std.mem.indexOf(u8, headerValue(form.head, "content-security-policy").?, "form-action 'none'") != null);
    // Nothing from the bridge is in it: not the prefix, not a session.
    var pb: [35]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, form.body, tokenPrefix(&pb, rig.token())) == null);
    try testing.expect(std.mem.indexOf(u8, form.body, rig.session_id) == null);
    // The token field is masked and invites no saving: no autocomplete, no username field beside it.
    try testing.expect(std.mem.indexOf(u8, form.body, "type=\"password\" autocomplete=\"off\" autocapitalize=\"off\" autocorrect=\"off\" spellcheck=\"false\"") != null);
    try testing.expect(std.mem.indexOf(u8, form.body, "current-password") == null);
    try testing.expect(std.mem.indexOf(u8, form.body, "username") == null);
    try testing.expectEqual(@as(usize, 1), std.mem.count(u8, form.body, "<input"));
    // Its script and style, at the top level only.
    for ([_][]const u8{ "/login.js", "/login.css" }) |p| {
        const r = try get(rig, p, "");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 200), r.status);
    }
    // Not anywhere else: the page, its other files, the prefix, the socket, `/login.html` itself.
    var ub: [96]u8 = undefined;
    for ([_][]const u8{ "/login.html", "/app.js", "/api/tree", "/ws", "/x" }) |p| {
        const r = try get(rig, p, "");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    for ([_][]const u8{ "/", "/login.js" }) |p| {
        const r = try get(rig, try std.fmt.bufPrint(&ub, "{s}{s}", .{ tokenPrefix(&pb, rig.token()), p }), "");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    // A wrong token in the header or the address is refused, not shown the form.
    for ([_][]const u8{ "rweb-token: wrong-token-0123456789abcdef0123456789\r\n", "" }) |h| {
        const r = try get(rig, if (h.len == 0) "/?token=wrong" else "/", h);
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
        try testing.expectEqualStrings("forbidden\n", r.body);
    }
    // A POST (the form submitting itself, were the CSP not there) gets nothing.
    const post = try httpRequest(try rig.tcp(), "POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
    defer freeHttp(post);
    try testing.expect(post.status == 403);
}

test "server: the form's header login gets the cookie and the redirect, with the token in no address" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    var hb: [96]u8 = undefined;
    const r = try get(rig, "/", try std.fmt.bufPrint(&hb, "rweb-token: {s}\r\n", .{rig.token()}));
    defer freeHttp(r);
    try testing.expectEqual(@as(u16, 303), r.status);
    var pb: [35]u8 = undefined;
    const pfx = tokenPrefix(&pb, rig.token());
    var lb: [64]u8 = undefined;
    try testing.expectEqualStrings(try std.fmt.bufPrint(&lb, "{s}/", .{pfx}), headerValue(r.head, "location").?);
    var cb: [160]u8 = undefined;
    try testing.expect(std.mem.indexOf(u8, r.head, try std.fmt.bufPrint(&cb, "rweb-token={s}; Path={s}/; HttpOnly; SameSite=Strict", .{ rig.token(), pfx })) != null);
    // The redirected request (fetch keeps the header) loads the page.
    var ub: [64]u8 = undefined;
    const page = try get(rig, try std.fmt.bufPrint(&ub, "{s}/", .{pfx}), try std.fmt.bufPrint(&hb, "rweb-token: {s}\r\n", .{rig.token()}));
    defer freeHttp(page);
    try testing.expectEqual(@as(u16, 200), page.status);
    try testing.expectEqualStrings(assets.find("/").?.body, page.body);
}

test "server: wrong tokens are limited, and a right one is not counted" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    rig.srv.opts.max_token_failures = 3;
    var hb: [96]u8 = undefined;
    const good = try std.fmt.bufPrint(&hb, "rweb-token: {s}\r\n", .{rig.token()});
    // Right tokens take nothing.
    for (0..5) |_| {
        const r = try get(rig, "/app.js", good);
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 200), r.status);
    }
    try testing.expectEqual(@as(u32, 0), rig.srv.limiter.used);
    // Three wrong ones (header, address, header) use the budget; a wrong cookie does not.
    for ([_][]const u8{ "rweb-token: nope\r\n", "", "Cookie: rweb-token=nope\r\n", "rweb-token: nope\r\n" }) |h| {
        const r = try get(rig, if (h.len == 0) "/app.js?token=nope" else "/app.js", h);
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    try testing.expectEqual(@as(u32, 3), rig.srv.limiter.used);
    // Then a wrong one gets 429, and the right one still gets in.
    for ([_]struct { []const u8, u16 }{ .{ "rweb-token: nope2\r\n", 429 }, .{ good, 200 } }) |c| {
        const r = try get(rig, "/app.js", c[0]);
        defer freeHttp(r);
        try testing.expectEqual(c[1], r.status);
    }
    // A request without any token still gets the form.
    const form = try get(rig, "/", "");
    defer freeHttp(form);
    try testing.expectEqual(@as(u16, 200), form.status);
    // A new window: the budget is back.
    rig.srv.limiter.mu.lockUncancelable(testing.io);
    rig.srv.limiter.window_start -= rig.srv.opts.token_window_ms;
    rig.srv.limiter.mu.unlock(testing.io);
    const again = try get(rig, "/app.js", "rweb-token: nope3\r\n");
    defer freeHttp(again);
    try testing.expectEqual(@as(u16, 403), again.status);
}

test "server: guesses from another site, or with another Host, never lock the owner out" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    var pb: [35]u8 = undefined;
    const pfx = tokenPrefix(&pb, rig.token());
    var cb: [128]u8 = undefined;
    const right_cookie = try std.fmt.bufPrint(&cb, "Cookie: rweb-token={s}\r\n", .{rig.token()});
    var ub: [64]u8 = undefined;
    const page = try std.fmt.bufPrint(&ub, "{s}/app.js", .{pfx});
    // 100 wrong guesses in the address from a page elsewhere, as an <img> or a link would send them:
    // refused uncounted.
    for (0..100) |i| {
        const h: []const u8 = if (i % 2 == 0) "Sec-Fetch-Site: cross-site\r\n" else "Origin: http://localhost:9\r\n";
        const r = try get(rig, "/app.js?token=nope", h);
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    try testing.expectEqual(@as(u32, 0), rig.srv.limiter.used);
    try testing.expectEqual(@backingInt(access.Refusal.cross_site_token), rig.srv.last_refusal.load(.acquire));
    // The right token from another site is refused too, without being compared.
    var qb: [96]u8 = undefined;
    const cross_right = try get(rig, try std.fmt.bufPrint(&qb, "/app.js?token={s}", .{rig.token()}), "Sec-Fetch-Site: same-site\r\n");
    defer freeHttp(cross_right);
    try testing.expectEqual(@as(u16, 403), cross_right.status);
    // The right cookie still gets in.
    const ok = try get(rig, page, right_cookie);
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
    // A request refused for another reason (here a PUT without an Origin) never counts.
    for (0..20) |_| {
        const r = try httpRequest(try rig.tcp(), "PUT /app.js?token=nope HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    try testing.expectEqual(@as(u32, 0), rig.srv.limiter.used);
}

test "server: 100 wrong header tokens get 429 after 10, and the right cookie and header still pass" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    try testing.expectEqual(@as(u32, 10), rig.srv.opts.max_token_failures);
    var refused: u32 = 0;
    var limited: u32 = 0;
    for (0..100) |_| {
        const r = try get(rig, "/app.js", "Origin: http://localhost\r\nSec-Fetch-Site: same-origin\r\nrweb-token: wrong-0123456789abcdef0123456789abcdef\r\n");
        defer freeHttp(r);
        switch (r.status) {
            403 => refused += 1,
            429 => limited += 1,
            else => return error.UnexpectedStatus,
        }
    }
    try testing.expectEqual(@as(u32, 10), refused);
    try testing.expectEqual(@as(u32, 90), limited);
    var pb: [35]u8 = undefined;
    var ub: [64]u8 = undefined;
    const page = try std.fmt.bufPrint(&ub, "{s}/app.js", .{tokenPrefix(&pb, rig.token())});
    var cb: [128]u8 = undefined;
    const by_cookie = try get(rig, page, try std.fmt.bufPrint(&cb, "Cookie: rweb-token={s}\r\n", .{rig.token()}));
    defer freeHttp(by_cookie);
    try testing.expectEqual(@as(u16, 200), by_cookie.status);
    var hb: [96]u8 = undefined;
    const by_header = try get(rig, "/app.js", try std.fmt.bufPrint(&hb, "Origin: http://localhost\r\nrweb-token: {s}\r\n", .{rig.token()}));
    defer freeHttp(by_header);
    try testing.expectEqual(@as(u16, 200), by_header.status);
    // The form's own header login still works, and so does the address the startup line prints.
    const login = try get(rig, "/", try std.fmt.bufPrint(&hb, "rweb-token: {s}\r\n", .{rig.token()}));
    defer freeHttp(login);
    try testing.expectEqual(@as(u16, 303), login.status);
    var qb: [96]u8 = undefined;
    const typed = try get(rig, try std.fmt.bufPrint(&qb, "/?token={s}", .{rig.token()}), "Sec-Fetch-Site: none\r\n");
    defer freeHttp(typed);
    try testing.expectEqual(@as(u16, 303), typed.status);
}

test "server: a planted wrong cookie on the form and its files takes nothing from the budget" {
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    for (0..30) |_| for ([_][]const u8{ "/", "/login.js", "/login.css" }) |p| {
        const r = try get(rig, p, "Cookie: rweb-token=planted-by-another-port\r\n");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 200), r.status);
    };
    // Elsewhere it is refused, still uncounted.
    const other = try get(rig, "/app.js", "Cookie: rweb-token=planted-by-another-port\r\n");
    defer freeHttp(other);
    try testing.expectEqual(@as(u16, 403), other.status);
    try testing.expectEqual(@as(u32, 0), rig.srv.limiter.used);
}

test "server: token mode with the default hosts serves 127.0.0.1 and localhost on its port, never another Host" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    // TCP (the printed http://127.0.0.1:PORT/ address): the listener's own port only.
    {
        const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
        defer rig.deinit();
        rig.srv.opts.access.allowed_hosts = try layout.tokenHosts(arena, rig.srv.port);
        var rb: [256]u8 = undefined;
        var hb: [64]u8 = undefined;
        for ([_][]const u8{ "127.0.0.1", "localhost" }) |name| {
            const host = try std.fmt.bufPrint(&hb, "{s}:{d}", .{ name, rig.srv.port });
            const form = try httpRequest(try rig.tcp(), try std.fmt.bufPrint(&rb, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host}));
            defer freeHttp(form);
            try testing.expectEqual(@as(u16, 200), form.status);
            var qb: [96]u8 = undefined;
            const typed = try httpRequest(try rig.tcp(), try std.fmt.bufPrint(&rb, "GET {s} HTTP/1.1\r\nHost: {s}\r\nSec-Fetch-Site: none\r\nConnection: close\r\n\r\n", .{ try std.fmt.bufPrint(&qb, "/?token={s}", .{rig.token()}), host }));
            defer freeHttp(typed);
            try testing.expectEqual(@as(u16, 303), typed.status);
        }
        for ([_][]const u8{ "evil.example", "evil.example:80", "127.0.0.1:1", "localhost" }) |host| {
            const r = try httpRequest(try rig.tcp(), try std.fmt.bufPrint(&rb, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{host}));
            defer freeHttp(r);
            try testing.expectEqual(@as(u16, 403), r.status);
            try testing.expectEqual(@backingInt(access.Refusal.bad_host), rig.srv.last_refusal.load(.acquire));
        }
    }
    // A unix socket behind `ssh -L 127.0.0.1:7700:<socket>`: the loopback names on any port.
    {
        var pb: [96]u8 = undefined;
        const path = try tmpSocketPath(&pb, testing.io);
        defer Io.Dir.cwd().deleteTree(testing.io, std.fs.path.dirname(path).?) catch {};
        const uids = [_]u32{@intCast(std.c.getuid())};
        var cfg = token_cfg;
        cfg.allowed_peer_uids = &uids;
        cfg.allowed_hosts = try layout.tokenHosts(arena, null);
        const rig = try Rig.init(.{}, cfg, .{ .unix = path });
        defer rig.deinit();
        const addr = try Io.net.UnixAddress.init(path);
        var rb: [256]u8 = undefined;
        for ([_]struct { []const u8, u16 }{ .{ "127.0.0.1:7700", 200 }, .{ "localhost:7700", 200 }, .{ "[::1]:7700", 200 }, .{ "evil.example:7700", 403 } }) |c| {
            const r = try httpRequest(try addr.connect(testing.io), try std.fmt.bufPrint(&rb, "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n", .{c[0]}));
            defer freeHttp(r);
            try testing.expectEqual(c[1], r.status);
        }
    }
}

test "server: owner and secret deployments never serve the token form" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const none = try get(rig, "/", "");
    defer freeHttp(none);
    try testing.expectEqual(@as(u16, 403), none.status);
    for ([_][]const u8{ "/login.js", "/login.html" }) |p| {
        const r = try get(rig, p, "");
        defer freeHttp(r);
        try testing.expectEqual(@as(u16, 403), r.status);
    }
    // The owner gets the page itself at `/`.
    const ok = try get(rig, "/", owner_hdrs);
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
    try testing.expectEqualStrings(assets.find("/").?.body, ok.body);
    const rig2 = try Rig.initExtra(.{}, owner_cfg, .{ .tcp_loopback = 0 }, .{ .backend_secret = "0123456789abcdef0123456789abcdef" });
    defer rig2.deinit();
    const s2 = try get(rig2, "/0123456789abcdef0123456789abcdef/", "");
    defer freeHttp(s2);
    try testing.expectEqual(@as(u16, 403), s2.status);
}

test "server: the TCP port is held on 127.0.0.1 and ::1, without SO_REUSEPORT, and served on both" {
    const io = testing.io;
    var b = try bind(testing.allocator, io, .{ .tcp_loopback = 0 }, null);
    var owned = true;
    defer if (owned) b.deinit(io);
    try testing.expect(b.port != 0 and b.listen.tcp_loopback == b.port);
    var a4 = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(b.port) };
    try testing.expectError(error.AddressInUse, a4.listen(io, .{}));
    // A socket that sets SO_REUSEPORT too (as std's `reuse_address` does) cannot share it.
    try testing.expectError(error.AddressInUse, a4.listen(io, .{ .reuse_address = true }));
    const have6 = b.listener6 != null;
    if (have6) {
        var a6 = Io.net.IpAddress{ .ip6 = Io.net.Ip6Address.loopback(b.port) };
        try testing.expectError(error.AddressInUse, a6.listen(io, .{}));
        try testing.expectError(error.AddressInUse, a6.listen(io, .{ .reuse_address = true }));
    } else try testing.expect(b.v6_missing != null);
    b.deinit(io);
    owned = false;

    // A port whose ::1 another socket holds is refused, not served half.
    if (have6) {
        var other6 = Io.net.IpAddress{ .ip6 = Io.net.Ip6Address.loopback(0) };
        var taken = try other6.listen(io, .{});
        defer taken.deinit(io);
        try testing.expectError(error.Ip6AddressInUse, bind(testing.allocator, io, .{ .tcp_loopback = taken.socket.address.getPort() }, null));
    }

    // Served on both, with the same checks.
    const rig = try Rig.init(.{}, token_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    if (rig.srv.listener6 == null) return;
    var a6 = Io.net.IpAddress{ .ip6 = Io.net.Ip6Address.loopback(rig.srv.port) };
    var hb: [96]u8 = undefined;
    var rb: [256]u8 = undefined;
    const ok = try httpRequest(try a6.connect(io, .{ .mode = .stream }), try std.fmt.bufPrint(&rb, "GET /app.js HTTP/1.1\r\nHost: [::1]\r\n{s}Connection: close\r\n\r\n", .{try std.fmt.bufPrint(&hb, "rweb-token: {s}\r\n", .{rig.token()})}));
    defer freeHttp(ok);
    try testing.expectEqual(@as(u16, 200), ok.status);
    const no = try httpRequest(try a6.connect(io, .{ .mode = .stream }), "GET /app.js HTTP/1.1\r\nHost: [::1]\r\nConnection: close\r\n\r\n");
    defer freeHttp(no);
    try testing.expectEqual(@as(u16, 403), no.status);
}

test "server: a refresh only ever adds own addresses, and keeps them when it fails" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const from_old = "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.5\r\n";
    const from_new = "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.77\r\n";
    try expectRefusedWith(rig, from_old, .own_address);
    const fine = try get(rig, "/", from_new);
    freeHttp(fine);
    try testing.expectEqual(@as(u16, 200), fine.status);
    // Failures and nonsense keep the list.
    try testing.expectEqual(Server.Refresh.failed, rig.srv.refreshOwnAddresses(error.TailscaleFailed));
    try testing.expectEqual(Server.Refresh.invalid, rig.srv.refreshOwnAddresses(&.{}));
    try testing.expectEqual(Server.Refresh.invalid, rig.srv.refreshOwnAddresses(&.{ "100.64.0.77", "not-an-ip" }));
    try testing.expectEqual(Server.Refresh.unchanged, rig.srv.refreshOwnAddresses(&.{"::ffff:100.64.0.5"}));
    try expectRefusedWith(rig, from_old, .own_address);
    // A new address is added; the old one is still refused, though Tailscale no longer lists it.
    try testing.expectEqual(Server.Refresh.added, rig.srv.refreshOwnAddresses(&.{ "100.64.0.77", "fd7a:115c:a1e0::77" }));
    try expectRefusedWith(rig, from_new, .own_address);
    try expectRefusedWith(rig, from_old, .own_address);
    try testing.expectEqual(Server.Refresh.unchanged, rig.srv.refreshOwnAddresses(&.{"100.64.0.5"}));
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const now = try rig.srv.ownAddresses(arena_state.allocator());
    try testing.expect(access.sameAddressList(now, &.{ "100.64.0.5", "100.64.0.77", "fd7a:115c:a1e0::77" }));
}

test "server: own addresses Tailscale has not confirmed for too long refuse requests until it answers" {
    const rig = try Rig.init(.{}, owner_cfg, .{ .tcp_loopback = 0 });
    defer rig.deinit();
    const elsewhere = "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.9\r\n";
    // A list the owner gave never goes out of date.
    try testing.expect(!rig.srv.ownAddressesStale());
    // Read from Tailscale: fine while it was confirmed within the limit (at start, here).
    rig.srv.opts.own_address_max_age_ms = 60_000;
    const fine = try get(rig, "/", elsewhere);
    freeHttp(fine);
    try testing.expectEqual(@as(u16, 200), fine.status);
    // Too long ago (as when the refresh hangs, Tailscale stops answering, or the machine slept): refused, from anywhere.
    rig.srv.own_checked_ms.store(bootNowMs(testing.io) - 60_001, .release);
    try expectRefusedWith(rig, elsewhere, .own_addresses_stale);
    // A failed or unusable answer confirms nothing.
    try testing.expectEqual(Server.Refresh.failed, rig.srv.refreshOwnAddresses(error.TailscaleFailed));
    try testing.expectEqual(Server.Refresh.invalid, rig.srv.refreshOwnAddresses(&.{}));
    try expectRefusedWith(rig, elsewhere, .own_addresses_stale);
    // Tailscale answers: judged as usual again, the new address included.
    try testing.expectEqual(Server.Refresh.added, rig.srv.refreshOwnAddresses(&.{ "100.64.0.5", "100.64.0.77" }));
    const again = try get(rig, "/", elsewhere);
    freeHttp(again);
    try testing.expectEqual(@as(u16, 200), again.status);
    try expectRefusedWith(rig, "Tailscale-User-Login: owner@example.com\r\nX-Forwarded-For: 100.64.0.77\r\n", .own_address);
}

fn startAndStop(a: Allocator, hub: *Hub) !void {
    const srv = try Server.start(a, testing.io, hub, .{ .listen = .{ .tcp_loopback = 0 }, .access = .{ .token = "an-allocation-failure-test-token-0123456789" } });
    srv.stop();
}

test "server: start fails cleanly at every allocation" {
    const f = try fake.Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const ctl = try rex.control.Control.open(testing.allocator, testing.io, .{ .socket_path = f.path });
    defer ctl.close();
    const h = try Hub.open(testing.allocator, testing.io, ctl, .{});
    defer h.close();
    try testing.checkAllAllocationFailures(testing.allocator, startAndStop, .{h});
}
