//! The rweb bridge: shows Rex terminal sessions in a web browser.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const rex = @import("rex");

pub const access = @import("access.zig");
pub const protocol = @import("protocol.zig");
pub const hub = @import("hub.zig");
pub const assets = @import("assets.zig");
pub const xfer = @import("xfer.zig");
pub const server = @import("server.zig");
pub const cli = @import("cli.zig");
pub const layout = @import("layout.zig");
pub const proc = @import("proc.zig");
const build_options = @import("build_options");

comptime {
    // std's start code gives main its `SafeAllocator` in Debug and ReleaseSafe only; ReleaseFast and
    // ReleaseSmall would get the C allocator. The decision above is for the safe one.
    if (builtin.mode != .debug and builtin.mode != .safe) @compileError("rweb is built in Debug or ReleaseSafe: its allocator decision (main) assumes std's SafeAllocator");
}

/// What `rweb --version` prints: the version, the commit, how it was built, and what it works with.
pub fn versionText() []const u8 {
    return std.fmt.comptimePrint(
        "rweb {s}\ncommit {s}\nbuild {t} {t}-{t}\nghostty {s}\nrex api revisions {d}-{d}\n",
        .{ build_options.version, @import("git_commit").commit, builtin.mode, builtin.cpu.arch, builtin.os.tag, build_options.ghostty, rex.control.api_min_supported, rex.control.api_max_supported },
    );
}

test "the owner comes from the node's user, and a tagged node has none" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const user_node =
        \\{"Self":{"UserID":42,"DNSName":"box.example.ts.net."},"User":{"42":{"LoginName":"you@example.com"}}}
    ;
    try std.testing.expectEqualStrings("you@example.com", try ownerFromStatus(a, user_node));
    const tagged =
        \\{"Self":{"UserID":7,"Tags":["tag:gateway"]},"User":{"7":{"LoginName":"box.example.ts.net"}}}
    ;
    try std.testing.expectError(error.TaggedNode, ownerFromStatus(a, tagged));
    const empty_tags =
        \\{"Self":{"UserID":42,"Tags":[]},"User":{"42":{"LoginName":"you@example.com"}}}
    ;
    try std.testing.expectEqualStrings("you@example.com", try ownerFromStatus(a, empty_tags));
    try std.testing.expectError(error.NoSelf, ownerFromStatus(a, "{}"));
    try std.testing.expectError(error.NoSelf, ownerFromStatus(a, "[]"));
}

test "malformed tailscale status is an error, never a crash" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const bad = [_][]const u8{
        \\{"Self":{"UserID":"7"},"User":{"7":{"LoginName":"x@y"}}}
        ,
        \\{"Self":{"UserID":7},"User":[]}
        ,
        \\{"Self":{"UserID":7},"User":{"7":"x@y"}}
        ,
        \\{"Self":{"UserID":7},"User":{"7":{"LoginName":7}}}
        ,
        \\{"Self":[],"User":{}}
        ,
    };
    for (bad) |j| try std.testing.expectError(error.NoSelf, ownerFromStatus(a, j));
    try std.testing.expectError(error.NoSelf, dnsNameFromStatus(a, "[]"));
    try std.testing.expectError(error.NoSelf, dnsNameFromStatus(a, "{\"Self\":7}"));
    try std.testing.expectError(error.NoSelf, dnsNameFromStatus(a, "{\"Self\":{\"DNSName\":\".\"}}"));
    try std.testing.expectEqualStrings("box.example.ts.net", try dnsNameFromStatus(a, "{\"Self\":{\"DNSName\":\"box.example.ts.net.\"}}"));
}

test "version text names the version, commit and Rex revisions" {
    const t = versionText();
    try std.testing.expect(std.mem.startsWith(u8, t, "rweb " ++ build_options.version ++ "\n"));
    try std.testing.expect(std.mem.indexOf(u8, t, "commit ") != null);
    try std.testing.expect(std.mem.indexOf(u8, t, "rex api revisions 18-24") != null);
}

const log = std.log.scoped(.rweb);

/// The bridge's log. rweb's own scopes (and unscoped messages) log at the build's level. Ghostty's are a
/// library's: only its errors are shown, and none at all from where it parses a program's output (an
/// escape sequence it does not know, a colour it cannot read): those say nothing about rweb, and any
/// program could fill the log with them.
pub const std_options: std.Options = .{ .logFn = logFiltered };

fn logFiltered(comptime level: std.log.Level, comptime scope: @EnumLiteral(), comptime format: []const u8, args: anytype) void {
    if (comptime !logShown(level, scope)) return;
    std.log.defaultLog(level, scope, format, args);
}

fn logShown(comptime level: std.log.Level, comptime scope: @EnumLiteral()) bool {
    const name = @tagName(scope);
    const ours = [_][]const u8{ "default", "rweb", "server", "hub", "fake_rex" };
    for (ours) |o| if (std.mem.eql(u8, name, o)) return true;
    if (std.mem.startsWith(u8, name, "rex_")) return true;
    // Ghostty's scopes that read what a program prints.
    const output_exact = [_][]const u8{ "stream", "stream_terminal", "parser", "sgr", "glyph", "osc", "terminal_dcs", "terminal_apc", "snapshot_kitty" };
    for (output_exact) |o| if (std.mem.eql(u8, name, o)) return false;
    const output_prefix = [_][]const u8{ "osc_", "kitty_", "terminal_tmux", "mouse_", "key_" };
    for (output_prefix) |o| if (std.mem.startsWith(u8, name, o)) return false;
    return level == .err;
}

test "log: rweb's scopes as the build says, Ghostty's errors only, its output parsers not at all" {
    try std.testing.expect(comptime logShown(.info, .rweb));
    try std.testing.expect(comptime logShown(.debug, .rex_mirror));
    try std.testing.expect(comptime logShown(.warn, .default));
    try std.testing.expect(comptime !logShown(.err, .stream));
    try std.testing.expect(comptime !logShown(.warn, .osc_color));
    try std.testing.expect(comptime !logShown(.err, .kitty_gfx));
    try std.testing.expect(comptime logShown(.err, .page_list));
    try std.testing.expect(comptime !logShown(.warn, .page_list));
}

/// Print to standard error (the terminal, or the service's log).
fn say(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt, args);
}

/// A startup refusal of a file or folder: what is wrong and the fix (`layout.explain`), then exit 2
/// (releasing the listener, if it was taken).
fn refuseFile(what: []const u8, path: []const u8, e: anyerror, problem: *const xfer.Problem, hints: xfer.Hints) noreturn {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    layout.explain(&w, what, path, e, problem, hints) catch {};
    say("{s}", .{w.buffered()});
    releaseListener();
    std.process.exit(2);
}

comptime {
    // One minimum for a secret, in the messages and in the checks.
    std.debug.assert(cli.min_token_len == xfer.min_secret_len);
}

/// The listener taken at startup, so that a refusal after it releases it before the process ends.
var held: ?struct { bound: *server.Bound, io: Io } = null;

fn releaseListener() void {
    if (held) |h| h.bound.deinit(h.io);
    held = null;
}

/// What a stop signal removes: the unix socket this process bound, by its folder and name, and only
/// while that name is still that socket (same device and inode). Set once, before the handler.
const StopSocket = struct {
    var dir_fd: std.posix.fd_t = -1;
    var name: [256:0]u8 = @splat(0);
    var dev: u64 = 0;
    var ino: u64 = 0;
};

/// Remove the socket `StopSocket` names, if it is still that socket. Only calls that are safe in a
/// signal handler: a stat and an unlink.
fn removeStopSocket() void {
    if (StopSocket.dir_fd < 0) return;
    const name = std.mem.sliceTo(&StopSocket.name, 0);
    if (xfer.statAt(StopSocket.dir_fd, name)) |n| {
        if (n.dev == StopSocket.dev and n.ino == StopSocket.ino) _ = std.c.unlinkat(StopSocket.dir_fd, &StopSocket.name, 0);
    } else |_| {}
}

/// SIGTERM and SIGINT: remove this process's own unix socket (only if it is still the one it bound)
/// and end at once with `_exit`. The kernel closes the listeners and every connection, Rex's included.
fn onStopSignal(sig: std.posix.SIG) callconv(.c) void {
    removeStopSocket();
    std.c._exit(if (sig == .INT) 130 else 0);
}

/// Remember the unix socket `b` bound, for `removeStopSocket`.
fn noteStopSocket(b: *const server.Bound) void {
    StopSocket.dir_fd = -1;
    const fd = b.sock_dir orelse return;
    const id = b.sock_id orelse return;
    if (b.sock_name.len >= StopSocket.name.len) return;
    @memcpy(StopSocket.name[0..b.sock_name.len], b.sock_name);
    StopSocket.name[b.sock_name.len] = 0;
    StopSocket.dev = id.dev;
    StopSocket.ino = id.ino;
    StopSocket.dir_fd = fd;
}

/// Stop cleanly on SIGTERM (a service manager) and SIGINT (Ctrl-C): see `onStopSignal`.
fn handleStopSignals(b: *const server.Bound) void {
    noteStopSocket(b);
    const act: std.posix.Sigaction = .{ .handler = .{ .handler = onStopSignal }, .mask = std.posix.sigemptyset(), .flags = 0 };
    std.posix.sigaction(.TERM, &act, null);
    std.posix.sigaction(.INT, &act, null);
}

pub fn main(init: std.process.Init) !void {
    // The release allocator is a decision, not a default (docs/zig-idiom-audit-2026-11-26.md, Phase B
    // step 2): std's `SafeAllocator` over the page allocator, which is what `init.gpa` is in the
    // ReleaseSafe build the archives use. It turns a use-after-free or double free into a crash. It
    // was measured against `smp_allocator` and the C allocator (src/bridge/bench.zig): 5 to 12 % more
    // CPU, the same latency and memory; kept for the bridge's safety. The comptime check below makes a
    // build mode that would hand this a different allocator fail to compile instead of changing it.
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    var it = init.minimal.args.iterate();
    _ = it.next();
    while (it.next()) |a| try argv.append(arena, a);
    const env_map = init.environ_map;
    const env: layout.Env = .{
        .home = env_map.get("HOME"),
        .xdg_config_home = env_map.get("XDG_CONFIG_HOME"),
        .xdg_runtime_dir = env_map.get("XDG_RUNTIME_DIR"),
        .uid = @intCast(std.c.getuid()),
    };
    var diag: cli.Diag = .{};
    const parsed = cli.parseEnv(arena, argv.items, env, &diag) catch |e| {
        switch (e) {
            error.Version => std.Io.File.stdout().writeStreamingAll(io, versionText()) catch {},
            error.ShortHelp => std.Io.File.stdout().writeStreamingAll(io, cli.short_usage) catch {},
            error.Usage => std.Io.File.stdout().writeStreamingAll(io, cli.usage) catch {},
            error.SocketPathTooLong => {
                say("rweb: the socket path {f} is {d} bytes, longer than a unix socket path can be here (at most {d}).\n", .{ xfer.Clean{ .s = diag.arg }, diag.arg.len, server.max_unix_path - 1 });
                say("  Fix: {s}\n", .{socketPathFix(argv.items)});
                std.process.exit(2);
            },
            else => {
                if (diag.arg.len > 0) say("rweb: {s}: {s}\n", .{ diag.arg, cli.explainArg(e, diag.arg) }) else say("rweb: {s}\n", .{cli.explain(e)});
                say("rweb: `rweb help` lists every option\n", .{});
                std.process.exit(2);
            },
        }
        std.process.exit(0);
    };
    if (parsed.token != null) say("rweb: WARNING: --token is visible to every user in the process list; use --token-file (or `rweb ssh`, which makes one)\n", .{});

    // ---- configuration: checked before the listener is taken, so a refusal never holds a port ----

    // `tailscale`, when this node's login, name or addresses are needed: by absolute path, checked
    // like a secret file's folders (never found through PATH, which another user may be able to
    // change).
    const ts: []const u8 = if (parsed.detect_own_addresses or parsed.owner_from_tailscale) tailscaleProgram(arena, io, parsed.tailscale) else "";

    // ---- the listener: taken now and kept through outages of Tailscale and Rex. First, so that a
    // listener that cannot be taken is refused before any file or folder is made for it; a refusal
    // after this releases it (`refuseFile`) ----
    const listen: server.Listen = switch (parsed.listen) {
        .unix => |p| .{ .unix = p },
        .tcp => |port| .{ .tcp_loopback = port },
    };
    var listen_problem: xfer.Problem = .{};
    var bound = server.bind(gpa, io, listen, &listen_problem) catch |e| listenFailed(listen, e, &listen_problem, parsed.command, argv.items);
    held = .{ .bound = &bound, .io = io };
    handleStopSignals(&bound);

    // Secrets come from files only their owner can read, never from the command line (which every
    // user on the machine can see). A layout's own files are made when missing.
    var problem: xfer.Problem = .{};
    const secret_hints: xfer.Hints = .{ .item_option = "--backend-secret-file", .folder_option = if (parsed.make_backend_secret) "--config-dir" else null, .made_by_rweb = parsed.make_backend_secret };
    const token_hints: xfer.Hints = .{ .item_option = "--token-file", .folder_option = if (parsed.make_token_file) "--config-dir" else null, .made_by_rweb = parsed.make_token_file };
    if (parsed.make_backend_secret) if (parsed.backend_secret_file) |path| {
        if (layout.ensureSecretFile(arena, io, path, &problem)) |made| {
            if (made) say("rweb: made a new backend secret in {s}\n", .{path});
        } else |e| refuseFile("its backend secret", path, e, &problem, secret_hints);
    };
    if (parsed.make_token_file) if (parsed.token_file) |path| {
        if (layout.ensureSecretFile(arena, io, path, &problem)) |made| {
            if (made) say("rweb: made a new token in {s}\n", .{path});
        } else |e| refuseFile("its token", path, e, &problem, token_hints);
    };
    const backend_secret: ?[]const u8 = if (parsed.backend_secret_file) |path| readSecretFile(arena, io, path, xfer.min_secret_len, true, &problem) catch |e| refuseFile("the backend secret file", path, e, &problem, secret_hints) else null;
    var token = parsed.token;
    if (parsed.token_file) |path| token = readSecretFile(arena, io, path, cli.min_token_len, true, &problem) catch |e| refuseFile("the token file", path, e, &problem, token_hints);
    if (parsed.random_token) {
        const t = try arena.create([layout.secret_len]u8);
        layout.newSecret(io, t) catch {
            say("rweb: the system gave no random bytes for a token; pass --token-file PATH\n", .{});
            releaseListener();
            std.process.exit(2);
        };
        token = t;
    }

    var uids: std.ArrayList(u32) = .empty;
    if (parsed.peer_uids) |list| for (list) |u| try uids.append(arena, switch (u) {
        .uid => |n| n,
        .self => @intCast(std.c.getuid()),
    });

    // File transfer: off unless asked for; uploads only into a folder that is ours alone.
    var transfer: xfer.Config = .{};
    if (parsed.enable_file_transfer) {
        transfer.enabled = true;
        transfer.max_bytes = @as(u64, parsed.max_transfer_mb) * 1024 * 1024;
        if (parsed.upload_dir) |dir| {
            // Opened once and kept open for the life of the process: uploads go into this folder,
            // whatever is later put at its path.
            var up_problem: xfer.Problem = .{};
            const up = xfer.openUploadDir(arena, io, dir, &up_problem) catch |e| refuseFile("the upload folder", dir, e, &up_problem, .{ .item_option = "--upload-dir" });
            transfer.upload_dir_handle = up.dir;
            transfer.upload_parts_handle = up.parts;
            // Only what no running rweb holds: another rweb may be using the same folder.
            const swept = xfer.sweepUploadParts(io, up.parts);
            if (swept > 0) say("rweb: removed {d} unfinished upload(s) an earlier rweb left behind\n", .{swept});
            transfer.upload_dir = dir;
            // What is pasted and shown: the folder's real path, as it was when it was opened.
            transfer.upload_dir_real = up.real_path;
        }
        say("rweb: file transfer ON: the page can download any file the terminal's user can read; uploads {s}{s}; limit {d} MB\n", .{
            if (transfer.upload_dir != null) "go to " else "are off",
            transfer.upload_dir_real orelse "",
            parsed.max_transfer_mb,
        });
    }
    defer if (transfer.upload_dir_handle) |d| d.close(io);
    defer if (transfer.upload_parts_handle) |d| d.close(io);
    var hub_cfg: hub.Config = .{ .observe_only = parsed.observe_only, .history_lines = parsed.history_lines, .transfer = transfer };
    // The page may send its debug messages only when the bridge logs them (`--debug-input`).
    hub_cfg.debug_input = parsed.debug_input;
    // The page's mode frame says token mode (a dropped connection then waits for a tap).
    hub_cfg.token_mode = token != null;

    const where = describeListener(arena, bound) catch "";
    say("rweb: listening on {s}{s}\n", .{ where, if (parsed.observe_only) ", observe-only" else "" });
    if (bound.listen == .tcp_loopback) {
        if (bound.v6_missing != null) say("rweb: this system has no IPv6 loopback, so [::1]:{d} is not held (only 127.0.0.1)\n", .{bound.port});
        if (backend_secret != null) say("rweb: requests must carry the secret first path segment (Tailscale Serve is pointed at http://127.0.0.1:{d}/<secret>)\n", .{bound.port});
        if (backend_secret == null and (parsed.owner != null or parsed.owner_from_tailscale)) say("rweb: WARNING: the owner's identity headers can be forged by any local process on this machine (no --backend-secret-file)\n", .{});
        if (token != null) say("rweb: WARNING: a token on a TCP port: on a machine with other accounts, another user can take this port while rweb is down and receive the token. For an SSH tunnel use `rweb ssh` (a unix socket in a 0700 folder, --allow-peer-uid self, and ssh -L 127.0.0.1:PORT:<socket>)\n", .{});
        // The token opens the bridge: it goes to a person at a terminal, never into a log.
        if (parsed.random_token) {
            const tty = std.Io.File.stderr().isTty(io) catch false;
            if (tty) {
                say("rweb: open http://127.0.0.1:{d}/?token={s}\n", .{ bound.port, token.? });
            } else {
                say("rweb: made a random token; it is not shown because standard error is not a terminal (it may be a log). Use `rweb ssh`, which keeps its token in a file\n", .{});
            }
        }
    }
    if (parsed.command == .ssh) if (bound.listen == .unix) {
        var buf: [4096]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        var hb: [std.posix.HOST_NAME_MAX]u8 = undefined;
        const host = std.posix.gethostname(&hb) catch "";
        // The account this process runs as, from the user database (never $USER, which the caller sets).
        var ub: [256]u8 = undefined;
        const user = accountName(&ub) orelse "";
        layout.sshNextStep(&w, bound.listen.unix, parsed.ssh_port, user, host, parsed.token_file) catch {};
        say("{s}", .{w.buffered()});
    };

    // ---- Tailscale: this node's addresses, login and name, asked until it answers ----
    var own: std.ArrayList([]const u8) = .empty;
    try own.appendSlice(arena, parsed.own_addresses);
    var owner = parsed.owner;
    var hosts: std.ArrayList([]const u8) = .empty;
    try hosts.appendSlice(arena, parsed.allowed_hosts);
    // Token mode with no host named: the loopback names the printed address and an SSH tunnel use,
    // so a page reached through a rebound DNS name gets nothing, the token form included.
    if (token != null and owner == null and !parsed.owner_from_tailscale and hosts.items.len == 0)
        try hosts.appendSlice(arena, try layout.tokenHosts(arena, if (bound.listen == .tcp_loopback) bound.port else null));
    var dns_name: ?[]const u8 = null;
    // When Tailscale last told us this node's addresses: the list's age is counted from here.
    var own_read_ms: ?i64 = null;
    if (parsed.detect_own_addresses or parsed.owner_from_tailscale) {
        var backoff: Backoff = .{};
        const facts = discoverTailscale(gpa, arena, io, ts, parsed.detect_own_addresses, parsed.owner_from_tailscale, &backoff) catch |e| {
            releaseListener();
            switch (e) {
                error.TaggedNode => say("rweb: this node is a tagged Tailscale device, so it has no owner login.\n  Fix: pass --owner LOGIN (your Tailscale login) and --allow-host <this node's DNS name> instead of letting rweb take them from Tailscale\n", .{}),
                else => say("rweb: stopped while waiting for Tailscale\n", .{}),
            }
            std.process.exit(2);
        };
        try own.appendSlice(arena, facts.addresses);
        own_read_ms = bootNowMs(io);
        if (facts.owner) |o| owner = o;
        if (facts.dns_name) |n| {
            try hosts.append(arena, n);
            dns_name = n;
        }
    }
    // Every own address must be one the rule can compare, and an owner rule needs at least one
    // unless the machine accepts its own address: fail closed rather than run without the rule.
    for (own.items) |addr| if (!access.isAddress(addr)) {
        releaseListener();
        say("rweb: Tailscale named \"{f}\" as one of this node's addresses, which is not an IP address, so rweb cannot refuse requests from this node.\n  Fix: pass this node's addresses with --own-address IP\n", .{xfer.Clean{ .s = addr }});
        std.process.exit(2);
    };
    if ((owner != null) and !parsed.allow_own_address and own.items.len == 0) {
        releaseListener();
        say("rweb: rweb knows none of this node's Tailscale addresses, so it cannot refuse requests that come from this machine itself.\n  Fix: pass them with --own-address IP (from `tailscale ip`)\n", .{});
        std.process.exit(2);
    }
    // `cli.parse` already refuses an owner without a host; this is the second line.
    if (owner != null and hosts.items.len == 0) {
        releaseListener();
        say("rweb: an owner rule needs the host names requests may be for.\n  Fix: pass --allow-host NAME (this node's DNS name)\n", .{});
        std.process.exit(2);
    }
    if (parsed.command == .tailscale) {
        var buf: [4096]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        const on: layout.Served = switch (bound.listen) {
            .unix => |p| .{ .unix = p },
            .tcp_loopback => |p| .{ .tcp = p },
        };
        layout.tailscaleNextStep(&w, on, parsed.backend_secret_file, dns_name orelse if (hosts.items.len > 0) hosts.items[0] else null) catch {};
        say("{s}", .{w.buffered()});
    }

    // ---- Rex: asked until it answers ----
    var finder = RexFinder.init(arena, io, env_map, parsed.rex_socket) catch |e| {
        releaseListener();
        return e;
    };
    var rex_backoff: Backoff = .{};
    const link = connectRex(gpa, io, &finder, hub_cfg, &rex_backoff) catch |e| {
        releaseListener();
        say("rweb: stopped while waiting for Rex\n", .{});
        if (e == error.Canceled) std.process.exit(1);
        return e;
    };
    defer link.ctl.close();
    defer link.hub.close();

    const srv = server.Server.startBound(gpa, io, link.hub, .{
        .listen = bound.listen,
        .problem = &listen_problem,
        .debug_input = parsed.debug_input,
        .backend_secret = backend_secret,
        .lab = parsed.lab,
        .own_address_max_age_ms = if (parsed.detect_own_addresses and !parsed.allow_own_address) own_address_max_age_ms else null,
        .own_addresses_read_ms = own_read_ms,
        .access = .{
            .owner = owner,
            .token = token,
            .own_addresses = own.items,
            .allow_own_address = parsed.allow_own_address,
            .allowed_peer_uids = if (parsed.peer_uids != null) uids.items else null,
            .allowed_hosts = hosts.items,
        },
    }, bound) catch |e| {
        releaseListener();
        say("rweb: cannot start serving: the system is out of resources\n", .{});
        if (e == error.OutOfMemory) return e;
        std.process.exit(1);
    };
    held = null; // the server owns the listener now
    defer srv.stop();
    say("rweb: serving (Rex at {s})\n", .{link.socket});

    // Serve until the process is stopped; meanwhile keep this node's own addresses current, so a
    // request from a new address of this machine is refused too. The first check is made at once (the
    // wait for Rex may have been long), then one a minute, sooner after a failure. The server itself
    // refuses requests once the list has gone unconfirmed for `own_address_max_age_ms`, whatever this
    // loop is doing.
    if (!parsed.detect_own_addresses) {
        while (true) io.sleep(.fromSeconds(3600), .awake) catch return;
    }
    var refresh_failed = false;
    while (true) {
        {
            var attempt = std.heap.ArenaAllocator.init(gpa);
            defer attempt.deinit();
            switch (srv.refreshOwnAddresses(tailscaleAddresses(attempt.allocator(), io, ts))) {
                .added => {
                    say("rweb: this node has a new Tailscale address; requests from it are refused from now on, as from the earlier ones\n", .{});
                    refresh_failed = false;
                },
                .unchanged => refresh_failed = false,
                .failed, .invalid => {
                    if (!refresh_failed) say("rweb: cannot read this node's Tailscale addresses now (Tailscale is down or signed out); keeping the last ones and asking again every {d} seconds. If it stays so for {d} seconds, requests are refused until Tailscale answers\n", .{ own_address_retry_s, own_address_max_age_ms / 1000 });
                    refresh_failed = true;
                },
            }
        }
        const wait_ms: i64 = @as(i64, if (refresh_failed) own_address_retry_s else own_address_refresh_s) * 1000;
        waitUntilBoot(io, bootNowMs(io) + wait_ms) catch return;
    }
}

/// This node's addresses are read from Tailscale this often, and this often after a failed read.
const own_address_refresh_s = 60;
const own_address_retry_s = 15;
/// A list not confirmed for this long (boot clock, sleep included) is not trusted
/// (`server.Options.own_address_max_age_ms`): after one missed refresh the loop retries every 15 s
/// (~4 tries before 150 s), and waking from a long sleep refuses requests until the prompt refresh
/// confirms the list.
const own_address_max_age_ms = 150_000;
comptime {
    std.debug.assert(own_address_max_age_ms > 2 * (own_address_refresh_s * 1000 + tailscale_timeout_ms));
}

/// Wait until the boot clock reaches `target_ms`, waking in short slices so a machine sleep (during
/// which the awake clock stops) triggers the next refresh promptly after waking.
fn waitUntilBoot(io: Io, target_ms: i64) Io.Cancelable!void {
    while (true) {
        const left = target_ms - bootNowMs(io);
        if (left <= 0) return;
        try io.sleep(.fromMilliseconds(@min(left, 5_000)), .awake);
    }
}

/// Where rweb listens, for its startup line.
fn describeListener(arena: std.mem.Allocator, b: server.Bound) ![]const u8 {
    return switch (b.listen) {
        .unix => |p| arena.print("unix:{s}", .{p}),
        .tcp_loopback => |port| if (b.listener6 != null)
            arena.print("http://127.0.0.1:{d}/ and http://[::1]:{d}/", .{ port, port })
        else
            arena.print("http://127.0.0.1:{d}/", .{port}),
    };
}

/// A listener that could not be taken: what is wrong and the fix, in the two lines of a file's
/// refusal, then exit 2. `args` are the command line's, to tell a layout's listener from one named
/// with an advanced option.
fn listenFailed(listen: server.Listen, e: anyerror, problem: *const xfer.Problem, command: cli.Command, args: []const []const u8) noreturn {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    listenFailedText(&w, listen, e, problem, command, args) catch {};
    say("{s}", .{w.buffered()});
    std.process.exit(2);
}

/// `listenFailed`'s words.
fn listenFailedText(w: *Io.Writer, listen: server.Listen, e: anyerror, problem: *const xfer.Problem, command: cli.Command, args: []const []const u8) Io.Writer.Error!void {
    switch (listen) {
        .unix => |p| switch (e) {
            error.AddressInUse => try w.print("rweb: another program is already listening on {f} (another rweb?).\n  Fix: stop it, or choose another path with --listen-unix\n", .{xfer.Clean{ .s = p }}),
            error.NotASocket => try w.print("rweb: {f} exists and is not a socket; rweb never replaces it.\n  Fix: move it away, or choose another path with --listen-unix\n", .{xfer.Clean{ .s = p }}),
            error.NameTooLong => try w.print("rweb: the socket path {f} is {d} bytes, longer than a unix socket path can be here (at most {d}).\n  Fix: {s}\n", .{ xfer.Clean{ .s = p }, p.len, server.max_unix_path - 1, socketPathFix(args) }),
            else => try xfer.explain(w, "its socket", p, e, problem, .{ .item_option = "--listen-unix" }),
        },
        .tcp_loopback => |port| {
            // The option that names the port: `--port N` under `rweb tailscale`, else `--listen-tcp`.
            const by_port = command == .tailscale and !hasArg(args, "--listen-tcp");
            const choose = if (by_port) "choose another port with --port N" else "choose another port with --listen-tcp PORT";
            switch (e) {
                error.AddressInUse => try w.print("rweb: another program is already listening on 127.0.0.1:{d}.\n  Fix: stop it, or {s}\n", .{ port, choose }),
                error.Ip6AddressInUse => try w.print("rweb: another program is already listening on [::1]:{d}, where `localhost` can lead.\n  Fix: stop it, or {s}\n", .{ port, choose }),
                error.AccessDenied => try w.print("rweb: no permission to listen on port {d}.\n  Fix: {s} above 1023\n", .{ port, choose }),
                else => try w.print("rweb: the system would not let rweb listen on 127.0.0.1:{d}.\n  Fix: {s}\n", .{ port, choose }),
            }
        },
    }
}

fn hasArg(args: []const []const u8, name: []const u8) bool {
    for (args) |a| if (std.mem.eql(u8, a, name)) return true;
    return false;
}

/// How to shorten a socket path that is too long: under a layout on macOS the socket is kept in
/// `<config>/run`, so a shorter `--config-dir`; otherwise a path given with `--listen-unix`.
fn socketPathFix(args: []const []const u8) []const u8 {
    const layout_socket = args.len > 0 and (std.mem.eql(u8, args[0], "ssh") or std.mem.eql(u8, args[0], "tailscale")) and !hasArg(args, "--listen-unix");
    if (layout_socket and builtin.os.tag.isDarwin()) return "pass a shorter --config-dir (the socket is kept under it), or give the socket a shorter path with --listen-unix";
    return "give the socket a shorter path with --listen-unix";
}

/// The name of the account this process runs as, from the system's user database (in `buf`).
fn accountName(buf: []u8) ?[]const u8 {
    const pw = std.c.getpwuid(std.c.getuid()) orelse return null;
    const name = std.mem.span(pw.name orelse return null);
    if (name.len == 0 or name.len > buf.len) return null;
    @memcpy(buf[0..name.len], name);
    return buf[0..name.len];
}

/// Waiting for Tailscale or Rex at startup: the delay doubles to a cap, and a failure is reported
/// the first time and then at most once a minute.
pub const Backoff = struct {
    delay_ms: u32 = 500,
    max_ms: u32 = 10_000,
    log_every_ms: i64 = 60_000,
    last_log: ?i64 = null,
    failures: u32 = 0,
    /// Report nothing (tests).
    quiet: bool = false,

    /// Count a failure at `now` (ms); whether to report it.
    pub fn failed(b: *Backoff, now: i64) bool {
        b.failures += 1;
        if (b.quiet) return false;
        if (b.last_log) |t| if (now - t < b.log_every_ms) return false;
        b.last_log = now;
        return true;
    }

    pub fn wait(b: *Backoff, io: Io) Io.Cancelable!void {
        try io.sleep(.fromMilliseconds(b.delay_ms), .awake);
        b.delay_ms = @min(b.max_ms, b.delay_ms *| 2);
    }
};

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

fn bootNowMs(io: Io) i64 {
    return Io.Clock.boot.now(io).toMilliseconds();
}

/// What Tailscale told about this node.
const Facts = struct { addresses: []const []const u8 = &.{}, owner: ?[]const u8 = null, dns_name: ?[]const u8 = null };

/// Ask Tailscale for this node's addresses and/or login and DNS name until it answers (it may be
/// down or signed out at boot). A tagged node, which has no owner login, is a configuration error.
fn discoverTailscale(gpa: std.mem.Allocator, arena: std.mem.Allocator, io: Io, ts: []const u8, want_addresses: bool, want_owner: bool, backoff: *Backoff) error{ TaggedNode, Canceled, OutOfMemory }!Facts {
    while (true) {
        var attempt = std.heap.ArenaAllocator.init(gpa);
        defer attempt.deinit();
        const a = attempt.allocator();
        var what: []const u8 = "addresses";
        const got: anyerror!Facts = blk: {
            var f: Facts = .{};
            if (want_addresses) f.addresses = tailscaleAddresses(a, io, ts) catch |e| break :blk e;
            if (want_owner) {
                what = "login";
                f.owner = tailscaleOwner(a, io, ts) catch |e| break :blk e;
                what = "DNS name";
                f.dns_name = tailscaleDnsName(a, io, ts) catch |e| break :blk e;
            }
            break :blk f;
        };
        if (got) |f| {
            if (backoff.failures > 0) say("rweb: Tailscale answered\n", .{});
            var out: Facts = .{};
            const list = try arena.alloc([]const u8, f.addresses.len);
            for (f.addresses, 0..) |x, i| list[i] = try arena.dupe(u8, x);
            out.addresses = list;
            if (f.owner) |o| out.owner = try arena.dupe(u8, o);
            if (f.dns_name) |n| out.dns_name = try arena.dupe(u8, n);
            return out;
        } else |e| switch (e) {
            error.TaggedNode => return error.TaggedNode,
            error.OutOfMemory => return error.OutOfMemory,
            else => if (backoff.failed(nowMs(io))) say("rweb: cannot read this node's Tailscale {s}: Tailscale is not running or not signed in. rweb keeps its listener and asks again (this message repeats at most once a minute)\n", .{what}),
        }
        try backoff.wait(io);
    }
}

/// Where Rex's socket is: the one given, or the first of the usual places that exists now. The
/// places are worked out once; each try only looks.
pub const RexFinder = struct {
    io: Io,
    given: ?[]const u8,
    places: []const []const u8,

    pub fn init(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map, given: ?[]const u8) !RexFinder {
        return .{ .io = io, .given = given, .places = try rexSocketPlaces(arena, env) };
    }

    pub fn socket(f: *RexFinder) ?[]const u8 {
        if (f.given) |g| return g;
        for (f.places) |p| if (exists(f.io, p)) return p;
        return null;
    }

    pub fn describe(f: *RexFinder, w: *Io.Writer) Io.Writer.Error!void {
        if (f.given) |g| return w.print("at {s}", .{g});
        try w.writeAll("in");
        for (f.places, 0..) |p, i| try w.print("{s} {s}", .{ if (i == 0) "" else ",", p });
    }
};

pub const RexLink = struct { ctl: *rex.control.Control, hub: *hub.Hub, socket: []const u8 };

/// Connect to Rex and open the hub, trying again until it works: Rex may not be running yet, or may
/// be restarting. `finder` has `socket() ?[]const u8` (null: no socket found yet) and `describe`.
pub fn connectRex(gpa: std.mem.Allocator, io: Io, finder: anytype, hub_cfg: hub.Config, backoff: *Backoff) error{ Canceled, OutOfMemory }!RexLink {
    while (true) {
        const path = finder.socket();
        const why: anyerror = blk: {
            const p = path orelse break :blk error.RexSocketNotFound;
            const ctl = rex.control.Control.open(gpa, io, .{ .socket_path = p, .client_name = "rweb", .client_version = build_options.version }) catch |e| break :blk e;
            const h = hub.Hub.open(gpa, io, ctl, hub_cfg) catch |e| {
                ctl.close();
                break :blk e;
            };
            if (backoff.failures > 0) say("rweb: connected to Rex at {s}\n", .{p});
            return .{ .ctl = ctl, .hub = h, .socket = p };
        };
        if (why == error.OutOfMemory) return error.OutOfMemory;
        if (why == error.Canceled) return error.Canceled;
        if (backoff.failed(nowMs(io))) {
            var buf: [1024]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            finder.describe(&w) catch {};
            var pbuf: [1200]u8 = undefined;
            say("rweb: {s}. rweb keeps its listener and tries again (this message repeats at most once a minute)\n", .{rexProblem(&pbuf, why, w.buffered())});
        }
        try backoff.wait(io);
    }
}

/// Why Rex could not be reached, in words (`where` is `at PATH` or `in A, B`), in `buf`.
fn rexProblem(buf: []u8, why: anyerror, where: []const u8) []const u8 {
    const text = switch (why) {
        error.RexSocketNotFound => std.fmt.bufPrint(buf, "Rex is not running: no socket {s} (pass --rex-socket PATH if it is elsewhere)", .{where}),
        error.FileNotFound, error.ConnectionRefused => std.fmt.bufPrint(buf, "Rex is not running: nothing answers {s}", .{where}),
        error.WrongPeer => std.fmt.bufPrint(buf, "the socket {s} is served by another user, not by Rex running as you; rweb will not talk to it", .{where}),
        error.BadWelcome => std.fmt.bufPrint(buf, "Rex {s} speaks an API revision this rweb does not (rweb works with revisions {d} to {d}); update rweb or Rex", .{ where, rex.control.api_min_supported, rex.control.api_max_supported }),
        error.AccessDenied, error.PermissionDenied => std.fmt.bufPrint(buf, "no permission to open Rex's socket {s}", .{where}),
        else => std.fmt.bufPrint(buf, "Rex {s} did not complete the connection", .{where}),
    };
    return text catch "Rex cannot be reached";
}

/// Where Rex's user socket may be: the app's on a Mac (first: `XDG_RUNTIME_DIR` is not the Mac's
/// own setting, and whoever set it chose where it points), `$XDG_RUNTIME_DIR/rex/server.sock`, then
/// `/run/user/<uid>/rex/server.sock`.
fn rexSocketPlaces(arena: std.mem.Allocator, env: *std.process.Environ.Map) ![]const []const u8 {
    var out: std.ArrayList([]const u8) = .empty;
    if (builtin.os.tag == .macos) if (env.get("HOME")) |home| {
        try out.append(arena, try arena.print("{s}/Library/Application Support/Rex/server.sock", .{home}));
    };
    if (env.get("XDG_RUNTIME_DIR")) |dir| try out.append(arena, try arena.print("{s}/rex/server.sock", .{dir}));
    try out.append(arena, try arena.print("/run/user/{d}/rex/server.sock", .{std.c.getuid()}));
    return out.items;
}

fn exists(io: Io, path: []const u8) bool {
    _ = Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

/// Where `tailscale` is looked for when `--tailscale` is not given: the places its installers put
/// it, in this order. Never `PATH`.
pub fn tailscaleCandidates(os: std.Target.Os.Tag) []const []const u8 {
    return if (os.isDarwin()) &.{
        "/Applications/Tailscale.app/Contents/MacOS/Tailscale",
        "/usr/local/bin/tailscale",
        "/opt/homebrew/bin/tailscale",
    } else &.{
        "/usr/bin/tailscale",
        "/usr/local/bin/tailscale",
        "/usr/sbin/tailscale",
    };
}

/// Why a `tailscale` was not used: the path tried, the check that failed, and what the check found
/// (where, owner, mode, access list), kept whole for the message.
pub const Refused = struct { path: []const u8, why: anyerror, problem: xfer.Problem = .{} };
/// What looking at one path found: the program's real path, nothing there, or a refusal.
pub const Probe = union(enum) { ok: []const u8, missing, refused: Refused };
pub const Choice = union(enum) { ok: []const u8, none, refused: Refused };

/// Which `tailscale` to run. A given path is the only one tried. Otherwise the candidates in order,
/// stopping at the first that exists: it is used if it passes `probe` and is the answer's refusal if
/// not. A refused program is never passed over for a later place, which could hold a wrapper that
/// runs the refused one. `none` when no candidate exists.
pub fn chooseTailscale(given: ?[]const u8, candidates: []const []const u8, ctx: anytype, comptime probe: fn (@TypeOf(ctx), []const u8) Probe) Choice {
    if (given) |g| return switch (probe(ctx, g)) {
        .ok => |p| .{ .ok = p },
        .missing => .{ .refused = .{ .path = g, .why = error.FileNotFound, .problem = .{ .ext_path = g } } },
        .refused => |r| .{ .refused = r },
    };
    for (candidates) |c| switch (probe(ctx, c)) {
        .ok => |p| return .{ .ok = p },
        .missing => {},
        .refused => |r| return .{ .refused = r },
    };
    return .none;
}

const SystemProbe = struct { arena: std.mem.Allocator, io: Io };

/// The program at `path`, checked by `xfer.checkedProgram`: `ok` holds the exact path to run. A
/// refusal carries the whole Problem by value (its path is kept as an offset into its own buffer, so
/// the copy still names where the check failed).
fn systemProbe(ctx: SystemProbe, path: []const u8) Probe {
    var problem: xfer.Problem = .{};
    const real = xfer.checkedProgram(ctx.arena, ctx.io, path, &problem) catch |e| {
        if (e == error.FileNotFound) return .missing;
        return .{ .refused = .{ .path = path, .why = e, .problem = problem } };
    };
    return .{ .ok = real };
}

/// The `tailscale` program to run, by its checked real path, or a clear message and exit.
fn tailscaleProgram(arena: std.mem.Allocator, io: Io, given: ?[]const u8) []const u8 {
    const candidates = tailscaleCandidates(builtin.os.tag);
    switch (chooseTailscale(given, candidates, SystemProbe{ .arena = arena, .io = io }, systemProbe)) {
        .ok => |p| return p,
        .refused => |r| {
            if (r.why == error.FileNotFound) {
                say("rweb: there is no tailscale program at {s}.\n  Fix: pass --tailscale PATH to where it is installed\n", .{r.path});
            } else {
                var buf: [2048]u8 = undefined;
                var w: Io.Writer = .fixed(&buf);
                layout.explain(&w, "the tailscale program", r.path, r.why, &r.problem, .{ .item_option = "--tailscale" }) catch {};
                say("{s}rweb: (rweb runs tailscale only from a place no other user can change; later install locations are not tried, so one cannot stand in for this one)\n", .{w.buffered()});
            }
        },
        .none => {
            say("rweb: cannot find the tailscale program in", .{});
            for (candidates) |c| say(" {s}", .{c});
            say(".\n  Fix: install Tailscale, or pass --tailscale PATH (it is never looked for in PATH)\n", .{});
        },
    }
    std.process.exit(2);
}

/// Runs `tailscale` with one deadline for its output and its exit together, and a cap on what it may
/// print (`proc.run`): a `tailscale` that hangs, babbles, or closes its output and stays must not stall
/// the own-address refresh or grow memory. Past the deadline it is killed; that is a failed call like
/// any other.
fn runTailscale(arena: std.mem.Allocator, io: Io, argv: []const []const u8) !proc.Result {
    return proc.run(arena, io, .{ .argv = argv, .timeout_ms = tailscale_timeout_ms, .output_max = tailscale_output_max });
}
const tailscale_output_max = 1 << 20;
const tailscale_timeout_ms = 10_000;

/// The login of the user this node belongs to, from `tailscale status --json`.
fn tailscaleOwner(arena: std.mem.Allocator, io: Io, ts: []const u8) ![]const u8 {
    const res = try runTailscale(arena, io, &.{ ts, "status", "--json" });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    return ownerFromStatus(arena, res.stdout);
}

/// The owner's login from `tailscale status --json`. A tagged node has no user login (its "user" is a
/// placeholder for the tag that no person signs in as), so it is refused: the owner must be named.
fn ownerFromStatus(arena: std.mem.Allocator, status_json: []const u8) ![]const u8 {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, status_json, .{});
    if (v != .object) return error.NoSelf;
    const self_v = v.object.get("Self") orelse return error.NoSelf;
    if (self_v != .object) return error.NoSelf;
    const self = self_v.object;
    if (self.get("Tags")) |tags| if (tags == .array and tags.array.items.len > 0) return error.TaggedNode;
    const uid = self.get("UserID") orelse return error.NoSelf;
    if (uid != .integer) return error.NoSelf;
    var key_buf: [24]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "{d}", .{uid.integer});
    const users = v.object.get("User") orelse return error.NoSelf;
    if (users != .object) return error.NoSelf;
    const user = users.object.get(key) orelse return error.NoSelf;
    if (user != .object) return error.NoSelf;
    const login = user.object.get("LoginName") orelse return error.NoSelf;
    if (login != .string or login.string.len == 0) return error.NoSelf;
    return login.string;
}

/// This node's MagicDNS name, without the trailing dot, from `tailscale status --json`.
fn tailscaleDnsName(arena: std.mem.Allocator, io: Io, ts: []const u8) ![]const u8 {
    const res = try runTailscale(arena, io, &.{ ts, "status", "--json" });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    return dnsNameFromStatus(arena, res.stdout);
}

/// This node's MagicDNS name from `tailscale status --json`; any other shape is `NoSelf`.
fn dnsNameFromStatus(arena: std.mem.Allocator, status_json: []const u8) ![]const u8 {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, status_json, .{});
    if (v != .object) return error.NoSelf;
    const self_v = v.object.get("Self") orelse return error.NoSelf;
    if (self_v != .object) return error.NoSelf;
    const dns = self_v.object.get("DNSName") orelse return error.NoSelf;
    if (dns != .string) return error.NoSelf;
    const name = std.mem.trimEnd(u8, dns.string, ".");
    if (name.len == 0) return error.NoSelf;
    return name;
}

/// The contents of a secret file, trimmed, read through `xfer.readPrivateFile` (a regular file of
/// ours, closed to group and others, in folders only we or root can change, never through a link),
/// and long enough; with `path_safe` it may hold only characters that are safe in a URL path.
fn readSecretFile(arena: std.mem.Allocator, io: Io, path: []const u8, min_len: usize, path_safe: bool, problem: *xfer.Problem) (xfer.OpenError || error{ TooShort, BadCharacters })![]const u8 {
    const raw = try xfer.readPrivateFile(arena, io, path, 4096, problem);
    const text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len < min_len) return error.TooShort;
    if (path_safe and !cli.isSafeSecret(text)) return error.BadCharacters;
    return text;
}

/// `tailscale ip` prints this node's addresses, one per line.
fn tailscaleAddresses(arena: std.mem.Allocator, io: Io, ts: []const u8) ![]const []const u8 {
    const res = try runTailscale(arena, io, &.{ ts, "ip" });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeAny(u8, res.stdout, "\r\n ");
    while (lines.next()) |l| try out.append(arena, try arena.dupe(u8, l));
    if (out.items.len == 0) return error.NoAddresses;
    return out.items;
}

fn writeTmp(io: Io, dir: Io.Dir, name: []const u8, mode: u32, text: []const u8) !void {
    const f = try dir.createFile(io, name, .{ .permissions = @fromBackingInt(@intCast(mode)) });
    defer f.close(io);
    try f.writeStreamingAll(io, text);
}

test "a secret file must be private, ours, long enough and made of safe characters" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const good = "0123456789abcdef0123456789abcdef0123";
    try writeTmp(io, tmp.dir, "ok", 0o600, good ++ "\n");
    try writeTmp(io, tmp.dir, "open", 0o644, good);
    try writeTmp(io, tmp.dir, "group", 0o640, good);
    try writeTmp(io, tmp.dir, "short", 0o600, "abc");
    try writeTmp(io, tmp.dir, "slash", 0o600, "0123456789abcdef0123456789abc/ef0123");
    try tmp.dir.symLink(io, "ok", "link", .{});
    try tmp.dir.createDirPath(io, "adir");
    const T = std.testing;
    var p: xfer.Problem = .{};
    try T.expectEqualStrings(good, try readSecretFile(arena, io, try arena.print("{s}/ok", .{root}), 32, true, &p));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try arena.print("{s}/open", .{root}), 32, true, &p));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try arena.print("{s}/group", .{root}), 32, true, &p));
    try T.expectError(error.TooShort, readSecretFile(arena, io, try arena.print("{s}/short", .{root}), 32, true, &p));
    try T.expectError(error.BadCharacters, readSecretFile(arena, io, try arena.print("{s}/slash", .{root}), 32, true, &p));
    // With path_safe off, other characters are kept.
    try T.expectEqualStrings("0123456789abcdef0123456789abc/ef0123", try readSecretFile(arena, io, try arena.print("{s}/slash", .{root}), 16, false, &p));
    try T.expectError(error.FileNotFound, readSecretFile(arena, io, try arena.print("{s}/missing", .{root}), 32, true, &p));
    // Never through a link, and never a directory.
    try T.expectError(error.SymLink, readSecretFile(arena, io, try arena.print("{s}/link", .{root}), 32, true, &p));
    try T.expectError(error.NotARegularFile, readSecretFile(arena, io, try arena.print("{s}/adir", .{root}), 32, true, &p));
}

test "a refused tailscale past a link keeps where and what the check found, for the message" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // `bin` -> `open`, a folder every user can change: the check fails at `<root>/open`, which the
    // walk holds in the Problem's own buffer, and the Problem is returned by value.
    try tmp.dir.createDirPath(io, "open");
    var z: [512:0]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(try std.fmt.bufPrintSentinel(&z, "{s}/open", .{root}, 0), 0o777));
    try writeTmp(io, tmp.dir, "open/tailscale", 0o755, "#!/bin/sh\n");
    try tmp.dir.symLink(io, "open", "bin", .{});
    const given = try arena.print("{s}/bin/tailscale", .{root});
    const got = systemProbe(.{ .arena = arena, .io = io }, given);
    const r = got.refused;
    try std.testing.expectEqual(error.FolderWritableByOthers, r.why);
    const open = try arena.print("{s}/open", .{root});
    try std.testing.expectEqualStrings(open, r.problem.pathText());
    // The message has the owner's mode, not only the place.
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try layout.explain(&w, "the tailscale program", r.path, r.why, &r.problem, .{});
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "(mode 0777)") != null);
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "/open can be changed by every user on this machine") != null);
}

test "listener refusals: two lines, the option that names the port, and the socket path's limit" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    const no: xfer.Problem = .{};
    try listenFailedText(&w, .{ .tcp_loopback = 7695 }, error.AddressInUse, &no, .tailscale, &.{ "tailscale", "--port", "7695" });
    try std.testing.expectEqualStrings("rweb: another program is already listening on 127.0.0.1:7695.\n  Fix: stop it, or choose another port with --port N\n", w.buffered());
    w = .fixed(&buf);
    try listenFailedText(&w, .{ .tcp_loopback = 8000 }, error.AddressInUse, &no, .advanced, &.{ "--listen-tcp", "8000" });
    try std.testing.expect(std.mem.endsWith(u8, w.buffered(), "  Fix: stop it, or choose another port with --listen-tcp PORT\n"));
    w = .fixed(&buf);
    try listenFailedText(&w, .{ .unix = "/x/s.sock" }, error.NotASocket, &no, .advanced, &.{});
    try std.testing.expectEqualStrings("rweb: /x/s.sock exists and is not a socket; rweb never replaces it.\n  Fix: move it away, or choose another path with --listen-unix\n", w.buffered());
    w = .fixed(&buf);
    try listenFailedText(&w, .{ .unix = "/x/s.sock" }, error.NameTooLong, &no, .ssh, &.{"ssh"});
    var want: [128]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, w.buffered(), try std.fmt.bufPrint(&want, "(at most {d}).\n  Fix: ", .{server.max_unix_path - 1})) != null);
    if (builtin.os.tag.isDarwin()) try std.testing.expect(std.mem.indexOf(u8, w.buffered(), "--config-dir") != null);
    // The parser and the server agree on the limit for this system.
    try std.testing.expectEqual(server.max_unix_path, cli.maxUnixPath(builtin.os.tag));
    try std.testing.expectEqual(@as(usize, if (builtin.os.tag.isDarwin()) 104 else 108), server.max_unix_path);
}

test "a socket path too long is refused before its folders are made" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    const xs: [110]u8 = @splat('x');
    const long = try arena.print("{s}/made/{s}/s.sock", .{ root, &xs });
    try std.testing.expectError(error.NameTooLong, server.bind(std.testing.allocator, io, .{ .unix = long }, null));
    try std.testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "made", .{}));
}

test "the ssh line's user is the account's, from the user database" {
    var ub: [256]u8 = undefined;
    const name = accountName(&ub).?;
    const pw = std.c.getpwuid(std.c.getuid()).?;
    try std.testing.expectEqualStrings(std.mem.span(pw.name.?), name);
}

test "a stop signal removes this process's own socket, and nothing put in its place" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    const tmp_root = if (builtin.os.tag.isDarwin()) "/private/tmp" else "/tmp";
    var pb: [96]u8 = undefined;
    const path = try std.fmt.bufPrint(&pb, tmp_root ++ "/rweb-test-{x}/s.sock", .{rnd});
    defer Io.Dir.cwd().deleteTree(io, std.fs.path.dirname(path).?) catch {};
    defer StopSocket.dir_fd = -1;
    {
        var b = try server.bind(gpa, io, .{ .unix = path }, null);
        defer b.deinit(io);
        noteStopSocket(&b);
        removeStopSocket();
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }));
    }
    {
        var b = try server.bind(gpa, io, .{ .unix = path }, null);
        defer b.deinit(io);
        noteStopSocket(&b);
        // Something else now has the name: left alone.
        try Io.Dir.cwd().deleteFile(io, path);
        const f = try Io.Dir.cwd().createFile(io, path, .{});
        f.close(io);
        removeStopSocket();
        _ = try Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
        try Io.Dir.cwd().deleteFile(io, path);
    }
}

/// A pretend file system for `chooseTailscale`: path -> what probing it finds.
const FakeProbe = struct {
    entries: []const struct { []const u8, Probe },

    fn probe(f: FakeProbe, path: []const u8) Probe {
        for (f.entries) |e| if (std.mem.eql(u8, e[0], path)) return e[1];
        return .missing;
    }
};

test "tailscale is taken from --tailscale or fixed places, never PATH, and must pass its checks" {
    const T = std.testing;
    // The fixed places: absolute, and per system.
    for ([_]std.Target.Os.Tag{ .linux, .macos }) |os| for (tailscaleCandidates(os)) |c| try T.expect(c[0] == '/');
    try T.expectEqualStrings("/Applications/Tailscale.app/Contents/MacOS/Tailscale", tailscaleCandidates(.macos)[0]);
    try T.expectEqualStrings("/usr/bin/tailscale", tailscaleCandidates(.linux)[0]);
    const cands = tailscaleCandidates(.linux);
    const refused: Probe = .{ .refused = .{ .path = "/usr/bin/tailscale", .why = error.FolderWritableByGroup, .problem = .{ .ext_path = "/usr/bin" } } };
    // Nothing installed.
    try T.expect(chooseTailscale(null, cands, FakeProbe{ .entries = &.{} }, FakeProbe.probe) == .none);
    // The first that exists and passes, by its real path.
    const fs1 = FakeProbe{ .entries = &.{.{ "/usr/local/bin/tailscale", Probe{ .ok = "/opt/ts/tailscale" } }} };
    try T.expectEqualStrings("/opt/ts/tailscale", chooseTailscale(null, cands, fs1, FakeProbe.probe).ok);
    // The first that exists decides: one that fails its checks is the answer, never passed over for
    // a later place (which could hold a wrapper that runs it)...
    const fs2 = FakeProbe{ .entries = &.{ .{ "/usr/bin/tailscale", refused }, .{ "/usr/sbin/tailscale", Probe{ .ok = "/usr/sbin/tailscale" } } } };
    try T.expectEqualStrings("/usr/bin/tailscale", chooseTailscale(null, cands, fs2, FakeProbe.probe).refused.path);
    const r2 = chooseTailscale(null, cands, fs2, FakeProbe.probe);
    try T.expectEqualStrings("/usr/bin", r2.refused.problem.pathText());
    // ...a missing one is passed over, and a refusal after it is still the answer.
    const fs3 = FakeProbe{ .entries = &.{ .{ "/usr/local/bin/tailscale", refused }, .{ "/usr/sbin/tailscale", Probe{ .ok = "/usr/sbin/tailscale" } } } };
    try T.expect(chooseTailscale(null, cands, fs3, FakeProbe.probe) == .refused);
    const fs5 = FakeProbe{ .entries = &.{.{ "/usr/sbin/tailscale", Probe{ .ok = "/usr/sbin/tailscale" } }} };
    try T.expectEqualStrings("/usr/sbin/tailscale", chooseTailscale(null, cands, fs5, FakeProbe.probe).ok);
    // A given path is the only one tried: refused or missing, the fixed places are not used.
    try T.expect(chooseTailscale("/home/me/bin/tailscale", cands, fs1, FakeProbe.probe) == .refused);
    try T.expectEqualStrings("/home/me/bin/tailscale", chooseTailscale("/home/me/bin/tailscale", cands, fs1, FakeProbe.probe).refused.path);
    const fs4 = FakeProbe{ .entries = &.{.{ "/home/me/bin/tailscale", Probe{ .ok = "/home/me/bin/tailscale" } }} };
    try T.expectEqualStrings("/home/me/bin/tailscale", chooseTailscale("/home/me/bin/tailscale", cands, fs4, FakeProbe.probe).ok);
}

test "the real probe refuses a program others can change and finds a missing one missing" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try writeTmp(io, tmp.dir, "ts", 0o755, "#!/bin/sh\n");
    try writeTmp(io, tmp.dir, "wide", 0o755, "#!/bin/sh\n");
    var z: [512:0]u8 = undefined;
    try std.testing.expectEqual(@as(c_int, 0), std.c.chmod(try std.fmt.bufPrintSentinel(&z, "{s}/wide", .{root}, 0), 0o757));
    const p: SystemProbe = .{ .arena = arena, .io = io };
    const ok = try arena.print("{s}/ts", .{root});
    try std.testing.expectEqualStrings(ok, systemProbe(p, ok).ok);
    try std.testing.expect(systemProbe(p, try arena.print("{s}/missing", .{root})) == .missing);
    try std.testing.expect(systemProbe(p, try arena.print("{s}/wide", .{root})).refused.why == error.ProgramWritableByOthers);
}

/// A Rex that is away, then at a path nobody answers, then up (`which`: 0, 1, 2).
const LateRex = struct {
    which: std.atomic.Value(u8) = .init(0),
    paths: [2][]const u8,
    asked: std.atomic.Value(u32) = .init(0),

    fn socket(f: *LateRex) ?[]const u8 {
        _ = f.asked.fetchAdd(1, .acq_rel);
        return switch (f.which.load(.acquire)) {
            0 => null,
            1 => f.paths[0],
            else => f.paths[1],
        };
    }

    fn describe(f: *LateRex, w: *Io.Writer) Io.Writer.Error!void {
        _ = f;
        try w.writeAll("in the test");
    }

    fn waitAsked(f: *LateRex, io: Io, more: u32) !void {
        const start = f.asked.load(.acquire);
        var waited: u32 = 0;
        while (f.asked.load(.acquire) < start + more) : (waited += 1) {
            if (waited > 2000) return error.Timeout;
            try io.sleep(.fromMilliseconds(5), .awake);
        }
    }
};

fn connectLate(gpa: std.mem.Allocator, io: Io, f: *LateRex, b: *Backoff) error{ Canceled, OutOfMemory }!RexLink {
    return connectRex(gpa, io, f, .{}, b);
}

test "the listener is taken first and held while Rex is away; a waiting request is served once Rex is up" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    const T = std.testing;
    var b = try server.bind(gpa, io, .{ .tcp_loopback = 0 }, null);
    var b_owned = true;
    defer if (b_owned) b.deinit(io);
    var a4 = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(b.port) };
    try T.expectError(error.AddressInUse, a4.listen(io, .{}));
    var tok: [layout.secret_len]u8 = undefined;
    try layout.newSecret(io, &tok);

    // A browser that connects now waits in the listen queue; nothing reads its request yet.
    const early = try a4.connect(io, .{ .mode = .stream });
    defer early.close(io);
    var qb: [256]u8 = undefined;
    var wb: [512]u8 = undefined;
    var ew = early.writer(io, &wb);
    try ew.interface.writeAll(try std.fmt.bufPrint(&qb, "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nrweb-token: {s}\r\nConnection: close\r\n\r\n", .{&tok}));
    try ew.interface.flush();

    var late: LateRex = .{ .paths = .{ "/nonexistent-rweb-test/server.sock", "" } };
    var backoff: Backoff = .{ .delay_ms = 5, .max_ms = 20, .quiet = true };
    var task = try io.concurrent(connectLate, .{ gpa, io, &late, &backoff });
    var task_done = false;
    defer if (!task_done) if (task.cancel(io)) |l| {
        l.hub.close();
        l.ctl.close();
    } else |_| {};
    // No socket at all, then a path nobody answers: rweb keeps asking, and keeps the port.
    try late.waitAsked(io, 3);
    late.which.store(1, .release);
    try late.waitAsked(io, 3);
    try T.expectError(error.AddressInUse, a4.listen(io, .{}));
    try T.expectError(error.AddressInUse, a4.listen(io, .{ .reuse_address = true }));
    if (b.listener6 != null) {
        var a6 = Io.net.IpAddress{ .ip6 = Io.net.Ip6Address.loopback(b.port) };
        try T.expectError(error.AddressInUse, a6.listen(io, .{}));
    }

    // Rex comes up.
    const f = try rex.fake.Fake.start(gpa, io);
    defer f.deinit();
    late.paths[1] = f.path;
    late.which.store(2, .release);
    const link = try task.await(io);
    task_done = true;
    defer link.ctl.close();
    defer link.hub.close();
    try T.expectEqualStrings(f.path, link.socket);
    const srv = try server.Server.startBound(gpa, io, link.hub, .{ .listen = b.listen, .access = .{ .token = &tok } }, b);
    b_owned = false;
    defer srv.stop();

    // The request that waited is answered: the token form's header login, a redirect with the cookie.
    var rb: [4096]u8 = undefined;
    var er = early.reader(io, &rb);
    var all: std.ArrayList(u8) = .empty;
    defer all.deinit(gpa);
    er.interface.appendRemainingUnlimited(gpa, &all) catch {};
    try T.expect(std.mem.startsWith(u8, all.items, "HTTP/1.1 303"));
    // And a new one.
    const c = try a4.connect(io, .{ .mode = .stream });
    defer c.close(io);
    var cw = c.writer(io, &wb);
    try cw.interface.writeAll("GET /login.js HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n");
    try cw.interface.flush();
    var cr = c.reader(io, &rb);
    var got: std.ArrayList(u8) = .empty;
    defer got.deinit(gpa);
    cr.interface.appendRemainingUnlimited(gpa, &got) catch {};
    try T.expect(std.mem.startsWith(u8, got.items, "HTTP/1.1 200"));
}

test "waiting for Tailscale or Rex backs off to a cap and reports at most once a minute" {
    var b: Backoff = .{ .delay_ms = 500, .max_ms = 10_000 };
    try std.testing.expect(b.failed(1_000)); // the first failure is reported
    try std.testing.expect(!b.failed(2_000));
    try std.testing.expect(!b.failed(60_999));
    try std.testing.expect(b.failed(61_000)); // a minute later
    try std.testing.expect(!b.failed(61_500));
    try std.testing.expectEqual(@as(u32, 5), b.failures);
    var d: Backoff = .{ .delay_ms = 1, .max_ms = 4 };
    for ([_]u32{ 2, 4, 4 }) |want| {
        try d.wait(std.testing.io);
        try std.testing.expectEqual(want, d.delay_ms);
    }
}

test "Rex's absence is told in words, never an error name" {
    for ([_]anyerror{ error.RexSocketNotFound, error.FileNotFound, error.ConnectionRefused, error.WrongPeer, error.BadWelcome, error.Timeout }) |e| {
        var buf: [1200]u8 = undefined;
        const text = rexProblem(&buf, e, "at /run/user/1000/rex/server.sock");
        try std.testing.expect(std.mem.indexOf(u8, text, "/run/user/1000/rex/server.sock") != null);
        try std.testing.expect(std.mem.indexOf(u8, text, @errorName(e)) == null);
    }
}

test {
    _ = access;
    _ = protocol;
    _ = hub;
    _ = assets;
    _ = xfer;
    _ = server;
    _ = cli;
    _ = layout;
    _ = proc;
    _ = @import("bench.zig");
}
