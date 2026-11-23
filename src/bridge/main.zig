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

const log = std.log.scoped(.rweb);

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var argv: std.ArrayList([]const u8) = .empty;
    var it = init.minimal.args.iterate();
    _ = it.next();
    while (it.next()) |a| try argv.append(arena, a);
    const parsed = cli.parse(arena, argv.items) catch |e| {
        std.debug.print("{s}\n", .{cli.usage});
        if (e != error.Usage) std.debug.print("rweb: {t}\n", .{e});
        std.process.exit(if (e == error.Usage) 0 else 2);
    };

    // Rex's socket.
    const rex_socket = parsed.rex_socket orelse try findRexSocket(arena, io, init.environ_map);

    // Own addresses: needed to refuse requests that came from this machine itself.
    var own: std.ArrayList([]const u8) = .empty;
    try own.appendSlice(arena, parsed.own_addresses);
    if (parsed.detect_own_addresses) {
        const found = tailscaleAddresses(arena, io) catch |e| {
            std.debug.print("rweb: cannot tell this node's Tailscale addresses ({t}); pass --own-address or --allow-own-address\n", .{e});
            std.process.exit(2);
        };
        try own.appendSlice(arena, found);
    }

    // The owner: given, or this node's own Tailscale login.
    var owner = parsed.owner;
    if (parsed.owner_from_tailscale) {
        owner = tailscaleOwner(arena, io) catch |e| {
            std.debug.print("rweb: cannot read this node's Tailscale login ({t}); pass --owner\n", .{e});
            std.process.exit(2);
        };
    }

    // Hosts a request may be for: those given, and this node's own DNS name when its login is used.
    var hosts: std.ArrayList([]const u8) = .empty;
    try hosts.appendSlice(arena, parsed.allowed_hosts);
    if (parsed.owner_from_tailscale) {
        if (tailscaleDnsName(arena, io)) |name| try hosts.append(arena, name) else |e| {
            std.debug.print("rweb: cannot read this node's DNS name ({t}); pass --allow-host NAME\n", .{e});
            std.process.exit(2);
        }
    }

    if (owner != null and hosts.items.len == 0) std.debug.print("rweb: WARNING: no --allow-host: a request for any Host name is accepted (DNS-rebinding defence is off)\n", .{});
    if (parsed.token != null) std.debug.print("rweb: WARNING: --token is visible to every user in the process list; use --token-file\n", .{});

    // Secrets come from files only their owner can read, never from the command line (which
    // every user on the machine can see).
    const backend_secret: ?[]const u8 = if (parsed.backend_secret_file) |path| readSecretFile(arena, io, path, 32, true) catch |e| secretFileFailed(path, e) else null;
    var token = parsed.token;
    if (parsed.token_file) |path| token = readSecretFile(arena, io, path, 16, false) catch |e| secretFileFailed(path, e);
    if (parsed.random_token) {
        var raw: [16]u8 = undefined;
        io.random(&raw);
        token = try std.fmt.allocPrint(arena, "{x}", .{raw});
    }

    var uids: std.ArrayList(u32) = .empty;
    if (parsed.peer_uids) |list| for (list) |u| try uids.append(arena, switch (u) {
        .uid => |n| n,
        .self => @intCast(std.c.getuid()),
    });

    const ctl = rex.control.Control.open(gpa, io, .{ .socket_path = rex_socket, .client_name = "rweb" }) catch |e| {
        std.debug.print("rweb: cannot reach Rex at {s}: {t}\n", .{ rex_socket, e });
        std.process.exit(1);
    };
    defer ctl.close();
    // File transfer: off unless asked for; uploads only into a folder that is ours alone.
    var transfer: xfer.Config = .{};
    if (parsed.enable_file_transfer) {
        transfer.enabled = true;
        transfer.max_bytes = @as(u64, parsed.max_transfer_mb) * 1024 * 1024;
        if (parsed.upload_dir) |dir| {
            checkUploadDir(arena, io, dir) catch |e| {
                std.debug.print("rweb: cannot use upload folder {s}: {t}\n", .{ dir, e });
                std.process.exit(2);
            };
            transfer.upload_dir = dir;
        }
        std.debug.print("rweb: file transfer ON: the page can download any file the terminal's user can read; uploads {s}{s}; limit {d} MB\n", .{
            if (transfer.upload_dir != null) "go to " else "are off",
            transfer.upload_dir orelse "",
            parsed.max_transfer_mb,
        });
    }
    const h = try hub.Hub.open(gpa, io, ctl, .{ .observe_only = parsed.observe_only, .history_lines = parsed.history_lines, .transfer = transfer });
    defer h.close();

    const listen: server.Listen = switch (parsed.listen) {
        .unix => |p| .{ .unix = p },
        .tcp => |port| .{ .tcp_loopback = port },
    };
    const srv = try server.Server.start(gpa, io, h, .{
        .listen = listen,
        .debug_input = parsed.debug_input,
        .backend_secret = backend_secret,
        .lab = parsed.lab,
        .access = .{
            .owner = owner,
            .token = token,
            .own_addresses = own.items,
            .allow_own_address = parsed.allow_own_address,
            .allowed_peer_uids = if (parsed.peer_uids != null) uids.items else null,
            .allowed_hosts = hosts.items,
        },
    });
    defer srv.stop();

    switch (listen) {
        .unix => |p| std.debug.print("rweb: listening on unix:{s} (Rex at {s}){s}\n", .{ p, rex_socket, if (parsed.observe_only) ", observe-only" else "" }),
        .tcp_loopback => {
            std.debug.print("rweb: listening on http://127.0.0.1:{d}/ (Rex at {s}){s}\n", .{ srv.port, rex_socket, if (parsed.observe_only) ", observe-only" else "" });
            if (backend_secret != null) std.debug.print("rweb: requests must carry the secret first path segment (point Tailscale Serve at http://127.0.0.1:{d}/<secret>)\n", .{srv.port});
            if (backend_secret == null and owner != null) std.debug.print("rweb: WARNING: the owner's identity headers can be forged by any local process on this machine (no --backend-secret-file)\n", .{});
            if (parsed.random_token) std.debug.print("rweb: open http://127.0.0.1:{d}/?token={s}\n", .{ srv.port, token.? });
        },
    }

    // Serve until the process is stopped.
    while (true) io.sleep(.fromSeconds(3600), .awake) catch return;
}

/// Rex's user socket: `$XDG_RUNTIME_DIR/rex/server.sock` on Linux, the app's on a Mac.
fn findRexSocket(arena: std.mem.Allocator, io: Io, env: *std.process.Environ.Map) ![]const u8 {
    if (env.get("XDG_RUNTIME_DIR")) |dir| {
        const p = try std.fmt.allocPrint(arena, "{s}/rex/server.sock", .{dir});
        if (exists(io, p)) return p;
    }
    if (builtin.os.tag == .macos) {
        if (env.get("HOME")) |home| {
            const p = try std.fmt.allocPrint(arena, "{s}/Library/Application Support/Rex/server.sock", .{home});
            if (exists(io, p)) return p;
        }
    }
    const uid = std.c.getuid();
    const p = try std.fmt.allocPrint(arena, "/run/user/{d}/rex/server.sock", .{uid});
    if (exists(io, p)) return p;
    std.debug.print("rweb: cannot find Rex's socket; pass --rex-socket\n", .{});
    std.process.exit(1);
}

fn exists(io: Io, path: []const u8) bool {
    _ = Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

/// The login of the user this node belongs to, from `tailscale status --json`.
fn tailscaleOwner(arena: std.mem.Allocator, io: Io) ![]const u8 {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "tailscale", "status", "--json" } });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, res.stdout, .{});
    const self = (v.object.get("Self") orelse return error.NoSelf).object;
    const uid = self.get("UserID") orelse return error.NoSelf;
    var key_buf: [24]u8 = undefined;
    const key = try std.fmt.bufPrint(&key_buf, "{d}", .{uid.integer});
    const users = (v.object.get("User") orelse return error.NoSelf).object;
    const user = (users.get(key) orelse return error.NoSelf).object;
    const login = user.get("LoginName") orelse return error.NoSelf;
    if (login != .string or login.string.len == 0) return error.NoSelf;
    return login.string;
}

/// This node's MagicDNS name, without the trailing dot, from `tailscale status --json`.
fn tailscaleDnsName(arena: std.mem.Allocator, io: Io) ![]const u8 {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "tailscale", "status", "--json" } });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, res.stdout, .{});
    const self = (v.object.get("Self") orelse return error.NoSelf).object;
    const dns = self.get("DNSName") orelse return error.NoSelf;
    if (dns != .string) return error.NoSelf;
    const name = std.mem.trimEnd(u8, dns.string, ".");
    if (name.len == 0) return error.NoSelf;
    return name;
}

/// The upload folder: made 0700 if missing; must then be a directory of ours that others cannot enter.
fn checkUploadDir(arena: std.mem.Allocator, io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().createDirPathStatus(io, path, @enumFromInt(0o700)) catch {}; // a new folder is 0700

    const st = try Io.Dir.cwd().statFile(io, path, .{});
    if (st.kind != .directory) return error.NotADirectory;
    if (@intFromEnum(st.permissions) & 0o077 != 0) return error.TooOpen;
    const path_z = try std.fmt.allocPrintSentinel(arena, "{s}", .{path}, 0);
    var sb: std.c.Stat = undefined;
    if (std.c.stat(path_z, &sb) != 0) return error.FileNotFound;
    if (sb.uid != std.c.getuid()) return error.NotOwned;
}

const SecretError = error{ TooOpen, NotOwned, TooShort, BadCharacters, FileNotFound, OutOfMemory } || Io.Dir.ReadFileAllocError || Io.Dir.StatFileError;

fn secretFileFailed(path: []const u8, e: anyerror) noreturn {
    std.debug.print("rweb: cannot use secret file {s}: {t}\n", .{ path, e });
    std.process.exit(2);
}

/// The contents of a secret file, trimmed. The file must be ours and closed to group and others,
/// and long enough; with `path_safe` it may hold only characters that are safe in a URL path.
fn readSecretFile(arena: std.mem.Allocator, io: Io, path: []const u8, min_len: usize, path_safe: bool) SecretError![]const u8 {
    const st = try Io.Dir.cwd().statFile(io, path, .{});
    if (@intFromEnum(st.permissions) & 0o077 != 0) return error.TooOpen;
    const path_z = try std.fmt.allocPrintSentinel(arena, "{s}", .{path}, 0);
    var sb: std.c.Stat = undefined;
    if (std.c.stat(path_z, &sb) != 0) return error.FileNotFound;
    if (sb.uid != std.c.getuid()) return error.NotOwned;
    const raw = try Io.Dir.cwd().readFileAlloc(io, path, arena, .limited(4096));
    const text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len < min_len) return error.TooShort;
    if (path_safe) for (text) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return error.BadCharacters;
    return text;
}

/// `tailscale ip` prints this node's addresses, one per line.
fn tailscaleAddresses(arena: std.mem.Allocator, io: Io) ![]const []const u8 {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "tailscale", "ip" } });
    if (res.term != .exited or res.term.exited != 0) return error.TailscaleFailed;
    var out: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.tokenizeAny(u8, res.stdout, "\r\n ");
    while (lines.next()) |l| try out.append(arena, try arena.dupe(u8, l));
    if (out.items.len == 0) return error.NoAddresses;
    return out.items;
}

fn writeTmp(io: Io, dir: Io.Dir, name: []const u8, mode: u32, text: []const u8) !void {
    const f = try dir.createFile(io, name, .{ .permissions = @enumFromInt(mode) });
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
    const T = std.testing;
    try T.expectEqualStrings(good, try readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/ok", .{root}), 32, true));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 32, true));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/group", .{root}), 32, true));
    try T.expectError(error.TooShort, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/short", .{root}), 32, true));
    try T.expectError(error.BadCharacters, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/slash", .{root}), 32, true));
    // A token may hold other characters (it is not part of a path).
    try T.expectEqualStrings("0123456789abcdef0123456789abc/ef0123", try readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/slash", .{root}), 16, false));
    try T.expectError(error.FileNotFound, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/missing", .{root}), 32, true));
}

test {
    _ = access;
    _ = protocol;
    _ = hub;
    _ = assets;
    _ = xfer;
    _ = server;
    _ = cli;
}
