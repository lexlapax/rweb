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
const build_options = @import("build_options");

/// What `rweb --version` prints: the version, the commit, how it was built, and what it works with.
pub fn versionText() []const u8 {
    return std.fmt.comptimePrint(
        "rweb {s}\ncommit {s}\nbuild {t} {t}-{t}\nghostty {s}\nrex api revisions {d}-{d}\n",
        .{ build_options.version, build_options.commit, builtin.mode, builtin.cpu.arch, builtin.os.tag, build_options.ghostty, rex.control.api_min_supported, rex.control.api_max_supported },
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
    try std.testing.expect(std.mem.indexOf(u8, t, "rex api revisions 18-19") != null);
}

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
        if (e == error.Version) {
            std.Io.File.stdout().writeStreamingAll(io, versionText()) catch {};
            std.process.exit(0);
        }
        switch (e) {
            error.NeedAllowHost => std.debug.print("rweb: --owner needs --allow-host NAME (this node's DNS name, repeatable): without it a page on any host name, a rebound DNS name included, reaches the bridge with the owner's identity. --owner-from-tailscale adds this node's name itself\n", .{}),
            error.BadToken => std.debug.print("rweb: --token must be at least 16 characters of letters, digits, - and _ (the --token-file rules)\n", .{}),
            else => {
                std.debug.print("{s}\n", .{cli.usage});
                if (e != error.Usage) std.debug.print("rweb: {t}\n", .{e});
            },
        }
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
    // Every own address must be one the rule can compare, and an owner rule needs at least one
    // unless the machine accepts its own address: fail closed rather than run without the rule.
    for (own.items) |addr| if (!access.isAddress(addr)) {
        std.debug.print("rweb: \"{s}\" is not an IP address; cannot refuse requests from this node\n", .{addr});
        std.process.exit(2);
    };
    if ((parsed.owner != null or parsed.owner_from_tailscale) and !parsed.allow_own_address and own.items.len == 0) {
        std.debug.print("rweb: no own address to refuse; pass --own-address or --allow-own-address\n", .{});
        std.process.exit(2);
    }

    // The owner: given, or this node's own Tailscale login.
    var owner = parsed.owner;
    if (parsed.owner_from_tailscale) {
        owner = tailscaleOwner(arena, io) catch |e| {
            if (e == error.TaggedNode) {
                std.debug.print("rweb: this node is a tagged Tailscale device, so it has no owner login; pass --owner LOGIN (your Tailscale login) and --allow-host <this node's DNS name> instead of --owner-from-tailscale\n", .{});
                std.process.exit(2);
            }
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

    // `cli.parse` already refuses an owner without a host; this is the second line.
    if (owner != null and hosts.items.len == 0) {
        std.debug.print("rweb: an owner rule needs --allow-host NAME\n", .{});
        std.process.exit(2);
    }
    if (parsed.token != null) std.debug.print("rweb: WARNING: --token is visible to every user in the process list; use --token-file\n", .{});

    // Secrets come from files only their owner can read, never from the command line (which
    // every user on the machine can see).
    var problem: xfer.Problem = .{};
    const backend_secret: ?[]const u8 = if (parsed.backend_secret_file) |path| readSecretFile(arena, io, path, 32, true, &problem) catch |e| secretFileFailed(path, e, problem) else null;
    var token = parsed.token;
    if (parsed.token_file) |path| token = readSecretFile(arena, io, path, cli.min_token_len, true, &problem) catch |e| secretFileFailed(path, e, problem);
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

    const ctl = rex.control.Control.open(gpa, io, .{ .socket_path = rex_socket, .client_name = "rweb", .client_version = build_options.version }) catch |e| {
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
            // Opened once and kept open for the life of the process: uploads go into this folder,
            // whatever is later put at its path.
            var up_problem: xfer.Problem = .{};
            transfer.upload_dir_handle = xfer.openUploadDir(arena, io, dir, &up_problem) catch |e| {
                std.debug.print("rweb: cannot use upload folder {s}: {t} (at {s})\n", .{ dir, e, up_problem.path });
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
    defer if (transfer.upload_dir_handle) |d| d.close(io);
    var hub_cfg: hub.Config = .{ .observe_only = parsed.observe_only, .history_lines = parsed.history_lines, .transfer = transfer };
    // The page may send its debug messages only when the bridge logs them (`--debug-input`).
    hub_cfg.debug_input = parsed.debug_input;
    const h = try hub.Hub.open(gpa, io, ctl, hub_cfg);
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
            // The token opens the bridge: it goes to a person at a terminal, never into a log.
            if (parsed.random_token) {
                const tty = std.Io.File.stderr().isTty(io) catch false;
                if (tty) {
                    std.debug.print("rweb: open http://127.0.0.1:{d}/?token={s}\n", .{ srv.port, token.? });
                } else {
                    std.debug.print("rweb: made a random token; it is not shown because standard error is not a terminal (it may be a log). To choose the token, put it in a file only you can read (mode 0600) and pass --token-file PATH\n", .{});
                }
            }
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
fn tailscaleDnsName(arena: std.mem.Allocator, io: Io) ![]const u8 {
    const res = try std.process.run(arena, io, .{ .argv = &.{ "tailscale", "status", "--json" } });
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

fn secretFileFailed(path: []const u8, e: anyerror, problem: xfer.Problem) noreturn {
    if (problem.path.len > 0 and !std.mem.eql(u8, problem.path, path)) {
        std.debug.print("rweb: cannot use secret file {s}: {t} (at {s})\n", .{ path, e, problem.path });
    } else std.debug.print("rweb: cannot use secret file {s}: {t}\n", .{ path, e });
    std.process.exit(2);
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
    try tmp.dir.symLink(io, "ok", "link", .{});
    try tmp.dir.createDirPath(io, "adir");
    const T = std.testing;
    var p: xfer.Problem = .{};
    try T.expectEqualStrings(good, try readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/ok", .{root}), 32, true, &p));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 32, true, &p));
    try T.expectError(error.TooOpen, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/group", .{root}), 32, true, &p));
    try T.expectError(error.TooShort, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/short", .{root}), 32, true, &p));
    try T.expectError(error.BadCharacters, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/slash", .{root}), 32, true, &p));
    // With path_safe off, other characters are kept.
    try T.expectEqualStrings("0123456789abcdef0123456789abc/ef0123", try readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/slash", .{root}), 16, false, &p));
    try T.expectError(error.FileNotFound, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/missing", .{root}), 32, true, &p));
    // Never through a link, and never a directory.
    try T.expectError(error.SymLink, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/link", .{root}), 32, true, &p));
    try T.expectError(error.NotARegularFile, readSecretFile(arena, io, try std.fmt.allocPrint(arena, "{s}/adir", .{root}), 32, true, &p));
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
