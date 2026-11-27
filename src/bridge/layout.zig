//! The two supported layouts, `rweb tailscale` and `rweb ssh`: where their files live, the files
//! rweb makes for them, and the next step each prints. The defaults are pure (the environment is
//! passed in) so they can be tested; only `ensureSecretFile` touches the system.

const std = @import("std");
const sys = @import("sys.zig");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const xfer = @import("xfer.zig");

/// What the layouts' defaults depend on, read from the process at startup (and made up in tests).
pub const Env = struct {
    os: std.Target.Os.Tag = builtin.os.tag,
    home: ?[]const u8 = null,
    xdg_config_home: ?[]const u8 = null,
    xdg_runtime_dir: ?[]const u8 = null,
    uid: u32 = 0,
};

/// The Tailscale Serve port the printed `tailscale serve` line uses.
pub const serve_https_port = 12443;
/// The loopback port `rweb tailscale` listens on on macOS (Serve there cannot reach a unix socket).
pub const default_tailscale_port = 7695;
/// The laptop's port in the printed `ssh -L` line.
pub const default_ssh_port = 7700;

/// `<config>`: `--config-dir`, else `$XDG_CONFIG_HOME/rweb` (an absolute one; the XDG rules ignore a
/// relative one), else `$HOME/.config/rweb`.
pub fn configDir(arena: Allocator, env: Env, given: ?[]const u8) error{ NoHome, OutOfMemory }![]const u8 {
    if (given) |g| return std.mem.trimEnd(u8, g, "/");
    if (env.xdg_config_home) |x| if (x.len > 0 and x[0] == '/') return arena.print("{s}/rweb", .{std.mem.trimEnd(u8, x, "/")});
    const home = env.home orelse return error.NoHome;
    if (home.len == 0 or home[0] != '/') return error.NoHome;
    return arena.print("{s}/.config/rweb", .{std.mem.trimEnd(u8, home, "/")});
}

/// The folder for sockets that live only while the user is logged in: `$XDG_RUNTIME_DIR`, else
/// `/run/user/<uid>` (Linux).
pub fn runtimeDir(arena: Allocator, env: Env) error{OutOfMemory}![]const u8 {
    if (env.xdg_runtime_dir) |x| if (x.len > 0 and x[0] == '/') return std.mem.trimEnd(u8, x, "/");
    return arena.print("/run/user/{d}", .{env.uid});
}

/// `rweb tailscale`'s unix socket (Linux).
pub fn tailscaleSocket(arena: Allocator, env: Env) error{OutOfMemory}![]const u8 {
    return arena.print("{s}/rweb/bridge.sock", .{try runtimeDir(arena, env)});
}

/// `rweb ssh`'s unix socket: in the runtime folder on Linux, under `<config>/run` on macOS (which
/// has no per-user runtime folder).
pub fn sshSocket(arena: Allocator, env: Env, config: []const u8) error{OutOfMemory}![]const u8 {
    if (env.os.isDarwin()) return arena.print("{s}/run/ssh.sock", .{config});
    return arena.print("{s}/rweb/ssh.sock", .{try runtimeDir(arena, env)});
}

// ---- secrets rweb makes ----

/// Characters in a secret rweb makes: 32 random bytes, base64url without padding.
pub const secret_len = std.base64.url_safe_no_pad.Encoder.calcSize(32);

/// A new secret: 32 bytes from the operating system's random source, base64url without padding
/// (letters, digits, `-` and `_`: safe in a path, a query, a header and a cookie).
pub fn newSecret(io: Io, out: *[secret_len]u8) !void {
    var raw: [32]u8 = undefined;
    try io.randomSecure(&raw);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    std.crypto.secureZero(u8, &raw);
}

/// Make the secret file at `path` if it is missing: its folder (and missing folders above it) made
/// 0700, each inside a folder that passed the checks, and the folder itself must be ours and closed
/// to others; the file created exclusively (never over anything, a link included) with mode 0600.
/// An existing file is left as it is (it is read and checked like any secret file). True when it was
/// made. On failure `problem` names what failed.
pub fn ensureSecretFile(arena: Allocator, io: Io, path: []const u8, problem: *xfer.Problem) !bool {
    problem.setPath(path);
    const dir = std.fs.path.dirname(path) orelse return error.BadPath;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.BadPath;
    const up = try xfer.openUploadDir(arena, io, dir, true, problem);
    defer up.dir.close(io);
    problem.setPath(path);
    var text: [secret_len + 1]u8 = undefined;
    try newSecret(io, text[0..secret_len]);
    defer std.crypto.secureZero(u8, &text);
    text[secret_len] = '\n';
    const f = up.dir.createFile(io, base, .{ .exclusive = true, .truncate = false, .permissions = @fromBackingInt(@intCast(0o600)) }) catch |e| switch (e) {
        error.PathAlreadyExists => return false,
        else => return e,
    };
    f.writeStreamingAll(io, &text) catch |e| {
        f.close(io);
        up.dir.deleteFile(io, base) catch {};
        return e;
    };
    f.close(io);
    return true;
}

// ---- the next step, printed at startup (never a secret) ----

/// `s` as one shell word: as it is when it has nothing a shell treats specially, else in single quotes.
pub fn shellQuote(w: *Io.Writer, s: []const u8) Io.Writer.Error!void {
    const plain = s.len > 0 and for (s) |c| {
        if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "_-./:@%+=,", c) != null)) break false;
    } else true;
    if (plain) return w.writeAll(s);
    try w.writeByte('\'');
    for (s) |c| if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
    try w.writeByte('\'');
}

/// Where Tailscale Serve is to send requests: rweb's unix socket or loopback port.
pub const Served = union(enum) { unix: []const u8, tcp: u16 };

/// What `rweb tailscale` prints: the `tailscale serve` line to run once and the address to open.
/// A unix socket (Linux) is served with `sudo`; a loopback port (macOS) through its backend secret,
/// read by the shell from its file, so the secret itself is never printed.
pub fn tailscaleNextStep(w: *Io.Writer, listen: Served, backend_secret_file: ?[]const u8, dns_name: ?[]const u8) Io.Writer.Error!void {
    try w.writeAll("rweb: if Tailscale Serve is not set up for rweb yet, run this once:\n  ");
    switch (listen) {
        .unix => |sock| {
            try w.print("sudo tailscale serve --bg --https={d} ", .{serve_https_port});
            var buf: [1100]u8 = undefined;
            try shellQuote(w, std.fmt.bufPrint(&buf, "unix:{s}", .{sock}) catch sock);
        },
        .tcp => |port| {
            try w.print("tailscale serve --bg --https={d} \"http://127.0.0.1:{d}/", .{ serve_https_port, port });
            if (backend_secret_file) |f| {
                try w.writeAll("$(cat ");
                try shellQuote(w, f);
                try w.writeAll(")");
            }
            try w.writeAll("\"");
        },
    }
    try w.writeAll("\nrweb: then open ");
    // Tailscale's answer, so only a plain name is printed as it is.
    try w.print("https://{s}:{d}/", .{ plainName(dns_name orelse "", "<this machine's Tailscale name>"), serve_https_port });
    try w.print(" (Tailscale Serve keeps this setting; `tailscale serve --https={d} off` removes it)\n", .{serve_https_port});
    if (listen == .tcp) try w.writeAll("rweb: this layout is for a Mac where you are the only account: the backend secret is in the Serve target, which other accounts on this machine can read\n");
}

/// The Host names token mode accepts when none are given: the loopback names a browser uses for the
/// address rweb prints (`127.0.0.1`, `localhost`, `[::1]`). On a TCP listener, with its port; behind a
/// unix socket (`tcp_port` null), on any port, since `ssh -L` forwards from a local port rweb does
/// not know. A page reached through a rebound DNS name gets nothing.
pub fn tokenHosts(arena: Allocator, tcp_port: ?u16) Allocator.Error![]const []const u8 {
    const names = [_][]const u8{ "127.0.0.1", "localhost", "[::1]" };
    const out = try arena.alloc([]const u8, names.len);
    for (names, 0..) |n, i| out[i] = if (tcp_port) |p| try arena.print("{s}:{d}", .{ n, p }) else n;
    return out;
}

/// A name for the printed `ssh` line: `s` when it holds only letters, digits, `-`, `.` and `_`
/// (no shell or terminal could read anything else into it), else `placeholder`.
pub fn plainName(s: []const u8, placeholder: []const u8) []const u8 {
    if (s.len == 0 or s.len > 253) return placeholder;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_')) return placeholder;
    return s;
}

/// What `rweb ssh` prints: the `ssh -L` line for the laptop, the address to open there and where to
/// find the token (by its file, never the token itself). `user` is the account's name from the
/// system's user database and `host` this machine's name; either, when it holds anything but letters,
/// digits, `-`, `.` and `_` (`plainName`), is printed as a placeholder to fill in.
pub fn sshNextStep(w: *Io.Writer, socket: []const u8, laptop_port: u16, user: []const u8, host: []const u8, token_file: ?[]const u8) Io.Writer.Error!void {
    try w.print("rweb: on your laptop, run (replace the host name if this machine is reached by another name):\n  ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -L ", .{});
    var buf: [1100]u8 = undefined;
    try shellQuote(w, std.fmt.bufPrint(&buf, "127.0.0.1:{d}:{s}", .{ laptop_port, socket }) catch socket);
    try w.writeByte(' ');
    try w.print("{s}@{s}", .{ plainName(user, "<you>"), plainName(host, "<this-machine>") });
    try w.print("\nrweb: then open http://127.0.0.1:{d}/ there and paste the token", .{laptop_port});
    if (token_file) |f| {
        try w.writeAll(" (`cat ");
        try shellQuote(w, f);
        try w.writeAll("` on this machine)");
    }
    try w.writeAll("\n");
}

// ---- refusals in plain words ----

/// What is wrong with a file or folder rweb refused, and the fix.
pub const explain = xfer.explain;

// ---- tests ----

const testing = std.testing;

test "config and socket paths follow XDG, then HOME; macOS keeps the ssh socket under config" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const linux: Env = .{ .os = .linux, .home = "/home/me", .uid = 1000 };
    try testing.expectEqualStrings("/home/me/.config/rweb", try configDir(a, linux, null));
    var x = linux;
    x.xdg_config_home = "/home/me/cfg/";
    try testing.expectEqualStrings("/home/me/cfg/rweb", try configDir(a, x, null));
    x.xdg_config_home = "relative/cfg"; // ignored, as the XDG rules say
    try testing.expectEqualStrings("/home/me/.config/rweb", try configDir(a, x, null));
    try testing.expectEqualStrings("/srv/rweb-cfg", try configDir(a, x, "/srv/rweb-cfg/"));
    try testing.expectError(error.NoHome, configDir(a, .{ .os = .linux }, null));
    try testing.expectError(error.NoHome, configDir(a, .{ .os = .linux, .home = "rel" }, null));
    try testing.expectEqualStrings("/run/user/1000/rweb/bridge.sock", try tailscaleSocket(a, linux));
    var r = linux;
    r.xdg_runtime_dir = "/run/user/1000/";
    try testing.expectEqualStrings("/run/user/1000/rweb/ssh.sock", try sshSocket(a, r, "/home/me/.config/rweb"));
    const mac: Env = .{ .os = .macos, .home = "/Users/me", .uid = 501 };
    try testing.expectEqualStrings("/Users/me/.config/rweb/run/ssh.sock", try sshSocket(a, mac, try configDir(a, mac, null)));
}

test "a made secret is 32 random bytes in base64url, 0600, made once and never overwritten" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var p: xfer.Problem = .{};
    // Its folders are made 0700, under folders that passed the checks.
    const path = try arena.print("{s}/cfg/rweb/token", .{root});
    try testing.expect(try ensureSecretFile(arena, io, path, &p));
    const first = try xfer.readPrivateFile(arena, io, path, 4096, &p);
    try testing.expectEqual(@as(usize, secret_len + 1), first.len);
    try testing.expectEqual(@as(usize, 43), secret_len);
    for (first[0..secret_len]) |c| try testing.expect(std.ascii.isAlphanumeric(c) or c == '-' or c == '_');
    var z: [512:0]u8 = undefined;
    try testing.expectEqual(@as(u32, 0o600), (try xfer.statAt(tmp.dir.handle, "cfg/rweb/token")).mode & 0o777);
    try testing.expectEqual(@as(u32, 0o700), (try xfer.statAt(tmp.dir.handle, "cfg/rweb")).mode & 0o777);
    // A second start keeps it.
    try testing.expect(!try ensureSecretFile(arena, io, path, &p));
    try testing.expectEqualStrings(first, try xfer.readPrivateFile(arena, io, path, 4096, &p));
    // Another one differs.
    const other = try arena.print("{s}/cfg/rweb/backend-secret", .{root});
    try testing.expect(try ensureSecretFile(arena, io, other, &p));
    try testing.expect(!std.mem.eql(u8, first, try xfer.readPrivateFile(arena, io, other, 4096, &p)));
    // A link in its place is never written through, and a file of the user's is never replaced.
    try tmp.dir.createDirPath(io, "cfg/rweb");
    try tmp.dir.symLink(io, "token", "cfg/rweb/linked", .{});
    try testing.expect(!try ensureSecretFile(arena, io, try arena.print("{s}/cfg/rweb/linked", .{root}), &p));
    try testing.expectEqualStrings(first, try xfer.readPrivateFile(arena, io, path, 4096, &p));
    // A folder others can enter is refused, with where.
    try tmp.dir.createDirPath(io, "open");
    try sys.chmod(try std.fmt.bufPrintSentinel(&z, "{s}/open", .{root}, 0), 0o755);
    try testing.expectError(error.TooOpen, ensureSecretFile(arena, io, try arena.print("{s}/open/token", .{root}), &p));
}

test "the printed next steps name files, never secrets, and quote what a shell would split" {
    var buf: [2048]u8 = undefined;
    var w: Io.Writer = .fixed(&buf);
    try tailscaleNextStep(&w, .{ .unix = "/run/user/1000/rweb/bridge.sock" }, null, "box.tail1.ts.net");
    try testing.expectEqualStrings(
        "rweb: if Tailscale Serve is not set up for rweb yet, run this once:\n" ++
            "  sudo tailscale serve --bg --https=12443 unix:/run/user/1000/rweb/bridge.sock\n" ++
            "rweb: then open https://box.tail1.ts.net:12443/ (Tailscale Serve keeps this setting; `tailscale serve --https=12443 off` removes it)\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try tailscaleNextStep(&w, .{ .unix = "/run/user/1000/rweb/bridge.sock" }, null, "box\x1b]0;x\x07.ts.net");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "open https://<this machine's Tailscale name>:12443/") != null);
    w = .fixed(&buf);
    try tailscaleNextStep(&w, .{ .tcp = 7695 }, "/Users/me/.config/rweb/backend-secret", null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "  tailscale serve --bg --https=12443 \"http://127.0.0.1:7695/$(cat /Users/me/.config/rweb/backend-secret)\"\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "sudo") == null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "for a Mac where you are the only account") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "reset") == null);
    w = .fixed(&buf);
    try sshNextStep(&w, "/run/user/1000/rweb/ssh.sock", 7700, "me", "box", "/home/me/.config/rweb/token");
    try testing.expectEqualStrings(
        "rweb: on your laptop, run (replace the host name if this machine is reached by another name):\n" ++
            "  ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 -L 127.0.0.1:7700:/run/user/1000/rweb/ssh.sock me@box\n" ++
            "rweb: then open http://127.0.0.1:7700/ there and paste the token (`cat /home/me/.config/rweb/token` on this machine)\n",
        w.buffered(),
    );
    w = .fixed(&buf);
    try sshNextStep(&w, "/Users/me/My Config/run/ssh.sock", 7800, "me", "mac.local", "/Users/me/My Config/token");
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "-L '127.0.0.1:7800:/Users/me/My Config/run/ssh.sock' me@mac.local") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "`cat '/Users/me/My Config/token'`") != null);
    // A host or user name with anything a shell or terminal could read into it is a placeholder.
    w = .fixed(&buf);
    try sshNextStep(&w, "/run/user/1000/rweb/ssh.sock", 7700, "me", "box\x1b[2J;rm -rf", null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "ssh.sock me@<this-machine>\n") != null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "\x1b") == null);
    w = .fixed(&buf);
    try sshNextStep(&w, "/run/user/1000/rweb/ssh.sock", 7700, "m e", "box-1.example_net", null);
    try testing.expect(std.mem.indexOf(u8, w.buffered(), "ssh.sock <you>@box-1.example_net\n") != null);
    w = .fixed(&buf);
    try shellQuote(&w, "it's");
    try testing.expectEqualStrings("'it'\\''s'", w.buffered());
}

test "token mode's default hosts: loopback names, with a TCP listener's port or any port behind a socket" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    const tcp = try tokenHosts(a, 7700);
    try testing.expectEqual(@as(usize, 3), tcp.len);
    try testing.expectEqualStrings("127.0.0.1:7700", tcp[0]);
    try testing.expectEqualStrings("localhost:7700", tcp[1]);
    try testing.expectEqualStrings("[::1]:7700", tcp[2]);
    const sock = try tokenHosts(a, null);
    try testing.expectEqualStrings("127.0.0.1", sock[0]);
    try testing.expectEqualStrings("[::1]", sock[2]);
}
