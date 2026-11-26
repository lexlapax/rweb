//! Command-line settings for the bridge, parsed without touching the system so the rules
//! (what must be given, what defaults to the safe side) can be tested.

const std = @import("std");
const Allocator = std.mem.Allocator;
const access = @import("access.zig");

pub const usage =
    \\rweb: shows Rex terminal sessions in a web browser
    \\
    \\  rweb (--listen-unix PATH | --listen-tcp PORT) [options]
    \\  rweb --version
    \\
    \\Where to listen (exactly one):
    \\  --listen-unix PATH        unix socket (absolute path, no links on it), created 0600 in a
    \\                            0700 directory of yours under folders only you or root can change
    \\  --listen-tcp PORT         loopback TCP only (127.0.0.1); 0 picks a port
    \\
    \\Who may connect:
    \\  --owner LOGIN             required Tailscale-User-Login (Tailscale Serve sets it); needs
    \\                            --allow-host
    \\  --owner-from-tailscale    take the owner from this node's own Tailscale login (`tailscale status`)
    \\  --token TOKEN             shared secret in the `token` query or `rweb-token` header, 16+
    \\                            letters, digits, - or _ (tests only: it shows in the process
    \\                            list; prefer --token-file)
    \\  --token-file PATH         the same, read from a file only you can read (mode 0600)
    \\  --random-token            make a token and print the URL when standard error is a
    \\                            terminal (loopback tests)
    \\  --own-address IP          this node's Tailscale address (repeatable); requests from
    \\                            it are refused. With --owner and none given, `tailscale ip`
    \\                            is asked; if that fails the bridge will not start
    \\  --allow-own-address       accept requests from this node's own address (single-user hosts)
    \\  --allow-peer-uid N|self   unix socket peers allowed (default: 0, tailscaled)
    \\  --allow-host NAME         the only Host names requests may be for (repeatable); with
    \\                            --owner-from-tailscale this node's own DNS name is added
    \\  --backend-secret-file PATH
    \\                            loopback TCP behind Tailscale Serve: the file (mode 0600, 32+
    \\                            letters, digits, - or _) holds a secret first path segment; point
    \\                            Serve at http://127.0.0.1:PORT/<secret>. Without it any local
    \\                            process can forge the owner's identity headers
    \\  --allow-forgeable-loopback-identity
    \\                            loopback TCP with --owner and no backend secret, for tests on a
    \\                            machine with one user
    \\
    \\Behaviour:
    \\  --rex-socket PATH         Rex's unix socket (default: the Mac app's, else XDG_RUNTIME_DIR's)
    \\  --tailscale PATH          the tailscale program to ask for this node's login, name and
    \\                            addresses (absolute; default: the first of a fixed list of
    \\                            install locations that exists, never PATH). It and its folders
    \\                            must be root's or yours, and no ACL may let another user change them
    \\  --observe-only            never write, resize or change anything in Rex
    \\  --history-lines N         scrollback rows sent when a terminal opens (default 1000)
    \\  --debug-input             log what browsers send (typed text included): for testing a keyboard, never for deployment
    \\  --enable-file-transfer    let the page download any file the terminal's user can read (through
    \\                            Rex) and, with --upload-dir, upload into one folder. Off by default
    \\  --upload-dir PATH         the only folder uploads may go to (absolute; made 0700 if missing)
    \\  --max-transfer-mb N       the most one transfer may carry, either way (default 256)
    \\  --enable-lab              serve the transport and selection lab pages (diagnostics; off by default)
    \\
;

pub const Listen = union(enum) { unix: []const u8, tcp: u16 };

pub const Parsed = struct {
    rex_socket: ?[]const u8 = null,
    /// `--tailscale`: the program to run, by absolute path. Null: the fixed install locations.
    tailscale: ?[]const u8 = null,
    listen: Listen,
    owner: ?[]const u8 = null,
    owner_from_tailscale: bool = false,
    token: ?[]const u8 = null,
    token_file: ?[]const u8 = null,
    random_token: bool = false,
    allowed_hosts: []const []const u8 = &.{},
    backend_secret_file: ?[]const u8 = null,
    allow_forgeable_loopback_identity: bool = false,
    lab: bool = false,
    enable_file_transfer: bool = false,
    upload_dir: ?[]const u8 = null,
    max_transfer_mb: u32 = 256,
    own_addresses: []const []const u8 = &.{},
    allow_own_address: bool = false,
    detect_own_addresses: bool = false,
    /// Null for a TCP listener (no peer check); `self` is replaced by the caller's uid.
    peer_uids: ?[]const PeerUid = null,
    observe_only: bool = false,
    history_lines: u32 = 1000,
    debug_input: bool = false,
};

pub const PeerUid = union(enum) { uid: u32, self };

/// The shortest token accepted, from `--token` or `--token-file`.
pub const min_token_len = 16;

/// Whether a secret holds only characters that are safe in a URL path, a query and a cookie:
/// letters, digits, `-` and `_` (so no CR or LF can reach a header).
pub fn isSafeSecret(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

pub const Error = error{
    Usage,
    /// `--version`: print the version and exit.
    Version,
    NoListener,
    TwoListeners,
    NoAccessRule,
    BadNumber,
    MissingValue,
    UnknownOption,
    /// A loopback TCP listener with an owner rule needs `--backend-secret-file`.
    NeedBackendSecret,
    /// `--own-address` that is not an IP address.
    BadAddress,
    /// `--owner` without any `--allow-host`: any Host name, a rebound one included, would be accepted.
    NeedAllowHost,
    /// `--token` that is too short or holds characters other than letters, digits, `-` and `_`.
    BadToken,
    /// `--listen-unix` or `--tailscale` with a relative path.
    NotAbsolute,
} || Allocator.Error;

/// Parse `args` (without the program name). Slices in the result point into `args`, except
/// the lists, which are allocated from `arena`.
pub fn parse(arena: Allocator, args: []const []const u8) Error!Parsed {
    var listen: ?Listen = null;
    var p: Parsed = .{ .listen = undefined };
    var own: std.ArrayList([]const u8) = .empty;
    var uids: std.ArrayList(PeerUid) = .empty;
    var hosts: std.ArrayList([]const u8) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const eql = std.mem.eql;
        if (eql(u8, a, "--help") or eql(u8, a, "-h")) return error.Usage;
        if (eql(u8, a, "--version")) return error.Version;
        if (eql(u8, a, "--listen-unix")) {
            if (listen != null) return error.TwoListeners;
            const path = try value(args, &i);
            // Serve and the bridge must name the same file, whatever the working directory.
            if (!isAbsolute(path)) return error.NotAbsolute;
            listen = .{ .unix = path };
        } else if (eql(u8, a, "--listen-tcp")) {
            if (listen != null) return error.TwoListeners;
            listen = .{ .tcp = std.fmt.parseInt(u16, try value(args, &i), 10) catch return error.BadNumber };
        } else if (eql(u8, a, "--owner")) {
            p.owner = try value(args, &i);
        } else if (eql(u8, a, "--owner-from-tailscale")) {
            p.owner_from_tailscale = true;
        } else if (eql(u8, a, "--token")) {
            const v = try value(args, &i);
            // The same rules as a token file: it reaches a cookie and a URL, so no CR, LF or space.
            if (v.len < min_token_len or !isSafeSecret(v)) return error.BadToken;
            p.token = v;
        } else if (eql(u8, a, "--token-file")) {
            p.token_file = try value(args, &i);
        } else if (eql(u8, a, "--allow-host")) {
            try hosts.append(arena, try value(args, &i));
        } else if (eql(u8, a, "--backend-secret-file")) {
            p.backend_secret_file = try value(args, &i);
        } else if (eql(u8, a, "--allow-forgeable-loopback-identity")) {
            p.allow_forgeable_loopback_identity = true;
        } else if (eql(u8, a, "--enable-file-transfer")) {
            p.enable_file_transfer = true;
        } else if (eql(u8, a, "--upload-dir")) {
            p.upload_dir = try value(args, &i);
        } else if (eql(u8, a, "--max-transfer-mb")) {
            p.max_transfer_mb = std.fmt.parseInt(u32, try value(args, &i), 10) catch return error.BadNumber;
            if (p.max_transfer_mb == 0 or p.max_transfer_mb > 4096) return error.BadNumber;
        } else if (eql(u8, a, "--enable-lab")) {
            p.lab = true;
        } else if (eql(u8, a, "--random-token")) {
            p.random_token = true;
        } else if (eql(u8, a, "--own-address")) {
            const v = try value(args, &i);
            // An address that does not parse would match nothing and quietly turn the rule off.
            if (!access.isAddress(v)) return error.BadAddress;
            try own.append(arena, v);
        } else if (eql(u8, a, "--allow-own-address")) {
            p.allow_own_address = true;
        } else if (eql(u8, a, "--allow-peer-uid")) {
            const v = try value(args, &i);
            if (eql(u8, v, "self")) try uids.append(arena, .self) else try uids.append(arena, .{ .uid = std.fmt.parseInt(u32, v, 10) catch return error.BadNumber });
        } else if (eql(u8, a, "--rex-socket")) {
            p.rex_socket = try value(args, &i);
        } else if (eql(u8, a, "--tailscale")) {
            p.tailscale = try value(args, &i);
            if (!isAbsolute(p.tailscale.?)) return error.NotAbsolute;
        } else if (eql(u8, a, "--observe-only")) {
            p.observe_only = true;
        } else if (eql(u8, a, "--debug-input")) {
            p.debug_input = true;
        } else if (eql(u8, a, "--history-lines")) {
            p.history_lines = std.fmt.parseInt(u32, try value(args, &i), 10) catch return error.BadNumber;
        } else return error.UnknownOption;
    }
    p.listen = listen orelse return error.NoListener;
    p.own_addresses = own.items;
    p.allowed_hosts = hosts.items;
    if (p.token != null and p.token_file != null) return error.Usage;
    // Transfers are a way to read and write files: only when asked for, never beside observe-only,
    // and uploads only into a folder that is named.
    if (p.upload_dir != null and !p.enable_file_transfer) return error.Usage;
    if (p.enable_file_transfer and p.observe_only) return error.Usage;
    if (p.upload_dir) |d| if (d.len == 0 or d[0] != '/') return error.Usage;

    switch (p.listen) {
        .unix => {
            // Tailscaled dials as root; anything else must be asked for.
            p.peer_uids = if (uids.items.len > 0) uids.items else &[_]PeerUid{.{ .uid = 0 }};
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and p.token_file == null and !p.random_token) return error.NoAccessRule;
            if (p.backend_secret_file != null) return error.Usage; // a unix socket has a real peer check
        },
        .tcp => {
            if (uids.items.len > 0) return error.Usage; // no peer check on TCP
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and p.token_file == null) p.random_token = true;
            // Any local process can send an owner's identity headers to a loopback port. The owner
            // rule is only worth having there when a secret path segment stands behind it.
            if ((p.owner != null or p.owner_from_tailscale) and p.backend_secret_file == null and !p.allow_forgeable_loopback_identity) return error.NeedBackendSecret;
        },
    }
    if (p.owner != null and p.owner_from_tailscale) return error.Usage;
    // An owner rule names the host it is for. (`--owner-from-tailscale` adds this node's DNS name.)
    if (p.owner != null and p.allowed_hosts.len == 0) return error.NeedAllowHost;
    if (p.token != null or p.token_file != null) p.random_token = false;
    // With an owner rule the own-address rule must be enforceable: fail closed.
    if ((p.owner != null or p.owner_from_tailscale) and !p.allow_own_address and p.own_addresses.len == 0) p.detect_own_addresses = true;
    return p;
}

fn isAbsolute(path: []const u8) bool {
    return path.len > 0 and path[0] == '/';
}

fn value(args: []const []const u8, i: *usize) Error![]const u8 {
    i.* += 1;
    if (i.* >= args.len) return error.MissingValue;
    return args[i.*];
}

// ---- tests ----

const testing = std.testing;

fn parseT(args: []const []const u8) Error!Parsed {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try parse(arena.allocator(), args);
    // Lists live in the arena: copy what the tests look at out of it.
    return .{
        .listen = p.listen,
        .owner = p.owner,
        .token = p.token,
        .random_token = p.random_token,
        .allow_own_address = p.allow_own_address,
        .backend_secret_file = p.backend_secret_file,
        .enable_file_transfer = p.enable_file_transfer,
        .upload_dir = p.upload_dir,
        .max_transfer_mb = p.max_transfer_mb,
        .allow_forgeable_loopback_identity = p.allow_forgeable_loopback_identity,
        .detect_own_addresses = p.detect_own_addresses,
        .observe_only = p.observe_only,
        .history_lines = p.history_lines,
        .tailscale = p.tailscale,
        .peer_uids = if (p.peer_uids) |u| (if (u.len == 1 and u[0] == .uid and u[0].uid == 0) &[_]PeerUid{.{ .uid = 0 }} else &[_]PeerUid{.self}) else null,
    };
}

test "a listener is required, and only one" {
    try testing.expectError(error.NoListener, parseT(&.{ "--owner", "a@b" }));
    try testing.expectError(error.TwoListeners, parseT(&.{ "--listen-tcp", "0", "--listen-unix", "/x" }));
}

test "--listen-unix and --tailscale take absolute paths only" {
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-unix", "rweb/b.sock", "--owner-from-tailscale" }));
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-unix", "./b.sock", "--owner-from-tailscale" }));
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-unix", "", "--owner-from-tailscale" }));
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-tcp", "0", "--tailscale", "tailscale" }));
    const p = try parseT(&.{ "--listen-unix", "/run/user/1000/rweb/b.sock", "--owner-from-tailscale", "--tailscale", "/usr/bin/tailscale" });
    try testing.expectEqualStrings("/usr/bin/tailscale", p.tailscale.?);
    try testing.expectEqualStrings("/run/user/1000/rweb/b.sock", p.listen.unix);
}

test "a unix socket needs an access rule and defaults to root as the only peer" {
    try testing.expectError(error.NoAccessRule, parseT(&.{ "--listen-unix", "/x/b.sock" }));
    const p = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example" });
    try testing.expectEqual(@as(u32, 0), p.peer_uids.?[0].uid);
    try testing.expect(p.detect_own_addresses); // fail closed: the own-address rule must be enforceable
    const q = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example", "--allow-own-address" });
    try testing.expect(!q.detect_own_addresses);
}

test "an --own-address that is not an address stops startup" {
    try testing.expectError(error.BadAddress, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example", "--own-address", "not-an-ip" }));
    try testing.expectError(error.BadAddress, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example", "--own-address", "100.64.0.5", "--own-address", "" }));
    const p = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example", "--own-address", "100.64.0.5", "--own-address", "fd7a:115c:a1e0::5" });
    try testing.expect(!p.detect_own_addresses); // the two addresses were kept: nothing to detect
}

test "loopback TCP without any rule gets a random token" {
    const p = try parseT(&.{ "--listen-tcp", "0" });
    try testing.expect(p.random_token);
    const q = try parseT(&.{ "--listen-tcp", "8080", "--token", "abcdefgh-0123456_" });
    try testing.expect(!q.random_token and std.mem.eql(u8, q.token.?, "abcdefgh-0123456_"));
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--allow-peer-uid", "0" }));
}

test "numbers and options are checked" {
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "70000" }));
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "0", "--history-lines", "x" }));
    try testing.expectError(error.MissingValue, parseT(&.{ "--listen-tcp", "0", "--owner" }));
    try testing.expectError(error.UnknownOption, parseT(&.{ "--listen-tcp", "0", "--nope" }));
    try testing.expectError(error.Usage, parseT(&.{"--help"}));
    try testing.expectError(error.Version, parseT(&.{"--version"}));
    try testing.expectError(error.Version, parseT(&.{ "--listen-tcp", "0", "--version" }));
    const p = try parseT(&.{ "--listen-tcp", "0", "--observe-only", "--history-lines", "50" });
    try testing.expect(p.observe_only and p.history_lines == 50);
}

test "owner from Tailscale counts as an owner rule" {
    const p = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner-from-tailscale" });
    try testing.expect(p.detect_own_addresses);
    try testing.expectError(error.Usage, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "a@b", "--allow-host", "box.example", "--owner-from-tailscale" }));
}

test "loopback TCP with an owner rule needs a backend secret, unless forgeability is accepted" {
    try testing.expectError(error.NeedBackendSecret, parseT(&.{ "--listen-tcp", "7695", "--owner-from-tailscale" }));
    try testing.expectError(error.NeedBackendSecret, parseT(&.{ "--listen-tcp", "7695", "--owner", "a@b", "--allow-host", "box.example", "--allow-own-address" }));
    const ok = try parseT(&.{ "--listen-tcp", "7695", "--owner-from-tailscale", "--backend-secret-file", "/x/secret" });
    try testing.expect(ok.backend_secret_file != null);
    const test_only = try parseT(&.{ "--listen-tcp", "7695", "--owner", "a@b", "--allow-host", "box.example", "--allow-forgeable-loopback-identity" });
    try testing.expect(test_only.allow_forgeable_loopback_identity);
    // A token-only loopback listener is the test setup and needs none of it.
    _ = try parseT(&.{ "--listen-tcp", "0" });
    // A unix socket has a real peer check: a backend secret there is a mistake.
    try testing.expectError(error.Usage, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "a@b", "--allow-host", "box.example", "--backend-secret-file", "/x/s" }));
}

test "token and token file are exclusive; hosts and lab are carried" {
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--token", "abcdefgh-0123456_", "--token-file", "/x" }));
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const p = try parse(arena.allocator(), &.{ "--listen-tcp", "0", "--allow-host", "a.example", "--allow-host", "b.example", "--enable-lab" });
    try testing.expectEqual(@as(usize, 2), p.allowed_hosts.len);
    try testing.expect(p.lab);
}

test "file transfer is off unless asked for, and uploads need a named absolute folder" {
    const off = try parseT(&.{ "--listen-tcp", "0" });
    try testing.expect(!off.enable_file_transfer and off.upload_dir == null);
    const on = try parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--upload-dir", "/home/me/Uploads", "--max-transfer-mb", "50" });
    try testing.expect(on.enable_file_transfer);
    try testing.expectEqualStrings("/home/me/Uploads", on.upload_dir.?);
    try testing.expectEqual(@as(u32, 50), on.max_transfer_mb);
    // A folder without the switch, a relative folder, an empty one, observe-only with transfer, silly sizes.
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--upload-dir", "/x" }));
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--upload-dir", "x" }));
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--upload-dir", "" }));
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--observe-only" }));
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "0", "--max-transfer-mb", "0" }));
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "0", "--max-transfer-mb", "99999" }));
}

test "an owner rule needs an allowed host, unless it comes from Tailscale" {
    try testing.expectError(error.NeedAllowHost, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com" }));
    try testing.expectError(error.NeedAllowHost, parseT(&.{ "--listen-tcp", "7695", "--owner", "a@b", "--allow-forgeable-loopback-identity" }));
    _ = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-host", "box.example" });
    // The node's own DNS name is added at startup.
    _ = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner-from-tailscale" });
    // A token-only listener needs none.
    _ = try parseT(&.{ "--listen-tcp", "0", "--token", "0123456789abcdef" });
}

test "--token follows the token-file rules" {
    for ([_][]const u8{ "short", "0123456789abcde", "0123456789abcdef\r\nSet-Cookie: x=y", "0123456789abcdef ", "0123456789abcdef;", "0123456789abcdef/x", "0123456789abcdéf" }) |bad| {
        try testing.expectError(error.BadToken, parseT(&.{ "--listen-tcp", "0", "--token", bad }));
    }
    const ok = try parseT(&.{ "--listen-tcp", "0", "--token", "Abc-def_0123456789" });
    try testing.expectEqualStrings("Abc-def_0123456789", ok.token.?);
    try testing.expect(isSafeSecret("a-Z_9") and !isSafeSecret("a b") and !isSafeSecret("a\n"));
}
