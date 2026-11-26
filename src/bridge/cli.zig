//! Command-line settings for the bridge, parsed without touching the system so the rules
//! (what must be given, what defaults to the safe side) can be tested.

const std = @import("std");
const Allocator = std.mem.Allocator;
const access = @import("access.zig");
const layout = @import("layout.zig");

pub const short_usage =
    \\rweb shows your Rex terminals in a web browser.
    \\
    \\  rweb tailscale    to your own devices, through Tailscale Serve
    \\  rweb ssh          through an SSH tunnel from your laptop
    \\
    \\Each sets everything up and prints the one command left to run.
    \\rweb --help lists every option.
    \\
;

pub const usage =
    \\rweb: shows Rex terminal sessions in a web browser
    \\
    \\  rweb tailscale [options]
    \\      Behind Tailscale Serve; only your own Tailscale login gets in.
    \\      Linux: a unix socket, $XDG_RUNTIME_DIR/rweb/bridge.sock.
    \\      macOS: 127.0.0.1:7695 behind a secret in <config>/backend-secret.
    \\      Prints the `tailscale serve` line to run once and the address to open.
    \\  rweb ssh [options]
    \\      For an SSH tunnel: a unix socket only your own user can connect to
    \\      (Linux $XDG_RUNTIME_DIR/rweb/ssh.sock, macOS <config>/run/ssh.sock) and a
    \\      token in <config>/token. Prints the `ssh` line for your laptop.
    \\  rweb --version
    \\
    \\  <config> is $XDG_CONFIG_HOME/rweb, else ~/.config/rweb. A missing token or secret
    \\  is made there (32 random bytes, mode 0600), and missing folders 0700.
    \\
    \\Layout options:
    \\  --config-dir PATH         <config> somewhere else (absolute; for example when your home
    \\                            folder is on a network disk, which rweb does not trust)
    \\  --port N                  rweb tailscale on macOS: the loopback port Serve forwards to
    \\                            (default 7695; Linux uses a unix socket). rweb ssh: the laptop's
    \\                            port in the printed line (7700)
    \\
    \\Advanced (unusual setups; each overrides what a layout sets):
    \\  --listen-unix PATH        unix socket (absolute path), created 0600 in a 0700 directory of
    \\                            yours that is not a link, under folders only you or root can
    \\                            change (links of yours or root's above it are followed)
    \\  --listen-tcp PORT         loopback TCP only (127.0.0.1 and ::1); 0 picks a port. Another
    \\                            account can take a TCP port while rweb is down: prefer a socket
    \\  --owner LOGIN             required Tailscale-User-Login (Tailscale Serve sets it); needs
    \\                            --allow-host
    \\  --owner-from-tailscale    take the owner from this node's own Tailscale login
    \\  --token-file PATH         a shared secret, read from a file only you can read (mode 0600,
    \\                            32+ letters, digits, - or _), entered on the page's token form
    \\  --own-address IP          this node's Tailscale address (repeatable); requests from it are
    \\                            refused. With an owner rule and none given, `tailscale ip` is
    \\                            asked (and asked again every minute while rweb runs)
    \\  --allow-peer-uid N|self   unix socket peers allowed (default: 0, tailscaled; rweb ssh: self)
    \\  --allow-host NAME         the only Host names requests may be for (repeatable); with
    \\                            --owner-from-tailscale this node's own DNS name is added
    \\  --backend-secret-file PATH
    \\                            loopback TCP behind Tailscale Serve: the file (mode 0600, 32+
    \\                            letters, digits, - or _) holds a secret first path segment; point
    \\                            Serve at http://127.0.0.1:PORT/<secret>. Without it any local
    \\                            process can forge the owner's identity headers
    \\  --rex-socket PATH         Rex's unix socket (default: the Mac app's, else XDG_RUNTIME_DIR's)
    \\  --tailscale PATH          the tailscale program to ask for this node's login, name and
    \\                            addresses (absolute; default: the first of a fixed list of
    \\                            install locations that exists, never PATH). It and its folders
    \\                            must be root's or yours, and no ACL may let another user change them
    \\  --observe-only            never write, resize or change anything in Rex
    \\  --history-lines N         scrollback rows sent when a terminal opens (default 1000)
    \\  --enable-file-transfer    let the page download any file the terminal's user can read (through
    \\                            Rex) and, with --upload-dir, upload into one folder. Off by default
    \\  --upload-dir PATH         the only folder uploads may go to (absolute; made 0700 if missing)
    \\  --max-transfer-mb N       the most one transfer may carry, either way (default 256)
    \\  --enable-lab              serve the transport and selection lab pages (diagnostics; off by default)
    \\  --debug-input             log what browsers send (typed text included): for testing a keyboard
    \\
    \\For tests (never in a service):
    \\  --token TOKEN             a shared secret on the command line, where every user on the
    \\                            machine can read it; 32+ letters, digits, - or _
    \\  --random-token            make a token and print the URL when standard error is a terminal
    \\  --allow-own-address       accept requests from this node's own Tailscale address: any local
    \\                            account can then act as you through Serve
    \\  --allow-forgeable-loopback-identity
    \\                            loopback TCP with --owner and no backend secret: any local process
    \\                            can then forge your identity
    \\
;

pub const Listen = union(enum) { unix: []const u8, tcp: u16 };

/// How rweb was asked to run: one of the two layouts, or with the advanced options alone.
pub const Command = enum { advanced, tailscale, ssh };

pub const Parsed = struct {
    command: Command = .advanced,
    /// `<config>`, for a layout.
    config_dir: ?[]const u8 = null,
    /// `rweb ssh`: the laptop's port in the printed `ssh -L` line.
    ssh_port: u16 = layout.default_ssh_port,
    /// The layout chose these secret files, so rweb makes them when missing. A file named on the
    /// command line is never made: it must be there.
    make_token_file: bool = false,
    make_backend_secret: bool = false,
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
pub const min_token_len = 32;

/// Whether a secret holds only characters that are safe in a URL path, a query and a cookie:
/// letters, digits, `-` and `_` (so no CR or LF can reach a header).
pub fn isSafeSecret(text: []const u8) bool {
    for (text) |c| if (!std.ascii.isAlphanumeric(c) and c != '-' and c != '_') return false;
    return true;
}

pub const Error = error{
    Usage,
    /// No arguments at all: the short help.
    ShortHelp,
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
    /// A path option with a relative path.
    NotAbsolute,
    /// `--token` and `--token-file` together.
    TwoTokens,
    /// `--owner` and `--owner-from-tailscale` together.
    TwoOwners,
    UploadDirNeedsTransfer,
    TransferWithObserveOnly,
    /// `--allow-peer-uid` on a TCP listener, which has no peer to check.
    PeerUidOnTcp,
    /// `--backend-secret-file` on a unix socket, which has a real peer check instead.
    BackendSecretOnUnix,
    /// `--port` or `--config-dir` without `tailscale` or `ssh`.
    NeedsLayout,
    /// A layout needs `<config>` and neither HOME nor XDG_CONFIG_HOME says where it is.
    NoHome,
    /// `rweb tailscale --port` on Linux, where the layout is a unix socket.
    PortNeedsMac,
    /// A unix socket path longer than the system takes (`Diag.arg` is the path).
    SocketPathTooLong,
} || Allocator.Error;

/// What a refusal was about, for its message: the argument that was wrong.
pub const Diag = struct { arg: []const u8 = "" };

/// What a refusal says, in plain words with the fix (the caller names `Diag.arg` beside it).
pub fn explain(e: Error) []const u8 {
    return switch (e) {
        error.NoListener => "say how rweb should run: `rweb tailscale`, `rweb ssh`, or (advanced) --listen-unix PATH or --listen-tcp PORT",
        error.TwoListeners => "give only one of --listen-unix and --listen-tcp",
        error.NoAccessRule => "a unix socket needs a rule for who may connect: --owner-from-tailscale, --owner LOGIN with --allow-host NAME, or --token-file PATH (`rweb tailscale` and `rweb ssh` set one)",
        error.BadNumber => "takes a number, and this one is out of range",
        error.MissingValue => "needs a value after it",
        error.UnknownOption => "this is not an option rweb knows",
        error.NeedBackendSecret => "an owner rule on a TCP port needs --backend-secret-file PATH: without it any program on this machine can send your Tailscale identity. `rweb tailscale` sets this up on macOS",
        error.BadAddress => "takes an IP address (this node's Tailscale address, from `tailscale ip`)",
        error.NeedAllowHost => "--owner needs --allow-host NAME (this node's DNS name, repeatable): without it a page on any host name, a rebound DNS name included, reaches the bridge with the owner's identity. --owner-from-tailscale adds this node's name itself",
        error.BadToken => "must be at least 32 characters of letters, digits, - and _; better, use `rweb ssh`, which makes a token file",
        error.NotAbsolute => "this option takes an absolute path (starting with /)",
        error.TwoTokens => "give either --token or --token-file, not both",
        error.TwoOwners => "give either --owner or --owner-from-tailscale, not both",
        error.UploadDirNeedsTransfer => "--upload-dir needs --enable-file-transfer",
        error.TransferWithObserveOnly => "--enable-file-transfer cannot be used with --observe-only",
        error.PeerUidOnTcp => "--allow-peer-uid is for a unix socket; a TCP port cannot tell who connects",
        error.BackendSecretOnUnix => "--backend-secret-file is for a TCP port; a unix socket checks who connects instead",
        error.NeedsLayout => "--port and --config-dir go with `rweb tailscale` or `rweb ssh`",
        error.NoHome => "HOME is not set, so rweb cannot tell where to keep its files; set HOME or pass --config-dir PATH",
        error.PortNeedsMac => "rweb tailscale takes --port on macOS only. On Linux it listens on a unix socket: a port would need a backend secret in the Tailscale Serve target, which other accounts on this machine can read. To use a port anyway, give --listen-tcp PORT and --backend-secret-file PATH",
        error.SocketPathTooLong => "is too long for a unix socket path (at most 103 bytes on macOS, 107 on Linux)",
        error.Usage, error.ShortHelp, error.Version => "",
        error.OutOfMemory => "out of memory",
    };
}

/// What a refusal says about the argument `arg` it names: `explain`, except that a number out of
/// range says what that option takes.
pub fn explainArg(e: Error, arg: []const u8) []const u8 {
    if (e == error.BadNumber) {
        const eql = std.mem.eql;
        if (eql(u8, arg, "--listen-tcp") or eql(u8, arg, "--port")) return "takes a port number, 0 to 65535";
        if (eql(u8, arg, "--max-transfer-mb")) return "takes a number of megabytes, 1 to 4096";
        if (eql(u8, arg, "--allow-peer-uid")) return "takes a user id (a number) or `self`";
        if (eql(u8, arg, "--history-lines")) return "takes a number of lines, 0 to 4294967295";
    }
    return explain(e);
}

/// The longest unix socket path `os` takes, NUL included (`sockaddr_un.sun_path`).
pub fn maxUnixPath(os: std.Target.Os.Tag) usize {
    return if (os.isDarwin()) 104 else 108;
}

/// Parse `args` (without the program name) with the advanced options' defaults only (the tests).
pub fn parse(arena: Allocator, args: []const []const u8) Error!Parsed {
    var d: Diag = .{};
    return parseEnv(arena, args, .{}, &d);
}

/// Parse `args` (without the program name). A layout command fills in, from `env`, whatever its
/// options did not give. Slices in the result point into `args`, except the lists and the paths a
/// layout makes, which are allocated from `arena`. On failure `diag.arg` names the argument.
pub fn parseEnv(arena: Allocator, args: []const []const u8, env: layout.Env, diag: *Diag) Error!Parsed {
    if (args.len == 0) return error.ShortHelp;
    if (std.mem.eql(u8, args[0], "help")) return error.Usage;
    var listen: ?Listen = null;
    var p: Parsed = .{ .listen = undefined };
    var own: std.ArrayList([]const u8) = .empty;
    var uids: std.ArrayList(PeerUid) = .empty;
    var hosts: std.ArrayList([]const u8) = .empty;
    var port: ?u16 = null;
    var i: usize = 0;
    if (std.mem.eql(u8, args[0], "tailscale")) {
        p.command = .tailscale;
        i = 1;
    } else if (std.mem.eql(u8, args[0], "ssh")) {
        p.command = .ssh;
        i = 1;
    }
    while (i < args.len) : (i += 1) {
        const a = args[i];
        diag.arg = a;
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
        } else if (eql(u8, a, "--port")) {
            port = std.fmt.parseInt(u16, try value(args, &i), 10) catch return error.BadNumber;
        } else if (eql(u8, a, "--config-dir")) {
            p.config_dir = try value(args, &i);
            if (!isAbsolute(p.config_dir.?)) return error.NotAbsolute;
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
    diag.arg = "";

    // ---- a layout fills in what was not given ----
    switch (p.command) {
        .advanced => if (port != null or p.config_dir != null) return error.NeedsLayout,
        .tailscale => {
            // On Linux the layout is a unix socket; a port there is the advanced options' choice.
            if (port != null and !env.os.isDarwin()) {
                diag.arg = "--port";
                return error.PortNeedsMac;
            }
            const config = try layout.configDir(arena, env, p.config_dir);
            p.config_dir = config;
            if (listen == null) listen = if (port != null or env.os.isDarwin())
                .{ .tcp = port orelse layout.default_tailscale_port }
            else
                .{ .unix = try layout.tailscaleSocket(arena, env) };
            // The identity rule is the layout's: kept unless another owner is named.
            if (p.owner == null) p.owner_from_tailscale = true;
            if (listen.? == .tcp and p.backend_secret_file == null and !p.allow_forgeable_loopback_identity) {
                p.backend_secret_file = try arena.print("{s}/backend-secret", .{config});
                p.make_backend_secret = true;
            }
        },
        .ssh => {
            const config = try layout.configDir(arena, env, p.config_dir);
            p.config_dir = config;
            if (port) |n| p.ssh_port = n;
            if (listen == null) listen = .{ .unix = try layout.sshSocket(arena, env, config) };
            if (listen.? == .unix and uids.items.len == 0) try uids.append(arena, .self);
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and p.token_file == null and !p.random_token) {
                p.token_file = try arena.print("{s}/token", .{config});
                p.make_token_file = true;
            }
        },
    }

    p.listen = listen orelse return error.NoListener;
    // Checked before anything is made: a path the system cannot bind fails only after its folders
    // and the token were made otherwise.
    if (p.listen == .unix and p.listen.unix.len >= maxUnixPath(env.os)) {
        diag.arg = p.listen.unix;
        return error.SocketPathTooLong;
    }
    p.own_addresses = own.items;
    p.allowed_hosts = hosts.items;
    if (p.token != null and p.token_file != null) return error.TwoTokens;
    // Transfers are a way to read and write files: only when asked for, never beside observe-only,
    // and uploads only into a folder that is named.
    if (p.upload_dir != null and !p.enable_file_transfer) return error.UploadDirNeedsTransfer;
    if (p.enable_file_transfer and p.observe_only) return error.TransferWithObserveOnly;
    if (p.upload_dir) |d| if (d.len == 0 or d[0] != '/') {
        diag.arg = "--upload-dir";
        return error.NotAbsolute;
    };

    switch (p.listen) {
        .unix => {
            // Tailscaled dials as root; anything else must be asked for.
            p.peer_uids = if (uids.items.len > 0) uids.items else &[_]PeerUid{.{ .uid = 0 }};
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and p.token_file == null and !p.random_token) return error.NoAccessRule;
            if (p.backend_secret_file != null) return error.BackendSecretOnUnix; // a unix socket has a real peer check
        },
        .tcp => {
            if (uids.items.len > 0) return error.PeerUidOnTcp; // no peer check on TCP
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and p.token_file == null) p.random_token = true;
            // Any local process can send an owner's identity headers to a loopback port. The owner
            // rule is only worth having there when a secret path segment stands behind it.
            if ((p.owner != null or p.owner_from_tailscale) and p.backend_secret_file == null and !p.allow_forgeable_loopback_identity) return error.NeedBackendSecret;
        },
    }
    if (p.owner != null and p.owner_from_tailscale) return error.TwoOwners;
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
    const q = try parseT(&.{ "--listen-tcp", "8080", "--token", "abcdefgh-0123456_abcdefgh-0123456" });
    try testing.expect(!q.random_token and std.mem.eql(u8, q.token.?, "abcdefgh-0123456_abcdefgh-0123456"));
    try testing.expectError(error.PeerUidOnTcp, parseT(&.{ "--listen-tcp", "0", "--allow-peer-uid", "0" }));
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
    try testing.expectError(error.TwoOwners, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "a@b", "--allow-host", "box.example", "--owner-from-tailscale" }));
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
    try testing.expectError(error.BackendSecretOnUnix, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "a@b", "--allow-host", "box.example", "--backend-secret-file", "/x/s" }));
}

test "token and token file are exclusive; hosts and lab are carried" {
    try testing.expectError(error.TwoTokens, parseT(&.{ "--listen-tcp", "0", "--token", "abcdefgh-0123456_abcdefgh-0123456", "--token-file", "/x" }));
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
    try testing.expectError(error.UploadDirNeedsTransfer, parseT(&.{ "--listen-tcp", "0", "--upload-dir", "/x" }));
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--upload-dir", "x" }));
    try testing.expectError(error.NotAbsolute, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--upload-dir", "" }));
    try testing.expectError(error.TransferWithObserveOnly, parseT(&.{ "--listen-tcp", "0", "--enable-file-transfer", "--observe-only" }));
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
    _ = try parseT(&.{ "--listen-tcp", "0", "--token", "0123456789abcdef0123456789abcdef" });
}

test "--token follows the token-file rules" {
    const b = "0123456789abcdef0123456789abcdef";
    for ([_][]const u8{ "short", "0123456789abcdef", b[0..31], b ++ "\r\nSet-Cookie: x=y", b ++ " ", b ++ ";", b ++ "/x", b ++ "é" }) |bad| {
        try testing.expectError(error.BadToken, parseT(&.{ "--listen-tcp", "0", "--token", bad }));
    }
    const ok = try parseT(&.{ "--listen-tcp", "0", "--token", "Abc-def_0123456789Abc-def_0123456789" });
    try testing.expectEqualStrings("Abc-def_0123456789Abc-def_0123456789", ok.token.?);
    try testing.expect(isSafeSecret("a-Z_9") and !isSafeSecret("a b") and !isSafeSecret("a\n"));
}

fn parseL(arena: Allocator, args: []const []const u8, env: layout.Env) Error!Parsed {
    var d: Diag = .{};
    return parseEnv(arena, args, env, &d);
}

const linux_env: layout.Env = .{ .os = .linux, .home = "/home/me", .xdg_runtime_dir = "/run/user/1000", .uid = 1000 };
const mac_env: layout.Env = .{ .os = .macos, .home = "/Users/me", .uid = 501 };

test "no arguments is the short help, which leads with the two commands" {
    try testing.expectError(error.ShortHelp, parse(testing.allocator, &.{}));
    const t = std.mem.indexOf(u8, short_usage, "rweb tailscale").?;
    const s = std.mem.indexOf(u8, short_usage, "rweb ssh").?;
    try testing.expect(t < 120 and s < 200);
    // The full help: the commands first, then Advanced, then the test-only options in their group.
    const adv = std.mem.indexOf(u8, usage, "\nAdvanced").?;
    const tests_at = std.mem.indexOf(u8, usage, "\nFor tests").?;
    try testing.expect(std.mem.indexOf(u8, usage, "rweb tailscale [options]").? < adv and adv < tests_at);
    for ([_][]const u8{ "--token TOKEN", "--random-token", "--allow-own-address", "--allow-forgeable-loopback-identity" }) |o| try testing.expect(std.mem.indexOf(u8, usage, o).? > tests_at);
    for ([_][]const u8{ "--listen-unix", "--listen-tcp", "--owner LOGIN", "--token-file", "--backend-secret-file", "--rex-socket", "--enable-file-transfer" }) |o| {
        const at = std.mem.indexOf(u8, usage, o).?;
        try testing.expect(at > adv and at < tests_at);
    }
}

test "rweb tailscale: a socket and this node's login on Linux, a port and a made secret on macOS" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try parseL(a, &.{"tailscale"}, linux_env);
    try testing.expectEqual(Command.tailscale, l.command);
    try testing.expectEqualStrings("/run/user/1000/rweb/bridge.sock", l.listen.unix);
    try testing.expect(l.owner_from_tailscale and l.detect_own_addresses and l.token_file == null and l.backend_secret_file == null);
    try testing.expectEqual(@as(u32, 0), l.peer_uids.?[0].uid); // tailscaled
    try testing.expectEqualStrings("/home/me/.config/rweb", l.config_dir.?);
    const m = try parseL(a, &.{"tailscale"}, mac_env);
    try testing.expectEqual(@as(u16, 7695), m.listen.tcp);
    try testing.expectEqualStrings("/Users/me/.config/rweb/backend-secret", m.backend_secret_file.?);
    try testing.expect(m.make_backend_secret and m.owner_from_tailscale and !m.random_token);
    const mp = try parseL(a, &.{ "tailscale", "--port", "7800", "--config-dir", "/Volumes/local/rweb" }, mac_env);
    try testing.expectEqual(@as(u16, 7800), mp.listen.tcp);
    try testing.expectEqualStrings("/Volumes/local/rweb/backend-secret", mp.backend_secret_file.?);
    // On Linux, --port is refused (the layout is a unix socket); the advanced options still allow a
    // port with a backend secret.
    var d: Diag = .{};
    try testing.expectError(error.PortNeedsMac, parseEnv(a, &.{ "tailscale", "--port", "7695" }, linux_env, &d));
    try testing.expectEqualStrings("--port", d.arg);
    try testing.expect(std.mem.indexOf(u8, explain(error.PortNeedsMac), "--listen-tcp PORT") != null);
    const lp = try parseL(a, &.{ "tailscale", "--listen-tcp", "7695", "--backend-secret-file", "/x/secret" }, linux_env);
    try testing.expectEqual(@as(u16, 7695), lp.listen.tcp);
    try testing.expect(!lp.make_backend_secret and lp.owner_from_tailscale);
}

test "rweb ssh: a socket only you may use, and a made token" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const l = try parseL(a, &.{"ssh"}, linux_env);
    try testing.expectEqual(Command.ssh, l.command);
    try testing.expectEqualStrings("/run/user/1000/rweb/ssh.sock", l.listen.unix);
    try testing.expect(l.peer_uids.?.len == 1 and l.peer_uids.?[0] == .self);
    try testing.expectEqualStrings("/home/me/.config/rweb/token", l.token_file.?);
    try testing.expect(l.make_token_file and !l.owner_from_tailscale and !l.detect_own_addresses and !l.random_token);
    try testing.expectEqual(@as(u16, 7700), l.ssh_port);
    const m = try parseL(a, &.{ "ssh", "--port", "7801" }, mac_env);
    try testing.expectEqualStrings("/Users/me/.config/rweb/run/ssh.sock", m.listen.unix);
    try testing.expectEqual(@as(u16, 7801), m.ssh_port);
    var x = linux_env;
    x.xdg_config_home = "/home/me/xdg";
    try testing.expectEqualStrings("/home/me/xdg/rweb/token", (try parseL(a, &.{"ssh"}, x)).token_file.?);
}

test "a layout's settings give way to the same advanced option" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const s = try parseL(a, &.{ "ssh", "--listen-unix", "/x/s.sock", "--token-file", "/x/tok", "--allow-peer-uid", "1001" }, linux_env);
    try testing.expectEqualStrings("/x/s.sock", s.listen.unix);
    try testing.expectEqualStrings("/x/tok", s.token_file.?);
    try testing.expect(!s.make_token_file); // a named file must be there
    try testing.expectEqual(@as(u32, 1001), s.peer_uids.?[0].uid);
    const t = try parseL(a, &.{ "tailscale", "--owner", "me@example.com", "--allow-host", "box.example", "--listen-unix", "/x/b.sock", "--own-address", "100.64.0.5" }, linux_env);
    try testing.expect(!t.owner_from_tailscale and !t.detect_own_addresses);
    try testing.expectEqualStrings("me@example.com", t.owner.?);
    const m = try parseL(a, &.{ "tailscale", "--backend-secret-file", "/x/secret" }, mac_env);
    try testing.expectEqualStrings("/x/secret", m.backend_secret_file.?);
    try testing.expect(!m.make_backend_secret);
    const tcp = try parseL(a, &.{ "ssh", "--listen-tcp", "7700" }, linux_env);
    try testing.expectEqual(@as(u16, 7700), tcp.listen.tcp);
    try testing.expect(tcp.peer_uids == null and tcp.make_token_file);
}

test "layout refusals: no home, layout-only options, and each has words" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.NoHome, parseL(a, &.{"ssh"}, .{ .os = .linux, .uid = 1000 }));
    _ = try parseL(a, &.{ "ssh", "--config-dir", "/srv/rweb" }, .{ .os = .linux, .uid = 1000 });
    try testing.expectError(error.NotAbsolute, parseL(a, &.{ "ssh", "--config-dir", "rel" }, linux_env));
    try testing.expectError(error.NeedsLayout, parseL(a, &.{ "--listen-tcp", "0", "--port", "1" }, linux_env));
    try testing.expectError(error.NeedsLayout, parseL(a, &.{ "--listen-tcp", "0", "--config-dir", "/x" }, linux_env));
    try testing.expectError(error.UnknownOption, parseL(a, &.{ "ssh", "tailscale" }, linux_env));
    var d: Diag = .{};
    try testing.expectError(error.UnknownOption, parseEnv(a, &.{ "ssh", "--nope" }, linux_env, &d));
    try testing.expectEqualStrings("--nope", d.arg);
    // Every refusal has its own words, none an error name.
    inline for (@typeInfo(Error).error_set.error_names.?) |name| {
        const err: Error = @errorCast(@field(anyerror, name));
        const text = explain(err);
        switch (err) {
            error.Usage, error.ShortHelp, error.Version => try testing.expectEqual(@as(usize, 0), text.len),
            else => {
                try testing.expect(text.len > 10);
                try testing.expect(std.mem.indexOf(u8, text, name) == null);
            },
        }
    }
}

test "each refusal names its argument once, a number says what that option takes, and help is a command" {
    try testing.expectError(error.Usage, parse(testing.allocator, &.{"help"}));
    try testing.expect(std.mem.indexOf(u8, explain(error.BadAddress), "--own-address") == null);
    try testing.expect(std.mem.indexOf(u8, explain(error.UnknownOption), "--help") == null);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    for ([_]struct { []const []const u8, []const u8, []const u8 }{
        .{ &.{ "--listen-tcp", "70000" }, "--listen-tcp", "port" },
        .{ &.{ "--listen-tcp", "0", "--history-lines", "x" }, "--history-lines", "lines" },
        .{ &.{ "--listen-tcp", "0", "--max-transfer-mb", "0" }, "--max-transfer-mb", "megabytes" },
        .{ &.{ "--listen-unix", "/x/s", "--token-file", "/x/t", "--allow-peer-uid", "me" }, "--allow-peer-uid", "user id" },
        .{ &.{ "ssh", "--port", "-1" }, "--port", "port" },
    }) |c| {
        var d: Diag = .{};
        try testing.expectError(error.BadNumber, parseEnv(a, c[0], linux_env, &d));
        try testing.expectEqualStrings(c[1], d.arg);
        try testing.expect(std.mem.indexOf(u8, explainArg(error.BadNumber, d.arg), c[2]) != null);
    }
}

test "a socket path too long for the system is refused before anything is made" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const x90: [90]u8 = @splat('x');
    const long = "/Users/me/" ++ x90; // 100 bytes: fits a Linux socket path, not under <config>/run on macOS
    const y102: [102]u8 = @splat('y');
    const y103 = y102 ++ "y";
    const y106 = y103 ++ "yyy";
    const y107 = y106 ++ "y";
    var d: Diag = .{};
    try testing.expectError(error.SocketPathTooLong, parseEnv(a, &.{ "ssh", "--config-dir", long }, mac_env, &d));
    try testing.expectEqualStrings(long ++ "/run/ssh.sock", d.arg);
    try testing.expectError(error.SocketPathTooLong, parseEnv(a, &.{ "--listen-unix", "/" ++ y107, "--token-file", "/x/t" }, linux_env, &d));
    _ = try parseEnv(a, &.{ "--listen-unix", "/" ++ y106, "--token-file", "/x/t" }, linux_env, &d);
    _ = try parseEnv(a, &.{ "--listen-unix", "/" ++ y102, "--token-file", "/x/t" }, mac_env, &d);
    try testing.expectError(error.SocketPathTooLong, parseEnv(a, &.{ "--listen-unix", "/" ++ y103, "--token-file", "/x/t" }, mac_env, &d));
}
