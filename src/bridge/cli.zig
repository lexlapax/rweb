//! Command-line settings for the bridge, parsed without touching the system so the rules
//! (what must be given, what defaults to the safe side) can be tested.

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const usage =
    \\rweb: shows Rex terminal sessions in a web browser
    \\
    \\  rweb (--listen-unix PATH | --listen-tcp PORT) [options]
    \\
    \\Where to listen (exactly one):
    \\  --listen-unix PATH        unix socket, created 0600 in a 0700 directory
    \\  --listen-tcp PORT         loopback TCP only (127.0.0.1); 0 picks a port
    \\
    \\Who may connect:
    \\  --owner LOGIN             required Tailscale-User-Login (Tailscale Serve sets it)
    \\  --owner-from-tailscale    take the owner from this node's own Tailscale login (`tailscale status`)
    \\  --token TOKEN             shared secret in the `token` query or `rweb-token` header
    \\  --random-token            make a token and print the URL (loopback tests)
    \\  --own-address IP          this node's Tailscale address (repeatable); requests from
    \\                            it are refused. With --owner and none given, `tailscale ip`
    \\                            is asked; if that fails the bridge will not start
    \\  --allow-own-address       accept requests from this node's own address (single-user hosts)
    \\  --allow-peer-uid N|self   unix socket peers allowed (default: 0, tailscaled)
    \\
    \\Behaviour:
    \\  --rex-socket PATH         Rex's unix socket (default: found from XDG_RUNTIME_DIR or the Mac app)
    \\  --observe-only            never write, resize or change anything in Rex
    \\  --history-lines N         scrollback rows sent when a terminal opens (default 1000)
    \\  --debug-input             log what browsers send (typed text included): for testing a keyboard, never for deployment
    \\
;

pub const Listen = union(enum) { unix: []const u8, tcp: u16 };

pub const Parsed = struct {
    rex_socket: ?[]const u8 = null,
    listen: Listen,
    owner: ?[]const u8 = null,
    owner_from_tailscale: bool = false,
    token: ?[]const u8 = null,
    random_token: bool = false,
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

pub const Error = error{
    Usage,
    NoListener,
    TwoListeners,
    NoAccessRule,
    BadNumber,
    MissingValue,
    UnknownOption,
} || Allocator.Error;

/// Parse `args` (without the program name). Slices in the result point into `args`, except
/// the lists, which are allocated from `arena`.
pub fn parse(arena: Allocator, args: []const []const u8) Error!Parsed {
    var listen: ?Listen = null;
    var p: Parsed = .{ .listen = undefined };
    var own: std.ArrayList([]const u8) = .empty;
    var uids: std.ArrayList(PeerUid) = .empty;
    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        const eql = std.mem.eql;
        if (eql(u8, a, "--help") or eql(u8, a, "-h")) return error.Usage;
        if (eql(u8, a, "--listen-unix")) {
            if (listen != null) return error.TwoListeners;
            listen = .{ .unix = try value(args, &i) };
        } else if (eql(u8, a, "--listen-tcp")) {
            if (listen != null) return error.TwoListeners;
            listen = .{ .tcp = std.fmt.parseInt(u16, try value(args, &i), 10) catch return error.BadNumber };
        } else if (eql(u8, a, "--owner")) {
            p.owner = try value(args, &i);
        } else if (eql(u8, a, "--owner-from-tailscale")) {
            p.owner_from_tailscale = true;
        } else if (eql(u8, a, "--token")) {
            p.token = try value(args, &i);
        } else if (eql(u8, a, "--random-token")) {
            p.random_token = true;
        } else if (eql(u8, a, "--own-address")) {
            try own.append(arena, try value(args, &i));
        } else if (eql(u8, a, "--allow-own-address")) {
            p.allow_own_address = true;
        } else if (eql(u8, a, "--allow-peer-uid")) {
            const v = try value(args, &i);
            if (eql(u8, v, "self")) try uids.append(arena, .self) else try uids.append(arena, .{ .uid = std.fmt.parseInt(u32, v, 10) catch return error.BadNumber });
        } else if (eql(u8, a, "--rex-socket")) {
            p.rex_socket = try value(args, &i);
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

    switch (p.listen) {
        .unix => {
            // Tailscaled dials as root; anything else must be asked for.
            p.peer_uids = if (uids.items.len > 0) uids.items else &[_]PeerUid{.{ .uid = 0 }};
            if (p.owner == null and !p.owner_from_tailscale and p.token == null and !p.random_token) return error.NoAccessRule;
        },
        .tcp => {
            if (uids.items.len > 0) return error.Usage; // no peer check on TCP
            if (p.owner == null and !p.owner_from_tailscale and p.token == null) p.random_token = true;
        },
    }
    if (p.owner != null and p.owner_from_tailscale) return error.Usage;
    if (p.token != null) p.random_token = false;
    // With an owner rule the own-address rule must be enforceable: fail closed.
    if ((p.owner != null or p.owner_from_tailscale) and !p.allow_own_address and p.own_addresses.len == 0) p.detect_own_addresses = true;
    return p;
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
        .detect_own_addresses = p.detect_own_addresses,
        .observe_only = p.observe_only,
        .history_lines = p.history_lines,
        .peer_uids = if (p.peer_uids) |u| (if (u.len == 1 and u[0] == .uid and u[0].uid == 0) &[_]PeerUid{.{ .uid = 0 }} else &[_]PeerUid{.self}) else null,
    };
}

test "a listener is required, and only one" {
    try testing.expectError(error.NoListener, parseT(&.{ "--owner", "a@b" }));
    try testing.expectError(error.TwoListeners, parseT(&.{ "--listen-tcp", "0", "--listen-unix", "/x" }));
}

test "a unix socket needs an access rule and defaults to root as the only peer" {
    try testing.expectError(error.NoAccessRule, parseT(&.{ "--listen-unix", "/x/b.sock" }));
    const p = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com" });
    try testing.expectEqual(@as(u32, 0), p.peer_uids.?[0].uid);
    try testing.expect(p.detect_own_addresses); // fail closed: the own-address rule must be enforceable
    const q = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "me@example.com", "--allow-own-address" });
    try testing.expect(!q.detect_own_addresses);
}

test "loopback TCP without any rule gets a random token" {
    const p = try parseT(&.{ "--listen-tcp", "0" });
    try testing.expect(p.random_token);
    const q = try parseT(&.{ "--listen-tcp", "8080", "--token", "abc" });
    try testing.expect(!q.random_token and std.mem.eql(u8, q.token.?, "abc"));
    try testing.expectError(error.Usage, parseT(&.{ "--listen-tcp", "0", "--allow-peer-uid", "0" }));
}

test "numbers and options are checked" {
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "70000" }));
    try testing.expectError(error.BadNumber, parseT(&.{ "--listen-tcp", "0", "--history-lines", "x" }));
    try testing.expectError(error.MissingValue, parseT(&.{ "--listen-tcp", "0", "--owner" }));
    try testing.expectError(error.UnknownOption, parseT(&.{ "--listen-tcp", "0", "--nope" }));
    try testing.expectError(error.Usage, parseT(&.{"--help"}));
    const p = try parseT(&.{ "--listen-tcp", "0", "--observe-only", "--history-lines", "50" });
    try testing.expect(p.observe_only and p.history_lines == 50);
}

test "owner from Tailscale counts as an owner rule" {
    const p = try parseT(&.{ "--listen-unix", "/x/b.sock", "--owner-from-tailscale" });
    try testing.expect(p.detect_own_addresses);
    try testing.expectError(error.Usage, parseT(&.{ "--listen-unix", "/x/b.sock", "--owner", "a@b", "--owner-from-tailscale" }));
}
