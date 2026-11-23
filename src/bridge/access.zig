//! Who may talk to the bridge. Pure: a request's facts go in, a decision comes out, so each
//! refusal can be tested (and shown to refuse) without a network.
//!
//! The bridge has the owner's full Rex access, so it authenticates every request itself:
//!
//! - On a unix socket only the peer `tailscaled` runs as (uid 0), or the bridge's own uid in
//!   tests, may connect at all.
//! - A request carrying `Tailscale-Funnel-Request` came from the public internet: refused.
//! - `Tailscale-User-Login` must be the configured owner. Serve strips client-supplied copies of
//!   it, but a loopback TCP listener cannot tell Serve from another local process; that
//!   exposure is accepted and recorded for desktop-mac.
//! - `X-Forwarded-For` naming one of this node's own Tailscale addresses means a local process
//!   asked Serve for the node's name and got the owner's identity: refused unless the machine's
//!   setting allows it (single-user hosts). Addresses are compared as addresses, not as text
//!   (`::ffff:100.64.0.5` is `100.64.0.5`), and while the rule is on, a request with no
//!   `X-Forwarded-For`, or one that is not an address, is refused too.
//! - A security-relevant header that appears twice is ambiguous (which one did the proxy set?):
//!   refused.
//! - With `allowed_hosts`, the `Host` (or `X-Forwarded-Host`) of every request must be one of
//!   them, so a page reaching the bridge through a rebound DNS name gets nothing.
//! - A WebSocket upgrade must carry an `Origin` whose host is `X-Forwarded-Host` (or `Host`
//!   when no proxy sits in front), so a page on another site cannot open one.
//! - A test or loopback deployment may also require a shared token.

const std = @import("std");

pub const Config = struct {
    /// Required `Tailscale-User-Login`. Null only when `token` is set (a local test server).
    owner: ?[]const u8 = null,
    /// Required shared secret, in the `rweb-token` header or the `token` query parameter.
    token: ?[]const u8 = null,
    /// This node's own Tailscale addresses, as text.
    own_addresses: []const []const u8 = &.{},
    allow_own_address: bool = false,
    /// For a unix listener: the peer uids allowed. Null for a TCP listener (no peer check).
    allowed_peer_uids: ?[]const u32 = null,
    /// Host names (without port) a request may be for. Empty: not checked.
    allowed_hosts: []const []const u8 = &.{},
};

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    /// Peer uid of the unix-socket connection, if there is one and it could be read.
    peer_uid: ?u32 = null,
    headers: []const Header,
    /// The `token` query parameter, already extracted.
    query_token: ?[]const u8 = null,
    is_websocket_upgrade: bool = false,
    /// A request that changes something (PUT): it needs a matching `Origin`, like a WebSocket.
    requires_origin: bool = false,

    pub fn header(r: Request, name: []const u8) ?[]const u8 {
        for (r.headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
        return null;
    }
};

pub const Refusal = enum {
    /// Neither an owner nor a token is configured.
    unconfigured,
    wrong_peer,
    funnel,
    no_identity,
    wrong_user,
    own_address,
    no_origin,
    bad_origin,
    bad_token,
    ambiguous_header,
    bad_host,
    no_forwarded_for,
    bad_forwarded_for,

    pub fn text(r: Refusal) []const u8 {
        return switch (r) {
            .unconfigured => "access is not configured",
            .wrong_peer => "peer not allowed",
            .funnel => "public (Funnel) requests are refused",
            .no_identity => "no Tailscale identity",
            .wrong_user => "not the owner",
            .own_address => "request from this node's own address",
            .no_origin => "missing Origin",
            .bad_origin => "bad Origin",
            .bad_token => "bad token",
            .ambiguous_header => "a header that must appear once appears twice",
            .bad_host => "host not allowed",
            .no_forwarded_for => "no X-Forwarded-For",
            .bad_forwarded_for => "X-Forwarded-For is not an address",
        };
    }
};

pub const Decision = union(enum) {
    allow,
    deny: Refusal,
};

/// Decide in a fixed order, so a log line says the first reason a request failed.
pub fn decide(cfg: Config, request: Request) Decision {
    if (cfg.owner == null and cfg.token == null) return .{ .deny = .unconfigured };

    if (cfg.allowed_peer_uids) |uids| {
        const uid = request.peer_uid orelse return .{ .deny = .wrong_peer };
        var ok = false;
        for (uids) |u| if (u == uid) {
            ok = true;
        };
        if (!ok) return .{ .deny = .wrong_peer };
    }

    if (duplicatedSecurityHeader(request.headers)) return .{ .deny = .ambiguous_header };

    // Funnel marks public-internet requests; refuse any header in its family.
    for (request.headers) |h| {
        if (std.ascii.startsWithIgnoreCase(h.name, "tailscale-funnel")) return .{ .deny = .funnel };
    }

    if (cfg.owner) |want_owner| {
        const login = request.header("tailscale-user-login") orelse return .{ .deny = .no_identity };
        if (!std.mem.eql(u8, login, want_owner)) return .{ .deny = .wrong_user };
    }

    if (!cfg.allow_own_address and cfg.own_addresses.len > 0) {
        const xff = request.header("x-forwarded-for") orelse return .{ .deny = .no_forwarded_for };
        var seen = false;
        var it = std.mem.tokenizeAny(u8, xff, ", ");
        while (it.next()) |addr| {
            seen = true;
            const a = parseAddress(addr) orelse return .{ .deny = .bad_forwarded_for };
            for (cfg.own_addresses) |own| {
                const o = parseAddress(own) orelse continue;
                if (sameAddress(a, o)) return .{ .deny = .own_address };
            }
        }
        if (!seen) return .{ .deny = .bad_forwarded_for };
    }

    if (cfg.token) |want| {
        const got = request.header("rweb-token") orelse request.query_token orelse
            cookieValue(request.header("cookie") orelse "", "rweb-token") orelse return .{ .deny = .bad_token };
        if (!constantTimeEql(want, got)) return .{ .deny = .bad_token };
    }

    const host = request.header("x-forwarded-host") orelse request.header("host");
    if (cfg.allowed_hosts.len > 0) {
        const h = host orelse return .{ .deny = .bad_host };
        if (!hostAllowed(cfg.allowed_hosts, h)) return .{ .deny = .bad_host };
    }

    if (request.is_websocket_upgrade or request.requires_origin) {
        const origin = request.header("origin") orelse return .{ .deny = .no_origin };
        if (!originMatchesHost(origin, host orelse return .{ .deny = .bad_origin })) return .{ .deny = .bad_origin };
    }
    return .allow;
}

/// Headers whose single value the decision relies on. Two of them cannot both be the proxy's.
const single_headers = [_][]const u8{
    "host",                 "origin",           "x-forwarded-host", "x-forwarded-for",
    "tailscale-user-login", "rweb-token",       "x-forwarded-proto",
};

fn duplicatedSecurityHeader(headers: []const Header) bool {
    for (single_headers) |name| {
        var n: u32 = 0;
        for (headers) |h| if (std.ascii.eqlIgnoreCase(h.name, name)) {
            n += 1;
        };
        if (n > 1) return true;
    }
    return false;
}

/// `host[:port]` against a list of bare host names.
pub fn hostAllowed(allowed: []const []const u8, host: []const u8) bool {
    var name = host;
    if (name.len > 0 and name[0] == '[') { // [v6]:port
        const close = std.mem.indexOfScalar(u8, name, ']') orelse return false;
        name = name[1..close];
    } else if (std.mem.lastIndexOfScalar(u8, name, ':')) |c| {
        if (std.mem.indexOfScalar(u8, name[0..c], ':') == null) name = name[0..c]; // not a bare v6
    }
    for (allowed) |a| if (std.ascii.eqlIgnoreCase(a, name)) return true;
    return false;
}

const Ip = union(enum) { v4: [4]u8, v6: [16]u8 };

/// An IP literal as bytes, with an IPv4-mapped IPv6 address turned into IPv4 and any zone dropped.
fn parseAddress(text: []const u8) ?Ip {
    const t = std.mem.trim(u8, text, "[]");
    if (std.Io.net.Ip4Address.parse(t, 0)) |a| return .{ .v4 = a.bytes } else |_| {}
    const no_zone = t[0 .. std.mem.indexOfScalar(u8, t, '%') orelse t.len];
    const a6 = std.Io.net.Ip6Address.parse(no_zone, 0) catch return null;
    const b = a6.bytes;
    if (std.mem.allEqual(u8, b[0..10], 0) and b[10] == 0xff and b[11] == 0xff) return .{ .v4 = b[12..16].* };
    return .{ .v6 = b };
}

fn sameAddress(a: Ip, b: Ip) bool {
    return switch (a) {
        .v4 => |x| b == .v4 and std.mem.eql(u8, &x, &b.v4),
        .v6 => |x| b == .v6 and std.mem.eql(u8, &x, &b.v6),
    };
}

/// `Origin: https://host[:port]` against a `Host`-style `host[:port]`.
pub fn originMatchesHost(origin: []const u8, host: []const u8) bool {
    const rest = if (std.mem.startsWith(u8, origin, "https://"))
        origin["https://".len..]
    else if (std.mem.startsWith(u8, origin, "http://"))
        origin["http://".len..]
    else
        return false;
    // Nothing after the authority: an origin has no path.
    if (std.mem.indexOfAny(u8, rest, "/?#@") != null) return false;
    return host.len > 0 and std.ascii.eqlIgnoreCase(rest, host);
}

fn constantTimeEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

/// The value of cookie `name` in a `Cookie` header.
pub fn cookieValue(header: []const u8, name: []const u8) ?[]const u8 {
    var it = std.mem.tokenizeAny(u8, header, "; ");
    while (it.next()) |kv| {
        const eq = std.mem.indexOfScalar(u8, kv, '=') orelse continue;
        if (std.mem.eql(u8, kv[0..eq], name)) return kv[eq + 1 ..];
    }
    return null;
}

/// Pull `token=` out of a request target's query string.
pub fn queryToken(target: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.tokenizeScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |kv| {
        if (std.mem.startsWith(u8, kv, "token=")) return kv["token=".len..];
    }
    return null;
}

// ---- tests ----

const testing = std.testing;

const owner = "owner@example.com";
const base_cfg: Config = .{ .owner = owner, .own_addresses = &.{ "100.64.0.5", "fd7a:115c:a1e0::5" } };

fn req(headers: []const Header) Request {
    return .{ .headers = headers };
}

fn expectDeny(want: Refusal, cfg: Config, r: Request) !void {
    try testing.expectEqual(Decision{ .deny = want }, decide(cfg, r));
}

test "the owner through Serve is allowed" {
    const h = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "100.64.0.9" } };
    try testing.expectEqual(Decision.allow, decide(base_cfg, req(&h)));
}

test "refuses when nothing is configured" {
    try expectDeny(.unconfigured, .{}, req(&.{}));
}

test "refuses a wrong user, and a request with no identity" {
    const h = [_]Header{.{ .name = "Tailscale-User-Login", .value = "someone@example.com" }};
    try expectDeny(.wrong_user, base_cfg, req(&h));
    try expectDeny(.no_identity, base_cfg, req(&.{}));
    // Near misses are wrong users too.
    const h2 = [_]Header{.{ .name = "Tailscale-User-Login", .value = "OWNER@example.com" }};
    try expectDeny(.wrong_user, base_cfg, req(&h2));
}

test "refuses Funnel even with the owner's identity" {
    const h = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "Tailscale-Funnel-Request", .value = "?1" } };
    try expectDeny(.funnel, base_cfg, req(&h));
}

test "refuses the node's own address, unless the machine allows it" {
    const h = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "100.64.0.5" } };
    try expectDeny(.own_address, base_cfg, req(&h));
    const h6 = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "fd7a:115c:a1e0::5" } };
    try expectDeny(.own_address, base_cfg, req(&h6));
    // Forged lists still refuse when any entry is the node's own address.
    const hl = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "100.64.0.9, 100.64.0.5" } };
    try expectDeny(.own_address, base_cfg, req(&hl));
    var allow = base_cfg;
    allow.allow_own_address = true;
    try testing.expectEqual(Decision.allow, decide(allow, req(&h)));
}

test "websocket upgrades need an Origin that matches the forwarded host" {
    const ok = [_]Header{
        .{ .name = "Tailscale-User-Login", .value = owner },
        .{ .name = "X-Forwarded-For", .value = "100.64.0.9" },
        .{ .name = "X-Forwarded-Host", .value = "box.tail1234.ts.net:10443" },
        .{ .name = "Origin", .value = "https://box.tail1234.ts.net:10443" },
    };
    var r = req(&ok);
    r.is_websocket_upgrade = true;
    try testing.expectEqual(Decision.allow, decide(base_cfg, r));

    const evil = [_]Header{
        .{ .name = "Tailscale-User-Login", .value = owner },
        .{ .name = "X-Forwarded-For", .value = "100.64.0.9" },
        .{ .name = "X-Forwarded-Host", .value = "box.tail1234.ts.net:10443" },
        .{ .name = "Origin", .value = "https://evil.example" },
    };
    r = req(&evil);
    r.is_websocket_upgrade = true;
    try expectDeny(.bad_origin, base_cfg, r);

    const none = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "100.64.0.9" } };
    r = req(&none);
    r.is_websocket_upgrade = true;
    try expectDeny(.no_origin, base_cfg, r);

    // A plain page load needs no Origin.
    try testing.expectEqual(Decision.allow, decide(base_cfg, req(&none)));
}

test "originMatchesHost is strict" {
    try testing.expect(originMatchesHost("https://a.example", "a.example"));
    try testing.expect(originMatchesHost("http://127.0.0.1:7690", "127.0.0.1:7690"));
    try testing.expect(!originMatchesHost("https://a.example", "a.example:8443"));
    try testing.expect(!originMatchesHost("https://a.example/x", "a.example"));
    try testing.expect(!originMatchesHost("https://user@a.example", "a.example"));
    try testing.expect(!originMatchesHost("null", "a.example"));
    try testing.expect(!originMatchesHost("ftp://a.example", "a.example"));
    try testing.expect(!originMatchesHost("https://a.example.evil.com", "a.example"));
}

test "unix peers: only the allowed uids" {
    var cfg = base_cfg;
    const uids = [_]u32{0};
    cfg.allowed_peer_uids = &uids;
    const h = [_]Header{ .{ .name = "Tailscale-User-Login", .value = owner }, .{ .name = "X-Forwarded-For", .value = "100.64.0.9" } };
    var r = req(&h);
    r.peer_uid = 0;
    try testing.expectEqual(Decision.allow, decide(cfg, r));
    r.peer_uid = 1000;
    try expectDeny(.wrong_peer, cfg, r);
    r.peer_uid = null; // could not be read: refuse
    try expectDeny(.wrong_peer, cfg, r);
}

test "token mode (local test servers)" {
    const cfg: Config = .{ .token = "s3cret-token" };
    try expectDeny(.bad_token, cfg, req(&.{}));
    var r = req(&.{});
    r.query_token = "wrong";
    try expectDeny(.bad_token, cfg, r);
    r.query_token = "s3cret-token";
    try testing.expectEqual(Decision.allow, decide(cfg, r));
    const h = [_]Header{.{ .name = "rweb-token", .value = "s3cret-token" }};
    try testing.expectEqual(Decision.allow, decide(cfg, req(&h)));
    // Owner and token together: both are required.
    const both: Config = .{ .owner = owner, .token = "t" };
    const only_token = [_]Header{.{ .name = "rweb-token", .value = "t" }};
    try expectDeny(.no_identity, both, req(&only_token));
}

test "queryToken" {
    try testing.expectEqualStrings("abc", queryToken("/ws?token=abc").?);
    try testing.expectEqualStrings("abc", queryToken("/?x=1&token=abc&y=2").?);
    try testing.expect(queryToken("/ws") == null);
    try testing.expect(queryToken("/ws?tokenx=1") == null);
}

test "token from a cookie (subresources and the socket carry it, not the query)" {
    const cfg: Config = .{ .token = "tok123" };
    const good = [_]Header{.{ .name = "Cookie", .value = "a=b; rweb-token=tok123; c=d" }};
    try testing.expectEqual(Decision.allow, decide(cfg, req(&good)));
    const bad = [_]Header{.{ .name = "Cookie", .value = "rweb-token=nope" }};
    try expectDeny(.bad_token, cfg, req(&bad));
    const other = [_]Header{.{ .name = "Cookie", .value = "xrweb-token=tok123" }};
    try expectDeny(.bad_token, cfg, req(&other));
    try testing.expectEqualStrings("1", cookieValue("x=1; y=2; z=3", "x").?);
    try testing.expect(cookieValue("", "x") == null);
}

test "the own-address rule compares addresses, and fails closed" {
    const login = Header{ .name = "Tailscale-User-Login", .value = owner };
    // An IPv4-mapped IPv6 spelling, a differently written IPv6 spelling, bracketed, zoned.
    const mapped = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = "::ffff:100.64.0.5" } };
    try expectDeny(.own_address, base_cfg, req(&mapped));
    const long6 = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = "FD7A:115C:A1E0:0:0:0:0:5" } };
    try expectDeny(.own_address, base_cfg, req(&long6));
    const zoned = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = "[fd7a:115c:a1e0::5%1]" } };
    try expectDeny(.own_address, base_cfg, req(&zoned));
    // No X-Forwarded-For at all, an empty one, and one that is not an address.
    try expectDeny(.no_forwarded_for, base_cfg, req(&.{login}));
    const empty = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = " , " } };
    try expectDeny(.bad_forwarded_for, base_cfg, req(&empty));
    const junk = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = "100.64.0.9, not-an-ip" } };
    try expectDeny(.bad_forwarded_for, base_cfg, req(&junk));
    // A near miss is somebody else.
    const near = [_]Header{ login, .{ .name = "X-Forwarded-For", .value = "100.64.0.50" } };
    try testing.expectEqual(Decision.allow, decide(base_cfg, req(&near)));
}

test "a security header that appears twice is refused, in any case" {
    const login = Header{ .name = "Tailscale-User-Login", .value = owner };
    const xff = Header{ .name = "X-Forwarded-For", .value = "100.64.0.9" };
    const twice = [_]Header{ login, .{ .name = "tailscale-user-login", .value = owner }, xff };
    try expectDeny(.ambiguous_header, base_cfg, req(&twice));
    const two_xff = [_]Header{ login, xff, .{ .name = "x-forwarded-for", .value = "100.64.0.5" } };
    try expectDeny(.ambiguous_header, base_cfg, req(&two_xff));
    const two_host = [_]Header{ login, xff, .{ .name = "Host", .value = "a" }, .{ .name = "HOST", .value = "b" } };
    try expectDeny(.ambiguous_header, base_cfg, req(&two_host));
}

test "every Funnel header refuses, not only one spelling" {
    const login = Header{ .name = "Tailscale-User-Login", .value = owner };
    const h = [_]Header{ login, .{ .name = "tailscale-funnel-something-new", .value = "1" } };
    try expectDeny(.funnel, base_cfg, req(&h));
}

test "a host list refuses any other Host, on every request" {
    var cfg = base_cfg;
    cfg.allowed_hosts = &.{"box.tail1234.ts.net"};
    const login = Header{ .name = "Tailscale-User-Login", .value = owner };
    const xff = Header{ .name = "X-Forwarded-For", .value = "100.64.0.9" };
    const ok = [_]Header{ login, xff, .{ .name = "X-Forwarded-Host", .value = "BOX.tail1234.ts.net:10443" } };
    try testing.expectEqual(Decision.allow, decide(cfg, req(&ok)));
    const rebound = [_]Header{ login, xff, .{ .name = "Host", .value = "evil.example" } };
    try expectDeny(.bad_host, cfg, req(&rebound));
    const none = [_]Header{ login, xff };
    try expectDeny(.bad_host, cfg, req(&none));
    // The forwarded host wins over Host, so a proxy-supplied name cannot be bypassed by Host.
    const mixed = [_]Header{ login, xff, .{ .name = "Host", .value = "box.tail1234.ts.net" }, .{ .name = "X-Forwarded-Host", .value = "evil.example" } };
    try expectDeny(.bad_host, cfg, req(&mixed));
    try testing.expect(hostAllowed(&.{"a.example"}, "a.example"));
    try testing.expect(hostAllowed(&.{"::1"}, "[::1]:8080"));
    try testing.expect(!hostAllowed(&.{"a.example"}, "a.example.evil.com"));
    try testing.expect(!hostAllowed(&.{"a.example"}, ""));
}

test "a PUT needs the page's own Origin, as a WebSocket does" {
    const login = Header{ .name = "Tailscale-User-Login", .value = owner };
    const xff = Header{ .name = "X-Forwarded-For", .value = "100.64.0.9" };
    const host = Header{ .name = "X-Forwarded-Host", .value = "box.tail1234.ts.net" };
    const ok = [_]Header{ login, xff, host, .{ .name = "Origin", .value = "https://box.tail1234.ts.net" } };
    var r = req(&ok);
    r.requires_origin = true;
    try testing.expectEqual(Decision.allow, decide(base_cfg, r));
    const evil = [_]Header{ login, xff, host, .{ .name = "Origin", .value = "https://evil.example" } };
    r = req(&evil);
    r.requires_origin = true;
    try expectDeny(.bad_origin, base_cfg, r);
    const none = [_]Header{ login, xff, host };
    r = req(&none);
    r.requires_origin = true;
    try expectDeny(.no_origin, base_cfg, r);
}
