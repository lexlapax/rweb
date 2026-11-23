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
//!   setting allows it (single-user hosts).
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
};

pub const Header = struct { name: []const u8, value: []const u8 };

pub const Request = struct {
    /// Peer uid of the unix-socket connection, if there is one and it could be read.
    peer_uid: ?u32 = null,
    headers: []const Header,
    /// The `token` query parameter, already extracted.
    query_token: ?[]const u8 = null,
    is_websocket_upgrade: bool = false,

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

    if (request.header("tailscale-funnel-request") != null) return .{ .deny = .funnel };

    if (cfg.owner) |want_owner| {
        const login = request.header("tailscale-user-login") orelse return .{ .deny = .no_identity };
        if (!std.mem.eql(u8, login, want_owner)) return .{ .deny = .wrong_user };
    }

    if (!cfg.allow_own_address) {
        if (request.header("x-forwarded-for")) |xff| {
            var it = std.mem.tokenizeAny(u8, xff, ", ");
            while (it.next()) |addr| for (cfg.own_addresses) |own| {
                if (std.mem.eql(u8, addr, own)) return .{ .deny = .own_address };
            };
        }
    }

    if (cfg.token) |want| {
        const got = request.header("rweb-token") orelse request.query_token orelse
            cookieValue(request.header("cookie") orelse "", "rweb-token") orelse return .{ .deny = .bad_token };
        if (!constantTimeEql(want, got)) return .{ .deny = .bad_token };
    }

    if (request.is_websocket_upgrade) {
        const origin = request.header("origin") orelse return .{ .deny = .no_origin };
        const host = request.header("x-forwarded-host") orelse request.header("host") orelse return .{ .deny = .bad_origin };
        if (!originMatchesHost(origin, host)) return .{ .deny = .bad_origin };
    }
    return .allow;
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
        .{ .name = "X-Forwarded-Host", .value = "box.tail1234.ts.net:10443" },
        .{ .name = "Origin", .value = "https://box.tail1234.ts.net:10443" },
    };
    var r = req(&ok);
    r.is_websocket_upgrade = true;
    try testing.expectEqual(Decision.allow, decide(base_cfg, r));

    const evil = [_]Header{
        .{ .name = "Tailscale-User-Login", .value = owner },
        .{ .name = "X-Forwarded-Host", .value = "box.tail1234.ts.net:10443" },
        .{ .name = "Origin", .value = "https://evil.example" },
    };
    r = req(&evil);
    r.is_websocket_upgrade = true;
    try expectDeny(.bad_origin, base_cfg, r);

    const none = [_]Header{.{ .name = "Tailscale-User-Login", .value = owner }};
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
    const h = [_]Header{.{ .name = "Tailscale-User-Login", .value = owner }};
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
