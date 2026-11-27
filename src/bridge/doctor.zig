//! `rweb doctor [tailscale|ssh] [options]`: checks a setup the way that command, with those options,
//! would use it, and says what to fix. It makes, changes and starts nothing: Rex is asked once, the
//! files and folders are checked as at startup without being made, the bridge's socket or port is
//! tried, and Tailscale is asked about the node and Serve (`tailscale status`, `tailscale serve
//! status`). A backend secret is compared, never printed.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const rex = @import("rex");
const cli = @import("cli.zig");
const layout = @import("layout.zig");
const server = @import("server.zig");
const xfer = @import("xfer.zig");
const sys = @import("sys.zig");
const main = @import("main.zig");
const build_options = @import("build_options");

/// The checks' results, written as they are made.
const Report = struct {
    w: *Io.Writer,
    passed: u32 = 0,
    warned: u32 = 0,
    failed: u32 = 0,

    fn ok(r: *Report, comptime fmt: []const u8, args: anytype) void {
        r.passed += 1;
        r.line("ok   ", fmt, args);
    }

    fn warn(r: *Report, comptime fmt: []const u8, args: anytype) void {
        r.warned += 1;
        r.line("note ", fmt, args);
    }

    fn fail(r: *Report, comptime fmt: []const u8, args: anytype) void {
        r.failed += 1;
        r.line("FAIL ", fmt, args);
    }

    fn line(r: *Report, mark: []const u8, comptime fmt: []const u8, args: anytype) void {
        r.w.print("  {s} " ++ fmt ++ "\n", .{mark} ++ args) catch {}; // an in-memory writer
    }

    /// Text from one of rweb's own explanations (several lines, each starting `rweb: ` or two
    /// spaces), indented under the check it belongs to.
    fn detail(r: *Report, text: []const u8) void {
        var it = std.mem.splitScalar(u8, std.mem.trimEnd(u8, text, "\n"), '\n');
        while (it.next()) |l| {
            const t = if (std.mem.startsWith(u8, l, "rweb: ")) l["rweb: ".len..] else std.mem.trimStart(u8, l, " ");
            r.w.print("        {s}\n", .{t}) catch {}; // an in-memory writer
        }
    }
};

/// Run every check that applies to `parsed` and print the report on standard output. True when none
/// failed (notes do not count).
pub fn run(gpa: Allocator, arena: Allocator, io: Io, parsed: cli.Parsed, env_map: *std.process.Environ.Map) !bool {
    var out: Io.Writer.Allocating = .init(arena);
    var r: Report = .{ .w = &out.writer };
    const what = switch (parsed.command) {
        .tailscale => "rweb tailscale",
        .ssh => "rweb ssh",
        .advanced => "rweb with these options",
    };
    try out.writer.print("rweb doctor: checking {s} (rweb {s})\n", .{ what, build_options.version });

    try checkRex(gpa, arena, io, parsed, env_map, &r);
    const secret = try checkSecrets(arena, io, parsed, &r);
    try checkUploads(arena, io, parsed, &r);
    try checkBridge(gpa, arena, io, parsed, &r);
    if (parsed.command == .tailscale or parsed.owner_from_tailscale or parsed.detect_own_addresses)
        try checkTailscale(arena, io, parsed, secret, &r);
    if (parsed.command == .ssh) if (parsed.listen == .unix) {
        var ub: [256]u8 = undefined;
        var hb: [std.posix.HOST_NAME_MAX]u8 = undefined;
        var buf: [2048]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        layout.sshNextStep(&w, parsed.listen.unix, parsed.ssh_port, main.accountName(&ub) orelse "", std.posix.gethostname(&hb) catch "", parsed.token_file) catch {};
        try out.writer.writeAll("\nThe tunnel, from your laptop:\n");
        r.detail(w.buffered());
    };

    try out.writer.print("rweb doctor: {d} passed, {d} {s}, {d} failed\n", .{ r.passed, r.warned, if (r.warned == 1) "note" else "notes", r.failed });
    std.Io.File.stdout().writeStreamingAll(io, out.written()) catch {}; // nothing to do if stdout is gone
    return r.failed == 0;
}

fn checkRex(gpa: Allocator, arena: Allocator, io: Io, parsed: cli.Parsed, env_map: *std.process.Environ.Map, r: *Report) !void {
    var finder = try main.RexFinder.init(arena, io, env_map, parsed.rex_socket);
    var where_buf: [1024]u8 = undefined;
    var where: Io.Writer = .fixed(&where_buf);
    finder.describe(&where) catch {};
    const why: anyerror = blk: {
        const path = finder.socket() orelse break :blk error.RexSocketNotFound;
        const ctl = rex.control.Control.open(gpa, io, .{ .socket_path = path, .client_name = "rweb-doctor", .client_version = build_options.version, .reconnect = false }) catch |e| break :blk e;
        defer ctl.close();
        return r.ok("Rex answers at {s}, API revision {d} (rweb speaks {d} to {d})", .{ path, ctl.revision, rex.control.api_min_supported, rex.control.api_max_supported });
    };
    if (why == error.OutOfMemory) return error.OutOfMemory;
    var buf: [1200]u8 = undefined;
    r.fail("{s}", .{main.rexProblem(&buf, why, where.buffered())});
}

/// The backend secret and token files. Returns the backend secret, for matching the Serve target.
fn checkSecrets(arena: Allocator, io: Io, parsed: cli.Parsed, r: *Report) !?[]const u8 {
    var secret: ?[]const u8 = null;
    if (parsed.backend_secret_file) |path| {
        secret = checkSecretFile(arena, io, r, "the backend secret", path, xfer.min_secret_len, parsed.make_backend_secret, .{ .item_option = "--backend-secret-file", .folder_option = if (parsed.make_backend_secret) "--config-dir" else null, .made_by_rweb = parsed.make_backend_secret });
    }
    if (parsed.token_file) |path| {
        _ = checkSecretFile(arena, io, r, "the token", path, cli.min_token_len, parsed.make_token_file, .{ .item_option = "--token-file", .folder_option = if (parsed.make_token_file) "--config-dir" else null, .made_by_rweb = parsed.make_token_file });
    }
    if (parsed.token != null) r.warn("--token is on the command line, where every user can read it; use --token-file", .{});
    return secret;
}

fn checkSecretFile(arena: Allocator, io: Io, r: *Report, what: []const u8, path: []const u8, min_len: usize, made_by_rweb: bool, hints: xfer.Hints) ?[]const u8 {
    var problem: xfer.Problem = .{};
    const text = main.readSecretFile(arena, io, path, min_len, true, &problem) catch |e| {
        if (e == error.FileNotFound and made_by_rweb) {
            r.warn("{s} ({s}) is not there yet; rweb makes it when it starts", .{ what, path });
            return null;
        }
        r.fail("{s} ({s})", .{ what, path });
        var buf: [2048]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        layout.explain(&w, what, path, e, &problem, hints) catch {};
        r.detail(w.buffered());
        return null;
    };
    r.ok("{s}: {s} is private and long enough", .{ what, path });
    return text;
}

fn checkUploads(arena: Allocator, io: Io, parsed: cli.Parsed, r: *Report) !void {
    if (!parsed.enable_file_transfer) return;
    const dir = parsed.upload_dir orelse return r.ok("file transfer: downloads on, uploads off", .{});
    var problem: xfer.Problem = .{};
    const up = xfer.openUploadDir(arena, io, dir, false, &problem) catch |e| {
        if (e == error.FileNotFound) return r.warn("the upload folder {s} is not there yet; rweb makes it when it starts", .{dir});
        r.fail("the upload folder {s}", .{dir});
        var buf: [2048]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        layout.explain(&w, "the upload folder", dir, e, &problem, .{ .item_option = "--upload-dir" }) catch {};
        return r.detail(w.buffered());
    };
    up.dir.close(io);
    up.parts.close(io);
    r.ok("the upload folder {s} is ours alone", .{dir});
}

fn checkBridge(gpa: Allocator, arena: Allocator, io: Io, parsed: cli.Parsed, r: *Report) !void {
    switch (parsed.listen) {
        .unix => |path| {
            var problem: xfer.Problem = .{};
            const state = server.checkSocket(gpa, io, path, &problem) catch |e| {
                if (e == error.OutOfMemory) return error.OutOfMemory;
                r.fail("the socket's folder, for {s}", .{path});
                var buf: [2048]u8 = undefined;
                var w: Io.Writer = .fixed(&buf);
                layout.explain(&w, "the socket", path, e, &problem, .{ .item_option = "--listen-unix" }) catch {};
                return r.detail(w.buffered());
            };
            switch (state) {
                .listening => r.ok("a bridge is listening on unix:{s}", .{path}),
                .missing_folder, .no_socket => r.fail("no bridge is running: nothing at unix:{s}. Start rweb (or its service)", .{path}),
                .stale => r.fail("unix:{s} is left from a bridge that stopped; nothing answers. Start rweb (or its service)", .{path}),
                .not_a_socket => r.fail("{s} is not a socket; rweb will not start there. Remove it, or choose another path", .{path}),
            }
        },
        .tcp => |port| {
            const addr: Io.net.IpAddress = .{ .ip4 = .loopback(port) };
            if (addr.connect(io, .{ .mode = .stream })) |conn| {
                conn.close(io);
                r.ok("a bridge is listening on 127.0.0.1:{d}", .{port});
            } else |_| r.fail("no bridge is running: nothing answers on 127.0.0.1:{d}. Start rweb (or its service)", .{port});
        },
    }
    _ = arena;
}

fn checkTailscale(arena: Allocator, io: Io, parsed: cli.Parsed, secret: ?[]const u8, r: *Report) !void {
    const candidates = main.tailscaleCandidates(builtin.os.tag);
    const ts = switch (main.chooseTailscale(parsed.tailscale, candidates, main.SystemProbe{ .arena = arena, .io = io }, main.systemProbe)) {
        .ok => |p| p,
        .none => return r.fail("Tailscale: no tailscale program in the places rweb looks; install it, or pass --tailscale PATH", .{}),
        .refused => |ref| {
            r.fail("Tailscale: the program at {s}", .{ref.path});
            var buf: [2048]u8 = undefined;
            var w: Io.Writer = .fixed(&buf);
            layout.explain(&w, "the tailscale program", ref.path, ref.why, &ref.problem, .{ .item_option = "--tailscale" }) catch {};
            return r.detail(w.buffered());
        },
    };

    const status = main.runTailscale(arena, io, &.{ ts, "status", "--json" }) catch |e|
        return r.fail("Tailscale: `{s} status` did not answer ({t})", .{ ts, e });
    if (status.term != .exited or status.term.exited != 0)
        return r.fail("Tailscale: `{s} status` failed; is tailscaled running?", .{ts});
    const node = parseStatus(arena, status.stdout) catch
        return r.fail("Tailscale: `{s} status --json` gave something rweb cannot read", .{ts});
    if (!std.mem.eql(u8, node.backend_state, "Running"))
        return r.fail("Tailscale is not connected (state {s}): sign in with `tailscale up` or the Tailscale app", .{node.backend_state});
    const dns = node.dns_name orelse return r.fail("Tailscale: this node has no MagicDNS name; turn on MagicDNS for the tailnet", .{});
    if (node.tagged) {
        if (parsed.owner_from_tailscale)
            r.fail("Tailscale: {s} is a tagged device, so it has no owner login; pass --owner LOGIN and --allow-host {s}", .{ dns, dns })
        else
            r.ok("Tailscale: {s}, a tagged device (the owner is named with --owner)", .{dns});
    } else if (main.ownerFromStatus(arena, status.stdout)) |login| {
        r.ok("Tailscale: {s}, signed in as {s} ({s})", .{ dns, login, ts });
    } else |_| r.ok("Tailscale: {s} ({s})", .{ dns, ts });
    if (node.cert_domains == 0)
        r.fail("Tailscale: HTTPS certificates are off for the tailnet; turn them on (admin console, DNS, HTTPS Certificates)", .{})
    else
        r.ok("Tailscale: HTTPS certificates are on", .{});

    if (parsed.command != .tailscale) return;
    const target: Target = switch (parsed.listen) {
        .unix => |p| .{ .unix = p },
        .tcp => |port| .{ .tcp = .{ .port = port, .secret = secret } },
    };
    const serve = main.runTailscale(arena, io, &.{ ts, "serve", "status", "--json" }) catch |e|
        return r.fail("Tailscale Serve: `{s} serve status` did not answer ({t})", .{ ts, e });
    if (serve.term != .exited or serve.term.exited != 0)
        return r.fail("Tailscale Serve: `{s} serve status` failed", .{ts});
    const found = findServe(arena, serve.stdout, target) catch
        return r.fail("Tailscale Serve: `{s} serve status --json` gave something rweb cannot read", .{ts});
    switch (found) {
        .entry => |e| {
            if (e.funnel) r.fail("Tailscale Serve: https://{s}/ also has Funnel on, which opens it to the internet; rweb refuses those requests, but turn Funnel off: tailscale funnel --https={s} off", .{ e.host_port, portOf(e.host_port) }) else r.ok("Tailscale Serve: https://{s}/ forwards to this bridge", .{e.host_port});
        },
        .old_secret => |hp| r.fail("Tailscale Serve: https://{s}/ forwards to 127.0.0.1 with another secret than {s}; run the `tailscale serve` line below again", .{ hp, parsed.backend_secret_file orelse "the backend secret file" }),
        .none => r.fail("Tailscale Serve: nothing forwards to this bridge", .{}),
    }
    if (found != .entry) {
        var buf: [4096]u8 = undefined;
        var w: Io.Writer = .fixed(&buf);
        const on: layout.Served = switch (parsed.listen) {
            .unix => |p| .{ .unix = p },
            .tcp => |p| .{ .tcp = p },
        };
        layout.tailscaleNextStep(&w, on, parsed.backend_secret_file, dns) catch {};
        r.detail(w.buffered());
    }
}

fn portOf(host_port: []const u8) []const u8 {
    const c = std.mem.lastIndexOfScalar(u8, host_port, ':') orelse return "443";
    return host_port[c + 1 ..];
}

// ---- what Tailscale says, read (pure, tested) ----

pub const Node = struct {
    backend_state: []const u8,
    dns_name: ?[]const u8,
    tagged: bool,
    cert_domains: usize,
};

/// The parts of `tailscale status --json` doctor looks at.
pub fn parseStatus(arena: Allocator, json: []const u8) !Node {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    if (v != .object) return error.BadStatus;
    const o = v.object;
    const state = o.get("BackendState") orelse return error.BadStatus;
    if (state != .string) return error.BadStatus;
    var node: Node = .{ .backend_state = state.string, .dns_name = null, .tagged = false, .cert_domains = 0 };
    if (o.get("CertDomains")) |c| if (c == .array) {
        node.cert_domains = c.array.items.len;
    };
    if (o.get("Self")) |self| if (self == .object) {
        if (self.object.get("DNSName")) |d| if (d == .string) {
            const name = std.mem.trimEnd(u8, d.string, ".");
            if (name.len > 0) node.dns_name = name;
        };
        if (self.object.get("Tags")) |t| if (t == .array and t.array.items.len > 0) {
            node.tagged = true;
        };
    };
    return node;
}

/// Where the bridge listens, as a Serve target names it.
pub const Target = union(enum) {
    unix: []const u8,
    tcp: struct { port: u16, secret: ?[]const u8 },
};

pub const Found = union(enum) {
    /// A handler forwards to the bridge, at `host_port` (`name:port`); `funnel` when Funnel is on there.
    entry: struct { host_port: []const u8, funnel: bool },
    /// A handler forwards to the bridge's port with a first path segment that is not the secret.
    old_secret: []const u8,
    none,
};

/// Which Serve handler, in `tailscale serve status --json`, forwards to `target`.
pub fn findServe(arena: Allocator, json: []const u8, target: Target) !Found {
    const v = try std.json.parseFromSliceLeaky(std.json.Value, arena, json, .{});
    if (v != .object) return error.BadServe;
    var old: ?[]const u8 = null;
    const web = v.object.get("Web") orelse return .none;
    if (web != .object) return error.BadServe;
    var it = web.object.iterator();
    while (it.next()) |site| {
        if (site.value_ptr.* != .object) continue;
        const handlers = site.value_ptr.object.get("Handlers") orelse continue;
        if (handlers != .object) continue;
        var hit = handlers.object.iterator();
        while (hit.next()) |h| {
            if (h.value_ptr.* != .object) continue;
            const proxy = h.value_ptr.object.get("Proxy") orelse continue;
            if (proxy != .string) continue;
            switch (matchProxy(proxy.string, target)) {
                .yes => return .{ .entry = .{ .host_port = site.key_ptr.*, .funnel = funnelOn(v.object, site.key_ptr.*) } },
                .other_secret => old = site.key_ptr.*,
                .no => {},
            }
        }
    }
    return if (old) |hp| .{ .old_secret = hp } else .none;
}

fn funnelOn(top: std.json.ObjectMap, host_port: []const u8) bool {
    const f = top.get("AllowFunnel") orelse return false;
    if (f != .object) return false;
    const on = f.object.get(host_port) orelse return false;
    return on == .bool and on.bool;
}

const Match = enum { yes, other_secret, no };

fn matchProxy(proxy: []const u8, target: Target) Match {
    switch (target) {
        .unix => |path| {
            const p = if (std.mem.startsWith(u8, proxy, "unix:")) proxy["unix:".len..] else return .no;
            return if (std.mem.eql(u8, p, path)) .yes else .no;
        },
        .tcp => |t| {
            var buf: [32]u8 = undefined;
            for ([_][]const u8{ "http://127.0.0.1", "http://localhost" }) |host| {
                const prefix = std.fmt.bufPrint(&buf, "{s}:{d}", .{ host, t.port }) catch return .no;
                if (!std.mem.startsWith(u8, proxy, prefix)) continue;
                const rest = std.mem.trimEnd(u8, proxy[prefix.len..], "/");
                if (rest.len > 0 and rest[0] != '/') continue; // a longer port number
                const secret = t.secret orelse return .yes; // not read: the port is what can be checked
                if (rest.len > 1 and @import("access.zig").constantTimeEql(rest[1..], secret)) return .yes;
                return .other_secret;
            }
            return .no;
        },
    }
}

// ---- tests ----

const testing = std.testing;

test "doctor reads tailscale status: state, name, tags, certificates" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const n = try parseStatus(a,
        \\{"BackendState":"Running","CertDomains":["box.example.ts.net"],
        \\ "Self":{"DNSName":"box.example.ts.net.","Tags":null,"UserID":1}}
    );
    try testing.expectEqualStrings("Running", n.backend_state);
    try testing.expectEqualStrings("box.example.ts.net", n.dns_name.?);
    try testing.expect(!n.tagged and n.cert_domains == 1);
    const t = try parseStatus(a,
        \\{"BackendState":"NeedsLogin","CertDomains":null,"Self":{"DNSName":"","Tags":["tag:gateway"]}}
    );
    try testing.expect(t.tagged and t.dns_name == null and t.cert_domains == 0);
    try testing.expectError(error.BadStatus, parseStatus(a, "[]"));
    try testing.expectError(error.BadStatus, parseStatus(a, "{\"Self\":{}}"));
}

test "doctor finds the Serve handler that forwards to the bridge, and Funnel on it" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    const json =
        \\{"TCP":{"443":{"HTTPS":true},"12443":{"HTTPS":true}},
        \\ "Web":{"box.example.ts.net:12443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7317"}}},
        \\        "box.example.ts.net:443":{"Handlers":{"/":{"Proxy":"unix:/run/user/1000/rweb/bridge.sock"}}}},
        \\ "AllowFunnel":{"box.example.ts.net:12443":true}}
    ;
    const f = try findServe(a, json, .{ .unix = "/run/user/1000/rweb/bridge.sock" });
    try testing.expectEqualStrings("box.example.ts.net:443", f.entry.host_port);
    try testing.expect(!f.entry.funnel);
    try testing.expect(try findServe(a, json, .{ .unix = "/run/user/1000/rweb/ssh.sock" }) == .none);
    // A port behind a secret: the right secret, another, a longer port, Funnel.
    const mac =
        \\{"Web":{"mac.example.ts.net:12443":{"Handlers":{"/":{"Proxy":"http://127.0.0.1:7695/s3cret"}}}},
        \\ "AllowFunnel":{"mac.example.ts.net:12443":true}}
    ;
    const ok = try findServe(a, mac, .{ .tcp = .{ .port = 7695, .secret = "s3cret" } });
    try testing.expect(ok.entry.funnel);
    try testing.expectEqualStrings("mac.example.ts.net:12443", (try findServe(a, mac, .{ .tcp = .{ .port = 7695, .secret = "other" } })).old_secret);
    try testing.expect(try findServe(a, mac, .{ .tcp = .{ .port = 769, .secret = "s3cret" } }) == .none);
    try testing.expect(try findServe(a, mac, .{ .tcp = .{ .port = 7695, .secret = null } }) == .entry);
    try testing.expect(try findServe(a, "{}", .{ .unix = "/x" }) == .none);
    try testing.expectError(error.BadServe, findServe(a, "{\"Web\":[]}", .{ .unix = "/x" }));
    try testing.expectEqualStrings("12443", portOf("mac.example.ts.net:12443"));
}
