//! The rweb bridge: shows Rex terminal sessions in a web browser.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const rex = @import("rex");

pub const access = @import("access.zig");
pub const protocol = @import("protocol.zig");
pub const hub = @import("hub.zig");
pub const assets = @import("assets.zig");
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

    // A token, if asked for.
    var token = parsed.token;
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
    const h = try hub.Hub.open(gpa, io, ctl, .{ .observe_only = parsed.observe_only, .history_lines = parsed.history_lines });
    defer h.close();

    const listen: server.Listen = switch (parsed.listen) {
        .unix => |p| .{ .unix = p },
        .tcp => |port| .{ .tcp_loopback = port },
    };
    const srv = try server.Server.start(gpa, io, h, .{
        .listen = listen,
        .debug_input = parsed.debug_input,
        .access = .{
            .owner = parsed.owner,
            .token = token,
            .own_addresses = own.items,
            .allow_own_address = parsed.allow_own_address,
            .allowed_peer_uids = if (parsed.peer_uids != null) uids.items else null,
        },
    });
    defer srv.stop();

    switch (listen) {
        .unix => |p| std.debug.print("rweb: listening on unix:{s} (Rex at {s}){s}\n", .{ p, rex_socket, if (parsed.observe_only) ", observe-only" else "" }),
        .tcp_loopback => {
            std.debug.print("rweb: listening on http://127.0.0.1:{d}/ (Rex at {s}){s}\n", .{ srv.port, rex_socket, if (parsed.observe_only) ", observe-only" else "" });
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

test {
    _ = access;
    _ = protocol;
    _ = hub;
    _ = assets;
    _ = server;
    _ = cli;
}
