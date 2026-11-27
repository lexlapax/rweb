//! The fixed workload of the Zig audit's Phase B (docs/zig-idiom-audit-2026-11-26.md, section 4), used
//! to choose the release allocator and to measure later steps. Not a test of behaviour: it runs only
//! when `RWEB_BENCH` is set, and prints its numbers. `RWEB_BENCH_ALLOC` picks the bridge's allocator
//! (`safe`, what a ReleaseSafe binary gets from std today; `smp`; `c`). Run each in its own process:
//!
//!     RWEB_BENCH=1 RWEB_BENCH_ALLOC=smp zig build test -Doptimize=ReleaseSafe -Dtest-filter=bench: 2>&1 | grep '^bench'
//!
//! The bridge (Rex client, hub, server) runs on the chosen allocator. The fake Rex and the browsers
//! stand for other processes and always run on `smp_allocator`, so what changes between runs is the
//! bridge's allocator only; the process's CPU time and memory include them, the same in every run.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const rex = @import("rex");
const fake = rex.fake;
const Hub = @import("hub.zig").Hub;
const server = @import("server.zig");

/// MiB of output per phase; `RWEB_BENCH_MIB` overrides it (a small number for a Debug run).
const default_output_mib = 32;
const keys = 1000;

fn nowNs(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

const Usage = struct { cpu_us: i64, maxrss_kib: i64, minflt: i64 };

fn usage() Usage {
    const r = std.posix.getrusage(0); // RUSAGE_SELF
    const cpu = (@as(i64, r.utime.sec) + @as(i64, r.stime.sec)) * 1_000_000 + @as(i64, r.utime.usec) + @as(i64, r.stime.usec);
    // macOS reports bytes, Linux kibibytes.
    const rss: i64 = if (builtin.os.tag.isDarwin()) @divTrunc(@as(i64, r.maxrss), 1024) else @as(i64, r.maxrss);
    return .{ .cpu_us = cpu, .maxrss_kib = rss, .minflt = @as(i64, r.minflt) };
}

/// Resident memory now, on Linux (`/proc/self/statm`); null elsewhere.
fn residentKib(io: Io) ?i64 {
    if (builtin.os.tag != .linux) return null;
    var buf: [128]u8 = undefined;
    const text = Io.Dir.cwd().readFile(io, "/proc/self/statm", &buf) catch return null;
    var it = std.mem.tokenizeScalar(u8, text, ' ');
    _ = it.next();
    const pages = std.fmt.parseInt(i64, it.next() orelse return null, 10) catch return null;
    return pages * @divTrunc(@as(i64, @intCast(std.heap.pageSize())), 1024);
}

const Browser = struct {
    conn: *rex.ws.Conn,

    fn connect(io: Io, port: u16, token: []const u8) !Browser {
        const gpa = std.heap.smp_allocator;
        var addr = Io.net.IpAddress{ .ip4 = Io.net.Ip4Address.loopback(port) };
        const stream = try addr.connect(io, .{ .mode = .stream });
        const path = try gpa.print("/ws?token={s}", .{token});
        defer gpa.free(path);
        return .{ .conn = try rex.ws.Conn.connectStream(gpa, io, stream, path, null, "Origin: http://localhost\r\n") };
    }

    fn deinit(b: Browser) void {
        b.conn.deinit(std.heap.smp_allocator);
    }

    fn send(b: Browser, comptime fmt: []const u8, args: anytype) !void {
        var buf: [512]u8 = undefined;
        try b.conn.writeFrame(.text, try std.fmt.bufPrint(&buf, fmt, args));
    }

    /// Read until a frame of `opcode` holds `needle`; returns the bytes of binary frames read.
    fn until(b: Browser, opcode: rex.ws.Opcode, needle: []const u8) !u64 {
        const gpa = std.heap.smp_allocator;
        var got: u64 = 0;
        while (true) {
            const m = try b.conn.readMessage(gpa);
            defer gpa.free(m.data);
            if (m.opcode == .close) return error.Closed;
            if (m.opcode == .binary) got += m.data.len;
            if (m.opcode == opcode and std.mem.indexOf(u8, m.data, needle) != null) return got;
        }
    }
};

fn openTerminal(b: Browser, sid: []const u8, bid: []const u8) !void {
    _ = try b.until(.text, "\"t\":\"tree\"");
    try b.send("{{\"t\":\"open\",\"session\":\"{s}\",\"block\":\"{s}\"}}", .{ sid, bid });
    _ = try b.until(.text, "\"t\":\"opened\"");
}

fn readUntilMarker(b: Browser, marker: []const u8, out: *u64) void {
    out.* = b.until(.binary, marker) catch 0;
}

/// Feed `mib` MiB of plain lines into the terminal, then the marker.
fn feedOutput(f: *fake.Fake, bid: []const u8, mib: usize, marker: []const u8) !void {
    var line: [80]u8 = undefined;
    var chunk: std.ArrayList(u8) = .empty;
    defer chunk.deinit(std.heap.smp_allocator);
    var sent: usize = 0;
    var n: usize = 0;
    while (sent < mib * 1024 * 1024) {
        chunk.clearRetainingCapacity();
        while (chunk.items.len < 16 * 1024) : (n += 1) {
            const l = try std.fmt.bufPrint(&line, "line {d:0>8} the quick brown fox jumps over the lazy dog\r\n", .{n});
            try chunk.appendSlice(std.heap.smp_allocator, l);
        }
        try f.feed(bid, chunk.items);
        sent += chunk.items.len;
    }
    try f.feed(bid, marker);
}

fn outputPhase(io: Io, f: *fake.Fake, viewers: []const Browser, bid: []const u8, label: []const u8, marker: []const u8, output_mib: usize) !void {
    var got: [3]u64 = @splat(0);
    var tasks: [3]?Io.Future(void) = @splat(null);
    const before = usage();
    const t0 = nowNs(io);
    for (viewers, 0..) |v, i| tasks[i] = try io.concurrent(readUntilMarker, .{ v, marker, &got[i] });
    try feedOutput(f, bid, output_mib, marker);
    for (&tasks) |*t| if (t.*) |*x| x.await(io);
    const ms = @divTrunc(nowNs(io) - t0, 1_000_000);
    const after = usage();
    std.debug.print("bench {s}: {d} MiB to {d} viewer(s): {d} ms wall, {d} ms CPU, peak RSS {d} KiB, {d} page faults; received", .{
        label, output_mib, viewers.len, ms, @divTrunc(after.cpu_us - before.cpu_us, 1000), after.maxrss_kib, after.minflt - before.minflt,
    });
    for (viewers, 0..) |_, i| std.debug.print(" {d} KiB", .{got[i] / 1024});
    std.debug.print("\n", .{});
    for (viewers, 0..) |_, i| if (got[i] == 0) return error.MarkerNotSeen;
}

test "bench: output, viewers and keystrokes through the bridge (only with RWEB_BENCH)" {
    if (testing.environ.getPosix("RWEB_BENCH") == null) return error.SkipZigTest;
    const which = testing.environ.getPosix("RWEB_BENCH_ALLOC") orelse "safe";
    const io = testing.io;

    var safe_state: std.heap.SafeAllocator = .init(std.heap.page_allocator, .{});
    defer _ = safe_state.deinit();
    const gpa: Allocator = if (std.mem.eql(u8, which, "safe"))
        safe_state.allocator()
    else if (std.mem.eql(u8, which, "smp"))
        std.heap.smp_allocator
    else if (std.mem.eql(u8, which, "c"))
        std.heap.c_allocator
    else
        return error.UnknownAllocator;

    const f = try fake.Fake.start(std.heap.smp_allocator, io);
    defer f.deinit();
    const made = try f.createSession("rweb-test-bench");
    const ctl = try rex.control.Control.open(gpa, io, .{ .socket_path = f.path });
    defer ctl.close();
    const hub = try Hub.open(gpa, io, ctl, .{});
    defer hub.close();
    var raw: [16]u8 = undefined;
    io.random(&raw);
    const token = std.fmt.bytesToHex(raw, .lower);
    const srv = try server.Server.start(gpa, io, hub, .{
        .listen = .{ .tcp_loopback = 0 },
        .access = .{ .token = &token },
        // The simulated browsers only read while output flows; a real page pings, these do not.
        .silent_limit_ms = 600_000,
    });
    defer srv.stop();

    std.debug.print("bench allocator {s} ({s}, {s})\n", .{ which, @tagName(builtin.mode), @tagName(builtin.os.tag) });
    const output_mib: usize = if (testing.environ.getPosix("RWEB_BENCH_MIB")) |v| try std.fmt.parseInt(usize, v, 10) else default_output_mib;
    const start = usage();

    // One viewer, then three.
    var vs: [3]Browser = undefined;
    for (&vs) |*v| v.* = try Browser.connect(io, srv.port, &token);
    defer for (vs) |v| v.deinit();
    try openTerminal(vs[0], made.session_id, made.block_id);
    try outputPhase(io, f, vs[0..1], made.block_id, which, "END-OF-OUTPUT-ONE", output_mib);
    try openTerminal(vs[1], made.session_id, made.block_id);
    try openTerminal(vs[2], made.session_id, made.block_id);
    try outputPhase(io, f, vs[0..3], made.block_id, which, "END-OF-OUTPUT-THREE", output_mib);

    // Keystrokes: each typed word, timed until its echo reaches the viewer.
    var rtt: [keys]i64 = undefined;
    const ku0 = usage();
    const kt0 = nowNs(io);
    for (&rtt, 0..) |*r, i| {
        var word: [16]u8 = undefined;
        const w = try std.fmt.bufPrint(&word, "k{d:0>5}x", .{i});
        const t0 = nowNs(io);
        try vs[0].send("{{\"t\":\"in\",\"d\":\"{s} \"}}", .{w});
        _ = try vs[0].until(.binary, w);
        r.* = @intCast(@divTrunc(nowNs(io) - t0, 1000));
        // One key every 10 ms at most: far faster than anyone types, and under the bridge's limit of
        // 200 messages a second per browser (over it, the browser is closed as a flood).
        const spent = nowNs(io) - t0;
        if (spent < 10_000_000) try io.sleep(.fromNanoseconds(@intCast(10_000_000 - spent)), .awake);
    }
    const kms = @divTrunc(nowNs(io) - kt0, 1_000_000);
    const ku1 = usage();
    std.mem.sort(i64, &rtt, {}, std.sort.asc(i64));
    std.debug.print("bench {s}: {d} keystrokes: round trip median {d} us, p99 {d} us, max {d} us; {d} ms wall, {d} ms CPU\n", .{
        which, keys, rtt[keys / 2], rtt[keys * 99 / 100], rtt[keys - 1], kms, @divTrunc(ku1.cpu_us - ku0.cpu_us, 1000),
    });

    // Settled: after the work, a pause, then memory.
    try io.sleep(.fromSeconds(3), .awake);
    const end = usage();
    std.debug.print("bench {s}: total CPU {d} ms, peak RSS {d} KiB, page faults {d}, resident after 3 s idle {?d} KiB\n", .{
        which, @divTrunc(end.cpu_us - start.cpu_us, 1000), end.maxrss_kib, end.minflt - start.minflt, residentKib(io),
    });
}
