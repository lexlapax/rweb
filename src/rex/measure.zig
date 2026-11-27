//! Measurements for the Zig audit's Phase B (docs/zig-idiom-audit-2026-11-26.md, section 4): what one
//! Rex call costs this client in allocations, bytes and time, against the fake server. Not a test of
//! behaviour: it runs only when `RWEB_MEASURE` is set, and prints its numbers. Build it in ReleaseSafe
//! for times that mean something:
//!
//!     RWEB_MEASURE=1 zig build test -Doptimize=ReleaseSafe 2>&1 | grep '^measure'
//!
//! The fake server runs on its own allocator, so only the client's work is counted (the control
//! connection's reader task included, since a reply is parsed there).

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const fake = @import("fake.zig");
const Control = @import("control.zig").Control;
const api_mod = @import("api.zig");
const Api = api_mod.Api;

const Counting = @import("counting.zig").Counting;

fn nowNs(io: Io) i96 {
    return Io.Clock.awake.now(io).nanoseconds;
}

/// Prints one line: allocations and bytes per call, and microseconds per call.
fn report(name: []const u8, n: u64, before: [2]u64, after: [2]u64, ns: i96) void {
    std.debug.print("measure {s}: {d} allocations, {d} bytes, {d} us per call ({d} calls)\n", .{
        name,
        (after[0] - before[0]) / n,
        (after[1] - before[1]) / n,
        @divTrunc(@as(i128, ns), @as(i128, n) * 1000),
        n,
    });
}

test "measure: the Rex client's calls (only with RWEB_MEASURE)" {
    if (testing.environ.getPosix("RWEB_MEASURE") == null) return error.SkipZigTest;
    const io = testing.io;
    const f = try fake.Fake.start(testing.allocator, io);
    defer f.deinit();
    var counting: Counting = .{ .child = std.heap.smp_allocator };
    const gpa = counting.allocator();
    const ctl = try Control.open(gpa, io, .{ .socket_path = f.path });
    defer ctl.close();
    var api = Api.init(gpa, ctl);
    defer api.deinit();

    // 50 sessions, as a tree refresh on a busy machine would see.
    var ids: [50]struct { sid: []const u8, bid: []const u8 } = undefined;
    for (&ids, 0..) |*s, i| {
        var lb: [32]u8 = undefined;
        const made = try f.createSession(try std.fmt.bufPrint(&lb, "rweb-test-measure-{d}", .{i}));
        s.* = .{ .sid = made.session_id, .bid = made.block_id };
    }
    try api.attach(ids[0].sid);
    const n: u64 = 200;

    // Warm up, so first-use growth is not counted.
    for (0..20) |_| {
        var l = try api.sessions();
        l.deinit();
    }

    {
        const b = counting.snap();
        const t0 = nowNs(io);
        for (0..n) |_| {
            var l = try api.sessions();
            if (l.value.len != 50) return error.TestUnexpectedResult;
            l.deinit();
        }
        report("session.list (50 sessions)", n, b, counting.snap(), nowNs(io) - t0);
    }
    {
        const b = counting.snap();
        const t0 = nowNs(io);
        for (0..n) |_| {
            var l = try api.blocks(ids[0].sid);
            l.deinit();
        }
        report("session.list_blocks", n, b, counting.snap(), nowNs(io) - t0);
    }
    {
        const b = counting.snap();
        const t0 = nowNs(io);
        for (0..n) |_| try api.paste(ids[0].sid, ids[0].bid, "echo measured");
        report("block.event (paste)", n, b, counting.snap(), nowNs(io) - t0);
    }
    {
        const b = counting.snap();
        const t0 = nowNs(io);
        for (0..n) |_| try api.resize(ids[0].sid, ids[0].bid, 80, 24);
        report("terminal.resize", n, b, counting.snap(), nowNs(io) - t0);
    }
    {
        // A tree refresh: the list, then each session's terminals.
        const rounds: u64 = 20;
        const b = counting.snap();
        const t0 = nowNs(io);
        for (0..rounds) |_| {
            var l = try api.sessions();
            defer l.deinit();
            for (l.value) |s| {
                var bl = try api.blocks(s.session_id);
                bl.deinit();
            }
        }
        report("tree refresh (list + 50 x list_blocks)", rounds, b, counting.snap(), nowNs(io) - t0);
    }
}
