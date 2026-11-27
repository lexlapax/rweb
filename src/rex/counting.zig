//! An allocator that counts what passes through it, for the measurements of the Zig audit's Phase B
//! (`src/rex/measure.zig`, `src/bridge/bench.zig`). Safe to share between tasks. With `profile` on, it
//! also groups allocations by the stack that made them, so the busiest call sites can be printed with
//! their source lines (`printSites`). Measurement only: never used by rweb itself.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Frames kept per call site: enough to get past std's lists and allocator wrappers.
const depth = 8;
const max_sites = 512;

const Site = struct { frames: [depth]usize, len: usize, count: u64, bytes: u64 };

pub const Counting = struct {
    child: Allocator,
    allocs: std.atomic.Value(u64) = .init(0),
    bytes: std.atomic.Value(u64) = .init(0),
    /// Group allocations by call site while on.
    profile: std.atomic.Value(bool) = .init(false),
    site_mu: std.atomic.Mutex = .unlocked,
    sites: [max_sites]Site = undefined,
    site_count: usize = 0,

    pub fn allocator(c: *Counting) Allocator {
        return .{ .ptr = c, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }

    /// Allocations and bytes so far.
    pub fn snap(c: *Counting) [2]u64 {
        return .{ c.allocs.load(.monotonic), c.bytes.load(.monotonic) };
    }

    fn note(c: *Counting, len: usize, ra: usize) void {
        _ = c.allocs.fetchAdd(1, .monotonic);
        _ = c.bytes.fetchAdd(len, .monotonic);
        if (!c.profile.load(.monotonic)) return;
        var buf: [depth]usize = undefined;
        const st = std.debug.captureCurrentStackTrace(.{ .first_address = ra }, &buf);
        var key: [depth]usize = @splat(0);
        @memcpy(key[0..st.return_addresses.len], st.return_addresses);
        while (!c.site_mu.tryLock()) std.atomic.spinLoopHint();
        defer c.site_mu.unlock();
        for (c.sites[0..c.site_count]) |*s| if (std.mem.eql(usize, &s.frames, &key)) {
            s.count += 1;
            s.bytes += len;
            return;
        };
        if (c.site_count == max_sites) return;
        c.sites[c.site_count] = .{ .frames = key, .len = st.return_addresses.len, .count = 1, .bytes = len };
        c.site_count += 1;
    }

    /// Forget the call sites counted so far.
    pub fn resetSites(c: *Counting) void {
        while (!c.site_mu.tryLock()) std.atomic.spinLoopHint();
        defer c.site_mu.unlock();
        c.site_count = 0;
    }

    /// Print the `n` busiest call sites since the last `resetSites`, each with its stack, per `per`
    /// units of work (for example per keystroke).
    pub fn printSites(c: *Counting, label: []const u8, n: usize, per: u64) void {
        while (!c.site_mu.tryLock()) std.atomic.spinLoopHint();
        defer c.site_mu.unlock();
        const sites = c.sites[0..c.site_count];
        std.mem.sort(Site, sites, {}, struct {
            fn lt(_: void, a: Site, b: Site) bool {
                return a.count > b.count;
            }
        }.lt);
        var buf: [256]u8 = undefined;
        const stderr = std.debug.lockStderr(&buf);
        defer std.debug.unlockStderr();
        const t = stderr.terminal();
        t.writer.print("sites {s}: {d} call sites\n", .{ label, sites.len }) catch return;
        for (sites[0..@min(n, sites.len)], 0..) |*s, i| {
            t.writer.print("sites {s} #{d}: {d} allocations ({d} per unit), {d} bytes\n", .{ label, i + 1, s.count, s.count / @max(per, 1), s.bytes }) catch return;
            const st: std.debug.StackTrace = .{ .return_addresses = s.frames[0..s.len], .skipped = .none };
            std.debug.writeStackTrace(&st, t) catch return;
        }
    }

    fn alloc(ctx: *anyopaque, len: usize, al: std.mem.Alignment, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.note(len, ra);
        return c.child.rawAlloc(len, al, ra);
    }
    fn resize(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) bool {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const ok = c.child.rawResize(mem, al, new_len, ra);
        if (ok and new_len > mem.len) _ = c.bytes.fetchAdd(new_len - mem.len, .monotonic);
        return ok;
    }
    fn remap(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, new_len: usize, ra: usize) ?[*]u8 {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        const p = c.child.rawRemap(mem, al, new_len, ra);
        if (p != null) c.note(if (new_len > mem.len) new_len - mem.len else 0, ra);
        return p;
    }
    fn free(ctx: *anyopaque, mem: []u8, al: std.mem.Alignment, ra: usize) void {
        const c: *Counting = @ptrCast(@alignCast(ctx));
        c.child.rawFree(mem, al, ra);
    }
};
