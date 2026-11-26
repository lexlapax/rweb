//! Run a program and collect what it prints, with one deadline for all of it: the program's output
//! and its exit together. The standard library's `std.process.run` (Zig 0.17.1) does not give that:
//! its timeout restarts with every read, it then waits for the exit without any limit (a program that
//! closes its output and stays is waited for forever), and its cleanup sends SIGTERM and waits again
//! without limit (so is a program that ignores SIGTERM). Here a program that is still there at the
//! deadline is killed with SIGKILL, which it cannot refuse, and reaped.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const Allocator = std.mem.Allocator;

comptime {
    // `waitpid` with `WNOHANG` and `kill`, through libc: the targets rweb is built for.
    if (!builtin.link_libc or !(builtin.os.tag == .linux or builtin.os.tag.isDarwin())) @compileError("proc.zig is written for Linux and macOS with libc");
}

pub const Options = struct {
    argv: []const []const u8,
    /// From the start of the call to the program's exit, reaped.
    timeout_ms: u32,
    /// The most the program may print on standard output, and the most on standard error.
    output_max: usize,
};

pub const Result = struct {
    term: std.process.Child.Term,
    /// The caller's to free, as is `stderr`.
    stdout: []u8,
    stderr: []u8,
};

pub const Error = error{ Timeout, StreamTooLong, WaitFailed } || std.process.SpawnError || Io.File.MultiReader.UnendingError || Allocator.Error || Io.Cancelable;

pub fn run(gpa: Allocator, io: Io, options: Options) Error!Result {
    const end_ms = nowMs(io) + options.timeout_ms;
    var child = try std.process.spawn(io, .{
        .argv = options.argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer end(&child, io);

    var buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var readers: Io.File.MultiReader = undefined;
    readers.init(gpa, io, buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer readers.deinit();
    while (true) {
        const left = end_ms - nowMs(io);
        if (left <= 0) return error.Timeout;
        readers.fill(64, .{ .duration = .{ .raw = .fromMilliseconds(left), .clock = .awake } }) catch |e| switch (e) {
            error.EndOfStream => break,
            error.Timeout, error.Canceled, error.ConcurrencyUnavailable => |other| return other,
        };
        if (readers.reader(0).buffered().len > options.output_max or readers.reader(1).buffered().len > options.output_max) return error.StreamTooLong;
    }
    try readers.checkAnyError();

    const term = try waitUntil(&child, io, end_ms);
    const stdout = try readers.toOwnedSlice(0);
    errdefer gpa.free(stdout);
    const stderr = try readers.toOwnedSlice(1);
    return .{ .term = term, .stdout = stdout, .stderr = stderr };
}

fn nowMs(io: Io) i64 {
    return Io.Clock.awake.now(io).toMilliseconds();
}

/// The child's exit, asked for without blocking until it has exited or `end_ms` has come. Its output
/// is closed by now, so it has usually exited already; the pauses start at a millisecond.
fn waitUntil(child: *std.process.Child, io: Io, end_ms: i64) error{ Timeout, WaitFailed, Canceled }!std.process.Child.Term {
    const pid = child.id.?;
    var pause_ms: i64 = 1;
    while (true) {
        var status: c_int = undefined;
        const got = std.c.waitpid(pid, &status, std.c.W.NOHANG);
        if (got == pid) {
            child.id = null;
            return Io.Threaded.statusToTerm(@bitCast(status));
        }
        if (got < 0) {
            if (std.c._errno().* == @backingInt(std.c.E.INTR)) continue;
            child.id = null; // not ours to wait for any more
            return error.WaitFailed;
        }
        const left = end_ms - nowMs(io);
        if (left <= 0) return error.Timeout;
        try io.sleep(.fromMilliseconds(@min(pause_ms, left)), .awake);
        pause_ms = @min(pause_ms * 2, 50);
    }
}

/// Leave nothing behind: a child that is still there is killed and reaped, and the pipes are closed.
fn end(child: *std.process.Child, io: Io) void {
    if (child.id) |pid| {
        // SIGKILL cannot be caught or ignored, so the wait that follows ends.
        _ = std.c.kill(pid, .KILL);
        var status: c_int = undefined;
        while (std.c.waitpid(pid, &status, 0) < 0 and std.c._errno().* == @backingInt(std.c.E.INTR)) {}
        child.id = null;
    }
    inline for (.{ "stdin", "stdout", "stderr" }) |name| {
        if (@field(child, name)) |f| {
            f.close(io);
            @field(child, name) = null;
        }
    }
}

const testing = std.testing;

fn sh(script: []const u8, timeout_ms: u32, output_max: usize) Error!Result {
    return run(testing.allocator, testing.io, .{ .argv = &.{ "/bin/sh", "-c", script }, .timeout_ms = timeout_ms, .output_max = output_max });
}

fn free(r: Result) void {
    testing.allocator.free(r.stdout);
    testing.allocator.free(r.stderr);
}

test "run: output, standard error and the exit code of a program that ends" {
    const ok = try sh("printf out; printf err >&2", 10_000, 1024);
    defer free(ok);
    try testing.expectEqualStrings("out", ok.stdout);
    try testing.expectEqualStrings("err", ok.stderr);
    try testing.expect(ok.term == .exited and ok.term.exited == 0);
    const failed = try sh("exit 3", 10_000, 1024);
    defer free(failed);
    try testing.expect(failed.term == .exited and failed.term.exited == 3);
}

/// `script` must not end within the deadline; the call must, soon after it.
fn expectCut(script: []const u8) !void {
    const start = nowMs(testing.io);
    try testing.expectError(error.Timeout, sh(script, 300, 1 << 20));
    const took = nowMs(testing.io) - start;
    // Not early (a timer may fire a few milliseconds short), and not long after.
    if (took < 250 or took >= 5_000) {
        std.debug.print("cut after {d} ms, for a deadline of 300 ms\n", .{took});
        return error.TestUnexpectedResult;
    }
}

test "run: a program that prints nothing and stays is cut at the deadline" {
    try expectCut("exec sleep 30");
}

test "run: a program that closes its output and stays is cut at the deadline" {
    try expectCut("exec >&- 2>&-; exec sleep 30");
}

test "run: a program that ignores SIGTERM is cut at the deadline" {
    try expectCut("trap '' TERM; exec sleep 30");
}

test "run: a program that keeps printing a little is cut at the deadline, not at each silence" {
    try expectCut("while :; do printf x; sleep 0.05; done");
}

test "run: a program that prints more than the limit is stopped" {
    try testing.expectError(error.StreamTooLong, sh("exec yes", 10_000, 4096));
    try testing.expectError(error.StreamTooLong, sh("exec yes >&2", 10_000, 4096));
}

fn runAndFree(gpa: Allocator) !void {
    const r = try run(gpa, testing.io, .{ .argv = &.{ "/bin/sh", "-c", "printf out; printf err >&2" }, .timeout_ms = 10_000, .output_max = 1024 });
    gpa.free(r.stdout);
    gpa.free(r.stderr);
}

test "run: a failed allocation leaks nothing and leaves no child" {
    try testing.checkAllAllocationFailures(testing.allocator, runAndFree, .{});
}

test "run: a program that is not there is an error" {
    if (run(testing.allocator, testing.io, .{ .argv = &.{"/nonexistent/rweb-test-program"}, .timeout_ms = 1000, .output_max = 16 })) |r| {
        free(r);
        return error.TestUnexpectedResult;
    } else |_| {}
}
