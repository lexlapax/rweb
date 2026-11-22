const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // Ghostty is built in the same mode as the rest: a Debug Ghostty is ~400x slower.
    const ghostty = b.lazyDependency("ghostty", .{ .target = target, .optimize = optimize });

    const rex = b.addModule("rex", .{
        .root_source_file = b.path("src/rex/root.zig"),
        .target = target,
        .optimize = optimize,
    });
    if (ghostty) |dep| rex.addImport("ghostty-vt", dep.module("ghostty-vt"));

    const tests = b.addTest(.{ .root_module = rex });
    const run_tests = b.addRunArtifact(tests);
    run_tests.has_side_effects = true; // live tests read REX_SOCKET, which the cache cannot see
    b.step("test", "Run unit tests (add --fuzz to fuzz the parsers)").dependOn(&run_tests.step);
}
