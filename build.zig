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
    // Fuzz targets for the byte parsers. A separate module without Ghostty: its C++ is not
    // instrumented for fuzzing, so linking it into a fuzz build fails.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/rex/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_mod });
    const run_fuzz = b.addRunArtifact(fuzz_tests);
    b.step("fuzz", "Fuzz the parsers: zig build fuzz --fuzz").dependOn(&run_fuzz.step);

    b.step("test", "Run unit tests (add --fuzz to fuzz the parsers)").dependOn(&run_tests.step);
}
