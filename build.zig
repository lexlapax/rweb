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

    const filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this") orelse &.{};
    const tests = b.addTest(.{ .root_module = rex, .filters = filters });
    const run_tests = b.addRunArtifact(tests);
    run_tests.has_side_effects = true; // live tests read REX_SOCKET, which the cache cannot see
    // The bridge: imports the Rex library and, through it, Ghostty.
    const bridge_mod = b.createModule(.{
        .root_source_file = b.path("src/bridge/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    bridge_mod.addImport("rex", rex);
    if (ghostty) |dep| bridge_mod.addImport("ghostty-vt", dep.module("ghostty-vt"));
    const exe = b.addExecutable(.{ .name = "rweb", .root_module = bridge_mod });
    b.installArtifact(exe);
    const run_exe = b.addRunArtifact(exe);
    run_exe.addPassthruArgs();
    b.step("run", "Run the bridge").dependOn(&run_exe.step);

    const bridge_tests = b.addTest(.{ .root_module = bridge_mod, .filters = filters });
    const run_bridge_tests = b.addRunArtifact(bridge_tests);
    run_bridge_tests.has_side_effects = true;

    // Fuzz targets for the byte parsers. A separate module without Ghostty: its C++ is not
    // instrumented for fuzzing, so linking it into a fuzz build fails.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_mod });
    const run_fuzz = b.addRunArtifact(fuzz_tests);
    b.step("fuzz", "Fuzz the parsers: zig build fuzz --fuzz").dependOn(&run_fuzz.step);

    // The page's pure logic (needs Node). Not part of `test`, so a machine without Node still builds.
    const web_tests = b.addSystemCommand(&.{ "node", "--test", "tests/web/keys.test.mjs" });
    b.step("web-test", "Test the page's key logic with Node").dependOn(&web_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_bridge_tests.step);
    test_step.dependOn(&run_fuzz.step);
}
