const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    // Pass the mode through: without it Ghostty builds as Debug, with its slow
    // integrity checks, whatever mode the spike uses.
    if (b.lazyDependency("ghostty", .{ .target = target, .optimize = optimize })) |dep| {
        mod.addImport("ghostty-vt", dep.module("ghostty-vt"));
    }

    const exe = b.addExecutable(.{ .name = "rweb-spike", .root_module = mod });
    b.installArtifact(exe);

    const run = b.addRunArtifact(exe);
    run.addPassthruArgs();
    b.step("run", "Run the spike").dependOn(&run.step);
}
