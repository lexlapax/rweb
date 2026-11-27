const std = @import("std");
const zon = @import("build.zig.zon");

/// A module `git_commit` with `pub const commit`: the -Dcommit value when given (setup-repo and release
/// builds pass it: they build from a `git archive` export, which has no .git); otherwise the checkout's
/// commit, read by a step that runs on every build, or "unknown" outside a git checkout. Not read while
/// configuring: Zig caches the configure step, so a commit read there goes stale after a `git pull`.
fn commitFile(b: *std.Build, given: ?[]const u8) std.Build.LazyPath {
    if (given) |c| {
        const wf = b.addWriteFiles();
        return wf.add("git_commit.zig", b.fmt("pub const commit = \"{f}\";\n", .{std.zig.fmtString(c)}));
    }
    // A working tree that differs from the commit (edits, new files) says so: `<commit>-dirty`.
    const stamp = b.addSystemCommand(&.{ "sh", "-c", "c=$(git rev-parse HEAD 2>/dev/null) && [ ${#c} -eq 40 ] || c=unknown; [ \"$c\" != unknown ] && [ -n \"$(git status --porcelain 2>/dev/null)\" ] && c=$c-dirty; printf 'pub const commit = \"%s\";\\n' \"$c\"" });
    stamp.setCwd(b.path("."));
    stamp.has_side_effects = true;
    return stamp.captureStdOut(.{ .basename = "git_commit.zig" });
}

/// The Rex library and the bridge for one target, each built on Ghostty for that target in the same mode
/// (a Debug Ghostty is ~400x slower). The one place the bridge's modules are made: the host build, its
/// tests and every release target use it.
const Modules = struct { rex: *std.Build.Module, bridge: *std.Build.Module };

fn bridgeModules(b: *std.Build, target: std.Build.ResolvedTarget, optimize: std.lang.Optimize, opts: *std.Build.Step.Options, commit: std.Build.LazyPath, asset_gen: std.Build.LazyPath, strip: ?bool) Modules {
    const ghostty = b.dependency("ghostty", .{ .target = target, .optimize = optimize });
    const rex = b.createModule(.{ .root_source_file = b.path("src/rex/root.zig"), .target = target, .optimize = optimize });
    rex.addImport("ghostty-vt", ghostty.module("ghostty-vt"));
    // libc: the bridge calls it directly (getpwuid, umask, ACLs on macOS); said here, not left to the
    // dependencies.
    const m = b.createModule(.{ .root_source_file = b.path("src/bridge/main.zig"), .target = target, .optimize = optimize, .strip = strip, .link_libc = true });
    m.addImport("rex", rex);
    m.addImport("ghostty-vt", ghostty.module("ghostty-vt"));
    m.addOptions("build_options", opts);
    m.addAnonymousImport("git_commit", .{ .root_source_file = commit });
    m.addAnonymousImport("asset_gen", .{ .root_source_file = asset_gen });
    return .{ .rex = rex, .bridge = m };
}

/// The page assets' ETags and gzip bodies, made once per build on the build machine by
/// `tools/assetgen.zig` (the same for every target), for `src/bridge/assets.zig` to embed.
fn assetGen(b: *std.Build) std.Build.LazyPath {
    const table = b.createModule(.{ .root_source_file = b.path("src/bridge/asset_table.zig"), .target = b.graph.host, .optimize = .safe });
    const gen_mod = b.createModule(.{ .root_source_file = b.path("tools/assetgen.zig"), .target = b.graph.host, .optimize = .safe });
    gen_mod.addImport("asset_table", table);
    const run = b.addRunArtifact(b.addExecutable(.{ .name = "assetgen", .root_module = gen_mod }));
    return run.addOutputDirectoryArg("assets").path(b, "asset_gen.zig");
}

fn bridgeExe(b: *std.Build, m: *std.Build.Module) *std.Build.Step.Compile {
    const exe = b.addExecutable(.{ .name = "rweb", .root_module = m });
    // Linux: position independent, so the static musl binary is static-pie and its addresses are
    // randomized at every start like a dynamic one's.
    if (m.resolved_target.?.result.os.tag == .linux) exe.pie = true;
    return exe;
}

/// "vt-1.0.2" from Ghostty's tag URL in build.zig.zon.
fn ghosttyTag(url: []const u8) []const u8 {
    const start = (std.mem.indexOf(u8, url, "/tags/") orelse return url) + "/tags/".len;
    const end = std.mem.indexOfPos(u8, url, start, ".tar.gz") orelse url.len;
    return url[start..end];
}

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Not `standardOptimizeOption`: its preferred mode would take `-Doptimize` away, which every
    // build of this repository passes. `--release` alone means ReleaseSafe, the mode releases ship.
    const optimize_help = "Debug (the default: Ghostty runs ~400x slower, for tests only) or ReleaseSafe (what releases ship; also --release); ReleaseFast and ReleaseSmall are refused when rweb compiles, since its allocator decision assumes std's SafeAllocator";
    const optimize: std.lang.Optimize = b.option(std.lang.Optimize, "optimize", optimize_help) orelse switch (b.graph.release_mode) {
        .off => .debug,
        .any, .safe => .safe,
        .fast => .fast,
        .small => .small,
    };

    const filters = b.option([]const []const u8, "test-filter", "Only run tests whose name contains this") orelse &.{};
    // What `rweb --version` reports (the commit: see `commitFile`).
    const opts = b.addOptions();
    opts.addOption([]const u8, "version", zon.version);
    opts.addOption([]const u8, "ghostty", ghosttyTag(zon.dependencies.ghostty.url));
    const commit = commitFile(b, b.option([]const u8, "commit", "Commit this build is from (default: git rev-parse HEAD at build time)"));

    const asset_gen = assetGen(b);
    const host = bridgeModules(b, target, optimize, opts, commit, asset_gen, null);
    // The Rex library, for a package that depends on this one.
    b.modules.put(b.graph.arena, "rex", host.rex) catch @panic("OOM");
    const tests = b.addTest(.{ .root_module = host.rex, .filters = filters });
    const run_tests = b.addRunArtifact(tests);
    run_tests.has_side_effects = true; // live tests read REX_SOCKET, which the cache cannot see
    const exe = bridgeExe(b, host.bridge);
    b.installArtifact(exe);
    const run_exe = b.addRunArtifact(exe);
    run_exe.addPassthruArgs();
    b.step("run", "Run the bridge").dependOn(&run_exe.step);

    // Release archives (Phase 5): ReleaseSafe and stripped (debug info would carry the build
    // folder's path, so the same commit built elsewhere would differ), one per platform the owner
    // runs. Linux is static musl, so it runs on any distribution. tools/dist.sh packs them.
    const dist_targets = [_]struct { name: []const u8, query: std.Target.Query }{
        .{ .name = "macos-arm64", .query = .{ .cpu_arch = .aarch64, .os_tag = .macos } },
        .{ .name = "linux-x86_64", .query = .{ .cpu_arch = .x86_64, .os_tag = .linux, .abi = .musl } },
    };
    const pack = b.addSystemCommand(&.{ "sh", "tools/dist.sh", zon.version });
    pack.addDirectoryArg(b.graph.path(.install_prefix, "dist"));
    pack.has_side_effects = true;
    for (dist_targets) |t| {
        const resolved = b.resolveTargetQuery(t.query);
        const d = bridgeExe(b, bridgeModules(b, resolved, .safe, opts, commit, asset_gen, true).bridge);
        const inst = b.addInstallArtifact(d, .{ .dest_dir = .{ .override = .{ .custom = b.fmt("dist/stage/{s}", .{t.name}) } } });
        pack.step.dependOn(&inst.step);
    }
    b.step("dist", "Release archives for macOS ARM64 and Linux x86-64 in zig-out/dist").dependOn(&pack.step);

    const bridge_tests = b.addTest(.{ .root_module = host.bridge, .filters = filters });
    const run_bridge_tests = b.addRunArtifact(bridge_tests);
    run_bridge_tests.has_side_effects = true;

    // Fuzz targets for the byte parsers. A separate module without Ghostty: its C++ is not
    // instrumented for fuzzing, so linking it into a fuzz build fails.
    const fuzz_mod = b.createModule(.{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    const fuzz_tests = b.addTest(.{ .root_module = fuzz_mod, .filters = filters });
    const run_fuzz = b.addRunArtifact(fuzz_tests);
    b.step("fuzz", "Fuzz the parsers: zig build fuzz --fuzz[=N] [-Dtest-filter=NAME]").dependOn(&run_fuzz.step);

    // The page's pure logic (needs Node). Not part of `test`, so a machine without Node still builds.
    const web_tests = b.addSystemCommand(&.{ "node", "--test", "tests/web/keys.test.mjs" });
    b.step("web-test", "Test the page's key logic with Node").dependOn(&web_tests.step);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
    test_step.dependOn(&run_bridge_tests.step);
    test_step.dependOn(&run_fuzz.step);
}
