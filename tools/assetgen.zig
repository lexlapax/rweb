//! Run by the build: for every asset in `src/bridge/asset_table.zig`, its ETag and (when gzip makes it
//! smaller) its gzip body, written into the folder named by the one argument as `asset_gen.zig` and
//! `<index>.gz`. The bridge embeds them (`src/bridge/assets.zig`), so it computes nothing on a request.
//! The output depends only on the assets, so release builds stay reproducible.

const std = @import("std");
const table = @import("asset_table");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var args = init.minimal.args.iterate();
    _ = args.next();
    const out_path = args.next() orelse return error.MissingOutputFolder;
    var out = try std.Io.Dir.cwd().openDir(io, out_path, .{});
    defer out.close(io);

    var src: std.Io.Writer.Allocating = .init(gpa);
    defer src.deinit();
    const w = &src.writer;
    try w.writeAll("//! Made by tools/assetgen.zig from src/bridge/asset_table.zig at build time; not edited by hand.\n\n");
    try w.writeAll("pub const etags = [_][]const u8{\n");
    for (table.all) |a| {
        var b: [34]u8 = undefined;
        try w.print("    \"{f}\",\n", .{std.zig.fmtString(table.etag(&b, a.body))});
    }
    try w.writeAll("};\n\npub const gz = [_]?[]const u8{\n");
    for (table.all, 0..) |a, i| {
        const z = try table.gzip(gpa, a.body);
        defer gpa.free(z);
        if (z.len >= a.body.len) {
            try w.writeAll("    null,\n");
            continue;
        }
        var name_buf: [32]u8 = undefined;
        const name = try std.fmt.bufPrint(&name_buf, "{d}.gz", .{i});
        const f = try out.createFile(io, name, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, z);
        try w.print("    @embedFile(\"{s}\"),\n", .{name});
    }
    try w.writeAll("};\n");
    const f = try out.createFile(io, "asset_gen.zig", .{});
    defer f.close(io);
    try f.writeStreamingAll(io, src.written());
}
