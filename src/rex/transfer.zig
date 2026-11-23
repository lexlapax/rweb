//! A Rex file download stream (`rex.data.bytes.v1`): the bytes of one file, read from Rex. The
//! ticket comes from the block method `download_begin` (see `api.zig`), and the handshake is the
//! same HELLO/WELCOME as for a terminal stream.
//!
//! Uploads do not use Rex's `upload_begin`: measured against Rex preview.21, it stages the bytes
//! in a private folder and deletes them when the stream closes, and nothing is typed into the
//! terminal for a client that is not the Rex app. The bridge writes uploads itself instead (see
//! `bridge/xfer.zig`).
//!
//! This layer only moves bytes. What may be moved, how much, and for whom is decided by the
//! bridge before a ticket is ever asked for.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ws = @import("ws.zig");
const wire = @import("wire.zig");

pub const subprotocol = "rex.data.bytes.v1";

pub const Error = error{
    /// REJECT: the ticket is unknown, used, expired, or for another user or subprotocol.
    Rejected,
    /// Not a WELCOME or REJECT where one was due.
    BadHandshake,
    /// The stream ended with a status other than 1000, or a frame that is not binary arrived.
    Failed,
} || Allocator.Error;

pub const Stream = struct {
    gpa: Allocator,
    io: Io,
    conn: *ws.Conn,
    /// The close status Rex ended the stream with, once it has. 1000 is a clean end.
    close_status: u16 = 0,
    /// Bytes read so far.
    bytes: u64 = 0,

    /// Open the stream a ticket names, and complete the handshake.
    pub fn open(gpa: Allocator, io: Io, socket_path: []const u8, ticket: [16]u8) !Stream {
        const c = try ws.Conn.connect(gpa, io, socket_path, "/api/data", subprotocol);
        errdefer c.deinit(gpa);
        var hello: [17]u8 = undefined;
        hello[0] = 0x01;
        @memcpy(hello[1..], &ticket);
        try c.writeFrame(.binary, &hello);
        const m = try c.readMessage(gpa);
        defer gpa.free(m.data);
        if (m.opcode == .close) return error.Rejected;
        if (m.opcode != .binary) return error.BadHandshake;
        switch (try wire.parseHandshake(m.data)) {
            .welcome => {},
            .reject => return error.Rejected,
        }
        return .{ .gpa = gpa, .io = io, .conn = c };
    }

    /// The next chunk of a download (1 to 64 KiB), owned by the caller, or null when Rex ended
    /// the stream cleanly.
    pub fn next(s: *Stream) Error!?[]u8 {
        while (true) {
            const m = s.conn.readMessage(s.gpa) catch return error.Failed;
            switch (m.opcode) {
                .binary => {
                    s.bytes += m.data.len;
                    return m.data;
                },
                .close => {
                    defer s.gpa.free(m.data);
                    s.close_status = if (m.data.len >= 2) std.mem.readInt(u16, m.data[0..2], .big) else 1005;
                    if (s.close_status == 1000) return null;
                    return error.Failed;
                },
                else => s.gpa.free(m.data),
            }
        }
    }

    /// Shut the socket at once, to cut a transfer short or wake a blocked read.
    pub fn abort(s: *Stream) void {
        s.conn.stream.shutdown(s.io, .both) catch {};
    }

    pub fn deinit(s: *Stream) void {
        s.conn.deinit(s.gpa);
    }
};

/// `<prefix>` followed by a new random UUID in lower-case canonical form, as Rex asks of a
/// data reference (`download:` or `upload:`).
pub fn newRef(io: Io, comptime prefix: []const u8) [prefix.len + 36]u8 {
    var raw: [16]u8 = undefined;
    io.random(&raw);
    raw[6] = (raw[6] & 0x0f) | 0x40; // version 4
    raw[8] = (raw[8] & 0x3f) | 0x80; // variant
    var out: [prefix.len + 36]u8 = undefined;
    @memcpy(out[0..prefix.len], prefix);
    const hex = "0123456789abcdef";
    var j: usize = prefix.len;
    for (raw, 0..) |b, i| {
        if (i == 4 or i == 6 or i == 8 or i == 10) {
            out[j] = '-';
            j += 1;
        }
        out[j] = hex[b >> 4];
        out[j + 1] = hex[b & 15];
        j += 2;
    }
    return out;
}

// ---- tests ----

test "newRef is a lower-case canonical UUID with its prefix" {
    const r = newRef(std.testing.io, "download:");
    try std.testing.expectEqualStrings("download:", r[0..9]);
    const u = r[9..];
    try std.testing.expectEqual(@as(usize, 36), u.len);
    for (u, 0..) |c, i| switch (i) {
        8, 13, 18, 23 => try std.testing.expectEqual(@as(u8, '-'), c),
        else => try std.testing.expect((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f')),
    };
    try std.testing.expectEqual(@as(u8, '4'), u[14]);
    try std.testing.expect(std.mem.indexOfScalar(u8, "89ab", u[19]) != null);
}

const api_mod = @import("api.zig");
const Control = @import("control.zig").Control;

test "live: download and list a directory against a real Rex (needs REX_SOCKET)" {
    const a = std.testing.allocator;
    const io = std.testing.io;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const ctl = try Control.open(a, io, .{ .socket_path = sock });
    defer ctl.close();
    var api = api_mod.Api.init(a, ctl);
    defer api.deinit();
    var made = try api.createSession("rweb-test-xfer");
    defer made.deinit();
    const sid = made.value.session_id;
    const bid = made.value.block_id;
    defer api.destroySession(sid) catch {};
    try api.attach(sid);

    // A file of known contents, in a directory only this test uses.
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    var dir_buf: [64]u8 = undefined;
    const dir = try std.fmt.bufPrint(&dir_buf, "/tmp/rweb-test-xfer-{x}", .{rnd});
    try std.Io.Dir.cwd().createDirPath(io, dir);
    defer std.Io.Dir.cwd().deleteTree(io, dir) catch {};
    const src_path = try std.fmt.allocPrint(a, "{s}/source.bin", .{dir});
    defer a.free(src_path);
    const content = try a.alloc(u8, 150_000);
    defer a.free(content);
    for (content, 0..) |*b, i| b.* = @truncate(i *% 2654435761 >> 7);
    {
        const f = try std.Io.Dir.cwd().createFile(io, src_path, .{});
        defer f.close(io);
        try f.writeStreamingAll(io, content);
    }

    // Download it.
    {
        const ref = newRef(io, "download:");
        var t = try api.downloadBegin(sid, bid, &ref, src_path);
        defer t.deinit();
        try std.testing.expectEqualStrings("source.bin", t.value.name);
        try std.testing.expectEqual(@as(u64, content.len), t.value.size);
        var st = try Stream.open(a, io, sock, t.value.ticket);
        defer st.deinit();
        var got: std.ArrayList(u8) = .empty;
        defer got.deinit(a);
        while (try st.next()) |chunk| {
            defer a.free(chunk);
            try got.appendSlice(a, chunk);
        }
        try std.testing.expectEqualSlices(u8, content, got.items);
        try std.testing.expectEqual(@as(u16, 1000), st.close_status);
    }

    // A directory listing sees the file.
    {
        var d = try api.listDir(sid, bid, dir);
        defer d.deinit();
        try std.testing.expectEqualStrings("ok", d.value.status);
        var seen = false;
        for (d.value.entries) |e| if (std.mem.eql(u8, e.name, "source.bin")) {
            seen = !e.dir;
        };
        try std.testing.expect(seen);
    }
}
