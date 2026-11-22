//! Minimal WebSocket client over a unix socket, enough to talk to Rex.
//! Spike code: no compression, no TLS, no extensions.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;

pub const Opcode = enum(u4) {
    continuation = 0,
    text = 1,
    binary = 2,
    close = 8,
    ping = 9,
    pong = 10,
    _,
};

pub const Message = struct {
    opcode: Opcode,
    /// Owned by the allocator passed to `readMessage`.
    data: []u8,
};

pub const Client = struct {
    io: Io,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    write_mutex: Io.Mutex = .init,
    read_buf: [64 * 1024]u8 = undefined,
    write_buf: [64 * 1024]u8 = undefined,

    /// Connect to `socket_path`, then upgrade `path` to a WebSocket with `subprotocol`.
    pub fn connect(
        gpa: Allocator,
        io: Io,
        socket_path: []const u8,
        path: []const u8,
        subprotocol: []const u8,
    ) !*Client {
        const addr = try Io.net.UnixAddress.init(socket_path);
        const stream = try addr.connect(io);
        errdefer stream.close(io);

        const c = try gpa.create(Client);
        errdefer gpa.destroy(c);
        c.* = .{
            .io = io,
            .stream = stream,
            .reader = undefined,
            .writer = undefined,
        };
        c.reader = stream.reader(io, &c.read_buf);
        c.writer = stream.writer(io, &c.write_buf);

        var key_raw: [16]u8 = undefined;
        io.random(&key_raw);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &key_raw);

        const w = &c.writer.interface;
        try w.print(
            "GET {s} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\nSec-WebSocket-Key: {s}\r\n" ++
                "Sec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {s}\r\n\r\n",
            .{ path, &key, subprotocol },
        );
        try w.flush();

        // Expected accept value.
        var sha1 = std.crypto.hash.Sha1.init(.{});
        sha1.update(&key);
        sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        var digest: [20]u8 = undefined;
        sha1.final(&digest);
        var accept: [28]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&accept, &digest);

        const r = &c.reader.interface;
        const status = try r.takeDelimiterInclusive('\n');
        if (std.mem.indexOf(u8, status, " 101 ") == null) {
            std.log.err("upgrade of {s} refused: {s}", .{ path, std.mem.trimEnd(u8, status, "\r\n") });
            return error.UpgradeRefused;
        }
        var accepted = false;
        while (true) {
            const line = std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
            if (line.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept") and std.mem.eql(u8, value, &accept))
                accepted = true;
        }
        if (!accepted) return error.BadAccept;
        return c;
    }

    pub fn deinit(c: *Client, gpa: Allocator) void {
        c.stream.close(c.io);
        gpa.destroy(c);
    }

    /// Send one masked frame. Safe to call from several tasks.
    pub fn writeFrame(c: *Client, op: Opcode, data: []const u8) !void {
        c.write_mutex.lockUncancelable(c.io);
        defer c.write_mutex.unlock(c.io);

        const w = &c.writer.interface;
        var hdr: [14]u8 = undefined;
        hdr[0] = 0x80 | @as(u8, @intFromEnum(op));
        var n: usize = 2;
        if (data.len < 126) {
            hdr[1] = 0x80 | @as(u8, @intCast(data.len));
        } else if (data.len <= 0xffff) {
            hdr[1] = 0x80 | 126;
            std.mem.writeInt(u16, hdr[2..4], @intCast(data.len), .big);
            n = 4;
        } else {
            hdr[1] = 0x80 | 127;
            std.mem.writeInt(u64, hdr[2..10], data.len, .big);
            n = 10;
        }
        var mask: [4]u8 = undefined;
        c.io.random(&mask);
        @memcpy(hdr[n .. n + 4], &mask);
        n += 4;
        try w.writeAll(hdr[0..n]);

        var chunk: [4096]u8 = undefined;
        var off: usize = 0;
        while (off < data.len) {
            const len = @min(chunk.len, data.len - off);
            for (0..len) |i| chunk[i] = data[off + i] ^ mask[(off + i) % 4];
            try w.writeAll(chunk[0..len]);
            off += len;
        }
        try w.flush();
    }

    /// Read one complete message, answering pings. Close frames are returned.
    pub fn readMessage(c: *Client, gpa: Allocator) !Message {
        const r = &c.reader.interface;
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(gpa);
        var msg_op: ?Opcode = null;
        while (true) {
            const h = try r.takeArray(2);
            const fin = h[0] & 0x80 != 0;
            const op: Opcode = @enumFromInt(@as(u4, @truncate(h[0])));
            const masked = h[1] & 0x80 != 0;
            var len: u64 = h[1] & 0x7f;
            if (len == 126) len = try r.takeInt(u16, .big) else if (len == 127) len = try r.takeInt(u64, .big);
            var mask: [4]u8 = .{ 0, 0, 0, 0 };
            if (masked) mask = (try r.takeArray(4)).*;
            if (len > 64 * 1024 * 1024) return error.FrameTooLarge;

            const start = buf.items.len;
            try buf.resize(gpa, start + @as(usize, @intCast(len)));
            try r.readSliceAll(buf.items[start..]);
            if (masked) for (buf.items[start..], 0..) |*b, i| {
                b.* ^= mask[i % 4];
            };

            switch (op) {
                .ping => {
                    const payload = try gpa.dupe(u8, buf.items[start..]);
                    defer gpa.free(payload);
                    buf.shrinkRetainingCapacity(start);
                    try c.writeFrame(.pong, payload);
                    continue;
                },
                .pong => {
                    buf.shrinkRetainingCapacity(start);
                    continue;
                },
                .close => {
                    const data = try gpa.dupe(u8, buf.items[start..]);
                    buf.deinit(gpa);
                    return .{ .opcode = .close, .data = data };
                },
                .continuation => {},
                else => msg_op = op,
            }
            if (fin) return .{ .opcode = msg_op orelse .binary, .data = try buf.toOwnedSlice(gpa) };
        }
    }
};
