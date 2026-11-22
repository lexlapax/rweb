//! WebSocket client (RFC 6455) over a unix socket, enough to talk to Rex:
//! no TLS, no extensions, no compression.
//!
//! The frame header parser is pure (`parseHeader`) so it can be tested and fuzzed
//! without a socket.

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

    pub fn isControl(op: Opcode) bool {
        return @intFromEnum(op) >= 8;
    }
};

pub const Message = struct {
    opcode: Opcode,
    /// Owned by the allocator passed to `readMessage`.
    data: []u8,
};

pub const Header = struct {
    fin: bool,
    opcode: Opcode,
    masked: bool,
    len: u64,
    mask: [4]u8,
    /// Bytes the header occupied.
    size: usize,
};

pub const ParseError = error{
    /// Not enough bytes yet; read more and retry.
    NeedMore,
    /// Reserved bits set (no extension was negotiated) or a reserved opcode.
    Protocol,
    /// A control frame that is fragmented or longer than 125 bytes.
    BadControl,
    /// Payload length above `max_len`.
    TooLarge,
};

/// Parse one frame header from the start of `bytes`.
pub fn parseHeader(bytes: []const u8, max_len: u64) ParseError!Header {
    if (bytes.len < 2) return error.NeedMore;
    const b0 = bytes[0];
    const b1 = bytes[1];
    if (b0 & 0x70 != 0) return error.Protocol;
    const op: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    switch (op) {
        .continuation, .text, .binary, .close, .ping, .pong => {},
        _ => return error.Protocol,
    }
    const fin = b0 & 0x80 != 0;
    const masked = b1 & 0x80 != 0;
    var len: u64 = b1 & 0x7f;
    var n: usize = 2;
    if (len == 126) {
        if (bytes.len < 4) return error.NeedMore;
        len = std.mem.readInt(u16, bytes[2..4], .big);
        n = 4;
    } else if (len == 127) {
        if (bytes.len < 10) return error.NeedMore;
        len = std.mem.readInt(u64, bytes[2..10], .big);
        if (len >> 63 != 0) return error.Protocol;
        n = 10;
    }
    if (op.isControl() and (!fin or len > 125)) return error.BadControl;
    if (len > max_len) return error.TooLarge;
    var mask: [4]u8 = .{ 0, 0, 0, 0 };
    if (masked) {
        if (bytes.len < n + 4) return error.NeedMore;
        @memcpy(&mask, bytes[n .. n + 4]);
        n += 4;
    }
    return .{ .fin = fin, .opcode = op, .masked = masked, .len = len, .mask = mask, .size = n };
}

/// Write a frame header into `out`; returns its length. Client frames are masked.
pub fn writeHeader(out: *[14]u8, op: Opcode, len: usize, mask: [4]u8, masked: bool) usize {
    out[0] = 0x80 | @as(u8, @intFromEnum(op));
    const m: u8 = if (masked) 0x80 else 0;
    var n: usize = 2;
    if (len < 126) {
        out[1] = m | @as(u8, @intCast(len));
    } else if (len <= 0xffff) {
        out[1] = m | 126;
        std.mem.writeInt(u16, out[2..4], @intCast(len), .big);
        n = 4;
    } else {
        out[1] = m | 127;
        std.mem.writeInt(u64, out[2..10], len, .big);
        n = 10;
    }
    if (!masked) return n;
    @memcpy(out[n .. n + 4], &mask);
    return n + 4;
}

pub fn acceptKey(key: []const u8) [28]u8 {
    var sha1 = std.crypto.hash.Sha1.init(.{});
    sha1.update(key);
    sha1.update("258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
    var digest: [20]u8 = undefined;
    sha1.final(&digest);
    var accept: [28]u8 = undefined;
    _ = std.base64.standard.Encoder.encode(&accept, &digest);
    return accept;
}

pub const Client = Conn;

/// One end of a WebSocket. A client masks what it sends; a server does not.
pub const Conn = struct {
    io: Io,
    stream: Io.net.Stream,
    reader: Io.net.Stream.Reader,
    writer: Io.net.Stream.Writer,
    /// What frames are read from and written to: the fields above, or an HTTP server's.
    r: *Io.Reader = undefined,
    w: *Io.Writer = undefined,
    /// False when the stream belongs to someone else (an HTTP server connection).
    owns_stream: bool = true,
    write_mutex: Io.Mutex = .init,
    /// True for the connecting side, which must mask its frames.
    is_client: bool = true,
    /// Server side: the subprotocol agreed in `accept` (one of the slices passed in).
    subprotocol: []const u8 = "",
    /// Largest message accepted, after reassembly.
    max_message: u64 = 64 * 1024 * 1024,
    read_buf: [64 * 1024]u8 = undefined,
    write_buf: [64 * 1024]u8 = undefined,

    /// Server side: read the upgrade request from an accepted `stream`, check it and answer 101.
    /// `subprotocol` is echoed if the client asked for it; otherwise the upgrade is refused.
    pub fn accept(gpa: Allocator, io: Io, stream: Io.net.Stream, subprotocols: []const []const u8) !*Conn {
        const c = try gpa.create(Conn);
        errdefer gpa.destroy(c);
        c.* = .{ .io = io, .stream = stream, .reader = undefined, .writer = undefined, .is_client = false };
        c.reader = stream.reader(io, &c.read_buf);
        c.writer = stream.writer(io, &c.write_buf);
        c.r = &c.reader.interface;
        c.w = &c.writer.interface;
        const r = c.r;
        const w = c.w;

        const req_line = try r.takeDelimiterInclusive('\n');
        if (!std.mem.startsWith(u8, req_line, "GET ")) return error.BadRequest;
        var key: ?[]const u8 = null;
        var key_buf: [64]u8 = undefined;
        var chosen: ?[]const u8 = null;
        var lines: usize = 0;
        while (true) {
            const line = std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
            if (line.len == 0) break;
            lines += 1;
            if (lines > 64) return error.BadRequest;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "sec-websocket-key") and value.len <= key_buf.len) {
                @memcpy(key_buf[0..value.len], value);
                key = key_buf[0..value.len];
            } else if (std.ascii.eqlIgnoreCase(name, "sec-websocket-protocol")) {
                var it = std.mem.tokenizeAny(u8, value, ", ");
                while (it.next()) |p| for (subprotocols) |sp| {
                    if (chosen == null and std.mem.eql(u8, p, sp)) chosen = sp;
                };
            }
        }
        const k = key orelse return error.BadRequest;
        const proto = chosen orelse {
            try w.writeAll("HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n");
            try w.flush();
            return error.BadSubprotocol;
        };
        const accept_val = acceptKey(k);
        try w.print(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n" ++
                "Sec-WebSocket-Accept: {s}\r\nSec-WebSocket-Protocol: {s}\r\n\r\n",
            .{ &accept_val, proto },
        );
        try w.flush();
        c.subprotocol = proto;
        return c;
    }

    /// Connect to `socket_path`, then upgrade `path` to a WebSocket with `subprotocol`.
    pub fn connect(
        gpa: Allocator,
        io: Io,
        socket_path: []const u8,
        path: []const u8,
        subprotocol: []const u8,
    ) !*Conn {
        const addr = try Io.net.UnixAddress.init(socket_path);
        const stream = try addr.connect(io);
        return connectStream(gpa, io, stream, path, subprotocol, "");
    }

    /// Upgrade `path` to a WebSocket on an already connected `stream`. `extra_headers` is
    /// header lines, each ending in CRLF (for tests that send an Origin, say). Closes the
    /// stream on failure.
    pub fn connectStream(
        gpa: Allocator,
        io: Io,
        stream: Io.net.Stream,
        path: []const u8,
        subprotocol: ?[]const u8,
        extra_headers: []const u8,
    ) !*Conn {
        errdefer stream.close(io);

        const c = try gpa.create(Conn);
        errdefer gpa.destroy(c);
        c.* = .{ .io = io, .stream = stream, .reader = undefined, .writer = undefined };
        c.reader = stream.reader(io, &c.read_buf);
        c.writer = stream.writer(io, &c.write_buf);
        c.r = &c.reader.interface;
        c.w = &c.writer.interface;

        var key_raw: [16]u8 = undefined;
        io.random(&key_raw);
        var key: [24]u8 = undefined;
        _ = std.base64.standard.Encoder.encode(&key, &key_raw);

        const w = c.w;
        try w.print(
            "GET {s} HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n" ++
                "Connection: Upgrade\r\nSec-WebSocket-Key: {s}\r\nSec-WebSocket-Version: 13\r\n",
            .{ path, &key },
        );
        if (subprotocol) |sp| try w.print("Sec-WebSocket-Protocol: {s}\r\n", .{sp});
        try w.writeAll(extra_headers);
        try w.writeAll("\r\n");
        try w.flush();

        const expected = acceptKey(&key);
        const r = c.r;
        const status = try r.takeDelimiterInclusive('\n');
        if (std.mem.indexOf(u8, status, " 101 ") == null) return error.UpgradeRefused;
        var accepted = false;
        while (true) {
            const line = std.mem.trimEnd(u8, try r.takeDelimiterInclusive('\n'), "\r\n");
            if (line.len == 0) break;
            const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
            const name = line[0..colon];
            const value = std.mem.trim(u8, line[colon + 1 ..], " \t");
            if (std.ascii.eqlIgnoreCase(name, "sec-websocket-accept") and std.mem.eql(u8, value, &expected))
                accepted = true;
        }
        if (!accepted) return error.BadAccept;
        return c;
    }

    /// Server side, on a connection an HTTP server already upgraded: frames go over `r` and
    /// `w`; the stream stays the caller's. `max_message` bounds what a peer can make us buffer.
    pub fn fromHttp(gpa: Allocator, io: Io, stream: Io.net.Stream, r: *Io.Reader, w: *Io.Writer, max_message: u64) !*Conn {
        const c = try gpa.create(Conn);
        c.* = .{
            .io = io,
            .stream = stream,
            .reader = undefined,
            .writer = undefined,
            .r = r,
            .w = w,
            .owns_stream = false,
            .is_client = false,
            .max_message = max_message,
        };
        return c;
    }

    pub fn deinit(c: *Conn, gpa: Allocator) void {
        if (c.owns_stream) c.stream.close(c.io);
        gpa.destroy(c);
    }

    /// Send one masked frame. Safe to call from several tasks.
    pub fn writeFrame(c: *Conn, op: Opcode, data: []const u8) !void {
        c.write_mutex.lockUncancelable(c.io);
        defer c.write_mutex.unlock(c.io);

        const w = c.w;
        var mask: [4]u8 = .{ 0, 0, 0, 0 };
        if (c.is_client) c.io.random(&mask);
        var hdr: [14]u8 = undefined;
        const n = writeHeader(&hdr, op, data.len, mask, c.is_client);
        try w.writeAll(hdr[0..n]);

        if (!c.is_client) {
            try w.writeAll(data);
            try w.flush();
            return;
        }
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
    pub fn readMessage(c: *Conn, gpa: Allocator) !Message {
        const r = c.r;
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(gpa);
        var msg_op: ?Opcode = null;
        while (true) {
            // The longest header is 14 bytes; peek progressively.
            var h: Header = undefined;
            var want: usize = 2;
            while (true) {
                const bytes = try r.peek(want);
                if (parseHeader(bytes, c.max_message - buf.items.len)) |ok| {
                    h = ok;
                    break;
                } else |err| switch (err) {
                    error.NeedMore => want += 2,
                    else => |e| return e,
                }
            }
            r.toss(h.size);
            const len: usize = @intCast(h.len);
            const op = h.opcode;
            if (op == .continuation and msg_op == null) return error.Protocol;
            if ((op == .text or op == .binary) and msg_op != null) return error.Protocol;

            const start = buf.items.len;
            try buf.resize(gpa, start + len);
            try r.readSliceAll(buf.items[start..]);
            if (h.masked) for (buf.items[start..], 0..) |*b, i| {
                b.* ^= h.mask[i % 4];
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
            if (h.fin) return .{ .opcode = msg_op.?, .data = try buf.toOwnedSlice(gpa) };
        }
    }
};

test "parseHeader: short, medium and long lengths" {
    const t = std.testing;
    try t.expectError(error.NeedMore, parseHeader(&.{0x81}, 1 << 20));
    const h = try parseHeader(&.{ 0x81, 0x05 }, 1 << 20);
    try t.expect(h.fin and !h.masked and h.len == 5 and h.size == 2 and h.opcode == .text);
    const h2 = try parseHeader(&.{ 0x82, 126, 0x01, 0x00 }, 1 << 20);
    try t.expectEqual(@as(u64, 256), h2.len);
    try t.expectError(error.NeedMore, parseHeader(&.{ 0x82, 127, 0, 0 }, 1 << 20));
    const h3 = try parseHeader(&.{ 0x82, 127, 0, 0, 0, 0, 0, 1, 0, 0 }, 1 << 20);
    try t.expectEqual(@as(u64, 65536), h3.len);
}

test "parseHeader: masked frame carries its mask" {
    const h = try parseHeader(&.{ 0x81, 0x83, 1, 2, 3, 4 }, 100);
    try std.testing.expect(h.masked);
    try std.testing.expectEqualSlices(u8, &.{ 1, 2, 3, 4 }, &h.mask);
    try std.testing.expectEqual(@as(usize, 6), h.size);
}

test "parseHeader: rejects bad frames" {
    const t = std.testing;
    try t.expectError(error.Protocol, parseHeader(&.{ 0xC1, 0x00 }, 100)); // RSV1
    try t.expectError(error.Protocol, parseHeader(&.{ 0x83, 0x00 }, 100)); // reserved opcode
    try t.expectError(error.BadControl, parseHeader(&.{ 0x09, 0x00 }, 100)); // fragmented ping
    try t.expectError(error.BadControl, parseHeader(&.{ 0x89, 126, 0, 126 }, 1000)); // long ping
    try t.expectError(error.TooLarge, parseHeader(&.{ 0x82, 101 }, 100));
    try t.expectError(error.Protocol, parseHeader(&.{ 0x82, 127, 0x80, 0, 0, 0, 0, 0, 0, 0 }, std.math.maxInt(u64)));
}

test "writeHeader round-trips through parseHeader" {
    const mask: [4]u8 = .{ 9, 8, 7, 6 };
    for ([_]usize{ 0, 5, 125, 126, 65535, 65536, 1 << 20 }) |len| {
        var out: [14]u8 = undefined;
        const n = writeHeader(&out, .binary, len, mask, true);
        const h = try parseHeader(out[0..n], 1 << 21);
        try std.testing.expectEqual(@as(u64, len), h.len);
        try std.testing.expect(h.masked and h.fin and h.opcode == .binary);
        try std.testing.expectEqualSlices(u8, &mask, &h.mask);
        try std.testing.expectEqual(n, h.size);
    }
}

test "acceptKey matches the RFC 6455 example" {
    const a = acceptKey("dGhlIHNhbXBsZSBub25jZQ==");
    try std.testing.expectEqualStrings("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", &a);
}



test "live: control hello against a real Rex (needs REX_SOCKET)" {
    const gpa = std.testing.allocator;
    const sock = std.testing.environ.getPosix("REX_SOCKET") orelse return error.SkipZigTest;
    if (sock.len == 0) return error.SkipZigTest;
    const io = std.testing.io;
    const c = try Conn.connect(gpa, io, sock, "/api/control", "rex.control.v1");
    defer c.deinit(gpa);
    try c.writeFrame(.text, "{\"type\":\"hello\",\"api_revision\":18,\"api_min_revision\":18," ++
        "\"client\":{\"kind\":\"other\",\"platform\":\"web\",\"name\":\"rweb-test\",\"version\":\"0.0.1\"}}");
    const m = try c.readMessage(gpa);
    defer gpa.free(m.data);
    try std.testing.expectEqual(Opcode.text, m.opcode);
    try std.testing.expect(std.mem.indexOf(u8, m.data, "welcome") != null);
}
