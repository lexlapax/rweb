//! WebSocket client (RFC 6455) over a unix socket, enough to talk to Rex:
//! no TLS, no extensions, no compression.
//!
//! The frame header parser is pure (`parseHeader`) so it can be tested and fuzzed
//! without a socket.

const std = @import("std");
const builtin = @import("builtin");
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

/// How long a handshake (the HTTP upgrade and the protocol's first messages) may take.
pub const handshake_timeout_ms: u32 = 10_000;

/// How long a frame written to Rex may take when its call has no timeout of its own (pongs, a
/// data stream's frames): see `Conn.write_timeout_ms`.
pub const write_timeout_ms: u32 = 10_000;

/// Largest message read during a handshake (the control WELCOME, a data WELCOME or REJECT):
/// every connection has a limit from its first read, raised once the handshake is done.
pub const handshake_max_message: u64 = 64 * 1024;

/// A deadline for a handshake: shuts `stream` (so a blocked read returns) unless stopped first.
/// Stop it before the stream is closed, on every path, and call `finish` before publishing what
/// the handshake made: a watchdog that fired has shut the socket, so the handshake has failed
/// even when its last read got in first.
pub const Watchdog = struct {
    /// The result is whether it fired (shut the stream).
    future: Io.Future(bool),

    pub fn start(io: Io, stream: Io.net.Stream, timeout_ms: u32) Io.ConcurrentError!Watchdog {
        return .{ .future = try io.concurrent(run, .{ io, stream, timeout_ms }) };
    }

    fn run(io: Io, stream: Io.net.Stream, timeout_ms: u32) bool {
        io.sleep(.fromMilliseconds(timeout_ms), .awake) catch return false; // stopped in time
        stream.shutdown(io, .both) catch {};
        return true;
    }

    /// Stop it (again is fine) and say whether it fired first.
    pub fn stopFired(w: *Watchdog, io: Io) bool {
        return w.future.cancel(io);
    }

    pub fn stop(w: *Watchdog, io: Io) void {
        _ = w.stopFired(io);
    }

    /// Stop it; `error.HandshakeTimeout` if it had already fired.
    pub fn finish(w: *Watchdog, io: Io) error{HandshakeTimeout}!void {
        if (w.stopFired(io)) return error.HandshakeTimeout;
    }
};

pub const PeerError = error{
    /// The process on the other end of Rex's socket is not running as this user (or the OS
    /// would not say who it is): something else took the socket's path.
    WrongPeer,
};

/// Connect to the unix socket at `socket_path` and check that the server runs as this user.
pub fn connectUnix(io: Io, socket_path: []const u8) !Io.net.Stream {
    const addr = try Io.net.UnixAddress.init(socket_path);
    const stream = try addr.connect(io);
    errdefer stream.close(io);
    try checkPeer(stream);
    return stream;
}

/// `error.WrongPeer` unless the other end of the unix socket `stream` runs as this user.
pub fn checkPeer(stream: Io.net.Stream) PeerError!void {
    const uid = peerUid(stream) orelse return error.WrongPeer;
    if (!peerAllowed(uid, myUid())) return error.WrongPeer;
}

/// This process's effective uid: what the kernel reports to a peer as us.
pub fn myUid() u32 {
    return if (builtin.os.tag == .linux) std.os.linux.geteuid() else @intCast(std.c.geteuid());
}

/// Who may serve Rex's socket: only this user (not even root, which has no reason to).
pub fn peerAllowed(peer_uid: u32, my_uid: u32) bool {
    return peer_uid == my_uid;
}

/// The uid of the process on the other end of a unix socket, if the OS will say.
pub fn peerUid(stream: Io.net.Stream) ?u32 {
    const fd = stream.socket.handle;
    switch (builtin.os.tag) {
        .macos, .freebsd, .netbsd, .openbsd => {
            var uid: std.c.uid_t = undefined;
            var gid: std.c.gid_t = undefined;
            if (getpeereid(fd, &uid, &gid) != 0) return null;
            return @intCast(uid);
        },
        .linux => {
            var cred: extern struct { pid: i32, uid: u32, gid: u32 } = undefined;
            // The system call itself, so this needs no libc (the fuzz build links none).
            const linux = std.os.linux;
            var len: linux.socklen_t = @sizeOf(@TypeOf(cred));
            const rc = linux.getsockopt(fd, linux.SOL.SOCKET, linux.SO.PEERCRED, @ptrCast(&cred), &len);
            if (linux.errno(rc) != .SUCCESS) return null;
            if (len != @sizeOf(@TypeOf(cred))) return null;
            return cred.uid;
        },
        else => return null,
    }
}

extern "c" fn getpeereid(fd: c_int, uid: *std.c.uid_t, gid: *std.c.gid_t) c_int;

/// Most pings and pongs a peer may send in any one second: each ping makes us write a pong, so a
/// flood is work we do for the peer. A connection that stays idle with a ping every few seconds is
/// far below it.
pub const max_control_per_second = 64;
/// Most frames in one fragmented message.
pub const max_frames_per_message: u32 = 4096;

/// A sliding one-second window over the times of the last `max_control_per_second` control frames.
pub const ControlRate = struct {
    times: [max_control_per_second]i64 = undefined,
    next: usize = 0,
    seen: usize = 0,
    /// For a limit above `max_control_per_second` (tests and the fuzzer only): frames counted in
    /// whole seconds from `bucket_start_ms`.
    bucket_start_ms: i64 = std.math.minInt(i64),
    bucket_count: u64 = 0,

    /// Count a control frame at `now_ms`; false if it is one too many for the last second.
    pub fn allow(r: *ControlRate, now_ms: i64) bool {
        return r.allowUpTo(now_ms, max_control_per_second);
    }

    /// As `allow`, with at most `limit` frames a second. Up to `max_control_per_second` the window
    /// slides; above it (only tests and the fuzzer raise it) it is counted in whole seconds.
    pub fn allowUpTo(r: *ControlRate, now_ms: i64, limit: u32) bool {
        if (limit > max_control_per_second) {
            if (now_ms -| r.bucket_start_ms >= 1000) {
                r.bucket_start_ms = now_ms;
                r.bucket_count = 0;
            }
            if (r.bucket_count >= limit) return false;
            r.bucket_count += 1;
            return true;
        }
        // The frame `limit` back from the newest, when there have been that many.
        if (r.seen >= limit) {
            const oldest = r.times[(r.next + max_control_per_second - limit) % max_control_per_second];
            if (limit == 0 or now_ms - oldest < 1000) return false;
        }
        r.times[r.next] = now_ms;
        r.next = (r.next + 1) % max_control_per_second;
        if (r.seen < max_control_per_second) r.seen += 1;
        return true;
    }
};

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
    /// Ping and pong frames in the last second: past `control_limit` the connection is a protocol
    /// error.
    control_rate: ControlRate = .{},
    /// Most ping and pong frames a second. Only tests and the fuzzer change it (the fuzzer raises
    /// it so an input can be a long run of control frames).
    control_limit: u32 = max_control_per_second,
    /// Longest a frame written with `writeFrame` may take; past it the stream is shut (see
    /// `writeFrameTimeout`). Null: no deadline (a browser connection, whose writes the bridge
    /// bounds itself). Connections to Rex set it once their handshake is done.
    write_timeout_ms: ?u32 = null,
    /// Ping and pong frames read so far, for a caller that counts them against its own limits
    /// (`readMessage` answers and drops them).
    control_frames: u64 = 0,
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

    /// Connect to `socket_path` (checking that its server runs as this user), then upgrade `path` to a WebSocket with `subprotocol`.
    pub fn connect(
        gpa: Allocator,
        io: Io,
        socket_path: []const u8,
        path: []const u8,
        subprotocol: []const u8,
    ) !*Conn {
        const stream = try connectUnix(io, socket_path);
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
        return upgrade(gpa, io, stream, path, subprotocol, extra_headers);
    }

    /// As `connectStream`, but a failure leaves `stream` open for the caller to close (one that
    /// published it so another task can shut it must unpublish it first). On success the
    /// connection owns the stream.
    pub fn upgrade(
        gpa: Allocator,
        io: Io,
        stream: Io.net.Stream,
        path: []const u8,
        subprotocol: ?[]const u8,
        extra_headers: []const u8,
    ) !*Conn {
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

    /// Send one frame (masked by a client), within `write_timeout_ms` if set. Safe to call from
    /// several tasks. A frame is written whole or not at all as far as cancellation goes: the
    /// task cannot be cancelled inside it (a half-written frame would corrupt every frame after
    /// it). An error from the stream can still leave part of a frame written: the connection is
    /// then unusable, and the caller must drop it.
    pub fn writeFrame(c: *Conn, op: Opcode, data: []const u8) !void {
        return c.writeFrameTimeout(op, data, c.write_timeout_ms);
    }

    /// As `writeFrame`, with its own deadline: if the frame is not written within `timeout_ms`
    /// (null: no deadline) of taking the write lock, the stream is shut, which fails this write
    /// (`error.WriteTimeout`) and every read and write after it, so the connection's owner drops
    /// it and reconnects. A peer that stops reading cannot hold a writer, or the tasks queued
    /// behind it, for longer. `error.ConcurrencyUnavailable` (no task for the deadline) means
    /// nothing was written and the connection is unchanged.
    pub fn writeFrameTimeout(c: *Conn, op: Opcode, data: []const u8, timeout_ms: ?u32) !void {
        const old_protection = c.io.swapCancelProtection(.blocked);
        defer _ = c.io.swapCancelProtection(old_protection);
        c.write_mutex.lockUncancelable(c.io);
        defer c.write_mutex.unlock(c.io);
        var dog: ?Watchdog = if (timeout_ms) |t| try Watchdog.start(c.io, c.stream, t) else null;
        const wrote = c.writeFrameLocked(op, data);
        if (dog) |*d| if (d.stopFired(c.io)) return error.WriteTimeout;
        return wrote;
    }

    fn writeFrameLocked(c: *Conn, op: Opcode, data: []const u8) !void {
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

    fn countControl(c: *Conn) error{Protocol}!void {
        c.control_frames +|= 1;
        if (!c.control_rate.allowUpTo(Io.Clock.awake.now(c.io).toMilliseconds(), c.control_limit)) return error.Protocol;
    }

    /// Read one complete message, answering pings. Close frames are returned.
    pub fn readMessage(c: *Conn, gpa: Allocator) !Message {
        const r = c.r;
        var buf: std.ArrayList(u8) = .empty;
        errdefer buf.deinit(gpa);
        var msg_op: ?Opcode = null;
        var frames: u32 = 0;
        while (true) {
            frames += 1;
            if (frames > max_frames_per_message) return error.Protocol; // a message made of endless empty fragments
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
            // RFC 6455 5.1: a client masks every frame it sends, a server masks none. A peer that
            // breaks the rule is not a browser (or is behind a proxy that must not see our data
            // as plain frames): close rather than guess.
            if (!c.is_client and !h.masked) return error.Protocol;
            if (c.is_client and h.masked) return error.Protocol;
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
                    try c.countControl();
                    const payload = try gpa.dupe(u8, buf.items[start..]);
                    defer gpa.free(payload);
                    buf.shrinkRetainingCapacity(start);
                    try c.writeFrame(.pong, payload);
                    continue;
                },
                .pong => {
                    try c.countControl();
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
            if (h.fin) {
                return .{ .opcode = msg_op.?, .data = try buf.toOwnedSlice(gpa) };
            }
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

/// A server-side connection over bytes in memory, for frame-level tests.
fn memConn(bytes: []const u8, out: *std.Io.Writer, r: *std.Io.Reader, is_client: bool) Conn {
    r.* = std.Io.Reader.fixed(bytes);
    return .{ .io = std.testing.io, .stream = undefined, .reader = undefined, .writer = undefined, .r = r, .w = out, .owns_stream = false, .is_client = is_client, .max_message = 1 << 16 };
}

fn maskedFrame(al: std.mem.Allocator, op: u8, fin: bool, payload: []const u8) ![]u8 {
    const mask = [4]u8{ 0x11, 0x22, 0x33, 0x44 };
    var f: std.ArrayList(u8) = .empty;
    try f.append(al, (if (fin) @as(u8, 0x80) else 0) | op);
    try f.append(al, 0x80 | @as(u8, @intCast(payload.len)));
    try f.appendSlice(al, &mask);
    for (payload, 0..) |b, i| try f.append(al, b ^ mask[i % 4]);
    return f.toOwnedSlice(al);
}

test "a server refuses an unmasked frame, a client refuses a masked one" {
    const gpa = std.testing.allocator;
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var r: std.Io.Reader = undefined;
    // Unmasked text frame "hi" to a server.
    var server = memConn(&.{ 0x81, 0x02, 'h', 'i' }, &sink.writer, &r, false);
    try std.testing.expectError(error.Protocol, server.readMessage(gpa));
    // The same, masked: accepted.
    const ok = try maskedFrame(gpa, 0x1, true, "hi");
    defer gpa.free(ok);
    var server2 = memConn(ok, &sink.writer, &r, false);
    const m = try server2.readMessage(gpa);
    defer gpa.free(m.data);
    try std.testing.expectEqualStrings("hi", m.data);
    // A masked frame sent to a client (what a server must never do).
    const bad = try maskedFrame(gpa, 0x1, true, "hi");
    defer gpa.free(bad);
    var client = memConn(bad, &sink.writer, &r, true);
    try std.testing.expectError(error.Protocol, client.readMessage(gpa));
    var client2 = memConn(&.{ 0x81, 0x02, 'h', 'i' }, &sink.writer, &r, true);
    const m2 = try client2.readMessage(gpa);
    defer gpa.free(m2.data);
    try std.testing.expectEqualStrings("hi", m2.data);
}

test "a peer that floods pings, or sends endless empty fragments, is cut off" {
    const gpa = std.testing.allocator;
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var r: std.Io.Reader = undefined;
    // 300 masked pings at once: one past `max_control_per_second` is a protocol error.
    var pings: std.ArrayList(u8) = .empty;
    defer pings.deinit(gpa);
    for (0..300) |_| {
        const f = try maskedFrame(gpa, 0x9, true, "");
        defer gpa.free(f);
        try pings.appendSlice(gpa, f);
    }
    var c = memConn(pings.items, &sink.writer, &r, false);
    try std.testing.expectError(error.Protocol, c.readMessage(gpa));
    try std.testing.expectEqual(@as(u64, max_control_per_second + 1), c.control_frames);

    // A text frame then 5000 empty continuation frames, never finished.
    var frags: std.ArrayList(u8) = .empty;
    defer frags.deinit(gpa);
    const first = try maskedFrame(gpa, 0x1, false, "");
    defer gpa.free(first);
    try frags.appendSlice(gpa, first);
    for (0..5000) |_| {
        const f = try maskedFrame(gpa, 0x0, false, "");
        defer gpa.free(f);
        try frags.appendSlice(gpa, f);
    }
    var c2 = memConn(frags.items, &sink.writer, &r, false);
    try std.testing.expectError(error.Protocol, c2.readMessage(gpa));

    // Up to the limit, pings between real messages are fine, and data does not reset the count.
    var ok: std.ArrayList(u8) = .empty;
    defer ok.deinit(gpa);
    for (0..4) |_| {
        for (0..max_control_per_second / 4) |_| {
            const f = try maskedFrame(gpa, 0x9, true, "");
            defer gpa.free(f);
            try ok.appendSlice(gpa, f);
        }
        const t = try maskedFrame(gpa, 0x1, true, "x");
        defer gpa.free(t);
        try ok.appendSlice(gpa, t);
    }
    const one_more = try maskedFrame(gpa, 0xA, true, "");
    defer gpa.free(one_more);
    try ok.appendSlice(gpa, one_more);
    var c3 = memConn(ok.items, &sink.writer, &r, false);
    for (0..4) |_| {
        const m = try c3.readMessage(gpa);
        gpa.free(m.data);
    }
    try std.testing.expectError(error.Protocol, c3.readMessage(gpa)); // the 65th within a second
}

test "control frames are limited per second, not per run: an idle connection pinged forever is fine" {
    var rate: ControlRate = .{};
    // A ping every 20 ms (50 a second) for an hour of pings and no data.
    var t: i64 = 0;
    for (0..200_000) |_| {
        try std.testing.expect(rate.allow(t));
        t += 20;
    }
    // A burst: 64 in one millisecond pass, the 65th within the second does not, and a second later
    // the window has room again.
    var burst: ControlRate = .{};
    for (0..max_control_per_second) |_| try std.testing.expect(burst.allow(5000));
    try std.testing.expect(!burst.allow(5999));
    try std.testing.expect(burst.allow(6000));
    // In any one second, never more than the limit, whatever the spacing.
    var any: ControlRate = .{};
    var allowed: std.ArrayList(i64) = .empty;
    defer allowed.deinit(std.testing.allocator);
    var prng = std.Random.DefaultPrng.init(7);
    var now: i64 = 0;
    for (0..20_000) |_| {
        now += prng.random().uintLessThan(u32, 40);
        if (any.allow(now)) try allowed.append(std.testing.allocator, now);
    }
    var lo: usize = 0;
    for (allowed.items, 0..) |x, hi| {
        while (x - allowed.items[lo] >= 1000) lo += 1;
        try std.testing.expect(hi - lo + 1 <= max_control_per_second);
    }
}

test "peer check: only this user may serve Rex's socket" {
    try std.testing.expect(peerAllowed(501, 501));
    try std.testing.expect(!peerAllowed(0, 501)); // not even root
    try std.testing.expect(!peerAllowed(502, 501));
    try std.testing.expect(!peerAllowed(501, 0));
}

/// A listening unix socket of our own under /tmp, for tests that need a real stream pair.
const TestListener = struct {
    path_buf: [64]u8 = undefined,
    path: []const u8 = "",
    server: Io.net.Server = undefined,

    fn init(l: *TestListener, io: Io) !void {
        var rnd: [6]u8 = undefined;
        io.random(&rnd);
        l.path = try std.fmt.bufPrint(&l.path_buf, "/tmp/rweb-ws-test-{x}.sock", .{rnd});
        const addr = try Io.net.UnixAddress.init(l.path);
        l.server = try addr.listen(io, .{});
    }

    fn deinit(l: *TestListener, io: Io) void {
        l.server.deinit(io);
        Io.Dir.deleteFileAbsolute(io, l.path) catch {};
    }
};

test "peer check: a socket served by this user passes" {
    const io = std.testing.io;
    var l: TestListener = .{};
    try l.init(io);
    defer l.deinit(io);
    const client = try connectUnix(io, l.path);
    defer client.close(io);
    const server_side = try l.server.accept(io);
    defer server_side.close(io);
    try std.testing.expectEqual(@as(?u32, myUid()), peerUid(client));
    try checkPeer(server_side);
}

test "watchdog: one that fired fails the handshake, one stopped in time does not" {
    const io = std.testing.io;
    var l: TestListener = .{};
    try l.init(io);
    defer l.deinit(io);
    const client = try connectUnix(io, l.path);
    defer client.close(io);
    const server_side = try l.server.accept(io);
    defer server_side.close(io);

    var early = try Watchdog.start(io, client, 10_000);
    try early.finish(io);
    early.stop(io); // stopping again, as a `defer` does, is fine

    var late = try Watchdog.start(io, client, 10);
    defer late.stop(io);
    try io.sleep(.fromMilliseconds(100), .awake); // a WELCOME read now would still succeed
    try std.testing.expectError(error.HandshakeTimeout, late.finish(io));
}

test "writeFrame: a task cancelled inside a frame still writes it whole" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var l: TestListener = .{};
    try l.init(io);
    defer l.deinit(io);
    const client_stream = try connectUnix(io, l.path);
    const server_stream = try l.server.accept(io);

    var client: Conn = .{ .io = io, .stream = client_stream, .reader = undefined, .writer = undefined };
    client.reader = client_stream.reader(io, &client.read_buf);
    client.writer = client_stream.writer(io, &client.write_buf);
    client.r = &client.reader.interface;
    client.w = &client.writer.interface;
    defer client_stream.close(io);
    var server: Conn = .{ .io = io, .stream = server_stream, .reader = undefined, .writer = undefined, .is_client = false, .max_message = 8 << 20 };
    server.reader = server_stream.reader(io, &server.read_buf);
    server.writer = server_stream.writer(io, &server.write_buf);
    server.r = &server.reader.interface;
    server.w = &server.writer.interface;
    defer server_stream.close(io);

    // Far more than the socket buffers hold, so the write blocks until the other side reads.
    const payload = try gpa.alloc(u8, 4 << 20);
    defer gpa.free(payload);
    for (payload, 0..) |*b, i| b.* = @truncate(i *% 31);

    const T = struct {
        fn write(c: *Conn, data: []const u8) anyerror!void {
            try c.writeFrame(.binary, data);
        }
        fn read(c: *Conn, a: Allocator) anyerror!Message {
            try c.io.sleep(.fromMilliseconds(150), .awake); // the cancel arrives while the write is blocked
            return c.readMessage(a);
        }
    };
    var writer = try io.concurrent(T.write, .{ &client, payload });
    try io.sleep(.fromMilliseconds(50), .awake);
    var reader = try io.concurrent(T.read, .{ &server, gpa });
    const wrote = writer.cancel(io);
    // Without the protection the write stops part-way and the reader would wait forever.
    if (wrote) |_| {} else |_| client_stream.shutdown(io, .both) catch {};
    try wrote;
    const m = try reader.await(io);
    defer gpa.free(m.data);
    try std.testing.expectEqual(Opcode.binary, m.opcode);
    try std.testing.expectEqualSlices(u8, payload, m.data);
}

/// A connected client and server `Conn` over a fresh unix socket pair, for tests.
const TestPair = struct {
    l: TestListener = .{},
    client: Conn = undefined,
    server: Conn = undefined,

    fn init(p: *TestPair, io: Io) !void {
        try p.l.init(io);
        const cs = try connectUnix(io, p.l.path);
        const ss = try p.l.server.accept(io);
        p.client = .{ .io = io, .stream = cs, .reader = undefined, .writer = undefined, .owns_stream = false };
        p.client.reader = cs.reader(io, &p.client.read_buf);
        p.client.writer = cs.writer(io, &p.client.write_buf);
        p.client.r = &p.client.reader.interface;
        p.client.w = &p.client.writer.interface;
        p.server = .{ .io = io, .stream = ss, .reader = undefined, .writer = undefined, .is_client = false, .owns_stream = false, .max_message = 8 << 20 };
        p.server.reader = ss.reader(io, &p.server.read_buf);
        p.server.writer = ss.writer(io, &p.server.write_buf);
        p.server.r = &p.server.reader.interface;
        p.server.w = &p.server.writer.interface;
    }

    fn deinit(p: *TestPair, io: Io) void {
        p.client.stream.close(io);
        p.server.stream.close(io);
        p.l.deinit(io);
    }
};

test "writeFrame: a peer that stops reading cannot hold a write past its deadline" {
    const gpa = std.testing.allocator;
    const io = std.testing.io;
    var p: TestPair = .{};
    try p.init(io);
    defer p.deinit(io);

    // Within its deadline, a frame goes through as before.
    p.client.write_timeout_ms = 10_000;
    try p.client.writeFrame(.text, "on time");
    const m = try p.server.readMessage(gpa);
    defer gpa.free(m.data);
    try std.testing.expectEqualStrings("on time", m.data);

    // The server stops reading; a frame far larger than the socket buffers blocks, and its
    // deadline shuts the stream instead of leaving the writer (and the write lock) held.
    const payload = try gpa.alloc(u8, 8 << 20);
    defer gpa.free(payload);
    @memset(payload, 'x');
    p.client.write_timeout_ms = 200;
    const t0 = Io.Clock.awake.now(io).toMilliseconds();
    try std.testing.expectError(error.WriteTimeout, p.client.writeFrame(.binary, payload));
    try std.testing.expect(Io.Clock.awake.now(io).toMilliseconds() - t0 < 5000);
    // The connection is shut: the next write fails at once, whatever its own deadline.
    try std.testing.expect(std.meta.isError(p.client.writeFrameTimeout(.text, "late", 60_000)));
    // And the peer sees the end of the stream after the part of the frame that got through.
    try std.testing.expect(std.meta.isError(p.server.readMessage(gpa)));
}

test "control frames: the limit can be raised (for the fuzzer), and a lowered one holds" {
    const gpa = std.testing.allocator;
    var sink: std.Io.Writer.Allocating = .init(gpa);
    defer sink.deinit();
    var r: std.Io.Reader = undefined;
    var pings: std.ArrayList(u8) = .empty;
    defer pings.deinit(gpa);
    for (0..1000) |_| {
        const f = try maskedFrame(gpa, 0x9, true, "");
        defer gpa.free(f);
        try pings.appendSlice(gpa, f);
    }
    const t = try maskedFrame(gpa, 0x1, true, "after");
    defer gpa.free(t);
    try pings.appendSlice(gpa, t);
    // Raised: a thousand pings in a row, then the message.
    var c = memConn(pings.items, &sink.writer, &r, false);
    c.control_limit = std.math.maxInt(u32);
    const m = try c.readMessage(gpa);
    defer gpa.free(m.data);
    try std.testing.expectEqualStrings("after", m.data);
    try std.testing.expectEqual(@as(u64, 1000), c.control_frames);
    // Raised to a number: that many and no more in a second.
    var c2 = memConn(pings.items, &sink.writer, &r, false);
    c2.control_limit = 500;
    try std.testing.expectError(error.Protocol, c2.readMessage(gpa));
    try std.testing.expectEqual(@as(u64, 501), c2.control_frames);
    // Lowered below the default: the sliding window uses it.
    var c3 = memConn(pings.items, &sink.writer, &r, false);
    c3.control_limit = 3;
    try std.testing.expectError(error.Protocol, c3.readMessage(gpa));
    try std.testing.expectEqual(@as(u64, 4), c3.control_frames);
    var rate: ControlRate = .{};
    for (0..3) |_| try std.testing.expect(rate.allowUpTo(100, 3));
    try std.testing.expect(!rate.allowUpTo(1099, 3));
    try std.testing.expect(rate.allowUpTo(1100, 3));
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
