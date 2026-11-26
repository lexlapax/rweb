//! Parsers for the bytes of Rex's handshakes, kept free of I/O and of Ghostty so they can be
//! fuzzed (see `fuzz.zig`).

const std = @import("std");
const Allocator = std.mem.Allocator;

pub const subprotocol = "rex.control.v1";

pub const Welcome = struct {
    resumed: bool,
    /// Owned by the allocator given to `parseWelcome`.
    token: ?[]u8,
    revision: u32,
    /// The server's message limit, if it sent a sane one (at least 64 KiB), and at most
    /// `client_max_message`.
    max_message: ?u64,
};

/// The largest message this client lets a server announce: a server's own limit is clamped to it.
pub const client_max_message: u64 = 16 * 1024 * 1024;
/// The largest message read on a data stream (a terminal's output or a download) once its
/// handshake is done. Rex's protocol sends a stream in binary messages of 1 to 65,536 bytes
/// (`/llms.txt`, data connections; downloads measured the same): 16 times that leaves room for a
/// change in Rex without letting one message hold more than a mebibyte.
pub const data_max_message: u64 = 1024 * 1024;
/// The longest reconnect token accepted. It goes back to the server in the next hello.
pub const max_reconnect_token = 256;

/// Parse the server's first message. Pure, so it can be fuzzed.
pub fn parseWelcome(gpa: Allocator, text: []const u8) WelcomeError!Welcome {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.BadWelcome,
    };
    defer parsed.deinit();
    if (parsed.value != .object) return error.BadWelcome;
    const o = parsed.value.object;
    const ty = o.get("type") orelse return error.BadWelcome;
    const proto = o.get("protocol") orelse return error.BadWelcome;
    if (ty != .string or !std.mem.eql(u8, ty.string, "welcome")) return error.BadWelcome;
    if (proto != .string or !std.mem.eql(u8, proto.string, subprotocol)) return error.BadWelcome;
    var w: Welcome = .{ .resumed = false, .token = null, .revision = 0, .max_message = null };
    if (o.get("client")) |cl| if (cl == .object) {
        if (cl.object.get("resumed")) |r| w.resumed = r == .bool and r.bool;
        if (cl.object.get("reconnect_token")) |t| if (t == .string) {
            if (t.string.len > max_reconnect_token) return error.BadWelcome;
            for (t.string) |ch| if (!std.ascii.isPrint(ch)) return error.BadWelcome;
            w.token = gpa.dupe(u8, t.string) catch return error.OutOfMemory;
        };
    };
    if (o.get("api_revision")) |r| if (r == .integer and r.integer >= 0 and r.integer < 1 << 31) {
        w.revision = @intCast(r.integer);
    };
    if (o.get("limits")) |l| if (l == .object) if (l.object.get("max_message_bytes")) |mb| {
        if (mb == .integer and mb.integer >= 65536) w.max_message = @min(@as(u64, @intCast(mb.integer)), client_max_message);
    };
    return w;
}

pub const WelcomeError = error{ BadWelcome, OutOfMemory };

pub const Handshake = union(enum) {
    welcome: struct { token: [16]u8, window_ms: u32, nonce: u64 },
    reject: u8,
};

/// Parse a WELCOME or REJECT. Pure, for tests and fuzzing.
pub fn parseHandshake(b: []const u8) error{BadHandshake}!Handshake {
    if (b.len == 0) return error.BadHandshake;
    switch (b[0]) {
        0x81 => {
            if (b.len != 32) return error.BadHandshake;
            const nonce = std.mem.readInt(u64, b[24..32], .little);
            if (nonce == 0) return error.BadHandshake;
            return .{ .welcome = .{
                .token = b[1..17].*,
                .window_ms = std.mem.readInt(u32, b[20..24], .little),
                .nonce = nonce,
            } };
        },
        0x82 => {
            if (b.len < 2) return error.BadHandshake;
            return .{ .reject = b[1] };
        },
        else => return error.BadHandshake,
    }
}

pub fn decodeTicket(text: []const u8) error{BadHandshake}![16]u8 {
    var out: [16]u8 = undefined;
    if (text.len != 22) return error.BadHandshake;
    std.base64.url_safe_no_pad.Decoder.decode(&out, text) catch return error.BadHandshake;
    return out;
}

/// The length of the snapshot at the start of `buf`, once all of it is there; null while more is
/// needed. Reads only the framing (a 10-byte envelope, then records of a 10-byte header, tag
/// u16 and payload length u32 little-endian plus a checksum, and the payload, up to the FINISH
/// record; see Ghostty's src/terminal/snapshot/main.zig), resuming at `scan.*`. A record that
/// would end past `limit` fails at once, before its bytes arrive.
pub fn snapshotEnd(buf: []const u8, scan: *usize, limit: usize) error{ BadSnapshot, SnapshotTooLarge }!?usize {
    const envelope_len = 10;
    const header_len = 10;
    const finish_tag: u16 = 6;
    if (scan.* == 0) {
        if (buf.len < envelope_len) {
            if (!std.mem.startsWith(u8, "GHOSTSNP", buf[0..@min(buf.len, 8)])) return error.BadSnapshot;
            return null;
        }
        if (!std.mem.eql(u8, buf[0..8], "GHOSTSNP")) return error.BadSnapshot;
        scan.* = envelope_len;
    }
    while (scan.* <= buf.len and buf.len - scan.* >= header_len) {
        const h = buf[scan.*..][0..header_len];
        const tag = std.mem.readInt(u16, h[0..2], .little);
        const payload: u64 = std.mem.readInt(u32, h[2..6], .little);
        const record_end = @as(u64, scan.*) + header_len + payload;
        if (record_end > limit) return error.SnapshotTooLarge;
        if (tag == finish_tag) return if (buf.len >= record_end) @intCast(record_end) else null;
        scan.* = @intCast(record_end); // may be past `buf.len` while the payload arrives
    }
    return null;
}

// ---- tests ----

const testing = std.testing;

test "parseWelcome" {
    const a = testing.allocator;
    const w = try parseWelcome(a, "{\"type\":\"welcome\",\"protocol\":\"rex.control.v1\",\"limits\":{\"max_message_bytes\":1048576},\"client\":{\"id\":\"c\",\"reconnect_token\":\"tok\",\"resumed\":true},\"api_revision\":18}");
    defer a.free(w.token.?);
    try testing.expect(w.resumed);
    try testing.expectEqualStrings("tok", w.token.?);
    try testing.expectEqual(@as(u32, 18), w.revision);
    try testing.expectEqual(@as(?u64, 1048576), w.max_message);
    try testing.expectError(error.BadWelcome, parseWelcome(a, "{\"type\":\"event\"}"));
    try testing.expectError(error.BadWelcome, parseWelcome(a, "[]"));
    try testing.expectError(error.BadWelcome, parseWelcome(a, "{\"type\":\"welcome\",\"protocol\":\"other\"}"));
    // A limit below the protocol's minimum is ignored.
    const w2 = try parseWelcome(a, "{\"type\":\"welcome\",\"protocol\":\"rex.control.v1\",\"limits\":{\"max_message_bytes\":10}}");
    try testing.expectEqual(@as(?u64, null), w2.max_message);
}

test "parseWelcome: the server's limit is clamped, and a long or odd reconnect token is refused" {
    const a = testing.allocator;
    const head = "{\"type\":\"welcome\",\"protocol\":\"rex.control.v1\",";
    const huge = try parseWelcome(a, head ++ "\"limits\":{\"max_message_bytes\":9223372036854775807}}");
    try testing.expectEqual(@as(?u64, client_max_message), huge.max_message);
    const fine = try parseWelcome(a, head ++ "\"limits\":{\"max_message_bytes\":2097152}}");
    try testing.expectEqual(@as(?u64, 2097152), fine.max_message);

    var buf: [600]u8 = undefined;
    const tok_arr: [max_reconnect_token]u8 = @splat('t');
    const tok: []const u8 = &tok_arr;
    const at_limit = try parseWelcome(a, try std.fmt.bufPrint(&buf, "{s}\"client\":{{\"reconnect_token\":\"{s}\"}}}}", .{ head, tok }));
    defer a.free(at_limit.token.?);
    try testing.expectEqual(@as(usize, max_reconnect_token), at_limit.token.?.len);
    try testing.expectError(error.BadWelcome, parseWelcome(a, try std.fmt.bufPrint(&buf, "{s}\"client\":{{\"reconnect_token\":\"{s}x\"}}}}", .{ head, tok })));
    try testing.expectError(error.BadWelcome, parseWelcome(a, head ++ "\"client\":{\"reconnect_token\":\"a\\nb\"}}"));
    try testing.expectError(error.BadWelcome, parseWelcome(a, head ++ "\"client\":{\"reconnect_token\":\"caf\\u00e9\"}}"));
}

test "parseHandshake" {
    var w: [32]u8 = @splat(0);
    w[0] = 0x81;
    std.mem.writeInt(u32, w[20..24], 60000, .little);
    std.mem.writeInt(u64, w[24..32], 77, .little);
    const h = try parseHandshake(&w);
    try testing.expectEqual(@as(u64, 77), h.welcome.nonce);
    try testing.expectEqual(@as(u32, 60000), h.welcome.window_ms);
    try testing.expectEqual(@as(u8, 3), (try parseHandshake(&.{ 0x82, 3 })).reject);
    try testing.expectError(error.BadHandshake, parseHandshake(w[0..31]));
    std.mem.writeInt(u64, w[24..32], 0, .little);
    try testing.expectError(error.BadHandshake, parseHandshake(&w)); // nonce is never zero
    try testing.expectError(error.BadHandshake, parseHandshake(&.{}));
    try testing.expectError(error.BadHandshake, parseHandshake(&.{0x55}));
}

test "decodeTicket" {
    const t = try decodeTicket("AAECAwQFBgcICQoLDA0ODw");
    try testing.expectEqual(@as(u8, 15), t[15]);
    try testing.expectError(error.BadHandshake, decodeTicket("short"));
}
