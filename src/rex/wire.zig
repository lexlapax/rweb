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
    /// The server's message limit, if it sent a sane one (at least 64 KiB).
    max_message: ?u64,
};

/// Parse the server's first message. Pure, so it can be fuzzed.
pub fn parseWelcome(gpa: Allocator, text: []const u8) WelcomeError!Welcome {
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, text, .{}) catch return error.BadWelcome;
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
            w.token = gpa.dupe(u8, t.string) catch return error.OutOfMemory;
        };
    };
    if (o.get("api_revision")) |r| if (r == .integer and r.integer >= 0 and r.integer < 1 << 31) {
        w.revision = @intCast(r.integer);
    };
    if (o.get("limits")) |l| if (l == .object) if (l.object.get("max_message_bytes")) |mb| {
        if (mb == .integer and mb.integer >= 65536) w.max_message = @intCast(mb.integer);
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
