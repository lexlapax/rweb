//! The browser protocol: the bridge's own, independent of Rex's. JSON text frames carry
//! commands and notices; binary frames carry terminal output for the terminal being viewed.
//!
//! Client to server (`t` names the message):
//!   tree                          refresh the session tree
//!   open {session, block}         view a terminal (replaces the one being viewed)
//!   close_view                    stop viewing
//!   in {d}                        typed or composed text (xterm.js onData)
//!   key {key}                     a physical key, as Rex's `client.key` takes it
//!   paste {d}   mouse {payload}   `block.event`s
//!   fit {cols, rows}              take ownership and resize (only when the user asks)
//!   redraw / more_history         a fresh redraw, the latter with all the scrollback
//!   observe {on}                  this browser's read-only switch
//!   new_session {label?} / new_terminal {session} / rename_session {session, label}
//!   rename_block {session, block, label} / close_block {session, block} / destroy_session {session}
//!   ping
//! Server to client: see `hub.zig` (`tree`, `opened`, `size`, `theme`, `exited`, `closed`,
//! `mode`, `notice`, `error`, `pong`).
//!
//! Everything here is untrusted input: bounded, validated, and never trusted to be well formed.

const std = @import("std");
const Allocator = std.mem.Allocator;

/// Largest text frame the bridge reads from a browser.
pub const max_message_bytes = 64 * 1024;
/// Largest `in` or `paste` payload in one message.
pub const max_input_bytes = 32 * 1024;
pub const max_id_bytes = 200;
pub const max_label_bytes = 128;
pub const max_cols_rows = 1000;

pub const Msg = union(enum) {
    tree,
    open: struct { session: []const u8, block: []const u8 },
    close_view,
    in: []const u8,
    /// The `key` object as JSON text, forwarded to `client.key`.
    key: []const u8,
    paste: []const u8,
    /// The `payload` as JSON text, forwarded in a `mouse` `block.event`.
    mouse: []const u8,
    fit: struct { cols: u16, rows: u16 },
    redraw,
    more_history,
    observe: bool,
    new_session: ?[]const u8,
    new_terminal: []const u8,
    rename_session: struct { session: []const u8, label: []const u8 },
    rename_block: struct { session: []const u8, block: []const u8, label: []const u8 },
    close_block: struct { session: []const u8, block: []const u8 },
    destroy_session: []const u8,
    ping,
};

pub const ParseError = error{ Malformed, TooLarge, UnknownType, BadField } || Allocator.Error;

/// Parse one text frame. Strings in the result live in `arena`.
pub fn parse(arena: Allocator, text: []const u8) ParseError!Msg {
    if (text.len > max_message_bytes) return error.TooLarge;
    const v = std.json.parseFromSliceLeaky(std.json.Value, arena, text, .{}) catch |e| switch (e) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    if (v != .object) return error.Malformed;
    const o = v.object;
    const t = try str(o, "t", 32);
    const eql = std.mem.eql;
    if (eql(u8, t, "tree")) return .tree;
    if (eql(u8, t, "close_view")) return .close_view;
    if (eql(u8, t, "redraw")) return .redraw;
    if (eql(u8, t, "more_history")) return .more_history;
    if (eql(u8, t, "ping")) return .ping;
    if (eql(u8, t, "open")) return .{ .open = .{ .session = try str(o, "session", max_id_bytes), .block = try str(o, "block", max_id_bytes) } };
    if (eql(u8, t, "in")) return .{ .in = try str(o, "d", max_input_bytes) };
    if (eql(u8, t, "paste")) return .{ .paste = try str(o, "d", max_input_bytes) };
    if (eql(u8, t, "key")) return .{ .key = try jsonOf(arena, o, "key", 4096) };
    if (eql(u8, t, "mouse")) return .{ .mouse = try jsonOf(arena, o, "payload", 4096) };
    if (eql(u8, t, "fit")) {
        const cols = try dim(o, "cols");
        const rows = try dim(o, "rows");
        return .{ .fit = .{ .cols = cols, .rows = rows } };
    }
    if (eql(u8, t, "observe")) {
        const on = o.get("on") orelse return error.BadField;
        if (on != .bool) return error.BadField;
        return .{ .observe = on.bool };
    }
    if (eql(u8, t, "new_session")) return .{ .new_session = if (o.get("label") != null) try label(o, "label") else null };
    if (eql(u8, t, "new_terminal")) return .{ .new_terminal = try str(o, "session", max_id_bytes) };
    if (eql(u8, t, "destroy_session")) return .{ .destroy_session = try str(o, "session", max_id_bytes) };
    if (eql(u8, t, "rename_session")) return .{ .rename_session = .{ .session = try str(o, "session", max_id_bytes), .label = try label(o, "label") } };
    if (eql(u8, t, "rename_block")) return .{ .rename_block = .{ .session = try str(o, "session", max_id_bytes), .block = try str(o, "block", max_id_bytes), .label = try label(o, "label") } };
    if (eql(u8, t, "close_block")) return .{ .close_block = .{ .session = try str(o, "session", max_id_bytes), .block = try str(o, "block", max_id_bytes) } };
    return error.UnknownType;
}

fn str(o: std.json.ObjectMap, name: []const u8, max: usize) ParseError![]const u8 {
    const v = o.get(name) orelse return error.BadField;
    if (v != .string) return error.BadField;
    if (v.string.len > max) return error.TooLarge;
    return v.string;
}

/// A label: no control characters, at most 128 bytes (Rex's own rule).
fn label(o: std.json.ObjectMap, name: []const u8) ParseError![]const u8 {
    const s = try str(o, name, max_label_bytes);
    for (s) |c| if (c < 0x20 or c == 0x7f) return error.BadField;
    return s;
}

fn dim(o: std.json.ObjectMap, name: []const u8) ParseError!u16 {
    const v = o.get(name) orelse return error.BadField;
    if (v != .integer or v.integer < 1 or v.integer > max_cols_rows) return error.BadField;
    return @intCast(v.integer);
}

/// The JSON text of an object-valued field.
fn jsonOf(arena: Allocator, o: std.json.ObjectMap, name: []const u8, max: usize) ParseError![]const u8 {
    const v = o.get(name) orelse return error.BadField;
    if (v != .object) return error.BadField;
    const text = std.json.Stringify.valueAlloc(arena, v, .{}) catch return error.OutOfMemory;
    if (text.len > max) return error.TooLarge;
    return text;
}

// ---- tests ----

const testing = std.testing;

fn parseT(text: []const u8) ParseError!Msg {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m = try parse(arena.allocator(), text);
    // Copy out nothing: only check tags and simple values in the tests below.
    return switch (m) {
        .in, .paste, .key, .mouse, .open, .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session => .tree, // marker: parsed
        else => m,
    };
}

test "simple messages" {
    try testing.expectEqual(Msg.tree, try parseT("{\"t\":\"tree\"}"));
    try testing.expectEqual(Msg.ping, try parseT("{\"t\":\"ping\"}"));
    try testing.expectEqual(Msg.redraw, try parseT("{\"t\":\"redraw\"}"));
    try testing.expectEqual(Msg{ .observe = true }, try parseT("{\"t\":\"observe\",\"on\":true}"));
    try testing.expectEqual(Msg{ .fit = .{ .cols = 100, .rows = 30 } }, try parseT("{\"t\":\"fit\",\"cols\":100,\"rows\":30}"));
}

test "values are carried" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m = try parse(arena.allocator(), "{\"t\":\"open\",\"session\":\"session:1\",\"block\":\"block:2\"}");
    try testing.expectEqualStrings("session:1", m.open.session);
    try testing.expectEqualStrings("block:2", m.open.block);
    const k = try parse(arena.allocator(), "{\"t\":\"key\",\"key\":{\"key\":\"key_a\",\"mods\":\"ctrl\"}}");
    try testing.expectEqualStrings("{\"key\":\"key_a\",\"mods\":\"ctrl\"}", k.key);
    const i = try parse(arena.allocator(), "{\"t\":\"in\",\"d\":\"ls\\r\"}");
    try testing.expectEqualStrings("ls\r", i.in);
    const s = try parse(arena.allocator(), "{\"t\":\"new_session\"}");
    try testing.expect(s.new_session == null);
}

test "rejects what it should" {
    const t = testing;
    try t.expectError(error.Malformed, parseT("not json"));
    try t.expectError(error.Malformed, parseT("[]"));
    try t.expectError(error.BadField, parseT("{}"));
    try t.expectError(error.UnknownType, parseT("{\"t\":\"rm -rf\"}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"in\",\"d\":5}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"key\",\"key\":\"x\"}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"fit\",\"cols\":0,\"rows\":5}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"fit\",\"cols\":100000,\"rows\":5}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"fit\",\"cols\":\"8\",\"rows\":5}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"observe\",\"on\":1}"));
    try t.expectError(error.BadField, parseT("{\"t\":\"rename_session\",\"session\":\"s\",\"label\":\"a\\nb\"}"));
    const long: [max_id_bytes + 1]u8 = @splat('x');
    const lj = try std.fmt.allocPrint(testing.allocator, "{{\"t\":\"new_terminal\",\"session\":\"{s}\"}}", .{long});
    defer testing.allocator.free(lj);
    try t.expectError(error.TooLarge, parseT(lj));
    const big = try testing.allocator.alloc(u8, max_message_bytes + 1);
    defer testing.allocator.free(big);
    @memset(big, ' ');
    try t.expectError(error.TooLarge, parseT(big));
}
