//! The browser protocol: the bridge's own, independent of Rex's. JSON text frames carry
//! commands and notices; binary frames carry terminal output for the terminal being viewed.
//!
//! Client to server (`t` names the message):
//!   tree                          refresh the session tree
//!   open {session, block}         view a terminal (replaces the one being viewed)
//!   close_view                    stop viewing
//!   in {d}                        typed or composed text (xterm.js onData)
//!   key {key}                     a physical key, as Rex's `client.key` takes it
//!   paste {d, force?}             a `block.event`; a multi-line paste into a program without
//!                                 bracketed paste is refused (`code: confirm_multiline`) unless
//!                                 `force` says the user confirmed it
//!   fit {cols, rows}              take ownership and resize (only when the user asks)
//!   redraw / more_history         a fresh redraw, the latter with all the scrollback
//!   text                          the screen and scrollback as plain text (reply: `text`)
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
/// A transfer is never announced as larger than this (the bridge's own cap is lower).
pub const max_transfer_size: i64 = 1 << 40;
pub const max_path_bytes = 1024;

pub const Msg = union(enum) {
    tree,
    open: struct { session: []const u8, block: []const u8 },
    close_view,
    in: []const u8,
    /// The `key` object as JSON text, forwarded to `client.key`.
    key: []const u8,
    paste: struct { text: []const u8, force: bool = false },
    fit: struct { cols: u16, rows: u16 },
    redraw,
    more_history,
    /// The screen and scrollback as plain text, for the page's Copy view.
    text,
    /// Title, folder, program and listening ports of the open terminal, for the page's header.
    info,
    /// List a directory (empty: the terminal's folder) for the download picker.
    ls: []const u8,
    /// Ask for a download token for a file.
    dl: []const u8,
    /// Ask for an upload token for a file the browser is about to send.
    ul: struct { name: []const u8, size: u64 },
    /// The newest text a program in the terminal copied (OSC 52).
    clip,
    /// `clear` or `reset` the open terminal.
    term_action: enum { clear, reset },
    observe: bool,
    new_session: ?[]const u8,
    new_terminal: []const u8,
    rename_session: struct { session: []const u8, label: []const u8 },
    rename_block: struct { session: []const u8, block: []const u8, label: []const u8 },
    close_block: struct { session: []const u8, block: []const u8 },
    destroy_session: []const u8,
    ping,
    /// Keyboard diagnostics from the page (`?dbg=1`); logged by a bridge started with
    /// `--debug-input`, ignored otherwise.
    dbg,
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
    if (eql(u8, t, "text")) return .text;
    if (eql(u8, t, "info")) return .info;
    if (eql(u8, t, "ls")) return .{ .ls = try pathField(o, "path", true) };
    if (eql(u8, t, "dl")) return .{ .dl = try pathField(o, "path", false) };
    if (eql(u8, t, "ul")) {
        const name = try str(o, "name", 255);
        if (name.len == 0 or !std.unicode.utf8ValidateSlice(name)) return error.BadField;
        for (name) |c| if (c < 0x20 or c == 0x7f) return error.BadField;
        const sv = o.get("size") orelse return error.BadField;
        if (sv != .integer or sv.integer < 0 or sv.integer > max_transfer_size) return error.BadField;
        return .{ .ul = .{ .name = name, .size = @intCast(sv.integer) } };
    }
    if (eql(u8, t, "clip")) return .clip;
    if (eql(u8, t, "term_action")) {
        const a = try str(o, "action", 16);
        if (eql(u8, a, "clear")) return .{ .term_action = .clear };
        if (eql(u8, a, "reset")) return .{ .term_action = .reset };
        return error.BadField;
    }
    if (eql(u8, t, "ping")) return .ping;
    if (eql(u8, t, "dbg")) return .dbg;
    if (eql(u8, t, "open")) return .{ .open = .{ .session = try str(o, "session", max_id_bytes), .block = try str(o, "block", max_id_bytes) } };
    if (eql(u8, t, "in")) return .{ .in = try str(o, "d", max_input_bytes) };
    if (eql(u8, t, "paste")) {
        const force = if (o.get("force")) |f| (if (f == .bool) f.bool else return error.BadField) else false;
        return .{ .paste = .{ .text = try str(o, "d", max_input_bytes), .force = force } };
    }
    if (eql(u8, t, "key")) return .{ .key = try keyJson(arena, o) };
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
/// A key press, rebuilt from fields checked one by one so that nothing the browser adds reaches
/// Rex's `client.key`, and with every value of the shape Rex expects.
fn keyJson(arena: Allocator, o: std.json.ObjectMap) ParseError![]const u8 {
    const v = o.get("key") orelse return error.BadField;
    if (v != .object) return error.BadField;
    const k = v.object;
    var it = k.iterator();
    while (it.next()) |e| {
        const known = [_][]const u8{ "key", "mods", "consumed_mods", "text", "unshifted_codepoint", "composing", "action" };
        for (known) |name| if (std.mem.eql(u8, e.key_ptr.*, name)) break else {} else return error.BadField;
    }
    const key = try wordField(k, "key", 40);
    const mods = if (k.contains("mods")) try wordField(k, "mods", 40) else "";
    const consumed = if (k.contains("consumed_mods")) try wordField(k, "consumed_mods", 40) else "";
    const action = if (k.contains("action")) try wordField(k, "action", 8) else "press";
    if (!std.mem.eql(u8, action, "press") and !std.mem.eql(u8, action, "repeat") and !std.mem.eql(u8, action, "release")) return error.BadField;
    var text: []const u8 = "";
    if (k.get("text")) |t| {
        if (t != .string or t.string.len > 16 or !std.unicode.utf8ValidateSlice(t.string)) return error.BadField;
        text = t.string;
    }
    var cp: i64 = 0;
    if (k.get("unshifted_codepoint")) |c| {
        if (c != .integer or c.integer < 0 or c.integer > 0x10FFFF) return error.BadField;
        cp = c.integer;
    }
    var composing = false;
    if (k.get("composing")) |c| {
        if (c != .bool) return error.BadField;
        composing = c.bool;
    }
    return std.json.Stringify.valueAlloc(arena, .{
        .key = key,
        .mods = mods,
        .consumed_mods = consumed,
        .text = text,
        .unshifted_codepoint = cp,
        .composing = composing,
        .action = action,
    }, .{}) catch return error.OutOfMemory;
}

/// A file or folder path from the browser: bounded, valid UTF-8, no control characters (no NUL,
/// no newline). `allow_empty` for a listing of the terminal's own folder.
fn pathField(o: std.json.ObjectMap, name: []const u8, allow_empty: bool) ParseError![]const u8 {
    const p = try str(o, name, max_path_bytes);
    if (p.len == 0 and !allow_empty) return error.BadField;
    if (!std.unicode.utf8ValidateSlice(p)) return error.BadField;
    for (p) |c| if (c < 0x20 or c == 0x7f) return error.BadField;
    return p;
}

/// A short field made of letters, digits, `_`, `+`, `,` and `-` only (key names and modifier lists).
fn wordField(o: std.json.ObjectMap, name: []const u8, max: usize) ParseError![]const u8 {
    const v = o.get(name) orelse return error.BadField;
    if (v != .string or v.string.len > max) return error.BadField;
    for (v.string) |c| if (!std.ascii.isAlphanumeric(c) and c != '_' and c != '+' and c != ',' and c != '-') return error.BadField;
    return v.string;
}

// ---- tests ----

const testing = std.testing;

fn parseT(text: []const u8) ParseError!Msg {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const m = try parse(arena.allocator(), text);
    // Copy out nothing: only check tags and simple values in the tests below.
    return switch (m) {
        .in, .paste, .key, .ls, .dl, .ul, .open, .new_session, .new_terminal, .rename_session, .rename_block, .close_block, .destroy_session => .tree, // marker: parsed
        else => m,
    };
}

test "simple messages" {
    try testing.expectEqual(Msg.tree, try parseT("{\"t\":\"tree\"}"));
    try testing.expectEqual(Msg.ping, try parseT("{\"t\":\"ping\"}"));
    try testing.expectEqual(Msg.redraw, try parseT("{\"t\":\"redraw\"}"));
    try testing.expectEqual(Msg.info, try parseT("{\"t\":\"info\"}"));
    try testing.expectEqual(Msg{ .term_action = .clear }, try parseT("{\"t\":\"term_action\",\"action\":\"clear\"}"));
    try testing.expectError(error.BadField, parseT("{\"t\":\"term_action\",\"action\":\"rm\"}"));
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
    try testing.expectEqualStrings("{\"key\":\"key_a\",\"mods\":\"ctrl\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":0,\"composing\":false,\"action\":\"press\"}", k.key);
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

test "a key press is rebuilt from checked fields only" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const good = "{\"t\":\"key\",\"key\":{\"key\":\"key_a\",\"mods\":\"ctrl,shift\",\"consumed_mods\":\"\",\"text\":\"a\",\"unshifted_codepoint\":97,\"composing\":false,\"action\":\"press\"}}";
    const m = try parse(arena.allocator(), good);
    try testing.expectEqualStrings("{\"key\":\"key_a\",\"mods\":\"ctrl,shift\",\"consumed_mods\":\"\",\"text\":\"a\",\"unshifted_codepoint\":97,\"composing\":false,\"action\":\"press\"}", m.key);
    // An extra field, a missing one, a wrong type, a key name with odd characters, a bad action.
    const bad = [_][]const u8{
        "{\"t\":\"key\",\"key\":{\"key\":\"a\",\"mods\":\"\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":0,\"composing\":false,\"action\":\"press\",\"session_id\":\"x\"}}",
        "{\"t\":\"key\",\"key\":{\"mods\":\"ctrl\"}}",
        "{\"t\":\"key\",\"key\":{\"key\":\"a\",\"mods\":\"\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":\"97\",\"composing\":false,\"action\":\"press\"}}",
        "{\"t\":\"key\",\"key\":{\"key\":\"a\\\"}\",\"mods\":\"\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":0,\"composing\":false,\"action\":\"press\"}}",
        "{\"t\":\"key\",\"key\":{\"key\":\"a\",\"mods\":\"\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":0,\"composing\":false,\"action\":\"explode\"}}",
        "{\"t\":\"key\",\"key\":{\"key\":\"a\",\"mods\":\"\",\"consumed_mods\":\"\",\"text\":\"\",\"unshifted_codepoint\":99999999,\"composing\":false,\"action\":\"press\"}}",
        "{\"t\":\"mouse\",\"payload\":{}}",
    };
    for (bad) |b| try testing.expect(std.meta.isError(parse(arena.allocator(), b)));
}

test "transfer messages are checked" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectEqualStrings("/etc", (try parse(a, "{\"t\":\"ls\",\"path\":\"/etc\"}")).ls);
    try testing.expectEqualStrings("", (try parse(a, "{\"t\":\"ls\",\"path\":\"\"}")).ls);
    try testing.expectEqualStrings("a b/c.txt", (try parse(a, "{\"t\":\"dl\",\"path\":\"a b/c.txt\"}")).dl);
    const u = try parse(a, "{\"t\":\"ul\",\"name\":\"pic.png\",\"size\":1234}");
    try testing.expectEqualStrings("pic.png", u.ul.name);
    try testing.expectEqual(@as(u64, 1234), u.ul.size);
    const bad = [_][]const u8{
        "{\"t\":\"dl\",\"path\":\"\"}", // nothing to download
        "{\"t\":\"dl\",\"path\":\"a\\nb\"}", // a newline in a path
        "{\"t\":\"dl\",\"path\":\"a\\u0000b\"}", // NUL
        "{\"t\":\"ls\",\"path\":5}",
        "{\"t\":\"ul\",\"name\":\"\",\"size\":1}",
        "{\"t\":\"ul\",\"name\":\"a\\u0001\",\"size\":1}",
        "{\"t\":\"ul\",\"name\":\"a\",\"size\":-1}",
        "{\"t\":\"ul\",\"name\":\"a\",\"size\":1099511627777}",
        "{\"t\":\"ul\",\"name\":\"a\",\"size\":\"1\"}",
    };
    for (bad) |b| try testing.expect(std.meta.isError(parse(a, b)));
}
