//! A fake Rex server for tests that need no real Rex, built from Rex's own protocol
//! document (`/llms.txt`, API revision 18). It speaks the control and data protocols on a
//! unix socket and keeps one libghostty-vt terminal per block, so its snapshots are the real
//! format. It is deliberately small: only what the client library uses, and answers that are
//! simplified where noted. A test against it does not prove behaviour against a real Rex.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const ghostty_vt = @import("ghostty-vt");
const ws = @import("ws.zig");

const log = std.log.scoped(.fake_rex);

pub const control_subprotocol = "rex.control.v1";
pub const data_subprotocol = "rex.data.terminal.v1";
pub const bytes_subprotocol = "rex.data.bytes.v1";

const Stream = struct {
    block_id: []u8,
    token: [16]u8,
    nonce: u64,
    bytes: std.ArrayList(u8) = .empty,
    /// Set when a connection is currently serving this stream.
    attached: bool = false,
    dead: bool = false,
    /// When set, the serving connection sends this close frame and the stream is gone.
    end: ?struct { code: u16, reason: []const u8 } = null,
    /// Raw bytes the serving connection writes as they are, outside any frame (for tests of a
    /// server that breaks the protocol). Owned.
    inject: ?[]u8 = null,
};

const Block = struct {
    id: []u8,
    term: ghostty_vt.Terminal,
};

const Session = struct {
    id: []u8,
    label: []u8,
    window_id: []u8,
    block: *Block,
};

/// A unix socket that accepts connections and never says a word: for handshake deadlines.
pub const Silent = struct {
    gpa: Allocator,
    io: Io,
    path: []u8,
    server: Io.net.Server,
    mu: Io.Mutex = .init,
    accepted: std.ArrayList(Io.net.Stream) = .empty,
    task: ?Io.Future(void) = null,
    stopping: bool = false,

    /// Listen at `path` (a fresh one under /tmp if null).
    pub fn start(gpa: Allocator, io: Io, path: ?[]const u8) !*Silent {
        const p = if (path) |x| try gpa.dupe(u8, x) else blk: {
            var rnd: [6]u8 = undefined;
            io.random(&rnd);
            break :blk try gpa.print("/tmp/rweb-silent-{x}.sock", .{rnd});
        };
        errdefer gpa.free(p);
        Io.Dir.deleteFileAbsolute(io, p) catch {};
        const addr = try Io.net.UnixAddress.init(p);
        const s = try gpa.create(Silent);
        errdefer gpa.destroy(s);
        s.* = .{ .gpa = gpa, .io = io, .path = p, .server = try addr.listen(io, .{}) };
        errdefer s.server.deinit(io);
        s.task = try io.concurrent(acceptLoop, .{s});
        return s;
    }

    fn acceptLoop(s: *Silent) void {
        while (true) {
            const st = s.server.accept(s.io) catch return;
            s.mu.lockUncancelable(s.io);
            defer s.mu.unlock(s.io);
            if (s.stopping) {
                st.close(s.io);
                return;
            }
            s.accepted.append(s.gpa, st) catch st.close(s.io);
        }
    }

    pub fn acceptedCount(s: *Silent) usize {
        s.mu.lockUncancelable(s.io);
        defer s.mu.unlock(s.io);
        return s.accepted.items.len;
    }

    pub fn deinit(s: *Silent) void {
        s.mu.lockUncancelable(s.io);
        s.stopping = true;
        s.mu.unlock(s.io);
        if (Io.net.UnixAddress.init(s.path)) |addr| {
            if (addr.connect(s.io)) |c| c.close(s.io) else |_| {}
        } else |_| {}
        if (s.task) |*t| t.cancel(s.io);
        for (s.accepted.items) |st| st.close(s.io);
        s.accepted.deinit(s.gpa);
        s.server.deinit(s.io);
        Io.Dir.deleteFileAbsolute(s.io, s.path) catch {};
        s.gpa.free(s.path);
        s.gpa.destroy(s);
    }
};

/// `file`: for a download, the bytes to send.
const Ticket = struct { bytes: [16]u8, block_id: []u8, file: ?[]u8 = null };

pub const Fake = struct {
    gpa: Allocator,
    io: Io,
    path: []u8,
    /// Newest and oldest API revision this server speaks.
    api_max: u32 = 18,
    api_min: u32 = 0,

    mu: Io.Mutex = .init,
    server: ?Io.net.Server = null,
    group: Io.Group = .init,
    accept_task: ?Io.Future(void) = null,
    sessions: std.ArrayList(*Session) = .empty,
    streams: std.ArrayList(*Stream) = .empty,
    tickets: std.ArrayList(Ticket) = .empty,
    /// reconnect token (hex) -> client id
    clients: std.StringHashMapUnmanaged([]u8) = .empty,
    next_id: u32 = 1,
    /// Count of control connections accepted, for tests.
    control_connections: u32 = 0,
    /// Live control connections, so a test can cut them.
    control_conns: std.ArrayList(*ws.Conn) = .empty,
    /// Every accepted stream (control and data), shut when the fake stops listening.
    live_streams: std.ArrayList(Io.net.Stream) = .empty,
    stopping: bool = false,
    event_seq: u64 = 0,
    /// Wait this long before sending a new data stream's first bytes (a slow snapshot), for tests.
    hold_data_ms: u32 = 0,
    /// If set, `data.connect` answers with this JSON as its payload, for tests of bad replies.
    data_connect_payload: ?[]const u8 = null,
    /// The only folder `download_begin` and `list_dir` serve from (its real path, owned): a
    /// fresh private folder per fake, removed with it. Anything outside it, or anything at all
    /// when null, is `not_found`. An empty `list_dir` path (the terminal's folder) lists it.
    files_root: ?[:0]u8 = null,
    /// The fake made `files_root` itself, so removes it; a folder a test hands over is never removed.
    owns_files_root: bool = false,
    /// Calls to this method are never answered, for tests of timeouts and cancellation.
    silent_method: ?[]const u8 = null,
    /// The resume window a data WELCOME announces.
    resume_window_ms: u32 = 60_000,
    /// Drop a resumed data connection right after its WELCOME, without a byte of the stream.
    drop_resumes: bool = false,
    /// Control connections stop reading (after their WELCOME) while this is set, so what a
    /// client writes piles up in the socket: for tests of write deadlines. A connection already
    /// waiting for a message reads that one first. Change it under `mu` once serving.
    stall_control_reads: bool = false,
    /// Data connections that resumed a stream (WELCOME sent), for tests.
    data_resumes: u32 = 0,
    /// Close statuses data clients sent, newest last, for tests (at most 64 kept).
    data_close_codes: std.ArrayList(u16) = .empty,

    /// Listen on a fresh socket under /tmp and start serving.
    pub fn start(gpa: Allocator, io: Io) !*Fake {
        var rnd: [6]u8 = undefined;
        io.random(&rnd);
        const path = try gpa.print("/tmp/rweb-fake-{x}.sock", .{rnd});
        errdefer gpa.free(path);
        const f = try gpa.create(Fake);
        errdefer gpa.destroy(f);
        f.* = .{ .gpa = gpa, .io = io, .path = path };
        try f.makeFilesRoot(rnd);
        errdefer f.removeFilesRoot();
        try f.listen();
        return f;
    }

    fn makeFilesRoot(f: *Fake, rnd: [6]u8) !void {
        var buf: [64]u8 = undefined;
        const dir = try std.fmt.bufPrint(&buf, "/tmp/rweb-fake-files-{x}", .{rnd});
        _ = try Io.Dir.cwd().createDirPathStatus(f.io, dir, @fromBackingInt(@intCast(0o700)));
        errdefer Io.Dir.cwd().deleteTree(f.io, dir) catch {};
        // The real path (on macOS /tmp is a link to /private/tmp), so requests compare with it.
        f.files_root = try Io.Dir.cwd().realPathFileAlloc(f.io, dir, f.gpa);
        f.owns_files_root = true;
    }

    fn removeFilesRoot(f: *Fake) void {
        const root = f.files_root orelse return;
        if (f.owns_files_root) Io.Dir.cwd().deleteTree(f.io, root) catch {};
        f.gpa.free(root);
        f.files_root = null;
        f.owns_files_root = false;
    }

    /// Serve files from `root` instead (a test's own folder; null serves none). The fake's own folder
    /// is removed; `root` is the test's and is never removed by the fake. `root` must exist.
    pub fn setFilesRoot(f: *Fake, root: ?[]const u8) !void {
        const real = if (root) |r| try Io.Dir.cwd().realPathFileAlloc(f.io, r, f.gpa) else null;
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        f.removeFilesRoot();
        f.files_root = real;
    }

    /// The close statuses data clients have sent so far.
    pub fn dataCloseCodes(f: *Fake, out: []u16) []u16 {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        const n = @min(out.len, f.data_close_codes.items.len);
        @memcpy(out[0..n], f.data_close_codes.items[0..n]);
        return out[0..n];
    }

    fn controlStalled(f: *Fake) bool {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        return f.stall_control_reads and !f.stopping;
    }

    pub fn dataResumes(f: *Fake) u32 {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        return f.data_resumes;
    }

    /// Write `bytes` raw on every connection serving `block_id`'s streams, outside any frame.
    pub fn injectRaw(f: *Fake, block_id: []const u8, bytes: []const u8) !void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        for (f.streams.items) |st| if (std.mem.eql(u8, st.block_id, block_id)) {
            if (st.inject) |old| f.gpa.free(old);
            st.inject = try f.gpa.dupe(u8, bytes);
        };
    }

    fn listen(f: *Fake) !void {
        Io.Dir.deleteFileAbsolute(f.io, f.path) catch {}; // a stale socket file from before a restart
        const addr = try Io.net.UnixAddress.init(f.path);
        f.server = try addr.listen(f.io, .{});
        f.mu.lockUncancelable(f.io);
        f.stopping = false;
        f.mu.unlock(f.io);
        f.accept_task = try f.io.concurrent(acceptLoop, .{f});
    }

    fn stopListening(f: *Fake) void {
        f.mu.lockUncancelable(f.io);
        f.stopping = true;
        for (f.live_streams.items) |st| st.shutdown(f.io, .both) catch {};
        f.mu.unlock(f.io);
        // Wake a blocked accept by connecting to ourselves.
        if (Io.net.UnixAddress.init(f.path)) |addr| {
            if (addr.connect(f.io)) |c| c.close(f.io) else |_| {}
        } else |_| {}
        if (f.accept_task) |*t| t.cancel(f.io);
        f.accept_task = null;
        f.group.cancel(f.io);
        f.group = .init;
        if (f.server) |*s| s.deinit(f.io);
        f.server = null;
    }

    pub fn deinit(f: *Fake) void {
        f.stopListening();
        Io.Dir.deleteFileAbsolute(f.io, f.path) catch {};
        f.clearConnectionState();
        for (f.sessions.items) |s| f.freeSession(s);
        f.sessions.deinit(f.gpa);
        f.tickets.deinit(f.gpa);
        f.control_conns.deinit(f.gpa);
        f.live_streams.deinit(f.gpa);
        f.streams.deinit(f.gpa);
        f.clients.deinit(f.gpa);
        f.data_close_codes.deinit(f.gpa);
        f.removeFilesRoot();
        f.gpa.free(f.path);
        f.gpa.destroy(f);
    }

    fn freeSession(f: *Fake, s: *Session) void {
        s.block.term.deinit(f.gpa);
        f.gpa.free(s.block.id);
        f.gpa.destroy(s.block);
        f.gpa.free(s.id);
        f.gpa.free(s.label);
        f.gpa.free(s.window_id);
        f.gpa.destroy(s);
    }

    fn clearConnectionState(f: *Fake) void {
        for (f.streams.items) |st| {
            f.gpa.free(st.block_id);
            st.bytes.deinit(f.gpa);
            if (st.inject) |x| f.gpa.free(x);
            f.gpa.destroy(st);
        }
        f.streams.clearRetainingCapacity();
        for (f.tickets.items) |t| {
            f.gpa.free(t.block_id);
            if (t.file) |x| f.gpa.free(x);
        }
        f.tickets.clearRetainingCapacity();
        var it = f.clients.iterator();
        while (it.next()) |e| {
            f.gpa.free(e.key_ptr.*);
            f.gpa.free(e.value_ptr.*);
        }
        f.clients.clearRetainingCapacity();
    }

    /// Simulate a Rex server restart as Phase 0 saw it (finding 11): every connection drops
    /// without a close frame, tokens and tickets stop working, and sessions and blocks keep
    /// their IDs but come back with new programs and empty screens.
    pub fn restart(f: *Fake) !void {
        f.stopListening();
        f.clearConnectionState();
        for (f.sessions.items) |s| {
            const cols = s.block.term.cols;
            const rows = s.block.term.rows;
            s.block.term.deinit(f.gpa);
            s.block.term = try newTerminal(f.gpa, f.io, cols, rows);
        }
        try f.listen();
    }

    /// Send an event with the given `payload` JSON to every control connection. Its `seq`
    /// counts up across calls (the real server counts per connection).
    pub fn broadcastEvent(f: *Fake, payload_json: []const u8) void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        f.event_seq += 1;
        const text = f.gpa.print("{{\"type\":\"event\",\"seq\":{d},\"payload\":{s}}}", .{ f.event_seq, payload_json }) catch return;
        defer f.gpa.free(text);
        for (f.control_conns.items) |cn| cn.writeFrame(.text, text) catch {};
    }

    /// Drop every control connection without a close frame; tokens stay valid.
    pub fn dropControlConnections(f: *Fake) void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        for (f.control_conns.items) |cn| cn.stream.shutdown(f.io, .both) catch {};
    }

    /// Drop every data connection without a close frame. Streams stay resumable.
    pub fn dropDataConnections(f: *Fake) void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        for (f.streams.items) |st| st.dead = true;
    }

    /// End a block's streams with a WebSocket close frame (4000 `block closed`, 1013
    /// `data reconnect required`, 1001 `data provider canceled`, ...). They cannot be resumed.
    pub fn endStreams(f: *Fake, block_id: []const u8, code: u16, reason: []const u8) void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        for (f.streams.items) |st| if (std.mem.eql(u8, st.block_id, block_id)) {
            st.end = .{ .code = code, .reason = reason };
        };
    }

    /// Program output for a block: applied to its terminal and appended to its streams.
    pub fn feed(f: *Fake, block_id: []const u8, bytes: []const u8) !void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        try f.feedLocked(block_id, bytes);
    }

    fn feedLocked(f: *Fake, block_id: []const u8, bytes: []const u8) !void {
        for (f.sessions.items) |s| {
            if (!std.mem.eql(u8, s.block.id, block_id)) continue;
            var vt = s.block.term.vtStream();
            vt.nextSlice(bytes);
        }
        for (f.streams.items) |st| {
            if (std.mem.eql(u8, st.block_id, block_id)) try st.bytes.appendSlice(f.gpa, bytes);
        }
    }

    /// Create a session with one window and one terminal; returns borrowed IDs.
    pub fn createSession(f: *Fake, label: ?[]const u8) !struct { session_id: []const u8, block_id: []const u8 } {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        const s = try f.createSessionLocked(label);
        return .{ .session_id = s.id, .block_id = s.block.id };
    }

    fn newId(f: *Fake, kind: []const u8) ![]u8 {
        const n = f.next_id;
        f.next_id += 1;
        return f.gpa.print("{s}:00000000-0000-0000-0000-{x:0>12}", .{ kind, n });
    }

    fn createSessionLocked(f: *Fake, label: ?[]const u8) !*Session {
        const gpa = f.gpa;
        const s = try gpa.create(Session);
        errdefer gpa.destroy(s);
        const blk = try gpa.create(Block);
        errdefer gpa.destroy(blk);
        s.id = try f.newId("session");
        errdefer gpa.free(s.id);
        s.window_id = try f.newId("window");
        errdefer gpa.free(s.window_id);
        blk.id = try f.newId("block");
        errdefer gpa.free(blk.id);
        s.label = try gpa.dupe(u8, label orelse "fake-session");
        errdefer gpa.free(s.label);
        blk.term = try newTerminal(gpa, f.io, 80, 24);
        errdefer blk.term.deinit(gpa);
        s.block = blk;
        try f.sessions.append(gpa, s);
        return s;
    }

    fn newTerminal(gpa: Allocator, io: Io, cols: u16, rows: u16) !ghostty_vt.Terminal {
        return ghostty_vt.Terminal.init(io, gpa, .{ .cols = cols, .rows = rows });
    }

    /// Resize a block's terminal and tell its streams, as Rex does with a `resize` message.
    fn resizeLocked(f: *Fake, block_id: []const u8, cols: u16, rows: u16) !void {
        for (f.sessions.items) |s| {
            if (!std.mem.eql(u8, s.block.id, block_id)) continue;
            try s.block.term.resize(f.gpa, .{ .cols = cols, .rows = rows });
        }
        for (f.streams.items) |st| {
            if (!std.mem.eql(u8, st.block_id, block_id)) continue;
            var buf: [160]u8 = undefined;
            const msg = try std.fmt.bufPrint(&buf, "\x1b_rex1;{d};{{\"type\":\"resize\",\"cols\":{d},\"rows\":{d},\"cell_width_px\":0,\"cell_height_px\":0,\"owner\":\"client:fake\"}}\x1b\\", .{ st.nonce, cols, rows });
            try st.bytes.appendSlice(f.gpa, msg);
        }
    }

    fn findSession(f: *Fake, id: []const u8) ?*Session {
        for (f.sessions.items) |s| if (std.mem.eql(u8, s.id, id)) return s;
        return null;
    }

    fn findBlockSession(f: *Fake, block_id: []const u8) ?*Session {
        for (f.sessions.items) |s| if (std.mem.eql(u8, s.block.id, block_id)) return s;
        return null;
    }

    // ---- connections ----

    fn acceptLoop(f: *Fake) void {
        while (true) {
            f.mu.lockUncancelable(f.io);
            const stop = f.stopping;
            f.mu.unlock(f.io);
            if (stop) return;
            const stream = f.server.?.accept(f.io) catch |e| switch (e) {
                error.Canceled => return,
                else => {
                    log.err("accept: {t}", .{e});
                    return;
                },
            };
            f.mu.lockUncancelable(f.io);
            f.live_streams.append(f.gpa, stream) catch {};
            const stop2 = f.stopping;
            f.mu.unlock(f.io);
            if (stop2) {
                f.unregisterStream(stream);
                stream.close(f.io);
                return;
            }
            f.group.concurrent(f.io, handleConn, .{ f, stream }) catch {
                f.unregisterStream(stream);
                stream.close(f.io);
            };
        }
    }

    /// Take a stream off the list `stopListening` shuts. Always before it is closed: shutting a
    /// closed descriptor is a bug (and a panic in debug builds).
    fn unregisterStream(f: *Fake, stream: Io.net.Stream) void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);
        for (f.live_streams.items, 0..) |x, i| if (x.socket.handle == stream.socket.handle) {
            _ = f.live_streams.swapRemove(i);
            break;
        };
    }

    fn handleConn(f: *Fake, stream: Io.net.Stream) void {
        const c = ws.Conn.accept(f.gpa, f.io, stream, &.{ control_subprotocol, data_subprotocol, bytes_subprotocol }) catch {
            f.unregisterStream(stream);
            stream.close(f.io);
            return;
        };
        if (std.mem.eql(u8, c.subprotocol, control_subprotocol)) {
            f.mu.lockUncancelable(f.io);
            f.control_conns.append(f.gpa, c) catch {};
            f.mu.unlock(f.io);
            f.control(c) catch |e| log.debug("control ended: {t}", .{e});
            f.mu.lockUncancelable(f.io);
            for (f.control_conns.items, 0..) |x, k| if (x == c) {
                _ = f.control_conns.swapRemove(k);
                break;
            };
            f.mu.unlock(f.io);
        } else if (std.mem.eql(u8, c.subprotocol, bytes_subprotocol)) {
            f.bytesConn(c) catch |e| log.debug("bytes ended: {t}", .{e});
        } else {
            f.dataConn(c) catch |e| log.debug("data ended: {t}", .{e});
        }
        f.unregisterStream(stream);
        c.deinit(f.gpa);
    }

    fn closeWith(c: *ws.Conn, code: u16, reason: []const u8) void {
        var buf: [125]u8 = undefined;
        std.mem.writeInt(u16, buf[0..2], code, .big);
        const n = @min(reason.len, buf.len - 2);
        @memcpy(buf[2 .. 2 + n], reason[0..n]);
        c.writeFrame(.close, buf[0 .. 2 + n]) catch {};
    }

    fn sendJson(f: *Fake, c: *ws.Conn, value: anytype) !void {
        const text = try std.json.Stringify.valueAlloc(f.gpa, value, .{ .emit_null_optional_fields = false });
        defer f.gpa.free(text);
        try c.writeFrame(.text, text);
    }

    fn respond(f: *Fake, c: *ws.Conn, id: []const u8, payload: anytype) !void {
        try f.sendJson(c, .{ .type = "response", .id = id, .seq = 0, .payload = payload });
    }

    fn respondError(f: *Fake, c: *ws.Conn, id: []const u8, code: []const u8, status: u16, message: []const u8) !void {
        try f.sendJson(c, .{
            .type = "response",
            .id = id,
            .seq = 0,
            .@"error" = .{ .code = code, .message = message, .status = status },
        });
    }

    fn control(f: *Fake, c: *ws.Conn) !void {
        const gpa = f.gpa;
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        // Copies of the ids: a session this or another connection destroys must not leave this list
        // pointing at its freed id.
        var attached: std.ArrayList([]const u8) = .empty;
        defer {
            for (attached.items) |a| gpa.free(a);
            attached.deinit(gpa);
        }

        // hello
        const hello_msg = try c.readMessage(gpa);
        defer gpa.free(hello_msg.data);
        if (hello_msg.opcode != .text) return closeWith(c, 1003, "protocol error");
        const hello = std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), hello_msg.data, .{}) catch
            return closeWith(c, 1002, "protocol error");
        if (hello != .object) return closeWith(c, 1002, "protocol error");
        const t = hello.object.get("type") orelse return closeWith(c, 1002, "protocol error");
        if (t != .string or !std.mem.eql(u8, t.string, "hello")) return closeWith(c, 1002, "protocol error");
        const cmax: u32 = intField(hello.object, "api_revision") orelse 0;
        const cmin: u32 = intField(hello.object, "api_min_revision") orelse 0;
        const rev = @min(cmax, f.api_max);
        if (rev < @max(cmin, f.api_min)) {
            return closeWith(c, 1008, if (cmin > f.api_max) "no common API revision: update the server" else "no common API revision: update the client");
        }

        var tok_raw: [16]u8 = undefined;
        f.io.random(&tok_raw);
        const token = try gpa.print("{x}", .{tok_raw});
        var client_id: []u8 = undefined;
        var resumed = false;
        {
            f.mu.lockUncancelable(f.io);
            defer f.mu.unlock(f.io);
            f.control_connections += 1;
            const old = if (hello.object.get("reconnect_token")) |v| (if (v == .string) v.string else null) else null;
            if (old) |o| if (f.clients.fetchRemove(o)) |kv| {
                gpa.free(kv.key);
                client_id = kv.value;
                resumed = true;
            };
            if (!resumed) {
                var idr: [6]u8 = undefined;
                f.io.random(&idr);
                client_id = try gpa.print("client:00000000-0000-0000-0000-{x}", .{idr});
            }
            try f.clients.put(gpa, token, client_id);
        }
        try f.sendJson(c, .{
            .type = "welcome",
            .protocol = control_subprotocol,
            .limits = .{ .max_message_bytes = 1048576 },
            .client = .{ .id = client_id, .reconnect_token = token, .resumed = resumed },
            .api_revision = rev,
            .api_server_revision = f.api_max,
            .api_min_revision = f.api_min,
        });

        while (true) {
            while (f.controlStalled()) f.io.sleep(.fromMilliseconds(10), .awake) catch return;
            const m = try c.readMessage(gpa);
            defer gpa.free(m.data);
            switch (m.opcode) {
                .close => return,
                .text => {},
                else => return closeWith(c, 1003, "protocol error"),
            }
            _ = arena_state.reset(.retain_capacity);
            const req = std.json.parseFromSliceLeaky(std.json.Value, arena_state.allocator(), m.data, .{}) catch
                return closeWith(c, 1002, "protocol error");
            if (req != .object) return closeWith(c, 1002, "protocol error");
            const ty = strField(req.object, "type") orelse return closeWith(c, 1002, "protocol error");
            if (!std.mem.eql(u8, ty, "request")) continue;
            const id = strField(req.object, "id") orelse return closeWith(c, 1002, "protocol error");
            const method = strField(req.object, "method") orelse return closeWith(c, 1002, "protocol error");
            // As Rex: a payload, and its `args`, must be JSON objects when present (Rex decodes them into
            // structs and answers `bad_request` otherwise; an empty list is not an empty object).
            const pv = req.object.get("payload");
            if (pv != null and pv.? != .object) {
                try f.respondError(c, id, "bad_request", 400, "payload must be an object");
                continue;
            }
            const payload: std.json.ObjectMap = if (pv) |x| x.object else no_object;
            if (payload.get("args")) |a| if (a != .object) {
                try f.respondError(c, id, "bad_request", 400, "args must be an object");
                continue;
            };
            try f.call(c, id, method, payload, &attached, arena_state.allocator());
        }
    }

    fn call(
        f: *Fake,
        c: *ws.Conn,
        id: []const u8,
        method: []const u8,
        p: std.json.ObjectMap,
        attached: *std.ArrayList([]const u8),
        arena: Allocator,
    ) !void {
        f.mu.lockUncancelable(f.io);
        defer f.mu.unlock(f.io);

        // Never answered: for tests of a call still waiting when the client closes.
        if (std.mem.eql(u8, method, "rweb.test.no_answer")) return;
        if (f.silent_method) |sm| if (std.mem.eql(u8, method, sm)) return;
        if (std.mem.eql(u8, method, "data.connect")) if (f.data_connect_payload) |raw| {
            const text = try arena.print("{{\"type\":\"response\",\"id\":{f},\"seq\":0,\"payload\":{s}}}", .{ std.json.fmt(id, .{}), raw });
            return c.writeFrame(.text, text);
        };
        if (std.mem.eql(u8, method, "session.list")) {
            const Item = struct { session_id: []const u8, label: []const u8 };
            const items = try arena.alloc(Item, f.sessions.items.len);
            for (f.sessions.items, items) |s, *it| it.* = .{ .session_id = s.id, .label = s.label };
            return f.respond(c, id, .{ .sessions = items });
        } else if (std.mem.eql(u8, method, "session.create")) {
            const s = try f.createSessionLocked(strField(p, "label"));
            // Simplified: one window with one block, whatever layout was asked for.
            return f.respond(c, id, .{
                .session_id = s.id,
                .initial_windows = .{.{ .window_id = s.window_id, .block_ids = .{s.block.id}, .revision = 1 }},
            });
        } else if (std.mem.eql(u8, method, "session.attach")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const s = f.findSession(sid) orelse return f.respondError(c, id, "session_not_found", 404, "session not found");
            if (!isAttached(attached.items, s.id)) {
                const copy = try f.gpa.dupe(u8, s.id);
                attached.append(f.gpa, copy) catch |e| {
                    f.gpa.free(copy);
                    return e;
                };
            }
            // Simplified view: Rex's real one carries much more.
            return f.respond(c, id, .{
                .session_id = s.id,
                .label = s.label,
                .revision = 1,
                .windows = .{.{ .window_id = s.window_id, .block_ids = .{s.block.id} }},
            });
        } else if (std.mem.eql(u8, method, "data.connect")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            if (!isAttached(attached.items, sid)) return f.respondError(c, id, "conflict", 409, "not attached to the session");
            const s = f.findSession(sid) orelse return f.respondError(c, id, "session_not_found", 404, "session not found");
            if (!std.mem.eql(u8, s.block.id, bid)) return f.respondError(c, id, "not_found", 404, "block not found");
            var raw: [16]u8 = undefined;
            f.io.random(&raw);
            try f.tickets.append(f.gpa, .{ .bytes = raw, .block_id = try f.gpa.dupe(u8, bid) });
            var enc: [22]u8 = undefined;
            _ = std.base64.url_safe_no_pad.Encoder.encode(&enc, &raw);
            return f.respond(c, id, .{ .ticket = enc[0..], .expires_in_ms = 60000 });
        } else if (std.mem.eql(u8, method, "session.destroy")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            if (!isAttached(attached.items, sid)) return f.respondError(c, id, "conflict", 409, "not attached to the session");
            for (f.sessions.items, 0..) |s, i| if (std.mem.eql(u8, s.id, sid)) {
                for (f.streams.items) |st| if (std.mem.eql(u8, st.block_id, s.block.id)) {
                    st.dead = true;
                };
                _ = f.sessions.orderedRemove(i);
                f.freeSession(s);
                break;
            };
            for (attached.items, 0..) |a, i| if (std.mem.eql(u8, a, sid)) {
                f.gpa.free(attached.swapRemove(i));
                break;
            };
            return f.respond(c, id, .{});
        } else if (std.mem.eql(u8, method, "session.attach_all")) {
            const Item = struct { session_id: []const u8, label: []const u8 };
            const items = try arena.alloc(Item, f.sessions.items.len);
            for (f.sessions.items, items) |s, *it| it.* = .{ .session_id = s.id, .label = s.label };
            return f.respond(c, id, .{ .sessions = items });
        } else if (std.mem.eql(u8, method, "session.list_blocks")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const s = f.findSession(sid) orelse return f.respondError(c, id, "session_not_found", 404, "session not found");
            return f.respond(c, id, .{ .blocks = .{.{
                .block_id = s.block.id,
                .label = "fake-block",
                .creator_name = "com.superlogical.terminal",
                .flavor = "com.superlogical.terminal.shell",
                .placement = "placed",
                .window_id = s.window_id,
            }} });
        } else if (std.mem.eql(u8, method, "session.set_label")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const s = f.findSession(sid) orelse return f.respondError(c, id, "session_not_found", 404, "session not found");
            const new = try f.gpa.dupe(u8, strField(p, "label") orelse "fake-session");
            f.gpa.free(s.label);
            s.label = new;
            return f.respond(c, id, .{ .revision = 2 });
        } else if (std.mem.eql(u8, method, "session.own_block")) {
            const bid = if (p.get("block_ids")) |b| (if (b == .array and b.array.items.len == 1 and b.array.items[0] == .string) b.array.items[0].string else null) else null;
            return f.respond(c, id, .{ .blocks = .{.{ .block_id = bid orelse "", .owner = "client:fake" }} });
        } else if (std.mem.eql(u8, method, "com.superlogical.terminal.resize")) {
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            const args = if (p.get("args")) |a| (if (a == .object) a.object else no_object) else no_object;
            const cols = intField(args, "columns") orelse return f.respondError(c, id, "bad_request", 400, "columns required");
            const rows = intField(args, "rows") orelse return f.respondError(c, id, "bad_request", 400, "rows required");
            try f.resizeLocked(bid, @intCast(cols), @intCast(rows));
            return f.respond(c, id, .{});
        } else if (std.mem.eql(u8, method, "client.key")) {
            // The fake has no keyboard encoder: the key's text is echoed.
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            const key = if (p.get("key")) |k| (if (k == .object) k.object else no_object) else no_object;
            const text = strField(key, "text") orelse "";
            if (std.mem.eql(u8, strField(key, "key") orelse "", "enter")) try f.feedLocked(bid, "\r\n") else try f.feedLocked(bid, text);
            return f.respond(c, id, .{ .handled = false });
        } else if (std.mem.eql(u8, method, "block.event")) {
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            const ev = if (p.get("event")) |e| (if (e == .object) e.object else no_object) else no_object;
            if (std.mem.eql(u8, strField(ev, "type") orelse "", "paste")) {
                const pl = if (ev.get("payload")) |x| (if (x == .object) x.object else no_object) else no_object;
                try f.feedLocked(bid, strField(pl, "text") orelse "");
            }
            return f.respond(c, id, .{});
        } else if (std.mem.eql(u8, method, "com.superlogical.terminal.download_begin")) {
            // Real files, read whole: the fake is a test double, not a file server.
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            if (!isAttached(attached.items, sid)) return f.respondError(c, id, "conflict", 409, "not attached to the session");
            const args = if (p.get("args")) |a| (if (a == .object) a.object else no_object) else no_object;
            const path = strField(args, "path") orelse return f.respondError(c, id, "bad_request", 400, "args.path required");
            const real = f.servedPath(arena, path) orelse return f.respondError(c, id, "not_found", 404, "no such file");
            const bytes = Io.Dir.cwd().readFileAlloc(f.io, real, f.gpa, .limited(64 * 1024 * 1024)) catch return f.respondError(c, id, "not_found", 404, "no such file");
            var raw: [16]u8 = undefined;
            f.io.random(&raw);
            try f.tickets.append(f.gpa, .{ .bytes = raw, .block_id = try f.gpa.dupe(u8, bid), .file = bytes });
            var enc: [22]u8 = undefined;
            _ = std.base64.url_safe_no_pad.Encoder.encode(&enc, &raw);
            const base = if (std.mem.lastIndexOfScalar(u8, path, '/')) |i| path[i + 1 ..] else path;
            return f.respond(c, id, .{ .ticket = enc[0..], .expires_in_ms = 60000, .path = path, .name = base, .size = bytes.len });
        } else if (std.mem.eql(u8, method, "com.superlogical.terminal.list_dir")) {
            const args = if (p.get("args")) |a| (if (a == .object) a.object else no_object) else no_object;
            const path = strField(args, "path") orelse "";
            const missing = .{ .path = path, .home = "", .status = "missing", .entries = &[_][]const u8{}, .truncated = false }; // `[]`: a `[]u8` would be written as a string
            const real = (if (path.len == 0) f.files_root else f.servedPath(arena, path)) orelse return f.respond(c, id, missing);
            var dir = Io.Dir.cwd().openDir(f.io, real, .{ .iterate = true }) catch return f.respond(c, id, missing);
            defer dir.close(f.io);
            const Entry = struct { name: []const u8, file: bool };
            var list: std.ArrayList(Entry) = .empty;
            var it = dir.iterate();
            while (try it.next(f.io)) |e| try list.append(arena, .{ .name = try arena.dupe(u8, e.name), .file = e.kind != .directory });
            return f.respond(c, id, .{ .path = path, .home = "", .status = "ok", .entries = list.items, .truncated = false });
        } else if (std.mem.eql(u8, method, "com.superlogical.terminal.write")) {
            const sid = strField(p, "session_id") orelse return f.respondError(c, id, "bad_request", 400, "session_id required");
            const bid = strField(p, "block_id") orelse return f.respondError(c, id, "bad_request", 400, "block_id required");
            if (!isAttached(attached.items, sid)) return f.respondError(c, id, "conflict", 409, "not attached to the session");
            const args = if (p.get("args")) |a| (if (a == .object) a.object else no_object) else no_object;
            const data = strField(args, "data") orelse return f.respondError(c, id, "bad_request", 400, "args.data required");
            // The fake has no shell: typed text is echoed, with line ends as a terminal makes them.
            var out: std.ArrayList(u8) = .empty;
            for (data) |ch| if (ch == '\n' or ch == '\r') try out.appendSlice(arena, "\r\n") else try out.append(arena, ch);
            try f.feedLocked(bid, out.items);
            return f.respond(c, id, .{ .bytes_written = data.len });
        }
        return f.respondError(c, id, "method_not_found", 404, "method not found");
    }

    /// The real path of `path` if it is inside `files_root` (or is it), else null. Caller holds `mu`.
    fn servedPath(f: *Fake, arena: Allocator, path: []const u8) ?[]const u8 {
        const root = f.files_root orelse return null;
        if (path.len == 0) return null;
        const real = Io.Dir.cwd().realPathFileAlloc(f.io, path, arena) catch return null;
        if (!insideRoot(root, real)) return null;
        return real;
    }

    fn isAttached(list: []const []const u8, sid: []const u8) bool {
        for (list) |a| if (std.mem.eql(u8, a, sid)) return true;
        return false;
    }

    /// A file download: HELLO with a file ticket, WELCOME, the bytes in 64 KiB messages, close 1000.
    fn bytesConn(f: *Fake, c: *ws.Conn) !void {
        const gpa = f.gpa;
        const hs = try c.readMessage(gpa);
        defer gpa.free(hs.data);
        if (hs.opcode != .binary or hs.data.len < 17 or hs.data[0] != 0x01) return reject(c, 0x05);
        var file: ?[]u8 = null;
        {
            f.mu.lockUncancelable(f.io);
            defer f.mu.unlock(f.io);
            var found: ?usize = null;
            for (f.tickets.items, 0..) |t, i| if (t.file != null and std.mem.eql(u8, &t.bytes, hs.data[1..17])) {
                found = i;
            };
            const i = found orelse return reject(c, 0x01);
            const t = f.tickets.swapRemove(i);
            gpa.free(t.block_id);
            file = t.file;
        }
        defer if (file) |x| gpa.free(x);
        var welcome: [32]u8 = @splat(0);
        welcome[0] = 0x81;
        std.mem.writeInt(u64, welcome[24..32], 1, .little);
        try c.writeFrame(.binary, &welcome);
        var off: usize = 0;
        const bytes = file.?;
        while (off < bytes.len) {
            const n = @min(65536, bytes.len - off);
            try c.writeFrame(.binary, bytes[off .. off + n]);
            off += n;
        }
        closeWith(c, 1000, "");
    }

    fn dataConn(f: *Fake, c: *ws.Conn) !void {
        const gpa = f.gpa;
        const hs = try c.readMessage(gpa);
        defer gpa.free(hs.data);
        if (hs.opcode != .binary or hs.data.len < 1) return reject(c, 0x05);

        var stream: *Stream = undefined;
        var sent: usize = 0;
        var resumed = false;
        {
            f.mu.lockUncancelable(f.io);
            defer f.mu.unlock(f.io);
            if (hs.data[0] == 0x01 and hs.data.len >= 17) {
                // HELLO: one use of a ticket, even when refused.
                var found: ?usize = null;
                for (f.tickets.items, 0..) |t, i| if (std.mem.eql(u8, &t.bytes, hs.data[1..17])) {
                    found = i;
                };
                const i = found orelse return reject(c, 0x01);
                const t = f.tickets.swapRemove(i);
                errdefer gpa.free(t.block_id);
                const s = f.findBlockSession(t.block_id) orelse return reject(c, 0x01);
                stream = try f.newStream(s, t.block_id);
            } else if (hs.data[0] == 0x02 and hs.data.len >= 25) {
                resumed = true;
                var found: ?*Stream = null;
                for (f.streams.items) |st| if (!st.dead or true) {
                    if (std.mem.eql(u8, &st.token, hs.data[1..17])) found = st;
                };
                stream = found orelse return reject(c, 0x01);
                if (stream.end != null) return reject(c, 0x03);
                const count = std.mem.readInt(u64, hs.data[17..25], .little);
                if (count > stream.bytes.items.len) return reject(c, 0x05);
                sent = @intCast(count);
                stream.dead = false;
            } else return reject(c, 0x05);
            f.io.random(&stream.token);
            stream.attached = true;
            var welcome: [32]u8 = @splat(0);
            welcome[0] = 0x81;
            @memcpy(welcome[1..17], &stream.token);
            std.mem.writeInt(u32, welcome[20..24], f.resume_window_ms, .little);
            std.mem.writeInt(u64, welcome[24..32], stream.nonce, .little);
            try c.writeFrame(.binary, &welcome);
            if (resumed) f.data_resumes += 1;
            if (resumed and f.drop_resumes) return; // dropped without a close frame
        }

        // What the client sends from here on: only a close (or pongs). A close ends the stream.
        var client_closed: std.atomic.Value(bool) = .init(false);
        var listener = try f.io.concurrent(dataClientReader, .{ f, c, &client_closed });
        defer {
            c.stream.shutdown(f.io, .both) catch {}; // the connection ends here: wake the listener
            listener.cancel(f.io);
        }

        // A slow snapshot, if a test asked for one.
        f.mu.lockUncancelable(f.io);
        const hold = f.hold_data_ms;
        f.mu.unlock(f.io);
        if (hold > 0) try f.io.sleep(.fromMilliseconds(hold), .awake);

        // Serve the stream until the connection fails or is dropped.
        var chunk: [65536]u8 = undefined;
        while (true) {
            var n: usize = 0;
            var dead = false;
            var end: ?@TypeOf(stream.end) = null;
            var inject: ?[]u8 = null;
            defer if (inject) |x| f.gpa.free(x);
            {
                f.mu.lockUncancelable(f.io);
                defer f.mu.unlock(f.io);
                if (client_closed.load(.acquire)) stream.dead = true; // ended by the client: gone
                dead = stream.dead;
                if (stream.end != null) end = stream.end;
                inject = stream.inject;
                stream.inject = null;
                if (!dead and stream.bytes.items.len > sent) {
                    n = @min(chunk.len, stream.bytes.items.len - sent);
                    @memcpy(chunk[0..n], stream.bytes.items[sent .. sent + n]);
                }
            }
            if (end) |e| if (e) |x| {
                closeWith(c, x.code, x.reason);
                f.mu.lockUncancelable(f.io);
                defer f.mu.unlock(f.io);
                stream.dead = true;
                return;
            };
            if (dead) return; // dropped without a close frame
            if (inject) |x| {
                c.write_mutex.lockUncancelable(f.io);
                defer c.write_mutex.unlock(f.io);
                c.w.writeAll(x) catch return;
                c.w.flush() catch return;
            }
            if (n == 0) {
                try f.io.sleep(.fromMilliseconds(2), .awake);
                continue;
            }
            try c.writeFrame(.binary, chunk[0..n]);
            sent += n;
        }
    }

    /// Read what a data client sends; record a close and stop.
    fn dataClientReader(f: *Fake, c: *ws.Conn, closed: *std.atomic.Value(bool)) void {
        while (true) {
            const m = c.readMessage(f.gpa) catch return;
            defer f.gpa.free(m.data);
            if (m.opcode != .close) continue;
            const code: u16 = if (m.data.len >= 2) std.mem.readInt(u16, m.data[0..2], .big) else 1005;
            f.mu.lockUncancelable(f.io);
            if (f.data_close_codes.items.len < 64) f.data_close_codes.append(f.gpa, code) catch {};
            f.mu.unlock(f.io);
            closed.store(true, .release);
            return;
        }
    }

    fn reject(c: *ws.Conn, reason: u8) void {
        c.writeFrame(.binary, &.{ 0x82, reason }) catch {};
        closeWith(c, 1008, "data handshake rejected");
    }

    /// Snapshot of the block's terminal, then a `resize` message, as a real stream starts.
    fn newStream(f: *Fake, s: *Session, block_id: []u8) !*Stream {
        const gpa = f.gpa;
        const st = try gpa.create(Stream);
        errdefer gpa.destroy(st);
        st.* = .{ .block_id = block_id, .token = undefined, .nonce = 0 };
        errdefer st.bytes.deinit(gpa);
        while (st.nonce == 0) {
            var nb: [8]u8 = undefined;
            f.io.random(&nb);
            st.nonce = std.mem.readInt(u64, &nb, .little);
        }
        var aw: Io.Writer.Allocating = .fromArrayList(gpa, &st.bytes);
        defer st.bytes = aw.toArrayList();
        try ghostty_vt.snapshot.encode(gpa, &aw.writer, &s.block.term, .{ .continuation = .ground });
        try aw.writer.print(
            "\x1b_rex1;{d};{{\"type\":\"resize\",\"cols\":{d},\"rows\":{d},\"cell_width_px\":0,\"cell_height_px\":0,\"owner\":null}}\x1b\\",
            .{ st.nonce, s.block.term.cols, s.block.term.rows },
        );
        try f.streams.append(gpa, st);
        return st;
    }
};

const no_object: std.json.ObjectMap = .empty;

/// Whether the real path `real` is the real path `root` or inside it.
fn insideRoot(root: []const u8, real: []const u8) bool {
    if (!std.mem.startsWith(u8, real, root)) return false;
    return real.len == root.len or real[root.len] == '/';
}

fn strField(o: std.json.ObjectMap, name: []const u8) ?[]const u8 {
    const v = o.get(name) orelse return null;
    return if (v == .string) v.string else null;
}

fn intField(o: std.json.ObjectMap, name: []const u8) ?u32 {
    const v = o.get(name) orelse return null;
    return if (v == .integer and v.integer >= 0 and v.integer < 1 << 31) @intCast(v.integer) else null;
}

// ---- tests ----

const testing = std.testing;

const hello_18 = "{\"type\":\"hello\",\"api_revision\":18,\"api_min_revision\":18," ++
    "\"client\":{\"kind\":\"other\",\"platform\":\"web\",\"name\":\"rweb-test\",\"version\":\"0\"}}";

fn connectControl(f: *Fake, hello: []const u8) !*ws.Conn {
    const c = try ws.Conn.connect(testing.allocator, f.io, f.path, "/api/control", control_subprotocol);
    errdefer c.deinit(testing.allocator);
    try c.writeFrame(.text, hello);
    return c;
}

/// Send a request and return the parsed response payload object. Caller frees with `deinit`.
fn rpc(c: *ws.Conn, id: []const u8, method: []const u8, payload: []const u8) !std.json.Parsed(std.json.Value) {
    const req = try testing.allocator.print("{{\"type\":\"request\",\"id\":\"{s}\",\"method\":\"{s}\",\"payload\":{s}}}", .{ id, method, payload });
    defer testing.allocator.free(req);
    try c.writeFrame(.text, req);
    const m = try c.readMessage(testing.allocator);
    defer testing.allocator.free(m.data);
    return std.json.parseFromSlice(std.json.Value, testing.allocator, m.data, .{});
}

fn readWelcome(c: *ws.Conn) !std.json.Parsed(std.json.Value) {
    const m = try c.readMessage(testing.allocator);
    defer testing.allocator.free(m.data);
    return std.json.parseFromSlice(std.json.Value, testing.allocator, m.data, .{});
}

/// A session with one terminal, attached, with a ticket for its stream.
const Opened = struct {
    session_id: []u8,
    block_id: []u8,
    ticket: [16]u8,

    fn deinit(o: Opened) void {
        testing.allocator.free(o.session_id);
        testing.allocator.free(o.block_id);
    }
};

fn open(c: *ws.Conn) !Opened {
    const a = testing.allocator;
    var created = try rpc(c, "1", "session.create", "{\"label\":\"rweb-test-fake\"}");
    defer created.deinit();
    const pl = created.value.object.get("payload").?.object;
    const sid = try a.dupe(u8, pl.get("session_id").?.string);
    errdefer a.free(sid);
    const bid = try a.dupe(u8, pl.get("initial_windows").?.array.items[0].object.get("block_ids").?.array.items[0].string);
    errdefer a.free(bid);
    const pa = try a.print("{{\"session_id\":\"{s}\"}}", .{sid});
    defer a.free(pa);
    var at = try rpc(c, "2", "session.attach", pa);
    at.deinit();
    return .{ .session_id = sid, .block_id = bid, .ticket = try getTicket(c, "3", sid, bid) };
}

fn getTicket(c: *ws.Conn, id: []const u8, sid: []const u8, bid: []const u8) ![16]u8 {
    const a = testing.allocator;
    const pd = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"data_ref_id\":\"terminal\",\"subprotocol\":\"{s}\"}}", .{ sid, bid, data_subprotocol });
    defer a.free(pd);
    var tk = try rpc(c, id, "data.connect", pd);
    defer tk.deinit();
    var raw: [16]u8 = undefined;
    try std.base64.url_safe_no_pad.Decoder.decode(&raw, tk.value.object.get("payload").?.object.get("ticket").?.string);
    return raw;
}

const DataHandshake = struct { conn: *ws.Conn, token: [16]u8, nonce: u64 };

fn dataHello(f: *Fake, ticket: [16]u8) !DataHandshake {
    const d = try ws.Conn.connect(testing.allocator, f.io, f.path, "/api/data", data_subprotocol);
    errdefer d.deinit(testing.allocator);
    var h: [17]u8 = undefined;
    h[0] = 0x01;
    @memcpy(h[1..], &ticket);
    try d.writeFrame(.binary, &h);
    return finishHandshake(d);
}

fn finishHandshake(d: *ws.Conn) !DataHandshake {
    const w = try d.readMessage(testing.allocator);
    defer testing.allocator.free(w.data);
    try testing.expectEqual(@as(usize, 32), w.data.len);
    try testing.expectEqual(@as(u8, 0x81), w.data[0]);
    return .{ .conn = d, .token = w.data[1..17].*, .nonce = std.mem.readInt(u64, w.data[24..32], .little) };
}

/// Read stream messages until `want` bytes have been collected.
fn readStream(d: *ws.Conn, out: *std.ArrayList(u8), want: usize) !void {
    while (out.items.len < want) {
        const m = try d.readMessage(testing.allocator);
        defer testing.allocator.free(m.data);
        try testing.expectEqual(ws.Opcode.binary, m.opcode);
        try out.appendSlice(testing.allocator, m.data);
    }
}

fn readUntil(d: *ws.Conn, out: *std.ArrayList(u8), needle: []const u8) !void {
    while (std.mem.indexOf(u8, out.items, needle) == null) try readStream(d, out, out.items.len + 1);
}

test "control: hello, welcome and revision negotiation" {
    const f = try Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(testing.allocator);
    var w = try readWelcome(c);
    defer w.deinit();
    const o = w.value.object;
    try testing.expectEqualStrings("welcome", o.get("type").?.string);
    try testing.expectEqualStrings(control_subprotocol, o.get("protocol").?.string);
    try testing.expectEqual(@as(i64, 18), o.get("api_revision").?.integer);
    try testing.expect(!o.get("client").?.object.get("resumed").?.bool);
}

test "control: a client newer than the server gets the server's newest revision" {
    const f = try Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try connectControl(f, "{\"type\":\"hello\",\"api_revision\":19,\"api_min_revision\":18}");
    defer c.deinit(testing.allocator);
    var w = try readWelcome(c);
    defer w.deinit();
    try testing.expectEqual(@as(i64, 18), w.value.object.get("api_revision").?.integer);
}

test "control: no common revision closes with 1008" {
    const f = try Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try connectControl(f, "{\"type\":\"hello\",\"api_revision\":25,\"api_min_revision\":19}");
    defer c.deinit(testing.allocator);
    const m = try c.readMessage(testing.allocator);
    defer testing.allocator.free(m.data);
    try testing.expectEqual(ws.Opcode.close, m.opcode);
    try testing.expectEqual(@as(u16, 1008), std.mem.readInt(u16, m.data[0..2], .big));
}

test "control: errors for unknown methods and unattached sessions" {
    const f = try Fake.start(testing.allocator, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(testing.allocator);
    var w = try readWelcome(c);
    w.deinit();
    var r = try rpc(c, "1", "no.such.method", "{}");
    defer r.deinit();
    try testing.expectEqualStrings("method_not_found", r.value.object.get("error").?.object.get("code").?.string);
    const s = try f.createSession(null);
    const p = try testing.allocator.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"data_ref_id\":\"terminal\"}}", .{ s.session_id, s.block_id });
    defer testing.allocator.free(p);
    var r2 = try rpc(c, "2", "data.connect", p);
    defer r2.deinit();
    try testing.expectEqualStrings("conflict", r2.value.object.get("error").?.object.get("code").?.string);
}

test "data: snapshot decodes, resize follows, typed text is echoed" {
    const a = testing.allocator;
    const f = try Fake.start(a, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(a);
    var w = try readWelcome(c);
    w.deinit();
    const o = try open(c);
    defer o.deinit();
    const hs = try dataHello(f, o.ticket);
    defer hs.conn.deinit(a);

    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    var nonce_buf: [64]u8 = undefined;
    const marker = try std.fmt.bufPrint(&nonce_buf, "\x1b_rex1;{d};{{\"type\":\"resize\"", .{hs.nonce});
    try readUntil(hs.conn, &buf, marker);

    // The bytes before the resize message are a snapshot libghostty-vt decodes.
    var reader: Io.Reader = .fixed(buf.items);
    var decoded = try ghostty_vt.snapshot.decode(a, testing.io, &reader, .{ .max_continuation_bytes = 1 << 20 });
    defer decoded.deinit(a);
    var term = decoded.toOwned();
    defer term.deinit(a);
    try testing.expectEqual(@as(u16, 80), term.cols);
    try testing.expectEqual(@as(u16, 24), term.rows);

    // Type into the block: the echo arrives on the stream, after the resize.
    const pw = try a.print("{{\"session_id\":\"{s}\",\"block_id\":\"{s}\",\"args\":{{\"data\":\"hi\\n\"}}}}", .{ o.session_id, o.block_id });
    defer a.free(pw);
    var wr = try rpc(c, "4", "com.superlogical.terminal.write", pw);
    defer wr.deinit();
    try testing.expectEqual(@as(i64, 3), wr.value.object.get("payload").?.object.get("bytes_written").?.integer);
    try readUntil(hs.conn, &buf, "hi\r\n");
}

test "data: a dropped stream resumes with an exact byte count, and a wrong count is refused" {
    const a = testing.allocator;
    const f = try Fake.start(a, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(a);
    var w = try readWelcome(c);
    w.deinit();
    const o = try open(c);
    defer o.deinit();
    const hs = try dataHello(f, o.ticket);
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(a);
    var nb: [64]u8 = undefined;
    const marker = try std.fmt.bufPrint(&nb, "\x1b_rex1;{d};{{\"type\":\"resize\"", .{hs.nonce});
    try readUntil(hs.conn, &buf, marker);
    const got = buf.items.len;
    f.dropDataConnections();
    hs.conn.deinit(a);

    // Output produced while the viewer was away.
    try f.feed(o.block_id, "while away");

    // A count above what was sent is refused (0x05).
    {
        const d = try ws.Conn.connect(a, f.io, f.path, "/api/data", data_subprotocol);
        defer d.deinit(a);
        var r: [25]u8 = undefined;
        r[0] = 0x02;
        @memcpy(r[1..17], &hs.token);
        std.mem.writeInt(u64, r[17..25], 1 << 40, .little);
        try d.writeFrame(.binary, &r);
        const m = try d.readMessage(a);
        defer a.free(m.data);
        try testing.expectEqualSlices(u8, &.{ 0x82, 0x05 }, m.data);
    }

    // The exact count resumes, with the same nonce, and delivers what was missed.
    const d = try ws.Conn.connect(a, f.io, f.path, "/api/data", data_subprotocol);
    defer d.deinit(a);
    var r: [25]u8 = undefined;
    r[0] = 0x02;
    @memcpy(r[1..17], &hs.token);
    std.mem.writeInt(u64, r[17..25], got, .little);
    try d.writeFrame(.binary, &r);
    const hs2 = try finishHandshake(d);
    try testing.expectEqual(hs.nonce, hs2.nonce);
    try testing.expect(!std.mem.eql(u8, &hs.token, &hs2.token));
    var rest: std.ArrayList(u8) = .empty;
    defer rest.deinit(a);
    try readUntil(d, &rest, "while away");
}

test "data: a ticket works once, and an unknown one is rejected" {
    const a = testing.allocator;
    const f = try Fake.start(a, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(a);
    var w = try readWelcome(c);
    w.deinit();
    const o = try open(c);
    defer o.deinit();
    const hs = try dataHello(f, o.ticket);
    hs.conn.deinit(a);

    const d = try ws.Conn.connect(a, f.io, f.path, "/api/data", data_subprotocol);
    defer d.deinit(a);
    var h: [17]u8 = undefined;
    h[0] = 0x01;
    @memcpy(h[1..], &o.ticket);
    try d.writeFrame(.binary, &h);
    const m = try d.readMessage(a);
    defer a.free(m.data);
    try testing.expectEqualSlices(u8, &.{ 0x82, 0x01 }, m.data);
}

test "restart: connections drop, old tokens start a new client, sessions keep their IDs" {
    const a = testing.allocator;
    const f = try Fake.start(a, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    defer c.deinit(a);
    var w = try readWelcome(c);
    const token = try a.dupe(u8, w.value.object.get("client").?.object.get("reconnect_token").?.string);
    defer a.free(token);
    w.deinit();
    const o = try open(c);
    defer o.deinit();
    try f.feed(o.block_id, "before");

    try f.restart();
    // The old control connection is gone, without a close frame.
    try testing.expect(std.meta.isError(c.readMessage(a)));

    const hello = try a.print("{{\"type\":\"hello\",\"api_revision\":18,\"api_min_revision\":18,\"reconnect_token\":\"{s}\"}}", .{token});
    defer a.free(hello);
    const c2 = try connectControl(f, hello);
    defer c2.deinit(a);
    var w2 = try readWelcome(c2);
    defer w2.deinit();
    try testing.expect(!w2.value.object.get("client").?.object.get("resumed").?.bool);

    var list = try rpc(c2, "1", "session.list", "{}");
    defer list.deinit();
    const sessions = list.value.object.get("payload").?.object.get("sessions").?.array.items;
    try testing.expectEqual(@as(usize, 1), sessions.len);
    try testing.expectEqualStrings(o.session_id, sessions[0].object.get("session_id").?.string);
}

test "control: reconnect token resumes the client within the window" {
    const a = testing.allocator;
    const f = try Fake.start(a, testing.io);
    defer f.deinit();
    const c = try connectControl(f, hello_18);
    var w = try readWelcome(c);
    const token = try a.dupe(u8, w.value.object.get("client").?.object.get("reconnect_token").?.string);
    defer a.free(token);
    const id1 = try a.dupe(u8, w.value.object.get("client").?.object.get("id").?.string);
    defer a.free(id1);
    w.deinit();
    c.deinit(a);

    const hello = try a.print("{{\"type\":\"hello\",\"api_revision\":18,\"api_min_revision\":18,\"reconnect_token\":\"{s}\"}}", .{token});
    defer a.free(hello);
    const c2 = try connectControl(f, hello);
    defer c2.deinit(a);
    var w2 = try readWelcome(c2);
    defer w2.deinit();
    const cl = w2.value.object.get("client").?.object;
    try testing.expect(cl.get("resumed").?.bool);
    try testing.expectEqualStrings(id1, cl.get("id").?.string);
    try testing.expect(!std.mem.eql(u8, token, cl.get("reconnect_token").?.string));
}
