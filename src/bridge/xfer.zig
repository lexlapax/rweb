//! File transfer, the parts that are about trust rather than bytes.
//!
//! A transfer is two steps. The page asks over its authenticated WebSocket (`dl` / `ul`); the
//! bridge checks the request, and answers with a **token**: 128 random bits, valid for 30
//! seconds, good for exactly one request. The page then fetches `GET /xfer/<token>` (download)
//! or `PUT /xfer/<token>` (upload). So no file is reachable by a URL a web page could guess or
//! be tricked into requesting: the token exists only inside the page that asked.
//!
//! Downloads read through Rex (`download_begin`), which opens regular files only. Uploads are
//! written by the bridge itself into one directory the owner named, never anywhere else, under
//! a sanitized name that cannot replace an existing file; then the quoted path is pasted into the
//! terminal.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const posix = std.posix;
const Allocator = std.mem.Allocator;

pub const Config = struct {
    /// Off unless the owner turns it on: it gives the page the owner's file access.
    enabled: bool = false,
    /// Where uploads go, as the owner named it: shown, and joined with the new file's name for the
    /// path pasted into the terminal. Null: uploads are off (downloads can still be on).
    upload_dir: ?[]const u8 = null,
    /// That folder, opened once at startup by `openUploadDir` and kept open: uploads are created
    /// relative to it, so replacing the path later (a rename, a symlink) cannot redirect them.
    /// Owned by whoever opened it. Uploads are refused while it is null.
    upload_dir_handle: ?Io.Dir = null,
    /// The most bytes one transfer may carry, either way.
    max_bytes: u64 = 256 * 1024 * 1024,
};

pub const Kind = enum { download, upload };

/// How long a token lives, how many may be waiting, and how many transfers may run at once.
pub const token_ttl_ms: i64 = 30_000;
pub const max_waiting: usize = 16;
pub const max_running: u32 = 4;

pub const Entry = struct {
    token: [32]u8,
    kind: Kind,
    expires_ms: i64,
    /// Download: the ticket for Rex's bytes stream. Unused for an upload.
    ticket: [16]u8 = @splat(0),
    /// What the file is called (a download: Rex's name for it; an upload: the browser's, to be sanitized).
    name: []u8,
    /// A download: the size Rex reported. An upload: the exact size the browser announced.
    size: u64,
    /// Upload: where to paste the new file's path.
    session_id: []u8 = &.{},
    block_id: []u8 = &.{},
    /// The viewer that asked (`Hub.mayUpload` checks it is still allowed when the token is used).
    viewer_id: u64 = 0,

    pub fn deinit(e: *Entry, gpa: Allocator) void {
        gpa.free(e.name);
        gpa.free(e.session_id);
        gpa.free(e.block_id);
    }
};

pub const Registry = struct {
    gpa: Allocator,
    io: Io,
    mu: Io.Mutex = .init,
    items: std.ArrayList(Entry) = .empty,
    running: std.atomic.Value(u32) = .init(0),

    pub fn init(gpa: Allocator, io: Io) Registry {
        return .{ .gpa = gpa, .io = io };
    }

    pub fn deinit(r: *Registry) void {
        for (r.items.items) |*e| e.deinit(r.gpa);
        r.items.deinit(r.gpa);
    }

    /// The boot clock keeps counting while the machine sleeps, so a token cannot outlive its 30
    /// seconds by a suspend (the awake clock stops then).
    fn now(r: *Registry) i64 {
        return Io.Clock.boot.now(r.io).toMilliseconds();
    }

    /// Take ownership of `e` (its strings), give it a token and a deadline, and return the token.
    /// Fails when too many are waiting; expired entries are dropped first.
    pub fn add(r: *Registry, e_in: Entry) error{TooMany}![32]u8 {
        var e = e_in;
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.sweepLocked();
        if (r.items.items.len >= max_waiting) {
            e.deinit(r.gpa);
            return error.TooMany;
        }
        var raw: [16]u8 = undefined;
        r.io.random(&raw);
        e.token = std.fmt.bytesToHex(raw, .lower);
        e.expires_ms = r.now() + token_ttl_ms;
        r.items.append(r.gpa, e) catch {
            e.deinit(r.gpa);
            return error.TooMany;
        };
        return e.token;
    }

    /// The entry for `token` if it exists, has not expired and is of `kind`; removed, so it is
    /// good once. The caller owns what is returned. The token is compared in constant time.
    pub fn take(r: *Registry, token: []const u8, kind: Kind) ?Entry {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.sweepLocked();
        var found: ?usize = null;
        for (r.items.items, 0..) |e, i| {
            if (token.len != e.token.len) continue;
            var diff: u8 = 0;
            for (e.token, token) |a, b| diff |= a ^ b;
            if (diff == 0) found = i;
        }
        const i = found orelse return null;
        if (r.items.items[i].kind != kind) return null; // a download token cannot start an upload
        return r.items.swapRemove(i);
    }

    /// Forget every token issued to viewer `id` (it left, or turned read-only).
    pub fn revokeViewer(r: *Registry, id: u64) void {
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        var i: usize = 0;
        while (i < r.items.items.len) {
            if (r.items.items[i].viewer_id == id) {
                var e = r.items.swapRemove(i);
                e.deinit(r.gpa);
            } else i += 1;
        }
    }

    fn sweepLocked(r: *Registry) void {
        const t = r.now();
        var i: usize = 0;
        while (i < r.items.items.len) {
            if (r.items.items[i].expires_ms <= t) {
                var e = r.items.swapRemove(i);
                e.deinit(r.gpa);
            } else i += 1;
        }
    }

    /// Reserve one of the running-transfer slots; false when all are in use.
    pub fn acquire(r: *Registry) bool {
        while (true) {
            const n = r.running.load(.acquire);
            if (n >= max_running) return false;
            if (r.running.cmpxchgWeak(n, n + 1, .acq_rel, .acquire) == null) return true;
        }
    }

    pub fn release(r: *Registry) void {
        _ = r.running.fetchSub(1, .acq_rel);
    }
};

/// A file name that is safe to create in the upload directory and to put on a shell line: letters,
/// digits and `. _ - + @ , ( )` and space survive, everything else (including `/`, `\`, control
/// characters and non-ASCII) becomes `_`; leading dots and spaces go (no hidden or `..` names);
/// at most 100 bytes, extension kept. Never empty.
pub fn safeName(out: []u8, name: []const u8) []const u8 {
    std.debug.assert(out.len >= 101);
    // The last path component only, whichever slash the browser used.
    var base = name;
    if (std.mem.lastIndexOfAny(u8, base, "/\\")) |i| base = base[i + 1 ..];
    // A long name is cut in the middle: the start and a short extension survive.
    var stem = base;
    var ext: []const u8 = "";
    if (base.len > 100) {
        const dot = std.mem.lastIndexOfScalar(u8, base, '.');
        if (dot != null and base.len - dot.? <= 12) {
            ext = base[dot.?..];
            stem = base[0 .. 100 - ext.len];
        } else stem = base[0..100];
    }
    var n: usize = 0;
    for ([_][]const u8{ stem, ext }) |part| for (part) |c| {
        const ok = std.ascii.isAlphanumeric(c) or c == '.' or c == '_' or c == '-' or c == '+' or c == '@' or c == ',' or c == '(' or c == ')' or c == ' ';
        out[n] = if (ok) c else '_';
        n += 1;
    };
    const trimmed = std.mem.trim(u8, out[0..n], ". ");
    if (trimmed.len == 0) {
        const fallback = "upload";
        @memcpy(out[0..fallback.len], fallback);
        return out[0..fallback.len];
    }
    if (trimmed.ptr != out.ptr) std.mem.copyForwards(u8, out[0..trimmed.len], trimmed);
    return out[0..trimmed.len];
}

/// The path wrapped for a POSIX shell: single quotes, with `'` written as `'\''`.
pub fn shellQuote(gpa: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.append(gpa, '\'');
    for (s) |c| {
        if (c == '\'') try out.appendSlice(gpa, "'\\''") else try out.append(gpa, c);
    }
    try out.append(gpa, '\'');
    return out.toOwnedSlice(gpa);
}

/// `attachment; filename="<ascii>"; filename*=UTF-8''<percent-encoded>` for any name, in `buf`
/// (512 bytes hold any name in full). The encoded name is cut to fit, never inside a UTF-8 sequence.
pub fn contentDisposition(buf: []u8, name: []const u8) []const u8 {
    var w: Io.Writer = .fixed(buf);
    w.writeAll("attachment; filename=\"") catch return "attachment";
    var shown: usize = 0;
    for (name) |c| {
        if (shown >= 80) break;
        const ok = c >= 0x20 and c < 0x7f and c != '"' and c != '\\' and c != '%' and c != '/' and c != ';';
        w.writeByte(if (ok) c else '_') catch return "attachment";
        shown += 1;
    }
    w.writeAll("\"; filename*=UTF-8''") catch return "attachment";
    const limit = @min(name.len, 120);
    var i: usize = 0;
    while (i < limit) {
        // A whole character or nothing: a cut sequence would make the name invalid UTF-8.
        const seq = std.unicode.utf8ByteSequenceLength(name[i]) catch 1;
        if (i + seq > limit) break;
        var need: usize = 0;
        for (name[i .. i + seq]) |c| need += if (unreserved(c)) 1 else 3;
        if (need > w.buffer.len - w.end) break;
        for (name[i .. i + seq]) |c| {
            if (unreserved(c)) w.writeByte(c) catch unreachable else w.print("%{X:0>2}", .{c}) catch unreachable;
        }
        i += seq;
    }
    return w.buffered();
}

fn unreserved(c: u8) bool {
    return std.ascii.isAlphanumeric(c) or c == '-' or c == '_' or c == '.' or c == '~';
}

// ---- files and folders that only we control ----
//
// A secret file, the upload folder and the unix socket's folder are checked on an open descriptor,
// not by path, and then used through that descriptor, so nothing can be swapped in between the
// check and the use. Every folder above them must be one no other user can change (owned by root
// or by us, and not writable by group or others unless sticky, as `/tmp` is), or a path that
// passes now could lead elsewhere later.

/// The owner and mode (file type bits included) of an open descriptor.
pub const OwnerMode = struct { uid: u32, mode: u32 };

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_ISVTX: u32 = 0o1000;

/// What failed, for the message: the path that was being checked when it did.
pub const Problem = struct { path: []const u8 = "" };

pub const CheckError = error{
    /// A folder above the file is owned by someone other than root or us.
    FolderNotOurs,
    /// A folder above the file is writable by group or others and not sticky.
    FolderWritableByOthers,
    NotADirectory,
    NotARegularFile,
    /// The file or folder is a symbolic link (never followed).
    SymLink,
    NotOwned,
    TooOpen,
    TooLong,
    BadPath,
    StatFailed,
    ReadFailed,
};

pub fn fdOwnerMode(fd: posix.fd_t) error{StatFailed}!OwnerMode {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true }, &stx);
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        return .{ .uid = stx.uid, .mode = stx.mode };
    } else {
        var sb: std.c.Stat = undefined;
        if (std.c.fstat(fd, &sb) != 0) return error.StatFailed;
        return .{ .uid = @intCast(sb.uid), .mode = @intCast(sb.mode) };
    }
}

fn myUid() u32 {
    return @intCast(std.c.getuid());
}

/// A folder on the way to a private file: a directory that only root or we can change.
pub fn checkAncestor(om: OwnerMode, uid: u32) CheckError!void {
    if (om.mode & S_IFMT != S_IFDIR) return error.NotADirectory;
    if (om.uid != 0 and om.uid != uid) return error.FolderNotOurs;
    if (om.mode & 0o022 != 0 and om.mode & S_ISVTX == 0) return error.FolderWritableByOthers;
}

/// A private folder (the upload folder, the socket's folder): a directory of ours, closed to others.
pub fn checkPrivateDir(om: OwnerMode, uid: u32) CheckError!void {
    if (om.mode & S_IFMT != S_IFDIR) return error.NotADirectory;
    if (om.uid != uid) return error.NotOwned;
    if (om.mode & 0o077 != 0) return error.TooOpen;
}

/// A private file (a secret): a regular file of ours, closed to others.
pub fn checkPrivateFile(om: OwnerMode, uid: u32) CheckError!void {
    if (om.mode & S_IFMT != S_IFREG) return error.NotARegularFile;
    if (om.uid != uid) return error.NotOwned;
    if (om.mode & 0o077 != 0) return error.TooOpen;
}

pub const OpenError = CheckError || posix.OpenError || Io.Dir.RealPathFileAllocError || Allocator.Error;

fn closeFd(io: Io, fd: posix.fd_t) void {
    (Io.Dir{ .handle = fd }).close(io);
}

fn openFailed(e: posix.OpenError) OpenError {
    return switch (e) {
        error.SymLinkLoop => error.SymLink, // O_NOFOLLOW on a symbolic link
        error.NotDir => error.NotADirectory,
        else => e,
    };
}

/// Open the folder that holds `path`, by its real path, one component at a time from `/`, never
/// following a link, checking each with `checkAncestor`. Returns the folder's descriptor (the
/// caller closes it) and the last component of `path`.
fn openParent(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError!struct { fd: posix.fd_t, base: []const u8 } {
    problem.path = path;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.BadPath;
    const parent = std.fs.path.dirname(path) orelse ".";
    problem.path = parent;
    const real = try Io.Dir.cwd().realPathFileAlloc(io, parent, arena);
    if (real.len == 0 or real[0] != '/') return error.BadPath;
    const uid = myUid();

    problem.path = "/";
    var fd = posix.openat(posix.AT.FDCWD, "/", .{ .DIRECTORY = true, .CLOEXEC = true }, 0) catch |e| return openFailed(e);
    errdefer closeFd(io, fd);
    try checkAncestor(fdOwnerMode(fd) catch return error.StatFailed, uid);
    var it = std.mem.tokenizeScalar(u8, real, '/');
    while (it.next()) |comp| {
        problem.path = real[0..it.index]; // the folders down to this one
        const next = posix.openat(fd, comp, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |e| return openFailed(e);
        closeFd(io, fd);
        fd = next;
        try checkAncestor(fdOwnerMode(fd) catch return error.StatFailed, uid);
    }
    problem.path = path;
    return .{ .fd = fd, .base = base };
}

/// The contents of a private file, at most `limit` bytes, read from the descriptor that was checked:
/// opened without following a link (and without blocking, so a FIFO cannot hang startup), then it
/// must be a regular file of ours that group and others cannot read, in folders only we or root
/// can change. On failure `problem.path` names what failed.
pub fn readPrivateFile(arena: Allocator, io: Io, path: []const u8, limit: usize, problem: *Problem) OpenError![]u8 {
    const parent = try openParent(arena, io, path, problem);
    defer closeFd(io, parent.fd);
    const fd = posix.openat(parent.fd, parent.base, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| return openFailed(e);
    defer closeFd(io, fd);
    try checkPrivateFile(fdOwnerMode(fd) catch return error.StatFailed, myUid());
    const buf = try arena.alloc(u8, limit + 1);
    var n: usize = 0;
    while (n < buf.len) {
        const got = posix.read(fd, buf[n..]) catch return error.ReadFailed;
        if (got == 0) break;
        n += got;
    }
    if (n > limit) return error.TooLong;
    return buf[0..n];
}

/// The upload folder: made 0700 if missing, then opened without following a link and checked on
/// its descriptor (a directory of ours, closed to others, in folders only we or root can change).
/// The caller keeps the returned folder open for as long as uploads may go into it.
pub fn openUploadDir(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError!Io.Dir {
    _ = Io.Dir.cwd().createDirPathStatus(io, path, @enumFromInt(0o700)) catch {}; // a new folder is 0700
    const parent = try openParent(arena, io, std.mem.trimEnd(u8, path, "/"), problem);
    defer closeFd(io, parent.fd);
    const fd = posix.openat(parent.fd, parent.base, .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true }, 0) catch |e| {
        // A link to a folder fails as "not a directory" on some systems: say what it is.
        if (e == error.NotDir) if ((Io.Dir{ .handle = parent.fd }).statFile(io, parent.base, .{ .follow_symlinks = false })) |st| {
            if (st.kind == .sym_link) return error.SymLink;
        } else |_| {};
        return openFailed(e);
    };
    errdefer closeFd(io, fd);
    try checkPrivateDir(fdOwnerMode(fd) catch return error.StatFailed, myUid());
    return .{ .handle = fd };
}

// ---- tests ----

const testing = std.testing;

fn entry(gpa: Allocator, kind: Kind, name: []const u8) !Entry {
    return .{ .token = undefined, .kind = kind, .expires_ms = 0, .name = try gpa.dupe(u8, name), .size = 3 };
}

test "a token works once, for its own kind only" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .download, "a.txt"));
    try testing.expectEqual(@as(usize, 32), t.len);
    // The wrong kind does not use it up.
    try testing.expect(r.take(&t, .upload) == null);
    var e = r.take(&t, .download).?;
    defer e.deinit(testing.allocator);
    try testing.expectEqualStrings("a.txt", e.name);
    // Used.
    try testing.expect(r.take(&t, .download) == null);
}

test "an unknown, short or altered token is nothing" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .upload, "b.bin"));
    var wrong = t;
    wrong[31] = if (t[31] == 'a') 'b' else 'a';
    try testing.expect(r.take(&wrong, .upload) == null);
    try testing.expect(r.take(t[0..31], .upload) == null);
    try testing.expect(r.take("", .upload) == null);
    var e = r.take(&t, .upload).?; // the real one was not harmed
    e.deinit(testing.allocator);
}

test "tokens are random, and at most max_waiting wait" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    var seen: [max_waiting][32]u8 = undefined;
    for (0..max_waiting) |i| seen[i] = try r.add(try entry(testing.allocator, .download, "x"));
    for (0..max_waiting) |i| for (i + 1..max_waiting) |j| try testing.expect(!std.mem.eql(u8, &seen[i], &seen[j]));
    try testing.expectError(error.TooMany, r.add(try entry(testing.allocator, .download, "x")));
}

test "running transfers are limited" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    for (0..max_running) |_| try testing.expect(r.acquire());
    try testing.expect(!r.acquire());
    r.release();
    try testing.expect(r.acquire());
}

test "safeName keeps names harmless" {
    var buf: [128]u8 = undefined;
    const cases = [_][2][]const u8{
        .{ "report.pdf", "report.pdf" },
        .{ "../../etc/passwd", "passwd" },
        .{ "C:\\Users\\x\\evil.exe", "evil.exe" },
        .{ ".bashrc", "bashrc" },
        .{ "..", "upload" },
        .{ "", "upload" },
        .{ "   ", "upload" },
        .{ "a b (1).txt", "a b (1).txt" },
        .{ "x;rm -rf ~.txt", "x_rm -rf _.txt" },
        .{ "$(reboot)`id`.sh", "_(reboot)_id_.sh" },
        .{ "naïve\x00name\n.txt", "na__ve_name_.txt" },
        .{ "dir/", "upload" },
    };
    for (cases) |c| try testing.expectEqualStrings(c[1], safeName(&buf, c[0]));
    // Long names are cut and keep their extension.
    var long_buf: [307]u8 = undefined;
    @memset(long_buf[0..300], 'a');
    @memcpy(long_buf[300..], ".tar.gz");
    const out = safeName(&buf, &long_buf);
    try testing.expect(out.len <= 100);
    try testing.expect(std.mem.endsWith(u8, out, ".gz"));
}

test "shellQuote survives anything" {
    const a = testing.allocator;
    for ([_][2][]const u8{
        .{ "/tmp/a b.txt", "'/tmp/a b.txt'" },
        .{ "it's", "'it'\\''s'" },
        .{ "$(x)`y`;|&", "'$(x)`y`;|&'" },
        .{ "", "''" },
    }) |c| {
        const q = try shellQuote(a, c[0]);
        defer a.free(q);
        try testing.expectEqualStrings(c[1], q);
    }
}

test "contentDisposition is an attachment, with a safe ASCII name and the real one encoded" {
    var buf: [400]u8 = undefined;
    try testing.expectEqualStrings("attachment; filename=\"a.txt\"; filename*=UTF-8''a.txt", contentDisposition(&buf, "a.txt"));
    const evil = contentDisposition(&buf, "x\"; filename=\"y\r\nSet-Cookie: a=b");
    try testing.expect(std.mem.indexOfAny(u8, evil, "\r\n") == null);
    try testing.expect(std.mem.indexOf(u8, evil, "filename=\"y") == null);
    try testing.expect(std.mem.startsWith(u8, evil, "attachment; filename=\""));
    const uni = contentDisposition(&buf, "é.txt");
    try testing.expect(std.mem.indexOf(u8, uni, "%C3%A9.txt") != null);
}

test "contentDisposition holds a long name of multibyte characters, or cuts it between characters" {
    var name_buf: [120]u8 = undefined; // 120 bytes: 40 characters of 3 bytes each
    for (0..40) |k| @memcpy(name_buf[k * 3 ..][0..3], "日");
    const name: []const u8 = &name_buf;
    var buf: [512]u8 = undefined;
    const full = contentDisposition(&buf, name);
    try testing.expect(std.mem.startsWith(u8, full, "attachment; filename=\""));
    const enc = full[std.mem.indexOf(u8, full, "UTF-8''").? + "UTF-8''".len ..];
    try testing.expectEqual(@as(usize, 360), enc.len); // every byte, encoded
    // A buffer too small for all of it: cut, at a character boundary, never "attachment" alone.
    var small: [200]u8 = undefined;
    const cut = contentDisposition(&small, name);
    try testing.expect(cut.len <= small.len and cut.len > "attachment".len);
    const cut_enc = cut[std.mem.indexOf(u8, cut, "UTF-8''").? + "UTF-8''".len ..];
    try testing.expect(cut_enc.len > 0 and cut_enc.len % 9 == 0); // whole 3-byte characters only
    try testing.expect(std.mem.startsWith(u8, cut_enc, "%E6%97%A5"));
}

fn writeFileMode(io: Io, dir: Io.Dir, name: []const u8, mode: u32, text: []const u8) !void {
    const f = try dir.createFile(io, name, .{ .permissions = @enumFromInt(mode) });
    defer f.close(io);
    try f.writeStreamingAll(io, text);
}

fn chmodPath(arena: Allocator, path: []const u8, mode: std.c.mode_t) !void {
    const z = try std.fmt.allocPrintSentinel(arena, "{s}", .{path}, 0);
    if (std.c.chmod(z, mode) != 0) return error.ChmodFailed;
}

test "a private file is read only through a checked descriptor, in folders nobody else can change" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try writeFileMode(io, tmp.dir, "ok", 0o600, "secret");
    try tmp.dir.symLink(io, "ok", "link", .{});
    try tmp.dir.createDirPath(io, "adir");
    try tmp.dir.createDirPath(io, "open");
    try writeFileMode(io, tmp.dir, "open/ok", 0o600, "secret");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 0o777);
    try tmp.dir.createDirPath(io, "sticky");
    try writeFileMode(io, tmp.dir, "sticky/ok", 0o600, "secret");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/sticky", .{root}), 0o1777);
    try writeFileMode(io, tmp.dir, "big", 0o600, "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx");

    var p: Problem = .{};
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/ok", .{root}), 4096, &p));
    // A symbolic link is not followed, even to a good file.
    try testing.expectError(error.SymLink, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/link", .{root}), 4096, &p));
    // A directory is not a file.
    try testing.expectError(error.NotARegularFile, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/adir", .{root}), 4096, &p));
    // A folder others can write to (not sticky) could have the file swapped: refused, and named.
    const open_ok = try std.fmt.allocPrint(arena, "{s}/open/ok", .{root});
    try testing.expectError(error.FolderWritableByOthers, readPrivateFile(arena, io, open_ok, 4096, &p));
    try testing.expect(std.mem.endsWith(u8, p.path, "/open"));
    // A sticky one (like /tmp) is fine: others cannot rename or remove what is ours there.
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/sticky/ok", .{root}), 4096, &p));
    // Too long, and missing.
    try testing.expectError(error.TooLong, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/big", .{root}), 16, &p));
    try testing.expectError(error.FileNotFound, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/missing", .{root}), 16, &p));
    // A relative path through a linked folder resolves to the real folder first.
    try tmp.dir.symLink(io, "sticky", "via", .{});
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/via/ok", .{root}), 4096, &p));
}

test "the owner and mode rules, for owners a test cannot create" {
    const me: u32 = 501;
    // Folders above: root's or ours, and not writable by others unless sticky.
    try checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o755 }, me);
    try checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o1777 }, me);
    try checkAncestor(.{ .uid = me, .mode = S_IFDIR | 0o700 }, me);
    try testing.expectError(error.FolderNotOurs, checkAncestor(.{ .uid = 1000, .mode = S_IFDIR | 0o755 }, me));
    try testing.expectError(error.FolderWritableByOthers, checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o775 }, me));
    try testing.expectError(error.NotADirectory, checkAncestor(.{ .uid = 0, .mode = S_IFREG | 0o755 }, me));
    // A private folder (uploads, the socket's) must be ours: root's is not enough.
    try checkPrivateDir(.{ .uid = me, .mode = S_IFDIR | 0o700 }, me);
    try testing.expectError(error.NotOwned, checkPrivateDir(.{ .uid = 0, .mode = S_IFDIR | 0o700 }, me));
    try testing.expectError(error.NotOwned, checkPrivateDir(.{ .uid = 1000, .mode = S_IFDIR | 0o700 }, me));
    try testing.expectError(error.TooOpen, checkPrivateDir(.{ .uid = me, .mode = S_IFDIR | 0o750 }, me));
    // A private file.
    try checkPrivateFile(.{ .uid = me, .mode = S_IFREG | 0o600 }, me);
    try testing.expectError(error.NotOwned, checkPrivateFile(.{ .uid = 1000, .mode = S_IFREG | 0o600 }, me));
    try testing.expectError(error.TooOpen, checkPrivateFile(.{ .uid = me, .mode = S_IFREG | 0o640 }, me));
    try testing.expectError(error.NotARegularFile, checkPrivateFile(.{ .uid = me, .mode = 0o010000 | 0o600 }, me)); // a FIFO
}

test "the upload folder is made private if missing, and must be a private folder of ours" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    var p: Problem = .{};
    // Missing: made 0700, and opened.
    const fresh = try std.fmt.allocPrint(arena, "{s}/up/loads/", .{root});
    const d = try openUploadDir(arena, io, fresh, &p);
    defer d.close(io);
    const st = try d.stat(io);
    try testing.expectEqual(@as(u32, 0o700), @intFromEnum(st.permissions) & 0o777);
    // Open to others, a link to a good folder, a file.
    try tmp.dir.createDirPath(io, "wide");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), 0o755);
    try testing.expectError(error.TooOpen, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), &p));
    try tmp.dir.symLink(io, "up/loads", "linked", .{});
    try testing.expectError(error.SymLink, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/linked", .{root}), &p));
    try writeFileMode(io, tmp.dir, "file", 0o600, "x");
    try testing.expect(openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/file", .{root}), &p) == error.NotADirectory);
}

test "a token that has expired is nothing, and is dropped" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    const t = try r.add(try entry(testing.allocator, .download, "old.txt"));
    // Make it 30 seconds old.
    r.mu.lockUncancelable(r.io);
    r.items.items[0].expires_ms = r.now() - 1;
    r.mu.unlock(r.io);
    try testing.expect(r.take(&t, .download) == null);
    try testing.expectEqual(@as(usize, 0), r.items.items.len); // swept, and its memory freed
}
