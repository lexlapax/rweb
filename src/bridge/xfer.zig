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
    /// Where uploads go, as the owner named it (shown at startup). Null: uploads are off (downloads
    /// can still be on).
    upload_dir: ?[]const u8 = null,
    /// That folder's real path, resolved when it was opened (`openUploadDir`): joined with the new
    /// file's name for the path pasted into the terminal and returned to the page, so a link in the
    /// given path cannot make the pasted path name another file later. Null: `upload_dir` is used.
    upload_dir_real: ?[]const u8 = null,
    /// That folder, opened once at startup by `openUploadDir` and kept open: uploads are created
    /// relative to it, so replacing the path later (a rename, a symlink) cannot redirect them.
    /// Owned by whoever opened it. Uploads are refused while it is null.
    upload_dir_handle: ?Io.Dir = null,
    /// The most bytes one transfer may carry, either way.
    max_bytes: u64 = 256 * 1024 * 1024,
};

pub const Kind = enum { download, upload };

/// How long a token lives, how many may be waiting (in all, and for one viewer), and how many
/// transfers may run at once.
pub const token_ttl_ms: i64 = 30_000;
pub const max_waiting: usize = 16;
pub const max_waiting_per_viewer: usize = 4;
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
    /// Fails when too many are waiting, in all or for `e.viewer_id` (so one page cannot take every
    /// slot); expired entries are dropped first.
    pub fn add(r: *Registry, e_in: Entry) error{TooMany}![32]u8 {
        var e = e_in;
        r.mu.lockUncancelable(r.io);
        defer r.mu.unlock(r.io);
        r.sweepLocked();
        var mine: usize = 0;
        for (r.items.items) |w| {
            if (w.viewer_id == e.viewer_id) mine += 1;
        }
        if (r.items.items.len >= max_waiting or mine >= max_waiting_per_viewer) {
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
// A secret file, the upload folder, the unix socket's folder and the `tailscale` program are checked
// on an open descriptor (or relative to one), not by path, and then used through that descriptor
// where the system allows, so nothing can be swapped in between the check and the use. Every folder
// above them must be one no other user can change: owned by root or by us, not writable by others
// unless sticky (as `/tmp` is), and not writable by its group unless sticky or the group is macOS's
// root-equivalent `admin`. No other group is trusted, on any system: who belongs to a group cannot
// be known for certain (directory services, nested groups, nscd, pam_group). Otherwise a path that
// passes now could lead elsewhere later. The given path is walked as given, from `/`: a link on it is
// followed only from a folder that already passed, and only when root or we own it (`Walker`). The
// mode bits are not the whole answer: an access control list can let another user write
// (`checkPosixAcl`, `checkDarwinAcl`), and a filesystem can report owners and modes that nobody here
// controls (`checkMount`: FUSE, a network filesystem, another user's volume; on Linux also a mount a
// user made, `checkMountOrigin`); these are checked on every descriptor too. Each refusal leaves what
// was found in a `Problem`, and `explain` turns it into a sentence and the command that fixes it.

/// The owner, group and mode (file type bits included) of an open descriptor.
pub const OwnerMode = struct { uid: u32, gid: u32 = 0, mode: u32 };

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFLNK: u32 = 0o120000;
const S_IFSOCK: u32 = 0o140000;
const S_ISVTX: u32 = 0o1000;

/// The longest path a walk holds (Linux's `PATH_MAX`).
const max_path = 4096;
/// The most links one walk follows (Linux's own limit).
pub const max_link_hops = 40;

/// What a check was looking at when it failed.
pub const Role = enum { unknown, folder_above, private_folder, private_file, program, link };

/// Whom a refused access control list entry names.
pub const AclWho = union(enum) { none, user: u32, group: u32, everyone, unknown };

/// What failed, for the message (`explain`): where, and what was found there. Where (`pathText`) is
/// a slice of the path that was given, or, past a link, a place in `buf` (the folders the walk
/// resolved), kept as an offset and length so that a copy of a Problem still names it; the rest is
/// filled as far as the failing check knew it.
pub const Problem = struct {
    /// Where it failed, when that is outside `buf` (the given path, or a copy the caller keeps).
    /// Set it with `setPath`, read it with `pathText`.
    ext_path: []const u8 = "",
    /// Where it failed, when that is in `buf`: `buf[off..][0..len]`.
    buf_path: ?struct { off: usize, len: usize } = null,
    buf: [max_path]u8 = undefined,
    role: Role = .unknown,
    /// The owner, group and mode of what failed (of the link, for a link).
    found: ?OwnerMode = null,
    acl_who: AclWho = .none,
    /// macOS: who mounted the filesystem.
    mount_owner: ?u32 = null,
    fs_type_buf: [64]u8 = undefined,
    fs_type_len: usize = 0,
    /// A link's target, or the source of a refused mount.
    detail_buf: [max_path]u8 = undefined,
    detail_len: usize = 0,

    /// Where it failed (or "").
    pub fn pathText(p: *const Problem) []const u8 {
        if (p.buf_path) |b| return p.buf[b.off..][0..b.len];
        return p.ext_path;
    }

    /// Say where it failed: `s` may be a slice of this Problem's own `buf`, or anything that outlives
    /// the Problem.
    pub fn setPath(p: *Problem, s: []const u8) void {
        const base = @intFromPtr(&p.buf);
        const at = @intFromPtr(s.ptr);
        if (s.len > 0 and at >= base and at + s.len <= base + p.buf.len) {
            p.buf_path = .{ .off = at - base, .len = s.len };
            p.ext_path = "";
        } else {
            p.buf_path = null;
            p.ext_path = s;
        }
    }

    /// The filesystem's type name ("nfs4", "fuse.sshfs", "smbfs"), or "".
    pub fn fsType(p: *const Problem) []const u8 {
        return p.fs_type_buf[0..p.fs_type_len];
    }

    /// A link's target, or a mount's source, or "".
    pub fn detail(p: *const Problem) []const u8 {
        return p.detail_buf[0..p.detail_len];
    }

    pub fn setFsType(p: *Problem, s: []const u8) void {
        p.fs_type_len = @min(s.len, p.fs_type_buf.len);
        @memcpy(p.fs_type_buf[0..p.fs_type_len], s[0..p.fs_type_len]);
    }

    pub fn setDetail(p: *Problem, s: []const u8) void {
        p.detail_len = @min(s.len, p.detail_buf.len);
        @memcpy(p.detail_buf[0..p.detail_len], s[0..p.detail_len]);
    }

    /// A new place is being looked at: forget what was found at the last one.
    fn look(p: *Problem, role: Role) void {
        p.role = role;
        p.found = null;
        p.acl_who = .none;
        p.mount_owner = null;
        p.fs_type_len = 0;
        p.detail_len = 0;
    }
};

pub const CheckError = error{
    /// A folder above the file is owned by someone other than root or us.
    FolderNotOurs,
    /// A folder above the file is writable by others and not sticky.
    FolderWritableByOthers,
    /// A folder above the file is writable by its group (not macOS's `admin`), and not sticky.
    FolderWritableByGroup,
    NotADirectory,
    NotARegularFile,
    /// The file or folder itself is a symbolic link (only links above it are followed).
    SymLink,
    /// A link on the path is owned by someone other than root or us (in a sticky folder such as
    /// `/tmp`, another user's link would choose where the path leads).
    LinkNotOurs,
    /// The path goes through more than `max_link_hops` links (or a loop of them).
    TooManyLinks,
    NotOwned,
    TooOpen,
    /// A program others could change.
    ProgramWritableByOthers,
    /// A program its group (not macOS's `admin`) could change.
    ProgramWritableByGroup,
    /// An access control list entry lets another user (or `everyone`) change it.
    AclGivesOthersWrite,
    /// An access control list entry lets another user read or enter a private file or folder.
    AclGivesOthersAccess,
    /// An access control list entry lets a group change it: on a folder above or a program, any
    /// group but macOS's `admin`; on a private file or folder, any group.
    AclGivesGroupWrite,
    /// An access control list entry lets a group (any, `admin` included) read or enter a private
    /// file or folder.
    AclGivesGroupAccess,
    /// Its access control list could not be read, or is not one this program understands.
    AclUnreadable,
    /// It is on a FUSE filesystem (Linux), whose owners and modes are whatever its server says.
    FuseFilesystem,
    /// It is on a network filesystem, whose server decides who may read or write, out of sight.
    NetworkFilesystem,
    /// It is on a filesystem not known to be a local one whose owners and modes mean what they say
    /// (Linux).
    UnknownFilesystem,
    /// It is on a filesystem another user mounted (macOS), with owners and modes that user chose.
    MountNotOurs,
    /// It is on a volume mounted with ownership ignored (macOS), where every user owns every file.
    MountIgnoresOwnership,
    /// It is on a filesystem mounted from a loop device (Linux): an image file, with owners and
    /// modes whoever made the image chose.
    LoopMount,
    /// It is on a filesystem a user mounted (Linux: through udisks, or listed in `/run/mount/utab`).
    UserMount,
    /// Which mount it is on could not be found out (Linux: no mount ID, or `/proc/self/mountinfo` or
    /// `/run/mount/utab` unreadable).
    MountInfoUnreadable,
    TooLong,
    BadPath,
    StatFailed,
    ReadFailed,
};

pub fn fdOwnerMode(fd: posix.fd_t) error{StatFailed}!OwnerMode {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true }, &stx);
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        return .{ .uid = stx.uid, .gid = stx.gid, .mode = stx.mode };
    } else {
        var sb: std.c.Stat = undefined;
        if (std.c.fstat(fd, &sb) != 0) return error.StatFailed;
        return .{ .uid = @intCast(sb.uid), .gid = @intCast(sb.gid), .mode = @intCast(sb.mode) };
    }
}

/// What a folder entry is, looked at without following a link.
pub const Node = struct { dev: u64, ino: u64, uid: u32, gid: u32, mode: u32 };

pub fn isSocket(n: Node) bool {
    return n.mode & S_IFMT == S_IFSOCK;
}

fn zName(buf: *[1024]u8, name: []const u8) error{NameTooLong}![*:0]const u8 {
    if (name.len >= buf.len) return error.NameTooLong;
    @memcpy(buf[0..name.len], name);
    buf[name.len] = 0;
    return buf[0..name.len :0];
}

/// The entry `name` in folder `dir_fd`, never following a link.
pub fn statAt(dir_fd: posix.fd_t, name: []const u8) error{ FileNotFound, NameTooLong, StatFailed }!Node {
    var zbuf: [1024]u8 = undefined;
    const z = try zName(&zbuf, name);
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const rc = linux.statx(dir_fd, z, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .INO = true }, &stx);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            else => return error.StatFailed,
        }
        return .{ .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor, .ino = stx.ino, .uid = stx.uid, .gid = stx.gid, .mode = stx.mode };
    } else {
        var sb: std.c.Stat = undefined;
        const rc = std.c.fstatat(dir_fd, z, &sb, std.c.AT.SYMLINK_NOFOLLOW);
        switch (std.c.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            else => return error.StatFailed,
        }
        const dev: u64 = switch (@typeInfo(@TypeOf(sb.dev)).int.bits) {
            32 => @as(u32, @bitCast(sb.dev)),
            else => @bitCast(sb.dev),
        };
        return .{ .dev = dev, .ino = @intCast(sb.ino), .uid = @intCast(sb.uid), .gid = @intCast(sb.gid), .mode = @intCast(sb.mode) };
    }
}

/// The target of the link `name` in folder `dir_fd`, in `buf`.
fn readLinkAt(dir_fd: posix.fd_t, name: []const u8, buf: []u8) error{ NameTooLong, ReadFailed }![]const u8 {
    var zbuf: [1024]u8 = undefined;
    const z = try zName(&zbuf, name);
    const n = std.c.readlinkat(dir_fd, z, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    const len: usize = @intCast(n);
    if (len >= buf.len) return error.NameTooLong;
    return buf[0..len];
}

fn myUid() u32 {
    return @intCast(std.c.getuid());
}

/// A folder on the way to a private file: a directory that only root or we can change. A folder its
/// group can write to passes only when it is sticky or `group_safe` (macOS's `admin`, see
/// `groupIsSafe`); one others can write to passes only when sticky.
pub fn checkAncestor(om: OwnerMode, uid: u32, group_safe: bool) CheckError!void {
    if (om.mode & S_IFMT != S_IFDIR) return error.NotADirectory;
    if (om.uid != 0 and om.uid != uid) return error.FolderNotOurs;
    if (om.mode & S_ISVTX != 0) return;
    if (om.mode & 0o002 != 0) return error.FolderWritableByOthers;
    if (om.mode & 0o020 != 0 and !group_safe) return error.FolderWritableByGroup;
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

/// A program the bridge runs (`tailscale`): a regular file of root's or ours that nobody else can
/// change (not writable by others, nor by its group unless `group_safe`).
pub fn checkProgram(om: OwnerMode, uid: u32, group_safe: bool) CheckError!void {
    if (om.mode & S_IFMT != S_IFREG) return error.NotARegularFile;
    if (om.uid != 0 and om.uid != uid) return error.NotOwned;
    if (om.mode & 0o002 != 0) return error.ProgramWritableByOthers;
    if (om.mode & 0o020 != 0 and !group_safe) return error.ProgramWritableByGroup;
}

/// A link on the way: one root or we own (in a sticky folder another user's link would choose where
/// the path leads). Pure.
pub fn checkLink(om: OwnerMode, uid: u32) CheckError!void {
    if (om.mode & S_IFMT != S_IFLNK) return error.SymLink;
    if (om.uid != 0 and om.uid != uid) return error.LinkNotOurs;
}

/// On macOS the `admin` group (gid 80): its members can become root with their own password, so a
/// folder or program only `admin` can change is as safe as one only root can (`/Applications`,
/// Homebrew's folders). It is trusted for that alone: to change a folder above a checked item or a
/// program, never to read or enter a private one.
pub const darwin_admin_gid: u32 = 80;

/// Whether a folder or program that group `gid` can change is safe: only macOS's root-equivalent
/// `admin`. No other group is trusted, on any system, since its members cannot all be known.
pub fn groupIsSafe(gid: u32) bool {
    return builtin.os.tag.isDarwin() and gid == darwin_admin_gid;
}

/// Tests only: the answer `groupAnswer` gives instead of `groupIsSafe` (a test cannot make a group
/// that is safe). Null: `groupIsSafe`.
pub var test_group_safe: ?bool = null;

fn groupAnswer(gid: u32) bool {
    if (builtin.is_test) if (test_group_safe) |v| return v;
    return groupIsSafe(gid);
}

/// Writable by its group, and by nobody else past a sticky bit: the only case the group decides.
fn groupDecides(om: OwnerMode) bool {
    return om.mode & 0o020 != 0 and om.mode & 0o002 == 0 and om.mode & S_ISVTX == 0;
}

// ---- filesystems ----

/// What a descriptor's filesystem says about who controls it.
pub const Mount = struct {
    /// Linux: the filesystem's magic number (`statfs.f_type`).
    linux_type: ?u64 = null,
    /// Linux: the mount's ID (`statx` `STATX_MNT_ID`), as in `/proc/self/mountinfo`.
    mnt_id: ?u64 = null,
    /// macOS: the user who mounted it (`statfs.f_owner`).
    owner: ?u32 = null,
    /// macOS: mounted with ownership ignored (`MNT_IGNORE_OWNERSHIP`, "Ignore ownership on this
    /// volume"), so every file looks like the looker's own.
    ignores_ownership: bool = false,
    /// macOS: on a local disk (`MNT_LOCAL`).
    local: ?bool = null,
    /// macOS: the filesystem's name (`f_fstypename`), for the message.
    type_name: [16]u8 = @splat(0),
};

/// Linux filesystem magic numbers (`statfs.f_type`).
pub const linux_fs = struct {
    // Local, with owners and modes that mean what they say.
    pub const ext: u32 = 0xEF53; // ext2, ext3, ext4
    pub const xfs: u32 = 0x58465342;
    pub const btrfs: u32 = 0x9123683E;
    pub const tmpfs: u32 = 0x01021994;
    pub const ramfs: u32 = 0x858458F6;
    pub const zfs: u32 = 0x2FC12FC1;
    pub const f2fs: u32 = 0xF2F52010;
    pub const bcachefs: u32 = 0xCA451A4E;
    pub const overlay: u32 = 0x794C7630;
    /// `fuse` and `fuseblk`.
    pub const fuse: u32 = 0x65735546;
    // Network: the server decides.
    pub const nfs: u32 = 0x6969;
    pub const smb: u32 = 0x517B;
    pub const cifs: u32 = 0xFF534D42;
    pub const smb2: u32 = 0xFE534D42;
    pub const ceph: u32 = 0x00C36400;
    pub const v9fs: u32 = 0x01021997;
    pub const afs: u32 = 0x6B414653;
    pub const coda: u32 = 0x73757245;
    pub const ncp: u32 = 0x564C;
    pub const gfs2: u32 = 0x01161970;
    pub const ocfs2: u32 = 0x7461636F;
    pub const lustre: u32 = 0x0BD00BD0;
    pub const orangefs: u32 = 0x20030528;
};

/// A Linux filesystem rweb trusts the owners and modes of: a local one with Unix ownership.
pub fn linuxFsIsLocal(t: u32) bool {
    const F = linux_fs;
    return switch (t) {
        F.ext, F.xfs, F.btrfs, F.tmpfs, F.ramfs, F.zfs, F.f2fs, F.bcachefs, F.overlay => true,
        else => false,
    };
}

pub fn linuxFsIsNetwork(t: u32) bool {
    const F = linux_fs;
    return switch (t) {
        F.nfs, F.smb, F.cifs, F.smb2, F.ceph, F.v9fs, F.afs, F.coda, F.ncp, F.gfs2, F.ocfs2, F.lustre, F.orangefs => true,
        else => false,
    };
}

/// A name for a Linux filesystem magic number, for the message when the mount table has none.
pub fn linuxFsName(t: u32) []const u8 {
    const F = linux_fs;
    return switch (t) {
        F.ext => "ext4",
        F.xfs => "xfs",
        F.btrfs => "btrfs",
        F.tmpfs => "tmpfs",
        F.ramfs => "ramfs",
        F.zfs => "zfs",
        F.f2fs => "f2fs",
        F.bcachefs => "bcachefs",
        F.overlay => "overlay",
        F.fuse => "fuse",
        F.nfs => "nfs",
        F.smb, F.smb2 => "smb",
        F.cifs => "cifs",
        F.ceph => "ceph",
        F.v9fs => "9p",
        F.afs => "afs",
        else => "",
    };
}

const darwin_mnt_local: u32 = 0x00001000;
const darwin_mnt_ignore_ownership: u32 = 0x00200000;

/// A filesystem whose owners and modes mean what they say: on Linux one of the local filesystems
/// `linuxFsIsLocal` lists (not FUSE, whose server reports whatever it likes; not a network
/// filesystem, whose server decides who may write by rules that cannot be seen from here; nothing
/// unknown); on macOS a local one (`MNT_LOCAL`) not mounted by another user (a disk image they
/// attached) and not ignoring ownership. Pure.
pub fn checkMount(m: Mount, uid: u32) CheckError!void {
    if (m.linux_type) |t64| {
        const t: u32 = @truncate(t64);
        if (t == linux_fs.fuse) return error.FuseFilesystem;
        if (!linuxFsIsLocal(t)) return if (linuxFsIsNetwork(t)) error.NetworkFilesystem else error.UnknownFilesystem;
    }
    if (m.owner) |o| if (o != 0 and o != uid) return error.MountNotOurs;
    if (m.ignores_ownership) return error.MountIgnoresOwnership;
    if (m.local) |l| if (!l) return error.NetworkFilesystem;
}

/// One line of Linux's `/proc/self/mountinfo`, as `checkMountOrigin` needs it. The strings are as the
/// file has them (spaces and such written as octal escapes).
pub const MountInfo = struct {
    id: u64,
    mount_point: []const u8,
    options: []const u8,
    fstype: []const u8,
    source: []const u8,
    super_options: []const u8,
};

/// `ID PARENT MAJ:MIN ROOT MOUNT_POINT OPTIONS [OPTIONAL...] - FSTYPE SOURCE SUPER_OPTIONS`, or null
/// when the line is not one. Pure.
pub fn parseMountInfoLine(line: []const u8) ?MountInfo {
    var it = std.mem.tokenizeScalar(u8, line, ' ');
    const id = std.fmt.parseInt(u64, it.next() orelse return null, 10) catch return null;
    _ = it.next() orelse return null; // parent
    _ = it.next() orelse return null; // major:minor
    _ = it.next() orelse return null; // root
    const mount_point = it.next() orelse return null;
    const options = it.next() orelse return null;
    while (it.next()) |f| {
        if (std.mem.eql(u8, f, "-")) break;
    } else return null;
    const fstype = it.next() orelse return null;
    const source = it.next() orelse return null;
    const super_options = it.next() orelse "";
    return .{ .id = id, .mount_point = mount_point, .options = options, .fstype = fstype, .source = source, .super_options = super_options };
}

/// The line of `mountinfo` (the file's text) for mount `id`, or null. Pure.
pub fn findMountInfo(text: []const u8, id: u64) ?MountInfo {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        const mi = parseMountInfoLine(line) orelse continue;
        if (mi.id == id) return mi;
    }
    return null;
}

/// Whether `utab` (`/run/mount/utab`, where `mount` and udisks record mounts users made and their
/// helper options) lists the mount: by `ID=`, or by `TARGET=` (older entries have no ID). Pure.
pub fn utabLists(utab: []const u8, mi: MountInfo) bool {
    var lines = std.mem.splitScalar(u8, utab, '\n');
    while (lines.next()) |line| {
        var fields = std.mem.tokenizeAny(u8, line, " \t\r");
        while (fields.next()) |f| {
            if (std.mem.startsWith(u8, f, "ID=")) {
                const id = std.fmt.parseInt(u64, f[3..], 10) catch continue;
                if (id == mi.id) return true;
            } else if (std.mem.startsWith(u8, f, "TARGET=")) {
                if (std.mem.eql(u8, f[7..], mi.mount_point)) return true;
            }
        }
    }
    return false;
}

fn hasOption(list: []const u8, opt: []const u8) bool {
    var it = std.mem.tokenizeScalar(u8, list, ',');
    while (it.next()) |o| if (std.mem.eql(u8, o, opt)) return true;
    return false;
}

/// Linux: a mount a user made is refused, since its owners and modes are whatever the image or
/// device they brought says: one from a loop device (an image file), one udisks made
/// (`uhelper=udisks2`), or one `/run/mount/utab` lists. `mi` null (the mount could not be found) is
/// refused too; `utab` null means there is no such file. Pure.
pub fn checkMountOrigin(mi: ?MountInfo, utab: ?[]const u8) CheckError!void {
    const m = mi orelse return error.MountInfoUnreadable;
    if (std.mem.startsWith(u8, m.source, "/dev/loop")) return error.LoopMount;
    if (hasOption(m.options, "uhelper=udisks2") or hasOption(m.super_options, "uhelper=udisks2")) return error.UserMount;
    if (utab) |u| if (utabLists(u, m)) return error.UserMount;
}

/// macOS's `struct statfs` (64-bit inodes, the only layout on ARM64).
const DarwinStatfs = extern struct {
    f_bsize: u32,
    f_iosize: i32,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_owner: u32,
    f_type: u32,
    f_flags: u32,
    f_fssubtype: u32,
    f_fstypename: [16]u8,
    f_mntonname: [1024]u8,
    f_mntfromname: [1024]u8,
    f_flags_ext: u32,
    f_reserved: [7]u32,
};

comptime {
    std.debug.assert(@offsetOf(DarwinStatfs, "f_owner") == 56 and @sizeOf(DarwinStatfs) == 2168);
}

fn fdMount(fd: posix.fd_t) error{StatFailed}!Mount {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        // `struct statfs` starts with `f_type`, a word (`__fsword_t`): 8 bytes on the 64-bit systems
        // this is built for, read here as the first `usize`. Another word size needs another reading.
        if (@sizeOf(usize) != 8) @compileError("fdMount reads statfs.f_type as a 64-bit word; check struct statfs for this target");
        var buf: [64]usize = undefined;
        const rc = linux.syscall2(.fstatfs, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&buf));
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        var stx: linux.Statx = undefined;
        const rc2 = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .MNT_ID = true }, &stx);
        const id: ?u64 = if (linux.errno(rc2) == .SUCCESS and stx.mask.MNT_ID) stx.mnt_id else null;
        return .{ .linux_type = buf[0], .mnt_id = id };
    } else if (builtin.os.tag.isDarwin()) {
        // `DarwinStatfs` is the 64-bit layout (its size and offsets are checked above).
        if (@sizeOf(usize) != 8) @compileError("DarwinStatfs is the 64-bit macOS struct statfs");
        const fstatfs = @extern(*const fn (c_int, *DarwinStatfs) callconv(.c) c_int, .{ .name = if (builtin.cpu.arch == .x86_64) "fstatfs$INODE64" else "fstatfs" });
        var sb: DarwinStatfs = undefined;
        if (fstatfs(fd, &sb) != 0) return error.StatFailed;
        return .{
            .owner = sb.f_owner,
            .ignores_ownership = sb.f_flags & darwin_mnt_ignore_ownership != 0,
            .local = sb.f_flags & darwin_mnt_local != 0,
            .type_name = sb.f_fstypename,
        };
    } else @compileError("rweb checks filesystems on Linux and macOS only");
}

/// A small file's contents, or null when it does not exist. More than `limit` bytes is an error.
fn readSmallFile(arena: Allocator, io: Io, path: []const u8, limit: usize) error{ ReadFailed, TooLong, OutOfMemory }!?[]u8 {
    const fd = posix.openat(posix.AT.FDCWD, path, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| switch (e) {
        error.FileNotFound => return null,
        else => return error.ReadFailed,
    };
    defer closeFd(io, fd);
    var list: std.ArrayList(u8) = .empty;
    while (true) {
        try list.ensureUnusedCapacity(arena, 16 * 1024);
        const got = posix.read(fd, list.unusedCapacitySlice()) catch return error.ReadFailed;
        if (got == 0) break;
        list.items.len += got;
        if (list.items.len > limit) return error.TooLong;
    }
    return list.items;
}

/// Linux: the mount `id` is on, from `/proc/self/mountinfo` (in `arena`); null when it cannot be found.
fn linuxMountInfo(arena: Allocator, io: Io, id: ?u64) ?MountInfo {
    const text = (readSmallFile(arena, io, "/proc/self/mountinfo", 16 * 1024 * 1024) catch return null) orelse return null;
    return findMountInfo(text, id orelse return null);
}

// ---- access control lists ----

/// Linux POSIX ACL entry tags and the write permission, as `system.posix_acl_access` stores them.
pub const posix_acl = struct {
    pub const version: u32 = 2;
    pub const user_obj: u16 = 0x01;
    pub const user: u16 = 0x02;
    pub const group_obj: u16 = 0x04;
    pub const group: u16 = 0x08;
    pub const mask: u16 = 0x10;
    pub const other: u16 = 0x20;
    pub const write: u16 = 0x02;
};

/// Linux: whether a POSIX access ACL (the `system.posix_acl_access` value: a little-endian u32
/// version 2, then 8-byte entries {u16 tag, u16 perm, u32 id}) lets anyone change the file but root,
/// `uid` and safe groups. A named user's, a named group's and the owning group's write count only
/// through the mask; a named user other than root or `uid` with write is refused, and a named group or
/// the owning group (`file_gid`) with write passes only when `groupSafe` says so. The owner and
/// "other" entries are the mode's own bits, checked there. A blob that is not such a list is refused.
/// Default ACLs are not looked at: what they give a new file is cut by its mode, and rweb makes only
/// 0700 folders and 0600 files. On a refusal `who` (if given) names the entry's user or group. Pure.
pub fn checkPosixAcl(blob: []const u8, uid: u32, file_gid: u32, ctx: anytype, comptime groupSafe: fn (@TypeOf(ctx), u32) bool, who: ?*AclWho) CheckError!void {
    const A = posix_acl;
    if (blob.len < 4 or (blob.len - 4) % 8 != 0) return error.AclUnreadable;
    if (std.mem.readInt(u32, blob[0..4], .little) != A.version) return error.AclUnreadable;
    const entries = blob[4..];
    var mask: ?u16 = null;
    var i: usize = 0;
    while (i < entries.len) : (i += 8) {
        const tag = std.mem.readInt(u16, entries[i..][0..2], .little);
        const perm = std.mem.readInt(u16, entries[i + 2 ..][0..2], .little);
        switch (tag) {
            A.user_obj, A.user, A.group_obj, A.group, A.other => {},
            A.mask => {
                if (mask != null) return error.AclUnreadable;
                mask = perm;
            },
            else => return error.AclUnreadable,
        }
    }
    i = 0;
    while (i < entries.len) : (i += 8) {
        const tag = std.mem.readInt(u16, entries[i..][0..2], .little);
        const perm = std.mem.readInt(u16, entries[i + 2 ..][0..2], .little);
        const id = std.mem.readInt(u32, entries[i + 4 ..][0..4], .little);
        // Without a mask (a list of the three mode entries alone) nothing is cut.
        if (perm & (mask orelse 0o7) & A.write == 0) continue;
        const bad: AclWho = switch (tag) {
            A.user => if (id != 0 and id != uid) .{ .user = id } else continue,
            A.group => if (!groupSafe(ctx, id)) .{ .group = id } else continue,
            A.group_obj => if (!groupSafe(ctx, file_gid)) .{ .group = file_gid } else continue,
            else => continue,
        };
        if (who) |w| w.* = bad;
        return if (bad == .user) error.AclGivesOthersWrite else error.AclGivesGroupWrite;
    }
}

/// Linux: the access ACL of `fd`, in `buf`, or null when it has none (or the filesystem has no ACLs).
fn readPosixAcl(fd: posix.fd_t, buf: []u8) CheckError!?[]const u8 {
    const linux = std.os.linux;
    const rc = linux.fgetxattr(fd, "system.posix_acl_access", buf.ptr, buf.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => buf[0..rc],
        .NODATA, .OPNOTSUPP => null,
        else => error.AclUnreadable, // too long (ERANGE) included
    };
}

/// One macOS ACL entry, as `checkDarwinAcl` needs it.
pub const DarwinAce = struct {
    allow: bool,
    /// Applies only to what is created inside (`only_inherit`), not to this file or folder.
    only_inherit: bool = false,
    /// The `ACL_*` permission bits.
    perms: u64,
    who: Who,

    pub const Who = union(enum) { user: u32, group: u32, unknown };
};

pub const darwin_acl = struct {
    pub const read_data: u64 = 1 << 1;
    pub const write_data: u64 = 1 << 2;
    pub const execute: u64 = 1 << 3;
    pub const delete: u64 = 1 << 4;
    pub const append_data: u64 = 1 << 5;
    pub const delete_child: u64 = 1 << 6;
    pub const write_attributes: u64 = 1 << 8;
    pub const write_extattributes: u64 = 1 << 10;
    pub const write_security: u64 = 1 << 12;
    pub const change_owner: u64 = 1 << 13;
    /// What lets a user change a file or folder, or what a folder holds: write data or add a file,
    /// append or add a folder, delete a child, delete, change the ACL, take ownership.
    pub const changes: u64 = write_data | append_data | delete_child | delete | write_security | change_owner;
    /// What else a private file or folder must not give: read or list, run or enter, change attributes.
    pub const private_also: u64 = read_data | execute | write_attributes | write_extattributes;
    pub const max_entries = 128;
};

/// macOS's `everyone` group (it holds every user).
pub const darwin_everyone_gid: u32 = 12;

/// What an ACL is on: a folder on the way or a program (only changes count, and entries that only
/// pass on to new items are not this one's), or a private file or folder of ours (any access counts,
/// and so do entries new items would inherit, such as an upload).
pub const AclUse = enum { shared, private };

/// macOS: whether ACL `entries` let anyone but root or `uid` change the file or folder
/// (`darwin_acl.changes`), or, when `private`, have any access to it. A group is trusted only on a
/// folder on the way or a program (`shared`), and only when `groupSafe` says so (`admin`; never
/// `everyone`); a private file or folder accepts no group at all. Deny entries (such as every home
/// folder's `everyone deny delete`) take nothing away from the mode's answer, so they pass. An entry
/// whose user or group is not known counts as another user's. On a refusal `who` (if given) names
/// the entry's user or group. Pure.
pub fn checkDarwinAcl(entries: []const DarwinAce, uid: u32, use: AclUse, ctx: anytype, comptime groupSafe: fn (@TypeOf(ctx), u32) bool, who: ?*AclWho) CheckError!void {
    for (entries) |e| {
        if (!e.allow) continue;
        if (use == .shared and e.only_inherit) continue;
        const relevant = darwin_acl.changes | (if (use == .private) darwin_acl.private_also else 0);
        if (e.perms & relevant == 0) continue;
        const bad: AclWho = switch (e.who) {
            .user => |u| if (u == 0 or u == uid) continue else .{ .user = u },
            .group => |g| if (g == darwin_everyone_gid) .everyone else if (use == .shared and groupSafe(ctx, g)) continue else .{ .group = g },
            .unknown => .unknown,
        };
        if (who) |w| w.* = bad;
        const writes = e.perms & darwin_acl.changes != 0;
        if (bad == .group) return if (writes) error.AclGivesGroupWrite else error.AclGivesGroupAccess;
        return if (writes) error.AclGivesOthersWrite else error.AclGivesOthersAccess;
    }
}

extern "c" fn acl_get_fd_np(fd: c_int, ty: c_int) ?*anyopaque;
extern "c" fn acl_set_fd_np(fd: c_int, acl: ?*anyopaque, ty: c_int) c_int;
extern "c" fn acl_init(count: c_int) ?*anyopaque;
extern "c" fn acl_free(obj: ?*anyopaque) c_int;
extern "c" fn acl_get_entry(acl: ?*anyopaque, entry_id: c_int, entry: *?*anyopaque) c_int;
extern "c" fn acl_get_tag_type(entry: ?*anyopaque, tag: *c_int) c_int;
extern "c" fn acl_get_permset_mask_np(entry: ?*anyopaque, mask: *u64) c_int;
extern "c" fn acl_get_flagset_np(obj: ?*anyopaque, flagset: *?*anyopaque) c_int;
extern "c" fn acl_get_flag_np(flagset: ?*anyopaque, flag: c_int) c_int;
extern "c" fn acl_get_qualifier(entry: ?*anyopaque) ?*anyopaque;
extern "c" fn mbr_uuid_to_id(uu: *const [16]u8, id: *u32, id_type: *c_int) c_int;

const ACL_TYPE_EXTENDED: c_int = 0x100;
const ACL_FIRST_ENTRY: c_int = 0;
const ACL_NEXT_ENTRY: c_int = -1;
const ACL_EXTENDED_ALLOW: c_int = 1;
const ACL_EXTENDED_DENY: c_int = 2;
const ACL_ENTRY_ONLY_INHERIT: c_int = 1 << 8;
const ID_TYPE_UID: c_int = 0;
const ID_TYPE_GID: c_int = 1;

/// macOS: the extended ACL entries of `fd`, in `out`; none when it has no ACL.
fn readDarwinAcl(fd: posix.fd_t, out: []DarwinAce) CheckError![]const DarwinAce {
    const acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) orelse {
        const err = std.c._errno().*;
        // ENOENT: no ACL; ENOTSUP (std's `OPNOTSUPP`, 45 on macOS) or EOPNOTSUPP (102, which std's
        // `E` does not name): a filesystem without ACLs.
        const darwin_eopnotsupp: c_int = 102;
        return if (err == @intFromEnum(std.c.E.NOENT) or err == @intFromEnum(std.c.E.OPNOTSUPP) or err == darwin_eopnotsupp) out[0..0] else error.AclUnreadable;
    };
    defer _ = acl_free(acl);
    var n: usize = 0;
    var ace: ?*anyopaque = null;
    var which = ACL_FIRST_ENTRY;
    while (acl_get_entry(acl, which, &ace) == 0) : (which = ACL_NEXT_ENTRY) {
        if (n == out.len) return error.AclUnreadable;
        var tag: c_int = 0;
        var perms: u64 = 0;
        var flags: ?*anyopaque = null;
        if (acl_get_tag_type(ace, &tag) != 0 or acl_get_permset_mask_np(ace, &perms) != 0 or acl_get_flagset_np(ace, &flags) != 0) return error.AclUnreadable;
        if (tag != ACL_EXTENDED_ALLOW and tag != ACL_EXTENDED_DENY) return error.AclUnreadable;
        var who: DarwinAce.Who = .unknown;
        if (acl_get_qualifier(ace)) |q| {
            defer _ = acl_free(q);
            var id: u32 = 0;
            var id_type: c_int = -1;
            if (mbr_uuid_to_id(@ptrCast(q), &id, &id_type) == 0) {
                if (id_type == ID_TYPE_UID) who = .{ .user = id } else if (id_type == ID_TYPE_GID) who = .{ .group = id };
            }
        }
        out[n] = .{ .allow = tag == ACL_EXTENDED_ALLOW, .only_inherit = acl_get_flag_np(flags, ACL_ENTRY_ONLY_INHERIT) == 1, .perms = perms, .who = who };
        n += 1;
    }
    return out[0..n];
}

/// macOS: give a folder rweb just made an empty ACL, so it holds none of the inheritable entries of
/// the folder it was made in. Best effort: the folder's check that follows refuses what is left.
fn dropInheritedAcl(fd: posix.fd_t) void {
    if (!builtin.os.tag.isDarwin()) return;
    const empty = acl_init(0) orelse return;
    defer _ = acl_free(empty);
    _ = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED);
}

// ---- checks on a descriptor ----

/// `groupAnswer` as the predicate the ACL rules take.
const GroupRule = struct {
    fn safe(_: GroupRule, gid: u32) bool {
        return groupAnswer(gid);
    }
};

/// Whether the group-write bit of `om` (a folder or program of root's or ours that nobody else may
/// write to) is safe. On Linux with an ACL that bit is the ACL's mask, so each entry it lets write is
/// decided (`checkPosixAcl`); otherwise the file's group must be a safe one (`groupAnswer`).
fn groupWriteSafe(fd: posix.fd_t, om: OwnerMode, uid: u32, p: ?*Problem) CheckError!bool {
    if (builtin.os.tag == .linux) {
        var buf: [16 * 1024]u8 = undefined;
        if (try readPosixAcl(fd, &buf)) |blob| {
            try checkPosixAcl(blob, uid, om.gid, GroupRule{}, GroupRule.safe, if (p) |pp| &pp.acl_who else null);
            return true;
        }
    }
    return groupAnswer(om.gid);
}

/// What every checked descriptor must pass besides its owner and mode: its filesystem
/// (`checkMount`, and on Linux `checkMountOrigin`) and, on macOS, its ACL (`checkDarwinAcl`; on Linux
/// the mode's group bits bound what an ACL gives, see `groupWriteSafe`).
fn checkFdExtras(gpa: Allocator, io: Io, fd: posix.fd_t, uid: u32, use: AclUse, p: ?*Problem) CheckError!void {
    const m = fdMount(fd) catch return error.StatFailed;
    if (builtin.os.tag == .linux) {
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const a = arena_state.allocator();
        const mi = linuxMountInfo(a, io, m.mnt_id);
        if (p) |pp| {
            pp.setFsType(if (mi) |x| x.fstype else linuxFsName(@truncate(m.linux_type orelse 0)));
            if (mi) |x| pp.setDetail(x.source);
        }
        try checkMount(m, uid);
        const utab = readSmallFile(a, io, "/run/mount/utab", 4 * 1024 * 1024) catch return error.MountInfoUnreadable;
        try checkMountOrigin(mi, utab);
    } else {
        if (p) |pp| {
            pp.setFsType(std.mem.sliceTo(&m.type_name, 0));
            pp.mount_owner = m.owner;
        }
        try checkMount(m, uid);
    }
    if (builtin.os.tag.isDarwin()) {
        var aces: [darwin_acl.max_entries]DarwinAce = undefined;
        try checkDarwinAcl(try readDarwinAcl(fd, &aces), uid, use, GroupRule{}, GroupRule.safe, if (p) |pp| &pp.acl_who else null);
    }
}

fn noteFound(p: ?*Problem, role: Role, om: OwnerMode) void {
    if (p) |pp| {
        pp.look(role);
        pp.found = om;
    }
}

fn checkAncestorFd(gpa: Allocator, io: Io, fd: posix.fd_t, uid: u32, p: ?*Problem) CheckError!void {
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    noteFound(p, .folder_above, om);
    // The ACL (Linux) is looked at only when the answer depends on it.
    const ask = groupDecides(om) and (om.uid == 0 or om.uid == uid) and om.mode & S_IFMT == S_IFDIR;
    try checkAncestor(om, uid, ask and try groupWriteSafe(fd, om, uid, p));
    try checkFdExtras(gpa, io, fd, uid, .shared, p);
}

/// A program on an open descriptor: `checkProgram`, an ACL that lets nobody else change it, and a
/// filesystem whose owners mean what they say.
pub fn checkProgramFd(gpa: Allocator, io: Io, fd: posix.fd_t, uid: u32, p: ?*Problem) CheckError!void {
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    noteFound(p, .program, om);
    const ask = om.mode & S_IFMT == S_IFREG and (om.uid == 0 or om.uid == uid) and om.mode & 0o020 != 0 and om.mode & 0o002 == 0;
    try checkProgram(om, uid, ask and try groupWriteSafe(fd, om, uid, p));
    try checkFdExtras(gpa, io, fd, uid, .shared, p);
}

/// A private folder (the upload folder, the socket's) on an open descriptor: `checkPrivateDir`, an
/// ACL that gives nobody else any access, and a filesystem whose owners mean what they say.
pub fn checkPrivateDirFd(gpa: Allocator, io: Io, fd: posix.fd_t) CheckError!void {
    return checkPrivateDirFdDetailed(gpa, io, fd, null);
}

/// `checkPrivateDirFd`, leaving what it found in `problem` for `explain` (its `path` is the caller's).
pub fn checkPrivateDirFdDetailed(gpa: Allocator, io: Io, fd: posix.fd_t, problem: ?*Problem) CheckError!void {
    const uid = myUid();
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    noteFound(problem, .private_folder, om);
    try checkPrivateDir(om, uid);
    try checkFdExtras(gpa, io, fd, uid, .private, problem);
}

fn checkPrivateFileFd(gpa: Allocator, io: Io, fd: posix.fd_t, p: ?*Problem) CheckError!void {
    const uid = myUid();
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    noteFound(p, .private_file, om);
    try checkPrivateFile(om, uid);
    try checkFdExtras(gpa, io, fd, uid, .private, p);
}

pub const OpenError = CheckError || posix.OpenError || Io.Dir.RealPathFileAllocError || Io.Dir.CreateDirError || Allocator.Error;

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

/// `name` in folder `fd`, opened as a folder without following a link; with `create`, made 0700
/// there first if it is missing, without the ACL entries it would inherit (macOS). The caller closes
/// it and checks it.
pub fn openFolderAt(io: Io, fd: posix.fd_t, name: []const u8, create: bool) OpenError!posix.fd_t {
    const flags: posix.O = .{ .DIRECTORY = true, .NOFOLLOW = true, .CLOEXEC = true };
    if (posix.openat(fd, name, flags, 0)) |got| return got else |e| {
        if (e != error.FileNotFound or !create) return folderOpenFailed(fd, name, e);
    }
    var made = true;
    (Io.Dir{ .handle = fd }).createDir(io, name, @enumFromInt(0o700)) catch |e| switch (e) {
        error.PathAlreadyExists => made = false, // made meanwhile, by us or root (the folder passed its check)
        else => return e,
    };
    const got = posix.openat(fd, name, flags, 0) catch |e| return folderOpenFailed(fd, name, e);
    if (made) dropInheritedAcl(got);
    return got;
}

fn folderOpenFailed(fd: posix.fd_t, name: []const u8, e: posix.OpenError) OpenError {
    // A link to a folder fails as "not a directory" on some systems: say what it is.
    if (e == error.NotDir) if (statAt(fd, name)) |n| {
        if (n.mode & S_IFMT == S_IFLNK) return error.SymLink;
    } else |_| {};
    return openFailed(e);
}

/// `name` in `dir_fd` was refused as a link: note what it is and where it leads, for the message.
fn noteLink(p: *Problem, dir_fd: posix.fd_t, name: []const u8) void {
    p.look(.link);
    if (statAt(dir_fd, name)) |n| {
        p.found = .{ .uid = n.uid, .gid = n.gid, .mode = n.mode };
    } else |_| {}
    var tbuf: [max_path]u8 = undefined;
    if (readLinkAt(dir_fd, name, &tbuf)) |t| p.setDetail(t) else |_| {}
}

/// The checked walk of a path, from `/`, one name at a time: each folder is opened without following
/// a link from the folder before it, which already passed `checkAncestor`, and is checked in turn. A
/// link met on the way must be root's or ours (`checkLink`); its target is read from the checked
/// folder that holds it, and the walk goes on from there (from `/` for an absolute target), at most
/// `max_link_hops` links in all. `..` is followed only inside a link's target; in the given path it
/// is refused, as is anything but an absolute path. What failed is left in `problem`: a slice of the
/// given path while the walk is on it, the folders it resolved once it has followed a link.
const Walker = struct {
    /// For the checks' passing needs (`checkFdExtras`), freed before each check returns.
    gpa: Allocator,
    io: Io,
    uid: u32,
    fd: posix.fd_t,
    problem: *Problem,
    given: []const u8,
    /// What is left to walk: `rest[pos..end]`; its last `given_left` bytes are the given path's.
    rest: [2 * max_path]u8,
    pos: usize,
    end: usize,
    given_left: usize,
    /// The path of `fd`, no link on it: `problem.buf[0..canon_len]` ("" for `/`).
    canon_len: usize,
    hops: u32,

    const Comp = struct { name: []const u8, given: bool, last: bool, end: usize };

    /// What the last name of the path is: a folder to open (`folder`), a name to return unopened
    /// (`name`), or one to return once any links it is are followed (`name_follow`).
    const Last = enum { folder, name, name_follow };

    fn init(w: *Walker, gpa: Allocator, io: Io, given: []const u8, problem: *Problem) OpenError!void {
        problem.setPath(given);
        if (given.len == 0 or given[0] != '/') return error.BadPath;
        if (given.len > max_path) return error.NameTooLong;
        w.gpa = gpa;
        w.io = io;
        w.uid = myUid();
        w.fd = -1;
        w.problem = problem;
        w.given = given;
        @memcpy(w.rest[0..given.len], given);
        w.pos = 0;
        w.end = given.len;
        w.given_left = given.len;
        w.canon_len = 0;
        w.hops = 0;
        problem.setPath("/");
        try w.toRoot();
    }

    fn deinit(w: *Walker) void {
        if (w.fd >= 0) closeFd(w.io, w.fd);
        w.fd = -1;
    }

    /// The descriptor the walk ended on; the caller closes it.
    fn take(w: *Walker) posix.fd_t {
        const fd = w.fd;
        w.fd = -1;
        return fd;
    }

    /// The path of the folder the walk is in, with every link on the way resolved.
    fn canonical(w: *const Walker) []const u8 {
        return if (w.canon_len == 0) "/" else w.problem.buf[0..w.canon_len];
    }

    fn toRoot(w: *Walker) OpenError!void {
        if (w.fd >= 0) closeFd(w.io, w.fd);
        w.fd = -1;
        w.canon_len = 0;
        w.fd = posix.openat(posix.AT.FDCWD, "/", .{ .DIRECTORY = true, .CLOEXEC = true }, 0) catch |e| return openFailed(e);
        try checkAncestorFd(w.gpa, w.io, w.fd, w.uid, w.problem);
    }

    fn next(w: *Walker) ?Comp {
        while (w.pos < w.end and w.rest[w.pos] == '/') w.pos += 1;
        if (w.pos == w.end) return null;
        const start = w.pos;
        while (w.pos < w.end and w.rest[w.pos] != '/') w.pos += 1;
        const given = start >= w.end - w.given_left;
        w.given_left = @min(w.given_left, w.end - w.pos);
        var p = w.pos;
        while (p < w.end and w.rest[p] == '/') p += 1;
        return .{ .name = w.rest[start..w.pos], .given = given, .last = p == w.end, .end = w.pos };
    }

    /// Point the problem's path at the name about to be looked at.
    fn blame(w: *Walker, c: Comp) void {
        const p = w.problem;
        p.look(.folder_above);
        if (c.given) {
            p.setPath(w.given[0 .. w.given.len - (w.end - c.end)]);
            return;
        }
        if (w.canon_len + 1 + c.name.len > p.buf.len) {
            p.setPath(w.given);
            return;
        }
        p.buf[w.canon_len] = '/';
        @memcpy(p.buf[w.canon_len + 1 ..][0..c.name.len], c.name);
        p.setPath(p.buf[0 .. w.canon_len + 1 + c.name.len]);
    }

    /// Go into folder `next_fd`, called `name`, opened from the current one, and check it.
    fn enter(w: *Walker, next_fd: posix.fd_t, name: []const u8) OpenError!void {
        closeFd(w.io, w.fd);
        w.fd = next_fd;
        if (w.canon_len + 1 + name.len > w.problem.buf.len) return error.NameTooLong;
        w.problem.buf[w.canon_len] = '/';
        @memcpy(w.problem.buf[w.canon_len + 1 ..][0..name.len], name);
        w.canon_len += 1 + name.len;
        try checkAncestorFd(w.gpa, w.io, w.fd, w.uid, w.problem);
    }

    /// `..` inside a link's target: the folder above, which the walk already passed through.
    fn up(w: *Walker) OpenError!void {
        if (w.canon_len == 0) return; // `/..` is `/`
        const parent = posix.openat(w.fd, "..", .{ .DIRECTORY = true, .CLOEXEC = true }, 0) catch |e| return openFailed(e);
        closeFd(w.io, w.fd);
        w.fd = parent;
        w.canon_len = std.mem.lastIndexOfScalar(u8, w.problem.buf[0..w.canon_len], '/') orelse 0;
        w.problem.setPath(w.canonical());
        try checkAncestorFd(w.gpa, w.io, w.fd, w.uid, w.problem);
    }

    /// The name `name` in the current (checked) folder is a link: check it, and walk its target
    /// next, before what is left of the path.
    fn follow(w: *Walker, name: []const u8) OpenError!void {
        const p = w.problem;
        p.look(.link);
        const n = statAt(w.fd, name) catch |e| return switch (e) {
            error.FileNotFound => error.FileNotFound,
            error.NameTooLong => error.NameTooLong,
            error.StatFailed => error.StatFailed,
        };
        const om: OwnerMode = .{ .uid = n.uid, .gid = n.gid, .mode = n.mode };
        p.found = om;
        var tbuf: [max_path]u8 = undefined;
        const target = if (om.mode & S_IFMT == S_IFLNK) readLinkAt(w.fd, name, &tbuf) catch |e| return switch (e) {
            error.NameTooLong => error.NameTooLong,
            error.ReadFailed => error.ReadFailed,
        } else "";
        p.setDetail(target);
        try checkLink(om, w.uid);
        w.hops += 1;
        if (w.hops > max_link_hops) return error.TooManyLinks;
        if (target.len == 0) return error.BadPath;
        // The target, then what was left: rest = target ++ "/" ++ rest[pos..end].
        const left = w.end - w.pos;
        if (target.len + 1 + left > w.rest.len) return error.NameTooLong;
        const dst = target.len + 1;
        if (dst <= w.pos) std.mem.copyForwards(u8, w.rest[dst..][0..left], w.rest[w.pos..w.end]) else std.mem.copyBackwards(u8, w.rest[dst..][0..left], w.rest[w.pos..w.end]);
        @memcpy(w.rest[0..target.len], target);
        w.rest[target.len] = '/';
        w.pos = 0;
        w.end = dst + left;
        if (target[0] == '/') try w.toRoot();
    }

    /// Walk the path. For `folder` the walk ends in the last folder (made 0700 if missing, with
    /// `create`, as are missing folders above it) and returns ""; otherwise it ends in the folder
    /// that holds the last name and returns that name (a slice valid while `w` lives).
    fn walk(w: *Walker, last: Last, create: bool) OpenError![]const u8 {
        while (w.next()) |c| {
            w.blame(c);
            const is_last = c.last and last != .folder;
            if (std.mem.eql(u8, c.name, ".")) {
                if (is_last) return error.BadPath;
                continue;
            }
            if (std.mem.eql(u8, c.name, "..")) {
                if (c.given or is_last) return error.BadPath;
                try w.up();
                continue;
            }
            if (is_last) {
                if (last == .name_follow) {
                    const n = statAt(w.fd, c.name) catch |e| switch (e) {
                        error.FileNotFound => return c.name,
                        error.NameTooLong => return error.NameTooLong,
                        error.StatFailed => return error.StatFailed,
                    };
                    if (n.mode & S_IFMT == S_IFLNK) {
                        try w.follow(c.name);
                        continue;
                    }
                }
                return c.name;
            }
            const next_fd = openFolderAt(w.io, w.fd, c.name, create) catch |e| switch (e) {
                error.SymLink => {
                    try w.follow(c.name);
                    continue;
                },
                else => return e,
            };
            try w.enter(next_fd, c.name);
        }
        if (last != .folder) return error.BadPath; // the path was `/` alone
        return "";
    }
};

/// Open the folder at the absolute path `dir` by the checked walk (`Walker`): every folder on the
/// way passes `checkAncestor`, and so does this one; a link on the way is followed only when root or
/// we own it, from a folder that passed. With `create`, a missing folder is made 0700 inside its
/// checked parent, then checked like the rest. The caller closes the descriptor; on failure
/// `problem` says where and what.
pub fn openChain(gpa: Allocator, io: Io, dir: []const u8, create: bool, problem: *Problem) OpenError!posix.fd_t {
    var w: Walker = undefined;
    try w.init(gpa, io, dir, problem);
    defer w.deinit();
    _ = try w.walk(.folder, create);
    return w.take();
}

/// The contents of a private file, at most `limit` bytes, read from the descriptor that was checked:
/// the folders above it walked and checked from `/` (`Walker`; a relative path is taken from the
/// current folder's real path), the file opened in the last of them without following a link (and
/// without blocking, so a FIFO cannot hang startup); then it must be a regular file of ours that
/// group and others cannot read. On failure `problem` says where and what.
pub fn readPrivateFile(arena: Allocator, io: Io, path: []const u8, limit: usize, problem: *Problem) OpenError![]u8 {
    problem.setPath(path);
    if (path.len == 0) return error.BadPath;
    const abs = if (path[0] == '/') path else blk: {
        var cwd_buf: [max_path]u8 = undefined;
        const n = std.process.currentPath(io, &cwd_buf) catch return error.BadPath;
        break :blk try std.fs.path.join(arena, &.{ cwd_buf[0..n], path });
    };
    var w: Walker = undefined;
    try w.init(arena, io, abs, problem);
    defer w.deinit();
    const name = try w.walk(.name, false);
    problem.setPath(path);
    problem.look(.private_file);
    const fd = posix.openat(w.fd, name, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| {
        const err = openFailed(e);
        if (err == error.SymLink) noteLink(problem, w.fd, name);
        return err;
    };
    defer closeFd(io, fd);
    try checkPrivateFileFd(arena, io, fd, problem);
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

/// The upload folder, opened and kept by the caller for as long as uploads may go into it, and its
/// real path (what is pasted into the terminal and shown to the page). The folders above it are
/// walked and checked from `/` (`Walker`; missing ones are made 0700, each inside its checked
/// parent); the folder itself is made 0700 if missing, opened without following a link and must be a
/// private folder of ours.
pub const UploadDir = struct { dir: Io.Dir, real_path: []const u8 };

pub fn openUploadDir(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError!UploadDir {
    problem.setPath(path);
    const trimmed = std.mem.trimEnd(u8, path, "/");
    if (trimmed.len == 0 or trimmed[0] != '/') return error.BadPath;
    var w: Walker = undefined;
    try w.init(arena, io, trimmed, problem);
    defer w.deinit();
    const base = try w.walk(.name, true);
    const real_path = try std.fs.path.join(arena, &.{ w.canonical(), base });
    problem.setPath(path);
    problem.look(.private_folder);
    const fd = openFolderAt(io, w.fd, base, true) catch |e| {
        if (e == error.SymLink) noteLink(problem, w.fd, base);
        return e;
    };
    errdefer closeFd(io, fd);
    try checkPrivateDirFdDetailed(arena, io, fd, problem);
    return .{ .dir = .{ .handle = fd }, .real_path = real_path };
}

/// The program at `path`, checked, and the exact path to run it by. The path is walked and checked
/// from `/` (`Walker`), links on it (the program's own name included) followed only from checked
/// folders and only when root or we own them; the program is opened inside the last folder without
/// following a link and checked on that descriptor (`checkProgramFd`). The path returned is that
/// folder's resolved path joined with the program's name: no link on it, every folder on it fixed, it
/// leads to the file that was checked. On failure `problem` says where and what.
pub fn checkedProgram(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError![]const u8 {
    problem.setPath(path);
    if (path.len == 0 or path[0] != '/') return error.BadPath;
    var w: Walker = undefined;
    try w.init(arena, io, path, problem);
    defer w.deinit();
    const base = try w.walk(.name_follow, false);
    const full = try std.fs.path.join(arena, &.{ w.canonical(), base });
    problem.setPath(full);
    problem.look(.program);
    // Without blocking, so a FIFO put there cannot hang startup; it then fails as not a regular file.
    const fd = posix.openat(w.fd, base, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| return openFailed(e);
    defer closeFd(io, fd);
    try checkProgramFd(arena, io, fd, myUid(), problem);
    return full;
}

// ---- plain-language messages ----

/// What `explain` asks of the system, so its text can be tested with made-up names.
pub const Names = struct {
    /// `$HOME`: paths under it are shown as `~/...`.
    home: ?[]const u8,
    /// The fixes for access lists differ: `chmod -N` on macOS, `setfacl -b` on Linux.
    darwin: bool,
    /// Our own uid: a link of ours (or root's) may be named as the way to the real path.
    uid: u32,
    user: *const fn (uid: u32, buf: []u8) ?[]const u8,
    group: *const fn (gid: u32, buf: []u8) ?[]const u8,

    pub fn system() Names {
        return .{
            .home = if (std.c.getenv("HOME")) |h| std.mem.span(h) else null,
            .darwin = builtin.os.tag.isDarwin(),
            .uid = myUid(),
            .user = systemUser,
            .group = systemGroup,
        };
    }
};

/// A user's name, for a message only (never for a decision).
fn systemUser(uid: u32, buf: []u8) ?[]const u8 {
    const pw = std.c.getpwuid(@intCast(uid)) orelse return null;
    const name = std.mem.span(pw.name orelse return null);
    if (name.len == 0 or name.len > buf.len) return null;
    @memcpy(buf[0..name.len], name);
    return buf[0..name.len];
}

/// A group's name, for a message only (never for a decision).
fn systemGroup(gid: u32, buf: []u8) ?[]const u8 {
    const gr = std.c.getgrgid(@intCast(gid)) orelse return null;
    const name = std.mem.span(gr.name orelse return null);
    if (name.len == 0 or name.len > buf.len) return null;
    @memcpy(buf[0..name.len], name);
    return buf[0..name.len];
}

/// The shortest secret (token or backend secret) rweb accepts from a file.
pub const min_secret_len = 32;

/// What a refusal's fix may say beyond the path: the option that names the item or its folder, and
/// whether the item is a layout's own file (which rweb makes again when it is missing).
pub const Hints = struct {
    /// The option that names the item itself (`--token-file`, `--upload-dir`, `--listen-unix`).
    item_option: ?[]const u8 = null,
    /// The option that names the folder the item is kept in (`--config-dir`).
    folder_option: ?[]const u8 = null,
    made_by_rweb: bool = false,
};

/// Say, in two lines, why rweb will not use `path` for `what` (a short noun phrase: "its token", "the
/// backend secret", "the upload folder", "the socket folder", "the tailscale program"), and the
/// command that fixes it, from the error and what the check left in `problem`. For example:
///
///     rweb: ~/.config can be changed by members of group "me" (mode 0775); rweb keeps its token under it.
///       Fix: chmod g-w ~/.config
///
/// Paths under `$HOME` are shown as `~/...`; user and group names are looked up for the message only.
/// Every text that did not come from rweb (paths, a link's target, user and group names, a
/// filesystem's type and source) is printed through `Clean`.
pub fn explain(w: *Io.Writer, what: []const u8, path: []const u8, err: anyerror, problem: *const Problem, hints: Hints) Io.Writer.Error!void {
    return explainWith(w, what, path, err, problem, hints, Names.system());
}

/// Whether byte `s[i]` starts something that must not reach a terminal as it is: a C0 control byte,
/// DEL, a C1 control (U+0080 to U+009F) in UTF-8, or a byte that is not part of valid UTF-8. The
/// length of what it starts (1 for a printable ASCII byte that is fine).
fn unsafeAt(s: []const u8, i: usize) struct { bad: bool, len: usize } {
    const b = s[i];
    if (b < 0x80) return .{ .bad = b < 0x20 or b == 0x7f, .len = 1 };
    const n = std.unicode.utf8ByteSequenceLength(b) catch return .{ .bad = true, .len = 1 };
    if (i + n > s.len) return .{ .bad = true, .len = 1 };
    const cp = std.unicode.utf8Decode(s[i..][0..n]) catch return .{ .bad = true, .len = 1 };
    return .{ .bad = cp >= 0x80 and cp <= 0x9f, .len = n };
}

fn hasUnsafe(s: []const u8) bool {
    var i: usize = 0;
    while (i < s.len) {
        const u = unsafeAt(s, i);
        if (u.bad) return true;
        i += u.len;
    }
    return false;
}

/// Text that did not come from rweb, as printed in a sentence: each control byte (C0, DEL, C1 in
/// UTF-8) and each byte that is not valid UTF-8 becomes `?`, so the text cannot move the cursor,
/// change the terminal or start a line that looks like rweb's.
pub const Clean = struct {
    s: []const u8,

    pub fn format(c: Clean, w: *Io.Writer) Io.Writer.Error!void {
        var i: usize = 0;
        while (i < c.s.len) {
            const u = unsafeAt(c.s, i);
            if (u.bad) try w.writeByte('?') else try w.writeAll(c.s[i..][0..u.len]);
            i += u.len;
        }
    }
};

/// A path as shown: `~/...` under home, through `Clean`.
const Shown = struct {
    path: []const u8,
    names: *const Names,
    /// For a command: quoted for a POSIX shell when it needs it (`~/` stays outside the quotes); a
    /// path with a control byte in it is written `$'...'` with that byte as `\xNN` (bash and zsh).
    shell: bool = false,

    pub fn format(s: Shown, w: *Io.Writer) Io.Writer.Error!void {
        var rest = s.path;
        var tilde = false;
        if (s.names.home) |h0| {
            const h = std.mem.trimEnd(u8, h0, "/");
            if (h.len > 0 and std.mem.startsWith(u8, s.path, h)) {
                if (s.path.len == h.len) return w.writeAll("~");
                if (s.path[h.len] == '/') {
                    tilde = true;
                    rest = s.path[h.len + 1 ..];
                }
            }
        }
        if (tilde) try w.writeAll("~/");
        if (!s.shell) return w.print("{f}", .{Clean{ .s = rest }});
        if (shellSafe(rest)) return w.writeAll(rest);
        if (hasUnsafe(rest)) {
            try w.writeAll("$'");
            var i: usize = 0;
            while (i < rest.len) {
                const u = unsafeAt(rest, i);
                if (u.bad) {
                    for (rest[i..][0..u.len]) |b| try w.print("\\x{x:0>2}", .{b});
                } else if (rest[i] == '\'' or rest[i] == '\\') {
                    try w.writeByte('\\');
                    try w.writeByte(rest[i]);
                } else try w.writeAll(rest[i..][0..u.len]);
                i += u.len;
            }
            return w.writeByte('\'');
        }
        try w.writeByte('\'');
        for (rest) |c| if (c == '\'') try w.writeAll("'\\''") else try w.writeByte(c);
        try w.writeByte('\'');
    }
};

fn shellSafe(s: []const u8) bool {
    if (s.len == 0) return false;
    for (s) |c| if (!(std.ascii.isAlphanumeric(c) or std.mem.indexOfScalar(u8, "/._-+,:@%", c) != null)) return false;
    return true;
}

/// A user, as named in a message: `you`, `root`, or `user "name"`.
const UserName = struct {
    uid: u32,
    names: *const Names,

    pub fn format(u: UserName, w: *Io.Writer) Io.Writer.Error!void {
        if (u.uid == 0) return w.writeAll("root");
        var buf: [256]u8 = undefined;
        if (u.names.user(u.uid, &buf)) |n| return w.print("user \"{f}\"", .{Clean{ .s = n }});
        return w.print("user {d}", .{u.uid});
    }
};

/// A group, as named in a message: `group "name"`.
const GroupName = struct {
    gid: u32,
    names: *const Names,

    pub fn format(g: GroupName, w: *Io.Writer) Io.Writer.Error!void {
        var buf: [256]u8 = undefined;
        if (g.names.group(g.gid, &buf)) |n| return w.print("group \"{f}\"", .{Clean{ .s = n }});
        return w.print("group {d}", .{g.gid});
    }
};

/// ` (mode 0775)`, or nothing when the mode is not known.
const ModeNote = struct {
    om: ?OwnerMode,

    pub fn format(m: ModeNote, w: *Io.Writer) Io.Writer.Error!void {
        const om = m.om orelse return;
        try w.print(" (mode {o:0>4})", .{om.mode & 0o7777});
    }
};

/// Who an access list entry lets in, as named in a message.
const AclName = struct {
    who: AclWho,
    names: *const Names,

    pub fn format(a: AclName, w: *Io.Writer) Io.Writer.Error!void {
        switch (a.who) {
            .user => |u| try w.print("{f}", .{UserName{ .uid = u, .names = a.names }}),
            .group => |g| try w.print("members of {f}", .{GroupName{ .gid = g, .names = a.names }}),
            .everyone => try w.writeAll("every user on this machine"),
            .unknown => try w.writeAll("an account this machine does not know"),
            .none => try w.writeAll("another user"),
        }
    }
};

/// ` (text)`, through `Clean`, or nothing.
const Paren = struct {
    s: []const u8,

    pub fn format(p: Paren, w: *Io.Writer) Io.Writer.Error!void {
        if (p.s.len > 0) try w.print(" ({f})", .{Clean{ .s = p.s }});
    }
};

/// ` to <target>`, through `Clean`, or nothing.
const LinkTo = struct {
    target: []const u8,

    pub fn format(l: LinkTo, w: *Io.Writer) Io.Writer.Error!void {
        if (l.target.len > 0) try w.print(" to {f}", .{Clean{ .s = l.target }});
    }
};

/// `explain`, with the system's answers in `names`.
pub fn explainWith(w: *Io.Writer, what: []const u8, path: []const u8, err: anyerror, problem: *const Problem, hints: Hints, names: Names) Io.Writer.Error!void {
    const n = &names;
    const where = if (problem.pathText().len > 0) problem.pathText() else path;
    const at_item = std.mem.eql(u8, where, path);
    const P: Shown = .{ .path = where, .names = n };
    const Q: Shown = .{ .path = where, .names = n, .shell = true };
    const om = problem.found;
    const mode = ModeNote{ .om = om };
    const socket_dir = err == error.SocketDirNotOurs or err == error.SocketDirNotPrivate; // server.zig's names
    const is_dir = socket_dir or if (om) |o| o.mode & S_IFMT == S_IFDIR else problem.role == .private_folder;
    const local_disk = "keep rweb's files on a local disk: --config-dir /local/path";
    const own_disk = "use a folder on your own disk";
    const target = problem.detail();
    // A link may be named as the way to the real path only when root or we own it: another user's
    // link leads wherever that user chose.
    const link_ours = if (om) |o| o.mode & S_IFMT == S_IFLNK and (o.uid == 0 or o.uid == n.uid) else false;

    // The subject: the item itself, or the folder above it where the check failed.
    if (at_item) {
        if (what.len > 0) try w.print("rweb: {s}, {f}, ", .{ what, P }) else try w.print("rweb: {f} ", .{P});
    } else try w.print("rweb: {f} ", .{P});

    const Fix = union(enum) { text: []const u8, chmod: []const u8, acl: bool, realpath, none };
    var fix: Fix = .none;
    // Whether the sentence already says how the place relates to `what`.
    var said_what = false;

    if (err == error.FolderWritableByGroup or err == error.ProgramWritableByGroup) {
        if (om) |o| try w.print("can be changed by members of {f}{f}", .{ GroupName{ .gid = o.gid, .names = n }, mode }) else try w.writeAll("can be changed by members of its group");
        fix = .{ .chmod = "g-w" };
    } else if (err == error.FolderWritableByOthers or err == error.ProgramWritableByOthers) {
        try w.print("can be changed by every user on this machine{f}", .{mode});
        // Its group may write too: one fix for both, or the next start refuses it again for g-w.
        const group_too = if (om) |o| o.mode & 0o020 != 0 else false;
        fix = .{ .chmod = if (group_too) "go-w" else "o-w" };
    } else if (err == error.FolderNotOurs) {
        if (om) |o| try w.print("belongs to {f}, not to you or root", .{UserName{ .uid = o.uid, .names = n }}) else try w.writeAll("belongs to another user, not to you or root");
        fix = .{ .text = "use a path whose folders belong to you or root" };
    } else if (err == error.NotOwned or err == error.SocketDirNotOurs) {
        const owner_text = if (problem.role == .program) ", not to you or root" else ", not to you";
        if (om) |o| try w.print("belongs to {f}{s}", .{ UserName{ .uid = o.uid, .names = n }, owner_text }) else try w.print("belongs to another user{s}", .{owner_text});
        fix = .{ .text = if (problem.role == .program) "use a copy that belongs to you or root" else if (is_dir) "use a folder of your own" else "use a file of your own" };
    } else if (err == error.TooOpen or err == error.SocketDirNotPrivate) {
        try w.writeAll(if (is_dir) "can be opened by " else "can be read by ");
        if (om) |o| {
            if (o.mode & 0o007 != 0) try w.writeAll("every user on this machine") else try w.print("members of {f}", .{GroupName{ .gid = o.gid, .names = n }});
        } else try w.writeAll("other users");
        try w.print("{f}", .{mode});
        fix = .{ .chmod = if (is_dir) "700" else "600" };
    } else if (err == error.SymLink) {
        if (!link_ours) {
            if (om) |o| {
                try w.print("is a link{f} that belongs to {f}, not to you or root", .{ LinkTo{ .target = target }, UserName{ .uid = o.uid, .names = n } });
            } else try w.print("is a link{f} whose owner rweb could not read", .{LinkTo{ .target = target }});
            fix = .{ .text = "remove the link, or use a path of your own: a link another user owns leads wherever that user chooses" };
        } else {
            if (at_item) {
                try w.print("is a link{f}; rweb does not follow a link there", .{LinkTo{ .target = target }});
            } else if (what.len > 0) {
                try w.print("is a link{f}, and rweb keeps {s} only in a folder that is not a link", .{ LinkTo{ .target = target }, what });
                said_what = true;
            } else try w.print("is a link{f}; rweb does not follow a link there", .{LinkTo{ .target = target }});
            fix = .realpath;
        }
    } else if (err == error.LinkNotOurs) {
        const owner: UserName = .{ .uid = if (om) |o| o.uid else std.math.maxInt(u32), .names = n };
        try w.print("is a link{f} owned by {f}, not by you or root", .{ LinkTo{ .target = target }, owner });
        fix = .{ .text = "use a path that does not go through another user's link" };
    } else if (err == error.TooManyLinks) {
        try w.writeAll("goes through too many links, or a loop of them");
        fix = .realpath;
    } else if (err == error.AclGivesOthersWrite or err == error.AclGivesGroupWrite) {
        try w.print("has an access list entry that lets {f} change it", .{AclName{ .who = problem.acl_who, .names = n }});
        fix = .{ .acl = err == error.AclGivesGroupWrite };
    } else if (err == error.AclGivesOthersAccess or err == error.AclGivesGroupAccess) {
        try w.print("has an access list entry that lets {f} {s} it", .{ AclName{ .who = problem.acl_who, .names = n }, if (is_dir) "open" else "read" });
        fix = .{ .acl = false };
    } else if (err == error.AclUnreadable) {
        try w.writeAll("has an access list rweb cannot read");
        fix = .{ .acl = false };
    } else if (err == error.NetworkFilesystem) {
        try w.print("is on a network disk{f}; its server decides who can read it", .{Paren{ .s = problem.fsType() }});
        fix = .{ .text = local_disk };
    } else if (err == error.UnknownFilesystem) {
        try w.print("is on a filesystem rweb does not know as a local disk{f}", .{Paren{ .s = problem.fsType() }});
        fix = .{ .text = local_disk };
    } else if (err == error.FuseFilesystem) {
        try w.print("is on a FUSE filesystem{f}, whose program decides who owns its files", .{Paren{ .s = problem.fsType() }});
        fix = .{ .text = own_disk };
    } else if (err == error.MountNotOurs) {
        if (problem.mount_owner) |o| try w.print("is on a disk {f} mounted, with the owners and modes they chose", .{UserName{ .uid = o, .names = n }}) else try w.writeAll("is on a disk another user mounted, with the owners and modes they chose");
        fix = .{ .text = own_disk };
    } else if (err == error.MountIgnoresOwnership) {
        try w.writeAll("is on a volume that ignores ownership, so every user owns every file on it");
        fix = .{ .text = own_disk };
    } else if (err == error.LoopMount) {
        try w.print("is on a disk image{f}, with the owners and modes whoever made it chose", .{Paren{ .s = problem.detail() }});
        fix = .{ .text = own_disk };
    } else if (err == error.UserMount) {
        try w.print("is on a disk a user mounted{f}", .{Paren{ .s = problem.detail() }});
        fix = .{ .text = own_disk };
    } else if (err == error.MountInfoUnreadable) {
        try w.writeAll("is on a disk rweb cannot identify (it reads /proc/self/mountinfo and /run/mount/utab)");
        fix = .{ .text = "run rweb where /proc is mounted and /run/mount/utab, if present, can be read" };
    } else if (err == error.FileNotFound) {
        try w.writeAll("does not exist");
        fix = .{ .text = "check the path" };
    } else if (err == error.AccessDenied or err == error.PermissionDenied) {
        try w.writeAll("cannot be opened by you");
        fix = .{ .text = "check its permissions" };
    } else if (err == error.NotADirectory or err == error.NotDir) {
        try w.writeAll("is not a folder");
        fix = .{ .text = "give the path of a folder" };
    } else if (err == error.NotARegularFile) {
        try w.writeAll("is not a regular file");
        fix = .{ .text = "give the path of a regular file" };
    } else if (err == error.TooLong) {
        try w.writeAll("is larger than rweb accepts");
        fix = .{ .text = "check that it is the right file" };
    } else if (err == error.TooShort) {
        try w.print("is too short to be a safe secret (it must hold at least {d} characters)", .{min_secret_len});
        fix = .{ .text = if (hints.made_by_rweb) "remove it and rweb makes a new one" else std.fmt.comptimePrint("put a random secret of at least {d} letters, digits, - or _ in it", .{min_secret_len}) };
    } else if (err == error.BadCharacters) {
        try w.writeAll("holds characters other than letters, digits, \"-\" and \"_\"");
        fix = .{ .text = if (hints.made_by_rweb) "remove it and rweb makes a new one" else "use a secret made only of those" };
    } else if (err == error.BadPath or err == error.SocketPathNotAbsolute or err == error.BadSocketPath) {
        try w.writeAll("is not a path rweb accepts: it must start with / and have no \"..\" in it");
        fix = .{ .text = "give the full path" };
    } else if (err == error.NameTooLong) {
        try w.writeAll("is too long a path");
        fix = .{ .text = "use a shorter path" };
    } else if (err == error.StatFailed or err == error.ReadFailed) {
        try w.writeAll("could not be read");
        fix = .{ .text = "check that it exists and belongs to you" };
    } else {
        try w.writeAll("cannot be used");
        fix = .{ .text = "check that it exists, belongs to you and is closed to other users" };
    }

    if (!at_item and what.len > 0 and !said_what) try w.print("; rweb keeps {s} under it", .{what});
    try w.writeAll(".\n  Fix: ");
    switch (fix) {
        .text => |t| try w.writeAll(t),
        .chmod => |how| try w.print("chmod {s} {f}", .{ how, Q }),
        .acl => |also_group| if (n.darwin) try w.print("chmod -N {f}", .{Q}) else if (also_group) try w.print("setfacl -b {f} && chmod g-w {f}", .{ Q, Q }) else try w.print("setfacl -b {f}", .{Q}),
        .realpath => {
            // The option that names this place, when there is one: the item's, or for the folder
            // it is kept in, the folder's.
            const option = if (err != error.SymLink) null else if (at_item) hints.item_option else hints.folder_option;
            const T: Shown = .{ .path = target, .names = n, .shell = true };
            if (option) |o| {
                if (target.len > 0 and target[0] == '/') try w.print("pass the real path: {s} {f}", .{ o, T }) else try w.print("pass the real path with {s} (realpath {f} prints it)", .{ o, Q });
            } else if (target.len > 0 and target[0] == '/') {
                try w.print("use the real path, {f}", .{Shown{ .path = target, .names = n }});
            } else try w.print("use the real path (realpath {f} prints it)", .{Q});
        },
        .none => try w.writeAll("check that it exists, belongs to you and is closed to other users"),
    }
    try w.writeAll("\n");
}

// ---- tests ----

const testing = std.testing;

fn entry(gpa: Allocator, kind: Kind, name: []const u8) !Entry {
    return entryFor(gpa, kind, name, 1);
}

fn entryFor(gpa: Allocator, kind: Kind, name: []const u8, viewer_id: u64) !Entry {
    return .{ .token = undefined, .kind = kind, .expires_ms = 0, .name = try gpa.dupe(u8, name), .size = 3, .viewer_id = viewer_id };
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
    // Spread over viewers, so the per-viewer limit is not what stops them.
    for (0..max_waiting) |i| seen[i] = try r.add(try entryFor(testing.allocator, .download, "x", i / max_waiting_per_viewer + 1));
    for (0..max_waiting) |i| for (i + 1..max_waiting) |j| try testing.expect(!std.mem.eql(u8, &seen[i], &seen[j]));
    try testing.expectError(error.TooMany, r.add(try entryFor(testing.allocator, .download, "x", 99)));
}

test "one viewer may have at most max_waiting_per_viewer tokens waiting" {
    var r = Registry.init(testing.allocator, testing.io);
    defer r.deinit();
    for (0..max_waiting_per_viewer) |_| _ = try r.add(try entryFor(testing.allocator, .upload, "x", 7));
    try testing.expectError(error.TooMany, r.add(try entryFor(testing.allocator, .download, "x", 7)));
    // Another page is not held back by it.
    const other = try r.add(try entryFor(testing.allocator, .download, "y", 8));
    // A token used, or the viewer's tokens revoked, frees its places.
    var e = r.take(&other, .download).?;
    e.deinit(testing.allocator);
    r.revokeViewer(7);
    for (0..max_waiting_per_viewer) |_| _ = try r.add(try entryFor(testing.allocator, .upload, "x", 7));
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
    try testing.expect(std.mem.endsWith(u8, p.pathText(), "/open"));
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
    try checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o755 }, me, false);
    try checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o1777 }, me, false);
    try checkAncestor(.{ .uid = me, .mode = S_IFDIR | 0o700 }, me, false);
    try testing.expectError(error.FolderNotOurs, checkAncestor(.{ .uid = 1000, .mode = S_IFDIR | 0o755 }, me, true));
    try testing.expectError(error.NotADirectory, checkAncestor(.{ .uid = 0, .mode = S_IFREG | 0o755 }, me, true));
    // Writable by its group: only when the group holds no one but us and root (or it is sticky).
    try testing.expectError(error.FolderWritableByGroup, checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o775 }, me, false));
    try checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o775 }, me, true);
    try checkAncestor(.{ .uid = me, .mode = S_IFDIR | 0o770 }, me, true);
    try checkAncestor(.{ .uid = me, .mode = S_IFDIR | 0o1770 }, me, false);
    // Writable by others: never, whatever the group, unless sticky.
    try testing.expectError(error.FolderWritableByOthers, checkAncestor(.{ .uid = 0, .mode = S_IFDIR | 0o777 }, me, true));
    try testing.expectError(error.FolderWritableByOthers, checkAncestor(.{ .uid = me, .mode = S_IFDIR | 0o757 }, me, true));
    // A program we run: root's or ours, and nobody else may change it.
    try checkProgram(.{ .uid = 0, .mode = S_IFREG | 0o755 }, me, false);
    try checkProgram(.{ .uid = me, .mode = S_IFREG | 0o700 }, me, false);
    try checkProgram(.{ .uid = me, .mode = S_IFREG | 0o775 }, me, true);
    try testing.expectError(error.ProgramWritableByGroup, checkProgram(.{ .uid = me, .mode = S_IFREG | 0o775 }, me, false));
    try testing.expectError(error.ProgramWritableByOthers, checkProgram(.{ .uid = 0, .mode = S_IFREG | 0o757 }, me, true));
    try testing.expectError(error.NotOwned, checkProgram(.{ .uid = 1000, .mode = S_IFREG | 0o755 }, me, true));
    try testing.expectError(error.NotARegularFile, checkProgram(.{ .uid = 0, .mode = S_IFDIR | 0o755 }, me, true));
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

test "a folder its group can write to passes only when the group is a safe one" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // Linux's umask 0002 makes folders like this one (and `.zig-cache` 0775).
    try tmp.dir.createDirPath(io, "grp");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/grp", .{root}), 0o775);
    try writeFileMode(io, tmp.dir, "grp/ok", 0o600, "secret");
    try writeFileMode(io, tmp.dir, "grp/prog", 0o775, "#!/bin/sh\n");
    const file = try std.fmt.allocPrint(arena, "{s}/grp/ok", .{root});
    const prog = try std.fmt.allocPrint(arena, "{s}/grp/prog", .{root});
    defer test_group_safe = null;
    var p: Problem = .{};
    // A safe group (macOS's admin): the folder, and a program it can write, pass.
    test_group_safe = true;
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, prog, &p));
    const up = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/grp/uploads", .{root}), &p);
    up.dir.close(io);
    // Any other group: refused, and the folder named.
    test_group_safe = false;
    try testing.expectError(error.FolderWritableByGroup, readPrivateFile(arena, io, file, 4096, &p));
    try testing.expect(std.mem.endsWith(u8, p.pathText(), "/grp"));
    try testing.expectError(error.FolderWritableByGroup, checkedProgram(arena, io, prog, &p));
}

test "no group is safe but macOS's admin, not even the user's own" {
    try testing.expect(!groupIsSafe(0x7ffe_1234));
    try testing.expect(!groupIsSafe(@intCast(std.c.getgid())));
    try testing.expect(!groupIsSafe(20)); // macOS's staff
    try testing.expectEqual(builtin.os.tag.isDarwin(), groupIsSafe(darwin_admin_gid));
}

test "a program is checked by its real path, in folders nobody else can change" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try writeFileMode(io, tmp.dir, "prog", 0o700, "#!/bin/sh\n");
    try tmp.dir.symLink(io, "prog", "via", .{});
    try writeFileMode(io, tmp.dir, "wide", 0o700, "#!/bin/sh\n");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), 0o757);
    try tmp.dir.createDirPath(io, "open");
    try writeFileMode(io, tmp.dir, "open/prog", 0o700, "#!/bin/sh\n");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 0o777);
    var p: Problem = .{};
    const prog = try std.fmt.allocPrint(arena, "{s}/prog", .{root});
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, prog, &p));
    // A link is resolved: the program that runs is the one that was checked.
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/via", .{root}), &p));
    try testing.expectError(error.ProgramWritableByOthers, checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), &p));
    try testing.expectError(error.FolderWritableByOthers, checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/open/prog", .{root}), &p));
    try testing.expect(std.mem.endsWith(u8, p.pathText(), "/open"));
    try testing.expectError(error.FileNotFound, checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/missing", .{root}), &p));
    try testing.expectError(error.BadPath, checkedProgram(arena, io, "prog", &p));
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
    const up = try openUploadDir(arena, io, fresh, &p);
    defer up.dir.close(io);
    const st = try up.dir.stat(io);
    try testing.expectEqual(@as(u32, 0o700), @intFromEnum(st.permissions) & 0o777);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/up/loads", .{root}), up.real_path);
    // Through a linked folder: the path to paste is the real one, not the link's.
    try tmp.dir.symLink(io, "up", "via", .{});
    const via = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/via/more", .{root}), &p);
    defer via.dir.close(io);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/up/more", .{root}), via.real_path);
    // Under a folder others can write to: refused, and nothing is made there.
    try tmp.dir.createDirPath(io, "open");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 0o777);
    try testing.expectError(error.FolderWritableByOthers, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/open/new/uploads", .{root}), &p));
    try testing.expectError(error.FileNotFound, tmp.dir.statFile(io, "open/new", .{}));
    try testing.expectError(error.BadPath, openUploadDir(arena, io, "relative/uploads", &p));
    // Open to others, a link to a good folder, a file.
    try tmp.dir.createDirPath(io, "wide");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), 0o755);
    try testing.expectError(error.TooOpen, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/wide", .{root}), &p));
    try tmp.dir.symLink(io, "up/loads", "linked", .{});
    try testing.expectError(error.SymLink, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/linked", .{root}), &p));
    try writeFileMode(io, tmp.dir, "file", 0o600, "x");
    try testing.expectError(error.NotADirectory, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/file", .{root}), &p));
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

/// A pretend set of safe groups for the ACL rules.
const FakeGroups = struct {
    safe_gids: []const u32,

    fn safe(f: FakeGroups, gid: u32) bool {
        return std.mem.indexOfScalar(u32, f.safe_gids, gid) != null;
    }
};

/// A `system.posix_acl_access` value from {tag, perm, id} triples.
fn posixAclBlob(buf: []u8, entries: []const [3]u32) []const u8 {
    std.mem.writeInt(u32, buf[0..4], posix_acl.version, .little);
    for (entries, 0..) |e, k| {
        const at = buf[4 + k * 8 ..];
        std.mem.writeInt(u16, at[0..2], @intCast(e[0]), .little);
        std.mem.writeInt(u16, at[2..4], @intCast(e[1]), .little);
        std.mem.writeInt(u32, at[4..8], e[2], .little);
    }
    return buf[0 .. 4 + entries.len * 8];
}

test "a POSIX ACL may let only root, us or a safe group write, through its mask" {
    const A = posix_acl;
    const me: u32 = 1000;
    const no_id = std.math.maxInt(u32);
    const groups = FakeGroups{ .safe_gids = &.{ 1000, 777 } };
    var buf: [256]u8 = undefined;
    const base = [_][3]u32{ .{ A.user_obj, 7, no_id }, .{ A.group_obj, 5, no_id }, .{ A.other, 5, no_id } };
    const check = struct {
        fn run(b: []u8, extra: []const [3]u32, gid: u32, g: FakeGroups) CheckError!void {
            var all: [8][3]u32 = undefined;
            @memcpy(all[0..3], &base);
            @memcpy(all[3..][0..extra.len], extra);
            return checkPosixAcl(posixAclBlob(b, all[0 .. 3 + extra.len]), me, gid, g, FakeGroups.safe, null);
        }
    }.run;
    // The three mode entries alone, and a named user who may only read.
    try check(&buf, &.{}, 1000, groups);
    try check(&buf, &.{ .{ A.user, 5, 1001 }, .{ A.mask, 7, no_id } }, 1000, groups);
    // A named user who may write: refused, unless it is root or us.
    try testing.expectError(error.AclGivesOthersWrite, check(&buf, &.{ .{ A.user, 7, 1001 }, .{ A.mask, 7, no_id } }, 1000, groups));
    try check(&buf, &.{ .{ A.user, 7, 0 }, .{ A.user, 7, me }, .{ A.mask, 7, no_id } }, 1000, groups);
    // A mask without write leaves every named entry read-only.
    try check(&buf, &.{ .{ A.user, 7, 1001 }, .{ A.group, 7, 4242 }, .{ A.mask, 5, no_id } }, 4242, groups);
    // No mask at all: nothing is cut.
    try testing.expectError(error.AclGivesOthersWrite, check(&buf, &.{.{ A.user, 6, 1001 }}, 1000, groups));
    // A named group that may write: as safe as the group is.
    try check(&buf, &.{ .{ A.group, 7, 777 }, .{ A.mask, 7, no_id } }, 1000, groups);
    try testing.expectError(error.AclGivesGroupWrite, check(&buf, &.{ .{ A.group, 7, 4242 }, .{ A.mask, 7, no_id } }, 1000, groups));
    // The owning group, with write through the mask: decided by the file's group.
    var gw = base;
    gw[1][1] = 7;
    try checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 7, no_id }})), me, 1000, groups, FakeGroups.safe, null);
    try testing.expectError(error.AclGivesGroupWrite, checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 7, no_id }})), me, 4242, groups, FakeGroups.safe, null));
    try checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 5, no_id }})), me, 4242, groups, FakeGroups.safe, null);
}

test "a POSIX ACL that is not one is refused" {
    const A = posix_acl;
    const g = FakeGroups{ .safe_gids = &.{} };
    var buf: [64]u8 = undefined;
    const ok = posixAclBlob(&buf, &.{.{ A.user_obj, 7, 0 }});
    try checkPosixAcl(ok, 1000, 1000, g, FakeGroups.safe, null);
    try testing.expectError(error.AclUnreadable, checkPosixAcl(ok[0..3], 1000, 1000, g, FakeGroups.safe, null)); // too short
    try testing.expectError(error.AclUnreadable, checkPosixAcl(ok[0 .. ok.len - 1], 1000, 1000, g, FakeGroups.safe, null)); // a cut entry
    var v1: [12]u8 = ok[0..12].*;
    v1[0] = 1;
    try testing.expectError(error.AclUnreadable, checkPosixAcl(&v1, 1000, 1000, g, FakeGroups.safe, null)); // another version
    try testing.expectError(error.AclUnreadable, checkPosixAcl(posixAclBlob(&buf, &.{.{ 0x40, 7, 5 }}), 1000, 1000, g, FakeGroups.safe, null)); // an unknown tag
    try testing.expectError(error.AclUnreadable, checkPosixAcl(posixAclBlob(&buf, &.{ .{ A.mask, 7, 0 }, .{ A.mask, 5, 0 } }), 1000, 1000, g, FakeGroups.safe, null)); // two masks
}

test "a macOS ACL may let only root, us or a safe group change things; deny entries pass" {
    const P = darwin_acl;
    const me: u32 = 501;
    const nobody: u32 = 4294967294;
    const g = FakeGroups{ .safe_gids = &.{ darwin_admin_gid, darwin_everyone_gid } };
    const deny_delete: DarwinAce = .{ .allow = false, .perms = P.delete, .who = .{ .group = darwin_everyone_gid } };
    // Every home folder's entry.
    try checkDarwinAcl(&.{deny_delete}, me, .shared, g, FakeGroups.safe, null);
    try checkDarwinAcl(&.{deny_delete}, me, .private, g, FakeGroups.safe, null);
    // Another user who may add a file, add a folder, delete, change the ACL or take ownership.
    for ([_]u64{ P.write_data, P.append_data, P.delete_child, P.delete, P.write_security, P.change_owner }) |perm| {
        try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = perm, .who = .{ .user = nobody } }}, me, .shared, g, FakeGroups.safe, null));
    }
    // Root and us may.
    try checkDarwinAcl(&.{ .{ .allow = true, .perms = P.changes, .who = .{ .user = 0 } }, .{ .allow = true, .perms = P.changes, .who = .{ .user = me } } }, me, .shared, g, FakeGroups.safe, null);
    // Reading is fine on the way, not on a private file or folder.
    const read: DarwinAce = .{ .allow = true, .perms = P.read_data | P.execute, .who = .{ .user = nobody } };
    try checkDarwinAcl(&.{read}, me, .shared, g, FakeGroups.safe, null);
    try testing.expectError(error.AclGivesOthersAccess, checkDarwinAcl(&.{read}, me, .private, g, FakeGroups.safe, null));
    // An entry only for new items: not this folder's, unless what it passes on is private (uploads).
    const inherit: DarwinAce = .{ .allow = true, .only_inherit = true, .perms = P.write_data, .who = .{ .user = nobody } };
    try checkDarwinAcl(&.{inherit}, me, .shared, g, FakeGroups.safe, null);
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{inherit}, me, .private, g, FakeGroups.safe, null));
    // Groups: a safe one may, `everyone` never (whatever the group rule says), another may not.
    try checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_admin_gid } }}, me, .shared, g, FakeGroups.safe, null);
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_everyone_gid } }}, me, .shared, g, FakeGroups.safe, null));
    try testing.expectError(error.AclGivesGroupWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.delete_child, .who = .{ .group = 20 } }}, me, .shared, g, FakeGroups.safe, null));
    // Someone the directory service does not know is someone else.
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .unknown }}, me, .shared, g, FakeGroups.safe, null));
}

test "a filesystem another user controls is refused" {
    const me: u32 = 501;
    try checkMount(.{}, me);
    try checkMount(.{ .linux_type = 0xEF53 }, me); // ext4
    // Network filesystems: their server decides, out of sight. Anything not known to be local.
    try testing.expectError(error.NetworkFilesystem, checkMount(.{ .linux_type = linux_fs.nfs }, me));
    try testing.expectError(error.NetworkFilesystem, checkMount(.{ .linux_type = linux_fs.cifs }, me));
    try testing.expectError(error.UnknownFilesystem, checkMount(.{ .linux_type = 0x12345678 }, me));
    try testing.expectError(error.UnknownFilesystem, checkMount(.{ .linux_type = 0x9fa0 }, me)); // procfs
    for ([_]u32{ linux_fs.xfs, linux_fs.btrfs, linux_fs.tmpfs, linux_fs.zfs, linux_fs.f2fs, linux_fs.overlay }) |t| try checkMount(.{ .linux_type = t }, me);
    // `f_type` is a signed word: a magic number with its top bit set comes sign-extended.
    try checkMount(.{ .linux_type = 0xFFFF_FFFF_F2F5_2010 }, me);
    try testing.expectError(error.FuseFilesystem, checkMount(.{ .linux_type = linux_fs.fuse }, me));
    // macOS: a volume not on a local disk.
    try checkMount(.{ .owner = 0, .local = true }, me);
    try testing.expectError(error.NetworkFilesystem, checkMount(.{ .owner = 0, .local = false }, me));
    try checkMount(.{ .owner = 0 }, me);
    try checkMount(.{ .owner = me }, me);
    try testing.expectError(error.MountNotOurs, checkMount(.{ .owner = 502 }, me));
    try testing.expectError(error.MountIgnoresOwnership, checkMount(.{ .owner = me, .ignores_ownership = true }, me));
}

test "the filesystems this test runs on pass" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    try checkMount(try fdMount(tmp.dir.handle), myUid());
}

test "a program is opened inside its checked folder, never through a link, and run by that path" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "real/bin");
    try writeFileMode(io, tmp.dir, "real/bin/ts", 0o755, "#!/bin/sh\n");
    try tmp.dir.symLink(io, "real", "via", .{});
    var p: Problem = .{};
    // Through a linked folder: the path to run is the checked one, with no link on it.
    const want = try std.fmt.allocPrint(arena, "{s}/real/bin/ts", .{root});
    try testing.expectEqualStrings(want, try checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/via/bin/ts", .{root}), &p));
    // A FIFO there is refused at once, not waited on; a folder is not a program.
    const fifo = try std.fmt.allocPrintSentinel(arena, "{s}/real/bin/fifo", .{root}, 0);
    try testing.expectEqual(@as(c_int, 0), mkfifo(fifo, 0o700));
    try testing.expectError(error.NotARegularFile, checkedProgram(arena, io, fifo, &p));
    try testing.expectError(error.NotARegularFile, checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/real/bin", .{root}), &p));
}

extern "c" fn mkfifo(path: [*:0]const u8, mode: std.c.mode_t) c_int;

fn runTool(arena: Allocator, io: Io, argv: []const []const u8) !void {
    const res = try std.process.run(arena, io, .{ .argv = argv });
    if (res.term != .exited or res.term.exited != 0) return error.ToolFailed;
}

test "macOS: an ACL entry that lets another user change a folder or program is refused; deny entries and what rweb makes pass" {
    if (!builtin.os.tag.isDarwin()) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "acl");
    try writeFileMode(io, tmp.dir, "acl/ok", 0o600, "secret");
    try writeFileMode(io, tmp.dir, "acl/prog", 0o755, "#!/bin/sh\n");
    const dir = try std.fmt.allocPrint(arena, "{s}/acl", .{root});
    const file = try std.fmt.allocPrint(arena, "{s}/acl/ok", .{root});
    const prog = try std.fmt.allocPrint(arena, "{s}/acl/prog", .{root});
    // Whatever happens, the entries go (an `everyone deny delete` would stop the clean-up).
    defer runTool(arena, io, &.{ "/bin/chmod", "-RN", dir }) catch {};
    var p: Problem = .{};
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    // A deny entry, as on every home folder: passes.
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "everyone deny delete", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try runTool(arena, io, &.{ "/bin/chmod", "-N", dir });
    // Another user who may add files to the folder could replace the file: refused, and named.
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "user:nobody allow add_file", dir });
    try testing.expectError(error.AclGivesOthersWrite, readPrivateFile(arena, io, file, 4096, &p));
    try testing.expect(std.mem.endsWith(u8, p.pathText(), "/acl"));
    try testing.expectError(error.AclGivesOthersWrite, checkedProgram(arena, io, prog, &p));
    try runTool(arena, io, &.{ "/bin/chmod", "-a", "user:nobody allow add_file", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, prog, &p));
    // On the files themselves: a secret nobody else may read, a program nobody else may change.
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "user:nobody allow read", file });
    try testing.expectError(error.AclGivesOthersAccess, readPrivateFile(arena, io, file, 4096, &p));
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "user:nobody allow read", prog });
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, prog, &p));
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "user:nobody allow write", prog });
    try testing.expectError(error.AclGivesOthersWrite, checkedProgram(arena, io, prog, &p));
    // An entry only for new folders: this folder passes; a folder rweb makes in it starts without
    // the entry, one made otherwise inherits it and is refused as an upload folder.
    try runTool(arena, io, &.{ "/bin/chmod", "+a", "user:nobody allow add_file,directory_inherit,only_inherit", dir });
    const up = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/acl/made", .{root}), &p);
    up.dir.close(io);
    try tmp.dir.createDirPath(io, "acl/other");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/acl/other", .{root}), 0o700);
    try testing.expectError(error.AclGivesOthersWrite, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/acl/other", .{root}), &p));
}

test "Linux: a named ACL entry that lets another user write to a folder is refused" {
    if (builtin.os.tag != .linux) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "acl");
    const dir = try std.fmt.allocPrint(arena, "{s}/acl", .{root});
    try chmodPath(arena, dir, 0o700);
    try writeFileMode(io, tmp.dir, "acl/ok", 0o600, "secret");
    const file = try std.fmt.allocPrint(arena, "{s}/acl/ok", .{root});
    var p: Problem = .{};
    // No `setfacl`, or a filesystem without ACLs: nothing to test here.
    runTool(arena, io, &.{ "setfacl", "-m", "u:65534:rwx", dir }) catch return error.SkipZigTest;
    try testing.expectError(error.AclGivesOthersWrite, readPrivateFile(arena, io, file, 4096, &p));
    try testing.expect(std.mem.endsWith(u8, p.pathText(), "/acl"));
    // A mask without write: the named user can no longer write, and the folder passes.
    try runTool(arena, io, &.{ "setfacl", "-m", "m::r-x", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try runTool(arena, io, &.{ "setfacl", "-b", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
}

test "a link on the path must be root's or ours" {
    const me: u32 = 501;
    try checkLink(.{ .uid = 0, .mode = S_IFLNK | 0o777 }, me);
    try checkLink(.{ .uid = me, .mode = S_IFLNK | 0o777 }, me);
    try testing.expectError(error.LinkNotOurs, checkLink(.{ .uid = 1000, .mode = S_IFLNK | 0o777 }, me));
    try testing.expectError(error.SymLink, checkLink(.{ .uid = me, .mode = S_IFDIR | 0o755 }, me));
}

test "links on the given path are followed only from checked folders, and the walk goes on from their targets" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    try tmp.dir.createDirPath(io, "good");
    try writeFileMode(io, tmp.dir, "good/ok", 0o600, "secret");
    try writeFileMode(io, tmp.dir, "good/prog", 0o755, "#!/bin/sh\n");
    try tmp.dir.symLink(io, "prog", "good/lnprog", .{});
    try tmp.dir.symLink(io, "good", "rel", .{});
    try tmp.dir.symLink(io, try std.fmt.allocPrint(arena, "{s}/good", .{root}), "abs", .{});
    try tmp.dir.createDirPath(io, "sub");
    try tmp.dir.symLink(io, "../good", "sub/up", .{});
    try tmp.dir.symLink(io, "rel", "chain", .{});
    var p: Problem = .{};
    // Relative and absolute targets, `..` in a target, a link to a link: all lead to the good folder.
    for ([_][]const u8{ "rel", "abs", "sub/up", "chain" }) |via| {
        try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/{s}/ok", .{ root, via }), 4096, &p));
    }
    // A program through links (its own name one too) is run by the path with no link on it.
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/good/prog", .{root}), try checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/sub/up/lnprog", .{root}), &p));
    // The upload folder's path to paste is the resolved one.
    const up = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/sub/up/new", .{root}), &p);
    up.dir.close(io);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/good/new", .{root}), up.real_path);
    // A link in a folder others can write to: that folder is refused before the link is read.
    try tmp.dir.createDirPath(io, "open");
    try writeFileMode(io, tmp.dir, "open/ok", 0o600, "secret");
    try tmp.dir.symLink(io, "../good", "open/l", .{});
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 0o777);
    try testing.expectError(error.FolderWritableByOthers, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/open/l/ok", .{root}), 4096, &p));
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/open", .{root}), p.pathText());
    // A link to such a folder: refused there, named by the path the walk resolved.
    try tmp.dir.symLink(io, "open", "toopen", .{});
    try testing.expectError(error.FolderWritableByOthers, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/toopen/ok", .{root}), 4096, &p));
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "{s}/open", .{root}), p.pathText());
    try testing.expectEqual(@as(u32, 0o777), p.found.?.mode & 0o7777);
    // Our own link in a sticky folder (like /tmp) is followed.
    try tmp.dir.createDirPath(io, "sticky");
    try tmp.dir.symLink(io, "../good", "sticky/l", .{});
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/sticky", .{root}), 0o1777);
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/sticky/l/ok", .{root}), 4096, &p));
    // A loop of links.
    try tmp.dir.symLink(io, "loop2", "loop1", .{});
    try tmp.dir.symLink(io, "loop1", "loop2", .{});
    try testing.expectError(error.TooManyLinks, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/loop1/ok", .{root}), 4096, &p));
    // `..` in the given path is refused; `.` changes nothing.
    try testing.expectError(error.BadPath, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/good/../good/ok", .{root}), 4096, &p));
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/./good/ok", .{root}), 4096, &p));
    // A relative path is walked from the current folder's real path.
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, ".zig-cache/tmp/{s}/rel/ok", .{&tmp.sub_path}), 4096, &p));
    // The secret itself a link: refused, with where it leads noted for the message.
    try tmp.dir.symLink(io, "good/ok", "fl", .{});
    try testing.expectError(error.SymLink, readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "{s}/fl", .{root}), 4096, &p));
    try testing.expectEqualStrings("good/ok", p.detail());
    // So is a link as the upload folder itself.
    try testing.expectError(error.SymLink, openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/rel", .{root}), &p));
    try testing.expectEqualStrings("good", p.detail());
    // A folder through a link, for the socket's chain.
    const fd = try openChain(arena, io, try std.fmt.allocPrint(arena, "{s}/sub/up", .{root}), false, &p);
    closeFd(io, fd);
}

test "macOS: /tmp and /var, links root owns in /, lead to their real folders" {
    if (!builtin.os.tag.isDarwin()) return error.SkipZigTest;
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var rnd: [4]u8 = undefined;
    io.random(&rnd);
    const name = try std.fmt.allocPrint(arena, "rweb-test-xfer-{x}", .{rnd});
    defer Io.Dir.cwd().deleteTree(io, std.fmt.allocPrint(arena, "/private/tmp/{s}", .{name}) catch unreachable) catch {};
    defer Io.Dir.cwd().deleteTree(io, std.fmt.allocPrint(arena, "/private/var/tmp/{s}", .{name}) catch unreachable) catch {};
    var p: Problem = .{};
    const up = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "/tmp/{s}/up", .{name}), &p);
    try writeFileMode(io, up.dir, "s", 0o600, "secret");
    up.dir.close(io);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "/private/tmp/{s}/up", .{name}), up.real_path);
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, try std.fmt.allocPrint(arena, "/tmp/{s}/up/s", .{name}), 4096, &p));
    const fd = try openChain(arena, io, "/var/tmp", false, &p);
    closeFd(io, fd);
    const vup = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "/var/tmp/{s}", .{name}), &p);
    vup.dir.close(io);
    try testing.expectEqualStrings(try std.fmt.allocPrint(arena, "/private/var/tmp/{s}", .{name}), vup.real_path);
}

test "a private file or folder accepts no group in its access list, admin included; admin may change folders on the way" {
    const P = darwin_acl;
    const me: u32 = 501;
    const g = FakeGroups{ .safe_gids = &.{darwin_admin_gid} };
    const admin_writes: DarwinAce = .{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_admin_gid } };
    const admin_reads: DarwinAce = .{ .allow = true, .perms = P.read_data, .who = .{ .group = darwin_admin_gid } };
    var who: AclWho = .none;
    try checkDarwinAcl(&.{admin_writes}, me, .shared, g, FakeGroups.safe, &who);
    try testing.expectError(error.AclGivesGroupWrite, checkDarwinAcl(&.{admin_writes}, me, .private, g, FakeGroups.safe, &who));
    try testing.expectEqual(AclWho{ .group = darwin_admin_gid }, who);
    try testing.expectError(error.AclGivesGroupAccess, checkDarwinAcl(&.{admin_reads}, me, .private, g, FakeGroups.safe, &who));
    // The entry's user is named; `everyone` is every user, not a group.
    try testing.expectError(error.AclGivesOthersAccess, checkDarwinAcl(&.{.{ .allow = true, .perms = P.read_data, .who = .{ .user = 1001 } }}, me, .private, g, FakeGroups.safe, &who));
    try testing.expectEqual(AclWho{ .user = 1001 }, who);
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_everyone_gid } }}, me, .shared, g, FakeGroups.safe, &who));
    try testing.expectEqual(AclWho.everyone, who);
}

test "Linux: a mount a user made is refused, and so is one that cannot be found" {
    const text =
        \\33 2 0:30 / / rw,relatime shared:1 - btrfs /dev/nvme1n1p2 rw,compress=zstd:3,subvol=/
        \\298 31 0:69 / /run/user/1000 rw,nosuid,nodev,relatime shared:412 - tmpfs tmpfs rw,mode=700,uid=1000
        \\512 33 7:3 / /mnt/img rw,relatime shared:600 master:2 - ext4 /dev/loop3 rw
        \\513 33 8:17 / /media/me/USB\040STICK rw,nosuid,nodev,relatime shared:601 - vfat /dev/sdb1 rw,uhelper=udisks2
        \\514 33 8:33 / /mnt/stick rw,relatime shared:602 - ext4 /dev/sdc1 rw
        \\515 33 8:49 / /mnt/old rw,relatime shared:603 - ext4 /dev/sdd1 rw
        \\not a mountinfo line
        \\
    ;
    const utab =
        \\ID=514 SRC=/dev/sdc1 TARGET=/mnt/stick ROOT=/ OPTS=uhelper=udisks2
        \\SRC=/dev/sdd1 TARGET=/mnt/old ROOT=/ OPTS=user=me
        \\
    ;
    const root_mi = findMountInfo(text, 33).?;
    try testing.expectEqualStrings("btrfs", root_mi.fstype);
    try testing.expectEqualStrings("/dev/nvme1n1p2", root_mi.source);
    try testing.expectEqualStrings("/", root_mi.mount_point);
    try checkMountOrigin(root_mi, utab);
    try checkMountOrigin(findMountInfo(text, 298), null);
    try testing.expectError(error.LoopMount, checkMountOrigin(findMountInfo(text, 512), null));
    try testing.expectError(error.UserMount, checkMountOrigin(findMountInfo(text, 513), null));
    try testing.expectError(error.UserMount, checkMountOrigin(findMountInfo(text, 514), utab)); // by ID
    try testing.expectError(error.UserMount, checkMountOrigin(findMountInfo(text, 515), utab)); // by target
    try checkMountOrigin(findMountInfo(text, 515), null);
    try testing.expectError(error.MountInfoUnreadable, checkMountOrigin(findMountInfo(text, 999), null));
    try testing.expect(parseMountInfoLine("1 2 3:4 / /x rw shared:1") == null); // no separator
    try testing.expect(parseMountInfoLine("") == null);
}

test "the walk's every folder passes on the system the tests run on" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    var p: Problem = .{};
    try checkFdExtras(testing.allocator, testing.io, tmp.dir.handle, myUid(), .shared, &p);
    if (builtin.os.tag == .linux) try testing.expect(p.fsType().len > 0);
}

fn fakeUser(uid: u32, buf: []u8) ?[]const u8 {
    const n: []const u8 = switch (uid) {
        1000 => "me",
        1001 => "bob",
        else => return null,
    };
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

fn fakeGroup(gid: u32, buf: []u8) ?[]const u8 {
    const n: []const u8 = switch (gid) {
        1000 => "me",
        50 => "staff",
        80 => "admin",
        7 => "ev\x1bl",
        else => return null,
    };
    @memcpy(buf[0..n.len], n);
    return buf[0..n.len];
}

fn explained(buf: []u8, what: []const u8, path: []const u8, err: anyerror, p: Problem, darwin: bool) []const u8 {
    return explainedHinted(buf, what, path, err, p, darwin, .{});
}

fn explainedHinted(buf: []u8, what: []const u8, path: []const u8, err: anyerror, p: Problem, darwin: bool, hints: Hints) []const u8 {
    var w: Io.Writer = .fixed(buf);
    explainWith(&w, what, path, err, &p, hints, .{ .home = "/home/me", .darwin = darwin, .uid = 1000, .user = fakeUser, .group = fakeGroup }) catch unreachable;
    return w.buffered();
}

test "every refusal is explained in plain words, with the command that fixes it" {
    var b: [1024]u8 = undefined;
    const tok = "/home/me/.config/rweb/token";
    const dir = S_IFDIR;
    const reg = S_IFREG;
    const Case = struct { err: anyerror, what: []const u8 = "its token", path: []const u8 = tok, p: Problem, darwin: bool = false, want: []const u8 };
    var fs_nfs: Problem = .{ .ext_path = "/home/me" };
    fs_nfs.setFsType("nfs4");
    var fs_vbox: Problem = .{ .ext_path = "/mnt/x" };
    fs_vbox.setFsType("vboxsf");
    var fs_fuse: Problem = .{ .ext_path = "/mnt/s" };
    fs_fuse.setFsType("fuse.sshfs");
    var loop: Problem = .{ .ext_path = "/mnt/img" };
    loop.setDetail("/dev/loop3");
    var umount: Problem = .{ .ext_path = "/media/me/stick" };
    umount.setDetail("/dev/sdb1");
    var link_abs: Problem = .{ .ext_path = "/home/me/token", .role = .link, .found = .{ .uid = 1000, .mode = S_IFLNK | 0o777 } };
    link_abs.setDetail("/data/token");
    var link_rel: Problem = .{ .ext_path = "/home/me/token", .role = .link, .found = .{ .uid = 0, .mode = S_IFLNK | 0o777 } };
    link_rel.setDetail("t2");
    var link_theirs: Problem = .{ .ext_path = "/tmp/x", .role = .link, .found = .{ .uid = 1001, .mode = S_IFLNK | 0o777 } };
    link_theirs.setDetail("/tmp/evil");
    const cases = [_]Case{
        .{ .err = error.FolderWritableByGroup, .p = .{ .ext_path = "/home/me/.config", .found = .{ .uid = 1000, .gid = 1000, .mode = dir | 0o775 } }, .want =
        \\rweb: ~/.config can be changed by members of group "me" (mode 0775); rweb keeps its token under it.
        \\  Fix: chmod g-w ~/.config
        \\
        },
        .{ .err = error.ProgramWritableByGroup, .what = "the tailscale program", .path = "/opt/ts/tailscale", .p = .{ .ext_path = "/opt/ts/tailscale", .role = .program, .found = .{ .uid = 0, .gid = 50, .mode = reg | 0o775 } }, .want =
        \\rweb: the tailscale program, /opt/ts/tailscale, can be changed by members of group "staff" (mode 0775).
        \\  Fix: chmod g-w /opt/ts/tailscale
        \\
        },
        .{ .err = error.FolderWritableByOthers, .p = .{ .ext_path = "/srv/rweb", .found = .{ .uid = 0, .mode = dir | 0o777 } }, .want =
        \\rweb: /srv/rweb can be changed by every user on this machine (mode 0777); rweb keeps its token under it.
        \\  Fix: chmod go-w /srv/rweb
        \\
        },
        .{ .err = error.FolderNotOurs, .what = "the upload folder", .path = "/srv/up", .p = .{ .ext_path = "/srv", .found = .{ .uid = 1001, .mode = dir | 0o755 } }, .want =
        \\rweb: /srv belongs to user "bob", not to you or root; rweb keeps the upload folder under it.
        \\  Fix: use a path whose folders belong to you or root
        \\
        },
        .{ .err = error.NotOwned, .p = .{ .ext_path = tok, .role = .private_file, .found = .{ .uid = 1001, .mode = reg | 0o600 } }, .want =
        \\rweb: its token, ~/.config/rweb/token, belongs to user "bob", not to you.
        \\  Fix: use a file of your own
        \\
        },
        .{ .err = error.TooOpen, .p = .{ .ext_path = tok, .role = .private_file, .found = .{ .uid = 1000, .mode = reg | 0o644 } }, .want =
        \\rweb: its token, ~/.config/rweb/token, can be read by every user on this machine (mode 0644).
        \\  Fix: chmod 600 ~/.config/rweb/token
        \\
        },
        .{ .err = error.TooOpen, .what = "the upload folder", .path = "/home/me/uploads", .p = .{ .ext_path = "/home/me/uploads", .role = .private_folder, .found = .{ .uid = 1000, .gid = 50, .mode = dir | 0o750 } }, .want =
        \\rweb: the upload folder, ~/uploads, can be opened by members of group "staff" (mode 0750).
        \\  Fix: chmod 700 ~/uploads
        \\
        },
        .{ .err = error.SymLink, .path = "/home/me/token", .p = link_abs, .want =
        \\rweb: its token, ~/token, is a link to /data/token; rweb does not follow a link there.
        \\  Fix: use the real path, /data/token
        \\
        },
        .{ .err = error.SymLink, .path = "/home/me/token", .p = link_rel, .want =
        \\rweb: its token, ~/token, is a link to t2; rweb does not follow a link there.
        \\  Fix: use the real path (realpath ~/token prints it)
        \\
        },
        .{ .err = error.LinkNotOurs, .path = "/tmp/x/token", .p = link_theirs, .want =
        \\rweb: /tmp/x is a link to /tmp/evil owned by user "bob", not by you or root; rweb keeps its token under it.
        \\  Fix: use a path that does not go through another user's link
        \\
        },
        .{ .err = error.TooManyLinks, .p = .{ .ext_path = "/home/me/a" }, .want =
        \\rweb: ~/a goes through too many links, or a loop of them; rweb keeps its token under it.
        \\  Fix: use the real path (realpath ~/a prints it)
        \\
        },
        .{ .err = error.AclGivesGroupWrite, .p = .{ .ext_path = "/home/me/.config", .acl_who = .{ .group = 50 } }, .want =
        \\rweb: ~/.config has an access list entry that lets members of group "staff" change it; rweb keeps its token under it.
        \\  Fix: setfacl -b ~/.config && chmod g-w ~/.config
        \\
        },
        .{ .err = error.AclGivesOthersWrite, .darwin = true, .p = .{ .ext_path = "/home/me/.config", .acl_who = .{ .user = 1001 } }, .want =
        \\rweb: ~/.config has an access list entry that lets user "bob" change it; rweb keeps its token under it.
        \\  Fix: chmod -N ~/.config
        \\
        },
        .{ .err = error.AclGivesOthersWrite, .p = .{ .ext_path = "/home/me/.config", .acl_who = .{ .user = 1001 } }, .want =
        \\rweb: ~/.config has an access list entry that lets user "bob" change it; rweb keeps its token under it.
        \\  Fix: setfacl -b ~/.config
        \\
        },
        .{ .err = error.AclGivesGroupAccess, .darwin = true, .p = .{ .ext_path = tok, .role = .private_file, .acl_who = .{ .group = 80 } }, .want =
        \\rweb: its token, ~/.config/rweb/token, has an access list entry that lets members of group "admin" read it.
        \\  Fix: chmod -N ~/.config/rweb/token
        \\
        },
        .{ .err = error.AclGivesOthersAccess, .darwin = true, .what = "the socket folder", .path = "/home/me/run", .p = .{ .ext_path = "/home/me/run", .role = .private_folder, .acl_who = .everyone }, .want =
        \\rweb: the socket folder, ~/run, has an access list entry that lets every user on this machine open it.
        \\  Fix: chmod -N ~/run
        \\
        },
        .{ .err = error.AclUnreadable, .p = .{ .ext_path = "/home/me/.config" }, .want =
        \\rweb: ~/.config has an access list rweb cannot read; rweb keeps its token under it.
        \\  Fix: setfacl -b ~/.config
        \\
        },
        .{ .err = error.NetworkFilesystem, .p = fs_nfs, .want =
        \\rweb: ~ is on a network disk (nfs4); its server decides who can read it; rweb keeps its token under it.
        \\  Fix: keep rweb's files on a local disk: --config-dir /local/path
        \\
        },
        .{ .err = error.UnknownFilesystem, .path = "/mnt/x/token", .p = fs_vbox, .want =
        \\rweb: /mnt/x is on a filesystem rweb does not know as a local disk (vboxsf); rweb keeps its token under it.
        \\  Fix: keep rweb's files on a local disk: --config-dir /local/path
        \\
        },
        .{ .err = error.FuseFilesystem, .path = "/mnt/s/token", .p = fs_fuse, .want =
        \\rweb: /mnt/s is on a FUSE filesystem (fuse.sshfs), whose program decides who owns its files; rweb keeps its token under it.
        \\  Fix: use a folder on your own disk
        \\
        },
        .{ .err = error.MountNotOurs, .path = "/Volumes/x/token", .p = .{ .ext_path = "/Volumes/x", .mount_owner = 1001 }, .want =
        \\rweb: /Volumes/x is on a disk user "bob" mounted, with the owners and modes they chose; rweb keeps its token under it.
        \\  Fix: use a folder on your own disk
        \\
        },
        .{ .err = error.MountIgnoresOwnership, .path = "/Volumes/x/token", .p = .{ .ext_path = "/Volumes/x" }, .want =
        \\rweb: /Volumes/x is on a volume that ignores ownership, so every user owns every file on it; rweb keeps its token under it.
        \\  Fix: use a folder on your own disk
        \\
        },
        .{ .err = error.LoopMount, .path = "/mnt/img/token", .p = loop, .want =
        \\rweb: /mnt/img is on a disk image (/dev/loop3), with the owners and modes whoever made it chose; rweb keeps its token under it.
        \\  Fix: use a folder on your own disk
        \\
        },
        .{ .err = error.UserMount, .path = "/media/me/stick/token", .p = umount, .want =
        \\rweb: /media/me/stick is on a disk a user mounted (/dev/sdb1); rweb keeps its token under it.
        \\  Fix: use a folder on your own disk
        \\
        },
        .{ .err = error.MountInfoUnreadable, .p = .{ .ext_path = "/home/me" }, .want =
        \\rweb: ~ is on a disk rweb cannot identify (it reads /proc/self/mountinfo and /run/mount/utab); rweb keeps its token under it.
        \\  Fix: run rweb where /proc is mounted and /run/mount/utab, if present, can be read
        \\
        },
        .{ .err = error.FileNotFound, .what = "the tailscale program", .path = "/usr/bin/tailscale", .p = .{ .ext_path = "/usr/bin/tailscale" }, .want =
        \\rweb: the tailscale program, /usr/bin/tailscale, does not exist.
        \\  Fix: check the path
        \\
        },
        .{ .err = error.FileNotFound, .p = .{ .ext_path = "/home/me/.config/rweb" }, .want =
        \\rweb: ~/.config/rweb does not exist; rweb keeps its token under it.
        \\  Fix: check the path
        \\
        },
        .{ .err = error.NotARegularFile, .p = .{ .ext_path = tok }, .want =
        \\rweb: its token, ~/.config/rweb/token, is not a regular file.
        \\  Fix: give the path of a regular file
        \\
        },
        .{ .err = error.BadPath, .path = "/home/me/../me/token", .p = .{ .ext_path = "/home/me/../me/token" }, .want =
        \\rweb: its token, ~/../me/token, is not a path rweb accepts: it must start with / and have no ".." in it.
        \\  Fix: give the full path
        \\
        },
        .{ .err = error.SocketDirNotPrivate, .what = "the socket folder", .path = "/home/me/run", .p = .{ .ext_path = "/home/me/run" }, .want =
        \\rweb: the socket folder, ~/run, can be opened by other users.
        \\  Fix: chmod 700 ~/run
        \\
        },
        .{ .err = error.Unexpected, .p = .{ .ext_path = tok }, .want =
        \\rweb: its token, ~/.config/rweb/token, cannot be used.
        \\  Fix: check that it exists, belongs to you and is closed to other users
        \\
        },
        // A path that needs quoting in the command; a group and a user with no name; not under home.
        .{ .err = error.FolderWritableByGroup, .p = .{ .ext_path = "/home/me/My Files", .found = .{ .uid = 1000, .gid = 4242, .mode = dir | 0o775 } }, .want =
        \\rweb: ~/My Files can be changed by members of group 4242 (mode 0775); rweb keeps its token under it.
        \\  Fix: chmod g-w ~/'My Files'
        \\
        },
        .{ .err = error.FolderNotOurs, .path = "/home/mex/t", .p = .{ .ext_path = "/home/mex", .found = .{ .uid = 4243, .mode = dir | 0o755 } }, .want =
        \\rweb: /home/mex belongs to user 4243, not to you or root; rweb keeps its token under it.
        \\  Fix: use a path whose folders belong to you or root
        \\
        },
        .{ .err = error.NotOwned, .what = "the tailscale program", .path = "/opt/ts", .p = .{ .ext_path = "/opt/ts", .role = .program, .found = .{ .uid = 1001, .mode = reg | 0o755 } }, .want =
        \\rweb: the tailscale program, /opt/ts, belongs to user "bob", not to you or root.
        \\  Fix: use a copy that belongs to you or root
        \\
        },
    };
    for (cases) |c| try testing.expectEqualStrings(c.want, explained(&b, c.what, c.path, c.err, c.p, c.darwin));
}

test "a program others and its group can change is fixed with go-w, one only others can with o-w" {
    var b: [1024]u8 = undefined;
    const both: Problem = .{ .ext_path = "/opt/ts/tailscale", .role = .program, .found = .{ .uid = 0, .gid = 50, .mode = S_IFREG | 0o777 } };
    try testing.expect(std.mem.endsWith(u8, explained(&b, "the tailscale program", "/opt/ts/tailscale", error.ProgramWritableByOthers, both, false), "  Fix: chmod go-w /opt/ts/tailscale\n"));
    const others: Problem = .{ .ext_path = "/opt/ts/tailscale", .role = .program, .found = .{ .uid = 0, .gid = 50, .mode = S_IFREG | 0o757 } };
    try testing.expect(std.mem.endsWith(u8, explained(&b, "the tailscale program", "/opt/ts/tailscale", error.ProgramWritableByOthers, others, false), "  Fix: chmod o-w /opt/ts/tailscale\n"));
}

test "text from outside rweb reaches the terminal without control bytes, in sentences and fixes" {
    var b: [2048]u8 = undefined;
    // A link whose target holds ESC, a newline and a C1 control (U+009B, CSI) in UTF-8.
    var link: Problem = .{ .ext_path = "/home/me/token", .role = .link, .found = .{ .uid = 1000, .mode = S_IFLNK | 0o777 } };
    link.setDetail("/data/\x1b[31mred\nrweb: fake line\xc2\x9b2J");
    const t = explained(&b, "its token", "/home/me/token", error.SymLink, link, false);
    try testing.expectEqualStrings(
        \\rweb: its token, ~/token, is a link to /data/?[31mred?rweb: fake line?2J; rweb does not follow a link there.
        \\  Fix: use the real path, /data/?[31mred?rweb: fake line?2J
        \\
    , t);
    // With the option to pass, the command spells the bytes out for the shell.
    const h = explainedHinted(&b, "its token", "/home/me/token", error.SymLink, link, false, .{ .item_option = "--token-file" });
    try testing.expectEqualStrings(
        \\rweb: its token, ~/token, is a link to /data/?[31mred?rweb: fake line?2J; rweb does not follow a link there.
        \\  Fix: pass the real path: --token-file $'/data/\x1b[31mred\x0arweb: fake line\xc2\x9b2J'
        \\
    , h);
    // A path with a control byte, in a sentence and in a command; a user's name; a filesystem type.
    const p: Problem = .{ .ext_path = "/srv/a\x1bb\x7f", .found = .{ .uid = 0, .gid = 7, .mode = S_IFDIR | 0o775 } };
    const g = explained(&b, "its token", "/srv/a\x1bb\x7f/token", error.FolderWritableByGroup, p, false);
    try testing.expectEqualStrings(
        \\rweb: /srv/a?b? can be changed by members of group "ev?l" (mode 0775); rweb keeps its token under it.
        \\  Fix: chmod g-w $'/srv/a\x1bb\x7f'
        \\
    , g);
    var fs: Problem = .{ .ext_path = "/mnt/x" };
    fs.setFsType("fuse.\x1b]0;x\x07");
    try testing.expect(std.mem.indexOf(u8, explained(&b, "its token", "/mnt/x/token", error.FuseFilesystem, fs, false), "(fuse.?]0;x?)") != null);
    // Bytes that are not UTF-8 are not passed on either; other UTF-8 is.
    try testing.expect(std.mem.indexOf(u8, explained(&b, "its token", "/home/me/caf\xc3\xa9/\xff", error.Unexpected, .{}, false), "~/caf\xc3\xa9/?") != null);
}

test "a link is named as the way to the real path only when it is ours or root's, with the option to pass" {
    var b: [1024]u8 = undefined;
    // Another user's link at the token: never "use the real path, <wherever they point it>".
    var theirs: Problem = .{ .ext_path = "/home/me/token", .role = .link, .found = .{ .uid = 1001, .mode = S_IFLNK | 0o777 } };
    theirs.setDetail("/tmp/bob/token");
    try testing.expectEqualStrings(
        \\rweb: its token, ~/token, is a link to /tmp/bob/token that belongs to user "bob", not to you or root.
        \\  Fix: remove the link, or use a path of your own: a link another user owns leads wherever that user chooses
        \\
    , explainedHinted(&b, "its token", "/home/me/token", error.SymLink, theirs, false, .{ .item_option = "--token-file" }));
    // Our own link at <config>: one sentence, and the option that names the folder.
    var cfg: Problem = .{ .ext_path = "/home/me/c", .role = .link, .found = .{ .uid = 1000, .mode = S_IFLNK | 0o777 } };
    cfg.setDetail("c2");
    const hints: Hints = .{ .item_option = "--token-file", .folder_option = "--config-dir", .made_by_rweb = true };
    try testing.expectEqualStrings(
        \\rweb: ~/c is a link to c2, and rweb keeps its token only in a folder that is not a link.
        \\  Fix: pass the real path with --config-dir (realpath ~/c prints it)
        \\
    , explainedHinted(&b, "its token", "/home/me/c/token", error.SymLink, cfg, false, hints));
    cfg.setDetail("/data/c");
    try testing.expect(std.mem.endsWith(u8, explainedHinted(&b, "its token", "/home/me/c/token", error.SymLink, cfg, false, hints), "  Fix: pass the real path: --config-dir /data/c\n"));
    // Our own link at <config>/token: the item's option.
    var tok: Problem = .{ .ext_path = "/home/me/c/token", .role = .link, .found = .{ .uid = 1000, .mode = S_IFLNK | 0o777 } };
    tok.setDetail("/data/token");
    try testing.expect(std.mem.endsWith(u8, explainedHinted(&b, "its token", "/home/me/c/token", error.SymLink, tok, false, hints), "  Fix: pass the real path: --token-file /data/token\n"));
}

test "a short secret names the minimum, and a layout's own file is made again when removed" {
    var b: [1024]u8 = undefined;
    const p: Problem = .{ .ext_path = "/home/me/c/token" };
    try testing.expectEqualStrings(
        \\rweb: its token, ~/c/token, is too short to be a safe secret (it must hold at least 32 characters).
        \\  Fix: remove it and rweb makes a new one
        \\
    , explainedHinted(&b, "its token", "/home/me/c/token", error.TooShort, p, false, .{ .made_by_rweb = true }));
    try testing.expect(std.mem.endsWith(u8, explained(&b, "the token file", "/home/me/c/token", error.TooShort, p, false), "  Fix: put a random secret of at least 32 letters, digits, - or _ in it\n"));
}

test "a Problem copied after a walk past a link still names where the walk failed" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = testing.io;
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try tmp.dir.realPathFileAlloc(io, ".", arena);
    // `lnk` -> `open`, a folder every user can change: the walk follows the link, then fails at
    // `<root>/open`, a path it holds in the Problem's own buffer.
    try tmp.dir.createDirPath(io, "open");
    try chmodPath(arena, try std.fmt.allocPrint(arena, "{s}/open", .{root}), 0o777);
    try writeFileMode(io, tmp.dir, "open/ts", 0o755, "#!/bin/sh\n");
    try tmp.dir.symLink(io, "open", "lnk", .{});
    var p: Problem = .{};
    try testing.expectError(error.FolderWritableByOthers, checkedProgram(arena, io, try std.fmt.allocPrint(arena, "{s}/lnk/ts", .{root}), &p));
    const want = try std.fmt.allocPrint(arena, "{s}/open", .{root});
    try testing.expectEqualStrings(want, p.pathText());
    try testing.expect(p.buf_path != null);
    const copy = p;
    p.buf[p.buf_path.?.off] = 'X'; // the copy has its own buffer
    try testing.expectEqualStrings(want, copy.pathText());
}

test "no internal error name reaches the user" {
    var b: [1024]u8 = undefined;
    inline for (@typeInfo(OpenError).error_set.error_names.?) |name| {
        const err = @field(anyerror, name);
        const text = explained(&b, "its token", "/home/me/t", err, .{ .ext_path = "/home/me" }, false);
        try testing.expect(std.mem.startsWith(u8, text, "rweb: ~ "));
        try testing.expect(std.mem.indexOf(u8, text, "\n  Fix: ") != null);
        try testing.expect(std.mem.indexOf(u8, text, name) == null);
    }
    // The system's names and home.
    var w: Io.Writer = .fixed(&b);
    try explain(&w, "its token", "/nowhere/t", error.FolderWritableByGroup, &.{ .ext_path = "/nowhere", .found = .{ .uid = 0, .gid = 0, .mode = S_IFDIR | 0o775 } }, .{});
    try testing.expect(std.mem.startsWith(u8, w.buffered(), "rweb: /nowhere can be changed by members of group \""));
}
