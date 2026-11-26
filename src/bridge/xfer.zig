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
// unless sticky (as `/tmp` is), and not writable by its group unless sticky or the group holds no
// user but us and root (Linux's one group per user, the `admin` group of a Mac with one
// administrator). Otherwise a path that passes now could lead elsewhere later. The mode bits are not
// the whole answer: an access control list can let another user write (`checkPosixAcl`,
// `checkDarwinAcl`), and a filesystem another user mounted can report any owner and mode
// (`checkMount`); both are checked on every descriptor too.

/// The owner, group and mode (file type bits included) of an open descriptor.
pub const OwnerMode = struct { uid: u32, gid: u32 = 0, mode: u32 };

const S_IFMT: u32 = 0o170000;
const S_IFDIR: u32 = 0o040000;
const S_IFREG: u32 = 0o100000;
const S_IFSOCK: u32 = 0o140000;
const S_ISVTX: u32 = 0o1000;

/// What failed, for the message: the path that was being checked when it did.
pub const Problem = struct { path: []const u8 = "" };

pub const CheckError = error{
    /// A folder above the file is owned by someone other than root or us.
    FolderNotOurs,
    /// A folder above the file is writable by others and not sticky.
    FolderWritableByOthers,
    /// A folder above the file is writable by a group that holds another user, and not sticky.
    FolderWritableByGroup,
    NotADirectory,
    NotARegularFile,
    /// The file or folder is a symbolic link (never followed).
    SymLink,
    NotOwned,
    TooOpen,
    /// A program someone other than root or us could change.
    ProgramWritableByOthers,
    /// An access control list entry lets another user, or a group that holds one, change it.
    AclGivesOthersWrite,
    /// An access control list entry lets another user read or enter a private file or folder.
    AclGivesOthersAccess,
    /// Its access control list could not be read, or is not one this program understands.
    AclUnreadable,
    /// It is on a FUSE filesystem (Linux), whose owners and modes are whatever its server says.
    FuseFilesystem,
    /// It is on a filesystem another user mounted (macOS), with owners and modes that user chose.
    MountNotOurs,
    /// It is on a volume mounted with ownership ignored (macOS), where every user owns every file.
    MountIgnoresOwnership,
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

/// The entry `name` in folder `dir_fd`, never following a link.
pub fn statAt(dir_fd: posix.fd_t, name: []const u8) error{ FileNotFound, NameTooLong, StatFailed }!Node {
    var zbuf: [1024]u8 = undefined;
    if (name.len >= zbuf.len) return error.NameTooLong;
    @memcpy(zbuf[0..name.len], name);
    zbuf[name.len] = 0;
    const z: [*:0]const u8 = zbuf[0..name.len :0];
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

fn myUid() u32 {
    return @intCast(std.c.getuid());
}

/// A folder on the way to a private file: a directory that only root or we can change. A folder its
/// group can write to passes only when it is sticky or `group_private` (the group holds no user but
/// us and root, see `groupIsPrivate`); one others can write to passes only when sticky.
pub fn checkAncestor(om: OwnerMode, uid: u32, group_private: bool) CheckError!void {
    if (om.mode & S_IFMT != S_IFDIR) return error.NotADirectory;
    if (om.uid != 0 and om.uid != uid) return error.FolderNotOurs;
    if (om.mode & S_ISVTX != 0) return;
    if (om.mode & 0o002 != 0) return error.FolderWritableByOthers;
    if (om.mode & 0o020 != 0 and !group_private) return error.FolderWritableByGroup;
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
/// change (not writable by others, nor by its group unless `group_private`).
pub fn checkProgram(om: OwnerMode, uid: u32, group_private: bool) CheckError!void {
    if (om.mode & S_IFMT != S_IFREG) return error.NotARegularFile;
    if (om.uid != 0 and om.uid != uid) return error.NotOwned;
    if (om.mode & 0o002 != 0) return error.ProgramWritableByOthers;
    if (om.mode & 0o020 != 0 and !group_private) return error.ProgramWritableByOthers;
}

/// Whether a group holds no user but `uid` and root: every listed member (`member_uids`, from the
/// group's entry and, on macOS, the directory service) and every user who has it as their primary
/// group (`primary_uids`) is one of the two. Pure, so the rule is tested without real accounts.
pub fn groupHoldsOnly(member_uids: []const u32, primary_uids: []const u32, uid: u32) bool {
    for (member_uids) |m| if (m != 0 and m != uid) return false;
    for (primary_uids) |p| if (p != 0 and p != uid) return false;
    return true;
}

/// The account lookups below use the C library's shared buffers.
var accounts_mu: Io.Mutex = .init;

extern "c" fn mbr_uid_to_uuid(uid: std.c.uid_t, uu: *[16]u8) c_int;
extern "c" fn mbr_gid_to_uuid(gid: std.c.gid_t, uu: *[16]u8) c_int;
extern "c" fn mbr_check_membership(user: *const [16]u8, group: *const [16]u8, ismember: *c_int) c_int;

/// On macOS the `admin` group (gid 80): its members can become root with their own password, so a
/// folder only `admin` can write to is as safe as one only root can (`/Applications`, Homebrew's
/// folders). Refusing it would protect against nothing root could not do anyway.
pub const darwin_admin_gid: u32 = 80;

/// Whether a group-writable folder of group `gid` is safe for `uid`: the group holds no other user
/// (see `groupIsPrivate`), or it is macOS's root-equivalent `admin` group.
pub fn groupIsSafe(io: Io, gid: u32, uid: u32) bool {
    if (builtin.os.tag.isDarwin() and gid == darwin_admin_gid) return true;
    return groupIsPrivate(io, gid, uid);
}

/// Whether group `gid` holds no user but `uid` (and root), asked of the system.
///
/// Linux: only the one-group-per-user case passes (`ownGroupOnly`, over every passwd and group entry),
/// and only when the system takes accounts from its files alone (`accountsAreFilesOnly`): this
/// static program reads `/etc/passwd` and `/etc/group` only, so a group that another account source
/// (systemd, LDAP, `[SUCCESS=merge]`) adds members to would look empty to it.
///
/// Elsewhere (macOS): the group's listed members (`getgrgid`, each name looked up with `getpwnam`)
/// and every account (`getpwent`) whose primary group it is; on macOS also every account the
/// directory service counts as a member (`mbr_check_membership`, which sees nested groups that the
/// member list does not). Fails closed: a group the system does not know, a member name that is not
/// a user, or a lookup that fails counts as another user. Accounts the system cannot list (some
/// network directories) are not seen.
pub fn groupIsPrivate(io: Io, gid: u32, uid: u32) bool {
    if (builtin.os.tag == .linux) return linuxGroupIsPrivate(io, gid, uid);
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    accounts_mu.lockUncancelable(io);
    defer accounts_mu.unlock(io);
    var members: std.ArrayList(u32) = .empty;
    var primary: std.ArrayList(u32) = .empty;

    const gr = std.c.getgrgid(gid) orelse return false;
    // Copy the names first: a user lookup may reuse the group's buffer.
    var names: std.ArrayList([:0]const u8) = .empty;
    var i: usize = 0;
    while (gr.mem[i]) |m| : (i += 1) {
        const copy = a.dupeSentinel(u8, std.mem.span(m), 0) catch return false;
        names.append(a, copy) catch return false;
    }
    for (names.items) |n| {
        const id: u32 = if (std.c.getpwnam(n.ptr)) |pw| pw.uid else std.math.maxInt(u32);
        members.append(a, id) catch return false;
    }

    const darwin = builtin.os.tag.isDarwin();
    var group_uuid: [16]u8 = undefined;
    if (darwin and mbr_gid_to_uuid(gid, &group_uuid) != 0) return false;
    std.c.setpwent();
    defer std.c.endpwent();
    var seen: usize = 0;
    while (std.c.getpwent()) |pw| : (seen += 1) {
        if (seen > 1_000_000) return false;
        if (pw.gid == gid) primary.append(a, pw.uid) catch return false;
        if (darwin and pw.uid != 0 and pw.uid != uid) {
            var user_uuid: [16]u8 = undefined;
            var is_member: c_int = 1;
            if (mbr_uid_to_uuid(pw.uid, &user_uuid) != 0 or mbr_check_membership(&user_uuid, &group_uuid, &is_member) != 0) is_member = 1;
            if (is_member != 0) members.append(a, pw.uid) catch return false;
        }
    }
    return groupHoldsOnly(members.items, primary.items, uid);
}

/// Linux: one passwd entry and one group entry, as much of them as `ownGroupOnly` needs.
pub const PasswdEntry = struct { name: []const u8, uid: u32, gid: u32 };
pub const GroupEntry = struct { name: []const u8, gid: u32, members: usize };

/// Linux's one group per user, the only group-writable case trusted there: group `gid` is `uid`'s
/// primary group and has that user's name, it is the only group entry with that gid and lists no
/// members, and no other account has it as its primary group. `users` and `groups` are every entry
/// of the account files; a list without root and `uid` is taken as incomplete (false). Pure, so the
/// rule is tested without real accounts.
pub fn ownGroupOnly(gid: u32, uid: u32, users: []const PasswdEntry, groups: []const GroupEntry) bool {
    var saw_root = false;
    var me: ?PasswdEntry = null;
    for (users) |u| {
        if (u.uid == 0) saw_root = true;
        if (u.uid == uid and me == null) me = u; // the entry `getpwuid` would give
        if (u.gid == gid and u.uid != uid) return false; // someone else's primary group too
    }
    const mine = me orelse return false;
    if (!saw_root or mine.gid != gid or mine.name.len == 0) return false;
    var found: usize = 0;
    for (groups) |g| {
        if (g.gid != gid) continue;
        found += 1;
        if (!std.mem.eql(u8, g.name, mine.name) or g.members != 0) return false;
    }
    return found == 1;
}

/// Whether `nsswitch.conf` (its text) takes users and groups from the account files alone: every
/// `passwd` and `group` line lists `files` and nothing else (no other source, no action such as
/// `[SUCCESS=merge]`). A database without a line uses the files.
pub fn nsswitchFilesOnly(text: []const u8) bool {
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |raw| {
        const line = if (std.mem.indexOfScalar(u8, raw, '#')) |i| raw[0..i] else raw;
        const colon = std.mem.indexOfScalar(u8, line, ':') orelse continue;
        const db = std.mem.trim(u8, line[0..colon], " \t\r");
        if (!std.mem.eql(u8, db, "passwd") and !std.mem.eql(u8, db, "group")) continue;
        var sources = std.mem.tokenizeAny(u8, line[colon + 1 ..], " \t\r");
        var any = false;
        while (sources.next()) |s| {
            if (!std.mem.eql(u8, s, "files")) return false;
            any = true;
        }
        if (!any) return false;
    }
    return true;
}

/// Whether this system takes accounts from its files alone (`nsswitchFilesOnly`), read from
/// `/etc/nsswitch.conf`, else `/usr/etc/nsswitch.conf` (where some distributions keep the default);
/// with neither, the C library uses the files. A file that cannot be read counts as other sources.
fn accountsAreFilesOnly(arena: Allocator, io: Io) bool {
    for ([_][]const u8{ "/etc/nsswitch.conf", "/usr/etc/nsswitch.conf" }) |p| {
        const fd = posix.openat(posix.AT.FDCWD, p, .{ .ACCMODE = .RDONLY, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| switch (e) {
            error.FileNotFound => continue,
            else => return false,
        };
        defer closeFd(io, fd);
        const buf = arena.alloc(u8, 256 * 1024) catch return false;
        var n: usize = 0;
        while (n < buf.len) {
            const got = posix.read(fd, buf[n..]) catch return false;
            if (got == 0) break;
            n += got;
        }
        if (n == buf.len) return false;
        return nsswitchFilesOnly(buf[0..n]);
    }
    return true;
}

/// Linux: `ownGroupOnly` over every passwd and group entry, when accounts come from the files alone.
fn linuxGroupIsPrivate(io: Io, gid: u32, uid: u32) bool {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    if (!accountsAreFilesOnly(a, io)) return false;
    accounts_mu.lockUncancelable(io);
    defer accounts_mu.unlock(io);
    var users: std.ArrayList(PasswdEntry) = .empty;
    var groups: std.ArrayList(GroupEntry) = .empty;
    {
        std.c.setpwent();
        defer std.c.endpwent();
        while (std.c.getpwent()) |pw| {
            if (users.items.len >= 1_000_000) return false;
            const name = a.dupe(u8, if (pw.name) |n| std.mem.span(n) else "") catch return false;
            users.append(a, .{ .name = name, .uid = pw.uid, .gid = pw.gid }) catch return false;
        }
    }
    {
        std.c.setgrent();
        defer std.c.endgrent();
        while (std.c.getgrent()) |gr| {
            if (groups.items.len >= 1_000_000) return false;
            var members: usize = 0;
            while (gr.mem[members] != null) members += 1;
            const name = a.dupe(u8, if (gr.name) |n| std.mem.span(n) else "") catch return false;
            groups.append(a, .{ .name = name, .gid = gr.gid, .members = members }) catch return false;
        }
    }
    return ownGroupOnly(gid, uid, users.items, groups.items);
}

/// Tests only: the answer `groupAnswer` gives instead of asking the system (a test cannot make a
/// group that holds only its user). Null: ask the system.
pub var test_group_private: ?bool = null;

fn groupAnswer(io: Io, gid: u32, uid: u32) bool {
    if (builtin.is_test) if (test_group_private) |v| return v;
    return groupIsSafe(io, gid, uid);
}

/// Writable by its group, and by nobody else past a sticky bit: the only case the group's members
/// decide.
fn groupDecides(om: OwnerMode) bool {
    return om.mode & 0o020 != 0 and om.mode & 0o002 == 0 and om.mode & S_ISVTX == 0;
}

// ---- filesystems ----

/// What a descriptor's filesystem says about who controls it.
pub const Mount = struct {
    /// Linux: the filesystem's magic number (`statfs.f_type`).
    linux_type: ?u64 = null,
    /// macOS: the user who mounted it (`statfs.f_owner`).
    owner: ?u32 = null,
    /// macOS: mounted with ownership ignored (`MNT_IGNORE_OWNERSHIP`, "Ignore ownership on this
    /// volume"), so every file looks like the looker's own.
    ignores_ownership: bool = false,
};

/// Linux's `FUSE_SUPER_MAGIC` (`fuse` and `fuseblk`).
pub const fuse_super_magic: u64 = 0x65735546;
const darwin_mnt_ignore_ownership: u32 = 0x00200000;

/// A filesystem whose owners and modes mean what they say: not FUSE (its server, another user's
/// with `allow_other`, reports whatever it likes), not mounted by another user (a disk image they
/// attached), and not ignoring ownership. Network filesystems (NFS, SMB) pass: their server decides
/// who may write, by rules that cannot be seen from here. Pure.
pub fn checkMount(m: Mount, uid: u32) CheckError!void {
    if (m.linux_type) |t| if (t == fuse_super_magic) return error.FuseFilesystem;
    if (m.owner) |o| if (o != 0 and o != uid) return error.MountNotOurs;
    if (m.ignores_ownership) return error.MountIgnoresOwnership;
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
        // `struct statfs` starts with `f_type`, a word on the 64-bit systems this is built for.
        var buf: [64]usize = undefined;
        const rc = linux.syscall2(.fstatfs, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(&buf));
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        return .{ .linux_type = buf[0] };
    }
    if (builtin.os.tag.isDarwin()) {
        const fstatfs = @extern(*const fn (c_int, *DarwinStatfs) callconv(.c) c_int, .{ .name = if (builtin.cpu.arch == .x86_64) "fstatfs$INODE64" else "fstatfs" });
        var sb: DarwinStatfs = undefined;
        if (fstatfs(fd, &sb) != 0) return error.StatFailed;
        return .{ .owner = sb.f_owner, .ignores_ownership = sb.f_flags & darwin_mnt_ignore_ownership != 0 };
    }
    return .{};
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
/// 0700 folders and 0600 files. Pure.
pub fn checkPosixAcl(blob: []const u8, uid: u32, file_gid: u32, ctx: anytype, comptime groupSafe: fn (@TypeOf(ctx), u32) bool) CheckError!void {
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
        switch (tag) {
            A.user => if (id != 0 and id != uid) return error.AclGivesOthersWrite,
            A.group => if (!groupSafe(ctx, id)) return error.AclGivesOthersWrite,
            A.group_obj => if (!groupSafe(ctx, file_gid)) return error.AclGivesOthersWrite,
            else => {},
        }
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

/// macOS: whether ACL `entries` let anyone but root, `uid` or a safe group (`groupSafe`; never
/// `everyone`) change the file or folder (`darwin_acl.changes`), or, when `private`, have any access
/// to it. Deny entries (such as every home folder's `everyone deny delete`) take nothing away from
/// the mode's answer, so they pass. An entry whose user or group is not known counts as another
/// user's. Pure.
pub fn checkDarwinAcl(entries: []const DarwinAce, uid: u32, use: AclUse, ctx: anytype, comptime groupSafe: fn (@TypeOf(ctx), u32) bool) CheckError!void {
    for (entries) |e| {
        if (!e.allow) continue;
        if (use == .shared and e.only_inherit) continue;
        const relevant = darwin_acl.changes | (if (use == .private) darwin_acl.private_also else 0);
        if (e.perms & relevant == 0) continue;
        const trusted = switch (e.who) {
            .user => |u| u == 0 or u == uid,
            .group => |g| g != darwin_everyone_gid and groupSafe(ctx, g),
            .unknown => false,
        };
        if (trusted) continue;
        return if (e.perms & darwin_acl.changes != 0) error.AclGivesOthersWrite else error.AclGivesOthersAccess;
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
        // ENOENT: no ACL; ENOTSUP, EOPNOTSUPP: a filesystem without ACLs.
        return if (err == 2 or err == 45 or err == 102) out[0..0] else error.AclUnreadable;
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
    io: Io,
    uid: u32,

    fn safe(r: GroupRule, gid: u32) bool {
        return groupAnswer(r.io, gid, r.uid);
    }
};

/// Whether the group-write bit of `om` (a folder or program of root's or ours that nobody else may
/// write to) is safe. On Linux with an ACL that bit is the ACL's mask, so each entry it lets write is
/// decided (`checkPosixAcl`); otherwise the file's group must hold no other user (`groupAnswer`).
fn groupWriteSafe(io: Io, fd: posix.fd_t, om: OwnerMode, uid: u32) CheckError!bool {
    if (builtin.os.tag == .linux) {
        var buf: [16 * 1024]u8 = undefined;
        if (try readPosixAcl(fd, &buf)) |blob| {
            try checkPosixAcl(blob, uid, om.gid, GroupRule{ .io = io, .uid = uid }, GroupRule.safe);
            return true;
        }
    }
    return groupAnswer(io, om.gid, uid);
}

/// What every checked descriptor must pass besides its owner and mode: its filesystem
/// (`checkMount`) and, on macOS, its ACL (`checkDarwinAcl`; on Linux the mode's group bits bound
/// what an ACL gives, see `groupWriteSafe`).
fn checkFdExtras(io: Io, fd: posix.fd_t, uid: u32, use: AclUse) CheckError!void {
    try checkMount(fdMount(fd) catch return error.StatFailed, uid);
    if (builtin.os.tag.isDarwin()) {
        var aces: [darwin_acl.max_entries]DarwinAce = undefined;
        try checkDarwinAcl(try readDarwinAcl(fd, &aces), uid, use, GroupRule{ .io = io, .uid = uid }, GroupRule.safe);
    }
}

fn checkAncestorFd(io: Io, fd: posix.fd_t, uid: u32) CheckError!void {
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    // The accounts (and a Linux ACL) are looked at only when the answer depends on them.
    const ask = groupDecides(om) and (om.uid == 0 or om.uid == uid) and om.mode & S_IFMT == S_IFDIR;
    try checkAncestor(om, uid, ask and try groupWriteSafe(io, fd, om, uid));
    try checkFdExtras(io, fd, uid, .shared);
}

/// A program on an open descriptor: `checkProgram`, an ACL that lets nobody else change it, and a
/// filesystem whose owners mean what they say.
pub fn checkProgramFd(io: Io, fd: posix.fd_t, uid: u32) CheckError!void {
    const om = fdOwnerMode(fd) catch return error.StatFailed;
    const ask = om.mode & S_IFMT == S_IFREG and (om.uid == 0 or om.uid == uid) and om.mode & 0o020 != 0 and om.mode & 0o002 == 0;
    try checkProgram(om, uid, ask and try groupWriteSafe(io, fd, om, uid));
    try checkFdExtras(io, fd, uid, .shared);
}

/// A private folder (the upload folder, the socket's) on an open descriptor: `checkPrivateDir`, an
/// ACL that gives nobody else any access, and a filesystem whose owners mean what they say.
pub fn checkPrivateDirFd(io: Io, fd: posix.fd_t) CheckError!void {
    const uid = myUid();
    try checkPrivateDir(fdOwnerMode(fd) catch return error.StatFailed, uid);
    try checkFdExtras(io, fd, uid, .private);
}

fn checkPrivateFileFd(io: Io, fd: posix.fd_t) CheckError!void {
    const uid = myUid();
    try checkPrivateFile(fdOwnerMode(fd) catch return error.StatFailed, uid);
    try checkFdExtras(io, fd, uid, .private);
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
        if (n.mode & S_IFMT == 0o120000) return error.SymLink;
    } else |_| {};
    return openFailed(e);
}

/// Open the folder at the absolute path `dir` one component at a time from `/`, never following a
/// link (a link anywhere on the way is refused, so the path names exactly the folders checked), and
/// check each with `checkAncestor`. With `create`, a missing folder is made 0700 inside its checked
/// parent, then checked like the rest. The caller closes the descriptor; on failure `problem.path`
/// names the folders down to the one that failed.
pub fn openChain(io: Io, dir: []const u8, create: bool, problem: *Problem) OpenError!posix.fd_t {
    problem.path = dir;
    if (dir.len == 0 or dir[0] != '/') return error.BadPath;
    const uid = myUid();
    problem.path = "/";
    var fd = posix.openat(posix.AT.FDCWD, "/", .{ .DIRECTORY = true, .CLOEXEC = true }, 0) catch |e| return openFailed(e);
    errdefer closeFd(io, fd);
    try checkAncestorFd(io, fd, uid);
    var it = std.mem.tokenizeScalar(u8, dir, '/');
    while (it.next()) |comp| {
        problem.path = dir[0..it.index]; // the folders down to this one
        if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return error.BadPath;
        const next = try openFolderAt(io, fd, comp, create);
        closeFd(io, fd);
        fd = next;
        try checkAncestorFd(io, fd, uid);
    }
    return fd;
}

/// Open the folder that holds `path`, by its real path, with `openChain`. Returns the folder's
/// descriptor (the caller closes it), its real path and the last component of `path`.
fn openParent(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError!struct { fd: posix.fd_t, base: []const u8, real_parent: []const u8 } {
    problem.path = path;
    const base = std.fs.path.basename(path);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.BadPath;
    const parent = std.fs.path.dirname(path) orelse ".";
    problem.path = parent;
    const real = try Io.Dir.cwd().realPathFileAlloc(io, parent, arena);
    if (real.len == 0 or real[0] != '/') return error.BadPath;
    const fd = try openChain(io, real, false, problem);
    problem.path = path;
    return .{ .fd = fd, .base = base, .real_parent = real };
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
    try checkPrivateFileFd(io, fd);
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

/// The real path of `path` when it exists; otherwise the real path of the deepest folder above it
/// that does, followed by the names that are missing (which `openChain` then makes, inside folders
/// it has checked).
fn realOrMissing(arena: Allocator, io: Io, path: []const u8) OpenError![]const u8 {
    var head = path;
    var missing: std.ArrayList([]const u8) = .empty; // deepest first
    while (true) {
        if (Io.Dir.cwd().realPathFileAlloc(io, head, arena)) |real| {
            var out: []const u8 = real;
            var k = missing.items.len;
            while (k > 0) {
                k -= 1;
                const comp = missing.items[k];
                if (std.mem.eql(u8, comp, ".") or std.mem.eql(u8, comp, "..")) return error.BadPath;
                out = try std.fs.path.join(arena, &.{ out, comp });
            }
            if (out.len == 0 or out[0] != '/') return error.BadPath;
            return out;
        } else |e| switch (e) {
            error.FileNotFound => {
                const comp = std.fs.path.basename(head);
                const up = std.fs.path.dirname(head) orelse return e;
                if (comp.len == 0) return e;
                try missing.append(arena, comp);
                head = up;
            },
            else => return e,
        }
    }
}

/// The upload folder, opened and kept by the caller for as long as uploads may go into it, and its
/// real path (what is pasted into the terminal and shown to the page). The folders above it must pass
/// `checkAncestor` (missing ones are made 0700, each inside its checked parent); the folder itself is
/// made 0700 if missing, opened without following a link and must be a private folder of ours.
pub const UploadDir = struct { dir: Io.Dir, real_path: []const u8 };

pub fn openUploadDir(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError!UploadDir {
    problem.path = path;
    const trimmed = std.mem.trimEnd(u8, path, "/");
    if (trimmed.len == 0 or trimmed[0] != '/') return error.BadPath;
    const base = std.fs.path.basename(trimmed);
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.BadPath;
    const real_parent = try realOrMissing(arena, io, std.fs.path.dirname(trimmed) orelse "/");
    const pfd = try openChain(io, real_parent, true, problem);
    defer closeFd(io, pfd);
    problem.path = path;
    const fd = try openFolderAt(io, pfd, base, true);
    errdefer closeFd(io, fd);
    try checkPrivateDirFd(io, fd);
    return .{ .dir = .{ .handle = fd }, .real_path = try std.fs.path.join(arena, &.{ real_parent, base }) };
}

/// The program at `path`, checked, and the exact path to run it by. Its real path is resolved once;
/// the folders on that path are then opened one by one from `/` without following a link
/// (`openChain`: a folder swapped for a link since is refused, so the folders checked are the ones
/// that path names, and none can be changed by another user); the program is opened inside the last
/// of them, again without following a link, and checked on that descriptor (`checkProgramFd`). The
/// path returned is that folder's path joined with the program's name: with every folder on it fixed,
/// it leads to the file that was checked. On failure `problem.path` names what failed.
pub fn checkedProgram(arena: Allocator, io: Io, path: []const u8, problem: *Problem) OpenError![]const u8 {
    problem.path = path;
    if (path.len == 0 or path[0] != '/') return error.BadPath;
    const real = try Io.Dir.cwd().realPathFileAlloc(io, path, arena);
    problem.path = real;
    if (real.len == 0 or real[0] != '/') return error.BadPath;
    const base = std.fs.path.basename(real);
    const parent = std.fs.path.dirname(real) orelse return error.BadPath;
    if (base.len == 0 or std.mem.eql(u8, base, ".") or std.mem.eql(u8, base, "..")) return error.BadPath;
    const pfd = try openChain(io, parent, false, problem);
    defer closeFd(io, pfd);
    problem.path = real;
    // Without blocking, so a FIFO put there cannot hang startup; it then fails as not a regular file.
    const fd = posix.openat(pfd, base, .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .CLOEXEC = true, .NONBLOCK = true, .NOCTTY = true }, 0) catch |e| return openFailed(e);
    defer closeFd(io, fd);
    try checkProgramFd(io, fd, myUid());
    return std.fs.path.join(arena, &.{ parent, base });
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
    try testing.expectError(error.ProgramWritableByOthers, checkProgram(.{ .uid = me, .mode = S_IFREG | 0o775 }, me, false));
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

test "a group holds only us and root, or it is shared" {
    const me: u32 = 501;
    try testing.expect(groupHoldsOnly(&.{}, &.{}, me));
    try testing.expect(groupHoldsOnly(&.{ 0, me }, &.{me}, me)); // Linux's one group per user
    try testing.expect(groupHoldsOnly(&.{ 0, me }, &.{}, me)); // a Mac's admin group with one administrator
    try testing.expect(!groupHoldsOnly(&.{ 0, me, 502 }, &.{}, me)); // a second administrator
    try testing.expect(!groupHoldsOnly(&.{me}, &.{ me, 503 }, me)); // someone else's primary group
    try testing.expect(!groupHoldsOnly(&.{std.math.maxInt(u32)}, &.{}, me)); // a member name that is no user
}

test "a folder its group can write to passes only when the group holds no one else" {
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
    defer test_group_private = null;
    var p: Problem = .{};
    // A group of us (and root) alone: the folder, and a program it can write, are ours in effect.
    test_group_private = true;
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try testing.expectEqualStrings(prog, try checkedProgram(arena, io, prog, &p));
    const up = try openUploadDir(arena, io, try std.fmt.allocPrint(arena, "{s}/grp/uploads", .{root}), &p);
    up.dir.close(io);
    // A shared group: refused, and the folder named.
    test_group_private = false;
    try testing.expectError(error.FolderWritableByGroup, readPrivateFile(arena, io, file, 4096, &p));
    try testing.expect(std.mem.endsWith(u8, p.path, "/grp"));
    try testing.expectError(error.FolderWritableByGroup, checkedProgram(arena, io, prog, &p));
}

test "a group the system does not know is not private" {
    try testing.expect(!groupIsPrivate(testing.io, 0x7ffe_1234, myUid()));
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
    try testing.expect(std.mem.endsWith(u8, p.path, "/open"));
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

test "macOS's admin group counts as root's; another shared group does not" {
    if (!builtin.os.tag.isDarwin()) return error.SkipZigTest;
    try testing.expect(groupIsSafe(testing.io, darwin_admin_gid, myUid()));
    try testing.expect(!groupIsSafe(testing.io, 0x7ffe_1234, myUid()));
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
            return checkPosixAcl(posixAclBlob(b, all[0 .. 3 + extra.len]), me, gid, g, FakeGroups.safe);
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
    try testing.expectError(error.AclGivesOthersWrite, check(&buf, &.{ .{ A.group, 7, 4242 }, .{ A.mask, 7, no_id } }, 1000, groups));
    // The owning group, with write through the mask: decided by the file's group.
    var gw = base;
    gw[1][1] = 7;
    try checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 7, no_id }})), me, 1000, groups, FakeGroups.safe);
    try testing.expectError(error.AclGivesOthersWrite, checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 7, no_id }})), me, 4242, groups, FakeGroups.safe));
    try checkPosixAcl(posixAclBlob(&buf, &(gw ++ [_][3]u32{.{ A.mask, 5, no_id }})), me, 4242, groups, FakeGroups.safe);
}

test "a POSIX ACL that is not one is refused" {
    const A = posix_acl;
    const g = FakeGroups{ .safe_gids = &.{} };
    var buf: [64]u8 = undefined;
    const ok = posixAclBlob(&buf, &.{.{ A.user_obj, 7, 0 }});
    try checkPosixAcl(ok, 1000, 1000, g, FakeGroups.safe);
    try testing.expectError(error.AclUnreadable, checkPosixAcl(ok[0..3], 1000, 1000, g, FakeGroups.safe)); // too short
    try testing.expectError(error.AclUnreadable, checkPosixAcl(ok[0 .. ok.len - 1], 1000, 1000, g, FakeGroups.safe)); // a cut entry
    var v1: [12]u8 = ok[0..12].*;
    v1[0] = 1;
    try testing.expectError(error.AclUnreadable, checkPosixAcl(&v1, 1000, 1000, g, FakeGroups.safe)); // another version
    try testing.expectError(error.AclUnreadable, checkPosixAcl(posixAclBlob(&buf, &.{.{ 0x40, 7, 5 }}), 1000, 1000, g, FakeGroups.safe)); // an unknown tag
    try testing.expectError(error.AclUnreadable, checkPosixAcl(posixAclBlob(&buf, &.{ .{ A.mask, 7, 0 }, .{ A.mask, 5, 0 } }), 1000, 1000, g, FakeGroups.safe)); // two masks
}

test "a macOS ACL may let only root, us or a safe group change things; deny entries pass" {
    const P = darwin_acl;
    const me: u32 = 501;
    const nobody: u32 = 4294967294;
    const g = FakeGroups{ .safe_gids = &.{ darwin_admin_gid, darwin_everyone_gid } };
    const deny_delete: DarwinAce = .{ .allow = false, .perms = P.delete, .who = .{ .group = darwin_everyone_gid } };
    // Every home folder's entry.
    try checkDarwinAcl(&.{deny_delete}, me, .shared, g, FakeGroups.safe);
    try checkDarwinAcl(&.{deny_delete}, me, .private, g, FakeGroups.safe);
    // Another user who may add a file, add a folder, delete, change the ACL or take ownership.
    for ([_]u64{ P.write_data, P.append_data, P.delete_child, P.delete, P.write_security, P.change_owner }) |perm| {
        try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = perm, .who = .{ .user = nobody } }}, me, .shared, g, FakeGroups.safe));
    }
    // Root and us may.
    try checkDarwinAcl(&.{ .{ .allow = true, .perms = P.changes, .who = .{ .user = 0 } }, .{ .allow = true, .perms = P.changes, .who = .{ .user = me } } }, me, .shared, g, FakeGroups.safe);
    // Reading is fine on the way, not on a private file or folder.
    const read: DarwinAce = .{ .allow = true, .perms = P.read_data | P.execute, .who = .{ .user = nobody } };
    try checkDarwinAcl(&.{read}, me, .shared, g, FakeGroups.safe);
    try testing.expectError(error.AclGivesOthersAccess, checkDarwinAcl(&.{read}, me, .private, g, FakeGroups.safe));
    // An entry only for new items: not this folder's, unless what it passes on is private (uploads).
    const inherit: DarwinAce = .{ .allow = true, .only_inherit = true, .perms = P.write_data, .who = .{ .user = nobody } };
    try checkDarwinAcl(&.{inherit}, me, .shared, g, FakeGroups.safe);
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{inherit}, me, .private, g, FakeGroups.safe));
    // Groups: a safe one may, `everyone` never (whatever the group rule says), another may not.
    try checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_admin_gid } }}, me, .shared, g, FakeGroups.safe);
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .{ .group = darwin_everyone_gid } }}, me, .shared, g, FakeGroups.safe));
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.delete_child, .who = .{ .group = 20 } }}, me, .shared, g, FakeGroups.safe));
    // Someone the directory service does not know is someone else.
    try testing.expectError(error.AclGivesOthersWrite, checkDarwinAcl(&.{.{ .allow = true, .perms = P.write_data, .who = .unknown }}, me, .shared, g, FakeGroups.safe));
}

test "a filesystem another user controls is refused" {
    const me: u32 = 501;
    try checkMount(.{}, me);
    try checkMount(.{ .linux_type = 0xEF53 }, me); // ext4
    try checkMount(.{ .linux_type = 0x6969 }, me); // NFS: its server decides, out of sight
    try testing.expectError(error.FuseFilesystem, checkMount(.{ .linux_type = fuse_super_magic }, me));
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

test "Linux trusts a group-writable folder only for the user's own group, seen whole" {
    const me: u32 = 1000;
    const users = [_]PasswdEntry{ .{ .name = "root", .uid = 0, .gid = 0 }, .{ .name = "me", .uid = me, .gid = 1000 }, .{ .name = "bob", .uid = 1001, .gid = 1001 } };
    const groups = [_]GroupEntry{ .{ .name = "root", .gid = 0, .members = 0 }, .{ .name = "me", .gid = 1000, .members = 0 }, .{ .name = "bob", .gid = 1001, .members = 0 }, .{ .name = "staff", .gid = 50, .members = 2 } };
    try testing.expect(ownGroupOnly(1000, me, &users, &groups));
    // Another group, someone else's, root's: no.
    try testing.expect(!ownGroupOnly(50, me, &users, &groups));
    try testing.expect(!ownGroupOnly(1001, me, &users, &groups));
    try testing.expect(!ownGroupOnly(0, me, &users, &groups));
    // A group the files do not list.
    try testing.expect(!ownGroupOnly(4242, me, &users, &groups));
    // Members listed, another name, a second entry with the same gid.
    try testing.expect(!ownGroupOnly(1000, me, &users, &[_]GroupEntry{ groups[0], .{ .name = "me", .gid = 1000, .members = 1 } }));
    try testing.expect(!ownGroupOnly(1000, me, &users, &[_]GroupEntry{ groups[0], .{ .name = "devs", .gid = 1000, .members = 0 } }));
    try testing.expect(!ownGroupOnly(1000, me, &users, &[_]GroupEntry{ groups[0], groups[1], .{ .name = "sneaky", .gid = 1000, .members = 1 } }));
    // Another account with it as its primary group.
    try testing.expect(!ownGroupOnly(1000, me, &[_]PasswdEntry{ users[0], users[1], .{ .name = "eve", .uid = 1002, .gid = 1000 } }, &groups));
    // Not my primary group.
    try testing.expect(!ownGroupOnly(1000, me, &[_]PasswdEntry{ users[0], .{ .name = "me", .uid = me, .gid = 100 } }, &groups));
    // Account files that do not list root, or me: incomplete.
    try testing.expect(!ownGroupOnly(1000, me, users[1..], &groups));
    try testing.expect(!ownGroupOnly(1000, me, &[_]PasswdEntry{ users[0], users[2] }, &groups));
}

test "accounts come from the files alone only when nsswitch.conf says files and nothing else" {
    try testing.expect(nsswitchFilesOnly(""));
    try testing.expect(nsswitchFilesOnly("passwd: files\ngroup: files\nhosts: files dns\n"));
    try testing.expect(nsswitchFilesOnly("# comment\npasswd:\tfiles # trailing\n  group :  files\r\nshadow: files sss\n"));
    try testing.expect(nsswitchFilesOnly("hosts: files mdns4_minimal dns\n")); // no line: the files
    try testing.expect(!nsswitchFilesOnly("passwd: files systemd\ngroup: files\n"));
    try testing.expect(!nsswitchFilesOnly("passwd: files\ngroup: files [SUCCESS=merge] systemd\n"));
    try testing.expect(!nsswitchFilesOnly("passwd: compat\n"));
    try testing.expect(!nsswitchFilesOnly("passwd: files sss\n"));
    try testing.expect(!nsswitchFilesOnly("group:\n"));
    try testing.expect(!nsswitchFilesOnly("passwd: files\npasswd: ldap\n"));
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
    try testing.expect(std.mem.endsWith(u8, p.path, "/acl"));
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
    try testing.expect(std.mem.endsWith(u8, p.path, "/acl"));
    // A mask without write: the named user can no longer write, and the folder passes.
    try runTool(arena, io, &.{ "setfacl", "-m", "m::r-x", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
    try runTool(arena, io, &.{ "setfacl", "-b", dir });
    try testing.expectEqualStrings("secret", try readPrivateFile(arena, io, file, 4096, &p));
}
