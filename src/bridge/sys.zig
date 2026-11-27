//! Every raw system and C library call the bridge makes, in one place. What std wraps (`std.posix`,
//! `std.Io`) is used directly elsewhere; this file holds what it does not. Each function here returns a
//! Zig error set or a plain value: no status code or `errno` leaves this file. Each C function or struct
//! declared by hand says which targets it is right for and carries a compile-time guard.
//!
//! The Rex library has one raw call of its own, `rex.ws.peerUid` (`getpeereid`, `SO_PEERCRED`), kept
//! there because the library cannot import the bridge; it is guarded the same way.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const c = std.c;

comptime {
    if (builtin.os.tag != .linux and !builtin.os.tag.isDarwin()) @compileError("rweb runs on Linux and macOS only");
}

// ---- who we are ----

pub fn uid() u32 {
    return @intCast(c.getuid());
}

pub fn gid() u32 {
    return @intCast(c.getgid());
}

/// `HOME` from the environment the C library holds, or null.
pub fn home() ?[]const u8 {
    return std.mem.span(c.getenv("HOME") orelse return null);
}

/// A user's name from the system's user database, copied into `buf`; null when there is none or it
/// does not fit.
pub fn userName(id: u32, buf: []u8) ?[]const u8 {
    const pw = c.getpwuid(@intCast(id)) orelse return null;
    return copyName(std.mem.span(pw.name orelse return null), buf);
}

/// A group's name from the system's group database, copied into `buf`; null as for `userName`.
pub fn groupName(id: u32, buf: []u8) ?[]const u8 {
    const gr = c.getgrgid(@intCast(id)) orelse return null;
    return copyName(std.mem.span(gr.name orelse return null), buf);
}

fn copyName(name: []const u8, buf: []u8) ?[]const u8 {
    if (name.len == 0 or name.len > buf.len) return null;
    @memcpy(buf[0..name.len], name);
    return buf[0..name.len];
}

// ---- in a signal handler ----

/// End the process at once (`_exit`): no `defer`, no flush. Safe in a signal handler.
pub fn exitNow(code: u8) noreturn {
    c._exit(code);
}

/// Remove `name` in folder `dir_fd`, if it can be. Safe in a signal handler; the result is not
/// looked at, since the process is ending and has nobody to tell.
pub fn unlinkAtBestEffort(dir_fd: posix.fd_t, name: [*:0]const u8) void {
    _ = c.unlinkat(dir_fd, name, 0);
}

// ---- files ----

/// Set the process's file mode creation mask, returning the one it replaces.
pub fn umask(mask: c.mode_t) c.mode_t {
    return c.umask(mask);
}

pub fn chmod(path: [*:0]const u8, mode: c.mode_t) error{ChmodFailed}!void {
    if (c.chmod(path, mode) != 0) return error.ChmodFailed;
}

/// Make a named pipe (tests use one as a file that is neither regular nor a folder).
pub fn mkfifo(path: [*:0]const u8, mode: c.mode_t) error{MkfifoFailed}!void {
    const mkfifo_c = @extern(*const fn ([*:0]const u8, c.mode_t) callconv(.c) c_int, .{ .name = "mkfifo" });
    if (mkfifo_c(path, mode) != 0) return error.MkfifoFailed;
}

/// Owner, group and mode of a file or folder.
pub const OwnerMode = struct { uid: u32, gid: u32 = 0, mode: u32 };

/// What a folder entry is, looked at without following a link.
pub const Node = struct { dev: u64, ino: u64, uid: u32, gid: u32, mode: u32 };

pub fn fdOwnerMode(fd: posix.fd_t) error{StatFailed}!OwnerMode {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const rc = linux.statx(fd, "", linux.AT.EMPTY_PATH, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true }, &stx);
        if (linux.errno(rc) != .SUCCESS) return error.StatFailed;
        return .{ .uid = stx.uid, .gid = stx.gid, .mode = stx.mode };
    } else {
        var sb: c.Stat = undefined;
        if (c.fstat(fd, &sb) != 0) return error.StatFailed;
        return .{ .uid = @intCast(sb.uid), .gid = @intCast(sb.gid), .mode = @intCast(sb.mode) };
    }
}

/// The entry `name` in folder `dir_fd`, never following a link.
pub fn statAt(dir_fd: posix.fd_t, name: [*:0]const u8) error{ FileNotFound, StatFailed }!Node {
    if (builtin.os.tag == .linux) {
        const linux = std.os.linux;
        var stx: linux.Statx = undefined;
        const rc = linux.statx(dir_fd, name, linux.AT.SYMLINK_NOFOLLOW, .{ .TYPE = true, .MODE = true, .UID = true, .GID = true, .INO = true }, &stx);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .NOENT => return error.FileNotFound,
            else => return error.StatFailed,
        }
        return .{ .dev = (@as(u64, stx.dev_major) << 32) | stx.dev_minor, .ino = stx.ino, .uid = stx.uid, .gid = stx.gid, .mode = stx.mode };
    } else {
        var sb: c.Stat = undefined;
        const rc = c.fstatat(dir_fd, name, &sb, c.AT.SYMLINK_NOFOLLOW);
        switch (c.errno(rc)) {
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
pub fn readLinkAt(dir_fd: posix.fd_t, name: [*:0]const u8, buf: []u8) error{ NameTooLong, ReadFailed }![]const u8 {
    const n = c.readlinkat(dir_fd, name, buf.ptr, buf.len);
    if (n < 0) return error.ReadFailed;
    const len: usize = @intCast(n);
    if (len >= buf.len) return error.NameTooLong;
    return buf[0..len];
}

/// Give `old_dir`'s `old_name` the further name `new_name` in `new_dir`; never replaces a name.
pub fn linkAt(old_dir: posix.fd_t, old_name: [*:0]const u8, new_dir: posix.fd_t, new_name: [*:0]const u8) error{ PathAlreadyExists, AccessDenied, NoSpaceLeft, DiskQuota, ReadOnlyFileSystem, LinkFailed }!void {
    if (c.linkat(old_dir, old_name, new_dir, new_name, 0) == 0) return;
    return switch (c.errno(@as(c_int, -1))) {
        .EXIST => error.PathAlreadyExists,
        .ACCES, .PERM => error.AccessDenied,
        .NOSPC => error.NoSpaceLeft,
        .DQUOT => error.DiskQuota,
        .ROFS => error.ReadOnlyFileSystem,
        else => error.LinkFailed,
    };
}

/// macOS: flush a file or folder to the disk itself (`F_FULLFSYNC`; `fsync` stops at the drive's own
/// cache). `error.Unsupported` when the filesystem or device has no full flush, so the caller falls
/// back to `fsync`; an answer nobody listed is taken the same way, since `fsync` still reports a real
/// failure.
pub fn fullFsync(fd: posix.fd_t) error{ Unsupported, InputOutput, NoSpaceLeft, DiskQuota, AccessDenied }!void {
    if (comptime !builtin.os.tag.isDarwin()) return error.Unsupported;
    while (true) {
        if (c.fcntl(fd, c.F.FULLFSYNC, @as(c_int, 0)) == 0) return;
        return switch (c.errno(@as(c_int, -1))) {
            .INTR => continue,
            .IO => error.InputOutput,
            .NOSPC => error.NoSpaceLeft,
            .DQUOT => error.DiskQuota,
            .ACCES, .PERM, .ROFS => error.AccessDenied,
            else => error.Unsupported,
        };
    }
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

const darwin_mnt_local: u32 = 0x00001000;
const darwin_mnt_ignore_ownership: u32 = 0x00200000;

/// macOS's `struct statfs` (64-bit inodes, the only layout on ARM64; x86-64 reaches it through
/// `fstatfs$INODE64`).
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
    std.debug.assert(@offsetOf(DarwinStatfs, "f_owner") == 56 and @offsetOf(DarwinStatfs, "f_flags") == 64 and
        @offsetOf(DarwinStatfs, "f_fstypename") == 72 and @sizeOf(DarwinStatfs) == 2168);
}

pub fn fdMount(fd: posix.fd_t) error{StatFailed}!Mount {
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
    } else {
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
    }
}

// ---- access control lists ----

/// Linux: the POSIX access ACL of `fd` (`system.posix_acl_access`), in `buf`, or null when it has none
/// or its filesystem has no ACLs. Too long for `buf` is unreadable.
pub fn posixAccessAcl(fd: posix.fd_t, buf: []u8) error{AclUnreadable}!?[]const u8 {
    if (builtin.os.tag != .linux) @compileError("POSIX ACLs are read on Linux only");
    const linux = std.os.linux;
    const rc = linux.fgetxattr(fd, "system.posix_acl_access", buf.ptr, buf.len);
    return switch (linux.errno(rc)) {
        .SUCCESS => buf[0..rc],
        .NODATA, .OPNOTSUPP => null,
        else => error.AclUnreadable, // too long (ERANGE) included
    };
}

/// One macOS ACL entry, as the folder and file checks need it.
pub const DarwinAce = struct {
    allow: bool,
    /// Applies only to what is created inside (`only_inherit`), not to this file or folder.
    only_inherit: bool = false,
    /// The `ACL_*` permission bits.
    perms: u64,
    who: Who,

    pub const Who = union(enum) { user: u32, group: u32, unknown };
};

// macOS `<sys/acl.h>` and `<membership.h>`: libSystem, the same on ARM64 and x86-64. The handles are
// opaque pointers; the integers are C `int`s, a permission set is a 64-bit mask.
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

comptime {
    // The declarations above are libSystem's on 64-bit macOS: `int` is 32 bits and a pointer 64.
    if (builtin.os.tag.isDarwin()) std.debug.assert(@sizeOf(c_int) == 4 and @sizeOf(*anyopaque) == 8);
}

/// macOS: the extended ACL entries of `fd`, in `out`; none when it has no ACL or its filesystem has
/// none. More entries than `out` holds is unreadable.
pub fn darwinAcl(fd: posix.fd_t, out: []DarwinAce) error{AclUnreadable}![]const DarwinAce {
    if (comptime !builtin.os.tag.isDarwin()) @compileError("macOS ACLs are read on macOS only");
    const acl = acl_get_fd_np(fd, ACL_TYPE_EXTENDED) orelse {
        const err = c._errno().*;
        // ENOENT: no ACL; ENOTSUP (std's `OPNOTSUPP`, 45 on macOS) or EOPNOTSUPP (102, which std's
        // `E` does not name): a filesystem without ACLs.
        const darwin_eopnotsupp: c_int = 102;
        return if (err == @backingInt(c.E.NOENT) or err == @backingInt(c.E.OPNOTSUPP) or err == darwin_eopnotsupp) out[0..0] else error.AclUnreadable;
    };
    defer _ = acl_free(acl); // nothing to do if freeing fails
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
            defer _ = acl_free(q); // as above
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

/// macOS: give `fd` an empty extended ACL, so a folder rweb just made holds none of the inheritable
/// entries of the folder it was made in. Best effort: the check that follows refuses what is left.
pub fn dropInheritedAcl(fd: posix.fd_t) void {
    if (comptime !builtin.os.tag.isDarwin()) return;
    const empty = acl_init(0) orelse return;
    defer _ = acl_free(empty); // nothing to do if freeing fails
    _ = acl_set_fd_np(fd, empty, ACL_TYPE_EXTENDED); // best effort, as said
}

// ---- processes ----

/// Whether `pid` has exited, without waiting: its status (as `waitpid` gives it), or null while it
/// runs. `error.WaitFailed` when it is not ours to wait for (any more).
pub fn waitNoHang(pid: c.pid_t) error{WaitFailed}!?u32 {
    while (true) {
        var status: c_int = undefined;
        const got = c.waitpid(pid, &status, c.W.NOHANG);
        if (got == pid) return @bitCast(status);
        if (got == 0) return null;
        switch (c.errno(@as(c_int, -1))) {
            .INTR => continue,
            else => return error.WaitFailed,
        }
    }
}

/// Wait for `pid` to end and reap it. Best effort: used after SIGKILL, whose wait cannot fail but by
/// the process not being ours, and then there is nothing to reap.
pub fn reap(pid: c.pid_t) void {
    var status: c_int = undefined;
    while (c.waitpid(pid, &status, 0) < 0 and c.errno(@as(c_int, -1)) == .INTR) {}
}

/// Send `sig` to `pid` (a negative `pid` names a process group; signal 0 only asks whether it exists).
pub fn kill(pid: c.pid_t, sig: c.SIG) error{ ProcessNotFound, KillFailed }!void {
    if (c.kill(pid, sig) == 0) return;
    return switch (c.errno(@as(c_int, -1))) {
        .SRCH => error.ProcessNotFound,
        else => error.KillFailed,
    };
}

// ---- the loopback listener ----

pub const Family = enum { v4, v6 };

pub const ListenError = error{
    AddressFamilyUnsupported,
    ProcessFdQuotaExceeded,
    SystemFdQuotaExceeded,
    AddressInUse,
    AddressNotAvailable,
    AccessDenied,
    SocketFailed,
    BindFailed,
    ListenFailed,
};

/// A listening loopback TCP socket on `port` (0: the system picks; the port taken is returned):
/// close-on-exec, `SO_REUSEADDR` (a restart is not held up by old connections in TIME_WAIT) and never
/// `SO_REUSEPORT`; IPv6 is `IPV6_V6ONLY`.
pub fn listenLoopback(family: Family, port: u16) ListenError!struct { fd: posix.fd_t, port: u16 } {
    const af: c_uint = if (family == .v4) posix.AF.INET else posix.AF.INET6;
    const fd = c.socket(af, posix.SOCK.STREAM, 0);
    if (fd < 0) return switch (c.errno(fd)) {
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .MFILE => error.ProcessFdQuotaExceeded,
        .NFILE => error.SystemFdQuotaExceeded,
        else => error.SocketFailed,
    };
    errdefer _ = c.close(fd); // closing a socket that never listened: nothing to report
    // Without close-on-exec a child (`tailscale`) would inherit the listener.
    if (c.fcntl(fd, posix.F.SETFD, @as(c_int, posix.FD_CLOEXEC)) != 0) return error.SocketFailed;
    const one: c_int = 1;
    if (c.setsockopt(fd, posix.SOL.SOCKET, posix.SO.REUSEADDR, &one, @sizeOf(c_int)) != 0) return error.SocketFailed;
    const rc = switch (family) {
        .v4 => blk: {
            var sa: posix.sockaddr.in = .{ .port = std.mem.nativeToBig(u16, port), .addr = std.mem.nativeToBig(u32, 0x7f00_0001) };
            break :blk c.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in));
        },
        .v6 => blk: {
            if (c.setsockopt(fd, posix.IPPROTO.IPV6, posix.IPV6.V6ONLY, &one, @sizeOf(c_int)) != 0) return error.SocketFailed;
            var sa: posix.sockaddr.in6 = .{ .port = std.mem.nativeToBig(u16, port), .flowinfo = 0, .addr = (std.Io.net.Ip6Address.loopback(0)).bytes, .scope_id = 0 };
            break :blk c.bind(fd, @ptrCast(&sa), @sizeOf(posix.sockaddr.in6));
        },
    };
    if (rc != 0) return switch (c.errno(rc)) {
        .ADDRINUSE => error.AddressInUse,
        .ADDRNOTAVAIL => error.AddressNotAvailable,
        .AFNOSUPPORT => error.AddressFamilyUnsupported,
        .ACCES => error.AccessDenied,
        else => error.BindFailed,
    };
    if (c.listen(fd, 128) != 0) return switch (c.errno(@as(c_int, -1))) {
        .ADDRINUSE => error.AddressInUse,
        else => error.ListenFailed,
    };
    if (port != 0) return .{ .fd = fd, .port = port };
    var got: posix.sockaddr.storage = undefined;
    var len: posix.socklen_t = @sizeOf(posix.sockaddr.storage);
    if (c.getsockname(fd, @ptrCast(&got), &len) != 0) return error.SocketFailed;
    // `sin_port` and `sin6_port` are at the same offset, after the family.
    const sin: *const posix.sockaddr.in = @ptrCast(&got);
    return .{ .fd = fd, .port = std.mem.bigToNative(u16, sin.port) };
}

comptime {
    std.debug.assert(@offsetOf(posix.sockaddr.in, "port") == @offsetOf(posix.sockaddr.in6, "port"));
}

// ---- tests ----

const testing = std.testing;

test "sys: names, ids and a refused kill come back as values and errors" {
    var buf: [256]u8 = undefined;
    try testing.expect(userName(uid(), &buf) != null);
    _ = groupName(gid(), &buf); // a group may have no name; only that the call is sound
    try testing.expect(userName(uid(), buf[0..0]) == null); // does not fit
    // A pid no process has (above every system's limit) is not found.
    try testing.expectError(error.ProcessNotFound, kill(std.math.maxInt(c.pid_t), @fromBackingInt(0)));
    try kill(c.getpid(), @fromBackingInt(0));
    try testing.expectError(error.WaitFailed, waitNoHang(c.getpid()));
}

test "sys: a loopback listener on port 0 reports the port it took, and refuses that port again" {
    const l = try listenLoopback(.v4, 0);
    defer _ = c.close(l.fd); // test cleanup
    try testing.expect(l.port != 0);
    try testing.expectError(error.AddressInUse, listenLoopback(.v4, l.port));
    if (listenLoopback(.v6, 0)) |l6| {
        defer _ = c.close(l6.fd); // test cleanup
        try testing.expect(l6.port != 0);
    } else |e| try testing.expect(e == error.AddressFamilyUnsupported or e == error.AddressNotAvailable);
}

test "sys: stat, link and readlink in a folder, and their errors" {
    var tmp = testing.tmpDir(.{});
    defer tmp.cleanup();
    const fd = tmp.dir.handle;
    try tmp.dir.writeFile(testing.io, .{ .sub_path = "a", .data = "x" });
    const n = try statAt(fd, "a");
    try testing.expectEqual(@as(u32, 0o100000), n.mode & 0o170000);
    try testing.expectEqual(uid(), n.uid);
    try testing.expectError(error.FileNotFound, statAt(fd, "missing"));
    try linkAt(fd, "a", fd, "b");
    try testing.expectError(error.PathAlreadyExists, linkAt(fd, "a", fd, "b"));
    try testing.expectEqual(n.ino, (try statAt(fd, "b")).ino);
    try tmp.dir.symLink(testing.io, "a", "l", .{});
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("a", try readLinkAt(fd, "l", &buf));
    try testing.expectError(error.NameTooLong, readLinkAt(fd, "l", buf[0..1]));
    try testing.expectError(error.ReadFailed, readLinkAt(fd, "a", &buf)); // not a link
    const om = try fdOwnerMode(fd);
    try testing.expectEqual(uid(), om.uid);
    _ = try fdMount(fd);
}
