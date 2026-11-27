//! Pure parsers of what Linux reports about files: a line of `/proc/self/mountinfo` and a POSIX access
//! ACL. Both are bytes from outside this program. They are kept apart from `xfer.zig`, which needs libc
//! and the Rex library, so the fuzzer (`src/fuzz.zig`) can reach them; `xfer.zig` uses them from here.

const std = @import("std");

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

/// Whom a refused access control list entry names (`checkPosixAcl`, and xfer's macOS check).
pub const AclWho = union(enum) { none, user: u32, group: u32, everyone, unknown };

/// How `checkPosixAcl` refuses; part of `xfer.CheckError`, whose comments say what each means.
pub const AclError = error{ AclGivesOthersWrite, AclGivesGroupWrite, AclUnreadable };

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
pub fn checkPosixAcl(blob: []const u8, uid: u32, file_gid: u32, ctx: anytype, comptime groupSafe: fn (@TypeOf(ctx), u32) bool, who: ?*AclWho) AclError!void {
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
