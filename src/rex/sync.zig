//! Checks on locks, for assertions.

const std = @import("std");

/// Whether `m` is locked, by any task. A `...Locked` function asserts it of the lock its caller must
/// hold: it cannot tell which task holds the lock, so it catches a call made with the lock not held
/// at all, the usual mistake, and not one made while another task holds it.
pub fn held(m: *const std.Io.Mutex) bool {
    return m.state.load(.monotonic) != .unlocked;
}

test "held: says whether a mutex is locked" {
    const io = std.testing.io;
    var m: std.Io.Mutex = .init;
    try std.testing.expect(!held(&m));
    m.lockUncancelable(io);
    try std.testing.expect(held(&m));
    m.unlock(io);
    try std.testing.expect(!held(&m));
}
