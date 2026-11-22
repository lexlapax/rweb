//! The rweb bridge: shows Rex terminal sessions in a web browser.

const std = @import("std");

pub const access = @import("access.zig");
pub const protocol = @import("protocol.zig");
pub const hub = @import("hub.zig");

test {
    _ = access;
    _ = protocol;
    _ = hub;
}
