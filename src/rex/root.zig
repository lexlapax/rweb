//! Client library for Rex's control and data protocols. Nothing outside this
//! directory should know Rex's wire format.

pub const ws = @import("ws.zig");

test {
    _ = ws;
}
