//! Client library for Rex's control and data protocols. Nothing outside this
//! directory should know Rex's wire format.

pub const ws = @import("ws.zig");
pub const fake = @import("fake.zig");
pub const control = @import("control.zig");
pub const rex1 = @import("rex1.zig");
pub const data = @import("data.zig");
pub const mirror = @import("mirror.zig");
pub const input = @import("input.zig");

test {
    _ = ws;
    _ = fake;
    _ = control;
    _ = rex1;
    _ = data;
    _ = mirror;
    _ = input;
}
