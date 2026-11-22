//! Client library for Rex's control and data protocols. Nothing outside this
//! directory should know Rex's wire format.

pub const ws = @import("ws.zig");
pub const wire = @import("wire.zig");
pub const fake = @import("fake.zig");
pub const control = @import("control.zig");
pub const rex1 = @import("rex1.zig");
pub const data = @import("data.zig");
pub const mirror = @import("mirror.zig");
pub const input = @import("input.zig");
pub const api = @import("api.zig");
pub const fuzz = @import("fuzz.zig");

test {
    _ = ws;
    _ = wire;
    _ = fake;
    _ = control;
    _ = rex1;
    _ = data;
    _ = mirror;
    _ = input;
    _ = api;
    _ = fuzz;
}
