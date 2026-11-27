//! Where a write to a terminal may end without splitting an escape sequence. Pure: kept apart from
//! `input.zig` so the fuzzer (`src/fuzz.zig`, built without Ghostty) can reach it.

const std = @import("std");

const EscState = enum { ground, esc, csi, string, string_esc, single_shift, raw };

/// The state after `ESC b`.
fn afterEsc(b: u8) EscState {
    return switch (b) {
        '[' => .csi,
        ']', 'P', '_', '^', 'X' => .string, // OSC, DCS, APC, PM, SOS
        'N', 'O' => .single_shift, // SS2, SS3: one more byte, as in ESC O A (an arrow key)
        0x20...0x2f => .esc, // intermediates, as in ESC ( B
        else => if (b >= 0x30 and b <= 0x7e) .ground else .esc, // a C0 control inside is acted on, not an end
    };
}

/// Where to end a write of `text[0..n]` so it does not stop inside an escape sequence: before
/// the sequence that `text[0..n]` ends inside, if any, as long as something is left (a sequence
/// longer than the whole write is sent as it is). An ESC is ASCII, so the cut stays on a
/// character boundary. An X10 mouse report (`CSI M` with no parameters) counts its three raw
/// bytes as part of the sequence, whatever they are.
pub fn escCut(text: []const u8, n: usize) usize {
    if (n >= text.len) return n; // all of it: nothing follows to complete a sequence
    var state: EscState = .ground;
    var start: usize = 0; // where the sequence being read began
    var raw_left: u8 = 0; // bytes still due in `.raw`
    for (text[0..n], 0..) |b, i| {
        // An X10 report's bytes are data, not controls: take them as they come.
        if (state == .raw) {
            raw_left -= 1;
            if (raw_left == 0) state = .ground;
            continue;
        }
        // CAN and SUB cancel any sequence; ESC starts a new one (in a string, maybe its end).
        if (b == 0x18 or b == 0x1a) {
            state = .ground;
            continue;
        }
        switch (state) {
            .ground, .esc, .csi, .single_shift => if (b == 0x1b) {
                state = .esc;
                start = i;
                continue;
            },
            .string => if (b == 0x1b) {
                state = .string_esc;
                continue;
            },
            .string_esc, .raw => {},
        }
        state = switch (state) {
            .ground => .ground,
            .esc => afterEsc(b),
            .csi => if (b == 'M' and i == start + 2) blk: {
                // `ESC [ M` with nothing between: X10 mouse, three raw bytes follow.
                raw_left = 3;
                break :blk .raw;
            } else if (b >= 0x40 and b <= 0x7e) .ground else .csi,
            .single_shift => .ground, // its final byte
            .string => if (b == 0x07) .ground else .string, // BEL ends an OSC
            .string_esc => if (b == '\\') .ground else blk: {
                // The string ended at that ESC, which starts a new sequence with `b`.
                start = i - 1;
                if (b == 0x1b) {
                    start = i;
                    break :blk .esc;
                }
                break :blk afterEsc(b);
            },
            .raw => unreachable,
        };
    }
    if (state == .ground or start == 0) return n;
    return start;
}

test "escCut ends a write before an escape sequence it would split" {
    const t = std.testing;
    const more = "...."; // something follows each window, so the cut matters
    const Case = struct { text: []const u8, n: usize, want: usize };
    for ([_]Case{
        .{ .text = "abc\x1b[12;3" ++ more, .n = 7, .want = 3 }, // inside a CSI
        .{ .text = "\x1b[1mab" ++ more, .n = 4, .want = 4 }, // a whole CSI
        .{ .text = "ab\x1b" ++ more, .n = 3, .want = 2 }, // a lone ESC at the end
        .{ .text = "ab\x1b]0;title\x07cd" ++ more, .n = 8, .want = 2 }, // inside an OSC
        .{ .text = "ab\x1b]0;title\x07cd" ++ more, .n = 12, .want = 12 }, // after its BEL
        .{ .text = "ab\x1b]0;t\x1b\\cd" ++ more, .n = 8, .want = 2 }, // between an OSC and its ST's backslash
        .{ .text = "ab\x1b]0;t\x1b\\cd" ++ more, .n = 9, .want = 9 }, // after ST
        .{ .text = "a\x1b(B" ++ more, .n = 3, .want = 1 }, // ESC ( B, cut after the intermediate
        .{ .text = "a\x1b(B" ++ more, .n = 4, .want = 4 },
        .{ .text = "a\x1b[1\x18b" ++ more, .n = 5, .want = 5 }, // CAN cancels the sequence
        .{ .text = "\x1b[1;2;3;4;5" ++ more, .n = 6, .want = 6 }, // a sequence longer than the write
        .{ .text = "x\x1b[<0;12;34M\x1b[<0;12" ++ more, .n = 18, .want = 12 }, // mouse reports
        .{ .text = "a\x1bOA" ++ more, .n = 3, .want = 1 }, // SS3 (an arrow key) needs its final byte
        .{ .text = "a\x1bOA" ++ more, .n = 4, .want = 4 },
        .{ .text = "a\x1bNx" ++ more, .n = 3, .want = 1 }, // SS2 likewise
        .{ .text = "a\x1bNx" ++ more, .n = 4, .want = 4 },
        .{ .text = "a\x1b[M !!" ++ more, .n = 4, .want = 1 }, // X10 mouse: CSI M, then three raw bytes
        .{ .text = "a\x1b[M !!" ++ more, .n = 6, .want = 1 },
        .{ .text = "a\x1b[M !!" ++ more, .n = 7, .want = 7 },
        .{ .text = "a\x1b[M\x1b\x1b\x1bb" ++ more, .n = 7, .want = 7 }, // its raw bytes are data, even an ESC
        .{ .text = "a\x1b[2M" ++ more, .n = 5, .want = 5 }, // CSI 2 M (delete lines) is not X10
        .{ .text = "abc", .n = 3, .want = 3 },
    }) |cs| try t.expectEqual(cs.want, escCut(cs.text, cs.n));
}
