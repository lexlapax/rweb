# Phase 1 result: Rex client library (Zig)

Status: **in progress**. Built and tested on desktop-mac against Rex `0.1.0-preview.21`
(commit `202b1b3f`), API revision 18. Not yet run against linux-box's Rex (preview.22, revision
19); the exit condition needs both. Plan: [PLAN.md](PLAN.md#phase-1-rex-client-library-zig).
Where this and the code differ, the code wins.

## What exists (`src/rex/`)

| File | What it is |
| --- | --- |
| `ws.zig` | WebSocket client and server role over a unix socket; pure `parseHeader`; size limits |
| `wire.zig` | Pure parsers: control welcome, data WELCOME/REJECT, ticket |
| `control.zig` | Control connection: hello, revision negotiation, calls, events, reconnect with token |
| `data.zig` | Data connection: ticket, HELLO, RESUME with exact counts, end reasons |
| `rex1.zig` | Splitter of program output and Rex's `resize`/`theme`/`child_exited` messages |
| `mirror.zig` | libghostty-vt terminal following one stream; `redraw` by the Phase 0 rules |
| `input.zig` | One ordered input queue per terminal |
| `api.zig` | Typed calls: sessions, blocks, windows, resize, format, process, ownership |
| `fake.zig` | Fake Rex server (revision 18) for tests that need no real Rex |
| `fuzz.zig` | Fuzz targets, built without Ghostty (`zig build fuzz --fuzz`) |

## Commands run (desktop-mac, 2026-11-22)

- `zig build test`: 53 pass, 6 skip (the live tests), repeatedly and in `-Doptimize=ReleaseSafe`.
- `REX_SOCKET="$HOME/Library/Application Support/Rex/server.sock" zig build test`: all pass,
  including the live tests. Each live test creates a `rweb-test-live-*` session, always
  destroys it, and `rex ls` shows only the owner's session afterwards.
- `zig build fuzz --fuzz` for 90 s (after `mkdir -p .zig-cache/tmp`, which the fuzzer needs):
  no failure in the five targets (ws header, data handshake, control welcome, `rex1` body, and
  stream-split invariance). That is a smoke run, not a fuzzing campaign.

## Findings

1. **Mirror agrees with Rex.** A live shell running `printf` with colour, a wide character and
   a combining character, then `echo`, gave identical text in the mirror and in Rex's
   `terminal.format` (live test in `mirror.zig`).
2. **Input order holds.** Ten commands submitted one character at a time through the queue all
   ran correctly on a real shell (live test in `input.zig`); the Phase 0 `ehco` problem needs
   the queue.
3. **Ownership (finding 7 of Phase 0), observed live.**
   - `session.own_block` `take` returns the block's owner as the calling client's ID.
   - A `block_owner_changed` event follows, with `reason: "take"`.
   - The stream's `resize` message carries `owner` only when a size change happens. After the
     owner called `terminal.resize`, the message showed that owner's ID. An owner change alone
     sends no `resize` message (the protocol document says so), which is what Phase 0 saw as
     `owner: null` after a take. **Track the owner from `block_owner_changed`; treat the
     `resize` message's `owner` as the owner at that size change only.**
   - `session.disown_block` returns the block with no owner.
4. **Rex restart** is simulated in the fake only (as in finding 11 of Phase 0); not re-tested
   for real, which needs the owner's approval.

## Limits of this evidence

- The fake covers revision 18 and a reduced `session.attach` view; it does not prove behaviour
  against a real Rex. The live tests do, on one Rex version so far.
- Our own 120-second pings are not sent yet; Rex's pings are answered.
- Events are queued without a bound in `Control`; the bridge must read them.
- No test on linux-box, and none on a phone or a desktop browser (those are Phase 2 onwards).
