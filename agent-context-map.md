# Agent context map

Last updated: 2026-11-22 (desktop-mac). Phase 3 built; owner trying it on phone and tablet; wterm (Ovis's terminal) added as an alternative for native long-press selection. Read first; load linked context lazily. Keep this file short: current
state, decisions, blockers and next actions. Put durable evidence in `docs/`.

## Handover (2026-11-22), picked up on desktop-mac

Phase 0 is finished and pushed. Phase 1 is in progress, steps 1 to 9 done: **Phase 1 exit met** (2026-11-22). The owner's grant for
desktop-mac and linux-box is in [AGENTS.md](AGENTS.md).

desktop-mac facts checked 2026-11-22: Zig 0.17.1 (`/opt/homebrew/bin/zig`); Rex.app
`0.1.0-preview.21`, commit `202b1b3f`, API revision 18 (supports 0 to 18); socket
`~/Library/Application Support/Rex/server.sock` (no `XDG_RUNTIME_DIR`; `rex ls` shows only the
owner's `calm-isle`). The spike builds from a fresh clone on macOS (`ReleaseSafe`, ~2 min,
Ghostty fetched). `spike/`'s Python probes remain Linux-only (`XDG_RUNTIME_DIR`, `systemctl`).

## Current state

- **Phase 0 done; the gate passed (2026-11-21).** A libghostty-vt mirror in a Zig spike shows a
  live Rex terminal in xterm.js correctly: prompt, colours, wide and combining characters, vim
  and the alternate screen, mouse, resize, theme, paste, Kitty keyboard (hybrid input),
  reconnect, 300k lines of output, program exit, a second viewer joining mid-vim. Each was
  compared row for row with Rex's own capture. Evidence: [docs/phase0-result.md](docs/phase0-result.md).
- Checked on 2026-11-22 with the owner's approval:
  - Rex server restart: sessions and block IDs survive; programs and screens do not; tokens
    from before are refused (finding 11).
  - Typing on the owner's Android phone (Gboard) through a temporary Serve port: words and
    voice input arrive once and in order. A space just before Enter is misordered or turned
    into a stray DEL, so keys and text need one order. There is no touch selection for copying
    (findings 12 and 13).
- The spike is in `spike/` (throwaway; Phase 1 starts fresh). No bridge code yet.

## Owner decisions (2026-11-21)

Recorded in [docs/PLAN.md](docs/PLAN.md#decisions-made-by-the-owner-2026-11-21):

1. Shape: a bridge running as the user next to Rex's unix socket, with Tailscale Serve in front.
2. Server in Zig (changed from Rust on 2026-11-21), one static binary per platform.
3. First version: list sessions and terminals; one terminal full-screen; type, resize,
   reconnect; usable on a phone; create, rename and close sessions and terminals.
4. Not in the first version: drawing a window's split layout; forking Ovis.

## Decisions after the design research (2026-11-21)

Recorded in [docs/PLAN.md](docs/PLAN.md#decisions-made-after-the-design-research-2026-11-21):

1. Bridge in Zig, importing libghostty-vt directly; `ReleaseSafe`, fuzzed parsers, few pinned dependencies.
2. Zig: installed on all three machines by setup-repo (0.17.1 on linux-box).
3. Own-address requests: rejected by default; a per-machine setting allows them on single-user hosts.
4. desktop-mac: included; the bridge starts a personal Rex server if none runs, and uses loopback TCP.

## Settled by Phase 0

- Rendering: bridge-side mirror; redraw = RIS + `TerminalFormatter` (all extras, `trim = false`),
  primary screen first while the alternate screen is up, a fresh redraw after every Rex resize.
- Input: hybrid. Keys to `client.key`; mouse, paste and composed text from xterm.js to
  `terminal.write`, one write in flight per terminal (Rex runs writes concurrently: `echo`
  arrived as `ehco` without this), keys queued behind it; Enter and Backspace through xterm.js
  on a soft keyboard. Query replies swallowed in the browser.
- Browser terminal: xterm.js 6.0.0 (embedded in the bridge, not from a CDN).
- Zig: `std.http.Server` WebSocket for browsers, own WebSocket client for Rex, `std.Io` threaded.
- Build: pass `target`/`optimize` to the Ghostty dependency (Debug Ghostty was ~400× slower).

## Next actions, in order

1. **Phase 1: Rex client library in Zig**, as in [docs/PLAN.md](docs/PLAN.md#phase-1-rex-client-library-zig),
   built fresh at the repository root, in this order:
   1. DONE: `build.zig`/`build.zig.zon` (Ghostty `vt-1.0.1` pinned), `src/rex/root.zig`,
      `src/rex/ws.zig` (pure `parseHeader`, size limits, fragmentation rules, fuzz test).
      `zig build test`; live tests need `REX_SOCKET=<socket>` (read-only hello/welcome).
   2. DONE (first cut): `src/rex/fake.zig`, a fake Rex server on a `/tmp` unix socket, API
      revision 18, snapshots from libghostty-vt. Supports hello/welcome and revision
      negotiation, reconnect tokens, `session.list/create/attach/destroy`, `data.connect`,
      `terminal.write` (echo), data HELLO/RESUME with exact byte counts, REJECT codes, and test
      hooks `feed`, `dropDataConnections`, `restart`. Simplified: no events (`seq` is always 0),
      one window and one block per session, a reduced `session.attach` view, no `key`/`resize`/
      `format`, no theme or `child_exited`. Grow it with the steps that need it.
      `ws.zig` gained a server role (`Conn.accept`) for it.
   3. DONE: `src/rex/control.zig`: hello and revision negotiation (hello under 512 bytes),
      `call` matched by id from any task, events and `connected`/`disconnected` notices through
      `nextEvent`, reconnect with backoff and the reconnect token. A short drop resumes the same
      client; a Rex restart gives `resumed=false` (finding 11), and the consumer must re-attach
      and re-read state. Not yet: our own 120 s ping, `seq`/response ordering helper for
      combining views with events (needs the real `session.attach` view, in step 7), a
      `session.bootstrap` helper.
   4. DONE: `src/rex/data.zig` (ticket via `data.connect`, HELLO, WELCOME, byte counting after
      the sink has the bytes, RESUME with the exact count and backoff within the server's
      window, `End` reasons: `block_closed` 4000, `restart_needed` for 1013/1001 canceled/
      refused resume/window passed, `failed`) and `src/rex/rex1.zig` (pure splitter of program
      output and `resize`/`theme`/`child_exited`, nonce-checked, split-safe, fuzz test). Fake
      gained `endStreams`. Not yet: the snapshot is not interpreted here (the mirror, step 5,
      does it); our own pings.
   5. DONE: `src/rex/mirror.zig`: one libghostty-vt terminal per stream behind one mutex;
      decodes the snapshot (accumulates and retries, as the spike did), splits `rex1` messages
      (resize applies to the terminal; theme, owner and exit are kept), observer callbacks,
      `redraw` by the Phase 0 rules (RIS, `TerminalFormatter` all extras `trim=false`, primary
      screen first while the alternate screen is up), `plainText`. `Data` now calls
      `Sink.welcome(nonce)` so `Mirror.initPending` + `sink()` just works. Not yet: a redraw
      after every Rex resize is the consumer's job (the `resized` observer says when); snapshot
      decode retries on every chunk (quadratic for a huge snapshot; fine so far).
   6. DONE: `src/rex/input.zig`: one call in flight per terminal, in arrival order across text
      (`terminal.write`), `client.key` and `block.event`; text queued behind a call is
      coalesced; invalid UTF-8 refused, 1 MiB backlog cap (`Backpressure`); a failed call loses
      that input only; input during a disconnect is dropped, not replayed. `Sender` abstracts
      the call so tests can record. Not yet: a viewer-facing size limit on keys/events.
   7. DONE: `src/rex/api.zig` typed calls (see [docs/phase1-result.md](docs/phase1-result.md)).
      Ownership answered live: track the owner from `block_owner_changed`; the `resize`
      message's `owner` is only the owner at that size change.
   8. DONE: `src/rex/fuzz.zig` + `wire.zig`; `zig build fuzz --fuzz` (needs
      `mkdir -p .zig-cache/tmp`); 90 s smoke run clean. Not a campaign.
   9. DONE: live tests pass on desktop-mac (preview.21, rev 18) and linux-box (preview.22, rev 19),
      59/59 each; see docs/phase1-result.md.
2. **Phase 3 (frontend) is built; see [docs/phase3-result.md](docs/phase3-result.md).** Its exit (a week of daily use on a phone and a laptop) is the owner's. **Next: Phase 4**, whose first step is the security review. `Control` now asks for revisions 18 to 19 (desktop-mac gets 18, linux-box 19) and surfaces
   `event_dropped` as `Event.dropped`: the bridge must re-read state on it (Phase 2). Large
   requests should be sent fragmented at 19; ours are small. `focus_history.reverse` unused. The real restart test is done on both machines.
   Phases 2–4 follow [docs/PLAN.md](docs/PLAN.md#phases).

## Phase 2 (bridge, `src/bridge/`): exit met; owner's sign-off pending

Owner's answers (2026-11-22): history on open = last ~1,000 lines; a wide terminal shrinks to fit
and Rex's size changes only on request; a read-only ("view only") switch on the page, off by
default, plus a bridge-wide locked `--observe-only`. Built: `access.zig`, `protocol.zig`,
`hub.zig`, `server.zig`, `assets.zig` + `web/` (page, vendored xterm.js), `cli.zig`, `main.zig`
(`zig build run -- --listen-tcp 0 --random-token`). Evidence, findings, limits:
[docs/phase2-result.md](docs/phase2-result.md). Checked on desktop-mac in Chrome, through Serve
port 11443 (each refusal shown), and on the owner's Android tablet (Samsung Keyboard and Gboard
both work); linux-box ran the full suite including live tests. Phone typing works since the owner turned off the phone Tailscale app's power saving (it had
stalled the tailnet path; evidence in Findings 5). Test infrastructure is all removed (bridge stopped,
Serve 11443 and 12443 gone, `rweb-test-phone` destroyed, temp files deleted). `tailscale up` on
desktop-mac needs `--accept-routes`; stop a foreground `tailscale serve` with SIGINT on its own process.
Phone layout reworked (slide-over menu). Tip: run tests with output to a file; piping
`zig build test` into `head` can hang. `mkdir -p .zig-cache/tmp` before `--fuzz`.

## Checks run for this update

- 2026-11-22, wterm trial: bundled and vendored wterm 0.6.0 + libghostty core (details and hashes in
  docs/phase3-result.md); Chrome checks of `?term=wterm` (draw, type, colour, wide/combining,
  query replies suppressed); `zig build test` green. Test setup still up for the owner: bridge on
  7695, Serve 12443 (`tailscale serve --https=12443 off` to remove), session `rweb-test-try`
  (`rex session kill rweb-test-try`).
- 2026-11-22, Phase 3 fixes (soft keyboard live forwarding, Copy view): `zig build test` and `zig
  build web-test` (10 pass) green; Samsung-style key sequence replayed in desktop Chrome, result
  confirmed through Rex's own capture. **Test setup still up on desktop-mac for the owner's devices:**
  bridge on 127.0.0.1:7695 (`rweb --listen-tcp 7695 --owner-from-tailscale --allow-own-address`),
  Serve port 12443 (remove: `tailscale serve --https=12443 off`), session `rweb-test-try`
  (destroy: `rex session kill rweb-test-try`).
- 2026-11-22, Phase 3: desktop-mac `zig build test` 107 pass + 1 skip (live), `ReleaseSafe` too; `zig
  build web-test` 8 pass; linux-box 145 pass + 1 skip (scratch copy removed). Chrome checks of the
  page at desktop and 400 px wide (throwaway session, destroyed); `rex ls` shows only `calm-isle`
  and `drifting-tundra`.
- 2026-11-22, final Phase 2 runs: desktop-mac `zig build test` with `REX_SOCKET`: 102 pass + 1 skip;
  linux-box (scratch copy, removed) 140 pass + 1 skip; `rex ls` shows only `calm-isle` and
  `drifting-tundra`. Phone typing confirmed by the shell's own screen.
- 2026-11-22, linux-box: scratch copy, `zig build test` with `REX_SOCKET`: 97 pass + 1 skip incl.
  Linux peer-uid and a live bridge test on Rex rev 19; copy removed; `rex ls` only
  `drifting-tundra`.
- 2026-11-22: bridge server tests (each access refusal over real HTTP, WebSocket end to end,
  observe-only over the wire, unix socket 0600/0700 and peer refusal); `zig build test` 89 pass +
  7 skip, six runs in a row.
- 2026-11-22: `zig build test` 76 pass + 7 skip (rex 51, bridge 25 incl. 12 hub tests against
  the fake, fuzz 36 as ordinary tests).
- 2026-11-22: revision 18 to 19 change: `zig build test` 55 pass + 7 skip; with `REX_SOCKET`
  61 pass + 1 skip (restart test gated) on desktop-mac (negotiated 18) and on linux-box (negotiated
  19, scratch copy removed). Both machines' `rex ls` show only the owner's session.
- 2026-11-22, desktop-mac: restart test `manual` mode added (`REX_RESTART_CMD=manual`). Quitting and
  reopening Rex.app did **not** restart the server (pid 2209, started 2026-11-20, kept running):
  Rex.app is a client. `rex server stop` was denied by the permission classifier, so the desktop-mac
  restart test is **not done**. The test run was stopped and its `rweb-test-live-restart`
  session killed with `rex session kill`; `rex ls` shows only `calm-isle`.
- 2026-11-22, linux-box: owner-authorized real Rex restart through the library (live test in
  `mirror.zig`): recovery as designed, 60/60 pass; scratch copy removed; `rex ls` shows only
  `drifting-tundra` (restored with a new shell, as in Phase 0).
- 2026-11-22, linux-box: fresh `/tmp` clone of `04ea5f4`; `zig build test` 53 pass + 6 skip; with
  `REX_SOCKET` 59/59 pass; clone removed; `rex ls` shows only `drifting-tundra`.
- 2026-11-22, desktop-mac: typed calls, fuzz targets: `zig build test` 53 pass + 6 skip, also
  `ReleaseSafe`; with `REX_SOCKET` all pass (live ownership/typed-call test); `rex ls` shows only
  `calm-isle` afterwards. Details in docs/phase1-result.md.
- 2026-11-22, desktop-mac: input queue added; `zig build test` 49 pass + 5 skip, five runs and
  `ReleaseSafe`, stable; with `REX_SOCKET`: 54/54, including a live test that submits ten
  commands one character at a time to a throwaway `rweb-test-live-input` shell on preview.21
  and sees all ten run correctly; session destroyed.
- 2026-11-22, desktop-mac: mirror added; `zig build test` 45 pass + 3 skip, five runs and
  `ReleaseSafe`, stable and leak-free; with `REX_SOCKET`: 49/49, including a live test that
  compares the mirror's text with Rex's own `terminal.format` on a throwaway
  `rweb-test-live-mirror` shell (colour, wide and combining characters) on preview.21; session
  destroyed.
- 2026-11-22, desktop-mac: data and `rex1` added; `zig build test` 38 pass + 2 skip, six runs and
  `ReleaseSafe`, stable and leak-free; with `REX_SOCKET`: 41/41, including a live test that
  streams a throwaway `rweb-test-live-data` shell on preview.21, types `echo` and reads it back;
  the session was destroyed (`rex ls` shows only `calm-isle`).
- 2026-11-22, desktop-mac: control client added; `zig build test` 22 pass + 1 skip, eight runs
  plus once in `ReleaseSafe`, stable and leak-free; with `REX_SOCKET`: 24/24 including live
  `session.list` and `server.version` on preview.21 (no sessions created).
- 2026-11-22, desktop-mac: fake server tests added; `zig build test`: 16 pass, 1 skip, three runs,
  no leaks (testing allocator). Also run once with `REX_SOCKET` set (see next line).
- 2026-11-22, desktop-mac: `zig build test` in the repository root: 7 pass, 1 skip (live). With
  `REX_SOCKET` set to the desktop-mac socket: 8/8 pass, including a control hello and welcome
  against Rex preview.21 / revision 18. No sessions were created or touched.

- Phase 0 spike runs 1–10 against Rex preview.22 / revision 19 on linux-box, Chrome 157, as listed
  in [docs/phase0-result.md](docs/phase0-result.md). Every run destroyed its `rweb-test-` session;
  one crashed run's session was closed with `rex session kill`; `rex ls` ends with only the
  owner's session. Captures are in the session scratchpad, not in Git.
- `zig build -Doptimize=ReleaseSafe` in `spike/` succeeds with Zig 0.17.1.
- Phone run on 2026-11-22: spike with `--origin` and `--ts-user`, foreground
  `tailscale serve --https=10443` (stopped afterwards; `tailscale serve status` shows no 10443);
  access guards checked with `curl`; test session destroyed.
- `spike/restart_probe.py` twice on 2026-11-22 (owner-approved restarts of `rex.service`); both
  test sessions destroyed; `rex ls` ends with only the owner's session, restored with a new shell.

## Task routing

| Need | Load |
| --- | --- |
| Phases, architecture, constraints, risks | [docs/PLAN.md](docs/PLAN.md) |
| What Phase 0 showed, and why the design is as it is | [docs/phase0-result.md](docs/phase0-result.md) |
| Snapshot format, libghostty-vt, browser terminals, Serve identity, machine facts | [docs/design-research.md](docs/design-research.md) |
| Rex protocol, streams, revisions; Ovis and herdr background | [docs/rex-web-research.md](docs/rex-web-research.md) |
| What Phase 1 built, findings, limits | [docs/phase1-result.md](docs/phase1-result.md) |
| Working example of every Rex call the bridge needs | `spike/src/main.zig`, `spike/src/ws.zig` |
| Live protocol reference (authoritative) | `curl --unix-socket "$XDG_RUNTIME_DIR/rex/server.sock" http://localhost/llms.txt` |
| Rex CLI usage | the `rex` skill (always pass `-s` and `-b` in tests) |
| Deployment (Phase 4) | the owner's `setup-repo` repository, with approval |

## Pins and machines

- Rex on linux-box: `0.1.0-preview.22` (commit `a086db17`), API revision 19 (accepts 0 to 19).
  Re-check with `rex version` before building; the revision moved 18 → 19 within a day.
- Rex listeners on linux-box: the user unix socket `/run/user/1000/rex/server.sock`
  (peer credentials) and a login-server socket; Tailscale listener disabled. Do not change them.
- desktop-mac: Rex.app preview.21 on 2026-11-20 (Sparkle, outside setup-repo), no boot-time Rex server;
  Tailscale.app (sandboxed, no unix-socket Serve backend).
- Tailscale 1.104.7 on linux-box (unix-socket Serve backends need ≥ 1.94; setting one needs root).
  Serve ports in use: 443 (Ovis), 9443 (Ovis canary), 8443 (desktop-mac).
- Zig 0.17.1 (`/usr/bin/zig`) on linux-box. libghostty-vt: Ghostty tag `vt-1.0.1` (needs ≥ 0.17.0),
  package hash `ghostty-1.4.1-dev-5UdBC4lkpgUYGLDYGJQcJoa9zOGZNB3qVMgMoS9CUH5O`; snapshot format 1.
- Deployment order for Phase 4: linux-box, then gateway-box, then desktop-mac.

- wterm fit: font and row height now shrink to fit stage width and height (Rex owns the grid size). Checked in Chrome at 1300x930 on `rweb-test-try`: 49 rows fit, nothing scrolled off. Owner reported the terminal not showing on phone/desktop before this fix; desktop is now up, phone not re-checked.

- Ovis-style sizing (wterm only): on touch screens the text keeps the +/- size and the page asks Rex to resize the terminal to fit (menu toggle "Fit Rex to this screen", localStorage `rweb.autofit`); key row now has ← → in the main row as in Ovis. Checked in Chrome at phone width on `rweb-test-try`: 71x34 at 14 px, 55x26 at 18 px. Not yet checked on the owner's phone. Bottom-sheet ⋯ menu and title tab switcher from Ovis not done.

- Ovis look (wterm): menus are bottom sheets with a title and Cancel on narrow screens; header shows the session name with the 1/N switcher; colours are Ovis's neutral dark (#181818 page, #ececec text, #1f1f1f bar, #2e2e2e lines, 6px buttons) and Rex's own colours are ignored unless "Use Rex colours" is on in the menu. Checked in Chrome at phone width only.

- Auto-fit loop fix: each device asks Rex for a size only when its own screen/font changes or a terminal is opened, never in reply to a size change by another device (owner saw the phone blink with the tablet also open). Not verified on the phone.

- Layout sizes now taken from Ovis's own phone layout (measured in its page): 14px text, 52px header with 44px borderless icon buttons, key bar #1f1f1f with 44x36 (49 wide for Shift/Enter) transparent keys, 13px monospace, 4px gaps, left-aligned, 6px radius. Checked in Chrome at phone width only.

- Ovis key bar details: expanded, the arrows form an inverted T beside the key rows with the collapse button in its top-right corner, and Esc/Tab move up beside the symbols. The ⋯ menu is a dropdown from the top right (bottom sheet dropped at the owner's request), no Cancel, closes on any outside click or the button again; menu and icon text is 13px like the keys. Checked in Chrome at phone width only.
