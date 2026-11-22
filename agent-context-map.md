# Agent context map

Last updated: 2026-11-22. Read first; load linked context lazily. Keep this file short: current
state, decisions, blockers and next actions. Put durable evidence in `docs/`.

## Handover (2026-11-22)

Work moves to a coding assistant on desktop-mac. Phase 0 is finished and pushed; Phase 1 has not
started. The owner's grant for desktop-mac and linux-box is in [AGENTS.md](AGENTS.md).

Before starting on desktop-mac:

1. Pull `main`, then check `zig version` (0.17.1 expected) and `rex version`. Rex.app updates
   itself; it was preview.21 on 2026-11-20, and Phase 1 must support its API revision.
2. Find Rex's socket. `spike/` and its Python probes read `XDG_RUNTIME_DIR`, and
   `restart_probe.py` uses `systemctl`, so they are Linux-only as written.
3. Nothing here has been built or run on macOS, and no fresh-clone build has been tried.

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
   1. `build.zig` with Ghostty pinned, and a `rex` module with its WebSocket client.
   2. The fake Rex server, built from `llms.txt`, with snapshots from libghostty-vt.
   3. Control connection: hello, revision negotiation, events, reconnect, restart recovery
      (finding 11).
   4. Data connection: tickets, HELLO/RESUME, byte counting, 1013, `rex1` messages.
   5. The mirror, one per open terminal, using the redraw rules.
   6. One ordered input queue per terminal (finding 12).
   7. Typed calls, and the ownership question (finding 7).
   8. Fuzz tests for every parser of outside bytes.
   9. Live tests in `rweb-test-` sessions on both Rex versions: desktop-mac and linux-box.
2. Phases 2–4 follow [docs/PLAN.md](docs/PLAN.md#phases).

## Checks run for this update

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
