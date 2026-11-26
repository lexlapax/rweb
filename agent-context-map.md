# Agent context map

Last updated: 2026-11-25 (laptop-mac: third review round and its fixes). **Phases 0 to 4 done and deployed on linux-box and desktop-mac**; the owner is using it (Phase 3's week of daily use is theirs). linux-box now runs on a unix socket (applied and verified); one reboot check on that setup is left. Read first; load linked contents only as needed.
state, decisions, blockers and next actions. Put durable evidence in `docs/`.

## 2026-11-25: third review round of `4c383fb` and its fixes

An independent readiness review on linux-box (Linux, live Rex: ready for the 0.1.1 release commit; three
observations), an external static rescan (one High, two Medium) and a four-part internal adversarial
review (31 more) were each checked against the code. Tally, plan, fixes, tests, checks and what is left:
[docs/security-review-2026-11-25-round3.md](docs/security-review-2026-11-25-round3.md). The worst: an
open refused by the rate limit (a round-2 regression) left the bridge on the old terminal while the page
showed the new one, so typing could go elsewhere; and test bridges used a fixed token, including the live
test against the real Rex. Fixed by mechanism: one terminal on both sides; budgets for every queue and
for shared work (live output coalesced, single theme, paced redraws, cell caps, viewer cap, ping rate,
busy-is-alive); terminal close order; peer and descriptor trust (socket folder chain, Rex peer uid,
`tailscale` from fixed places, upload real path); paste integrity (multi-line confirmation, server-side
ESC/C1 strip, keyboard commits as pastes); Rex connection robustness; random test tokens and a confined
fake; build-time commit stamp. Owner's decisions: private groups pass; multi-line pastes ask; reviewers
named generically. Added: macOS `admin` counts as root's. Checked on laptop-mac: unit 243/252 (9 live
skipped), live 251/252, fuzz corpus, web 26/26, release-base, ReleaseSafe in Chrome (multi-line paste
question into `sh`) and the iOS Simulator, and `--owner-from-tailscale` finding Tailscale. Not run: Linux,
Serve from another device, Android. Note: round 2 ran a coverage-guided fuzz session whose web page
listened on loopback without a token (coverage only); none since. **Next:** the owner has both reviews look
at the fix commit; then the 0.1.1 release commit (date the changelog), archives with `tools/release.sh` on
an Apple-silicon Mac, tag and private release, all on the owner's word.

## 2026-11-25: second security review of `ded0668` and its fixes

An external static scan rescanned `ded0668` (11 findings); an internal adversarial review in four parts (front end,
Rex library, hub concurrency, page and release) added 42 more, among them a deadlock and use-after-free
crashes in the hub. Every finding was checked against the code; D4 was partly refuted (bounded recursion)
but hid a real byte-reordering bug. Verdicts, the plan by mechanism, each fix and its tests, checks and
what is left: [docs/security-review-2026-11-25-round2.md](docs/security-review-2026-11-25-round2.md).
In short: terminals are reference-counted and nothing waits on Rex under `Hub.mu` (the restart residual
below is fixed); every viewer queue, Rex event queue, input queue, history redraw and Copy text is
bounded; the Rex library has message, token, depth and handshake limits and ownership fixes; the rex1
splitter is a state machine checked against a reference model and fuzzed; secret files and the upload
folder are trusted only through checked descriptors with safe parent folders; upload tokens are checked
against their viewer at use; pastes lose ESC and C1 and go as pastes; `--owner` needs `--allow-host`.
Owner's decision on the scan's #3 (macOS Serve target holds the backend secret): document only.
Checked on laptop-mac: unit 253/263 (10 live skipped), live 208/209 against local Rex, fuzz corpus, web
22/22, release-base, ReleaseSafe bridge in Chrome (typing, hostile paste in both engines) and the iOS
Simulator. Not checked: Linux runs, a Serve deployment of this build, a phone keyboard's paste.
**Deployment note:** startup now refuses secret files and upload folders under folders another user can
change; laptop-mac's layout passes, check each host when deploying. **Next:** the owner has both reviews
look at the fix commit; no version, GitHub Release or deployment until the owner says so.

## 2026-11-25: release reviews of `7a53f54` and their fixes

Two independent reviews ran on `7a53f54` (an independent release-readiness review on linux-box; an external
static security scan). Every finding was checked against the code and accepted; fixes, verdicts and tests are
in [docs/release-review-2026-11-25.md](docs/release-review-2026-11-25.md): private release folder
(`tools/release-base.test.sh`), SSH-tunnel cookie scoped to `/s/<id>/` with a redirect (the page uses
relative addresses), `--own-address` validated and fail-closed, snapshot framed and decoded once plus
terminal open outside `Hub.mu`, eviction of the oldest idle pending connection, version-agnostic README,
typed Tailscale JSON parsing. Checked on laptop-mac: unit 150/159 (9 skipped), live ReleaseSafe 206/207
(gated restart skipped), web 17/17, Chrome and iOS-Simulator Mobile Safari in tunnel mode. Not yet
checked: the page through Serve from another device (with the next deployment). **Next:** the owner has
both reviews look at the fix commit; no version, GitHub Release or deployment until the owner says so.
Left on purpose then: a stream restart (supervisor) still opened under `Hub.mu`; fixed in the second review.

## 2026-11-25: next work agreed

**Work in worktrees** (`~/projects/lexlapax/.worktrees/rweb/<topic>`, branch `wt/<topic>`), not in the
main checkout; see [AGENTS.md](AGENTS.md#worktrees-owner-2026-11-25).

Item 1 (Enter first) done and checked in Chrome on laptop-mac, not deployed (needs a setup-repo pin bump). Order: feedback items 1 and 2 ([docs/feedback.md](docs/feedback.md)); the name (decided: keep `rweb`, see PLAN Phase 5 step 0); then Phase 5 (release builds for the owner's
machines) and Phase 6 (distribution to other people, behind Superlogical's answer, a licence and a
cleaned public repo). Owner's decision: distribution means both. See [docs/PLAN.md](docs/PLAN.md#phase-5-release-builds-for-the-owners-machines).

## Handover (2026-11-23): the week of daily use has started

**Read this first when resuming.** The owner is now using only Rex and rweb for a week (herdr sessions closed;
see `setup-repo` task `rex-multiplexer-rollout` and `work-rweb-deployment`). This assistant session is expected
to resume **inside a Rex session**, so:

- **Never** stop or restart the Rex server (`rex server stop`, restarting Rex.app), close or kill the session you
  are running in, resize it, or touch any session that is not yours. Test sessions: name them `rweb-test-…`,
  close them when done. Restarting the *bridge* (`launchctl kickstart`, `systemctl --user restart rweb`) does
  not end Rex sessions and is safe.
- State: both hosts serve rweb at `https://<host>.example.ts.net:12443/` (linux-box on a unix
  socket, desktop-mac on loopback plus secret), started by the `rweb` setup-repo module; file transfer is on.
  Everything is committed and pushed (rweb and setup-repo). Phases 0 to 4 are done
  ([docs/phase4-result.md](docs/phase4-result.md)); the week is Phase 3's exit and is the owner's to judge.
- **Feedback log (2026-11-23):** the owner's notes from daily use go in [docs/feedback.md](docs/feedback.md). 1 Enter first: done 2026-11-25, not deployed. 2 no scrolling up on the phone: done (full-screen programs now get wheel reports or Up/Down keys from a drag), confirmed on the owner's phone; live test setup removed. Both deployed 2026-11-25: setup-repo pin `4b8dc92` (commit `329142c`, record `2026-11-25-rweb-pin-4b8dc92`) applied on laptop-mac, desktop-mac and linux-box. gateway-box waits for Phase 5's release binaries. Next: Phase 5. **Phase 5 in progress** in worktree `~/projects/lexlapax/.worktrees/rweb/phase5-release` (branch `wt/phase5-release`): steps 1-3 done (version 0.1.0, `rweb --version`, `zig build dist` with static Linux and third-party notices, `tools/release.sh`, proven on linux-box; [docs/phase5-result.md](docs/phase5-result.md)). **0.1.0 release binaries (`a744ead`) run on laptop-mac, desktop-mac, linux-box and gateway-box** through setup-repo's archive install (step 5); the first three confirmed on the owner's phone; gateway-box waits for the owner's `rweb-serve on` (sudo). No GitHub Release yet (step 4, owner's word). **gateway-box is a tagged Tailscale node** (`tag:gateway`): `--owner-from-tailscale` cannot work there, so setup-repo names the owner (`hosts/gateway-box/rweb/identity`, like Ovis's explicit owner); reachable and checked through Serve 2026-11-25. **0.1.1 (not deployed):** rweb refuses `--owner-from-tailscale` on a tagged node with a clear message; user guide notes tagged machines. Zig pin measured (docs/phase5-result.md, "Pinning Zig"): official Zig 0.17.1 makes same-platform builds reproducible; across host platforms 31 bytes (Highway's embedded cache path) still differ. Release builds use official Zig 0.17.1 (`zig-0.17.1`, setup-repo module `zig-release`, on laptop-mac and desktop-mac) through `tools/release.sh`; both Macs build byte-identical archives for the same commit (checked on `5ad9b59`). **Docs for users (2026-11-25):** README (why, what, how, quick start), [docs/user-guide.md](docs/user-guide.md) (Tailscale and SSH-tunnel setup, services, several machines, the page, troubleshooting), [docs/architecture.md](docs/architecture.md) (Mermaid diagrams), [docs/README.md](docs/README.md) (index); shipped in the archive. Owner's rules for them: generic for anyone, no owner deployment details (setup-repo, host names); purpose is quick responses from a phone or tablet, one rweb per machine; Windows later. Add new items there; do not act on them until asked.
- linux-box's reboot check on the unix-socket setup: done 2026-11-25 (setup-repo record
  `2026-11-25-linux-box-reboot-cleanup`). Skipped by the owner: a link
  between the two hosts' pages. Paused: a folder allow-list for downloads.
- If the owner reports a problem: ask for `rweb-serve status` plus `journalctl --user -u rweb -n 30`
  (linux-box) or `tail -30 ~/Library/Logs/rweb.log` (desktop-mac). Update path: `setup-repo` runbook
  `docs/runbooks/rweb.md`, "Update". Do not apply the module or change Serve without the owner's go-ahead.

## Handover (2026-11-22), picked up on desktop-mac

Phase 0 is finished and pushed. Phase 1 is in progress, steps 1 to 9 done: **Phase 1 exit met** (2026-11-22). The owner's grant for
desktop-mac and linux-box is in [AGENTS.md](AGENTS.md).

desktop-mac facts checked 2026-11-22: Zig 0.17.1 (`/opt/homebrew/bin/zig`); Rex.app
`0.1.0-preview.21`, commit `202b1b3f`, API revision 18 (supports 0 to 18); socket
`~/Library/Application Support/Rex/server.sock` (no `XDG_RUNTIME_DIR`; `rex ls` shows only the
owner's `calm-isle`). The spike builds from a fresh clone on macOS (`ReleaseSafe`, ~2 min,
Ghostty fetched). `spike/`'s Python probes remain Linux-only (`XDG_RUNTIME_DIR`, `systemctl`).

## Current state

- **2026-11-23, where things stand:** the bridge runs on both hosts behind Tailscale Serve (`https://<host>.example.ts.net:12443/`), deployed by the `rweb` module in setup-repo (runbook `docs/runbooks/rweb.md`), with file transfer on. The security review and hardening are done ([docs/security-hardening-2026-11-23.md](docs/security-hardening-2026-11-23.md)); the Phase 4 record is [docs/phase4-result.md](docs/phase4-result.md). **Next:** at linux-box's next reboot, check `rweb-serve status` and the address, then record it in setup-repo. Skipped by the owner: a link between the two hosts. Paused: a download folder allow-list.

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

## Owner decisions (2026-11-25)

- Mobile checks: use the iOS Simulator (desktop-mac, laptop-mac) and the Android emulator (linux-box) yourself; ask the owner only for what they cannot show (AGENTS.md, "Mobile checks").
- Licence: **MIT**, the same as Ghostty and libghostty-vt (`LICENSE`, in the archives from 0.1.1).
- Release builds wait until there is more for a release; no GitHub Release before the owner says so.

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
(`zig build run -- --listen-tcp 0 --random-token`; since 0.1.1 the token's address is printed only to a
terminal). Evidence, findings, limits:
[docs/phase2-result.md](docs/phase2-result.md). Checked on desktop-mac in Chrome, through Serve
port 11443 (each refusal shown), and on the owner's Android tablet (Samsung Keyboard and Gboard
both work); linux-box ran the full suite including live tests. Phone typing works since the owner turned off the phone Tailscale app's power saving (it had
stalled the tailnet path; evidence in Findings 5). Test infrastructure is all removed (bridge stopped,
Serve 11443 and 12443 gone, `rweb-test-phone` destroyed, temp files deleted). `tailscale up` on
desktop-mac needs `--accept-routes`; stop a foreground `tailscale serve` with SIGINT on its own process.
Phone layout reworked (slide-over menu). Tip: run tests with output to a file; piping
`zig build test` into `head` can hang. `mkdir -p .zig-cache/tmp` before `--fuzz`.

## Checks run for this update

- 2026-11-25, 0.1.1 tagged-node refusal: `zig build test` 141 pass + 9 skip (no live), `web-test`, `ReleaseSafe`;
  a static Linux build run on tagged gateway-box with `--owner-from-tailscale` exits 2 with the new message.

- 2026-11-25, docs: SSH-tunnel mode proven (installed rweb on linux-box, loopback + `--token-file`, `ssh -L`
  from laptop-mac: 403 without token, 200 with, cookie afterwards, page in Chrome connected and listed
  sessions; all removed). The six Mermaid diagrams rendered without errors in Mermaid 10.9.1 (Chrome,
  loopback token server, removed). Quick-start commands checked on macOS and Linux (`shasum`/`sha256sum
  --ignore-missing`, secret recipe 43 chars). Relative links resolve; `zig build dist` ships the docs.

- 2026-11-25, Phase 5 steps 2-3: `zig build dist` on laptop-mac; reproducibility (same folder identical,
  different folder or machine not); linux-box (Rex preview.22, rev 19) `zig build test
  -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe` with `REX_SOCKET` 195 pass + 1 skip; the Mac-built
  Linux archive ran on linux-box (200 with token, 403 without). Details in docs/phase5-result.md.
  Commit `9b4df80` was made without its context-map line; this commit adds it.

- 2026-11-25, laptop-mac (Rex 0.1.0-preview.23), Phase 5 step 1: `zig build test` 186 pass + 10 skip
  (no live); with `REX_SOCKET` 148 pass + 1 skip (restart test), `rex ls` afterwards only the owner's
  sessions; `web-test` pass; `ReleaseSafe` build; `rweb --version` checked in the checkout, and in an
  export without `.git` (`commit unknown`, and with `-Dcommit=`).

- 2026-11-22, wterm trial: bundled and vendored wterm 0.6.0 + libghostty core (details and hashes in
  docs/phase3-result.md); Chrome checks of `?term=wterm` (draw, type, colour, wide/combining,
  query replies suppressed); `zig build test` green. (Test setup since removed; see the last entry.)
- 2026-11-22, Phase 3 fixes (soft keyboard live forwarding, Copy view): `zig build test` and `zig
  build web-test` (10 pass) green; Samsung-style key sequence replayed in desktop Chrome, result
  confirmed through Rex's own capture. **(Test setup since removed; see the last entry.)**
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
| Owner's running feedback from daily use (numbered, with status) | [docs/feedback.md](docs/feedback.md) |
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

- Ovis pane management (all widths): top bar shows the workspace name with a dim "i/N" terminal count; a tab strip under it has one tab per terminal in the workspace and a "+" that adds a terminal and switches to it. The old "1/N ▾" dropdown is gone. Checked in Chrome at phone width with a throwaway second and third terminal in `rweb-test-try` (closed again). Not done from Ovis: per-tab ⋯ menu, the machine › workspace line, the search and Chat buttons.

- Tab strip now has a ⋯ for the current terminal (rename, new, close). Rex features reviewed from its llms.txt for further UI (not built): terminal.title/pwd/process/ports/program_status, hosts.list (other Rex servers), windows and panes (focus/zoom), clipboard_read, upload/download, server.status.

- Terminal info (new protocol message `info`, Api.termInfo): the bridge asks Rex for terminal title, working folder (falls back to the foreground program's folder), foreground program, last exit code and listening ports; the page polls every 4 s while visible and shows `program · …/folder` under the workspace name (red "exit N" after a failed command) and `:port` chips beside the tab ⋯. Checked live on `rweb-test-try` with a throwaway `python3 -m http.server` (closed). Hosts/machine switching not built: the bridge talks only to its own machine's Rex socket.

- Program status and terminal actions: `info` also carries Rex's program_status (most urgent record: error > blocked > working > done) shown as a coloured dot, message and percent under the workspace name; new `term_action` message (clear, reset) behind "Clear screen" and "Reset terminal…" in the ⋯ menu. Clear verified live; the status display verified by feeding the page a synthetic `info` message because Rex's OSC 7501 sender format is not in llms.txt (my guesses recorded no status).

- Clipboard from the terminal: new `clip` message (Rex clipboard_read, newest copy up to 48 KiB) opens in the Copy view via "Copied by a program…" in the ⋯ menu; verified live with a real OSC 52 copy from a program in `rweb-test-try`. Tabs from different Rex windows get a thin divider. NOT built, by decision: file upload/download (would let the web page read and write any file on the machine; needs the Phase 4 security review first) and machine switching (bridge talks only to its own Rex socket).

- Drawer restyled to match the header and tab strip (flat rows, borderless 28px icon buttons, accent "New session", current terminal highlighted with an accent bar). Checked in Chrome at phone width only.

- Collapsed key bar is one line that scrolls sideways with the ^ button pinned at the right; the clipboard menu item is now "Text copied in the terminal…" with a one-line explanation. Checked in Chrome at 360px width.

- Expanded key bar is three rows: a full-width extras strip that scrolls sideways, then the modifiers beside an inverted-T arrow pad with the collapse button in its corner. Collapse returns to the single scrolling line. Checked in Chrome at phone width.

- Expanded key bar filled edge to edge: extras row (PgUp PgDn | ~ / \ - `) shares the full width; modifiers plus Home, End, Paste form an even 5x2 grid beside the arrow pad. Home/End/Paste move back to the extras row on collapse. Checked in Chrome at phone width.

- **2026-11-23: wterm is now the default terminal** (xterm.js stays as the fallback in the ⋯ menu, remembered per browser in `rweb.term`). Test setup removed on desktop-mac: bridge stopped, Serve 12443 off, session `rweb-test-try` killed, temp files deleted; the owner's other Serve entries and `calm-isle` untouched. Nothing of rweb runs on desktop-mac now. State: Phases 1-3 built and owner-tested on phone and tablet; Phase 3's exit (a week of daily use) is the owner's. Next: Phase 4 (security review first, covering `'wasm-unsafe-eval'` in the CSP, the loopback-forgeable identity on desktop-mac and the held-back file transfer; then release builds and a `setup-repo` module), only on the owner's go-ahead.

- **2026-11-23: security hardening done** ([docs/security-hardening-2026-11-23.md](docs/security-hardening-2026-11-23.md)): the first review's 7 findings plus 11 more of my own (Host/DNS rebinding, secrets in argv and the URL, stale-socket deletion, WebSocket ping and fragment floods, raw JSON passthrough of key/mouse, heavy-call amplification, log forging, unpinned vendor files, missing headers, an untested code path in main.zig) are fixed with a failing-without-the-fix test each. macOS boundary: loopback TCP with an owner rule now refuses to start without `--backend-secret-file` (a secret first path segment that Tailscale Serve is pointed at); verified live through real Serve on desktop-mac (forged headers 404, via Serve 200, WebSocket connects, secret not in the log or the address bar), then removed. Checks: `REX_SOCKET=… zig build test` 125 pass + 1 skip (restart test), `web-test` 14 pass, `fuzz` pass, ReleaseSafe builds. Still open before deployment: Phase 3's week of use (owner's), the owner's approval, re-verifying the linux-box unix-socket path through real Serve, and the `setup-repo` module (requirements in §4 of the hardening doc). File transfer remains unbuilt and unapproved. The bridge is not running anywhere.

- **2026-11-23: file transfer built** ([docs/file-transfer.md](docs/file-transfer.md)): off unless `--enable-file-transfer`; downloads through Rex's `download_begin` + `rex.data.bytes.v1` (works, verified byte-identical live), uploads written by the bridge itself into `--upload-dir` because Rex's `upload_begin` stages then deletes the file for non-app clients (measured). One-time 30 s tokens issued over the Origin-checked socket; `GET/PUT /xfer/<token>`; sanitized never-overwriting names, 0600, quoted path pasted with a trailing space; picker in the ⋯ menu. `zig build test` with `REX_SOCKET`: 147 pass + 1 skip; web-test 14; fuzz; ReleaseSafe builds. Live browser test on desktop-mac with throwaway session/folder, all removed. Found and fixed on the way: two arena-copy leaks in `api.zig`, `app.js` code placed after `main()` (now guarded by a test). Next: the linux-box unix-socket check through real Serve.

- **2026-11-23: linux-box verified** (docs/security-hardening-2026-11-23.md §6): scratch clone built there, `zig build test` with live Rex preview.22/rev 19: 194 pass + 1 skip; found and fixed a Linux-only compile error (owner check now uses `statx`). Same-user forgery on the unix socket refused at accept. Serve to a unix socket needs root, so that one chain is **not run** (the owner's `sudo`; the two commands are in §6). Loopback TCP with the secret prefix verified end to end through linux-box's real Serve (200 from another node, 403 for its own address, 404 forged, 431 for 70 headers, 403 wrong Host, WebSocket connects). Everything removed from linux-box; `rex ls` shows only `drifting-tundra`, Serve has its original three entries.

- **2026-11-23: deployment module written in setup-repo** (commit `8becbde`, local, not pushed; `modules/rweb`, `docs/runbooks/rweb.md`, task `work-rweb-deployment`). Pins rweb commit `713a418c80cf…`, builds it on each host with a recorded checksum, makes the backend secret, runs the bridge at boot (systemd user unit with lingering on linux-box, LaunchAgent on desktop-mac) on `127.0.0.1:7695`, and `rweb-serve on` adds the Serve entry `https://<host>:12443 -> http://127.0.0.1:7695/<secret>`. Tested in throwaway homes on both hosts and through real Serve on desktop-mac; nothing applied to the live hosts. Needs from the owner: push rweb (the pin must exist on both hosts), pull + `bin/mls apply rweb` + `rweb-serve on` on each host.
