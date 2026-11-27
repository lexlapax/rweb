# Agent context map

Last updated: 2026-11-27 (0.2.0 released; Phase 6: `rweb doctor` and rebuildable browser code done; signed checksums next).
Read first; load linked
context lazily. Keep this file short: current
state, decisions, blockers and next actions. Put durable evidence in `docs/`.






## 2026-11-26: links to rweb's page (owner)

The header logo is a link, and the ⋯ menu ends with "About rweb": both open `https://github.com/lexlapax/rweb`
in a new tab with `noopener noreferrer` (the page also sends `Referrer-Policy: no-referrer`), since this
page's address names the machine and, through a tunnel, the token's path. It is the page's only outside
address: `assets.zig` and the server's CSP test allow exactly that link and nothing else. Checked in
desktop Chrome on a ReleaseSafe bridge (a real click opened the GitHub page; the header unchanged).

The logo also turns (one turn per 2.4 s) while the terminal on screen receives output, and stops upright
at the end of a turn once no output came for 1.2 s (`keys.js` `keepTurning`, tested); none with
`prefers-reduced-motion`. Checked in desktop Chrome on a ReleaseSafe bridge: still at rest, turning during
a 4-second `echo` loop, upright again after it.

## Where things stand (2026-11-26, end of the day)

- 0.1.1 is released (GitHub Release `v0.1.1`, commit `1846885`) and runs on the owner's four machines;
  the repository is public. Phase 5 is done; Phase 6's gates are met and its steps' status is in
  [docs/PLAN.md](docs/PLAN.md) ("Phase 6"): no channel, `doctor` or signed checksums yet.
- **Phase B** of [docs/zig-idiom-audit-2026-11-26.md](docs/zig-idiom-audit-2026-11-26.md) (section 4):
  **step 1 done** (typed JSON in the Rex client; allocations per call down 57 to 74 %; results and the
  `.{}`-is-a-list trap the fake hid, in the audit). `src/rex/measure.zig` measures the client
  (`RWEB_MEASURE=1`). **Step 2 done**: the release allocator stays std's `SafeAllocator`, now stated in `main` and
  checked at compile time; measured with the fixed workload `src/bridge/bench.zig` (`RWEB_BENCH=1`):
  5 to 12 % more CPU than `smp`/C, same latency and memory. **Step 3 done**: the output path makes no allocations once warm
  (48 to 80 per MiB before), a keystroke 4 instead of 23 (reusable read buffers, a pool of two live
  buffers per viewer, requests written in one pass); `src/rex/counting.zig` counts and profiles call
  sites. F4 and F16 followed (replies and redraws handed over, not copied;
  a browser connection 128 KiB smaller). **Step 4 done**: `checkAllAllocationFailures` for 12 parsers and
  owning types, and 166 fail-from-N rounds of a hub handling every message type; found a double free in
  `Mirror.setNonce` on out-of-memory (fixed), and three smaller faults. **Step 5 done**: the supervisor
  sleeps until an event or its next deadline (it woke every 200 ms), a new stream waits on the mirror's
  "settled" signal (it polled every 5 ms), one deadline watcher per Rex connection (a task per frame
  before), and each task calls Rex through its own `Api` (one lock serialised every call). A closed block
  reaches the page in 2.4 ms (195), opening takes 0.8 ms (7.4), a resize behind another browser's stuck
  listing 0.7 ms (4.9 s). Found on the way: the supervisor swallowed a cancel in places, which the 200 ms
  poll had hidden (`close` waited 30 s); it now checks `closing` before every wait. **Step 6 done**:
  30 assertions (lock held in every `...Locked` function via `rex.sync.held`, exact viewer queue counts,
  frame kinds, reference counts, list links, the event ring's bounds); the workload is unchanged with
  them. **Step 7 in progress** (its "Progress" note in the audit): one `bridgeModules` in `build.zig`
  and an `-Doptimize` whose help says a plain build is Debug; `--test-timeout 60s` in `tools/release.sh`;
  the socket's own error logged where Rex and browser connections end; fuzz targets for `cleanPaste`,
  `escCut`, the mountinfo and POSIX ACL parsers (moved to std-only `rex/escape.zig`, `bridge/protocol.zig`,
  `bridge/fsparse.zig`) and a seeded random-output test for the mirror; `zig build fuzz -Dtest-filter=`.
  Checked: macOS live against revision 24 (ReleaseSafe 366 pass, 5 skip), Debug 358/13 skip, linux-box
  live 450/6 skip, 2M fuzz inputs per new target. Owner (2026-11-27): no unstripped binaries (releases
  stay stripped at compile time); valgrind on linux-box through setup-repo (`dev` module, pushed;
  the owner installed it). 2026-11-27: the bridge filters its log (Ghostty's output parsers silent, its
  other scopes errors only); the suite ran under Valgrind on linux-box (static musl at x86_64_v3, since
  AVX-512 and Arch's loader stop it otherwise): all tests pass, the only reports are a futex wake inside
  std's `Io.Threaded`. `src/bridge/sys.zig` holds every raw call of the bridge, each
  returning a Zig error set (macOS live 370/5 skip, linux-box live 454/6 skip). `error_tracing` measured: +6 % binary, no CPU or
  latency cost beyond noise, not enabled (stripped releases would show addresses only). **Open in step 7:**
  F14, F17, F18, F19, F22 as their files are next touched. **0.2.0 (owner, 2026-11-27: every recommendation
  taken):** version set, changelog dated and grouped by topic, README names the current release, its
  0.2.0 review and build commands (owner asked for both), archives carry the README's screenshots, user
  guide notes the upgrade. Release commit `010e057`; `tools/release.sh 010e057` on laptop-mac
  (official Zig 0.17.1): linux-x86_64 `6c07756d…`, macos-arm64 `f992b849…` in `zig-out/release/0.2.0/`.
  **Trial 2026-11-27, those archives through setup-repo's pin (local commits on laptop-mac and linux-box,
  unpushed) on both, each behind its existing Serve entry:** `rweb --version` 0.2.0 / 010e057 / revisions
  18-24; desktop Chrome (laptop-mac) → linux-box: list, open, typing, a closed terminal leaves the page at
  once; escape sequences that Ghostty complains about left nothing in linux-box's log (the filter, in a
  running bridge); iOS Simulator Mobile Safari (laptop-mac) → linux-box: page loads and connects; Android
  emulator Chrome (linux-box) → laptop-mac: drawer, open, typing through Gboard, key bar. Web tests 45/45
  (Node on linux-box; laptop-mac has none on PATH). Throwaway `rweb-test-trial020` sessions killed on both.
  **Released 2026-11-27:** the owner's phone check passed; tag `v0.2.0` at `010e057`, GitHub Release
  "rweb 0.2.0" (Latest) with both archives and `SHA256SUMS` (downloaded back and verified; archives carry
  no private names); setup-repo pin pushed and applied: all four machines run `rweb-0.2.0-010e057157c5`
  behind unchanged Serve entries, 0.1.1 kept for rollback. **Phase B done (2026-11-27):** F14, F17, F18, F19,
  F22 fixed (the audit's "five leftovers" note; checks macOS live 370/5 skip, Debug 362/13, linux-box live
  453/6, web 45/45); in CHANGELOG "Unreleased". **Phase 6, the owner's order (2026-11-27): `doctor`,
  rebuildable browser code, signed checksums, channels; then the owner's review round 7, then a release.**
  `rweb doctor [tailscale|ssh] [options]` done (`src/bridge/doctor.zig`): Rex, secret/token/upload files
  (checked without being made: `openUploadDir` and the socket folder take `create`), the bridge (Linux:
  `/proc/net/unix`, so a running bridge logs no refused peer; else a connect), Tailscale sign-in, HTTPS
  certificates, the Serve entry (the secret compared in memory, never printed) and Funnel. Checked on
  laptop-mac (all pass; the ssh layout and a wrong Rex socket fail with fixes) and linux-box (all pass,
  no log line); macOS live 458/5 skip, linux-box live suite passed. Rebuildable browser code done
  (`tools/vendor/`, [docs/vendored-browser-code.md](docs/vendored-browser-code.md)): all eight vendored files
  rebuild byte-identical from integrity-checked npm packages on macOS and Linux; `ghostty-vt.wasm` is
  wterm's own module (69 exports of its own; the pinned Ghostty's wasm build exports its C API), so it is
  checked against its package, not built (the owner asked to try; stopped and reported as agreed). Run
  in this session at the owner's word after assistant-sandbox's rules declined network work.
  **Next:** signed checksums, owner's choice 2026-11-27: `ssh-keygen -Y sign` with a dedicated Ed25519 key
  in 1Password (the owner makes the key); then channels.
- Small items for the next release: `tools/dist.sh` ships the README without `assets/screenshots/`;
  whether the build should refuse group- or world-writable `zig-pkg` folders.
- Not verified: a host's sleep and wake against the stale-address refusal.
- Rex (2026-11-26, later): laptop-mac rebooted and its server now runs revision 24 (`server.version`);
  rweb's live suite passed against it.
- Rex (2026-11-26): every machine has 0.1.0-preview.25 installed (API revision 24, server speaks 0 to 24).
  linux-box and the other machines restarted onto it; desktop-mac's server still ran revision 18 when
  this was built (its restart ends every session there; the owner's). rweb now asks for 18 to 24: its
  live suite passed at revision 24 (linux-box) and at 18 (desktop-mac), and a browser run against the
  revision-24 server (open, type, new terminal and `exit`, Copy view, fit, Reconnect) passed. The 18 to 24
  differences in Rex's own document: new methods and optional arguments rweb does not use, and the
  `com.superlogical.fs` block type, which the tree now leaves out with every non-terminal block. Not
  changed: the deployed binary (0.1.1, revisions 18 to 19), which a preview.25 server serves at 19.

## 2026-11-26: GitHub settings (owner)

Pull requests and projects are turned off on the repository (wiki and discussions were off already);
forks are allowed (always, for a public repository). Issues stay on, for bug reports only: a form in
`.github/ISSUE_TEMPLATE/bug_report.yml`, blank issues off. README and CONTRIBUTING.md say so.

## 2026-11-26: screenshots

`assets/screenshots/desktop.png` and `phone.png`, shown at the top of the README; how they were made and
what was kept out of them (host and tailnet names, personal sessions, the prompt): its README. The phone
address is blurred. Found while making them: the clones' `zig-pkg/` and `zig-out/` were writable by group
and others (Zig keeps the modes of the dependency tarballs); fixed by hand on the owner's machines with
`chmod -R go-w`. Release archives were not affected (`tools/release.sh` builds in its own private folder
with a new cache). Not yet decided: whether rweb's build should do this itself.

## 2026-11-26: public

- Superlogical (Discord, 2026-11-22): no restrictions on Rex clients; please do not use Rex's dinosaur logo
  (rweb's logo is its own).
- The owner chose to rewrite this repository's history and make it public. In every file version and
  commit message, the owner's tailnet name became `example.ts.net`, the hosts `linux-box`, `desktop-mac`,
  `laptop-mac` and `gateway-box`, and the private setup repository `setup-repo`; every commit is authored
  by the owner's GitHub no-reply address. The README names the maintainer. The pre-rewrite history is kept
  only in the owner's own backup.
- Deployment (the owner's, outside this repository): rweb is now each host's main Tailscale Serve
  address (port 443).

## 2026-11-26: `f43ae8e` deployed

- Deployed through setup-repo on laptop-mac, desktop-mac, linux-box and gateway-box (its pin `a9451b7`, its action
  record `2026-11-26-rweb-f43ae8e-fleet.md`): a preflight of the new binary with each host's real
  settings, then the apply; each page answers through Serve from another node, linux-box refuses its own
  address, no host logs the stale-address warning. `rweb-0.1.1-1908e25eab91` is kept on each for rollback.
- In desktop Chrome through Serve to linux-box, a throwaway `rweb-test-serve` session (removed): a paste
  whose clipboard answered late was dropped after a switch and arrived without one; an upload was saved
  and its path typed, nothing left in `.rweb-partial/`.
- **Browsers through Serve, after a forced re-apply and restart on every host (all four run `f43ae8e`,
  restarted 14:17):** one scripted run of 16 checks per browser and host, each from another node, with a
  throwaway two-terminal `rweb-test-` session, and Rex's own capture of both terminals read afterwards:
  desktop Chrome (laptop-mac) against linux-box, gateway-box and desktop-mac; Android emulator Chrome
  (linux-box) against laptop-mac and gateway-box; iOS Simulator Mobile Safari (laptop-mac, safaridriver)
  against linux-box and desktop-mac. 7 of 7 runs passed every check, no page errors. The checks: a late
  paste dropped after a switch and after away-and-back, delivered when staying; Reset answered after a
  switch not sent; upload saved and its path typed, nothing left in `.rweb-partial/`; picker lists and
  closes after a switch; Copy view; View only blocks a paste; reconnect reopens the same terminal. The
  clipboard delay was made by replacing `navigator.clipboard.readText` in the page; taps were the page's
  own `click()`, not touch. Sessions, uploads, safaridriver and the emulator removed or stopped.
- **The owner's phone (2026-11-26):** the owner tested this build on their phone and reported "tested all
  done" (the step list given: paste, typing and key bar, upload, download, Copy, reconnect, on each host).
- **Not verified:** a host's sleep and wake.
- **Next:** on the owner's word, the 0.1.1 release commit (date the changelog), tag and private release. The archives in
  `zig-out/release/0.1.1/` are of `f43ae8e`; a release commit changes the commit, so they are rebuilt then.

## 2026-11-26: round six + follow-up hardening (pushed on `main`; not yet deployed)

Record: [docs/security-review-2026-11-26-round6.md](docs/security-review-2026-11-26-round6.md) (tally,
fixes by mechanism, follow-up review of `449812a`, tests, checks, what is not verified).

- **Inputs on `1908e25` (committed as `449812a`):** a scan (Medium: a paste could
  reach another terminal; Low: reused Zig cache in `release.sh`) and readiness reviews (two blockers in
  the same day's upload and `tailscale` changes; a conditional Medium on stale own addresses; two Lows).
  All seven real; five more variants found.
- **Follow-up audit of `449812a` (fixed and merged on `main`):**
  1. Own-address staleness switched from `Clock.awake` to `Clock.boot` + 5 s wait slices so suspend counts
     toward the 150 s limit and wake triggers a prompt refresh; documented that already-open WebSockets
     are checked at upgrade time rather than severed mid-connection.
  2. Upload, Copy/Clip, modal and `viewGen` gaps: `Viewer.view_gen` + `Entry.view_gen` + `xfers.revokeViewerUploads`
     on `unsubscribe` (A → B → A cannot revive upload tokens or paste mid-flight uploads); `Hub.handleTransfer`
     no longer locks `api_mu` for `.ul`; `app.js` binds file picking (`xf.pick`), queued uploads (`stillView`),
     Copy/clipboard replies (`copyPendingView`), and `ls` replies to the active view, aborts in-flight upload XHR
     and bumps `viewGen` on reconnect/disconnect, closes `#xferdlg` on `ls`/`dl` `stale`/`reload`, guards
     `dialogResult` against re-entry, aligns Reset post-dialog checks, and `keys.js` `pasteRefusal` measures
     exact JSON-encoded ID lengths.
  3. `xfer.sweepUploadParts` handles `DT_UNKNOWN` directory entries (via `statAt` + `f.stat` kind check).
  4. `server.syncToDisk` on macOS checks `errno` on `F_FULLFSYNC` (retries `EINTR`, falls back to `fsync`
     only for unsupported-filesystem errors, fails immediately on `EIO`/`ENOSPC`/`EDQUOT`/permission errors).
  5. `proc.run` spawns the child in its own process group (`.pgid = 0`), kills `-pid` + `pid` past the
     deadline (preventing grandchild hangs), and calls `readers.checkAnyError()` in the read loop.
  6. `tools/release.sh` refuses unrecognized non-empty folders before `chmod 0700`, strips extended ACLs
     (`chmod -N` / `setfacl -b`), and fails if `+` ACL markers remain.
- **Protocol change:** a page left open from before `449812a` is told to reload when it pastes, resizes,
  resets, uploads or opens the file picker.
- **Upgrade notes:** remove an old `/tmp/rweb-release` once before the next `release.sh`; a host whose
  Tailscale stops answering for 150 s (including sleep) now refuses requests until it answers.
- **Checks run on the follow-up commit:**
  - macOS (`laptop-mac`, Apple silicon, Zig 0.17.1): `zig fmt --check src build.zig` clean; `zig build test`
    Debug 401/412 (11 skipped, 0 failed) and `ReleaseSafe` 401/412 (11 skipped, 0 failed); `zig build web-test`
    44/44; `tools/release-base.test.sh` 7 ok, 1 skipped (root-only), including macOS ACL strip.
  - Linux (`linux-box`, x86-64, Zig 0.17.1, live Rex `0.1.0-preview.22`, commit `a086db17`, API revision 19):
    `zig fmt --check` clean; `REX_SOCKET=… zig build test -Doptimize=ReleaseSafe` 409/412 (3 skipped, 0 failed);
    `zig build web-test` 44/44; `tools/release-base.test.sh` 6 ok, 1 skipped (root-only). Scratch copy removed;
    `rex ls` unchanged.
  - Live — Android Emulator (`setup-repo_pixel_api37` / `emulator-5554` on `linux-box`, Chrome via ADB+CDP against
    Linux `ReleaseSafe` bridge on `127.0.0.1` + throwaway `rweb-test-r6-emu` 2-terminal session): token form
    sign-in, terminal render, delayed paste A → B and A → B → A dropped (verified via `rex capture` of both
    blocks), staying paste delivered, Reset & Fit dropped on `viewGen` change, Download picker stale close,
    Upload e2e (0600, `.rweb-partial/` empty, quoted path pasted), Upload A → B → A dropped, late Copy text
    suppressed on switch, Reconnect `viewGen` bump, 0 console errors.
  - Live — Desktop Chrome (`laptop-mac`, macOS `ReleaseSafe` bridge on `127.0.0.1` + throwaway `rweb-test-r6`):
    token form sign-in, live shell render, Reset & Fit modals, Download picker listing, 0 console errors
    (JS monkey-patch checks blocked by MCP approval timeout; covered in Android Emulator Chrome).
  - Live — iOS Simulator (`Setup-repo iPhone` on `laptop-mac`, Mobile Safari against the same macOS bridge):
    loaded `/s/<id>/`, served page + wterm/WASM assets, connected over WebSocket (green dot), rendered UI.
  - All throwaway sessions, bridges, emulator instance, and temp folders cleaned up afterwards.
- **A second look at `c8fc37d` (`f43ae8e`, pushed):** the upload request sent its refusal
  while holding the viewer's lock when the terminal closed under it (the viewer's task, then the hub,
  would have stopped); fixed with `Viewer.viewGenOf`. An unlisted errno from macOS's full flush now falls
  back to `fsync`. Checks: `c8fc37d` re-run on macOS (401/412 both modes) and Linux live (409/412); with
  the fix, macOS 402/413 in Debug and `ReleaseSafe`, Linux `ReleaseSafe` with the live Rex 410/413 (3
  skipped). Not run on the fix: a browser. Record: the round-6 document's last section.
- **Archives:** `tools/release.sh f43ae8e` on laptop-mac (official Zig 0.17.1): `zig-out/release/0.1.1/`
  with `SHA256SUMS` (verified) and `BUILDINFO`; Linux `13174e9d…`, macOS `b38079d2…`; the packed macOS
  binary reports commit `f43ae8e`. The `1908e25` archives are kept in `zig-out/release/0.1.1-1908e25eab91/`.
- **Not verified:** the owner's physical phone, `rweb tailscale` through Serve with this build, real host
  sleep/wake with live Tailscale, two concurrent bridges uploading at once, a real power cut.
- **Next:** deploy `f43ae8e` through `setup-repo` (the owner's approval) with Serve testing from another
  node and the owner's phone, then the 0.1.1 release commit and tag on the owner's word. Deployed hosts still run `1908e25`.

## 2026-11-26: pushed and deployed

- `main` at `1908e25` is pushed (owner's word). Archives from `tools/release.sh 1908e25` on laptop-mac
  (`zig-out/release/0.1.1/`, with `BUILDINFO`); the earlier 0.1.1 archives are kept in
  `zig-out/release/0.1.1-d1cf9218d72a/`.
- Deployed through setup-repo on laptop-mac, desktop-mac, linux-box and gateway-box (its pin `c47dfaf`, its action
  record `2026-11-26-rweb-1908e25-fleet.md`): before the pin, the new binary was run on each host with
  that host's real settings on a throwaway socket or port and started without a refusal; after the apply,
  each host's page answered through Serve from another node. The deployments still start rweb with the
  earlier option form, not `rweb tailscale`.
- **Not verified:** the owner's phone on this build; the upload change in a browser.
- **Next:** the external security scan and readiness review of `1908e25`; then the items listed under
  round five and the Zig idiom pass below. The changelog is not dated and nothing is tagged: this is not
  the 0.1.1 release commit.

## 2026-11-26: Zig idiom pass (owner: "did you follow the Zig ethos")

- **What:** an idiom audit of the whole source and the owner's research note
  (`tools/zig-idioms-audit-checklist`, in the research repository) run as a 38-item checklist. Record:
  docs/zig-idiom-audit-2026-11-26.md (verdict: no rewrite; findings F1 to F24 with status; the checklist
  item by item: 21 pass, 16 need a fix, 1 not applicable; Phase B). Rules: AGENTS.md "Zig practice".
- **Changed now (no behaviour change):** the pinned Zig's current names: `@backingInt` /
  `@fromBackingInt` (the formatter's rewrite is no longer reverted), `Allocator.print` for
  `std.fmt.allocPrint` (204 sites), `dependencyLazy`; `zig fmt --check src build.zig` passes.
- **Fixed now (small):** `tailscale` runs with a deadline and an output cap; a failed `Hub.open` frees
  what it made; an untracked connection is closed; close-on-exec failure fails the listener;
  `tools/release.sh` tests in `ReleaseSafe`.
- **Checks run:** macOS `zig build test` after the renames 382/393 (11 skipped) and after the small
  fixes 315/325 (10 skipped; fuzz from cache), web tests 42/42; Linux after the renames only: with the
  live Rex 390/393 (3 skipped), without it 381/393 (12 skipped), `zig fmt --check` clean; the Linux
  release binary read with `readelf` (static PIE, no interpreter, no needed libraries). **Not run
  then:** the small fixes on Linux and `tools/release.sh` (both run later the same day, below); any
  measurement.
- **After that, same day:** uploads are written to a part file and named only when complete; leftover
  part files are removed at start (so a stop, crash or power cut never leaves a file that looks whole).
  Checks on that commit: macOS `zig build test` 316/326 (10 skipped; fuzz from cache); Linux with the
  live Rex 391/394 (3 skipped), without it 382/394 (12 skipped), which also covers the small fixes above;
  `zig fmt --check` clean on both; `tools/release.sh HEAD` as a dry run in a scratch base (tests in
  `ReleaseSafe`, both archives, checksums). Not run: the upload change in a browser or simulator.
- **Open (Phase B, after 0.1.1, each with measurements):** typed JSON in the Rex client; the release
  allocator decision; per-frame and per-keystroke allocations; `checkAllAllocationFailures` tests; event
  waits, one write-deadline watcher, the mutex around Rex calls; assertions on internal invariants. The audit document lists each with file and line.

## 2026-11-26: round five (in progress, not merged, not released)

Record: [docs/security-review-2026-11-26-round5.md](docs/security-review-2026-11-26-round5.md); the
owner's decisions are in [docs/PLAN.md](docs/PLAN.md) ("Owner's decisions (2026-11-26)").

- **What it changed.** Two commands, `rweb tailscale` and `rweb ssh`, set everything up (secret, token,
  folders; `--config-dir`, `--port`) and print the one step left; the old options stay as "Advanced".
  The listener is taken first and held while rweb waits for Tailscale and Rex (it no longer exits).
  `[::1]` is held too. Token mode has a token form, a wrong-token limit and tap to reconnect. No group is
  trusted (macOS `admin` only for folders above and programs); local disks only; links followed only from
  checked folders when root's or the user's. Tokens are 32+ characters. Refusals are plain sentences with
  a `Fix:` line. New source: `src/bridge/layout.zig`, `src/bridge/web/login.{html,js,css}`.
- **State.** The code is committed on `wt/reviews-note` at `124eb91` (worktree
  `~/projects/lexlapax/.worktrees/rweb/reviews-note`), not merged to `main`, not deployed. A second pass
  (internal re-review, a readiness review on macOS, a Zig idiom audit; findings S1 to S13 in the record)
  is fixed and merged.
- **Checks actually run on the merged work (2026-11-26):** macOS: `zig build test` 382/393 (11 skipped),
  web tests 42/42. Linux with the live Rex: 390/393 (3 skipped), web tests 42/42, release-base test,
  `zig build dist`. The Linux release binary as a new user (refusals and their Fix lines, `rweb ssh`,
  the form over the socket, socket removed on SIGTERM). Live on a Mac with a throwaway session: the
  Tailscale layout from the Android emulator (Chrome) and the iOS Simulator (Safari), and the tunnel
  layout from both (form, sign-in, drop, one attempt per tap). Exact results and limits:
  docs/security-review-2026-11-26-round5.md.
- **Not verified:** the owner's phone; `rweb tailscale` on Linux through Serve (needs `sudo tailscale
  serve`); typing into the form in iOS Safari (automation cannot tap there); the deployed hosts against
  the new refusals. `tools/release.sh` not run.
- **State then:** merged to `main` locally, not pushed. Pushed and deployed later the same day (above).
- **Next:** the owner's other review; before upgrading a host, check it against the new refusals
  (group-writable folders above rweb's files, token length 32, local disks), and consider moving the
  deployments to `rweb tailscale`; the deferred Zig idiom items (typed JSON in the Rex client, release
  allocator choice with measurements, per-frame allocations, event waits, write-deadline watcher, the
  api mutex); then, on the owner's word: push, the 0.1.1 release commit (date the changelog), archives,
  tag and private release.

## 2026-11-26: logo

The owner chose concept A ("prompt in a window", Terminal green: tile `#181818`, foreground `#ececec`,
accent `#3fb950`). Sources, colours, sizes and spacing in [assets/logo/README.md](assets/logo/README.md);
`assets/logo/build.sh` exports every raster with headless Chrome (byte-identical on a rerun) and
`ico.py` packs `favicon.ico`. The page serves `icons/` (favicon SVG and ICO, apple-touch-icon, 192, 512,
maskable 512) and `manifest.webmanifest` (relative URLs, `display: standalone`), with links in
`index.html`; the logo shows before the title while no terminal is open (CSS `:has`, app.js unchanged).
CSP gains `manifest-src 'self'` (`img-src 'self' data:` was already there); the manifest link uses
`crossorigin="use-credentials"` so the tunnel's cookie reaches it. Tests: the manifest names embedded
PNGs of the stated sizes; the server serves each icon with its type and the CSP has `manifest-src`.
README heading is the lockup (`<picture>`, dark and light). Checked on laptop-mac: `zig build test`
265/275 (10 skipped, no live), `web-test` 29/29, `zig build`; the header and every raster looked at in
headless Chrome. Not checked: a phone's home screen or a simulator. Release archives (`tools/dist.sh`)
copy `README.md` without `assets/`, so there the heading shows its alt text.

## 2026-11-26: the reviews, described for readers

At the owner's request, README "Security, in short" gains "How it was reviewed" (the design review, four
rounds of scan, readiness and internal adversarial review, over 120 findings, the live test, links to each
round's record), and docs/README.md gains a "How it was reviewed" section listing every round (round 4 was
missing from the index), and "About this project" says point releases will follow as the owner finds
things worth adding or fixing. Reviewers named generically. Round 5 has its own section above; the README and the index now say five rounds and no longer say the
final candidate was run live (that run comes before each release and is recorded in the round's document).

## 2026-11-25: fourth review round of `c5fd3c1` and its fixes

A readiness review on linux-box (hold: a startup race made two round-3 hub tests fail on Linux), an external
rescan (Linux ACL writer on `tailscale`, unterminated control strings, the CDN-loading spike) and a
four-part internal review (25 more) were checked against the code. Tally, plan, fixes, tests, checks and
what is left: [docs/security-review-2026-11-25-round4.md](docs/security-review-2026-11-25-round4.md). The
worst: round 3's server-side paste cleaning broke every paste with characters such as `’ € ß` or emoji;
kitty graphics in the mirror (unbounded placements, 400 MB image loads). Fixed by mechanism: the mirror is
a renderer (kitty/glyph off, 64 KiB control strings, scrollback and redraw/Copy byte budgets); paste and
page correctness; one checked path (ACLs on Linux and macOS, strict Linux groups, foreign mounts refused,
`tailscale` run by its checked path); Rex write deadlines and resume streaks; `release.sh` tests and pins
Zig, `-dirty` stamps; spike removed (owner's decision); README "About this project" and `CONTRIBUTING.md`
(owner's request). Checked on laptop-mac: unit 326/337, live 272/274, fuzz corpus, web 29/29. **Next (owner's
plan):** commit locally (not pushed), build archives with `tools/release.sh`, swap the live service on
laptop-mac and linux-box through a setup-repo worktree pin, test through Serve with the iOS Simulator
(laptop-mac → linux-box) and the Android emulator (linux-box → laptop-mac), then the owner tests; push only
after that. Live test so far (f13222f on laptop-mac and linux-box through setup-repo): both started with their
live config; through linux-box's Serve from desktop Chrome a Unicode paste (`’ € ß`, Cyrillic, emoji, CJK)
and a two-line paste into zsh worked, and rapid terminal switching never sent typing to a terminal not on
screen; but keystrokes typed right after a switch were dropped (the round-3 page waited for `opened`
before sending input; not needed for safety since the bridge handles a page's messages in order). Fixed in
the next commit; the tools scripts are now executable (`tools/release.sh` never was). Live with 4c79a12:
typing still lost right after a switch on desktop because focus stays on the clicked tab until `opened`
(as in 0.1.0); the page now focuses the terminal when the switch starts (wide screens only). Android
emulator on linux-box → laptop-mac through Serve: page, drawer, typing through Gboard and the key bar's ^C
work; iOS Simulator on laptop-mac → linux-box: page loads and connects through Serve. Owner's phone test
(Samsung, Chrome): tapping End on the key bar opened the Paste dialog (Paste fired on first touch; now on
a completed tap ending on it); copy looked broken: on the emulator, menu Copy, long-press Copy and menu
Paste (after Chrome's clipboard permission) work, but "Select all" took in the page's labels and hidden
dialogs (now only terminal text, the Copy view and fields are selectable). Logo (concept A, terminal
green) added in every format and wired into the page, manifest and README. Owner: the header logo was only
shown with no terminal open (the page restores the last terminal, so it was never seen); now always shown.
Owner confirmed on their phone (both hosts): logo, End, copy and paste, Select all, the multi-line question.
Live record: docs/security-review-2026-11-25-round4.md, "Live test before the push". Deployed: d1cf921 on
laptop-mac and linux-box (setup-repo pin commits local on both, unpushed). **Next:** the owner's word to merge
and push rweb and setup-repo; then the 0.1.1 release commit (date the changelog), archives, tag and private
release; desktop-mac and gateway-box still run 0.1.0.

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
- The spike was in `spike/` (throwaway; Phase 1 started fresh). Removed 2026-11-25 (fourth review round); in
  Git history up to `c5fd3c1`.

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
| Working example of every Rex call the bridge needs | `src/rex/` (the spike's `spike/src/main.zig` is in Git history up to `c5fd3c1`) |
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
