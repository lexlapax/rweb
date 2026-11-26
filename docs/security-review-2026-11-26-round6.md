# Security review, round 6 (2026-11-26)

Inputs, on commit `1908e25` (round 5's fixes, the Zig idiom pass, and two changes made after them: uploads
through a part file, and a deadline on `tailscale`): an external static security scan (one Medium, one
Low; neither round-5 finding came back), and two release-readiness reviews. One, on Linux with the live
Rex, judged the commit ready and noted that the `tailscale` timeout restarts with every read. The other,
reading the two new changes, found two release blockers in them, a conditional Medium and two Lows. Every
item was checked against the code and the pinned Zig's standard library; all seven are real.

Why they were missed: both blockers are in code written the same day, after round 5's reviews, and
reviewed by nobody but its author. The other five are one question the earlier rounds did not ask of
every place: **what can change while something waits?** A paste waits for the clipboard; an upload
waits for its bytes; a call waits for a child process; a list of addresses waits a minute for its next
refresh; a release folder waits between runs. Each fix below answers that question where it arose, and
the same question was then asked of the neighbours (the variants, V1 to V5).

## Tally

| Id | Finding | Severity | Verdict |
|----|---------|----------|---------|
| S1 | The page's Paste waits for the clipboard, or for the Paste box, without keeping the terminal it was asked for; if the view changes meanwhile, up to 32 KiB of clipboard text goes to the terminal then on screen (`app.js` `doPaste`) | Medium | Accepted |
| V1 | The same in "Reset terminal…" and "Fit terminal to this window…": the answer to the question is sent to whatever terminal is open when it is given | Medium-low | Found here; fixed with S1 |
| V2 | An upload's token was issued for the terminal the bridge had open when it was asked, not the one the files were chosen for; the page compared afterwards. The download picker's listings and downloads went through whatever terminal was open when each was asked | Low | Found here and by the internal review; fixed with S1 |
| R1 | The removal of leftover part files at startup takes every regular file named `.rweb-upload-*.part` in the upload folder: an upload in progress in another rweb using the same folder (it then fails when it is named), or a file of the user's with such a name | Release blocker | Accepted |
| R2 | The `tailscale` deadline was `std.process.run`'s `timeout`: in Zig 0.17.1 it restarts with every read, and the wait for the child's exit that follows has no limit, so a `tailscale` that closes its output and stays stalls the own-address refresh for good | Release blocker | Accepted |
| V3 | Worse than reported: `std.process.run`'s cleanup on a timeout (`Child.kill`) sends SIGTERM and then waits without limit, so a child that ignores SIGTERM hangs the call even when the timeout fires | Release blocker (same fix) | Found here in the std source |
| R3 | The own-address list is kept when a refresh fails, without limit. After an address change that rweb could not learn of, a request from the node itself, which Serve attributes to the owner, is not refused (unless a token is also required) | Medium, conditional | Accepted |
| V4 | The first refresh came a minute after serving began, though the wait for Rex between reading the addresses and serving has no limit | Low | Found here; fixed with R3 |
| R4 | An uploaded file's path is pasted after a check that the page may still write to that terminal, but not in one step with it, and by a direct Rex call rather than the terminal's input queue: a switch, a disconnect or view-only in between is not seen | Low | Accepted |
| V5 | That direct call also bypassed the one-call-in-flight order the queue exists for (Phase 0: concurrent writes arrive out of order), so the path could land inside what was being typed | Low | Found here; fixed with R4 |
| R5 | The docs said a power cut never leaves a file that looks whole; nothing was flushed to disk before the file was named, so after a power cut a named file could be short or empty | Low | Accepted (flushed, and the claim narrowed to what a flush gives) |
| S2 | `tools/release.sh` makes its base folder private but reuses the Zig cache found in it; a cache planted while the folder was open to others would be built from | Low | Accepted |

## Fixes, by mechanism

**What is asked of a terminal goes to that terminal or nowhere (S1, V1, V2).** The page keeps a count of
views (`state.viewGen`, raised each time it shows another terminal, shows none, or reconnects). Anything that waits before
it is sent is held with the view it was asked in (`keys.js` `holdView`) and sent only if that view is
still on screen (`stillView`): a paste after the clipboard or the Paste box, the multi-line question,
Reset, Fit, file uploads (held from when "Upload files…" is chosen), and pending Copy/clipboard replies (`text`, `clip`).
A switch away and back is another view; what was asked before it is dropped with a notice.
The download picker is held the same way: it is for the terminal it was opened on, ignores late `ls` replies
for an earlier view, and closes, unsent, if another is on screen when something in it is asked or when the bridge
refuses `ls`/`dl` as `stale`/`reload`. Queued uploads follow the view they were chosen in (`stillView`), not just
the terminal identity, and an in-flight upload XHR is aborted on disconnect so reconnecting never wedges the queue.
Second line, in the bridge: `paste`, `fit`, `term_action`, `ul`, `ls`
and `dl` name their terminal (`session`, `block`; `protocol.Target`), and the hub does them only if that is the terminal it has open for the page
(`Hub.forTerminal`): `code: stale` otherwise. A message that names none is refused with `code: reload`
(a page left open from an earlier rweb; the page says to reload). Upload tokens are also stamped with the viewer's
view generation (`Viewer.view_gen`) and revoked immediately when the viewer leaves a terminal (`unsubscribe`), so
switching away and back to the same terminal cannot revive a token or paste a mid-flight upload. Typed input (`in`, `key`) is sent in the
same turn as the key press and stays as it was: the bridge handles one page's messages in order.

**An unfinished upload is rweb's own, locked while written (R1, R5).** Part files live in `.rweb-partial/`
inside the upload folder: made 0700, opened once at startup without following a link, checked like the
upload folder itself. A part file's name is 32 random hex digits and `.part`; it is created exclusively
and held under `flock` until it is closed (`xfer.createUploadPart`; on macOS the lock is taken in the
`open`, on Linux right after it, and a file removed in between is noticed by its link count and made
again). The startup sweep removes only regular files of that exact name that it can lock (including on
filesystems whose directory entries report `DT_UNKNOWN`, where `statAt` and `fstat` verify a regular file
without following links): what a stopped rweb left, never an upload another rweb is writing, and nothing in
the upload folder itself. Before the file is named it is flushed (`F_FULLFSYNC` on macOS, falling back to
`fsync` only when the filesystem reports `F_FULLFSYNC` unsupported and failing immediately on `EIO`,
`ENOSPC`, `EDQUOT` or permission errors; `fsync` elsewhere); it is named by a hard link from
the part folder into the upload folder, and the upload folder is flushed too before the page is told it
worked (if that fails, the name is taken back and the upload reported failed).

**The path is pasted in one step with its check, in the terminal's input order (R4, V5).**
`Hub.pasteUpload` checks, under the page's own lock, that it is still there, may write, and still shows
that exact terminal view (`view_gen`), and queues the paste in the terminal's input queue before releasing the lock. The reply
says `pasted: false` when it was not, and the page says the file was saved and its path not typed. That
is the last moment only: a page that leaves the terminal or turns read-only before the `PUT` starts has its
upload tokens revoked (404); a page that changes while the bytes are arriving is refused (403) and nothing is saved.

**One deadline for a child's output and its exit (R2, V3).** `src/bridge/proc.zig` replaces
`std.process.run` for `tailscale`: the child runs in its own process group (`.pgid = 0`), with one end time
for reading both pipes (checking read errors in the loop) and for the exit, which is asked for with
`waitpid(WNOHANG)` until then; a child still there has its process group (`-pid`) and itself sent `SIGKILL`
and reaped, so grandchild processes cannot outlive the deadline or keep pipes open. The child is
killed only while it is unreaped, so no other process can get the signal.

**A list that has not been confirmed is not trusted (R3, V4).** The server records when the own
addresses were last confirmed (when they were read at startup, before the wait for Rex, and at each
refresh that Tailscale answered with a usable list), measured on the **boot clock** (`Io.Clock.boot`), which
keeps advancing while the machine sleeps. When they are read from Tailscale and that is more than 150 seconds ago, every request the rule
would judge is refused (`own_addresses_stale`), until Tailscale answers. It is judged at each request,
from the clock, so it holds if the refresh loop itself were stuck. The loop refreshes at once when
serving begins, every minute after, and every 15 seconds after a failure, waiting in 5-second slices against
the boot-clock target so a wake from sleep triggers a refresh promptly. Not with a list the owner gave
(`--own-address` without detection) or `--allow-own-address`. **Left as documented limits:** an address
change is seen at the next refresh (up to about a minute), and already-open WebSocket connections are checked
at upgrade time rather than severed mid-connection on an address change or staleness.

**Nothing found in the release folder is used (S2).** After the base folder is found ours and not a link,
an unrecognized non-empty folder is refused *before* its mode or ACLs are modified, so a folder named by mistake
loses nothing and keeps its permissions. For a folder `release.sh` made (marked with `.rweb-release-base`) or
an empty one, `release.sh` sets `0700`, strips extended ACLs (`chmod -N` on macOS, `setfacl -b` on Linux,
failing if any ACL marker `+` remains), removes everything inside, and makes the source and Zig cache new
each run (removing them at its end). An old `/tmp/rweb-release` from before this change has no marker:
remove it once. Two runs at once in one base are not supported.

## The internal review of these fixes

A reviewer with no part in the fixes read the whole change against its claims and the pinned standard
library. It confirmed the locking and sweep, the flush order, the lock order of `pasteUpload` (`Hub.mu`,
the viewer's lock, then the input queue's, which is a leaf), the child deadline, and that every message
of the four kinds names its terminal. It found, and these are fixed in the same commit:

- the idle watchdog of an upload still ran during the flushes, so a flush slower than 30 seconds would
  have cut a finished upload (it now ends with the body);
- "confirmed at start" was the time serving began, not the time the addresses were read;
- the download picker's `ls` and `dl` named no terminal (V2);
- `release.sh` emptied whatever folder its override named, even in its check-only mode (the marker);
- wording that claimed more than the code: when a file is saved without its path being typed, what a
  failed reply leaves behind, the view rule for uploads;
- an `else` in a switch over a small error set, and no allocation-failure test for `proc.run`.

Left as they are, on purpose: `createUploadPart` maps the many errors of creating a file to one with an
`else`, as the file's other callers of the same std calls do. Part files that the unreleased `1908e25`
build left in an upload folder itself (`.rweb-upload-*.part`) are not removed by this build: removing
files by name from the user's folder is what R1 was. That build ran for a day on the owner's machines; a
leftover exists only if rweb was stopped mid-upload there.

## Tests added

- `proc.zig`: a program that ends (output, standard error, exit code); and one that prints nothing and
  stays, closes its output and stays, ignores SIGTERM, or keeps printing a little: each cut at the
  deadline; output over the limit; a program that is not there.
- `xfer.zig`: the sweep removes an unlocked part file and leaves a locked one, other names, a folder
  with a part name and names of other shapes; a part file is 0600, locked and removed; the part folder
  is made 0700 and a link in its place is refused.
- `hub.zig`: a paste, resize, terminal action and upload request for another terminal are refused
  (`stale`), one naming none is refused (`reload`), none of the text reaches the terminal and no upload
  token is issued; an upload's path arrives between two pieces of typing in order, and is refused for
  another terminal, another viewer, view-only, no terminal and a viewer that left.
- `protocol.zig`: the four messages carry their terminal; half a name or a wrong shape is malformed.
- `access.zig`, `server.zig`: a stale list refuses requests from anywhere, a failed or unusable refresh
  confirms nothing, a good one restores judging and adds the new address; a list the owner gave never
  goes stale.
- `server.zig`: the upload reply says `pasted`; nothing is left in the part folder.
- `tests/web/keys.test.mjs`: `holdView` and `stillView` (another terminal, away and back, none); a paste
  at the limit still fits with its terminal named.
- `tools/release-base.test.sh`: a used folder (a cache, links out of it, a hard link) is emptied and
  what its links led to is kept.

## Checks run

On the final tree, 2026-11-26, Zig 0.17.1 on both machines.

- **macOS (Apple silicon; Rex 0.1.0-preview.21, API revision 18; no live Rex tests):** `zig fmt --check
  src build.zig` clean; `zig build test` 400 passed, 11 skipped, 0 failed (rex 114/122, bridge 217/219,
  fuzz corpus 69/70), the same with `-Doptimize=ReleaseSafe`; `zig build web-test` 44/44;
  `tools/release-base.test.sh` 6 ok, 1 skipped (needs root).
- **Linux (x86-64; Rex 0.1.0-preview.22, commit `a086db17`, API revision 19), a scratch copy, removed
  afterwards:** `zig fmt --check` clean; `REX_SOCKET=… zig build test -Dtarget=x86_64-linux-musl
  -Doptimize=ReleaseSafe` 408 passed, 3 skipped, 0 failed (rex 121/122, the skip is the gated restart;
  bridge 217/219, two macOS-only; fuzz 70/70); without the live Rex 11 skipped, 0 failed; web tests
  44/44; `tools/release-base.test.sh` 6 ok, 1 skipped. `rex ls` the same before and after.
- **`tools/release.sh` as a dry run** in a scratch base, on a commit object of the final tree:
  the tests passed in `ReleaseSafe` on the exported tree, both archives were packed, `SHA256SUMS` verified and
  `BUILDINFO` written (official Zig 0.17.1, Darwin arm64); afterwards the base held only its marker. The
  dry run's archives were removed: they are of a tree, not of a commit on `main`.
- **Live, macOS, desktop Chrome, a `ReleaseSafe` bridge on `127.0.0.1` with a random token and throwaway
  `rweb-test-` sessions of two terminals (all removed afterwards):**
  - Paste chosen on terminal 1 with the clipboard made to answer after 2 seconds, terminal 2 opened
    meanwhile: nothing arrived in either terminal (checked with Rex's own capture of both) and the page
    said "Not sent: the terminal on screen changed". The same staying on one terminal: the text arrived
    there. Away and back to the same terminal while the clipboard was pending: not sent.
  - An upload with a hostile name: saved under its safe name, 0600, its quoted path at the prompt,
    nothing left in `.rweb-partial/`.
  - A second bridge started on the same upload folder with a planted leftover part file, a file of
    another name in `.rweb-partial/`, and two part-like names in the upload folder itself: it removed the
    one leftover and nothing else.
  - The download picker: listed the terminal's folder and started a download; opened again and the view
    changed under it, the next request was not sent and the picker closed.

**Not verified (on `449812a`):** the owner's phone; the Android emulator and the iOS Simulator (the page's Paste,
Reset, Fit and upload paths were driven in desktop Chrome only, the clipboard's delay by replacing
`navigator.clipboard.readText` in the page); a real upload in progress in one bridge while another starts
(covered by the unit test of the lock, not run with two processes); a real power cut; `rweb tailscale`
through Serve with this build; a stale own-address list on a live node (unit and server tests only). The
simulator and Serve runs belong to the live test before the push, as in rounds 4 and 5.

## Follow-up review of `449812a` and fixes

A follow-up audit of `449812a` against its hypothesis, variants, code and remediations found seven remaining
gaps, all fixed in the follow-up commit on `main`:

1. **Own-address staleness paused during suspend (`server.zig`, `main.zig`).** `Io.Clock.awake` stops
   counting while the host sleeps, so a machine sleeping across a Tailscale IP change woke with a "fresh"
   address list and slept the rest of its 60-second timer before refreshing. Switched freshness tracking to
   `Io.Clock.boot` and changed the refresh wait loop (`waitUntilBoot`) to sleep in 5-second slices so a wake
   from suspend triggers a refresh promptly. Also documented that already-open WebSockets are judged at upgrade
   time rather than cut mid-connection.
2. **Upload A → B → A view reuse, client upload/copy/ls view leaks, and `api_mu` serialization (`hub.zig`,
   `xfer.zig`, `server.zig`, `app.js`, `keys.js`).**
   - `Viewer` now tracks a monotonic `view_gen` (bumped in `claimLocked` and `unsubscribe`) stamped onto each
     upload token (`Entry.view_gen`), and `unsubscribe` revokes the viewer's pending upload tokens immediately
     (`xfers.revokeViewerUploads`, returning 404). Switching A → B → A can no longer revive a token or allow
     `pasteUpload` to paste a mid-flight upload into a reopened terminal.
   - `Hub.handleTransfer` moved `h.api_mu` inside `.ls`/`.dl` after `forTerminal`, so `.ul` (which makes no
     Rex call) no longer stalls behind slow directory listings.
   - `app.js`: bound file picking (`xf.pick = holdView()`) from menu click to `#upfile.onchange`; changed
     `pumpUploads` and `dropForeignUploads` to require `stillView(u.view)` rather than terminal ID alone;
     bumped `state.viewGen`, cleared `copyPendingView`, and aborted any in-flight upload XHR (`clearActiveUpload`)
     on `connect()` / `ws.onclose` so a drop mid-upload cannot wedge the queue; gated `text`, `clip` and `ls`
     replies on `ready() && stillView(...)`; closed `#xferdlg` on `ls`/`dl` `stale`/`reload` errors; aligned
     Reset terminal's post-dialog checks (`stillView` + `canType() && ready()`); prevented `dialogResult`
     re-entry while `dlg.open`; updated `keys.js` `pasteRefusal` to measure exact JSON-escaped `session`/`block`
     lengths.
3. **`sweepUploadParts` skipped `DT_UNKNOWN` entries (`xfer.zig`).** On Linux filesystems that return
   `DT_UNKNOWN` from `getdents64` (e.g., XFS without `ftype`, overlayfs, FUSE/tmpfs variants), leftover part
   files were never swept. Extracted `sweepPartEntry`, accepting `.file` and `.unknown` and verifying regular
   files via `statAt` (`S_IFREG`) and `f.stat(io).kind == .file` on the opened descriptor (still never following
   symlinks or removing directories or locked files).
4. **macOS `F_FULLFSYNC` fell back to `fsync` on `EIO` (`server.zig`).** `syncToDisk` now inspects `errno`
   from `fcntl(F_FULLFSYNC)`: retries `EINTR`, falls back to `fsync` only on `OPNOTSUPP`, `INVAL`, `NOTTY`,
   `NODEV`, or `NOSYS`, and fails immediately on `EIO`, `ENOSPC`, `EDQUOT`, `ACCES`, `PERM`, `ROFS` or
   unexpected errors.
5. **`proc.run` left grandchild processes alive and deferred read-error checks (`proc.zig`).** Children now
   run in their own process group (`.pgid = 0`), `end()` kills `-pid` as well as `pid` so grandchildren holding
   stdout/stderr open are terminated at the deadline, and `readers.checkAnyError()` runs inside the read loop.
6. **`tools/release.sh` mutated unrecognized folders before refusing and left ACLs intact.** Moved the
   unrecognized non-empty folder check ahead of `chmod 0700`, added ACL stripping (`chmod -N` on macOS,
   `setfacl -b` on Linux), and failed if an extended ACL (`+`) remains.

### Checks run on the follow-up commit (2026-11-26, Zig 0.17.1)

- **macOS (`laptop-mac`, Apple silicon):** `zig fmt --check src build.zig` clean; `zig build test` Debug
  401 passed, 11 skipped, 0 failed (rex 114/122, bridge 218/220, fuzz 69/70); `zig build test -Doptimize=ReleaseSafe`
  401 passed, 11 skipped, 0 failed (332/342 + 69/70 cached fuzz); `zig build web-test` 44/44;
  `sh tools/release-base.test.sh` 7 ok, 1 skipped (root-only), including macOS extended ACL stripping and
  mode preservation on refused folders.
- **Linux (`linux-box`, x86-64; live Rex `0.1.0-preview.22`, commit `a086db17`, API revision 19; scratch copy
  removed afterwards):** `zig fmt --check src build.zig` clean; `REX_SOCKET=/run/user/1000/rex/server.sock
  zig build test -Doptimize=ReleaseSafe` 409 passed, 3 skipped, 0 failed (rex 121/122, bridge 218/220, fuzz
  70/70 cached); `zig build web-test` 44/44; `sh tools/release-base.test.sh` 6 ok, 1 skipped (root-only).
  `rex ls` unchanged before and after.
- **Live — Android Emulator (`setup-repo_pixel_api37` / `emulator-5554` on `linux-box`, Chrome driven over ADB +
  CDP against Linux `ReleaseSafe` bridge on `127.0.0.1`, throwaway `rweb-test-r6-emu` 2-terminal session, all
  removed afterwards):**
  - Token form sign-in and redirect to `/s/<id>/`; live terminal render; 0 console errors.
  - Delayed clipboard paste dropped on A → B and on A → B → A (`Not sent: the terminal on screen changed`),
    and delivered when staying on A (`RWEB_ANDR_OK`), verified via `rex capture` of both blocks.
  - Reset terminal and Fit terminal dialogs dropped after `viewGen` change (`Not sent: the terminal on screen changed`).
  - Download picker listed `dl-sample.txt` and closed on stale view change without starting a download.
  - Upload end-to-end with hostile name (`andr-r6; $(id).txt`) saved `0600` as `andr-r6_ _(id).txt` with
    `.rweb-partial/` empty and quoted path pasted into the prompt.
  - Two-file upload queued with immediate A → B → A switch dropped (`Upload stopped: you switched terminals`),
    neither file written.
  - Late Copy text (`text`) reply after switching terminals suppressed (`#copydlg` stayed closed).
  - Reconnect bumped `viewGen` and restored the open terminal cleanly.
- **Live — Desktop Chrome (`laptop-mac`, macOS `ReleaseSafe` bridge on `127.0.0.1`, throwaway `rweb-test-r6`
  2-terminal session, all removed afterwards):** token form sign-in and `/s/<id>/` redirect, live shell render,
  Reset and Fit confirmation modals, Download picker listing, 0 console errors. (JS monkey-patching checks in
  desktop Chrome were blocked by an MCP tool approval timeout; those cases were verified live in Android
  Emulator Chrome above.)
- **Live — iOS Simulator (`Setup-repo iPhone` on `laptop-mac`, Mobile Safari against the same macOS `ReleaseSafe`
  bridge):** loaded `/s/<id>/`, served all page/wterm/WASM assets, connected over WebSocket (green status
  indicator), rendered the session prompt (`Pick a terminal from the list.`). (Simulator automation cannot tap
  inside Mobile Safari.)

**Still not verified:** the owner's physical phone (real soft keyboard, touch hardware, Tailscale app);
`rweb tailscale` through Serve from another tailnet node with this build; real host sleep/wake with live
Tailscale; two concurrent bridges uploading to the same folder; a real power cut.

## A second look at the follow-up commit (`c8fc37d`)

Read in full against `449812a`, and run on both machines. One defect, fixed:

- **A lock taken twice in the upload request.** The check that the page still shows the pinned terminal
  held the viewer's lock and, when the terminal had closed in between (another task clears it), sent the
  refusal while still holding it; sending takes the same lock. The viewer's task would have stopped
  there for good, and the hub with it at the next terminal that closed, since closing takes every
  viewer's lock under the hub's. The window is the moment between two lines, reached only when a
  terminal closes exactly as an upload is asked for. Now `Viewer.viewGenOf` answers with the lock
  released and the refusal is sent after. The test covers the helper and that the viewer answers
  afterwards; the race itself is not reproduced by a test.
- **Changed with it:** on macOS an errno from the full flush that nobody listed fell through to a failed
  upload; it now falls back to `fsync`, which still reports a real failure.

Confirmed as they are: the boot clock counts sleep on both systems (`BOOTTIME` on Linux,
`MONOTONIC_RAW` on macOS, read in the pinned standard library); the process group is killed only while
the child is unreaped; upload tokens are revoked after the hub's lock is released; the sweep does not
open a non-regular file; `release.sh` checks its marker before changing a folder's mode.
Noted, not changed: a reconnect raises the page's view count, so uploads still queued then are dropped
with the "you switched terminals" notice, and an open file picker closes at its next request.

Checks on `c8fc37d`: macOS `zig build test` 401 passed, 11 skipped, 0 failed, the same in `ReleaseSafe`;
web tests 44/44; release-base test 7 ok, 1 skipped. Linux `ReleaseSafe` with the live Rex (preview.22,
revision 19) 409 passed, 3 skipped, 0 failed; web tests 44/44; `rex ls` unchanged. With the fix above:
macOS 402 passed, 11 skipped, 0 failed in Debug and `ReleaseSafe`. Not run on the fix: Linux, a browser.
