# Security review, round 3 (2026-11-25)

Inputs, on commit `4c383fb`: an independent release-readiness review on Linux (verdict: ready; three
observations, A1-A3), an external static security scan (three findings, X1-X3), and an internal adversarial
review in four parts, each by a reviewer reading the code without the others' conclusions: the hub and
viewer path (H), the Rex library changes of round 2 (L), filesystem, process and build trust (F), and the
protocol, page and budgets (P). Every item was checked against the code before it was accepted.

## Tally

| Id | Finding | Severity | Verdict |
|----|---------|----------|---------|
| X1 | The unix listen socket's folder is checked, but not the folders above it, and bind and cleanup use the path | High | Accepted |
| X2 | `tree` requests are not counted as heavy and copy the cached tree under `Hub.mu` before coalescing | Medium | Accepted |
| X3 | A redraw appends a theme frame and leaves older queued ones (round 2's `dropScreenLocked` keeps `.theme`); `push` replaces the first queued copy, so an older one can arrive last | Medium | Accepted |
| A1 | `rweb --version` shows a stale commit after `git pull` (Zig caches the configure step) | Low | Accepted |
| A2 | Group-writable folders (Linux umask 0002, one group per user) are refused; tests fail when `.zig-cache` is `0775` | Low | Accepted (owner: allow a group that holds only the user and root) |
| A3 | Review records and a commit name the AI review tools | Hygiene | Accepted (owner: generic wording; the pushed commit stays) |
| P1 | An `open` refused by the rate limit leaves the bridge on the old terminal while the page shows the new one: typing goes to the wrong terminal. A regression from round 2 (open became heavy) | High | Accepted |
| F1 | Test bridges use one fixed token on loopback, including the live test against the real Rex; the fake Rex serves any file a caller names (breaks the rule that test servers use a random token) | High | Accepted |
| H1/L2 | Every ESC in program output reaches each viewer as its own 1-byte frame; the 1 MiB live cap counts payload only, so about a million frames fit | Medium | Accepted |
| H2 | `closeTerminalLocked` empties the terminal's viewer list before clearing each viewer's `term`; a subscribe in between re-adds a viewer with no reference (output pushed into a freed viewer) | Medium | Accepted |
| H3 | Mirror-locked work (Copy, redraws) is limited per socket only; 64 sockets multiply it; a Copy reply is built before the reply budget is checked; viewers can take every connection slot | Medium | Accepted |
| P3 | One slow Rex call holds `api_mu` up to 30 s in a reader task; other readers block, their silence timer fires and every browser is dropped | Medium | Accepted |
| L1 | Cancelling the input worker mid-write leaves a half-written frame on the shared control connection | Medium | Accepted |
| F2 | Rex's socket is trusted by path, with no check of the server's uid; `XDG_RUNTIME_DIR` is searched first even on macOS | Medium | Accepted |
| P2 | wterm sends keyboard-committed text (a phone keyboard's clipboard chip, composition) raw as typed input, outside the paste path | Medium | Accepted |
| H4 | Overflow redraws are not rate-limited and keep "all history" after `more_history` | Medium-low | Accepted |
| H5 | WebSocket pings and fragments are not counted against the per-second cap | Medium-low | Accepted |
| P4 | Redraws and Copy text are capped by rows, not cells (1000 columns × 11,000 rows) | Medium-low | Accepted |
| F3 | `tailscale` is found through `PATH`; the documented LaunchAgent puts `/opt/homebrew/bin` (group `admin`) first | Medium-low | Accepted |
| F4 | The upload folder's real path is checked, but the given path (possibly through a link) is what gets pasted; the folder is created before the check | Low-medium | Accepted |
| P5 | A multi-line paste runs line by line in a program without bracketed paste | Low-medium | Accepted (owner: ask to confirm) |
| L3 | `Control.close` can hang when the reader's cancel is consumed inside a reconnect while Rex is down | Low-medium | Accepted |
| L4 | A data stream resumes in a hot loop on a protocol or size error; 256 Rex pings with no data drop an idle connection | Low-medium | Accepted |
| L5 | Handshake reads and data and transfer streams keep the 64 MiB default message limit | Low | Accepted |
| L6 | The handshake watchdog can fire after a handshake was published | Low | Accepted |
| L7 | A cut coalesced write can split an escape sequence across two writes | Low | Accepted |
| L8 | `Data.close` shuts the socket before sending its close frame, so Rex never gets a clean close | Low | Accepted |
| L9 | Some `Api` calls still swallow cancellation | Low | Accepted |
| H6 | A failed redraw clears a redraw request that arrived meanwhile (a restart's) | Low | Accepted |
| H7 | `Viewer.overflows` can overflow (a panic in ReleaseSafe after about 2^32 refusals) | Low | Accepted |
| P6 | `dl` begins a Rex download before the size check and never cancels it; the 16 waiting tokens are shared by all viewers | Low | Accepted |
| P7 | `clip` shows and copies program-set clipboard text with control characters | Low | Accepted |
| P8 | A paste over the frame limit closes the WebSocket instead of being refused | Low | Accepted |
| P9 | A fast wheel flick in wterm sends one message per row and can trip the 200/s cap | Low | Accepted |
| F5 | macOS ACLs are not looked at by the folder checks | Low | Accepted as a documented limit |
| F6 | A relative `--listen-unix` path crashes on restart after an unclean exit (an assertion in std) | Low | Accepted |
| F7 | Transfer file names go to the log, which some admin groups can read on Linux | Low | Not changed: the log is the owner's record of what moved; documented |

## Plan: fixes by mechanism

1. **The page and the bridge always agree on the terminal.** (P1) A refused `open` (rate limit or failure)
   also leaves the old terminal, and every refusal names the message it refuses (`for: 'open'`). The page
   types only after an `opened` that matches the terminal it shows, and clears its view on a refused open.
   The heavy limit is split so a tab switch (open, fit, two info polls) cannot trip it: reads (`info`,
   `clip`, `tree`) 16 a second, work (open, fit, Copy, redraws, transfers, actions, management) 8 a second.
2. **One budget for work, one for each queue.** (X2, X3, H1, H3, H4, H5, H7, P3, P4, P6, P8, P9)
   - Live output: a new chunk joins the last unsent live frame (up to 64 KiB), and every frame is charged a
     fixed overhead against the cap, so tiny frames cannot multiply.
   - Redraws: a redraw drops every queued theme; a theme update replaces every queued copy, so at most one is
     queued and the newest wins. Overflow redraws: at most one a second per viewer, and `more_history` applies
     to one redraw only.
   - Size: redraw history and Copy text are capped in cells (rows × columns), not just rows.
   - Shared work: a hub-wide budget for mirror-locked work (opens, redraws, Copy) on top of the per-viewer
     limits; a Copy request is refused before any work when its reply could not be queued; at most 32
     WebSocket viewers, so plain requests always find a connection slot.
   - Tree: counted as a read; a request is answered only when the viewer's queued tree is older than the
     current one; the copy is made outside `Hub.mu`.
   - Rate: pings and other control frames count against the per-second cap; the page sends a wheel flick as
     one message; the page refuses a paste over the limit with a message.
   - Liveness: a connection whose handler is waiting on Rex counts as alive; directory listings, downloads and
     terminal info get a 5-second timeout instead of 30.
   - Transfers: at most 4 waiting tokens per viewer; a download over the limit is refused before Rex starts it
     where the size is known; `overflows` saturates.
3. **Lifetime and ordering.** (H2, H6) Closing a terminal clears each viewer's `term` and the terminal's
   viewer list in one critical section under the terminal's viewer lock; redraw requests carry a sequence
   number so a failed redraw clears only its own request.
4. **Trust the peer and the descriptor, not the path.** (X1, F2, F3, F4, F6, A2)
   - Listen socket: an absolute path; every folder above it checked like the secret files'; the folder kept
     open; the bound socket's device and inode recorded, and it is removed at shutdown only if still the same.
   - Rex's socket: after every connect, the server must run as this user (peer credentials); on macOS the
     app's socket is tried before `XDG_RUNTIME_DIR`.
   - `tailscale`: from `--tailscale PATH` or fixed locations, and the binary and its folders must pass the same
     checks (not `PATH`).
   - Upload folder: created only after the folders above it pass, relative to the checked parent; the path
     pasted and returned is the real one.
   - Group-writable folders pass when the group holds no user other than this one and root (as a listed
     member or a primary group): Linux's one-group-per-user default and Homebrew on a single-admin Mac work,
     a shared group is still refused.
5. **Input integrity.** (P2, P5, P7, L7) Text a phone keyboard commits in one go (more than one character, or
   any newline, ESC or C1) goes through the paste path. A multi-line paste into a program without bracketed
   paste needs the user's confirmation: the bridge checks the program's mode at paste time and asks the page
   to confirm. The bridge strips ESC and C1 from pastes too. Clipboard text is shown and copied without
   control characters and labelled as set by a program. A cut coalesced write never splits an escape
   sequence.
6. **Rex connections.** (L1, L3, L4, L5, L6, L8, L9) A frame is written whole or the connection is dropped and
   rebuilt; reconnect loops stop when closing; protocol and size errors end a stream instead of resuming; ping
   floods are limited per second instead of per run; every connection has a message limit from its first
   read; a watchdog that fired fails its handshake; `Data.close` sends its close frame before shutting the
   socket; cancellation passes through every `Api` call.
7. **Tests and build.** (F1, A1, A2) Every test bridge gets a random token; the fake Rex serves files only
   from a per-test folder; the commit is stamped at build time (done: a new commit shows in `--version`
   without clearing the cache, `-Dcommit` still wins and is quoted safely).
8. **Docs.** (A3, F5, F7) Reviewers named generically; ACLs and transfer names in the log documented;
   everything above reflected in the user guide, architecture, file transfer and changelog.

Owner's decisions (2026-11-25): group-writable folders pass when the group holds only the user and root;
a multi-line paste into a program without bracketed paste asks for confirmation; reviewers are named
generically. Added while implementing, on the same reasoning as the group rule: on macOS the `admin`
group counts as root's, because its members can become root with their own password, so refusing a
folder only `admin` can write (the Tailscale app, Homebrew) would protect against nothing.

## What was done, and the tests that show it

| Plan item | Findings | Tests |
|-----------|----------|-------|
| 1. Same terminal on both sides | P1 | `hub: an open refused by the rate limit also leaves the terminal being viewed`; `hub: reads and work have separate allowances…`; the page types only after a matching `opened` and treats a refused open as "no terminal" (checked in Chrome: typing reached the opened terminal) |
| 2. Budgets | X2, X3, H1, H3, H4, H5, H7, P3, P4, P6, P8, P9 | `hub: output in tiny pieces joins one frame…`; `contiguous program output reaches the sink in one call…`; `hub: at most one theme is queued, the newest…`; `hub: a viewer that falls behind is redrawn at most once a second`; `hub: a viewer that already has the current tree is not sent another copy`; `hub: work under a mirror's lock has a budget over all viewers`; `hub: a second Copy before the first is sent is refused before any work`; `mirror: Copy text and redraw history can be capped in cells`; `server: at most max_viewers WebSockets, and plain requests still get in`; `a peer that floods pings…`, `control frames are limited per second, not per run…`; `server: a browser whose handler waits on Rex is not dropped as silent` (fails without the fix); `api: listings, downloads and terminal info wait for Rex only as long as the quick timeout`; `one viewer may have at most max_waiting_per_viewer tokens waiting`; `server: a message over the limit is answered with an error…`; Node tests for the paste size limit |
| 3. Lifetime and ordering | H2, H6 | `closeTerminalLocked` detaches viewers and empties the terminal's list in one critical section under its viewer lock; redraw requests carry a sequence number. Covered by the existing close and restart tests; the race itself is not reproduced by a test |
| 4. Peer and descriptor | X1, F2, F3, F4, F6, A2 | `server: the unix socket's folders are checked to the root, and only our own socket is removed`; `--listen-unix and --tailscale take absolute paths only`; `peer check: only this user may serve Rex's socket`, `peer check: a socket served by this user passes` (and the live tests against this Mac's Rex); `tailscale is taken from --tailscale or fixed places, never PATH…`; `a program is checked by its real path…`; `the real probe refuses a program others can change…`; `a group holds only us and root, or it is shared`; `a folder its group can write to passes only when the group holds no one else`; `a group the system does not know is not private`; `macOS's admin group counts as root's…`; the upload-folder tests (real path pasted, nothing made under a folder others can write) |
| 5. Input integrity | P2, P5, P7, L7 | `hub: a multi-line paste needs confirming when the program has no bracketed paste; ESC never goes through`; `hub: cleanPaste removes ESC and C1…`; `mirror: bracketedPaste follows the program's mode 2004`; `input: escCut…`, `input: a cut coalesced write never splits an escape sequence`; Node tests for `commitIsPaste`, `pastePreview`, `cleanClip`. In Chrome against a release build: a two-line paste into plain `sh` opened the question, nothing was sent until Paste, then both lines ran |
| 6. Rex connections | L1, L3, L4, L5, L6, L8, L9 | `writeFrame: a task cancelled inside a frame still writes it whole` (fails without the fix); `control: a write that fails part-way drops the connection, and it reconnects`; `control: close while Rex is down returns at once`; `data: a protocol or size error from the server ends the stream instead of resuming`; `data: a server that takes every resume and drops it again runs out of the resume window`; `control: a connection's limit is set from its first read`; `watchdog: one that fired fails the handshake…`; `data: close sends a 1000 close frame that reaches the server`; `api: cancellation passes through termInfo…` (fails without the fix) |
| 7. Tests and build | F1, A1, A2 | Every test bridge makes its own random token; `fake: downloads and listings are served only from the fake's own folder` (and the fake removes only a folder it made itself, never one a test hands it); the commit is stamped by a build step: a new commit showed in `--version` without clearing the cache, `-Dcommit` still won, and a hostile `-Dcommit` value became a plain string |
| 8. Docs | A3, F5, F7 | Reviewers named generically in the review records and the context map (the pushed commit message is unchanged: no force-push); user guide ("Files and folders rweb checks", `tailscale` locations, pasting, troubleshooting, upgrade note), architecture, file transfer (tokens per browser, the log), changelog |

## Checks run (macOS, Apple silicon, Zig 0.17.1)

- `zig build test`: 243 of 252 passed, 9 skipped (the live tests); twice more with no failure.
- With `REX_SOCKET` set to this Mac's Rex (its `llms.txt` describes API revision 18): 251 of 252 passed, 1
  skipped (the gated Rex restart); the live tests made and closed their own `rweb-test-` sessions, and the
  owner's sessions were untouched.
- `zig build fuzz` (corpus), `zig build web-test` 26 of 26, `tools/release-base.test.sh` 4 passed and 1
  skipped (needs root).
- A `ReleaseSafe` bridge on 127.0.0.1 with a random token, against a throwaway `rweb-test-r3` session:
  typing, the multi-line paste question in Chrome, and Mobile Safari in the iOS Simulator; the bridge log
  held no token. The same build started with `--owner-from-tailscale` on this Mac (which has two admin
  accounts) found and accepted the Tailscale program.

## Done differently, and what is left

- The socket is bound by path, not relative to its folder (macOS has no `bindat`); safe because every folder
  on the path has just been checked and no link is allowed.
- The race in H2 and the hang in L3 are fixed by construction; their tests check the outcome, not the
  narrow interleaving.
- The private-group check reads the system's account database; a static Linux build (musl) sees only
  `/etc/passwd` and `/etc/group`, so users from a network directory are not seen. Linux with umask 0002 was
  not run.
- A coverage-guided fuzz run (`zig build fuzz --fuzz`) starts Zig's fuzz web page on 127.0.0.1 without a
  token, which the repository's rule for test servers forbids. Round 2 ran one for about eight minutes
  (the page shows coverage only); this round did not, and coverage-guided runs need a way to bind that
  page safely before they are used again.
- Not tested here: Linux, a Serve deployment of this build from another device, a phone keyboard's
  clipboard insert, the Android emulator.
- Deployment: hosts must have `tailscale` in a listed place (the Linux packages and the macOS app do);
  a `--listen-unix` path must have no links; setup-repo's paths were checked on laptop-mac (and, by the
  readiness review, on linux-box); check each host when deploying.
