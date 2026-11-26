# Security review, round 4 (2026-11-25)

Inputs, on commit `c5fd3c1`: an independent release-readiness review on Linux (verdict: hold, one blocker,
R1), an external static security scan (three findings, X1-X3), and an internal adversarial review in four
parts, each by a reviewer reading the code without the others' conclusions: the round-3 hub, server and
page changes (H), the library and the limits inside the pinned Ghostty (L), filesystem and process trust
(T), and everything outside the product code (O). Every item was checked against the code before it was
accepted.

## Tally

| Id | Finding | Severity | Verdict |
|----|---------|----------|---------|
| R1 | `onEvent(.connected)` re-broadcasts "Rex up" and re-reads the tree for the connection `Hub.open` already set up; two round-3 hub tests race it and failed on Linux | Blocker | Accepted |
| X1 | A named POSIX ACL entry (Linux) can give another user write to the `tailscale` program or a folder above it; the checks read only mode bits | High | Accepted |
| X2 | Unterminated control strings keep growing parser state across chunks | Medium | Accepted; L1, L2 and L4 show the real limits |
| X3 | The Phase 0 spike loads xterm.js from a CDN without integrity checks and can type into a real Rex | Medium | Accepted (owner: remove the spike) |
| H1 | The server's paste cleaning removed bytes 0x80-0x9F one by one, which are also UTF-8 continuation bytes: `’ “ — € ß`, Cyrillic, every emoji and much CJK became invalid and the paste was mangled or lost. A round-3 bug | High | Accepted |
| L1 | Kitty graphics placements have no count limit and each new one scans all the others: unbounded memory and quadratic CPU under the mirror lock, from about 20 bytes of output each | High | Accepted |
| L2 | Kitty images: a 520 KB zlib bomb inflates to 400 MB; unfinished chunked loads hold up to 400 MB per screen, outside the 10 MB storage limit | High | Accepted |
| H2/L5 | The multi-line paste check reads the mirror without `tmu`; a stream restart can free it meanwhile. A round-3 bug | Medium | Accepted |
| L3 | Redraws and Copy text have no byte bound; the formatter turns cheap input into about 100 bytes per cell (styles) or kilobytes (hyperlinks) | Medium | Accepted |
| L4 | Per-terminal memory follows Rex's scrollback limits (unlimited if Rex says so); the glyph protocol's glossary holds up to about 74 MiB that rweb never shows | Medium | Accepted |
| T1 | `tailscale` is checked at one resolution of its path and run from another, so a folder flipped between the two lets another user's program run | Medium | Accepted |
| O2 | The documented release step `zig build dist` builds the working tree, uncommitted edits included, stamped as a clean commit; no tests gate it; the Zig used is not recorded | Medium | Accepted |
| L6 | A frame write to Rex cannot be cancelled and has no deadline, so a Rex that stops reading blocks the writer (and `api_mu`) for good | Medium-low | Accepted |
| T2 | The private-group rule sees only the first group entry for a gid and only what the static binary's account files list; other group sources (duplicate gid lines, NSS, `pam_group`) are invisible | Medium-low | Accepted |
| T3 | A filesystem another user mounts (FUSE with `allow_other`, a macOS disk image) can report any owner and mode | Low-medium | Accepted |
| L7 | A resumed data stream never resets its streak, so an idle terminal dropped twice more than a minute apart is restarted instead of resumed | Low-medium | Accepted |
| O4 | The vendored browser code cannot be rebuilt from recorded sources: truncated tarball hashes, an undocumented wasm inside `wterm.js`, a prebuilt `ghostty-vt.wasm` of unknown Ghostty version | Low-medium | Accepted: documented, rebuild planned for Phase 6 |
| H3 | A late `open` error or `closed` for an earlier terminal clears the terminal the page has switched to since | Low-medium | Accepted |
| H4 | A transient open failure on reconnect (Rex restarting) forgets the terminal to restore | Low | Accepted |
| H5 | The hub-wide work budget can refuse another viewer's `open` | Low | Accepted |
| H6 | Queued uploads continue into whichever terminal opens next | Low | Accepted |
| T4 | A refused `tailscale` candidate is passed over for a later one, which may be a script that runs the refused program | Low | Accepted |
| L8 | The input cutter can still split SS3 keys (`ESC O A`) and X10 mouse reports | Low | Accepted |
| L9 | Program output can turn on bracketed paste (mode 2004) and so skip the multi-line question in a shell that does not use it | Low | Accepted as a documented limit (xterm trusts the mode the same way) |
| L10 | The per-second control-frame limit stops the WebSocket fuzzer after 64 control frames per input | Low | Accepted |
| O1, O3, O5, O6 | Spike: the Rex restart probe has no guard; keystrokes logged by default; probes can read the owner's sessions; a fixed port | Medium-high to low | Resolved by removing the spike (X3) |

## Plan: fixes by mechanism

1. **The mirror is a renderer, not a full terminal.** (X2, L1, L2, L3, L4) Turn off what rweb never shows:
   kitty graphics (image storage limit 0, which Ghostty treats as off) and the kitty and glyph APC handlers,
   so their bytes are not even buffered. Bound what stays: scrollback at most 10,000 lines and a fixed byte
   budget whatever Rex allows; OSC and DCS strings bounded by Ghostty's own fixed limits (checked and
   recorded); redraw and Copy formatted into writers that stop at a byte budget, a redraw falling back to
   less history and finally the screen alone.
2. **Paste and page correctness.** (H1, H2, H3, H4, H5, H6, L8, L9) Clean pastes by character, not by byte
   (done); read the paste mode under `tmu` (done); name the terminal in `open` errors, and let the page act on
   an error or `closed` only for the terminal it shows; keep the terminal to restore across a transient
   failure; leave `open` out of the hub-wide budget; bind each queued upload to its terminal; cut input never
   inside SS3 or X10 sequences; document that a program can claim bracketed paste.
3. **One checked path for programs and folders.** (X1, T1, T2, T3, T4)
   - `tailscale`: open it without following links inside its checked folder and run exactly that path; stop
     at the first candidate that exists (a refused one is an error, not a reason to try the next).
   - ACLs: on Linux read `system.posix_acl_access` from the open descriptor when the group-write bit is set,
     and refuse a named user or group entry whose effective write reaches anyone but root, the owner or a safe
     group; on macOS refuse ALLOW entries that give write or delete to anyone but root, the owner or a safe
     group (deny entries, such as the home folder's, pass), and strip inherited ACLs from what rweb creates.
   - Groups: on Linux a group-writable folder passes only in the one-group-per-user case (the owner's
     primary group, named like the owner, the only entry with that gid, no members), checked across every
     group entry, failing closed when the account files are incomplete or other account sources are in use.
   - Mounts: refuse a FUSE filesystem (Linux) and a mount another user owns (macOS) on a checked path.
4. **Rex connections.** (L6, L7, L10) Every frame written to Rex has a deadline that shuts the connection when
   it passes; a resumed stream that stays up resets its streak; the control-frame rate can be raised for the
   fuzzer.
5. **Releases.** (O2, O4) `tools/release.sh` is the only documented way to make release archives; it runs the
   tests on the exported commit first, refuses a Zig other than the pinned one unless told otherwise, and
   records the Zig used; a build from a changed working tree says `-dirty` in `--version`. Vendored code's
   provenance is written down as far as it is known, with what is not, and a reproducible rebuild planned for
   Phase 6.
6. **Startup and the spike.** (R1, X3, O1, O3, O5, O6) The first connection is not re-announced (done); the
   spike is removed from the tree, with its record kept in `docs/phase0-result.md` and Git history (done).

Owner's decision (2026-11-25): remove the spike. Before pushing, the owner asked for the release build to
be tried on the live setup (macOS and Linux) through setup-repo, then with the simulators, then by the owner.

## What was done, and the tests that show it

| Plan item | Findings | Change and tests |
|-----------|----------|------------------|
| 1. Renderer limits | X2, L1, L2, L3, L4 | `mirror.zig`: snapshot decoded with kitty image storage 0; kitty and glyph APC handlers off; unknown APC and OSC dropped; OSC heap strings and DCS kept to 64 KiB; scrollback capped at 10,000 rows and 32 MiB (or Rex's smaller limits, kept across a reset); snapshot refused over the cell cap from its first record; redraws formatted in a 16 MiB budget with fewer history rows on overflow; Copy formatted in 8 × 1 MiB. Tests: a snapshot with kitty images decodes without them; 4 MiB of unterminated kitty APC, 10,000 placements and 2 MiB of glyph APC leave heap growth under 64 KiB; 2 MiB OSC 52 and DCS strings, terminators split across chunks, leave growth under 128 KiB and text renders after; the scrollback caps and Rex's smaller limits; a 2048×1024 snapshot refused from its first 64 bytes; style- and hyperlink-dense redraws stay in budget with less history; dense Copy stays in budget. Each test fails with its fix removed |
| 2. Paste and page | H1-H6, L8, L9 | `cleanPaste` keeps every character whole and refuses invalid UTF-8 (test with `’ “ ” — € ß`, Cyrillic, an emoji and CJK); the paste mode is read under `tmu`; `open` refusals carry `session`, `block`, `rate`, `transient` (test); `closed` carries `session`; `open` left out of the hub-wide budget. Page: `aboutTerm`, `openRefusal`, `openRetryDelay`, `partitionUploads` with Node tests (29 in all). `escCut` handles SS3 and X10 mouse (tests at several cut points and in the randomised token test). L9 documented in the user guide |
| 3. One checked path | X1, T1-T4 | `xfer.zig`: Linux POSIX ACLs parsed from the open descriptor when the group-write bit is set (tests: named user write refused, read-only passes, mask without write passes, group entries by the group rule, malformed refused; end to end with `setfacl`, run on linux-box); macOS ACLs (tests: deny passes, `allow add_file` for another user refused and named, inherited entries dropped from folders rweb makes); Linux groups only for the owner's own group of one with files-only accounts (pure tests); FUSE and foreign or ownership-ignoring mounts refused (pure tests; this Mac's and linux-box's file systems pass); `tailscale` opened in its checked folder and run by that path, first existing location decides (tests, including a linked folder and a FIFO). A Linux test binary of these ran on linux-box: 39 passed, 3 skipped |
| 4. Rex connections | L6, L7, L10 | Writes to Rex time out (the call's timeout, else 10 s) and drop the connection (tests: a peer that stops reading; a stalled control connection reconnects and the next call works); a resumed stream that stays up 5 s or delivers data resets its streak (test fails without the fix); the control-frame rate is raisable for the fuzzer (seeded with 200 control frames) |
| 5. Releases | O2, O4 | `release.sh` runs `zig build test` on the export without `REX_SOCKET`, refuses a non-pinned Zig unless `RWEB_RELEASE_ANY_ZIG=1`, writes `BUILDINFO`; the commit stamp adds `-dirty` for a changed working tree (checked: this worktree showed `-dirty`); README and PLAN name `tools/release.sh` as the release path; provenance recorded in `THIRD-PARTY-NOTICES.md` and `phase3-result.md`, rebuild planned in PLAN Phase 6 |
| 6. Startup and spike | R1, X3, O1, O3, O5, O6 | `onEvent(.connected)` returns for generations already set up; the two tests that raced it passed five runs each here (they failed on Linux before); `spike/` removed, `phase0-result.md` says where it is in history |

Also added at the owner's request: "About this project" in the README, and `CONTRIBUTING.md`.

## Checks run before the live test (macOS, Apple silicon, Zig 0.17.1)

- `zig build test`: 326 of 337 passed, 11 skipped (live tests and the Linux-only ACL test).
- With `REX_SOCKET` set to this Mac's Rex: 272 of 274 passed, 2 skipped (the gated restart, the Linux ACL
  test); the owner's sessions were untouched.
- `zig build fuzz` (corpus only; a coverage-guided run was not started), `zig build web-test` 29 of 29,
  `tools/release-base.test.sh` 4 passed and 1 skipped.

## Left

- Not tested: a FUSE mount or another user's macOS disk image (pure tests only); a Linux group-writable path
  under files-only accounts (pure test only).
- NFS and SMB permissions on the server side are not visible to these checks (documented).
- A redraw whose visible screen alone exceeds 16 MiB fails (`RedrawTooLarge`) rather than sending part of
  it; it takes a very large screen full of styles or links.
