# Security review, round 2 (2026-11-25)

Inputs: OpenAI Daybreak's rescan of `ded0668` (11 findings, numbered D1-D11 here) and an internal adversarial
review in four parts, each by a reviewer reading the code without the others' conclusions: the request
front end and transfers (H), the Rex client library (R), hub concurrency and read-only enforcement (C), and
the page and release tooling (W). Every finding below was checked against the code before it was accepted.

## Verdicts on Daybreak's findings

| # | Finding | Verdict |
|---|---------|---------|
| D1 | rex1 resize has no geometry or cell budget | Accepted |
| D2 | Copy text and all-history redraw format the whole history before any limit; Copy view makes a node per line | Accepted |
| D3 | macOS Serve target carries the backend secret (argv while `tailscale serve` runs; `tailscale serve status`) | Accepted as a documented limit: the owner chose documentation only. The macOS loopback layout is for a Mac with no other local accounts |
| D4 | rex1 recovery recurses and copies | Partly refuted: recursion depth and copying are bounded by the prefix length (about 28 bytes), so there is no quadratic work. The same code has a real bug: an ESC inside a candidate body followed by a byte other than `\` comes out after that byte (reordered output). Fixed by the rewrite |
| D5 | WELCOME `max_message` has no client ceiling; a long reconnect token trips `assert(hello.len < 512)` | Accepted |
| D6 | Stream restart does its I/O under `Hub.mu` | Accepted |
| D7 | Control events queue without bound, `orderedRemove(0)` | Accepted |
| D8 | `connectOnce` publishes conn and token before a fallible append | Accepted (out-of-memory only) |
| D9 | Secret files checked by path, then read by path | Accepted |
| D10 | Upload folder approved by path, re-resolved per upload | Accepted |
| D11 | Upload tokens stay good after the viewer turns read-only, leaves the terminal or disconnects | Accepted |

## New findings from the internal review

High, all in the hub (C):
- C1 Deadlock: `manage` holds `api_mu` while `markTreeDirty` takes `Hub.mu`; `openTerminal` holds `Hub.mu` while
  `ensureAttachedLocked` takes `api_mu`. A management call racing the first open of a session hangs the bridge.
- C2 `unsubscribe` touches the terminal after clearing `v.term` and before taking `Hub.mu`; the supervisor's
  `closeTerminalLocked` can destroy it in between: use-after-free and double destroy (a shell exiting while the tab
  closes or switches).
- C3 `input`, `clip`, `term_action`, `transfer` and `sendInfo` use `v.term` without pinning it; a terminal closed at
  that moment is freed under them (typing as a shell exits).
- C4 `in_redraw` is one bool shared by the reader (`sendText`) and writer (`redrawFor`) tasks: whichever ends first
  unpins the terminal while the other still uses it.

Medium:
- C5 A failed subscribe leaves `v.term` set with no reference; a later unsubscribe takes another viewer's reference.
- C6 `open`, `fit`, `term_action` and management messages are not rate-limited as heavy; the 200/s cutoff needs two
  hot seconds in a row.
- C7 `pushText` counts live output frames against the 256 text-frame cap, so `closed`, `exited`, `mode`, `rex`,
  `theme` and replies are silently dropped behind a chatty terminal.
- C8 The viewer queue has no byte budget for text frames, and the redraw path appends past the count cap.
- R1 `data.connect` reads `payload.object` without checking the payload is an object (panic on a bad Rex reply).
- R2 `Mirror.deinit` never frees the VT stream (OSC/APC/DCS buffers a program can fill to megabytes), and a mirror
  that failed after going live skips `term.deinit`: leaks on every close and restart.
- R3 A mirror that fails after going live freezes its terminal for good: no callback, no restart, a log line per
  message.
- W1 With the xterm.js engine (the fallback, or forced by `?term=xterm`, which is then remembered), a paste is
  wrapped in bracketed-paste markers without removing ESC, so a pastejacked `\e[201~` ends the paste early and the
  rest is typed; the touch path sends pastes raw.

Low:
- C9 The silent-browser check runs only when the queue is idle, and WebSocket writes have no deadline.
- C10 A restart can erase a stream end that arrives before `ended` is cleared.
- C11 `refreshTree` can return with `api_mu` held (out-of-memory).
- C12 Tree and event checks match block ids and event names by substring; a failed `blocks()` closes that
  session's open terminals.
- C13 Upload entry strings leak when a later copy fails.
- R4 A theme message without a palette leaks its strings (struct literal copies the arena before allocating).
- R5 An out-of-memory error duplicating the owner string leaves a freed pointer that `deinit` frees again.
- R6 `cloneValue` recurses per JSON nesting level (stack overflow on a hostile Rex reply).
- R7 `Control.close` can free the connection while writers or callers are still inside.
- R8 The input queue counts only text bytes; a coalesced write can exceed the control message limit and be dropped.
- R9 Handshakes (control welcome, data welcome, transfer) have no deadline, and `close` cannot reach a connection
  still in its handshake.
- R10 A duplicate response id leaks the first copy. R11 `Api.run` reports transport errors (and cancellation) as
  `RexError` with a stale message.
- R12 Fuzz gaps: WebSocket reassembly, snapshot framing, JSON dispatch; the splitter target rarely reaches the
  message path and never the size limit, and compares only counts.
- H1 The SSH-tunnel cookie's isolation from other localhost services rests on `<id>`, which is treated as public.
- H2 `<id>` lets anyone who sees the URL test token guesses offline; a human-chosen 16-character token is weak.
- H3 The `/s/<id>` redirect runs before `access.decide` and copies raw query bytes (bare LF, CR, NUL) into
  `Location`.
- H4 `--owner` without `--allow-host` only warns.
- H5 `--token` on the command line is not validated (length, characters: CRLF reaches `Set-Cookie`); the random
  token URL goes to the log.
- H6 A local process can churn connections on a TCP listener and keep real requests out (denial of service).
- H7 Transfer bodies and download streams have no progress deadline; a token is used up before a transfer slot is
  taken.
- H8 `prepareSocketDir` checks the socket folder's mode but not its owner.
- H9 Transfer-token expiry uses the awake clock, which stops while the machine sleeps.
- H10 A name with many non-ASCII bytes overflows the `Content-Disposition` buffer (fails safe).
- W2 `?term=` and `?dbg=1` from a link change behaviour; `?term=` is remembered.
- W3 A page response that sets the token cookie is cacheable (`no-cache`, not `no-store`).
- W4 Vendored scripts are cached for a day without revalidation, so a fixed `wterm.js` can lag an upgrade.
- W5 `/api/tree` is served outside the lab gate and nothing uses it.
- W6 Lab pages keep `?token=` in the address bar and print an assistant-addressed line.
- W7 `release.sh` claims reproducibility across machines (only within one host platform); `SHA256SUMS` is unsigned;
  a rebuilt version silently overwrites its folder; `dist.sh` can pack a stale stage.

## Plan: fixes by mechanism, not by finding

1. **Terminal lifetime: one reference count, no I/O under `Hub.mu`.** (C1-C5, C10, C11, D6)
   Every user of a terminal (a viewer's subscription, a handler's call, a redraw, the Copy view, a restart) holds a
   reference taken under `Hub.mu`; `in_redraw` and its spin-waits go. Closing a terminal unregisters it and drops
   the viewers' references; the last reference destroys it, outside `Hub.mu`. Attaching, opening, restarting
   (ticket, WebSocket, snapshot, each with a deadline) and destroying happen without `Hub.mu`; a restart publishes
   its new stream only if the terminal is still registered. `api_mu` joins the documented lock order (never taken
   with `Hub.mu` held, and nothing takes `Hub.mu` while holding it). A failed subscribe undoes itself.
2. **Every queue and buffer has a budget, and overflow has a defined meaning.** (D1, D2, D5, D7, C6-C9, R8, B)
   - Viewer queue: one byte budget for all frames plus a text-frame count; state frames (`closed`, `exited`, `mode`,
     `rex`, `theme`) are kept as latest-value slots, never dropped; overflow of output still becomes a redraw.
   - History: redraw and Copy text are built from at most a fixed number of rows (selection before formatting),
     then the byte cap; the reply says it was cut; the page caps the lines it renders.
   - Control events: a fixed ring; overflow collapses to one `dropped` event, which already means "re-read state".
   - Input: every queued item counts bytes; a coalesced write is cut to fit the control message limit.
   - Resize: 1-4096 per axis and at most 1,048,576 cells; any other resize is ignored and logged once.
   - WELCOME: a client ceiling on `max_message` (16 MiB), a reconnect-token budget (256 bytes), and the hello is
     built in a checked buffer instead of asserted.
   - Rate: `open`, `fit`, `term_action` and management count as heavy; the server's message cap is per window.
   - Liveness: the silent-browser check runs on every loop; writes and transfers have progress deadlines.
3. **Ownership in the Rex library.** (D8, R1-R7, R9-R11)
   Publish nothing into shared state until every fallible step is done; shape-check every payload; free the VT
   stream; turn a mirror failure into a stream end (so the supervisor restarts it); fix the theme arena and owner
   order; clone JSON without recursion past a depth cap; make `close` wait out writers and callers; give handshakes
   deadlines; free duplicate responses; keep transport errors distinct from Rex's.
4. **The rex1 splitter as an iterative state machine.** (D4, R12)
   It holds only the bytes that can still become a message, emits everything else in order, never recurses or
   re-copies. Tested against a simple reference splitter over random inputs and every split point, up to the body
   limit; the fuzz target compares bytes and messages with the reference, seeds the real prefix, and reaches the
   size limit. Snapshot framing moves to `wire.zig` so it is fuzzed; WebSocket reassembly gets a fuzz target.
5. **Files: open once, check the descriptor, use the descriptor.** (D9, D10, H8)
   Secret files are opened with no-follow, checked on the descriptor (regular, ours, closed to others) and read
   from it; every directory above them must be ours or root's and not writable by others (sticky folders allowed).
   The upload folder is opened once at startup with the same checks, kept open, and files are created exclusively
   relative to it. The unix-socket folder must be ours.
6. **Authorize at the time of use.** (D11, W5)
   An upload token names the viewer that asked and its terminal. Redemption, and again the paste, require that the
   viewer still exists, may write, and still views that terminal. `/api/tree` exists only with `--enable-lab`.
7. **The request front end.** (H3-H5, H9, H10, W3, W4)
   Targets with control bytes are refused before routing; the prefix redirect runs after `access.decide` and
   encodes what it copies; `--token` follows the token-file rules; the random-token URL is printed only to a
   terminal; `--owner` needs `--allow-host`; token expiry uses the boot clock; a response that sets the cookie is
   `no-store`; vendored files revalidate.
8. **The page.** (W1, W2, W6, D2)
   Every paste, in both engines and on the touch path, goes through `{t:'paste'}` with ESC and C1 removed;
   `?term=` applies to that page load only and `?dbg=1` needs the bridge to allow it; the Copy view renders at most
   a fixed number of lines and says so; lab pages drop the token from the address and the stray wording.
9. **Docs and release.** (D3, H1, H2, H6, W7)
   The macOS layout requires a Mac with no other local accounts (why: Serve's target and status); `/s/<id>/` is
   part of the secret, and the token must come from the generator in the guide; checksums detect corruption, not
   tampering; `release.sh` states what it reproduces, refuses to overwrite a built version, and `dist.sh` clears
   its stage.

Not changed, by decision: moving the tunnel token out of a cookie (H1, documented instead); a slow KDF for `<id>`
(H2, documented: tokens come from the generator); signing releases (W7, needs the owner's key and choice of tool);
per-process accounting for a local connection flood (H6, denial of service by a local process, documented).

## What was done, and the tests that show it

| Plan item | Findings | Change | Tests |
|-----------|----------|--------|-------|
| 1. Terminal lifetime | C1-C5, C10, C11, D6 | `hub.zig`: `Terminal.refs` counts viewers and tasks (`pin`/`unpin`); `in_redraw` and its spin-waits are gone. Closing a terminal unregisters it and detaches every viewer whose `term` is it (found through the hub's viewer list, not the terminal's); the last reference destroys it outside `Hub.mu`. `openTerminal`, `ensureAttached` and `restartTerminal` wait on Rex without `Hub.mu`; a restart takes the stream's end before opening and swaps in the new stream only if the terminal is still registered. A redraw delivers only if the viewer still looks at that terminal. `api_mu` and `Hub.mu` are never held together; `manage` marks the tree dirty after releasing `api_mu`. A failed subscribe gives its reference back. `refreshTree` releases `api_mu` on every path. | `hub: management calls racing the first open of new sessions do not deadlock`; `hub: a closed block reaches its viewers while they type and leave, without a crash`; `hub: a block that closes is told to its viewer, and the terminal goes`; `hub: a slow stream restart does not hold up other viewers`; the existing open, share, restart and slow-snapshot tests. The deadlock and close tests, run against the hub at `ded0668`, hung (stopped after 300 s); they pass now. |
| 2. Budgets | D1, D2, D5, D7, C6-C9, R8 | Viewer queue: frame kinds; live output 1 MiB then a redraw; one queued redraw, its scrollback capped at 10,000 rows; replies 256 frames and 8 MiB; mode, Rex state, theme and tree replace their queued copy; `closed` and `exited` always queued; O(1) dequeue. Copy text from at most 20,000 rows (`plainTextAll` selects before formatting), then 1 MiB. Control events in a 1,024-slot, 4 MiB ring that collapses to one `dropped`. Input counts every item's bytes and cuts coalesced text to fit the message limit. Resize 1-4,096 per side, at most 1,048,576 cells. WELCOME: 16 MiB ceiling, reconnect token at most 256 printable bytes, hello in a 1 KiB buffer. Heavy requests include `open`, `fit`, `term_action` and management; 200 messages per one-second window. The silence check runs every writer turn; frame writes have a 30 s deadline (a watchdog shuts the socket); transfers are cut after 30 s without bytes. | `hub: state frames replace their queued copy; closed gets through a full reply queue`; `hub: opening again and again without reading keeps one redraw queued`; `hub: opening, sizing and terminal actions count against the heavy-request limit`; `mirror: plainTextAll formats only the last rows when there are more`; `mirror: a resize outside the limits is ignored, and the limits themselves work`; `control: the event queue is a bounded ring…`, `…server events have a byte budget`, `…merges them without losing the last state`, `…with a producer faster than the consumer…`; `input: keys and events count against the byte cap too`, `input: a coalesced write is cut so each request fits the message limit`; `parseWelcome: the server's limit is clamped…`; `control: a hello too large for its buffer is an error, not an assertion`; `server: a silent browser is dropped even while its terminal keeps the queue busy`; `server: a browser that stops reading is dropped at the write deadline`; `server: one hot second is enough to be cut off`; `server: an upload that stops sending is cut, and its partial file removed`. |
| 3. Library ownership | D8, R1-R7, R9-R11 | `connectOnce` publishes only after every fallible step; payload shapes checked (`data.connect`, and `call` requires an object); the mirror frees its VT stream and terminal whenever they were made, reports a failure once as the stream end `mirror_failed` (the hub restarts it); theme and owner allocate before they swap; `cloneValue` stops at depth 64; `close` waits for in-flight calls and writers without giving up on cancellation; handshakes have a 10 s deadline and `close` can shut a connection still in its handshake; a duplicate response frees the first; `Api.run` passes cancellation through and names transport errors. Also found and fixed: `Input.key` and `Input.blockEvent` freed an item twice on backpressure. | `control: open publishes nothing that a failed step frees (every allocation failing in turn)`; `data: a data.connect payload that is not an object is an error, not a crash`; `mirror: an unterminated OSC 52 is freed with the mirror`; `mirror: a theme with no palette leaks nothing`; `mirror: a failure after going live ends the stream once, and later bytes are dropped`; `api: cloneValue stops at max_json_depth`; `api: a call that gets no answer says why…`; `control: close waits for a call still waiting for its answer`; `control: the handshake has a deadline`; `control: close shuts a reconnect still in its handshake`; `data: the handshake has a deadline`; `data: close shuts a resume still in its handshake…`; `the download handshake has a deadline`; `control: a second response for the same id frees the first`. |
| 4. Splitter | D4, R12 | `rex1.zig` rewritten as a state machine (held candidate, pending ESC, body runs), no recursion or re-copying; a reference splitter in the tests; fuzz targets for the splitter (bytes and messages against the reference, the real prefix and bodies around the limit seeded), snapshot framing (moved to `wire.zig`) and WebSocket reassembly. | `an ESC inside a body that is not the terminator keeps its place in the output` (the reordering case); `the streaming splitter agrees with the reference on random streams` (1,500 seeded streams, whole, byte by byte, random chunks, every split point); `a body of exactly max_body is a message; one byte more is program output`; the three fuzz targets' corpus runs. An 8-minute coverage-guided fuzz run of all targets found nothing. |
| 5. Files | D9, D10, H8 | `xfer.zig`: `openParent` opens every folder from `/` without following links and checks it on the descriptor (root's or ours, not writable by others unless sticky); `readPrivateFile` opens with `O_NOFOLLOW` and reads from the descriptor it checked; `openUploadDir` makes the folder `0700` if missing, checks it the same way and keeps it open; uploads are created and removed relative to it. The socket folder must be ours. | `a private file is read only through a checked descriptor, in folders nobody else can change`; `the owner and mode rules, for owners a test cannot create`; `the upload folder is made private if missing, and must be a private folder of ours`; `server: an upload goes into the folder opened at startup, whatever replaces its path` (renamed away and replaced by a folder, then by a link); the socket-folder test extended. |
| 6. Authorize at use | D11, W5 | Upload tokens carry the viewer's id; `Hub.mayUpload` requires that viewer to exist, write and look at that terminal, checked when the upload arrives and again before the file is kept and its path pasted; tokens are withdrawn when the viewer turns read-only or leaves. `/api/tree` only with `--enable-lab`. | `hub: an upload token is good only while its viewer may write to that terminal`; `server: an upload token stops working once its page turns read-only or leaves the terminal` (404 after read-only, 403 after leaving, no file made); the lab-off 404 list. |
| 7. Front end | H3-H5, H9, H10, W3, W4 | Targets with bytes ≤ 0x20 or 0x7f get 400 before routing; the bare-prefix redirect runs after `access.decide` and percent-encodes the query; `--owner` needs `--allow-host`; `--token` follows the token-file rules; `--random-token` prints its address only to a terminal; transfer tokens use the boot clock; `Content-Disposition` cuts the encoded name at character boundaries (512-byte buffer); a cookie-setting response is `no-store`; vendored files are `no-cache` with their ETag; a transfer takes its running slot before its token. | `server: a target with a control byte or a space is refused before routing`; the cookie test (403 without a token, the redirect after the check, the query encoded); `An owner rule needs an allowed host, unless it comes from Tailscale`; `--token follows the token-file rules`; `contentDisposition holds a long name of multibyte characters…`; `server: a busy bridge does not use up a transfer token`. |
| 8. Page | W1, W2, W6, D2 | Every paste (both engines' paste events, `beforeinput` paste and drop, wterm's own paste method, the soft-keyboard path) goes through `sendPaste`: ESC and C1 removed, sent as `{t:'paste'}`; `?term=` for that load only; diagnostics need `mode.debug`; the Copy view renders the last 5,000 lines with a note; lab pages drop the token from the address and the stray wording. | Node: `cleanPaste`, `isPasteInput`, `pickTerm`, `debugOn`, `copyView` (22 tests). Chrome on macOS against a release build and real Rex: a pasted `echo pasted\x1b[201~; echo INJECTED` arrived as text without its ESC and did not run, in wterm and with `?term=xterm` (also without `\x9b`), and `?term=` was not saved. |
| 9. Docs and release | D3, H1, H2, H6, W7 | README and user guide: the macOS layout is for a Mac with no other local accounts; `/s/<id>/` is as private as the token, tokens come from the generator, history and rotation; checksums detect damage only; folder rules; new troubleshooting rows. `release.sh` states what it reproduces and refuses to overwrite a built version; `dist.sh` refuses an empty stage and removes the stage after packing. Architecture, file-transfer and changelog updated. | `tools/release-base.test.sh`; `zig build dist` twice gave the same archives and left no stage. |

## Checks run (macOS, Apple silicon, Zig 0.17.1)

- `zig build test`: 253 of 263 passed, 10 skipped (the live tests); twice more with no failure.
- With `REX_SOCKET` set to this Mac's Rex (its `llms.txt` describes API revision 18): 208 of 209 passed, 1 skipped; the live tests
  made and closed their own `rweb-test-` sessions, and the owner's sessions were untouched.
- `zig build fuzz` (corpus) passed; `zig build web-test`: 22 of 22; `tools/release-base.test.sh`: 4 passed, 1
  skipped (needs root).
- `zig build -Doptimize=ReleaseSafe`, then a test bridge on 127.0.0.1 with a random token file and uploads on,
  against a throwaway `rweb-test-r2` session: `/?token=` answered 303 to `/s/<id>/`; `/api/tree` 404 without
  the lab; a target with a control byte 400; in Chrome the page connected, a typed command round-tripped, and
  the paste checks above held; Mobile Safari in the iOS Simulator connected. The bridge log held no token.

## Done differently from the plan, and what is left

- Frame writes get their deadline from a watchdog task that shuts the socket, not `SO_SNDTIMEO`: Zig 0.17.1's
  socket write treats `EAGAIN` as a bug.
- `dist.sh` removes its stage after packing rather than before (the build puts the binaries there just before
  it runs); a stale stage left by an older checkout could still be packed once.
- Transport errors from `Api` still surface as `RexError` (with the error's name as the message), so the
  bridge's error handling is unchanged; only cancellation passes through.
- A redraw's frames are not counted against the live-output cap: only one is ever queued and its rows are
  capped, so counting it would only make a slow viewer redraw in a loop.
- Not tested: a stalled download (the watchdog is the same as for uploads); the soft-keyboard paste path on a
  real phone or simulator keyboard; a Serve deployment of this build from another device; Linux (the code
  compiles for Linux, the tests ran on macOS only).
- By decision: the macOS layout keeps its secret in Serve's target (documented); the tunnel token stays in a
  cookie and `<id>` stays a plain hash (documented); releases are not signed (needs the owner's key and tool);
  a local process can still churn connections on a TCP listener (denial of service only).
- Deployment note: rweb now refuses to start when a secret file, token file or upload folder sits under a
  folder another user can change. The layout setup-repo uses on laptop-mac passes; check each host when
  deploying.
