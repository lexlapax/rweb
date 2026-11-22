# Phase 0 result: a live Rex terminal in a browser

Done on 2026-11-21 on linux-box. The Rex server restart and typing from a real phone were checked
on 2026-11-22 with the owner's approval. **The gate passes.** Route 1 from the plan (a libghostty-vt mirror
in the bridge, with VT redraws sent to xterm.js) shows a live Rex terminal correctly. Routes 2
and 3 were not needed; the plan said to stop at the first route that passes. The spike is in
[`spike/`](../spike/): throwaway code, not the base for Phase 1.

## Versions

| Part | Version |
| --- | --- |
| Rex server | `0.1.0-preview.22`, commit `a086db17`, built 2026-11-19 |
| Rex API | revision 19 negotiated (hello sent `api_revision` 19, `api_min_revision` 18) |
| Zig | 0.17.1 (`/usr/bin/zig`, installed through setup-repo) |
| libghostty-vt | Ghostty tag `vt-1.0.1`, Zig package hash `ghostty-1.4.1-dev-5UdBC4lkpgUYGLDYGJQcJoa9zOGZNB3qVMgMoS9CUH5O` |
| Snapshot format | `GHOSTSNP` version 1 |
| Browser terminal | xterm.js 6.0.0 and `@xterm/addon-fit` 0.11.0, from jsDelivr |
| Browser | Chrome 157, Linux x86_64, on linux-box; for the phone check, the owner's Android phone with Gboard (browser version not recorded) |

## What the spike does

1. Opens Rex's control WebSocket on the unix socket, sends the hello, creates a session named
   `rweb-test-<random>` with one shell, attaches, gets a `data.connect` ticket and opens the data
   WebSocket.
2. Collects stream bytes until `ghostty_vt.snapshot.decode` succeeds, takes the decoded terminal,
   replays the continuation, and from then on removes Rex's own `ESC _ rex1;<nonce>;<json> ESC \`
   messages and feeds the rest into the libghostty-vt terminal.
3. Serves a page on `127.0.0.1:7690`. Every request needs a random 128-bit token, and the
   WebSocket upgrade also checks `Origin`. A viewer that joins gets a size message, the theme,
   and a VT redraw from the mirror, then the live bytes.
4. On a Rex `resize` it resizes the mirror and sends every viewer a new redraw.
5. Destroys its session on exit.

To check correctness, the page sent its visible rows to the spike, and `spike/compare.py`
compared them row for row with `rex capture --format vt` for the same block. Every row of the
screen was compared, including blank ones. Unless noted otherwise, each check below ended with
`differing=0`.

## Checks

| Check | How | Result |
| --- | --- | --- |
| Snapshot decode | every run | 1,157-byte `GHOSTSNP` v1 snapshot for 80×24 decoded by libghostty-vt; the nonce-marked `resize` came straight after, as documented |
| Shell prompt, colours, wide, combining, emoji | `printf` with SGR colours, 日本, `e` + U+0301, U+1F642 | screen matches; code points identical in the browser and in Rex |
| No query replies from the browser | `printf '\e[c\e[5n\e[6n'` then four `read`s in zsh | with the swallowing handlers: one reply each (`?62;22c`, `0n`, `6;1R`), nothing extra |
| Negative control | same, with the handlers off (`swallow=0`) | xterm.js answered too: `[?1;2cnR` arrived at the prompt as typed text, with a wrong cursor report (`1;1`) |
| Full-screen program | `vim -u NONE -N -n`, typing, `:q!` | matches during and after |
| Viewer joining while the alternate screen is up | second tab opened during vim | **failed at first**: the main screen behind vim was lost. Fixed (see Findings); afterwards both tabs matched during vim and after `:q!`, with 40 lines of scrollback |
| Mouse | `set mouse=a`, click on a line | vim's ruler moved to the clicked cell (`2,17` in write mode, `1,5` in hybrid mode) |
| Resize | "Fit to window": `session.own_block` take, then `terminal.resize` | Rex went to 224×102 and sent `resize`; both tabs redrew and matched all 102 rows |
| Theme | `com.superlogical.terminal.set_theme` | Rex sent `theme`; both tabs applied it |
| Paste | `term.paste(...)` in write mode and in hybrid mode | bracketed paste; `echo pasted-$((6*7))` printed `pasted-42`; in vim the text went in at the cursor |
| Kitty keyboard protocol | probe program pushes `CSI > 1 u`, records Escape, Shift+Enter, `a` | write mode (xterm.js 6.0.0 encodes keys): `\x1b\ra`, legacy and ambiguous. Key mode (`client.key`, Rex encodes keys): `\x1b[27u\x1b[13;2ua`, correct |
| Reconnect | page closed its socket | back after 1.5 s (1 s retry delay), redraw matched |
| Large output | `seq 1 300000` (2.3 MB) | screen matches; a fresh join afterwards got a 774 KB redraw and kept 10,024 lines of scrollback |
| Throughput | timing in the data loop; a bare Python client on the same block | Rex delivered 3.1 MB in 0.3 s (about 10 MB/s). The mirror fed 62 KB in about 1.4 ms (about 45 MB/s) once Ghostty was built in the same mode as the spike |
| Program exit | `exit 3` | `child_exited` with `exit_code` 3, then the data connection closed with 4000 `block closed` |
| Rex server restart | `spike/restart_probe.py`: own test session, control and data connections open, `systemctl --user restart rex.service`; run twice | see finding 11. Rex was back in about 0.1–0.2 s; the test session came back with the same session and block IDs, a new shell and an empty screen; a new data stream worked |
| Typing from a real phone | spike behind a temporary foreground `tailscale serve --https=10443`, with `--origin` and `--ts-user` set; the owner typed, backspaced, used voice input and pressed Enter in both input modes | see finding 12. Ordinary typing and voice input reached the shell correctly in both modes. A space typed just before Enter went wrong in both. Copying text was not possible (finding 13). Screens were not dumped (Check was not tapped), so this rests on the input log, Rex's own capture and the owner's report |
| Access guards for the phone run | `curl` from linux-box | loopback with the token but no `Tailscale-User-Login`: 403. Through Serve without the token: 403. Through Serve with the token: 200 |
| Cleanup | every run | the spike destroyed its session; `rex ls` showed only the owner's session after each run |

## Not checked

- Data-connection resume and the 1013 `data reconnect required` path. They belong to Phase 1.

## Findings that change later phases

1. **`terminal.write` calls are not ordered.** Rex runs block methods concurrently: typing `echo`
   arrived as `ehco`. The bridge keeps one write in flight per terminal, queues everything typed
   meanwhile and sends it as one write when the response arrives. With that, about 100 typed
   characters went out in 58 writes, all in order. `client.key` and `block.event` are ordered
   methods and need no queue.
2. **Input path: hybrid.** Physical keys go to `client.key`, so Rex encodes them for the
   program's current keyboard mode, Kitty protocol included. Everything else xterm.js produces
   goes through the serialised `terminal.write`: mouse reports (xterm.js knows the mouse mode
   from the stream), pastes (it adds the bracketed-paste markers when the mode is on), and
   composed text from input methods or phone keyboards that have no usable physical key. Query
   replies are swallowed with CSI, DCS and OSC handlers.
3. **Redraw rules.** Use `TerminalFormatter` with `extra = .all` and `trim = false`. Without
   `trim = false` trailing blank rows are dropped and the viewer's screen sits one row off. When
   the alternate screen is active, draw the primary screen first with `ScreenFormatter`. The
   terminal state then switches the viewer to the alternate screen, saving the cursor the way
   the program did. Send a new redraw after every Rex `resize`, because xterm.js and Ghostty
   reflow differently. Start the redraw with RIS.
4. **Redraw size.** With full scrollback a redraw was 774 KB. Phase 2 should cap the scrollback
   sent on join, at least for phones.
5. **Build.** Pass `target` and `optimize` to the Ghostty dependency. Without them it builds as
   Debug, with integrity checks that made the mirror about 400 times slower (550 ms per 62 KB).
   libghostty-vt also compiles C++ (simdutf, highway) and links `libc++`. A static binary needs
   libc++ linked statically, which is a Phase 4 check. The ReleaseSafe spike binary is 15 MB.
6. **Viewers must not block the stream.** The spike writes to viewers while holding the mirror
   lock, so one slow viewer would stall every other viewer and the read from Rex. This was not
   observed (the slowness seen was the Debug build), but Phase 2's bounded per-viewer queues,
   written outside the mirror lock, are needed.
7. **Ownership.** After `session.own_block` take, Rex's `resize` message still carried
   `owner: null`. Phase 1 should check the ownership semantics against `block_owner_changed`.
8. **Libraries and I/O model.** Zig's `std.http.Server` (with its WebSocket support) served the
   page and the browser socket. Zig's standard library has no WebSocket client, so the spike has
   its own (about 190 lines) for Rex. `std.Io`'s default threaded implementation with
   `io.concurrent` tasks worked. No third-party Zig library was needed, and none is planned
   for Phase 1.
9. **Tests against the owner's Rex.** `rex capture` without `-b` reads the focused block of the
   default window, which is the owner's session, so tests always pass `-s` and `-b`. A crash
   before cleanup left one test session behind (closed with `rex session kill`), so Phase 1
   needs a cleanup step that closes `rweb-test-` sessions its run created. `rex block stream`
   is not implemented in preview.22.
10. **Frontend assets.** The spike loads xterm.js from jsDelivr. The bridge must embed it, with
    its MIT licence, and load nothing from a CDN.

11. **What a Rex server restart looks like to a client** (Rex preview.22, two runs on
    2026-11-22, owner-approved):
    - The control connection ends with no close frame (plain EOF). The data connection gets a
      close frame, 1001 `data provider canceled`.
    - `rex.socket` keeps the unix socket open, so the next connect succeeds at once; the new
      server answered the hello about 0.1–0.2 s after the old one stopped.
    - The old control `reconnect_token` gives a new client (new client ID, `resumed` absent), so
      every `session.attach` must be redone. A plain connection drop without a restart resumed
      the same client, as documented. `server.status` reports a new `instance_id`.
    - A data RESUME with the old token is refused with reason `0x01`. Get a new ticket and send a
      HELLO; the new stream starts with a fresh snapshot and a new channel nonce.
    - Sessions and blocks come back with the same IDs, and the session's view revision jumps
      (1 to 3,000,000,001, then to 4,000,000,001 on the second run). The programs do not: the
      shell is a new process and the screen and scrollback start empty. The owner's session came
      back the same way, with a new idle shell.
    - So the bridge treats a control EOF as a possible restart: reconnect with the token; if
      the client is new, re-attach, get new tickets, replace each mirror with the new snapshot,
      and send viewers a full redraw. Open terminals lose their contents, which the browser
      should say rather than show silently.

12. **Phone keyboard input** (Android, Gboard, 2026-11-22). Gboard sends every key as keyCode
    229 with `key` `Unidentified` and an empty `code` (68 of 72 keydowns), so both modes hand
    typing to xterm.js. Text arrives as compositions, and xterm.js sends each word once, when its
    composition ends (`echo`, `hello `, `world`). Voice input arrives as one composition per
    phrase. Backspace inside a composition stays in the keyboard and sends nothing. Nothing was
    doubled; the doubling seen with synthetic events on desktop did not happen on a real phone.
    Enter is a real key (keyCode 13), sometimes with `code` `Enter`. A space Gboard inserted just
    before Enter went wrong in both modes:
    - Hybrid mode: Enter went to `client.key` at once, and xterm.js sent the space through
      `terminal.write` 8 ms later, so the space reached the shell after the Enter.
    - Write mode: xterm.js never sent the space, and sent a DEL (0x7f) 10 ms after the Enter.
      At an empty shell prompt that does nothing; in an editor it would delete a character.

    So keys and text need one order. In the browser, while a soft keyboard is in use, Enter and
    Backspace go through xterm.js like the text before them. In the bridge, `client.key` waits
    for the `terminal.write` in flight. The stray DEL needs its own fix and a test in an editor.
13. **Copying on a phone.** Long-press brings up no selection handles in either mode; xterm.js
    has no touch selection. The frontend needs its own way to copy, such as a select mode that
    shows the screen and scrollback as plain text for the phone's own selection.

## Reproducing

```sh
cd spike
zig build -Doptimize=ReleaseSafe
./zig-out/bin/rweb-spike --port 7690 --capture /path/outside/the/repo/cap.bin
# open the printed URL; add &input=key for hybrid input, &swallow=0 for the negative control
# stop with: touch /path/outside/the/repo/cap.bin.stop
python3 compare.py SESSION BLOCK /path/outside/the/repo/cap.bin.screen.json
# phone: with the owner's approval, add --origin https://<host>:10443 --ts-user <owner login>,
# run `tailscale serve --https=10443 http://127.0.0.1:7690` in the foreground, stop it afterwards
# restarts rex.service: every program in every Rex session ends. Only with the owner's approval.
python3 -I restart_probe.py
```

Captured streams contain real terminal output and stay out of Git.
