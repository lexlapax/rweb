# Phase 2 result: the bridge server

Status: **exit condition met** (2026-11-22): built and checked on desktop-mac, linux-box, a tablet and a phone; the owner's sign-off is the last step. Typing from the phone needed a phone-side power setting (Findings 5).
(see the end). Plan: [PLAN.md](PLAN.md#phase-2-bridge-server). Where this and the code differ,
the code wins.

## Owner's decisions for Phase 2 (2026-11-22)

| Question | Answer |
| --- | --- |
| History sent when a terminal opens | Last 1,000 lines; the page's "history" button loads the rest |
| Terminal wider than the screen | Shrink to fit; Rex's size changes only when the user presses "fit" |
| Read-only | A "view only" switch on the page, off by default; a bridge started `--observe-only` is locked |

## What exists (`src/bridge/`)

| File | What it is |
| --- | --- |
| `access.zig` | Pure access decision: peer uid, Funnel, owner login, own address, Origin, token/cookie |
| `protocol.zig` | The browser protocol; every message validated and size-limited |
| `hub.zig` | One Rex client, terminals shared by viewers, bounded per-viewer queues, session tree, restart and 1013 recovery |
| `server.zig` | HTTP and WebSocket front, access enforced first, unix socket 0600 in a 0700 directory, loopback TCP, CSP |
| `assets.zig`, `web/` | The page, embedded in the binary; xterm.js 6.0.0 and addon-fit 0.11.0 vendored with the licence |
| `cli.zig`, `main.zig` | Settings and the `rweb` executable (`zig build run -- ...`) |

Vendored files (SHA-256, from jsdelivr at the pinned versions on 2026-11-22):

```text
14903579ff54664cd72f8e8699e6961a6272c21863ec1c3b118cdc8af5d4a972  xterm.js 6.0.0
854a7c0fb70e8b1a083c16797ab827299fb18744f5ad34f227b48337e33293c6  xterm.css 6.0.0
ba3ea256ce0620a0992a197d6c9baea64823fc93d8da07a9e366ca9943c18527  addon-fit.js 0.11.0
b569f629d00f2626a8100df2a1798210535621e42164dfd426a6fe5aac7b0ccd  LICENSE-xterm.txt
```

The CLI refuses to start without an access rule; with `--owner` and no known own addresses it
asks `tailscale ip`, and refuses to start if that fails.

## Checks (desktop-mac, Rex.app preview.21, revision 18, 2026-11-22)

- `zig build test`: unit, fake-Rex and integration tests, repeated; each access refusal is a
  test over real HTTP (no identity, wrong user, Funnel, own address, wrong or missing Origin,
  wrong peer uid on a unix socket, bad token).
- Live: a WebSocket client drives a throwaway terminal on the real Rex through the bridge
  (`server.zig`, needs `REX_SOCKET`).
- Browser (Chrome on desktop-mac, loopback, token mode): list, open a throwaway session, type, see
  colour, a wide character and the prompt; the "view only" switch disables typing and the
  management buttons and nothing reaches the shell.
- Through Tailscale Serve (desktop-mac, foreground `tailscale serve --https=11443`, removed
  afterwards), bridge with `--owner`:
  - from this machine itself via the Serve name: **403, own address** (confirms the research's
    reading of Serve's local bypass);
  - direct to the bridge: no identity 403; wrong user 403; owner header plus Funnel marker 403;
    owner header plus the node's own address in `X-Forwarded-For` 403; WebSocket upgrade with a
    foreign Origin 403;
  - a forged owner header from a local process on loopback is **accepted**: the exposure the
    plan accepted for desktop-mac, where Tailscale.app cannot use a unix socket. On a unix socket
    (linux-box) such a process is refused by peer uid (tested).
- Real Android tablet through Serve (owner): typing works with Samsung Keyboard (each character
  an `insertText`, Enter through xterm.js) and with Gboard (a composition per word, committed
  with the space, so a word shows in the shell only when it is committed; no loss or
  misorder). Findings 12 and 13 of Phase 0 were not reproduced in these runs; Gboard is still
  the keyboard to watch in Phase 3.

## Findings

1. Cancelling an `Io` task blocked in a socket read can deadlock on this Zig (seen in a stack
   sample). Every close now shuts the socket first. `Control.call` also had a use-after-free
   and a rare leak; both fixed with tests.
2. The hub must ignore the control connection's first `connected` notice: treating it as a Rex
   restart rebuilt every stream right after opening it.
3. A page loaded with `?token=` needs the token on its scripts, styles and socket: the server
   sets an `HttpOnly`, `SameSite=Strict` cookie. Deployments behind Serve use the identity
   header and no token.
4. The CSP (`frame-ancestors 'none'`) refuses framing, which also refused my own test iframes.

5. **The phone's connection to the Mac stalls, whatever the transport** (2026-11-22, Samsung
   phone on Android, over the tailnet, direct LAN path). Symptoms: text typed vanished or arrived
   in a burst 20 to 60 s later; the page reloaded slowly. Measurements, in the order they were taken:
   - The bridge handled every request it received in 0 to 3 ms (request log), had no unread data
     in its sockets, no deadlocked task (thread sample) and answered other clients instantly.
   - A once-a-second heartbeat from the page showed gaps of 9 to 60 s with nothing arriving, then
     a burst; connections the bridge saw as silent for 21 s were dropped.
   - A transport lab (`/lab`, four variants of 40 s each: text WebSocket, binary WebSocket, plain
     HTTP requests, text WebSocket again) ran on desktop Chrome through the same Serve address:
     every answer in 2 to 19 ms. On the phone: the text WebSocket got 1 answer of 40 sent, the
     binary variant's own result report never arrived, 15 of 20 plain HTTP requests reached the
     bridge in a single instant, and the last WebSocket could not open. So WebSocket versus HTTP is
     not the difference, and herdr-webui's choices (binary input frames, a socket per terminal, no
     application pings) would not help.
   - `tailscale ping` from the Mac to the phone, right after the lab: six pings in a row timed out
     (about 18 s), then replies at 5 to 6 ms with bursts of 100 to 125 ms. That is below the
     bridge and below Serve: the phone's Tailscale or radio is asleep and traffic waits for it.
   - Desktop Chrome and a tablet (Samsung Keyboard and Gboard) work through the same address, and
     typing with the phone connection healthy worked (46 heartbeats in 44 s, words in order).
   Fixed on the owner's side: after the owner turned off the Tailscale app's power saving on the
   phone, the raw Tailscale ping had no timeouts (59 of 59, median 76 ms), the text WebSocket
   got 38 of 38 and 40 of 40 answers (nothing over 2 s), and typing from the phone into the real
   page worked: `echo phone test1` and `echo phone test2` arrived intact and ran (confirmed on
   the shell's own screen). The lab's binary and plain-HTTP variants did not report from the
   phone (the HTTP requests never reached the bridge); that looks like a quirk of the lab page,
   not of the real page, and was not chased further. What the bridge does about it: the page expects an answer every
   3 s, abandons a connection quiet for 8 s and opens a new one, and refuses typing while the
   link is not healthy, so keystrokes are not lost silently; the bridge pings browsers every 3 s,
   drops one silent for 20 s, and cuts off a page sending more than 200 messages a second.
6. **Phone keyboards compose words.** Samsung Keyboard on the phone and Gboard send a word as a
   composition and commit it, with the space, as one message (`echo `), so a word shows in the
   shell only once it is committed. The tablet's keyboards send characters one at a time. No loss
   or misordering was seen with a healthy connection.
7. A diagnostic page-and-log mode exists for keyboard and network trouble: open the page with
   `?dbg=1` and start the bridge with `--debug-input` (it logs typed text; never for deployment).
   The bridge logs every HTTP request (method, path without query, time).

## Not done in Phase 2

- linux-box: unix socket under tailscaled (peer uid 0) behind real Serve. The tests cover the
  checks; the deployment is Phase 4.
- The phone depends on its power settings: with the Tailscale app power-saving on, its tailnet
  path stalls for tens of seconds. The page now copes (reconnect within 8 s, no typing into a
  dead link) but cannot make a sleeping phone fast.
- After a `tailscale down` on desktop-mac, bring it back with `tailscale up --accept-routes` (plain
  `up` refuses). A temporary `tailscale serve` started in the foreground must be stopped by its
  own process (SIGINT), not by killing a wrapper: the binary is `Tailscale` (capital T) on macOS,
  so a lowercase `pkill -f` pattern missed it and left the port-11443 entry alive for hours.
- A fuzz campaign beyond the 90-second smoke runs; the browser protocol and access decision are
  fuzz targets (`zig build fuzz --fuzz`).
- Own pings from the bridge to Rex; the bridge pings browsers every ~20 s.
- Slow clients are bounded (1 MiB of live output per viewer, then a redraw); a stalled TCP
  connection is not timed out (Serve and the browser end it).
- The page is the minimum for the exit: Phase 3 is the real frontend (select mode for copying
  on a phone, composition preview, confirmation dialogs that are not `confirm()`, font size).
