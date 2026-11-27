# rweb architecture

How rweb is put together: where it runs, how a request is checked, how terminal output reaches the
browser and how input gets back to Rex. For setup see the [user guide](user-guide.md); for the reasons
behind each choice, the plan and the test records linked at the end (in the source repository).

## Where it runs

One rweb per machine that runs Rex. Each rweb serves only its own Rex, runs as the same user as Rex, and
talks to Rex only through Rex's own unix socket. It never listens on the network: Tailscale Serve or an
SSH tunnel brings the browser to it. Two commands set up the two ways in: `rweb tailscale` (a unix socket
on Linux, loopback behind a secret path on macOS, the owner taken from the machine's Tailscale login) and
`rweb ssh` (a unix socket only the same user can connect to, and a token). Each makes the files it needs
and prints the one step left; `layout.zig` holds their defaults.

```mermaid
flowchart LR
  subgraph Devices["Your devices"]
    P["Phone / tablet browser"]
    L["Laptop browser"]
  end
  subgraph M1["Machine A"]
    S1["Tailscale Serve<br/>https://a.tailnet.ts.net:12443"] --> W1["rweb"] --> R1["Rex server"]
  end
  subgraph M2["Machine B"]
    S2["Tailscale Serve<br/>https://b.tailnet.ts.net:12443"] --> W2["rweb"] --> R2["Rex server"]
  end
  P --> S1
  P --> S2
  L -- "or: ssh -L tunnel to a unix socket + token" --> W2
```

## Inside rweb

```mermaid
flowchart TB
  subgraph rweb["rweb (one process)"]
    SRV["server.zig<br/>HTTP + WebSocket front"]
    ACC["access.zig<br/>who may talk to rweb"]
    HUB["hub.zig<br/>session tree, open terminals, viewers"]
    PAGE["assets.zig + web/<br/>the page, built in"]
    XF["xfer.zig<br/>file transfer (optional)"]
    subgraph LIB["src/rex: Rex client library"]
      CTL["control.zig<br/>hello, calls, events, reconnect"]
      API["api.zig<br/>typed calls"]
      DATA["data.zig + rex1.zig<br/>one output stream per terminal"]
      MIR["mirror.zig<br/>libghostty-vt terminal per stream"]
      IN["input.zig<br/>one ordered input queue per terminal"]
    end
  end
  BR["Browser"] <--> SRV
  SRV --> ACC
  SRV --> PAGE
  SRV <--> HUB
  SRV --> XF
  HUB --> API --> CTL
  HUB --> DATA --> MIR
  HUB --> IN --> CTL
  CTL <--> REX["Rex control socket"]
  DATA <--> REX
```

- The **Rex client library** (`src/rex`) knows Rex's protocols and nothing about browsers. The **browser
  protocol** (`protocol.zig`) is rweb's own, so a change in Rex stays inside the library.
- rweb holds **one control connection** to Rex for calls and events, and **one data connection per
  terminal that at least one browser is viewing** (Rex allows one per client per terminal).
- The page (HTML, JavaScript, the browser terminals wterm and xterm.js) is **embedded in the binary**;
  nothing is loaded from elsewhere, and the vendored files are pinned by checksum.
- The library treats what Rex sends, and what programs print, as untrusted. It sets its own ceilings
  (at most 16 MiB per control message whatever Rex advertises, 64 KiB until the handshake is done, 1 MiB
  per data or download message; a reconnect token of at most 256 printable bytes; JSON nested at most
  64 deep; at most 64 pings a second), gives every handshake 10 seconds, writes each frame whole even
  when its task is cancelled but drops the connection if a write to Rex does not finish in time (the
  call's timeout, or 10 seconds), resumes a dropped data stream unless it keeps failing with nothing
  delivered, gives directory listings, downloads and terminal info 5 seconds instead of
  30, and checks after every connect that Rex's socket is served by this same user. It keeps Rex's events in a
  fixed ring (1,024 events, 4 MiB): on overflow the queued events collapse into one "dropped" notice,
  which makes the hub re-read the tree, and connection notices are never lost. Rex's own messages inside
  a terminal's output (`rex1`) are split off by a small state machine that keeps every other byte in
  order and hands contiguous output on in one piece; a resize must be 1 to 4,096 cells on each side and
  at most 1,048,576 cells, or it is ignored. A stream that breaks the protocol ends (and is reopened)
  instead of resuming the same bad message forever.
  A mirror that fails (a bad snapshot, out of memory) reports it as the stream's end, and the hub opens
  a new stream, as it does when Rex asks for one.
- The mirror is a renderer, not a full terminal, and keeps what a program can make it hold small: kitty
  graphics and the glyph protocol are off (their bytes are not even buffered), unknown OSC and APC strings
  are dropped, OSC and DCS strings are kept to 64 KiB, scrollback to 10,000 rows and 32 MiB (or Rex's own
  smaller limits), a snapshot to 256 MiB and 1,048,576 cells. A redraw is formatted within 16 MiB, carrying
  less history when it would not fit (the screen alone at worst); Copy text is formatted within eight times
  its 1 MiB limit. The bounds and where they are set are listed at the top of `src/rex/mirror.zig`.

## A request, from the browser to rweb

```mermaid
flowchart TB
  A["Request arrives"] --> U{"Unix socket?"}
  U -- yes --> PEER{"Peer is an allowed user?<br/>(root, which is tailscaled;<br/>rweb ssh: your own user)"}
  PEER -- no --> X1["Refused at accept"]
  U -- "no (loopback)" --> SEC{"Secret first path segment<br/>or token, as configured?"}
  SEC -- no --> X2["404 / 403"]
  PEER -- yes --> H
  SEC -- yes --> H{"Funnel header?<br/>Duplicate identity headers?"}
  H -- yes --> X3["403"]
  H -- no --> O{"Owner rule:<br/>Tailscale-User-Login is you?<br/>not from this machine's own address?"}
  O -- no --> X4["403"]
  O -- yes --> HOST{"Host is this machine's name?"}
  HOST -- no --> X5["403"]
  HOST -- yes --> WS{"WebSocket upgrade?"}
  WS -- "yes: Origin must match the host" --> OK["Served"]
  WS -- no --> OK
```

Every check is a pure function in `access.zig`, so each refusal has a test that shows it refusing. Behind
Tailscale on Linux the unix socket is in a `0700` directory and accepts only root; on macOS the loopback
listener answers anything without the secret with a bare 404.

With an SSH tunnel (`rweb ssh`) the socket accepts only the user rweb runs as, which is what SSH's forward
connects as, and the token rule replaces the owner rule. A page load of `/` that carries no token gets
the token form (`login.html`, `login.js`, `login.css`: static files with nothing from rweb in them), after
every check but the token's; nothing else is served without the token. The form sends the token once in a
`rweb-token` request header, and rweb answers with a redirect to `/s/<id>/`, where `<id>` is a hash of the
token (`/?token=` in the address gets the same redirect, for compatibility). `<id>` does not show the
token, but anyone who sees it can check guesses of the token against it, so tokens are random (rweb makes
them: 32 random bytes) and at least 32 URL-safe characters, and the address is kept as private as the
token. The token moves into an `HttpOnly`, `SameSite=Strict` cookie scoped to that path. A browser sends
a host's cookies to every port of that host, so a cookie for `/` on `127.0.0.1` would reach any other
local web service you open, and two tunnels on two ports would overwrite each other's; scoped to its own
unguessable path it reaches neither. The page uses relative addresses only, so it works under `/s/<id>/`
and, behind Serve, at `/`.

Wrong tokens are limited to 10 a minute for the whole listener; past that, wrong tokens get 429 until the
minute ends, so a token cannot be guessed online at any useful rate. In token mode the page does not
reconnect by itself after a drop: it shows "Disconnected" and makes one attempt per tap, so its cookie is
not sent to whatever holds the port unless the person asks. This is a limit, not a cure: the tunnel's
local end is plain HTTP on loopback, which cannot prove who is answering, so a program that holds the
forwarded port while the tunnel is down receives the cookie on a reload and could show a look-alike
form. The user guide says to use the tunnel only on devices nobody else uses.

**The listener comes first.** At startup rweb checks its configuration, then takes its socket or port and
keeps it while it waits for Tailscale (its login, name and addresses) and for Rex, asking again with a
growing delay instead of exiting. So the socket or port is never free for another account to take during
an outage. Connections wait in the listen queue; no request is read before the access rules are complete
and Rex has answered. A loopback port is held on `127.0.0.1` and on `[::1]`, without `SO_REUSEPORT`, so
`localhost` cannot lead to another account's listener. While rweb runs it asks Tailscale for the
machine's own addresses again every minute (every 15 seconds after a failed try), so the rule that
refuses requests from the machine itself follows a changed address. Each try has ten seconds in all;
`tailscale` and its process group are killed past that (`proc.zig`). If no try has succeeded for two and a half minutes (on the boot clock, which keeps counting while the machine sleeps; after a wake the refresh runs within a few seconds), the list may be out
of date, and rweb refuses requests until Tailscale answers again; this is judged at each request, so it
holds even if the asking itself were stuck. A change of address is seen within about a minute; already-open WebSocket connections are judged at upgrade time rather than cut mid-connection.

Before a request is read, it holds one of a few pending slots. When they are all taken, the oldest
connection that has not sent a request yet is dropped for the new one: idle connections from a local
process cannot keep the owner out, while Serve, which sends its request at once, gets through.

A request whose target holds a control byte or a space is refused before anything else looks at it, and
every redirect is built only from what rweb knows plus a percent-encoded query, after the access check.
The responses that set the token cookie are never cached (`no-store`); the page's own files and the
vendored scripts are revalidated on every load (`no-cache` with an ETag), so an upgrade reaches the
browser at once. `/api/tree` and the lab pages exist only with `--enable-lab`.

Secret files (the backend secret, the token file), the upload folder, the unix socket's folder and the
`tailscale` program are trusted only through an open descriptor. The path is walked from `/`: every
folder on it must be root's or yours and not writable by others (unless sticky, as `/tmp` is) or by its
group, with no access-control entry that lets another user or a group change it. No group is trusted,
because who is in a group cannot be known for certain; the one exception is macOS's root-equivalent
`admin`, and only for folders above an item and for programs. A link on the path is followed only when
root or you own it and the folder it sits in has already passed, and the walk goes on from its target.
Every folder and the item must be on a local disk: a network filesystem, FUSE, a disk image, a mount a
user made, a volume that ignores ownership and a filesystem rweb does not know are all refused, because
there someone else decides who owns and reads the files. The item itself is opened without following a
link and checked on that descriptor: a secret must be a regular file of yours closed to group and others,
with no access-control entry for anyone else, and is read from the descriptor that was checked. The two
commands make a missing secret or token themselves (created exclusively, mode `0600`, in folders made
`0700` under folders that passed). The upload folder is created only once the folders above it pass,
stays open for the life of the process, and files are created relative to it; the path pasted is its
real path. The unix socket's folder stays open too: stale sockets are inspected and removed relative to
it, and at shutdown the socket is removed only if the entry is still the one rweb bound. `tailscale`
comes from `--tailscale` or the first of a fixed list of install locations that exists, never from
`PATH`; it is opened inside its checked folder and run by exactly that path, and a refusal is final (the
next location is not tried). Each refusal is reported as a plain sentence with the fix (`xfer.zig`,
`explain`).

A browser connection that goes quiet for 20 seconds (unless rweb is still working on its last request),
or whose socket does not take a frame within 30 seconds, is dropped, so a phone that stopped reading
cannot hold a slot, a viewer or a stream. At most 32 browsers are connected at once, so ordinary
requests always find one of the 64 connection slots. A page may send at most 200 messages in any one
second; of those, at most 16 reads (terminal info, the clipboard, the tree) and 8 pieces of work
(opening or sizing a terminal, redraws, Copy, transfers, terminal actions, management). Opening,
redraws and Copy also share a budget of 32 a second across all browsers, because they run under a
terminal's lock. A refused request names itself; a refused open also leaves the terminal that was
open, and the page types only into the terminal it shows.

## Opening a terminal

```mermaid
sequenceDiagram
  participant B as Browser
  participant H as rweb hub
  participant M as Mirror (libghostty-vt)
  participant R as Rex
  B->>H: open {session, terminal}
  alt first viewer of this terminal
    H->>R: data.connect (ticket), stream HELLO
    R-->>M: snapshot (Ghostty format), then live output
  end
  H->>M: redraw: reset, scrollback (last 1,000 lines), screen, modes
  M-->>B: redraw (binary frame)
  loop while viewing
    R-->>M: output (rex1 messages split off: resize, theme, exit)
    M-->>B: same bytes, through a bounded per-viewer queue
  end
  R-->>H: resize
  H-->>B: fresh redraw for every viewer
```

- The mirror decodes Rex's snapshot into a libghostty-vt terminal and keeps feeding it the live output,
  so any browser can join at any time and get an exact redraw. Reconnecting is the same: a fresh redraw,
  no byte-exact resume.
- A redraw is a terminal reset followed by libghostty-vt's formatter output with every extra (colours,
  modes, cursor); while a full-screen program is up, the main screen is drawn first.
- Each viewer has a bounded send queue. A viewer that falls behind loses its queued output and gets a
  fresh redraw, so a slow phone never holds up the others or the read from Rex. The bound covers every
  frame: live output (1 MiB, then a redraw, at most one a second; output joins the last unsent frame
  up to 64 KiB, and each frame counts 64 bytes extra, so tiny pieces cannot pile up), at most one
  redraw (its scrollback capped at 10,000 rows and 1,000,000 cells, chosen before anything is
  formatted; "all scrollback" applies to one redraw), replies (256 frames, 8 MiB, then dropped; one Copy
  at a time, refused before any work while one is queued), and state frames (mode, Rex up or down,
  theme, tree), of which at most one each is queued and the newest wins; a tree is sent only when it is
  newer than the one the browser has. `closed` and `exited` always get through. The Copy view's text is
  built from at most the last 20,000 rows, 2,000,000 cells and 1 MiB.
- A terminal lives while anything refers to it: each viewer looking at it, and each task using it for a
  moment (a typed key, a redraw, the Copy view, a stream restart). Closing it (its block went away) takes
  it out of the list and detaches its viewers at once; the last reference destroys it. The hub's main
  lock is never held while waiting on Rex: attaching, opening a stream, waiting for its snapshot and
  restarting a stream all happen outside it, so one slow terminal cannot stall the others. Nor does any
  other lock wrap a call to Rex: each request calls through its own client value, and the connection
  matches answers to calls, so a call Rex is slow to answer holds up only the browser that made it.
- The hub's supervisor (Rex's events, stream restarts, tree reads) sleeps until Rex sends an event or
  something wakes it (a stream ended, the tree changed), or until its next deadline (a restart's backoff,
  the 150 ms gap between tree reads); it does not poll.
- The mirror never answers terminal queries: Rex's own terminal already answered the program, and the
  page drops any reply the browser terminal produces.

## Input, from the browser to Rex

```mermaid
flowchart LR
  K["Physical key<br/>or key bar"] -- "key {…}" --> Q
  T["Typed text, phone keyboard,<br/>voice, paste, mouse, wheel"] -- "in / paste" --> Q
  Q["input.zig<br/>one ordered queue per terminal,<br/>one call in flight"] -- "client.key" --> R["Rex"]
  Q -- "terminal.write" --> R
```

Keys go to Rex's `client.key`, so Rex encodes them for whatever keyboard mode the program uses. Text,
pastes and mouse reports go to `terminal.write`. Rex runs writes concurrently, so rweb keeps one call in
flight per terminal and queues the rest in order. On a phone a drag over a full-screen program becomes
mouse-wheel reports (or ↑/↓ keys if the program did not ask for the mouse).

## The browser protocol

WebSocket at `/ws`. JSON text frames carry commands and notices; binary frames carry terminal output.
Browser to rweb: `tree`, `open`, `close_view`, `in`, `key`, `paste`, `fit`, `redraw`, `more_history`,
`text`, `info`, `clip`, `observe`, `new_session`, `new_terminal`, `rename_session`, `rename_block`,
`close_block`, `destroy_session`, `term_action`, transfer requests, `ping`. rweb to browser: `tree`,
`opened`, `size`, `theme`, `exited`, `closed`, `mode`, `info`, `notice`, `error`, `pong`. Every message
is bounded and validated; the full list is at the top of `src/bridge/protocol.zig`.

## Source layout

| Path | What it is |
| --- | --- |
| `src/rex/` | Rex client library: `ws.zig` (WebSocket over a unix socket), `control.zig` (hello, revisions, calls, events, reconnect), `api.zig` (typed calls), `data.zig` and `rex1.zig` (output streams), `mirror.zig` (libghostty-vt terminal), `input.zig` (ordered input), `transfer.zig` (downloads), `wire.zig` (handshake parsers), `fake.zig` (a fake Rex for tests) |
| `src/bridge/` | The program: `main.zig` (start-up, `--version`), `cli.zig` (commands and options), `layout.zig` (the two commands' defaults, the files they make, the next step they print), `access.zig` (who may talk to it), `server.zig` (HTTP and WebSocket), `protocol.zig` (browser protocol), `hub.zig` (sessions, terminals, viewers), `xfer.zig` (file transfer, and the checks and explanations for files and folders), `proc.zig` (bounded child-process runner for `tailscale`), `assets.zig` (embedded page) |
| `src/bridge/web/` | The page: `index.html`, `app.js`, `app.css`, `keys.js` (pure key and touch logic, tested with Node), `wterm-shim.js`, `diag.js`, `manifest.webmanifest`; `login.html`, `login.js`, `login.css` (the token form); `icons/` holds the favicons and app icons; `vendor/` holds xterm.js and wterm with their licences and checksums |
| `src/fuzz.zig` | Fuzz targets for every parser that reads outside bytes (`zig build fuzz --fuzz`) |
| `tests/web/` | Tests for the page's logic (`zig build web-test`) |
| `assets/logo/` | The logo's SVG sources, the social preview and `build.sh`, which exports the rasters (the page's icons are in `src/bridge/web/icons/`) |
| `tools/` | `dist.sh` and `release.sh` (release archives; `release-base.test.sh` checks its folder rules), `notices.py` (third-party notices) |

## Pinned dependencies

| | Pin | Why it matters |
| --- | --- | --- |
| Zig | 0.17.1 | Builds everything, including Ghostty's C++ |
| libghostty-vt | Ghostty tag `vt-1.0.1` (by hash in `build.zig.zon`) | Decodes Rex's snapshot format; rweb refuses an unknown snapshot version |
| Rex API | revisions 18–19 | Rex refuses clients outside its supported range |
| wterm, xterm.js | 0.6.0, 6.0.0 (checksums in `vendor/SHA256SUMS`, checked by a test) | The browser terminals |

## Further reading (in the source repository)

- [PLAN.md](PLAN.md): goal, decisions, constraints, phases.
- [phase0-result.md](phase0-result.md): the proof that a browser can show a live Rex terminal correctly.
- [design-research.md](design-research.md), [rex-web-research.md](rex-web-research.md): the evidence behind the design.
- [security-hardening-2026-11-23.md](security-hardening-2026-11-23.md): the security review and fixes.
- [file-transfer.md](file-transfer.md): file transfer design and limits.
