# Design research before Phase 0

Done on 2026-11-21 to check [PLAN.md](PLAN.md) before implementation. Nothing was connected to
Rex's data stream, built or installed; findings come from Rex's own protocol document, the
owner's `setup-repo` records and upstream source and documentation. Items marked *read, not
tested* come from reading code and need a test before they are relied on.

Rex on linux-box: `0.1.0-preview.22`, commit `a086db17`, built 2026-11-19, API revision 19
(supports 0 to 19), protocol document 343,674 bytes, unchanged from the original research.

## 1. Rex protocol details the plan did not account for

From `llms.txt` (revision 19):

- **One data connection per client per block.** REJECT `0x02`: "This client already has a
  connection to the same data source of that block, and a client can have only one at a time."
  Several browser viewers of one terminal need either one Rex client each, or one bridge stream
  fanned out to all of them.
- **The server bounds buffering itself.** A data connection that falls behind is closed with
  1013 `data reconnect required` ("more output piled up while the client was away than the server
  could keep"). The bridge never has to buffer without limit: when a viewer falls behind, drop it
  to a fresh snapshot.
- **Resume needs an exact byte count** and lasts 60 seconds, for control and data. The fragile
  link is phone to bridge, not bridge to Rex, so resume between bridge and Rex covers only local
  hiccups; a browser reconnect is simplest as a fresh redraw.
- **Size follows the owner.** `terminal.resize` applies at once only if the caller owns the
  block or nobody does; `own_block` `take` or `request` sets the owner; "owning a block gives no
  other rights over it". A browser must draw the terminal at Rex's size (from the stream's
  `resize` messages), not at its own viewport size, unless the user chooses to take ownership.
- **Input.** `terminal.write` takes a UTF-8 string (raw bytes above 0x7F that are not UTF-8,
  such as X10 mouse reports, cannot be sent); `client.key` takes W3C `KeyboardEvent.code` keys,
  gives Rex's Lua bindings the first chance, and lets Rex's server-side Ghostty encode keys for
  the program's current keyboard mode (including the Kitty protocol); `block.event` carries key,
  paste, mouse, wheel and focus.
- **Rex messages in the stream:** `resize` (always right after the snapshot), `theme` (default
  colours and palette changes), `child_exited`. Unknown types are skipped.
- **Control connections** need a hello within 5 s, under 512 bytes and uncompressed; the server
  pings every 120 s; an event backlog over 8 MiB closes the connection; results over 1 MiB fail
  with `too_large` (`format` supports `max_bytes` plus `blob_read`).

## 2. The opening snapshot is binary

Rex's stream opens with Ghostty's binary snapshot format, not VT: a 10-byte header (`GHOSTSNP`
then a 16-bit version, currently 1) followed by tagged records with CRCs, covering screen,
scrollback, cursor, modes, size and Kitty graphics. xterm.js and other generic emulators cannot
read it.

- libghostty-vt has a public C API for it (`include/ghostty/vt/snapshot.h`: encoder and a
  streaming decoder that restores a terminal). The header says the byte format "is versioned
  separately from the library and isn't covered by the ABI promise", so the decoder must match
  the snapshot version Rex sends.
- libghostty-vt also has a formatter (`formatter.h`) that emits text, HTML or VT; "VT output is
  meant to be written to another terminal to recreate the screen". Rex's
  `com.superlogical.terminal.format` with `vt` and the `extra_*` options is this formatter. It
  redraws the active screen only.
- A terminal created without the `WRITE_PTY` callback does not answer queries, so a server-side
  mirror stays silent.
- libghostty-vt 1.0.0 was tagged around 2026-11-06 and 1.0.1 around 2026-11-11; MIT; stable C
  ABI from 1.0. It is built with Zig; WebAssembly is a supported target but no prebuilt `.wasm`
  is published.
- Rust bindings (moot since the bridge moved to Zig): `libghostty-vt` / `libghostty-vt-sys` 0.2.2 (2026-09-28, MIT OR Apache-2.0).
  The release has the formatter but no snapshot module; `snapshot.rs` is on the repository's main
  branch only. Handles are `!Send` and `!Sync`.

Sources: <https://github.com/ghostty-org/ghostty/blob/main/src/terminal/snapshot/envelope.zig>,
<https://github.com/ghostty-org/ghostty/blob/main/include/ghostty/vt/snapshot.h>,
<https://github.com/ghostty-org/ghostty/pull/14801>, <https://libghostty.tip.ghostty.org/>,
<https://github.com/uzaaft/libghostty-rs>, <https://docs.rs/crate/libghostty-vt/latest>.

## 3. Browser terminals

- **xterm.js** 6.0.0 (2025-12-22); 6.1 betas add Kitty keyboard (`vtExtensions.kittyKeyboard`,
  off by default). It answers queries (DA1/2/3, XTVERSION, DECRQM, DSR 5/6, `CSI 18 t`, DECRQSS,
  OSC 4/10/11/12 `?`, Kitty `CSI ? u`) through `onData`, the same event as keystrokes; there is
  no option to suppress replies only. Rex's server-side terminal already answers those queries,
  so a browser view that forwards `onData` would send duplicate replies as typed input. Two
  fixes: register CSI/DCS/OSC handlers that swallow the queries, or set `disableStdin: true` and
  send input by another path (which also blocks xterm.js's own paste and mouse output). Source:
  <https://github.com/xtermjs/xterm.js/blob/master/src/common/services/CoreService.ts>.
- **coder/ghostty-web** 0.4.0 (stable 2025-12-09; `next` 0.4.0-next.25, 2026-11-18): MIT,
  xterm.js-compatible API over a patched older Ghostty, mobile support merged, cannot load
  `GHOSTSNP`; suppressing query replies is an open PR (#165).
- **gkoreli/ghostty-vt-js** 0.6.0 (2026-11-06): MIT, one maintainer, unpatched Ghostty C ABI,
  WebGL2/Canvas; merged PR #1 adds `restoreTerminal(bytes)` written for Rex's
  `rex.data.terminal.v1` stream. Very young.
- Ovis uses xterm.js with a libghostty-vt WebAssembly overlay, and the owner has used it from
  Android for typing and paste (setup-repo Ovis rollout records).
- No existing project serves a remote Rex or libghostty terminal to a browser from server-held
  state. zmx (PR 138) sends `GHOSTSNP` on attach, but to native terminal clients.

## 4. Tailscale Serve identity

- Serve adds `Tailscale-User-Login`, `Tailscale-User-Name`, `Tailscale-User-Profile-Pic` and
  `Tailscale-Headers-Info` for traffic from user-owned nodes (none for tagged nodes; Funnel gets
  only `Tailscale-Funnel-Request: ?1`), strips client-supplied copies, and overwrites
  `X-Forwarded-For`, `X-Forwarded-Host` and `X-Forwarded-Proto`. Its documentation warns that a
  loopback backend can be forged by "other services running on the Serve device".
- **Local bypass (read, not tested).** Serve also listens on the node's own tailnet addresses so
  the machine can reach itself, and WhoIs maps that address to the node's owner, so a local
  process of any user requesting `https://<host>.ts.net` would carry the owner's identity. Such a
  request shows one of the node's own Tailscale addresses in `X-Forwarded-For`. This applies to
  any Serve-fronted app on these machines, Ovis included.
- **Unix socket backend:** `tailscale serve ... unix:/path` since v1.94.0; since v1.98.9 setting
  it requires root. tailscaled dials as root, so a 0600 socket owned by the user works and other
  users cannot reach it. `Host` arrives as `localhost` for unix backends; compare `Origin` with
  `X-Forwarded-Host`. **The macOS App Store and Standalone Tailscale apps cannot use it** (the
  sandbox resets the connection; issue #21900). Linux-box runs 1.104.7; desktop-mac runs
  Tailscale.app.
- WebSockets pass through Serve (HTTP/1.1 upgrade, no timeouts set, `Origin` unchanged); an
  open issue (#18827) reports drops every 10 to 40 seconds on 1.94.2, so ping and reconnect.
- Rust has `tailscale-localapi` 0.6.0 for whois; in Zig, whois is an HTTP call over tailscaled's
  socket that the bridge makes itself, if it is used.

Sources: <https://tailscale.com/docs/features/tailscale-serve.md>,
<https://github.com/tailscale/tailscale/blob/main/ipn/ipnlocal/serve.go>, tailscale PRs #18089,
#19977, #20378, #21999 and issues #21900, #18827.

## 5. The machines

From the owner's `setup-repo` repository:

- **linux-box, gateway-box:** Rex from the signed pacman `preview` channel, a systemd user server
  started at boot (`rex server install`, linger on). Package upgrades restart the Rex server, so
  the bridge must survive the socket disappearing and coming back.
- **desktop-mac:** Rex.app, updated by Sparkle outside setup-repo, at `0.1.0-preview.21` on
  2026-11-20 (a different API revision from linux-box). macOS has no boot-time Rex server; one
  starts with Rex.app or on the first `ssh://` client. FileVault needs a disk unlock after reboot.
- **Tailscale Serve:** other services already use some HTTPS ports on both machines, so rweb takes a
  port of its own. Linux Serve changes are run by the operator with `sudo`.
- Remote Rex.app clients reach linux-box over `ssh://`, so a browser and a desktop client can
  both be attached to one block, and the desktop client may own it.
