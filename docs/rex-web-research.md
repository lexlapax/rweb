# Rex in a web browser: research and recommendation

Researched on 2026-11-21. This is a copy of the research that led to this project, taken from
the owner's research knowledge base (`notes/agents/rex-in-ovis-web.md` and its run folder
there). It is a snapshot: Rex is a preview and Ovis moves fast, so re-check versions before
relying on a detail.

Question: what would it take to add Rex sessions to the Ovis / Herdr web UI over WebSockets,
for example in a fork of Ovis?

Citations such as [C10] refer to the claims in Appendix A; each claim names its sources, which
are listed in Appendices A to C.

Rex's own protocol document is the primary reference for building a client. On a machine with
a running Rex server, read it with:

```sh
curl --unix-socket "$XDG_RUNTIME_DIR/rex/server.sock" http://localhost/llms.txt
```

**Answer:** Rex does not need a WebSocket layer added: its server already speaks one, documented
for third-party clients, with a live terminal byte stream. [C10] [C11] The work is on the client
side, and it comes in two sizes. A terminal-only bridge is small. Making Rex a backend of an
Ovis fork is large: Ovis's whole data model is Herdr's, its one existing second backend took
about 5,800 lines written by its own maintainer, and upstream changes about fifty commits a day.
[C3] [C4] [C6] Recommended order: first a one-or-two-day spike that proves a Rex terminal renders
in a browser; then decide between a small standalone page and an Ovis fork. Do not start with
the fork.

**Confidence:** medium. The facts about both products come from their own source and protocol
document, but nothing was connected or run: whether a browser can display Rex's stream, which
every design depends on, is untested.

## Detail

### What each side gives you

- **Ovis** sends raw terminal bytes to the browser over one WebSocket, and the browser parses
  them with xterm.js plus a libghostty-vt WebAssembly layer. [C1] On the server it never reads a
  pane itself: it runs the multiplexer's own attach command on a PTY. [C2] It has no generic
  "run this command in a tab" mode. [C2]
- **Ovis already has a second backend.** herdr-core was added as an adapter that answers
  Herdr's socket API, so the rest of the server does not know the difference, plus a capability
  record with a `pty-cli` attach mode. [C4] A backend must answer a session snapshot, pane and
  agent lookups, process info, read, send, and an event stream; Ovis can keep workspaces, tabs
  and splits itself. [C5]
- **Rex** serves a control WebSocket and a data WebSocket on every listener, including the unix
  socket, and tells third parties to write clients against them. [C10] Output is a resumable
  binary stream; input, resize and ownership are control calls. [C11] It also lists sessions,
  windows, blocks and layout, and reports each terminal's processes and directory, which is the
  kind of data Ovis's agent views need. [C19]

### The obstacle common to every design

Rex's stream does not start as plain terminal output. It opens with a snapshot in Ghostty's own
format, "meant for terminal emulators built on Ghostty", followed by a marked `resize` message
and then the program's output. [C12] Two ways around it, neither tested:

1. Read the snapshot with libghostty in the browser. libghostty is MIT-licensed and Ovis
   already ships a libghostty-vt WebAssembly build. [C20] Whether that build can load this
   snapshot is unknown.
2. Skip the snapshot up to the first marked `resize`, paint the screen from
   `terminal.format` in VT form instead, then pass the live output through and strip Rex's
   marked messages. [C12] [C13] This would feed any emulator, xterm.js included, at the cost of
   a possible mismatch between the painted screen and the first live bytes.

The Linux `rex` CLI has no command that attaches a session inside a terminal, so Ovis's
existing "run the attach CLI on a PTY" path has nothing to run today. [C18] A small attach
program doing step 2 would fill that gap, and it is the same program whichever design follows.

### Designs

| Design | What it is | What you get | Cost and risk |
| --- | --- | --- | --- |
| A. Attach shim + small page | A program that speaks Rex's two WebSockets on the unix socket and emits plain terminal bytes; a minimal page with a browser terminal, served on the tailnet | One Rex terminal per tab in a browser, session list | Smallest. Own auth needed, because Rex trusts only the transport. [C14] |
| B. Browser straight to Rex | A static page that opens Rex's WebSockets on a `tailnet` or `tailnet-serve` listener, with `--websocket-origin-pattern` | Same as A with no bridge process; identity from Tailscale | Needs workaround 1 or 2 inside the browser; exposes the full Rex API to that page. [C14] |
| C. Rex backend in an Ovis fork | An adapter that answers Herdr's API from Rex, plus the shim from A as the `pty-cli` attach | Ovis's dashboard, mobile UI, agent chat views and pairing, on Rex | Largest. See below. |
| D. Wait | Rex's protocol already names `web` as a client platform [C10] | Vendor client, if it comes | No date; no web client is listed today. [C17] |

### Why C is expensive

- Herdr's types are the app's data model end to end, and about 70 server files import the
  Herdr client. [C3] The adapter approach hides this, but herdr-core still needed about 5,800
  lines and 14 test files. [C4]
- Ovis is large and moves fast under one maintainer, so a fork must rebase constantly or freeze
  at a version. [C6] [C7]
- Rex is a preview: its API revision changed within a day of this research. Old revisions stay
  accepted, which helps a pinned client. [C15]
- Upstream has an unexplained third runtime slot, `alt-runtime`, that cannot start yet. [C8]
  Nobody has proposed a non-Herdr backend upstream. [C9] Asking the maintainer what the slot is
  for costs one issue and could change the plan.
- Rex is a proprietary binary with no licence text found; the protocol document invites
  third-party clients, but no terms were read. [C16] [C10]

Effort, as an estimate with no measurement behind it: the spike one to two days; design A or B
about a week to something usable daily; design C several weeks to reach what herdr-core has,
then ongoing merge work.

### Fit with the machines

All three hosts already run a Rex server on a unix socket, and Ovis behind Tailscale Serve.
Design A keeps that shape: the bridge runs as the user next to the socket, bound to loopback,
with Tailscale Serve in front, as Ovis is today. Design B needs Rex's own tailnet listener,
which is off on these machines.

## Disagreements

None between sources. The two researchers read different products.

## Open questions

- Can a browser render Rex's stream: does a WebAssembly libghostty load the Ghostty snapshot,
  and does the skip-and-repaint workaround hold up? Not tested; attaching was outside the
  read-only limit of this run.
- What Rex allows a browser by default on its WebSocket origin check, and whether it can serve
  static pages itself.
- What Ovis's `alt-runtime` is, and whether upstream would take an outside backend.
- Rex's licence terms for third-party clients, and whether Superlogical plans a web client.
  The changelog and roadmap are behind the beta Discord.
- How Ovis's relay, remote-PC, push and native-app layers behave on a non-Herdr backend.

## Appendix A: verified claims

- C1 [high] {S1.1, S1.4, S1.8} Ovis is a Bun server and React client; the browser gets a pane's raw terminal bytes as `pty-data` frames on one `/ws` WebSocket and parses them itself with xterm.js plus a libghostty-vt WebAssembly layer.
- C2 [high] {S1.6, S1.7, S1.15} For every pane Ovis runs the multiplexer's own attach command (`herdr terminal attach <id>`) on a PTY through a small Rust sidecar; it has no plain-shell tab or other arbitrary-command terminal.
- C3 [high] {S1.5, S1.15} Ovis reaches Herdr through one RPC client of about 38 methods, but about 70 server files import it and Herdr's generated types are the data model of the whole app, browser included.
- C4 [high] {S1.3, S1.4} Ovis 0.5.3 already serves a second backend (herdr-core) through an adapter that answers Herdr's socket API from the other runtime, about 5,800 non-test lines with 14 test files, and a `RuntimeCapabilities` record whose `attach: "pty-cli"` mode fits a backend with an attach CLI.
- C5 [high] {S1.4, S1.11} The minimum a backend must answer is ping, a session snapshot, pane and agent lookups, process info, read, send text and keys, and an event stream; workspaces, tabs and splits can be kept by Ovis itself in terminal labels and one layout document.
- C6 [high] {S1.2, S1.12, S1.13} Ovis is MIT licensed, effectively single-maintainer and fast-moving: six releases in nine days up to v0.5.9 on 2026-11-21, with the latest 100 commits spanning about two days.
- C7 [low] {S1.15} By a line count over the 0.5.3 tree (derived, not published), Ovis is large: about 107,000 non-test server lines, 133,000 frontend lines and about 870 test files.
- C8 [high] {S1.14, S1.4} Ovis accepts a third runtime name, `alt-runtime`, on the wire but refuses to start it, still so in v0.5.9; nothing found says what it is.
- C9 [medium] {S1.13, S1.12} No Ovis issue, pull request or document proposes Rex, tmux, zellij or another non-Herdr multiplexer as a backend.
- C10 [high] {S2.2, S2.4} Rex's server exposes an HTTP and WebSocket API on every listener including the unix socket: a control WebSocket at `/api/control`, data WebSockets at `/api/data`, and its own protocol document at `/llms.txt`, which says it exists "so that you can write your own client, script, or tool" and lists `web` as a client platform.
- C11 [high] {S2.4, S2.3} Terminal output is a live binary stream: `data.connect` gives a single-use ticket for a one-way WebSocket (`rex.data.terminal.v1`) that can be resumed for 60 seconds; input, resize and ownership go over the control connection (`terminal.write`, `client.key`, `block.event`, `terminal.resize`, `session.own_block`).
- C12 [high] {S2.4, S0.2} The stream opens with a snapshot "in Ghostty's snapshot format", which the document says "is meant for terminal emulators built on Ghostty"; a `resize` message marked with the connection's nonce "comes right after the snapshot", and program output with nonce-marked APC messages follows.
- C13 [high] {S2.4, S2.3} Without the Ghostty format, `com.superlogical.terminal.format` returns screen and scrollback as text, HTML or VT escape sequences that redraw the screen; it is a snapshot, not a stream.
- C14 [high] {S2.5, S2.10} Rex identifies callers only by transport (unix peer credentials, Tailscale login, or the login server); a plain HTTP listener needs `--allow-anonymous` and then gives every connection full access; `--websocket-origin-pattern` allows cross-origin browser WebSockets and `tailnet` and `tailnet-serve` listeners exist.
- C15 [high] {S2.1, S2.4} Rex is a preview that negotiates numbered API revisions (this server accepts 0 to 19) and moved from revision 18 to 19 within a day of this research; no written stability promise was found.
- C16 [medium] {S2.8, S2.13} Rex is distributed as a proprietary binary with no source or licence text in the package; no terms restricting third-party clients were found.
- C17 [high] {S2.9, S2.12} Superlogical's public docs list macOS, iOS and Windows apps and Linux and FreeBSD servers, with a Linux client "that isn't part of testing yet"; no web or Android client is listed.
- C18 [high] {S0.1} The Linux `rex` CLI in 0.1.0-preview.22 has no command that attaches a session inside the calling terminal; it has `capture`, `send`, `send-key`, `events` and `block stream`.
- C19 [high] {S2.3, S2.4} Rex's API has what Ovis's agent views need from a backend in kind: session, window and block listings with layout, per-terminal process and working-directory methods, and structural events.
- C20 [high] {S2.14, S1.9} libghostty is MIT-licensed and Ovis already ships a libghostty-vt WebAssembly module in the browser.

Coordinator sources:

- S0.1 primary 2026-11-21 file://localhost/usr/bin/rex | local commands `rex help`, `rex session --help`, `rex attach --help`, `rex block --help`, `rex block stream --help` on linux-box (0.1.0-preview.22): no command that attaches a session in the calling terminal
- S0.2 primary 2026-11-21 http://localhost/llms.txt | local `curl --unix-socket /run/user/1000/rex/server.sock http://localhost/llms.txt`, section "The Terminal Stream" read in full by the coordinator

## Appendix B: findings on Ovis

Read from the local 0.5.3 source tree (commit 184ac6d, read only) and the public GitHub
repository on 2026-11-21. Paths below are relative to
`~/.local/share/setup-repo/ovis/releases/0.5.3/app/`. Local files are logged by their GitHub URL at
that commit, because the run checker requires a URL; each was read in the local copy, whose
receipt names the same commit.

### Sources
- S1.1 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/AGENTS.md | Ovis 0.5.3 root agent notes: architecture summary and "bridge traps" (with server/AGENTS.md) [read in the local 0.5.3 copy of this commit]
- S1.2 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/package.json | Ovis 0.5.3 package manifest: runtime, dependencies, scripts, licence (with receipt.json and LICENSE beside it) [read in the local 0.5.3 copy of this commit]
- S1.3 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/server/runtime/capabilities.ts | RuntimeCapabilities record: the two runtimes Ovis serves and what each can do [read in the local 0.5.3 copy of this commit]
- S1.4 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/server/herdr-core/adapter.ts | The herdr-core adapter: answers herdr's socket API from another runtime (with runtime.ts, attach-session.ts in the same directory) [read in the local 0.5.3 copy of this commit]
- S1.5 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/server/herdr/client.ts | The single herdr RPC client and its typed method table (methods.ts) [read in the local 0.5.3 copy of this commit]
- S1.6 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/server/core/terminal-process.ts | How a pane's live terminal is started: `herdr terminal attach` on a PTY, or an hc stream [read in the local 0.5.3 copy of this commit]
- S1.7 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/crates/pty-sidecar/README.md | Rust PTY host: protocol, fallbacks (with server/pty/session.ts) [read in the local 0.5.3 copy of this commit]
- S1.8 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/shared/protocol.ts | Ovis's HTTP/WebSocket contract: /ws frames, roles, access rules, snapshot types [read in the local 0.5.3 copy of this commit]
- S1.9 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/src/lib/ghostty/overlay.ts | Browser terminal rendering: libghostty-vt wasm layer over xterm.js (with vt.ts) [read in the local 0.5.3 copy of this commit]
- S1.10 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/server/dispatch.ts | Request dispatch: /ws upgrade origin and access checks (with machine-security.ts, access.ts) [read in the local 0.5.3 copy of this commit]
- S1.11 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/docs/herdr-core-layout.md | How Ovis keeps workspaces/tabs/splits itself on a runtime that has none (with docs/runtime-move.md, docs/guide.md "Herdr app terminals") [read in the local 0.5.3 copy of this commit]
- S1.12 primary 2026-11-12 https://github.com/devswha/ovis/blob/184ac6d47c5c87b0b90c59c32db69cf84d54ee86/README.md | Ovis README: positioning, install, credits (with docs/guide.md FAQ, CONTRIBUTING.md, CLA.md) [read in the local 0.5.3 copy of this commit]
- S1.13 primary 2026-11-21 https://github.com/devswha/ovis | GitHub repository metadata, releases, contributors, commits (read through the GitHub API)
- S1.14 primary 2026-11-11 https://github.com/devswha/ovis/pull/3640 | Merged PR "know alt-runtime as a runtime on the wire, chosen only by OVIS_RUNTIME or Settings"
- S1.15 derived 2026-11-21 - | Line and file counts and method tallies computed over the 0.5.3 tree with find, wc and grep

### Claims
- C1.1 [high] {S1.1, S1.2} Ovis is a Bun server (`server/`, bundled Bun 1.4.4) plus a React 19 + xterm.js client (`src/`, built with Vite) sharing a wire contract in `shared/`; its own notes say "herdr owns every pty, scrollback and agent state; this app is only a bridge".
- C1.2 [high] {S1.7, S1.1} The "PTY sidecar" is a small Rust binary (`crates/pty-sidecar`, about 1,200 lines) that runs one command on a PTY, taking `<cols> <rows> <command> [args...]` as argv, newline-delimited JSON control frames on stdin (`i` input, `r` resize, `p` pause, `w` SIGWINCH) and writing PTY bytes to stdout; a Node script using node-pty is the fallback because node-pty "panics the runtime" inside Bun.
- C1.3 [high] {S1.6, S1.7} The only thing the sidecar runs for a pane is the multiplexer's own attach client: `herdr terminal attach <terminal> [--takeover]` with `HERDR_SOCKET_PATH` set, so Herdr, not Ovis, draws the pane and keeps scrollback.
- C1.4 [high] {S1.8} The browser reaches a terminal over one WebSocket, `/ws` (`/ws?machine_id=<id>` for another PC), with JSON frames: client `attach {pane_id, cols, rows}`, `input`, `keys`, `resize`, `detach`, `pty-ack`, `role`, `watch`; server `snapshot`, `pty-data {pane_id, data}`, `pty-exit`, `pane-geometry`, `pane-status`, `session-changed`; `pty-data` carries the raw terminal byte stream as a string with optional ack-based flow control.
- C1.5 [high] {S1.9, S1.2} Escape codes are parsed in the browser: xterm.js 6.0.0 (patched) is the engine that takes keys, selection and answers program queries, while a libghostty-vt WebAssembly module parses the same bytes and draws the visible rows as DOM text over it ("libghostty-vt draws every xterm terminal's screen ... while xterm stays the engine under it").
- C1.6 [high] {S1.5, S1.1} Ovis talks to Herdr over a unix socket (`HERDR_SOCKET`) with newline-delimited JSON RPC, one connection per call except `events.subscribe`; the client in `server/herdr/client.ts` (1,271 lines) wraps about 38 methods including `session.snapshot`, `pane.get/read/send_text/send_keys/process_info/split/move/swap/resize/zoom/close/rename/focus/scroll`, `tab.*`, `workspace.*`, `worktree.*`, `agent.get/start/prompt/rename`, `layout.set_split_ratio`, `plugin.list` and `events.subscribe`.
- C1.7 [high] {S1.15, S1.5} Herdr calls are funnelled through that one client, but about 70 non-test server files import it, and wire types generated from Herdr's API schema (protocol 22: `PaneInfo`, `TabInfo`, `WorkspaceInfo`, `SessionSnapshot`, `AgentStatus`) are re-exported into the browser contract, so Herdr's data model is the app's data model end to end.
- C1.8 [high] {S1.3, S1.4} Ovis 0.5.3 already serves a second backend, herdr-core (`hc`), and the way it was added is an adapter that listens on a socket, points `HERDR_SOCKET` at itself and answers Herdr's API from the other runtime "so none of those callers learns a second runtime"; `server/herdr-core/` is about 5,800 non-test lines (adapter.ts 1,484) with 14 test files.
- C1.9 [high] {S1.3} A `RuntimeCapabilities` record is the declared abstraction boundary ("a runtime is one record here, not a branch at every gate"), with fields `attach: "pty-cli" | "hc"`, `agents: "detected" | "reported"`, `foreground`, `seen`, `pins`, `machines`, `spawner`; a backend whose attach is a CLI run on a PTY fits the existing `pty-cli` mode.
- C1.10 [high] {S1.4} The methods the herdr-core adapter answers show the minimum a backend must supply: `ping`, `session.snapshot`, `pane.get`, `agent.get`, `pane.process_info`, `pane.read`, `pane.send_text`, `pane.send_keys`, `agent.prompt`, `events.subscribe` (status, pane and layout lifecycle events), plus optional layout calls (`pane.split/move/swap/resize/zoom/close/rename`, `tab.*`, `workspace.*`, `worktree.*`); anything else is refused as `unsupported`.
- C1.11 [high] {S1.11} Where the backend has no workspaces, tabs or splits, Ovis keeps them itself: labels on each terminal (`herdr.space`, `herdr.tab`, `ovis.*`) and one `ovis-layout` document holding a split tree, so a backend only needs terminals plus somewhere to keep labels and one document.
- C1.12 [high] {S1.14, S1.4} A third runtime name, `alt-runtime`, is already accepted on the wire (`OVIS_RUNTIME`, `POST /api/runtime`, Settings types) but cannot be started: `startRuntime` throws "this Ovis cannot start alt-runtime yet"; the PR does not say what alt-runtime is, and v0.5.9 still has the same refusal and only the two capability records.
- C1.13 [high] {S1.15, S1.6} There is no plain-shell tab: `PtySession` (the arbitrary-command PTY wrapper) is constructed in two places only, the pane attach in `server/core/terminal-process.ts` and a private CLI sign-in flow in `server/usage-login.ts`; every terminal the UI shows is a pane of the runtime, and new shells are started by asking the runtime (`pane.split`, `tab.create`, hc `terminal.run`).
- C1.14 [high] {S1.8, S1.1} The UI model is workspaces, tabs and panes from `session.snapshot`, with per-pane agent identity and status; agent chat views are read by Ovis from each agent's own transcript files, but binding a pane to an agent and session depends on runtime data (`pane.process_info` foreground processes, cwd, `agent_status`, `agent_session`), and prompt answers and chat sends go through `agent.prompt`, `pane.send_text` and `pane.send_keys`.
- C1.15 [high] {S1.8, S1.10} The `/ws` upgrade is refused with 403 unless `sameOrigin(request)` passes (`Sec-Fetch-Site` and `Origin` checks), and needs the same access as the API: a local request with no proxy in front, the PC's own Tailscale login as `tailscale serve` states it, a paired device's cookie, or the shared token (`OVIS_TOKEN`) as cookie or bearer; with no token and no paired device "anything that reaches the server is let in"; a connection can be demoted to an `observe` role that cannot type or resize.
- C1.16 [high] {S1.2, S1.12} The licence is MIT ("Copyright (c) 2026 devswha"); contributions upstream require signing a CLA that grants the maintainer a perpetual sublicensable licence, which does not restrict forking.
- C1.17 [high] {S1.13} The project is very active and effectively single-maintainer: created 2026-09-17, 2,172 stars and 307 forks, newest release v0.5.9 on 2026-11-21 (0.5.3 was 2026-11-12, six releases in nine days), the last 100 commits span about two days, and devswha has 2,621 contributions against 63 for the next contributor.
- C1.18 [high] {S1.15} The code base is large: about 107,000 non-test lines in `server/` (434 test files, 180,000 test lines), about 133,000 non-test lines in `src/` including 29,000 of CSS (436 test files), about 15,000 in `shared/`, 1,200 Rust lines in the sidecar, and 129,000 lines of scripts, mostly browser regression runs.
- C1.19 [medium] {S1.13, S1.12} No issue, PR or doc found proposes tmux, zellij, Rex or any non-Herdr multiplexer as a backend: searches for those words returned only unrelated items (tmux running inside a pane, CI image), and the FAQ names collie as the client "for herdr, tmux and zellij", positioning Ovis as a Herdr client.
- C1.20 [medium] {S1.1, S1.11, S1.4} Many features beyond the terminal assume Herdr itself (its plugin manifest and `min_herdr_version = "0.9.0"`, `herdr update`, worktrees, remote-PC bridges that discover Herdr sockets over SSH, the herdr-to-herdr-core move), so a fork that only adds an adapter would leave those refusing or needing per-runtime gates, as herdr-core's adapter does with `unsupported`.

### Against
- The "only a bridge" framing understates the work: the herdr-core backend, written by the upstream maintainer for a sibling product with a purpose-built API (`terminal.attach`, `terminal.read`, labels, documents, an event stream), still took about 5,800 lines plus 14 test files and continues to produce runtime-specific bugs (open issues 4321, 3963; closed 3939 about `pane.process_info` on herdr-core). {S1.4, S1.13}
- The adapter pattern hides the second runtime from callers only partly: `capabilities()` gates exist across the server, the attach path branches on `onCore`, and browser types carry herdr-core-only fields (`grid`, `own_tab`, `parent_pane_id`), so a third backend is not a pure drop-in. {S1.3, S1.6, S1.8}
- Upstream moves at roughly 50 commits a day with releases every one to two days, and `server/`, `shared/` are the hottest areas; a fork carrying a backend would face constant merge pressure. {S1.13}
- Rex already has its own libghostty renderer; Ovis's browser side would re-parse the byte stream of a Rex attach client with xterm.js plus libghostty-vt, which works for any TTY program but adds a second terminal layer rather than using Rex's state directly. {S1.9, derived}
- The existence of the unexplained `alt-runtime` slot suggests upstream is preparing a third runtime of its own; it may or may not be open to third-party backends, and nothing found says either way. {S1.14}

### Gaps
- Herdr's own API documentation was not read; the method list comes from Ovis's client and its types generated from `herdr api schema --json` (protocol 22), not from Herdr's docs.
- What `alt-runtime` is (PR 3640 gives no description) and whether upstream would accept an external backend: no maintainer statement found; GitHub Discussions were not searched (only issues and PRs).
- The source between 0.5.3 and 0.5.9 was checked only for `server/runtime/capabilities.ts`, `server/herdr-core/runtime.ts` and the directory list; other changes in six releases were not reviewed.
- Nothing was built or run, so the claim that an arbitrary attach CLI works through the `pty-cli` path is from reading code, not a test; the attach code also parses Herdr-specific refusal text and take-over behaviour that another CLI would not produce.
- The relay, remote-PC (SSH bridge), push and native app layers were not read in depth; how each behaves on a non-Herdr runtime is unknown.
- Line counts are raw `wc -l` over .ts/.tsx/.mjs/.rs/.css excluding generated files; comments and blank lines are included.

## Appendix C: findings on Rex

Note on versions: the brief gives server 0.1.0-preview.21, API revision 18. The machine now runs
0.1.0-preview.22, API revision 19 (package built 2026-11-19, installed 2026-11-20). Everything
below describes revision 19.

Local sources carry a `localhost` URL because the run checker requires a URL; the command that
produced each one is in its title.

### Sources
- S2.1 primary 2026-11-21 file://localhost/usr/bin/rex | local commands `rex version`, `rex server status`, `rex whoami`, `rex client ls`: version, API revision, listeners, identity
- S2.2 primary 2026-11-21 file://localhost/usr/bin/rex | local commands `rex api list` and `rex api list --json`: 75 server methods, 3 block types, HTTP paths
- S2.3 primary 2026-11-21 file://localhost/usr/bin/rex | local command `rex api describe METHOD` for data.connect, session.bootstrap, session.attach, session.own_block, block.event, client.key, com.superlogical.terminal.resize and .size
- S2.4 primary 2026-11-21 http://localhost/llms.txt | local command `curl --unix-socket /run/user/1000/rex/server.sock http://localhost/llms.txt`: the server's own "Rex API" document (344 KB Markdown, API revision 19), sections Endpoints, The Control Connection, Data Connections, The Terminal Stream, method and event reference
- S2.5 primary 2026-11-21 file://localhost/usr/bin/rex | local command `rex server run --help`: listener, admission, Tailscale, WebSocket origin and block plugin flags
- S2.6 primary 2026-11-21 file://localhost/etc/rex/accounts.jsonc | local command `rex login-server --help` and the comments in `/etc/rex/accounts.jsonc`: multi-account login server and principal syntax
- S2.7 primary 2026-11-21 file://localhost/usr/bin/rex | local commands `rex help` and `--help` for api, events, capture, send, send-key, client, block, do, actions, hosts, home, skill: CLI surface
- S2.8 primary 2026-11-21 file://localhost/usr/bin/rex | local commands `pacman -Qi rex`, `pacman -Ql rex`, `strings /usr/bin/rex`: package licence field, installed files, embedded docs URLs
- S2.9 primary unknown https://www.superlogical.com/rex/docs/llms.txt | index of Rex's public documentation pages
- S2.10 primary unknown https://www.superlogical.com/rex/docs/linux/remote-access.md | Remote Access: listener types, endpoint syntax, how callers are identified
- S2.11 primary unknown https://www.superlogical.com/rex/docs/automate/server-api.md | Server API: discovering and calling methods, generating bindings
- S2.12 primary unknown https://www.superlogical.com/rex/docs/installation.md | Installation: which apps and servers are in testing
- S2.13 primary unknown https://www.superlogical.com/rex/docs/reference/privacy.md | Privacy & Telemetry: no account or licence checks, outbound connections
- S2.14 primary 2026-07-29 https://mitchellh.com/writing/superlogical | Mitchell Hashimoto's post announcing Superlogical and its use of libghostty
- S2.15 secondary 2026-08-01 https://www.devclass.com/devops/2026/08/01/dev-who-gave-hashicorp-its-name-returns-with-a-faster-terminal-multiplexer/5282025 | DevClass article on Superlogical's multiplexer, with Hashimoto quotes

### Claims
- C2.1 [high] {S2.1, S2.8} The installed Rex is 0.1.0-preview.22, built 2026-11-19, and its server speaks "api: revision 19 (supports 0 to 19)"; the only listeners on this machine are the unix socket `/run/user/1000/rex/server.sock` (peer_credentials, primary) and a login-server unix socket, with Tailscale disabled.
- C2.2 [high] {S2.4, S2.2} The server API is HTTP plus WebSocket on whatever address the server listens on, including the unix socket: `GET /api/control` (control WebSocket), `GET /api/data` (data WebSockets), `GET /api/help` (JSON Schema of every method), `GET /llms.txt` and `GET /llms.html` (the full protocol document).
- C2.3 [high] {S2.4} The control protocol is Rex's own JSON framing, not JSON-RPC or gRPC: WebSocket subprotocol `rex.control.v1`, one JSON object per text message, client sends `hello` then `request` messages `{type, id, method, payload}`, server sends `welcome`, `response` and unsolicited `event` messages with a per-connection `seq`.
- C2.4 [high] {S2.4} The protocol document is addressed to third-party authors: "This page documents the API that every client uses, so that you can write your own client, script, or tool", and the hello's `client.platform` field lists `web` among its values (macos, ios, linux, windows, freebsd, web, other).
- C2.5 [high] {S2.4} Compatibility is handled by numbered API revisions negotiated in hello/welcome (`api_revision`, `api_min_revision`); the server "translates every message to and from that revision's shapes, so an older client keeps working with a newer server", and this server still accepts revisions 0 to 19. No written stability guarantee beyond this mechanism was found.
- C2.6 [high] {S2.2, S2.3} The API has 75 server methods (session, window, block, client, hosts, server, data, target) plus per-block methods; the terminal block `com.superlogical.terminal` adds 19 methods including write, resize, size, format, modes, process, pwd, upload_begin and download_begin.
- C2.7 [high] {S2.4, S2.3} There is a live output stream, not only snapshots: `data.connect` returns a single-use 16-byte ticket (valid 60 s, same user only), the client opens a WebSocket at `/api/data` with subprotocol `rex.data.terminal.v1`, sends a 17-byte binary HELLO, receives a 32-byte WELCOME, and then "every binary message from the server is part of the stream", in chunks of 1 to 65,536 bytes.
- C2.8 [high] {S2.4} The terminal stream is not plain VT from the start: it "starts with a snapshot of the terminal in Ghostty's snapshot format", then the program's output, with Rex messages (`resize`, `theme`, `child_exited`) embedded as APC sequences `ESC _ rex1;<nonce>;<json> ESC \`; the document states "The snapshot format is meant for terminal emulators built on Ghostty."
- C2.9 [high] {S2.4} A dropped data connection can be resumed for 60 seconds with a 25-byte RESUME carrying the reconnect token and an exact count of bytes received; a dropped control connection keeps its client for 60 seconds and resumes with a `reconnect_token`, but events during the gap are lost.
- C2.10 [high] {S2.4, S2.3} Data connections are one-way ("Bytes flow only from the server to the client"); input goes over the control connection by `com.superlogical.terminal.write` (text and escape sequences), `client.key` (W3C KeyboardEvent-code keys, Lua bindings get first chance) or `block.event` (key, paste, mouse, wheel, focus).
- C2.11 [high] {S2.3, S2.4} Size is negotiated by ownership: each client requests a size with `com.superlogical.terminal.resize` (columns, rows, optional cell pixel size), the terminal uses the owner's size, and `session.own_block` with mode `take` or `request` decides the owner; "Owning a block gives no other rights over it."
- C2.12 [high] {S2.4, S2.3} A snapshot path exists without the Ghostty format: `com.superlogical.terminal.format` returns the screen and scrollback as `text`, `html` or `vt` ("escape sequences that redraw the screen with its colors and styles"), which `rex capture --format` exposes; results over the 1 MiB message limit fail with `too_large` and are read with `blob_read`.
- C2.13 [high] {S2.4, S2.7} A client is "a program connected to the server, such as Rex.app, the `rex` CLI, or a script"; any connection that sends a hello gets a client ID, and attaching with `session.attach` or `session.bootstrap` is what permits data connections and block ownership, so a headless or custom client attaches by the same calls the native app uses.
- C2.14 [high] {S2.4, S2.7} `rex events` and the control connection carry structural and block events (session, window, block, client, owner, view-revision changes, plus `block_event`s such as directory or port changes), not terminal output; an event backlog over 8 MiB closes the connection.
- C2.15 [high] {S2.5, S2.10} `rex server run --listen` takes one endpoint (default the local unix socket) and `--extra-listen` accepts "unix, http, tailnet, tailnet-serve, or login-server" endpoints; `--tailscale` serves the API as an embedded tsnet node at an address like `https://rex.<tailnet>.ts.net`; clients can also reach a server through `ssh://[USER@]HOST[:PORT][/SOCKET]`.
- C2.16 [high] {S2.5, S2.10} A plain HTTP/TCP listener has no authentication of its own: Rex refuses it unless `--allow-anonymous` is passed, and then "every connection gets full access"; the docs say "Rex trusts a caller based only on how they connect today, so it can't check who someone is unless the network tells it."
- C2.17 [high] {S2.1, S2.6, S2.10} Identity comes from the transport: unix peer credentials locally ("uid 1000 over unix"), Tailscale login or tag on tailnet listeners (node owner only by default), and the root-run login server maps principals such as `peer:1000`, `tailscale:alice@example.com` or `anonymous` to OS accounts through `/etc/rex/accounts.jsonc`, which ships empty.
- C2.18 [high] {S2.5} The server has explicit browser support in its listener: `--websocket-origin-pattern PATTERN` is documented as "allow browser WebSockets from cross-origin PATTERN (repeatable)", which implies cross-origin browser WebSockets are refused by default.
- C2.19 [medium] {S2.4} The welcome message can advertise other "carriers" for the same server, with `quic` given as the example name, so WebSocket over HTTP is not the only transport the protocol anticipates.
- C2.20 [high] {S2.4} Some methods are accepted "only over its local Unix socket, or its named pipe on Windows" and fail with status 403 over TCP or Tailscale, so a bridge running locally on the socket has more of the API than a remote client.
- C2.21 [high] {S2.9, S2.12} Superlogical's public docs list macOS and iOS apps, a Windows app and server, and Linux and FreeBSD servers ("Server only"); "We have a Rex client for Linux that isn't part of testing yet". No web, browser or Android client appears in the docs index or installation page.
- C2.22 [medium] {S2.9, S2.11} The public docs have "Server API" and "Server API Methods" pages that describe calling methods through the CLI and Lua and say the `--json` output is "useful for generating bindings", but the index has no page on writing a client; the wire protocol is documented only in the server's own `/llms.txt`.
- C2.23 [medium] {S2.8, S2.13} The Arch package declares `Licenses: Proprietary` and installs only the binary, units, config and terminfo (no source, licence text or schema files); the privacy page says Rex has "no account or license checks". No terms restricting third-party clients were found.
- C2.24 [high] {S2.14} Superlogical builds on libghostty as "a public building block for terminal applications" and will "consume the same MIT-licensed components available to everyone else", so the engine a client needs to read the stream's snapshot is openly licensed even though Rex is not.
- C2.25 [high] {S2.7, S2.3} Lua scripting can observe and drive but not render: `rex do` scripts call the same server API (`rex.call`), register `rex.on` event handlers and can run until stopped, and `client.set_script` loads Lua for a client; nothing in the help describes Lua access to the data stream.
- C2.26 [medium] {S2.5, S2.2} The server can load third-party block types: `--block-dir DIR` is documented as "discover executable block plugins in DIR", and `block_creator.list` describes each creator's methods, events and flavors; the public docs index has no page on block plugins.
- C2.27 [low] {S2.15} Hashimoto is quoted saying the design "does require that every connecting client be a very smart, high-functioning, compliant client", consistent with clients embedding a full terminal engine.

### Against
- The live stream is not something xterm.js or another generic browser emulator can consume as is: it opens with a Ghostty-format snapshot and the server's own document says that format "is meant for terminal emulators built on Ghostty" (S2.4). A browser client needs a libghostty build that runs in the browser and reads that snapshot, or must fall back to polling `format` with `vt`, which is a redraw snapshot and not a stream.
- There is no authentication a browser can present on its own. A plain HTTP listener needs `--allow-anonymous` and gives every connection full access; identified access needs a unix socket, Tailscale or the login server (S2.5, S2.10). A web deployment therefore needs its own authenticating bridge or a tailnet in front.
- Rex is a preview with no stated API stability promise; the API moved from revision 18 to 19 between the brief being written and this run, and the public docs site does not document the wire protocol at all (S2.1, S2.9, S2.11).
- Rex is proprietary and closed source per the package metadata (S2.8); no public repository, licence text or terms of use were found, so nothing confirms that third-party clients are permitted, only that the server's document invites them.
- Data-connection tickets work only for "the same user as the control connection" and a client may hold only one connection per block data source (S2.4), which constrains a bridge that multiplexes several browser viewers through one identity.
- Superlogical's own statements list no web client, and the changelog and roadmap sit behind the beta Discord and its Community MCP (S2.9, S2.12).

### Gaps
- Not tested live: no connection to `/api/control` or `/api/data` was opened, because attaching is outside the read-only limit. The handshake, the snapshot bytes and the behaviour of `--websocket-origin-pattern` are taken from the server's documentation and help text, not observed.
- The exact definition of "Ghostty's snapshot format", and whether a WebAssembly libghostty can load it in a browser, was not researched here.
- The default origin rule for browser WebSockets (same-origin only, or all refused) and whether the server can serve static pages itself were not found.
- `/api/help` and `/llms.html` were listed but not fetched; only `/llms.txt` was read, and of its 344 KB the method and event reference was sampled, not read in full.
- The public `llms-full.txt` (610 KB) was read only for its first 100 KB; `reference/api.md`, `reference/events.md`, `reference/lua.md`, the iOS pages and `linux/login-server.md` were not read.
- No changelog, roadmap, Discord or forum statement about a web client or a third-party client protocol could be read; the changelog is reachable only through the Discord-gated Community MCP.
- No licence text, EULA or terms of service for Rex was found; "Proprietary" comes from the package metadata alone. A third-party page said to state the same returned HTTP 403 and was not read.
- The `quic` carrier, the block plugin interface (`--block-dir`) and `rex block stream` have one-line descriptions only; their protocols are undocumented in what was read.
- `rex __internal skill` (the agent guide) was not run, since it is not on the brief's list of allowed commands.
