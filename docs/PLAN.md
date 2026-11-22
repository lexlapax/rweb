# rweb: high-level plan

Written 2026-11-21. Background and evidence: [rex-web-research.md](rex-web-research.md).

## Goal

Reach Rex sessions from a web browser, including a phone, over the owner's private tailnet,
without the Rex desktop app running on the server and without exposing Rex's own API to the
network.

## Decisions made by the owner (2026-11-21)

| Decision | Choice |
| --- | --- |
| Shape | A bridge process that runs as the user next to Rex's unix socket, speaks Rex's protocol, and serves the page and its own WebSocket on loopback. Tailscale Serve goes in front, as Ovis is deployed today. |
| Server language | Rust, one static binary per platform. |
| First usable version | List sessions and their terminals; open one terminal full-screen; type, resize, reconnect; usable on a phone; create, rename and close sessions and terminals from the browser. |
| Not in the first version | Drawing a Rex window's split layout. Forking Ovis. |
| Repository | `lexlapax/rweb`, private. |

## Constraints

- Single user, private tailnet, no public exposure, no vendor relay.
- Rex is a preview. Pin the API revision the client speaks and re-test on each Rex update.
- Rex trusts only the transport. Never start or ask for a Rex listener with `--allow-anonymous`.
  The bridge talks to the unix socket only.
- The bridge has the user's full Rex access, so it must authenticate browsers itself: bind to
  loopback, check Origin on the WebSocket upgrade, and accept only requests that arrive through
  Tailscale Serve with the owner's identity.
- Deployment is through the owner's `setup-repo` repository with pinned, checksummed artifacts.
  Nothing is installed on a machine by hand.
- Development and tests use throwaway Rex sessions that the test created. Never attach to, send
  input to, resize or close a session the owner is using.

## Phases

Each phase ends with something that runs and a short record of what was verified. Do not start a
phase before the previous one's exit condition is met.

### Phase 0: spike (gate for everything else)

Question to answer: can a browser terminal show a live Rex terminal correctly?

- Connect to `/api/control` on the unix socket, complete the hello, attach, create a throwaway
  session, get a ticket with `data.connect`, open `/api/data`, and save the raw stream to a file.
- Look at the opening snapshot. Try both ways of handling it:
  1. skip to the first nonce-marked `resize` message, paint the screen from
     `com.superlogical.terminal.format` in VT form, then pass live output through with Rex's
     marked messages removed, into xterm.js;
  2. feed the stream, snapshot included, to a libghostty build in the browser.
- Check a shell prompt, a full-screen program (for example `vim` or `htop`), colours, resize,
  and reconnect after a dropped connection.

Exit: a written result in `docs/` saying which way works, with the evidence, and the choice of
browser terminal. If neither works, stop and report; the rest of the plan does not hold.

### Phase 1: Rex client library (Rust)

- Control connection: hello and revision negotiation, requests and responses, events, resume.
- Data connection: ticket, handshake, byte counting, resume within the 60-second window,
  parsing of Rex's marked messages (resize, theme, child exited).
- Typed calls for the methods the first version needs: list and inspect sessions, windows and
  blocks; create, rename, close; terminal write, key, resize, format, process; block ownership.
- A fake Rex server built from the protocol document, for tests that need no real Rex.

Exit: tests pass against the fake server and against a live local Rex using throwaway sessions.

### Phase 2: bridge server

- One binary: serves the embedded frontend, a small JSON API and one browser WebSocket.
- Its own browser protocol, kept independent of Rex's so a Rex change stays inside the client
  library: session tree, attach, output, input, resize, detach, lifecycle events.
- Access control as in Constraints, plus an observe-only mode that cannot type or resize.
- Sizing policy when several browsers view one terminal, and when the desktop app owns it.
- Flow control so a slow phone cannot make the bridge buffer without limit.

Exit: a terminal works end to end from a browser on the same machine.

### Phase 3: frontend

- Session and terminal list with live updates; one terminal full-screen; reconnect with state
  kept; touch keyboard helpers (Esc, Ctrl, Tab, arrows), paste, font size.
- Create, rename and close sessions and terminals, with a confirmation before closing.

Exit: daily use from a phone and a laptop browser for a week without falling back to SSH.

### Phase 4: packaging and deployment

- Release builds for Linux x64 and macOS ARM64 with checksums.
- A `rweb` module in `setup-repo`: pinned version and checksum, a systemd user unit on Linux and a
  LaunchAgent on macOS, loopback port, and the Tailscale Serve mapping as an operator step.
- Start after login and reboot behaviour verified on linux-box, then gateway-box, then desktop-mac.

Exit: all three machines serve rweb after a reboot, recorded in setup-repo.

### Later, not planned in detail

- Draw a Rex window's split layout.
- Reuse the client library as an attach program for an Ovis fork, if Ovis's views are wanted.
- Ask Superlogical about third-party client terms and a web client, and Ovis's maintainer what
  its `alt-runtime` slot is for.

## Risks

| Risk | What limits it |
| --- | --- |
| Rex's stream cannot be rendered in a browser | Phase 0 is first and is a stop condition. |
| Rex changes its API | Pinned revision; the server still accepts old ones; the fake server and live tests show breakage early. |
| Rex ships its own web client | The project is small by design; stop if that happens. |
| The bridge becomes a way into every terminal | Loopback only, origin and identity checks, no anonymous Rex listener, a security review before Phase 4. |
| Licence terms forbid third-party clients | None found; ask the vendor before any public release. |

## Open questions for the build

- Which browser terminal (decided by Phase 0).
- How Tailscale Serve identity reaches the bridge and how to verify it cannot be forged locally.
- What the bridge does when the desktop app and a browser both want to own a terminal's size.
