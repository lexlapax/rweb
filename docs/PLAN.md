# rweb: high-level plan

Written 2026-11-21; revised the same day after the design research in
[design-research.md](design-research.md). Background and evidence:
[rex-web-research.md](rex-web-research.md).

## Goal

Reach Rex sessions from a web browser, including a phone, over the owner's private tailnet,
without the Rex desktop app running on the server and without exposing Rex's own API to the
network.

## Decisions made by the owner (2026-11-21)

| Decision | Choice |
| --- | --- |
| Shape | A bridge process that runs as the user next to Rex's unix socket, speaks Rex's protocol, and serves the page and its own WebSocket on loopback. Tailscale Serve goes in front, as Ovis is deployed today. |
| Server language | Zig, one static binary per platform (changed from Rust on 2026-11-21; see below). |
| First usable version | List sessions and their terminals; open one terminal full-screen; type, resize, reconnect; usable on a phone; create, rename and close sessions and terminals from the browser. |
| Not in the first version | Drawing a Rex window's split layout. Forking Ovis. |
| Repository | `lexlapax/rweb`, private until 2026-11-26, public since (see Phase 6). |

## Decisions made after the design research (2026-11-21)

| Decision | Choice |
| --- | --- |
| Bridge language | Zig instead of Rust. libghostty-vt is a Zig package, so the bridge imports it directly, with no bindings and one toolchain. Accepted costs: Zig is before 1.0 and its releases break code, it does not prevent use-after-free, and it has fewer libraries. |
| Zig toolchain | Installed on every build machine (linux-box, gateway-box, desktop-mac) by the owner's `setup-repo` repository, pinned to the Zig version the chosen libghostty-vt release requires (`vt-1.0.1` needs 0.17.0; Ghostty's main branch needs 0.17.1). The build checks the Zig version and fails on a mismatch. |
| Requests from the machine's own Tailscale address | Rejected by default. A per-machine setting accepts them on hosts where no other user logs in, such as linux-box. |
| desktop-mac | Included. The bridge starts a personal Rex server when none is running, as an `ssh://` client does, and listens on loopback TCP because Tailscale.app cannot forward to a unix socket; the exposure to other local users is accepted and recorded. |

## Constraints

- Single user, private tailnet, no public exposure, no vendor relay.
- Rex is a preview. Pin the API revision the client speaks, accept older servers down to the
  oldest revision in use (desktop-mac runs preview.21), and re-test on each Rex update. Rex
  upgrades restart the Rex server; the bridge must survive the socket going away and coming back.
- Rex trusts only the transport. Never start or ask for a Rex listener with `--allow-anonymous`.
  The bridge talks to the unix socket only.
- The snapshot at the start of Rex's stream is Ghostty's binary format, versioned outside
  libghostty's ABI promise. Pin the libghostty-vt version, check the snapshot header version and
  fail explicitly on one the bridge does not know, never guess.
- The bridge has the user's full Rex access, so it must authenticate browsers itself:
  - Listen on a unix socket (mode 0600, directory 0700) that Tailscale Serve proxies to, and
    accept only peers with uid 0 (tailscaled). On desktop-mac, where Tailscale.app cannot use a
    unix socket, the bridge listens on loopback TCP instead. For an SSH tunnel (`rweb ssh`, since
    round 5) the unix socket accepts only the bridge's own user, and a token is required.
  - Require `Tailscale-User-Login` to equal the configured owner; reject any request carrying
    `Tailscale-Funnel-Request`; reject requests whose `X-Forwarded-For` is one of the node's own
    Tailscale addresses unless that machine's setting allows them; check `Origin` against
    `X-Forwarded-Host` on the WebSocket upgrade. Funnel stays off for the port.
  - Processes running as the owner's own user are not prevented; they can already use Rex's
    socket directly.
- The browser terminal must never send query replies back as input. Rex's server-side terminal
  already answers programs' queries.
- Zig is pinned to the version libghostty-vt requires, and moving to a newer libghostty-vt
  moves the whole bridge to its Zig version in one change. Dependencies are pinned by hash in
  `build.zig.zon` and kept few. Releases build in `ReleaseSafe`, so bounds and overflow checks
  stay on; the code is written to keep ownership plain (one owner per allocation, arenas per
  request or connection) because Zig does not check it.
- Deployment is through the owner's `setup-repo` repository with pinned, checksummed artifacts.
  Nothing is installed on a machine by hand.
- Development and tests use throwaway Rex sessions that the test created. Never attach to, send
  input to, resize or close a session the owner is using.

## Architecture

```text
browser (xterm.js) --WSS--> Tailscale Serve --unix socket--> bridge --unix socket--> Rex
                                                               |
                                    one Rex client; per open terminal: one data stream
                                    into a libghostty-vt mirror, fanned out to viewers
```

- The bridge holds one Rex control connection and, for each terminal at least one browser
  shows, one data connection (Rex allows one per client per block).
- It decodes the stream's snapshot into a libghostty-vt terminal, removes Rex's `rex1` messages,
  and feeds the live output into that terminal. The mirror never answers queries.
- A browser that opens a terminal gets a VT redraw from libghostty-vt's formatter, then the live
  output. Reconnecting is the same: a fresh redraw, so the browser needs no byte-exact resume.
- Each viewer has a bounded send queue. A viewer that falls behind has its queue dropped and gets
  a fresh redraw; the bridge never buffers without limit. Rex bounds its own side and asks for a
  new stream (status 1013), which the bridge handles by re-snapshotting.
- The browser protocol is the bridge's own (session tree, open, output, input, resize, close,
  lifecycle events), independent of Rex's.
- Redraws (confirmed in Phase 0): RIS, then libghostty-vt's `TerminalFormatter` with every extra
  and no trimming; while the alternate screen is up, the primary screen first. A new redraw goes
  to every viewer after each Rex `resize`, since xterm.js and Ghostty reflow differently.
- Input (confirmed in Phase 0) is a hybrid. Physical keys go to `client.key`, so Rex encodes them
  for the program's keyboard mode. Mouse reports, pastes and composed text (input methods, phone
  keyboards) come from xterm.js and go to `terminal.write`. Rex runs `terminal.write` calls
  concurrently, so the bridge keeps one in flight per terminal and coalesces the rest. Keys and
  text also need one order between them (Phase 0, finding 12): a `client.key` waits for the
  write in flight, and while a soft keyboard is in use the browser sends Enter and Backspace
  through xterm.js after the text before them. The browser swallows terminal queries, because
  Rex's own terminal answers them.
- Viewers are written to outside the mirror's lock, through their bounded queues, so a slow
  viewer never stalls the others or the read from Rex.

## Phases

Each phase ends with something that runs and a short record of what was verified. Do not start a
phase before the previous one's exit condition is met.

### Phase 0: spike (gate for everything else)

**Done 2026-11-21; the gate passed.** Route 1 works with xterm.js 6.0.0 and hybrid input; routes
2 and 3 were not needed. Evidence and findings: [phase0-result.md](phase0-result.md). A Rex
server restart and typing from a real phone were checked on 2026-11-22 with the owner's approval.

Question to answer: can a browser terminal show a live Rex terminal correctly?

Throwaway Zig code under `spike/`, not built on later. It starts once `setup-repo` has installed
the pinned Zig on linux-box.

- Connect to `/api/control` on the unix socket, complete the hello, attach, create a throwaway
  `rweb-test-` session, get a ticket with `data.connect`, open `/api/data`, and save the raw
  stream to a file. Record the snapshot header and version.
- Try the routes in this order, stopping at the first that passes the checks:
  1. **Bridge-side mirror:** decode the snapshot with libghostty-vt (Ghostty's `vt-1.0.1` tag as
     a `build.zig.zon` dependency, pinned by hash), strip the `rex1` messages, feed live output,
     and serve a formatter VT redraw plus live output to xterm.js.
  2. **Format repaint:** skip the snapshot up to the first nonce-marked `resize`, paint from
     `com.superlogical.terminal.format` in VT form with every `extra_*` option, then pass live
     output through. Measure how often output arriving between the snapshot and the format reply
     is drawn twice or lost.
  3. **Browser-side decode:** `ghostty-vt-js`'s `restoreTerminal`, only if 1 and 2 fail.
- Input: compare xterm.js encoding keys (sent with `terminal.write`, with handlers that swallow
  query replies) with `disableStdin` plus `client.key` / `block.event`, which let Rex encode keys
  for the program's keyboard mode. Pick one.
- Checks: a shell prompt; a full-screen program (`vim` or `htop`); a program that enables the
  Kitty keyboard protocol; the alternate screen; colours and the `theme` message; wide and
  combining characters; paste (bracketed); mouse in a program that asks for it; resize; that no
  query reply comes back as input; reconnect after a dropped browser connection; a Rex server
  restart; and typing from a phone browser.
- Zig groundwork: which WebSocket and HTTP code to use (Zig's `std.http` WebSocket, or
  karlseguin's `websocket.zig` and `http.zig`, both on Zig 0.17.0; Rex works without
  compression) and which I/O model (`std.Io` threaded or evented).

Exit: a written result in `docs/` saying which route, input path, libraries and I/O model work,
with the evidence and the Rex, Zig, libghostty-vt and browser terminal versions. If no route
works, stop and report; the rest of the plan does not hold.

### Phase 1: Rex client library (Zig)

- Control connection: hello and revision negotiation (down to the oldest revision in use),
  requests and responses, events, resume, reconnect after a Rex restart.
- Data connection: ticket, handshake, byte counting, resume within the 60-second window,
  re-snapshot on 1013, parsing of Rex's marked messages (resize, theme, child exited).
- Terminal mirror: the libghostty-vt terminal per open block, touched by one thread only,
  producing VT redraws by the rules under Architecture. Ghostty is built in the same optimize
  mode as the bridge (Phase 0: a Debug Ghostty was about 400 times slower).
- Input: one ordered queue per terminal. One `terminal.write` in flight, the rest coalesced; a
  `client.key` or `block.event` waits until the write before it has answered.
- Ownership: check what `session.own_block` changes against `block_owner_changed` and the
  `owner` field of `resize` (Phase 0 saw `owner: null` after a take).
- Recovery from a Rex server restart, as Phase 0 saw it (finding 11): the control connection
  ends without a close frame, data gets 1001 `data provider canceled`, the old tokens give a new
  client and a refused resume, and sessions and blocks keep their IDs but come back with new
  programs and empty screens. Reconnect, re-attach, get new tickets, replace each mirror with
  the new snapshot and redraw viewers. Test it against the fake server; re-test for real only
  with the owner's approval.
- Test hygiene: every live test names its sessions `rweb-test-`, closes them even when it fails,
  and passes `-s` and `-b` to any `rex` CLI call.
- Typed calls for the methods the first version needs: list and inspect sessions, windows and
  blocks; create, rename, close; terminal write, key, resize, format, process; block ownership.
- A fake Rex server built from the protocol document, with snapshots made by libghostty-vt's
  encoder, for tests that need no real Rex.
- Fuzz tests (`zig build test --fuzz`) for every parser that reads bytes from outside: the
  control JSON, data handshake, `rex1` messages, and later the browser protocol and HTTP headers.

Exit: tests pass against the fake server and against a live local Rex using throwaway sessions,
on both Rex versions in use.

### Phase 2: bridge server

- One binary: serves the embedded frontend, a small JSON API and one browser WebSocket.
- The browser protocol and fan-out described under Architecture.
- Access control as in Constraints, plus an observe-only mode that never writes, resizes or takes
  ownership.
- Sizing: a browser draws the terminal at Rex's size and scales or scrolls to fit. It changes the
  size only when the user asks, by taking ownership and resizing; a desktop client that owns the
  block keeps its size otherwise.
- WebSocket ping both ways; the browser reconnects on its own.
- The frontend embeds xterm.js with its licence; nothing loads from a CDN.
- A join sends a capped amount of scrollback (Phase 0: a full-scrollback redraw was 774 KB),
  with more on request.

Exit: a terminal works end to end from a browser through Tailscale Serve on a test port,
including typing from a real phone, and the access checks (wrong user, forged headers on the
socket, the node's own address, Funnel, wrong Origin, observe-only) are each shown to refuse.

### Phase 3: frontend

- Session and terminal list with live updates; one terminal full-screen; reconnect with state
  kept; touch keyboard helpers (Esc, Ctrl, Tab, arrows), paste, font size.
- Copying on a phone: xterm.js has no touch selection (Phase 0, finding 13), so a select mode
  shows the screen and scrollback as plain text for the phone's own selection handles.
- Soft-keyboard input: Enter and Backspace through xterm.js while a soft keyboard is in use, and
  no stray DEL after Enter (Phase 0, finding 12), tested on a real phone in a shell and in an
  editor.
- Create, rename and close sessions and terminals, with a confirmation before closing.

Exit: daily use from a phone and a laptop browser for a week without falling back to SSH.

### Phase 4: packaging and deployment

Status 2026-11-23: exit met for linux-box and desktop-mac; what changed from this plan, and what is open, is in
[phase4-result.md](phase4-result.md).

- Security review of the bridge before any deployment.
- Release builds for Linux x64 and macOS ARM64 (`ReleaseSafe`) with checksums, libghostty-vt
  compiled in. libghostty-vt compiles C++ (simdutf, highway) and links `libc++`, so a static Linux
  binary needs libc++ linked statically (likely a musl target); check before packaging.
- A `rweb` module in `setup-repo`: pinned version and checksum, a systemd user unit on Linux
  (ordered after Rex's user server) and a LaunchAgent on macOS, the bridge's socket path, and the
  Tailscale Serve mapping as an operator step on a port no other service uses.
- On macOS the bridge starts a personal Rex server (with the bundled CLI, as an `ssh://` client
  does) when none is running; it never changes Rex's listeners or config.
- Start after login and reboot behaviour verified on linux-box, then gateway-box, then desktop-mac.

Exit: each machine in scope serves rweb after a reboot, recorded in setup-repo.

### Owner's decision (2026-11-25): distribution means both

Release builds go first to the owner's own machines (Phase 5), then to other people (Phase 6).
Before either: the owner's open feedback items ([feedback.md](feedback.md)) and the name.

### Owner's decisions (2026-11-26), from the fifth review

Record: [security-review-2026-11-26-round5.md](security-review-2026-11-26-round5.md).

| Decision | Choice |
| --- | --- |
| Command line | Redesigned with sane security defaults: one command per supported layout (`rweb tailscale`, `rweb ssh`) that makes its own secret, token and folders and prints the one step left. Every refusal says in plain words what is wrong and the fix. No flag that loosens a check is added. The existing options stay, under "Advanced". This brings forward part of Phase 6's "Generalise" (no config file yet). |
| SSH tunnel | A unix socket on the Rex machine, not a port; a token form instead of a token in the address; in token mode a dropped page reconnects only on a tap. |
| Groups | No group is trusted, on Linux or macOS (the round-3 decision "private groups pass" is withdrawn). macOS `admin` passes only for folders above an item and for programs. |
| Disks | Local disks only: network, FUSE, user-mounted and unknown filesystems are refused; `--config-dir` moves rweb's files. |
| README | "About this project" states that the project was built with AI coding assistants; it is the only such mention (AGENTS.md). |

### Phase 5: release builds for the owner's machines

0. **Name: decided 2026-11-25, the owner keeps `rweb`**, described as "a web client for Rex (not
   affiliated with Superlogical)". Evidence: trademark policies (Docker, Linux Foundation, Rust,
   Mozilla, PSF) allow "name for X" and restrict X-prefixed names, so `rex…` names would risk a
   forced rename in Phase 6; `rweb` is free on Homebrew, Arch/AUR, Debian, npm and PyPI (only a Rust
   library crate shares it); it follows the `tmate` pattern. The research behind it is kept
   in the owner's knowledge base.
   Original brief: settle the name before the first versioned release, from external research
   (collisions in Homebrew, Arch/AUR, Debian, crates.io, npm, PyPI and GitHub; Rex trademark;
   short, easy to type and remember). A rename touches the repo, binary, setup-repo module, unit and
   LaunchAgent names, config paths, browser storage keys, the `rweb-test-` rule and the owner's repository index; plan
   it as one change with a migration of both live hosts.
1. **Version** (done 2026-11-25: `build.zig.zon` 0.1.0, `CHANGELOG.md`, `rweb --version` on stdout with
   commit from `-Dcommit` or git, `unknown` in an export without either; the bridge reports the
   version to Rex). Semantic version from 0.1.0 in `build.zig.zon`, a `CHANGELOG.md`, and a
   `--version` flag printing version, commit, Ghostty pin and the Rex API revisions supported.
2. **`zig build dist`** (done 2026-11-25; Linux is static musl instead of glibc; results and the
   reproducibility measurements in [phase5-result.md](phase5-result.md); `tools/release.sh` builds a
   commit reproducibly). Cross-builds `ReleaseSafe` binaries on one machine for macOS ARM64 and
   Linux x86-64 (glibc, pinned version), each in `<name>-<version>-<target>.tar.gz` with the
   binary, LICENSE, third-party notices (xterm.js MIT, wterm Apache-2.0, Ghostty MIT,
   libghostty-vt's C++ libraries) and a README, plus `SHA256SUMS`.
3. **Prove it** (done 2026-11-25, see phase5-result.md; byte equality holds on one machine at one path,
   not across machines with different Zig builds). The Linux artifact runs on linux-box with the full test suite, live tests
   included; two builds of the same commit are compared for byte equality.
4. **Publish** (not yet: on the owner's word the release binaries run on the machines first; see
   phase5-result.md. Before it, two independent reviews (release readiness, security) and their fixes:
   [release-review-2026-11-25.md](release-review-2026-11-25.md); then a rescan and an internal adversarial
   review, fixed by mechanism: [security-review-2026-11-25-round2.md](security-review-2026-11-25-round2.md),
   then a third round: [security-review-2026-11-25-round3.md](security-review-2026-11-25-round3.md),
   a fourth with the live test: [security-review-2026-11-25-round4.md](security-review-2026-11-25-round4.md),
   and a fifth, which redesigned the command line: [security-review-2026-11-26-round5.md](security-review-2026-11-26-round5.md);
   its live run on macOS and Linux and its simulator and phone tests come before the release). A GitHub Release on the private repository (the owner approves each release);
   hosts fetch with `gh release download`.
5. **setup-repo** (done 2026-11-25: installs the pinned archive, build fallback kept; live on laptop-mac,
   desktop-mac and linux-box). The pin becomes version plus SHA-256 per platform; the hook downloads,
   verifies and installs, keeps the previous build for rollback, and keeps building from source
   as a fallback. The runbook's update path becomes: tag, `tools/release.sh <commit>` (it tests and
   builds that commit's clean export with the pinned Zig; `zig build dist` alone packs the working tree),
   release, bump the pin, apply.

gateway-box (owner, 2026-11-25) gets rweb only once this phase's release binaries exist; it has no module yet.

Exit: every host in scope (linux-box, desktop-mac, laptop-mac, then gateway-box) runs the released artifact and serves it after a reboot (this includes linux-box's
pending reboot check), recorded in setup-repo.

### Phase 6: distribution to other people

Gates, all before any public step (**all met 2026-11-26**):

- Superlogical's answer on third-party clients and on the name: **given 2026-11-22** in Superlogical's
  Discord: no restrictions on making Rex clients; they asked that Rex's logo (the dinosaur) not be used.
  rweb's logo is its own.
- A licence for the project, compatible with the vendored code: **decided 2026-11-25, MIT**, the same as
  Ghostty and libghostty-vt (owner's choice).
- A public repository without the owner's setup: **done 2026-11-26, a different way than planned.** The
  owner chose to rewrite this repository's history rather than start a new one: in every file version
  and commit message the tailnet, host and setup-repository names became generic, commits are authored
  by the owner's GitHub no-reply address, and the README names the maintainer. The rewritten history
  went to a new public `lexlapax/rweb`, and the old private repository was deleted, so GitHub holds no
  copy of the old objects. v0.1.1, v0.2.0 and v0.3.0 are GitHub Releases there.

Where the steps below stand (2026-11-27):

- Step 1: the command line was generalised in round five (`rweb tailscale`, `rweb ssh`: no owner flags,
  secrets and folders made, plain refusals with a fix) and the user guide covers Serve on Linux and
  macOS. `rweb doctor` since 0.3.0: checks Rex, the files, the bridge, Tailscale and
  Serve as the command it names would use them, and says what to fix.
- Step 2: rounds five and six reviewed rweb for other people's machines (shared hosts, groups, disks,
  procedures). Done for now; repeat when step 1 or 3 changes much.
- Step 3: made 2026-11-27: a Homebrew formula (release binary, macOS ARM64
  and Linux x86-64, `brew services`), an AUR package `rweb-bin` (with a systemd user unit), and the
  services in the archive (`contrib/`); `tools/packaging.sh` makes them from a signed release
  ([packaging/README.md](../packaging/README.md)). Published 2026-11-27 at 0.2.0, updated to 0.3.0:
  the tap `lexlapax/homebrew-rweb` and the AUR package `rweb-bin`; each release updates them.
- Step 4: tagged releases with checksums and notes, and the Rex revisions in `rweb --version`: done.
  Signed checksums: from 0.3.0, `SHA256SUMS.sig` (`ssh-keygen -Y sign`, namespace `file`, key
  `rweb-release` in `tools/release-signers`, the README and the user guide; held in the owner's 1Password
  and used through its SSH agent).
- Step 5: done 2026-11-27 (`tools/vendor/rebuild.sh`, [vendored-browser-code.md](vendored-browser-code.md)):
  every vendored file rebuilt byte-identical from integrity-checked npm packages, the wterm bundle by the
  pinned esbuild. `ghostty-vt.wasm` is checked against its published package, not rebuilt from source:
  it is wterm's own module, which the pinned Ghostty does not produce.
- Added by the owner, 2026-11-27: an update check. The bridge asks GitHub's latest-release API daily and
  tells a newer version (log, page, `rweb doctor`); on by default, `--no-update-check` turns it off. In
  0.3.0.
- Added by the owner, 2026-11-27, for after 0.3.0 and before new features: a check of the upstreams rweb
  pins (Rex, Ghostty's libghostty-vt, Zig, the vendored browser packages) for changes to account for.
  Done: `tools/upstream-check.sh` ([upstream-check.md](upstream-check.md)). First run after 0.3.0:
  Ghostty `vt-1.0.2` is out (rweb pins `vt-1.0.1`); everything else as pinned or kept on purpose.
- Exit: not met (nobody else has installed it from a channel).

Then:

1. **Generalise.** A config file instead of owner-specific flags (owner login, tailnet,
   listen mode); a `doctor` command that checks Rex's socket, Tailscale, Serve and permissions;
   docs for setting up Tailscale Serve on Linux and macOS. Single user per install and
   tailnet-only stay as they are.
2. **Security review again** for other people's setups (no owner-specific assumptions left).
3. **Channels.** A Homebrew formula (a tap; building from source avoids notarization, prebuilt
   macOS binaries would need signing and notarization), a Linux tarball with a systemd user unit,
   and an AUR package.
4. **Release process.** Tagged releases with checksums and notes; a stated Rex
   version/revision support range; signed checksums.
5. **Rebuildable browser code.** Every vendored file rebuilt from recorded sources and compared: the wterm
   bundle from its packages fetched by npm integrity with a committed entry file and build script,
   `ghostty-vt.wasm` built from the pinned Ghostty, xterm.js checked against npm's integrity
   (see `phase3-result.md`, "Provenance").

Exit: someone else installs it from a published channel on Linux and macOS and reaches their own
Rex from a phone, following only the docs.

### Later, not planned in detail

- Draw a Rex window's split layout.
- Reuse the client library as an attach program for an Ovis fork, if Ovis's views are wanted.
- Ask Ovis's maintainer what
  its `alt-runtime` slot is for.

## Risks

| Risk | What limits it |
| --- | --- |
| Rex's stream cannot be rendered in a browser | Retired: Phase 0 showed it rendered correctly through the bridge-side mirror. |
| Rex changes its API | Pinned revision; the server still accepts old ones; the fake server and live tests show breakage early. |
| A Rex update changes the snapshot format | Pinned libghostty-vt; the bridge checks the snapshot version and refuses an unknown one; the format repaint route remains as a fallback. |
| The browser sends query replies as input | Handlers that swallow queries; Phase 0 showed they are needed and that they work. |
| The bridge becomes a way into every terminal | Unix socket behind Serve, peer and identity checks, own-address and Funnel refusal, Origin check, no anonymous Rex listener, a security review before Phase 4. |
| A Zig release breaks the bridge's code or its libraries | Zig pinned with libghostty-vt; upgrades are one deliberate change; few dependencies, pinned by hash. |
| A memory-safety bug in the bridge | `ReleaseSafe` builds, plain ownership, fuzzed parsers, and the security review before Phase 4. |
| Rex ships its own web client | The project is small by design; stop if that happens. |
| Licence terms forbid third-party clients | None found; ask the vendor before any public release. |

## Open questions for the build

- Whether Serve's own-address identity, read from Tailscale's source, behaves as read (tested in
  Phase 2).
- How much scrollback a join sends by default (Phase 2).
- How to stop xterm.js sending a DEL after Enter on Gboard (Phase 0, finding 12; Phase 3).
