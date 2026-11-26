# Changelog

Versions follow [semantic versioning](https://semver.org). Newest first. `rweb --version` prints the
version, the commit it was built from, the build mode and target, the Ghostty (libghostty-vt) tag and
the Rex API revisions it speaks.

## 0.1.1 (not yet released)

- A machine that is a tagged Tailscale device has no owner login: `--owner-from-tailscale` now refuses
  to start there and says to pass `--owner LOGIN --allow-host NAME` (before, rweb started and refused
  everyone).
- User guide: tagged machines.
- Licence: MIT, the same as Ghostty and libghostty-vt; `LICENSE` is in the repository and the release
  archives.
- SSH tunnel: the token's cookie is now scoped to the page's own path, `/s/<id>/`, which `/?token=`
  redirects to. Before, it was scoped to the whole host, and a browser sends a host's cookies to every
  port: another web service on `127.0.0.1` could receive the token, and two tunnels on two ports
  overwrote each other's sign-in. Bookmark the address you land on. The page uses relative addresses.
- A token file may hold only letters, digits, `-` and `_` (the user guide's command makes such tokens).
- `--own-address` must be an IP address; before, a malformed one quietly turned off the refusal of
  requests from the machine itself. Discovered addresses are checked too, and the access check refuses
  everything if an own address cannot be compared.
- Opening a terminal decodes Rex's snapshot once, when all of it has arrived (found from its framing),
  instead of after every chunk; the 256 MiB limit holds for complete snapshots too and fails from a
  record's header, before its bytes arrive. Opening no longer blocks other browsers while it waits.
- When every pending connection slot is taken, the oldest connection that has not sent a request is
  dropped for the new one, so idle local connections cannot lock the owner out.
- Malformed `tailscale status --json` is an error at startup, never a crash.
- `tools/release.sh` refuses a release folder that is a link or another user's, and makes its own
  private (`0700`) before building in it.

From the second review (details: `docs/security-review-2026-11-25-round2.md`):

- Fixed a deadlock: a management action (new session, rename) racing the first open of a session could
  hang the bridge. Fixed use-after-free crashes when a terminal closed (its shell exited) while a browser
  typed into it, switched away or closed. A terminal is now kept alive by a reference from every viewer
  and every task using it, and the last one destroys it.
- No waiting on Rex while holding the hub's lock: attaching, opening a stream and restarting one happen
  outside it, so a slow or stuck terminal no longer freezes the other browsers.
- Every browser's queue is bounded in bytes and frames. State updates (mode, Rex up or down, theme, the
  session list) replace their own queued copy, and `closed` and `exited` always get through, so a
  busy terminal can no longer hide them. "Load all scrollback" and the Copy view send at most the last
  10,000 and 20,000 rows; the Copy view shows at most 5,000 lines and says when it cut.
- Opening, sizing and terminal actions count against the per-browser limit of 8 heavy requests a
  second; the 200-messages-a-second limit is a hard cap per second. A browser that stops reading is
  dropped after 30 seconds, and the 20-second silence check runs even while output keeps flowing.
- Pastes: every paste, in both terminals and from a phone keyboard, goes to Rex as a paste with ESC and
  C1 control characters removed, so a pasted text cannot end bracketed paste early and type the rest as
  commands.
- `?term=` in the address applies to that page load only; `?dbg=1` works only when rweb runs with
  `--debug-input`.
- Upload tokens belong to the page that asked: they are withdrawn when it turns read-only or leaves,
  and refused when it has moved to another terminal, both when the upload arrives and before its path is
  pasted. A transfer that sends nothing for 30 seconds is cut. Token lifetimes count while the machine
  sleeps.
- Secret files, the token file and the upload folder are checked on an open descriptor and used through
  it; every folder above them must be root's or yours and not writable by others. The upload folder is
  opened once at startup. The unix socket's folder must be yours. **Upgrade note:** rweb now refuses to
  start when one of these sits under a folder another user can change; the error names the folder.
- `--owner` requires `--allow-host` (unless `--owner-from-tailscale`); `--token` follows the token-file
  rules; `--random-token` prints its address only to a terminal.
- A request target with a control byte or a space is refused; the `/s/<id>` redirect comes after the
  access check and encodes what it copies. Responses that set the token cookie are not cached;
  vendored scripts are revalidated on every load. `/api/tree` needs `--enable-lab`.
- The Rex client: a ceiling of 16 MiB per message whatever Rex advertises, reconnect tokens of at most
  256 printable bytes, 10-second handshakes, JSON nested at most 64 deep, Rex's events in a bounded
  ring, the welcome built without an assertion, ownership fixes on reconnect and close, the input queue
  bounded in bytes for every kind of input, and a duplicate response no longer leaks.
- The terminal mirror: resizes outside 1-4,096 per side or over 1,048,576 cells are ignored; a mirror
  that fails is restarted instead of freezing; fixed memory leaks (the escape-sequence parser's buffers,
  theme strings) and a double free on out-of-memory. Rex's in-band messages are split off by a rewritten
  splitter that never reorders program output (the old one could swap an ESC and the byte after it).
- Fuzzing covers the splitter against a reference model, snapshot framing and WebSocket message
  reassembly.
- Docs: the macOS Tailscale layout is for a Mac where you are the only local account; the SSH tunnel's
  `/s/<id>/` address is as private as its token; checksums detect damage, not tampering.
- `tools/release.sh` will not overwrite a version it already built; `tools/dist.sh` removes its stage
  after packing.

## 0.1.0 (2026-11-25, built and installed; not published)

The first numbered version: the bridge and page as used daily on Linux and macOS, plus the fixes from
the first days of that use.

- Purpose: reach your Rex sessions from a phone, tablet or laptop browser when you are away from the
  machine, for quick answers and commands. One rweb per machine.
- Bridge: one binary next to a Rex server, talking to Rex's own unix socket only (API revisions
  18–19); serves the page behind Tailscale Serve on a unix socket (Linux) or loopback TCP with a
  secret first path segment (macOS), or on loopback with a token behind an SSH tunnel; accepts only
  your own Tailscale identity, checks Host and Origin, refuses the machine's own address and Funnel.
- Terminal: a libghostty-vt mirror per terminal (Ghostty `vt-1.0.1`), exact redraws for every browser that joins,
  history on open (1,000 lines, more on request); wterm in the browser by default, xterm.js as a
  fallback.
- Page: sessions and terminals (create, rename, close), tab strip, phone layout with a key bar,
  fit-to-screen on touch devices, view-only switch, Copy view, terminal info and program status,
  clipboard from the terminal, clear and reset.
- File transfer (off unless enabled): downloads through Rex, uploads into one folder, one-time tokens.
- Key bar: Enter is the first key.
- Phones: a drag over a full-screen program (alternate screen) scrolls it, as a mouse wheel would;
  touch diagnostics in the ⋯ menu, off by default.
- `rweb --version`; the bridge reports its version to Rex instead of `0.0.0`.
- Releases: archives for macOS (Apple silicon) and Linux x86-64 (static), with `SHA256SUMS` and
  third-party notices; documentation: README, user guide, architecture. Windows support will come later.
