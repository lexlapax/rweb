# Changelog

Versions follow [semantic versioning](https://semver.org). Newest first. `rweb --version` prints the
version, the commit it was built from, the build mode and target, the Ghostty (libghostty-vt) tag and
the Rex API revisions it speaks.

## Unreleased

- `rweb doctor [tailscale|ssh] [options]` checks a setup and says what to fix: Rex (running, answering,
  a revision rweb speaks), the secret, token and upload folder (as at startup), whether a bridge is
  listening, and for Tailscale its sign-in, HTTPS certificates and a Serve entry that forwards to this
  bridge with Funnel off. It changes nothing, never prints a secret, and exits 1 when a check fails.
- When the page reports a failure it says what happened in words ("Rex did not answer in time", "the
  terminal's output could not be reached"), not an internal error name; the name goes to rweb's log.
- Building: the page's files are compressed and given their validators at build time, not on the first
  request.

## 0.2.0 (2026-11-27)

Works with Rex 0.1.0-preview.25, is quicker to react and lighter on busy terminals, and is the result of a
pass over the whole code against Zig practice for production code
(`docs/zig-idiom-audit-2026-11-26.md`, in the source repository). No options, files or Serve entries
change: install the archive over 0.1.1 and restart rweb.

Rex:

- rweb speaks Rex API revisions 18 to 24 (Rex 0.1.0-preview.25 is revision 24; 0.1.1 spoke 18 to 19).
  Nothing rweb uses changed in 20 to 24, and an older server is still served at its own revision.
- The list shows terminals only: Rex's other blocks (its file-transfer blocks, new in preview.25, and its
  onboarding walkthrough) have no terminal to open and are left out.
- Each answer from Rex is parsed once and read into a typed structure, and requests are written in one
  pass; a tree refresh with 50 sessions makes 63 % fewer allocations. A malformed answer is refused more
  strictly (a field of the wrong type is an error, not ignored).

The page:

- A terminal that closes leaves the page at once (it took up to 0.2 s), and opening one is a few
  milliseconds faster. One browser's request that Rex is slow to answer (a folder listing, say) no longer
  holds up another browser's: before, every request to Rex waited for the one in progress.
- The logo at the top left, and "About rweb" in the ⋯ menu, open rweb's page on GitHub in a new tab,
  without sending this page's address (it names your machine).
- The logo turns slowly while the terminal on screen prints, and rests upright once it is quiet (still
  with reduced motion).

Speed and memory:

- Terminal output reaches the page without memory allocations once warm (before: one per chunk for each
  viewer, and two per chunk read from Rex); a keystroke makes 4 instead of 23. Linux: about 12 % less CPU
  and half the page faults on a 32 MiB burst to three viewers. Measured with a fixed workload
  (`src/bridge/bench.zig`); the memory allocator stays the safe one, now as a stated decision.

Fixes:

- A double free in the terminal mirror when memory ran out as a stream reconnected.
- When a transfer could not be registered for lack of memory the page said "too many transfers"; it now
  says what happened.
- If something the bridge relies on internally turns out wrong, it stops (a service set up as the user
  guide shows starts it again) instead of carrying on with damaged state.

The log:

- It no longer repeats what the terminal emulator thinks of a program's output (unknown escape sequences,
  bad colours), which any program could fill it with; the emulator's other errors still show.
- A connection that ends on a socket error says which (`ConnectionResetByPeer`, say), not only
  "ReadFailed".

Release archives, building and the project:

- The archive carries the README's screenshots (they were missing, so its pictures were broken).
- `zig build --help` says a plain build is Debug (for tests; the terminal emulator runs much slower) and
  ReleaseSafe is what releases ship; `zig build --release` alone now means ReleaseSafe. `zig build fuzz`
  takes `-Dtest-filter` to fuzz one target; `tools/release.sh` stops a test that hangs after 60 s.
- New tests: every type that owns memory and every parser fails each of its allocations in turn; fuzz
  targets for the paste cleaner, the escape-sequence cut, the mount table and ACL parsers; random
  terminal output for the mirror. The suite ran clean under Valgrind on Linux.
- README: screenshots of the page on a desktop and on a phone. Issues are for bug reports, through a bug
  report form; pull requests are turned off on GitHub.

## 0.1.1 (2026-11-26)

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
- `tools/release.sh` refuses a release folder that is a link or another user's, refuses an unrecognized
  non-empty folder before changing its mode, makes its own private (`0700`, with extended ACLs stripped)
  before building in it, and keeps nothing found in it: the source and the Zig cache are made
  new by every run (remove an old `/tmp/rweb-release` once).
- The page has a logo: a favicon, home-screen icons for iOS and Android with a web app manifest (added to
  a home screen, it opens without the browser's bars), and the logo at the left of the header. Sources
  and rules: `assets/logo/`.

From the second review (details: `docs/security-review-2026-11-25-round2.md`, in the source repository):

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

From the third review (details: `docs/security-review-2026-11-25-round3.md`, in the source repository):

- Fixed: an open refused by the rate limit left the bridge on the old terminal while the page showed the
  new one, so typing could go to a terminal not on screen. A refused open now also leaves the old
  terminal, refusals name the request, and the page types only into the terminal it has confirmed.
  Reads (info, clipboard, tree, 16 a second) and work (8 a second) have separate allowances, and
  opening, redraws and Copy share a budget across all browsers.
- Fixed a race in which a terminal closing while a browser opened it could leave that browser on the
  closed terminal's output list.
- Queues: output in tiny pieces joins one frame (each frame also counts 64 bytes); at most one theme is
  queued; a browser that falls behind is redrawn at most once a second; "all scrollback" applies once;
  redraws and Copy are capped in cells as well as rows; one Copy at a time; the tree is sent only when
  newer; at most 32 browsers at once; pings count against a per-second limit.
- A connection waiting on a slow Rex call is not dropped as silent; directory listings, downloads and
  terminal info time out after 5 seconds.
- Pastes: a multi-line paste into a program without bracketed paste asks first; the bridge also removes
  ESC and C1; text a phone keyboard inserts in one go is treated as a paste; a paste over 32 KB is refused
  with a message; program-set clipboard text is shown without control characters.
- The unix socket: an absolute path, every folder above it checked, the folder kept open, and the socket
  removed at shutdown only if it is still rweb's. (Links on the path: see the fifth review below.) Rex's socket must be served by your own
  user, and on macOS the app's socket is tried first. `tailscale` is run from `--tailscale PATH` or fixed
  locations, never from `PATH`, and must pass the same folder checks. The upload folder is created only
  after its parent folders pass, and the real path is pasted.
- Folder checks accept macOS's `admin` group. (They also accepted a group-writable folder whose group
  holds only you; the fifth review removed that, see below.)
- The Rex client: a frame is written whole even if its task is cancelled; closing during a reconnect
  returns at once; a stream that breaks the protocol ends instead of resuming forever; message limits
  from the first read (64 KiB in handshakes, 1 MiB per data message); a fired handshake deadline fails
  the handshake; a terminal's stream is closed cleanly; a long input write is never cut inside an escape
  sequence; cancellation passes through every call.
- `rweb --version` shows the commit being built (it is read at build time, not cached from an earlier
  configure); `-Dcommit` still overrides it.
- Tests: every test bridge uses a random token, and the stand-in Rex serves files only from its own
  folder.
- Docs name reviewers generically.

From the fourth review (details: `docs/security-review-2026-11-25-round4.md`, in the source repository):

- Fixed: pastes containing characters such as `’ “ — € ß`, Cyrillic, emoji or much CJK text were mangled
  or lost by the bridge's paste cleaning (it removed UTF-8 continuation bytes); and a race between the
  paste check and a stream restart.
- The terminal mirror no longer runs kitty graphics or the glyph protocol, which a program could use to
  make it hold hundreds of megabytes or spend quadratic time; control strings are kept to 64 KiB,
  scrollback to 10,000 rows and 32 MiB, and redraws and Copy text to fixed byte budgets (a redraw carries
  less history rather than more memory).
- Access control lists are checked (Linux POSIX ACLs and macOS ACLs) on the secret files, the upload and
  socket folders, the `tailscale` program and the folders above them; file systems another user mounts
  are refused (the group and disk rules were tightened again in the fifth review, below); `tailscale` is run by exactly the path that was checked, and a refused install location is
  final.
- Writes to Rex have deadlines; an idle terminal's stream is resumed rather than restarted after repeated
  drops; typed input is never cut inside an SS3 key or an X10 mouse report.
- The page: an error or `closed` for a terminal it has moved away from is ignored; a terminal being restored
  is retried while Rex is restarting instead of forgotten; queued uploads stop when you switch terminals;
  `open` errors name their terminal and whether they may pass; `open` no longer counts against the hub-wide
  budget.
- Startup no longer re-announces the first connection to Rex (two tests raced it on Linux).
- Releases: `tools/release.sh` runs the tests on the exported commit first, refuses a Zig other than the
  pinned one unless told otherwise, and writes `BUILDINFO`; a build from a changed working tree shows
  `-dirty` in `rweb --version`; the docs name `tools/release.sh` as the only release path.
- The Phase 0 spike is removed from the tree (it loaded xterm.js from a CDN; it is in Git history).
- The page, from live testing on phones: the key bar's Paste acts on a completed tap that ends on it (a
  touch meant for End next to it could open the paste dialog); only terminal text, the Copy view and
  fields can be selected, so a long press or "Select all" copies terminal text instead of the page's
  labels and hidden dialogs; typing right after switching terminals reaches the new terminal.
- README: "About this project"; `CONTRIBUTING.md`. Vendored browser code: what is and is not known about
  its provenance is recorded, and a rebuild from recorded sources is planned for Phase 6.

From the fifth review (details: `docs/security-review-2026-11-26-round5.md`, in the source repository):

- Two commands set rweb up, one for each supported way in. `rweb tailscale`: behind Tailscale Serve,
  only your own Tailscale login (Linux: the unix socket `$XDG_RUNTIME_DIR/rweb/bridge.sock`; macOS:
  `127.0.0.1:7695` behind a secret). `rweb ssh`: for an SSH tunnel, a unix socket only your own user can
  connect to and a token. Each makes what it needs (a missing secret or token, 32 random bytes, mode
  `0600`; missing folders `0700`; nothing existing is replaced), keeps it in `$XDG_CONFIG_HOME/rweb` or
  `~/.config/rweb`, and prints the one step left: the `tailscale serve` line, or the `ssh` line for your
  laptop. `--config-dir PATH` moves the files; `--port N` changes the port. `rweb` alone prints a short
  help. The 0.1.0 options all still work, alone or added to a command; `rweb --help` lists them under
  "Advanced" and the test-only ones under "For tests".
- Every refusal at startup is a plain sentence that names what is wrong, and for a file or folder a
  `Fix:` line with the command that puts it right. Internal error names no longer appear.
- rweb takes its socket or port first and keeps it. When Tailscale or Rex is not up at start it no longer
  exits: it says so, at most once a minute, and asks again. Requests wait unanswered until Rex is up. A
  socket path too long for the system is refused before anything is made.
- A loopback port is held on `[::1]` as well as `127.0.0.1`, so `localhost` cannot lead to another
  account's listener; a port taken on either is refused with a message.
- SSH tunnel: the documented setup is a unix socket on the Rex machine (a port there is free while rweb
  is down, and another account could take it and receive the token). A token on a `--listen-tcp` port
  still works and prints a warning.
- SSH tunnel: the page at `/` is a token form. The token is sent once in a request header, never in the
  address, and the answer is the redirect to `/s/<id>/` with the cookie. `/?token=` still works.
- SSH tunnel: after a dropped connection the page shows "Disconnected" and a Reconnect button instead of
  retrying by itself, and each tap makes one attempt, so nothing is sent to whatever holds the port
  unless you ask. Behind Tailscale the page reconnects by itself as before.
- Behind a token, rweb answers only for `127.0.0.1`, `localhost` and `[::1]` unless `--allow-host` says
  otherwise, and refuses a token that arrives from another website, even a right one (a link on another
  site cannot sign you in; type or bookmark the address).
- An upload is written in a folder of rweb's own inside the upload folder (`.rweb-partial/`), flushed to
  disk, and only then given its real name in the upload folder, so a stop, a crash or a power cut never
  leaves a file there that looks whole and is not. If rweb is stopped in the middle, the next start
  removes what was left. An unfinished upload stays locked while it is written: a second rweb using the
  same upload folder leaves it alone when it starts. Nothing outside `.rweb-partial/` is ever removed.
- An uploaded file's path is typed into the terminal through the same queue as your typing, and only if
  the page is still on that exact terminal view and may still write when the upload ends. If you switch
  terminals (even away and back), disconnect, or turn on "View only" while a file is queued or on its way,
  the upload token is revoked (404) or refused (403) and nothing is saved; in the last moment, when the file
  is already saved, the page says its path was not typed.
- A paste, "Reset terminal", "Fit terminal to this window", an upload, Copy/clipboard replies and the download
  picker go to the terminal view that was on screen when you asked, or nowhere. Before, a paste that waited
  for the clipboard (the browser may ask first) or for the Paste box could go to another terminal if the view
  changed meanwhile. These messages now name their terminal and the bridge refuses one for any other. A page
  left open from an earlier rweb is told to reload.
- rweb gives `tailscale` ten seconds in all, for its answer and its exit, and reads at most 1 MiB from
  it; past that it and its process group are killed. A `tailscale` (or child it spawns) that hangs, keeps
  printing, closes its output and stays, or ignores being asked to stop cannot stall the check of this
  machine's own addresses.
- If Tailscale has not confirmed this machine's addresses for two and a half minutes (on the boot clock,
  which keeps counting while the machine sleeps; a wake triggers a refresh promptly), rweb refuses requests
  until it does: an address the machine may have gained meanwhile cannot slip past the rule that refuses
  requests from the machine itself. Not with `--own-address` alone (a list you gave does not go out of date)
  or `--allow-own-address`.
- Wrong tokens are limited: after 10 in a minute, wrong tokens get 429 until the minute ends. A right
  token is never refused, and a web page on another site cannot use up the allowance.
- **Upgrade note:** a token must be at least 32 characters (0.1.0 accepted 16), in a token file and with
  `--token`.
- **Upgrade note:** no group is trusted. A folder or program its group can write to is refused, on Linux
  and macOS, even when the group holds only you; the message gives the `chmod g-w` that fixes it. macOS's
  `admin` group passes only for folders above an item and for programs. A secret, token, upload folder or
  socket folder may have no access list entry for any group.
- **Upgrade note:** only local disks are trusted. A secret, token, upload folder, socket folder or
  `tailscale` program on a network disk (NFS, SMB), a FUSE filesystem, a disk image, a disk a user
  mounted or a filesystem rweb does not know is refused. With a home folder on a network disk, use
  `--config-dir`.
- Links on a checked path are followed only when root or you own them and the folder they sit in has
  passed its checks; the item itself is never opened through a link.
- This machine's own Tailscale addresses are read again every minute while rweb runs, so a request from
  a new address of the machine is refused too. Startup messages no longer suggest `--allow-own-address`.
- Docs: the user guide is written around the two commands, with the options in "Advanced: every option";
  what "your login" covers (every device and account signed in to Tailscale as you); how to stop or
  remove rweb; the tunnel's known limit (plain HTTP on loopback cannot prove who is answering: use it
  only on devices nobody else uses).
- README: "About this project" says the project was built with AI coding assistants.
- Release archives include the README's logo (`assets/logo/`); the third-party notices record what is
  known about each vendored file's provenance.

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
