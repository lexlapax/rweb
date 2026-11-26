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
