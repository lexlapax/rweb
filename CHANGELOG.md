# Changelog

Versions follow [semantic versioning](https://semver.org). Newest first. `rweb --version` prints the
version, the commit it was built from, the build mode and target, the Ghostty (libghostty-vt) tag and
the Rex API revisions it speaks.

## 0.1.0 (not yet released)

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
