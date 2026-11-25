# Changelog

Versions follow [semantic versioning](https://semver.org). Newest first. `rweb --version` prints the
version, the commit it was built from, the build mode and target, the Ghostty (libghostty-vt) tag and
the Rex API revisions it speaks.

## 0.1.0 (not yet released)

The first numbered version: what has run on the owner's machines since Phase 4, plus the fixes from
the first days of daily use.

- Bridge: one static binary next to a Rex server, talking to Rex's own unix socket only (API revisions
  18–19); serves the page behind Tailscale Serve on a unix socket (Linux) or loopback TCP with a
  secret first path segment (macOS); accepts only the owner's Tailscale identity, checks Host and
  Origin, refuses the node's own address and Funnel.
- Terminal: a libghostty-vt mirror per terminal (Ghostty `vt-1.0.1`), redraws by Phase 0's rules,
  history on open (1,000 lines, more on request); wterm in the browser by default, xterm.js as a
  fallback.
- Page: sessions and terminals (create, rename, close), tab strip, phone layout with a key bar,
  fit-to-screen on touch devices, view-only switch, Copy view, terminal info and program status,
  clipboard from the terminal, clear and reset.
- File transfer (off unless enabled): downloads through Rex, uploads into one folder, one-time tokens.
- Key bar: Enter is the first key (feedback 1).
- Phones: a drag over a full-screen program (alternate screen) scrolls it, as a mouse wheel would
  (feedback 2); touch diagnostics in the ⋯ menu, off by default.
- `rweb --version`; the bridge reports its version to Rex instead of `0.0.0`.
