# Screenshots

Shown in the top-level README and the user guide, and shipped in the release archives.

- `desktop.png`: a desktop browser, the session list and a terminal running vim on
  `src/bridge/access.zig` (1294 × 822, the page area only, so no address bar).
- `phone.png`: Mobile Safari on an iPhone simulator, a terminal showing `rweb --version` and `git log`,
  the key bar above Safari's address bar (1206 × 2622).
- `menu.png`: the same desktop page with the ⋯ menu open (1294 × 822).

How they were made (2026-11-27, rweb 0.3.0): a test bridge on `127.0.0.1` with a random token (the
page is the same as behind Tailscale Serve), on two throwaway Rex sessions running plain `bash` with a
neutral prompt in an rweb checkout, so no personal session, host name or prompt appears. The desktop
shots come from headless Chrome, driven over a loopback debugging port; in them only the test session is
listed (the page's list was narrowed in that browser for the picture; nothing else differs from the real
page). The phone shot is the simulator's own screenshot, with the simulator's status bar and its
metadata removed. The sessions, the bridge and the token were removed afterwards.
