# Phase 4 result: packaging and deployment

Status (2026-11-23): **exit condition met for linux-box and desktop-mac.** Each serves rweb after a reboot, and the
deployment is recorded in `setup-repo` (task `work-rweb-deployment`, runbook `docs/runbooks/rweb.md`, action
records of 2026-11-23). linux-box then moved from loopback-plus-secret to a unix socket (applied by the owner,
verified through Serve); its reboot check is to be repeated on that setup (see "Open").

Phase 3's own exit, a week of daily use on a phone and a laptop, is the owner's and has not been recorded.

## What the plan asked for, and what happened

| Plan item | Result |
|---|---|
| Security review before any deployment | Done twice: an independent source review and a second, wider one, with every finding fixed and tested. [security-review-2026-11-23.md](security-review-2026-11-23.md), [security-hardening-2026-11-23.md](security-hardening-2026-11-23.md). |
| Release builds for Linux x64 and macOS ARM64 with checksums | **Changed.** Nothing is distributed as a binary. Each host builds the pinned commit itself (`ReleaseSafe`, about a minute, with `zig` from the repo's own tarball export) and records the SHA-256 of what it built; the service wrapper refuses a binary that no longer matches. Builds are not byte-reproducible between hosts (different checksums for the same commit were observed), so the checksum guards the installed file, not the source; the source is pinned by commit and the vendored browser code by `SHA256SUMS`, which a test enforces. No static musl build was needed. |
| `rweb` module in `setup-repo`: pin, systemd user unit after Rex, LaunchAgent, Serve as an operator step | Done: `modules/rweb` in setup-repo. Serve is a one-time operator step through `rweb-serve on`, on **port 12443** (443, 8443, 9443 and 10443 are taken). |
| macOS: start a personal Rex server if none runs | **Not built, deliberately.** On macOS Rex.app owns the server. The bridge exits when Rex's socket is missing and the LaunchAgent starts it again, so it comes up once Rex does. |
| Start-after-login and reboot behaviour verified on linux-box, then gateway-box, then desktop-mac | linux-box and desktop-mac verified; **gateway-box is not in scope** (the owner scoped deployment to linux-box and desktop-mac). |

Additions beyond the plan: file transfer ([file-transfer.md](file-transfer.md), on by the owner's choice),
program/terminal info in the header, and the Ovis-style layout work recorded in the Phase 3 notes.

## How it is deployed

- **linux-box (Linux):** a systemd user unit with lingering (starts at boot, before login), after `rex.service`,
  restarting after 5 s if Tailscale or Rex is not ready. Listens on a unix socket (`$XDG_RUNTIME_DIR/rweb/bridge.sock`)
  that only root, i.e. `tailscaled`, may connect to; same-user processes are refused at accept.
- **desktop-mac (macOS):** a LaunchAgent that starts at login (FileVault is on, so a person unlocks the disk at
  boot and that unlock logs the user in). Loopback `127.0.0.1:7695` behind a secret first path segment, because
  Tailscale.app cannot forward to a unix socket.
- Both: `rweb-serve on` adds `https://<host>.example.ts.net:12443/` (tailnet only, never Funnel).
  File transfer on, uploads to `~/rweb-uploads` (0700), 256 MB per transfer.

## Evidence (all 2026-11-23)

- Apply and Serve on both hosts by the owner; read-only checks from the other host: 200 for `/`, `/app.js`,
  `/api/tree`; a host's own address refused (403) by design; the existing Serve entries untouched.
- linux-box reboot with nobody logged in: service active, one automatic retry while Tailscale came up, Serve
  entry survived. desktop-mac reboot and login: LaunchAgent running, started once, no retry, Serve entry survived.
- Phone: both addresses opened; file download and upload tested on desktop-mac from the phone; on linux-box the
  same was tested through Serve from Chrome (byte-identical checksums, hostile file name neutralised).
- Tests at the end of the work: `zig build test` with live Rex on desktop-mac (preview.21, API revision 18) and
  linux-box (preview.22, revision 19): 147 pass + 1 skip and 194 pass + 1 skip; `web-test` 14; fuzz targets;
  `ReleaseSafe` builds on both platforms.
- Tailscale 1.104.7 on both hosts; Zig 0.17.1.

## Found while deploying

- A Linux-only compile error in the owner check for secret and upload files (the C `stat` does not exist in
  that shape on Linux): found only by running the suite on linux-box; fixed with `statx`.
- `tailscale serve` prints the address it forwards to, which ends in the secret: the helper now filters it.
- macOS cannot turn on automatic login with FileVault; the runbook said it could and was corrected.
- Tailscale lets only root point Serve at a unix socket, which is why linux-box's Serve step needs `sudo`.

## Open

- **linux-box, reboot check on the unix-socket setup:** the move was applied by the owner and verified through
  Serve (200 from desktop-mac, own address 403, same-user forgery refused at accept); what is left is one reboot to
  confirm systemd recreates `/run/user/1000/rweb` (0700) at boot and the bridge comes up, to be recorded in setup-repo.
- **Phase 3 exit:** a week of daily use (owner).
- **Skipped by the owner:** a link between the two hosts' pages. **Paused:** an optional folder allow-list for
  downloads (downloads can read anything the terminal's user can read).
- Not done and not planned: gateway-box; Serve under load; an upstream audit of wterm, xterm.js and the wasm core.
