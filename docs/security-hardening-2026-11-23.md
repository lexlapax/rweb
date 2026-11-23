# Security hardening, 2026-11-23

Follows [security-review-2026-11-23.md](security-review-2026-11-23.md) (the first, source-only review of
commit `f14b7b9`). This document adds a second, independent source review, merges the findings, gives the
plan that fixed them, and records what was verified and how.

Scope and limits: source review plus tests, and one live test on desktop-mac. It is not a penetration test, a
dependency audit of Zig, Ghostty, wterm, xterm.js, Rex or Tailscale, or a test of every browser. Phase 3's
week of daily use has not been recorded, so **deployment still needs the owner's approval**. Nothing was
deployed; the bridge is not running on any machine.

## 1. Findings, merged

`R` is the first review's number; `M` is new in this one. Severity is the reviewer's judgement of impact
for this deployment (a bridge holding the owner's full Rex access, reachable by the tailnet).

| ID | Sev | Finding | Source |
|----|-----|---------|--------|
| F1 | High | On macOS the bridge listens on loopback TCP (Tailscale.app cannot forward to a unix socket). Any local process can send forged `Tailscale-User-Login` / `X-Forwarded-*` headers and gets the owner's Rex access. | R1 |
| F2 | High | Only the first 48 request headers were passed to the access check; a Funnel or own-address header after that was never seen. | R2 |
| F3 | Med | Connections took one of 64 slots before authentication, with no deadline for the request head: slowloris. The unix peer was checked only after the head arrived. | R3 |
| F4 | Med | `/api/lab/result` logged its whole query string (token included). The lab pages were served in every build. | R4 |
| F5 | Med | WebSocket masking was not enforced by role. | R5 |
| F6 | Med | wterm's query-reply suppression failed open if its private hook was missing, and nothing else stopped a terminal's answer to a program's query (title report, DA, CPR) being typed into the shell. | R6 |
| F7 | Low | Own-address check compared text, and accepted a request with no `X-Forwarded-For`. | R7 |
| F8 | Med | `Host` was only checked on WebSocket upgrades: no defence against DNS rebinding for pages and `/api/tree`. | M |
| F9 | Med | Secrets in the wrong places: `--token` in the process list (every local user sees it), the test token left in the address bar and sent as `?token=` on the WebSocket, cookie without `Secure` behind HTTPS. | M |
| F10 | Med | `Server.start` deleted whatever file was at the socket path (a regular file, or another bridge's live socket). | M (also R, "other boundaries") |
| F11 | Med | A peer could send endless pings (a pong written for each, uncounted by the message-rate limit) or endless empty continuation frames. | M |
| F12 | Med | The key message forwarded an arbitrary JSON object to Rex's `client.key`; a `mouse` message forwarded an arbitrary `block.event` payload. The page never sends `mouse`. | M |
| F13 | Low | Authenticated heavy requests (`info`, `clip`, `text`, `redraw`, `more_history`) could be sent 200 a second, each making Rex or the mirror do work. | M |
| F14 | Low | The request log wrote the client's own path text: log forging, and it would have logged the new secret prefix. | M |
| F15 | Low | Vendored executable code (wterm, xterm.js, the wasm core) had hashes in a document but nothing enforced them. | M |
| F16 | Low | Missing response headers: `Cross-Origin-Resource-Policy`, `X-Frame-Options`, `Permissions-Policy`. | M |
| F17 | Low | Funnel was detected by one header spelling. Repeated security headers (two `Host`, two `Tailscale-User-Login`) were resolved by taking the first. | M (extends R2) |
| F18 | Info | Test coverage gap: a function in `main.zig` that nothing in the tests referenced contained a compile error that only a release build showed. | M |

## 2. The plan

Fix the trust boundary first, then the places an attacker can reach it from, then defence in depth, then make
each fix permanent with a test that fails without it.

1. **Make the macOS boundary enforceable (F1).** Not a token in a header: Tailscale Serve cannot add one,
   and a secret the local adversary can read is no boundary. Instead the bridge accepts only requests whose
   path starts with a long random first segment, and Tailscale Serve is pointed at
   `http://127.0.0.1:PORT/<secret>`, so Serve adds the segment and a local process does not know it. The
   secret lives in a 0600 file (never on a command line); the bridge refuses a file others can read, one not
   owned by its user, a short one, or one with characters unsafe in a path. Everything without the segment
   gets a bare 404 before any header is looked at. Loopback TCP with an owner rule *refuses to start*
   without it unless `--allow-forgeable-loopback-identity` is given (single-user test machines).
2. **Judge only complete, unambiguous requests (F2, F7, F8, F17).** Reject more than 64 headers with 431;
   refuse any security header that appears twice; refuse every `Tailscale-Funnel*` header; compare
   `X-Forwarded-For` as parsed addresses (IPv4-mapped IPv6, zones, brackets) and require it, as a valid
   address, whenever the own-address rule is on; check `Host`/`X-Forwarded-Host` against an allow-list on
   every request (the node's own DNS name is added automatically with `--owner-from-tailscale`).
3. **Shrink the pre-authentication surface (F3, F10).** Unix peers are checked at accept. Connections that
   have not passed the access check are capped (16) separately from the 64 total, and must send their head
   within 10 s. A unix path that is a file, or has a live listener, is never replaced.
4. **Harden the WebSocket layer (F5, F11).** Masking is enforced by role in both directions; pings/pongs
   between data messages (256) and frames per message (4096) are bounded.
5. **Narrow what the browser can make the bridge send (F12, F13, F6).** `key` is rebuilt field by field;
   `mouse` is removed; heavy calls are capped at 8 a second per browser; the page strips terminal replies
   from everything it sends to Rex, and wterm refuses to start (so the page falls back to xterm.js) if it
   cannot silence its replies.
6. **Stop leaking and forging (F4, F9, F14).** Lab pages and endpoints are off unless `--enable-lab`; no
   query is ever logged; the log names only paths the bridge serves; `--token-file`; the page removes the
   token from the address bar and the socket relies on the cookie; `Secure` behind HTTPS.
7. **Pin and header-harden (F15, F16).** `web/vendor/SHA256SUMS` plus a test that every vendored asset
   matches and none is missing from the manifest; the three missing headers.
8. **Prove it (F18).** Unit and wire tests for each fix; live tests against the real Rex; one live test of the
   secret prefix through real Tailscale Serve.

## 3. What was done, with evidence

| ID | Fix | Where | Test that fails without it |
|----|-----|-------|----------------------------|
| F1 | Backend secret prefix; `NeedBackendSecret`; `--backend-secret-file` | `server.zig` `stripSecret`, `cli.zig`, `main.zig` | `server: the backend secret keeps local processes out…`, `stripSecret`, `loopback TCP with an owner rule needs a backend secret…`, `a secret file must be private…` |
| F2 | 431 past 64 headers; duplicates and the Funnel family refused | `server.zig`, `access.zig` | `headers past the 48th can no longer hide a refusal`, `a repeated identity header is refused`, `every Funnel header refuses…` |
| F3 | Head deadline, pending cap, peer check at accept | `server.zig` | `a connection that never sends a request is cut…`, `a unix socket is private…` |
| F4 | Lab off by default, no query logged | `server.zig` | `the diagnostic pages are off unless asked for…` |
| F5 | Masking by role | `ws.zig` | `a server refuses an unmasked frame, a client refuses a masked one` |
| F6 | Fail-closed shim; `stripReplies` | `wterm-shim.js`, `keys.js`, `app.js` | node tests `terminal replies … are never sent to Rex`, `what a person types … is not a reply` |
| F7 | Parsed address comparison, `X-Forwarded-For` required | `access.zig` | `the own-address rule compares addresses, and fails closed` |
| F8 | `allowed_hosts` on every request | `access.zig`, `main.zig` | `a host list refuses any other Host, on every request` |
| F9 | `--token-file`, token removed from URL, `Secure` cookie | `cli.zig`, `main.zig`, `app.js`, `server.zig` | CLI tests; secret-file test |
| F10 | `clearStaleSocket` | `server.zig` | `a unix socket path that is a file, or in use, is never replaced` |
| F11 | Control-frame and fragment budgets | `ws.zig` | `a peer that sends only pings, or endless empty fragments, is cut off` |
| F12 | `keyJson` canonical rebuild; `mouse` removed | `protocol.zig`, `hub.zig` | `a key press is rebuilt from checked fields only` |
| F13 | `allowHeavy` | `hub.zig` | `a browser cannot make Rex do heavy work more than a few times a second` |
| F14 | `knownPath` in the log | `server.zig` | live: the bridge log held 0 occurrences of the secret |
| F15 | `SHA256SUMS` | `assets.zig` | `vendored files match their pinned checksums` |
| F16 | Headers added | `server.zig` | `assets are served with a strict content security policy` (headers present) |
| F18 | Secret-file reader now tested; release build checked | `main.zig` | `zig build -Doptimize=ReleaseSafe` |

### Verification record (desktop-mac, `f14b7b9` + this work)

- `REX_SOCKET=… zig build test`: 125 of 126 pass (the skipped one is the Rex restart test, which needs the
  owner's approval to restart Rex). The live tests ran against the real Rex (preview.21, API revision 18)
  using `rweb-test-` sessions, closed afterwards; they exercise the masking rule in both directions.
- `zig build web-test`: 14 pass. `zig build fuzz`: pass. `zig build -Doptimize=ReleaseSafe`: builds.
- **Live, through real Tailscale Serve** (Tailscale 1.104.7 on desktop-mac): bridge on loopback with a secret
  file, Serve pointed at `http://127.0.0.1:7697/<secret>`. Results: forged owner headers sent directly to the
  port without the secret → 404 (also `/api/tree`, and a wrong secret); the same paths through Serve → 200;
  a browser loaded the page and its WebSocket connected through Serve (Origin and Host checks passed with
  `X-Forwarded-Host` carrying a port); the secret appeared neither in the address bar nor in the bridge log.
  The Serve entry, bridge and secret file were removed afterwards.

## 4. Deployment requirements (for the `setup-repo` module)

- desktop-mac (loopback TCP): `rweb --listen-tcp PORT --owner-from-tailscale --backend-secret-file F`, with `F`
  mode 0600 in a directory only the user can enter, created at install time with at least 32 random
  characters from `[A-Za-z0-9_-]` (for example `openssl rand -hex 24`); Serve target
  `http://127.0.0.1:PORT/<contents of F>`. Do **not** pass `--allow-own-address` unless the machine has one
  user and the owner accepts that a local process can then reach Serve under the node's name.
- linux-box (unix socket): `--listen-unix` in a 0700 directory, peer uid 0 (tailscaled) is the default;
  `--owner-from-tailscale`; no backend secret (the peer check is the boundary).
- Never in a unit file or launch agent: `--token`, `--debug-input`, `--enable-lab`,
  `--allow-forgeable-loopback-identity`; `--enable-file-transfer` only as a deliberate choice, with
  `--upload-dir` in a folder only the user can enter. The bridge prints a warning if an owner rule runs without
  `--allow-host`.
- Release binary: build with `-Doptimize=ReleaseSafe` or faster; pin and checksum it as `AGENTS.md` requires.
- Re-run the checks in §3 on the machine it will run on after any change to Tailscale, Rex or a vendored file.

## 5. Residual risk and what was not done

- **Same-user local code is not stopped.** A process running as the owner can already use Rex's socket and
  read the secret file. The secret prefix protects against *other* local users and processes that cannot read
  the owner's files; it is not a sandbox. On macOS, a file the owner can read is readable by any process the
  owner runs.
- **Serve under load and its own timeouts were not exercised.** Serve's behaviour with these checks was
  measured on both machines (§6). One piece is still open: **Serve pointed at a unix socket on linux-box needs
  root** (`tailscale serve … unix:PATH` answers "must be root, or be an operator and able to run `sudo
  tailscale`"), so I could not run that exact chain, and `sudo` is the owner's to run. Everything either side
  of it was tested; see §6 for the two commands that finish it.
- **CSP keeps `style-src 'unsafe-inline'` and `script-src … 'wasm-unsafe-eval'`.** xterm.js injects `<style>`
  elements, and wterm needs WebAssembly compilation. Scripts and wasm are served from the bridge and pinned
  (F15); there is no `unsafe-eval` and no external origin (`default-src 'none'`, `connect-src 'self'`). Script
  that already runs in the page can do more with wasm than without it, and nothing here audits wterm, the wasm
  core or xterm.js upstream.
- **Observe-only is not a confidentiality boundary:** it still allows reading terminals, metadata and the
  clipboard.
- **File transfer** was designed, reviewed and built afterwards; see [file-transfer.md](file-transfer.md). It is
  off unless `--enable-file-transfer` is given, and downloads give the page the owner's own file access (no
  per-folder allow-list), which is why. Never enable it in a unit file without deciding that on purpose.
- **Limits are not proofs.** Message sizes, queues and the new caps bound memory and CPU, but no targeted
  stress test of snapshot decoding, slow readers or connection churn was run.
- **The vendored files' provenance is as recorded in `phase3-result.md`**; the manifest pins what is in the
  repository, not what upstream published.
- The first review's `--debug-input` remark stands: it logs typed text and must stay off.
- Two cache directories left in `/tmp` by the first review (`rweb-security-*`) were not touched.

## 6. linux-box (Linux, Rex preview.22 / API revision 19, Tailscale 1.104.7)

Built from a scratch clone in `/tmp` of `1e6e873`, everything below removed afterwards (no bridge process, no
file under `/tmp` or `/run/user/1000`, Serve back to the original three entries, `rex ls` shows only
`drifting-tundra`).

- **Tests.** `REX_SOCKET=… zig build test`: 194 of 195 pass (the skip is the restart test), including the live
  tests against linux-box's Rex. This found a real bug the macOS run could not: the owner check for secret and
  upload files used the C `stat`, which does not compile on Linux. Fixed with `statx` and committed.
- **Unix socket, same-user forgery (the linux-box threat).** A process running as the same user connected to
  the bridge's socket with the owner's `Tailscale-User-Login` and a forged `X-Forwarded-For`: the connection was
  closed at accept ("refused: peer not allowed"), curl got a reset, no request was read. Only uid 0
  (tailscaled) is allowed by default. The socket was 0600 in a 0700 directory.
- **Serve to a unix socket: not run.** It needs root. To finish it, with the bridge running as
  `rweb --listen-unix /run/user/1000/rweb-sv-test/bridge.sock --owner-from-tailscale`, the owner runs on
  linux-box `sudo tailscale serve --bg --https=12445 unix:/run/user/1000/rweb-sv-test/bridge.sock`, and
  afterwards `sudo tailscale serve --https=12445 off`. Expected: the owner's other nodes get 200, linux-box's own
  address gets 403 "request from this node's own address".
- **Serve to loopback TCP with the secret prefix, on linux-box (a deployment option that needs no root).**
  Same mechanism as desktop-mac, without `--allow-own-address`:
  from desktop-mac (another node of the owner) through Serve: page, script and `/api/tree` all 200; transfer
  address 404 (transfer off); from linux-box itself through Serve: **403 "request from this node's own address"**
  (the rule works on the real thing); forged headers sent directly to the loopback port without the secret: 404;
  the port is not reachable from desktop-mac. A browser on desktop-mac loaded the page through Serve and its
  WebSocket connected (one session listed, transfer not offered).
- **What Serve does to headers (measured through the real proxy).** A client-supplied `Tailscale-User-Login`
  is overwritten (the bridge still sees the owner), a client-supplied `Tailscale-Funnel-Request` is stripped,
  other headers pass through: 70 extra headers reached the bridge and were refused with **431 "too many
  headers"** (F2 holds on a real proxy), and a wrong `Host` was refused with **"host not allowed"** (F8 holds).
  A client-supplied `X-Forwarded-For` does not make the request pass or fail by itself; the bridge refuses on
  any listed address that is the node's own, and requires the header.
- **Choice for the `setup-repo` module on linux-box:** either the unix socket (peer uid 0, needs the root-run
  Serve command above, which a root-run setup-repo can do) or loopback TCP with the secret prefix (verified end
  to end above, no special rights). Both are enforced boundaries; the unix socket has the stronger one (a kernel
  peer check rather than a secret), the TCP one has the same mechanism on both machines.
