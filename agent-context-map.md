# Agent context map

Last updated: 2026-11-21. Read first; load linked context lazily. Keep this file short: current
state, decisions, blockers and next actions. Put durable evidence in `docs/`.

## Current state

- **Planning complete; nothing is built (2026-11-21).** Research, plan and agent rules are
  committed. No code, no Zig build, no frontend yet.
- **Plan revised after design research (2026-11-21):** [docs/design-research.md](docs/design-research.md).
  Rex's snapshot is Ghostty's binary `GHOSTSNP` format, so the preferred route is a bridge-side
  libghostty-vt mirror serving VT redraws to xterm.js; access is a 0600 unix socket behind
  Tailscale Serve with identity, own-address, Funnel and Origin checks.
- **Phase 0 (spike) not started.** It is the gate for every later phase. It waits for setup-repo
  to install Zig 0.17.0 on linux-box.

## Owner decisions (2026-11-21)

Recorded in [docs/PLAN.md](docs/PLAN.md#decisions-made-by-the-owner-2026-11-21):

1. Shape: a bridge running as the user next to Rex's unix socket, serving the page and its own
   WebSocket on loopback, with Tailscale Serve in front.
2. Server in Zig (changed from Rust on 2026-11-21), one static binary per platform.
3. First version: list sessions and terminals; one terminal full-screen; type, resize,
   reconnect; usable on a phone; create, rename and close sessions and terminals.
4. Not in the first version: drawing a window's split layout; forking Ovis.

## Decisions after the design research (2026-11-21)

Recorded in [docs/PLAN.md](docs/PLAN.md#decisions-made-after-the-design-research-2026-11-21):

1. Bridge in Zig, importing libghostty-vt directly; `ReleaseSafe`, fuzzed parsers, few pinned dependencies.
2. Zig: installed on all three machines by setup-repo, pinned to what libghostty-vt needs (0.17.0 for `vt-1.0.1`).
3. Own-address requests: rejected by default; a per-machine setting allows them on single-user hosts.
4. desktop-mac: included; the bridge starts a personal Rex server if none runs, and uses loopback TCP.

## Next actions, in order

1. **Phase 0 spike** in `spike/`, as in [docs/PLAN.md](docs/PLAN.md#phase-0-spike-gate-for-everything-else):
   capture a raw stream from an `rweb-test-` session, then try the bridge-side mirror, the format
   repaint, and browser-side decode, in that order; pick the input path; run the checks; write
   the result in `docs/`. If no route works, stop and report.
2. Phases 1–4 follow [docs/PLAN.md](docs/PLAN.md#phases).

## Checks run for this update

- Documentation only: wrote `AGENTS.md` and this map; design research and plan revision.
- Read-only: `rex version` (preview.22, revision 19), fetched `llms.txt` over the unix socket,
  `tailscale version` (1.104.7), read setup-repo's Rex, Ovis and herdr-web records. No session
  created, no Rex data connection opened.

## Task routing

| Need | Load |
| --- | --- |
| Phases, architecture, constraints, risks, pending decisions | [docs/PLAN.md](docs/PLAN.md) |
| Snapshot format, libghostty-vt, browser terminals, Serve identity, machine facts | [docs/design-research.md](docs/design-research.md) |
| Rex protocol, streams, revisions; Ovis and herdr background | [docs/rex-web-research.md](docs/rex-web-research.md) |
| Live protocol reference (authoritative) | `curl --unix-socket "$XDG_RUNTIME_DIR/rex/server.sock" http://localhost/llms.txt` |
| Rex CLI usage | the `rex` skill |
| Deployment (Phase 4) | the owner's `setup-repo` repository, with approval |

## Pins and machines

- Rex at research time: `0.1.0-preview.22`, API revision 19 (server accepts 0 to 19), on
  linux-box. Re-check with `rex version` before building; the revision moved 18 → 19 within a day.
- Rex listeners on linux-box: the user unix socket `/run/user/1000/rex/server.sock`
  (peer credentials) and a login-server socket; Tailscale listener disabled. Do not change them.
- desktop-mac: Rex.app preview.21 (Sparkle, outside setup-repo), no boot-time Rex server;
  Tailscale.app (sandboxed, no unix-socket Serve backend).
- Tailscale 1.104.7 on linux-box (unix-socket Serve backends need ≥ 1.94; setting one needs root).
  Serve ports in use: 443 (Ovis), 9443 (Ovis canary), 8443 (desktop-mac).
- libghostty-vt: Ghostty tag `vt-1.0.1` (needs Zig 0.17.0); main needs 0.17.1.
- linux-box: Zig not installed yet (setup-repo will install 0.17.0 on all three machines).
- Deployment order for Phase 4: linux-box, then gateway-box, then desktop-mac.
