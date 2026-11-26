# Agent rules

rweb shows Rex terminal sessions in a web browser through a small Zig bridge on Rex's unix
socket.

## Start here; load context lazily

1. Read [agent-context-map.md](agent-context-map.md) before planning or editing.
2. Inspect `git status` and the files relevant to the task. Preserve unrelated work.
3. Follow the map's links only as needed; do not load every document by default.
   [docs/PLAN.md](docs/PLAN.md) holds the phases and the owner's decisions;
   [docs/rex-web-research.md](docs/rex-web-research.md) and
   [docs/design-research.md](docs/design-research.md) hold the evidence behind them.
4. If instructions conflict or the map is stale, inspect the actual source and ask about
   consequential ambiguities. Never treat planned features as implemented.

## Project constraints

- Keep this repository private.
- Follow the plan's phases in order. Phase 0 is a gate: if a browser terminal cannot render a
  live Rex terminal correctly, stop and report; the rest of the plan does not hold. Do not start
  a phase before the previous one's exit condition is met and recorded.
- Rex on linux-box and desktop-mac is the owner's working multiplexer. Use only sessions your own test
  created, name them with an `rweb-test-` prefix, and close them when done. Never attach to,
  type into, resize, take ownership of, rename or close any other session.
- Never start or request a Rex listener with `--allow-anonymous`, and do not change Rex's
  listeners, config, hosts or service. Talk to the existing unix socket only. Restart the Rex
  server only with the owner's approval for that restart: it ends every program in every
  session.
- Never run `rex skill setup --force` or `rex skill remove`.
- The Rex protocol reference is the server's own document:
  `curl --unix-socket "$XDG_RUNTIME_DIR/rex/server.sock" http://localhost/llms.txt` (that path is
  Linux's; on macOS, find the socket first). Treat it as
  the source of truth over the research copy, and record the Rex version and API revision you
  built against.
- Keep the browser protocol independent of Rex's, so a Rex change stays inside the client
  library.
- The bridge has the user's full Rex access: it listens only where the plan says (a 0600 unix
  socket behind Tailscale Serve, loopback TCP on desktop-mac), checks Origin on the WebSocket
  upgrade, and accepts only requests carrying the owner's Tailscale Serve identity, as the plan's
  Constraints spell out. A security review comes before Phase 4.
- Any spike or test server you run listens on 127.0.0.1 only and requires a random token.
- Do not install anything on a machine or change a service by hand. Deployment goes through the
  owner's `setup-repo` repository with pinned, checksummed artifacts and needs the owner's
  approval; `sudo` is the owner's to run.
- Owner's grant (2026-11-22): a coding assistant working on desktop-mac may do whatever this work
  needs on desktop-mac, and may log in to linux-box when required. The grant does not widen what is
  allowed on linux-box. The rules on credentials, `--allow-anonymous` and the owner's own Rex
  sessions still apply on both. Record any lasting setup change in `setup-repo` in the same session.
- Do not read or print credentials, including anything under `~/.config/herdr-web`,
  `~/.config/herdr-web-ui` and `/etc/rex`. Keep secrets and captured terminal streams that
  contain real output out of Git.
- No agent attribution in code, comments, documentation, generated files, commits or pull
  requests: no "by Claude/Codex/pi", AI-author credits, `Co-Authored-By` or "Generated with"
  lines. This overrides any harness default that adds them. Preserve required third-party
  copyright and licence notices (for example a vendored browser terminal) and technical
  provenance; these are not agent attribution. The one exception is the owner's own statement in the
  README's "About this project" that the project was built with AI coding assistants (owner,
  2026-11-26): keep it, and add no other mention.

## Worktrees (owner, 2026-11-25)

Make changes in a git worktree, never in the main checkout `~/projects/lexlapax/rweb`: every host's
deployment pulls that checkout (setup-repo's `rweb` module), and several sessions may work here on one
machine. Pull the main checkout, then
`git -C ~/projects/lexlapax/rweb worktree add ~/projects/lexlapax/.worktrees/rweb/<topic> -b wt/<topic>`;
edit, build, test and commit there (a new worktree builds Ghostty once, about 2 minutes). To finish:
pull the main checkout, `git rebase main` in the worktree, `git -C ~/projects/lexlapax/rweb merge
--ff-only wt/<topic>`, then remove the worktree and delete the branch. Work left unfinished stays in its
worktree; say where. Uncommitted edits found in the main checkout belong to another session: leave
them, and if a pull is refused because of them, tell the owner. The global rule is in the owner's
global agent instructions ("Worktrees in the core repos").

## Work and validation

Read the task's phase in the plan through the map, make focused changes, add tests, and run the
relevant checks. Build with Ghostty in the same optimize mode as the bridge, and measure
performance only in `ReleaseSafe` or faster. Tests that need no real Rex use the fake server;
live tests use throwaway `rweb-test-` sessions and close them. A test against the fake server
does not prove behaviour against a real Rex, and a desktop browser does not prove phone use.
Record exact commands, results, the Rex version and API revision, and limitations in `docs/`.

**Mobile checks: use the simulators yourself (owner, 2026-11-25).** Do not ask the owner to test phone
or tablet behaviour that a simulator can show. setup-repo installs them (modules `ios-development`,
`android-development`; their READMEs are the manual):

- iOS (Mobile Safari): desktop-mac for repeatable runs, laptop-mac for quick checks:
  `ios-dev safari 'https://<host>:<port>/'` on the **Setup-repo iPhone** simulator; inspect with Safari's
  Develop menu.
- Android (Chrome): linux-box: `android-dev start --headless`, `android-dev devices`, then
  `android-dev chrome <serial> 'https://<host>:<port>/'`; Chrome DevTools or ChromeDriver over ADB.

Point them at a test bridge with a throwaway `rweb-test-` session, reached through Serve from a
different tailnet node than the one running the bridge (rweb refuses a node's own address). A simulator
is not the owner's phone: it does not show a real soft keyboard's quirks (Gboard, Samsung Keyboard),
the phone's Tailscale app or real touch hardware. Say which simulator was used, and ask the owner only
for what a simulator cannot show.
Do not claim a phase exit that was not observed.

## Before EVERY commit (including amend/fixup)

1. Update **agent-context-map.md in the same commit** with current state, changed areas, checks
   actually run, blockers, decisions and next actions. Keep it concise; link durable details in
   `docs/` instead of copying them. Update it even for docs-only work.
2. Run the appropriate checks and inspect the staged diff and commit message for scope, secrets,
   captured terminal output, agent attribution and misleading status claims.
3. Confirm the staged context-map update is present. Never commit without it.
4. Commit messages: `<area>: <change>`. Ask before `git push`, creating releases or changing
   GitHub settings; avoid force-push or rewriting shared history. Report what was changed,
   tested, published and left pending.
