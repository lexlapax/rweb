# AGENTS.md

rweb shows Rex terminal sessions in a web browser through a small Rust bridge. Read
`docs/PLAN.md` first, then `docs/rex-web-research.md`. The plan's phases are in order; Phase 0
is a gate.

## Rules

- Keep this repository private.
- No agent attribution: no `Co-Authored-By`, "Generated with" or similar lines in commits, pull
  requests, documents or code.
- Ask before `git push`, creating releases, or changing GitHub settings.
- Rex on this machine is the owner's working multiplexer. Use only sessions your own test
  created, name them with an `rweb-test-` prefix, and close them when done. Never attach to,
  type into, resize, take ownership of, rename or close any other session.
- Never start or request a Rex listener with `--allow-anonymous`, and do not change Rex's
  listeners, config, hosts or service. Talk to the existing unix socket only.
- Never run `rex skill setup --force` or `rex skill remove`.
- Do not install anything on a machine or change a service by hand. Deployment goes through the
  owner's `setup-repo` repository and needs the owner's approval; `sudo` is the owner's to run.
- Do not read or print credentials, including anything under `~/.config/herdr-web`,
  `~/.config/herdr-web-ui` and `/etc/rex`.
- The Rex protocol reference is the server's own document:
  `curl --unix-socket "$XDG_RUNTIME_DIR/rex/server.sock" http://localhost/llms.txt`. Treat it
  as the source of truth over the research copy, and note the API revision you built against.

## Working here

- Record what each phase verified in `docs/`, with the Rex version and API revision.
- Keep the browser protocol independent of Rex's, so a Rex change stays inside the client
  library.
- Commit messages: `<area>: <change>`.
