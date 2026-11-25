# rweb

A web client for [Rex](https://www.superlogical.com/rex), the terminal multiplexer. Not affiliated
with Superlogical.

rweb is one small program that runs next to a Rex server as the same user. It talks to Rex over Rex's
own unix socket and serves a browser terminal (phone, tablet or laptop) on your private tailnet
through Tailscale Serve. You can list, open, create, rename and close sessions and terminals, type,
resize and reconnect.

## What is in a release archive

- `rweb`: the program (macOS on Apple silicon, or Linux x86-64 as a static binary).
- `CHANGELOG.md`, `THIRD-PARTY-NOTICES.md` (the software it contains or serves, with licences).

`rweb --version` prints the version, the commit it was built from and the Rex API revisions it speaks.

## Running it

rweb has the user's full Rex access, so it only serves what Tailscale Serve forwards and only to the
owner's Tailscale identity:

- Linux: `rweb --listen-unix "$XDG_RUNTIME_DIR/rweb/bridge.sock" --owner-from-tailscale`, then point
  Tailscale Serve at that socket (`tailscale serve --bg --https=PORT unix:...`, which needs root).
- macOS: `rweb --listen-tcp PORT --owner-from-tailscale --backend-secret-file FILE`, then point
  Serve at `http://127.0.0.1:PORT/<secret>` (the secret keeps other local programs out).

`rweb --help` lists every option. File transfer is off unless `--enable-file-transfer` is given.

## Building

Zig 0.17.1: `zig build -Doptimize=ReleaseSafe` builds the program; `zig build test` runs the tests
(with `REX_SOCKET=<path>` the live tests too); `zig build dist` makes the release archives in
`zig-out/dist`.

## Documents

- [docs/PLAN.md](docs/PLAN.md): phases, decisions and constraints.
- [docs/security-hardening-2026-11-23.md](docs/security-hardening-2026-11-23.md): the security design.
- [docs/file-transfer.md](docs/file-transfer.md): file transfer and its limits.
