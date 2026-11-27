# Security review, round 7 (2026-11-27)

Inputs, on commit `1779bea` (everything since round 6's commit, `c4be8c1` in the public history: round 6's
fixes, 0.1.1, Phase B of the Zig audit, 0.2.0, and after it `rweb doctor`, the update check, signed
checksums, the Homebrew and AUR packages and the rebuildable vendored code):

- an external security scan: one Medium, one Low, and a hardening request on the update check;
- a release-readiness review on Linux with Zig 0.17.1: three blockers, five should-fix items, five nits.
  Every build, test, fuzz, web and dist step it ran passed;
- an internal review by a fresh reader of the new code paths (doctor, the update check, sys.zig, the
  path from a release to the page, packaging and signing), told nothing of the other two reports: three
  Lows.

Each item was checked against the code, and where it concerned Zig against the pinned standard library
(`lib/std/http/Client.zig`, `Io.zig`, `Io/Threaded.zig`). All but one are real. That one was already
fixed after the reviewed commit. Two are recorded rather than fixed: the version bump, which is the
release itself, and a limit of std on macOS.

## Tally

| Id | Finding | Severity | Verdict |
|----|---------|----------|---------|
| D1 | The `Origin` check compared the authority only: behind Serve a page at `http://<name>` (port 80) matched a request for `<name>` (HTTPS, port 443), so any plain-HTTP content on port 80 of the same name could open a WebSocket, and Serve would attach the owner's identity | Medium | Fixed |
| D2, A3 | Private details in the public tree: a private repository's name, the sandbox tool's name, the owner's Rex session name, and which other services hold which Serve ports | Low | Fixed in the tree; the history keeps what was published |
| D3 | The update check followed redirects (std's default: up to 3, to any host, HTTPS to plain HTTP included) | Low (hardening) | Fixed |
| A1 | The version (build.zig.zon, CHANGELOG heading, README, user guide) still names 0.2.0 | Release step | Done in the release commit |
| A2 | The formula template's header was not stripped; Homebrew did not install `THIRD-PARTY-NOTICES.md` | Low | Header: fixed in `306bd41`, after the reviewed commit. Notices: fixed |
| A-S1 | `--no-update-check` missing from the user guide's options; doctor's GitHub check undocumented in the guide and `--help` | Should-fix | Fixed |
| A-S2 | `-Doptimize` help named ReleaseFast and ReleaseSmall, which `main.zig` refuses at compile time | Should-fix | Fixed |
| A-S3 | The architecture's source table missed ten files and `assets/screenshots/` | Should-fix | Fixed |
| A-S4 | Stale lines in the context map | Should-fix | Fixed |
| A-S5 | The docs index missed the new docs and called Phase B left over | Should-fix | Fixed |
| A-N1..N5 | Round 6's fixes under round 5's changelog heading; doctor printed Zig error names; no Homebrew or AUR uninstall; the plan's date; the fit addon's version in the notices | Nit | Fixed |
| I1 | On macOS a hung name lookup holds a check past its 10 s deadline: std uses the system `getaddrinfo`, which it cannot cancel (`Io/Threaded.zig`, its own TODO), and `Select.cancel` waits for the task | Low | Recorded: in `update.zig` and the user guide. The bridge's checker runs in its own task; only `rweb doctor` waits. Linux (static musl, Zig's resolver) is cancellable |
| I2 | `rweb doctor` printed names, logins and states from `tailscale ... --json` raw, so a control character in them reached the terminal | Low | Fixed |
| I3 | `tools/packaging.sh` piped the fill into the header strip: a failed step or a header that no longer matched gave an empty formula or PKGBUILD reported as made | Low | Fixed; also `tools/dist.sh`'s `tar | gzip` |

## Fixes, by mechanism

**The page's origin is a fact of the configuration (D1).** `access.pageScheme` says how pages reach the
browser: HTTPS behind Serve (an owner rule), plain HTTP for a token (loopback, or an SSH tunnel to it).
`access.requestHost` says which name the request is for: `X-Forwarded-Host` behind Serve, which sets it
after removing any copy the client sent, and otherwise `Host` only, since there anyone could send an
`X-Forwarded-Host`. `originMatches` takes the scheme from the configuration and compares the origin's
name and effective port with the requested authority's, a missing port being the scheme's default. A port
must be 1 to 65535 in plain digits, and an IPv6 address must be in brackets. The same comparison serves
the WebSocket upgrade, every request that is not GET or HEAD, and the guard on tokens in a header or query.
`hostAllowed` uses the scheme's default port too, so `--allow-host name:443` now matches a request for
`name` behind Serve. Typed or bookmarked sign-in (no `Origin`, `Sec-Fetch-Site: none`) is unchanged.

**One answer, from GitHub (D3).** The fetch sets `.redirect_behavior = .unhandled`; a 3xx is not 200 and
fails the check. Certificate checks, the deadline, the 64 KiB cap and `--no-update-check` are as before.

**Outside text through one filter (I2).** Doctor prints Tailscale's strings through `xfer.Clean`, which
the rest of rweb uses for outside text: control bytes and invalid UTF-8 become `?`.

**Every step's status counts (I3).** `packaging.sh` checks the version's form and that each SHA-256 is one
64-hex value. It fills each template into a file, drops the lines marked `#: ` (now the template header's
mark, in place of a range that could run to the end), and checks that the formula starts with its class
and holds the version and both hashes, and that the PKGBUILD holds its name, version and both hashes.
`dist.sh` writes the tar, then gzips it, in two steps. The gzip bytes are the same as from the pipe.

**The public tree (D2).** Generic wording replaced each item, and `git grep` for each name and port shows
none left. What remains: example ports in tests (`box.tail1234.ts.net:8443`) and rweb's own spike port in
the Phase 0 record, neither tied to another service. The history is not rewritten. Commit `1779bea`'s
subject keeps the sandbox tool's name.

## Tests

- `access.zig`:
  - "an Origin must match on scheme, name and port": Serve's HTTPS page with and without a default port;
    the tunnel's page over IPv4, a name and `[::1]`.
  - Cross-scheme refusals in both directions, wrong ports, a default port of the other scheme, and 24
    malformed origins (empty port, `+443`, `4_43`, `0`, `65536`, leading zeros, path, query, fragment,
    user, space, tab, unbracketed IPv6, unclosed brackets).
  - "the scheme and the forwarded host come from the configuration".
  - "round 7: ... every path that checks Origin": upgrade and PUT behind Serve and with a token, over
    IPv4 and IPv6; the header and query token guard; command-line sign-in unchanged; `X-Forwarded-Host`
    ignored without a proxy (it lets no rebound name in); default ports in the host list.
- `server.zig`: an HTTPS origin is refused at the upgrade in token mode. "behind Serve, a plain-HTTP page
  of the same name opens no WebSocket" runs over a real connection.
- `update.zig`: "a redirect is not followed": 301, 302, 307 and 308 with a `Location` to a second server
  that would answer 9.9.9. The check fails, and the second server is never asked.
- `cli.zig`: `--no-update-check` turns the check off for `rweb tailscale`, `rweb ssh` and `rweb doctor`,
  and the check is on without it.
- `doctor.zig`: Tailscale text with escape sequences prints without them.
- With its fix taken out, each new access and update test fails; with the fix in, it passes.
- `tools/packaging.sh`, signed with a throwaway key in a private agent:
  - the real 0.2.0 `SHA256SUMS` gives a PKGBUILD identical to the published AUR one, and a formula that
    differs from the tap's only by the doctor sentence the 0.2.0 tap leaves out;
  - a bad version, a doubled archive line and an empty template each stop it with a message.
- The formula and the tap pass `brew style` and `brew audit --strict`. They were not installed: the
  repository's rules forbid installing on the machine.

## Checks

- laptop-mac (Zig 0.17.1, no `REX_SOCKET`): `zig fmt --check src build.zig tools`, `git diff --check`, `zig build test` 464 pass + 14 skipped, ReleaseSafe with `--test-timeout 60s` the same, `zig build fuzz`, the Origin target fuzzed for 120 s with no failure, `zig build dist`, `tools/release-base.test.sh` 7 ok.
- linux-box (Zig 0.17.1, a clone of the branch in `/tmp`, removed after): fmt, `zig build test` 463 + 15 skipped, ReleaseSafe the same, `zig build web-test` 46/46, `zig build dist`.

## Not verified here

- A browser through a real Serve entry against this code: the change compares a scheme that Serve always
  gives (HTTPS) and the same `X-Forwarded-Host` as before, but it is checked in the release's live run, as
  every release is.
- A Homebrew install of the updated formula, for the reason above.
