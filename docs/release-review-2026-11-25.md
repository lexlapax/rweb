# Release reviews of 0.1.1 (2026-11-25)

Two independent reviews of commit `7a53f54` (`main`), before any version or GitHub release:

- **Release readiness** (agy, on linux-box, Linux x86-64): builds, the full test suite with live Rex,
  archive contents and determinism, licences and notices, docs against the CLI, hygiene.
- **Security** (OpenAI Daybreak, full-repository static scan): five findings, four Medium and one Low.

Each finding was checked against the code before anything was changed. All were accepted; none was
refuted. The fixes are in one commit after `7a53f54`, for both reviews to look at again. The second
round (a rescan of the fixed commit and an internal adversarial review) is in
[security-review-2026-11-25-round2.md](security-review-2026-11-25-round2.md).

## Security findings

| # | Finding | Verdict | Fix | Tests |
| --- | --- | --- | --- | --- |
| S1 | `tools/release.sh` builds under a fixed `/tmp/rweb-release/<commit>` without checking the base folder: another local account could swap the source before the build | Accepted. Real on a shared release host; the release hosts so far are single-user | The base must be a real directory (not a link), owned by the user running the script, and is made `0700` before anything is put in it; anything else stops the script with a message. `/tmp`'s sticky bit keeps other users from renaming or replacing a folder they do not own. The fixed path is kept, so builds stay reproducible | `tools/release-base.test.sh`: link refused (and nothing written through it), plain file refused, an open folder of ours made `0700`, a new one created `0700`; a folder owned by another user is refused when run as root |
| S2 | In SSH-tunnel mode the token's cookie is scoped to `127.0.0.1` and `/`; browsers send a host's cookies to every port, so any other local web service the browser opens gets the token | Accepted. The same scoping also made two tunnels on two ports overwrite each other's cookie (the user guide's "several machines" setup) | The page lives at `/s/<id>/`, `<id>` = first 16 bytes of SHA-256(`"rweb cookie path\0"` + token) in hex: stable for a token, different per token; it does not show the token, but anyone who sees it can test guesses of the token against it (round 2, H2: tokens must be random and the address kept private). `/?token=` answers `303` to `/s/<id>/` (other query parameters kept, the token dropped), sets the cookie with `Path=/s/<id>/`, and deletes 0.1.0's `Path=/` cookie. `/s/<id>` gets its slash by `302`. The page and its scripts use relative addresses only (Serve mode still serves at `/`). Token files must hold only letters, digits, `-` and `_` (as the documented generator makes), so the token is always cookie- and URL-safe. A separate `.localhost` host name per tunnel (the review's suggestion) was not used: Safari and iOS do not reliably resolve `*.localhost`, and a path works in every browser | `server: the token cookie is scoped to the token's own path, never to the whole host` (redirect, `Location`, both `Set-Cookie`s, wrong token refused before any redirect, slash redirect, page, files, tree and WebSocket under the prefix, a longer look-alike prefix is not it); `page scripts load and connect by relative paths only`; the page test now requires relative references. In Chrome on macOS: the redirect, wterm loaded entirely under the prefix, a typed command round-tripped in a throwaway terminal, `document.cookie` cannot see the token, a bookmark of the prefix works without the token, and a stand-in web service on another `127.0.0.1` port received no rweb cookie. Mobile Safari in the iOS Simulator: redirect, cookie and socket work |
| S3 | A malformed `--own-address` turns off automatic discovery and then matches nothing, so the local-node refusal is silently off | Accepted | `--own-address` must be an IP address (`BadAddress` at startup); discovered addresses are checked the same way, and an owner rule with no own address and no `--allow-own-address` stops startup. `access.decide` refuses every request (`bad_own_address`) if a configured own address does not parse, as a second line | `an --own-address that is not an address stops startup` (CLI); `an own address that is not an address refuses every request, not none` (access, incl. that `--allow-own-address` still works and which spellings parse) |
| S4 | The mirror decodes the whole growing snapshot after every chunk (quadratic work), checks the 256 MiB cap only on an incomplete decode (a complete oversized snapshot passes), and opening a terminal holds the hub's lock while it waits | Accepted. The snapshot comes from the local Rex, but its size follows terminal history that any program can fill | The end of the snapshot is found from its record framing (10-byte envelope, then 10-byte record headers with a payload length, up to FINISH; Ghostty's `src/terminal/snapshot/main.zig`), which costs nothing per chunk; a record that would end past the cap fails from its header alone, before its bytes arrive; the snapshot is decoded once, and must end exactly where its framing said. Opening a new terminal now waits for its snapshot without the hub's lock; if another viewer opened the same terminal meanwhile, the first registered is kept and the other closed | `mirror: the snapshot's end is found from its framing, and a size over the limit fails early` (agrees with the decoder's own end; byte-by-byte feeding finds it once; a 4 GiB record header refused at once); `hub: a terminal whose snapshot is slow does not hold up other viewers` (1.5 s snapshot; the hub answers in under 0.5 s); `hub: two viewers opening one terminal at once end up sharing one` |
| S5 | On loopback TCP a local process can hold all 16 pre-authentication slots with idle connections and keep the owner out | Accepted (Low). A separate pool alone would not help: any finite pool can be filled | When the pending slots are full, a new connection evicts the oldest connection that has not sent a request head yet. Serve sends its request at once, so it moves past that stage before it can be evicted; idle or slow connections are the ones dropped. A hard cap of twice the slots remains in case eviction cannot keep up | `server: idle connections filling the pending slots do not keep a real request out` (two slots, six idle sockets, a 30 s head deadline: three real requests served at once, the oldest idle socket closed) |

Left as they are, on purpose:

- A stream **restart** (after Rex restarts, or a stream ends and must be rebuilt) still opens under the
  hub's lock, from the supervisor. It is bounded (5 s), caused by Rex rather than by a browser, and moving
  it out needs the terminal pinned against removal meanwhile. Opening a terminal from a browser, the path
  the finding names, no longer holds the lock.
- A process running as the same user on the browser's device can read the browser's cookie store anyway;
  that is outside what a cookie's scope can defend.

## Release-readiness findings

| Item | Verdict | Change |
| --- | --- | --- |
| `README.md` names version 0.1.0 in four places, and ships in every archive | Accepted | Version-agnostic: points to `CHANGELOG.md` and `rweb --version`; install commands use `<version>` |
| `CHANGELOG.md` marks 0.1.1 and 0.1.0 "not yet released" | Correct until the release itself | The release commit stamps the date; 0.1.0 is marked as built and installed but not published |
| Official archives must be built on an Apple-silicon Mac with `zig-0.17.1` from the final commit | Agreed; already the procedure | At release time: `tools/release.sh <commit>` |
| `docs/phase5-result.md` "Next" stale; archive contents line missing `docs/` | Accepted | Updated |
| `src/bridge/access.zig` comment names a host and predates `--backend-secret-file` | Accepted | Rewritten |
| `ownerFromStatus` reads `UserID`, `User` and the user entry without checking their JSON types (a panic in `ReleaseSafe` on odd `tailscale status --json`) | Accepted; `tailscaleDnsName` had the same pattern | Every value's type is checked; both return `NoSelf` on any other shape. Test: `malformed tailscale status is an error, never a crash` |

The readiness review's mobile note (no page changes since 0.1.0) no longer holds: the page now uses
relative addresses. Checked in Chrome and in Mobile Safari (iOS Simulator) in SSH-tunnel mode as above.
Behind Serve the page is at `/`, where relative and absolute addresses are the same; a check through
Serve from another device comes with the next deployment.

## Checks run on the fixes (macOS, Apple silicon)

- `zig build test --summary all`: 150 passed, 9 skipped (the live and gated tests).
- `REX_SOCKET=… zig build test -Doptimize=ReleaseSafe --summary all` against the local Rex (API revision
  19): 206 passed, 1 skipped (the gated Rex-restart test). The owner's sessions were the same before and
  after; the browser check's throwaway `rweb-test-cookie` session was closed.
- `zig build web-test`: 17 passed.
- `sh tools/release-base.test.sh`: 4 passed, 1 skipped (needs root).
