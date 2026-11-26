# Security review, round 5 (2026-11-26)

Inputs, on commit `426e4dd`: an independent release-readiness review on Linux (verdict: ready; four nits),
an external static security scan (one High, one Medium), and an internal review aimed this time at the
classes behind the scan's findings, in three parts, each by a reviewer reading the code without the
others' conclusions: every endpoint and who can own or replace it (E), every decision that rests on a
lookup that can be incomplete (L), and every documented procedure walked as an attacker on shared machines
(P). Every item was checked against the code.

Why the earlier internal rounds missed the scan's two findings: they were split by code area, and neither
finding lives in one file. The tunnel flaw is in the documented procedure (a fixed loopback port another
account can hold while rweb is down); round 2 had even accepted "a local process can churn connections on
a TCP listener" without asking who owns that port when rweb is not running. The macOS group flaw is the
same class as the Linux one fixed in round 4, which was fixed only on Linux. This round adds the missing
step: variant analysis of each finding across endpoints, platforms and procedures.

## Tally

| Id | Finding | Severity | Verdict |
|----|---------|----------|---------|
| X1 / P1 / E3 | SSH tunnel, Rex machine: the documented fixed loopback port can be held by another account while rweb is down (not started, Rex or Tailscale down at start, restarting); the owner's requests, token and cookie go to it | High | Accepted |
| P2 / E1 | SSH tunnel, client: another account or app can hold the forwarded port while the tunnel is down; `-L 7700:…` without a bind address can bind only `::1` and carry on; the page reconnects every 4 s with its cookie; the docs claim the cookie never reaches other local services | High | Accepted |
| E2 | macOS Serve target `127.0.0.1:7695` can be held while rweb is down; Serve then sends it the backend secret and the owner's identity | High (Medium under the single-account rule) | Accepted |
| E3 | rweb binds its port last and exits when Rex or Tailscale is unreachable at start, so the port is free for whole outages | Medium | Accepted |
| X2 / L1 | macOS: a group counts as private from the accounts that can be listed; directory, network and nested members are invisible (verified: `netaccounts` passes) | Medium | Accepted (fixed: macOS never counts a group as private; `admin` stays) |
| P3 | "Only you" in the docs: Tailscale identity covers every device and account signed in as the owner | Medium | Accepted (docs; optional token as a second factor) |
| L2 | Network filesystems pass the checks; their server-side permissions are invisible | Medium | Accepted (refused; the message says to keep rweb's files on a local disk) |
| L4 | Private items (secret, token, upload and socket folders) accept ACL grants to groups, `admin` included | Medium-low | Accepted |
| L3 | A link in the given path, in a folder another user can write, chooses which checked path is used | Medium-low | Accepted |
| P4 | rweb's own startup message suggests `--allow-own-address` | Medium | Accepted |
| E4 | The page sends its credentials to whatever answers on its origin after a drop | Medium | Accepted (owner: tunnel mode reconnects on a tap) |
| L5 | Linux: a user-made loop or udisks mount is not refused | Low-medium | Accepted |
| L6 / L7 | Linux one-person-group rule: groups can come from initgroups, nscd, pam_group, gshadow, subgid and stale credentials | Low-medium | Accepted (the rule is removed; see the command line below) |
| P5 | No procedure to stop or remove rweb; the quick start leaves Serve forwarding to an unsupervised port | Medium-low | Accepted |
| P6 | The token travels through the URL bar: history, sync and suggestion services | Low-medium | Accepted (a token form on the page) |
| E5 | `[::1]` on the same port is never held; `localhost` can reach another account's listener | Low-medium | Accepted |
| P7 | A token file needs only 16 characters, and `<id>` lets anyone who sees it test guesses offline | Low | Accepted (32 characters) |
| P9 | Own addresses are read once at startup | Low | Accepted |
| L8 | The macOS `admin` exception is keyed on gid 80 and applies to private items and ACLs too | Low | Accepted (only for write checks on folders and programs) |
| E6 | macOS `tailscale` CLI's LocalAPI is a loopback port that could be held while Tailscale is down | Low (low confidence) | Documented |
| P8 | Releases are not signed | Low | Planned (PLAN Phase 6) |
| R1-R4 | Readiness nits: changelog logo line, provenance notes only in the generated file, a stale `release.sh` comment, the README's logo not in the archives | Nit | Fixed |

## Plan: fixes by mechanism

1. **No credential goes to a port nobody checked.** (X1, P1, P2, E1-E5)
   - The SSH layout uses a unix socket on the Rex machine in a private folder (`--listen-unix … --token-file …
     --allow-peer-uid self`) and `ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:PORT:/path/to/bridge.sock`:
     nothing on the Rex machine can be held by another account, and the forward fails loudly if its local
     port is taken. Checked live: 403 without the token, the redirect with it, a taken port stops ssh.
   - rweb binds its listener first and keeps it through Rex and Tailscale outages (retrying them instead of
     exiting), and holds `[::1]` as well as `127.0.0.1` on its TCP port.
   - In tunnel mode the page reconnects only on a tap after a drop; a token can be entered on a form instead
     of in the address.
   - A token on a TCP listener prints a warning that points to the unix-socket layout.
2. **Trust only what can be known.** (X2, L1-L8)
   - macOS never counts an ordinary group as private; `admin` passes only write checks on folders and
     programs. Private items accept ACL grants to no group.
   - Linux trusts no group either: a group-writable folder is refused, with the `chmod g-w` that fixes it.
   - Only local filesystems pass; Linux user-made mounts are refused.
   - Links are followed only during the checked walk, each from a folder that already passed.
3. **Docs say exactly what is trusted.** (P3-P6, P9, E6)
   - "Your login" means every device and account signed in as you; how to limit it with Tailscale's access
     rules and Tailnet Lock.
   - The startup message stops suggesting `--allow-own-address`; own addresses are refreshed while running.
   - "Stop or remove rweb"; use `127.0.0.1`, not `localhost`; on macOS remove the Serve entry when rweb is
     stopped for long; the cookie claim corrected.
4. **Readiness nits.** (R1-R4) Done.
5. **The command line, redesigned.** (owner, 2026-11-26: "sane security defaults … the UX, even for the
   command line, has to be holistically thought through".) Safety must not depend on the user knowing
   which of twenty flags to combine, how to make a secret, or what an error name means. No opt-in flag
   that loosens a check is added; each refusal instead says, in plain words, what is wrong and the one
   command that fixes it.
   - **One command per supported layout, everything defaulted:**
     - `rweb tailscale`: behind Tailscale Serve. Linux: unix socket `$XDG_RUNTIME_DIR/rweb/bridge.sock`,
       owner from this node's Tailscale login. macOS: `127.0.0.1:7695` (`--port` to change) with the
       backend secret in `<config>/backend-secret`. Prints the exact `tailscale serve` line to run once.
     - `rweb ssh`: unix socket `$XDG_RUNTIME_DIR/rweb/ssh.sock` (macOS `<config>/run/ssh.sock`), only your
       own user may connect, token in `<config>/token`. Prints the exact `ssh -L …` line for the laptop,
       with this machine's user and host name filled in, and how to sign in.
     - `<config>` is `$XDG_CONFIG_HOME/rweb`, else `~/.config/rweb`; `--config-dir` moves it (for a home
       folder on a network disk).
   - **rweb makes its own files and folders:** a missing secret or token is generated (32 random bytes,
     base64url, created exclusively at 0600) and its folders made 0700, only under folders that pass the
     checks. No hand-typed `head | base64 | tr` pipelines, no `chmod` steps in the guide.
   - **Errors say what and how to fix:** for example
     `rweb: ~/.config can be changed by members of group "me" (mode 0775); rweb keeps its token under it.`
     `  Fix: chmod g-w ~/.config`. Every refusal (group or others write, wrong owner, link, access list,
     network or user-mounted disk, too-open file) has its own plain sentence and fix; internal error names
     no longer reach the user.
   - **The existing options stay** for unusual setups and the current deployments, listed after the two
     commands under "Advanced", with the test-only ones (`--token`, `--random-token`,
     `--allow-own-address`, `--allow-forgeable-loopback-identity`) in their own "For tests" group.
     Everything a layout command sets can be overridden by the same advanced option.
   - **No token as a second factor beside Tailscale in the guide:** one rule per layout, fewer combinations
     to get wrong.

## Second pass: the round-5 code reviewed

The plan above was built as commit `124eb91` (the two commands, the listener taken first, the token form,
tap to reconnect, no group trusted, local disks only, plain messages). That is new code, so it got its own
pass before anything else: an internal adversarial re-review of the new code, an independent
release-readiness review on macOS (builds, tests, the release archives, the binary as a new user meets it
with deliberately broken setups in a temporary folder, the docs against the code line by line), and an
audit of the code against Zig idiom. Every item was checked against the code.

| Id | Finding | Verdict |
|----|---------|---------|
| S1 | The wrong-token limit could be used to lock the owner out: the token was counted before the other checks, so a web page on another site (or a stale cookie) could spend the allowance, and a right token was refused while the limit was reached | Fixed: the checks that need no token come first; wrong tokens from cross-site requests and wrong tokens that arrive only in a cookie are not counted; a right token is never refused |
| S2 | Token mode: one tap on Reconnect armed retries without end, so after one tap the page again sent its cookie to whatever answered | Fixed: one attempt per tap |
| S3 | Plain HTTP on loopback cannot authenticate the server: a program holding the forwarded port while the tunnel is down receives the cookie on a reload and can show a look-alike token form | Documented as a known limit (user guide section 7, README, architecture): use the tunnel only on devices nobody else uses |
| S4 | The message for a refused `tailscale` program used a slice that no longer pointed at live memory | Fixed |
| S5 | Explanations printed paths and names as found, raw control bytes included, to the terminal or log | Fixed |
| S6 | The every-minute refresh of the machine's own addresses replaced the list, so an address that Tailscale stopped reporting was accepted again | Fixed: a refresh only adds |
| S7 | `rweb tailscale --port N` on Linux quietly switched to a loopback port with a backend secret | Fixed: refused on Linux, with what to use instead |
| S8 | The printed `ssh` line took the user and host from the environment and the host name as they were | Fixed |
| S9 | The token field's autocomplete setting invited the browser to save the token as a password | Fixed |
| S10 | A socket path too long for the system was refused only after the token and folders had been made | Fixed: the length is checked before anything is made |
| S11 | The bridge's tests did not compile for Linux (`layout.zig`, a test read `std.c.Stat`, which is empty there), so the Linux suite could not have run on this commit | Fixed |
| S12 | Messages, from running each refusal and its fix: a 0777 folder needed two rounds (`chmod o-w`, then `chmod g-w`); the Serve hint named `tailscale serve reset`, which removes every Serve entry; a taken port did not name `--port`; a short token file's fix gave no length; a link at a layout's own file named no option; `--history-lines` and `--own-address` messages were wrong or doubled; the help said a `--listen-unix` path may have no links | Fixed |
| S13 | Docs: the changelog had nothing from this round and two lines the round made false; the user guide, architecture notes and README described the old command line and trust rules; the README said the final candidate had been run live | Fixed: the guide is written around the two commands; the changelog, architecture notes, README, plan and this record are brought up to the code |

### Zig idiom audit

Verdict: no rewrite; a targeted refactor.

Folded into this round:

- one `peerUid` (the bridge and the Rex client each had their own);
- compile-time guards for the targets rweb supports, instead of code that fails later on another one;
- message dispatch that is exhaustive over the message types, so a new type cannot be silently ignored;
- no swallowed allocation failures in the hub;
- the Linux build links libc explicitly and is position-independent (PIE).

Deferred until after 0.1.1, each to be decided with measurements:

- typed JSON in the Rex client instead of dynamic values;
- the release build's allocator;
- per-frame allocations on the output path;
- waiting on events instead of polling;
- the write-deadline watcher;
- the mutex around `api` calls.

### Fixes, tests and checks

Run on the merged branch (all second-pass fixes in), 2026-11-26. Rex on the Linux host: API revision 19.

- Each second-pass fix has a unit test beside it (`src/bridge/server.zig`, `access.zig`, `xfer.zig`,
  `layout.zig`, `cli.zig`, `main.zig`, `hub.zig`, `protocol.zig`, `tests/web/keys.test.mjs`).
- macOS arm64, no `REX_SOCKET`: `zig build test --summary all`: 382/393 passed, 11 skipped (rex 114 pass
  8 skip, bridge 201 pass 2 skip, fuzz 67 pass 1 skip). `zig build web-test`: 42/42.
- Linux x86-64, against the live Rex (`REX_SOCKET` set):
  `zig build test -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe --summary all`: 390/393 passed,
  3 skipped (rex 121 pass 1 skip, bridge 201 pass 2 skip, fuzz 68 pass). `zig build web-test`: 42/42.
  The owner's sessions were the same before and after. Not run on Linux without a live Rex.
- `tools/release-base.test.sh` on Linux: passed, one case skipped (needs root). `zig build dist` on Linux
  and macOS: both archives and `SHA256SUMS`; the Linux binary is a static-pie, stripped ELF.
  `tools/release.sh` itself was not run (it is for the release commit).
- The Linux release binary as a new user, in a temporary folder: a group-writable parent and a
  world-writable parent are each refused with the right `chmod` line and nothing is made first;
  `rweb tailscale --port` is refused with its explanation; `rweb ssh` makes the token (0600), its folders
  (0700) and socket, prints the `ssh` line, and over the socket: the form 200, a foreign `Host` 403, a
  wrong token 403, the right token 303 to `/s/<id>/`; SIGTERM removes the socket.
- Live, Tailscale layout: `rweb tailscale --port 7796` (macOS release binary) on a Mac, a temporary Serve
  entry on its own port, a throwaway `rweb-test-` session. From Chrome on the Android emulator (Android
  17, on another tailnet node): the page connects, the throwaway terminal opens, text typed through the
  emulator reaches the shell. From Safari on the iOS Simulator (iOS 27.2, another node): the page loads
  and connects. Not run: `rweb tailscale` on Linux through Serve (it needs `sudo tailscale serve`, the
  owner's to run).
- Live, tunnel layout: `rweb ssh` on the same Mac, `ssh -N -o ExitOnForwardFailure=yes -L
  127.0.0.1:7700:<socket>` from the device's host.
  - Android emulator, Chrome: the form shows; a wrong token says "Wrong token" and clears the field; the
    right token lands on `/s/<id>/` with no token in the address; the throwaway terminal opens. With the
    tunnel killed the page shows the Disconnected banner; a listener put on the port received 0
    connections in 12 s with nobody tapping and exactly 1 after one tap ("Could not connect. Is the SSH
    tunnel running?"); with the tunnel back, one tap reconnects.
  - iOS Simulator, Safari: the form shows; signed in by address (`?token=`), because automated taps and
    typing do not reach the page on this simulator version; after the tunnel is killed the page shows
    "Disconnected. Restart the SSH tunnel, then reconnect." with the Reconnect button. Not shown there:
    typing into the form, the tap itself.
- All test bridges, the Serve entry, the session, the tunnels and temporary files were removed; the
  deployed services were not touched.
- Not verified by any of this: the owner's phone (a real soft keyboard, the phone's Tailscale app, an
  SSH app forwarding to a unix socket), a Linux host through Serve with the new command, existing
  deployments against the new refusals.

For reference, the readiness review's results on `124eb91` itself, before the fixes (macOS arm64, Zig
0.17.1, no live Rex): `zig build test --summary all` 290/300 passed, 10 skipped; `zig build web-test`
36/36; `zig build -Dtarget=x86_64-linux-musl -Doptimize=ReleaseSafe` built; `zig build test
-Dtarget=x86_64-linux-musl` failed to compile (S11); `tools/release-base.test.sh` 4 ok, 1 skipped (needs
root); `zig build dist` twice gave the same checksums, with the expected members, modes and timestamps.
The token form, header sign-in, the `/s/<id>/` cookie and the wrong-token limit were checked with curl
against the release binary on `127.0.0.1` with the tests' stand-in Rex. Not run then: Linux, a live Rex,
a browser, a simulator, a phone.

### What is left

- The owner's phone, `rweb tailscale` on Linux through Serve, and checking the existing hosts against the
  new refusals (group-writable folders, token length, disks) before they are upgraded.
- Clean shutdown was added: on SIGTERM or SIGINT rweb removes its socket if the entry is still its own
  (checked on Linux and macOS). SIGKILL leaves it; the next start clears it.
- The deferred items of the idiom audit.
