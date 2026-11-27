# rweb user guide

rweb lets you reach your Rex sessions from a phone, tablet or laptop browser when you are away from the
machine: answer a prompt, check an output, run a quick command. This guide covers installing it, reaching
it through Tailscale or an SSH tunnel, starting it at boot or login, running it on several machines,
using the page, upgrading and troubleshooting. For why rweb exists see the [README](../README.md); for
how it works see [architecture.md](architecture.md).

Contents: [1 What you need](#1-what-you-need) · [2 Install](#2-install) ·
[3 Choose how to reach it](#3-choose-how-to-reach-it) · [4 Tailscale setup](#4-tailscale-setup) ·
[5 Run behind Tailscale on Linux](#5-run-behind-tailscale-on-linux) ·
[6 Run behind Tailscale on macOS](#6-run-behind-tailscale-on-macos) · [7 SSH tunnel](#7-ssh-tunnel) ·
[8 Several machines](#8-several-machines) · [9 Using the page](#9-using-the-page) ·
[10 File transfer](#10-file-transfer-off-by-default) ·
[11 Upgrade, stop or remove](#11-upgrade-roll-back-stop-or-remove) ·
[12 Troubleshooting](#12-troubleshooting) · [13 Advanced: every option](#13-advanced-every-option)

## 1. What you need

- **A machine running Rex**, Linux (x86-64) or macOS (Apple silicon), with the Rex server running for your
  user. rweb does not start Rex. It finds Rex's socket in `~/Library/Application Support/Rex/` (macOS),
  `$XDG_RUNTIME_DIR/rex/` or `/run/user/<uid>/rex/`; `--rex-socket PATH` names another place. If Rex is
  not running when rweb starts, rweb waits for it (section 12).
  Windows is not supported yet; it will come later.
- **A way in**: Tailscale on the Rex machine and on your phone or laptop (section 4), or SSH access to the
  Rex machine (section 7).
- **A browser** on the phone, tablet or laptop. Nothing is installed there.

## 2. Install

**Homebrew** (macOS on Apple silicon, Linux x86-64), from the tap `lexlapax/rweb`:

```sh
brew tap lexlapax/rweb && brew trust lexlapax/rweb   # Homebrew loads a tap's formulae only once trusted
brew install rweb
```

Then run `rweb tailscale` once in a terminal (section 5 or 6), and `brew services start rweb` keeps it
running at login (on Linux, also `sudo loginctl enable-linger "$USER"` to start it at boot). The formula
installs the release archive below, checked by its SHA-256.

**Arch Linux**, from the AUR: the package `rweb-bin`, with any AUR helper
(`yay -S rweb-bin`). It installs `/usr/bin/rweb` and a systemd user unit, `rweb.service`, that runs
`rweb tailscale`: `systemctl --user enable --now rweb`.

**The release archive**, anywhere else. Download the archive for your platform, `SHA256SUMS` and `SHA256SUMS.sig` from the release, then:

```sh
echo 'rweb-release namespaces="file" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIB0wc9eAtN/xCGWv2pru3OpgCrJd6mUNNxhHU7ht0RdW' > rweb-release-signers
ssh-keygen -Y verify -f rweb-release-signers -I rweb-release -n file -s SHA256SUMS.sig < SHA256SUMS
shasum -a 256 -c SHA256SUMS --ignore-missing     # Linux: sha256sum -c SHA256SUMS --ignore-missing
tar -xzf rweb-<version>-<platform>.tar.gz
mkdir -p ~/.local/bin && install -m 0755 rweb-<version>-<platform>/rweb ~/.local/bin/rweb
rweb --version
```

The first two lines check that `SHA256SUMS` was signed with rweb's release key (`ssh-keygen` is part of
OpenSSH; it should say `Good "file" signature for rweb-release`); the third that the archive is the one
`SHA256SUMS` names. Take the key from this guide or the README (also `tools/release-signers` in the source
repository), not from the release page, so that someone who could change the release could not also
change the key. Releases signed so: from 0.3.0 on.

The archive holds `rweb`, this guide and the architecture notes (`docs/`), the README and its pictures
(`assets/`), the services of sections 5 and 6 (`contrib/systemd/rweb.service`,
`contrib/launchd/local.rweb.plist`), the changelog, the licence (MIT) and the third-party notices. `rweb --version` shows the
version, the commit it was built from, and the Rex API revisions it speaks. To build from source instead:
`zig build -Doptimize=ReleaseSafe` with Zig 0.17.1 (see the README).

## 3. Choose how to reach it

rweb never listens on the network. It listens on a unix socket or on loopback, and something you trust
brings your browser to it. There is one command for each way:

| | `rweb tailscale` | `rweb ssh` |
| --- | --- | --- |
| Who is let in | your own Tailscale login, checked on every request | whoever has the token |
| From a phone | the Tailscale app; open an `https://` address | an SSH app that forwards ports to a unix socket |
| Address | `https://<machine>.<tailnet>.ts.net:<port>/`, the same everywhere | `http://127.0.0.1:<port>/` on the device running the tunnel |
| Needs | Tailscale on both ends | SSH access to the Rex machine |
| Best for | everyday use, phones | no Tailscale, or occasional use from a laptop nobody else uses |

`rweb` alone prints these two commands; `rweb --help` lists every option.

**What the commands set up.** Each command chooses where rweb listens, makes the files it needs and
prints the one step that is left (a `tailscale serve` line, or an `ssh` line for your laptop). rweb keeps
its files in `<config>`, which is `$XDG_CONFIG_HOME/rweb` when that is set, else `~/.config/rweb`. A
missing secret or token is made there (32 random bytes, mode `0600`) and missing folders are made `0700`;
an existing file is never replaced. You do not make secrets or folders by hand. Two options apply to both
commands:

- `--config-dir PATH` puts `<config>` somewhere else (an absolute path). Use it when your home folder is
  on a network disk, which rweb does not trust (section 12, "Files and folders rweb checks").
- `--port N`: for `rweb ssh`, the port on your laptop in the printed `ssh` line (default 7700); for
  `rweb tailscale` on macOS, the loopback port Serve forwards to (default 7695).

**Starting before Rex or Tailscale.** rweb takes its socket or port first and keeps it. If Tailscale or
Rex is not up yet (at boot, say), rweb does not exit: it says so once a minute and asks again until they
answer. Until Rex has answered, a browser that connects gets no reply and waits.

**What "your own Tailscale login" covers.** Every device signed in to Tailscale as you, and every account
and program on those devices: Tailscale names the person, not the app or the local user. If you sign in to
Tailscale as yourself on a shared computer, a server or a build machine, anything running there can reach
rweb as you. Keep your login on devices only you use, or limit who can reach the rweb port with
Tailscale's access rules (grants that let only your phone and laptop reach port 12443 on the Rex
machine), and consider Tailnet Lock.

## 4. Tailscale setup

Do this once per tailnet, then once per machine.

1. **Install Tailscale** on the Rex machine ([download](https://tailscale.com/download); on Linux your
   distribution's package plus `sudo tailscale up`, on macOS the Tailscale app) and on your phone or
   laptop. Sign in to **the same Tailscale account** on all of them: rweb lets in only the login the Rex
   machine itself belongs to.
2. **Turn on MagicDNS and HTTPS certificates** for the tailnet in the Tailscale admin console (the DNS
   page). Serve needs them to give the machine an `https://<machine>.<tailnet>.ts.net` address with a
   valid certificate.
3. **Linux only:** Tailscale 1.94 or newer, which can forward to a unix socket (setting that up needs
   root). Check with `tailscale version`.
4. **Where rweb finds `tailscale`.** rweb runs it to learn your login, the machine's name and the
   machine's own addresses, from fixed places only, never through `PATH`: on macOS the app's own program
   (`/Applications/Tailscale.app/Contents/MacOS/Tailscale`), then `/usr/local/bin/tailscale` and
   `/opt/homebrew/bin/tailscale`; on Linux `/usr/bin/tailscale`, `/usr/local/bin/tailscale` and
   `/usr/sbin/tailscale`. Elsewhere, pass `--tailscale /absolute/path`. The program and every folder above
   it must be root's or yours, so another account cannot swap it (see "Files and folders rweb checks" in
   section 12).
5. **Check:** `tailscale status` on the Rex machine lists your phone or laptop, and both show the same
   user.

**Tagged machines.** If the Rex machine is a tagged device (a server or gateway added with a tag, shown
under its tags in the admin console), it has no owner login, and rweb stops with a message that says so.
Name yourself instead: `rweb tailscale --owner you@example.com --allow-host <machine>.<tailnet>.ts.net`
(your Tailscale login and the machine's own name). rweb refuses `--owner` without `--allow-host`.

Keep **Funnel off** for rweb's port: Funnel would publish it on the internet, and rweb refuses every
request that comes through Funnel anyway. Devices that are tagged, or shared into your tailnet by someone
else, do not carry your login and are refused. If your tailnet restricts access with ACLs, allow your
devices to reach the Rex machine on the port you choose below.

## 5. Run behind Tailscale on Linux

`rweb tailscale` listens on the unix socket `$XDG_RUNTIME_DIR/rweb/bridge.sock`, in a folder only you can
enter, and accepts connections only from root, which is `tailscaled`. No other program on the machine,
not even one running as you, can use it. It takes the owner from the machine's own Tailscale login.

Try it in a terminal first:

```sh
rweb tailscale
```

It prints the `sudo tailscale serve …` line to run once and the address to open. Run that line in another
terminal, then open the address on your phone or laptop (from **another device**: a request from the Rex
machine itself is refused, because any program there could make it). Stop rweb with Ctrl-C.

To keep it running, a systemd user service. **From the AUR** it is installed already
(`/usr/lib/systemd/user/rweb.service`, running `/usr/bin/rweb tailscale`): skip the file and run the
commands below it. **With Homebrew**, `brew services start rweb` takes its place (and the `loginctl` line
below still applies). **From the archive**, copy `contrib/systemd/rweb.service` from it to
`~/.config/systemd/user/rweb.service`; it is this file:

```ini
[Unit]
Description=rweb, a web client for Rex
# If your Rex server runs as a user service, start after it:
After=rex.service
Wants=rex.service

[Service]
ExecStart=%h/.local/bin/rweb tailscale
# rweb waits for Tailscale and Rex by itself; this restarts it only if it stops.
Restart=always
RestartSec=5
UMask=0077
NoNewPrivileges=yes

[Install]
WantedBy=default.target
```

```sh
systemctl --user daemon-reload && systemctl --user enable --now rweb
sudo loginctl enable-linger "$USER"      # start at boot, before you log in
journalctl --user -u rweb -n 20          # the Serve line and the address, if you have not run it yet
tailscale serve status                   # what Serve forwards
```

The printed line uses port 12443; any free port works instead (change the number after `--https=`;
`tailscale serve status` lists those in use). Tailscale stores the Serve entry and keeps it across
reboots, so you set it up once; section 11 says how to remove it.

## 6. Run behind Tailscale on macOS

The Tailscale app cannot forward to a unix socket, so `rweb tailscale` listens on loopback,
`127.0.0.1:7695` (and `[::1]:7695`, so `localhost` cannot lead to another program). Any local program
could send a loopback request carrying your identity headers, so rweb also requires a long secret as the
first part of every path, which only Tailscale Serve knows. rweb makes that secret in
`<config>/backend-secret` the first time it starts.

**Use this layout only on a Mac where you are the only local account.** The secret is part of the Serve
target, so other accounts on the Mac may be able to read it in `tailscale serve status`, or in the
process list while the `tailscale serve` command runs. And while rweb is not running (before you log in,
after you log out, while it restarts), another account could listen on its port and receive your requests,
the secret included. With the secret, another account could send requests with your identity to rweb. On a
Mac shared with other accounts, do not run rweb this way. When you stop using rweb for a while, remove
the Serve entry (section 11); if you ever see the page fail for no reason you know, make a new secret
(remove `<config>/backend-secret`, restart rweb and run the printed Serve line again).

Try it in a terminal first:

```sh
rweb tailscale
```

It prints the `tailscale serve …` line to run once (the line reads the secret from its file, so the secret
itself is never printed) and the address to open. Run that line in another terminal, then open
`https://<machine>.<tailnet>.ts.net:12443/` on your phone or laptop. Open it from **another device**: a
request from the Rex machine itself is refused, because any program there could make it. Stop rweb with
Ctrl-C. `--port N` chooses another loopback port.

To keep it running: **with Homebrew**, `brew services start rweb` (its log is
`$(brew --prefix)/var/log/rweb.log`, where the Serve line and the address appear). **From the archive**, a LaunchAgent: copy
`contrib/launchd/local.rweb.plist` from it to `~/Library/LaunchAgents/local.rweb.plist` and replace `YOU`
with your user name. It is this file:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.rweb</string>
  <key>ProgramArguments</key><array>
    <string>/Users/YOU/.local/bin/rweb</string>
    <string>tailscale</string>
  </array>
  <key>StandardOutPath</key><string>/Users/YOU/Library/Logs/rweb.log</string>
  <key>StandardErrorPath</key><string>/Users/YOU/Library/Logs/rweb.log</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
```

```sh
launchctl bootstrap "gui/$(id -u)" ~/Library/LaunchAgents/local.rweb.plist
tail -20 ~/Library/Logs/rweb.log         # the Serve line and the address, if you have not run it yet
```

rweb does not need `PATH` (it finds `tailscale` in fixed places, section 4). A LaunchAgent starts when
you log in, which is when Rex.app runs; with FileVault on, nothing of yours runs until you have unlocked
the disk after a restart.

## 7. SSH tunnel

Without Tailscale, `rweb ssh` listens on a unix socket on the Rex machine that only your own user can
connect to, and SSH forwards a port on your device to it. A token is what stands between a program that
can reach that port and your Rex sessions. rweb makes the token (random, in `<config>/token`, readable
only by you) the first time it starts; do not make one up, and never pass it on a command line.

Why a unix socket and not a port on the Rex machine: a port is free while rweb is not running, and on a
machine with other accounts another user could take it then and receive your token. A socket in a folder
only you can open cannot be taken.

On the Rex machine (on macOS, turn on Remote Login in System Settings → General → Sharing first):

```sh
rweb ssh
```

It prints two things: the `ssh` line to run on your laptop, with the socket's path and this machine's
user and host name filled in, and the command that shows the token. The socket is
`$XDG_RUNTIME_DIR/rweb/ssh.sock` on Linux and `<config>/run/ssh.sock` on macOS. The printed line looks
like this:

```sh
ssh -N -o ExitOnForwardFailure=yes -o ServerAliveInterval=15 \
    -L 127.0.0.1:7700:/run/user/1000/rweb/ssh.sock you@rex-machine
```

Use the name or address your laptop reaches the Rex machine by if it differs from the one printed. Keep
the `127.0.0.1:` in front of the port, and keep `ExitOnForwardFailure=yes`: if another program already
holds the port, ssh then stops with an error instead of running without a tunnel. `rweb ssh --port N`
prints another laptop port. On a phone, use an SSH app that can forward a local port to a remote unix
socket, and keep it open while you use the page.

To keep rweb running, use the service file from section 5 or 6 with `ssh` in place of `tailscale`. The
Homebrew and AUR services run `rweb tailscale`; for a tunnel, write that file yourself (on Linux,
`systemctl --user edit --full rweb` makes a copy of the AUR unit to change).

**Signing in.** Open `http://127.0.0.1:7700/` (use `127.0.0.1`, not `localhost`). The page shows a token
form. On the Rex machine, `cat` the token file rweb named at startup (`~/.config/rweb/token` unless you
moved `<config>`) and paste its contents into the form. The token is sent once, in a request header,
never in the address, so it does not end up in the browser's history or synced address suggestions. rweb
moves you to `http://127.0.0.1:7700/s/<id>/` with the token in a session cookie for that path only.
Bookmark that address: later visits in the same browser session need no token. After the browser forgets
the cookie, sign in with the form again. (Opening `http://127.0.0.1:7700/?token=<the token>` also works,
but leaves the token in the history.)

**If the tunnel drops** (sleep, a network change), the page shows **Disconnected** and a **Reconnect**
button instead of retrying by itself: whatever holds the port after a drop gets nothing unless you ask.
Restart the tunnel first, then tap Reconnect; each tap makes one attempt.

**A known limit: use the tunnel only on devices nobody else uses.** The page is plain HTTP on loopback,
and plain HTTP cannot prove who is answering. Cookies are not tied to a port: a browser sends
`127.0.0.1`'s cookies to whatever program holds port 7700 at that moment. What limits the token's cookie
is its path: it is sent only for addresses under `/s/<id>/`, which other local services do not know. So:

- another web service on another port of `127.0.0.1` does not receive the cookie, as long as nothing
  sends your browser to that port with the `/s/<id>/` path;
- a program that holds port 7700 on your device while the tunnel is down receives the cookie when you
  reload the page or tap Reconnect, and could show a look-alike token form at `/` and receive the token
  you paste.

`ExitOnForwardFailure=yes` makes ssh refuse to start when the port is already held, and the page does not
reconnect by itself, but neither can tell you who answers. Use the tunnel only on devices other people do
not log in to, and on a phone, with apps you trust. Where that is not so, use Tailscale (section 4).

Treat the `/s/<id>/` address like the token. The `<id>` is made from the token, and with it someone can
test guesses of the token on their own machine; that is why the token is random and at least 32
characters. Do not share the address or post screenshots that show it. To change the token, remove
`<config>/token` and restart rweb: it makes a new one, and the old token and the old `/s/<id>/` address
stop working.

## 8. Several machines

Run one rweb on each machine that runs Rex; each serves only its own Rex. With Tailscale every machine
gets its own address, so the same port can be used on all of them:

```text
https://desk.<tailnet>.ts.net:12443/      sessions on desk
https://server.<tailnet>.ts.net:12443/    sessions on server
```

Bookmark each, or add each to the phone's home screen. With SSH tunnels give each machine its own local
port (`rweb ssh --port 7701` on desk, `rweb ssh --port 7702` on server, each printing its own `ssh` line);
each has its own token and its own sign-in, and each `/s/<id>/` address is as secret as its token
(section 7). Rex sessions on one machine are not visible through another machine's rweb.

## 9. Using the page

- **Sessions and terminals.** The ☰ drawer lists sessions and their terminals; tap one to open it. The top
  bar shows the session, the running program and folder, and listening ports. The tab strip switches
  between the session's terminals, and **+** adds one. Create, rename and close sessions in the drawer and
  terminals in the tab's ⋯ menu.
- **Typing on a phone.** Tap the terminal for the keyboard. The key bar adds the keys a phone keyboard
  lacks: Enter, Esc, Tab, ^C, Ctrl, Alt and Shift (tap once to apply to the next key) and the arrows; **^**
  expands it with PgUp/PgDn, Home/End, symbols and Paste.
- **Scrolling.** Drag to scroll back through history. Over a full-screen program (an editor, a pager, a
  coding agent) a drag scrolls inside that program, as a mouse wheel would.
- **Size.** Rex owns the terminal's size, and every client shares it. On a touch screen the page asks Rex
  to fit the terminal to your screen ("Fit Rex to this screen" in the ⋯ menu); elsewhere it shrinks the
  text to fit instead. **+/−** in the ⋯ menu changes the text size.
- **The ⋯ menu** (top right): Copy text (a view for selecting and copying lines); Text copied in the
  terminal (what a program put on the clipboard); Paste; Download a file and Upload files (when enabled);
  Clear screen; Reset terminal; text size **−/+**; View only (no typing from this browser); Fit Rex to this
  screen; Use Rex colours (with wterm, Rex's colour theme in place of the page's own; xterm.js always uses Rex's); Fit terminal to this window;
  Load all scrollback; Touch diagnostics; the terminal engine (wterm, or the older xterm.js); Reconnect;
  "rweb X.Y.Z is available" when a newer release is out (the ⋯ button then has a dot; the item opens the
  release notes, section 11); About rweb, with this rweb's version under it (it opens rweb's page on
  GitHub in a new tab, as the logo at the top left also does; no address of your page is sent with it).
  [The menu in a desktop browser](../assets/screenshots/menu.png). The logo turns slowly while the terminal
  on screen is printing and comes to rest upright a moment after it stops; it stays still if your
  device asks for reduced motion.
- **Pasting.** A paste reaches the program as a paste, without escape characters, so pasted text cannot
  pretend the paste ended and type the rest as commands. Text a phone keyboard inserts in one go (its
  clipboard suggestion, say) is treated as a paste too. If the text has several lines and the program has
  not turned on bracketed paste (plain `sh`, an old shell, some REPLs), each line would run as it arrives,
  so the page shows the text and asks first (the page goes by what the program announced: a program that
  claims bracketed paste and does not handle it is not caught). A paste is at most 32 KB. "Text copied in
  the terminal" shows what a program put on the clipboard, without control characters; any program can
  set it.
- **Reconnecting.** Behind Tailscale it is automatic: after sleep or a network change the page reconnects
  and redraws. Through an SSH tunnel the page shows **Disconnected** and waits for you to tap
  **Reconnect** (section 7).

## 10. File transfer (off by default)

`--enable-file-transfer` (added to `rweb tailscale` or `rweb ssh`) lets the page download any file your
user can read (through Rex), and with `--upload-dir DIR` upload into that one folder. rweb makes the
folder `0700` if it is missing. It must be yours, closed to other users and on a local disk, and the
folders above it must pass the checks in section 12 ("Files and folders rweb checks"). Uploaded files
never replace an existing one, and their path is pasted at the prompt of the terminal you chose them
for (if you switch terminals or turn on "View only" while it is on its way, the upload is refused). A
file appears in the folder only when all of it has arrived and is on disk; until then it is in
`.rweb-partial/` inside the folder, which is rweb's own (what a stopped rweb left there is removed at
the next start; do not keep files in it). `--max-transfer-mb N` limits the
size (default 256). Turn it on only if you want the browser to have that reach. Design and limits:
[file-transfer.md](file-transfer.md) (in the source repository).

## 11. Upgrade, roll back, stop or remove

**Knowing when to upgrade.** Once a day, starting 10 minutes after it starts, rweb asks GitHub's API for
its latest release (one HTTPS request to `api.github.com`, given up after 10 seconds; only the version is
read; it follows no redirect). When a newer version is out it says so once in its log, puts a dot on the page's ⋯ button with an
item, "rweb X.Y.Z is available", that opens the release notes, and `rweb doctor` reports it with the
upgrade command for how rweb was installed. It never downloads or installs anything. What GitHub learns
from it: this machine's address, that it runs rweb, and which version. To turn it off, start rweb with
`--no-update-check`: add it to `ExecStart` or the LaunchAgent's `ProgramArguments`; for the AUR unit,
`systemctl --user edit --full rweb`; with Homebrew, run rweb from your own service (section 5 or 6)
instead of `brew services`.

To upgrade, read [CHANGELOG.md](../CHANGELOG.md), then:

- **Homebrew:** `brew upgrade rweb && brew services restart rweb`.
- **AUR:** upgrade `rweb-bin` with your helper (`yay -Syu rweb-bin`), then `systemctl --user restart rweb`.
- **Archive:** install the new archive over `~/.local/bin/rweb` as in section 2, signature first (keep the
  old binary if you may want it back), then `systemctl --user restart rweb` on Linux or
  `launchctl kickstart -k "gui/$(id -u)/local.rweb"` on macOS.

`rweb doctor` names the command for how this rweb was installed. Restarting rweb does not touch your Rex
sessions; pages behind Tailscale reconnect by themselves, and a page through an SSH tunnel waits for a
tap on Reconnect. The Serve entry, the secret and the token stay as they are.

**Upgrading to 0.3.1.** Nothing to change. The ⋯ menu's "About rweb" shows the version you run.

**Upgrading to 0.3.0.** Nothing to change: the options, files and Serve entry are the same as in 0.2.0.
New: rweb asks GitHub once a day whether a newer release is out (above); add `--no-update-check` to the
service's command to turn that off. `rweb doctor` checks a setup. A page reached over plain HTTP behind
Tailscale Serve, or on another port, can no longer open a terminal: open rweb at the `https://` address
`rweb tailscale` printed, as before.

**Upgrading to 0.2.0.** Nothing to change: the options, files and Serve entry are the same as in 0.1.1.
It speaks Rex API revisions 18 to 24, so it works with Rex 0.1.0-preview.25 at its own revision and still
with older servers.

**Upgrading to 0.1.1.** A service that starts rweb with the 0.1.0 options (`--listen-unix`,
`--listen-tcp`, `--owner-from-tailscale`, `--backend-secret-file`, `--token-file` and the rest) keeps
working: they are all still there (section 13). You can move to `rweb tailscale` or `rweb ssh` when it
suits you; on Linux and macOS `rweb tailscale` uses the same socket, port and secret file as the 0.1.0
guide did, so the Serve entry stays valid. What 0.1.1 refuses that 0.1.0 accepted, each with a message
that names what to fix (section 12):

- A token shorter than 32 characters, in a token file or with `--token` (0.1.0 accepted 16), or one with
  characters other than letters, digits, `-` and `_`. A token made as the 0.1.0 guide said is long enough.
- `--owner` without `--allow-host`.
- A secret file, token file, upload folder, socket folder or `tailscale` program that another user could
  change or replace. In particular: a folder above it that its group can write to (no group is trusted
  any more, not even a group that holds only you; `chmod g-w` the folder), and a network disk or a disk a
  user mounted (move rweb's files to a local disk with `--config-dir`, or name local paths).
- A `--listen-unix` path that is not absolute.

What 0.1.1 does differently:

- rweb no longer exits when Tailscale or Rex is not up at start. It keeps its socket or port and asks
  again, so a service no longer restarts in a loop at boot.
- Through an SSH tunnel: sign in with the token form at `/` and use the `/s/<id>/` address it leads to
  (section 7); after a drop the page waits for a tap on Reconnect; the documented setup is a unix socket
  on the Rex machine, not a port. A `--listen-tcp` port with a token still works and prints a warning.
- `tailscale` must be in one of the places section 4 lists, or named with `--tailscale`.

To stop rweb for good, or for a long time, remove what points at it as well as rweb itself, so nothing
keeps sending your requests to a port or socket nobody serves:

```sh
tailscale serve --https=12443 off                          # the Serve entry (use your port; Linux: sudo)
systemctl --user disable --now rweb                        # Linux
sudo loginctl disable-linger "$USER"                       # Linux, if nothing else needs it
launchctl bootout "gui/$(id -u)/local.rweb"                # macOS
rm ~/Library/LaunchAgents/local.rweb.plist                 # macOS
rm -f ~/.config/rweb/backend-secret ~/.config/rweb/token   # the secret and the token
rm -rf ~/.config/rweb/run                                  # macOS: the folder of rweb ssh's socket
rm ~/.local/bin/rweb
```

Installed with Homebrew: `brew services stop rweb && brew uninstall rweb` in place of the service and
binary lines (`brew untap lexlapax/rweb` too, when nothing else comes from it). From the AUR:
`systemctl --user disable --now rweb` and `sudo pacman -R rweb-bin`. The Serve entry and the files in
`~/.config/rweb` are removed as above either way.

`tailscale serve --https=12443 off` removes only that entry; `tailscale serve reset` removes every Serve
entry on the machine, rweb's or not. When you have only tried rweb in a terminal, stop it with Ctrl-C and
remove the Serve entry the same way, or set up the service from section 5 or 6.

## 12. Troubleshooting

Start with `rweb doctor`. It checks a setup the way `rweb tailscale` would use it (`rweb doctor ssh` for
an SSH tunnel; add the options you start rweb with, such as `--config-dir`) and says what to fix: Rex
(running, answering, an API revision rweb speaks), the backend secret or token file and the upload folder
(the same checks as at startup), whether a bridge is listening, and for Tailscale whether it is signed
in, has HTTPS certificates on, and has a Serve entry that forwards to this bridge with Funnel off. Last, it
asks GitHub whether a newer rweb is released, as the bridge does once a day (section 11), and says how to
upgrade this one; `--no-update-check` leaves that out. On macOS, when name lookups hang, that last check
can take as long as the system's resolver does before it gives up. It changes nothing and exits 1 when a check fails. A file rweb makes at its first start is a note, not a
failure. It never prints the backend secret or the token.

```
$ rweb doctor
rweb doctor: checking rweb tailscale (rweb 0.3.1)
  ok    Rex answers at /run/user/1000/rex/server.sock, API revision 24 (rweb speaks 18 to 24)
  ok    a bridge is listening on unix:/run/user/1000/rweb/bridge.sock
  ok    Tailscale: box.example.ts.net, signed in as you@example.com (/usr/bin/tailscale)
  ok    Tailscale: HTTPS certificates are on
  FAIL  Tailscale Serve: nothing forwards to this bridge
        if Tailscale Serve is not set up for rweb yet, run this once:
        sudo tailscale serve --bg --https=12443 unix:/run/user/1000/rweb/bridge.sock
        …
  ok    rweb 0.3.1 is the latest release
rweb doctor: 5 passed, 0 notes, 1 failed
```

Logs: `journalctl --user -u rweb -n 50` (Linux service, the AUR's included), `~/Library/Logs/rweb.log`
(macOS LaunchAgent), `$(brew --prefix)/var/log/rweb.log` (`brew services`, on macOS and Linux).
When rweb refuses to start, its message names what is wrong and, for a file or folder, ends with a
`Fix:` line holding the command or change that puts it right. Run it and start rweb again; a second
message means a second thing to fix.

| You see | Why, and what to do |
| --- | --- |
| A message about a file or folder (the token file, the backend secret, the upload folder, the socket's folder, the `tailscale` program, or a folder above one of them), with a `Fix:` line | Another user could read, change or replace it: it is too open, not yours, a link where rweb follows none, has an access list entry for someone else, or is on a disk rweb does not trust. Do what the `Fix:` line says. The rules are below. |
| `… is on a network disk` (or a FUSE filesystem, a disk image, a disk a user mounted) | rweb keeps its files only on local disks. `rweb tailscale --config-dir /local/path` (or `rweb ssh --config-dir …`) moves them; for an upload folder or socket, name a local path. |
| `Rex is not running: …` | rweb found no Rex socket, or nothing answers on it. rweb keeps running and asks again; start Rex, or pass `--rex-socket PATH` if the socket is elsewhere. Until Rex answers, the page does not load. |
| The page never loads right after rweb started | The same: rweb holds its socket or port but answers nothing until Rex is up. Check the log. |
| `the socket … is served by another user` | The Rex socket rweb found does not belong to your user: rweb refuses it. Check `--rex-socket` and `XDG_RUNTIME_DIR`. |
| `Rex … speaks an API revision this rweb does not` | Rex is newer or older than this rweb supports (`rweb --version` shows the range): update rweb or Rex. |
| `this node is a tagged Tailscale device` | Use `--owner` and `--allow-host` (section 4, tagged machines). |
| `cannot find the tailscale program …` or `there is no tailscale program at …` | Tailscale is not where rweb looks (section 4): install it, or pass `--tailscale /absolute/path`. |
| A message about `the tailscale program` with a `Fix:` line | That program, or a folder above it, can be changed by another account. rweb does not try the other install locations after a refusal: fix that one, or pass `--tailscale` with another. |
| `cannot read this node's Tailscale …` | Tailscale is down, or not signed in. rweb keeps running and asks again; start Tailscale or sign in. |
| The page stops loading and the log says `this node's Tailscale addresses have not been confirmed …` | Tailscale has not answered rweb for two and a half minutes, so rweb cannot tell a request from this machine itself and refuses all until it answers. Start Tailscale or sign in; rweb carries on by itself. |
| `rweb knows none of this node's Tailscale addresses` | Pass them with `--own-address IP` (from `tailscale ip`). |
| `--owner needs --allow-host NAME` | Add `--allow-host <machine>.<tailnet>.ts.net` (section 4, tagged machines). |
| `--token: must be at least 32 characters …` | Use `rweb ssh`, which makes a token file, instead of `--token`. |
| A token file that `is too short` or `holds characters other than …` | A token is at least 32 letters, digits, `-` and `_`. Remove the file and start `rweb ssh` again: it makes a new one. |
| `another program is already listening on …` | Another rweb is running, or another program holds the port: stop it, or choose another port (`--port N`) or socket. |
| `… is too long for a unix socket` | A unix socket's path may be about 100 characters. Choose a shorter `--config-dir` (macOS `rweb ssh`) or `--listen-unix` path. |
| `… exists and is not a socket` | Something else sits at the socket's path; rweb never replaces it. Move it away. |
| `HOME is not set …` | rweb cannot tell where `<config>` is: set `HOME` or pass `--config-dir PATH`. |
| `made a random token; it is not shown …` | `--random-token` (or `--listen-tcp` with no access rule) shows its address only in a terminal, never in a log. Use `rweb ssh`. |
| The page keeps reconnecting while others work | rweb takes at most 32 browser connections at once and answers more with 503 "too many viewers"; close other tabs. |
| 403 from your phone through Tailscale | The phone is signed in to a different Tailscale account, or is a tagged or shared device; or you opened the page on the Rex machine itself (use another device). The log line `refused: …` says which. |
| The token form says "Wrong token" | Paste the whole contents of the token file (section 7), with nothing added. |
| 429, or the form says "Too many attempts" | More than 10 wrong tokens were tried in a minute. Wait a minute. |
| **Disconnected**, with a Reconnect button (SSH tunnel) | The tunnel dropped. Start it again, then tap Reconnect (section 7). |
| 404 for everything (macOS, Tailscale) | Serve does not point at the current secret: run the `tailscale serve` line rweb printed again. |
| The browser cannot connect at all | Tailscale: `tailscale serve status` on the Rex machine. SSH: is the tunnel still open? |
| Sessions do not appear | rweb cannot reach Rex, or Rex refused its API revision: check the log and `rweb --version`. |
| Typing does nothing | View only is on (⋯ menu), or rweb runs with `--observe-only`. |
| The page loads but never connects, and the log says `refused: bad Origin` | The page was opened at another address than the one rweb serves: over `http://` behind Tailscale, on another port, or through another name. Open the `https://` address `rweb tailscale` printed (or, for a tunnel, the `http://127.0.0.1:<port>/` one). |
| A dot on the ⋯ button | A newer rweb is released: the ⋯ menu's "rweb X.Y.Z is available" opens its notes; section 11 says how to upgrade. |
| `rweb doctor` notes `could not ask GitHub for rweb's latest release` | This machine could not reach `api.github.com` (offline, a proxy, a firewall). A note, not a failure; `--no-update-check` leaves the check out. |
| `brew install rweb` will not load the formula | Homebrew loads a third-party tap's formulae only once the tap is trusted: `brew trust lexlapax/rweb`, then install again. |

**Files and folders rweb checks.** The backend secret, the token file, the upload folder, the unix
socket's folder and the `tailscale` program must be such that no other account could change them. The
rules:

- **The item itself.** A secret or token is a regular file of yours, mode `0600`. The upload folder and
  the socket's folder are yours, mode `0700`. None of them may be a link. The `tailscale` program is
  root's or yours and not writable by anyone else.
- **Every folder above it**, up to `/`, belongs to you or root and is not writable by others (a sticky
  folder such as `/tmp` is fine).
- **No group is trusted.** A folder or program its group can write to is refused, even when that group
  holds only you: who is in a group cannot be known for certain. The one exception is macOS's `admin`
  group, whose members can become root anyway, and only for folders above an item and for programs; a
  secret, token, upload folder or socket folder may be open to no group at all.
- **Access control lists count too.** An entry that lets another user or a group change one of these (or
  read a private one) is refused; entries that only deny (such as macOS's default on your home folder)
  are fine.
- **Local disks only.** Network file systems (NFS, SMB), FUSE, a disk image, a disk a user mounted, a
  volume that ignores ownership, and a filesystem rweb does not know are refused: on those, someone else
  decides who owns and reads the files. If your home folder is on a network disk, use `--config-dir`.
- **Links.** A link on the path is followed only when root or you own it and the folder it sits in has
  passed the checks; the walk continues from where it leads (so macOS's `/tmp` and `/var` work). The item
  itself is opened without following a link and checked on what was opened.

rweb also checks that the Rex socket it connects to is served by your own user.

## 13. Advanced: every option

`rweb tailscale` and `rweb ssh` are the supported setups. Everything they set can also be given by hand,
for unusual setups and for services written for rweb 0.1.0; these options still work, alone or added to
a command (an option given overrides what the command would set). `rweb --help` is the full list.

What the two commands are equal to:

```sh
# rweb tailscale, Linux
rweb --listen-unix "$XDG_RUNTIME_DIR/rweb/bridge.sock" --owner-from-tailscale
# rweb tailscale, macOS (rweb tailscale also makes the secret file)
rweb --listen-tcp 7695 --owner-from-tailscale --backend-secret-file ~/.config/rweb/backend-secret
# rweb ssh, Linux (rweb ssh also makes the token file; macOS: ~/.config/rweb/run/ssh.sock)
rweb --listen-unix "$XDG_RUNTIME_DIR/rweb/ssh.sock" --allow-peer-uid self --token-file ~/.config/rweb/token
```

With the options alone, rweb makes no secret or token: a file you name must exist, be yours, mode `0600`
and hold at least 32 letters, digits, `-` or `_`.

- **Where it listens.** `--listen-unix PATH` (absolute; the socket is made `0600` in a `0700` folder of
  yours) or `--listen-tcp PORT` (loopback only, `127.0.0.1` and `::1`; `0` picks a port). A port is free
  while rweb is not running, so on a machine with other accounts prefer a socket.
- **Who gets in.** `--owner-from-tailscale`, or `--owner LOGIN` with `--allow-host NAME`; or
  `--token-file PATH`. `--allow-peer-uid N|self` says which local users may connect to a unix socket
  (default: root, which is `tailscaled`; `rweb ssh` sets `self`). `--backend-secret-file PATH` is needed
  with an owner rule on a TCP port. `--own-address IP` names this machine's Tailscale addresses when
  rweb should not ask `tailscale ip` (it asks at start and every minute after).
- **Rex and Tailscale.** `--rex-socket PATH`, `--tailscale PATH`.
- **What the page may do.** `--observe-only`, `--history-lines N` (default 1000),
  `--enable-file-transfer`, `--upload-dir PATH`, `--max-transfer-mb N` (section 10).
- **Diagnostics.** `--enable-lab`, `--debug-input` (logs what browsers send, typed text included).
- **The update check.** `--no-update-check`: rweb does not ask GitHub, once a day, whether a newer rweb is
  released (section 11), and `rweb doctor` leaves that check out.
- **For tests only, never in a service.** `--token TOKEN` (visible in the process list), `--random-token`
  (a token for one run, shown only in a terminal), `--allow-own-address` and
  `--allow-forgeable-loopback-identity` (each removes a protection; `rweb --help` says which).

A token on a loopback port (`--listen-tcp 7700 --token-file …` with
`ssh -L 127.0.0.1:7700:127.0.0.1:7700`) still works, and rweb holds the port from the moment it starts,
but the port is free while rweb is not running: use it only on a Rex machine where you are the only
account. rweb prints a warning when it runs that way.
