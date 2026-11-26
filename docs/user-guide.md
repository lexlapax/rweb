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
[10 File transfer](#10-file-transfer-off-by-default) · [11 Upgrade](#11-upgrade-and-roll-back) ·
[12 Troubleshooting](#12-troubleshooting)

## 1. What you need

- **A machine running Rex**, Linux (x86-64) or macOS (Apple silicon), with the Rex server running for your
  user. rweb does not start Rex. It finds Rex's socket in `$XDG_RUNTIME_DIR/rex/` or `/run/user/<uid>/rex/`
  (Linux) or `~/Library/Application Support/Rex/` (macOS); `--rex-socket PATH` names another place.
  Windows is not supported yet; it will come later.
- **A way in**: Tailscale on the Rex machine and on your phone or laptop (section 4), or SSH access to the
  Rex machine (section 7).
- **A browser** on the phone, tablet or laptop. Nothing is installed there.

## 2. Install

Download the archive for your platform and `SHA256SUMS` from the release, then:

```sh
shasum -a 256 -c SHA256SUMS --ignore-missing     # Linux: sha256sum -c SHA256SUMS --ignore-missing
tar -xzf rweb-<version>-<platform>.tar.gz
mkdir -p ~/.local/bin && install -m 0755 rweb-<version>-<platform>/rweb ~/.local/bin/rweb
rweb --version
```

The checksums catch a damaged or incomplete download. They do not prove that nobody changed the release:
`SHA256SUMS` comes from the same place as the archives, so whoever could change one could change both.

The archive holds `rweb`, this guide and the architecture notes (`docs/`), the README, the changelog, the
licence (MIT) and the third-party notices. `rweb --version` shows the version, the commit it was built from, and the Rex
API revisions it speaks. To build from source instead: `zig build -Doptimize=ReleaseSafe` with Zig 0.17.1 (see the README).

## 3. Choose how to reach it

rweb never listens on the network. It listens on a unix socket or on loopback, and something you trust
brings your browser to it:

| | Tailscale Serve | SSH tunnel |
| --- | --- | --- |
| Who is let in | your own Tailscale login, checked on every request | whoever has the token |
| From a phone | the Tailscale app; open an `https://` address | an SSH app that forwards ports |
| Address | `https://<machine>.<tailnet>.ts.net:<port>/`, the same everywhere | `http://127.0.0.1:<port>/` on the device running the tunnel |
| Needs | Tailscale on both ends | SSH access to the Rex machine |
| Best for | everyday use, phones | no Tailscale, or occasional use from a laptop |

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
4. **macOS only:** make sure the `tailscale` command works in a terminal (the app's command-line tool).
   rweb runs it to learn your login and the machine's own addresses.
5. **Check:** `tailscale status` on the Rex machine lists your phone or laptop, and both show the same
   user.

**Tagged machines.** If the Rex machine is a tagged device (a server or gateway added with a tag, shown
under its tags in the admin console), it has no owner login, so `--owner-from-tailscale` cannot work and
rweb refuses to start with it. Name yourself instead: replace `--owner-from-tailscale` with
`--owner you@example.com --allow-host <machine>.<tailnet>.ts.net` (your Tailscale login and the machine's
own name) in sections 5 and 6. rweb refuses `--owner` without `--allow-host`.

Keep **Funnel off** for rweb's port: Funnel would publish it on the internet, and rweb refuses every
request that comes through Funnel anyway. Devices that are tagged, or shared into your tailnet by someone
else, do not carry your login and are refused. If your tailnet restricts access with ACLs, allow your
devices to reach the Rex machine on the port you choose below.

## 5. Run behind Tailscale on Linux

rweb listens on a unix socket in a directory only you can enter and accepts connections only from root,
which is `tailscaled`. No other program on the machine, not even one running as you, can use it.

As a systemd user service, `~/.config/systemd/user/rweb.service`:

```ini
[Unit]
Description=rweb, a web client for Rex
# If your Rex server runs as a user service, start after it:
After=rex.service
Wants=rex.service

[Service]
RuntimeDirectory=rweb
RuntimeDirectoryMode=0700
ExecStart=%h/.local/bin/rweb --listen-unix %t/rweb/bridge.sock --owner-from-tailscale
# At boot Tailscale or Rex may not be up yet: rweb exits and is started again.
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
sudo tailscale serve --bg --https=12443 "unix:/run/user/$(id -u)/rweb/bridge.sock"
tailscale serve status                   # shows the address to open
```

Any free port works instead of 12443 (`tailscale serve status` lists those in use). Tailscale stores the
Serve entry and keeps it across reboots, so you set it up once.

## 6. Run behind Tailscale on macOS

The Tailscale app cannot forward to a unix socket, so rweb listens on loopback. Any local program could
send a loopback request carrying your identity headers, so rweb also requires a long secret as the first
part of every path, which only Tailscale Serve knows; it refuses to start on loopback with an owner rule
and no secret.

**Use this layout only on a Mac where you are the only local account.** The secret is part of the Serve
target, so other accounts on the Mac may be able to read it in `tailscale serve status`, or in the
process list while the `tailscale serve` command runs. With it, another account could send requests with
your identity to rweb. On a Mac shared with other accounts, do not run rweb this way.

```sh
mkdir -p ~/.config/rweb
(umask 077; head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > ~/.config/rweb/backend-secret)
```

rweb reads the secret only from a file that is yours and closed to others, in folders that are yours or the
system's and not writable by others (`~/.config/rweb` made as above is fine).

As a LaunchAgent, `~/Library/LaunchAgents/local.rweb.plist` (replace `YOU` with your user name):

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>local.rweb</string>
  <key>EnvironmentVariables</key><dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
  <key>ProgramArguments</key><array>
    <string>/Users/YOU/.local/bin/rweb</string>
    <string>--listen-tcp</string><string>7695</string>
    <string>--owner-from-tailscale</string>
    <string>--backend-secret-file</string><string>/Users/YOU/.config/rweb/backend-secret</string>
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
tailscale serve --bg --https=12443 "http://127.0.0.1:7695/$(cat ~/.config/rweb/backend-secret)"
```

`PATH` must reach the `tailscale` command. A LaunchAgent starts when you log in, which is when Rex.app
runs; with FileVault on, nothing of yours runs until you have unlocked the disk after a restart.

Then open `https://<machine>.<tailnet>.ts.net:12443/` on your phone or laptop. Open it from **another
device**: a request from the Rex machine itself is refused, because any program there could make it.

## 7. SSH tunnel

Without Tailscale, run rweb on loopback with a token and forward a port to it over SSH. The token is the
only thing standing between a process that can reach the port and your Rex sessions, so keep it in a
file only you can read and never pass it on the command line. Make it with the command below, which picks
a random one; do not make one up. The token file's folders must be yours or the system's and not writable
by others.

On the Rex machine (Linux or macOS):

```sh
mkdir -p ~/.config/rweb
(umask 077; head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n' > ~/.config/rweb/token)
rweb --listen-tcp 7700 --token-file ~/.config/rweb/token
```

To keep it running, use the service files from section 5 or 6 with this command line instead (on Linux,
drop `RuntimeDirectory=`; on macOS, replace the arguments).

On the laptop or phone:

```sh
ssh -N -L 7700:127.0.0.1:7700 you@rex-machine
```

Then open `http://127.0.0.1:7700/?token=<the token>` in that device's browser. rweb moves you to
`http://127.0.0.1:7700/s/<id>/` and the token into a session cookie for that path only, and removes it from
the address. Bookmark that address: later visits in the same browser session need no token, and the
`<id>` stays the same while the token file does. After the browser forgets the cookie, open the address
with the token again. The cookie is never sent to other web services on your device, even ones on other
`127.0.0.1` ports. The token file may hold only letters, digits, `-` and `_` (the command above makes such
a token). On a phone, use an SSH app that supports local port forwarding and keep it open
while you use the page. Keep the forwarded port on loopback (no `-g`, no `GatewayPorts`), or other devices
on that network could reach it.

Treat the `/s/<id>/` address like the token. The `<id>` is made from the token, and with it someone can
test guesses of the token on their own machine; that is why the token must be random. Do not share the
address or post screenshots that show it. The first address, with `?token=`, can stay in the browser's
history and address suggestions: open it once per browser, or delete it from the history afterwards. To
change the token, write a new token file with the same command and restart rweb; the old token and the
old `/s/<id>/` address then stop working.

For a quick test, `--random-token` makes a token for that run only and prints the address with it, but
only when rweb runs in a terminal. A token given with `--token` must be at least 16 characters of letters,
digits, `-` and `_`; it shows in the process list, so prefer the token file.

## 8. Several machines

Run one rweb on each machine that runs Rex; each serves only its own Rex. With Tailscale every machine
gets its own address, so the same port can be used on all of them:

```text
https://desk.<tailnet>.ts.net:12443/      sessions on desk
https://server.<tailnet>.ts.net:12443/    sessions on server
```

Bookmark each, or add each to the phone's home screen. With SSH tunnels give each machine its own local
port (`-L 7701:127.0.0.1:7700 you@desk`, `-L 7702:127.0.0.1:7700 you@server`) and its own token; each keeps
its own sign-in, and each `/s/<id>/` address is as secret as its token (section 7). Rex sessions on one
machine are not visible through another machine's rweb.

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
- **The ⋯ menu** (top right): text size; View only (no typing from this browser); Fit Rex to this screen;
  Fit terminal to this window; Load all scrollback; Copy text (a view for selecting and copying lines);
  Text copied in the terminal (what a program put on the clipboard); Paste; Clear screen; Reset terminal;
  Download a file and Upload files (when enabled); the terminal engine (wterm, or the older xterm.js);
  Touch diagnostics; Reconnect.
- **Reconnecting** is automatic: after sleep or a network change the page reconnects and redraws.

## 10. File transfer (off by default)

`--enable-file-transfer` lets the page download any file your user can read (through Rex), and with
`--upload-dir DIR` upload into that one folder. The folder and every folder above it must be yours or the
system's and not writable by others. Uploaded files never replace an existing one, and their
path is pasted at the prompt. `--max-transfer-mb N` limits the size (default 256). Turn it on only if you
want the browser to have that reach. Design and limits: [file-transfer.md](file-transfer.md) (in the
source repository).

## 11. Upgrade and roll back

Read [CHANGELOG.md](../CHANGELOG.md), install the new archive over `~/.local/bin/rweb` (keep the old binary
if you may want it back), then restart rweb: `systemctl --user restart rweb` on Linux,
`launchctl kickstart -k "gui/$(id -u)/local.rweb"` on macOS. Restarting rweb does not touch your Rex
sessions, and open pages reconnect. The Serve entry, the secret and the token stay as they are.

Upgrading to 0.1.1: rweb now checks more at startup and stops with a message naming what to fix (see
section 12). It refuses `--owner` without `--allow-host`, a `--token` shorter than 16 characters or with
other characters than letters, digits, `-` and `_`, and a secret file, token file or upload folder that is a
link or sits under a folder another user can change. If you made those files as this guide says, nothing
changes. Address the SSH tunnel through the `/s/<id>/` address it redirects to (section 7).

## 12. Troubleshooting

Logs: `journalctl --user -u rweb -n 50` (Linux service), `~/Library/Logs/rweb.log` (macOS LaunchAgent).

| You see | Why, and what to do |
| --- | --- |
| `cannot find Rex's socket` | Rex is not running, or its socket is elsewhere: start Rex, or pass `--rex-socket`. |
| `this node is a tagged Tailscale device` | Use `--owner` and `--allow-host` instead of `--owner-from-tailscale` (section 4, tagged machines). |
| `cannot tell this node's Tailscale addresses` | The `tailscale` command is missing from `PATH` or Tailscale is down. |
| `--owner needs --allow-host NAME` | Add `--allow-host <machine>.<tailnet>.ts.net` (section 4, tagged machines). |
| `--token must be at least 16 characters` | Use a token file made with the command in section 7 instead. |
| `cannot use secret file …` or `cannot use upload folder …` | The message names the file or folder and the folder where the check failed. `SymLink`: point the option at the real file. `TooOpen` or `NotOwned`: `chmod 600` the file (`700` a folder) and make sure it is yours. `FolderWritableByOthers` or `FolderNotOurs`: a folder above it can be changed by another user; move the file somewhere under your home folder. |
| `SocketDirNotOurs` or `SocketDirNotPrivate` | The unix socket's folder must be yours and `0700`; use the runtime folder from section 5. |
| 403 "request from this node's own address" | You opened the page on the Rex machine itself. Use another device. |
| 403 from your phone through Tailscale | The phone is signed in to a different Tailscale account, or is a tagged or shared device. |
| 403 through an SSH tunnel | No token or the wrong one: open `http://127.0.0.1:<port>/?token=<token>` once. |
| 404 for everything (macOS, Tailscale) | Serve does not point at the current secret: run the `tailscale serve` line again. |
| The browser cannot connect at all | Tailscale: `tailscale serve status` on the Rex machine. SSH: is the tunnel still open? |
| Sessions do not appear | rweb cannot reach Rex, or Rex refused its API revision: check the log and `rweb --version`. |
| Typing does nothing | View only is on (⋯ menu), or rweb runs with `--observe-only`. |

`rweb --help` lists every option.
