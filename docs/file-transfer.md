# File transfer: design, threat model, and what was measured

Status: built and tested on macOS, 2026-11-23. **Off unless the owner starts the bridge with
`--enable-file-transfer`.** This is the separate design and review that
[security-hardening-2026-11-23.md](security-hardening-2026-11-23.md) asked for before the feature existed.

## What it does

- **Download.** ⋯ menu, "Download a file…": a picker (folders first, filter, hidden-file switch, a typed
  `/path` or `~/path` plus Enter) starting at the terminal's own folder. Tapping a file starts an ordinary
  browser download.
- **Upload.** ⋯ menu, "Upload files…": the phone's file chooser (several files, one after another, with
  progress). Each file is saved in one folder the owner named, and its quoted real path (links resolved
  when rweb started) is pasted into the terminal (no Enter), with a trailing space so several uploads paste
  as separate words.
- **Limits.** One transfer carries at most `--max-transfer-mb` (default 256) either way; at most 4 run at
  once and 16 wait.

Flags: `--enable-file-transfer`, `--upload-dir ABSOLUTE_PATH` (uploads stay off without it),
`--max-transfer-mb N`. Not allowed together with `--observe-only`.

## How a transfer is authorised

A transfer is two steps, so that **no file is reachable by an address a web page could guess or be tricked
into requesting**:

1. The page asks over its WebSocket (`ls`, `dl`, `ul`). That socket already passed the identity, Host,
   Origin and (on macOS loopback) backend-secret checks. The bridge refuses when transfer is off, when the
   viewer is read-only, when no terminal is open, when the file is over the limit, or (upload) when no
   upload folder is set. These asks count against the 8-per-second heavy-request cap.
2. The bridge answers with a **token**: 128 random bits, valid 30 seconds (on a clock that keeps counting
   while the machine sleeps), good for one request, of one kind (a download token cannot start an upload
   and the reverse), and tied to the page and terminal view generation (`view_gen`) that asked. An upload
   token works only while that page may still write to that exact terminal view: it is withdrawn immediately
   when the page turns read-only, closes, or leaves the terminal (404), so switching away and back cannot
   revive an earlier view's token; if a race still reaches the upload handler or finishes after a view change,
   it is refused (403) before saving or saved without pasting (`"pasted": false`). The page then requests `GET /xfer/<token>`
   or `PUT /xfer/<token>`. Those pass the same access check as any request; a `PUT` also needs a matching
   `Origin`, as a WebSocket does, so another site's page cannot send one. The token is compared in constant
   time, and the request log never prints it (`/xfer/(token)`).

## Threat model

| Threat | Answer |
|---|---|
| A web page in the owner's browser (CSRF) makes the bridge hand over or accept a file | Tokens exist only inside the page that asked over the Origin-checked socket; `PUT` needs the page's own Origin. Tested: a cross-origin and an Origin-less `PUT` get 403 and the token is not spent. |
| A guessed or replayed address | 128-bit random, single use, 30 s; unknown/short/odd tokens get a bare 404, same as when transfer is off. Tested. |
| Reading files the owner never meant to share | Downloads give the page **the same files the owner's terminal can read** (Rex checks it is a regular file). That is the owner's own authority, and the reason it is off by default and logged. It is not a sandbox: there is no per-folder allow-list. |
| An upload overwriting or escaping | The bridge, not Rex, writes the file, into the one folder (made 0700; refused at startup if anyone else can enter it, by mode or by an access list, if it is not ours, if it is a link, if it or a folder above it is not on a local disk, or if a folder above it is another user's, writable by others without the sticky bit, or writable by its group; the user guide's "Files and folders rweb checks" has the full rules). The folder is opened once at startup and kept open, and files are created relative to that open folder, so renaming it or putting a link in its place later cannot send uploads elsewhere. The bytes go into a part file (32 random hex digits and `.part`, created exclusively, mode 0600) in a folder of rweb's own inside the upload folder, `.rweb-partial/` (made 0700, opened at startup without following a link, and checked like the upload folder). When all of them have arrived the file is flushed to disk (`F_FULLFSYNC` on macOS, `fsync` elsewhere), then given its real name in the upload folder by a hard link that fails if the name exists, so nothing is ever replaced (`a.txt`, `a (1).txt`, …), and the folder is flushed too before the page is told it worked. If rweb is stopped or the machine loses power in the middle, only the part file is left, never a file in the upload folder that looks whole; this holds as far as the disk honours a flush. A part file stays locked (`flock`) while it is written, and the next start removes only part files it can lock: what a stopped rweb left, not an upload in progress in another rweb that uses the same folder. Nothing outside `.rweb-partial/`, and nothing in it that does not have a part file's exact name, is ever removed. The name is the last path component only, with everything but letters, digits and `. _ - + @ , ( )` and space replaced by `_`, no leading dots, at most 100 bytes. Tested with `../../etc/evil;rm -rf ~.txt`. |
| Shell injection through an uploaded name | The pasted path is single-quoted with `'` escaped, and the name is already sanitized. Nothing is run: no Enter is sent. |
| Header injection through a download name | `Content-Disposition` is built from a restricted ASCII form plus a percent-encoded `filename*`; control characters and quotes cannot appear. Tested. |
| Content sniffing / script from a download | `application/octet-stream`, `attachment`, `nosniff`, `no-store`, and the page's CSP (`default-src 'none'`). |
| Filling the disk or memory | Size announced up front and checked against the limit and against `Content-Length`; a download aborts past the limit; uploads stream in 64 KiB pieces; an incomplete or mismatching upload is deleted. 4 running, 16 waiting; a transfer takes a running slot before its token is used, so a busy bridge does not waste a token. |
| A transfer that stalls | No bytes for 30 seconds, either way, and the connection is cut (a partial upload is deleted), so a stuck phone cannot hold a running slot. |
| A read-only viewer | Refused at the first step. |
| The path typed into a terminal the page has left | The upload's token is for one page, one terminal and one view generation (`view_gen`), and the page's request for it names the terminal the files were chosen for (refused for any other). Leaving the terminal revokes pending upload tokens immediately (404), so switching away and back cannot revive an earlier view's token. When the upload ends, the check that the page is still there, may write and still shows that exact terminal view, and the queueing of the path, are one step under the page's lock; the path goes through the terminal's own input queue, in order with typing. A page that switches, leaves or turns read-only before or while the bytes arrive gets 404/403 and nothing is saved; one that does so in the last moment, after the file is named, gets the file and no paste (`"pasted": false`). The download picker's requests (`ls`, `dl`) name the terminal the picker was opened for and are refused for any other, closing the picker on stale view changes. |
| Many tokens held open | Capped at 16, and at 4 per browser so one page cannot block the others; expired ones are swept. A download Rex has begun but nobody fetched ends when Rex's own ticket expires (Rex has no call to cancel it). |
| Who sees what moved | The bridge logs each transfer with its file name and size: that is the owner's record. On Linux the user journal can be read by the `adm`, `systemd-journal` and `wheel` groups. |

## What was measured about Rex (preview.21, API revision 18)

- **Download works as documented.** `download_begin` returns a ticket, the `rex.data.bytes.v1` stream
  carries the file in 64 KiB binary messages and ends with close 1000. A 150 000-byte file came back
  byte-identical, with the right name and size. (Live test: `live: download and list a directory…`.)
- **Rex's `upload_begin` is not usable by a client other than the Rex app.** The bytes arrive and are staged
  under `~/Library/Application Support/Rex/uploads/…` (0600), but the file is deleted when the stream
  closes, the stream does not close until the client does, and nothing is typed into the terminal, with or
  without a batch id. So the bridge writes uploads itself. If a later Rex documents the missing step, this
  can be revisited; the advantage of the current design is that the destination is one folder the owner chose.
- **Bug found by testing against the real thing:** two functions in `api.zig` copied an arena before filling
  it, so their results leaked; found by the live test's leak check and fixed.

## Tests

- Unit: token registry (one use, kind, expiry, randomness, capacity, constant-time compare), name
  sanitizing (traversal, shell characters, control characters, long names), shell quoting, header building,
  message parsing (`ls`/`dl`/`ul` bounds), CLI rules.
- Wire (fake Rex, real HTTP and WebSocket): off by default; download through a token; missing file and
  over-limit file refused; read-only viewers refused; directory listing; upload lands only in the folder
  under a safe, new name with the path pasted; refusal of a foreign Origin, no Origin, wrong size, reuse,
  oversize announcement, and a download token used for an upload; an upload token after its page turned
  read-only or left the terminal (404, no file made; reopening the same terminal does not revive it); an upload folder whose path was renamed away and
  replaced by another folder or a link (the upload still lands in the original); a stalled upload cut and its
  partial file removed; a busy bridge keeping the token.
- Live (real Rex): download round trip and listing. Live (real Chrome and Rex, release build, throwaway
  session and folder): picker and typed path; a 300 000-byte download byte-identical by SHA-256, the token
  refused on reuse, the dialog closing; a 2 MB upload byte-identical with a hostile name (`../../phone pic; $(touch pwned).bin`
  saved as `phone pic_ _(touch pwned).bin`, no file created elsewhere, path pasted quoted); over-limit upload
  and download both refused with a readable message. All test files, the session and the bridge were removed.

## Not covered

- No per-folder allow-list for downloads, and no download of directories.
- Transfers are not resumable and run one at a time per page.
- Not tested through Tailscale Serve or on a phone (the transport is plain HTTP on the same origin as the
  page, so Serve passes it through, but the 4-concurrent limit and large uploads over a slow link are untested).
- A file Rex reports as larger than it is (the stream may carry more or fewer bytes than `size`) is cut at
  the limit, not at the announced size.
