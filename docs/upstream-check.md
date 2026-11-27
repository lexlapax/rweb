# Upstream check

rweb pins what it is built from and what it talks to. After each release, before new features, look at
what changed upstream of those pins and account for each change: take it, or record why not.

```sh
tools/upstream-check.sh rex        # the Rex server on this machine; no network
tools/upstream-check.sh network    # GitHub, ziglang.org and npm: run it where downloaded text is handled
                                   # (on the owner's machines, the sandbox's job profile)
```

Each line is `NAME PINNED FOUND VERDICT`. Only version-looking strings are printed. Exit 0: as pinned;
1: something to look at; 2: a check could not be made.

| Item | Pinned in | Found from | What a change means, and what to do |
| --- | --- | --- | --- |
| `rex-api-revision` | `src/rex/control.zig` `api_max_supported` | the Rex server's `llms.txt` ("describes API revision N") | A newer revision: read what changed in `llms.txt`, decide whether rweb uses any of it, raise `api_max_supported` with tests (fake and live), and record the Rex version and revision in the docs. An older server is fine down to 18. |
| `rex-llms.txt` | `tools/upstream.lock` (`rex-version`, `rex-llms-sha256`) | a SHA-256 of the server's `llms.txt` | The protocol document changed, even at the same revision: diff it against the version recorded, check every call, event and stream rweb uses, run the live tests, then record the new hash. Do this on macOS and Linux. |
| `ghostty-vt` | `build.zig.zon` (the `vt-*` tag and its hash) | Ghostty's `vt-*` tags on GitHub | A new libghostty-vt: read its notes, check the snapshot format version rweb accepts, update the tag and hash, rebuild, run every test, fuzz and a live run, and regenerate `THIRD-PARTY-NOTICES.md`. |
| `zig` | `build.zig.zon` `minimum_zig_version`, setup-repo's `zig-release` | ziglang.org's releases | A new Zig: run the stale-API search from the Zig audit's checklist first (AGENTS.md, "Zig practice"), fix its hits in the same change, and rebuild Ghostty with it. |
| npm packages | `tools/vendor/packages.lock` | npm's `latest` for each | A new xterm.js, fit addon or wterm: update the lock, run `tools/vendor/rebuild.sh` (in the sandbox), test the page on desktop and the simulators. A new esbuild only matters when the wterm bundle is rebuilt: the pinned esbuild is what makes it byte-identical, so keep it unless wterm changes. |

## Results

**2026-11-27, after 0.3.0** (the network half in the sandbox's job profile on laptop-mac; the Rex half on
laptop-mac and linux-box):

| Item | Pinned | Found | To do |
| --- | --- | --- | --- |
| `rex-api-revision` | 24 | 24 (Rex 0.1.0-preview.25, both machines) | nothing |
| `rex-llms.txt` | preview.25 | the same document on both machines | nothing |
| `ghostty-vt` | 1.0.1 | 1.0.2 | **look at it before new features**: what vt-1.0.2 changes, and whether rweb takes it |
| `zig` | 0.17.1 | 0.17.1 | nothing |
| `@xterm/xterm`, `@xterm/addon-fit`, `@wterm/core`, `@wterm/dom`, `@wterm/ghostty` | 6.0.0, 0.11.0, 0.6.0 ×3 | the same | nothing |
| `esbuild` | 0.25.12 | 0.28.2 | nothing: kept, as above |
