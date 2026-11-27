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
| `ghostty-vt` | 1.0.1 | 1.0.2 | **taken for 0.3.1** (below) |
| `zig` | 0.17.1 | 0.17.1 | nothing |
| `@xterm/xterm`, `@xterm/addon-fit`, `@wterm/core`, `@wterm/dom`, `@wterm/ghostty` | 6.0.0, 0.11.0, 0.6.0 ×3 | the same | nothing |
| `esbuild` | 0.25.12 | 0.28.2 | nothing: kept, as above |

**Ghostty `vt-1.0.2`, taken 2026-11-27 for 0.3.1.** What changed since `vt-1.0.1` (106 commits, read from
GitHub's comparison through the sandbox's job profile): terminal-core fixes (soft wraps and semantic prompt
marks across IL/DL, a clone's padding rows, hyperlink hashing, PageList integrity while growing), a
snapshot fix ("a restored snapshot keeps a pending wrap at any column"; `src/terminal/snapshot/` changed,
no new format version), wider skin-tone emoji clusters, mouse-encoder state across syncs, and changes
rweb does not build (fonts, GTK, kitty drag and drop, CI). Its dependencies are unchanged
(`THIRD-PARTY-NOTICES.md` regenerates byte-identical). Checked: `zig build test` with live Rex
(preview.25, revision 24) 473 passed, 5 skipped, in Debug and in ReleaseSafe; `zig build fuzz`, and 300 s
of `--fuzz` with no failure; no `rweb-test-` session left behind.

**2026-11-27, after 0.3.1** (the Rex half on laptop-mac; the network half in the sandbox's job profile):
Rex revision 24 and its `llms.txt` unchanged; `ghostty-vt` 1.0.2, Zig 0.17.1, xterm.js 6.0.0, the fit addon
0.11.0 and wterm 0.6.0 all as pinned; esbuild 0.28.2 newer, kept as above. Nothing to do before new work.
