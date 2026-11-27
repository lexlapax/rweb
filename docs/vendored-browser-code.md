# The vendored browser code, rebuilt (2026-11-27)

rweb's page uses two browser terminals, embedded in the binary from `src/bridge/web/vendor/`: xterm.js
with its fit addon, and wterm (a DOM terminal over Ghostty's terminal compiled to WebAssembly). Until now
their provenance was partly unrecorded (docs/phase3-result.md, "Provenance"): no npm integrity strings,
no bundle entry file, no record of where `wterm.css` and `ghostty-vt.wasm` came from. PLAN Phase 6 step 5
asked for every vendored file to be rebuilt from recorded sources and compared.

## How to check

```sh
tools/vendor/rebuild.sh     # from anywhere in the repository; needs curl, tar, openssl
```

For each package in `tools/vendor/packages.lock` it downloads the tarball from registry.npmjs.org by exact
version, checks it against the integrity the registry publishes for that version and against the
lock's, unpacks it without running any package script, and then rebuilds each vendored file. It prints
one line per file, `same` or `DIFFERENT`, and exits 0 only when all are the same.

| Vendored file | From |
|---|---|
| `xterm.js` | `@xterm/xterm` 6.0.0, `lib/xterm.js` |
| `xterm.css` | `@xterm/xterm` 6.0.0, `css/xterm.css` |
| `addon-fit.js` | `@xterm/addon-fit` 0.11.0, `lib/addon-fit.js` |
| `LICENSE-xterm.txt` | `@xterm/xterm` 6.0.0, `LICENSE` |
| `wterm.js` | bundled from `tools/vendor/entry.mjs` (`@wterm/dom`, `@wterm/core`, `@wterm/ghostty` 0.6.0) by esbuild 0.25.12: `--bundle --format=iife --minify --legal-comments=none --define:import.meta.url='"https://rweb.invalid/vendor/"'` |
| `wterm.css` | `@wterm/dom` 0.6.0, `src/terminal.css` |
| `ghostty-vt.wasm` | `@wterm/ghostty` 0.6.0, `wasm/ghostty-vt.wasm` (prebuilt by the wterm project) |
| `LICENSE-wterm.txt` | `@wterm/core` 0.6.0, `LICENSE` |

esbuild runs as its own binary from npm (`@esbuild/darwin-arm64`, `@esbuild/linux-x64` or
`@esbuild/linux-arm64`, all pinned); another platform needs its `@esbuild/...` package added to the lock.

Since the script downloads from npm, run it where nothing it fetches can reach private data: a sandbox
or container that holds only a copy of the checkout (`sh tools/vendor/rebuild.sh` there). On the owner's
machines a sandbox with no agent runs it, and its output comes back for review.

## Result

Run 2026-11-27 on macOS (Apple silicon) and Linux (x86-64): every tarball matched the registry's
published integrity, and **all eight vendored files were rebuilt byte-identical**, the esbuild bundle
included. The integrities are now in the lock, so a later run also fails if the registry ever served
different bytes for these versions.

## What is not rebuilt: `ghostty-vt.wasm` from source

`ghostty-vt.wasm` is the wterm project's own WebAssembly module: wterm's wrapper around Ghostty's
terminal, with its own interface. Building Ghostty's wasm library from the Ghostty rweb pins (`vt-1.0.1`,
`zig build -Demit-lib-vt -Dtarget=wasm32-freestanding`) gives a different module: it exports Ghostty's C
API (217 `ghostty_*` functions and the table), while the vendored one exports 69 functions of wterm's
design (`init`, `write`, `resize`, `get_viewport`, `get_scrollback_line`, `graphics_*` and so on) and
imports only `env.log`; they share one export. ReleaseSmall gives 914 KB, the vendored file is 600 KB.
So the pinned Ghostty cannot stand in for it, and wterm's JavaScript would not run on Ghostty's own
module. Rebuilding it from source needs the wterm repository at the commit of `@wterm/ghostty` 0.6.0 and
the Ghostty commit it was built against; that was not attempted. What is checked is that the file is
byte-identical to the one in the published package, which the registry's integrity covers.

Run again 2026-11-27 in that sandbox (Linux, ARM64): every package verified against the lock and the
registry, all eight files identical. `@esbuild/linux-arm64`'s integrity came from that run, matched the
registry's, and was recorded at the owner's word.

## How it was run

The owner chose to run the script in the working session (2026-11-27) after the sandbox's web profile
declined to: its rules forbid reaching other hosts. Since then a sandbox profile for jobs like this one
has run it on Linux ARM64. The script prints only names, package
paths, hashes and integrities; no downloaded file was opened.
