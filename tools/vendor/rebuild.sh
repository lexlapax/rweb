#!/bin/sh
# Rebuilds rweb's vendored browser files (src/bridge/web/vendor/) from their npm packages and says,
# file by file, whether the result is byte-identical to what is vendored (SHA256SUMS there).
#
# Each package in tools/vendor/packages.lock is downloaded from registry.npmjs.org by exact version and
# its tarball checked against the lock's sha512 integrity; a package the lock has no integrity for yet
# is used anyway and its integrity printed, to be reviewed and recorded. Tarballs are unpacked; no
# package script is ever run. Then:
#   xterm.js, xterm.css, addon-fit.js, LICENSE-xterm.txt: taken from the xterm packages;
#   wterm.js: bundled from tools/vendor/entry.mjs by the pinned esbuild (its own binary for this
#     platform, from npm), as the vendored bundle was made;
#   wterm.css, ghostty-vt.wasm, LICENSE-wterm.txt: taken from the wterm packages (ghostty-vt.wasm is
#     the wterm project's own build around Ghostty's terminal, prebuilt in @wterm/ghostty).
# Prints only file names, package paths, hashes and integrities; never file contents.
# Usage: tools/vendor/rebuild.sh            (from anywhere in the repository; needs curl, tar, openssl)
# Exit: 0 when every vendored file was rebuilt identical, 1 otherwise.
set -eu
top=$(cd "$(dirname "$0")/../.." && pwd)
vendor=$top/src/bridge/web/vendor
lock=$top/tools/vendor/packages.lock
work=$(mktemp -d "${TMPDIR:-/tmp}/rweb-vendor.XXXXXX")
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/node_modules" "$work/out" "$work/tgz"

sha256() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
integrity() { printf 'sha512-%s' "$(openssl dgst -sha512 -binary "$1" | openssl base64 -A)"; }

case "$(uname -s)-$(uname -m)" in
  Darwin-arm64) esbuild_pkg=@esbuild/darwin-arm64 ;;
  Linux-x86_64) esbuild_pkg=@esbuild/linux-x64 ;;
  *) echo "rebuild.sh: no esbuild package is pinned for $(uname -s) $(uname -m); add its @esbuild package to the lock" >&2; exit 2 ;;
esac

bad=0
grep -v '^#' "$lock" | while read -r name version want; do
  [ -n "$name" ] || continue
  case "$name" in @esbuild/*) [ "$name" = "$esbuild_pkg" ] || continue ;; esac
  base=${name##*/}
  url="https://registry.npmjs.org/$name/-/$base-$version.tgz"
  tgz="$work/tgz/$base-$version.tgz"
  curl -fsSL --proto '=https' --max-filesize 52428800 -o "$tgz" "$url" || { echo "rebuild.sh: cannot download $url" >&2; exit 1; }
  got=$(integrity "$tgz")
  # What the registry publishes for this version (npm's own check): the tarball must match it.
  published=$(curl -fsSL --proto '=https' --max-filesize 10485760 "https://registry.npmjs.org/$name/$version" |
    tr ',' '\n' | sed -n 's/.*"integrity":"\(sha512-[A-Za-z0-9+/=]*\)".*/\1/p' | head -n 1)
  if [ "$published" != "$got" ]; then
    echo "MISMATCH  $name $version: the tarball's integrity is $got, the registry publishes ${published:-none}" >&2
    exit 1
  fi
  if [ "$want" = "-" ]; then
    echo "integrity $name $version $got   (matches the registry; not in the lock yet: review, then record it)"
  elif [ "$want" != "$got" ]; then
    echo "MISMATCH  $name $version: the tarball's integrity is $got, the lock says $want" >&2
    exit 1
  else
    echo "verified  $name $version (the lock and the registry)"
  fi
  mkdir -p "$work/node_modules/$name"
  tar -xzf "$tgz" -C "$work/node_modules/$name" --strip-components=1
done

nm=$work/node_modules
# The files taken as they are.
cp "$nm/@xterm/xterm/lib/xterm.js" "$work/out/xterm.js"
cp "$nm/@xterm/xterm/css/xterm.css" "$work/out/xterm.css"
cp "$nm/@xterm/addon-fit/lib/addon-fit.js" "$work/out/addon-fit.js"
cp "$nm/@xterm/xterm/LICENSE" "$work/out/LICENSE-xterm.txt"

# The bundle, as recorded in docs/phase3-result.md ("The other terminal: wterm").
cp "$top/tools/vendor/entry.mjs" "$work/entry.mjs"
(cd "$work" && "$nm/$esbuild_pkg/bin/esbuild" entry.mjs --bundle --format=iife --minify --legal-comments=none \
  --define:import.meta.url='"https://rweb.invalid/vendor/"' --log-level=warning --outfile=out/wterm.js)

cp "$nm/@wterm/dom/src/terminal.css" "$work/out/wterm.css"
cp "$nm/@wterm/ghostty/wasm/ghostty-vt.wasm" "$work/out/ghostty-vt.wasm"
cp "$nm/@wterm/core/LICENSE" "$work/out/LICENSE-wterm.txt"

# The verdict, file by file.
while read -r want f; do
  if [ ! -f "$work/out/$f" ]; then echo "MISSING   $f"; bad=1; continue; fi
  got=$(sha256 "$work/out/$f")
  if [ "$got" = "$want" ]; then echo "same      $f"; else echo "DIFFERENT $f: rebuilt $got, vendored $want"; bad=1; fi
done < "$vendor/SHA256SUMS"
exit $bad
