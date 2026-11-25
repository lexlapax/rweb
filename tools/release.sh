#!/bin/sh
# Builds the release archives for one commit, reproducibly: the commit is exported with `git archive`
# into a fixed path and built there, so any machine with the same Zig gets byte-identical archives
# (Ghostty's C++ embeds a cache path that depends on where the build runs; see docs/phase5-result.md).
# The compiler is the pinned official Zig, `zig-<minimum_zig_version>` from PATH, when it is installed
# (package managers' builds of the same version compile differently); otherwise `zig`, with a warning.
# Usage: tools/release.sh [COMMIT]   (default: HEAD; run inside the repository)
# Result: the archives and SHA256SUMS in zig-out/release/<version>/ of the current checkout.
set -eu
commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
top=$(git rev-parse --show-toplevel)
build=/tmp/rweb-release/$commit
rm -rf "$build"
mkdir -p "$build"
git -C "$top" archive "$commit" | tar -x -C "$build"
want=$(sed -n 's/^ *\.minimum_zig_version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
if command -v "zig-$want" >/dev/null 2>&1; then
  zig=zig-$want
else
  zig=zig
  echo "warning: zig-$want (official Zig $want) is not on PATH; building with $(command -v zig) $(zig version)" >&2
fi
echo "building with $zig $("$zig" version) ($(command -v "$zig"))"
(cd "$build" && ZIG_GLOBAL_CACHE_DIR=/tmp/rweb-release/zig-cache "$zig" build dist -Dcommit="$commit")
version=$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
out=$top/zig-out/release/$version
mkdir -p "$out"
cp "$build"/zig-out/dist/rweb-*.tar.gz "$build/zig-out/dist/SHA256SUMS" "$out/"
rm -rf "$build"
echo "rweb $version from $commit, built with $zig $("$zig" version):"
cat "$out/SHA256SUMS"
