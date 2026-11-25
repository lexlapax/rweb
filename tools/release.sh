#!/bin/sh
# Builds the release archives for one commit, reproducibly: the commit is exported with `git archive`
# into a fixed path and built there, so any machine with the same Zig gets byte-identical archives
# (Ghostty's C++ embeds a cache path that depends on where the build runs; see docs/PLAN.md Phase 5).
# Usage: tools/release.sh [COMMIT]   (default: HEAD; run inside the repository)
# Result: the archives and SHA256SUMS in zig-out/release/<version>/ of the current checkout.
set -eu
commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
top=$(git rev-parse --show-toplevel)
build=/tmp/rweb-release/$commit
rm -rf "$build"
mkdir -p "$build"
git -C "$top" archive "$commit" | tar -x -C "$build"
(cd "$build" && zig build dist -Dcommit="$commit")
version=$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
out=$top/zig-out/release/$version
mkdir -p "$out"
cp "$build"/zig-out/dist/rweb-*.tar.gz "$build/zig-out/dist/SHA256SUMS" "$out/"
rm -rf "$build"
echo "rweb $version from $commit:"
cat "$out/SHA256SUMS"
