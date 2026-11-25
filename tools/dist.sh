#!/bin/sh
# Packs the release archives that `zig build dist` staged, deterministically: the same binaries
# always give the same archives (sorted member list, owner 0, fixed modes and timestamps, no
# extended attributes, gzip without name or time). Works with BSD tar (macOS) and GNU tar (Linux).
# Usage (from build.zig, in the repository root): sh tools/dist.sh VERSION DIST_DIR
set -eu
version=$1
dist=$2
stage=$dist/stage
stamp=202601010000.00 # 2026-01-01 00:00 UTC, for every file in every archive
files="CHANGELOG.md README.md THIRD-PARTY-NOTICES.md docs docs/architecture.md docs/user-guide.md rweb"

if tar --version 2>/dev/null | grep -q bsdtar; then
  tarc() { COPYFILE_DISABLE=1 tar -c -n --format ustar --uid 0 --gid 0 --uname root --gname root --no-xattrs --no-mac-metadata -f - "$@"; }
else
  tarc() { tar -c --no-recursion --format=ustar --owner=0 --group=0 --numeric-owner -f - "$@"; }
fi

rm -rf "$dist/work"
rm -f "$dist"/rweb-*.tar.gz "$dist/SHA256SUMS"
for dir in "$stage"/*/; do
  target=$(basename "$dir")
  name=rweb-$version-$target
  work=$dist/work/$name
  mkdir -p "$work"
  cp "$dir/rweb" "$work/rweb"
  cp CHANGELOG.md README.md THIRD-PARTY-NOTICES.md "$work/"
  mkdir -p "$work/docs"
  cp docs/architecture.md docs/user-guide.md "$work/docs/"
  chmod 0755 "$work" "$work/docs" "$work/rweb"
  chmod 0644 "$work/CHANGELOG.md" "$work/README.md" "$work/THIRD-PARTY-NOTICES.md" "$work/docs/architecture.md" "$work/docs/user-guide.md"
  find "$work" -exec env TZ=UTC touch -t "$stamp" {} +
  members=$name
  for f in $files; do members="$members $name/$f"; done
  # shellcheck disable=SC2086 # the member list is meant to split
  (cd "$dist/work" && tarc $members) | gzip -n -9 > "$dist/$name.tar.gz"
done
rm -rf "$dist/work"
cd "$dist"
if command -v sha256sum >/dev/null 2>&1; then sha256sum rweb-*.tar.gz > SHA256SUMS; else shasum -a 256 rweb-*.tar.gz > SHA256SUMS; fi
cat SHA256SUMS
