#!/bin/sh
# Builds the release archives for one commit, reproducibly: the commit is exported with `git archive`
# into a fixed path and built there, so any machine with the same Zig gets byte-identical archives
# (Ghostty's C++ embeds a cache path that depends on where the build runs; see docs/phase5-result.md).
# The compiler is the pinned official Zig, `zig-<minimum_zig_version>` from PATH, when it is installed
# (package managers' builds of the same version compile differently); otherwise `zig`, with a warning.
# Usage: tools/release.sh [COMMIT]   (default: HEAD; run inside the repository)
# Result: the archives and SHA256SUMS in zig-out/release/<version>/ of the current checkout.
#
# The fixed path is in a shared /tmp, so the base folder must be ours alone before anything is put in
# it: a real directory (not a link), owned by this user, mode 0700. /tmp's sticky bit then keeps other
# users from renaming or replacing it, and its mode keeps them out of the source and the Zig cache.
set -eu
commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
top=$(git rev-parse --show-toplevel)
base=${RWEB_RELEASE_BASE:-/tmp/rweb-release}  # the override exists for tools/release-base.test.sh

die() { echo "release.sh: $*" >&2; exit 1; }
owner_of() { stat -c %u "$1" 2>/dev/null || stat -f %u "$1"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

(umask 077; mkdir "$base" 2>/dev/null) || true
[ -L "$base" ] && die "$base is a symbolic link; remove it and run again"
[ -d "$base" ] || die "$base is not a directory; remove it and run again"
[ "$(owner_of "$base")" = "$(id -u)" ] || die "$base belongs to another user; remove it (as that user or root) and run again"
# Ours and not a link: closing it is safe (nobody else could have written into it while it was ours).
chmod 0700 "$base"
[ "$(mode_of "$base")" = 700 ] || die "$base could not be made private (mode $(mode_of "$base"))"
[ "${RWEB_RELEASE_CHECK_ONLY:-}" = 1 ] && { echo "release base ok: $base"; exit 0; }

build=$base/$commit
rm -rf "$build"
mkdir "$build"
git -C "$top" archive "$commit" | tar -x -C "$build"
want=$(sed -n 's/^ *\.minimum_zig_version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
if command -v "zig-$want" >/dev/null 2>&1; then
  zig=zig-$want
else
  zig=zig
  echo "warning: zig-$want (official Zig $want) is not on PATH; building with $(command -v zig) $(zig version)" >&2
fi
echo "building with $zig $("$zig" version) ($(command -v "$zig"))"
(cd "$build" && ZIG_GLOBAL_CACHE_DIR="$base/zig-cache" "$zig" build dist -Dcommit="$commit")
version=$(sed -n 's/^ *\.version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
out=$top/zig-out/release/$version
mkdir -p "$out"
cp "$build"/zig-out/dist/rweb-*.tar.gz "$build/zig-out/dist/SHA256SUMS" "$out/"
rm -rf "$build"
echo "rweb $version from $commit, built with $zig $("$zig" version):"
cat "$out/SHA256SUMS"
