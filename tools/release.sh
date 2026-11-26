#!/bin/sh
# Builds the release archives for one commit, reproducibly: the commit is exported with `git archive`
# into a fixed path and built there (Ghostty's C++ embeds a cache path that depends on where the build
# runs). Machines of the same host platform (for example two Apple-silicon Macs) with the same official
# Zig get byte-identical archives; machines of different host platforms do not, because that embedded
# path still differs (see docs/phase5-result.md, "Pinning Zig").
# The compiler is the pinned official Zig, `zig-<minimum_zig_version>` from PATH, when it is installed
# (package managers' builds of the same version compile differently); otherwise `zig`, with a warning.
# Usage: tools/release.sh [COMMIT]   (default: HEAD; run inside the repository)
# It runs the tests on the exported commit first and packs nothing if they fail. It is the only way to
# make release archives: `zig build dist` alone packs the working tree, uncommitted edits included.
# Result: the archives, SHA256SUMS and BUILDINFO in zig-out/release/<version>/ of the current checkout. A version
# that has a folder there already is not built again; remove the folder on purpose to rebuild it.
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

version=$(git -C "$top" show "$commit:build.zig.zon" | sed -n 's/^ *\.version = "\(.*\)",$/\1/p')
[ -n "$version" ] || die "no .version in build.zig.zon at $commit"
out=$top/zig-out/release/$version
[ -e "$out" ] && die "$out exists already, so $version is not built again (it would replace those archives).
To rebuild $version on purpose, remove it first: rm -rf '$out'"

build=$base/$commit
rm -rf "$build"
mkdir "$build"
git -C "$top" archive "$commit" | tar -x -C "$build"
want=$(sed -n 's/^ *\.minimum_zig_version = "\(.*\)",$/\1/p' "$build/build.zig.zon")
if command -v "zig-$want" >/dev/null 2>&1; then
  zig=zig-$want
elif [ "${RWEB_RELEASE_ANY_ZIG:-}" = 1 ]; then
  zig=zig
  echo "warning: zig-$want (official Zig $want) is not on PATH; building with $(command -v zig) $(zig version), as RWEB_RELEASE_ANY_ZIG=1 allows" >&2
else
  die "zig-$want (official Zig $want) is not on PATH. Release archives are built with it (other builds of the
same version compile differently). Install it, or set RWEB_RELEASE_ANY_ZIG=1 to build with $(command -v zig || echo zig) anyway."
fi
echo "building with $zig $("$zig" version) ($(command -v "$zig"))"
# The tests run on exactly what is packed (the exported commit), never against a real Rex: the live
# tests need REX_SOCKET, which is removed here.
(cd "$build" && env -u REX_SOCKET ZIG_GLOBAL_CACHE_DIR="$base/zig-cache" "$zig" build test) || die "the tests failed on $commit; nothing was packed"
(cd "$build" && ZIG_GLOBAL_CACHE_DIR="$base/zig-cache" "$zig" build dist -Dcommit="$commit")
mkdir -p "$top/zig-out/release"
mkdir "$out" || die "$out appeared during the build; nothing was copied into it"
cp "$build"/zig-out/dist/rweb-*.tar.gz "$build/zig-out/dist/SHA256SUMS" "$out/"
# What built it, for anyone comparing archives later.
{
  echo "version $version"
  echo "commit $commit"
  echo "zig $("$zig" version) ($(command -v "$zig"))"
  echo "host $(uname -s) $(uname -m)"
  echo "built $(date -u +%Y-%m-%dT%H:%M:%SZ)"
} > "$out/BUILDINFO"
rm -rf "$build"
echo "rweb $version from $commit, built with $zig $("$zig" version):"
cat "$out/SHA256SUMS"
