#!/bin/sh
# Builds the release archives for one commit, reproducibly: the commit is exported with `git archive`
# into a fixed path and built there (Ghostty's C++ embeds a cache path that depends on where the build
# runs). Machines of the same host platform (for example two Apple-silicon Macs) with the same official
# Zig get byte-identical archives; machines of different host platforms do not, because that embedded
# path still differs (see docs/phase5-result.md, "Pinning Zig").
# The compiler is the pinned official Zig, `zig-<minimum_zig_version>` from PATH, when it is installed
# (package managers' builds of the same version compile differently); without it the script stops, unless
# RWEB_RELEASE_ANY_ZIG=1 says to use `zig` from PATH anyway.
# Usage: tools/release.sh [COMMIT]   (default: HEAD; run inside the repository)
# It runs the tests on the exported commit first and packs nothing if they fail. It is the only way to
# make release archives: `zig build dist` alone packs the working tree, uncommitted edits included.
# Result: the archives, SHA256SUMS and BUILDINFO in zig-out/release/<version>/ of the current checkout. A version
# that has a folder there already is not built again; remove the folder on purpose to rebuild it.
#
# The fixed path is in a shared /tmp, so the base folder must be ours alone before anything is put in
# it: a real directory (not a link), owned by this user, mode 0700. /tmp's sticky bit then keeps other
# users from renaming or replacing it, and its mode keeps them out of the source and the Zig cache.
# What an earlier run, or anyone who could write there before it was closed, left in it is not trusted
# either: it is emptied, and the source and the Zig cache are made new by each run. (So every run
# fetches the pinned dependencies again and compiles everything; that is the price.)
set -eu
commit=$(git rev-parse --verify "${1:-HEAD}^{commit}")
top=$(git rev-parse --show-toplevel)
base=${RWEB_RELEASE_BASE:-/tmp/rweb-release}  # the override exists for tools/release-base.test.sh

die() { echo "release.sh: $*" >&2; exit 1; }
owner_of() { stat -c %u "$1" 2>/dev/null || stat -f %u "$1"; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

marker=$base/.rweb-release-base   # says the folder is release.sh's own, to empty
made=0
(umask 077; mkdir "$base" 2>/dev/null) && made=1
[ -L "$base" ] && die "$base is a symbolic link; remove it and run again"
[ -d "$base" ] || die "$base is not a directory; remove it and run again"
[ "$(owner_of "$base")" = "$(id -u)" ] || die "$base belongs to another user; remove it (as that user or root) and run again"
# Check the marker before touching the folder's permissions or contents, so a folder of yours named
# by mistake is neither modified nor emptied.
if [ "$made" = 0 ] && [ ! -e "$marker" ] && [ ! -L "$marker" ]; then
  if [ ! -r "$base" ] || [ -n "$(ls -A "$base" 2>/dev/null || echo unreadable)" ]; then
    die "$base has files in it and was not made by release.sh, which would empty it. If it is an old release folder, remove it (rm -rf '$base') and run again"
  fi
fi
# Ours and not a link: closing it is safe. Strip any ACL too (`chmod 0700` on macOS leaves extended
# ACLs in place, so another user granted write there would keep it during the build).
chmod 0700 "$base"
if [ "$(uname -s)" = Darwin ]; then
  chmod -N "$base" 2>/dev/null || true
elif command -v setfacl >/dev/null 2>&1; then
  setfacl -b "$base" 2>/dev/null || true
fi
[ "$(mode_of "$base")" = 700 ] || die "$base could not be made private (mode $(mode_of "$base"))"
case "$(ls -ld "$base" | awk '{print $1}')" in
  *+*) die "$base still has an access control list; remove it and run again" ;;
esac
# Closed from here on, but it may have been open before (made by hand, or by something else): a Zig
# cache found in it could hold another user's file, a link, or a hard link to some file of ours, and
# the build would use it. Owners and modes cannot show all of that, so nothing found is kept. The
# source and the cache stay at their fixed paths all the same: the build embeds paths, and archives of
# one commit must stay byte-identical. `rm` removes a link, never what it leads to; something of
# another user's that cannot be removed stops the run.
# Two runs at once in one base would remove each other's work: run one at a time.
find "$base" -mindepth 1 -maxdepth 1 -exec rm -rf {} + || true
[ -z "$(ls -A "$base")" ] || die "$base could not be emptied (see above); remove it, as its owner or root, and run again"
: > "$marker"
[ "${RWEB_RELEASE_CHECK_ONLY:-}" = 1 ] && { echo "release base ok: $base"; exit 0; }

version=$(git -C "$top" show "$commit:build.zig.zon" | sed -n 's/^ *\.version = "\(.*\)",$/\1/p')
[ -n "$version" ] || die "no .version in build.zig.zon at $commit"
out=$top/zig-out/release/$version
[ -e "$out" ] && die "$out exists already, so $version is not built again (it would replace those archives).
To rebuild $version on purpose, remove it first: rm -rf '$out'"

build=$base/$commit
cache=$base/zig-cache
mkdir "$build" "$cache"   # both new: the base was emptied above, and `mkdir` fails on anything there
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
(cd "$build" && env -u REX_SOCKET ZIG_GLOBAL_CACHE_DIR="$cache" "$zig" build test -Doptimize=ReleaseSafe) || die "the tests failed on $commit; nothing was packed"
(cd "$build" && ZIG_GLOBAL_CACHE_DIR="$cache" "$zig" build dist -Dcommit="$commit")
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
rm -rf "$build" "$cache"
echo "rweb $version from $commit, built with $zig $("$zig" version):"
cat "$out/SHA256SUMS"
