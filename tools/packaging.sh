#!/bin/sh
# Makes the Homebrew formula and the AUR PKGBUILD for a release, from the templates in packaging/ and the
# release's SHA256SUMS (made by tools/release.sh, in zig-out/release/<version>/), after checking that
# SHA256SUMS carries a good signature from the rweb-release key (tools/release-signers).
# Usage: tools/packaging.sh VERSION    (inside the repository)
# Result: zig-out/release/<version>/packaging/homebrew/rweb.rb and .../aur/PKGBUILD. The formula goes to the
# tap (Formula/rweb.rb); the PKGBUILD, with `makepkg --printsrcinfo > .SRCINFO`, to the AUR package rweb-bin.
set -eu
version=${1:?usage: tools/packaging.sh VERSION}
top=$(git rev-parse --show-toplevel)
rel=${RWEB_PACKAGING_RELEASE_DIR:-$top/zig-out/release/$version}   # the override is for tests
signers=${RWEB_PACKAGING_SIGNERS:-$top/tools/release-signers}       # likewise
die() { echo "packaging.sh: $*" >&2; exit 1; }
printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' || die "not a release version: $version"
[ -f "$rel/SHA256SUMS" ] || die "no $rel/SHA256SUMS: run tools/release.sh for $version first"
[ -f "$rel/SHA256SUMS.sig" ] || die "$rel/SHA256SUMS is not signed (no SHA256SUMS.sig); packages are made only from a signed release"
ssh-keygen -q -Y verify -f "$signers" -I rweb-release -n file -s "$rel/SHA256SUMS.sig" < "$rel/SHA256SUMS" >/dev/null ||
  die "the signature on $rel/SHA256SUMS does not verify against tools/release-signers"
sum() { awk -v f="rweb-$version-$1.tar.gz" '$2 == f { print $1 }' "$rel/SHA256SUMS"; }
mac=$(sum macos-arm64)
linux=$(sum linux-x86_64)
[ -n "$mac" ] && [ -n "$linux" ] || die "SHA256SUMS lacks an archive for macos-arm64 or linux-x86_64"
unit=$(shasum -a 256 "$top/packaging/aur/rweb.service" 2>/dev/null || sha256sum "$top/packaging/aur/rweb.service")
unit=${unit%% *}
# Each a single SHA-256 (two lines for one archive in SHA256SUMS would put a newline in it).
for h in "$mac" "$linux" "$unit"; do
  case $h in *[!0-9a-f]*) die "SHA256SUMS or rweb.service gave something that is not one SHA-256" ;; esac
  [ ${#h} -eq 64 ] || die "SHA256SUMS or rweb.service gave something that is not one SHA-256"
done
# Each step on its own, so a failure stops the script (a pipeline's status is its last command's).
# Lines starting `#: ` describe the template and are left out.
make() {
  sed -e "s/@VERSION@/$version/g" -e "s/@SHA256_MACOS_ARM64@/$mac/g" -e "s/@SHA256_LINUX_X86_64@/$linux/g" \
    -e "s/@SHA256_AUR_SERVICE@/$unit/g" "$1" > "$2.tmp"
  grep -v '^#: ' "$2.tmp" > "$2" || { rm -f "$2.tmp" "$2"; die "$1 gave nothing"; }
  rm -f "$2.tmp"
}
mkdir -p "$rel/packaging/homebrew" "$rel/packaging/aur"
formula=$rel/packaging/homebrew/rweb.rb
pkgbuild=$rel/packaging/aur/PKGBUILD
make "$top/packaging/homebrew/rweb.rb.in" "$formula"
make "$top/packaging/aur/PKGBUILD.in" "$pkgbuild"
cp "$top/packaging/aur/rweb.service" "$rel/packaging/aur/rweb.service"
! grep -q '@[A-Z0-9_]*@' "$formula" "$pkgbuild" || die "a placeholder was left unfilled"
# What each must hold, so an empty or cut-short file is never reported as made.
[ "$(head -n 1 "$formula")" = "class Rweb < Formula" ] || die "$formula does not start with the formula"
for want in "sha256 \"$mac\"" "sha256 \"$linux\"" "/v$version/rweb-$version-macos-arm64.tar.gz"; do
  grep -qF "$want" "$formula" || die "$formula lacks $want"
done
grep -qx 'pkgname=rweb-bin' "$pkgbuild" || die "$pkgbuild lacks pkgname=rweb-bin"
for want in "pkgver=$version" "'$linux'" "'$unit'"; do
  grep -qF "$want" "$pkgbuild" || die "$pkgbuild lacks $want"
done
echo "made $rel/packaging/homebrew/rweb.rb and $rel/packaging/aur/{PKGBUILD,rweb.service} for rweb $version"
