#!/bin/sh
# Checks that tools/release.sh refuses an unsafe release base folder before it puts anything in it,
# makes a folder of ours private, and keeps nothing that was in it. Runs in seconds (it stops after the checks, before any build).
# Usage: sh tools/release-base.test.sh   (inside the repository)
set -eu
here=$(cd "$(dirname "$0")" && pwd)
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
fail=0
run() { RWEB_RELEASE_BASE=$1 RWEB_RELEASE_CHECK_ONLY=1 sh "$here/release.sh" >"$t/out" 2>&1; }
mode_of() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }
expect_refused() {
  if run "$1"; then echo "FAIL: $2 was accepted"; fail=1; else echo "ok: $2 refused ($(cat "$t/out"))"; fi
}

mkdir "$t/elsewhere"
ln -s "$t/elsewhere" "$t/link"
expect_refused "$t/link" "a symbolic link"
[ -z "$(ls -A "$t/elsewhere")" ] || { echo "FAIL: something was written through the link"; fail=1; }

: > "$t/file"
expect_refused "$t/file" "a plain file"

mkdir -m 0755 "$t/open"
if run "$t/open" && [ "$(mode_of "$t/open")" = 700 ]; then echo "ok: an open folder of ours is made 0700"; else echo "FAIL: open folder: $(cat "$t/out")"; fail=1; fi

if run "$t/new" && [ "$(mode_of "$t/new")" = 700 ]; then echo "ok: a new folder is created 0700"; else echo "FAIL: new folder: $(cat "$t/out")"; fail=1; fi

# What was in a folder that was open before (a Zig cache, a link out of it) is not kept; what a link
# led to is not touched.
mkdir -m 0777 "$t/used" "$t/used/zig-cache" "$t/used/zig-cache/p"
: > "$t/used/.rweb-release-base"
: > "$t/used/zig-cache/p/planted"
: > "$t/elsewhere/keep"
ln -s "$t/elsewhere" "$t/used/zig-cache/out"
ln -s "$t/elsewhere" "$t/used/0000000000000000000000000000000000000000"
ln "$t/elsewhere/keep" "$t/used/zig-cache/hard"
if run "$t/used" && [ "$(ls -A "$t/used")" = .rweb-release-base ] && [ -f "$t/elsewhere/keep" ] && [ "$(mode_of "$t/used")" = 700 ]; then echo "ok: a used folder of ours is emptied, and what its links led to is kept"; else echo "FAIL: used folder: $(cat "$t/out"); left: $(ls -A "$t/used")"; fail=1; fi

# A folder with files in it that release.sh did not make is refused, and keeps them.
mkdir "$t/mine"
: > "$t/mine/thesis.txt"
expect_refused "$t/mine" "a folder with files that release.sh did not make"
[ -f "$t/mine/thesis.txt" ] || { echo "FAIL: a file in a folder release.sh did not make was removed"; fail=1; }

# A folder owned by another user cannot be made without root; when run as root, check it.
if [ "$(id -u)" = 0 ]; then
  mkdir "$t/theirs" && chown 1:1 "$t/theirs"
  expect_refused "$t/theirs" "a folder owned by another user"
else
  echo "skip: a folder owned by another user (needs root to set up)"
fi
exit $fail
