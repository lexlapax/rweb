#!/bin/sh
# Checks that tools/release.sh refuses an unsafe release base folder before it puts anything in it,
# and makes a folder of ours private. Runs in seconds (it stops after the checks, before any build).
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

# A folder owned by another user cannot be made without root; when run as root, check it.
if [ "$(id -u)" = 0 ]; then
  mkdir "$t/theirs" && chown 1:1 "$t/theirs"
  expect_refused "$t/theirs" "a folder owned by another user"
else
  echo "skip: a folder owned by another user (needs root to set up)"
fi
exit $fail
