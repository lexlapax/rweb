#!/bin/sh
# Reports what changed upstream of rweb's pins, so each change is looked at before new work:
#   rex       the Rex server here: its API revision against the ones rweb speaks, and its protocol
#             document (llms.txt) against the one this rweb was built for (tools/upstream.lock)
#   ghostty   Ghostty's newest libghostty-vt tag (vt-*) against build.zig.zon's
#   zig       Zig's newest release against build.zig.zon's minimum_zig_version
#   npm       each package in tools/vendor/packages.lock against its latest version, and esbuild
# Usage: tools/upstream-check.sh [rex|network|all]   (default all; inside the repository)
#   rex       only the local Rex server (no network)
#   network   only what is asked of GitHub, ziglang.org and npm (run it in a sandbox: it reads the
#             internet; see docs/upstream-check.md)
# Prints one line per item: NAME  PINNED  FOUND  same|NEWER|CHANGED|unreadable|skipped. Only version
# strings are printed, and only ones that look like a version; anything else is "unreadable".
# Exit: 0 all current, 1 something to look at (NEWER or CHANGED), 2 a check could not be made.
set -eu
what=${1:-all}
case $what in rex|network|all) ;; *) echo "usage: tools/upstream-check.sh [rex|network|all]" >&2; exit 2 ;; esac
top=$(cd "$(dirname "$0")/.." && pwd)
lock=$top/tools/upstream.lock
status=0

# A version-looking string or nothing: letters, digits, `.`, `-`, `_` and `+`, at most 40.
version_only() { printf '%s\n' "$1" | grep -Ex '[0-9A-Za-z._+-]{1,40}' || true; }
report() {   # name pinned found
  found=$(version_only "$3")
  if [ -z "$found" ]; then verdict=unreadable; [ $status -lt 2 ] && status=2
  elif [ "$found" = "$2" ]; then verdict=same
  else verdict=NEWER; status=$(( status > 1 ? status : 1 )); fi
  printf '%-22s %-22s %-22s %s\n' "$1" "$2" "${found:--}" "$verdict"
}
line() { printf '%-22s %-22s %-22s %s\n' "$@"; }
newest() { sort -t. -k1,1n -k2,2n -k3,3n | tail -n 1; }   # of X.Y.Z lines
fetch() { curl -fsSL --proto '=https' --max-time 20 --max-filesize 4000000 "$1" 2>/dev/null || true; }
lockval() { awk -v k="$1" '$1 == k { print $2 }' "$lock"; }

printf '%-22s %-22s %-22s %s\n' NAME PINNED FOUND VERDICT

if [ "$what" != network ]; then
  # The Rex server of this user: its own socket, as rweb finds it.
  sock=${REX_SOCKET:-}
  if [ -z "$sock" ]; then
    for s in "$HOME/Library/Application Support/Rex/server.sock" "$HOME/Library/Application Support/rex/server.sock" \
             "${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/rex/server.sock"; do
      [ -S "$s" ] && { sock=$s; break; }
    done
  fi
  max=$(sed -n 's/^pub const api_max_supported: u32 = \([0-9]*\);/\1/p' "$top/src/rex/control.zig")
  if [ -z "$sock" ]; then
    line rex-api-revision "$max" - "skipped (no Rex server here)"
  else
    doc=$(curl -fsS --max-time 10 --unix-socket "$sock" http://localhost/llms.txt 2>/dev/null || true)
    rev=$(printf '%s\n' "$doc" | sed -n 's/.*describes API revision \([0-9]*\)\..*/\1/p' | head -n 1)
    if [ -z "$rev" ]; then report rex-api-revision "$max" ""
    elif [ "$rev" -gt "$max" ]; then line rex-api-revision "$max" "$rev" NEWER; status=$(( status > 1 ? status : 1 ))
    elif [ "$rev" -eq "$max" ]; then line rex-api-revision "$max" "$rev" same
    else line rex-api-revision "$max" "$rev" "same (older; rweb speaks it too)"; fi
    want=$(lockval rex-llms-sha256)
    if [ -z "$doc" ]; then line rex-llms.txt "$(lockval rex-version)" - unreadable; status=2
    else
      sum=$(printf '%s\n' "$doc" | { shasum -a 256 2>/dev/null || sha256sum; } | cut -c1-64)
      if [ "$sum" = "$want" ]; then line rex-llms.txt "$(lockval rex-version)" "$(lockval rex-version)" same
      else line rex-llms.txt "$(lockval rex-version)" "sha256:$(printf %s "$sum" | cut -c1-12)" CHANGED; status=$(( status > 1 ? status : 1 )); fi
    fi
  fi
fi

if [ "$what" != rex ]; then
  pinned=$(sed -n 's|.*ghostty/archive/refs/tags/vt-\([0-9.]*\)\.tar\.gz.*|\1|p' "$top/build.zig.zon")
  found=$(fetch "https://api.github.com/repos/ghostty-org/ghostty/git/matching-refs/tags/vt-" |
    grep -oE '"refs/tags/vt-[0-9]+\.[0-9]+\.[0-9]+"' | sed 's|"refs/tags/vt-||; s|"||' | newest)
  report ghostty-vt "$pinned" "$found"

  pinned=$(sed -n 's/.*minimum_zig_version = "\([^"]*\)".*/\1/p' "$top/build.zig.zon")
  found=$(fetch https://ziglang.org/download/index.json | grep -oE '"[0-9]+\.[0-9]+\.[0-9]+": *\{' | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | newest)
  report zig "$pinned" "$found"

  # Each npm package once (the three esbuild platform packages share esbuild's version).
  grep -v '^#' "$top/tools/vendor/packages.lock" | awk 'NF >= 2 { print $1, $2 }' | sed 's|^@esbuild/[^ ]*|esbuild|' | sort -u |
  while read -r pkg ver; do
    found=$(fetch "https://registry.npmjs.org/$pkg/latest" | grep -oE '"version": *"[^"]*"' | head -n 1 | sed 's/.*"\([^"]*\)"$/\1/')
    report "$pkg" "$ver" "$found"
  done > "${TMPDIR:-/tmp}/rweb-upstream.$$"
  cat "${TMPDIR:-/tmp}/rweb-upstream.$$"
  grep -q ' NEWER$' "${TMPDIR:-/tmp}/rweb-upstream.$$" && status=$(( status > 1 ? status : 1 ))
  grep -q ' unreadable$' "${TMPDIR:-/tmp}/rweb-upstream.$$" && status=2
  rm -f "${TMPDIR:-/tmp}/rweb-upstream.$$"
fi

case $status in
  0) echo "upstream-check: everything is as pinned" ;;
  1) echo "upstream-check: something changed upstream; see docs/upstream-check.md for what to do with each" ;;
  *) echo "upstream-check: a check could not be made (unreadable); run it again, or look by hand" ;;
esac
exit $status
