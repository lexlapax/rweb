#!/bin/sh
# Export the logo's rasters from the SVG sources in this folder: headless Chrome draws each SVG at its
# exact pixel size (scale factor 1, transparent background unless a backdrop is given) and ico.py packs
# the favicon. Writes the web icons to src/bridge/web/icons/ and the rest to this folder. Run again
# after changing a source; the same Chrome gives the same files. CHROME=/path/to/chrome to choose one.
set -eu

here=$(cd "$(dirname "$0")" && pwd)
repo=$(cd "$here/../.." && pwd)
web="$repo/src/bridge/web/icons"
chrome=${CHROME:-"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"}
[ -x "$chrome" ] || { echo "build.sh: no Chrome at $chrome (set CHROME)" >&2; exit 1; }
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
mkdir -p "$web" "$here/png"

# shot SOURCE.svg OUT.png SIZE [PAGE_WIDTH PAGE_HEIGHT BACKDROP]: SOURCE drawn SIZE wide, centred on a
# page of PAGE_WIDTH x PAGE_HEIGHT pixels (default: the image's own size) filled with BACKDROP.
shot() {
    src=$1 out=$2 size=$3
    h=$(awk -v s="$size" -v vb="$(sed -n 's/.*viewBox="\([^"]*\)".*/\1/p' "$here/$src")" \
        'BEGIN { split(vb, v, " "); printf "%d", s * v[4] / v[3] + 0.5 }')
    pw=${4:-$size} ph=${5:-$h} bg=${6:-transparent}
    printf '<!doctype html><html><body style="margin:0;width:%spx;height:%spx;display:flex;align-items:center;justify-content:center;background:%s"><img src="file://%s/%s" width="%s" height="%s"></body></html>\n' \
        "$pw" "$ph" "$bg" "$here" "$src" "$size" "$h" >"$tmp/page.html"
    "$chrome" --headless=new --user-data-dir="$tmp/profile" --no-first-run --disable-gpu \
        --force-device-scale-factor=1 --default-background-color=00000000 --hide-scrollbars \
        --window-size="$pw,$ph" --screenshot="$tmp/shot.png" "file://$tmp/page.html" >/dev/null 2>&1
    got=$(sips -g pixelWidth -g pixelHeight "$tmp/shot.png" | awk '/pixel/ { printf "%s ", $2 }')
    [ "$got" = "$pw $ph " ] || { echo "build.sh: $out came out ${got% }, not $pw $ph" >&2; exit 1; }
    mv "$tmp/shot.png" "$out"
    echo "$out ($pw x $ph)"
}

# 16 and 32 px from the small variant (crisper); 48 px and up from the full icon.
shot icon-small.svg "$here/png/icon-16.png" 16
shot icon-small.svg "$here/png/icon-32.png" 32
shot icon.svg "$here/png/icon-48.png" 48
python3 "$here/ico.py" "$web/favicon.ico" "$here/png/icon-16.png" "$here/png/icon-32.png" "$here/png/icon-48.png"
echo "$web/favicon.ico (16, 32, 48)"
cp "$here/icon-small.svg" "$web/favicon.svg"
echo "$web/favicon.svg"

# iOS rounds the corners itself, so its icon is full-bleed.
shot icon-square.svg "$web/apple-touch-icon.png" 180
shot icon.svg "$web/icon-192.png" 192
shot icon.svg "$web/icon-512.png" 512
shot icon-maskable.svg "$web/icon-maskable-512.png" 512

# GitHub's social preview: the lockup centred on the tile colour.
shot lockup.svg "$here/social-preview.png" 810 1280 640 '#181818'
