#!/usr/bin/env python3
"""Compare the browser's screen with Rex's own capture of the same test block.

Usage: compare.py SESSION BLOCK BROWSER_JSON
BROWSER_JSON is the browser's visible rows, written by the spike from window.rweb.dump().
Only ever pass the spike's own rweb-test- session and block.
"""
import json
import re
import subprocess
import sys


def main() -> int:
    session, block, browser_file = sys.argv[1:4]
    if not session.startswith("session:") or not block.startswith("block:"):
        print("pass full session: and block: IDs", file=sys.stderr)
        return 2
    rex = subprocess.run(
        ["rex", "capture", "-s", session, "-b", block, "--format", "vt"],
        check=True, capture_output=True, text=True,
    ).stdout
    browser = [l.rstrip() for l in json.load(open(browser_file))]
    rows = len(browser)
    # The VT capture keeps every screen row. Expand cursor-forward (CSI n C) into
    # spaces, strip the other escape sequences, and split rows on CRLF.
    text = re.sub(r"\x1b\[(\d*)C", lambda m: " " * int(m.group(1) or 1), rex)
    text = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(\x07|\x1b\\)|\x1b[()][0-9A-Za-z]|\x1b[=>78DEHMc]", "", text)
    lines = [l.rstrip() for l in text.replace("\r", "").split("\n")]
    # The CLI ends its output with a newline, which may or may not be a row
    # separator: try both readings and keep the closer one.
    best = None
    for cand in (lines, lines[:-1]):
        screen = cand[-rows:]
        screen = [""] * (rows - len(screen)) + screen
        d = [(i, b, r) for i, (b, r) in enumerate(zip(browser, screen)) if b != r]
        if best is None or len(d) < len(best):
            best = d
    diffs = best
    print(f"rows={rows} differing={len(diffs)}")
    for i, b, r in diffs:
        print(f"  row {i}:\n    browser: {b!r}\n    rex:     {r!r}")
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
