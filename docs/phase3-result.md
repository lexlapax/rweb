# Phase 3 result: the frontend

Status: **built and checked in Chrome on desktop-mac (desktop and phone width) and by tests; not yet
tried on the owner's phone or tablet with this build.** The plan's exit ("daily use from a phone
and a laptop browser for a week without falling back to SSH") is the owner's to observe and is not
claimed. Plan: [PLAN.md](PLAN.md#phase-3-frontend). Where this and the code differ, the code wins.

## Owner's decisions for Phase 3 (2026-11-22)

| Question | Answer |
| --- | --- |
| Key row | Like Ovis's terminal view: one bottom row on touch screens, hidden on a laptop |
| Text size | + and − buttons, remembered per device (no pinch) |
| Copying on a phone | A Copy button that opens the screen and history as plain text, with "Copy all" |
| Appearance | Dark, with each terminal's own colours |

Ovis (running on desktop-mac) was looked at, view only: a slim top bar (menu, breadcrumb, terminal
switcher, menu), the terminal filling the screen, and one key row: Esc, Tab, ^C, Ctrl, Alt, Shift,
Enter, ↑, ↓ and a "more" chevron. Its chat view is out of scope for now.

## What exists (`src/bridge/web/`)

| File | What it is |
| --- | --- |
| `index.html`, `app.css` | Slim top bar (menu, session › terminal, terminal tabs or an "1/2 ▾" switcher, status dot, ⋯ menu), a banner for states, the list as a drawer, dialogs |
| `app.js` | Connection with watchdog, tree and tabs, dialogs, Copy and Paste, key row, remembered settings |
| `keys.js` | Pure logic: key names, modifier latching and Ctrl/Alt translation, key rows, font clamp, fit scale |
| `tests/web/keys.test.mjs` | 8 Node tests of `keys.js` (`zig build web-test`) |

Bridge additions: a `text` request answered with the screen and scrollback as plain text
(soft-wrapped lines joined, at most 1 MiB, the end kept at a line start).

Behaviour:
- **Key row** on touch screens and narrow windows: Esc, Tab, ^C, Ctrl, Alt, Shift (sticky for one
  key), Enter, ↑, ↓, and a ⌃ button that opens ← → Home End PgUp PgDn | ~ / \ - ` and Paste.
  Arrows and paging repeat while held. Buttons take `pointerdown` without taking focus, so the
  soft keyboard stays up. A latched Ctrl/Alt/Shift applies to the next key button or the next
  single character from the soft keyboard (Ctrl+L, Alt+F), never to a composed word.
- **⋯ menu:** Copy text…, Paste…, Text size − / +, View only, Fit terminal to this window…, Load
  all scrollback, Reconnect.
- **Dialogs are in the page** (no `confirm()`/`prompt()`): new session, rename, and a confirmation
  before closing a terminal or session, where the safe choice has the focus.
- **Remembered per device:** text size, whether the list is open, and the last terminal (reopened
  after a reload if it still exists).
- **Soft keyboard:** the page follows the visual viewport, so the cursor stays above it. Enter and
  Backspace go through xterm.js while a soft keyboard is in use (Phase 0, finding 12).
- **Status:** a coloured dot and a banner for reconnecting, stalled connection, Rex unreachable,
  view only, and program exited. Typing is refused (with a notice) while the link is stalled.
- Labels and terminal text reach the page only as text content: no `innerHTML`, no inline script
  or style (tests guard this).

## Checks (desktop-mac, 2026-11-22)

- `zig build test`: 107 pass, 1 skip with the live Rex tests; also in `ReleaseSafe`; linux-box 145
  pass, 1 skip. `zig build web-test`: 8 pass. New tests: Copy text from the hub and the mirror (all
  history, no escape sequences, wrapped lines joined, truncation keeps the end), assets served,
  page references only embedded files and has no inline code or pop-ups.
- In Chrome with a throwaway session (`rweb-test-ui`, destroyed afterwards): created it through
  the dialog; opened it; typed and ran a command; the ⋯ menu; text size 14 → 16 persisted and the
  terminal reopened after a reload; Copy view showed the whole screen as plain text. At 400 px
  wide: the list hidden, compact bar, the key row; Enter then ^C interrupted a `sleep 300`;
  latched Ctrl plus a soft-keyboard `l` cleared the screen and released the latch; the ⌃ panel;
  a second terminal appeared in the "1/2 ▾" switcher; closing it asked first (Cancel focused, a
  cancel closed nothing, confirming closed it); closing the session asked first and removed it.

## Fixed after the owner's first phone and tablet try (2026-11-22)

- **Backspace deleted a character in the shell but the page still showed it.** Phone keyboards
  hold a word back until you press space, and on Backspace re-open the word they already
  committed; xterm.js's composition overlay then kept showing text the shell no longer had. On a
  touch device (`pointer: coarse`, or the first keyboard event with no key code) the page now
  takes over: the hidden text box holds what has been typed since the last Enter, and every
  change to it is mirrored to the shell at once (`editsBetween`: keep the common start, send
  DELs for what went, type what came). The shell's own echo is the only display. xterm.js never
  sees these events (intercepted in the capture phase on the terminal's outer element, since its
  own `input` handler on the text box registers first and sent each space twice).
  Checked by replaying a Samsung-style sequence in desktop Chrome: compose `echo`, commit with a
  space, Backspace, the keyboard re-opening the word and retyping it, a word composed then
  rewritten by autocorrect (`soft` to `sofa`), Enter. The page sent `e c h o ␣ DEL DEL o ␣ s o
  f t DEL a`-style edits with nothing doubled, and Rex's own capture of the shell showed
  `echo sofa` and `sofa`. A real phone is still the proof.
- **Long-press in the terminal itself** (Ovis allows it). Cause: xterm.js's stylesheet sets
  `user-select: none` on the whole terminal and it does mouse-only selection of its own. This page
  uses xterm.js's DOM renderer (the screen is 24 ordinary text rows, checked), so on touch screens
  (`pointer: coarse`) the rows are now selectable natively. Checked here that, with the rule, the
  rows select and read back; whether a long press on the owner's phone then shows handles and
  survives xterm's own handlers is to be confirmed.
- **No selection handles in the Copy view** (a read-only text box first, then plain text; the
  long press showed no handles on the owner's phone in either). Backspace and the Copy all and
  Copy last 100 lines buttons were confirmed working on the phone. The Copy view now also has a
  selection the page makes itself, which needs no OS handles: tap a line to start, tap another to
  select down or up to it, then "Copy N lines" (and Clear, and Share… where the browser has it).
  Copying falls back to the old `execCommand` way. Checked in Chrome on 40 numbered lines: start,
  extend down, extend up, clear, and the button label. The owner's phone showed no handles on
  long press even so, so there is also a **Use handles** button: it makes the text editable but
  locked (no keyboard, `inputmode=none`; paste, cut, drop and typing are blocked, and any change
  that gets through is undone), because Chrome on Android shows selection handles on editable
  text more reliably than on plain text. Checked in Chrome that the lock holds against scripted
  inserts and deletes. On the owner's phone **Use handles worked** (handles appeared), and Paste
  worked. A selection lab page (`/labsel`) then showed handles on all eight differently built
  boxes, including a copy of the Copy screen's structure: the page's styles, click handlers and
  dialog are not what stopped them. The remaining difference is that in the real page the
  terminal's hidden input box still had the focus (and the soft keyboard connection) when the
  Copy screen opened, which is also what "Use handles" changes. The Copy screen now blurs the
  terminal and focuses its own text. Whether a plain long press now shows handles is to be
  confirmed on the phone.
- Paste was not tried yet.

## The other terminal: wterm (2026-11-22)

The owner wanted Ovis's behaviour: long-press selection with handles on the terminal itself. That
is not available in xterm.js, which turns off text selection for the whole terminal and does
mouse-only selection of its own (and my overrides did not get it working on the owner's phone).
herdr-webui, which Ovis is built from, draws the screen with **wterm** (Vercel Labs, Apache-2.0):
terminal rows as ordinary DOM text, with libghostty compiled to WebAssembly as the core
(`@wterm/ghostty`), the same engine family as the bridge. The owner was right that this should
have been looked at first; the Phase 0 choice of xterm.js was made on rendering correctness only.

What was done:
- Vendored `@wterm/dom` 0.6.0, `@wterm/core` 0.6.0 and `@wterm/ghostty` 0.6.0 (tarballs checked
  with `npm pack`, nothing installed or run) as one bundle:
  `esbuild entry.mjs --bundle --format=iife --minify --legal-comments=none
  --define:import.meta.url='"https://rweb.invalid/vendor/"'` with esbuild 0.25.12, from
  `import {WTerm} from "@wterm/dom"; import {GhosttyCore} from "@wterm/ghostty";
  globalThis.RwebWterm = {WTerm, GhosttyCore}`. Tarball SHA-256: dom
  `ab72f96c…c1eb`, core `8c34da7e…374c8`, ghostty `4ce92ce9…fdd02`. Files in
  `src/bridge/web/vendor/`: `wterm.js` (245 KB, 84 KB compressed, sha256 `fbe16525…bd1b`),
  `wterm.css` (`01be4dbf…0f66`), `ghostty-vt.wasm` (600 KB, 200 KB compressed, `1fa4e703…e3a2`),
  `LICENSE-wterm.txt` (Apache-2.0, same text for all three packages).
- The page's security policy now allows WebAssembly (`'wasm-unsafe-eval'` in `script-src`): a
  change for the security review.
- `wterm-shim.js` gives wterm the small xterm-like surface `app.js` uses. wterm hands its own
  replies to terminal queries to the page as if typed, so the shim drops them (Rex's terminal has
  already answered the program). Checked: after `printf '\033[c\033[5n\033[6n'` only Rex's one set
  of answers appears, no duplicates. Soft-keyboard text, composition and Backspace are left to
  wterm (it keeps a placeholder in its input box so Backspace works on touch screens); only
  physical keys are taken over and sent to Rex as key events.
- `?term=wterm` (remembered on the device) or the ⋯ menu's terminal item switches; xterm.js stays
  the default for now. If wterm fails to start the page falls back to xterm.js and says so.
- Found and fixed while checking, each a real bug of mine rather than of wterm: (1) shrinking the
  terminal to fit a narrow screen with a CSS scale broke wterm, which measures cells and places
  its typing overlay from on-screen coordinates (this is the owner's "text overwrites appear in
  the display" on the phone, most likely): for wterm the font size is now reduced until all
  columns fit, with no scaling; (2) wterm sizes its box for the rows it was created with, so
  after Rex's terminal grew to 30 rows the top rows were scrolled out of view: the box now
  fills the stage; (3) wterm's theme call needs 24-bit numbers and exactly 16 palette entries, so
  Rex's `RRGGBB` strings threw and the theme was silently ignored: the shim converts them and fills
  the palette from wterm's defaults.
- Checked in Chrome: the live Rex terminal draws; typed commands run; colour; a wide character
  and a combining accent are right; terminal queries leave no duplicate replies. Also checked: `less` (alternate screen) draws and quitting restores the earlier
  screen; sticky Ctrl plus a soft-keyboard letter (Ctrl+L) clears the screen and releases the latch;
  Rex resizing to 100×30 gives 30 real rows with the font shrinking to fit; the theme (colours and
  palette overrides) applies; the page reconnects by itself with the screen intact. On the
  owner's phone: long-press selection with handles and Copy works on the terminal itself.
  **Not yet checked:** typing with the Samsung and Gboard keyboards on wterm (including Backspace),
  mouse reporting, paste, Rex restart, and scrollback with the history cap.

## Not verified, and limits

- **Real devices with this build.** Everything above was Chrome on the Mac. Still to try on the
  phone and tablet: the soft keyboard and key row together, the visual-viewport behaviour, Copy and
  its selection handles, the paste fallback, and Phase 0 findings 12 and 13 on Gboard and Samsung
  Keyboard. They were not reproduced in Phase 2 with a healthy connection.
- The phone needs its Tailscale power saving off (Phase 2, Findings 5).
- The Copy view shows the text as-is (no colour). "Copy all" and "Copy last 100 lines" need the
  browser to allow clipboard writes (https is enough); otherwise it says so and you select instead.
- Live forwarding of soft-keyboard edits means a CJK input method (which composes before it
  commits) would send its raw letters; not a concern for the owner's use, but a limit.
- No pinch-to-zoom, no chat view, no split layout (all outside the first version).
- Paste uses the browser's clipboard read; where that is refused a text box asks for the text.
