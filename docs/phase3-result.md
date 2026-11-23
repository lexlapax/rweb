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

## Not verified, and limits

- **Real devices with this build.** Everything above was Chrome on the Mac. Still to try on the
  phone and tablet: the soft keyboard and key row together, the visual-viewport behaviour, Copy and
  its selection handles, the paste fallback, and Phase 0 findings 12 and 13 on Gboard and Samsung
  Keyboard. They were not reproduced in Phase 2 with a healthy connection.
- The phone needs its Tailscale power saving off (Phase 2, Findings 5).
- The Copy view is a text box: it shows the text as-is (no colour) and copies with the browser's
  own selection or "Copy all" (which needs the browser to allow clipboard writes; otherwise it
  selects the text for you to copy).
- No pinch-to-zoom, no chat view, no split layout (all outside the first version).
- Paste uses the browser's clipboard read; where that is refused a text box asks for the text.
