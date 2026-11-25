# Feedback from daily use

The owner's running list of things found while using rweb every day (from 2026-11-23, Phase 3's
week of use). Newest last. Each item gets a number, a date, a status (`open`, `done <commit>`,
`declined <why>`) and where in the code it lives. Do not renumber.

| # | Date | Area | Feedback | Status |
| --- | --- | --- | --- | --- |
| 1 | 2026-11-23 | Key bar | In the bottom pane's bottom row (the key bar), **Enter should be the first button**. | done 2026-11-25 (`web: Enter first in the key bar`) |
| 2 | 2026-11-23 | Phone, terminal | On the phone, **the terminal cannot be scrolled up** (to see earlier output). | done 2026-11-25 (`web: touch drags scroll full-screen programs`), confirmed on the owner's phone |

## Details

### 1. Enter first in the key bar

- Today the main row is Esc, Tab, ^C, Ctrl, Alt, Shift, **Enter**, ↑, ↓, ←, →; Enter is seventh.
- Where: `ROW_MAIN` in `src/bridge/web/keys.js`. The expanded layout in `index.html`/CSS (modifiers beside
  the arrow pad, Shift and Enter 49 px wide) may need to follow the new order.
- Check at phone width, collapsed (one scrolling line, so Enter must be visible without scrolling) and
  expanded.
- Done 2026-11-25: Enter is first in `ROW_MAIN` (collapsed bar: Enter, Esc, Tab, ^C, Ctrl, Alt, Shift, arrows).
  Expanded, Enter starts the bar's bottom row (Enter, Shift, Home, End, Paste; above it Esc, Tab, ^C, Ctrl,
  Alt) by a grid placement in `app.css`. Checked in Chrome at phone width on laptop-mac (Rex preview.23)
  against a throwaway `rweb-test-keys` session: both layouts, collapse restores the order, and the Enter
  button ran a typed `echo`. `zig build test` 139 pass + 9 skip (no live), `web-test` 14 pass. Not yet
  on the phone; reaches the hosts with the next setup-repo pin bump.

### 2. No scrolling up on the phone

- Reported as: on the phone, touch does not scroll the terminal back through earlier output.
- Background to check first: history on open is the last ~1,000 lines (Phase 2 decision); the Copy view
  exists for selecting text; touch selection and scrolling were findings 12 and 13 of the Phase 0 phone
  run. Look at how touch drags are handled by the wterm default and by the xterm.js fallback, and whether
  the alternate screen (vim, less) is involved or only the shell's scrollback.
- Owner's detail (2026-11-23): on **wterm** (the default engine), at a **shell prompt**, wanting to look
  at previous output. So it is the shell's scrollback, not the alternate screen. Not yet reproduced here;
  the xterm.js fallback is untested for this.
- Investigated 2026-11-25 on laptop-mac (Rex preview.23), throwaway `rweb-test-keys` with 300 lines of
  output; **not reproduced**:
  - wterm scrolls its own element (`#term`, `overflow-y: auto`, `touch-action: auto` up the chain); it has
    no touch handlers that block scrolling, and on touch screens its input box is one cell.
  - History survives the phone's resize path: with "Fit Rex to this screen" on and the window shrunk as a
    keyboard would, Rex went to 59x12 and the browser kept its scrollback (redraws carry up to 1,000 lines).
  - Desktop wheel scrolling works, and the position holds while the cursor blinks and `info` polls.
  - A separate headless Chrome (loopback debugging port) emulating a phone (touch, `pointer: coarse`):
    a real touch drag scrolled the terminal back, both with the keyboard closed and after a tap that
    focused wterm's input box with the viewport shrunk to keyboard height.
  - Related finding: when the screen shrinks and the page does not get Rex's size (another client owns
    it), the view stays where it was, so the prompt can end up below the visible area until output arrives.
  - Not covered by emulation: real Android Chrome and Gboard, the deployed build, a terminal whose size
    the desktop Rex app owns. Next step needs the owner's phone.
- 2026-11-25: touch diagnostics added for the live test (`web/diag.js`, ⋯ menu "Touch diagnostics", off by
  default, `rweb.diag`): passive listeners only, a panel that ignores the pointer, showing the touched
  element and its parents, whether touchstart/touchmove were cancelled, `pointercancel` (the browser took
  the gesture), scroll events on the terminal and the page, and the terminal's scroll numbers. Checked in
  the emulated phone: a working drag shows `pointercancel 1` and terminal scroll events.
- **Cause found 2026-11-25 in the live phone test** (owner's Android Chrome 158 through a temporary Serve
  port 11443 on laptop-mac): scrolling works over a shell's history (panel: `pointercancel 1`, terminal
  scroll events). It fails over a **full-screen program on the alternate screen** (the owner's terminal
  running Claude Code): `sh 555 ch 555 max 0`, `oy hidden`, 88 touch moves, none cancelled, nothing to
  scroll. A full-screen program keeps its own history; a desktop terminal sends it the mouse wheel, a
  touch drag sent nothing.
- **Fix:** `wterm-shim.js` turns a vertical drag (after 8 px, so taps still work) into what a wheel would
  send when the terminal has nothing of its own to scroll: wheel reports through wterm's own mouse
  encoding if the program asked for the mouse, otherwise Up/Down keys in the program's cursor-key mode
  (`dragMode`, `dragRows`, `scrollKeys` in `keys.js`, with tests). Over the shell's history nothing
  changes. Verified in an emulated phone (headless Chrome, touch) against Rex's own capture and a
  recording program: `less` 470 → 446 by Up keys; a program with SGR mouse reporting received 24
  `ESC[<64;…M` wheel-up reports and no keys; shell history still scrolls natively. `zig build test` 139
  pass + 9 skip, `web-test` 17 pass. The xterm.js fallback is unchanged.
- **Confirmed 2026-11-25 on the owner's phone** (same Serve test port, fixed build): dragging over the
  terminal running Claude Code scrolls its view. Test setup removed: Serve 11443 off, test bridge stopped,
  its secret deleted, `rweb-test-touch` killed. Not yet deployed (setup-repo pin bump).
