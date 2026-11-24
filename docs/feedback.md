# Feedback from daily use

The owner's running list of things found while using rweb every day (from 2026-11-23, Phase 3's
week of use). Newest last. Each item gets a number, a date, a status (`open`, `done <commit>`,
`declined <why>`) and where in the code it lives. Do not renumber.

| # | Date | Area | Feedback | Status |
| --- | --- | --- | --- | --- |
| 1 | 2026-11-23 | Key bar | In the bottom pane's bottom row (the key bar), **Enter should be the first button**. | open |
| 2 | 2026-11-23 | Phone, terminal | On the phone, **the terminal cannot be scrolled up** (to see earlier output). | open |

## Details

### 1. Enter first in the key bar

- Today the main row is Esc, Tab, ^C, Ctrl, Alt, Shift, **Enter**, ↑, ↓, ←, →; Enter is seventh.
- Where: `ROW_MAIN` in `src/bridge/web/keys.js`. The expanded layout in `index.html`/CSS (modifiers beside
  the arrow pad, Shift and Enter 49 px wide) may need to follow the new order.
- Check at phone width, collapsed (one scrolling line, so Enter must be visible without scrolling) and
  expanded.

### 2. No scrolling up on the phone

- Reported as: on the phone, touch does not scroll the terminal back through earlier output.
- Background to check first: history on open is the last ~1,000 lines (Phase 2 decision); the Copy view
  exists for selecting text; touch selection and scrolling were findings 12 and 13 of the Phase 0 phone
  run. Look at how touch drags are handled by the wterm default and by the xterm.js fallback, and whether
  the alternate screen (vim, less) is involved or only the shell's scrollback.
- Owner's detail (2026-11-23): on **wterm** (the default engine), at a **shell prompt**, wanting to look
  at previous output. So it is the shell's scrollback, not the alternate screen. Not yet reproduced here;
  the xterm.js fallback is untested for this.
