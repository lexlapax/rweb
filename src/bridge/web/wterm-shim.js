'use strict';
// Makes wterm (DOM text rows, native selection, libghostty core) look like the small part of
// xterm.js's API that app.js uses, so the page can run on either terminal.
//
// Differences from xterm.js that matter here:
// - wterm answers terminal queries itself ("host responses") and hands the replies to onData as
//   if typed. Rex's own terminal already answered the program, so every reply is dropped.
// - Soft-keyboard text, composition and Backspace on touch screens are wterm's own business
//   (it keeps a placeholder in its input box so Backspace works). Only physical keys are taken
//   over by the page, to be sent to Rex as key events.
window.makeWtermTerminal = async function (host, {fontSize}) {
  const {WTerm, GhosttyCore} = window.RwebWterm;
  const core = await GhosttyCore.load({wasmPath: '/vendor/ghostty-vt.wasm'});
  // No auto-sizing: the grid is Rex's, and changes only when Rex says so.
  const handlers = {data: () => {}};
  const wt = new WTerm(host, {core, cols: 80, rows: 24, autoResize: false, cursorBlink: true, scrollbackLines: 10000, onData: d => handlers.data(d), onBinary: () => {}});
  await wt.init();
  // Drop wterm's replies to terminal queries (see above), draining them so they cannot pile up.
  if (wt.bridge && typeof wt.bridge.getResponse === 'function') {
    const orig = wt.bridge.getResponse.bind(wt.bridge);
    wt.bridge.getResponse = () => { while (orig() !== null) {} return null; };
  }
  host.classList.add('rweb-wterm');

  // The font size the grid is drawn at now. The page asks for a preferred size; when the grid would
  // be wider than the screen the size is reduced to fit. wterm measures cells and places its typing
  // overlay from on-screen coordinates, so shrinking with a CSS scale would put text in the wrong
  // place: the font itself is made smaller instead.
  let applied = fontSize;
  const setFont = px => { applied = px; host.style.setProperty('--term-font-size', px + 'px'); host.style.setProperty('--term-row-height', Math.round(px * 1.2) + 'px'); try { wt._measureCharSize && wt._measureCharSize(); } catch {} };
  setFont(fontSize);
  const cell = () => { try { return wt._measureCharSize(); } catch { return null; } };

  const theme = {base: null, cur: null};
  const term = {
    kind: 'wterm', wt,
    element: host,
    get textarea() { return wt.input && wt.input.textarea; },
    get cols() { return wt.cols; }, get rows() { return wt.rows; },
    write(data) { wt.write(data); },
    reset() { wt.write('\x1bc'); },
    resize(c, r) { wt.resize(c, r); },
    focus() { wt.focus(); },
    blur() { const t = term.textarea; if (t) t.blur(); },
    onData(cb) { handlers.data = cb; },
    onBinary() {},
    hasSelection() { try { return (window.getSelection().toString() || '').length > 0 && host.contains(window.getSelection().anchorNode); } catch { return false; } },
    // xterm.js lets the page see a key first and say "not yours" by returning false. Same here:
    // a capture listener on the terminal element runs before wterm's own handler on its input box.
    attachCustomKeyEventHandler(fn) {
      for (const type of ['keydown', 'keyup']) host.addEventListener(type, e => { if (fn(e) === false) { e.stopImmediatePropagation(); e.stopPropagation(); } }, true);
    },
    options: {
      set fontSize(px) { setFont(px); },
      get fontSize() { return applied; },
      // Rex sends colours as "RRGGBB" or "#RRGGBB" and a palette as "index=RRGGBB" for the entries it
      // changed. wterm wants 24-bit numbers and all 16 palette entries, so fill in what Rex left out.
      set theme(t) {
        const num = v => { const m = /^#?([0-9a-fA-F]{6})$/.exec(String(v || '')); return m ? parseInt(m[1], 16) : null; };
        if (!theme.base) {
          const css = name => num(getComputedStyle(host).getPropertyValue(name).trim());
          theme.base = {foreground: css('--term-fg') ?? 0xd4d4d4, background: css('--term-bg') ?? 0x1e1e1e, cursor: css('--term-cursor') ?? 0xaeafad,
            palette: Array.from({length: 16}, (_, i) => css('--term-color-' + i) ?? 0)};
          theme.cur = {...theme.base, palette: theme.base.palette.slice()};
        }
        const c = theme.cur;
        if (num(t.foreground) !== null) c.foreground = num(t.foreground);
        if (num(t.background) !== null) c.background = num(t.background);
        if (num(t.cursor) !== null) c.cursor = num(t.cursor);
        for (const entry of t.palette || []) {
          const m = /^(\d+)=([0-9a-fA-F]{6})$/.exec(entry);
          if (m && Number(m[1]) < 16) c.palette[Number(m[1])] = parseInt(m[2], 16);
        }
        try { wt.setThemeColors({foreground: c.foreground, background: c.background, cursor: c.cursor, palette: c.palette.slice()}); }
        catch (e) { console.warn('theme', e); }
      },
    },
    parser: {registerCsiHandler() {}, registerDcsHandler() {}, registerOscHandler() {}},
    loadAddon() {},
    // The grid that fits `width` x `height` pixels, for "fit terminal to this window".
    proposeDimensions(width, height) {
      const m = cell(); if (!m || !m.charWidth || !m.rowHeight) return null;
      return {cols: Math.max(2, Math.floor(width / m.charWidth)), rows: Math.max(1, Math.floor(height / m.rowHeight))};
    },
    // Draw at `preferred` px, or smaller so that all columns fit in `stageWidth` pixels (never below
    // 5 px). Returns the size used.
    fitFont(preferred, stageWidth, stageHeight) {
      const m = cell();
      const ratio = m && m.charWidth && applied ? m.charWidth / applied : 0.6;   // glyph width per px of font
      let px = Math.min(preferred, stageWidth / (ratio * wt.cols), stageHeight ? Math.floor(stageHeight / wt.rows) / 1.2 : Infinity);   // whole-pixel rows, which setFont rounds up
      px = Math.max(5, Math.floor(px * 10) / 10);
      if (stageHeight) while (px > 5 && Math.round(px * 1.2) * wt.rows > stageHeight) px = Math.round((px - 0.1) * 10) / 10;
      if (Math.abs(px - applied) > 0.05) setFont(px);
      return px;
    },
    // Width in pixels of the whole grid, for shrink-to-fit.
    screenWidth() { const m = cell(); return m && m.charWidth ? Math.ceil(m.charWidth * wt.cols) : host.scrollWidth; },
    // Text of the visible rows, for tests.
    screenRows() { return [...host.querySelectorAll('.term-row:not(.term-scrollback-row)')].map(r => r.textContent.replace(/ /g, ' ').replace(/\s+$/, '')); },
    selectionText() { try { return wt.getSelectionText(); } catch { return ''; } },
  };
  return term;
};
