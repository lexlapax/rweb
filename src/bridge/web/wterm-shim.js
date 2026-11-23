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
  const wt = new WTerm(host, {core, cols: 80, rows: 24, autoResize: false, cursorBlink: true, onData: d => handlers.data(d), onBinary: () => {}});
  await wt.init();
  // Drop wterm's replies to terminal queries (see above), draining them so they cannot pile up.
  if (wt.bridge && typeof wt.bridge.getResponse === 'function') {
    const orig = wt.bridge.getResponse.bind(wt.bridge);
    wt.bridge.getResponse = () => { while (orig() !== null) {} return null; };
  }
  host.classList.add('rweb-wterm');

  const setFont = px => { host.style.setProperty('--term-font-size', px + 'px'); try { wt._measureCharSize && wt._measureCharSize(); } catch {} };
  setFont(fontSize);
  const cell = () => { try { return wt._measureCharSize(); } catch { return null; } };

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
      set theme(t) {
        const c = {};
        if (t.foreground) c.foreground = t.foreground;
        if (t.background) c.background = t.background;
        if (t.cursor) c.cursor = t.cursor;
        try { wt.setThemeColors(Object.keys(c).length ? c : null); } catch (e) { console.warn('theme', e); }
      },
    },
    parser: {registerCsiHandler() {}, registerDcsHandler() {}, registerOscHandler() {}},
    loadAddon() {},
    // The grid that fits `width` x `height` pixels, for "fit terminal to this window".
    proposeDimensions(width, height) {
      const m = cell(); if (!m || !m.charWidth || !m.rowHeight) return null;
      return {cols: Math.max(2, Math.floor(width / m.charWidth)), rows: Math.max(1, Math.floor(height / m.rowHeight))};
    },
    // Width in pixels of the whole grid, for shrink-to-fit.
    screenWidth() { const m = cell(); return m && m.charWidth ? Math.ceil(m.charWidth * wt.cols) : host.scrollWidth; },
    // Text of the visible rows, for tests.
    screenRows() { return [...host.querySelectorAll('.term-row:not(.term-scrollback-row)')].map(r => r.textContent.replace(/ /g, ' ').replace(/\s+$/, '')); },
    selectionText() { try { return wt.getSelectionText(); } catch { return ''; } },
  };
  return term;
};
