'use strict';
// Pure key logic for the page: no DOM, so it is tested with `node --test tests/web`.
// Loaded as a plain script (exports RwebKeys on `window`) and as a CommonJS module in tests.
(function (root) {
  // Rex names physical keys after W3C codes in snake_case: "KeyA" -> "key_a", "Digit1" -> "digit_1".
  function snake(code) {
    return String(code).replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Za-z])([0-9])/g, '$1_$2').toLowerCase();
  }

  // Rex wants modifiers joined with "+" in this order.
  function modsString(m) {
    return [m.shift && 'shift', m.ctrl && 'ctrl', m.alt && 'alt', m.super && 'super'].filter(Boolean).join('+');
  }

  // The `key` object of Rex's `client.key`.
  function keyObject(key, mods, action, text) {
    const t = text || '';
    return {
      key, mods: modsString(mods || {}), consumed_mods: (t && mods && mods.shift) ? 'shift' : '', text: t,
      unshifted_codepoint: t ? t.toLowerCase().codePointAt(0) : 0, composing: false, action: action || 'press',
    };
  }

  // Text typed on a soft keyboard with Ctrl latched: Ctrl+A..Z -> 0x01..0x1a, and the usual few more.
  function ctrlText(ch) {
    if (ch.length !== 1) return null;
    const c = ch.toUpperCase().charCodeAt(0);
    if (c >= 65 && c <= 90) return String.fromCharCode(c - 64);
    if (ch === ' ' || ch === '@') return '\x00';
    if (ch === '[') return '\x1b';
    if (ch === '\\') return '\x1c';
    if (ch === ']') return '\x1d';
    if (ch === '^') return '\x1e';
    if (ch === '_') return '\x1f';
    if (ch === '?') return '\x7f';
    return null;
  }

  // Apply latched modifiers to soft-keyboard text. Returns the bytes to send. Anything that is not
  // a single character (a pasted word, a composition) goes through unchanged: a latched Ctrl is
  // for the next key press, not for a sentence.
  function applyLatched(latched, text) {
    if (!latched || text.length !== 1 && !(text.codePointAt(0) > 0xffff && text.length === 2)) return {text, used: false};
    let out = text, used = false;
    if (latched.shift && /[a-z]/.test(out)) { out = out.toUpperCase(); used = true; }
    if (latched.ctrl) { const c = ctrlText(out); if (c !== null) { out = c; used = true; } }
    if (latched.alt) { out = '\x1b' + out; used = true; }
    return {text: out, used};
  }

  // The bottom key row. `latch` keys toggle a modifier; `key` keys send a physical key; `text` keys
  // send text; `repeat` keys repeat while held.
  const ROW_MAIN = [
    {label: 'Esc', key: 'escape'},
    {label: 'Tab', key: 'tab'},
    {label: '^C', key: 'key_c', mods: {ctrl: true}, title: 'Ctrl+C'},
    {label: 'Ctrl', latch: 'ctrl'},
    {label: 'Alt', latch: 'alt'},
    {label: 'Shift', latch: 'shift'},
    {label: 'Enter', key: 'enter'},
    {label: '↑', key: 'arrow_up', repeat: true, title: 'Up'},
    {label: '↓', key: 'arrow_down', repeat: true, title: 'Down'},
    {label: '←', key: 'arrow_left', repeat: true, title: 'Left'},
    {label: '→', key: 'arrow_right', repeat: true, title: 'Right'},
  ];
  const ROW_MORE = [
    {label: 'Home', key: 'home'},
    {label: 'End', key: 'end'},
    {label: 'PgUp', key: 'page_up', repeat: true},
    {label: 'PgDn', key: 'page_down', repeat: true},
    {label: '|', text: '|', key: 'backslash', mods: {shift: true}},
    {label: '~', text: '~', key: 'backquote', mods: {shift: true}},
    {label: '/', text: '/', key: 'slash'},
    {label: '\\', text: '\\', key: 'backslash'},
    {label: '-', text: '-', key: 'minus'},
    {label: '`', text: '`', key: 'backquote'},
  ];

  // The soft keyboard edits a hidden text box that holds what has been typed since the last Enter.
  // Instead of waiting for a word to be committed, the page mirrors every change to the shell:
  // keep the common start, delete what went, type what came. Backspace is DEL (0x7f), as xterm
  // sends it. Works on code points, so an emoji is one deletion.
  function editsBetween(prev, next) {
    const a = Array.from(prev), b = Array.from(next);
    let p = 0;
    while (p < a.length && p < b.length && a[p] === b[p]) p++;
    return {deletes: a.length - p, inserts: b.slice(p).join('')};
  }
  function editBytes(prev, next) {
    const e = editsBetween(prev, next);
    return '\x7f'.repeat(e.deletes) + e.inserts;
  }

  // The last `n` lines of `text`, ignoring blank lines at the end.
  function lastLines(text, n) {
    const lines = String(text).replace(/\s+$/, '').split('\n');
    return lines.slice(Math.max(0, lines.length - n)).join('\n');
  }

  // Tap-to-select lines in the Copy view. `sel` is {anchor, end} (line numbers, or null). Tapping
  // with nothing selected starts at that line; tapping again extends to it (either direction);
  // tapping a third time starts over from the tapped line.
  function tapLine(sel, i) {
    if (!sel) return {anchor: i, end: i, open: true};          // `open`: the next tap extends
    if (sel.open) return {anchor: sel.anchor, end: i, open: false};
    return {anchor: i, end: i, open: true};
  }
  function selectedRange(sel) {
    if (!sel) return null;
    return {from: Math.min(sel.anchor, sel.end), to: Math.max(sel.anchor, sel.end)};
  }
  function selectedText(lines, sel) {
    const r = selectedRange(sel);
    if (!r) return '';
    return lines.slice(r.from, r.to + 1).join('\n');
  }

  const FONT_MIN = 8, FONT_MAX = 28, FONT_DEFAULT = 14;
  function clampFont(n) {
    n = Math.round(Number(n));
    if (!Number.isFinite(n)) return FONT_DEFAULT;
    return Math.min(FONT_MAX, Math.max(FONT_MIN, n));
  }

  // The scale that makes a terminal `screenWidth` px wide fit in `stageWidth`, never below `floor`
  // (below it the terminal scrolls sideways instead) and never above 1.
  function fitScale(stageWidth, screenWidth, floor) {
    if (!(screenWidth > 0) || !(stageWidth > 0)) return 1;
    return Math.max(floor === undefined ? 0.35 : floor, Math.min(1, stageWidth / screenWidth));
  }

  const api = {snake, modsString, keyObject, ctrlText, applyLatched, editsBetween, editBytes, lastLines, tapLine, selectedRange, selectedText, ROW_MAIN, ROW_MORE, clampFont, fitScale, FONT_MIN, FONT_MAX, FONT_DEFAULT};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.RwebKeys = api;
})(typeof window !== 'undefined' ? window : globalThis);
