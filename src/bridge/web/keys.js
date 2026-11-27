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
  // Enter comes first so it shows without scrolling the one-line bar (feedback 1).
  const ROW_MAIN = [
    {label: 'Enter', key: 'enter'},
    {label: 'Esc', key: 'escape'},
    {label: 'Tab', key: 'tab'},
    {label: '^C', key: 'key_c', mods: {ctrl: true}, title: 'Ctrl+C'},
    {label: 'Ctrl', latch: 'ctrl'},
    {label: 'Alt', latch: 'alt'},
    {label: 'Shift', latch: 'shift'},
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

  // What a terminal writes back to answer a program's question (cursor position, device
  // attributes, mode reports, title and colour reports, ...). Rex's own terminal has already
  // answered the program; one answered here and typed into the shell would let program output
  // type text. Keys, text, pastes, mouse and focus reports are not replies and pass.
  const REPLIES = [
    /\x1b\[[?>=]?[0-9;:]*[$ ]?[cn]/g,           // device attributes, device status (0n, ?..n, ...)
    /\x1b\[[0-9]+;[0-9]+R/g,                   // cursor position report
    /\x1b\[\??[0-9;:]*\$y/g,                    // mode report
    /\x1b\[\?[0-9;]*u/g,                       // keyboard protocol flags report
    /\x1b\[[0-9;]*[ ]?[xt]/g,                  // terminal parameters, window size reports
    /\x1bP[^\x1b\x07]*(?:\x1b\\|\x07|\x9c)/g,   // DCS replies (XTVERSION, DECRQSS, XTGETTCAP)
    /\x1b\][^\x1b\x07]*(?:\x1b\\|\x07|\x9c)/g,  // OSC replies (colours, title, clipboard)
  ];
  function stripReplies(text) {
    let out = String(text);
    for (const re of REPLIES) out = out.replace(re, '');
    return out;
  }

  // A vertical touch drag over the terminal (feedback 2). The browser scrolls the terminal's own
  // history by itself. A full-screen program (alternate screen) has no history in the browser and
  // scrolls its own, so a drag there is turned into what a desktop mouse wheel would send: wheel
  // reports if the program asked for the mouse, otherwise Up/Down keys (the "alternate scroll"
  // most terminals do). Returns 'native', 'wheel' or 'keys'.
  function dragMode({altScreen, mouseTracking, scrollable}) {
    if (altScreen) return mouseTracking ? 'wheel' : 'keys';
    if (!scrollable && mouseTracking) return 'wheel';
    return 'native';
  }
  // Whole rows a drag of `dy` pixels has moved (positive: the finger went down, towards older
  // output), and the pixels left over for the next move.
  function dragRows(dy, rowHeight) {
    const h = rowHeight > 0 ? rowHeight : 17;
    const rows = Math.trunc(dy / h);
    return {rows, rest: dy - rows * h};
  }
  // The keys for `rows` rows of scrolling: Up for older output, Down for newer, in the cursor-key
  // form the program asked for (application mode sends ESC O A).
  function scrollKeys(rows, appCursor) {
    const one = (appCursor ? '\x1bO' : '\x1b[') + (rows > 0 ? 'A' : 'B');
    return one.repeat(Math.min(Math.abs(rows), 100));
  }

  // Pasted text, made safe to hand to Rex as a paste. ESC and the C1 controls (U+0080 to U+009F,
  // among them the one-character CSI, U+009B) are removed: with them a pasted text could carry its
  // own "end of paste" (ESC [ 201 ~) and have the rest typed as commands ("pastejacking"), or send
  // any other control sequence the shell would act on. Nothing a person means to paste needs them.
  function cleanPaste(text) {
    return String(text).replace(/[\x1b\x80-\x9f]/g, '');
  }
  // `beforeinput` and `input` types that put text in from outside: a paste, a drop, a yank (Ctrl+Y
  // in a macOS text field) or a replacement the browser or keyboard chose (spelling suggestions).
  const PASTE_INPUTS = ['insertFromPaste', 'insertFromPasteAsQuotation', 'insertFromDrop', 'insertFromYank', 'insertReplacementText'];
  function isPasteInput(inputType) { return PASTE_INPUTS.includes(inputType); }

  // Text a keyboard commits in one go (a composition, a word, a phone keyboard's clipboard chip) is
  // typed only when it looks like typing: a short word with no line end, ESC or C1 control. Anything
  // else goes the paste way (cleaned, bracketed when the program asked, confirmed when it has lines),
  // so a clipboard chip cannot type commands. A lone ESC or C1 cannot come from a keyboard: it goes the
  // paste way too, where it is dropped. A lone line end is Enter and stays typed.
  const COMMIT_TYPE_MAX = 16;
  function commitIsPaste(text) {
    const s = String(text), n = Array.from(s).length;
    if (n === 0) return false;
    if (n > COMMIT_TYPE_MAX) return true;
    if (/[\x1b\x80-\x9f]/.test(s)) return true;
    return n > 1 && /[\r\n]/.test(s);
  }

  // Bytes of `text` in UTF-8 (a lone surrogate counts as U+FFFD, as a browser sends it).
  function utf8Length(text) {
    let n = 0;
    for (const ch of String(text)) {
      const c = ch.codePointAt(0);
      n += c < 0x80 ? 1 : c < 0x800 ? 2 : c < 0x10000 ? 3 : 4;
    }
    return n;
  }
  // The bridge takes at most PASTE_MAX_BYTES of text in one paste, in a message of at most
  // MESSAGE_MAX_BYTES; a larger message would close the connection. Returns the notice to show
  // instead of sending, or null when the paste fits. When `target` ({session, block}) is given,
  // its exact JSON-encoded size is checked (JSON escaping can expand characters up to 6x).
  const PASTE_MAX_BYTES = 32 * 1024, MESSAGE_MAX_BYTES = 64 * 1024, ID_MAX_BYTES = 200;
  function pasteRefusal(d, target) {
    const bytes = utf8Length(d);
    if (bytes > PASTE_MAX_BYTES) return `Too long to paste: ${Math.ceil(bytes / 1024)} KB; the limit is ${PASTE_MAX_BYTES / 1024} KB`;
    const session = target ? String(target.session) : 'x'.repeat(ID_MAX_BYTES);
    const block = target ? String(target.block) : 'x'.repeat(ID_MAX_BYTES);
    if (utf8Length(JSON.stringify({t: 'paste', d: String(d), force: true, session, block})) > MESSAGE_MAX_BYTES)
      return `Too long to paste: its control characters make it more than ${MESSAGE_MAX_BYTES / 1024} KB to send`;
    return null;
  }

  // What the "paste several lines?" question shows: the first `max` characters, how many lines the
  // whole text has, and whether it was cut.
  const PREVIEW_MAX_CHARS = 2000;
  function pastePreview(text, max) {
    const s = String(text), chars = Array.from(s), limit = max === undefined ? PREVIEW_MAX_CHARS : max;
    const cut = chars.length > limit;
    const parts = s.split(/\r\n|\r|\n/);                  // a line end at the very end starts no new line
    return {shown: cut ? chars.slice(0, limit).join('') : s, lines: parts.length - (parts.length > 1 && parts[parts.length - 1] === '' ? 1 : 0), chars: chars.length, cut};
  }

  // Text a program put on the terminal's clipboard, made safe to show and copy: no C0 controls but
  // tab and line feed, no DEL, ESC or C1 controls. A program chose this text; it must not carry
  // anything that would act when pasted somewhere else.
  function cleanClip(text) {
    return String(text).replace(/[\x00-\x08\x0b-\x1f\x7f-\x9f]/g, '');
  }

  // The Copy view shows at most COPY_MAX_LINES rows (one element each), the last ones. Returns the
  // lines to show, how many there were, and the note to show above them ('' when nothing is left
  // out). `truncated`: the bridge already sent only the end of a longer history.
  const COPY_MAX_LINES = 5000;
  function groupDigits(n) { return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ','); }
  function copyView(text, truncated, max) {
    const all = String(text).split('\n'), limit = max === undefined ? COPY_MAX_LINES : max;
    const lines = all.length > limit ? all.slice(all.length - limit) : all;
    const cut = lines.length < all.length;
    let note = '';
    if (truncated) note = `The history is longer than the bridge sends: showing its last ${groupDigits(lines.length)} lines.`;
    else if (cut) note = `Showing the last ${groupDigits(lines.length)} of ${groupDigits(all.length)} lines.`;
    return {lines, total: all.length, cut, note};
  }

  // Which terminal draws the page. `?term=wterm` or `?term=xterm` in the address chooses for that
  // page load only; the choice saved on this device (by the menu's switch) is used otherwise. A link
  // someone sends must not change what this device uses from then on.
  function pickTerm(param, saved) {
    if (param === 'wterm' || param === 'xterm') return param;
    return saved === 'xterm' ? 'xterm' : 'wterm';
  }
  // Input diagnostics (`?dbg=1`) send every key event to the bridge's log. They run only when the
  // bridge says it was started to receive them (`debug: true` in its `mode` message), so a link with
  // `?dbg=1` alone does nothing.
  function debugOn(asked, mode) { return !!asked && !!mode && mode.debug === true; }

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

  // ---- which terminal a message is about ----
  // Terminals are named by `session` and `block` (compared as strings: ids may come as numbers).
  function sameTerm(a, b) { return !!a && !!b && String(a.session) === String(b.session) && String(a.block) === String(b.block); }
  // Something the person asks for can wait before it is sent: for the clipboard, for an answer to a
  // question. (Uploads wait too, for their turn; they follow their terminal, not the view: see
  // `partitionUploads`.) It was asked of the terminal on screen then, so it is held with
  // that view (`holdView`): the terminal and `gen`, a count the page raises each time it shows another
  // terminal or none. When the wait is over it is sent only if that view is still the one on screen
  // (`stillView`); a switch away and back is another view, and what was asked before it is not sent.
  // The message names the terminal too (`session`, `block`), and the bridge refuses one that is not
  // for the terminal it has open for this page.
  // The header logo keeps turning, at the end of each turn, only if terminal output came within this
  // long: a burst of output gives a turn or two, a busy program keeps it going, and it rests upright.
  const LOGO_IDLE_MS = 1200;
  function keepTurning(now, lastOutputAt) { return now - lastOutputAt < LOGO_IDLE_MS; }

  function holdView(current, gen) { return current ? {session: current.session, block: current.block, gen} : null; }
  function stillView(held, current, gen) { return !!held && held.gen === gen && sameTerm(held, current); }
  // Whether a message that names a terminal (an `open` refusal, `closed`) is about `current`, the
  // terminal the page shows. A late one for a terminal the page has left since must not clear the one
  // it shows now (H3). A field the message leaves out is not compared; a message that names no
  // terminal at all (an older bridge) is taken as about the current one, as before.
  function aboutTerm(m, current) {
    const has = v => v !== undefined && v !== null;
    if (!m || (!has(m.session) && !has(m.block))) return true;
    if (!current) return false;
    if (has(m.session) && String(m.session) !== String(current.session)) return false;
    if (has(m.block) && String(m.block) !== String(current.block)) return false;
    return true;
  }
  // What the page does with a refused `open` (H3, H4): 'ignore' it (it is about another terminal),
  // 'retry' it (the terminal is being restored after a (re)connect and the refusal may pass: Rex not
  // answering, a snapshot late, or the rate), or 'clear' the view (the terminal is not there, or the
  // person chose it just now and should see why at once).
  function openRefusal(m, current, restoring) {
    if (!aboutTerm(m, current)) return 'ignore';
    if (restoring && current && m && (m.transient === true || m.rate === true)) return 'retry';
    return 'clear';
  }
  // Wait before retry number `attempt` (0, 1, ...): 1 s, 2 s, 4 s, 8 s, then 10 s each.
  const OPEN_RETRY_MAX_MS = 10000;
  function openRetryDelay(attempt) {
    const n = Math.max(0, Math.floor(Number(attempt) || 0));
    return Math.min(OPEN_RETRY_MAX_MS, 1000 * 2 ** Math.min(n, 4));
  }
  // Queued uploads each name the terminal (`term`) that was shown when the files were chosen (H6).
  // Before the next one is sent, those for another terminal are dropped, not sent to this one.
  function partitionUploads(queue, current) {
    const keep = [], drop = [];
    for (const u of queue || []) (u && sameTerm(u.term, current) ? keep : drop).push(u);
    return {keep, drop};
  }

  // ---- the connection (E4, M2) ----
  // In token mode (the bridge's `mode` message says `auth: "token"`: an SSH tunnel to a loopback
  // port), whatever answers on this origin after a drop may not be rweb: another account can hold
  // the port while the tunnel or rweb is down, and every connection hands it the page's cookie. So
  // each request (loading the page, a tap on Reconnect) makes exactly one connection attempt; when
  // that attempt fails, closes before it opens, or drops later, the page waits for the next tap. No
  // timer ever reconnects in token mode. In Tailscale mode the page reconnects by itself, with backoff.
  //
  // `linkStep(s, ev, tokenMode)` is the whole decision. `s` is {phase, why}: phase 'trying' (a
  // connection is being made), 'open' (it opened) or 'waiting' (for a tap; `why` says why: 'dropped',
  // 'failed' or 'foreign'). Events: 'ask' (the page loads, or a tap), 'open' (the socket opened),
  // 'close' (it closed, or the watchdog gave up on it), 'foreign' (its first message was not rweb's;
  // see `looksLikeRweb`). Returns the new {phase, why} and `act`: 'connect' (one attempt now),
  // 'retry' (reconnect after the backoff: Tailscale mode only) or 'none'.
  const LINK_START = Object.freeze({phase: 'trying', why: null});
  function linkStep(s, ev, tokenMode) {
    const cur = s || LINK_START, token = tokenMode === true;
    switch (ev) {
      case 'ask': return {phase: 'trying', why: null, act: 'connect'};
      case 'open': return cur.phase === 'trying' ? {phase: 'open', why: null, act: 'none'} : {...cur, act: 'none'};
      case 'close':
        if (cur.phase === 'waiting') return {...cur, act: 'none'};       // a late close: still waiting
        if (!token) return {phase: 'trying', why: null, act: 'retry'};
        return {phase: 'waiting', why: cur.phase === 'open' ? 'dropped' : 'failed', act: 'none'};
      case 'foreign':
        if (!token) return {...cur, act: 'none'};
        return {phase: 'waiting', why: 'foreign', act: 'none'};
    }
    return {...cur, act: 'none'};
  }
  // What the banner says while the page waits for a tap.
  function waitText(why) {
    if (why === 'failed') return 'Could not connect. Is the SSH tunnel running?';
    if (why === 'foreign') return 'This does not look like rweb. Check the SSH tunnel.';
    return 'Disconnected. Restart the SSH tunnel, then reconnect.';
  }
  // In token mode the first message on a new connection must be rweb's `mode` message, well formed,
  // saying `auth: "token"`; otherwise the page closes the connection and shows nothing it sent. This
  // only catches accidents (another program on the tunnel's port, a wrong port): whatever holds the
  // port can send this message too, and has had the cookie by then.
  const MODE_FLAGS = ['observe', 'locked', 'rex_up', 'download', 'upload', 'debug'];
  function looksLikeRweb(data) {
    if (typeof data !== 'string') return false;
    let m;
    try { m = JSON.parse(data); } catch { return false; }
    if (!m || typeof m !== 'object' || Array.isArray(m)) return false;
    if (m.t !== 'mode' || m.auth !== 'token') return false;
    return MODE_FLAGS.every(k => typeof m[k] === 'boolean');
  }
  // Token mode, once known, stays for the page's life: a later `mode` message without `auth` (from
  // whatever answered after a reconnect) does not turn automatic reconnects back on. It is known
  // before any connection from the page's own address: only token mode serves the page under
  // `/s/<id>/`, so a page that cannot reach rweb at all on load does not retry by itself either.
  function tokenModeFrom(wasTokenMode, mode) { return wasTokenMode === true || (!!mode && mode.auth === 'token'); }
  function tokenModeFromPath(pathname) { return /^\/s\/[A-Za-z0-9_-]+\//.test(String(pathname || '')); }

  const api = {linkStep, LINK_START, waitText, looksLikeRweb, tokenModeFrom, tokenModeFromPath, sameTerm, keepTurning, LOGO_IDLE_MS, holdView, stillView, aboutTerm, openRefusal, openRetryDelay, OPEN_RETRY_MAX_MS, partitionUploads, snake, modsString, keyObject, ctrlText, applyLatched, editsBetween, editBytes, lastLines, tapLine, selectedRange, selectedText, ROW_MAIN, ROW_MORE, clampFont, fitScale, stripReplies, dragMode, dragRows, scrollKeys, cleanPaste, isPasteInput, commitIsPaste, COMMIT_TYPE_MAX, utf8Length, pasteRefusal, PASTE_MAX_BYTES, MESSAGE_MAX_BYTES, pastePreview, PREVIEW_MAX_CHARS, cleanClip, copyView, COPY_MAX_LINES, pickTerm, debugOn, FONT_MIN, FONT_MAX, FONT_DEFAULT};
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.RwebKeys = api;
})(typeof window !== 'undefined' ? window : globalThis);
