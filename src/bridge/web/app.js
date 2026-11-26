'use strict';
// rweb page. No framework, no network access except this origin. Everything that comes from
// Rex (labels, ids, terminal text) is untrusted: it only ever reaches the page as textContent
// or as terminal input, never as HTML.

const $ = id => document.getElementById(id);
const K = window.RwebKeys;
const NARROW = matchMedia('(max-width: 900px)');
const LS = {
  get(k, d) { try { const v = localStorage.getItem('rweb.' + k); return v === null ? d : JSON.parse(v); } catch { return d; } },
  set(k, v) { try { localStorage.setItem('rweb.' + k, JSON.stringify(v)); } catch {} },
};
// Input diagnostics: asked for with ?dbg=1, and on only once the bridge's `mode` message says it
// was started to log them (see `setDebug`).
const dbgAsked = new URLSearchParams(location.search).get('dbg') === '1';
let dbgOn = false;

const state = {
  ws: null, retry: 500, observe: false, locked: false, rexUp: true,
  tree: [], current: null,               // {session, block}
  opened: false,                          // the bridge confirmed it shows `current` (see `ready`)
  cols: 80, rows: 24, historyRows: 0,
  soft: false,                            // a soft keyboard is in use
  latched: {ctrl: false, alt: false, shift: false},
  fontSize: K.clampFont(LS.get('fontSize', K.FONT_DEFAULT)),
  exited: null, tried: false,             // tried: the remembered terminal has been looked for
  restore: null,                          // {attempt, timer}: `current` is being restored (see `openRetry`)
};
const link = {lastRx: performance.now(), healthy: false};

// ---- the terminal ----
// Two terminals can draw the screen. xterm.js is the default. wterm (the one Ovis uses) draws
// ordinary text rows, so the phone's own long-press selection, handles and Copy work on it.
// The ⋯ menu's switch chooses, and the choice is remembered on this device; `?term=wterm` or
// `?term=xterm` chooses for that page load only (keys.js `pickTerm`).
async function main() {
// A test token in the address would stay in history and be sent on every request; the server has
// put it in a cookie by now, so the address bar and the socket use the cookie from here on.
if (new URLSearchParams(location.search).has('token')) {
  const q = new URLSearchParams(location.search); q.delete('token');
  history.replaceState(null, '', location.pathname + (q.toString() ? '?' + q : '') + location.hash);
}
const kind = K.pickTerm(new URLSearchParams(location.search).get('term'), LS.get('term', 'wterm'));
const loadScript = src => new Promise((ok, no) => { const s = document.createElement('script'); s.src = src; s.onload = ok; s.onerror = () => no(new Error('could not load ' + src)); document.head.append(s); });
let term = null, fitAddon = null, termKind = 'xterm', startupNote = null;
let wtermPaste = () => {};                // set to sendPaste once the page is ready
if (kind === 'wterm') {
  try {
    const l = document.createElement('link'); l.rel = 'stylesheet'; l.href = 'vendor/wterm.css'; document.head.append(l);
    await loadScript('vendor/wterm.js'); await loadScript('wterm-shim.js');
    term = await window.makeWtermTerminal($('term'), {fontSize: state.fontSize});
    // wterm sends every paste it sees (a paste event, or a paste arriving as an input event) through
    // its `sendPaste`, which would type it. The page takes those over (see "pastes" below); without
    // the hook, wterm is not used.
    const inp = term.wt && term.wt.input;
    if (!inp || typeof inp.sendPaste !== 'function') { try { term.wt.destroy(); } catch {} $('term').replaceChildren(); $('term').classList.remove('rweb-wterm'); throw new Error('wterm: cannot take over pastes on this build'); }
    inp.sendPaste = text => { try { if (inp.selectionActions) inp.selectionActions.clearSelection(); } catch {} wtermPaste(String(text)); };
    // wterm types text a keyboard commits (its `input` and `compositionend` handlers) straight through
    // onData, so a phone keyboard's clipboard chip or a long composition would be typed, line ends and
    // all. While either handler runs, what it commits is typed only if it looks like typing (keys.js
    // `commitIsPaste`); anything else, and any paste-type input, goes the paste way. Its handlers were
    // bound when it started, so the listeners are swapped for the wrapped ones (and `destroy` still
    // removes them). Without these hooks wterm is not used.
    const ta = inp.textarea;
    if (!ta || typeof inp.handleInput !== 'function' || typeof inp.handleCompositionEnd !== 'function' || typeof inp._onInput !== 'function' || typeof inp._onCompositionEnd !== 'function') {
      try { term.wt.destroy(); } catch {} $('term').replaceChildren(); $('term').classList.remove('rweb-wterm'); throw new Error('wterm: cannot take over committed text on this build');
    }
    const committing = orig => function (ev) {
      // A touch Backspace: wterm sends DEL (or the program's key encoding) through onData; not text.
      if (ev && ev.inputType === 'deleteContentBackward' && this.touchPrimary) return orig.call(this, ev);
      const typed = this.onData, asPaste = !!ev && K.isPasteInput(ev.inputType);
      this.onData = (d, ...rest) => {
        if (asPaste || K.commitIsPaste(d)) { try { if (this.selectionActions) this.selectionActions.clearSelection(); } catch {} wtermPaste(String(d)); }
        else typed.call(this, d, ...rest);
      };
      try { return orig.call(this, ev); } finally { this.onData = typed; }
    };
    ta.removeEventListener('input', inp._onInput); ta.removeEventListener('compositionend', inp._onCompositionEnd);
    inp.handleInput = committing(inp.handleInput); inp.handleCompositionEnd = committing(inp.handleCompositionEnd);
    inp._onInput = inp.handleInput.bind(inp); inp._onCompositionEnd = inp.handleCompositionEnd.bind(inp);
    ta.addEventListener('compositionend', inp._onCompositionEnd); ta.addEventListener('input', inp._onInput);
    fitAddon = {proposeDimensions: () => term.proposeDimensions($('stage').clientWidth, $('stage').clientHeight)};
    termKind = 'wterm';
    // The page behind the grid matches wterm's own background until Rex sends a theme.
    const own = getComputedStyle($('term')).getPropertyValue('--term-bg').trim();
    if (own) document.documentElement.style.setProperty('--term-bg', own);
  } catch (e) { console.warn('wterm did not start; using xterm.js', e); startupNote = 'wterm did not start: using the standard terminal'; term = null; }
}
if (!term) {
  term = new Terminal({
    cols: 80, rows: 24, scrollback: 10000, allowProposedApi: true,
    fontFamily: 'ui-monospace, Menlo, Consolas, monospace', fontSize: state.fontSize, cursorBlink: true,
  });
  fitAddon = new FitAddon.FitAddon();
  term.loadAddon(fitAddon);
  term.open($('term'));
  // Rex's own terminal answers programs' queries; this one must not, or the reply would be typed.
  for (const id of [{final:'c'},{prefix:'>',final:'c'},{prefix:'=',final:'c'},{final:'n'},{prefix:'?',final:'n'},
    {intermediates:'$',final:'p'},{prefix:'?',intermediates:'$',final:'p'},{prefix:'>',final:'q'},{final:'t'},{prefix:'?',final:'u'}])
    term.parser.registerCsiHandler(id, () => true);
  term.parser.registerDcsHandler({intermediates:'$', final:'q'}, () => true);
  for (const n of [4, 10, 11, 12]) term.parser.registerOscHandler(n, data => data.includes('?'));
}

function send(obj) { if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify(obj)); }
// `opened`: the bridge has said it shows state.current (an `opened` for it arrived). Until then the
// bridge may still be on the terminal shown before, so nothing is typed and its output is not drawn.
function ready() { return !!state.current && state.opened; }
// Typing does not wait for `opened`: the bridge handles one page's messages in order, so input sent after
// an `open` reaches that terminal, or nothing if the open was refused (a refused open also leaves the old
// terminal). Waiting would drop what is typed in the moment after a switch.
function canType() { return !!state.current && !state.observe && state.rexUp && link.healthy; }
// Why typing was refused, for the notice.
function whyNot() { return !link.healthy ? 'Not connected: not sent' : 'Typing is off'; }

function clearLatched() {
  state.latched = {ctrl: false, alt: false, shift: false};
  for (const b of document.querySelectorAll('#keys [data-latch]')) b.setAttribute('aria-pressed', 'false');
}

// Pastes, mouse reports and keys xterm.js encodes come through onData. On a touch device typed
// text does not (see the soft keyboard below).
term.onData(d => {
  d = K.stripReplies(d);                    // never type a terminal's answer to a program's question
  if (!d) return;
  if (!canType()) { if (state.current && !link.healthy) notice(whyNot()); return; }
  if (d === '\r') softReset();                       // a new line starts: forget what was typed
  const r = K.applyLatched(state.latched, d);
  if (r.used) clearLatched();
  send({t: 'in', d: r.text});
});
term.onBinary(d => { d = K.stripReplies(d); if (d && canType()) send({t: 'in', d}); });

// ---- pastes ----
// Every paste goes to Rex as a paste ({t: 'paste'}), never as typed input, and without ESC or C1
// controls (keys.js `cleanPaste`): a pasted text that carried its own "end of paste" would otherwise
// have the rest typed as commands. Neither terminal's own paste handling runs: these listeners sit on
// the terminal's container in the capture phase, so they see the events before anything inside it
// and stop them there. wterm's other way in (a paste arriving as an input event) comes here through
// the hook set up where wterm starts (`wtermPaste`).
// A paste over the bridge's limit is refused here with a notice: sent, it would close the connection.
// A paste with line ends into a program that has not turned on bracketed paste would run line by
// line: the bridge refuses it (`confirm_multiline`) and the page asks first (`askMultiline`). The text
// is kept for that question only until it is answered, the terminal changes, or a few seconds pass.
const multi = {pending: null, timer: 0};
function forgetPaste() { multi.pending = null; clearTimeout(multi.timer); }
function sendPaste(text) {
  const d = K.cleanPaste(text || '');
  if (!d) return;
  if (!canType()) { if (state.current) notice(whyNot()); return; }
  const tooLong = K.pasteRefusal(d);
  if (tooLong) { notice(tooLong); return; }
  if (soft.on) softReset();
  if (/[\r\n]/.test(d)) {
    forgetPaste();
    multi.pending = {d, session: state.current.session, block: state.current.block};
    multi.timer = setTimeout(forgetPaste, 15000);
  }
  send({t: 'paste', d});
}
wtermPaste = sendPaste;
async function askMultiline(msg) {
  const p = multi.pending, dlg = $('mldlg'); forgetPaste();
  if (!p || !sameTerm(p, state.current)) { notice(msg || 'Paste not sent'); return; }
  if (dlg.open) { notice('Paste not sent: answer the open question first'); return; }
  const v = K.pastePreview(p.d);
  const r = await dialogResult(dlg, done => {
    $('ml-msg').textContent = `This text has ${v.lines} line${v.lines === 1 ? '' : 's'}. The program in this terminal has not turned on bracketed paste, so each line may run as soon as it arrives.`;
    $('ml-text').textContent = v.shown;
    $('ml-text').scrollTop = 0;
    $('ml-note').textContent = v.cut ? `Showing the first ${K.PREVIEW_MAX_CHARS.toLocaleString('en')} of ${v.chars.toLocaleString('en')} characters.` : '';
    $('ml-note').hidden = !v.cut;
    $('ml-cancel').onclick = () => done(null);
    dlg.querySelector('form').onsubmit = e => { e.preventDefault(); done('yes'); };
    setTimeout(() => $('ml-cancel').focus(), 0);     // the safe choice has the focus
  });
  if (r !== 'yes') return;
  if (!canType() || !sameTerm(p, state.current)) { notice(state.current ? whyNot() : 'Paste not sent: the terminal changed'); return; }
  send({t: 'paste', d: p.d, force: true});
}
$('term').addEventListener('paste', e => {
  e.preventDefault(); e.stopPropagation();
  sendPaste(e.clipboardData ? e.clipboardData.getData('text/plain') : '');
}, true);
// A soft keyboard's paste (and a drop) can come as an input event with no paste event before it.
// A replacement (a spelling suggestion) is left to the input event that follows: it replaces text
// already in the box, which only the soft-keyboard mirror and wterm's handler (both hooked) can see.
$('term').addEventListener('beforeinput', e => {
  if (!K.isPasteInput(e.inputType) || e.inputType === 'insertReplacementText') return;
  const text = e.data || (e.dataTransfer && e.dataTransfer.getData('text/plain')) || '';
  if (!text) return;            // nothing to take here: the input event that follows is a paste too
  e.preventDefault(); e.stopPropagation();
  sendPaste(text);
}, true);

// ---- soft keyboard ----
// Phone keyboards compose words, hold them back until you press space, and on Backspace re-open
// the word they already committed. xterm.js's overlay then shows text the shell no longer has.
// So on a touch device the page takes over: the hidden text box holds what has been typed since
// the last Enter, and every change to it is mirrored to the shell at once (delete what went,
// type what came). The shell's own echo is then the only display, as with a desktop keyboard.
const soft = {on: termKind === 'xterm' && matchMedia('(pointer: coarse)').matches, prev: '', composing: false};
function softReset() { soft.prev = ''; if (term.textarea && term.textarea.value !== '') term.textarea.value = ''; }
function softSync(pasted) {
  const ta = term.textarea, now = ta.value;
  const e = K.editsBetween(soft.prev, now);
  soft.prev = now;
  if (!e.deletes && !e.inserts) return;
  if (!canType()) { if (state.current) notice(whyNot()); return; }
  // A paste the beforeinput listener could not take, or text the keyboard committed that does not
  // look like typing (keys.js `commitIsPaste`: lines, ESC or C1, or long): it goes the paste way.
  if (pasted || K.commitIsPaste(e.inserts)) {
    if (e.deletes) send({t: 'in', d: '\x7f'.repeat(e.deletes)});
    return sendPaste(e.inserts);
  }
  // A soft keyboard cannot type ESC or C1 controls; any in the box came from somewhere else.
  let ins = K.cleanPaste(e.inserts);
  if (!e.deletes) { const r = K.applyLatched(state.latched, ins); if (r.used) clearLatched(); ins = r.text; }
  send({t: 'in', d: '\x7f'.repeat(e.deletes) + ins});
  if (!soft.composing && Array.from(now).length > 100) softReset();   // keep the text box short
}
(function installSoft() {
  if (termKind !== 'xterm') return;           // wterm does its own soft-keyboard input
  // Capture phase on the terminal's outer element: it runs before anything on the text box, so
  // xterm.js's own handlers (registered on the box earlier than we could) never see these events.
  const root = term.element;
  const only = (fn) => e => { if (e.target === term.textarea && soft.on) { e.stopPropagation(); fn(e); } };
  root.addEventListener('compositionstart', only(() => { soft.composing = true; }), true);
  root.addEventListener('compositionupdate', only(() => {}), true);
  root.addEventListener('compositionend', only(() => { soft.composing = false; }), true);
  root.addEventListener('beforeinput', only(() => {}), true);
  root.addEventListener('input', only(e => softSync(K.isPasteInput(e.inputType))), true);
})();

// Physical keys go to Rex, which encodes them for the program's keyboard mode. Keys with no usable
// code (phone keyboards, input methods) are the soft keyboard's business.
term.attachCustomKeyEventHandler(e => {
  if (e.type !== 'keydown' && e.type !== 'keyup') return false;
  const softKey = e.isComposing || e.keyCode === 229 || e.key === 'Unidentified' || !e.code;
  if (softKey) { state.soft = true; if (!e.code && termKind === 'xterm') soft.on = true; }
  if (soft.on && e.type === 'keydown') {
    // Backspace: with text in the box the input event does the deleting; with none, xterm sends DEL.
    if (e.key === 'Backspace') return term.textarea.value.length === 0;
    if (e.key === 'Enter') return true;               // xterm sends the line end, and the box is cleared
    if (softKey) return false;                          // everything else is the input event's job
  }
  if (softKey) return true;
  if (state.soft && (e.key === 'Enter' || e.key === 'Backspace')) return true;
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'v') return true;      // paste
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && term.hasSelection()) return true; // copy
  if (!canType()) { if (e.type === 'keydown' && state.current && !link.healthy) notice(whyNot()); return false; }
  const mods = {shift: e.shiftKey, ctrl: e.ctrlKey, alt: e.altKey, super: e.metaKey};
  const text = (e.key.length === 1 && !e.ctrlKey && !e.metaKey) ? e.key : '';
  send({t: 'key', key: K.keyObject(K.snake(e.code), mods, e.type === 'keyup' ? 'release' : (e.repeat ? 'repeat' : 'press'), text)});
  e.preventDefault();
  return false;
});

// ---- layout: draw at Rex's size and shrink to fit; Rex's size changes only when asked ----
// Like Ovis: on a touch screen the text keeps the size chosen with +/- and Rex's terminal is resized to
// fit the screen (it changes for everyone viewing it). Elsewhere, and when switched off in the menu,
// Rex's size is kept and wterm shrinks its text to fit instead.
const COARSE = matchMedia('(pointer: coarse)');
function autoFitOn() { return LS.get('autofit', COARSE.matches) === true && termKind === 'wterm'; }
let fitTimer = 0, lastFit = '';
function scheduleFit() {
  clearTimeout(fitTimer);
  fitTimer = setTimeout(() => {
    if (!autoFitOn() || !ready() || state.observe || !state.rexUp || document.visibilityState !== 'visible') return;
    const stage = $('stage'); if (stage.hidden) return;
    const d = term.proposeDimensions(stage.clientWidth - 2, stage.clientHeight);
    if (!d || (d.cols === state.cols && d.rows === state.rows)) return;
    const key = d.cols + 'x' + d.rows; if (key === lastFit) return;     // asked already; do not repeat
    lastFit = key; send({t: 'fit', cols: d.cols, rows: d.rows});
  }, 350);
}
function layout() {
  const stage = $('stage');
  if (stage.hidden) return;
  if (autoFitOn()) { $('term').style.transform = ''; term.setFontPx(state.fontSize); scheduleFit(); return; }
  if (termKind === 'wterm') {
    // No CSS scaling for wterm (it would break its cell measuring and typing overlay): the font shrinks instead.
    $('term').style.transform = '';
    term.fitFont(state.fontSize, stage.clientWidth - 2, stage.clientHeight);
    return;
  }
  const screen = term.element && term.element.querySelector('.xterm-screen');
  if (!screen) return;
  const scale = K.fitScale(stage.clientWidth, screen.offsetWidth);
  $('term').style.transform = scale < 1 ? `scale(${scale})` : '';
}
new ResizeObserver(layout).observe($('stage'));

// The visible height changes when a soft keyboard opens: follow it so the cursor stays in view.
function followViewport() {
  const vv = window.visualViewport;
  document.documentElement.style.setProperty('--vh', (vv ? Math.round(vv.height) : innerHeight) + 'px');
  if (vv) scrollTo(0, 0);
}
if (window.visualViewport) { visualViewport.addEventListener('resize', followViewport); visualViewport.addEventListener('scroll', followViewport); }
followViewport();

function hex(c) { return c && !c.startsWith('#') ? '#' + c : c; }
function applyTheme(t) {
  if (termKind === 'wterm' && !LS.get('rextheme', false)) return;   // Ovis's colours, not Rex's
  const theme = {};
  if (t.foreground) theme.foreground = hex(t.foreground);
  if (t.background) {
    theme.background = hex(t.background);
    document.documentElement.style.setProperty('--term-bg', theme.background);
    $('theme-color').setAttribute('content', theme.background);
  }
  if (t.cursor) theme.cursor = hex(t.cursor);
  if (t.palette) theme.palette = t.palette;      // wterm uses it; xterm.js ignores it
  term.options.theme = theme;
}

function setFontSize(n) {
  state.fontSize = K.clampFont(n); LS.set('fontSize', state.fontSize);
  if (termKind === 'xterm') term.options.fontSize = state.fontSize;
  lastFit = '';
  requestAnimationFrame(layout);
  const el = $('font-now'); if (el) el.textContent = state.fontSize + ' px';
}

// ---- status ----
function notice(text) {
  const n = $('notice'); n.textContent = text; n.hidden = false;
  clearTimeout(notice.t); notice.t = setTimeout(() => { n.hidden = true; }, 4500);
}
function renderStatus() {
  const dot = $('dot');
  let cls = 'good', label = 'connected', banner = null, bad = false;
  if (!state.ws || state.ws.readyState !== 1) { cls = 'warn'; label = 'reconnecting'; banner = 'Reconnecting…'; }
  else if (!link.healthy) { cls = 'warn'; label = 'connection stalled'; banner = 'Connection stalled: typing is paused until it recovers.'; }
  else if (!state.rexUp) { cls = 'bad'; label = 'Rex unreachable'; banner = 'Rex is not reachable. This page will reconnect when it is back.'; bad = true; }
  else if (state.observe) { banner = state.locked ? 'View only (locked by the server): nothing you do here changes anything.' : 'View only: typing and changes are off.'; }
  else if (state.exited !== null) { banner = `The program in this terminal exited (${state.exited}).`; }
  dot.className = 'dot ' + cls; dot.setAttribute('aria-label', label); dot.title = label;
  const b = $('banner'); b.hidden = banner === null; b.textContent = banner || ''; b.className = bad ? 'bad' : '';
  requestAnimationFrame(layout);
}

// ---- connection ----
// A phone's connection through Tailscale Serve can go silently dead. So: ask for a reply every
// 3 s, and if nothing has come back for 8 s give the socket up and open a new one at once. Typing
// is refused until something arrives, so no keystroke is sent into a dead connection.
function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${location.pathname.replace(/[^/]*$/, '')}ws${location.search}`);
  state.ws = ws; ws.binaryType = 'arraybuffer';
  state.opened = false; forgetPaste();         // a new connection shows nothing until it says `opened`
  const mine = () => state.ws === ws;          // a socket we abandoned must not act
  link.lastRx = performance.now(); link.healthy = false; renderStatus();
  ws.onopen = () => {
    if (!mine()) return;
    state.retry = 500; link.lastRx = performance.now();
    if (state.current) { startRestore(); send({t: 'open', session: state.current.session, block: state.current.block}); }
    renderStatus();
  };
  ws.onclose = () => {
    if (!mine()) return;
    link.healthy = false; renderStatus();
    setTimeout(() => { if (mine()) connect(); }, state.retry); state.retry = Math.min(state.retry * 2, 4000);
  };
  ws.onmessage = ev => {
    if (!mine()) return;
    link.lastRx = performance.now();
    if (!link.healthy) { link.healthy = true; renderStatus(); }
    // Output is drawn only once the bridge has said it shows this page's terminal (see `ready`).
    if (typeof ev.data !== 'string') { if (ready()) term.write(new Uint8Array(ev.data)); return; }
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    try { handleMessage(m); } catch (e) { if (dbgOn) dbgSend({ev: 'handler-threw', mt: m.t, msg: String(e && e.stack || e).slice(0, 300)}); }
  };
}
setInterval(() => send({t: 'ping'}), 3000);
setInterval(() => {
  const ws = state.ws;
  if (!ws || ws.readyState !== 1) return;
  const quiet = performance.now() - link.lastRx;
  if (quiet > 5000 && link.healthy) { link.healthy = false; renderStatus(); }
  if (quiet > 8000) {
    state.ws = null; try { ws.close(); } catch {}
    state.retry = 500; connect();
  }
}, 1000);

function handleMessage(m) {
  switch (m.t) {
    case 'mode': setDebug(K.debugOn(dbgAsked, m)); state.canDownload = !!m.download; state.canUpload = !!m.upload; state.observe = m.observe; state.locked = m.locked; state.rexUp = m.rex_up; updateControls(); renderStatus(); break;
    case 'rex': state.rexUp = m.up; renderStatus(); if (m.up) retryOpenNow(); break;
    case 'tree': {
      state.tree = m.sessions; renderAll(); maybeRestore();
      const pn = state.pendingNew;                               // a terminal was just added with +: switch to it
      if (pn) { const s = state.tree.find(x => x.id === pn.session); if (s && s.blocks.length > pn.count) { state.pendingNew = null; openBlock(s.id, s.blocks[s.blocks.length - 1].id); } }
      break;
    }
    case 'opened':
      // Another terminal's (the bridge had not switched yet, or has left this one): not drawn here, and
      // nothing is typed until this terminal's own `opened` arrives.
      if (!sameTerm(m, state.current)) { state.opened = false; break; }
      state.opened = true; stopRestore();
      state.info = null; renderInfo(); pollInfo();
      state.cols = m.cols; state.rows = m.rows; state.historyRows = m.history_rows;
      state.exited = (m.exited !== undefined && m.exited !== null) ? m.exited : null;
      $('empty').hidden = true; $('stage').hidden = false; $('keys').hidden = false;
      term.resize(m.cols, m.rows); layout(); updateControls(); renderStatus();
      if (!NARROW.matches) term.focus();
      pumpUploads();
      break;
    case 'theme': if (ready()) applyTheme(m); break;
    case 'info': if (ready()) { state.info = m; renderInfo(); } break;
    case 'exited': if (ready()) { state.exited = m.code; renderStatus(); } break;
    // A late `closed` for a terminal the page has left since is not about the one it shows (H3).
    case 'closed': if (K.aboutTerm(m, state.current)) showEmpty('That terminal was closed.'); break;
    case 'notice': notice(m.msg); break;
    case 'error': onError(m); break;
    case 'text': openCopy(m.text, m.truncated); break;
    case 'clip': {
      // A program chose this text: shown and copied without control characters, and labelled as its.
      const t = typeof m.text === 'string' ? K.cleanClip(m.text) : '';
      if (t) openCopy(t, false, true); else notice('Nothing has been copied by a program in this terminal yet.');
      break;
    }
    case 'ls': renderDir(m); break;
    case 'xfer': onXfer(m); break;
    case 'pong': break;
  }
}

// A refusal names the message it refuses (`for`); a rate refusal also says `rate: true`. An older
// bridge said `for: 'rate'` without naming the message. Whatever was waiting on the refused message is
// let go here, so nothing waits for an answer that will not come.
function onError(m) {
  const f = m.for, msg = String(m.msg || 'refused');
  // A refused open names the terminal it asked for; one for a terminal the page has left since is
  // ignored (H3). An old bridge's unnamed rate refusal while a terminal is opening is taken as that
  // open's: it is the only message sent then.
  if (f === 'open') { openRefused(m, msg); return; }
  if (f === 'rate' && state.current && !state.opened) { openRefused({for: 'open', rate: true}, msg); return; }
  if (f === 'paste' && m.code === 'confirm_multiline') { askMultiline(msg); return; }
  // The bridge closes the connection after this one; the page reconnects as usual.
  if (f === 'message') { notice(`Not sent: the message was ${msg}`); return; }
  switch (f) {
    case 'rate':                                     // an older bridge: it could be any of these
      ulRefused(msg, true); state.pendingNew = null; lastFit = ''; $('xf-list').setAttribute('aria-busy', 'false');
      notice(`Refused: ${msg}`); return;
    case 'ls': $('xf-list').setAttribute('aria-busy', 'false'); xfNote(`Cannot list that folder: ${msg}`); return;
    case 'dl': xfNote(`Cannot download: ${msg}`); notice(`Cannot download: ${msg}`); return;
    case 'ul': ulRefused(msg, m.rate === true); return;
    case 'new_terminal': state.pendingNew = null; break;
    case 'fit': lastFit = ''; break;                 // the next layout may ask again
    case 'info': return;                             // a background poll: the next one tries again
    case 'paste': forgetPaste(); break;
    case 'manage': case 'input': notice(msg); return;
  }
  notice(`${f}: ${msg}`);
}
// The bridge left the terminal it was on, so the page shows none, unless the refusal is for another
// terminal (ignored) or one that may pass while the terminal is restored after a (re)connect (retried,
// keeping the terminal and the one this device remembers: H4).
function openRefused(m, msg) {
  const what = K.openRefusal(m, state.current, !!state.restore);
  if (what === 'ignore') return;
  if (what === 'retry') { openRetry(m); return; }
  forgetLast(state.current);
  clearView('Pick a terminal from the list.');
  notice(`Cannot open that terminal: ${msg}`);
}
// Restoring `current` after a (re)connect: a transient or rate refusal of its open is retried with
// backoff (keys.js `openRetryDelay`) while the socket is up. It stops on success (`opened`), on a
// refusal that will not pass, when the person picks a terminal, or when the view is cleared.
function startRestore() { stopRestore(); state.restore = {attempt: 0, timer: 0}; }
function stopRestore() { if (state.restore) clearTimeout(state.restore.timer); state.restore = null; }
function openRetry(m) {
  const r = state.restore; clearTimeout(r.timer);
  const text = m.transient !== true && m.rate === true ? 'Too many requests; retrying…' : 'Rex is not answering; retrying…';
  notice(text);
  if ($('stage').hidden) $('empty').textContent = text;
  r.timer = setTimeout(() => { r.timer = 0; retryOpen(r); }, K.openRetryDelay(r.attempt++));
}
function retryOpen(r) {
  if (state.restore !== r || !state.current || state.opened) return;
  if (!state.ws || state.ws.readyState !== 1) return;     // the next connection opens it again
  send({t: 'open', session: state.current.session, block: state.current.block});
}
// Rex is back: a waiting retry goes now.
function retryOpenNow() { const r = state.restore; if (r && r.timer) { clearTimeout(r.timer); r.timer = 0; retryOpen(r); } }
function sameTerm(a, b) { return K.sameTerm(a, b); }
// The terminal this device reopens on load is forgotten when it is `t`.
function forgetLast(t) { if (t && sameTerm(LS.get('last', null), t)) LS.set('last', null); }

function showEmpty(text) { forgetLast(state.current); clearView(text); }
function clearView(text) {
  state.info = null; renderInfo(); forgetPaste(); stopRestore();
  state.current = null; state.opened = false; state.exited = null;
  $('stage').hidden = true; $('keys').hidden = true; $('empty').hidden = false; $('empty').textContent = text;
  renderAll(); updateControls(); renderStatus();
}

// ---- the tree, tabs and controls ----
function currentInfo() {
  if (!state.current) return null;
  for (const s of state.tree) for (const b of s.blocks) if (b.id === state.current.block) return {s, b};
  return null;
}
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function iconButton(text, label, on) { const b = el('button', 'small', text); b.setAttribute('aria-label', label); b.title = label; b.onclick = on; b.disabled = state.observe; return b; }

function renderAll() { renderTree(); renderCrumb(); updateControls(); }

// What the terminal reports about itself (title, folder, program, listening ports), shown dim under
// the workspace name and as port chips by the tabs.
function shortPath(p) {
  if (!p) return '';
  let path = p.replace(/^file:\/\/[^/]*/, '');
  try { path = decodeURIComponent(path); } catch {}
  path = path.replace(/^\/(Users|home)\/[^/]+/, '~');
  const parts = path.split('/').filter(Boolean);
  return parts.length > 3 ? '…/' + parts.slice(-2).join('/') : path;
}
function renderInfo() {
  const i = state.current ? state.info : null, sub = $('crumb-sub'), ports = $('ports');
  sub.replaceChildren(); ports.replaceChildren();
  if (!i) return;
  const bits = [];
  if (i.state && i.state !== 'idle') { const d = el('span', 'sdot ' + i.state); d.title = i.status_msg || i.state; sub.append(d); }
  if (i.status_msg) bits.push(i.status_msg + (Number.isInteger(i.progress) ? ` ${i.progress}%` : ''));
  const what = !i.status_msg && (i.program || i.title);
  if (what) bits.push(what);
  const where = shortPath(i.pwd); if (where) bits.push(where);
  sub.append(bits.join(' · '));
  if (i.exit_code) { const x = el('span', 'bad', ` exit ${i.exit_code}`); sub.append(x); }
  for (const p of i.ports || []) { const c = el('span', 'chip', ':' + p); c.title = 'Listening on port ' + p; ports.append(c); }
}
let infoTimer = 0;
function pollInfo() {
  clearTimeout(infoTimer);
  if (ready() && link.healthy && document.visibilityState === 'visible') send({t: 'info'});
  infoTimer = setTimeout(pollInfo, 4000);
}
function renderCrumb() {
  const info = currentInfo();
  $('crumb-session').textContent = info ? info.s.label : 'rweb';
  $('crumb-term').textContent = info ? info.b.label : '';
  $('crumb-sep').hidden = !info;
  const tabs = $('tabs'); tabs.replaceChildren();
  $('tabsel').hidden = true;
  $('tabrow').hidden = !info;
  if (info) {
    const n = info.s.blocks.length, i = info.s.blocks.findIndex(b => b.id === state.current.block) + 1;
    $('crumb-count').textContent = n > 1 ? ` ${i}/${n}` : '';
    let prevWin = null;
    info.s.blocks.forEach(b => {
      const t = el('button', '', b.label);
      if (prevWin !== null && b.window !== prevWin) t.classList.add('newwin');   // a different Rex window starts here
      prevWin = b.window;
      if (b.id === state.current.block) t.setAttribute('aria-current', 'true');
      t.onclick = () => openBlock(info.s.id, b.id);
      tabs.append(t);
    });
    $('tab-add').disabled = state.observe;
    $('tab-add').onclick = () => { state.pendingNew = {session: info.s.id, count: info.s.blocks.length}; send({t: 'new_terminal', session: info.s.id}); };
  }
  requestAnimationFrame(layout);
}

function renderTree() {
  const root = $('tree'); root.replaceChildren();
  for (const s of state.tree) {
    const box = el('div', 'session');
    const name = el('div', 'name');
    name.append(el('span', 'label', s.label));
    name.append(iconButton('+', `New terminal in ${s.label}`, () => send({t: 'new_terminal', session: s.id})));
    name.append(iconButton('✎', `Rename session ${s.label}`, async () => {
      const l = await ask({title: 'Rename session', label: 'Name', value: s.label, ok: 'Rename'});
      if (l) send({t: 'rename_session', session: s.id, label: l});
    }));
    name.append(iconButton('✕', `Close session ${s.label}`, async () => {
      if (await confirmAction({title: 'Close session?', message: `"${s.label}" and every terminal in it will end, and the programs running in them.`, ok: 'Close session'}))
        send({t: 'destroy_session', session: s.id});
    }));
    box.append(name);
    for (const b of s.blocks) {
      const cur = state.current && state.current.block === b.id;
      const row = el('div', 'block' + (cur ? ' current' : ''));
      const open = el('button', 'label', b.label + (b.owner ? ' •' : ''));
      if (cur) open.setAttribute('aria-current', 'true');
      open.title = b.owner ? `A desktop or another client is using this terminal's size` : '';
      open.onclick = () => openBlock(s.id, b.id);
      row.append(open);
      row.append(iconButton('✎', `Rename terminal ${b.label}`, async () => {
        const l = await ask({title: 'Rename terminal', label: 'Name', value: b.label, ok: 'Rename'});
        if (l) send({t: 'rename_block', session: s.id, block: b.id, label: l});
      }));
      row.append(iconButton('✕', `Close terminal ${b.label}`, async () => {
        if (await confirmAction({title: 'Close terminal?', message: `The program running in "${b.label}" will end.`, ok: 'Close terminal'}))
          send({t: 'close_block', session: s.id, block: b.id});
      }));
      box.append(row);
    }
    root.append(box);
  }
  if (!state.tree.length) root.append(el('div', 'dim', 'No sessions yet.'));
}

function updateControls() {
  $('new-session').disabled = state.observe;
  $('menu').setAttribute('aria-expanded', String($('list').classList.contains('open')));
  const fit = $('pop-fit'); if (fit) fit.disabled = !ready() || state.observe;
  const ro = $('pop-ro'); if (ro) { ro.setAttribute('aria-pressed', String(state.observe)); ro.disabled = state.locked; ro.textContent = state.locked ? 'View only (locked by the server)' : 'View only'; }
  const hi = $('pop-hist'); if (hi) hi.disabled = !ready() || state.historyRows === 0;
}

// `restoring`: reopening the terminal this device had open (see `openRetry`), not the person's choice.
function openBlock(session, block, restoring) {
  lastFit = '';
  if (restoring) startRestore(); else stopRestore();
  state.current = {session, block}; state.opened = false; state.exited = null; LS.set('last', state.current);
  forgetPaste();
  term.reset(); clearLatched(); softReset();
  send({t: 'open', session, block});
  // On a wide screen typing goes to the terminal at once (on a phone this would pop up the keyboard):
  // what is typed right after a switch reaches the terminal just opened, as the bridge keeps the order.
  if (!NARROW.matches && !restoring) term.focus();
  closeListIfNarrow(); closePop();
  renderAll(); renderStatus();
}
// Reopen the terminal this device had open last, once the tree says it still exists.
function maybeRestore() {
  if (state.tried) return;
  state.tried = true;
  const last = LS.get('last', null);
  if (!last || state.current) return;
  const exists = state.tree.some(s => s.id === last.session && s.blocks.some(b => b.id === last.block));
  if (exists) openBlock(last.session, last.block, true);
}

// ---- list drawer ----
function setList(open) { $('list').classList.toggle('open', open); LS.set('list', open); updateControls(); requestAnimationFrame(layout); }
function closeListIfNarrow() { if (NARROW.matches) setList(false); }
$('menu').onclick = () => setList(!$('list').classList.contains('open'));
$('scrim').onclick = () => setList(false);
$('new-session').onclick = async () => {
  const l = await ask({title: 'New session', label: 'Name (optional)', value: '', ok: 'Create', optional: true});
  if (l !== null) send({t: 'new_session', ...(l ? {label: l} : {})});
};
(function initList() { const saved = LS.get('list', null); $('list').classList.toggle('open', saved === null ? !NARROW.matches : (saved && !NARROW.matches)); updateControls(); })();

// ---- popovers: the ... menu and the terminal switcher ----
let popFor = null;
function closePop() { $('pop').hidden = true; if (popFor) popFor.setAttribute('aria-expanded', 'false'); popFor = null; }
function openPop(anchor, build) {
  if (popFor === anchor) return closePop();
  closePop();
  const pop = $('pop'); pop.replaceChildren();
  const sheet = false; pop.classList.remove('sheet');   // a dropdown from the button, not a bottom sheet
  if (sheet) {
    const info = currentInfo(), t = el('div', 'sheet-title');
    const b = el('b', '', info ? info.s.label : 'rweb'), sm = el('small', '', info ? info.b.label : '');
    t.append(b, sm); pop.append(t);
  }
  build(pop);
  if (sheet) { const c = el('button', 'sheet-cancel', 'Cancel'); c.onclick = closePop; pop.append(c); }
  pop.hidden = false;
  if (!sheet) {
    const r = anchor.getBoundingClientRect();
    pop.style.top = Math.round(r.bottom + 4) + 'px';
    pop.style.left = Math.max(6, Math.min(innerWidth - pop.offsetWidth - 6, r.right - pop.offsetWidth)) + 'px';
  }
  anchor.setAttribute('aria-expanded', 'true'); popFor = anchor;
  const first = pop.querySelector('button:not(:disabled)'); if (first) first.focus();
}
document.addEventListener('pointerdown', e => { if (popFor && !$('pop').contains(e.target) && !popFor.contains(e.target)) closePop(); });
document.addEventListener('keydown', e => { if (e.key === 'Escape' && popFor) { const a = popFor; closePop(); a.focus(); } });
function item(pop, text, on, id) { const b = el('button', '', text); b.setAttribute('role', 'menuitem'); if (id) b.id = id; b.onclick = () => { on(b); }; pop.append(b); return b; }

$('more').onclick = () => openPop($('more'), pop => {
  item(pop, 'Copy text…', () => { closePop(); requestCopy(); }, 'pop-copy').disabled = !ready();
  const clip = item(pop, 'Text copied in the terminal…', () => { closePop(); try { term.blur(); } catch {} send({t: 'clip'}); }, 'pop-clip');
  clip.disabled = !ready(); clip.title = 'Shows the last text a program such as vim or tmux copied inside the terminal, so you can copy it to your phone';
  clip.append(el('small', 'hint', 'What vim, tmux or similar last copied'));
  item(pop, 'Paste…', () => { closePop(); doPaste(); }, 'pop-paste').disabled = !ready() || state.observe;
  if (state.canDownload) item(pop, 'Download a file…', () => { closePop(); openFiles(); }, 'pop-dl').disabled = !ready() || state.observe;
  if (state.canUpload) item(pop, 'Upload files…', () => { closePop(); xf.pick = state.current ? {session: state.current.session, block: state.current.block} : null; $('upfile').click(); }, 'pop-ul').disabled = !ready() || state.observe;
  item(pop, 'Clear screen', () => { closePop(); send({t: 'term_action', action: 'clear'}); }).disabled = !ready() || state.observe;
  item(pop, 'Reset terminal…', async () => { closePop(); if (await confirmAction({title: 'Reset the terminal?', message: 'It returns to its starting state and the screen and scrollback are cleared. Programs keep running.', ok: 'Reset'}) && ready()) send({t: 'term_action', action: 'reset'}); }).disabled = !ready() || state.observe;
  const sz = el('div', 'sizer'); sz.append(el('span', '', 'Text size'));
  const minus = el('button', '', '−'); minus.setAttribute('aria-label', 'Smaller text'); minus.onclick = () => setFontSize(state.fontSize - 1);
  const now = el('span', 'dim', state.fontSize + ' px'); now.id = 'font-now'; now.style.flex = '0 0 auto'; now.style.minWidth = '48px'; now.style.textAlign = 'center';
  const plus = el('button', '', '+'); plus.setAttribute('aria-label', 'Larger text'); plus.onclick = () => setFontSize(state.fontSize + 1);
  sz.append(minus, now, plus); pop.append(sz);
  const ro = item(pop, 'View only', () => send({t: 'observe', on: !state.observe}), 'pop-ro');
  ro.setAttribute('role', 'menuitemcheckbox');
  if (termKind === 'wterm') { const af = item(pop, autoFitOn() ? 'Fit Rex to this screen: on' : 'Fit Rex to this screen: off', () => { LS.set('autofit', !autoFitOn()); lastFit = ''; closePop(); layout(); }); af.setAttribute('role', 'menuitemcheckbox'); af.setAttribute('aria-pressed', String(autoFitOn())); }
  if (termKind === 'wterm') { const rt = item(pop, LS.get('rextheme', false) ? 'Use Rex colours: on' : 'Use Rex colours: off', () => { LS.set('rextheme', !LS.get('rextheme', false)); location.reload(); }); rt.setAttribute('role', 'menuitemcheckbox'); }
  item(pop, 'Fit terminal to this window…', async () => {
    closePop();
    const d = fitAddon.proposeDimensions();
    if (d && await confirmAction({title: 'Resize the terminal?', message: `Resize it to ${d.cols} × ${d.rows}. It changes for everyone viewing it, including the desktop.`, ok: 'Resize'})) { if (canType()) send({t: 'fit', cols: d.cols, rows: d.rows}); else notice(whyNot()); }
  }, 'pop-fit');
  item(pop, 'Load all scrollback', () => { closePop(); send({t: 'more_history'}); }, 'pop-hist');
  { const dg = LS.get('diag', false); const it = item(pop, dg ? 'Touch diagnostics: on' : 'Touch diagnostics: off', () => { LS.set('diag', !dg); location.reload(); }); it.setAttribute('role', 'menuitemcheckbox'); it.setAttribute('aria-pressed', String(dg)); }
  item(pop, termKind === 'wterm' ? 'Terminal: wterm (switch to the older xterm.js)' : 'Terminal: xterm.js (switch back to wterm)', () => {
    LS.set('term', termKind === 'wterm' ? 'xterm' : 'wterm');
    const q = new URLSearchParams(location.search); q.delete('term');      // a ?term= would override it
    history.replaceState(null, '', location.pathname + (q.toString() ? '?' + q : '') + location.hash);
    location.reload();
  });
  item(pop, 'Reconnect', () => { closePop(); if (state.ws) { const w = state.ws; state.ws = null; try { w.close(); } catch {} } connect(); });
  updateControls();
});
$('tab-menu').onclick = () => openPop($('tab-menu'), pop => {
  const info = currentInfo(); if (!info) return; const {s, b} = info;
  item(pop, 'Rename terminal…', async () => { closePop(); const l = await ask({title: 'Rename terminal', label: 'Name', value: b.label, ok: 'Rename'}); if (l) send({t: 'rename_block', session: s.id, block: b.id, label: l}); }).disabled = state.observe;
  item(pop, 'New terminal', () => { closePop(); state.pendingNew = {session: s.id, count: s.blocks.length}; send({t: 'new_terminal', session: s.id}); }).disabled = state.observe;
  item(pop, 'Close terminal…', async () => { closePop(); if (await confirmAction({title: 'Close terminal?', message: `The program running in "${b.label}" will end.`, ok: 'Close terminal'})) send({t: 'close_block', session: s.id, block: b.id}); }).disabled = state.observe;
});
$('tabsel').onclick = () => openPop($('tabsel'), pop => {
  const info = currentInfo(); if (!info) return;
  info.s.blocks.forEach(b => { const x = item(pop, b.label, () => openBlock(info.s.id, b.id)); if (b.id === state.current.block) x.setAttribute('aria-current', 'true'); });
});

// ---- dialogs (in the page, so nothing depends on the browser's own pop-ups) ----
function dialogResult(dlg, setup) {
  return new Promise(resolve => {
    let value = null;
    const done = v => { value = v; if (dlg.open) dlg.close(); };
    setup(done);
    dlg.addEventListener('close', () => resolve(value), {once: true});
    dlg.showModal();
  });
}
function ask({title, label, value, ok, optional}) {
  const dlg = $('dlg'), inp = $('dlg-input');
  return dialogResult(dlg, done => {
    $('dlg-title').textContent = title; $('dlg-msg').textContent = ''; $('dlg-msg').hidden = true;
    $('dlg-label').textContent = label; $('dlg-label').hidden = false; inp.hidden = false; inp.value = value || '';
    const okb = $('dlg-ok'); okb.textContent = ok || 'OK'; okb.className = '';
    $('dlg-form').onsubmit = e => { e.preventDefault(); const v = inp.value.trim(); if (v || optional) done(v); };
    $('dlg-cancel').onclick = () => done(null);
    setTimeout(() => { inp.focus(); inp.select(); }, 0);
  });
}
async function confirmAction({title, message, ok}) {
  const dlg = $('dlg');
  const r = await dialogResult(dlg, done => {
    $('dlg-title').textContent = title; $('dlg-msg').textContent = message; $('dlg-msg').hidden = false;
    $('dlg-label').hidden = true; $('dlg-input').hidden = true;
    const okb = $('dlg-ok'); okb.textContent = ok || 'OK'; okb.className = 'danger';
    $('dlg-form').onsubmit = e => { e.preventDefault(); done('yes'); };
    $('dlg-cancel').onclick = () => done(null);
    setTimeout(() => $('dlg-cancel').focus(), 0);   // the safe choice has the focus
  });
  return r === 'yes';
}

// ---- copy and paste ----
function requestCopy() { try { term.blur(); } catch {} send({t: 'text'}); }
let copyFull = '', copyLines = [], copySel = null, copyNative = false;
function copyToClipboard(text) {
  // The clipboard API needs a secure page and a user action; the old way is the fallback.
  const old = () => new Promise((ok, no) => {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
    document.body.append(ta); ta.focus(); ta.select();
    let good = false; try { good = document.execCommand('copy'); } catch {}
    ta.remove(); good ? ok() : no(new Error('copy refused'));
  });
  return (navigator.clipboard && navigator.clipboard.writeText ? navigator.clipboard.writeText(text) : Promise.reject()).catch(old);
}
function renderCopySelection() {
  const r = K.selectedRange(copySel);
  const rows = $('copytext').children;
  for (let i = 0; i < rows.length; i++) {
    rows[i].classList.toggle('sel', !!r && i >= r.from && i <= r.to);
    rows[i].classList.toggle('mark', !!copySel && copySel.open && i === copySel.anchor);
  }
  const n = r ? r.to - r.from + 1 : 0;
  $('copy-sel').disabled = !n; $('copy-clear').disabled = !n;
  $('copy-sel').textContent = n ? `Copy ${n} line${n === 1 ? '' : 's'}` : 'Copy selected';
  $('copy-help').textContent = !copySel ? 'Tap a line to start a selection, then tap another line to select down (or up) to it.'
    : copySel.open ? 'Now tap the last line to select down (or up) to it.' : 'Tap Copy, or tap a line to start again.';
}
// `fromProgram`: the text a program put on the terminal's clipboard (already cleaned, keys.js
// `cleanClip`), labelled as such so it is not mistaken for the terminal's own text.
function openCopy(text, truncated, fromProgram) {
  const dlg = $('copydlg'), box = $('copytext');
  $('copy-title').textContent = fromProgram ? 'Text copied in the terminal' : 'Copy text';
  const view = K.copyView(text, truncated);           // a node per line: only the last COPY_MAX_LINES
  copyFull = text; copyLines = view.lines; copySel = null;
  const build = () => {
    box.replaceChildren();
    const frag = document.createDocumentFragment();
    copyLines.forEach((l, i) => { const d = document.createElement('div'); d.className = 'ln'; d.dataset.i = i; d.textContent = l === '' ? ' ' : l; frag.append(d); });
    box.append(frag);
    renderCopySelection();
  };
  build();
  // "Use handles": the text becomes editable but locked (no edits, no keyboard), because Chrome on
  // Android reliably shows its selection handles and toolbar on editable text and not always on plain text.
  const setNative = on => {
    copyNative = on; box.contentEditable = on ? 'true' : 'false'; box.classList.toggle('native', on);
    box.setAttribute('inputmode', 'none'); box.setAttribute('spellcheck', 'false'); box.setAttribute('autocapitalize', 'off'); box.setAttribute('autocorrect', 'off');
    $('copy-native').setAttribute('aria-pressed', String(on)); $('copy-native').textContent = on ? 'Tap lines instead' : 'Use handles';
    if (on) { copySel = null; renderCopySelection(); $('copy-help').textContent = 'Long-press a word, then drag the handles. Your device\u2019s own Copy button appears above the selection.'; }
  };
  // Locked: nothing can be typed, pasted, cut or dropped, and if anything gets through anyway the
  // original text is put back.
  box.onbeforeinput = e => e.preventDefault();
  box.onpaste = box.oncut = box.ondrop = e => e.preventDefault();
  box.oninput = () => { if (box.textContent !== copyLines.map(l => l === '' ? ' ' : l).join('')) { build(); if (copyNative) box.focus(); } };
  box.onkeydown = e => { if (copyNative && !(e.ctrlKey || e.metaKey) && e.key.length === 1) e.preventDefault(); };
  $('copy-native').onclick = () => setNative(!copyNative);
  setNative(false);
  box.onclick = e => { if (copyNative) return; const row = e.target.closest('.ln'); if (!row) return; copySel = K.tapLine(copySel, Number(row.dataset.i)); renderCopySelection(); };
  $('copy-note').textContent = fromProgram ? 'Set by a program in this terminal' + (view.note ? '. ' + view.note : '') : view.note;
  const done = what => () => notice(what), fail = () => notice('Could not copy: your browser refused');
  $('copy-all').onclick = () => copyToClipboard(copyFull).then(done('Copied everything'), fail);
  $('copy-last').onclick = () => copyToClipboard(K.lastLines(copyFull, 100)).then(done('Copied the last 100 lines'), fail);
  $('copy-sel').onclick = () => { const t = K.selectedText(copyLines, copySel); if (t) copyToClipboard(t).then(done('Copied the selected lines'), fail); };
  $('copy-clear').onclick = () => { copySel = null; renderCopySelection(); };
  const share = $('copy-share'); share.hidden = !navigator.share;
  share.onclick = () => navigator.share({text: copySel ? K.selectedText(copyLines, copySel) : copyFull}).catch(() => {});
  $('copy-close').onclick = () => dlg.close();
  renderCopySelection();
  // The terminal's hidden input box must not keep the focus (and the soft keyboard connection): on
  // Android that stops Chrome from offering selection handles on the text below. Give the text the focus.
  try { term.blur(); if (document.activeElement && document.activeElement !== document.body) document.activeElement.blur(); } catch {}
  if (!dlg.open) dlg.showModal();
  box.focus({preventScroll: true});
  box.scrollTop = box.scrollHeight;
}
async function doPaste() {
  if (!canType()) return;
  let text = '';
  try { text = await navigator.clipboard.readText(); } catch { text = null; }
  if (text) return sendPaste(text);
  if (text === '') return notice('The clipboard is empty');
  const dlg = $('pastedlg'), ta = $('pastetext'); ta.value = '';
  const r = await dialogResult(dlg, done => {
    $('paste-cancel').onclick = () => done(null);
    dlg.querySelector('form').onsubmit = e => { e.preventDefault(); done(ta.value); };
    setTimeout(() => ta.focus(), 0);
  });
  if (r) sendPaste(r);
}

// ---- the key row ----
(function buildKeys() {
  const main = $('keys-main'), more = $('keys-more');
  const make = (k, parent) => {
    const b = el('button', '', k.label);
    if (k.label.length >= 5) b.dataset.w = 'wide';
    if (k.title) { b.title = k.title; b.setAttribute('aria-label', k.title); }
    if (k.latch) { b.dataset.latch = k.latch; b.setAttribute('aria-pressed', 'false'); }
    if (k.key === 'enter') b.dataset.enter = '';
    b._k = k; parent.append(b);
  };
  K.ROW_MAIN.forEach(k => make(k, main));
  const toggle = el('button', '', '⌃'); toggle.setAttribute('aria-label', 'More keys'); toggle.setAttribute('aria-expanded', 'false');
  toggle.onpointerdown = e => { e.preventDefault(); const open = $('keys-more').hidden; $('keys-more').hidden = !open; toggle.setAttribute('aria-expanded', String(open)); toggle.textContent = open ? '⌄' : '⌃'; $('keys').classList.toggle('expanded', open);
    // Expanded, Home, End and Paste join the modifiers so the left block is an even 5 x 2 grid.
    const fill = [...$('keys').querySelectorAll('button')].filter(b => (b._k && (b._k.key === 'home' || b._k.key === 'end')) || b.dataset.keep === 'paste');
    const order = b => (b._k && b._k.key === 'home') ? 0 : (b._k && b._k.key === 'end') ? 1 : 2;
    fill.sort((a, b) => order(a) - order(b));
    if (open) $('keys-mods').append(...fill); else more.prepend(...fill.filter(b => b.dataset.keep !== 'paste')), more.append(...fill.filter(b => b.dataset.keep === 'paste'));
    requestAnimationFrame(layout); };
  // The arrows and the toggle sit in one pad: in a line when collapsed, an inverted T when expanded.
  const pad = el('div', 'pad'); pad.id = 'keys-pad';
  const pos = {'↑': 'up', '↓': 'down', '←': 'left', '→': 'right'};
  for (const b of [...main.querySelectorAll('button')]) if (pos[b.textContent]) { b.dataset.pos = pos[b.textContent]; pad.append(b); }
  toggle.dataset.pos = 'toggle'; pad.append(toggle);
  // The modifier keys get their own box so the expanded bar can put them beside the arrow pad.
  const mods = el('div', ''); mods.id = 'keys-mods'; mods.append(...main.querySelectorAll(':scope > button'));
  main.append(mods, pad);
  K.ROW_MORE.forEach(k => make(k, more));
  // Paste opens a dialog, so it acts on a completed tap that ends on it, not on first touch like the
  // other keys: a touch meant for its neighbour (End) must not open it.
  const paste = el('button', '', 'Paste'); paste.dataset.keep = 'paste';
  let pasteDown = false;
  paste.onpointerdown = e => { e.preventDefault(); pasteDown = true; };
  paste.onpointercancel = () => { pasteDown = false; };
  paste.onpointerup = e => {
    e.preventDefault();
    const on = document.elementFromPoint(e.clientX, e.clientY);
    if (pasteDown && on && on.closest('button') === paste) doPaste();
    pasteDown = false;
  };
  more.append(paste);
})();

let hold = null;
function pressKey(btn) {
  const k = btn._k; if (!k) return;
  if (k.latch) {
    state.latched[k.latch] = !state.latched[k.latch];
    btn.setAttribute('aria-pressed', String(state.latched[k.latch]));
    return;
  }
  if (!canType()) { notice(whyNot()); return; }
  const mods = Object.assign({}, k.mods || {});
  const used = Object.keys(state.latched).some(m => state.latched[m]);
  for (const m of Object.keys(state.latched)) if (state.latched[m]) mods[m] = true;
  const text = k.text && !mods.ctrl && !mods.alt ? k.text : '';
  send({t: 'key', key: K.keyObject(k.key, mods, 'press', text)});
  if (used) clearLatched();
  if (k.repeat) {
    hold = {btn, mods, text, timer: setTimeout(() => { hold.iv = setInterval(() => { if (canType()) send({t: 'key', key: K.keyObject(k.key, mods, 'repeat', text)}); }, 70); }, 420)};
  } else hold = {btn, mods, text};
}
function releaseKey() {
  if (!hold) return;
  const {btn, mods, text} = hold; clearTimeout(hold.timer); clearInterval(hold.iv); hold = null;
  const k = btn._k; if (k && !k.latch && canType()) send({t: 'key', key: K.keyObject(k.key, mods, 'release', text)});
}
// pointerdown with preventDefault keeps focus in the terminal, so the soft keyboard stays up.
$('keys').addEventListener('pointerdown', e => { const b = e.target.closest('button'); if (!b || !b._k) return; e.preventDefault(); pressKey(b); });
for (const ev of ['pointerup', 'pointercancel', 'pointerleave']) $('keys').addEventListener(ev, releaseKey);

// ---- diagnostics: open with ?dbg=1 and start the bridge with --debug-input ----
// Nothing is sent unless the bridge's `mode` message allows it (`debug: true`).
function dbgSend(o) { if (dbgOn) send({ms: Math.round(performance.now()), ...o, t: 'dbg'}); }
let dbgStarted = false;
function setDebug(on) {
  dbgOn = on;
  if (!on || dbgStarted || !term.textarea) return;
  dbgStarted = true;
  setInterval(() => dbgSend({ev: 'hb', vis: document.visibilityState}), 1000);
  const ta = term.textarea;
  for (const ev of ['keydown', 'keyup']) ta.addEventListener(ev, e => dbgSend({ev, key: e.key, code: e.code, kc: e.keyCode, comp: e.isComposing}), true);
  for (const ev of ['beforeinput', 'input']) ta.addEventListener(ev, e => dbgSend({ev, it: e.inputType, data: e.data, comp: e.isComposing, val: ta.value}), true);
  for (const ev of ['compositionstart', 'compositionupdate', 'compositionend']) ta.addEventListener(ev, e => dbgSend({ev, data: e.data}), true);
  addEventListener('error', e => dbgSend({ev: 'jserror', msg: String(e.message), line: e.lineno, col: e.colno}));
}

// Test hooks: what the terminal shows, for automated checks.
window.rweb = {
  term, state, soft,
  kind: termKind,
  screen() { if (termKind === 'wterm') return term.screenRows(); const b = term.buffer.active, out = []; for (let i = 0; i < term.rows; i++) out.push(b.getLine(b.viewportY + i).translateToString(true)); return out; },
};
setFontSize(state.fontSize);
renderStatus();
connect();
if (startupNote) notice(startupNote);

// ---- file transfer ----
// Only offered when the bridge was started with it on. A download is asked for over the socket; the
// answer is a one-time address the page opens as an ordinary download. An upload sends the file in
// one request to a one-time address; the bridge saves it in its upload folder and pastes the path.
// Each queued upload is {file, term}: `term` is the terminal shown when the files were chosen (`pick`,
// set when Upload is chosen from the menu), and the file goes to that terminal or nowhere (H6).
const xf = {dir: '', home: '', entries: [], hidden: LS.get('showHidden', false), queue: [], current: null, pick: null};

function fmtSize(n) {
  if (!Number.isFinite(n)) return '';
  if (n < 1024) return n + ' B';
  if (n < 1048576) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
  if (n < 1073741824) return (n / 1048576).toFixed(n < 10485760 ? 1 : 0) + ' MB';
  return (n / 1073741824).toFixed(1) + ' GB';
}
function joinPath(dir, name) { return dir === '/' || dir === '' ? '/' + name : dir + '/' + name; }
function parentOf(dir) { const i = dir.lastIndexOf('/'); return i <= 0 ? '/' : dir.slice(0, i); }
function xfNote(text) { $('xf-note').textContent = text || ''; }

function openFiles() {
  $('xf-hidden').checked = xf.hidden; $('xf-filter').value = ''; xfNote('');
  $('xferdlg').showModal();
  listDir('');
}
function listDir(path) { $('xf-list').setAttribute('aria-busy', 'true'); send({t: 'ls', path}); }

function renderDir(m) {
  xf.dir = m.path || xf.dir; xf.home = m.home || xf.home; xf.entries = m.entries || [];
  { let p = xf.home && xf.dir.startsWith(xf.home) ? '~' + xf.dir.slice(xf.home.length) : xf.dir; const parts = p.split('/'); if (parts.length > 4) p = '\u2026/' + parts.slice(-3).join('/'); $('xf-path').textContent = p; }
  $('xf-up').disabled = xf.dir === '/' || !xf.dir;
  $('xf-list').setAttribute('aria-busy', 'false');
  xfNote(m.status === 'ok' ? (m.truncated ? 'A long folder: type in the filter to find the rest.' : '')
    : m.status === 'denied' ? 'That folder cannot be read.' : m.status === 'missing' ? 'That folder is not there.' : 'That is not a folder.');
  drawDir();
}
function drawDir() {
  const list = $('xf-list'); list.replaceChildren();
  const q = $('xf-filter').value.trim().toLowerCase();
  const rows = xf.entries.filter(e => (xf.hidden || !e.n.startsWith('.')) && (!q || e.n.toLowerCase().includes(q)))
    .sort((a, b) => (b.d - a.d) || a.n.localeCompare(b.n, undefined, {sensitivity: 'base'}));
  for (const e of rows) {
    const b = el('button', 'xf-row' + (e.d ? ' dir' : ''));
    b.setAttribute('role', 'listitem');
    b.append(el('span', 'xf-ico', e.d ? '\u{1F4C1}' : '\u{1F4C4}'), el('span', 'xf-name', e.n));
    b.onclick = () => {
      const full = joinPath(xf.dir, e.n);
      if (e.d) { $('xf-filter').value = ''; listDir(full); }
      else { send({t: 'dl', path: full}); xfNote(`Asking for ${e.n}…`); }
    };
    list.append(b);
  }
  if (!rows.length) list.append(el('div', 'dim xf-empty', q ? 'No names match.' : 'Nothing here.'));
}
$('xf-close').onclick = () => $('xferdlg').close();
$('xferdlg').addEventListener('click', e => { if (e.target === $('xferdlg')) $('xferdlg').close(); });
$('xf-up').onclick = () => listDir(parentOf(xf.dir));
$('xf-home').onclick = () => listDir('~');
$('xf-filter').oninput = drawDir;
// A path typed in the filter box (starting with / or ~) and Enter goes there.
$('xf-filter').onkeydown = e => {
  const v = $('xf-filter').value.trim();
  if (e.key === 'Enter' && (v.startsWith('/') || v.startsWith('~'))) { e.preventDefault(); $('xf-filter').value = ''; listDir(v); }
};
$('xf-hidden').onchange = e => { xf.hidden = e.target.checked; LS.set('showHidden', xf.hidden); drawDir(); };

function onXfer(m) {
  if (m.kind === 'download') {
    const a = document.createElement('a');
    a.href = 'xfer/' + m.token; a.download = m.name; a.hidden = true;
    document.body.append(a); a.click(); a.remove();
    notice(`Downloading ${m.name} (${fmtSize(m.size)})`);
    if ($('xferdlg').open) { $('xferdlg').close(); }
  } else if (m.kind === 'upload' && xf.current) {
    // The token is good only for the terminal it was asked for; the page has switched since.
    if (!sameTerm(xf.current.term, state.current)) { xf.current = null; return pumpUploads(true); }
    putFile(xf.current.file, m.token);
  }
}

$('upfile').onchange = e => {
  const term = xf.pick || (state.current && {session: state.current.session, block: state.current.block});
  xf.pick = null;
  if (term) for (const file of e.target.files) xf.queue.push({file, term});
  e.target.value = '';
  pumpUploads();
};
// `stopped`: an upload was already dropped for another terminal (say so even if none is queued).
function pumpUploads(stopped) {
  if (xf.current) return;
  if (xf.queue.length && canType()) {
    const p = K.partitionUploads(xf.queue, state.current);
    if (p.drop.length) { xf.queue = p.keep; stopped = true; }
  }
  if (stopped) notice('Upload stopped: you switched terminals');
  if (!xf.queue.length || !canType()) return;
  xf.current = xf.queue.shift();
  send({t: 'ul', name: xf.current.file.name, size: xf.current.file.size});
}
// The bridge refused the upload waiting for its token. Refused for the rate, the file goes back to the
// front of the queue and is asked for again a second later (three times at most); otherwise it is
// dropped. Either way the queue moves on.
function ulRefused(msg, rate) {
  const f = xf.current; xf.current = null;
  if (!f) return;
  const tries = (ulRefused.tries.get(f) || 0) + 1;
  if (rate && tries <= 3) { ulRefused.tries.set(f, tries); xf.queue.unshift(f); setTimeout(pumpUploads, 1100); return; }
  ulRefused.tries.delete(f);
  notice(`Cannot upload ${f.file.name}: ${msg}`);
  pumpUploads();
}
ulRefused.tries = new WeakMap();
function putFile(file, token) {
  const req = new XMLHttpRequest();
  req.open('PUT', 'xfer/' + token);
  req.upload.onprogress = ev => { if (ev.lengthComputable) notice(`Uploading ${file.name} ${Math.round(100 * ev.loaded / ev.total)}%`); };
  const done = msg => { notice(msg); xf.current = null; pumpUploads(); };
  req.onload = () => {
    if (req.status !== 200) return done(`Upload of ${file.name} failed (${req.status})`);
    let name = file.name; try { name = JSON.parse(req.responseText).name || name; } catch {}
    done(`Uploaded ${name}: its path is at the prompt`);
  };
  req.onerror = () => done(`Upload of ${file.name} failed`);
  req.send(file);
}
}
main().catch(e => { console.error(e); const el = document.getElementById('empty'); if (el) el.textContent = 'The page failed to start: ' + e.message; });


