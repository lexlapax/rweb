'use strict';
// rweb page: a session list, one terminal, and the browser side of the bridge protocol.
// No framework and no network access except this origin. Labels are untrusted text: only
// textContent is used.

const $ = id => document.getElementById(id);
const state = {
  ws: null, retry: 500, observe: false, locked: false, rexUp: true,
  tree: [], current: null,   // {session, block}
  cols: 80, rows: 24, historyRows: 0, ctrl: false, soft: false,
};

// ---- the terminal ----
const term = new Terminal({
  cols: 80, rows: 24, scrollback: 10000, allowProposedApi: true,
  fontFamily: 'ui-monospace, Menlo, Consolas, monospace', fontSize: 14, cursorBlink: true,
});
const fitAddon = new FitAddon.FitAddon();
term.loadAddon(fitAddon);
term.open($('term'));

// Rex's own terminal answers programs' queries; this one must not, or the reply would be typed.
for (const id of [{final:'c'},{prefix:'>',final:'c'},{prefix:'=',final:'c'},{final:'n'},{prefix:'?',final:'n'},
  {intermediates:'$',final:'p'},{prefix:'?',intermediates:'$',final:'p'},{prefix:'>',final:'q'},{final:'t'},{prefix:'?',final:'u'}])
  term.parser.registerCsiHandler(id, () => true);
term.parser.registerDcsHandler({intermediates:'$', final:'q'}, () => true);
for (const n of [4, 10, 11, 12]) term.parser.registerOscHandler(n, data => data.includes('?'));

function send(obj) { if (state.ws && state.ws.readyState === 1) state.ws.send(JSON.stringify(obj)); }
function canType() { return state.current && !state.observe && state.rexUp; }

// Composed text, soft-keyboard text, pastes and mouse reports come from xterm.js.
term.onData(d => { if (canType()) send({t: 'in', d: state.ctrl ? ctrlOf(d) : d}); });
term.onBinary(d => { if (canType()) send({t: 'in', d}); });

function ctrlOf(d) {
  state.ctrl = false; $('ctrl').classList.remove('on');
  if (d.length === 1) { const c = d.toUpperCase().charCodeAt(0); if (c >= 64 && c <= 95) return String.fromCharCode(c - 64); }
  return d;
}

// Physical keys go to Rex, which encodes them for the program's keyboard mode. Phone keyboards
// and input methods report no usable key: those go through xterm.js (onData) above, and while
// one is in use Enter and Backspace do too, so they keep their order with the text before them.
const snake = code => code.replace(/([a-z0-9])([A-Z])/g, '$1_$2').replace(/([A-Za-z])([0-9])/g, '$1_$2').toLowerCase();
term.attachCustomKeyEventHandler(e => {
  if (e.type !== 'keydown' && e.type !== 'keyup') return false;
  if (e.isComposing || e.keyCode === 229 || e.key === 'Unidentified' || !e.code) { state.soft = true; return true; }
  if (state.soft && (e.key === 'Enter' || e.key === 'Backspace')) return true;
  if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key.toLowerCase() === 'v') return true;   // paste
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'c' && term.hasSelection()) return true; // copy
  if (!canType()) return false;
  const mods = [e.shiftKey && 'shift', e.ctrlKey && 'ctrl', e.altKey && 'alt', e.metaKey && 'super'].filter(Boolean).join('+');
  const text = (e.key.length === 1 && !e.ctrlKey && !e.metaKey) ? e.key : '';
  send({t: 'key', key: {
    key: snake(e.code), mods, consumed_mods: (text && e.shiftKey) ? 'shift' : '', text,
    unshifted_codepoint: e.key.length === 1 ? e.key.toLowerCase().codePointAt(0) : 0, composing: false,
    action: e.type === 'keyup' ? 'release' : (e.repeat ? 'repeat' : 'press'),
  }});
  e.preventDefault();
  return false;
});

// ---- layout: draw at Rex's size and shrink to fit; never change Rex's size unasked ----
function layout() {
  const stage = $('stage');
  if (stage.hidden) return;
  const screen = term.element && term.element.querySelector('.xterm-screen');
  if (!screen) return;
  const w = screen.offsetWidth, avail = stage.clientWidth;
  const scale = w > 0 ? Math.max(0.35, Math.min(1, avail / w)) : 1;
  $('term').style.transform = scale < 1 ? `scale(${scale})` : '';
  $('term').style.height = '';
}
new ResizeObserver(layout).observe($('stage'));

function hex(c) { return c && !c.startsWith('#') ? '#' + c : c; }
function applyTheme(t) {
  const theme = {};
  if (t.foreground) theme.foreground = hex(t.foreground);
  if (t.background) { theme.background = hex(t.background); $('stage').style.background = theme.background; }
  if (t.cursor) theme.cursor = hex(t.cursor);
  term.options.theme = theme;
}

// ---- connection ----
function setStatus(text, warn) { const s = $('status'); s.textContent = text; s.style.color = warn ? 'var(--warn)' : ''; }
function notice(text) {
  const n = $('notice'); n.textContent = text; n.hidden = false;
  clearTimeout(notice.t); notice.t = setTimeout(() => { n.hidden = true; }, 5000);
}

function connect() {
  const ws = new WebSocket(`${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}/ws${location.search}`);
  state.ws = ws; ws.binaryType = 'arraybuffer';
  ws.onopen = () => {
    state.retry = 500; setStatus('connected');
    if (state.current) send({t: 'open', session: state.current.session, block: state.current.block});
  };
  ws.onclose = () => {
    setStatus('disconnected, retrying', true);
    setTimeout(connect, state.retry); state.retry = Math.min(state.retry * 2, 8000);
  };
  ws.onmessage = ev => {
    if (typeof ev.data !== 'string') { term.write(new Uint8Array(ev.data)); return; }
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    onMessage(m);
  };
}
setInterval(() => send({t: 'ping'}), 20000);

function onMessage(m) {
  switch (m.t) {
    case 'mode': state.observe = m.observe; state.locked = m.locked; state.rexUp = m.rex_up; updateButtons(); break;
    case 'rex': state.rexUp = m.up; setStatus(m.up ? 'connected' : 'Rex is not reachable', !m.up); break;
    case 'tree': state.tree = m.sessions; renderTree(); break;
    case 'opened':
      state.cols = m.cols; state.rows = m.rows; state.historyRows = m.history_rows;
      $('empty').hidden = true; $('stage').hidden = false; $('keys').hidden = false;
      term.resize(m.cols, m.rows); layout(); updateButtons(); term.focus();
      if (m.exited !== undefined && m.exited !== null) notice(`the program exited (${m.exited})`);
      break;
    case 'theme': applyTheme(m); break;
    case 'exited': notice(`the program exited (${m.code})`); break;
    case 'closed': state.current = null; $('stage').hidden = true; $('keys').hidden = true; $('empty').hidden = false; $('empty').textContent = 'That terminal was closed.'; renderTree(); updateButtons(); break;
    case 'notice': notice(m.msg); break;
    case 'error': notice(`${m.for}: ${m.msg}`); break;
  }
}

function updateButtons() {
  const ro = $('ro'); ro.classList.toggle('on', state.observe); ro.disabled = state.locked;
  ro.textContent = state.locked ? 'read-only (locked)' : (state.observe ? 'read-only: on' : 'read-only');
  $('fit').disabled = !state.current || state.observe;
  $('history').disabled = !state.current || state.historyRows === 0;
  $('new-session').disabled = state.observe;
}
$('ro').onclick = () => send({t: 'observe', on: !state.observe});
$('history').onclick = () => send({t: 'more_history'});
$('fit').onclick = () => {
  const stage = $('stage'); term.resize(term.cols, term.rows);
  const d = fitAddon.proposeDimensions();
  if (d && confirm(`Resize this terminal to ${d.cols}x${d.rows}? It changes for everyone viewing it.`)) send({t: 'fit', cols: d.cols, rows: d.rows});
};
$('menu').onclick = () => $('list').classList.toggle('open');
$('new-session').onclick = () => { const l = prompt('Name for the new session (optional)'); if (l !== null) send({t: 'new_session', ...(l ? {label: l} : {})}); };
$('ctrl').onclick = () => { state.ctrl = !state.ctrl; $('ctrl').classList.toggle('on', state.ctrl); term.focus(); };
$('keys').addEventListener('click', e => {
  const k = e.target.dataset && e.target.dataset.k; if (!k || !canType()) return;
  send({t: 'key', key: {key: k, mods: '', consumed_mods: '', text: '', unshifted_codepoint: 0, composing: false, action: 'press'}});
  send({t: 'key', key: {key: k, mods: '', consumed_mods: '', text: '', unshifted_codepoint: 0, composing: false, action: 'release'}});
  term.focus();
});

// ---- the session list ----
function el(tag, cls, text) { const e = document.createElement(tag); if (cls) e.className = cls; if (text !== undefined) e.textContent = text; return e; }
function renderTree() {
  const root = $('tree'); root.replaceChildren();
  for (const s of state.tree) {
    const box = el('div', 'session');
    const name = el('div', 'name');
    name.append(el('span', 'label', s.label));
    const add = el('button', 'small', '+'); add.title = 'New terminal';
    add.onclick = () => send({t: 'new_terminal', session: s.id});
    const ren = el('button', 'small', 'rename');
    ren.onclick = () => { const l = prompt('New name', s.label); if (l) send({t: 'rename_session', session: s.id, label: l}); };
    const del = el('button', 'small', 'close');
    del.onclick = () => { if (confirm(`Close session "${s.label}" and every terminal in it?`)) send({t: 'destroy_session', session: s.id}); };
    for (const b of [add, ren, del]) b.disabled = state.observe;
    name.append(add, ren, del);
    box.append(name);
    for (const b of s.blocks) {
      const row = el('div', 'block' + (state.current && state.current.block === b.id ? ' current' : ''));
      const open = el('button', 'label', b.label + (b.owner ? ' •' : ''));
      open.title = b.owner ? `claimed by ${b.owner}` : '';
      open.onclick = () => openBlock(s.id, b.id);
      const rn = el('button', 'small', 'rename');
      rn.onclick = () => { const l = prompt('New name', b.label); if (l) send({t: 'rename_block', session: s.id, block: b.id, label: l}); };
      const cl = el('button', 'small', 'close');
      cl.onclick = () => { if (confirm(`Close terminal "${b.label}"? The program in it ends.`)) send({t: 'close_block', session: s.id, block: b.id}); };
      for (const x of [rn, cl]) x.disabled = state.observe;
      row.append(open, rn, cl);
      box.append(row);
    }
    root.append(box);
  }
  if (!state.tree.length) root.append(el('div', 'dim', 'No sessions.'));
}
function openBlock(session, block) {
  state.current = {session, block}; term.reset();
  send({t: 'open', session, block});
  if (matchMedia('(max-width: 700px)').matches) $('list').classList.remove('open');
  renderTree(); updateButtons();
}

// Test hooks: what the terminal shows, for automated checks.
window.rweb = {
  term, state,
  screen() { const b = term.buffer.active, out = []; for (let i = 0; i < term.rows; i++) out.push(b.getLine(b.viewportY + i).translateToString(true)); return out; },
};
connect();
