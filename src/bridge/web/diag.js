'use strict';
// Touch diagnostics, off unless turned on in the ⋯ menu (localStorage `rweb.diag`). It only
// listens (passive listeners, no preventDefault) and draws a small panel that ignores the pointer,
// so it cannot change what a touch does. Made to find why a drag does not scroll the terminal on a
// phone (feedback item 2): which element a touch lands on, whether anything cancelled it, whether
// the browser took it as a scroll, and the scroll numbers of the terminal and the page.
(function () {
  let on = false;
  try { on = localStorage.getItem('rweb.diag') === 'true'; } catch {}
  if (!on) return;
  const panel = document.createElement('pre');
  panel.id = 'diag';
  panel.style.cssText = 'position:fixed;top:56px;right:4px;z-index:99;max-width:70vw;margin:0;padding:6px;font:10px/1.3 ui-monospace,Menlo,monospace;color:#9f9;background:rgba(0,0,0,.82);border:1px solid #3a3;border-radius:6px;pointer-events:none;white-space:pre-wrap;word-break:break-all';
  const name = e => {
    if (!e || !e.tagName) return String(e);
    let s = e.tagName.toLowerCase();
    if (e.id) s += '#' + e.id;
    const c = (typeof e.className === 'string' ? e.className : '').trim().split(/\s+/).filter(Boolean).slice(0, 2);
    if (c.length) s += '.' + c.join('.');
    return s;
  };
  const chain = e => { const out = []; for (let n = e; n && n.tagName && out.length < 4; n = n.parentElement) out.push(name(n)); return out.join(' < '); };
  const ev = {start: '-', at: '-', chain: '-', moves: 0, movePrevented: 0, startPrevented: false, pcancel: 0, termScrolls: 0, winScrolls: 0, last: '-'};
  let t0 = 0;
  const term = () => document.getElementById('term');
  const fmt = () => {
    const t = term(), vv = window.visualViewport;
    let ts = 'no #term';
    if (t) { const cs = getComputedStyle(t); ts = `st ${Math.round(t.scrollTop)} sh ${t.scrollHeight} ch ${t.clientHeight} max ${t.scrollHeight - t.clientHeight}\n  oy ${cs.overflowY} ta ${cs.touchAction} cls ${t.className}`; }
    return [
      `coarse ${matchMedia('(pointer: coarse)').matches} ua ${navigator.userAgent.replace(/.*(Chrome\/[\d.]+|Firefox\/[\d.]+|Version\/[\d.]+ Safari).*/, '$1')}`,
      `term ${ts}`,
      `page sy ${Math.round(scrollY)} vv ${vv ? Math.round(vv.height) + '@' + Math.round(vv.offsetTop) : '-'} ih ${innerHeight}`,
      `active ${name(document.activeElement)}`,
      `touch on ${ev.at}`,
      `  under ${ev.chain}`,
      `start prevented ${ev.startPrevented}  moves ${ev.moves} (prevented ${ev.movePrevented})`,
      `pointercancel ${ev.pcancel}  scroll: term ${ev.termScrolls} page ${ev.winScrolls}`,
      `last ${ev.last}`,
    ].join('\n');
  };
  const draw = () => { panel.textContent = fmt(); };
  const opt = {capture: true, passive: true};
  // Capture listeners record the target; bubble listeners on window run last and see whether any
  // handler on the way cancelled the event.
  addEventListener('touchstart', e => {
    Object.assign(ev, {moves: 0, movePrevented: 0, startPrevented: false, pcancel: 0, termScrolls: 0, winScrolls: 0});
    t0 = performance.now();
    const p = e.touches[0];
    const hit = p ? document.elementFromPoint(p.clientX, p.clientY) : null;
    ev.at = name(e.target) + (hit && hit !== e.target ? ' (point: ' + name(hit) + ')' : '');
    ev.chain = chain(e.target);
    ev.last = 'touchstart'; draw();
  }, opt);
  addEventListener('touchstart', e => { ev.startPrevented = e.defaultPrevented; draw(); }, {passive: true});
  addEventListener('touchmove', e => { ev.moves++; if (e.defaultPrevented) ev.movePrevented++; ev.last = 'touchmove +' + Math.round(performance.now() - t0) + 'ms'; draw(); }, {passive: true});
  addEventListener('touchend', () => { ev.last = 'touchend +' + Math.round(performance.now() - t0) + 'ms'; draw(); }, {passive: true});
  addEventListener('pointercancel', () => { ev.pcancel++; ev.last = 'pointercancel (browser took the gesture)'; draw(); }, opt);
  addEventListener('scroll', e => { if (e.target === document || e.target === window) ev.winScrolls++; else if (e.target === term()) ev.termScrolls++; draw(); }, opt);
  const start = () => { document.body.append(panel); draw(); setInterval(draw, 500); };
  if (document.body) start(); else addEventListener('DOMContentLoaded', start);
})();
