'use strict';
// Compares ways of talking to the bridge from this browser, one at a time. Each sends one small
// message a second; the bridge answers at once (and the WebSocket variants also get a push a
// second from the server). Reported: round trips, slow or lost answers, gaps in what the server
// pushed. Results are also sent to the bridge, which logs them.
const out = document.getElementById('out');
const log = s => { out.textContent += s + '\n'; };
const DURATION_MS = 40000, TICK_MS = 1000;
const sleep = ms => new Promise(r => setTimeout(r, ms));
const wsUrl = p => `${location.protocol === 'https:' ? 'wss' : 'ws'}://${location.host}${p}${location.search}`;

function summarize(name, s) {
  const rtts = s.rtts.slice().sort((a, b) => a - b);
  const line = `${name}: sent ${s.sent}, answered ${s.rtts.length}, never answered ${s.sent - s.rtts.length}, ` +
    `median ${rtts.length ? Math.round(rtts[rtts.length >> 1]) : '-'} ms, worst ${rtts.length ? Math.round(rtts[rtts.length - 1]) : '-'} ms, ` +
    `answers over 2 s: ${rtts.filter(x => x > 2000).length}` +
    (s.pushGapMax !== undefined ? `, longest silence from the server: ${Math.round(s.pushGapMax)} ms` : '') +
    (s.error ? `, ERROR ${s.error}` : '');
  log(line);
  fetch(`/api/lab/result?v=${encodeURIComponent(name)}&sent=${s.sent}&ans=${s.rtts.length}&worst=${Math.round(rtts[rtts.length - 1] || 0)}` +
    `&slow=${rtts.filter(x => x > 2000).length}&gap=${Math.round(s.pushGapMax || 0)}`, {cache: 'no-store'}).catch(() => {});
}

async function wsVariant(name, binary) {
  const s = {sent: 0, rtts: [], pushGapMax: 0};
  const sentAt = new Map();
  let lastPush = null;
  const ws = new WebSocket(wsUrl('/labws'));
  ws.binaryType = 'arraybuffer';
  const opened = new Promise(res => { ws.onopen = res; ws.onerror = () => { s.error = 'socket error'; res(); }; });
  ws.onmessage = ev => {
    const now = performance.now();
    if (typeof ev.data === 'string') {
      const m = JSON.parse(ev.data);
      if (m.push !== undefined) { if (lastPush !== null) s.pushGapMax = Math.max(s.pushGapMax, now - lastPush); lastPush = now; return; }
    }
    const seq = binary ? new DataView(ev.data).getUint32(0) : JSON.parse(ev.data).seq;
    if (sentAt.has(seq)) { s.rtts.push(now - sentAt.get(seq)); sentAt.delete(seq); }
  };
  await opened;
  const end = performance.now() + DURATION_MS;
  while (performance.now() < end && ws.readyState === 1) {
    const seq = ++s.sent; sentAt.set(seq, performance.now());
    if (binary) { const b = new DataView(new ArrayBuffer(8)); b.setUint32(0, seq); ws.send(b.buffer); }
    else ws.send(JSON.stringify({seq}));
    await sleep(TICK_MS);
  }
  await sleep(2000);
  if (ws.readyState !== 1) s.error = (s.error || '') + ' socket closed early';
  ws.close();
  summarize(name, s);
}

async function httpVariant(name) {
  const s = {sent: 0, rtts: []};
  const end = performance.now() + DURATION_MS;
  const pending = [];
  while (performance.now() < end) {
    const seq = ++s.sent, t0 = performance.now();
    pending.push(fetch(`/api/lab/hb?seq=${seq}`, {cache: 'no-store'}).then(r => r.text()).then(() => { s.rtts.push(performance.now() - t0); }).catch(() => {}));
    await sleep(TICK_MS);
  }
  await Promise.race([Promise.allSettled(pending), sleep(5000)]);
  summarize(name, s);
}

document.getElementById('go').onclick = async () => {
  document.getElementById('go').disabled = true;
  log(`${new Date().toLocaleTimeString()} starting; protocol ${performance.getEntriesByType('navigation')[0]?.nextHopProtocol}`);
  for (const [name, fn] of [
    ['websocket, text frames', () => wsVariant('websocket, text frames', false)],
    ['websocket, binary frames', () => wsVariant('websocket, binary frames', true)],
    ['plain HTTP requests', () => httpVariant('plain HTTP requests')],
    ['websocket, text frames (again)', () => wsVariant('websocket, text frames (again)', false)],
  ]) { log(`... running ${name}`); await fn(); }
  log('done. Tell Claude it finished.');
};
