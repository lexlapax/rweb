import test from 'node:test';
import assert from 'node:assert/strict';
import {createRequire} from 'node:module';
const K = createRequire(import.meta.url)('../../src/bridge/web/keys.js');

test('snake names physical keys the way Rex expects', () => {
  assert.equal(K.snake('KeyA'), 'key_a');
  assert.equal(K.snake('Digit1'), 'digit_1');
  assert.equal(K.snake('ArrowUp'), 'arrow_up');
  assert.equal(K.snake('Backspace'), 'backspace');
  assert.equal(K.snake('NumpadEnter'), 'numpad_enter');
});

test('modifiers are joined in Rex order', () => {
  assert.equal(K.modsString({}), '');
  assert.equal(K.modsString({ctrl: true, shift: true}), 'shift+ctrl');
  assert.equal(K.modsString({super: true, alt: true, ctrl: true, shift: true}), 'shift+ctrl+alt+super');
});

test('key objects carry what client.key needs', () => {
  const k = K.keyObject('key_c', {ctrl: true}, 'press', '');
  assert.deepEqual(k, {key: 'key_c', mods: 'ctrl', consumed_mods: '', text: '', unshifted_codepoint: 0, composing: false, action: 'press'});
  const s = K.keyObject('key_a', {shift: true}, 'press', 'A');
  assert.equal(s.consumed_mods, 'shift');
  assert.equal(s.unshifted_codepoint, 97);
});

test('Ctrl turns letters into control characters', () => {
  assert.equal(K.ctrlText('c'), '\x03');
  assert.equal(K.ctrlText('C'), '\x03');
  assert.equal(K.ctrlText('a'), '\x01');
  assert.equal(K.ctrlText('z'), '\x1a');
  assert.equal(K.ctrlText('['), '\x1b');
  assert.equal(K.ctrlText('?'), '\x7f');
  assert.equal(K.ctrlText('1'), null);
  assert.equal(K.ctrlText('ab'), null);
});

test('latched modifiers apply to one soft-keyboard character, not to words', () => {
  assert.deepEqual(K.applyLatched({ctrl: true}, 'd'), {text: '\x04', used: true});
  assert.deepEqual(K.applyLatched({alt: true}, 'f'), {text: '\x1bf', used: true});
  assert.deepEqual(K.applyLatched({shift: true}, 'q'), {text: 'Q', used: true});
  assert.deepEqual(K.applyLatched({ctrl: true, alt: true}, 'b'), {text: '\x1b\x02', used: true});
  // A word (a composition or a paste) is not a key press: it goes through and the latch stays.
  assert.deepEqual(K.applyLatched({ctrl: true}, 'hello'), {text: 'hello', used: false});
  // Ctrl with a character that has no control form leaves it alone and keeps the latch.
  assert.deepEqual(K.applyLatched({ctrl: true}, '5'), {text: '5', used: false});
  assert.deepEqual(K.applyLatched(null, 'x'), {text: 'x', used: false});
  assert.deepEqual(K.applyLatched({}, 'x'), {text: 'x', used: false});
});

test('the key rows are what the owner asked for, and every entry is usable', () => {
  const main = K.ROW_MAIN.map(k => k.label);
  assert.deepEqual(main, ['Enter', 'Esc', 'Tab', '^C', 'Ctrl', 'Alt', 'Shift', '↑', '↓', '←', '→']);
  for (const k of [...K.ROW_MAIN, ...K.ROW_MORE]) {
    assert.ok(k.label && (k.latch || k.key), `entry ${k.label} does something`);
    if (k.latch) assert.ok(['ctrl', 'alt', 'shift'].includes(k.latch));
  }
  // The symbols phone keyboards bury are all reachable.
  const more = K.ROW_MORE.map(k => k.text).filter(Boolean);
  for (const ch of ['|', '~', '/', '\\', '-', '`']) assert.ok(more.includes(ch), ch);
  // Held arrows and paging repeat; Esc and Enter do not.
  assert.ok(K.ROW_MAIN.find(k => k.label === '↑').repeat);
  assert.ok(!K.ROW_MAIN.find(k => k.label === 'Enter').repeat);
});

test('font size is clamped and survives garbage', () => {
  assert.equal(K.clampFont(14), 14);
  assert.equal(K.clampFont(2), K.FONT_MIN);
  assert.equal(K.clampFont(99), K.FONT_MAX);
  assert.equal(K.clampFont('18'), 18);
  assert.equal(K.clampFont('x'), K.FONT_DEFAULT);
  assert.equal(K.clampFont(undefined), K.FONT_DEFAULT);
  assert.equal(K.clampFont(13.6), 14);
});

test('a wide terminal shrinks to fit but never below the floor', () => {
  assert.equal(K.fitScale(800, 400), 1);
  assert.equal(K.fitScale(300, 600), 0.5);
  assert.equal(K.fitScale(100, 1000), 0.35);
  assert.equal(K.fitScale(100, 1000, 0.5), 0.5);
  assert.equal(K.fitScale(0, 600), 1);
  assert.equal(K.fitScale(300, 0), 1);
});

test('soft keyboard edits are mirrored as deletes and inserts', () => {
  assert.deepEqual(K.editsBetween('', 'e'), {deletes: 0, inserts: 'e'});
  assert.deepEqual(K.editsBetween('ech', 'echo'), {deletes: 0, inserts: 'o'});
  assert.deepEqual(K.editsBetween('echo', 'ech'), {deletes: 1, inserts: ''});
  assert.deepEqual(K.editsBetween('echo ', 'echo'), {deletes: 1, inserts: ''});
  // Autocorrect replaces the end of what was typed.
  assert.deepEqual(K.editsBetween('say ehco', 'say echo'), {deletes: 3, inserts: 'cho'});
  assert.deepEqual(K.editsBetween('abc', 'abc'), {deletes: 0, inserts: ''});
  assert.deepEqual(K.editsBetween('abc', ''), {deletes: 3, inserts: ''});
  // Code points, not UTF-16 units: an emoji is one deletion.
  assert.deepEqual(K.editsBetween('a\u{1F600}', 'a'), {deletes: 1, inserts: ''});
  assert.equal(K.editBytes('echo', 'ech'), '\x7f');
  assert.equal(K.editBytes('ehco', 'echo'), '\x7f\x7f\x7fcho');
  assert.equal(K.editBytes('', 'hello '), 'hello ');
});

test('the Copy buttons: the last lines of the text, without trailing blanks', () => {
  const t = 'a\nb\nc\nd\n\n\n';
  assert.equal(K.lastLines(t, 2), 'c\nd');
  assert.equal(K.lastLines(t, 100), 'a\nb\nc\nd');
  assert.equal(K.lastLines('', 5), '');
  assert.equal(K.lastLines('one', 1), 'one');
});

test('tap-to-select lines: first tap starts, second extends either way, third restarts', () => {
  let s = null;
  s = K.tapLine(s, 3);
  assert.deepEqual(K.selectedRange(s), {from: 3, to: 3});
  assert.equal(s.open, true);
  let down = K.tapLine(s, 6);
  assert.deepEqual(K.selectedRange(down), {from: 3, to: 6});
  assert.equal(down.open, false);
  let up = K.tapLine(s, 1);
  assert.deepEqual(K.selectedRange(up), {from: 1, to: 3});
  // A third tap starts a new selection at that line.
  const again = K.tapLine(down, 9);
  assert.deepEqual(K.selectedRange(again), {from: 9, to: 9});
  assert.equal(again.open, true);
  assert.equal(K.selectedRange(null), null);
});

test('the selected lines are what gets copied', () => {
  const lines = ['zero', 'one', 'two', 'three', 'four'];
  assert.equal(K.selectedText(lines, {anchor: 1, end: 3}), 'one\ntwo\nthree');
  assert.equal(K.selectedText(lines, {anchor: 3, end: 1}), 'one\ntwo\nthree');
  assert.equal(K.selectedText(lines, {anchor: 4, end: 4}), 'four');
  assert.equal(K.selectedText(lines, null), '');
  // A selection past the end is clipped, not an error.
  assert.equal(K.selectedText(lines, {anchor: 3, end: 99}), 'three\nfour');
});

test('terminal replies to a program\'s queries are never sent to Rex', () => {
  const replies = [
    '\x1b[12;40R', '\x1b[?62;4c', '\x1b[>0;276;0c', '\x1b[=1c', '\x1b[0n', '\x1b[?997;1n', '\x1b[?1;2$y', '\x1b[4$y',
    '\x1b[?0u', '\x1b[8;24;80t', '\x1bP>|XTerm(1)\x1b\\', '\x1bP1$r0m\x1b\\', '\x1b]11;rgb:0000/0000/0000\x07',
    '\x1b]10;rgb:ffff/ffff/ffff\x1b\\', '\x1b]52;c;aGk=\x07', '\x1b]lA title a program set\x1b\\',
  ];
  for (const r of replies) assert.equal(K.stripReplies(r), '', JSON.stringify(r));
  // A reply that carries text a program chose still goes, whatever the text says.
  assert.equal(K.stripReplies('\x1b]lrm -rf ~\r\x1b\\'), '');
  assert.equal(K.stripReplies('\x1bP1$rrm -rf ~\r\x1b\\'), '');
});

test('what a person types, pastes or does with the mouse is not a reply', () => {
  const real = ['ls -la\r', '\x1b[A', '\x1b[1;5C', '\x1b[15~', '\x1b[<0;10;5M', '\x1b[<0;10;5m', '\x1b[I', '\x1b[O',
    '\x1b[200~paste me\x1b[201~', 'héllo wörld ✓', '\x1bOP', '\x7f', '\x03', '\x1b[Z'];
  for (const t of real) assert.equal(K.stripReplies(t), t, JSON.stringify(t));
  assert.equal(K.stripReplies('ab\x1b[1;1Rcd'), 'abcd');
  assert.equal(K.stripReplies('\x1b[?62;4c\x1b[A'), '\x1b[A');
});

test('a touch drag scrolls history natively and a full-screen program like a wheel (feedback 2)', () => {
  // The shell's own history: the browser scrolls it.
  assert.equal(K.dragMode({altScreen: false, mouseTracking: false, scrollable: true}), 'native');
  assert.equal(K.dragMode({altScreen: false, mouseTracking: true, scrollable: true}), 'native');
  assert.equal(K.dragMode({altScreen: false, mouseTracking: false, scrollable: false}), 'native');
  // A full-screen program: wheel reports if it asked for the mouse, else Up/Down keys.
  assert.equal(K.dragMode({altScreen: true, mouseTracking: true, scrollable: false}), 'wheel');
  assert.equal(K.dragMode({altScreen: true, mouseTracking: false, scrollable: false}), 'keys');
  // Mouse on the main screen with nothing to scroll: the program gets the wheel.
  assert.equal(K.dragMode({altScreen: false, mouseTracking: true, scrollable: false}), 'wheel');
});

test('drag distance becomes whole rows, keeping the remainder', () => {
  assert.deepEqual(K.dragRows(40, 17), {rows: 2, rest: 6});
  assert.deepEqual(K.dragRows(-40, 17), {rows: -2, rest: -6});
  assert.deepEqual(K.dragRows(10, 17), {rows: 0, rest: 10});
  assert.equal(K.dragRows(34, 0).rows, 2);           // no row height yet: 17 px rows
});

test('scroll keys: finger down is Up (older), in the cursor-key mode the program asked for', () => {
  assert.equal(K.scrollKeys(2, false), '\x1b[A\x1b[A');
  assert.equal(K.scrollKeys(-1, false), '\x1b[B');
  assert.equal(K.scrollKeys(1, true), '\x1bOA');
  assert.equal(K.scrollKeys(-3, true), '\x1bOB'.repeat(3));
  assert.equal(K.scrollKeys(1000, false).length, 3 * 100);   // capped
  // Not mistaken for a reply and dropped.
  assert.equal(K.stripReplies(K.scrollKeys(2, true)), K.scrollKeys(2, true));
});

test('a paste loses ESC and the C1 controls, so it cannot end itself early (W1)', () => {
  // A pastejacked text: its own "end of paste", then a command and Enter.
  assert.equal(K.cleanPaste('\x1b[201~curl x|sh\r'), '[201~curl x|sh\r');
  assert.ok(!K.cleanPaste('a\x1b[201~b\x1b').includes('\x1b'));
  // The one-character CSI and the rest of C1.
  assert.equal(K.cleanPaste('\x9b201~rm -rf ~\r'), '201~rm -rf ~\r');
  assert.equal(K.cleanPaste('x\x80\x85\x90\x9c\x9fy'), 'xy');
  // Ordinary text, lines, tabs and letters just past C1 stay as they are.
  const plain = 'ls -la\nfor i in 1 2; do echo "$i"\tdone\r\nhéllo wörld ✓  é \u{1f600}';
  assert.equal(K.cleanPaste(plain), plain);
  assert.equal(K.cleanPaste(''), '');
});

test('paste and drop input types are pastes; typing is not', () => {
  for (const t of ['insertFromPaste', 'insertFromPasteAsQuotation', 'insertFromDrop', 'insertFromYank', 'insertReplacementText']) assert.ok(K.isPasteInput(t), t);
  for (const t of ['insertText', 'insertCompositionText', 'deleteContentBackward', 'insertLineBreak', undefined, '']) assert.ok(!K.isPasteInput(t), String(t));
});

test('the Copy view shows at most the last 5,000 lines and says when it cut (D2)', () => {
  assert.equal(K.COPY_MAX_LINES, 5000);
  const short = K.copyView('a\nb\nc', false);
  assert.deepEqual(short.lines, ['a', 'b', 'c']);
  assert.equal(short.cut, false); assert.equal(short.note, '');
  const long = Array.from({length: 12345}, (_, i) => 'line ' + i).join('\n');
  const v = K.copyView(long, false);
  assert.equal(v.lines.length, 5000); assert.equal(v.total, 12345); assert.equal(v.cut, true);
  assert.equal(v.lines[0], 'line 7345'); assert.equal(v.lines[4999], 'line 12344');
  assert.equal(v.note, 'Showing the last 5,000 of 12,345 lines.');
  // The bridge cut the history: say so, with how much is shown.
  assert.equal(K.copyView('a\nb', true).note, 'The history is longer than the bridge sends: showing its last 2 lines.');
  assert.equal(K.copyView(long, true).note, 'The history is longer than the bridge sends: showing its last 5,000 lines.');
  assert.equal(K.copyView('x\ny\nz', false, 2).note, 'Showing the last 2 of 3 lines.');
});

test('?term= chooses for one page load; the saved choice is the default (W2)', () => {
  assert.equal(K.pickTerm('xterm', 'wterm'), 'xterm');
  assert.equal(K.pickTerm('wterm', 'xterm'), 'wterm');
  assert.equal(K.pickTerm(null, 'xterm'), 'xterm');
  assert.equal(K.pickTerm(null, undefined), 'wterm');
  assert.equal(K.pickTerm('other', 'junk'), 'wterm');
});

test('?dbg=1 does nothing unless the bridge allows input diagnostics (W2)', () => {
  assert.equal(K.debugOn(true, {t: 'mode', debug: true}), true);
  assert.equal(K.debugOn(true, {t: 'mode'}), false);             // missing: off
  assert.equal(K.debugOn(true, {t: 'mode', debug: 'true'}), false);
  assert.equal(K.debugOn(true, {t: 'mode', debug: false}), false);
  assert.equal(K.debugOn(false, {t: 'mode', debug: true}), false);
  assert.equal(K.debugOn(true, null), false);
});

test('committed text is typed only when it looks like typing (P2)', () => {
  // Single characters and short words stay typed, including a lone Enter.
  for (const t of ['a', 'é', '\u{1f600}', 'hello ', 'git', '\r', '\n', '1234567890123456', '\u{1f600}'.repeat(16)]) assert.equal(K.commitIsPaste(t), false, JSON.stringify(t));
  assert.equal(K.commitIsPaste(''), false);
  // A line end with anything else, ESC or C1 anywhere, or longer than 16 characters goes the paste way.
  for (const t of ['ls\r', 'a\nb', '\r\n', 'curl x|sh\n', '\x1b', '\x1b[A', 'x\x9b', '\x9b', '\x85', '12345678901234567', '\u{1f600}'.repeat(17)])
    assert.equal(K.commitIsPaste(t), true, JSON.stringify(t));
  assert.equal(K.COMMIT_TYPE_MAX, 16);
});

test('a paste over 32 KB is refused before it is sent (P8)', () => {
  assert.equal(K.utf8Length('abc'), 3);
  assert.equal(K.utf8Length('é'), 2);
  assert.equal(K.utf8Length('✓'), 3);
  assert.equal(K.utf8Length('\u{1f600}'), 4);
  assert.equal(K.utf8Length('\ud800'), 3);                      // a lone surrogate is sent as U+FFFD
  assert.equal(K.pasteRefusal('x'.repeat(32 * 1024)), null);
  assert.equal(K.pasteRefusal('x'.repeat(32 * 1024 + 1)), 'Too long to paste: 33 KB; the limit is 32 KB');
  assert.equal(K.pasteRefusal('é'.repeat(20000)), 'Too long to paste: 40 KB; the limit is 32 KB');
  assert.equal(K.pasteRefusal('ls -la\nexit\n'), null);
  // Within 32 KB of text but over the 64 KB message once its control characters are escaped.
  assert.match(K.pasteRefusal('\x01'.repeat(30000)), /^Too long to paste: its control characters/);
});

test('the multi-line paste question shows the first 2,000 characters and the line count (P5)', () => {
  const short = K.pastePreview('echo a\necho b\n');
  assert.deepEqual(short, {shown: 'echo a\necho b\n', lines: 2, chars: 14, cut: false});
  assert.equal(K.pastePreview('a\r\nb\rc').lines, 3);
  assert.equal(K.pastePreview('one').lines, 1);
  assert.equal(K.pastePreview('\n').lines, 1);
  const long = Array.from({length: 1000}, (_, i) => 'line ' + i).join('\n');
  const v = K.pastePreview(long);
  assert.equal(K.PREVIEW_MAX_CHARS, 2000);
  assert.equal(v.cut, true); assert.equal(Array.from(v.shown).length, 2000); assert.ok(long.startsWith(v.shown));
  assert.equal(v.lines, 1000); assert.equal(v.chars, long.length);
  // Code points, not UTF-16 units: an emoji is not cut in half.
  assert.equal(K.pastePreview('\u{1f600}'.repeat(3), 2).shown, '\u{1f600}\u{1f600}');
});

test('program-set clipboard text loses control characters but keeps tabs and lines (P7)', () => {
  assert.equal(K.cleanClip('a\tb\nc'), 'a\tb\nc');
  assert.equal(K.cleanClip('line\r\nnext'), 'line\nnext');
  assert.equal(K.cleanClip('x\x1b[201~rm -rf ~\x07'), 'x[201~rm -rf ~');
  assert.equal(K.cleanClip('\x00\x01\x08\x0b\x0c\x1f\x7f\x80\x9b\x9fok'), 'ok');
  // Letters just past C1 stay.
  assert.equal(K.cleanClip('é\u00a0ü ✓ \u{1f600}'), 'é\u00a0ü ✓ \u{1f600}');
});

test('a refused open or closed acts only on the terminal the page shows (H3)', () => {
  const cur = {session: 's1', block: 'b2'};
  assert.equal(K.sameTerm(cur, {session: 's1', block: 'b2'}), true);
  assert.equal(K.sameTerm({session: 7, block: 9}, {session: '7', block: '9'}), true);
  assert.equal(K.sameTerm(cur, null), false);
  assert.equal(K.aboutTerm({t: 'closed', session: 's1', block: 'b2'}, cur), true);
  assert.equal(K.aboutTerm({t: 'closed', block: 'b2'}, cur), true);                // block only: compared alone
  assert.equal(K.aboutTerm({t: 'closed', block: 'b1'}, cur), false);               // late, for the one left
  assert.equal(K.aboutTerm({t: 'closed', session: 's0', block: 'b2'}, cur), false);
  assert.equal(K.aboutTerm({t: 'closed', block: 'b2'}, null), false);              // nothing shown
  // An older bridge names no terminal: as before, taken as about the current one.
  assert.equal(K.aboutTerm({t: 'error', for: 'open', msg: 'x'}, cur), true);
  assert.equal(K.aboutTerm({t: 'error', for: 'open', session: null, block: null}, cur), true);
  assert.equal(K.openRefusal({for: 'open', session: 's1', block: 'b1', msg: 'no such terminal'}, cur, false), 'ignore');
  assert.equal(K.openRefusal({for: 'open', session: 's1', block: 'b1', transient: true}, cur, true), 'ignore');
  assert.equal(K.openRefusal({for: 'open', session: 's1', block: 'b2', msg: 'no such terminal'}, cur, false), 'clear');
  assert.equal(K.openRefusal({for: 'open', msg: 'old bridge'}, cur, false), 'clear');
});

test('a transient or rate refusal of a restored terminal is retried with backoff (H4)', () => {
  const cur = {session: 's1', block: 'b2'}, me = {for: 'open', session: 's1', block: 'b2'};
  assert.equal(K.openRefusal({...me, transient: true}, cur, true), 'retry');
  assert.equal(K.openRefusal({...me, rate: true}, cur, true), 'retry');
  assert.equal(K.openRefusal({for: 'open', rate: true}, cur, true), 'retry');       // an older bridge's rate refusal
  // Not transient: the terminal is not there; stop and clear.
  assert.equal(K.openRefusal(me, cur, true), 'clear');
  assert.equal(K.openRefusal({...me, transient: false}, cur, true), 'clear');
  assert.equal(K.openRefusal({...me, transient: 'true'}, cur, true), 'clear');
  // Chosen by the person just now (not a restore): cleared at once, with the reason.
  assert.equal(K.openRefusal({...me, transient: true}, cur, false), 'clear');
  assert.equal(K.openRefusal({...me, rate: true}, cur, false), 'clear');
  assert.deepEqual([0, 1, 2, 3, 4, 5, 50].map(K.openRetryDelay), [1000, 2000, 4000, 8000, 10000, 10000, 10000]);
  assert.equal(K.openRetryDelay(-1), 1000);
  assert.equal(K.openRetryDelay(undefined), 1000);
  assert.equal(K.OPEN_RETRY_MAX_MS, 10000);
});

test('queued uploads for a terminal the page has left are dropped, not sent to the new one (H6)', () => {
  const a = {session: 's1', block: 'b1'}, b = {session: 's1', block: 'b2'};
  const q = [{file: 'one', term: a}, {file: 'two', term: a}, {file: 'three', term: b}];
  const onB = K.partitionUploads(q, b);
  assert.deepEqual(onB.keep.map(u => u.file), ['three']);
  assert.deepEqual(onB.drop.map(u => u.file), ['one', 'two']);
  const onA = K.partitionUploads(q, a);
  assert.deepEqual(onA.keep.map(u => u.file), ['one', 'two']);
  assert.deepEqual(onA.drop.map(u => u.file), ['three']);
  assert.deepEqual(K.partitionUploads(q, null).keep, []);
  assert.deepEqual(K.partitionUploads([{file: 'x'}], a), {keep: [], drop: [{file: 'x'}]});   // no terminal: never sent
  assert.deepEqual(K.partitionUploads([], a), {keep: [], drop: []});
});

// ---- E4, M2: in token mode, one connection attempt per request ----
// Runs events through linkStep from the page's start, as app.js does, and returns each step's result.
function run(tokenMode, events) {
  let s = K.LINK_START;
  return events.map(ev => { const r = K.linkStep(s, ev, tokenMode); s = {phase: r.phase, why: r.why}; return r; });
}

test('token mode: page load connects once; a drop waits for a tap', () => {
  const r = run(true, ['open', 'close']);
  assert.deepEqual(r[0], {phase: 'open', why: null, act: 'none'});
  assert.deepEqual(r[1], {phase: 'waiting', why: 'dropped', act: 'none'});
  assert.equal(K.waitText(r[1].why), 'Disconnected. Restart the SSH tunnel, then reconnect.');
});

test('token mode: a tap makes one attempt; if it fails the page waits again, no timer armed', () => {
  const r = run(true, ['open', 'close', 'ask', 'close']);
  assert.deepEqual(r[2], {phase: 'trying', why: null, act: 'connect'});
  assert.deepEqual(r[3], {phase: 'waiting', why: 'failed', act: 'none'});        // not 'retry'
  assert.equal(K.waitText(r[3].why), 'Could not connect. Is the SSH tunnel running?');
  // A page load that cannot connect at all waits the same way.
  assert.deepEqual(run(true, ['close'])[0], {phase: 'waiting', why: 'failed', act: 'none'});
  // Taps after failures: each one attempt, never a retry.
  const many = run(true, ['close', 'ask', 'close', 'ask', 'close']);
  assert.ok(many.every(x => x.act !== 'retry'));
  assert.deepEqual(many.map(x => x.act), ['none', 'connect', 'none', 'connect', 'none']);
});

test('token mode: a tap, an open, then a drop waits again', () => {
  const r = run(true, ['close', 'ask', 'open', 'close']);
  assert.deepEqual(r[2], {phase: 'open', why: null, act: 'none'});
  assert.deepEqual(r[3], {phase: 'waiting', why: 'dropped', act: 'none'});
  // A late close while waiting changes nothing.
  assert.deepEqual(run(true, ['open', 'close', 'close'])[2], {phase: 'waiting', why: 'dropped', act: 'none'});
});

test('token mode: a first message that is not rweb\'s closes and waits', () => {
  const r = run(true, ['open', 'foreign', 'close']);
  assert.deepEqual(r[1], {phase: 'waiting', why: 'foreign', act: 'none'});
  assert.deepEqual(r[2], {phase: 'waiting', why: 'foreign', act: 'none'});
  assert.equal(K.waitText('foreign'), 'This does not look like rweb. Check the SSH tunnel.');
});

test('Tailscale mode reconnects by itself, as before', () => {
  for (const mode of [false, undefined, 'yes']) {
    const r = run(mode, ['open', 'close', 'close', 'open', 'close']);
    assert.deepEqual(r.map(x => x.act), ['none', 'retry', 'retry', 'none', 'retry']);
    assert.ok(r.every(x => x.phase !== 'waiting'));
  }
  assert.equal(run(false, ['ask'])[0].act, 'connect');                // the menu's Reconnect
  assert.equal(run(false, ['open', 'foreign'])[1].phase, 'open');      // the check is token mode's only
});

test('token mode: the first message must be a well-formed rweb mode message', () => {
  const ok = {t: 'mode', observe: false, locked: false, rex_up: true, download: false, upload: false, debug: false, auth: 'token'};
  assert.equal(K.looksLikeRweb(JSON.stringify(ok)), true);
  assert.equal(K.looksLikeRweb(JSON.stringify({...ok, auth: undefined})), false);      // a Tailscale-mode bridge
  assert.equal(K.looksLikeRweb(JSON.stringify({...ok, auth: 'tailscale'})), false);
  assert.equal(K.looksLikeRweb(JSON.stringify({...ok, t: 'tree'})), false);
  assert.equal(K.looksLikeRweb(JSON.stringify({...ok, rex_up: 'yes'})), false);
  assert.equal(K.looksLikeRweb(JSON.stringify({t: 'mode', auth: 'token'})), false);
  assert.equal(K.looksLikeRweb('HTTP/1.1 200 OK'), false);
  assert.equal(K.looksLikeRweb('[]'), false);
  assert.equal(K.looksLikeRweb('null'), false);
  assert.equal(K.looksLikeRweb(new ArrayBuffer(4)), false);
  assert.equal(K.looksLikeRweb(undefined), false);
});

test('token mode is known from the page address before any connection', () => {
  assert.equal(K.tokenModeFromPath('/s/AbC-_09/'), true);
  assert.equal(K.tokenModeFromPath('/s/AbC/ws'), true);
  assert.equal(K.tokenModeFromPath('/'), false);
  assert.equal(K.tokenModeFromPath('/secret/'), false);
  assert.equal(K.tokenModeFromPath('/x/s/abc/'), false);
});

test('token mode comes from the mode message and stays', () => {
  assert.equal(K.tokenModeFrom(false, {t: 'mode', auth: 'token'}), true);
  assert.equal(K.tokenModeFrom(false, {t: 'mode'}), false);
  assert.equal(K.tokenModeFrom(false, {t: 'mode', auth: 'tailscale'}), false);
  assert.equal(K.tokenModeFrom(false, null), false);
  // A later mode message without `auth` (whatever answered a reconnect) does not undo it.
  assert.equal(K.tokenModeFrom(true, {t: 'mode'}), true);
  assert.equal(K.tokenModeFrom(true, null), true);
});

// ---- P6: the token form ----
const L = createRequire(import.meta.url)('../../src/bridge/web/login.js');
const ORIGIN = 'http://127.0.0.1:7700';

test('the token form takes rweb tokens and trims a pasted one', () => {
  assert.deepEqual(L.cleanToken('  abcDEF0123-_xyz \n'), {token: 'abcDEF0123-_xyz'});
  assert.ok(L.cleanToken('').msg);
  assert.ok(L.cleanToken('   ').msg);
  assert.ok(L.cleanToken(undefined).msg);
  // Nothing a header could not carry, or that rweb never issues, is sent.
  for (const bad of ['a b', 'tok;en', 'tök', 'a\r\nX-Evil: 1', 'a/b', '🙂']) assert.ok(L.cleanToken(bad).msg, bad);
});

test('the token form follows only a redirect to this origin\'s page', () => {
  assert.deepEqual(L.loginResult(200, ORIGIN + '/s/abc123/', ORIGIN), {go: ORIGIN + '/s/abc123/'});
  assert.deepEqual(L.loginResult(200, ORIGIN + '/s/a-b_C/?x=1#y', ORIGIN), {go: ORIGIN + '/s/a-b_C/'});
  // Not the page: the login page again, another path, another origin, an unparsable address.
  for (const url of [ORIGIN + '/', ORIGIN + '/s/abc', ORIGIN + '/s/abc/ws', ORIGIN + '/s//', ORIGIN + '/x/s/abc/',
    'http://127.0.0.1:7701/s/abc/', 'https://127.0.0.1:7700/s/abc/', 'http://evil.example/s/abc/', '', 'not a url']) {
    const r = L.loginResult(200, url, ORIGIN);
    assert.equal(r.go, undefined, url);
    assert.ok(r.msg, url);
  }
});

test('the token form says why a token was refused', () => {
  assert.deepEqual(L.loginResult(403, ORIGIN + '/', ORIGIN), {msg: 'Wrong token'});
  assert.deepEqual(L.loginResult(429, ORIGIN + '/', ORIGIN), {msg: 'Too many attempts; wait a minute'});
  assert.match(L.loginResult(500, ORIGIN + '/', ORIGIN).msg, /HTTP 500/);
  assert.equal(L.loginResult(0, '', ORIGIN).go, undefined);
});

// The form itself, run as login.html runs it (a plain script), with a stand-in page and fetch.
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
const LOGIN_SRC = readFileSync(new URL('../../src/bridge/web/login.js', import.meta.url), 'utf8');
function loginPage(answer) {
  const els = {
    token: {value: '', focused: 0, focus() { this.focused++; }},
    'login-msg': {textContent: ''},
  };
  const button = {disabled: false};
  let onSubmit = null;
  els.login = {addEventListener(ev, f) { if (ev === 'submit') onSubmit = f; }, querySelector: () => button};
  const calls = [], replaced = [], logged = [];
  const ctx = {
    document: {getElementById: id => els[id] || null},
    location: {origin: ORIGIN, replace: u => replaced.push(u)},
    fetch: async (url, opts) => { calls.push({url, opts}); return answer(url, opts); },
    console: new Proxy({}, {get: () => (...a) => logged.push(a)}),
    URL,
  };
  ctx.window = ctx;
  vm.runInNewContext(LOGIN_SRC, ctx);
  return {els, button, calls, replaced, logged, ctx,
    async submit(value) { els.token.value = value; let prevented = false; await onSubmit({preventDefault() { prevented = true; }}); return prevented; }};
}

test('the token form sends the token once, in a header, and opens the page', async () => {
  const p = loginPage(async () => ({status: 200, url: ORIGIN + '/s/abc123/'}));
  assert.ok(await p.submit('tok-123_abcdefghijklmnop'));
  assert.equal(p.calls.length, 1);
  const {url, opts} = p.calls[0];
  assert.equal(url, '/');
  assert.deepEqual({...opts.headers}, {'rweb-token': 'tok-123_abcdefghijklmnop'});
  assert.equal(opts.redirect, 'follow');
  assert.equal(opts.credentials, 'same-origin');
  assert.equal(p.els.token.value, '');                       // cleared
  assert.deepEqual(p.replaced, [ORIGIN + '/s/abc123/']);     // no token in the address
  assert.deepEqual(p.logged, []);
  assert.ok(!JSON.stringify(p.replaced).includes('tok-123'));
});

test('the token form shows refusals and keeps no token', async () => {
  for (const [status, text] of [[403, 'Wrong token'], [429, 'Too many attempts; wait a minute']]) {
    const p = loginPage(async () => ({status, url: ORIGIN + '/'}));
    await p.submit('tok-123_abcdefghijklmnop');
    assert.equal(p.els['login-msg'].textContent, text);
    assert.equal(p.els.token.value, '');
    assert.equal(p.button.disabled, false);
    assert.deepEqual(p.replaced, []);
    assert.deepEqual(p.logged, []);
  }
  // A network failure, and a token rweb never issues (nothing sent).
  const down = loginPage(async () => { throw new TypeError('Failed to fetch'); });
  await down.submit('tok-123_abcdefghijklmnop');
  assert.equal(down.els['login-msg'].textContent, 'Could not reach rweb');
  assert.equal(down.button.disabled, false);
  const odd = loginPage(async () => { throw new Error('must not be called'); });
  await odd.submit('not a token');
  assert.equal(odd.calls.length, 0);
  assert.equal(odd.els.token.value, '');
  assert.match(odd.els['login-msg'].textContent, /Wrong token/);
});

test('what waits is held with the view it was asked in, and sent only if that view is still on screen', () => {
  const a = {session: 's1', block: 'b1'}, b = {session: 's1', block: 'b2'};
  assert.equal(K.holdView(null, 3), null);
  const held = K.holdView(a, 3);
  assert.deepEqual(held, {session: 's1', block: 'b1', gen: 3});
  assert.equal(K.stillView(held, a, 3), true);
  // Another terminal is on screen when the clipboard answers: not sent.
  assert.equal(K.stillView(held, b, 4), false);
  // Away and back to the same terminal is another view: what was asked before is not sent.
  assert.equal(K.stillView(held, a, 5), false);
  // No terminal on screen, or nothing held.
  assert.equal(K.stillView(held, null, 4), false);
  assert.equal(K.stillView(null, a, 3), false);
  // The held view is a copy: a later change to the page's own object does not move it.
  const cur = {session: 's1', block: 'b1'}, h2 = K.holdView(cur, 1);
  cur.block = 'b9';
  assert.equal(h2.block, 'b1');
});

test('a paste that fits still fits with its terminal named', () => {
  // The largest paste of the worst characters to encode that the limit lets through leaves room for
  // the two longest names.
  const d = '\x01'.repeat(10000);
  assert.equal(K.pasteRefusal(d), null);
  const msg = JSON.stringify({t: 'paste', d, force: true, session: 's'.repeat(200), block: 'b'.repeat(200)});
  assert.ok(K.utf8Length(msg) <= K.MESSAGE_MAX_BYTES);
});
