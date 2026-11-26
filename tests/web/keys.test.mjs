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
  for (const t of ['insertFromPaste', 'insertFromPasteAsQuotation', 'insertFromDrop']) assert.ok(K.isPasteInput(t), t);
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
