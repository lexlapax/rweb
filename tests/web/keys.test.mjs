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
  assert.deepEqual(main, ['Esc', 'Tab', '^C', 'Ctrl', 'Alt', 'Shift', 'Enter', '↑', '↓']);
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
