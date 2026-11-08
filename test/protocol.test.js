'use strict';
// The tests of relay/protocol.js: every message reads back as it was written, and anything that isn't exactly a message is refused.
// Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const P = require('../relay/protocol');

const secret = Buffer.from('0123456789abcdef', 'latin1');
const code = Buffer.from('ABCD2345', 'latin1');

test('every type reads back as it was written', () => {
  for (const type of Object.values(P.TYPE)) {
    const bytes = P.encode({ type, secret, code, port: 27501, number: 3 });
    assert.strictEqual(bytes.length, P.kMessageBytes);
    const m = P.decode(bytes);
    assert.ok(m, `type ${type} reads back`);
    assert.strictEqual(m.type, type);
    assert.ok(m.secret.equals(secret));
    assert.ok(m.code.equals(code));
    assert.strictEqual(m.port, 27501);
    assert.strictEqual(m.number, 3);
  }
});

test('a message with no secret or code reads them back as null', () => {
  const m = P.decode(P.encode({ type: P.TYPE.HOST_OPEN }));
  assert.strictEqual(m.secret, null);
  assert.strictEqual(m.code, null);
  assert.strictEqual(m.port, 0);
});

test('a message is the same size whatever its type, so no answer is bigger than its question', () => {
  const sizes = new Set(Object.values(P.TYPE).map((type) => P.encode({ type }).length));
  assert.deepStrictEqual([...sizes], [P.kMessageBytes]);
});

test('anything that is not exactly a message is not one', () => {
  const good = P.encode({ type: P.TYPE.JOIN, code });
  assert.ok(P.decode(good));

  assert.strictEqual(P.decode(good.subarray(0, 63)), null, 'one byte short');
  assert.strictEqual(P.decode(Buffer.concat([good, Buffer.alloc(1)])), null, 'one byte over');
  assert.strictEqual(P.decode(Buffer.alloc(0)), null, 'nothing');
  assert.strictEqual(P.decode('AVPR'), null, 'not bytes at all');

  const change = (at, value) => { const b = Buffer.from(good); b[at] = value; return P.decode(b); };
  assert.strictEqual(change(0, 0x41 + 1), null, 'the wrong magic');
  assert.strictEqual(change(4, 2), null, 'another version');
  assert.strictEqual(change(5, 0), null, 'no type');
  assert.strictEqual(change(5, 99), null, 'an unknown type');
  assert.strictEqual(change(6, 1), null, 'a reserved byte not 0 (6)');
  assert.strictEqual(change(7, 1), null, 'a reserved byte not 0 (7)');
  assert.strictEqual(change(36, 1), null, 'the padding not 0 (36)');
  assert.strictEqual(change(63, 1), null, 'the padding not 0 (63)');
  assert.strictEqual(change(24, 0x30), null, 'a code with a 0 in it, which no code has');
  assert.strictEqual(change(31, 0), null, 'a code with a 0 byte at its end');
});

test('a code is only ever 8 of the code letters', () => {
  assert.ok(P.isCode(Buffer.from('23456789', 'latin1')));
  assert.ok(!P.isCode(Buffer.from('ABCDEFGI', 'latin1')), 'I is not a code letter');
  assert.ok(!P.isCode(Buffer.from('abcdefgh', 'latin1')), 'small letters are not');
  assert.ok(!P.isCode(Buffer.from('ABCDEFG', 'latin1')), '7 letters are not a code');
  assert.ok(!P.isCode('ABCDEFGH'), 'text is not bytes');
  assert.strictEqual(P.kCodeLetters.length, 32);
  assert.ok(!/[01IO]/.test(P.kCodeLetters), 'no letters that look like another');
});

test('the relay\'s own code cannot write a wrong message', () => {
  assert.throws(() => P.encode({ type: 99 }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, secret: Buffer.alloc(15) }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, code: Buffer.from('ABCDEFGI', 'latin1') }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, port: 65536 }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, number: -1 }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, port: 1.5 }));
});

test('what decode gives back holds copies, not the packet it came in', () => {
  const bytes = P.encode({ type: P.TYPE.HOST_KEEP, secret });
  const m = P.decode(bytes);
  bytes.fill(0);
  assert.ok(m.secret.equals(secret));
});
