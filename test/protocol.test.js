'use strict';
// The tests of relay/protocol.js and relay/pass.js: every message reads back as it was written, anything that isn't exactly a message is
// refused, and a pass is the HMAC PROTOCOL.md section 3 writes. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const P = require('../relay/protocol');
const { makePass, isRegion } = require('../relay/pass');

const secret = Buffer.from('0123456789abcdef', 'latin1');
const code = Buffer.from('ABCD2345', 'latin1');
const pass = Buffer.from('fedcba9876543210', 'latin1');
const passTime = 1794268800;   // 2026-11-11, as whole seconds

// Every field a type uses, filled in; the rest left out
function full(type) {
  const uses = P.USES[type];
  return {
    type,
    ...(uses.includes('secret') ? { secret } : {}),
    ...(uses.includes('code') ? { code } : {}),
    ...(uses.includes('port') ? { port: 27501 } : {}),
    ...(uses.includes('number') ? { number: 3 } : {}),
    ...(uses.includes('pass') ? { pass, passTime } : {}),
  };
}

test('every type reads back as it was written, each with the fields it uses', () => {
  assert.strictEqual(Object.keys(P.TYPE).length, 15, 'the 15 types of PROTOCOL.md section 2');

  for (const type of Object.values(P.TYPE)) {
    const fields = full(type);
    const bytes = P.encode(fields);
    assert.strictEqual(bytes.length, P.kMessageBytes);
    const m = P.decode(bytes);
    assert.ok(m, `type ${type} reads back`);
    assert.strictEqual(m.type, type);
    assert.deepStrictEqual(m.secret, fields.secret || null);
    assert.deepStrictEqual(m.code, fields.code || null);
    assert.strictEqual(m.port, fields.port || 0);
    assert.strictEqual(m.number, fields.number || 0);
    assert.deepStrictEqual(m.pass, fields.pass || null);
    assert.strictEqual(m.passTime, fields.passTime || 0);
  }
});

test('which fields each type uses is PROTOCOL.md section 2\'s table, row for row', () => {
  const T = P.TYPE;
  assert.deepStrictEqual(P.USES, {
    [T.HOST_OPEN]: ['secret'],
    [T.HOST_OPENED]: ['secret', 'code', 'pass'],
    [T.HOST_KEEP]: ['secret'],
    [T.HOST_KEPT]: ['secret', 'number', 'pass'],
    [T.HOST_CLOSE]: ['secret'],
    [T.JOIN]: ['secret', 'code'],
    [T.JOIN_PORT]: ['secret', 'code', 'port'],
    [T.NEW_JOINER]: ['secret', 'port'],
    [T.HOST_HELLO]: ['secret', 'port'],
    [T.JOINER_HELLO]: ['secret'],
    [T.READY]: ['secret', 'port'],
    [T.REFUSED]: ['number'],
    [T.COOKIE]: ['secret'],
    [T.ECHO]: ['secret', 'number'],
    [T.ECHO_BACK]: ['secret', 'number'],
  });
  assert.deepStrictEqual([T.ECHO, T.ECHO_BACK], [14, 15]);
});

test('the fields sit where PROTOCOL.md says, little-endian', () => {
  const b = P.encode({ type: P.TYPE.HOST_KEPT, secret, number: 0x0102, pass, passTime: 0x0102030405 });
  assert.strictEqual(b.subarray(0, 4).toString('latin1'), 'AVPR');
  assert.deepStrictEqual([b[4], b[5], b[6], b[7]], [1, P.TYPE.HOST_KEPT, 0, 0]);
  assert.ok(b.subarray(8, 24).equals(secret));
  assert.deepStrictEqual([b[34], b[35]], [0x02, 0x01]);
  assert.ok(b.subarray(36, 52).equals(pass));
  assert.deepStrictEqual([...b.subarray(52, 60)], [0x05, 0x04, 0x03, 0x02, 0x01, 0, 0, 0]);
  assert.ok(b.subarray(60, 64).equals(Buffer.alloc(4)));
});

test('a message with no secret or code reads them back as null', () => {
  const m = P.decode(P.encode({ type: P.TYPE.HOST_OPEN }));
  assert.strictEqual(m.secret, null);
  assert.strictEqual(m.code, null);
  assert.strictEqual(m.port, 0);
  assert.strictEqual(m.pass, null);
});

test('a message is the same size whatever its type, so no answer is bigger than its question', () => {
  const sizes = new Set(Object.values(P.TYPE).map((type) => P.encode(full(type)).length));
  assert.deepStrictEqual([...sizes], [P.kMessageBytes]);
});

test('anything that is not exactly a message is not one', () => {
  const good = P.encode({ type: P.TYPE.JOIN, code });
  assert.ok(P.decode(good));

  assert.strictEqual(P.decode(good.subarray(0, 63)), null, 'one byte short');
  assert.strictEqual(P.decode(Buffer.concat([good, Buffer.alloc(1)])), null, 'one byte over');
  assert.strictEqual(P.decode(Buffer.alloc(0)), null, 'nothing');
  assert.strictEqual(P.decode('AVPR'), null, 'not bytes at all');

  const change = (at, value, from = good) => { const b = Buffer.from(from); b[at] = value; return P.decode(b); };
  assert.strictEqual(change(0, 0x41 + 1), null, 'the wrong magic');
  assert.strictEqual(change(4, 2), null, 'another version');
  assert.strictEqual(change(5, 0), null, 'no type');
  assert.strictEqual(change(5, 16), null, 'the type after the last');
  assert.strictEqual(change(5, 99), null, 'an unknown type');
  assert.strictEqual(change(6, 1), null, 'a reserved byte not 0 (6)');
  assert.strictEqual(change(7, 1), null, 'a reserved byte not 0 (7)');
  assert.strictEqual(change(60, 1), null, 'the padding not 0 (60)');
  assert.strictEqual(change(63, 1), null, 'the padding not 0 (63)');
  assert.strictEqual(change(24, 0x30), null, 'a code with a 0 in it, which no code has');
  assert.strictEqual(change(31, 0), null, 'a code with a 0 byte at its end');

  const kept = P.encode({ type: P.TYPE.HOST_KEPT, secret, pass, passTime: 1 });
  const big = Buffer.from(kept);
  big.writeBigUInt64LE(BigInt(Number.MAX_SAFE_INTEGER) + 1n, 52);
  assert.strictEqual(P.decode(big), null, 'a pass time past the most a number holds exactly');
  big.writeBigUInt64LE(BigInt(Number.MAX_SAFE_INTEGER), 52);
  assert.ok(P.decode(big), 'and the most it holds is a message');
});

test('a field its type doesn\'t use, not 0, makes it no message', () => {
  // One byte of each field, in turn, on every type that doesn't use that field
  const at = { secret: 8, code: 24, port: 32, number: 34, pass: 36, passTime: 52 };
  const usedBy = { secret: 'secret', code: 'code', port: 'port', number: 'number', pass: 'pass', passTime: 'pass' };
  let tried = 0;

  for (const type of Object.values(P.TYPE)) {
    const bytes = P.encode(full(type));

    for (const field of Object.keys(at)) {
      if (!P.USES[type].includes(usedBy[field])) {
        const b = Buffer.from(bytes);
        if (field === 'code') b.write('ABCD2345', at.code, 'latin1'); else b[at[field]] = 1;
        assert.strictEqual(P.decode(b), null, `type ${type} with a ${field}`);
        tried++;
      }
    }
  }

  assert.ok(tried > 40, `${tried} tried`);
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
  assert.throws(() => P.encode({ type: P.TYPE.JOIN_PORT, port: 65536 }));
  assert.throws(() => P.encode({ type: P.TYPE.REFUSED, number: -1 }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN_PORT, port: 1.5 }));
  assert.throws(() => P.encode({ type: P.TYPE.HOST_KEPT, pass: Buffer.alloc(15) }));
  assert.throws(() => P.encode({ type: P.TYPE.HOST_KEPT, passTime: -1 }));
  assert.throws(() => P.encode({ type: P.TYPE.HOST_KEPT, passTime: Number.MAX_SAFE_INTEGER + 1 }));
  assert.throws(() => P.encode({ type: P.TYPE.JOIN, port: 1 }), 'a field JOIN doesn\'t use');
  assert.throws(() => P.encode({ type: P.TYPE.HOST_KEEP, pass }), 'a pass on a HOST_KEEP');
  assert.throws(() => P.encode({ type: P.TYPE.ECHO_BACK, code }), 'a code on an ECHO_BACK');
});

test('what decode gives back holds copies, not the packet it came in', () => {
  const bytes = P.encode({ type: P.TYPE.HOST_KEPT, secret, pass, passTime });
  const m = P.decode(bytes);
  bytes.fill(0);
  assert.ok(m.secret.equals(secret));
  assert.ok(m.pass.equals(pass));
});

test('a pass is the HMAC PROTOCOL.md section 3 writes, byte for byte', () => {
  const key = Buffer.alloc(32, 7);
  const time = Buffer.alloc(8);
  time.writeBigUInt64LE(BigInt(passTime));
  const what = Buffer.concat([Buffer.from('AVPX-PASS-1', 'latin1'), Buffer.from('virginia', 'latin1'), Buffer.from([0]), code, time]);
  const want = crypto.createHmac('sha256', key).update(what).digest().subarray(0, 16);
  assert.ok(makePass(key, 'virginia', code, passTime).equals(want));

  assert.ok(!makePass(key, 'paris', code, passTime).equals(want), 'another region, another pass');
  assert.ok(!makePass(key, 'virginia', Buffer.from('ABCD2346', 'latin1'), passTime).equals(want), 'another code');
  assert.ok(!makePass(key, 'virginia', code, passTime + 1).equals(want), 'another second');
  assert.ok(!makePass(Buffer.alloc(32, 8), 'virginia', code, passTime).equals(want), 'another key');

  assert.throws(() => makePass(Buffer.alloc(31), 'virginia', code, passTime), 'a key that isn\'t 32 bytes');
  assert.throws(() => makePass(key, 'Virginia', code, passTime), 'a region with a capital');
  assert.throws(() => makePass(key, 'virginia', code, 1.5), 'a fraction of a second');
});

test('a region is 1 to 16 small letters, digits and -', () => {
  for (const good of ['virginia', 'saopaulo', 'paris', 'a', 'us-east-1', 'x'.repeat(16)]) assert.ok(isRegion(good), good);
  for (const bad of ['', 'x'.repeat(17), 'Paris', 'sao paulo', 'sao_paulo', 'paris\n', 'vir.ginia', 7, null]) assert.ok(!isRegion(bad), String(bad));
});
