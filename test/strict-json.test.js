'use strict';
// The tests of list/strict-json.js: it takes exactly what PROTOCOL.md section 4 ("How a body is read") says, refuses everything else,
// and agrees with JSON.parse on every body it takes. Written 2026-11-08 by Melanikus for AVPx Dedicated Server.
const test = require('node:test');
const assert = require('node:assert');
const { readObject } = require('../list/strict-json');
const { seededRandom } = require('../support/seeded-random');

const read = (text) => readObject(Buffer.from(text, 'latin1'));
const BS = String.fromCharCode(92);   // a backslash, written as a number so the cases below read plainly
const Q = String.fromCharCode(34);

test('it takes a flat object of strings and whole numbers, with JSON\'s whitespace', () => {
  assert.deepStrictEqual({ ...read('{"a":"b","n":7}') }, { a: 'b', n: 7 });
  assert.deepStrictEqual({ ...read(' \t\r\n{ "a" : "b" ,\n "n" : 0 }\r\n ') }, { a: 'b', n: 0 });
  assert.deepStrictEqual({ ...read('{}') }, {});
  assert.deepStrictEqual({ ...read(`{"q":"${BS}${Q}${BS}${BS}"}`) }, { q: `${Q}${BS}` }, 'the two escapes');
  assert.strictEqual(read('{"n":9007199254740991}').n, 9007199254740991, 'the most a number holds exactly');
  const proto = read('{"__proto__":"x"}');
  assert.strictEqual(Object.getPrototypeOf(proto), null, 'no prototype');
  assert.strictEqual(proto.__proto__, 'x', 'so "__proto__" is only a key');
});

test('it refuses everything else', () => {
  const refused = (text, why) => assert.strictEqual(read(text), null, why);
  refused('{"a":1,"a":2}', 'a key twice');
  refused('{"a":"b","a":"b"}', 'a key twice, the same both times');
  refused(`{"a":"${BS}u0041"}`, 'a \\u escape');
  refused(`{"a":"${BS}n"}`, 'a \\n escape');
  refused(`{"a":"${BS}/"}`, 'a \\/ escape');
  refused(`{"a":"${BS}"}`, 'a backslash at the end of a string');
  refused('{"a":1.0}', 'a fraction, even .0');
  refused('{"a":1e0}', 'an exponent');
  refused('{"a":-1}', 'a minus');
  refused('{"a":+1}', 'a plus');
  refused('{"a":01}', 'a leading 0');
  refused('{"a":9007199254740992}', 'past the most a number holds exactly');
  refused('{"a":12345678901234567}', '17 digits');
  refused('{"a":{"b":1}}', 'an object inside');
  refused('{"a":[1]}', 'a list inside');
  refused('{"a":true}', 'true');
  refused('{"a":null}', 'null');
  refused('{"a":"x\ty"}', 'a tab inside a string');
  refused('{"a":"x\ny"}', 'a line break inside a string');
  refused(`{"a":"caf${String.fromCharCode(0xe9)}"}`, 'a byte past ASCII');
  refused(`{"a":"${String.fromCharCode(0x7f)}"}`, 'DEL');
  refused('{"a":1,}', 'a comma at the end');
  refused('{,"a":1}', 'a comma at the start');
  refused('{"a" 1}', 'no colon');
  refused('{"a":1 "b":2}', 'no comma');
  refused('{a:1}', 'a key without quotes');
  refused('{"a":\'b\'}', 'single quotes');
  refused('{"a":1}x', 'something after the object');
  refused('{"a":1}{}', 'a second object');
  refused('{"a":1', 'no closing brace');
  refused('{"a":"b', 'no closing quote');
  refused('[]', 'a list');
  refused('"a"', 'a string');
  refused('7', 'a number');
  refused('', 'nothing');
  refused('   ', 'only spaces');
  refused(`${String.fromCharCode(0xef, 0xbb, 0xbf)}{}`, 'a byte-order mark before it');
  refused('{"a":1}\f', 'a form feed, which JSON doesn\'t count as whitespace');
  assert.strictEqual(readObject('{"a":1}'), null, 'text, not bytes');
});

test('on every body it takes, it reads the same as JSON.parse', () => {
  const random = seededRandom(21);
  const letters = `abcxyz 019${Q}${BS}!~`;
  for (let i = 0; i < 2000; i++) {
    const r = random(16);
    const keys = new Set();
    const parts = [];
    for (let k = 0; k < r[0] % 6; k++) {
      let key = '';
      for (let c = 0; c < 1 + (r[k + 1] % 5); c++) key += letters[(r[k + c + 2] + c) % letters.length];
      if (keys.has(key)) continue;
      keys.add(key);
      const value = r[k + 8] % 2 ? r[k + 9] * 1000 + r[k + 10] : key.split('').reverse().join('');
      parts.push(`${JSON.stringify(key)}:${JSON.stringify(value)}`);
    }
    const text = `{${parts.join(',')}}`;
    assert.deepStrictEqual({ ...read(text) }, JSON.parse(text), text);
  }
});

test('nothing a body holds can throw out of it', () => {
  const random = seededRandom(22);
  for (let i = 0; i < 5000; i++) {
    const junk = random(random(1)[0] % 64);
    if (junk.length) junk[0] = 0x7b;
    const out = readObject(junk);
    assert.ok(out === null || typeof out === 'object');
  }
});
